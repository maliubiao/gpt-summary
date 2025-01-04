Response:
Let's break down the thought process for analyzing this `scroll_into_view_util.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this Chromium Blink engine source file, particularly concerning its relationship to web technologies (JavaScript, HTML, CSS), provide examples, and identify potential errors and debugging strategies.

2. **Initial Scan for Keywords and Concepts:**  Quickly read through the code, looking for recurring terms and familiar concepts related to scrolling and web development. Keywords like `scrollIntoView`, `ScrollableArea`, `LayoutBox`, `Frame`, `VisualViewport`, `alignment`, `behavior`, `smooth scroll`, `cross-origin`, `focused editable`, `scroll margin`, etc., immediately jump out. The include headers also provide clues (e.g., `v8_scroll_into_view_options.h`, `document.h`, `html_frame_owner_element.h`).

3. **Identify the Core Functionality:** The file name itself, `scroll_into_view_util.cc`, strongly suggests its primary purpose is to handle the logic behind the `scrollIntoView()` JavaScript method and related internal scrolling mechanisms within Blink.

4. **Deconstruct Key Functions:** Start examining the major functions defined in the file. The function `ScrollRectToVisible` appears to be the main entry point. Analyze its parameters and the steps it performs. Notice the bubbling behavior (`PerformBubblingScrollIntoView`), handling of different scroll types (programmatic, user), and the interaction with parent frames.

5. **Map to Web Concepts:** Connect the identified functions and concepts to their corresponding web technologies:

    * **`scrollIntoView()`:**  Directly related to the JavaScript method of the same name. Mention how developers use it to bring elements into view.
    * **CSS `scroll-behavior`:** The `behavior` parameter in the code maps directly to the CSS property. Explain the `smooth` and `auto` values.
    * **CSS `scroll-snap-align` and Scroll Margins:** The code explicitly handles these CSS properties. Illustrate with examples of how they influence scrolling behavior.
    * **HTML `<iframe>`:** The code considers cross-frame scrolling and the role of `HTMLFrameOwnerElement`. Give an example of how `scrollIntoView` can work across iframes, and the security considerations involved.
    * **Focusing Editable Elements:**  The handling of `for_focused_editable` links to the user experience of focusing on input fields and text areas. Explain the special considerations for these elements.
    * **Visual Viewport:**  Mention how the visual viewport is involved, especially in the context of fixed positioning and mobile considerations.

6. **Trace the Logic Flow:** Follow the execution path of `ScrollRectToVisible`. Observe how it determines the scrollable areas, calculates the target scroll position based on alignment, and handles propagation to parent frames. The `PerformBubblingScrollIntoView` function is crucial here.

7. **Consider Edge Cases and Error Scenarios:** Think about what could go wrong or lead to unexpected behavior:

    * **Cross-Origin Issues:** The code explicitly checks for cross-origin boundaries. Explain the security implications and when scrolling might be blocked.
    * **`display: none` elements:**  The code mentions that a `display: none` iframe won't propagate the scroll. This is a common web development issue.
    * **Fixed Positioning:**  The special handling of `position: fixed` elements is important to understand.
    * **Smooth Scrolling and Interruptions:**  The logic around `SmoothScrollSequencer` suggests potential issues if multiple scroll requests occur.

8. **Illustrate with Examples:**  Provide concrete examples in HTML, CSS, and JavaScript to demonstrate how the concepts discussed in the code manifest in a web page. This makes the explanation much more tangible.

9. **Infer Input and Output:** For key functions, especially `PerformBubblingScrollIntoView` and `GetScrollOffsetToExpose`, make educated guesses about potential inputs (e.g., a `LayoutBox`, a `PhysicalRect`, scroll parameters) and the expected outputs (e.g., a new `PhysicalRect`, a `ScrollOffset`). This helps solidify understanding of their purpose.

10. **Identify User/Programming Errors:**  Based on the code's logic, pinpoint common mistakes developers might make:

    * Incorrectly assuming cross-origin scrolling will always work.
    * Not understanding the impact of `scroll-margin` and `scroll-snap-align`.
    * Issues with nested scroll containers.
    * Problems with scrolling elements inside fixed-position containers.

11. **Describe the Debugging Process:**  Explain how a developer might end up in this code during debugging:

    * Setting breakpoints in `scrollIntoView()`.
    * Tracing scroll events.
    * Investigating unexpected scrolling behavior.
    * Looking at the call stack when a scroll-related issue occurs.

12. **Structure and Organize:** Present the information in a clear, logical manner. Start with a high-level overview, then delve into specifics, and conclude with debugging tips. Use headings and bullet points to improve readability.

13. **Refine and Review:** After drafting the analysis, reread it to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have emphasized the role of `LayoutBox` enough, and a review would highlight that.

By following this systematic approach, combining code analysis with knowledge of web technologies, and thinking through potential use cases and errors, a comprehensive and informative explanation of the `scroll_into_view_util.cc` file can be constructed.
好的，我们来详细分析一下 `blink/renderer/core/scroll/scroll_into_view_util.cc` 这个文件的功能。

**文件功能概述:**

这个文件 (`scroll_into_view_util.cc`)  是 Chromium Blink 渲染引擎中负责实现元素滚动到可视区域的核心工具类。它提供了一系列静态方法，用于处理各种滚动到视图的操作，包括：

* **计算滚动偏移量:**  根据不同的对齐方式 (`align-items`, `justify-content` 的滚动版本)，计算需要滚动的精确距离，以使目标元素进入可视区域。
* **处理跨框架滚动:**  当目标元素位于不同的 iframe 中时，它负责将滚动请求传递到父框架，直到目标元素最终可见。
* **处理平滑滚动:**  它与 `SmoothScrollSequencer` 协同工作，实现 CSS `scroll-behavior: smooth` 属性的平滑滚动效果。
* **处理 `scrollIntoView()` JavaScript API:**  它是 JavaScript `element.scrollIntoView()` 方法在 Blink 引擎内部的实现基础。
* **处理聚焦可编辑元素时的滚动:**  针对用户点击或通过 JavaScript 聚焦可编辑元素（如 `<input>`, `<textarea>`)，提供特殊的滚动和缩放逻辑，以确保元素清晰可见。
* **处理滚动边距 (`scroll-margin`)**: 考虑元素的 `scroll-margin` 属性，在滚动时留出一定的边距。
* **处理可视视口 (Visual Viewport):**  考虑在移动设备上调整可视视口，以使元素可见。
* **处理跨域情况:**  在适当的情况下允许跨域的 `scrollIntoView` 操作，并进行安全检查。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **JavaScript `element.scrollIntoView()`:**
   - **功能关系:**  `scroll_into_view_util.cc` 中的 `ScrollRectToVisible` 函数是 `element.scrollIntoView()` 方法的核心实现。当 JavaScript 调用 `element.scrollIntoView()` 或 `element.scrollIntoView(options)` 时，最终会调用到这个 C++ 函数。
   - **举例说明:**
     ```javascript
     // HTML: <div id="target">我需要被滚动到可视区域</div>
     const targetElement = document.getElementById('target');

     // 调用 scrollIntoView()，默认行为：尽可能让元素完全可见
     targetElement.scrollIntoView();

     // 调用 scrollIntoView(options)，指定对齐方式和滚动行为
     targetElement.scrollIntoView({
       behavior: 'smooth', // 平滑滚动
       block: 'center',    // 垂直方向居中
       inline: 'nearest'  // 水平方向尽可能靠近边缘
     });
     ```
     当执行这些 JavaScript 代码时，Blink 引擎内部会使用 `scroll_into_view_util.cc` 中的函数来计算滚动位置并执行滚动操作。

2. **HTML `<iframe>`:**
   - **功能关系:**  `scroll_into_view_util.cc` 负责处理跨 iframe 的滚动。当目标元素位于一个 iframe 中，而滚动操作在父窗口或另一个同源/跨域的 iframe 中触发时，这个文件中的逻辑会负责将滚动请求传递到正确的框架。
   - **举例说明:**
     ```html
     <!-- 父窗口 -->
     <!DOCTYPE html>
     <html>
     <head>
         <title>Parent Window</title>
     </head>
     <body>
         <iframe id="myIframe" src="iframe.html"></iframe>
         <button onclick="scrollIntoIframe()">滚动 iframe 中的元素</button>
         <script>
             function scrollIntoIframe() {
                 const iframe = document.getElementById('myIframe');
                 const iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                 const targetElement = iframeDocument.getElementById('iframeTarget');
                 targetElement.scrollIntoView({ behavior: 'smooth' });
             }
         </script>
     </body>
     </html>

     <!-- iframe.html -->
     <!DOCTYPE html>
     <html>
     <head>
         <title>Iframe</title>
     </head>
     <body>
         <div id="iframeTarget" style="height: 2000px;">这是 iframe 中需要滚动的元素</div>
     </body>
     </html>
     ```
     当点击父窗口的按钮时，`scrollIntoIframe` 函数会尝试滚动 iframe 中的 `iframeTarget` 元素。`scroll_into_view_util.cc` 中的逻辑会识别出目标元素位于不同的框架，并将滚动请求传递给 iframe。

3. **CSS `scroll-behavior: smooth`:**
   - **功能关系:**  `scroll_into_view_util.cc` 与 `SmoothScrollSequencer` 协同工作，来实现平滑滚动效果。当 CSS 中设置了 `scroll-behavior: smooth` 时，或者 JavaScript `scrollIntoView()` 的 `behavior` 选项设置为 `'smooth'` 时，这个文件中的逻辑会触发平滑滚动动画。
   - **举例说明:**
     ```css
     /* CSS 设置平滑滚动 */
     html {
         scroll-behavior: smooth;
     }

     /* 或者针对特定元素 */
     .scrollable-container {
         scroll-behavior: smooth;
         overflow: auto;
         height: 300px;
     }
     ```
     当页面或特定容器设置了 `scroll-behavior: smooth` 后，任何导致滚动的操作（例如点击锚点链接，使用 `scrollIntoView()`）都会触发平滑的滚动动画，这背后的实现就涉及到 `scroll_into_view_util.cc`。

4. **CSS `scroll-margin`:**
   - **功能关系:** `scroll_into_view_util.cc` 会读取元素的 `scroll-margin` 属性值，并在计算滚动位置时考虑这些边距。这确保了在元素滚动到可视区域时，周围会留有一定的空白。
   - **举例说明:**
     ```css
     #target {
         scroll-margin-top: 20px;
         scroll-margin-bottom: 30px;
         /* ... 其他样式 */
     }
     ```
     当 `#target` 元素通过 `scrollIntoView()` 滚动到可视区域时，`scroll_into_view_util.cc` 会确保 `#target` 的顶部与滚动容器的顶部之间至少有 20px 的间距，底部至少有 30px 的间距。

**逻辑推理 (假设输入与输出):**

假设我们有一个 `<div>` 元素，其 ID 为 `target`，位于一个可以滚动的容器内。

**假设输入:**

* **目标元素:** `LayoutBox` 对象，对应于 ID 为 `target` 的 `<div>` 元素。
* **滚动容器:**  包含目标元素的 `ScrollableArea` 对象。
* **滚动参数:** `mojom::blink::ScrollIntoViewParamsPtr`，包含以下信息：
    * `align_x`: `ScrollAlignment::CenterAlways()` (水平居中)
    * `align_y`: `ScrollAlignment::ToEdgeIfNeeded()` (垂直方向尽可能靠近边缘)
    * `behavior`: `mojom::blink::ScrollBehavior::kSmooth`
    * `type`: `mojom::blink::ScrollType::kProgrammatic` (通过 JavaScript 或内部逻辑触发)
    * 目标元素没有设置 `scroll-margin`。

**预期输出:**

* **滚动偏移量:** `ScrollOffset` 对象，表示滚动容器需要滚动的 `x` 和 `y` 偏移量，以使 `target` 元素在滚动容器中水平居中，并在垂直方向上尽可能靠近顶部或底部边缘（如果当前已部分可见，则可能不滚动）。
* **平滑滚动动画:** 如果滚动容器支持平滑滚动（`scroll-behavior: smooth`），则会启动一个平滑的滚动动画。

**用户或编程常见的使用错误:**

1. **跨域 iframe 滚动限制:**
   - **错误:** 尝试从一个域的页面滚动到另一个不同源域的 iframe 中的元素，并且没有正确设置 CORS 或使用 `crossOriginIsolated` 等机制。
   - **后果:**  滚动可能被阻止，或者行为不符合预期。
   - **用户操作:** 用户点击了一个链接或按钮，该操作尝试滚动到一个跨域 iframe 中的元素。

2. **在 `display: none` 元素上调用 `scrollIntoView()`:**
   - **错误:**  在 CSS 中设置了 `display: none` 的元素上调用 `scrollIntoView()`。
   - **后果:** 元素不可见，滚动操作通常不会发生或者行为不明确。
   - **用户操作:**  虽然用户通常不会直接在不可见元素上触发滚动，但可能是程序逻辑错误，尝试滚动一个当前隐藏的元素。

3. **误解 `block` 和 `inline` 对齐方式:**
   - **错误:**  错误地理解 `scrollIntoView` options 中的 `block` 和 `inline` 属性如何影响垂直和水平滚动，特别是在不同的书写模式下。
   - **后果:**  元素没有滚动到期望的位置。
   - **用户操作:** 开发者编写了 JavaScript 代码，使用了错误的 `block` 或 `inline` 值，导致滚动结果不符合预期。

4. **忘记考虑 `scroll-margin`:**
   - **错误:**  在设计布局或进行滚动操作时，没有考虑到元素的 `scroll-margin` 属性，导致元素滚动到可视区域后，紧贴着容器边缘，没有预期的空白。
   - **用户操作:**  用户可能觉得元素滚动得太靠近边缘，影响阅读体验。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户交互触发 JavaScript 滚动:**
   - 用户点击了一个带有 `href` 属性的锚点链接 (`<a href="#target">`)。
   - 用户点击了一个按钮，该按钮的 `onclick` 事件处理程序调用了 `element.scrollIntoView()`。
   - 用户在地址栏中输入了一个包含锚点的 URL (例如 `example.com/#target`)。

2. **浏览器解析和执行 JavaScript:**
   - 浏览器解析 HTML，遇到锚点链接或 JavaScript 代码。
   - JavaScript 引擎执行相关的滚动操作。

3. **Blink 引擎接收滚动请求:**
   - JavaScript 的 `element.scrollIntoView()` 调用会映射到 Blink 引擎的内部接口。

4. **进入 `scroll_into_view_util.cc`:**
   - Blink 引擎内部会调用 `core/dom/Element.cc` 中的相关方法来处理滚动请求。
   - 最终会调用到 `blink::scroll_into_view_util::ScrollRectToVisible` 函数，这是 `scroll_into_view_util.cc` 中处理滚动到视图的核心入口点。

5. **执行滚动逻辑:**
   - `ScrollRectToVisible` 函数会根据传入的参数（目标元素、滚动容器、对齐方式、滚动行为等）执行以下步骤：
     - 获取目标元素的布局信息 (`LayoutBox`)。
     - 获取滚动容器的信息 (`ScrollableArea`)。
     - 如果需要，处理跨框架的滚动。
     - 计算目标滚动偏移量 (`GetScrollOffsetToExpose`)。
     - 如果需要平滑滚动，与 `SmoothScrollSequencer` 交互。
     - 更新滚动容器的滚动位置。

**调试线索:**

当开发者遇到与 `scrollIntoView()` 相关的 bug 时，可以按照以下步骤进行调试：

1. **在 JavaScript 中设置断点:** 在调用 `element.scrollIntoView()` 的地方设置断点，检查传入的参数和当前元素的状态。
2. **使用浏览器的开发者工具:**
   - **Elements 面板:**  检查目标元素及其祖先元素的样式，特别是 `overflow`, `scroll-behavior`, `scroll-margin` 等属性。
   - **Performance 面板:**  查看滚动操作是否触发了预期的布局和绘制。
   - **Console 面板:**  记录滚动相关的事件或信息。
3. **在 Blink 引擎源代码中设置断点:**  如果需要深入了解 Blink 引擎的内部行为，可以在 `scroll_into_view_util.cc` 中的关键函数（例如 `ScrollRectToVisible`, `PerformBubblingScrollIntoView`, `GetScrollOffsetToExpose`) 设置断点，跟踪滚动逻辑的执行过程。这通常需要编译 Chromium 才能实现。
4. **检查滚动相关的事件监听器:**  查看是否有 JavaScript 代码阻止了默认的滚动行为或添加了自定义的滚动逻辑。

总而言之，`blink/renderer/core/scroll/scroll_into_view_util.cc` 是 Blink 引擎中实现元素滚动到可视区域功能的核心模块，它与 JavaScript, HTML, CSS 紧密相关，处理各种复杂的滚动场景，并为开发者提供了强大的控制能力。理解其功能有助于更好地理解浏览器如何处理滚动，并解决相关的开发问题。

Prompt: 
```
这是目录为blink/renderer/core/scroll/scroll_into_view_util.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"

#include <optional>
#include <tuple>

#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scroll_into_view_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/map_coordinates_flags.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

// Returns true if a scroll into view can continue to cause scrolling in the
// parent frame.
bool AllowedToPropagateToParent(
    const LocalFrame& from_frame,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  // Focused editable scrolling (i.e. scroll an input the user tapped on)
  // always originates from a user action in the browser so it should always be
  // allowed to cross origins and we shouldn't stop it for policy or other
  // reasons.
  DCHECK(!params->for_focused_editable || params->cross_origin_boundaries);
  if (params->for_focused_editable)
    return true;

  // TODO(bokan): For now, we'll do the safe thing and just block all other
  // types of scrollIntoView from propagating out of a fenced frame but we may
  // need to loosen this if we find other critical use cases.
  // https://crbug.com/1324816.
  if (from_frame.IsFencedFrameRoot())
    return false;

  if (!params->cross_origin_boundaries) {
    Frame* parent_frame = from_frame.Tree().Parent();
    if (parent_frame &&
        !parent_frame->GetSecurityContext()->GetSecurityOrigin()->CanAccess(
            from_frame.GetSecurityContext()->GetSecurityOrigin())) {
      return false;
    }
  }

  if (params->type != mojom::blink::ScrollType::kProgrammatic)
    return true;

  if (!from_frame.GetDocument())
    return true;

  return !from_frame.GetDocument()->IsVerticalScrollEnforced();
}

ALWAYS_INLINE ScrollableArea* GetScrollableAreaForLayoutBox(
    const LayoutBox& box,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  if (box.IsScrollContainer() && !box.IsLayoutView()) {
    return box.GetScrollableArea();
  } else if (!box.ContainingBlock()) {
    return params->make_visible_in_visual_viewport
               ? box.GetFrameView()->GetScrollableArea()
               : box.GetFrameView()->LayoutViewport();
  }
  return nullptr;
}

// Helper to return the parent LayoutBox, crossing local frame boundaries, that
// a scroll should bubble up to or nullptr if the local root has been reached.
// The return optional will be empty if the scroll is blocked from bubbling to
// the root.
std::optional<LayoutBox*> GetScrollParent(
    const LayoutBox& box,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  bool is_fixed_to_frame = box.StyleRef().GetPosition() == EPosition::kFixed &&
                           box.Container() == box.View();

  // Within a document scrolls bubble along the containing block chain but if
  // we're in a position:fixed element, we want to immediately bubble up across
  // the frame boundary since scrolling the frame won't affect the box's
  // position.
  if (box.ContainingBlock() && !is_fixed_to_frame)
    return box.ContainingBlock();

  // Otherwise, we're bubbling across a frame boundary. We may be
  // prevented from doing so for security or policy reasons. If so, we're
  // done.
  if (!AllowedToPropagateToParent(*box.GetFrame(), params))
    return std::nullopt;

  if (!box.GetFrame()->IsLocalRoot()) {
    // The parent is a local iframe, convert to the absolute coordinate space
    // of its document and continue from the owner's LayoutBox.
    HTMLFrameOwnerElement* owner_element = box.GetDocument().LocalOwner();
    DCHECK(owner_element);

    // A display:none iframe can have a LayoutView but its owner element won't
    // have a LayoutObject. If that happens, don't bubble the scroll.
    if (!owner_element->GetLayoutObject())
      return std::nullopt;

    return owner_element->GetLayoutObject()->EnclosingBox();
  }

  // If the owner is remote, the scroll must continue via IPC.
  DCHECK(box.GetFrame()->IsMainFrame() ||
         box.GetFrame()->Parent()->IsRemoteFrame());
  return nullptr;
}

ALWAYS_INLINE void AdjustRectToNotEmpty(PhysicalRect& rect) {
  if (rect.Width() <= 0) {
    rect.SetWidth(LayoutUnit(1));
  }
  if (rect.Height() <= 0) {
    rect.SetHeight(LayoutUnit(1));
  }
}

ALWAYS_INLINE void AdjustRectAndParamsForParentFrame(
    const LayoutBox& current_box,
    const LayoutBox* next_box,
    PhysicalRect& absolute_rect_to_scroll,
    mojom::blink::ScrollIntoViewParamsPtr& params) {
  // If the next box to scroll is in another frame, we need to convert the
  // scroll box to the new frame's absolute coordinates.
  if (next_box && next_box->View() != current_box.View()) {
    scroll_into_view_util::ConvertParamsToParentFrame(
        params, gfx::RectF(absolute_rect_to_scroll), *current_box.View(),
        *next_box->View());

    absolute_rect_to_scroll = current_box.View()->LocalToAncestorRect(
        absolute_rect_to_scroll, next_box->View(), kTraverseDocumentBoundaries);
  }
}

// Helper that reveals the given rect, given in absolute coordinates, by
// scrolling the given `box` LayoutBox and then all its ancestors up to the
// local root frame.  To continue the reveal through remote ancestors, use
// LayoutObject::ScrollRectToVisible. If the scroll bubbled up to the local
// root successfully, returns the updated absolute rect in the absolute
// coordinates of the local root. Otherwise returns an empty optional.
std::optional<PhysicalRect> PerformBubblingScrollIntoView(
    const LayoutBox& box,
    const PhysicalRect& absolute_rect,
    mojom::blink::ScrollIntoViewParamsPtr& params,
    const PhysicalBoxStrut& scroll_margin,
    bool from_remote_frame) {
  DCHECK(params->type == mojom::blink::ScrollType::kProgrammatic ||
         params->type == mojom::blink::ScrollType::kUser);

  if (!box.GetFrameView())
    return std::nullopt;

  PhysicalRect absolute_rect_to_scroll = absolute_rect;
  PhysicalBoxStrut active_scroll_margin = scroll_margin;
  bool scrolled_to_area = false;
  bool will_sequence_scrolls =
      !RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled() &&
      params->is_for_scroll_sequence;

  // TODO(bokan): Temporary, to track cross-origin scroll-into-view prevalence.
  // https://crbug.com/1339003.
  const SecurityOrigin* starting_frame_origin =
      box.GetFrame()->GetSecurityContext()->GetSecurityOrigin();

  const LayoutBox* current_box = &box;
  while (current_box) {
    AdjustRectToNotEmpty(absolute_rect_to_scroll);

    // If we've reached the main frame's layout viewport (which is always set to
    // the global root scroller, see ViewportScrollCallback::SetScroller), if
    // this scroll-into-view is for focusing an editable. We do this so
    // that we can allow a smooth "scroll and zoom" animation to do the final
    // scroll in cases like scrolling a focused editable box into view.
    // TODO(bokan): Ensure a fenced frame doesn't get a global root scroller
    // and then remove the !IsInFencedFrameTree condition.
    // https://crbug.com/1314858
    if (!current_box->GetFrame()->IsInFencedFrameTree() &&
        params->for_focused_editable && current_box->IsGlobalRootScroller()) {
      break;
    }

    ScrollableArea* area_to_scroll =
        GetScrollableAreaForLayoutBox(*current_box, params);
    if (area_to_scroll) {
      ScrollOffset scroll_before = area_to_scroll->GetScrollOffset();
      CHECK(!will_sequence_scrolls ||
            area_to_scroll->GetSmoothScrollSequencer());
      wtf_size_t num_scroll_sequences =
          will_sequence_scrolls
              ? area_to_scroll->GetSmoothScrollSequencer()->GetCount()
              : 0ul;

      absolute_rect_to_scroll = area_to_scroll->ScrollIntoView(
          absolute_rect_to_scroll, active_scroll_margin, params);
      scrolled_to_area = true;

      // TODO(bokan): Temporary, to track cross-origin scroll-into-view
      // prevalence. https://crbug.com/1339003.
      // If this is for a scroll sequence, GetScrollOffset won't change until
      // all the animations in the sequence are run which happens
      // asynchronously after this method returns. Thus, for scroll sequences,
      // check instead if an entry was added to the sequence which occurs only
      // if the scroll offset is changed as a result of ScrollIntoView.
      bool scroll_changed =
          will_sequence_scrolls
              ? area_to_scroll->GetSmoothScrollSequencer()->GetCount() !=
                    num_scroll_sequences
              : area_to_scroll->GetScrollOffset() != scroll_before;
      if (scroll_changed && !params->for_focused_editable &&
          params->type == mojom::blink::ScrollType::kProgrammatic) {
        const SecurityOrigin* current_frame_origin =
            current_box->GetFrame()->GetSecurityContext()->GetSecurityOrigin();
        if (!current_frame_origin->CanAccess(starting_frame_origin) ||
            from_remote_frame) {
          // ScrollIntoView caused a visible scroll in an origin that can't be
          // accessed from where the ScrollIntoView was initiated.
          DCHECK(params->cross_origin_boundaries);
          UseCounter::Count(
              current_box->GetFrame()->LocalFrameRoot().GetDocument(),
              WebFeature::kCrossOriginScrollIntoView);
        }
      }
    }

    bool is_fixed_to_frame =
        current_box->StyleRef().GetPosition() == EPosition::kFixed &&
        current_box->Container() == current_box->View();

    VisualViewport& visual_viewport =
        current_box->GetFrame()->GetPage()->GetVisualViewport();
    if (is_fixed_to_frame && params->make_visible_in_visual_viewport) {
      // If we're in a position:fixed element, scrolling the layout viewport
      // won't have any effect and would be wrong so we want to bubble up to
      // the layout viewport's parent. For subframes that's the frame's owner.
      // For the main frame that's the visual viewport but it isn't associated
      // with a LayoutBox so we just scroll it here as a special case.
      // Note: In non-fixed cases, the visual viewport will have been scrolled
      // by the frame scroll via the RootFrameViewport
      // (GetFrameView()->GetScrollableArea() above).
      if (current_box->GetFrame()->IsMainFrame() &&
          visual_viewport.IsActiveViewport()) {
        absolute_rect_to_scroll =
            current_box->GetFrame()
                ->GetPage()
                ->GetVisualViewport()
                .ScrollIntoView(absolute_rect_to_scroll, active_scroll_margin,
                                params);
        scrolled_to_area = true;
      }

      // TODO(bokan): To be correct we should continue to bubble the scroll
      // from a subframe since ancestor frames can still scroll the element
      // into view. However, making that change had some compat-impact so we
      // intentionally keep this behavior for now while
      // https://crbug.com/1334265 is resolved.
      break;
    }

    // If the scroll was stopped prior to reaching the local root, we cannot
    // return a rect since the caller cannot know which frame it's relative to.
    std::optional<LayoutBox*> next_box_opt =
        GetScrollParent(*current_box, params);
    if (!next_box_opt) {
      return std::nullopt;
    }

    LayoutBox* next_box = *next_box_opt;

    AdjustRectAndParamsForParentFrame(*current_box, next_box,
                                      absolute_rect_to_scroll, params);

    // Once we've taken the scroll-margin into account, don't apply it to
    // ancestor scrollers.
    // TODO(crbug.com/1325839): Instead of just nullifying the scroll-margin,
    // maybe we should be applying the scroll-margin of the containing
    // scrollers themselves? This will probably need to be spec'd as the current
    // scroll-into-view spec[1] only refers to the bounding border box.
    // [1] https://drafts.csswg.org/cssom-view-1/#scroll-a-target-into-view
    if (scrolled_to_area) {
      active_scroll_margin = PhysicalBoxStrut();
    }

    current_box = next_box;
  }

  return absolute_rect_to_scroll;
}

}  // namespace

namespace scroll_into_view_util {

void ScrollRectToVisible(const LayoutObject& layout_object,
                         const PhysicalRect& absolute_rect,
                         mojom::blink::ScrollIntoViewParamsPtr params,
                         bool from_remote_frame) {
  LayoutBox* enclosing_box = layout_object.EnclosingBox();
  if (!enclosing_box)
    return;

  LocalFrame* frame = layout_object.GetFrame();

  params->is_for_scroll_sequence |=
      params->type == mojom::blink::ScrollType::kProgrammatic;
  bool will_sequence_scrolls =
      !RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled() &&
      params->is_for_scroll_sequence;

  SmoothScrollSequencer* old_sequencer = nullptr;
  if (will_sequence_scrolls) {
    old_sequencer = frame->CreateNewSmoothScrollSequence();
    frame->GetSmoothScrollSequencer()->SetScrollType(params->type);
  }

  PhysicalBoxStrut scroll_margin =
      layout_object.Style() ? layout_object.Style()->ScrollMarginStrut()
                            : PhysicalBoxStrut();
  PhysicalRect absolute_rect_to_scroll = absolute_rect;
  absolute_rect_to_scroll.Expand(scroll_margin);
  std::optional<PhysicalRect> updated_absolute_rect =
      PerformBubblingScrollIntoView(*enclosing_box, absolute_rect_to_scroll,
                                    params, scroll_margin, from_remote_frame);

  if (will_sequence_scrolls) {
    if (frame->GetSmoothScrollSequencer()->IsEmpty()) {
      // If the scroll into view was a no-op (the element was already in the
      // proper place), reinstate any previously running smooth scroll sequence
      // so that it can continue running. This prevents unintentionally
      // clobbering a scroll by e.g. setting focus() to an in-view element.
      frame->ReinstateSmoothScrollSequence(old_sequencer);
    } else {
      // Otherwise clobber any previous sequence.
      if (old_sequencer) {
        old_sequencer->AbortAnimations();
      }
      frame->GetSmoothScrollSequencer()->RunQueuedAnimations();
    }
  }

  // If the scroll into view stopped early (i.e. before the local root),
  // there's no need to continue bubbling or finishing a scroll focused
  // editable into view.
  if (!updated_absolute_rect)
    return;

  LocalFrame& local_root = frame->LocalFrameRoot();
  LocalFrameView* local_root_view = local_root.View();

  if (!local_root_view)
    return;

  if (!local_root.IsOutermostMainFrame()) {
    // Continue the scroll via IPC if there's a remote ancestor.
    if (AllowedToPropagateToParent(local_root, params)) {
      local_root_view->ScrollRectToVisibleInRemoteParent(*updated_absolute_rect,
                                                         std::move(params));
    }
  } else if (params->for_focused_editable) {
    // If we're scrolling a focused editable into view, once we reach the main
    // frame we need to perform an animated scroll and zoom to bring the
    // editable into a legible size.
    gfx::RectF caret_rect_in_root_frame(*updated_absolute_rect);
    DCHECK(!caret_rect_in_root_frame.IsEmpty());
    local_root.GetPage()->GetChromeClient().FinishScrollFocusedEditableIntoView(
        caret_rect_in_root_frame, std::move(params));
  }
}

gfx::RectF FocusedEditableBoundsFromParams(
    const gfx::RectF& caret_rect,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  DCHECK(params->for_focused_editable);
  DCHECK(!params->for_focused_editable->size.IsEmpty());

  gfx::PointF editable_location =
      caret_rect.origin() + params->for_focused_editable->relative_location;
  return gfx::RectF(editable_location, params->for_focused_editable->size);
}

void ConvertParamsToParentFrame(mojom::blink::ScrollIntoViewParamsPtr& params,
                                const gfx::RectF& caret_rect_in_src,
                                const LayoutObject& src_frame,
                                const LayoutView& dest_frame) {
  if (!params->for_focused_editable)
    return;

  // The source frame will be a LayoutView if the conversion is local or a
  // LayoutEmbeddedContent if we're crossing a remote boundary.
  DCHECK(src_frame.IsLayoutView() || src_frame.IsLayoutEmbeddedContent());

  gfx::RectF editable_bounds_in_src =
      FocusedEditableBoundsFromParams(caret_rect_in_src, params);

  PhysicalRect editable_bounds_in_dest = src_frame.LocalToAncestorRect(
      PhysicalRect::EnclosingRect(editable_bounds_in_src), &dest_frame,
      kTraverseDocumentBoundaries);

  PhysicalRect caret_rect_in_dest = src_frame.LocalToAncestorRect(
      PhysicalRect::EnclosingRect(caret_rect_in_src), &dest_frame,
      kTraverseDocumentBoundaries);

  params->for_focused_editable->relative_location = gfx::Vector2dF(
      editable_bounds_in_dest.offset - caret_rect_in_dest.offset);
  params->for_focused_editable->size = gfx::SizeF(editable_bounds_in_dest.size);

  DCHECK(!params->for_focused_editable->size.IsEmpty());
}

mojom::blink::ScrollIntoViewParamsPtr CreateScrollIntoViewParams(
    const mojom::blink::ScrollAlignment& align_x,
    const mojom::blink::ScrollAlignment& align_y,
    mojom::blink::ScrollType scroll_type,
    bool make_visible_in_visual_viewport,
    mojom::blink::ScrollBehavior scroll_behavior,
    bool is_for_scroll_sequence,
    bool cross_origin_boundaries) {
  auto params = mojom::blink::ScrollIntoViewParams::New();
  params->align_x = mojom::blink::ScrollAlignment::New(align_x);
  params->align_y = mojom::blink::ScrollAlignment::New(align_y);
  params->type = scroll_type;
  params->make_visible_in_visual_viewport = make_visible_in_visual_viewport;
  params->behavior = scroll_behavior;
  params->is_for_scroll_sequence = is_for_scroll_sequence;
  params->cross_origin_boundaries = cross_origin_boundaries;
  return params;
}

namespace {
mojom::blink::ScrollAlignment ResolveToPhysicalAlignment(
    V8ScrollLogicalPosition::Enum inline_alignment,
    V8ScrollLogicalPosition::Enum block_alignment,
    ScrollOrientation axis,
    const ComputedStyle& computed_style) {
  bool is_horizontal_writing_mode = computed_style.IsHorizontalWritingMode();
  V8ScrollLogicalPosition::Enum alignment =
      ((axis == kHorizontalScroll && is_horizontal_writing_mode) ||
       (axis == kVerticalScroll && !is_horizontal_writing_mode))
          ? inline_alignment
          : block_alignment;

  if (alignment == V8ScrollLogicalPosition::Enum::kCenter) {
    return ScrollAlignment::CenterAlways();
  }
  if (alignment == V8ScrollLogicalPosition::Enum::kNearest) {
    return ScrollAlignment::ToEdgeIfNeeded();
  }
  if (alignment == V8ScrollLogicalPosition::Enum::kStart) {
    PhysicalToLogical<const mojom::blink::ScrollAlignment& (*)()> to_logical(
        computed_style.GetWritingDirection(), ScrollAlignment::TopAlways,
        ScrollAlignment::RightAlways, ScrollAlignment::BottomAlways,
        ScrollAlignment::LeftAlways);
    if (axis == kHorizontalScroll) {
      return is_horizontal_writing_mode ? (*to_logical.InlineStart())()
                                        : (*to_logical.BlockStart())();
    } else {
      return is_horizontal_writing_mode ? (*to_logical.BlockStart())()
                                        : (*to_logical.InlineStart())();
    }
  }
  if (alignment == V8ScrollLogicalPosition::Enum::kEnd) {
    PhysicalToLogical<const mojom::blink::ScrollAlignment& (*)()> to_logical(
        computed_style.GetWritingDirection(), ScrollAlignment::TopAlways,
        ScrollAlignment::RightAlways, ScrollAlignment::BottomAlways,
        ScrollAlignment::LeftAlways);
    if (axis == kHorizontalScroll) {
      return is_horizontal_writing_mode ? (*to_logical.InlineEnd())()
                                        : (*to_logical.BlockEnd())();
    } else {
      return is_horizontal_writing_mode ? (*to_logical.BlockEnd())()
                                        : (*to_logical.InlineEnd())();
    }
  }

  // Default values
  if (is_horizontal_writing_mode) {
    return (axis == kHorizontalScroll) ? ScrollAlignment::ToEdgeIfNeeded()
                                       : ScrollAlignment::TopAlways();
  }
  return (axis == kHorizontalScroll) ? ScrollAlignment::LeftAlways()
                                     : ScrollAlignment::ToEdgeIfNeeded();
}

V8ScrollLogicalPosition::Enum SnapAlignmentToV8ScrollLogicalPosition(
    cc::SnapAlignment alignment) {
  switch (alignment) {
    case cc::SnapAlignment::kNone:
      return V8ScrollLogicalPosition::Enum::kNearest;
    case cc::SnapAlignment::kStart:
      return V8ScrollLogicalPosition::Enum::kStart;
    case cc::SnapAlignment::kEnd:
      return V8ScrollLogicalPosition::Enum::kEnd;
    case cc::SnapAlignment::kCenter:
      return V8ScrollLogicalPosition::Enum::kCenter;
  }
}

}  // namespace

mojom::blink::ScrollIntoViewParamsPtr CreateScrollIntoViewParams(
    const ScrollIntoViewOptions& options,
    const ComputedStyle& computed_style) {
  mojom::blink::ScrollBehavior behavior = mojom::blink::ScrollBehavior::kAuto;
  if (options.behavior().AsEnum() == V8ScrollBehavior::Enum::kSmooth) {
    behavior = mojom::blink::ScrollBehavior::kSmooth;
  }
  if (options.behavior() == V8ScrollBehavior::Enum::kInstant) {
    behavior = mojom::blink::ScrollBehavior::kInstant;
  }

  auto align_x = ResolveToPhysicalAlignment(options.inlinePosition().AsEnum(),
                                            options.block().AsEnum(),
                                            kHorizontalScroll, computed_style);
  auto align_y = ResolveToPhysicalAlignment(options.inlinePosition().AsEnum(),
                                            options.block().AsEnum(),
                                            kVerticalScroll, computed_style);

  mojom::blink::ScrollIntoViewParamsPtr params =
      CreateScrollIntoViewParams(align_x, align_y);
  params->behavior = behavior;
  return params;
}

mojom::blink::ScrollIntoViewParamsPtr CreateScrollIntoViewParams(
    const ComputedStyle& computed_style) {
  V8ScrollLogicalPosition::Enum inline_alignment =
      SnapAlignmentToV8ScrollLogicalPosition(
          computed_style.GetScrollSnapAlign().alignment_inline);
  V8ScrollLogicalPosition::Enum block_alignment =
      SnapAlignmentToV8ScrollLogicalPosition(
          computed_style.GetScrollSnapAlign().alignment_block);
  auto align_x = ResolveToPhysicalAlignment(inline_alignment, block_alignment,
                                            kHorizontalScroll, computed_style);
  auto align_y = ResolveToPhysicalAlignment(inline_alignment, block_alignment,
                                            kVerticalScroll, computed_style);

  mojom::blink::ScrollIntoViewParamsPtr params =
      CreateScrollIntoViewParams(align_x, align_y);
  params->behavior = computed_style.GetScrollBehavior();
  return params;
}

ScrollOffset GetScrollOffsetToExpose(
    const ScrollableArea& scroll_area,
    const PhysicalRect& local_expose_rect,
    const PhysicalBoxStrut& expose_scroll_margin,
    const mojom::blink::ScrollAlignment& align_x,
    const mojom::blink::ScrollAlignment& align_y) {
  // Represent the rect in the container's scroll-origin coordinate.
  PhysicalRect scroll_origin_to_expose_rect = local_expose_rect;
  scroll_origin_to_expose_rect.Move(scroll_area.LocalToScrollOriginOffset());
  // Prevent degenerate cases by giving the visible rect a minimum non-0 size.
  PhysicalRect non_zero_visible_rect = scroll_area.VisibleScrollSnapportRect();
  ScrollOffset current_scroll_offset = scroll_area.GetScrollOffset();
  LayoutUnit minimum_layout_unit;
  minimum_layout_unit.SetRawValue(1);
  if (non_zero_visible_rect.Width() <= LayoutUnit()) {
    non_zero_visible_rect.SetWidth(minimum_layout_unit);
  }
  if (non_zero_visible_rect.Height() <= LayoutUnit()) {
    non_zero_visible_rect.SetHeight(minimum_layout_unit);
  }

  // The scroll_origin_to_expose_rect includes the scroll-margin of the element
  // that is being exposed. We want to exclude the margin for deciding whether
  // it's already visible, but include it when calculating the scroll offset
  // that we need to scroll to in order to achieve the desired alignment.
  PhysicalRect expose_rect_no_margin = scroll_origin_to_expose_rect;
  expose_rect_no_margin.Contract(expose_scroll_margin);

  // Determine the appropriate X behavior.
  mojom::blink::ScrollAlignment::Behavior scroll_x;
  PhysicalRect expose_rect_x(
      expose_rect_no_margin.X(), non_zero_visible_rect.Y(),
      expose_rect_no_margin.Width(), non_zero_visible_rect.Height());
  LayoutUnit intersect_width =
      Intersection(non_zero_visible_rect, expose_rect_x).Width();
  if (intersect_width == expose_rect_no_margin.Width()) {
    // If the rectangle is fully visible, use the specified visible behavior.
    // If the rectangle is partially visible, but over a certain threshold,
    // then treat it as fully visible to avoid unnecessary horizontal scrolling
    scroll_x = align_x.rect_visible;
  } else if (intersect_width == non_zero_visible_rect.Width()) {
    // The rect is bigger than the visible area.
    scroll_x = align_x.rect_visible;
  } else if (intersect_width > 0) {
    // If the rectangle is partially visible, but not above the minimum
    // threshold, use the specified partial behavior
    scroll_x = align_x.rect_partial;
  } else {
    scroll_x = align_x.rect_hidden;
  }

  if (scroll_x == mojom::blink::ScrollAlignment::Behavior::kClosestEdge) {
    // Closest edge is the right in two cases:
    // (1) exposeRect to the right of and smaller than nonZeroVisibleRect
    // (2) exposeRect to the left of and larger than nonZeroVisibleRect
    if ((scroll_origin_to_expose_rect.Right() > non_zero_visible_rect.Right() &&
         scroll_origin_to_expose_rect.Width() <
             non_zero_visible_rect.Width()) ||
        (scroll_origin_to_expose_rect.Right() < non_zero_visible_rect.Right() &&
         scroll_origin_to_expose_rect.Width() >
             non_zero_visible_rect.Width())) {
      scroll_x = mojom::blink::ScrollAlignment::Behavior::kRight;
    }
  }

  // Determine the appropriate Y behavior.
  mojom::blink::ScrollAlignment::Behavior scroll_y;
  PhysicalRect expose_rect_y(
      non_zero_visible_rect.X(), expose_rect_no_margin.Y(),
      non_zero_visible_rect.Width(), expose_rect_no_margin.Height());
  LayoutUnit intersect_height =
      Intersection(non_zero_visible_rect, expose_rect_y).Height();
  if (intersect_height == expose_rect_no_margin.Height()) {
    // If the rectangle is fully visible, use the specified visible behavior.
    scroll_y = align_y.rect_visible;
  } else if (intersect_height == non_zero_visible_rect.Height()) {
    // The rect is bigger than the visible area.
    scroll_y = align_y.rect_visible;
  } else if (intersect_height > 0) {
    // If the rectangle is partially visible, use the specified partial behavior
    scroll_y = align_y.rect_partial;
  } else {
    scroll_y = align_y.rect_hidden;
  }

  if (scroll_y == mojom::blink::ScrollAlignment::Behavior::kClosestEdge) {
    // Closest edge is the bottom in two cases:
    // (1) exposeRect below and smaller than nonZeroVisibleRect
    // (2) exposeRect above and larger than nonZeroVisibleRect
    if ((scroll_origin_to_expose_rect.Bottom() >
             non_zero_visible_rect.Bottom() &&
         scroll_origin_to_expose_rect.Height() <
             non_zero_visible_rect.Height()) ||
        (scroll_origin_to_expose_rect.Bottom() <
             non_zero_visible_rect.Bottom() &&
         scroll_origin_to_expose_rect.Height() >
             non_zero_visible_rect.Height())) {
      scroll_y = mojom::blink::ScrollAlignment::Behavior::kBottom;
    }
  }

  // We would like calculate the ScrollPosition to move
  // |scroll_origin_to_expose_rect| inside the scroll_snapport, which is based
  // on the scroll_origin of the scroller.
  non_zero_visible_rect.Move(
      -PhysicalOffset::FromVector2dFRound(current_scroll_offset));

  // Given the X behavior, compute the X coordinate.
  float x;
  if (scroll_x == mojom::blink::ScrollAlignment::Behavior::kNoScroll) {
    x = current_scroll_offset.x();
  } else if (scroll_x == mojom::blink::ScrollAlignment::Behavior::kRight) {
    x = (scroll_origin_to_expose_rect.Right() - non_zero_visible_rect.Right())
            .ToFloat();
  } else if (scroll_x == mojom::blink::ScrollAlignment::Behavior::kCenter) {
    x = ((scroll_origin_to_expose_rect.X() +
          scroll_origin_to_expose_rect.Right() -
          (non_zero_visible_rect.X() + non_zero_visible_rect.Right())) /
         2)
            .ToFloat();
  } else {
    x = (scroll_origin_to_expose_rect.X() - non_zero_visible_rect.X())
            .ToFloat();
  }

  // Given the Y behavior, compute the Y coordinate.
  float y;
  if (scroll_y == mojom::blink::ScrollAlignment::Behavior::kNoScroll) {
    y = current_scroll_offset.y();
  } else if (scroll_y == mojom::blink::ScrollAlignment::Behavior::kBottom) {
    y = (scroll_origin_to_expose_rect.Bottom() - non_zero_visible_rect.Bottom())
            .ToFloat();
  } else if (scroll_y == mojom::blink::ScrollAlignment::Behavior::kCenter) {
    y = ((scroll_origin_to_expose_rect.Y() +
          scroll_origin_to_expose_rect.Bottom() -
          (non_zero_visible_rect.Y() + non_zero_visible_rect.Bottom())) /
         2)
            .ToFloat();
  } else {
    y = (scroll_origin_to_expose_rect.Y() - non_zero_visible_rect.Y())
            .ToFloat();
  }

  return ScrollOffset(x, y);
}

mojom::blink::ScrollAlignment PhysicalAlignmentFromSnapAlignStyle(
    const LayoutBox& box,
    ScrollOrientation axis) {
  cc::ScrollSnapAlign snap = box.Style()->GetScrollSnapAlign();
  return ResolveToPhysicalAlignment(
      SnapAlignmentToV8ScrollLogicalPosition(snap.alignment_inline),
      SnapAlignmentToV8ScrollLogicalPosition(snap.alignment_block), axis,
      *box.Style());
}

}  // namespace scroll_into_view_util

}  // namespace blink

"""

```
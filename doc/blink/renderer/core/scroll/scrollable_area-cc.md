Response:
My thought process for analyzing the provided C++ code snippet for `ScrollableArea` in Blink went something like this:

1. **Identify the Core Purpose:** The filename `scrollable_area.cc` and the class name `ScrollableArea` strongly suggest that this class is responsible for managing scrollable regions within the rendering engine. The copyright notices at the beginning reinforce this being fundamental code.

2. **Scan for Key Members and Methods:** I started quickly scanning the code for member variables, method names, and included headers. This helps establish the class's responsibilities and dependencies. I looked for patterns related to scrolling, animation, user interaction, styling, and internal state management.

3. **Group Functionality by Category:** As I scanned, I mentally grouped related methods and members. For instance:
    * **Scrolling:** Methods like `SetScrollOffset`, `ScrollBy`, `UserScroll`, `ResolveScrollDelta`, `ClampScrollOffset`, `MinimumScrollOffset`, `MaximumScrollOffset`.
    * **Scrollbars:** Methods like `HorizontalScrollbar`, `VerticalScrollbar`, `DidAddScrollbar`, `WillRemoveScrollbar`, and members related to overlay scrollbars.
    * **Animation:** Members like `scroll_animator_`, `programmatic_scroll_animator_`, `MacScrollbarAnimator`, and methods related to animation (`CancelScrollAnimation`, `AnimateToOffset`).
    * **User Input:** `UserScroll`, `MouseEnteredScrollbar`, `MouseExitedScrollbar`, `MouseCapturedScrollbar`, `MouseReleasedScrollbar`.
    * **Styling:** Methods like `DetermineScrollBehavior`, `ScrollBehaviorStyle`, and members related to overlay scrollbar theming (`overlay_scrollbar_color_scheme__`).
    * **Layout Integration:**  Inclusion of headers like `layout_box.h`, `layout_view.h`.
    * **Event Handling:** Inclusion of `event_handler.h`.
    * **Scroll Snapping:**  References to `cc::ScrollSnapData`, `cc::SnapSelectionStrategy`.
    * **Scroll into View:**  Methods related to `ScrollIntoView`.
    * **Scroll Start:** Methods and logic related to `scroll-start` and `scroll-start-target` CSS properties.

4. **Analyze Individual Method Groups:** Once I had a general idea, I delved deeper into the purpose of each grouped category:
    * **Scrolling:** I noted the distinction between programmatic and user-initiated scrolling, the handling of different scroll granularities (pixel, line, page), and the clamping of scroll offsets. The interaction with the compositor thread (through `compositor_task_runner_`) is also important.
    * **Scrollbars:** The code manages both standard and overlay scrollbars, including their visibility, interaction, and theming. The platform-specific `MacScrollbarAnimator` is noteworthy.
    * **Animation:**  I saw separate animators for programmatic scrolls and user-initiated smooth scrolls, suggesting different handling mechanisms.
    * **User Input:**  The methods here clearly manage how user interactions (mouse movements, clicks) affect scrolling and scrollbar behavior.
    * **Styling:**  The code takes into account CSS properties like `scroll-behavior` and handles overlay scrollbar theming.
    * **Layout Integration:**  The class interacts closely with the layout engine to determine scroll extents and manage the visual representation of scrollable areas.
    * **Event Handling:**  It plays a role in processing scroll-related events.
    * **Scroll Snapping:**  The presence of scroll snap related code indicates that the class supports snapping behavior.
    * **Scroll into View:** While the `ScrollIntoView` method itself might be unimplemented, its presence indicates that this class is involved in the logic for scrolling elements into view.
    * **Scroll Start:**  The handling of `scroll-start` and `scroll-start-target` CSS properties highlights the class's role in initializing the scroll position.

5. **Consider Relationships with Web Technologies:** I then explicitly considered how this C++ code relates to JavaScript, HTML, and CSS:
    * **JavaScript:**  JavaScript can trigger programmatic scrolling via methods like `scrollTo()` or by manipulating the `scrollLeft` and `scrollTop` properties. This C++ code is the underlying implementation that executes those actions.
    * **HTML:** HTML elements with `overflow: auto`, `overflow: scroll`, or `overflow: hidden` (in some cases) create scrollable areas managed by this C++ class.
    * **CSS:** CSS properties like `scroll-behavior`, `scroll-snap-type`, `scroll-snap-align`, `scrollbar-color`, `scrollbar-width`, `scroll-start`, and `scroll-start-target` directly influence the behavior and appearance of the scrollable areas managed by this class.

6. **Infer Logic and Provide Examples:** Based on the method names and their purpose, I inferred the underlying logic. For example, `ClampScrollOffset` likely ensures that the requested scroll offset stays within the valid bounds. I then created simple HTML/CSS examples to illustrate these relationships.

7. **Identify Potential User/Programming Errors:** I thought about common mistakes developers or users might make that would involve this code:
    * Incorrectly setting `overflow` properties.
    * Expecting smooth scrolling without setting `scroll-behavior: smooth`.
    * Issues with scroll snapping configuration.
    * Misunderstanding how `scroll-start` and `scroll-start-target` work.

8. **Trace User Operations:**  I outlined the steps a user might take to trigger the code in `scrollable_area.cc`, starting from a high-level interaction (like scrolling with the mouse wheel) and breaking it down to how it might eventually reach this C++ code.

9. **Summarize Functionality (for Part 1):** Finally, I condensed the key findings into a concise summary of the class's main responsibilities.

Throughout this process, I relied on my knowledge of web browser architecture, the Blink rendering engine, and web technologies like HTML, CSS, and JavaScript. The code itself provides many clues through its naming conventions and the included headers. When uncertain about a specific detail, I'd make an educated guess based on the context and then look for supporting evidence in the surrounding code.
这是 `blink/renderer/core/scroll/scrollable_area.cc` 文件的第一部分，它定义了 `ScrollableArea` 类。根据提供的代码，我们可以归纳出它的主要功能如下：

**`ScrollableArea` 类的核心功能：**

1. **管理可滚动区域:** `ScrollableArea` 是 Blink 渲染引擎中负责管理内容可滚动区域的核心类。它处理与滚动相关的各种操作，包括设置滚动偏移、执行平滑滚动、处理用户滚动输入、以及与滚动条的交互。

2. **处理用户和程序触发的滚动:** 该类区分用户发起的滚动（例如，鼠标滚轮、拖拽滚动条）和程序触发的滚动（例如，JavaScript 的 `scrollTo()` 方法）。

3. **实现平滑滚动:**  通过 `ScrollAnimatorBase` 和 `ProgrammaticScrollAnimator`，`ScrollableArea` 实现了平滑滚动效果，可以响应 CSS 的 `scroll-behavior` 属性。

4. **管理滚动条:** 该类负责创建、管理和更新与可滚动区域关联的水平和垂直滚动条。它处理滚动条的显示、隐藏和交互。

5. **支持覆盖滚动条 (Overlay Scrollbars):** 代码中包含了对覆盖滚动条的支持，包括控制其显示和淡入淡出效果。

6. **处理 `scroll-start` 和 `scroll-start-target` CSS 属性:** 该类实现了对 CSS 新增的 `scroll-start` 和 `scroll-start-target` 属性的支持，允许在页面加载时设置初始滚动位置。

7. **集成滚动吸附 (Scroll Snapping):** 代码中引用了 `cc::ScrollSnapData` 等，表明 `ScrollableArea` 也参与处理滚动吸附的逻辑。

8. **提供滚动完成回调机制:**  允许注册滚动完成时的回调函数，以便在滚动动画结束或其他滚动操作完成后执行特定的代码。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * 当 JavaScript 调用 `element.scrollTo(x, y)` 或修改 `element.scrollLeft` 和 `element.scrollTop` 属性时，最终会调用到 `ScrollableArea::SetScrollOffset` 方法来更新滚动位置。
    * **假设输入:** JavaScript 代码 `element.scrollTo({ top: 100, left: 50, behavior: 'smooth' });`
    * **输出:**  `ScrollableArea::SetScrollOffset` 会接收到目标偏移量 (50, 100)，滚动类型 `kProgrammatic`，滚动行为 `kSmooth`。

* **HTML:**
    * HTML 元素如果设置了 `overflow: auto` 或 `overflow: scroll` 样式，并且内容超出容器大小时，会创建一个 `ScrollableArea` 实例来管理该元素的滚动行为。
    * 当用户点击 HTML 中的锚点链接 (`<a href="#target">`) 时，浏览器会尝试滚动到目标元素，这会触发 `ScrollableArea` 的相关方法。

* **CSS:**
    * CSS 的 `overflow` 属性（如 `auto`, `scroll`, `hidden`）决定了是否以及如何显示滚动条，并激活 `ScrollableArea` 的功能。
    * CSS 的 `scroll-behavior: smooth` 属性会影响 `ScrollableArea::SetScrollOffset` 的行为，使其执行平滑滚动动画。
    * **假设输入:**  CSS 样式 `body { scroll-behavior: smooth; }`
    * **输出:** 当 JavaScript 调用 `window.scrollTo()` 或用户点击页面内的锚点链接时，`ScrollableArea` 会根据 `kSmooth` 的滚动行为执行平滑动画。
    * CSS 的 `scroll-start` 和 `scroll-start-target` 属性会被解析并用于初始化 `ScrollableArea` 的滚动位置。

**逻辑推理的假设输入与输出：**

* **假设输入:** 用户通过鼠标滚轮向下滚动一个内容溢出的 `div` 元素。
* **输出:**
    1. 浏览器捕获鼠标滚轮事件。
    2. 事件被传递到 Blink 渲染引擎。
    3. `ScrollableArea::UserScroll` 方法被调用，接收到滚动的方向和步长。
    4. `ScrollableArea` 计算新的滚动偏移量。
    5. `ScrollableArea::ScrollOffsetChanged` 方法被调用，更新内部的滚动状态并通知相关的滚动条进行更新。
    6. 浏览器重绘受影响的区域。

**用户或编程常见的使用错误举例说明：**

* **错误使用 `overflow: hidden`:**  如果开发者设置了 `overflow: hidden`，内容溢出时不会显示滚动条，用户也无法滚动查看隐藏的内容。这可能导致用户体验问题。
* **过度依赖 JavaScript 滚动:**  过度使用 JavaScript 来实现滚动效果，而没有考虑到浏览器的默认行为和性能优化，可能会导致页面卡顿或不流畅。
* **没有正确处理滚动完成事件:**  如果需要在一个滚动动画完成后执行某些操作，开发者可能忘记注册滚动完成的回调函数，导致逻辑错误。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户操作:** 用户在浏览器中打开一个包含可滚动元素的网页。
2. **渲染引擎初始化:** Blink 渲染引擎解析 HTML 和 CSS，为可滚动的元素创建 `ScrollableArea` 对象。
3. **用户触发滚动:**
    * **鼠标滚轮滚动:** 用户滚动鼠标滚轮。浏览器将滚轮事件传递给渲染引擎。
    * **拖拽滚动条:** 用户点击并拖拽滚动条的滑块。浏览器将鼠标事件传递给渲染引擎。
    * **键盘操作:** 用户使用键盘上的方向键或 Page Up/Down 键进行滚动。浏览器将键盘事件传递给渲染引擎。
    * **触摸操作:** 用户在触摸屏上滑动。浏览器将触摸事件传递给渲染引擎。
    * **点击锚点链接:** 用户点击一个指向页面内特定位置的锚点链接。
4. **事件处理:**  渲染引擎的事件处理机制（例如 `EventHandler`）接收到这些事件。
5. **调用 `ScrollableArea` 方法:**  根据事件类型和目标元素，事件处理机制会调用 `ScrollableArea` 相应的处理方法，例如：
    * 鼠标滚轮滚动、键盘操作、触摸操作通常会触发 `ScrollableArea::UserScroll`。
    * JavaScript 调用 `scrollTo()` 会触发 `ScrollableArea::SetScrollOffset`。
    * 点击锚点链接可能会触发 `ScrollableArea::SetScrollOffset` 或与 `ScrollIntoView` 相关的逻辑。
6. **执行滚动逻辑:**  `ScrollableArea` 内部的方法会计算新的滚动位置，更新滚动条状态，并触发页面的重绘。

**归纳一下它的功能 (针对第 1 部分):**

`blink/renderer/core/scroll/scrollable_area.cc` 文件的第一部分主要定义了 `ScrollableArea` 类的基础结构和核心功能，涵盖了：

* **基本的滚动管理:**  设置和获取滚动偏移，处理不同类型的滚动输入。
* **平滑滚动的基础:**  初始化和使用滚动动画器。
* **滚动条的管理:**  与滚动条对象的交互和状态更新。
* **覆盖滚动条的支持:**  控制覆盖滚动条的显示和隐藏。
* **`scroll-start` 和 `scroll-start-target` 的初步实现:**  读取和应用这些 CSS 属性的值。
* **滚动完成回调机制:**  提供注册和执行滚动完成回调的功能。

总而言之，这部分代码奠定了 `ScrollableArea` 类的基础，使其能够处理各种滚动操作，并与浏览器的其他组件（如事件处理、布局、渲染）进行交互。

### 提示词
```
这是目录为blink/renderer/core/scroll/scrollable_area.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2010, Google Inc. All rights reserved.
 * Copyright (C) 2008, 2011 Apple Inc. All Rights Reserved.
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

#include "third_party/blink/renderer/core/scroll/scrollable_area.h"

#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "cc/input/main_thread_scrolling_reason.h"
#include "cc/input/scroll_snap_data.h"
#include "cc/input/scroll_utils.h"
#include "cc/input/scrollbar.h"
#include "cc/input/snap_selection_strategy.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink-forward.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/scroll/mac_scrollbar_animator.h"
#include "third_party/blink/renderer/core/scroll/programmatic_scroll_animator.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/scroll/smooth_scroll_sequencer.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/graphics/compositing/paint_artifact_compositor.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

namespace blink {

int ScrollableArea::PixelsPerLineStep(LocalFrame* frame) {
  if (!frame)
    return cc::kPixelsPerLineStep;
  return frame->GetPage()->GetChromeClient().WindowToViewportScalar(
      frame, cc::kPixelsPerLineStep);
}

float ScrollableArea::MinFractionToStepWhenPaging() {
  return cc::kMinFractionToStepWhenPaging;
}

int ScrollableArea::MaxOverlapBetweenPages() const {
  return GetPageScrollbarTheme().MaxOverlapBetweenPages();
}

// static
float ScrollableArea::DirectionBasedScrollDelta(
    ui::ScrollGranularity granularity) {
  return (granularity == ui::ScrollGranularity::kScrollByPercentage)
             ? cc::kPercentDeltaForDirectionalScroll
             : 1;
}

// static
mojom::blink::ScrollBehavior ScrollableArea::DetermineScrollBehavior(
    mojom::blink::ScrollBehavior behavior_from_param,
    mojom::blink::ScrollBehavior behavior_from_style) {
  if (behavior_from_param == mojom::blink::ScrollBehavior::kSmooth)
    return mojom::blink::ScrollBehavior::kSmooth;

  if (behavior_from_param == mojom::blink::ScrollBehavior::kAuto &&
      behavior_from_style == mojom::blink::ScrollBehavior::kSmooth) {
    return mojom::blink::ScrollBehavior::kSmooth;
  }

  return mojom::blink::ScrollBehavior::kInstant;
}

ScrollableArea::ScrollableArea(
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner)
    : overlay_scrollbar_color_scheme__(
          static_cast<unsigned>(mojom::blink::ColorScheme::kLight)),
      horizontal_scrollbar_needs_paint_invalidation_(false),
      vertical_scrollbar_needs_paint_invalidation_(false),
      scroll_corner_needs_paint_invalidation_(false),
      scrollbars_hidden_if_overlay_(true),
      scrollbar_captured_(false),
      mouse_over_scrollbar_(false),
      has_been_disposed_(false),
      compositor_task_runner_(std::move(compositor_task_runner)) {
  DCHECK(compositor_task_runner_);
}

ScrollableArea::~ScrollableArea() = default;

void ScrollableArea::Dispose() {
  if (HasBeenDisposed())
    return;
  DisposeImpl();
  fade_overlay_scrollbars_timer_ = nullptr;
  has_been_disposed_ = true;
}

void ScrollableArea::ClearScrollableArea() {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->Dispose();
  if (scroll_animator_) {
    scroll_animator_->DetachElement();
    scroll_animator_.Clear();
  }
  if (programmatic_scroll_animator_) {
    programmatic_scroll_animator_->DetachElement();
    programmatic_scroll_animator_.Clear();
  }
  if (fade_overlay_scrollbars_timer_)
    fade_overlay_scrollbars_timer_->Value().Stop();
}

MacScrollbarAnimator* ScrollableArea::GetMacScrollbarAnimator() const {
#if BUILDFLAG(IS_MAC)
  if (!mac_scrollbar_animator_) {
    mac_scrollbar_animator_ =
        MacScrollbarAnimator::Create(const_cast<ScrollableArea*>(this));
  }
#endif
  return mac_scrollbar_animator_.Get();
}

ScrollAnimatorBase& ScrollableArea::GetScrollAnimator() const {
  if (!scroll_animator_)
    scroll_animator_ =
        ScrollAnimatorBase::Create(const_cast<ScrollableArea*>(this));

  return *scroll_animator_;
}

ProgrammaticScrollAnimator& ScrollableArea::GetProgrammaticScrollAnimator()
    const {
  if (!programmatic_scroll_animator_) {
    programmatic_scroll_animator_ =
        MakeGarbageCollected<ProgrammaticScrollAnimator>(
            const_cast<ScrollableArea*>(this));
  }

  return *programmatic_scroll_animator_;
}

ScrollbarOrientation ScrollableArea::ScrollbarOrientationFromDirection(
    ScrollDirectionPhysical direction) const {
  return (direction == kScrollUp || direction == kScrollDown)
             ? kVerticalScrollbar
             : kHorizontalScrollbar;
}

float ScrollableArea::ScrollStep(ui::ScrollGranularity granularity,
                                 ScrollbarOrientation orientation) const {
  switch (granularity) {
    case ui::ScrollGranularity::kScrollByLine:
      return LineStep(orientation);
    case ui::ScrollGranularity::kScrollByPage:
      return PageStep(orientation);
    case ui::ScrollGranularity::kScrollByDocument:
      return DocumentStep(orientation);
    case ui::ScrollGranularity::kScrollByPixel:
    case ui::ScrollGranularity::kScrollByPrecisePixel:
      return PixelStep(orientation);
    case ui::ScrollGranularity::kScrollByPercentage:
      return PercentageStep(orientation);
    default:
      NOTREACHED();
  }
}

ScrollOffset ScrollableArea::ResolveScrollDelta(
    ui::ScrollGranularity granularity,
    const ScrollOffset& delta) {
  gfx::SizeF step(ScrollStep(granularity, kHorizontalScrollbar),
                  ScrollStep(granularity, kVerticalScrollbar));

  if (granularity == ui::ScrollGranularity::kScrollByPercentage) {
    LocalFrame* local_frame = GetLayoutBox()->GetFrame();
    DCHECK(local_frame);
    gfx::SizeF viewport(local_frame->GetPage()->GetVisualViewport().Size());

    // Convert to screen coordinates (physical pixels).
    float page_scale_factor = local_frame->GetPage()->PageScaleFactor();
    step.Scale(page_scale_factor);

    gfx::Vector2dF pixel_delta =
        cc::ScrollUtils::ResolveScrollPercentageToPixels(delta, step, viewport);

    // Rescale back to rootframe coordinates.
    pixel_delta.Scale(1 / page_scale_factor);

    return pixel_delta;
  }

  return gfx::ScaleVector2d(delta, step.width(), step.height());
}

ScrollResult ScrollableArea::UserScroll(ui::ScrollGranularity granularity,
                                        const ScrollOffset& delta,
                                        ScrollCallback on_finish) {
  TRACE_EVENT2("input", "ScrollableArea::UserScroll", "x", delta.x(), "y",
               delta.y());

  // This callback runs ScrollableArea::RunScrollCompleteCallbacks which
  // will run all the callbacks in the Vector pending_scroll_complete_callbacks_
  // and ScrollAnimator::UserScroll may run this callback for a previous scroll
  // animation. Delay queuing up this |on_finish| so that it is run when the
  // callback for this scroll animation is run and not when the callback
  // for a previous scroll animation is run.
  ScrollCallback run_scroll_complete_callbacks(BindOnce(
      [](WeakPersistent<ScrollableArea> area, ScrollCallback callback,
         ScrollCompletionMode mode) {
        if (area) {
          if (callback) {
            area->RegisterScrollCompleteCallback(std::move(callback));
          }
          area->RunScrollCompleteCallbacks(mode);
        }
      },
      WrapWeakPersistent(this), std::move(on_finish)));

  ScrollOffset pixel_delta = ResolveScrollDelta(granularity, delta);

  ScrollOffset scrollable_axis_delta(
      UserInputScrollable(kHorizontalScrollbar) ? pixel_delta.x() : 0,
      UserInputScrollable(kVerticalScrollbar) ? pixel_delta.y() : 0);
  ScrollOffset delta_to_consume =
      GetScrollAnimator().ComputeDeltaToConsume(scrollable_axis_delta);

  if (delta_to_consume.IsZero()) {
    std::move(run_scroll_complete_callbacks)
        .Run(ScrollCompletionMode::kZeroDelta);
    return ScrollResult(false, false, pixel_delta.x(), pixel_delta.y());
  }

  CancelProgrammaticScrollAnimation();
  if (SmoothScrollSequencer* sequencer = GetSmoothScrollSequencer())
    sequencer->AbortAnimations();

  ScrollResult result =
      GetScrollAnimator().UserScroll(granularity, scrollable_axis_delta,
                                     std::move(run_scroll_complete_callbacks));
  if (result.DidScroll()) {
    UpdateScrollMarkers();
  }

  // Delta that wasn't scrolled because the axis is !userInputScrollable
  // should count as unusedScrollDelta.
  ScrollOffset unscrollable_axis_delta = pixel_delta - scrollable_axis_delta;
  result.unused_scroll_delta_x += unscrollable_axis_delta.x();
  result.unused_scroll_delta_y += unscrollable_axis_delta.y();

  return result;
}

ScrollOffset ScrollableArea::PendingScrollAnchorAdjustment() const {
  return pending_scroll_anchor_adjustment_;
}

void ScrollableArea::ClearPendingScrollAnchorAdjustment() {
  pending_scroll_anchor_adjustment_ = ScrollOffset();
}

bool ScrollableArea::SetScrollOffset(const ScrollOffset& offset,
                                     mojom::blink::ScrollType scroll_type,
                                     mojom::blink::ScrollBehavior behavior,
                                     ScrollCallback on_finish) {
  if (on_finish)
    RegisterScrollCompleteCallback(std::move(on_finish));

  ScrollableArea::ScrollCallback run_scroll_complete_callbacks(WTF::BindOnce(
      [](WeakPersistent<ScrollableArea> area, ScrollCompletionMode mode) {
        if (area) {
          area->RunScrollCompleteCallbacks(mode);
        }
      },
      WrapWeakPersistent(this)));
  bool filter_scroll = false;
  if (SmoothScrollSequencer* sequencer = GetSmoothScrollSequencer()) {
    DCHECK(!RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled());
    filter_scroll = sequencer->FilterNewScrollOrAbortCurrent(scroll_type);
  } else if (active_smooth_scroll_type_.has_value()) {
    DCHECK(RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled());
    filter_scroll = ShouldFilterIncomingScroll(scroll_type);
  }

  if (filter_scroll) {
    std::move(run_scroll_complete_callbacks)
        .Run(ScrollCompletionMode::kFinished);
    return false;
  }

  ScrollOffset previous_offset = GetScrollOffset();

  ScrollOffset clamped_offset = ClampScrollOffset(offset);
  if (ScrollOffsetIsNoop(clamped_offset) &&
      scroll_type != mojom::blink::ScrollType::kProgrammatic) {
    std::move(run_scroll_complete_callbacks)
        .Run(ScrollCompletionMode::kZeroDelta);
    return false;
  }

  TRACE_EVENT("blink", "ScrollableArea::SetScrollOffset", "offset",
              offset.ToString());
  TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                       "SetScrollOffset", TRACE_EVENT_SCOPE_THREAD,
                       "current_offset", GetScrollOffset().ToString());
  TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                       "SetScrollOffset", TRACE_EVENT_SCOPE_THREAD, "type",
                       scroll_type);
  TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("blink.debug"),
                       "SetScrollOffset", TRACE_EVENT_SCOPE_THREAD, "behavior",
                       behavior);

  if (behavior == mojom::blink::ScrollBehavior::kAuto)
    behavior = ScrollBehaviorStyle();

  gfx::Vector2d animation_adjustment = gfx::ToRoundedVector2d(clamped_offset) -
                                       gfx::ToRoundedVector2d(previous_offset);

  // After a scroller has been explicitly scrolled, we should no longer apply
  // scroll-start or scroll-start-target.
  if (IsExplicitScrollType(scroll_type)) {
    StopApplyingScrollStart();
  }

  switch (scroll_type) {
    case mojom::blink::ScrollType::kCompositor:
      ScrollOffsetChanged(clamped_offset, scroll_type);
      break;
    case mojom::blink::ScrollType::kClamping:
      ScrollOffsetChanged(clamped_offset, scroll_type);
      GetScrollAnimator().AdjustAnimation(animation_adjustment);
      break;
    case mojom::blink::ScrollType::kAnchoring:
      ScrollOffsetChanged(clamped_offset, scroll_type);
      GetScrollAnimator().AdjustAnimation(animation_adjustment);
      pending_scroll_anchor_adjustment_ += clamped_offset - previous_offset;
      break;
    case mojom::blink::ScrollType::kScrollStart:
      ScrollOffsetChanged(clamped_offset, scroll_type);
      GetScrollAnimator().AdjustAnimation(animation_adjustment);
      break;
    case mojom::blink::ScrollType::kProgrammatic:
      if (ProgrammaticScrollHelper(clamped_offset, behavior,
                                   /* is_sequenced_scroll */ false,
                                   animation_adjustment,
                                   std::move(run_scroll_complete_callbacks))) {
        if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled() &&
            behavior == mojom::blink::ScrollBehavior::kSmooth) {
          active_smooth_scroll_type_ = scroll_type;
        }
        return true;
      }
      return false;
    case mojom::blink::ScrollType::kSequenced:
      return ProgrammaticScrollHelper(clamped_offset, behavior,
                                      /* is_sequenced_scroll */ true,
                                      animation_adjustment,
                                      std::move(run_scroll_complete_callbacks));
    case mojom::blink::ScrollType::kUser:
      if (RuntimeEnabledFeatures::MultiSmoothScrollIntoViewEnabled() &&
          behavior == mojom::blink::ScrollBehavior::kSmooth) {
        if (ProgrammaticScrollHelper(
                clamped_offset, behavior,
                /* is_sequenced_scroll */ false, animation_adjustment,
                std::move(run_scroll_complete_callbacks))) {
          active_smooth_scroll_type_ = scroll_type;
          return true;
        }
        return false;
      } else {
        UserScrollHelper(clamped_offset, behavior);
        break;
      }
    default:
      NOTREACHED();
  }

  UpdateScrollMarkers();

  std::move(run_scroll_complete_callbacks).Run(ScrollCompletionMode::kFinished);
  return true;
}

bool ScrollableArea::SetScrollOffset(const ScrollOffset& offset,
                                     mojom::blink::ScrollType type,
                                     mojom::blink::ScrollBehavior behavior) {
  return SetScrollOffset(offset, type, behavior, ScrollCallback());
}

float ScrollableArea::ScrollStartValueToOffsetAlongAxis(
    const ScrollStartData& data,
    cc::SnapAxis axis) const {
  using Type = blink::ScrollStartValueType;
  using Axis = cc::SnapAxis;
  DCHECK(axis == Axis::kX || axis == Axis::kY);
  const float axis_scroll_extent = axis == Axis::kX
                                       ? ScrollSize(kHorizontalScrollbar)
                                       : ScrollSize(kVerticalScrollbar);
  switch (data.value_type) {
    case Type::kAuto:
    case Type::kStart:
    case Type::kTop:
    case Type::kLeft:
      return axis == Axis::kX ? MinimumScrollOffset().x()
                              : MinimumScrollOffset().y();
    case Type::kCenter:
      return axis == Axis::kX
                 ? MinimumScrollOffset().x() + 0.5 * axis_scroll_extent
                 : MinimumScrollOffset().y() + 0.5 * axis_scroll_extent;
    case Type::kEnd:
      return axis == Axis::kX ? MaximumScrollOffset().x()
                              : MaximumScrollOffset().y();
    case Type::kBottom:
      return axis == Axis::kY ? MaximumScrollOffset().y()
                              : MinimumScrollOffset().x();
    case Type::kRight:
      return axis == Axis::kX ? MaximumScrollOffset().x()
                              : MinimumScrollOffset().y();
    case Type::kLengthOrPercentage: {
      float offset = FloatValueForLength(data.value, axis_scroll_extent);
      return axis == Axis::kY ? MinimumScrollOffset().y() + offset
                              : MinimumScrollOffset().x() + offset;
    }
    default:
      return axis == Axis::kX ? MinimumScrollOffset().x()
                              : MinimumScrollOffset().y();
  }
}

ScrollOffset ScrollableArea::ScrollOffsetFromScrollStartData(
    const ScrollStartData& y_value,
    const ScrollStartData& x_value) const {
  ScrollOffset offset;

  offset.set_x(ScrollStartValueToOffsetAlongAxis(x_value, cc::SnapAxis::kX));
  offset.set_y(ScrollStartValueToOffsetAlongAxis(y_value, cc::SnapAxis::kY));

  return ClampScrollOffset(offset);
}

bool ScrollableArea::ScrollStartIsDefault() const {
  if (!GetLayoutBox()) {
    return true;
  }
  return GetLayoutBox()->Style()->ScrollStartX() == ScrollStartData() &&
         GetLayoutBox()->Style()->ScrollStartY() == ScrollStartData();
}

const LayoutObject* ScrollableArea::GetScrollStartTarget() const {
  for (const auto& fragment : GetLayoutBox()->PhysicalFragments()) {
    if (auto scroll_start_target = fragment.ScrollStartTarget()) {
      return scroll_start_target;
    }
  }
  return nullptr;
}

void ScrollableArea::ScrollToScrollStartTarget(
    const LayoutObject* scroll_start_target) {
  using Behavior = mojom::ScrollAlignment_Behavior;
  mojom::blink::ScrollAlignment align_x(
      Behavior::kNoScroll, Behavior::kNoScroll, Behavior::kNoScroll);
  mojom::blink::ScrollAlignment align_y(
      Behavior::kNoScroll, Behavior::kNoScroll, Behavior::kNoScroll);
  const LayoutBox* target_box = scroll_start_target->EnclosingBox();
  if (!target_box) {
    return;
  }
  cc::ScrollSnapAlign snap_alignment =
      scroll_start_target->Style()->GetScrollSnapAlign();
  switch (snap_alignment.alignment_block) {
    case cc::SnapAlignment::kStart:
      align_y = ScrollAlignment::TopAlways();
      break;
    case cc::SnapAlignment::kCenter:
      align_y = ScrollAlignment::CenterAlways();
      break;
    case cc::SnapAlignment::kEnd:
      align_y = ScrollAlignment::BottomAlways();
      break;
    default:
      align_y = GetLayoutBox()->HasTopOverflow()
                    ? ScrollAlignment::BottomAlways()
                    : ScrollAlignment::TopAlways();
  }
  switch (snap_alignment.alignment_inline) {
    case cc::SnapAlignment::kStart:
      align_x = ScrollAlignment::LeftAlways();
      break;
    case cc::SnapAlignment::kCenter:
      align_x = ScrollAlignment::CenterAlways();
      break;
    case cc::SnapAlignment::kEnd:
      align_x = ScrollAlignment::RightAlways();
      break;
    default:
      align_x = GetLayoutBox()->HasLeftOverflow()
                    ? ScrollAlignment::RightAlways()
                    : ScrollAlignment::LeftAlways();
  }
  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(align_x, align_y);
  params->behavior = mojom::blink::ScrollBehavior::kInstant;
  params->type = mojom::blink::ScrollType::kScrollStart;
  ScrollIntoView(target_box->AbsoluteBoundingBoxRectForScrollIntoView(),
                 PhysicalBoxStrut(), params);
}

void ScrollableArea::ApplyScrollStart() {
  if (RuntimeEnabledFeatures::CSSScrollStartTargetEnabled()) {
    if (const LayoutObject* scroll_start_target = GetScrollStartTarget()) {
      if (auto* box = GetLayoutBox()) {
        UseCounter::Count(box->GetDocument(),
                          WebFeature::kCSSScrollStartTarget);
      }
      ScrollToScrollStartTarget(scroll_start_target);
      // scroll-start-target takes precedence over scroll-start, so we should
      // return here.
      return;
    }
  }

  if (RuntimeEnabledFeatures::CSSScrollStartEnabled()) {
    const auto& y_data = GetLayoutBox()->Style()->ScrollStartY();
    const auto& x_data = GetLayoutBox()->Style()->ScrollStartX();
    ScrollOffset scroll_start_offset =
        ScrollOffsetFromScrollStartData(y_data, x_data);
    SetScrollOffset(scroll_start_offset, mojom::blink::ScrollType::kScrollStart,
                    mojom::blink::ScrollBehavior::kInstant);
  }
}

void ScrollableArea::ScrollBy(const ScrollOffset& delta,
                              mojom::blink::ScrollType type,
                              mojom::blink::ScrollBehavior behavior) {
  SetScrollOffset(GetScrollOffset() + delta, type, behavior);
}

bool ScrollableArea::ProgrammaticScrollHelper(
    const ScrollOffset& offset,
    mojom::blink::ScrollBehavior scroll_behavior,
    bool is_sequenced_scroll,
    gfx::Vector2d animation_adjustment,
    ScrollCallback on_finish) {
  bool should_use_animation =
      scroll_behavior == mojom::blink::ScrollBehavior::kSmooth &&
      ScrollAnimatorEnabled();
  if (should_use_animation) {
    // If the programmatic scroll will be animated, cancel any user scroll
    // animation already in progress. We don't want two scroll animations
    // running at the same time.
    CancelScrollAnimation();
  }

  if (ScrollOffsetIsNoop(offset)) {
    CancelProgrammaticScrollAnimation();
    if (on_finish)
      std::move(on_finish).Run(ScrollCompletionMode::kZeroDelta);
    return false;
  }

  ScrollCallback callback = std::move(on_finish);
  callback = ScrollCallback(WTF::BindOnce(
      [](ScrollCallback original_callback, WeakPersistent<ScrollableArea> area,
         ScrollCompletionMode mode) {
        if (area) {
          area->OnScrollFinished(/*enqueue_scrollend=*/mode ==
                                 ScrollCompletionMode::kFinished);
        }
        if (original_callback)
          std::move(original_callback).Run(mode);
      },
      std::move(callback), WrapWeakPersistent(this)));

  // Enqueue scrollsnapchanging if necessary.
  if (auto* snap_container = GetSnapContainerData()) {
    UpdateScrollSnapChangingTargetsAndEnqueueScrollSnapChanging(
        snap_container->GetTargetSnapAreaElementIds());
  }

  if (should_use_animation) {
    GetProgrammaticScrollAnimator().AnimateToOffset(offset, is_sequenced_scroll,
                                                    std::move(callback));
  } else {
    GetProgrammaticScrollAnimator().ScrollToOffsetWithoutAnimation(
        offset, is_sequenced_scroll);

    // If the programmatic scroll was NOT animated, we should adjust (but not
    // cancel) a user scroll animation already in progress (crbug.com/1264266).
    GetScrollAnimator().AdjustAnimation(animation_adjustment);

    if (callback)
      std::move(callback).Run(ScrollCompletionMode::kFinished);
  }
  UpdateScrollMarkers();
  return true;
}

void ScrollableArea::UserScrollHelper(
    const ScrollOffset& offset,
    mojom::blink::ScrollBehavior scroll_behavior) {
  CancelProgrammaticScrollAnimation();
  if (SmoothScrollSequencer* sequencer = GetSmoothScrollSequencer())
    sequencer->AbortAnimations();

  float x = UserInputScrollable(kHorizontalScrollbar)
                ? offset.x()
                : GetScrollAnimator().CurrentOffset().x();
  float y = UserInputScrollable(kVerticalScrollbar)
                ? offset.y()
                : GetScrollAnimator().CurrentOffset().y();

  // Smooth user scrolls (keyboard, wheel clicks) are handled via the userScroll
  // method.
  // TODO(bokan): The userScroll method should probably be modified to call this
  //              method and ScrollAnimatorBase to have a simpler
  //              animateToOffset method like the ProgrammaticScrollAnimator.
  DCHECK_EQ(scroll_behavior, mojom::blink::ScrollBehavior::kInstant);
  GetScrollAnimator().ScrollToOffsetWithoutAnimation(ScrollOffset(x, y));
}

PhysicalRect ScrollableArea::ScrollIntoView(
    const PhysicalRect& rect_in_absolute,
    const PhysicalBoxStrut& scroll_margin,
    const mojom::blink::ScrollIntoViewParamsPtr& params) {
  // TODO(bokan): This should really be implemented here but ScrollAlignment is
  // in Core which is a dependency violation.
  NOTREACHED();
}

void ScrollableArea::ScrollOffsetChanged(const ScrollOffset& offset,
                                         mojom::blink::ScrollType scroll_type) {
  TRACE_EVENT2("input", "ScrollableArea::scrollOffsetChanged", "x", offset.x(),
               "y", offset.y());
  TRACE_EVENT_INSTANT1("input", "Type", TRACE_EVENT_SCOPE_THREAD, "type",
                       scroll_type);

  ScrollOffset old_offset = GetScrollOffset();
  ScrollOffset truncated_offset =
      ShouldUseIntegerScrollOffset()
          ? ScrollOffset(gfx::ToFlooredVector2d(offset))
          : offset;

  // Tell the derived class to scroll its contents.
  UpdateScrollOffset(truncated_offset, scroll_type);

  // If the layout object has been detached as a result of updating the scroll
  // this object will be cleaned up shortly.
  if (HasBeenDisposed())
    return;

  // Tell the scrollbars to update their thumb postions.
  // If the scrollbar does not have its own layer, it must always be
  // invalidated to reflect the new thumb offset, even if the theme did not
  // invalidate any individual part.
  if (Scrollbar* horizontal_scrollbar = HorizontalScrollbar())
    horizontal_scrollbar->OffsetDidChange(scroll_type);
  if (Scrollbar* vertical_scrollbar = VerticalScrollbar())
    vertical_scrollbar->OffsetDidChange(scroll_type);

  ScrollOffset delta = GetScrollOffset() - old_offset;
  // TODO(skobes): Should we exit sooner when the offset has not changed?
  bool offset_changed = !delta.IsZero();

  if (GetMacScrollbarAnimator() && offset_changed &&
      IsExplicitScrollType(scroll_type) && ScrollbarsCanBeActive()) {
    GetMacScrollbarAnimator()->DidChangeUserVisibleScrollOffset(delta);
  }

  if (GetLayoutBox()) {
    if (offset_changed && GetLayoutBox()->GetFrameView() &&
        GetLayoutBox()
            ->GetFrameView()
            ->GetPaintTimingDetector()
            .NeedToNotifyInputOrScroll()) {
      GetLayoutBox()->GetFrameView()->GetPaintTimingDetector().NotifyScroll(
          scroll_type);
    }
  }

  if (offset_changed && GetLayoutBox() && GetLayoutBox()->GetFrameView()) {
    GetLayoutBox()->GetFrameView()->GetLayoutShiftTracker().NotifyScroll(
        scroll_type, delta);
    // FrameSelection caches visual selection information which needs to be
    // invalidated after scrolling.
    GetLayoutBox()->GetFrameView()->GetFrame().Selection().MarkCacheDirty();
  }

  GetScrollAnimator().SetCurrentOffset(offset);
}

mojom::blink::ScrollBehavior ScrollableArea::V8EnumToScrollBehavior(
    V8ScrollBehavior::Enum behavior) {
  switch (behavior) {
    case V8ScrollBehavior::Enum::kAuto:
      return mojom::blink::ScrollBehavior::kAuto;
    case V8ScrollBehavior::Enum::kInstant:
      return mojom::blink::ScrollBehavior::kInstant;
    case V8ScrollBehavior::Enum::kSmooth:
      return mojom::blink::ScrollBehavior::kSmooth;
  }
  NOTREACHED();
}

void ScrollableArea::RegisterScrollCompleteCallback(ScrollCallback callback) {
  DCHECK(!HasBeenDisposed());
  pending_scroll_complete_callbacks_.push_back(std::move(callback));
}

void ScrollableArea::RunScrollCompleteCallbacks(ScrollCompletionMode mode) {
  Vector<ScrollCallback> callbacks(
      std::move(pending_scroll_complete_callbacks_));
  for (auto& callback : callbacks) {
    std::move(callback).Run(mode);
  }
}

void ScrollableArea::ContentAreaWillPaint() const {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->ContentAreaWillPaint();
}

void ScrollableArea::MouseEnteredContentArea() const {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->MouseEnteredContentArea();
}

void ScrollableArea::MouseExitedContentArea() const {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->MouseExitedContentArea();
}

void ScrollableArea::MouseMovedInContentArea() const {
  if (mac_scrollbar_animator_)
    mac_scrollbar_animator_->MouseMovedInContentArea();
}

void ScrollableArea::MouseEnteredScrollbar(Scrollbar& scrollbar) {
  mouse_over_scrollbar_ = true;

  if (GetMacScrollbarAnimator())
    GetMacScrollbarAnimator()->MouseEnteredScrollbar(scrollbar);
  ShowNonMacOverlayScrollbars();
  if (fade_overlay_scrollbars_timer_)
    fade_overlay_scrollbars_timer_->Value().Stop();
}

void ScrollableArea::MouseExitedScrollbar(Scrollbar& scrollbar) {
  mouse_over_scrollbar_ = false;

  if (GetMacScrollbarAnimator())
    GetMacScrollbarAnimator()->MouseExitedScrollbar(scrollbar);
  if (HasOverlayScrollbars() && !scrollbars_hidden_if_overlay_) {
    // This will kick off the fade out timer.
    ShowNonMacOverlayScrollbars();
  }
}

void ScrollableArea::MouseCapturedScrollbar() {
  scrollbar_captured_ = true;
  ShowNonMacOverlayScrollbars();
  if (fade_overlay_scrollbars_timer_)
    fade_overlay_scrollbars_timer_->Value().Stop();
}

void ScrollableArea::MouseReleasedScrollbar() {
  scrollbar_captured_ = false;
  // This will kick off the fade out timer.
  ShowNonMacOverlayScrollbars();
}

void ScrollableArea::DidAddScrollbar(Scrollbar& scrollbar,
                                     ScrollbarOrientation orientation) {
  if (GetMacScrollbarAnimator()) {
    if (orientation == kVerticalScrollbar)
      GetMacScrollbarAnimator()->DidAddVerticalScrollbar(scrollbar);
    else
      GetMacScrollbarAnimator()->DidAddHorizontalScrollbar(scrollbar);
  }

  // <rdar://problem/9797253> AppKit resets the scrollbar's style when you
  // attach a scrollbar
  SetOverlayScrollbarColorScheme(GetOverlayScrollbarColorScheme());
}

void ScrollableArea::WillRemoveScrollbar(Scrollbar& scrollbar,
                                         ScrollbarOrientation orientation) {
  if (mac_scrollbar_animator_) {
    if (orientation == kVerticalScrollbar)
      mac_scrollbar_animator_->WillRemov
```
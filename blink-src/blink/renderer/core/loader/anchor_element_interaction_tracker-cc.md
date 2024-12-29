Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its functionality and connections to web technologies.

**1. Initial Skim and Keyword Recognition:**

The first step is a quick skim of the code, looking for recognizable keywords and patterns:

* **Includes:**  `#include` statements reveal dependencies. Notice `javascript`, `html`, `css` are *not* directly included, but things like `HTMLAnchorElementBase`, `Document`, `WebMouseEvent`, `PointerEvent` are strong hints of HTML and user interaction.
* **Namespaces:**  `blink` immediately points to the Chromium rendering engine.
* **Class Name:** `AnchorElementInteractionTracker` is the central focus. The name suggests it tracks how users interact with anchor elements (links).
* **Member Variables:** Look for key data members. `mouse_motion_estimator_`, `interaction_host_`, `hover_timer_`, `viewport_heuristic_timer_`, and `largest_anchor_element_in_viewport_` all suggest specific functionalities.
* **Methods:**  Focus on public and interesting-looking private methods like `OnMouseMoveEvent`, `OnPointerEvent`, `OnClickEvent`, `HoverTimerFired`, `ViewportHeuristicTimerFired`, `AnchorPositionsUpdated`. These are the action points.
* **Comments:** Pay attention to the comments, especially those starting with `TODO` or explaining complex logic. The "least squares linear regression" comment is a red flag for more detailed analysis later.
* **Features:** The mentions of `blink::features::kPreloadingViewportHeuristics` are important. This signals that some functionality is controlled by feature flags.
* **Metrics:** The use of `base::UmaHistogramPercentage` indicates data collection for performance analysis and A/B testing.
* **Mojo:**  `interaction_host_` and the `.mojom-blink.h` include point to the use of Mojo, Chromium's inter-process communication system.

**2. Deeper Dive into Key Components:**

Now, focus on understanding the core responsibilities of the main components:

* **`MouseMotionEstimator`:**  The name strongly suggests it analyzes mouse movement. The code confirms this, using a queue of mouse positions and timestamps to calculate velocity and acceleration using a least-squares method. This is a more involved calculation than a simple speed check.
* **`interaction_host_`:** The "host" suffix often implies an interface to another part of the system. The `.mojom` file confirms this is a Mojo interface, likely used to communicate interaction data to the browser process. The methods called on it (`OnPointerDown`, `OnPointerHover`, `OnViewportHeuristicTriggered`) confirm it's sending interaction information.
* **`hover_timer_`:**  Timers are often used for delays or periodic tasks. The `HoverTimerFired` method suggests it's triggered after a certain amount of time the mouse hovers over a link.
* **`viewport_heuristic_timer_`:** Similar to the hover timer, this one likely fires after a delay related to viewport analysis. The connection to `kPreloadingViewportHeuristics` is key here.

**3. Mapping Functionality to Web Concepts:**

Connect the code's actions to user interactions and web technologies:

* **Clicking a link:**  `OnClickEvent` is the direct handler. It collects metrics and sends data.
* **Hovering over a link:** `OnPointerEvent` with `kPointerover` and `kPointerout` triggers the hover timer. `HoverTimerFired` then sends data.
* **Mouse movement:** `OnMouseMoveEvent` feeds data into the `MouseMotionEstimator`. This is used to understand the *intent* behind the hover.
* **Scrolling:** The `AnchorPositionsUpdated` method, triggered by the `AnchorElementViewportPositionTracker`, clearly relates to how the viewport changes and how anchors are positioned within it.
* **Preloading:** The feature flag `kPreloadingViewportHeuristics` and the `OnViewportHeuristicTriggered` method strongly suggest this code is involved in deciding which links to preload based on user interaction.

**4. Inferring Logic and Making Assumptions:**

Based on the code and the understanding of web interactions, make educated guesses about the underlying logic:

* **Hover intent:** The `MouseMotionEstimator` likely helps determine if a hover is a deliberate action or just accidental mouse movement. High velocity might mean the user isn't intending to click.
* **Viewport Heuristics:** This feature probably tries to predict which link the user is most likely to click next based on the size and position of anchors in the current viewport. The "largest anchor" logic supports this. The delay suggests waiting for a stable viewport state.
* **Preloading benefits:**  The ultimate goal is likely to improve page load times by proactively fetching resources for links the user is likely to visit.

**5. Constructing Examples and Use Cases:**

Think about concrete scenarios to illustrate the code's behavior:

* **JavaScript Interaction:**  While no direct JS interaction is in *this file*, realize that JavaScript *actions* can *lead* to these events. For example, a JS animation might reposition elements, triggering `AnchorPositionsUpdated`.
* **CSS Styling:** CSS affects the size and layout of anchor elements, which is crucial for the viewport heuristics. A large, prominent link due to CSS will be more likely to be preloaded.
* **User Errors:** Misconfigurations of browser settings (like mouse sensitivity) could affect the accuracy of the mouse motion estimation.

**6. Tracing User Actions:**

Work backward from the code to understand how a user's actions lead to its execution. A sequence of mouse movements, a hover, or a scroll are typical triggers.

**7. Refining and Organizing:**

Finally, structure the findings into a clear and understandable explanation, using headings, bullet points, and examples. Focus on the key functionalities and their connections to web technologies. Address the specific requirements of the prompt (functionality, JavaScript/HTML/CSS relation, logic, errors, debugging).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is this just about tracking clicks?"  **Correction:**  The presence of hover and viewport heuristics shows it's more than just click tracking; it's about *predicting* interactions.
* **Initial thought:** "The mouse motion is simple speed calculation." **Correction:** The least squares regression indicates a more sophisticated analysis of acceleration and velocity.
* **Realization:**  The Mojo interface is crucial. It means this code isn't working in isolation; it's communicating with other browser components.

By following this detailed thought process, you can effectively analyze and understand even complex source code like the provided example.
好的，让我们来详细分析一下 `blink/renderer/core/loader/anchor_element_interaction_tracker.cc` 这个文件。

**功能概要:**

`AnchorElementInteractionTracker` 的主要功能是追踪用户与页面上锚元素（`<a>` 标签）的交互行为，并基于这些交互数据向浏览器报告，以便浏览器可以进行一些优化操作，例如预加载链接。

具体来说，它负责：

1. **监听和记录鼠标事件:**  追踪鼠标在屏幕上的移动轨迹 (`OnMouseMoveEvent`)，以及鼠标在锚元素上的按下 (`OnPointerEvent` - `pointerdown`)、悬停 (`OnPointerEvent` - `pointerover`) 和移出 (`OnPointerEvent` - `pointerout`) 事件。
2. **估计鼠标运动:** 使用 `MouseMotionEstimator` 类来估算鼠标的速度和加速度。这可以帮助判断用户是否是有意地悬停在链接上，还是只是偶然经过。
3. **管理悬停定时器:**  当鼠标悬停在链接上时，启动一个定时器 (`hover_timer_`)。如果用户在指定的时间内仍然悬停，则认为这是一个有意的悬停行为，并向浏览器报告。
4. **处理点击事件:** 记录用户点击锚元素的事件 (`OnClickEvent`)，并收集相关的指标数据。
5. **基于视口启发式算法进行预加载建议:**  如果启用了 `kPreloadingViewportHeuristics` 特性，它会监听锚元素在视口中的位置和大小变化 (`AnchorPositionsUpdated`)，并根据启发式规则（例如，视口中最大的链接）来建议浏览器预加载链接。
6. **通过 Mojo 接口与浏览器进程通信:**  使用 `interaction_host_` 这个 Mojo 接口将追踪到的交互数据和预加载建议发送到浏览器进程。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个 C++ 文件位于 Blink 渲染引擎的核心部分，它直接处理由浏览器解析 HTML、执行 JavaScript 和应用 CSS 后生成的 DOM 结构。

* **HTML:**  `AnchorElementInteractionTracker` 主要关注 HTML 中的 `<a>` 标签（锚元素）。它需要识别这些元素，并获取它们的 `href` 属性（链接目标地址）。
    * **举例:**  当用户将鼠标悬停在一个 HTML 链接 `<a href="https://example.com">Example</a>` 上时，`AnchorElementInteractionTracker` 会捕获 `pointerover` 事件，并提取 `href` 属性 "https://example.com"。

* **JavaScript:** JavaScript 代码可以动态地创建、修改和删除锚元素，也可以阻止或自定义默认的链接跳转行为。 `AnchorElementInteractionTracker` 会对当前 DOM 树中的锚元素进行操作。
    * **举例:**  JavaScript 可以使用 `document.createElement('a')` 创建一个新的链接，并添加到页面中。`AnchorElementInteractionTracker` 会追踪与这个新链接的交互。
    * **举例:** JavaScript 可以通过 `preventDefault()` 方法阻止链接的默认跳转行为。虽然 `AnchorElementInteractionTracker` 会记录相关的交互事件（例如 `pointerdown`），但它并不会干预 JavaScript 的行为。

* **CSS:** CSS 样式会影响锚元素的视觉呈现，包括大小、位置等。这些信息会被 `AnchorElementInteractionTracker` 用于视口启发式算法，判断哪些链接在用户的视线范围内且足够突出。
    * **举例:**  一个 CSS 样式使得某个链接的字体很大，背景颜色很醒目，这会增加该链接在视口中被认为是“重要”的可能性，从而可能被 `AnchorElementInteractionTracker` 选中进行预加载建议。`AnchorPositionsUpdated` 方法会获取到经过 CSS 渲染后的锚元素的大小和位置。

**逻辑推理、假设输入与输出:**

**场景 1：简单的鼠标悬停**

* **假设输入:**
    * 用户将鼠标指针移动到页面上的一个链接 `<a href="/page2">Page Two</a>` 上。
    * 鼠标指针在该链接上停留了 300 毫秒（假设 `GetHoverDwellTime()` 返回 200 毫秒）。
* **逻辑推理:**
    1. `OnMouseMoveEvent` 会持续记录鼠标的屏幕坐标。
    2. 当鼠标进入链接区域时，触发 `OnPointerEvent`，`event_type` 为 `pointerover`。
    3. `hover_event_candidates_` 会记录该链接的 URL 和悬停开始时间。
    4. `hover_timer_` 被启动，延迟时间为 `GetHoverDwellTime()`。
    5. 在延迟时间到达时，`HoverTimerFired` 被调用。
    6. 检查 `hover_event_candidates_` 中该链接的悬停时间是否已超过阈值。
    7. 由于 300 毫秒 > 200 毫秒，`interaction_host_->OnPointerHover("/page2", ...)` 被调用，向浏览器报告用户有意悬停在该链接上。
* **输出:**  通过 Mojo 接口发送一个 `OnPointerHover` 消息，包含目标链接 `/page2` 以及鼠标的运动数据（速度、加速度）。

**场景 2：视口启发式预加载**

* **假设输入:**
    * 页面上有三个链接：
        * `<a href="/pageA" style="font-size: 10px;">Link A</a>`
        * `<a href="/pageB" style="font-size: 20px;">Link B</a>`
        * `<a href="/pageC" style="font-size: 15px;">Link C</a>`
    * 用户滚动页面，使得这三个链接都在视口内。
    * 启用了 `kPreloadingViewportHeuristics` 特性。
* **逻辑推理:**
    1. 当锚元素的位置或大小发生变化时，`AnchorElementViewportPositionTracker` 会通知 `AnchorElementInteractionTracker` 调用 `AnchorPositionsUpdated`。
    2. `AnchorPositionsUpdated` 会计算每个锚元素在视口中的大小。假设 Link B 的渲染后尺寸最大。
    3. 比较视口中最大的两个链接（Link B 和 Link C）的大小差异是否超过阈值 (`largest_anchor_threshold`)。
    4. 如果 Link B 比 Link C 大很多，并且符合其他启发式规则（例如，在 pointerdown 事件附近），则 `largest_anchor_element_in_viewport_` 会被设置为 Link B 的元素。
    5. `viewport_heuristic_timer_` 被启动，延迟时间为 `config.delay`。
    6. 在延迟时间到达时，`ViewportHeuristicTimerFired` 被调用。
    7. `interaction_host_->OnViewportHeuristicTriggered("/pageB")` 被调用，建议浏览器预加载 `/pageB`。
* **输出:** 通过 Mojo 接口发送一个 `OnViewportHeuristicTriggered` 消息，包含建议预加载的链接 `/pageB`。

**用户或编程常见的使用错误:**

* **用户错误：鼠标抖动或快速掠过链接。**  如果用户只是快速地将鼠标移过链接，`AnchorElementInteractionTracker` 可能会错误地触发 `pointerover` 和 `pointerout` 事件，但由于悬停时间不足，通常不会触发 `OnPointerHover`。然而，如果鼠标在链接上短暂地停留，可能会导致误判。
* **编程错误：动态修改 DOM 后未及时更新锚元素位置信息。** 如果 JavaScript 代码动态地添加、删除或移动锚元素，但相关的布局信息没有及时更新，`AnchorElementInteractionTracker` 的视口启发式算法可能会基于过时的信息做出错误的预加载建议。
* **编程错误：CSS 样式导致锚元素重叠或不可见。**  如果 CSS 样式使得某些锚元素完全重叠或被隐藏，`AnchorElementInteractionTracker` 可能无法正确地识别和追踪这些元素的交互。

**用户操作如何一步步到达这里，作为调试线索:**

以下是一个用户操作导致 `AnchorElementInteractionTracker` 代码执行的典型流程，可以作为调试线索：

1. **用户加载网页:**  当浏览器加载包含锚元素的 HTML 页面时，Blink 渲染引擎会解析 HTML 并创建 DOM 树。
2. **创建 `AnchorElementInteractionTracker`:**  在创建 `Document` 对象时，会创建与之关联的 `AnchorElementInteractionTracker` 对象。
3. **用户移动鼠标:**
    * 当用户在页面上移动鼠标时，浏览器会生成 `mousemove` 事件。
    * Blink 的事件处理机制会将该事件传递给相关的监听器，包括 `AnchorElementInteractionTracker::OnMouseMoveEvent`。
    * `OnMouseMoveEvent` 会更新 `MouseMotionEstimator` 的鼠标位置信息。
4. **用户将鼠标悬停在链接上:**
    * 当鼠标指针进入一个锚元素的边界时，浏览器会生成 `mouseover` 或 `pointerover` 事件。
    * 该事件被传递给 `AnchorElementInteractionTracker::OnPointerEvent`。
    * 如果是 `pointerover` 事件，并且是主指针，则会将该链接加入悬停候选列表，并启动悬停定时器。
5. **悬停定时器触发:**
    * 如果用户在链接上停留的时间超过 `GetHoverDwellTime()`，`hover_timer_` 会触发 `AnchorElementInteractionTracker::HoverTimerFired`。
    * `HoverTimerFired` 会检查悬停时间是否足够长，并调用 `interaction_host_->OnPointerHover` 向浏览器报告。
6. **用户点击链接:**
    * 当用户点击一个锚元素时，浏览器会生成 `mousedown` 和 `mouseup` 事件，最终触发 `click` 事件。
    * `AnchorElementInteractionTracker::OnPointerEvent` 会处理 `pointerdown` 事件，记录 pointer down 的位置。
    * `AnchorElementInteractionTracker::OnClickEvent` 会处理 `click` 事件，收集点击相关的指标数据，并可能进行额外的分析。
7. **页面滚动导致视口变化:**
    * 当用户滚动页面时，视口会发生变化。
    * `AnchorElementViewportPositionTracker` 会检测到锚元素在视口中的位置和大小变化。
    * `AnchorElementViewportPositionTracker::AnchorPositionsUpdated` 方法会被调用，更新锚元素的位置信息，并触发 `AnchorElementInteractionTracker::AnchorPositionsUpdated`。
    * `AnchorPositionsUpdated` 会根据视口启发式算法判断是否需要建议预加载。
    * 如果需要，`viewport_heuristic_timer_` 会被启动，并在超时后调用 `AnchorElementInteractionTracker::ViewportHeuristicTimerFired`，最终通过 `interaction_host_` 向浏览器发送预加载建议。

**调试线索:**

* **断点设置:** 在 `OnMouseMoveEvent`, `OnPointerEvent`, `HoverTimerFired`, `OnClickEvent`, `AnchorPositionsUpdated`, `ViewportHeuristicTimerFired` 等关键方法中设置断点，观察代码执行流程和变量值。
* **日志输出:**  在关键路径上添加 `DLOG` 或 `DVLOG` 输出，记录事件类型、目标 URL、鼠标坐标、时间戳等信息。
* **Mojo 消息监控:**  可以使用 Chromium 提供的工具（例如 `chrome://tracing` 或 `about:ipc`) 监控 `interaction_host_` 发送的 Mojo 消息，查看发送了哪些交互数据和预加载建议。
* **Feature Flag 检查:**  确认 `blink::features::kPreloadingViewportHeuristics` 特性是否已启用，因为这会影响视口启发式预加载的逻辑。
* **时间戳分析:**  分析事件发生的时间戳，可以帮助理解事件发生的顺序和时间间隔，例如，悬停事件是否在 `GetHoverDwellTime()` 规定的时间内触发。
* **DOM 状态检查:**  在事件处理过程中，检查相关的 DOM 元素属性（例如 `href`, 样式）和布局信息，确保 `AnchorElementInteractionTracker` 操作的是预期的元素和状态。

希望以上详细的分析能够帮助你理解 `AnchorElementInteractionTracker.cc` 的功能和工作原理。

Prompt: 
```
这是目录为blink/renderer/core/loader/anchor_element_interaction_tracker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/anchor_element_interaction_tracker.h"

#include "base/metrics/histogram_functions.h"
#include "base/strings/strcat.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_pointer_properties.h"
#include "third_party/blink/public/mojom/preloading/anchor_element_interaction_host.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics.h"
#include "third_party/blink/renderer/core/html/anchor_element_metrics_sender.h"
#include "third_party/blink/renderer/core/html/anchor_element_viewport_position_tracker.h"
#include "third_party/blink/renderer/core/pointer_type_names.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"

namespace blink {

namespace {
constexpr double eps = 1e-9;
const base::TimeDelta kMousePosQueueTimeDelta{base::Milliseconds(500)};
const base::TimeDelta kMouseAccelerationAndVelocityInterval{
    base::Milliseconds(50)};

// Config for viewport heuristic derived from field trial params.
struct ViewportHeuristicConfig {
  // Min/max values of distance_from_pointer_down_ratio for an anchor to be
  // selected by the heuristic.
  std::pair<float, float> distance_from_ptr_down_ratio_bounds;
  // The largest anchor should be larger than the next largest anchor by this
  // threshold to be selected by the heuristic. More specifically, for the
  // largest anchor a1, and the next largest anchor a2:
  // (size(a1) - size(a2)) / size(a2) >= `largest_anchor_threshold`.
  double largest_anchor_threshold;
  // Time to wait before informing the browser of the largest anchor element
  // selected by the heuristic.
  base::TimeDelta delay;
};

ViewportHeuristicConfig GetViewportHeuristicConfig() {
  // -0.3 is the lower bound of the middle 75% of distance_from_ptr_down_ratio
  // values of clicked anchors (i.e. the P12.5 value).
  const base::FeatureParam<double> kDistanceFromPointerDownLowerBound{
      &features::kPreloadingViewportHeuristics, "distance_from_ptr_down_low",
      -0.3};
  // 0.0 is the upper bound of the middle 75% of distance_from_ptr_down_ratio
  // values of clicked anchors (i.e. the P87.5 value).
  const base::FeatureParam<double> kDistanceFromPointerDownUpperBound{
      &features::kPreloadingViewportHeuristics, "distance_from_ptr_down_hi",
      0.0};
  // Note: The default value was selected arbitrarily and hasn't been tuned.
  const base::FeatureParam<double> kLargestAnchorThreshold{
      &features::kPreloadingViewportHeuristics, "largest_anchor_threshold",
      0.5};
  // Note: The default value was selected arbitrarily and hasn't been tuned.
  const base::FeatureParam<base::TimeDelta> kDelay{
      &features::kPreloadingViewportHeuristics, "delay",
      base::Milliseconds(1000)};

  double low = std::clamp(kDistanceFromPointerDownLowerBound.Get(), -1.0, 1.0);
  double high = std::clamp(kDistanceFromPointerDownUpperBound.Get(), low, 1.0);
  return {
      .distance_from_ptr_down_ratio_bounds = std::make_pair(low, high),
      .largest_anchor_threshold = std::max(kLargestAnchorThreshold.Get(), 0.0),
      .delay = kDelay.Get()};
}

}  // namespace

AnchorElementInteractionTracker::MouseMotionEstimator::MouseMotionEstimator(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : update_timer_(
          task_runner,
          this,
          &AnchorElementInteractionTracker::MouseMotionEstimator::OnTimer),
      clock_(base::DefaultTickClock::GetInstance()) {
  CHECK(clock_);
}

void AnchorElementInteractionTracker::MouseMotionEstimator::Trace(
    Visitor* visitor) const {
  visitor->Trace(update_timer_);
}

double AnchorElementInteractionTracker::MouseMotionEstimator::
    GetMouseTangentialAcceleration() const {
  // Tangential acceleration = (a.v)/|v|
  return DotProduct(acceleration_, velocity_) /
         std::max(static_cast<double>(velocity_.Length()), eps);
}

inline void AnchorElementInteractionTracker::MouseMotionEstimator::AddDataPoint(
    base::TimeTicks timestamp,
    gfx::PointF position) {
  mouse_position_and_timestamps_.push_front(
      MousePositionAndTimeStamp{.position = position, .ts = timestamp});
}
inline void
AnchorElementInteractionTracker::MouseMotionEstimator::RemoveOldDataPoints(
    base::TimeTicks now) {
  while (!mouse_position_and_timestamps_.empty() &&
         (now - mouse_position_and_timestamps_.back().ts) >
             kMousePosQueueTimeDelta) {
    mouse_position_and_timestamps_.pop_back();
  }
}

void AnchorElementInteractionTracker::MouseMotionEstimator::Update() {
  // Bases on the mouse position/timestamp data
  // (ts0,ts1,ts2,...),(px0,px1,px2,...),(py0,py1,py2,...), we like to find
  // acceleration (ax, ay) and velocity (vx,vy) values that best fit following
  // set of equations:
  // {px1 = 0.5*ax*(ts1-ts0)**2 + vx0*(ts1-ts0) + px0},
  // {py1 = 0.5*ay*(ts1-ts0)**2 + vy0*(ts1-ts0) + py0},
  // {px2 = 0.5*ax*(ts2-ts0)**2 + vx0*(ts2-ts0) + px0},
  // {py2 = 0.5*ay*(ts2-ts0)**2 + vy0*(ts2-ts0) + py0},
  // ...
  // It can be solved using least squares linear regression by computing metrics
  // A (2x2), X (2x1), and Y (2x1) where:
  // a11 = 0.25*[(ts1-ts0)**4+(ts2-ts0)**4+...]
  // a12 = a21 = 0.5*[(ts1-ts0)**3+(ts2-ts0)**3+...]
  // a22 = (ts1-ts0)**2+(ts2-ts0)**2+...
  // x1 = 0.5*(px1-px0)*(ts1-ts0)**2+0.5*(px2-px0)*(ts2-ts0)**2+...
  // x2 = (px1-px0)*(ts1-ts0)+(px2-px0)*(ts2-ts0)+...
  // y1 = 0.5*(py1-py0)*(ts1-ts0)**2+0.5*(py2-py0)*(ts2-ts0)**2+...
  // y2 = (py1-py0)*(ts1-ts0)+(py2-py0)*(ts2-ts0)+...
  // and the solution is:
  // | ax  ay |       | a11 a12 |   | x1 y1 |
  // | vx0 vy0| = inv(| a12 a22 |)* | x2 y2 |
  // At the end the latest velocity is:
  // vx = ax*(ts-ts0) + vx0
  // vy = ay*(ts-ts0) + vy0

  // Since, we use `(ts-ts0)**4` to construct the matrix A, measuring the time
  // in seconds will cause rounding errors and make the numerical solution
  // unstable. Therefore, we'll use milli-seconds for time measurement and then
  // we rescale the acceleration/velocity estimates at the end.
  constexpr double kRescaleVelocity = 1e3;
  constexpr double kRescaleAcceleration = 1e6;

  // We need at least 2 data points to compute the acceleration and velocity.
  if (mouse_position_and_timestamps_.size() <= 1u) {
    acceleration_ = {0.0, 0.0};
    velocity_ = {0.0, 0.0};
    return;
  }
  auto back = mouse_position_and_timestamps_.back();
  auto front = mouse_position_and_timestamps_.front();
  auto replace_zero_with_eps = [](double x) {
    return x >= 0.0 ? std::max(x, eps) : std::min(x, -eps);
  };
  // With 2 data points, we could assume acceleration is zero and just estimate
  // the velocity.
  if (mouse_position_and_timestamps_.size() == 2u) {
    acceleration_ = {0.0, 0.0};
    velocity_ = front.position - back.position;
    velocity_.InvScale(
        replace_zero_with_eps((front.ts - back.ts).InSecondsF()));
    return;
  }
  // with 3 or more data points, we can use the above mentioned linear
  // regression approach.
  double a11 = 0, a12 = 0, a22 = 0;
  double x1 = 0, x2 = 0;
  double y1 = 0, y2 = 0;
  for (wtf_size_t i = 0; i < mouse_position_and_timestamps_.size() - 1; i++) {
    const auto& mouse_data = mouse_position_and_timestamps_.at(i);
    double t = (mouse_data.ts - back.ts).InMilliseconds();
    double t_square = t * t;
    double t_cube = t * t_square;
    double t_quad = t * t_cube;
    double px = mouse_data.position.x() - back.position.x();
    double py = mouse_data.position.y() - back.position.y();
    a11 += t_quad;
    a12 += t_cube;
    a22 += t_square;
    x1 += px * t_square;
    x2 += px * t;
    y1 += py * t_square;
    y2 += py * t;
  }
  a11 *= 0.25;
  a12 *= 0.5;
  x1 *= 0.5;
  y1 *= 0.5;

  double determinant = replace_zero_with_eps(a11 * a22 - a12 * a12);
  acceleration_.set_x(kRescaleAcceleration * (a22 * x1 - a12 * x2) /
                      determinant);
  velocity_.set_x(kRescaleVelocity * (-a12 * x1 + a11 * x2) / determinant +
                  acceleration_.x() * (front.ts - back.ts).InSecondsF());

  acceleration_.set_y(kRescaleAcceleration * (a22 * y1 - a12 * y2) /
                      determinant);
  velocity_.set_y(kRescaleVelocity * (-a12 * y1 + a11 * y2) / determinant +
                  acceleration_.y() * (front.ts - back.ts).InSecondsF());
}

void AnchorElementInteractionTracker::MouseMotionEstimator::OnTimer(
    TimerBase*) {
  RemoveOldDataPoints(clock_->NowTicks());
  Update();
  if (IsEmpty()) {
    // If there are no new mouse movements for more than
    // `kMousePosQueueTimeDelta`, the `mouse_position_and_timestamps_` will be
    // empty. Returning without firing `update_timer_`
    // will prevent us from perpetually firing the timer event.
    return;
  }
  update_timer_.StartOneShot(kMouseAccelerationAndVelocityInterval, FROM_HERE);
}

void AnchorElementInteractionTracker::MouseMotionEstimator::OnMouseMoveEvent(
    gfx::PointF position) {
  AddDataPoint(clock_->NowTicks(), position);
  if (update_timer_.IsActive()) {
    update_timer_.Stop();
  }
  OnTimer(&update_timer_);
}

void AnchorElementInteractionTracker::MouseMotionEstimator::
    SetTaskRunnerForTesting(
        scoped_refptr<base::SingleThreadTaskRunner> task_runner,
        const base::TickClock* clock) {
  update_timer_.SetTaskRunnerForTesting(task_runner, clock);
  clock_ = clock;
}

AnchorElementInteractionTracker::AnchorElementInteractionTracker(
    Document& document)
    : mouse_motion_estimator_(MakeGarbageCollected<MouseMotionEstimator>(
          document.GetTaskRunner(TaskType::kUserInteraction))),
      interaction_host_(document.GetExecutionContext()),
      hover_timer_(document.GetTaskRunner(TaskType::kUserInteraction),
                   this,
                   &AnchorElementInteractionTracker::HoverTimerFired),
      clock_(base::DefaultTickClock::GetInstance()),
      document_(&document),
      viewport_heuristic_timer_(
          document.GetTaskRunner(TaskType::kUserInteraction),
          this,
          &AnchorElementInteractionTracker::ViewportHeuristicTimerFired) {
  document.GetFrame()->GetBrowserInterfaceBroker().GetInterface(
      interaction_host_.BindNewPipeAndPassReceiver(
          document.GetExecutionContext()->GetTaskRunner(
              TaskType::kInternalDefault)));
  if (base::FeatureList::IsEnabled(
          blink::features::kPreloadingViewportHeuristics)) {
    auto* anchor_metrics_sender =
        AnchorElementMetricsSender::GetForFrame(GetDocument()->GetFrame());
    auto* anchor_viewport_observer =
        AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(document);
    // The viewport-based heuristic implemented by this class isn't as accurate
    // when all anchors are not sampled in (i.e. not reported to
    // `anchor_viewport_observer`), so we don't register for notifications (and
    // don't run the heuristic) in that case.
    if (anchor_viewport_observer && anchor_metrics_sender &&
        anchor_metrics_sender->AllAnchorsSampledIn()) {
      anchor_viewport_observer->AddObserver(this);
    }
  }
}

AnchorElementInteractionTracker::~AnchorElementInteractionTracker() = default;

void AnchorElementInteractionTracker::Trace(Visitor* visitor) const {
  visitor->Trace(interaction_host_);
  visitor->Trace(hover_timer_);
  visitor->Trace(mouse_motion_estimator_);
  visitor->Trace(document_);
  visitor->Trace(largest_anchor_element_in_viewport_);
  visitor->Trace(viewport_heuristic_timer_);
  AnchorElementViewportPositionTracker::Observer::Trace(visitor);
}

// static
base::TimeDelta AnchorElementInteractionTracker::GetHoverDwellTime() {
  static base::FeatureParam<base::TimeDelta> hover_dwell_time{
      &blink::features::kSpeculationRulesPointerHoverHeuristics,
      "HoverDwellTime", base::Milliseconds(200)};
  return hover_dwell_time.Get();
}

void AnchorElementInteractionTracker::OnMouseMoveEvent(
    const WebMouseEvent& mouse_event) {
  mouse_motion_estimator_->OnMouseMoveEvent(mouse_event.PositionInScreen());
}

void AnchorElementInteractionTracker::OnPointerEvent(
    EventTarget& target,
    const PointerEvent& pointer_event) {
  if (!target.ToNode()) {
    return;
  }
  if (!pointer_event.isPrimary()) {
    return;
  }

  const AtomicString& event_type = pointer_event.type();

  if (event_type == event_type_names::kPointerdown) {
    last_pointer_down_locations_[1] = last_pointer_down_locations_[0];
    last_pointer_down_locations_[0] = pointer_event.screenY();

    if (auto* viewport_position_tracker =
            AnchorElementViewportPositionTracker::MaybeGetOrCreateFor(
                *GetDocument())) {
      viewport_position_tracker->RecordPointerDown(pointer_event);
    }

    // If we already had a timer running, we stop it because the user is likely
    // about to start scrolling again.
    viewport_heuristic_timer_.Stop();
  }

  HTMLAnchorElementBase* anchor =
      FirstAnchorElementIncludingSelf(target.ToNode());
  if (!anchor) {
    return;
  }
  KURL url = GetHrefEligibleForPreloading(*anchor);
  if (url.IsEmpty()) {
    return;
  }

  if (auto* sender =
          AnchorElementMetricsSender::GetForFrame(GetDocument()->GetFrame())) {
    sender->MaybeReportAnchorElementPointerEvent(*anchor, pointer_event);
  }

  // interaction_host_ might become unbound: Android's low memory detector
  // sometimes call NotifyContextDestroyed to save memory. This unbinds mojo
  // pipes using that ExecutionContext even if those pages can still navigate.
  if (!interaction_host_.is_bound()) {
    return;
  }

  if (event_type == event_type_names::kPointerdown) {
    // TODO(crbug.com/1297312): Check if user changed the default mouse
    // settings
    if (pointer_event.button() !=
            static_cast<int>(WebPointerProperties::Button::kLeft) &&
        pointer_event.button() !=
            static_cast<int>(WebPointerProperties::Button::kMiddle)) {
      return;
    }
    interaction_host_->OnPointerDown(url);
    return;
  }

  if (event_type == event_type_names::kPointerover) {
    hover_event_candidates_.insert(
        url, HoverEventCandidate{
                 .is_mouse =
                     pointer_event.pointerType() == pointer_type_names::kMouse,
                 .anchor_id = AnchorElementId(*anchor),
                 .timestamp = clock_->NowTicks() + GetHoverDwellTime()});
    if (!hover_timer_.IsActive()) {
      hover_timer_.StartOneShot(GetHoverDwellTime(), FROM_HERE);
    }
  } else if (event_type == event_type_names::kPointerout) {
    // Since the pointer is no longer hovering on the link, there is no need to
    // check the timer. We should just remove it here.
    hover_event_candidates_.erase(url);
  }
}

void AnchorElementInteractionTracker::OnClickEvent(
    HTMLAnchorElementBase& anchor,
    const MouseEvent& click_event) {
  if (auto* sender =
          AnchorElementMetricsSender::GetForFrame(GetDocument()->GetFrame())) {
    sender->MaybeReportClickedMetricsOnClick(anchor);
  }

  LocalFrame* frame = anchor.GetDocument().GetFrame();
  if (!frame->IsMainFrame() || !frame->View()) {
    return;
  }

  Screen* screen = frame->DomWindow()->screen();
  const int screen_height = screen->height();
  if (screen_height == 0) {
    return;
  }

  const char* orientation_pattern =
      screen->width() <= screen_height ? ".Portrait" : ".Landscape";
  double click_y = click_event.screenY();
  int normalized_click_y = base::ClampRound(100.0f * (click_y / screen_height));
  base::UmaHistogramPercentage(
      base::StrCat({"Blink.AnchorElementInteractionTracker.ClickLocationY",
                    orientation_pattern}),
      normalized_click_y);

  if (last_pointer_down_locations_[1]) {
    double click_distance = click_y - last_pointer_down_locations_[1].value();
    // Because a click could happen both above and below the previous pointer
    // down, |click_distance| can be any value between -|screen_height| and
    // |screen_height| inclusive. We shift and scale it to be values between 0
    // and 100 before recording to UMA.
    int shifted_normalized_click_distance =
        base::ClampRound(50.0f * (1 + click_distance / screen_height));
    base::UmaHistogramPercentage(
        base::StrCat({"Blink.AnchorElementInteractionTracker"
                      ".ClickDistanceFromPreviousPointerDown",
                      orientation_pattern}),
        shifted_normalized_click_distance);
  }
}

void AnchorElementInteractionTracker::HoverTimerFired(TimerBase*) {
  if (!interaction_host_.is_bound()) {
    return;
  }
  const base::TimeTicks now = clock_->NowTicks();
  auto next_fire_time = base::TimeTicks::Max();
  Vector<KURL> to_be_erased;
  for (const auto& hover_event_candidate : hover_event_candidates_) {
    // Check whether pointer hovered long enough on the link to send the
    // PointerHover event to interaction host.
    if (now >= hover_event_candidate.value.timestamp) {
      auto pointer_data = mojom::blink::AnchorElementPointerData::New(
          /*is_mouse_pointer=*/hover_event_candidate.value.is_mouse,
          /*mouse_velocity=*/
          mouse_motion_estimator_->GetMouseVelocity().Length(),
          /*mouse_acceleration=*/
          mouse_motion_estimator_->GetMouseTangentialAcceleration());

      if (hover_event_candidate.value.is_mouse) {
        if (auto* sender = AnchorElementMetricsSender::GetForFrame(
                GetDocument()->GetFrame())) {
          sender->MaybeReportAnchorElementPointerDataOnHoverTimerFired(
              hover_event_candidate.value.anchor_id, pointer_data->Clone());
        }
      }

      interaction_host_->OnPointerHover(
          /*target=*/hover_event_candidate.key, std::move(pointer_data));
      to_be_erased.push_back(hover_event_candidate.key);

      continue;
    }
    // Update next fire time
    next_fire_time =
        std::min(next_fire_time, hover_event_candidate.value.timestamp);
  }
  WTF::RemoveAll(hover_event_candidates_, to_be_erased);
  if (!next_fire_time.is_max()) {
    hover_timer_.StartOneShot(next_fire_time - now, FROM_HERE);
  }
}

void AnchorElementInteractionTracker::SetTaskRunnerForTesting(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const base::TickClock* clock) {
  hover_timer_.SetTaskRunnerForTesting(task_runner, clock);
  mouse_motion_estimator_->SetTaskRunnerForTesting(task_runner, clock);
  clock_ = clock;
}

HTMLAnchorElementBase*
AnchorElementInteractionTracker::FirstAnchorElementIncludingSelf(Node* node) {
  HTMLAnchorElementBase* anchor = nullptr;
  while (node && !anchor) {
    anchor = DynamicTo<HTMLAnchorElementBase>(node);
    node = node->parentNode();
  }
  return anchor;
}

KURL AnchorElementInteractionTracker::GetHrefEligibleForPreloading(
    const HTMLAnchorElementBase& anchor) {
  KURL url = anchor.Href();
  if (url.ProtocolIsInHTTPFamily()) {
    return url;
  }
  return KURL();
}

void AnchorElementInteractionTracker::AnchorPositionsUpdated(
    HeapVector<Member<AnchorPositionUpdate>>& position_updates) {
  CHECK(base::FeatureList::IsEnabled(
      blink::features::kPreloadingViewportHeuristics));
  static const ViewportHeuristicConfig config = GetViewportHeuristicConfig();

  // Reset the delay timer (if active); this could happen if a programmatic
  // scroll happened after the timer started.
  viewport_heuristic_timer_.Stop();

  std::array<AnchorPositionUpdate*, 2> largest_anchors = {nullptr, nullptr};
  for (AnchorPositionUpdate* anchor_position : position_updates) {
    if (anchor_position->size_in_viewport == 0) {
      continue;
    }

    // If the anchor is not within a specified distance from the most recent
    // pointerdown on the page, we remove it from consideration.
    auto [low, high] = config.distance_from_ptr_down_ratio_bounds;
    if (anchor_position->distance_from_pointer_down.has_value() &&
        (anchor_position->distance_from_pointer_down < low ||
         anchor_position->distance_from_pointer_down > high)) {
      continue;
    }

    if (!largest_anchors[0] || anchor_position->size_in_viewport >
                                   largest_anchors[0]->size_in_viewport) {
      largest_anchors[1] = largest_anchors[0];
      largest_anchors[0] = anchor_position;
    } else if (!largest_anchors[1] ||
               anchor_position->size_in_viewport >
                   largest_anchors[1]->size_in_viewport) {
      largest_anchors[1] = anchor_position;
    }
  }

  if (!largest_anchors[0]) {
    return;
  }

  if (largest_anchors[1]) {
    const double size_difference = largest_anchors[0]->size_in_viewport -
                                   largest_anchors[1]->size_in_viewport;
    // If the largest two anchors are similar in size, we don't preload
    // anything.
    if (size_difference / largest_anchors[1]->size_in_viewport <
        config.largest_anchor_threshold) {
      return;
    }
  }

  largest_anchor_element_in_viewport_ = largest_anchors[0]->anchor_element;
  viewport_heuristic_timer_.StartOneShot(config.delay, FROM_HERE);
}

void AnchorElementInteractionTracker::ViewportHeuristicTimerFired(
    TimerBase* timer) {
  CHECK(base::FeatureList::IsEnabled(
      blink::features::kPreloadingViewportHeuristics));
  if (!largest_anchor_element_in_viewport_ || !GetDocument()->GetFrame()) {
    return;
  }

  // interaction_host_ might become unbound: Android's low memory detector
  // sometimes call NotifyContextDestroyed to save memory. This unbinds mojo
  // pipes using that ExecutionContext even if those pages can still navigate.
  if (!interaction_host_.is_bound()) {
    return;
  }

  interaction_host_->OnViewportHeuristicTriggered(
      largest_anchor_element_in_viewport_->Url());
}

}  // namespace blink

"""

```
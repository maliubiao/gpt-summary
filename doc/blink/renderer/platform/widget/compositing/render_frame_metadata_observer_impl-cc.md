Response:
Let's break down the thought process for analyzing this C++ code and answering the user's questions.

**1. Understanding the Core Purpose:**

The file name itself, `render_frame_metadata_observer_impl.cc`, gives a strong hint. "RenderFrameMetadata" suggests data related to rendering a frame. "Observer" implies a mechanism to watch for changes. "Impl" means this is the implementation of that observer.

Therefore, the primary function is to observe changes in the metadata associated with rendering frames and notify other components (the "client").

**2. Identifying Key Components and Interactions:**

* **`RenderFrameMetadataObserverImpl` class:** This is the central class. It receives metadata, decides if it's changed enough to report, and sends updates.
* **`cc::RenderFrameMetadata`:**  This structure holds the rendering metadata (scroll offsets, page scale, viewport size, etc.).
* **`viz::CompositorFrameMetadata`:** Related to the compositing process, likely used for synchronization and tracking frame submissions. Notice the `frame_token`.
* **Mojo Interfaces (`cc::mojom::blink::RenderFrameMetadataObserver`, `cc::mojom::blink::RenderFrameMetadataObserverClient`):**  These define the communication contracts. The `Impl` *receives* observations, and the *client* receives notifications. Mojo suggests inter-process communication.
* **`client_remote_`:**  A pointer to the object that will receive the metadata updates.
* **`last_render_frame_metadata_`:**  Used to compare the current metadata with the previous one to detect changes.
* **`ShouldSendRenderFrameMetadata` function:**  The core logic for deciding whether to send an update.

**3. Analyzing the Code - Function by Function (or Block by Block):**

* **Constructor/Destructor:** Standard setup and teardown.
* **`BindToCurrentSequence`:**  Essential for Mojo, associating the observer with a specific thread or execution context.
* **`OnRenderFrameSubmission` (The most important function):**
    * Receives the current `render_frame_metadata` and `compositor_frame_metadata`.
    * Checks if updates should be sent based on:
        * Testing flags (`report_all_frame_submissions_for_testing_enabled_`).
        * The `ShouldSendRenderFrameMetadata` function.
        * Force send flag.
        * Android-specific root scroll offset updates.
    * Caches the metadata.
    * Sends updates to the `client_remote_` via `OnRenderFrameMetadataChanged`.
    * Handles Android-specific root scroll offset updates via `OnRootScrollOffsetChanged`.
    * Manages the `frame_token` for tracking.
* **`UpdateRootScrollOffsetUpdateFrequency` (Android Specific):** Controls how frequently root scroll offset updates are sent.
* **`ReportAllFrameSubmissionsForTesting`:**  A testing hook to force all metadata updates to be sent.
* **`SendLastRenderFrameMetadata`:** Sends the cached metadata, likely used for initial setup or testing.
* **`ShouldSendRenderFrameMetadata`:**  Compares various fields of the metadata to determine if a significant change has occurred. It also sets the `needs_activation_notification` flag. This is where many specific metadata properties are examined.
* **`DidEndScroll` (Android Specific):**  Handles sending root scroll offset updates when scrolling ends.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding *what* the metadata represents.

* **Scroll Offset:** Directly relates to the `scrollTop` and `scrollLeft` properties in JavaScript, and how the user navigates the HTML content.
* **Page Scale Factor:**  Influenced by the `<meta viewport>` tag in HTML and can be manipulated by the user (pinch-to-zoom). JavaScript can read and sometimes modify this.
* **Viewport Size:** The dimensions of the visible area, affected by browser window size and device orientation. JavaScript can access these values (e.g., `window.innerWidth`). CSS media queries rely on viewport size.
* **Top/Bottom Controls Height/Ratio:**  Think of browser toolbars or mobile address bars. These affect the available viewport and how content is laid out, influencing CSS layout and potentially JavaScript calculations.
* **Background Color:**  CSS `background-color`.
* **Mobile Optimized:** Indicates if the page is designed for mobile, often related to viewport settings and responsive CSS.
* **Device Scale Factor:** Pixel density of the screen, affecting how CSS pixels are rendered.

**5. Logical Reasoning (Hypothetical Inputs/Outputs):**

Think about specific scenarios:

* **Scenario:** User scrolls down the page.
    * **Input:** `OnRenderFrameSubmission` called with a `render_frame_metadata` where `root_scroll_offset` has changed.
    * **Output:** `ShouldSendRenderFrameMetadata` returns `true` (or the Android-specific logic triggers), and `OnRenderFrameMetadataChanged` (or `OnRootScrollOffsetChanged` on Android) is called on the client.

* **Scenario:**  A CSS animation changes the background color.
    * **Input:** `OnRenderFrameSubmission` called with a `render_frame_metadata` where `root_background_color` has changed.
    * **Output:** `ShouldSendRenderFrameMetadata` returns `true`, and `OnRenderFrameMetadataChanged` is called.

**6. Identifying Potential Usage Errors:**

Focus on the purpose of the class and common misuses of observer patterns:

* **Not binding the receiver:**  If `BindToCurrentSequence` isn't called, the Mojo connection won't be established, and no updates will be sent.
* **Incorrectly interpreting the "testing" flag:**  Assuming metadata is *always* sent can lead to unexpected behavior if testing isn't enabled.
* **Android-specific assumptions:** Forgetting that root scroll offset updates are handled differently on Android.

**7. Structuring the Answer:**

Organize the information logically, starting with the core function and then elaborating on specific aspects. Use clear headings and bullet points for readability. Provide concrete examples to illustrate the connections to web technologies and potential errors.

By following these steps, you can effectively analyze the given C++ code and provide a comprehensive answer to the user's questions. The key is to combine code analysis with an understanding of the underlying browser architecture and web technologies.
这个文件 `render_frame_metadata_observer_impl.cc` 是 Chromium Blink 渲染引擎中的一部分，其主要功能是**观察和传递渲染帧的元数据信息**。  它作为渲染器进程（renderer process）和合成器进程（compositor process）之间传递渲染状态信息的一个桥梁。

更具体地说，它的功能包括：

1. **接收来自合成器进程的渲染帧元数据:**  合成器进程在生成渲染帧后，会将其相关的元数据信息传递给这个观察者。这些元数据包含了渲染帧的各种属性，例如：
    * 滚动偏移量 (`root_scroll_offset`)
    * 页面缩放因子 (`page_scale_factor`, `external_page_scale_factor`)
    * 视口大小 (`viewport_size_in_pixels`, `scrollable_viewport_size`)
    * 顶部/底部控件的高度和显示比例 (`top_controls_height`, `top_controls_shown_ratio`, `bottom_controls_height`, `bottom_controls_shown_ratio`)
    * 本地表面 ID (`local_surface_id`)
    * 背景颜色 (`root_background_color`)
    * 选择状态 (`selection`)
    * 是否滚动到顶部 (`is_scroll_offset_at_top`)
    * 等等。

2. **判断元数据是否发生变化:**  `RenderFrameMetadataObserverImpl` 会缓存上一次的元数据，并在接收到新的元数据时进行比较，判断哪些关键属性发生了变化。

3. **将变化的元数据通知给渲染器的其他部分:** 当检测到元数据发生变化时，它会将这些信息通过 Mojo 接口 `cc::mojom::blink::RenderFrameMetadataObserverClient` 发送给渲染器进程中的客户端。这些客户端可能是负责 JavaScript 执行、布局计算、绘画等模块。

4. **支持测试模式:**  提供了一个测试模式，可以强制每次渲染帧提交都发送元数据，即使元数据没有发生显著变化。这对于调试和测试渲染流程非常有用。

5. **(Android/iOS 特定)处理滚动边界情况:** 在 Android 和 iOS 平台上，当滚动接近顶部、底部、左侧或右侧边缘时，即使滚动偏移量没有显著变化，也可能需要通知渲染器，以便进行 overscroll 效果或其他处理。

6. **(Android 特定)控制根滚动偏移量更新频率:** 在 Android 上，可以控制根滚动偏移量的更新频率，例如只在滚动结束时更新，或者每次渲染帧都更新。

**它与 JavaScript, HTML, CSS 的功能关系：**

`RenderFrameMetadataObserverImpl` 扮演着连接底层渲染机制和上层 Web 技术（JavaScript, HTML, CSS）的关键角色。  它传递的元数据直接反映了 HTML 结构、CSS 样式和 JavaScript 操作带来的视觉效果变化。

**举例说明：**

* **HTML & CSS & 滚动 (JavaScript 可能参与):**
    * **假设输入:** 用户通过鼠标滚轮或触摸滑动页面。合成器进程检测到滚动偏移量发生变化。
    * **逻辑推理:** `OnRenderFrameSubmission` 被调用，新的 `cc::RenderFrameMetadata` 包含更新后的 `root_scroll_offset`。`ShouldSendRenderFrameMetadata` 检测到 `root_scroll_offset` 的变化。
    * **输出:** `OnRenderFrameMetadataChanged` 被调用，将新的滚动偏移量发送给渲染器的客户端。
    * **JavaScript 关系:** JavaScript 可以通过 `window.scrollTo()` 或修改元素的 `scrollTop` 属性来触发滚动。渲染器接收到元数据变化后，可能会触发 JavaScript 事件，例如 `scroll` 事件，允许 JavaScript 代码响应滚动。
    * **HTML 关系:** HTML 结构决定了滚动容器和可滚动内容的大小。
    * **CSS 关系:** CSS 的 `overflow` 属性决定了元素是否可以滚动，以及滚动条的样式。

* **CSS & 视口变化 (JavaScript 可能参与):**
    * **假设输入:** 用户调整浏览器窗口大小。合成器进程检测到视口大小发生变化。
    * **逻辑推理:** `OnRenderFrameSubmission` 被调用，新的 `cc::RenderFrameMetadata` 包含更新后的 `viewport_size_in_pixels`。`ShouldSendRenderFrameMetadata` 检测到 `viewport_size_in_pixels` 的变化。
    * **输出:** `OnRenderFrameMetadataChanged` 被调用，将新的视口大小发送给渲染器的客户端。
    * **JavaScript 关系:** JavaScript 可以通过 `window.innerWidth` 和 `window.innerHeight` 获取视口大小，并根据视口大小执行不同的逻辑。
    * **HTML 关系:** HTML 的 `<meta viewport>` 标签影响初始视口的大小和缩放行为。
    * **CSS 关系:** CSS 媒体查询 (`@media`) 允许根据视口大小应用不同的样式规则。当视口大小变化时，浏览器会重新评估媒体查询，并可能应用不同的 CSS 样式。

* **CSS & 页面缩放 (JavaScript 可能参与):**
    * **假设输入:** 用户按下 `Ctrl` + `+` 进行页面放大。合成器进程检测到页面缩放因子发生变化。
    * **逻辑推理:** `OnRenderFrameSubmission` 被调用，新的 `cc::RenderFrameMetadata` 包含更新后的 `page_scale_factor`。`ShouldSendRenderFrameMetadata` 检测到 `page_scale_factor` 的变化。
    * **输出:** `OnRenderFrameMetadataChanged` 被调用，将新的页面缩放因子发送给渲染器的客户端。
    * **JavaScript 关系:** JavaScript 可以通过 `window.devicePixelRatio` (设备像素比) 和 `window.screen.width/height` 等信息间接感知页面缩放，并可能根据缩放级别调整某些元素的布局或大小。
    * **HTML 关系:** `<meta viewport>` 标签可以限制用户的缩放行为。
    * **CSS 关系:** CSS 中的长度单位（如 `px`, `em`, `rem`）会受到页面缩放的影响。

**用户或编程常见的使用错误举例：**

1. **假设输入:** 开发者在 JavaScript 中修改了元素的 `scrollTop` 属性，导致页面滚动。
   * **错误理解:**  开发者可能错误地认为每次 JavaScript 修改 `scrollTop` 后，`RenderFrameMetadataObserverImpl` 会立即发送更新后的 `root_scroll_offset`。
   * **实际情况:**  `RenderFrameMetadataObserverImpl` 是在合成器进程渲染新帧后才获取并发送元数据的。JavaScript 修改 `scrollTop` 后，会触发布局和合成，最终在合成器生成新帧时，元数据才会被更新和发送。如果合成器没有生成新帧（例如，因为修改过于频繁），那么观察者可能不会立即报告变化。

2. **假设输入:**  一个复杂的网页包含大量的动态内容和 CSS 动画，导致渲染帧元数据频繁变化。
   * **潜在问题:** 如果测试模式 (`ReportAllFrameSubmissionsForTesting(true)`) 被意外启用或长时间开启，`RenderFrameMetadataObserverImpl` 会在每次渲染帧提交时都发送元数据，即使变化很小或不重要，这可能会导致不必要的通信开销和性能问题。

3. **假设输入 (Android 特定):** 开发者依赖于每次滚动偏移量发生微小变化时都能收到通知。
   * **潜在问题:** 在 Android 上，可以通过 `UpdateRootScrollOffsetUpdateFrequency` 控制根滚动偏移量的更新频率。如果频率设置为 `kOnScrollEnd`，那么只有在滚动结束后才会发送通知，中间的滚动过程中的偏移量变化可能不会被立即报告。开发者需要根据需求合理设置更新频率。

**总结：**

`RenderFrameMetadataObserverImpl` 是一个幕后英雄，它默默地监视着渲染过程中的关键状态，并将这些状态变化通知给渲染引擎的其他部分。理解它的功能有助于开发者更好地理解浏览器的工作原理，以及如何有效地使用 JavaScript、HTML 和 CSS 来构建高性能的 Web 应用。它在连接底层渲染和上层 Web 技术栈方面起着至关重要的作用。

Prompt: 
```
这是目录为blink/renderer/platform/widget/compositing/render_frame_metadata_observer_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/widget/compositing/render_frame_metadata_observer_impl.h"

#include <cmath>

#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "cc/mojom/render_frame_metadata.mojom-shared.h"
#include "components/viz/common/quads/compositor_frame_metadata.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
constexpr float kEdgeThreshold = 10.0f;
#endif
}  // namespace

RenderFrameMetadataObserverImpl::RenderFrameMetadataObserverImpl(
    mojo::PendingReceiver<cc::mojom::blink::RenderFrameMetadataObserver>
        receiver,
    mojo::PendingRemote<cc::mojom::blink::RenderFrameMetadataObserverClient>
        client_remote)
    : receiver_(std::move(receiver)),
      client_remote_(std::move(client_remote)) {}

RenderFrameMetadataObserverImpl::~RenderFrameMetadataObserverImpl() {}

void RenderFrameMetadataObserverImpl::BindToCurrentSequence() {
  DCHECK(receiver_.is_valid());
  render_frame_metadata_observer_receiver_.Bind(std::move(receiver_));
  render_frame_metadata_observer_client_.Bind(std::move(client_remote_));
}

void RenderFrameMetadataObserverImpl::OnRenderFrameSubmission(
    const cc::RenderFrameMetadata& render_frame_metadata,
    viz::CompositorFrameMetadata* compositor_frame_metadata,
    bool force_send) {
  // By default only report metadata changes for fields which have a low
  // frequency of change. However if there are changes in high frequency
  // fields these can be reported while testing is enabled.
  bool send_metadata = false;
  bool needs_activation_notification = true;
  if (render_frame_metadata_observer_client_) {
    if (report_all_frame_submissions_for_testing_enabled_) {
      last_frame_token_ = compositor_frame_metadata->frame_token;
      compositor_frame_metadata->send_frame_token_to_embedder = true;
      render_frame_metadata_observer_client_->OnFrameSubmissionForTesting(
          last_frame_token_);
      send_metadata = !last_render_frame_metadata_ ||
                      *last_render_frame_metadata_ != render_frame_metadata;
    } else {
      send_metadata = !last_render_frame_metadata_ ||
                      ShouldSendRenderFrameMetadata(
                          *last_render_frame_metadata_, render_frame_metadata,
                          &needs_activation_notification);
    }
    send_metadata |= force_send;
  }

#if BUILDFLAG(IS_ANDROID)
  bool is_frequency_all_updates =
      root_scroll_offset_update_frequency_.value_or(
          cc::mojom::blink::RootScrollOffsetUpdateFrequency::kNone) ==
      cc::mojom::blink::RootScrollOffsetUpdateFrequency::kAllUpdates;
  const bool send_root_scroll_offset_changed =
      is_frequency_all_updates && !send_metadata &&
      render_frame_metadata_observer_client_ && last_render_frame_metadata_ &&
      last_render_frame_metadata_->root_scroll_offset !=
          render_frame_metadata.root_scroll_offset &&
      render_frame_metadata.root_scroll_offset.has_value();
#endif

  // Always cache the full metadata, so that it can correctly be sent upon
  // ReportAllFrameSubmissionsForTesting or on android, which notifies on any
  // root scroll offset change. This must only be done after we've compared the
  // two for changes.
  last_render_frame_metadata_ = render_frame_metadata;

  // If the metadata is different, updates all the observers; or the metadata is
  // generated for first time and same as the default value, update the default
  // value to all the observers.
  if (send_metadata && render_frame_metadata_observer_client_) {
    auto metadata_copy = render_frame_metadata;
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
    // On non-Android, sending |root_scroll_offset| outside of tests would
    // leave the browser process with out of date information. It is an
    // optional parameter which we clear here.
    if (!report_all_frame_submissions_for_testing_enabled_)
      metadata_copy.root_scroll_offset = std::nullopt;
#endif

    last_frame_token_ = compositor_frame_metadata->frame_token;
    compositor_frame_metadata->send_frame_token_to_embedder =
        needs_activation_notification;
    render_frame_metadata_observer_client_->OnRenderFrameMetadataChanged(
        needs_activation_notification ? last_frame_token_ : 0u, metadata_copy);
#if BUILDFLAG(IS_ANDROID)
    last_root_scroll_offset_android_ = metadata_copy.root_scroll_offset;
#endif
    TRACE_EVENT_WITH_FLOW1(
        TRACE_DISABLED_BY_DEFAULT("viz.surface_id_flow"),
        "RenderFrameMetadataObserverImpl::OnRenderFrameSubmission",
        metadata_copy.local_surface_id &&
                metadata_copy.local_surface_id->is_valid()
            ? metadata_copy.local_surface_id->submission_trace_id() +
                  metadata_copy.local_surface_id->embed_trace_id()
            : 0,
        TRACE_EVENT_FLAG_FLOW_OUT, "local_surface_id",
        metadata_copy.local_surface_id
            ? metadata_copy.local_surface_id->ToString()
            : "null");
  }

#if BUILDFLAG(IS_ANDROID)
  if (send_root_scroll_offset_changed) {
    DCHECK(!send_metadata);
    render_frame_metadata_observer_client_->OnRootScrollOffsetChanged(
        *render_frame_metadata.root_scroll_offset);
    last_root_scroll_offset_android_ =
        *render_frame_metadata.root_scroll_offset;
  }
#endif

  // Always cache the initial frame token, so that if a test connects later on
  // it can be notified of the initial state.
  if (!last_frame_token_) {
    last_frame_token_ = compositor_frame_metadata->frame_token;
    compositor_frame_metadata->send_frame_token_to_embedder =
        needs_activation_notification;
  }
}

#if BUILDFLAG(IS_ANDROID)
void RenderFrameMetadataObserverImpl::UpdateRootScrollOffsetUpdateFrequency(
    cc::mojom::blink::RootScrollOffsetUpdateFrequency frequency) {
  if (!RuntimeEnabledFeatures::CCTNewRFMPushBehaviorEnabled()) {
    root_scroll_offset_update_frequency_ = frequency;
    if (frequency ==
        cc::mojom::blink::RootScrollOffsetUpdateFrequency::kAllUpdates) {
      SendLastRenderFrameMetadata();
    }
    return;
  }

  if ((!root_scroll_offset_update_frequency_.has_value() ||
       frequency > root_scroll_offset_update_frequency_) &&
      last_render_frame_metadata_.has_value()) {
    SendLastRenderFrameMetadata();
  }
  root_scroll_offset_update_frequency_ = frequency;
}
#endif

void RenderFrameMetadataObserverImpl::ReportAllFrameSubmissionsForTesting(
    bool enabled) {
  report_all_frame_submissions_for_testing_enabled_ = enabled;

  if (enabled)
    SendLastRenderFrameMetadata();
}

void RenderFrameMetadataObserverImpl::SendLastRenderFrameMetadata() {
  if (!last_frame_token_)
    return;

  // When enabled for testing send the cached metadata.
  DCHECK(render_frame_metadata_observer_client_);
  DCHECK(last_render_frame_metadata_.has_value());
  render_frame_metadata_observer_client_->OnRenderFrameMetadataChanged(
      last_frame_token_, *last_render_frame_metadata_);
}

bool RenderFrameMetadataObserverImpl::ShouldSendRenderFrameMetadata(
    const cc::RenderFrameMetadata& rfm1,
    const cc::RenderFrameMetadata& rfm2,
    bool* needs_activation_notification) const {
  if (rfm1.root_background_color != rfm2.root_background_color ||
      rfm1.is_scroll_offset_at_top != rfm2.is_scroll_offset_at_top ||
      rfm1.selection != rfm2.selection ||
      rfm1.page_scale_factor != rfm2.page_scale_factor ||
      rfm1.external_page_scale_factor != rfm2.external_page_scale_factor ||
      rfm1.is_mobile_optimized != rfm2.is_mobile_optimized ||
      rfm1.delegated_ink_metadata != rfm2.delegated_ink_metadata ||
      rfm1.device_scale_factor != rfm2.device_scale_factor ||
      rfm1.viewport_size_in_pixels != rfm2.viewport_size_in_pixels ||
      rfm1.top_controls_height != rfm2.top_controls_height ||
      rfm1.top_controls_shown_ratio != rfm2.top_controls_shown_ratio ||
      rfm1.local_surface_id != rfm2.local_surface_id ||
      rfm2.new_vertical_scroll_direction !=
          viz::VerticalScrollDirection::kNull ||
      (rfm2.primary_main_frame_item_sequence_number !=
           cc::RenderFrameMetadata::kInvalidItemSequenceNumber &&
       rfm1.primary_main_frame_item_sequence_number !=
           rfm2.primary_main_frame_item_sequence_number)) {
    *needs_activation_notification = true;
    return true;
  }

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  if (rfm1.bottom_controls_height != rfm2.bottom_controls_height ||
      rfm1.bottom_controls_shown_ratio != rfm2.bottom_controls_shown_ratio ||
      rfm1.top_controls_min_height_offset !=
          rfm2.top_controls_min_height_offset ||
      rfm1.bottom_controls_min_height_offset !=
          rfm2.bottom_controls_min_height_offset ||
      rfm1.min_page_scale_factor != rfm2.min_page_scale_factor ||
      rfm1.max_page_scale_factor != rfm2.max_page_scale_factor ||
      rfm1.root_overflow_y_hidden != rfm2.root_overflow_y_hidden ||
      rfm1.scrollable_viewport_size != rfm2.scrollable_viewport_size ||
      rfm1.root_layer_size != rfm2.root_layer_size ||
      rfm1.has_transparent_background != rfm2.has_transparent_background) {
    *needs_activation_notification = true;
    return true;
  }

  gfx::PointF old_root_scroll_offset =
      rfm1.root_scroll_offset.value_or(gfx::PointF());
  gfx::PointF new_root_scroll_offset =
      rfm2.root_scroll_offset.value_or(gfx::PointF());
  gfx::RectF old_viewport_rect(
      gfx::PointF(old_root_scroll_offset.x(), old_root_scroll_offset.y()),
      rfm1.scrollable_viewport_size);
  gfx::RectF new_viewport_rect(
      gfx::PointF(new_root_scroll_offset.x(), new_root_scroll_offset.y()),
      rfm2.scrollable_viewport_size);
  gfx::RectF new_root_layer_rect(rfm2.root_layer_size);
  bool at_left_or_right_edge =
      rfm2.root_layer_size.width() > rfm2.scrollable_viewport_size.width() &&
      (std::abs(new_viewport_rect.right() - new_root_layer_rect.right()) <
           kEdgeThreshold ||
       std::abs(new_viewport_rect.x() - new_root_layer_rect.x()) <
           kEdgeThreshold);

  bool at_top_or_bottom_edge =
      rfm2.root_layer_size.height() > rfm2.scrollable_viewport_size.height() &&
      (std::abs(new_viewport_rect.y() - new_root_layer_rect.y()) <
           kEdgeThreshold ||
       std::abs(new_viewport_rect.bottom() - new_root_layer_rect.bottom()) <
           kEdgeThreshold);

  if (old_viewport_rect != new_viewport_rect &&
      (at_left_or_right_edge || at_top_or_bottom_edge)) {
    *needs_activation_notification = false;
    return true;
  }
#endif

  *needs_activation_notification = false;
  return false;
}

#if BUILDFLAG(IS_ANDROID)
void RenderFrameMetadataObserverImpl::DidEndScroll() {
  if (!last_render_frame_metadata_.has_value()) {
    return;
  }

  auto root_scroll_offset = last_render_frame_metadata_->root_scroll_offset;
  if (!root_scroll_offset.has_value() ||
      root_scroll_offset == last_root_scroll_offset_android_) {
    return;
  }

  if (root_scroll_offset_update_frequency_.value_or(
          cc::mojom::blink::RootScrollOffsetUpdateFrequency::kNone) !=
      cc::mojom::blink::RootScrollOffsetUpdateFrequency::kOnScrollEnd) {
    return;
  }

  render_frame_metadata_observer_client_->OnRootScrollOffsetChanged(
      root_scroll_offset.value());
  last_root_scroll_offset_android_ = root_scroll_offset;
}
#endif

}  // namespace blink

"""

```
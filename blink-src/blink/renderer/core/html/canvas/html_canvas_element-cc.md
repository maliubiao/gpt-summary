Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `html_canvas_element.cc` file. The request also asks to identify relationships with JavaScript, HTML, and CSS, provide examples of logical reasoning with input and output, illustrate common user/programming errors, and explain the steps involved for a user action to reach this code.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `html_canvas_element.cc` strongly suggests this file implements the `<canvas>` HTML element in the Blink rendering engine.

2. **Analyze the includes:** The included headers provide clues about the file's responsibilities. Look for categories like:
    * **Basic types and utilities:** `<math.h>`, `<limits>`, `<memory>`, `<utility>`, `base/...`, `build/...`
    * **Blink-specific core:**  `third_party/blink/renderer/core/...` (dom, html, css, frame, page, etc.)
    * **Graphics/Rendering:** `third_party/blink/renderer/platform/graphics/...`
    * **Bindings (JavaScript interaction):** `third_party/blink/renderer/bindings/...`
    * **Platform integration:** `third_party/blink/public/platform/...`
    * **Metrics and tracing:** `base/metrics`, `base/trace_event`, `services/metrics`

3. **Examine the class definition:** The `HTMLCanvasElement` class is the central element. Its methods and member variables will reveal its functionality.

4. **Focus on key methods and concepts:** Look for methods related to:
    * **Creation and destruction:** Constructor, destructor, `Dispose`
    * **Attribute handling:** `ParseAttribute`, setters for `width` and `height`
    * **Rendering context management:** `GetCanvasRenderingContext`, `RegisterRenderingContextFactory`
    * **Drawing and updates:** `DidDraw`, `DoDeferredPaintInvalidation`, `Reset`
    * **Compositing:** `SetNeedsCompositingUpdate`, `ShouldBeDirectComposited`
    * **Resource management:** `GetOrCreateCanvasResourceProvider`, `DiscardResourceProvider`
    * **Interactions with other systems:**  `PageVisibilityObserver`,  `ExecutionContextLifecycleObserver`
    * **Privacy and security:** `RecordIdentifiabilityMetric`, `OriginClean`
    * **Performance and optimization:**  Mentions of acceleration, low latency

5. **Relate to web technologies:**
    * **HTML:** The `<canvas>` tag itself, attributes like `width` and `height`.
    * **JavaScript:**  The API exposed to JavaScript for drawing, getting contexts (`getContext('2d')`, `getContext('webgl')`), methods like `toDataURL`, `toBlob`.
    * **CSS:** How CSS affects the canvas element (size, visibility, compositing hints).

6. **Consider user actions:**  Think about the steps a user takes to make the browser execute this code. This usually involves:
    * Loading a web page containing a `<canvas>` element.
    * JavaScript interacting with the canvas (getting the context, drawing).
    * Browser rendering the page and the canvas content.

7. **Infer logical reasoning:** Look for conditional logic and how different inputs affect the state and behavior of the `HTMLCanvasElement`.

8. **Identify potential errors:** Think about common mistakes developers make when using the canvas API.

**Self-Correction/Refinement during the process:**

* **Initial thought:** This file just handles basic canvas element properties.
* **Correction:**  The inclusion of graphics and rendering headers, context management, and compositing methods shows it's involved in the core rendering pipeline.
* **Initial thought:**  The file directly implements all canvas drawing.
* **Correction:** It *manages* the canvas element and its context. The actual drawing is delegated to the context objects (like `CanvasRenderingContext2D`, `WebGLRenderingContext`).
* **Initial thought:** User interaction only involves JavaScript drawing calls.
* **Correction:**  User actions like resizing the browser window or changing CSS styles can also trigger code within this file.

By following these steps, we can construct a comprehensive summary of the `HTMLCanvasElement::cc` file's functionality.
这是对Chromium Blink引擎中 `blink/renderer/core/html/canvas/html_canvas_element.cc` 文件的第一部分代码的功能归纳。

**功能归纳:**

这段代码主要负责实现 HTML `<canvas>` 元素的**核心功能和生命周期管理**。它定义了 `HTMLCanvasElement` 类，该类是 Blink 渲染引擎中代表 `<canvas>` DOM 元素的 C++ 对象。其主要职责包括：

1. **元素初始化和属性管理:**
   - 创建和初始化 `HTMLCanvasElement` 对象，包括设置默认的宽高。
   - 处理 `<canvas>` 元素的 `width` 和 `height` 属性的解析和更新，并触发相应的重置操作。
   - 维护画布的尺寸信息。

2. **渲染上下文管理:**
   - 提供创建和管理不同类型的 Canvas 渲染上下文（如 2D、WebGL）的机制。
   - 注册和获取 `CanvasRenderingContextFactory`，用于创建特定类型的渲染上下文。
   - 维护当前关联的渲染上下文对象 (`context_`)。
   - 处理渲染上下文的创建，包括处理跨域情况和设置电源偏好。
   - 负责在上下文创建后进行一些初始化操作，例如设置滤镜质量。

3. **渲染和更新:**
   - 跟踪画布的“脏区域” (`dirty_rect_`)，即需要重绘的区域。
   - 响应 `DidDraw` 事件，标记画布的脏区域。
   - 实现延迟绘制失效 (`DoDeferredPaintInvalidation`)，将脏区域通知布局对象进行重绘。
   - 处理画布的 `Reset` 操作，当 `width` 或 `height` 属性改变时会调用，用于清理和重新初始化画布状态。
   - 管理画布是否需要进行合成更新 (`SetNeedsCompositingUpdate`)。

4. **性能优化和特性支持:**
   - 支持低延迟画布 (`LowLatencyEnabled`)，以更低的延迟渲染画布内容。
   - 统计禁用硬件加速的画布数量，并基于此决定是否默认禁用新创建画布的硬件加速。
   - 跟踪 `transferToGPUTexture()` 是否被调用。
   - 支持配置高动态范围 (`configureHighDynamicRange`)。

5. **与其他 Blink 组件的交互:**
   - 与布局系统 (`LayoutHTMLCanvas`) 交互，创建和管理画布的布局对象。
   - 与合成器 (`cc::Layer`) 交互，管理画布的合成层。
   - 使用 `CanvasResourceProvider` 提供画布的渲染资源。
   - 与 `PageAnimator` 交互，通知画布需要重绘。
   - 使用 `UseCounter` 记录画布特性的使用情况。
   - 使用 `ukm::UkmRecorder` 记录画布相关的指标。

6. **生命周期管理:**
   - 实现 `Dispose` 方法，用于清理画布相关的资源。
   - 监听页面可见性变化 (`PageVisibilityObserver`)。
   - 监听执行上下文生命周期 (`ExecutionContextLifecycleObserver`)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    -  `HTMLCanvasElement` 类直接对应 HTML 中的 `<canvas>` 标签。
    -  代码中解析了 `<canvas>` 标签的 `width` 和 `height` 属性。例如，当 HTML 中有 `<canvas width="500" height="300"></canvas>` 时，`ParseAttribute` 方法会被调用，并更新 `HTMLCanvasElement` 对象的内部尺寸。
* **JavaScript:**
    -  JavaScript 通过 `document.getElementById('myCanvas')` 获取 `HTMLCanvasElement` 对象的引用。
    -  JavaScript 调用 `canvas.getContext('2d')` 或 `canvas.getContext('webgl')` 时，会触发 `GetCanvasRenderingContext` 方法，创建相应的渲染上下文对象。例如，`const ctx = canvas.getContext('2d');` 这行 JavaScript 代码会最终调用到 `GetCanvasRenderingContextInternal`。
    -  JavaScript 可以通过设置 `canvas.width` 和 `canvas.height` 属性来改变画布大小，这会触发 `setWidth` 和 `setHeight` 方法，并最终调用 `Reset` 方法。
* **CSS:**
    -  CSS 可以控制 `<canvas>` 元素的显示大小，但这**不会影响**画布的**实际分辨率**（由 `width` 和 `height` 属性决定）。例如，CSS 可以设置 `canvas { width: 400px; height: 200px; }`，但这仅仅改变了画布在页面上的显示尺寸，画布的内部缓冲区大小仍然由 `width` 和 `height` 属性决定。
    -  CSS 的 `display: none;` 会阻止布局对象的创建。
    -  CSS 的一些属性可能会影响画布的合成行为。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. 用户在 HTML 中创建了一个 `<canvas>` 元素，没有设置 `width` 和 `height` 属性。
    ```html
    <canvas id="myCanvas"></canvas>
    ```
2. JavaScript 代码获取该元素并尝试获取 2D 渲染上下文：
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    ```

**逻辑推理与输出:**

1. 由于 HTML 中没有设置 `width` 和 `height` 属性，`ParseAttribute` 方法会使用默认值 `kDefaultCanvasWidth` (300) 和 `kDefaultCanvasHeight` (150) 初始化 `HTMLCanvasElement` 的尺寸。
2. 当 JavaScript 调用 `getContext('2d')` 时，`GetCanvasRenderingContext` 方法会被调用，参数 `type` 为 "2d"。
3. `GetCanvasRenderingContextInternal` 方法会查找已注册的 2D 渲染上下文工厂。
4. 如果找到了 2D 上下文工厂，它会创建一个 `CanvasRenderingContext2D` 对象，并将其赋值给 `context_` 成员变量。
5. 最终，`getContext('2d')` 方法会返回创建的 `CanvasRenderingContext2D` 对象（赋值给 `ctx` 变量），JavaScript 代码可以使用该对象进行 2D 绘图。

**用户或编程常见的使用错误举例说明:**

1. **未设置 `width` 和 `height` 属性或设置了无效值:**  如果用户忘记在 HTML 中设置 `width` 和 `height` 属性，或者设置了负数或非数字值，画布将使用默认尺寸，这可能不是用户期望的结果。
2. **在 `transferControlToOffscreen()` 调用后尝试修改 `width` 或 `height`:** 代码中检查了 `IsOffscreenCanvasRegistered()`，如果画布已经被转移到 OffscreenCanvas，尝试修改尺寸会抛出 `InvalidStateError` 异常。这是一个常见的错误，因为开发者可能忘记在转移后画布的控制权已经转移。
    ```javascript
    const offscreenCanvas = canvas.transferControlToOffscreen();
    canvas.width = 500; // 这会抛出异常
    ```
3. **假设 CSS 的尺寸会改变画布分辨率:**  开发者可能会错误地认为使用 CSS 设置画布的宽度和高度会改变其绘图缓冲区的大小。实际上，这只会改变画布在页面上的显示尺寸，而不会影响其内部像素数量，可能导致图像变形或模糊。

**用户操作如何一步步的到达这里:**

1. **用户在文本编辑器中编写 HTML 文件:**  在 HTML 文件中，用户添加了 `<canvas>` 标签，可能设置了 `width` 和 `height` 属性，也可能没有设置。
2. **用户在 HTML 文件中编写 JavaScript 代码:**  JavaScript 代码通过 `document.getElementById()` 等方法获取 `<canvas>` 元素的引用。
3. **用户调用 `canvas.getContext('2d')` 或 `canvas.getContext('webgl')`:** 这会触发 Blink 引擎中 `HTMLCanvasElement` 类的 `GetCanvasRenderingContext` 方法。
4. **浏览器加载并解析 HTML 文件:**  当浏览器解析到 `<canvas>` 标签时，会创建 `HTMLCanvasElement` 对象，并调用 `ParseAttribute` 方法处理其属性。
5. **浏览器执行 JavaScript 代码:**  当执行到获取渲染上下文的代码时，会调用到 `HTMLCanvasElement` 类的相应方法。
6. **用户与画布交互 (例如，通过 JavaScript 进行绘制):**  JavaScript 调用渲染上下文的绘图 API (例如 `ctx.fillRect()`) 会最终触发 `HTMLCanvasElement` 的 `DidDraw` 方法，标记需要重绘的区域。
7. **浏览器进行渲染和合成:**  Blink 引擎会根据 `dirty_rect_` 等信息，决定何时以及如何重新渲染画布的内容，并将画布的内容合成到最终的页面渲染中。
8. **用户调整浏览器窗口大小或页面缩放:** 这可能会触发画布尺寸的重新计算和 `Reset` 方法的调用。

总而言之，这段代码是 `<canvas>` 元素在 Blink 渲染引擎中的核心实现，负责管理画布的属性、渲染上下文、以及与渲染流程的交互。它连接了 HTML 结构、JavaScript API 和底层的渲染机制。

Prompt: 
```
这是目录为blink/renderer/core/html/canvas/html_canvas_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2004, 2006, 2007 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2010 Torch Mobile (Beijing) Co. Ltd. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"

#include <math.h>

#include <limits>
#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/typed_macros.h"
#include "build/build_config.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_source_id.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metric_builder.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_metrics.h"
#include "third_party/blink/public/common/privacy_budget/identifiability_study_settings.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/gpu/gpu.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/resources/grit/blink_image_resources.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_encode_options.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/fileapi/file.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_async_blob_creator.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_draw_listener.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_font_cache.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context_factory.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_resource_tracker.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/html/canvas/predefined_color_space.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/hit_test_canvas_result.h"
#include "third_party/blink/renderer/core/layout/layout_html_canvas.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_auto_dark_mode.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/canvas_2d_layer_bridge.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_dispatcher.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/image_data_buffer.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_to_video_frame_copier.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_transform.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/image-encoders/image_encoder_utils.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/base/resource/resource_scale_factor.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/skia_conversions.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

// These two constants determine if a newly created canvas starts with
// acceleration disabled. Specifically:
// 1. More than `kDisableAccelerationThreshold` canvases have been created.
// 2. The percent of canvases with acceleration disabled is >=
//    `kDisableAccelerationPercent`.
constexpr unsigned kDisableAccelerationThreshold = 100;
constexpr unsigned kDisableAccelerationPercent = 95;

BASE_FEATURE(kOneCopyCanvasCapture,
             "OneCopyCanvasCapture",
#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_WIN)
             base::FEATURE_ENABLED_BY_DEFAULT
#else
             base::FEATURE_DISABLED_BY_DEFAULT
#endif
);

// Kill switch for not requesting continuous begin frame for low latency canvas.
BASE_FEATURE(kLowLatencyCanvasNoBeginFrameKillSwitch,
             "LowLatencyCanvasNoBeginFrameKillSwitch",
             base::FEATURE_ENABLED_BY_DEFAULT);

// These values come from the WhatWG spec.
constexpr int kDefaultCanvasWidth = 300;
constexpr int kDefaultCanvasHeight = 150;

// A default value of quality argument for toDataURL and toBlob
// It is in an invalid range (outside 0.0 - 1.0) so that it will not be
// misinterpreted as a user-input value
constexpr int kUndefinedQualityValue = -1.0;
constexpr int kMinimumAccelerated2dCanvasSize = 128 * 129;

// A default size used for canvas memory allocation when canvas size is greater
// than 2^20.
constexpr uint32_t kMaximumCanvasSize = 2 << 20;

// Tracks whether canvases should start out with acceleration disabled.
class DisabledAccelerationCounterSupplement final
    : public GarbageCollected<DisabledAccelerationCounterSupplement>,
      public Supplement<Document> {
 public:
  static const char kSupplementName[];

  static DisabledAccelerationCounterSupplement& From(Document& d) {
    DisabledAccelerationCounterSupplement* supplement =
        Supplement<Document>::From<DisabledAccelerationCounterSupplement>(d);
    if (!supplement) {
      supplement =
          MakeGarbageCollected<DisabledAccelerationCounterSupplement>(d);
      ProvideTo(d, supplement);
    }
    return *supplement;
  }

  explicit DisabledAccelerationCounterSupplement(Document& d)
      : Supplement<Document>(d) {}

  // Called when acceleration has been disabled on a canvas.
  void IncrementDisabledCount() {
    ++acceleration_disabled_count_;
    UpdateAccelerationDisabled();
  }

  // Returns true if canvas acceleration should be disabled.
  bool ShouldDisableAcceleration() {
    UpdateAccelerationDisabled();
    return acceleration_disabled_;
  }

 private:
  void UpdateAccelerationDisabled() {
    if (acceleration_disabled_) {
      return;
    }
    if (acceleration_disabled_count_ < kDisableAccelerationThreshold) {
      return;
    }
    if (acceleration_disabled_count_ * 100 /
            GetSupplementable()->GetNumberOfCanvases() >=
        kDisableAccelerationPercent) {
      acceleration_disabled_ = true;
    }
  }

  // Number of canvases with acceleration disabled.
  unsigned acceleration_disabled_count_ = 0;
  bool acceleration_disabled_ = false;
};

// static
const char DisabledAccelerationCounterSupplement::kSupplementName[] =
    "DisabledAccelerationCounterSupplement";

// Tracks whether `transferToGPUTexture()` has been invoked on any canvas
// element created within the associated Document.
class TransferToGPUTextureInvokedSupplement final
    : public GarbageCollected<TransferToGPUTextureInvokedSupplement>,
      public Supplement<Document> {
 public:
  static constexpr char kSupplementName[] =
      "TransferToGPUTextureInvokedSupplement";

  static TransferToGPUTextureInvokedSupplement& From(Document& d) {
    TransferToGPUTextureInvokedSupplement* supplement =
        Supplement<Document>::From<TransferToGPUTextureInvokedSupplement>(d);
    if (!supplement) {
      supplement =
          MakeGarbageCollected<TransferToGPUTextureInvokedSupplement>(d);
      ProvideTo(d, supplement);
    }
    return *supplement;
  }

  explicit TransferToGPUTextureInvokedSupplement(Document& d)
      : Supplement<Document>(d) {}

  void SetTransferToGPUTextureWasInvoked() {
    transfer_to_gpu_texture_was_invoked_ = true;
  }

  bool TransferToGPUTextureWasInvoked() {
    return transfer_to_gpu_texture_was_invoked_;
  }

 private:
  bool transfer_to_gpu_texture_was_invoked_ = false;
};

}  // namespace

HTMLCanvasElement::HTMLCanvasElement(Document& document)
    : HTMLElement(html_names::kCanvasTag, document),
      ExecutionContextLifecycleObserver(GetExecutionContext()),
      PageVisibilityObserver(document.GetPage()),
      CanvasRenderingContextHost(
          CanvasRenderingContextHost::HostType::kCanvasHost,
          gfx::Size(kDefaultCanvasWidth, kDefaultCanvasHeight)),
      context_creation_was_blocked_(false),
      ignore_reset_(false),
      origin_clean_(true),
      surface_layer_bridge_(nullptr),
      externally_allocated_memory_(0) {
  UseCounter::Count(document, WebFeature::kHTMLCanvasElement);
  // Create supplements now, as they may be needed at a
  // time when garbage collected objects can not be created.
  DisabledAccelerationCounterSupplement::From(GetDocument());
  TransferToGPUTextureInvokedSupplement::From(GetDocument());
  GetDocument().IncrementNumberOfCanvases();
  auto* execution_context = GetExecutionContext();
  if (execution_context) {
    CanvasResourceTracker::For(execution_context->GetIsolate())
        ->Add(this, execution_context);
  }
  SetHasCustomStyleCallbacks();
}

HTMLCanvasElement::~HTMLCanvasElement() {
  if (externally_allocated_memory_ > 0) {
    external_memory_accounter_.Decrease(v8::Isolate::GetCurrent(),
                                        externally_allocated_memory_);
  }
}

void HTMLCanvasElement::Dispose() {
  disposing_ = true;
  // We need to record metrics before we dispose of anything
  if (context_)
    UMA_HISTOGRAM_BOOLEAN("Blink.Canvas.HasRendered", bool(ResourceProvider()));

  // It's possible that the placeholder frame has been disposed but its ID still
  // exists. Make sure that it gets unregistered here
  UnregisterPlaceholderCanvas();

  // We need to drop frame dispatcher, to prevent mojo calls from completing.
  frame_dispatcher_ = nullptr;
  DiscardResourceProvider();

  if (context_) {
    if (context_->Host())
      context_->DetachHost();
    context_ = nullptr;
  }

  canvas2d_bridge_ = nullptr;

  if (surface_layer_bridge_) {
    // Observer has to be cleared out at this point. Otherwise the
    // SurfaceLayerBridge may call back into the observer which is undefined
    // behavior. In the worst case, the dead canvas element re-adds itself into
    // a data structure which may crash at a later point in time. See
    // https://crbug.com/976577.
    surface_layer_bridge_->ClearObserver();
  }
}

void HTMLCanvasElement::ColorSchemeMayHaveChanged() {
  if (context_) {
    context_->ColorSchemeMayHaveChanged();
  }
}

void HTMLCanvasElement::ParseAttribute(
    const AttributeModificationParams& params) {
  if (params.name == html_names::kWidthAttr ||
      params.name == html_names::kHeightAttr) {
    Reset();
  }
  HTMLElement::ParseAttribute(params);
}

LayoutObject* HTMLCanvasElement::CreateLayoutObject(
    const ComputedStyle& style) {
  if (GetExecutionContext() &&
      GetExecutionContext()->CanExecuteScripts(kNotAboutToExecuteScript)) {
    // Allocation of a layout object indicates that the canvas doesn't
    // have display:none set, so is conceptually being displayed.
    bool is_displayed = GetLayoutObject() && style_is_visible_;
    SetIsDisplayed(is_displayed);
    return MakeGarbageCollected<LayoutHTMLCanvas>(this);
  }
  return HTMLElement::CreateLayoutObject(style);
}

Node::InsertionNotificationRequest HTMLCanvasElement::InsertedInto(
    ContainerNode& node) {
  SetIsInCanvasSubtree(true);
  ColorSchemeMayHaveChanged();
  return HTMLElement::InsertedInto(node);
}

bool HTMLCanvasElement::SizeChangesAreAllowed(ExceptionState& exception_state) {
  if (IsOffscreenCanvasRegistered()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot resize canvas after call to transferControlToOffscreen().");
    return false;
  }
  return true;
}

void HTMLCanvasElement::setHeight(unsigned value,
                                  ExceptionState& exception_state) {
  if (SizeChangesAreAllowed(exception_state)) {
    SetUnsignedIntegralAttribute(html_names::kHeightAttr, value,
                                 kDefaultCanvasHeight);
  }
}

void HTMLCanvasElement::setWidth(unsigned value,
                                 ExceptionState& exception_state) {
  if (SizeChangesAreAllowed(exception_state)) {
    SetUnsignedIntegralAttribute(html_names::kWidthAttr, value,
                                 kDefaultCanvasWidth);
  }
}

void HTMLCanvasElement::SetSize(gfx::Size new_size) {
  if (new_size == Size())
    return;
  ignore_reset_ = true;
  SetIntegralAttribute(html_names::kWidthAttr, new_size.width());
  SetIntegralAttribute(html_names::kHeightAttr, new_size.height());
  ignore_reset_ = false;
  Reset();
}

HTMLCanvasElement::ContextFactoryVector&
HTMLCanvasElement::RenderingContextFactories() {
  DCHECK(IsMainThread());
  DEFINE_STATIC_LOCAL(
      ContextFactoryVector, context_factories,
      (static_cast<int>(CanvasRenderingContext::CanvasRenderingAPI::kMaxValue) +
       1));
  return context_factories;
}

CanvasRenderingContextFactory* HTMLCanvasElement::GetRenderingContextFactory(
    int rendering_api) {
  DCHECK_LE(
      rendering_api,
      static_cast<int>(CanvasRenderingContext::CanvasRenderingAPI::kMaxValue));
  return RenderingContextFactories()[rendering_api].get();
}

void HTMLCanvasElement::RegisterRenderingContextFactory(
    std::unique_ptr<CanvasRenderingContextFactory> rendering_context_factory) {
  CanvasRenderingContext::CanvasRenderingAPI rendering_api =
      rendering_context_factory->GetRenderingAPI();
  DCHECK_LE(rendering_api,
            CanvasRenderingContext::CanvasRenderingAPI::kMaxValue);
  DCHECK(!RenderingContextFactories()[static_cast<int>(rendering_api)]);
  RenderingContextFactories()[static_cast<int>(rendering_api)] =
      std::move(rendering_context_factory);
}

void HTMLCanvasElement::RecordIdentifiabilityMetric(
    IdentifiableSurface surface,
    IdentifiableToken value) const {
  blink::IdentifiabilityMetricBuilder(GetDocument().UkmSourceID())
      .Add(surface, value)
      .Record(GetDocument().UkmRecorder());
}

void HTMLCanvasElement::IdentifiabilityReportWithDigest(
    IdentifiableToken canvas_contents_token) const {
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          blink::IdentifiableSurface::Type::kCanvasReadback)) {
    RecordIdentifiabilityMetric(
        blink::IdentifiableSurface::FromTypeAndToken(
            blink::IdentifiableSurface::Type::kCanvasReadback,
            IdentifiabilityInputDigest(context_)),
        canvas_contents_token.ToUkmMetricValue());
  }
}

CanvasRenderingContext* HTMLCanvasElement::GetCanvasRenderingContext(
    const String& type,
    const CanvasContextCreationAttributesCore& attributes) {
  auto* old_contents_cc_layer = ContentsCcLayer();
  auto* result = GetCanvasRenderingContextInternal(type, attributes);

  Document& doc = GetDocument();
  if (IsRenderingContext2D()) {
    UseCounter::CountWebDXFeature(doc, WebDXFeature::kCanvas2d);
  }
  if (attributes.alpha) {
    UseCounter::CountWebDXFeature(doc, WebDXFeature::kCanvas2dAlpha);
  }
  if (attributes.desynchronized) {
    UseCounter::CountWebDXFeature(doc, WebDXFeature::kCanvas2dDesynchronized);
  }
  if (attributes.will_read_frequently ==
      CanvasContextCreationAttributesCore::WillReadFrequently::kTrue) {
    UseCounter::CountWebDXFeature(doc,
                                  WebDXFeature::kCanvas2dWillreadfrequently);
  }
  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kCanvasRenderingContext)) {
    IdentifiabilityMetricBuilder(doc.UkmSourceID())
        .Add(IdentifiableSurface::FromTypeAndToken(
                 IdentifiableSurface::Type::kCanvasRenderingContext,
                 CanvasRenderingContext::RenderingAPIFromId(type)),
             !!result)
        .Record(doc.UkmRecorder());
  }

  if (attributes.color_space != PredefinedColorSpace::kSRGB)
    UseCounter::Count(doc, WebFeature::kCanvasUseColorSpace);

  if (ContentsCcLayer() != old_contents_cc_layer)
    SetNeedsCompositingUpdate();

  return result;
}

bool HTMLCanvasElement::IsPageVisible() const {
  return GetPage() && GetPage()->IsPageVisible();
}

CanvasRenderingContext* HTMLCanvasElement::GetCanvasRenderingContextInternal(
    const String& type,
    const CanvasContextCreationAttributesCore& attributes) {
  CanvasRenderingContext::CanvasRenderingAPI rendering_api =
      CanvasRenderingContext::RenderingAPIFromId(type);

  // Unknown type.
  if (rendering_api == CanvasRenderingContext::CanvasRenderingAPI::kUnknown) {
    return nullptr;
  }

  CanvasRenderingContextFactory* factory =
      GetRenderingContextFactory(static_cast<int>(rendering_api));
  if (!factory)
    return nullptr;

  // FIXME - The code depends on the context not going away once created, to
  // prevent JS from seeing a dangling pointer. So for now we will disallow the
  // context from being changed once it is created.
  if (context_) {
    if (context_->GetRenderingAPI() == rendering_api)
      return context_.Get();

    factory->OnError(this,
                     "Canvas has an existing context of a different type");
    return nullptr;
  }

  // Tell the debugger about the attempt to create a canvas context
  // even if it will fail, to ease debugging.
  probe::DidCreateCanvasContext(&GetDocument());

  // If this context is cross-origin, it should prefer to use the low-power GPU
  LocalFrame* frame = GetDocument().GetFrame();
  CanvasContextCreationAttributesCore recomputed_attributes = attributes;
  if (frame && frame->IsCrossOriginToOutermostMainFrame()) {
    recomputed_attributes.power_preference =
        CanvasContextCreationAttributesCore::PowerPreference::kLowPower;
  }

  context_ = factory->Create(this, recomputed_attributes);
  if (!context_)
    return nullptr;

  if (IsWebGL() || IsWebGPU() || IsImageBitmapRenderingContext()) {
    context_->SetFilterQuality(FilterQuality());
  }
  context_->RecordUKMCanvasRenderingAPI();
  context_->RecordUMACanvasRenderingAPI();
  // Since the |context_| is created, free the transparent image,
  // |transparent_image_| created for this canvas if it exists.
  if (transparent_image_.get()) {
    transparent_image_.reset();
  }

  context_creation_was_blocked_ = false;

  if (IsWebGL())
    UpdateMemoryUsage();

  LayoutObject* layout_object = GetLayoutObject();
  if (layout_object) {
    if (IsRenderingContext2D() && !context_->CreationAttributes().alpha) {
      // In the alpha false case, canvas is initially opaque, so we need to
      // trigger an invalidation.
      DidDraw();
    }
  }

  if (context_->CreationAttributes().desynchronized) {
    if (!CreateLayer())
      return nullptr;
    SetNeedsUnbufferedInputEvents(true);
    frame_dispatcher_ = std::make_unique<CanvasResourceDispatcher>(
        nullptr, GetDocument().GetTaskRunner(TaskType::kInternalDefault),
        GetPage()
            ->GetPageScheduler()
            ->GetAgentGroupScheduler()
            .CompositorTaskRunner(),
        surface_layer_bridge_->GetFrameSinkId().client_id(),
        surface_layer_bridge_->GetFrameSinkId().sink_id(),
        CanvasResourceDispatcher::kInvalidPlaceholderCanvasId, Size());
    if (!base::FeatureList::IsEnabled(
            kLowLatencyCanvasNoBeginFrameKillSwitch)) {
      // We don't actually need the begin frame signal when in low latency mode,
      // but we need to subscribe to it or else dispatching frames will not
      // work.
      frame_dispatcher_->SetNeedsBeginFrame(IsPageVisible());
    }

    UseCounter::Count(GetDocument(), WebFeature::kHTMLCanvasElementLowLatency);
  }

  // A 2D context does not know before lazy creation whether or not it is
  // direct composited. The Canvas2DLayerBridge will handle this
  if (!IsRenderingContext2D())
    SetNeedsCompositingUpdate();

  SetOpacityMode(GetRenderingContextSkColorInfo().isOpaque() ? kOpaque
                                                             : kNonOpaque);

  return context_.Get();
}

void HTMLCanvasElement::configureHighDynamicRange(
    const CanvasHighDynamicRangeOptions* options,
    ExceptionState& exception_state) {
  gfx::HDRMetadata hdr_metadata;
  ParseCanvasHighDynamicRangeOptions(options, hdr_metadata);

  if (IsOffscreenCanvasRegistered()) {
    // TODO(https://crbug.com/1274220): Implement HDR support for offscreen
    // canvas.
    NOTIMPLEMENTED();
  }

  CanvasResourceHost::SetHdrMetadata(hdr_metadata);
  if (context_ && (IsWebGL() || IsWebGPU())) {
    context_->SetHdrMetadata(hdr_metadata);
  }
}

bool HTMLCanvasElement::ShouldBeDirectComposited() const {
  return (context_ && context_->IsComposited()) || (!!surface_layer_bridge_);
}

Settings* HTMLCanvasElement::GetSettings() const {
  auto* window = DynamicTo<LocalDOMWindow>(GetExecutionContext());
  if (window && window->GetFrame())
    return window->GetFrame()->GetSettings();
  return nullptr;
}

bool HTMLCanvasElement::IsWebGL1Enabled() const {
  Settings* settings = GetSettings();
  return settings && settings->GetWebGL1Enabled();
}

bool HTMLCanvasElement::IsWebGL2Enabled() const {
  Settings* settings = GetSettings();
  return settings && settings->GetWebGL2Enabled();
}

bool HTMLCanvasElement::IsWebGLBlocked() const {
  Document& document = GetDocument();
  bool blocked = false;
  mojo::Remote<mojom::blink::GpuDataManager> gpu_data_manager;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      gpu_data_manager.BindNewPipeAndPassReceiver());
  gpu_data_manager->Are3DAPIsBlockedForUrl(document.Url(), &blocked);
  return blocked;
}

void HTMLCanvasElement::SetContextCreationWasBlocked() {
  context_creation_was_blocked_ = true;
  // This canvas's cc::Layer (or whether it has one at all) has likely
  // changed, so schedule a compositing update.
  SetNeedsCompositingUpdate();
}

void HTMLCanvasElement::DidDraw(const SkIRect& rect) {
  if (rect.isEmpty())
    return;

  // To avoid issuing invalidations multiple times, we can check |dirty_rect_|
  // and only issue invalidations the first time it becomes non-empty.
  if (dirty_rect_.IsEmpty()) {
    if (LayoutObject* layout_object = GetLayoutObject()) {
      if (layout_object->PreviousVisibilityVisible() &&
          GetDocument().GetPage()) {
        GetDocument().GetPage()->Animator().SetHasCanvasInvalidation();
      }
      if (!LowLatencyEnabled()) {
        layout_object->SetShouldCheckForPaintInvalidation();
      }
    }
  }

  canvas_is_clear_ = false;
  dirty_rect_.Union(gfx::Rect(gfx::SkIRectToRect(rect)));
}

void HTMLCanvasElement::PreFinalizeFrame() {
  RecordCanvasSizeToUMA();

  // Low-latency 2d canvases produce their frames after the resource gets single
  // buffered.
  if (LowLatencyEnabled() && !dirty_rect_.IsEmpty() &&
      GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)) {
    // TryEnableSingleBuffering() the first time we FinalizeFrame().  This is
    // a nop if already single buffered or if single buffering is unsupported.
    ResourceProvider()->TryEnableSingleBuffering();
  }
}

void HTMLCanvasElement::PostFinalizeFrame(FlushReason reason) {
  if (LowLatencyEnabled() && !dirty_rect_.IsEmpty() &&
      GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU)) {
    const base::TimeTicks start_time = base::TimeTicks::Now();
    if (scoped_refptr<CanvasResource> canvas_resource =
            ResourceProvider()->ProduceCanvasResource(reason)) {
      const gfx::Rect src_rect(Size());
      dirty_rect_.Intersect(src_rect);
      const gfx::Rect int_dirty = dirty_rect_;
      const SkIRect damage_rect = SkIRect::MakeXYWH(
          int_dirty.x(), int_dirty.y(), int_dirty.width(), int_dirty.height());
      frame_dispatcher_->DispatchFrame(std::move(canvas_resource), start_time,
                                       damage_rect, IsOpaque());
    }
    dirty_rect_ = gfx::Rect();
  }

  // If the canvas is visible, notifying listeners is taken care of in
  // DoDeferredPaintInvalidation(), which allows the frame to be grabbed prior
  // to compositing, which is critically important because compositing may clear
  // the canvas's image. (e.g. WebGL context with preserveDrawingBuffer=false).
  // If the canvas is not visible, DoDeferredPaintInvalidation will not get
  // called, so we need to take care of business here.
  if (!did_notify_listeners_for_current_frame_)
    NotifyListenersCanvasChanged();
  did_notify_listeners_for_current_frame_ = false;
}

void HTMLCanvasElement::DisableAcceleration(
    std::unique_ptr<CanvasResourceProvider> new_provider_for_testing) {
  DisabledAccelerationCounterSupplement::From(GetDocument())
      .IncrementDisabledCount();
  // Create and configure an unaccelerated Canvas2DLayerBridge.
  SetPreferred2DRasterMode(RasterModeHint::kPreferCPU);

  if (canvas2d_bridge_) {
    ReplaceExisting2dLayerBridge(std::move(new_provider_for_testing));
  }

  // We must force a paint invalidation on the canvas even if it's
  // content did not change because it layer was destroyed.
  DidDraw();
  SetNeedsCompositingUpdate();
}

void HTMLCanvasElement::SetNeedsCompositingUpdate() {
  Element::SetNeedsCompositingUpdate();
}

void HTMLCanvasElement::DoDeferredPaintInvalidation() {
  DCHECK(!dirty_rect_.IsEmpty());
  if (LowLatencyEnabled()) {
    // Low latency canvas handles dirty propagation in FinalizeFrame();
    return;
  }
  LayoutBox* layout_box = GetLayoutBox();

  gfx::RectF content_rect;
  if (layout_box) {
    if (auto* replaced = DynamicTo<LayoutReplaced>(layout_box))
      content_rect = gfx::RectF(replaced->ReplacedContentRect());
    else
      content_rect = gfx::RectF(layout_box->PhysicalContentBoxRect());
  }

  if (IsRenderingContext2D()) {
    gfx::Rect src_rect(Size());
    dirty_rect_.Intersect(src_rect);

    gfx::RectF invalidation_rect;
    if (layout_box) {
      gfx::RectF mapped_dirty_rect = gfx::MapRect(
          gfx::RectF(dirty_rect_), gfx::RectF(src_rect), content_rect);
      if (context_->IsComposited()) {
        // Composited 2D canvases need the dirty rect to be expressed relative
        // to the content box, as opposed to the layout box.
        mapped_dirty_rect.Offset(-content_rect.OffsetFromOrigin());
      }
      invalidation_rect = mapped_dirty_rect;
    } else {
      invalidation_rect = gfx::RectF(dirty_rect_);
    }

    if (dirty_rect_.IsEmpty())
      return;

    DoPaintInvalidation(gfx::ToEnclosingRect(invalidation_rect));
  }

  if (IsImageBitmapRenderingContext() && RenderingContext()->CcLayer()) {
    RenderingContext()->CcLayer()->SetNeedsDisplay();
  }

  NotifyListenersCanvasChanged();
  did_notify_listeners_for_current_frame_ = true;

  if (layout_box && !ShouldBeDirectComposited()) {
    // If the canvas is not composited, propagate the paint invalidation to
    // |layout_box| as the painted result will change.
    layout_box->SetShouldDoFullPaintInvalidation();
  }

  dirty_rect_ = gfx::Rect();
}

void HTMLCanvasElement::Reset() {
  if (ignore_reset_)
    return;

  dirty_rect_ = gfx::Rect();

  unsigned w = 0;
  AtomicString value = FastGetAttribute(html_names::kWidthAttr);
  if (value.empty() || !ParseHTMLNonNegativeInteger(value, w) ||
      w > 0x7fffffffu) {
    w = kDefaultCanvasWidth;
  }

  unsigned h = 0;
  value = FastGetAttribute(html_names::kHeightAttr);
  if (value.empty() || !ParseHTMLNonNegativeInteger(value, h) ||
      h > 0x7fffffffu) {
    h = kDefaultCanvasHeight;
  }

  if (IsRenderingContext2D()) {
    context_->Reset();
    origin_clean_ = true;
  }
  canvas_is_clear_ = true;

  gfx::Size old_size = Size();
  gfx::Size new_size(w, h);

  // If the size of an existing buffer matches, we can reuse that buffer.
  // This optimization is only done for 2D canvases for now.
  if (IsRenderingContext2D() && ResourceProvider() != nullptr &&
      old_size == new_size) {
    return;
  }

  SetSurfaceSize(new_size);

  if ((IsWebGL() && old_size != Size()) || IsWebGPU()) {
    context_->Reshape(width(), height());
  }

  if (LayoutObject* layout_object = GetLayoutObject()) {
    if (layout_object->IsCanvas()) {
      if (old_size != Size())
        To<LayoutHTMLCanvas>(layout_object)->CanvasSizeChanged();
      layout_object->SetShouldDoFullPaintInvalidation();
    }
  }
}

bool HTMLCanvasElement::PaintsIntoCanvasBuffer() const {
  if (OffscreenCanvasFrame())
    return false;
  DCHECK(context_);
  if (!context_->IsComposited())
    return true;
  auto* settings = GetDocument().GetSettings();
  if (settings && settings->GetAcceleratedCompositingEnabled())
    return false;

  return true;
}

void HTMLCanvasElement::NotifyListenersCanvasChanged() {
  if (listeners_.size() == 0)
    return;

  if (!OriginClean()) {
    listeners_.clear();
    return;
  }

  bool listener_needs_new_frame_capture = false;
  for (const CanvasDrawListener* listener : listeners_) {
    if (listener->NeedsNewFrame())
      listener_needs_new_frame_capture = true;
  }

  if (!listener_needs_new_frame_capture)
    return;

  scoped_refptr<StaticBitmapImage> source_image;
  if (!copier_) {
    copier_ = std::make_unique
"""


```
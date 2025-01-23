Response:
My thought process to summarize the functionality of `canvas_rendering_context_2d.cc` goes through these stages:

1. **Identify the Core Function:** The filename itself, "canvas_rendering_context_2d.cc," immediately points to the implementation of the 2D rendering context for HTML `<canvas>` elements within the Blink rendering engine. This will be the central theme.

2. **Scan for Key Classes and Concepts:** I quickly scan the included headers and class declarations within the provided code snippet. This reveals important components:
    * `CanvasRenderingContext2D`: The main class we are analyzing.
    * `BaseRenderingContext2D`: A base class, suggesting shared functionality with other canvas contexts.
    * `HTMLCanvasElement`: The DOM element the context is associated with.
    * `CanvasResourceProvider`:  A crucial component for managing the underlying graphics resources (like textures and paint records).
    * `cc::PaintCanvas`, `cc::PaintRecord`:  Classes related to Chromium's compositing and painting infrastructure, indicating how canvas drawing is integrated into the browser's rendering pipeline.
    * `CanvasState`, `Path`: Classes representing the internal state of the canvas and geometric paths, respectively.
    * Various graphics-related headers (`SkiaUtils`, `GraphicsTypes`, `PaintFilter`, etc.).
    * Includes related to font handling (`CanvasFontCache`, `Font`).

3. **Analyze Key Methods and their Purpose:** I look for methods that suggest major functionalities. Some prominent ones are:
    * `Factory::Create()`:  Indicates the creation process of the context.
    * `LoseContext()`, `RestoreProviderAndContextIfPossible()`, `TryRestoreContextEvent()`:  Clearly related to handling context loss and restoration (important for resource management and robustness).
    * Drawing primitives (implicitly through the inclusion of `BaseRenderingContext2D`, though not explicitly shown in this snippet,  I know they exist).
    * `WritePixels()`: Direct pixel manipulation.
    * `clearRect()`: Clearing a rectangular area.
    * `ScrollPathIntoViewInternal()`:  Integrating canvas drawing with scrolling.
    * `GetOrCreatePaintCanvas()`, `FlushCanvas()`: Managing the recording and execution of drawing commands.
    * `ResolveFont()`: Handling font selection and loading.
    * `getImageDataInternal()`:  Accessing pixel data from the canvas.
    * `FinalizeFrame()`:  Part of the rendering pipeline.
    * `PageVisibilityChanged()`: Handling visibility changes.

4. **Infer Functionality based on Includes and Members:** Even without detailed code examination, the included headers and member variables provide strong clues. For example:
    * Inclusion of `cc/layers/texture_layer.h` suggests the canvas content can be backed by a GPU texture for compositing.
    * Inclusion of font-related headers points to text rendering capabilities.
    * Inclusion of `third_party/skia` headers signifies the use of the Skia graphics library.

5. **Connect to Web Standards (JavaScript, HTML, CSS):** I consider how the functionality relates to web development. The 2D canvas API is a well-defined standard accessed via JavaScript. The connection to HTML is through the `<canvas>` element. The link to CSS is less direct but exists through styling the canvas element and potentially influencing font resolution.

6. **Identify Potential User Errors:** Based on the functionalities, I think about common mistakes developers might make, such as drawing after context loss, incorrect usage of coordinates, or performance issues with frequent pixel manipulation.

7. **Trace User Actions (Debugging Clues):**  I mentally walk through a typical user interaction with a canvas to understand how the code might be reached: a page loading, a script accessing the canvas API, drawing operations being performed, and potentially context loss/restoration scenarios.

8. **Structure the Summary:** Finally, I organize the information into a coherent summary, grouping related functionalities and providing examples where applicable. I aim for clarity and conciseness while covering the main aspects. I explicitly mention the "Part 1" nature of the provided snippet and focus on summarizing the overall function.

Essentially, I use a top-down and bottom-up approach, starting with the obvious purpose and then digging into the code details to identify supporting functionalities and their connections to the broader web platform. The includes and method names are the primary guides for this initial summarization.
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

基于提供的代码片段，我们可以归纳出 `blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.cc` 文件的主要功能是 **实现了 HTML `<canvas>` 元素的 2D 渲染上下文（CanvasRenderingContext2D）的核心逻辑。**  这是浏览器中用于在 canvas 上进行 2D 图形绘制的关键组件。

更具体地说，它负责以下方面（基于代码片段中的信息）：

**核心功能：**

1. **上下文的创建和管理:**
   - 提供了 `Factory::Create` 方法用于创建 `CanvasRenderingContext2D` 对象。
   - 管理上下文的生命周期，包括初始化、销毁。
   - 处理上下文丢失和恢复（`LoseContext`, `RestoreProviderAndContextIfPossible`, `TryRestoreContextEvent`）。这在 GPU 资源不足或其他错误情况下会发生。
   - 追踪上下文的状态，例如是否丢失 (`isContextLost`)。

2. **与底层图形系统的交互:**
   - 使用 Skia 图形库进行实际的绘制操作（通过 `cc::PaintCanvas`, `cc::PaintRecord` 等）。
   - 管理 `CanvasResourceProvider`，该提供者负责与 GPU 或 CPU 后端交互，管理纹理和其他资源。
   - 提供 `WritePixels` 方法，允许直接写入像素数据到画布。
   - 提供 `FlushCanvas` 方法，将记录的绘制操作提交到渲染管线。

3. **画布状态的管理:**
   - 维护画布的当前状态，包括变换矩阵、裁剪区域等（虽然状态本身可能在 `CanvasRenderingContext2DState` 中定义，但这里负责管理和应用）。
   - 提供方法来保存和恢复画布的状态 (`RestoreCanvasMatrixClipStack`)。
   - 管理是否启用抗锯齿 (`ShouldAntialias`, `SetShouldAntialias`)。

4. **处理 JavaScript API 调用:**
   - 这是 `CanvasRenderingContext2D` 的 C++ 实现，对应于 JavaScript 中通过 `canvas.getContext('2d')` 获取到的对象。它必然包含或关联着对 JavaScript API 的实现，例如 `clearRect` (尽管具体实现可能在 `BaseRenderingContext2D`)。

5. **集成到 Blink 渲染引擎:**
   - 与 Blink 的其他模块进行交互，例如布局 (`LayoutObject`, `LayoutBox`)、样式 (`ComputedStyle`) 和 compositing (`cc::layers::TextureLayer`).
   - 监听文档的生命周期事件，例如页面可见性变化 (`PageVisibilityChanged`).
   - 使用 Chromium 的 tracing 机制 (`TRACE_EVENT0`).

6. **字体处理:**
   - 管理画布使用的字体 (`ResolveFont`)，并缓存已解析的字体信息 (`fonts_resolved_using_current_style_`).
   - 监听样式变化并更新字体缓存 (`StyleDidChange`).

7. **图像数据获取:**
   - 提供 `getImageDataInternal` 方法，允许从画布读取像素数据。

8. **与辅助功能 (Accessibility) 的集成:** (虽然代码片段中没有直接体现，但 canvas 渲染上下文通常会涉及辅助功能树的更新)

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `CanvasRenderingContext2D` 是 JavaScript 中 `CanvasRenderingContext2D` 接口的底层实现。
    * **举例：** 当 JavaScript 调用 `ctx.fillRect(10, 10, 50, 50);` 时，最终会调用到 `CanvasRenderingContext2D` 中相应的 C++ 方法，该方法会记录绘制矩形的操作，并通过 Skia 渲染到画布上。
    * **举例：** JavaScript 中设置 `ctx.fillStyle = 'red';` 会影响到 `CanvasRenderingContext2D` 对象内部状态的更新。

* **HTML:**  `CanvasRenderingContext2D` 作用于 HTML 的 `<canvas>` 元素。
    * **举例：**  `<canvas id="myCanvas" width="200" height="100"></canvas>`  定义了一个画布元素。JavaScript 通过 `document.getElementById('myCanvas').getContext('2d')` 获取到与这个 canvas 关联的 `CanvasRenderingContext2D` 对象。
    * **举例：**  `<canvas>` 元素的 `width` 和 `height` 属性决定了 `CanvasRenderingContext2D` 的初始绘图区域大小。

* **CSS:** CSS 可以影响 `<canvas>` 元素的显示样式，但直接控制 `CanvasRenderingContext2D` 的绘图行为较少。
    * **举例：**  CSS 可以设置 `<canvas>` 元素的边框、背景色等，但这些样式不会直接影响通过 `CanvasRenderingContext2D` 绘制的内容。
    * **举例：**  CSS 的字体属性可能会间接影响 `CanvasRenderingContext2D` 中文本的渲染，因为 `CanvasRenderingContext2D` 需要解析 CSS 字体字符串。

**逻辑推理 (假设输入与输出)：**

* **假设输入 (JavaScript 调用):** `ctx.clearRect(0, 0, 100, 100);`
* **输出 (内部操作):** `CanvasRenderingContext2D::clearRect` 方法被调用，它会指示 Skia 在画布上清除一个 100x100 的矩形区域。最终，画布上对应区域的像素会被擦除。

* **假设输入 (页面失去焦点):** 用户切换到其他标签页或最小化浏览器窗口。
* **输出 (内部操作):** `CanvasRenderingContext2D::PageVisibilityChanged` 方法被调用，可能会触发一些优化操作，例如清理字体缓存以节省内存。

**用户或编程常见的使用错误：**

* **在上下文丢失后继续绘制：**  如果 GPU 资源不足或其他原因导致上下文丢失，尝试继续调用 `ctx.fillRect()` 等方法将不会有任何效果，甚至可能导致错误。开发者需要监听 `contextlost` 事件并进行适当处理。
* **不必要的频繁 `getImageData` 调用：**  `getImageData` 操作会复制画布的像素数据到内存中，是一个相对昂贵的操作。频繁调用会导致性能问题。
* **忘记处理字体加载：**  在绘制文本之前，需要确保字体已经加载完成。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个包含 `<canvas>` 元素的网页。**
2. **JavaScript 代码获取 `CanvasRenderingContext2D` 对象：** `const ctx = document.getElementById('myCanvas').getContext('2d');`
3. **JavaScript 代码调用 `CanvasRenderingContext2D` 的方法进行绘制：** 例如 `ctx.fillStyle = 'blue'; ctx.fillRect(20, 20, 80, 80);`
4. **Blink 渲染引擎接收到这些 JavaScript 调用。**
5. **JavaScript 调用会被桥接到 C++ 层的 `CanvasRenderingContext2D` 对象。**
6. **`CanvasRenderingContext2D` 对象调用 Skia 库进行实际的图形渲染。**
7. **如果发生上下文丢失 (例如 GPU 驱动崩溃)，Blink 会触发 `LoseContext` 方法。**
8. **如果页面重新可见，Blink 可能会尝试恢复上下文，调用 `RestoreProviderAndContextIfPossible`。**

**总结 (针对第 1 部分):**

这个代码文件 `canvas_rendering_context_2d.cc` 是 Chromium Blink 引擎中实现 HTML5 Canvas 2D 渲染上下文的核心组件。它负责处理 JavaScript API 调用，管理画布的状态和资源，并与底层的 Skia 图形库进行交互以完成实际的图形绘制。它还包含了处理上下文丢失和恢复的逻辑，确保了在异常情况下的鲁棒性。该文件是连接 JavaScript Canvas API 和底层图形渲染的关键桥梁。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012 Apple Inc.
 * All rights reserved.
 * Copyright (C) 2008, 2010 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2007 Alp Toker <alp@atoker.com>
 * Copyright (C) 2008 Eric Seidel <eric@webkit.org>
 * Copyright (C) 2008 Dirk Schulze <krit@webkit.org>
 * Copyright (C) 2010 Torch Mobile (Beijing) Co. Ltd. All rights reserved.
 * Copyright (C) 2012, 2013 Intel Corporation. All rights reserved.
 * Copyright (C) 2013 Adobe Systems Incorporated. All rights reserved.
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

#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h"

#include <stddef.h>

#include <optional>
#include <string_view>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"
#include "base/trace_event/common/trace_event_common.h"
#include "cc/layers/texture_layer.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "cc/layers/texture_layer_impl.h"
#include "cc/paint/paint_canvas.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "gpu/command_buffer/client/context_support.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/metrics/document_update_reason.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_token.h"
#include "third_party/blink/public/mojom/frame/color_scheme.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_enums.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_rendering_context_2d_settings.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_will_read_frequently.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_typedefs.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_canvasrenderingcontext2d_gpucanvascontext_imagebitmaprenderingcontext_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_context_creation_attributes_core.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_font_cache.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_performance_monitor.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_rect.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/map_coordinates_flags.h"
#include "third_party/blink/renderer/core/scroll/scroll_alignment.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/filter_operations.h"
#include "third_party/blink/renderer/core/svg/svg_resource_client.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_state.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/path_2d.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/canvas_2d_layer_bridge.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_context_rate_limiter.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_canvas.h"  // IWYU pragma: keep (https://github.com/clangd/clangd/issues/2044)
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_filter.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/stroke_data.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/hash_table.h"
#include "third_party/blink/renderer/platform/wtf/key_value_pair.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/skia/include/core/SkColor.h"
#include "third_party/skia/include/core/SkRect.h"
#include "third_party/skia/include/core/SkRefCnt.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size.h"

// UMA Histogram macros trigger a bug in IWYU.
// https://github.com/include-what-you-use/include-what-you-use/issues/1546
// IWYU pragma: no_include <atomic>
// IWYU pragma: no_include "base/metrics/histogram_base.h"

namespace base {
struct PendingTask;
}  // namespace base
namespace cc {
class PaintFlags;
}  // namespace cc

namespace blink {
class ExecutionContext;
class FontSelector;
class ImageData;
class ImageDataSettings;
class LayoutObject;
class SVGResource;

static mojom::blink::ColorScheme GetColorSchemeFromCanvas(
    HTMLCanvasElement* canvas) {
  if (canvas && canvas->isConnected()) {
    if (auto* style = canvas->GetComputedStyle()) {
      return style->UsedColorScheme();
    }
  }
  return mojom::blink::ColorScheme::kLight;
}

namespace {

gpu::ContextSupport* GetContextSupport() {
  if (!SharedGpuContext::ContextProviderWrapper()) {
    return nullptr;
  }
  return SharedGpuContext::ContextProviderWrapper()
      ->ContextProvider()
      ->ContextSupport();
}

}  // namespace

CanvasRenderingContext* CanvasRenderingContext2D::Factory::Create(
    CanvasRenderingContextHost* host,
    const CanvasContextCreationAttributesCore& attrs) {
  DCHECK(!host->IsOffscreenCanvas());
  CanvasRenderingContext* rendering_context =
      MakeGarbageCollected<CanvasRenderingContext2D>(
          static_cast<HTMLCanvasElement*>(host), attrs);
  DCHECK(rendering_context);
  return rendering_context;
}

CanvasRenderingContext2D::CanvasRenderingContext2D(
    HTMLCanvasElement* canvas,
    const CanvasContextCreationAttributesCore& attrs)
    : CanvasRenderingContext(canvas, attrs, CanvasRenderingAPI::k2D),
      BaseRenderingContext2D(
          canvas->GetDocument().GetTaskRunner(TaskType::kInternalDefault)),
      should_prune_local_font_cache_(false),
      color_params_(attrs.color_space, attrs.pixel_format, attrs.alpha) {
  identifiability_study_helper_.SetExecutionContext(
      canvas->GetTopExecutionContext());
  if (canvas->GetDocument().GetSettings() &&
      canvas->GetDocument().GetSettings()->GetAntialiasedClips2dCanvasEnabled())
    clip_antialiasing_ = kAntiAliased;
  SetShouldAntialias(true);
  ValidateStateStack();
}

V8RenderingContext* CanvasRenderingContext2D::AsV8RenderingContext() {
  return MakeGarbageCollected<V8RenderingContext>(this);
}

CanvasRenderingContext2D::~CanvasRenderingContext2D() = default;

bool CanvasRenderingContext2D::IsOriginTopLeft() const {
  // Use top-left origin since Skia Graphite won't support bottom-left origin.
  return true;
}

bool CanvasRenderingContext2D::IsComposited() const {
  // The following case is necessary for handling the special case of canvases
  // in the dev tools overlay.
  const HTMLCanvasElement* const element = canvas();
  auto* settings = element->GetDocument().GetSettings();
  if (settings && !settings->GetAcceleratedCompositingEnabled()) {
    return false;
  }
  return element->IsComposited();
}

void CanvasRenderingContext2D::Stop() {
  if (!isContextLost()) [[likely]] {
    // Never attempt to restore the context because the page is being torn down.
    context_restorable_ = false;
    LoseContext(kSyntheticLostContext);
  }
}

void CanvasRenderingContext2D::SendContextLostEventIfNeeded() {
  if (!needs_context_lost_event_)
    return;

  needs_context_lost_event_ = false;
  dispatch_context_lost_event_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void CanvasRenderingContext2D::LoseContext(LostContextMode lost_mode) {
  if (context_lost_mode_ != kNotLostContext)
    return;
  context_lost_mode_ = lost_mode;
  ResetInternal();
  HTMLCanvasElement* const element = canvas();
  if (element != nullptr) [[likely]] {
    if (context_lost_mode_ == kSyntheticLostContext) {
      element->DiscardResourceProvider();
    }

    if (element->IsPageVisible()) {
      dispatch_context_lost_event_timer_.StartOneShot(base::TimeDelta(),
                                                      FROM_HERE);
      return;
    }
  }
  needs_context_lost_event_ = true;
}

void CanvasRenderingContext2D::RestoreProviderAndContextIfPossible() {
  if (!context_restorable_)
    return;
  // This code path is for restoring from an eviction
  // Restoring from surface failure is handled internally
  DCHECK(context_lost_mode_ != kNotLostContext &&
         !canvas()->ResourceProvider());

  if (CanCreateCanvas2dResourceProvider()) {
    dispatch_context_restored_event_timer_.StartOneShot(base::TimeDelta(),
                                                        FROM_HERE);
  }
}

void CanvasRenderingContext2D::Trace(Visitor* visitor) const {
  visitor->Trace(filter_operations_);
  CanvasRenderingContext::Trace(visitor);
  BaseRenderingContext2D::Trace(visitor);
  SVGResourceClient::Trace(visitor);
}

void CanvasRenderingContext2D::TryRestoreContextEvent(TimerBase* timer) {
  if (context_lost_mode_ == kNotLostContext) {
    // Canvas was already restored (possibly thanks to a resize), so stop
    // trying.
    try_restore_context_event_timer_.Stop();
    return;
  }

  DCHECK(context_lost_mode_ != kWebGLLoseContextLostContext);

  // If lost mode is |kSyntheticLostContext| and |context_restorable_| is set to
  // true, it means context is forced to be lost for testing purpose. Restore
  // the context.
  if (context_lost_mode_ == kSyntheticLostContext) {
    if (Host()->GetOrCreateResourceProviderWithCurrentRasterModeHint()) {
      try_restore_context_event_timer_.Stop();
      DispatchContextRestoredEvent(nullptr);
      return;
    }
  }

  // If RealLostContext, it means the context was not lost due to surface
  // failure but rather due to a an eviction, which means image buffer exists.
  if (context_lost_mode_ == kRealLostContext && IsPaintable() && Restore()) {
    try_restore_context_event_timer_.Stop();
    DispatchContextRestoredEvent(nullptr);
    return;
  }

  // If it fails to restore the context, TryRestoreContextEvent again.
  if (++try_restore_context_attempt_count_ > kMaxTryRestoreContextAttempts) {
    // After 4 tries, we start the final attempt, allocate a brand new image
    // buffer instead of restoring
    try_restore_context_event_timer_.Stop();
    if (CanvasRenderingContextHost* host = Host()) [[likely]] {
      host->DiscardResourceProvider();
    }
    if (CanCreateCanvas2dResourceProvider())
      DispatchContextRestoredEvent(nullptr);
  }
}

bool CanvasRenderingContext2D::Restore() {
  CanvasRenderingContextHost* host = Host();
  CHECK(host);
  CHECK(host->context_lost());
  if (host->GetRasterMode() == RasterMode::kCPU) {
    return false;
  }
  DCHECK(!host->ResourceProvider());

  host->ClearLayerTexture();

  base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper =
      SharedGpuContext::ContextProviderWrapper();

  if (!context_provider_wrapper->ContextProvider()->IsContextLost()) {
    CanvasResourceProvider* resource_provider =
        host->GetOrCreateCanvasResourceProviderImpl(RasterModeHint::kPreferGPU);

    // The current paradigm does not support switching from accelerated to
    // non-accelerated, which would be tricky due to changes to the layer tree,
    // which can only happen at specific times during the document lifecycle.
    // Therefore, we can only accept the restored surface if it is accelerated.
    if (resource_provider && host->GetRasterMode() == RasterMode::kCPU) {
      host->ReplaceResourceProvider(nullptr);
      // FIXME: draw sad canvas picture into new buffer crbug.com/243842
    } else {
      host->set_context_lost(false);
    }
  }

  host->UpdateMemoryUsage();

  return host->ResourceProvider();
}

void CanvasRenderingContext2D::WillDrawImage(CanvasImageSource* source) const {
  canvas()->WillDrawImageTo2DContext(source);
}

bool CanvasRenderingContext2D::WritePixels(const SkImageInfo& orig_info,
                                           const void* pixels,
                                           size_t row_bytes,
                                           int x,
                                           int y) {
  DCHECK(IsPaintable());
  CanvasRenderingContextHost* host = Host();
  CHECK(host);

  CanvasResourceProvider* provider =
      canvas()->GetOrCreateResourceProviderWithCurrentRasterModeHint();
  if (provider == nullptr) {
    return false;
  }

  if (x <= 0 && y <= 0 && x + orig_info.width() >= host->Size().width() &&
      y + orig_info.height() >= host->Size().height()) {
    MemoryManagedPaintRecorder& recorder = provider->Recorder();
    if (recorder.HasSideRecording()) {
      // Even with opened layers, WritePixels would write to the main canvas
      // surface under the layers. We can therefore clear the paint ops recorded
      // before the first `beginLayer`, but the layers themselves must be kept
      // untouched. Note that this operation makes little sense and is actually
      // disabled in `putImageData` by raising an exception if layers are
      // opened. Still, it's preferable to handle this scenario here because the
      // alternative would be to crash or leave the canvas in an invalid state.
      recorder.ReleaseMainRecording();
    } else {
      recorder.RestartRecording();
    }
  } else {
    host->FlushRecording(FlushReason::kWritePixels);

    // Short-circuit out if an error occurred while flushing the recording.
    if (!host->ResourceProvider()->IsValid()) {
      return false;
    }
  }

  return host->ResourceProvider()->WritePixels(orig_info, pixels, row_bytes, x,
                                               y);
}

void CanvasRenderingContext2D::Reset() {
  // This is a multiple inheritance bootstrap
  BaseRenderingContext2D::ResetInternal();
}

void CanvasRenderingContext2D::RestoreCanvasMatrixClipStack(
    cc::PaintCanvas* c) const {
  RestoreMatrixClipStack(c);
}

bool CanvasRenderingContext2D::ShouldAntialias() const {
  return GetState().ShouldAntialias();
}

void CanvasRenderingContext2D::SetShouldAntialias(bool do_aa) {
  GetState().SetShouldAntialias(do_aa);
}

void CanvasRenderingContext2D::ScrollPathIntoViewInternal(const Path& path) {
  if (!IsTransformInvertible() || path.IsEmpty()) [[unlikely]] {
    return;
  }

  HTMLCanvasElement* const element = canvas();
  element->GetDocument().UpdateStyleAndLayout(
      DocumentUpdateReason::kJavaScript);

  LayoutObject* renderer = element->GetLayoutObject();
  LayoutBox* layout_box = element->GetLayoutBox();
  if (!renderer || !layout_box)
    return;

  const int width = Width();
  const int height = Height();
  if (width == 0 || height == 0) {
    return;
  }

  // Apply transformation and get the bounding rect
  Path transformed_path = path;
  transformed_path.Transform(GetState().GetTransform());
  gfx::RectF bounding_rect = transformed_path.BoundingRect();

  // We first map canvas coordinates to layout coordinates.
  PhysicalRect path_rect = PhysicalRect::EnclosingRect(bounding_rect);
  PhysicalRect canvas_rect = layout_box->PhysicalContentBoxRect();
  // TODO(fserb): Is this kIgnoreTransforms correct?
  canvas_rect.Move(
      layout_box->LocalToAbsolutePoint(PhysicalOffset(), kIgnoreTransforms));
  path_rect.SetX(
      (canvas_rect.X() + path_rect.X() * canvas_rect.Width() / width));
  path_rect.SetY(
      (canvas_rect.Y() + path_rect.Y() * canvas_rect.Height() / height));
  path_rect.SetWidth((path_rect.Width() * canvas_rect.Width() / width));
  path_rect.SetHeight((path_rect.Height() * canvas_rect.Height() / height));

  // Then we clip the bounding box to the canvas visible range.
  path_rect.Intersect(canvas_rect);

  // Horizontal text is aligned at the top of the screen
  mojom::blink::ScrollAlignment horizontal_scroll_mode =
      ScrollAlignment::ToEdgeIfNeeded();
  mojom::blink::ScrollAlignment vertical_scroll_mode =
      ScrollAlignment::TopAlways();

  // Vertical text needs be aligned horizontally on the screen
  bool is_horizontal_writing_mode =
      element->EnsureComputedStyle()->IsHorizontalWritingMode();
  if (!is_horizontal_writing_mode) {
    bool is_right_to_left =
        element->EnsureComputedStyle()->IsFlippedBlocksWritingMode();
    horizontal_scroll_mode = (is_right_to_left ? ScrollAlignment::RightAlways()
                                               : ScrollAlignment::LeftAlways());
    vertical_scroll_mode = ScrollAlignment::ToEdgeIfNeeded();
  }
  scroll_into_view_util::ScrollRectToVisible(
      *renderer, path_rect,
      scroll_into_view_util::CreateScrollIntoViewParams(
          horizontal_scroll_mode, vertical_scroll_mode,
          mojom::blink::ScrollType::kProgrammatic, false,
          mojom::blink::ScrollBehavior::kAuto));
}

void CanvasRenderingContext2D::clearRect(double x,
                                         double y,
                                         double width,
                                         double height) {
  BaseRenderingContext2D::clearRect(x, y, width, height);
}

sk_sp<PaintFilter> CanvasRenderingContext2D::StateGetFilter() {
  HTMLCanvasElement* const element = canvas();
  return GetState().GetFilter(element, element->Size(), this);
}

cc::PaintCanvas* CanvasRenderingContext2D::GetOrCreatePaintCanvas() {
  if (isContextLost()) [[unlikely]] {
    return nullptr;
  }

  Canvas2DLayerBridge* bridge = canvas()->GetOrCreateCanvas2DLayerBridge();
  if (bridge == nullptr) [[unlikely]] {
    return nullptr;
  }

  CanvasResourceProvider* provider = ResourceProvider();
  if (provider != nullptr) [[likely]] {
    // If we already had a provider, we can check whether it recorded ops passed
    // the autoflush limit.
    if (layer_count_ == 0) [[likely]] {
      // TODO(crbug.com/1246486): Make auto-flushing layer friendly.
      provider->FlushIfRecordingLimitExceeded();
    }
  } else {
    // If we have no provider, try creating one.
    provider = canvas()->GetOrCreateResourceProviderWithCurrentRasterModeHint();
    if (provider == nullptr) [[unlikely]] {
      return nullptr;
    }
  }

  return &provider->Recorder().getRecordingCanvas();
}

const cc::PaintCanvas* CanvasRenderingContext2D::GetPaintCanvas() const {
  if (isContextLost()) [[unlikely]] {
    return nullptr;
  }
  const CanvasResourceProvider* provider = ResourceProvider();
  if (!provider) [[unlikely]] {
    return nullptr;
  }
  return &provider->Recorder().getRecordingCanvas();
}

const MemoryManagedPaintRecorder* CanvasRenderingContext2D::Recorder() const {
  const CanvasResourceProvider* provider = ResourceProvider();
  if (provider == nullptr) [[unlikely]] {
    return nullptr;
  }
  return &provider->Recorder();
}

void CanvasRenderingContext2D::WillDraw(
    const SkIRect& dirty_rect,
    CanvasPerformanceMonitor::DrawType draw_type) {
  if (ShouldAntialias()) {
    SkIRect inflated_dirty_rect = dirty_rect.makeOutset(1, 1);
    CanvasRenderingContext::DidDraw(inflated_dirty_rect, draw_type);
  } else {
    CanvasRenderingContext::DidDraw(dirty_rect, draw_type);
  }
  // Always draw everything during printing.
  if (CanvasResourceProvider* provider = ResourceProvider();
      layer_count_ == 0 && provider != nullptr) [[likely]] {
    // TODO(crbug.com/1246486): Make auto-flushing layer friendly.
    provider->FlushIfRecordingLimitExceeded();
  }
}

std::optional<cc::PaintRecord> CanvasRenderingContext2D::FlushCanvas(
    FlushReason reason) {
  CanvasResourceProvider* provider = ResourceProvider();
  if (provider == nullptr) [[unlikely]] {
    return std::nullopt;
  }
  return provider->FlushCanvas(reason);
}

bool CanvasRenderingContext2D::WillSetFont() const {
  // The style resolution required for fonts is not available in frame-less
  // documents.
  const HTMLCanvasElement* const element = canvas();
  Document& document = element->GetDocument();
  if (!document.GetFrame()) {
    return false;
  }

  document.UpdateStyleAndLayoutTreeForElement(element,
                                              DocumentUpdateReason::kCanvas);
  return true;
}

bool CanvasRenderingContext2D::CurrentFontResolvedAndUpToDate() const {
  // An empty cache may indicate that a style change has occurred
  // which would require that the font be re-resolved. This check has to
  // come after the layout tree update in WillSetFont() to flush pending
  // style changes.
  return GetState().HasRealizedFont() &&
         fonts_resolved_using_current_style_.size() > 0;
}

void CanvasRenderingContext2D::setFontForTesting(const String& new_font) {
  // Dependency inversion to allow BaseRenderingContext2D::setFont
  // to be invoked from core unit tests.
  setFont(new_font);
}

bool CanvasRenderingContext2D::ResolveFont(const String& new_font) {
  HTMLCanvasElement* const element = canvas();
  Document& document = element->GetDocument();
  CanvasFontCache* canvas_font_cache = document.GetCanvasFontCache();

  // Map the <canvas> font into the text style. If the font uses keywords like
  // larger/smaller, these will work relative to the canvas.
  const ComputedStyle* computed_style = element->EnsureComputedStyle();
  if (computed_style) {
    auto i = fonts_resolved_using_current_style_.find(new_font);
    if (i != fonts_resolved_using_current_style_.end()) {
      auto add_result = font_lru_list_.PrependOrMoveToFirst(new_font);
      DCHECK(!add_result.is_new_entry);
      GetState().SetFont(i->value, Host()->GetFontSelector());
    } else {
      MutableCSSPropertyValueSet* parsed_style =
          canvas_font_cache->ParseFont(new_font);
      if (!parsed_style)
        return false;
      ComputedStyleBuilder font_style_builder =
          document.GetStyleResolver().CreateComputedStyleBuilder();
      FontDescription element_font_description(
          computed_style->GetFontDescription());
      // Reset the computed size to avoid inheriting the zoom factor from the
      // <canvas> element.
      element_font_description.SetComputedSize(
          element_font_description.SpecifiedSize());
      element_font_description.SetAdjustedSize(
          element_font_description.SpecifiedSize());

      font_style_builder.SetFontDescription(element_font_description);
      const ComputedStyle* font_style = font_style_builder.TakeStyle();
      Font font = document.GetStyleEngine().ComputeFont(*element, *font_style,
                                                        *parsed_style);

      // We need to reset Computed and Adjusted size so we skip zoom and
      // minimum font size.
      FontDescription final_description(font.GetFontDescription());
      final_description.SetComputedSize(final_description.SpecifiedSize());
      final_description.SetAdjustedSize(final_description.SpecifiedSize());

      fonts_resolved_using_current_style_.insert(new_font, final_description);
      auto add_result = font_lru_list_.PrependOrMoveToFirst(new_font);
      DCHECK(add_result.is_new_entry);
      PruneLocalFontCache(canvas_font_cache->HardMaxFonts());  // hard limit
      should_prune_local_font_cache_ = true;  // apply soft limit
      GetState().SetFont(final_description, Host()->GetFontSelector());
    }
  } else {
    Font resolved_font;
    if (!canvas_font_cache->GetFontUsingDefaultStyle(*element, new_font,
                                                     resolved_font)) {
      return false;
    }

    // We need to reset Computed and Adjusted size so we skip zoom and
    // minimum font size for detached canvas.
    FontDescription final_description(resolved_font.GetFontDescription());
    final_description.SetComputedSize(final_description.SpecifiedSize());
    final_description.SetAdjustedSize(final_description.SpecifiedSize());
    GetState().SetFont(final_description, Host()->GetFontSelector());
  }
  return true;
}

void CanvasRenderingContext2D::DidProcessTask(
    const base::PendingTask& pending_task) {
  CanvasRenderingContext::DidProcessTask(pending_task);
  // This should be the only place where canvas() needs to be checked for
  // nullness because the circular refence with HTMLCanvasElement means the
  // canvas and the context keep each other alive. As long as the pair is
  // referenced, the task observer is the only persistent refernce to this
  // object
  // that is not traced, so didProcessTask() may be called at a time when the
  // canvas has been garbage collected but not the context.
  const HTMLCanvasElement* const element = canvas();
  if (should_prune_local_font_cache_) {
    if (element != nullptr) [[likely]] {
      should_prune_local_font_cache_ = false;
      PruneLocalFontCache(
          element->GetDocument().GetCanvasFontCache()->MaxFonts());
    }
  }
}

void CanvasRenderingContext2D::PruneLocalFontCache(size_t target_size) {
  if (target_size == 0) {
    // Short cut: LRU does not matter when evicting everything
    font_lru_list_.clear();
    fonts_resolved_using_current_style_.clear();
    return;
  }
  while (font_lru_list_.size() > target_size) {
    fonts_resolved_using_current_style_.erase(font_lru_list_.back());
    font_lru_list_.pop_back();
  }
}

void CanvasRenderingContext2D::StyleDidChange(const ComputedStyle* old_style,
                                              const ComputedStyle& new_style) {
  if (old_style && old_style->GetFont() == new_style.GetFont())
    return;
  PruneLocalFontCache(0);
}

void CanvasRenderingContext2D::ClearFilterReferences() {
  filter_operations_.RemoveClient(*this);
  filter_operations_.clear();
}

void CanvasRenderingContext2D::UpdateFilterReferences(
    const FilterOperations& filters) {
  filters.AddClient(*this);
  ClearFilterReferences();
  filter_operations_ = filters;
}

void CanvasRenderingContext2D::ResourceContentChanged(SVGResource*) {
  ClearFilterReferences();
  GetState().ClearResolvedFilter();
}

bool CanvasRenderingContext2D::OriginClean() const {
  return Host()->OriginClean();
}

void CanvasRenderingContext2D::SetOriginTainted() {
  Host()->SetOriginTainted();
}

int CanvasRenderingContext2D::Width() const {
  return Host()->Size().width();
}

int CanvasRenderingContext2D::Height() const {
  return Host()->Size().height();
}

bool CanvasRenderingContext2D::CanCreateCanvas2dResourceProvider() const {
  return canvas()->GetOrCreateCanvas2DLayerBridge();
}

scoped_refptr<StaticBitmapImage> blink::CanvasRenderingContext2D::GetImage(
    FlushReason reason) {
  CanvasHibernationHandler* hibernation_handler =
      canvas()->GetHibernationHandler();
  if (!hibernation_handler) {
    return nullptr;
  }

  if (hibernation_handler->IsHibernating()) {
    return UnacceleratedStaticBitmapImage::Create(
        hibernation_handler->GetImage());
  }

  if (!Host()->IsResourceValid()) {
    return nullptr;
  }
  // GetOrCreateResourceProvider needs to be called before FlushRecording, to
  // make sure "hint" is properly taken into account.
  if (!Host()->GetOrCreateResourceProviderWithCurrentRasterModeHint()) {
    return nullptr;
  }
  Host()->FlushRecording(reason);
  return Host()->ResourceProvider()->Snapshot(reason);
}

ImageData* CanvasRenderingContext2D::getImageDataInternal(
    int sx,
    int sy,
    int sw,
    int sh,
    ImageDataSettings* image_data_settings,
    ExceptionState& exception_state) {
  UMA_HISTOGRAM_BOOLEAN(
      "Blink.Canvas.GetImageData.WillReadFrequently",
      CreationAttributes().will_read_frequently ==
          CanvasContextCreationAttributesCore::WillReadFrequently::kTrue);
  return BaseRenderingContext2D::getImageDataInternal(
      sx, sy, sw, sh, image_data_settings, exception_state);
}

void CanvasRenderingContext2D::FinalizeFrame(FlushReason reason) {
  TRACE_EVENT0("blink", "CanvasRenderingContext2D::FinalizeFrame");
  if (!IsPaintable()) {
    return;
  }

  // Make sure surface is ready for painting: fix the rendering mode now
  // because it will be too late during the paint invalidation phase.
  if (!canvas()->GetOrCreateResourceProviderWithCurrentRasterModeHint()) {
    return;
  }

  CanvasRenderingContextHost* host = Host();
  CHECK(host);

  host->FlushRecording(reason);
  if (reason == FlushReason::kCanvasPushFrame) {
    if (host->IsDisplayed()) {
      // Make sure the GPU is never more than two animation frames behind.
      constexpr unsigned kMaxCanvasAnimationBacklog = 2;
      if (host->IncrementFramesSinceLastCommit() >=
          static_cast<int>(kMaxCanvasAnimationBacklog)) {
        if (host->IsComposited() && !host->RateLimiter()) {
          host->CreateRateLimiter();
        }
      }
    }

    if (host->RateLimiter()) {
      host->RateLimiter()->Tick();
    }
  }
}

CanvasRenderingContextHost*
CanvasRenderingContext2D::GetCanvasRenderingContextHost() const {
  return Host();
}

ExecutionContext* CanvasRenderingContext2D::GetTopExecutionContext() const {
  return Host()->GetTopExecutionContext();
}

Color CanvasRenderingContext2D::GetCurrentColor() const {
  const HTMLCanvasElement* const element = canvas();
  if (!element || !element->isConnected() || !element->InlineStyle()) {
    return Color::kBlack;
  }
  Color color = Color::kBlack;
  CSSParser::ParseColor(
      color, element->InlineStyle()->GetPropertyValue(CSSPropertyID::kColor));
  return color;
}

void CanvasRenderingContext2D::PageVisibilityChanged() {
  HTMLCanvasElement* const element = canvas();
  if (IsPaintable()) {
    OnPageVisibilityChangeWhenPaintable();
  }
  if (!element->IsPageVisible()) {
    PruneLocalFontCache(0);
  }
}

void CanvasRenderingContext2D::OnPageVisibilityChangeWhenPaintable() {
```
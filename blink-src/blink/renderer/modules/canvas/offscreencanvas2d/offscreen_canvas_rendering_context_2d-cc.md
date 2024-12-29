Response:
My thinking process to analyze the C++ code and answer the user's request goes through several stages:

1. **Understanding the Request:**  The user wants to understand the functionality of `offscreen_canvas_rendering_context_2d.cc` in the Chromium Blink engine. They're specifically interested in its relationship to JavaScript, HTML, CSS, debugging information, common errors, and user actions leading to this code.

2. **Initial Code Scan and Keyword Recognition:** I quickly scan the code for prominent keywords and class names. This gives me a high-level overview:
    * `OffscreenCanvasRenderingContext2D`: This is the core class, so its methods and members are central to the functionality.
    * `#include`:  The included headers hint at dependencies and related functionalities. For example, `CanvasRenderingContext.h`, `base/metrics/histogram_functions.h`, `third_party/blink/public/common/features.h`, and various platform/graphics headers suggest interaction with other parts of the rendering engine, metrics, feature flags, and graphics libraries.
    * `namespace blink`: This confirms it's part of the Blink rendering engine.
    * Methods like `fillRect`, `strokeRect`, `fillText`, `drawImage`, `getImageData`, `putImageData`, `getContextAttributes`, `transferToImageBitmap`, `pushFrame`, `loseContext`, `restoreContext`: These are typical 2D canvas API methods, suggesting this class implements the 2D rendering context for offscreen canvases.
    * Mentions of `OffscreenCanvas`, `CanvasResourceProvider`, `PaintCanvas`, `Skia`, `FontDescription`, `FontSelector`: These indicate interactions with canvas objects, resource management, the Skia graphics library, and font handling.

3. **Identifying Core Functionality:** Based on the keywords and the structure of the code, I deduce the primary purpose: This file implements the 2D rendering context for `OffscreenCanvas` in Blink. It provides the core drawing capabilities of the 2D Canvas API but for canvases not directly attached to the DOM.

4. **Analyzing Key Methods and Concepts:** I dive deeper into specific methods and concepts to understand their roles:
    * **`Factory::Create`:** This is the standard factory pattern for creating instances of the class.
    * **Constructor/Destructor:** Handles initialization and cleanup.
    * **`FinalizeFrame`:** Likely prepares the rendering commands for execution.
    * **`PushFrame`:**  Crucial for committing the rendered content. It involves transferring the rendered output to where it can be consumed (e.g., for display or further processing).
    * **`TransferToImageBitmap`:**  A key feature of `OffscreenCanvas`, allowing efficient transfer of rendered content to an `ImageBitmap`.
    * **`GetImage`:** Retrieves a snapshot of the canvas content.
    * **`LoseContext`/`RestoreContext`:**  Handles cases where the underlying graphics context is lost and needs to be restored.
    * **Font handling (using `OffscreenFontCache`, `FontDescription`, `FontSelector`):** Shows how the context manages and resolves font information.
    * **`CanvasResourceProvider`:**  A central component responsible for managing the underlying graphics resources (textures, buffers, etc.).
    * **Dirty region tracking (`dirty_rect_for_commit_`):** Optimizes rendering by only updating the changed parts of the canvas.

5. **Relating to JavaScript, HTML, and CSS:** I connect the C++ implementation to the corresponding web technologies:
    * **JavaScript:** The methods in this C++ file directly correspond to the JavaScript `OffscreenCanvasRenderingContext2D` API. Examples: `fillRect` in C++ is called when the JavaScript `context.fillRect()` is invoked.
    * **HTML:** The `OffscreenCanvas` element in HTML creates the underlying object that this rendering context operates on.
    * **CSS:** CSS affects text rendering (font styles, sizes, colors) and potentially other visual aspects of the canvas. The code explicitly interacts with CSS parsing and font resolution.

6. **Inferring Logic and Providing Examples:** I consider the logical flow within the methods and invent simple scenarios to illustrate input and output:
    * **`ResolveFont`:** Input: a font string like "Arial 16px". Output: A `FontDescription` object.
    * **Drawing operations:** Input: drawing commands (e.g., `fillRect(10, 10, 50, 50)`). Output: Modifications to the underlying `PaintCanvas`.

7. **Identifying Potential Errors:** Based on my understanding of the API and the code, I consider common user mistakes:
    * Calling methods after the context is lost.
    * Using invalid input parameters (e.g., negative dimensions).
    * Not handling context loss events.

8. **Debugging and User Actions:** I think about how a developer might end up looking at this specific C++ file during debugging:
    * Setting breakpoints in the JavaScript `OffscreenCanvasRenderingContext2D` methods and stepping into the native code.
    * Examining crash reports or logs that point to this file.
    * Investigating performance issues related to canvas rendering.

9. **Structuring the Answer:** Finally, I organize my findings into a clear and comprehensive answer, using headings and bullet points for readability. I ensure I address all aspects of the user's request, including functionality, relationships to web technologies, logical examples, error scenarios, and debugging. I prioritize clarity and provide concrete examples where possible.

This iterative process of scanning, analyzing, connecting, and inferring allows me to build a detailed understanding of the C++ code and its role within the broader web ecosystem.
这个C++文件 `offscreen_canvas_rendering_context_2d.cc` 是 Chromium Blink 渲染引擎的一部分，它实现了 **OffscreenCanvasRenderingContext2D** 接口的功能。 这个接口允许在不连接到 DOM 的情况下（比如在 Web Worker 中）进行 2D 图形绘制。

以下是该文件的主要功能：

**1. 实现 OffscreenCanvas 的 2D 渲染上下文:**

*   **提供 2D 绘图 API:**  这个文件实现了 JavaScript 中 `OffscreenCanvasRenderingContext2D` 对象暴露的各种 2D 绘图方法，例如：
    *   `fillRect()`: 填充矩形。
    *   `strokeRect()`: 绘制矩形边框。
    *   `fillText()`: 绘制填充文本。
    *   `strokeText()`: 绘制文本边框。
    *   `drawImage()`: 绘制图像。
    *   `beginPath()`, `moveTo()`, `lineTo()`, `closePath()`, `stroke()`, `fill()`: 路径绘制相关方法。
    *   `arc()`, `quadraticCurveTo()`, `bezierCurveTo()`: 绘制弧线和曲线。
    *   `translate()`, `rotate()`, `scale()`, `transform()`, `setTransform()`: 变换操作。
    *   `save()`, `restore()`: 保存和恢复绘图状态。
    *   `createLinearGradient()`, `createRadialGradient()`: 创建线性渐变和径向渐变。
    *   `createPattern()`: 创建图案填充。
    *   `clearRect()`: 清空矩形区域。
    *   `getImageData()`, `putImageData()`: 获取和设置像素数据。
    *   `getContextAttributes()`: 获取上下文属性。
    *   `isPointInPath()`, `isPointInStroke()`: 判断点是否在路径或描边内。
    *   `measureText()`: 测量文本尺寸。
*   **管理绘图状态:**  它维护着当前绘图上下文的状态，包括填充颜色、描边颜色、线宽、字体、变换矩阵等。
*   **与底层图形库交互:**  它使用 Skia 图形库进行实际的绘制操作。
*   **处理上下文生命周期:**  包括创建、销毁、以及处理上下文丢失和恢复事件。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **JavaScript:**  `OffscreenCanvasRenderingContext2D.cc` 是 JavaScript `OffscreenCanvasRenderingContext2D` API 的底层实现。当 JavaScript 代码调用 `offscreenCanvas.getContext('2d')` 获取到 2D 渲染上下文对象，并调用其上的方法时，最终会调用到这个 C++ 文件中的相应实现。

    *   **例子:**  在 JavaScript 中调用 `context.fillRect(10, 10, 50, 50)` 会触发 `OffscreenCanvasRenderingContext2D::WillDraw` 和底层的 Skia 绘制调用来填充一个矩形。

*   **HTML:**  虽然 `OffscreenCanvas` 不直接连接到 DOM，但它可以通过 JavaScript 创建并传递数据。  这个 C++ 文件处理的是 `OffscreenCanvas` 的渲染逻辑，而 `OffscreenCanvas` 对象本身可以通过 HTML 中的 `<canvas>` 元素或者在 JavaScript 中创建。

    *   **例子:**  尽管这个文件是针对 OffscreenCanvas 的，但其 2D 绘图的 API 与普通的 `<canvas>` 元素的 2D 上下文 API 非常相似。  `OffscreenCanvas` 的内容最终可以通过 `transferToImageBitmap()` 方法转换为 `ImageBitmap`，然后可以用在 HTML 的 `<img>` 标签或者另一个 Canvas 中。

*   **CSS:** CSS 可以影响 `OffscreenCanvas` 中文本的渲染。例如，可以通过 CSS 设置字体家族、大小、样式等。 当 JavaScript 代码设置 `context.font` 属性时，这个 C++ 文件会解析这个字符串，并使用 CSS 引擎来查找和加载相应的字体。

    *   **例子:**  JavaScript 代码 `context.font = 'bold 16px Arial';` 会触发 `OffscreenCanvasRenderingContext2D::ResolveFont` 方法，该方法会使用 CSS 解析器来解析字体字符串，并查找名为 "Arial" 的字体。

**3. 逻辑推理与假设输入输出:**

*   **假设输入:**  JavaScript 调用 `context.fillStyle = 'red'; context.fillRect(0, 0, 100, 100);`
*   **逻辑推理:**
    1. `context.fillStyle = 'red';`  会设置 `OffscreenCanvasRenderingContext2D` 对象的内部状态，将填充颜色设置为红色。
    2. `context.fillRect(0, 0, 100, 100);` 会调用 `OffscreenCanvasRenderingContext2D::WillDraw`，并最终调用 Skia 的绘制函数，使用当前填充颜色（红色）在坐标 (0, 0) 绘制一个 100x100 的矩形。
*   **假设输出:**  `OffscreenCanvas` 的底层图形缓冲区中，坐标 (0, 0) 到 (100, 100) 的区域会被填充为红色像素。

*   **假设输入:** JavaScript 调用 `context.font = 'italic 20px "Times New Roman"';`
*   **逻辑推理:**
    1. `context.font = ...` 会调用 `OffscreenCanvasRenderingContext2D::ResolveFont`。
    2. `ResolveFont` 会解析字体字符串，并尝试从字体缓存中查找或通过 `FontSelector` 获取对应的 `FontDescription` 对象。
*   **假设输出:**  `OffscreenCanvasRenderingContext2D` 对象的状态中，字体信息会被更新为斜体的 20px Times New Roman 字体。后续的文本绘制操作将使用这个字体。

**4. 用户或编程常见的使用错误:**

*   **在上下文丢失后尝试绘图:** 当 `OffscreenCanvas` 的底层图形资源丢失时（例如，由于 GPU 资源不足），渲染上下文会失效。如果 JavaScript 代码没有正确处理 `contextlost` 事件并继续调用绘图方法，这些调用将不会有效果，或者可能抛出异常。

    *   **例子:**
        ```javascript
        const canvas = new OffscreenCanvas(200, 100);
        const ctx = canvas.getContext('2d');
        canvas.addEventListener('contextlost', (event) => {
          console.log('Context lost!');
          event.preventDefault(); // 阻止浏览器默认的上下文恢复行为
          // ... 尝试恢复上下文的逻辑 ...
        });

        // ... 一段时间后，上下文可能丢失 ...

        ctx.fillRect(0, 0, 50, 50); // 如果上下文丢失，这次调用无效
        ```

*   **使用无效的字体字符串:** 如果 JavaScript 代码设置了无法解析或不存在的字体字符串，`ResolveFont` 方法可能会失败，导致文本使用默认字体渲染。

    *   **例子:**
        ```javascript
        const canvas = new OffscreenCanvas(200, 100);
        const ctx = canvas.getContext('2d');
        ctx.font = 'nonExistentFont 12px'; // 可能会导致使用默认字体
        ctx.fillText('Hello', 10, 20);
        ```

*   **在 Web Worker 中错误地操作 DOM:**  `OffscreenCanvas` 的一个主要用途是在 Web Worker 中进行渲染。在 Worker 中直接访问或修改 DOM 是不允许的。应该使用 `postMessage` 等机制将渲染结果（例如，通过 `transferToImageBitmap()` 获取的 `ImageBitmap`）传递回主线程进行显示。

    *   **错误例子 (在 Worker 中):**
        ```javascript
        // worker.js
        const canvas = new OffscreenCanvas(200, 100);
        const ctx = canvas.getContext('2d');
        ctx.fillRect(0, 0, 50, 50);
        document.body.appendChild(canvas); // 错误！无法在 Worker 中操作 DOM
        ```

**5. 用户操作如何一步步到达这里 (调试线索):**

1. **用户交互或脚本执行:** 用户与网页交互（例如，点击按钮、滚动页面），或者 JavaScript 代码定时执行，触发了需要在后台进行图形渲染的操作。
2. **创建 OffscreenCanvas:** JavaScript 代码创建了一个 `OffscreenCanvas` 对象。
    ```javascript
    const offscreenCanvas = new OffscreenCanvas(width, height);
    ```
3. **获取 2D 渲染上下文:**  JavaScript 代码调用 `getContext('2d')` 获取 `OffscreenCanvasRenderingContext2D` 对象。
    ```javascript
    const ctx = offscreenCanvas.getContext('2d');
    ```
4. **调用 2D 绘图方法:** JavaScript 代码调用 `ctx` 上的各种绘图方法，例如 `fillRect()`, `stroke()`, `fillText()` 等。
    ```javascript
    ctx.fillStyle = 'blue';
    ctx.fillRect(10, 10, 80, 40);
    ```
5. **Blink 引擎处理 JavaScript 调用:**  当 JavaScript 引擎执行这些方法时，会通过 Blink 的绑定机制，将调用转发到对应的 C++ 实现，即 `offscreen_canvas_rendering_context_2d.cc` 中的方法。
6. **Skia 库进行实际绘制:**  `OffscreenCanvasRenderingContext2D` 的 C++ 代码会调用 Skia 库的接口，将绘图指令转换为底层的图形操作，最终修改 `OffscreenCanvas` 关联的图形缓冲区。
7. **可能涉及的调试步骤:**
    *   **在 JavaScript 代码中设置断点:** 开发者可以在 JavaScript 中调用 `OffscreenCanvasRenderingContext2D` 方法的地方设置断点，观察参数传递和执行流程。
    *   **使用 Chrome 的开发者工具:**  Performance 面板可以帮助分析 Canvas 渲染的性能瓶颈。
    *   **在 C++ 代码中设置断点:**  如果需要深入了解 Blink 引擎的内部实现，开发者可以在 `offscreen_canvas_rendering_context_2d.cc` 中相关的 C++ 方法设置断点，例如 `WillDraw`, `DrawRect`, `ResolveFont` 等，来跟踪执行过程和变量状态。这通常需要编译 Chromium 源码。
    *   **查看 Chromium 的 tracing 信息:**  Chromium 提供了 tracing 功能，可以记录 Blink 引擎内部的各种事件，包括 Canvas 相关的操作，可以帮助理解渲染流程。

总而言之，`offscreen_canvas_rendering_context_2d.cc` 是 Chromium Blink 引擎中实现 `OffscreenCanvas` 2D 渲染的核心组件，它负责处理 JavaScript 的绘图指令，与底层图形库交互，并管理 Canvas 的状态。理解这个文件有助于深入理解 Web 平台的 2D 图形渲染机制。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.h"

#include "base/metrics/histogram_functions.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_font_stretch.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_canvas_text_rendering.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_gpucanvascontext_imagebitmaprenderingcontext_offscreencanvasrenderingcontext2d_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/core/css/offscreen_font_selector.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/resolver/font_style_resolver.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/canvas/text_metrics.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_settings.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/graphics_types.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/linked_hash_set.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace {
const size_t kHardMaxCachedFonts = 250;
const size_t kMaxCachedFonts = 25;
// Max delay to fire context lost for context in iframes.
static const unsigned kMaxIframeContextLoseDelay = 100;

class OffscreenFontCache {
 public:
  void PruneLocalFontCache(size_t target_size) {
    while (font_lru_list_.size() > target_size) {
      fonts_resolved_.erase(font_lru_list_.back());
      font_lru_list_.pop_back();
    }
  }

  void AddFont(String name, blink::FontDescription font) {
    fonts_resolved_.insert(name, font);
    auto add_result = font_lru_list_.PrependOrMoveToFirst(name);
    DCHECK(add_result.is_new_entry);
    PruneLocalFontCache(kHardMaxCachedFonts);
  }

  blink::FontDescription* GetFont(String name) {
    auto i = fonts_resolved_.find(name);
    if (i != fonts_resolved_.end()) {
      auto add_result = font_lru_list_.PrependOrMoveToFirst(name);
      DCHECK(!add_result.is_new_entry);
      return &(i->value);
    }
    return nullptr;
  }

 private:
  HashMap<String, blink::FontDescription> fonts_resolved_;
  LinkedHashSet<String> font_lru_list_;
};

OffscreenFontCache& GetOffscreenFontCache() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<OffscreenFontCache>,
                                  thread_specific_pool, ());
  return *thread_specific_pool;
}

}  // namespace

namespace blink {

CanvasRenderingContext* OffscreenCanvasRenderingContext2D::Factory::Create(
    CanvasRenderingContextHost* host,
    const CanvasContextCreationAttributesCore& attrs) {
  DCHECK(host->IsOffscreenCanvas());
  CanvasRenderingContext* rendering_context =
      MakeGarbageCollected<OffscreenCanvasRenderingContext2D>(
          static_cast<OffscreenCanvas*>(host), attrs);
  DCHECK(rendering_context);
  return rendering_context;
}

OffscreenCanvasRenderingContext2D::~OffscreenCanvasRenderingContext2D() =
    default;

OffscreenCanvasRenderingContext2D::OffscreenCanvasRenderingContext2D(
    OffscreenCanvas* canvas,
    const CanvasContextCreationAttributesCore& attrs)
    : CanvasRenderingContext(canvas, attrs, CanvasRenderingAPI::k2D),
      BaseRenderingContext2D(canvas->GetTopExecutionContext()->GetTaskRunner(
          TaskType::kInternalDefault)),
      color_params_(attrs.color_space, attrs.pixel_format, attrs.alpha) {
  identifiability_study_helper_.SetExecutionContext(
      canvas->GetTopExecutionContext());
  is_valid_size_ = IsValidImageSize(Host()->Size());

  // Clear the background transparent or opaque.
  if (IsCanvas2DBufferValid())
    DidDraw(CanvasPerformanceMonitor::DrawType::kOther);

  ExecutionContext* execution_context = canvas->GetTopExecutionContext();
  if (auto* window = DynamicTo<LocalDOMWindow>(execution_context)) {
    if (window->GetFrame() && window->GetFrame()->GetSettings() &&
        window->GetFrame()->GetSettings()->GetDisableReadingFromCanvas())
      canvas->SetDisableReadingFromCanvasTrue();
    return;
  }
  dirty_rect_for_commit_.setEmpty();
  WorkerSettings* worker_settings =
      To<WorkerGlobalScope>(execution_context)->GetWorkerSettings();
  if (worker_settings && worker_settings->DisableReadingFromCanvas())
    canvas->SetDisableReadingFromCanvasTrue();
}

void OffscreenCanvasRenderingContext2D::Trace(Visitor* visitor) const {
  CanvasRenderingContext::Trace(visitor);
  BaseRenderingContext2D::Trace(visitor);
}

void OffscreenCanvasRenderingContext2D::FinalizeFrame(FlushReason reason) {
  TRACE_EVENT0("blink", "OffscreenCanvasRenderingContext2D::FinalizeFrame");

  // Make sure surface is ready for painting: fix the rendering mode now
  // because it will be too late during the paint invalidation phase.
  if (!GetOrCreateCanvasResourceProvider())
    return;
  Host()->FlushRecording(reason);
}

// BaseRenderingContext2D implementation
bool OffscreenCanvasRenderingContext2D::OriginClean() const {
  return Host()->OriginClean();
}

void OffscreenCanvasRenderingContext2D::SetOriginTainted() {
  Host()->SetOriginTainted();
}

int OffscreenCanvasRenderingContext2D::Width() const {
  return Host()->Size().width();
}

int OffscreenCanvasRenderingContext2D::Height() const {
  return Host()->Size().height();
}

bool OffscreenCanvasRenderingContext2D::CanCreateCanvas2dResourceProvider()
    const {
  const CanvasRenderingContextHost* const host = Host();
  if (host == nullptr || host->Size().IsEmpty()) [[unlikely]] {
    return false;
  }
  return !!GetOrCreateCanvasResourceProvider();
}

CanvasResourceProvider*
OffscreenCanvasRenderingContext2D::GetOrCreateCanvasResourceProvider() const {
  DCHECK(Host() && Host()->IsOffscreenCanvas());
  OffscreenCanvas* host = HostAsOffscreenCanvas();
  if (host == nullptr) [[unlikely]] {
    return nullptr;
  }
  host->CheckForGpuContextLost();
  return host->GetOrCreateResourceProvider();
}

CanvasResourceProvider*
OffscreenCanvasRenderingContext2D::GetCanvasResourceProvider() const {
  return Host()->ResourceProvider();
}

void OffscreenCanvasRenderingContext2D::Reset() {
  Host()->DiscardResourceProvider();
  BaseRenderingContext2D::ResetInternal();
  // Because the host may have changed to a zero size
  is_valid_size_ = IsValidImageSize(Host()->Size());
  // We must resize the damage rect to avoid a potentially larger damage than
  // actual canvas size. See: crbug.com/1227165
  dirty_rect_for_commit_ = SkIRect::MakeWH(Width(), Height());
}

scoped_refptr<CanvasResource>
OffscreenCanvasRenderingContext2D::ProduceCanvasResource(FlushReason reason) {
  CanvasResourceProvider* provider = GetOrCreateCanvasResourceProvider();
  if (!provider) {
    return nullptr;
  }
  scoped_refptr<CanvasResource> frame = provider->ProduceCanvasResource(reason);
  if (!frame)
    return nullptr;

  frame->SetOriginClean(OriginClean());
  return frame;
}

bool OffscreenCanvasRenderingContext2D::PushFrame() {
  if (dirty_rect_for_commit_.isEmpty())
    return false;

  SkIRect damage_rect(dirty_rect_for_commit_);
  FinalizeFrame(FlushReason::kOffscreenCanvasPushFrame);
  bool ret = Host()->PushFrame(
      ProduceCanvasResource(FlushReason::kOffscreenCanvasPushFrame),
      damage_rect);
  dirty_rect_for_commit_.setEmpty();
  GetOffscreenFontCache().PruneLocalFontCache(kMaxCachedFonts);
  return ret;
}

CanvasRenderingContextHost*
OffscreenCanvasRenderingContext2D::GetCanvasRenderingContextHost() const {
  return Host();
}
ExecutionContext* OffscreenCanvasRenderingContext2D::GetTopExecutionContext()
    const {
  return Host()->GetTopExecutionContext();
}

ImageBitmap* OffscreenCanvasRenderingContext2D::TransferToImageBitmap(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  WebFeature feature = WebFeature::kOffscreenCanvasTransferToImageBitmap2D;
  UseCounter::Count(ExecutionContext::From(script_state), feature);

  if (layer_count_ != 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "`transferToImageBitmap()` cannot be called while layers are opened.");
    return nullptr;
  }

  if (!GetOrCreateCanvasResourceProvider())
    return nullptr;
  scoped_refptr<StaticBitmapImage> image = GetImage(FlushReason::kTransfer);
  if (!image)
    return nullptr;
  image->SetOriginClean(OriginClean());
  // Before discarding the image resource, we need to flush pending render ops
  // to fully resolve the snapshot.
  image->PaintImageForCurrentFrame().FlushPendingSkiaOps();

  Host()->DiscardResourceProvider();

  return MakeGarbageCollected<ImageBitmap>(std::move(image));
}

scoped_refptr<StaticBitmapImage> OffscreenCanvasRenderingContext2D::GetImage(
    FlushReason reason) {
  FinalizeFrame(reason);
  if (!IsPaintable())
    return nullptr;
  scoped_refptr<StaticBitmapImage> image =
      GetCanvasResourceProvider()->Snapshot(reason);

  return image;
}

V8RenderingContext* OffscreenCanvasRenderingContext2D::AsV8RenderingContext() {
  return nullptr;
}

V8OffscreenRenderingContext*
OffscreenCanvasRenderingContext2D::AsV8OffscreenRenderingContext() {
  return MakeGarbageCollected<V8OffscreenRenderingContext>(this);
}

Color OffscreenCanvasRenderingContext2D::GetCurrentColor() const {
  return Color::kBlack;
}

cc::PaintCanvas* OffscreenCanvasRenderingContext2D::GetOrCreatePaintCanvas() {
  if (!is_valid_size_ || isContextLost() ||
      !GetOrCreateCanvasResourceProvider()) [[unlikely]] {
    return nullptr;
  }
  return GetPaintCanvas();
}

const cc::PaintCanvas* OffscreenCanvasRenderingContext2D::GetPaintCanvas()
    const {
  if (!is_valid_size_ || isContextLost()) [[unlikely]] {
    return nullptr;
  }
  CanvasResourceProvider* const provider = GetCanvasResourceProvider();
  if (provider == nullptr) [[unlikely]] {
    return nullptr;
  }
  return &provider->Canvas();
}

const MemoryManagedPaintRecorder* OffscreenCanvasRenderingContext2D::Recorder()
    const {
  const CanvasResourceProvider* provider = GetCanvasResourceProvider();
  if (provider == nullptr) [[unlikely]] {
    return nullptr;
  }
  return &provider->Recorder();
}

void OffscreenCanvasRenderingContext2D::WillDraw(
    const SkIRect& dirty_rect,
    CanvasPerformanceMonitor::DrawType draw_type) {
  // Call sites should ensure GetPaintCanvas() returns non-null before calling
  // this.
  DCHECK(GetPaintCanvas());
  dirty_rect_for_commit_.join(dirty_rect);
  GetCanvasPerformanceMonitor().DidDraw(draw_type);
  if (GetState().ShouldAntialias()) {
    SkIRect inflated_dirty_rect = dirty_rect_for_commit_.makeOutset(1, 1);
    Host()->DidDraw(inflated_dirty_rect);
  } else {
    Host()->DidDraw(dirty_rect_for_commit_);
  }
  if (!layer_count_) {
    // TODO(crbug.com/1246486): Make auto-flushing layer friendly.
    GetCanvasResourceProvider()->FlushIfRecordingLimitExceeded();
  }
}

sk_sp<PaintFilter> OffscreenCanvasRenderingContext2D::StateGetFilter() {
  return GetState().GetFilterForOffscreenCanvas(Host()->Size(), this);
}

void OffscreenCanvasRenderingContext2D::LoseContext(LostContextMode lost_mode) {
  if (context_lost_mode_ != kNotLostContext)
    return;
  context_lost_mode_ = lost_mode;
  if (CanvasRenderingContextHost* host = Host();
      host != nullptr && context_lost_mode_ == kSyntheticLostContext)
      [[unlikely]] {
    host->DiscardResourceProvider();
  }
  uint32_t delay = base::RandInt(1, kMaxIframeContextLoseDelay);
  dispatch_context_lost_event_timer_.StartOneShot(base::Milliseconds(delay),
                                                  FROM_HERE);
}

bool OffscreenCanvasRenderingContext2D::IsPaintable() const {
  return Host()->ResourceProvider();
}

bool OffscreenCanvasRenderingContext2D::WritePixels(
    const SkImageInfo& orig_info,
    const void* pixels,
    size_t row_bytes,
    int x,
    int y) {
  if (!GetOrCreateCanvasResourceProvider())
    return false;

  DCHECK(IsPaintable());
  Host()->FlushRecording(FlushReason::kWritePixels);

  // Short-circuit out if an error occurred while flushing the recording.
  if (!Host()->ResourceProvider()->IsValid()) {
    return false;
  }

  return Host()->ResourceProvider()->WritePixels(orig_info, pixels, row_bytes,
                                                 x, y);
}

bool OffscreenCanvasRenderingContext2D::ResolveFont(const String& new_font) {
  OffscreenFontCache& font_cache = GetOffscreenFontCache();
  FontDescription* cached_font = font_cache.GetFont(new_font);
  CanvasRenderingContextHost* const host = Host();
  if (cached_font) {
    GetState().SetFont(*cached_font, host->GetFontSelector());
  } else {
    auto* style =
        CSSParser::ParseFont(new_font, host->GetTopExecutionContext());
    if (!style) {
      return false;
    }
    FontDescription desc =
        FontStyleResolver::ComputeFont(*style, host->GetFontSelector());

    font_cache.AddFont(new_font, desc);
    GetState().SetFont(desc, host->GetFontSelector());
  }
  return true;
}

bool OffscreenCanvasRenderingContext2D::IsCanvas2DBufferValid() const {
  if (IsPaintable())
    return GetCanvasResourceProvider()->IsValid();
  return false;
}

void OffscreenCanvasRenderingContext2D::DispatchContextLostEvent(
    TimerBase* time) {
  ResetInternal();
  BaseRenderingContext2D::DispatchContextLostEvent(time);
}

void OffscreenCanvasRenderingContext2D::TryRestoreContextEvent(
    TimerBase* timer) {
  if (context_lost_mode_ == kNotLostContext) {
    // Canvas was already restored (possibly thanks to a resize), so stop
    // trying.
    try_restore_context_event_timer_.Stop();
    return;
  }

  DCHECK(context_lost_mode_ != kWebGLLoseContextLostContext);

  if (context_lost_mode_ == kSyntheticLostContext) {
    // If lost mode is |kSyntheticLostContext| and |context_restorable_| is set
    // to true, it means context is forced to be lost for testing purpose.
    // Restore the context.
    CanvasResourceProvider* provider = GetOrCreateCanvasResourceProvider();
    if (provider) {
      try_restore_context_event_timer_.Stop();
      DispatchContextRestoredEvent(nullptr);
      return;
    }
  } else if (context_lost_mode_ == kRealLostContext) {
    // If lost mode is |kRealLostContext|, it means the context was not lost due
    // to surface failure but rather due to a an eviction, which means image
    // buffer exists.
    OffscreenCanvas* const canvas = HostAsOffscreenCanvas();
    CHECK(canvas != nullptr);
    // Let the OffscreenCanvas know that it should attempt to recreate the
    // resource dispatcher in order to restore the context.
    canvas->SetRestoringGpuContext(true);
    CanvasResourceProvider* provider = GetOrCreateCanvasResourceProvider();
    canvas->SetRestoringGpuContext(false);
    if (provider) {
      try_restore_context_event_timer_.Stop();
      DispatchContextRestoredEvent(nullptr);
      return;
    }
  }

  // It gets here if lost mode is |kRealLostContext| and it fails to create a
  // new PaintCanvas. Discard the old resource and allocating a new one here.
  if (++try_restore_context_attempt_count_ > kMaxTryRestoreContextAttempts) {
    if (CanvasRenderingContextHost* host = Host()) [[likely]] {
      host->DiscardResourceProvider();
    }
    try_restore_context_event_timer_.Stop();
    if (CanvasResourceProvider* provider = GetOrCreateCanvasResourceProvider();
        provider) {
      DispatchContextRestoredEvent(nullptr);
    }
  }
}

std::optional<cc::PaintRecord> OffscreenCanvasRenderingContext2D::FlushCanvas(
    FlushReason reason) {
  if (CanvasResourceProvider* provider = GetCanvasResourceProvider())
      [[likely]] {
    return provider->FlushCanvas(reason);
  }
  return std::nullopt;
}

OffscreenCanvas* OffscreenCanvasRenderingContext2D::HostAsOffscreenCanvas()
    const {
  return static_cast<OffscreenCanvas*>(Host());
}

FontSelector* OffscreenCanvasRenderingContext2D::GetFontSelector() const {
  return Host()->GetFontSelector();
}

int OffscreenCanvasRenderingContext2D::LayerCount() const {
  return BaseRenderingContext2D::LayerCount();
}

}  // namespace blink

"""

```
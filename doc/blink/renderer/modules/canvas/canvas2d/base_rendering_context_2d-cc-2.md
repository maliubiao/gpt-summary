Response:
The user wants a summary of the functionality of the provided C++ code snippet from `base_rendering_context_2d.cc`. They are particularly interested in the code's relationship with JavaScript, HTML, and CSS, along with examples. They also want to understand potential user or programming errors, how a user's action might lead to this code execution (as a debugging hint), and a concise summary of the code's purpose.

Here's a breakdown of the code and how to address each point:

1. **Functionality Listing:** The code primarily deals with drawing operations on a canvas. I can list the functions defined in the snippet and their basic actions (e.g., `fill()`, `stroke()`, `fillRect()`, `drawImage()`, `createLinearGradient()`, `createPattern()`, etc.).

2. **Relationship with JavaScript, HTML, CSS:**
    * **JavaScript:**  The methods in this C++ file are the underlying implementations for the Canvas 2D API in JavaScript. I can provide examples of how JavaScript calls map to these C++ functions (e.g., `context.fillRect(10, 10, 50, 50)` calls the `fillRect` method in the C++ code).
    * **HTML:** The `<canvas>` HTML element is where these drawing operations take place. The C++ code interacts with the underlying representation of this element.
    * **CSS:** CSS can affect the canvas indirectly (e.g., setting the size of the `<canvas>` element). The C++ code needs to be aware of these dimensions.

3. **Logical Reasoning (Hypothetical Input/Output):** For functions like `isPointInPath` or `isPointInStroke`, I can create simple scenarios:
    * **Input:** A path definition (e.g., a rectangle), coordinates (x, y).
    * **Output:** `true` if the point is within/on the path, `false` otherwise.

4. **User/Programming Errors:**  I can identify common mistakes related to canvas usage that these functions might handle or where errors could occur:
    * Incorrect arguments to drawing functions (e.g., negative width/height).
    * Using an invalid image source for `drawImage`.
    * Errors in gradient or pattern creation.

5. **User Operations as Debugging Clues:** I need to describe the steps a user takes in a web browser that would eventually trigger the execution of these C++ functions:
    * Creating a `<canvas>` element in HTML.
    * Obtaining the 2D rendering context using JavaScript (`canvas.getContext('2d')`).
    * Calling drawing methods on the context object.

6. **Function Summary:** I'll provide a concise summary of the code's purpose, which is to implement the core drawing functionalities of the HTML Canvas 2D API within the Chromium Blink engine.

**Pre-computation/Pre-analysis:**

* **Identify Core Drawing Functions:**  Scan the code for methods that perform drawing or manipulation of canvas state (fill, stroke, rects, paths, images, clipping, etc.).
* **Link to JavaScript API:** For each identified C++ function, recall or look up the corresponding JavaScript Canvas 2D API method.
* **Consider Edge Cases and Validation:** Note the checks for invalid inputs (e.g., in `ValidateRectForCanvas`).
* **Think about the Rendering Pipeline:** Understand that JavaScript calls go through the browser's rendering engine (Blink in this case) and eventually interact with graphics libraries (like Skia).

**Confidence Score:** 5/5 - I'm confident I can address all the user's requests based on my understanding of the code and the context of Chromium's rendering engine.
这是 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 文件的第三部分，主要包含以下功能：

**核心绘图操作和状态管理 (延续自前一部分)：**

* **`fill(Path2D* dom_path, const V8CanvasFillRule& winding_rule)`:** 使用指定的 `Path2D` 对象和填充规则进行填充。
* **`stroke()`:** 使用当前路径和描边样式进行描边。
* **`stroke(Path2D* dom_path)`:** 使用指定的 `Path2D` 对象和描边样式进行描边。
* **`fillRect(double x, double y, double width, double height)`:** 填充一个矩形。
* **`strokeRect(double x, double y, double width, double height)`:** 描边一个矩形。
* **`ClipInternal(const Path& path, const V8CanvasFillRule& winding_rule, UsePaintCache use_paint_cache)`:**  内部函数，用于实现裁剪操作。
* **`clip(const V8CanvasFillRule& winding_rule)`:** 使用当前路径进行裁剪。
* **`clip(Path2D* dom_path, const V8CanvasFillRule& winding_rule)`:** 使用指定的 `Path2D` 对象进行裁剪。
* **`isPointInPath(const double x, const double y, const V8CanvasFillRule& winding_rule)`:** 判断一个点是否在当前路径的填充区域内。
* **`isPointInPath(Path2D* dom_path, const double x, const double y, const V8CanvasFillRule& winding_rule)`:** 判断一个点是否在指定 `Path2D` 对象的填充区域内。
* **`IsPointInPathInternal(...)`:**  `isPointInPath` 的内部实现。
* **`isPointInStroke(const double x, const double y)`:** 判断一个点是否在当前路径的描边线上。
* **`isPointInStroke(Path2D* dom_path, const double x, const double y)`:** 判断一个点是否在指定 `Path2D` 对象的描边线上。
* **`IsPointInStrokeInternal(...)`:** `isPointInStroke` 的内部实现。
* **`GetClearFlags()`:** 获取用于 `clearRect` 的 PaintFlags。
* **`clearRect(double x, double y, double width, double height)`:** 清空一个矩形区域。

**图像绘制：**

* **`drawImage(...)` (多个重载版本):**  绘制图像到画布上，支持不同的参数组合，包括绘制整个图像或图像的某个区域到画布的某个区域。
* **`ShouldDrawImageAntialiased(const gfx::RectF& dest_rect) const`:**  根据目标矩形大小和当前变换，判断是否应该对图像绘制进行抗锯齿处理。
* **`DispatchContextLostEvent(TimerBase*)`:**  分发 `contextlost` 事件，表示渲染上下文丢失。
* **`DispatchContextRestoredEvent(TimerBase*)`:** 分发 `contextrestored` 事件，表示渲染上下文已恢复。
* **`DrawImageInternal(...)`:** 内部函数，执行实际的图像绘制操作，支持 `HTMLVideoElement` 和 `VideoFrame` 作为图像源。
* **`SetOriginTaintedByContent()`:** 设置画布的原点被内容污染的标志。

**其他操作：**

* **`placeElement(Element* element, double x, double y, ExceptionState& exception_state)`:** (目前是桩函数)  计划用于将元素放置在画布上。
* **`RectContainsTransformedRect(...) const`:** 判断一个矩形是否包含另一个经过变换的矩形。
* **`createLinearGradient(...)`:** 创建一个线性渐变对象。
* **`createRadialGradient(...)`:** 创建一个径向渐变对象。
* **`createConicGradient(...)`:** 创建一个圆锥渐变对象。
* **`createPattern(...)` (多个重载版本):** 创建一个用于填充或描边的图案对象。

**与 JavaScript, HTML, CSS 的关系和举例说明：**

* **JavaScript:** 这个 C++ 文件中的方法直接对应了 HTML Canvas 2D API 的 JavaScript 方法。
    * **`fill()`/`stroke()`:**  当 JavaScript 中调用 `context.fill()` 或 `context.stroke()` 时，会最终调用到这里的 `fill()` 和 `stroke()` 方法。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const context = canvas.getContext('2d');
        context.fillStyle = 'red';
        context.fillRect(10, 10, 100, 50); // 调用到 C++ 的 fillRect
        context.strokeRect(10, 10, 100, 50); // 调用到 C++ 的 strokeRect
        ```
    * **`drawImage()`:**  JavaScript 的 `context.drawImage(image, x, y)` 等方法会调用到这里的 `drawImage` 方法。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const context = canvas.getContext('2d');
        const img = new Image();
        img.onload = function() {
          context.drawImage(img, 50, 50); // 调用到 C++ 的 drawImage
        };
        img.src = 'myimage.png';
        ```
    * **`createLinearGradient()`/`createRadialGradient()`/`createPattern()`:**  JavaScript 中创建渐变和图案对象的方法对应于此。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const context = canvas.getContext('2d');
        const gradient = context.createLinearGradient(0, 0, 200, 0); // 调用到 C++ 的 createLinearGradient
        gradient.addColorStop(0, 'red');
        gradient.addColorStop(1, 'blue');
        context.fillStyle = gradient;
        context.fillRect(10, 10, 150, 80);
        ```
* **HTML:**  `<canvas>` 元素是所有这些操作发生的基础。JavaScript 通过获取 `<canvas>` 元素的 2D 渲染上下文来调用这些 C++ 功能。
    ```html
    <canvas id="myCanvas" width="200" height="100"></canvas>
    ```
* **CSS:** CSS 可以影响 `<canvas>` 元素的尺寸和样式，但直接的绘图操作是由 JavaScript 和底层的 C++ 代码控制的。CSS 设置的尺寸会影响画布的坐标系统。

**逻辑推理 (假设输入与输出)：**

* **`isPointInPath(15, 15)` 假设：**
    * **假设输入:**  当前路径是一个从 (10, 10) 到 (100, 50) 到 (10, 50) 闭合的三角形，填充规则为非零环绕。要判断的点是 (15, 15)。
    * **逻辑推理:** 点 (15, 15) 位于三角形内部。
    * **输出:** `true`

* **`isPointInStroke(5, 5)` 假设：**
    * **假设输入:** 当前路径是一条从 (0, 0) 到 (10, 10) 的线段，线宽为 2。要判断的点是 (5, 5)。
    * **逻辑推理:** 点 (5, 5) 位于线段上（考虑线宽）。
    * **输出:** `true`

**用户或编程常见的使用错误举例说明：**

* **传递无效的坐标或尺寸:**
    * **错误:** `context.fillRect(10, 10, -50, 50);` // 负宽度
    * **说明:** `ValidateRectForCanvas` 会检查这些值，并阻止绘制操作。
* **使用未加载完成的图像进行绘制:**
    * **错误:**  在图像的 `onload` 事件触发前就调用 `drawImage`。
    * **说明:** 这会导致无法绘制图像或绘制不完整。Blink 的代码会尝试获取图像源，如果图像未准备好，可能直接返回。
* **在没有定义路径的情况下调用 `fill()` 或 `stroke()`:**
    * **错误:**  直接调用 `context.fill()` 或 `context.stroke()` 而没有使用 `beginPath()`, `moveTo()`, `lineTo()` 等方法定义路径。
    * **说明:**  虽然不会报错，但不会有任何绘制效果，因为没有路径可以填充或描边。
* **`createRadialGradient` 中半径为负数:**
    * **错误:** `context.createRadialGradient(50, 50, -10, 70, 70, 30);`
    * **说明:**  代码中的 `createRadialGradient` 方法会检查半径是否小于 0，并抛出 `DOMExceptionCode::kIndexSizeError` 异常。
* **使用跨域的图像且未配置 CORS:**
    * **错误:**  尝试使用来自不同域名的图像作为 `drawImage` 或 `createPattern` 的源，但服务器没有设置正确的 CORS 头。
    * **说明:** 这会导致画布被污染，无法使用 `toDataURL()` 等方法导出画布内容。`WouldTaintCanvasOrigin` 函数会检查这种情况。

**用户操作如何一步步的到达这里 (作为调试线索)：**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 代码中包含一个 `<canvas>` 元素。**
3. **网页的 JavaScript 代码获取该 `<canvas>` 元素的 2D 渲染上下文：**
   ```javascript
   const canvas = document.getElementById('myCanvas');
   const context = canvas.getContext('2d');
   ```
4. **JavaScript 代码调用 `context` 上的绘图方法，例如 `fillRect()`, `drawImage()`, `beginPath()`, `lineTo()`, `fill()`, `stroke()`, `createLinearGradient()`, `createPattern()` 等。**
5. **浏览器引擎 (Blink) 接收到这些 JavaScript 调用，并将它们映射到 `BaseRenderingContext2D` 类中相应的 C++ 方法的调用。**
6. **例如，如果 JavaScript 代码调用 `context.fillRect(10, 20, 50, 30)`，则会最终执行到 `base_rendering_context_2d.cc` 文件中的 `BaseRenderingContext2D::fillRect(10, 20, 50, 30)` 方法。**
7. **在 C++ 代码中，会进行参数验证、状态获取、实际的 Skia 图形库调用等操作，最终在屏幕上渲染出相应的图形。**

**功能归纳：**

这个代码片段实现了 HTML Canvas 2D API 的核心绘图功能，包括填充、描边、矩形绘制、路径操作、裁剪、图像绘制、渐变和图案的创建。它负责接收来自 JavaScript 的绘图指令，进行必要的参数处理和验证，并调用底层的 Skia 图形库来完成实际的渲染工作。同时，它还处理了画布上下文的丢失和恢复事件。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
_path, CanvasRenderingContext2DState::kFillPaintType,
                   winding_rule, path2d_use_paint_cache_);
}

void BaseRenderingContext2D::stroke() {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kStroke);
  }
  DrawPathInternal(*this, CanvasRenderingContext2DState::kStrokePaintType,
                   SkPathFillType::kWinding, UsePaintCache::kDisabled);
}

void BaseRenderingContext2D::stroke(Path2D* dom_path) {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kStroke__Path, dom_path->GetIdentifiableToken());
  }
  DrawPathInternal(*dom_path, CanvasRenderingContext2DState::kStrokePaintType,
                   SkPathFillType::kWinding, path2d_use_paint_cache_);
}

void BaseRenderingContext2D::fillRect(double x,
                                      double y,
                                      double width,
                                      double height) {
  if (!ValidateRectForCanvas(x, y, width, height))
    return;

  if (!GetOrCreatePaintCanvas())
    return;
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kFillRect, x, y,
                                                width, height);
  }

  // We are assuming that if the pattern is not accelerated and the current
  // canvas is accelerated, the texture of the pattern will not be able to be
  // moved to the texture of the canvas receiving the pattern (because if the
  // pattern was unaccelerated is because it was not possible to hold that image
  // in an accelerated texture - that is, into the GPU). That's why we disable
  // the acceleration to be sure that it will work.
  const CanvasRenderingContext2DState& state = GetState();
  const bool has_pattern =
      state.HasPattern(CanvasRenderingContext2DState::kFillPaintType);
  if (IsAccelerated() && has_pattern &&
      !state.PatternIsAccelerated(
          CanvasRenderingContext2DState::kFillPaintType)) {
    DisableAcceleration();
    base::UmaHistogramEnumeration(
        "Blink.Canvas.GPUFallbackToCPU",
        GPUFallbackToCPUScenario::kLargePatternDrawnToGPU);
  }

  // clamp to float to avoid float cast overflow when used as SkScalar
  AdjustRectForCanvas(x, y, width, height);
  gfx::RectF rect(ClampTo<float>(x), ClampTo<float>(y), ClampTo<float>(width),
                  ClampTo<float>(height));
  Draw<OverdrawOp::kNone>(
      [rect](cc::PaintCanvas* c, const cc::PaintFlags* flags)  // draw lambda
      { c->drawRect(gfx::RectFToSkRect(rect), *flags); },
      [rect, this](const SkIRect& clip_bounds)  // overdraw test lambda
      { return RectContainsTransformedRect(rect, clip_bounds); },
      rect, CanvasRenderingContext2DState::kFillPaintType,
      has_pattern ? CanvasRenderingContext2DState::kNonOpaqueImage
                  : CanvasRenderingContext2DState::kNoImage,
      CanvasPerformanceMonitor::DrawType::kRectangle);
}

static void StrokeRectOnCanvas(const gfx::RectF& rect,
                               cc::PaintCanvas* canvas,
                               const cc::PaintFlags* flags) {
  DCHECK_EQ(flags->getStyle(), cc::PaintFlags::kStroke_Style);
  if ((rect.width() > 0) != (rect.height() > 0)) {
    // When stroking, we must skip the zero-dimension segments
    SkPath path;
    path.moveTo(rect.x(), rect.y());
    path.lineTo(rect.right(), rect.bottom());
    path.close();
    canvas->drawPath(path, *flags);
    return;
  }
  canvas->drawRect(gfx::RectFToSkRect(rect), *flags);
}

void BaseRenderingContext2D::strokeRect(double x,
                                        double y,
                                        double width,
                                        double height) {
  if (!ValidateRectForCanvas(x, y, width, height))
    return;

  if (!GetOrCreatePaintCanvas())
    return;
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kStrokeRect, x, y,
                                                width, height);
  }

  // clamp to float to avoid float cast overflow when used as SkScalar
  AdjustRectForCanvas(x, y, width, height);
  float fx = ClampTo<float>(x);
  float fy = ClampTo<float>(y);
  float fwidth = ClampTo<float>(width);
  float fheight = ClampTo<float>(height);

  gfx::RectF rect(fx, fy, fwidth, fheight);
  gfx::RectF bounds = rect;
  InflateStrokeRect(bounds);

  if (!ValidateRectForCanvas(bounds.x(), bounds.y(), bounds.width(),
                             bounds.height()))
    return;

  Draw<OverdrawOp::kNone>(
      [rect](cc::PaintCanvas* c, const cc::PaintFlags* flags)  // draw lambda
      { StrokeRectOnCanvas(rect, c, flags); },
      kNoOverdraw, bounds, CanvasRenderingContext2DState::kStrokePaintType,
      GetState().HasPattern(CanvasRenderingContext2DState::kStrokePaintType)
          ? CanvasRenderingContext2DState::kNonOpaqueImage
          : CanvasRenderingContext2DState::kNoImage,
      CanvasPerformanceMonitor::DrawType::kRectangle);
}

void BaseRenderingContext2D::ClipInternal(const Path& path,
                                          const V8CanvasFillRule& winding_rule,
                                          UsePaintCache use_paint_cache) {
  cc::PaintCanvas* c = GetOrCreatePaintCanvas();
  if (!c) {
    return;
  }
  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  SkPath sk_path = path.GetSkPath();
  sk_path.setFillType(CanvasFillRuleToSkiaFillType(winding_rule));
  GetState().ClipPath(sk_path, clip_antialiasing_);
  c->clipPath(sk_path, SkClipOp::kIntersect, clip_antialiasing_ == kAntiAliased,
              use_paint_cache);
}

void BaseRenderingContext2D::clip(const V8CanvasFillRule& winding_rule) {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kClip,
        IdentifiabilitySensitiveStringToken(winding_rule.AsString()));
  }
  ClipInternal(GetPath(), winding_rule, UsePaintCache::kDisabled);
}

void BaseRenderingContext2D::clip(Path2D* dom_path,
                                  const V8CanvasFillRule& winding_rule) {
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kClip__Path, dom_path->GetIdentifiableToken(),
        IdentifiabilitySensitiveStringToken(winding_rule.AsString()));
  }
  ClipInternal(dom_path->GetPath(), winding_rule, path2d_use_paint_cache_);
}

bool BaseRenderingContext2D::isPointInPath(
    const double x,
    const double y,
    const V8CanvasFillRule& winding_rule) {
  return IsPointInPathInternal(GetPath(), x, y, winding_rule);
}

bool BaseRenderingContext2D::isPointInPath(
    Path2D* dom_path,
    const double x,
    const double y,
    const V8CanvasFillRule& winding_rule) {
  return IsPointInPathInternal(dom_path->GetPath(), x, y, winding_rule);
}

bool BaseRenderingContext2D::IsPointInPathInternal(
    const Path& path,
    const double x,
    const double y,
    const V8CanvasFillRule& winding_rule) {
  cc::PaintCanvas* c = GetOrCreatePaintCanvas();
  if (!c)
    return false;
  if (!IsTransformInvertible()) [[unlikely]] {
    return false;
  }

  if (!std::isfinite(x) || !std::isfinite(y))
    return false;
  gfx::PointF point(ClampTo<float>(x), ClampTo<float>(y));
  AffineTransform ctm = GetState().GetTransform();
  gfx::PointF transformed_point = ctm.Inverse().MapPoint(point);

  return path.Contains(
      transformed_point,
      SkFillTypeToWindRule(CanvasFillRuleToSkiaFillType(winding_rule)));
}

bool BaseRenderingContext2D::isPointInStroke(const double x, const double y) {
  return IsPointInStrokeInternal(GetPath(), x, y);
}

bool BaseRenderingContext2D::isPointInStroke(Path2D* dom_path,
                                             const double x,
                                             const double y) {
  return IsPointInStrokeInternal(dom_path->GetPath(), x, y);
}

bool BaseRenderingContext2D::IsPointInStrokeInternal(const Path& path,
                                                     const double x,
                                                     const double y) {
  cc::PaintCanvas* c = GetOrCreatePaintCanvas();
  if (!c)
    return false;
  if (!IsTransformInvertible()) [[unlikely]] {
    return false;
  }

  if (!std::isfinite(x) || !std::isfinite(y))
    return false;
  gfx::PointF point(ClampTo<float>(x), ClampTo<float>(y));
  const CanvasRenderingContext2DState& state = GetState();
  const AffineTransform& ctm = state.GetTransform();
  gfx::PointF transformed_point = ctm.Inverse().MapPoint(point);

  StrokeData stroke_data;
  stroke_data.SetThickness(state.LineWidth());
  stroke_data.SetLineCap(state.GetLineCap());
  stroke_data.SetLineJoin(state.GetLineJoin());
  stroke_data.SetMiterLimit(state.MiterLimit());
  Vector<float> line_dash(state.LineDash().size());
  base::ranges::copy(state.LineDash(), line_dash.begin());
  stroke_data.SetLineDash(line_dash, state.LineDashOffset());
  return path.StrokeContains(transformed_point, stroke_data, ctm);
}

cc::PaintFlags BaseRenderingContext2D::GetClearFlags() const {
  cc::PaintFlags clear_flags;
  clear_flags.setStyle(cc::PaintFlags::kFill_Style);
  if (HasAlpha()) {
    clear_flags.setBlendMode(SkBlendMode::kClear);
  } else {
    clear_flags.setColor(SK_ColorBLACK);
  }
  return clear_flags;
}

void BaseRenderingContext2D::clearRect(double x,
                                       double y,
                                       double width,
                                       double height) {
  if (!ValidateRectForCanvas(x, y, width, height))
    return;

  cc::PaintCanvas* c = GetOrCreatePaintCanvas();
  if (!c)
    return;
  if (!IsTransformInvertible()) [[unlikely]] {
    return;
  }

  SkIRect clip_bounds;
  if (!c->getDeviceClipBounds(&clip_bounds))
    return;
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(CanvasOps::kClearRect, x, y,
                                                width, height);
  }

  cc::PaintFlags clear_flags = GetClearFlags();

  // clamp to float to avoid float cast overflow when used as SkScalar
  AdjustRectForCanvas(x, y, width, height);
  float fx = ClampTo<float>(x);
  float fy = ClampTo<float>(y);
  float fwidth = ClampTo<float>(width);
  float fheight = ClampTo<float>(height);

  gfx::RectF rect(fx, fy, fwidth, fheight);
  if (RectContainsTransformedRect(rect, clip_bounds)) {
    CheckOverdraw(&clear_flags, CanvasRenderingContext2DState::kNoImage,
                  OverdrawOp::kClearRect);
    WillDraw(clip_bounds, CanvasPerformanceMonitor::DrawType::kOther);
    c->drawRect(gfx::RectFToSkRect(rect), clear_flags);
  } else {
    SkIRect dirty_rect;
    if (ComputeDirtyRect(rect, clip_bounds, &dirty_rect)) {
      WillDraw(clip_bounds, CanvasPerformanceMonitor::DrawType::kOther);
      c->drawRect(gfx::RectFToSkRect(rect), clear_flags);
    }
  }
}

static inline void ClipRectsToImageRect(const gfx::RectF& image_rect,
                                        gfx::RectF* src_rect,
                                        gfx::RectF* dst_rect) {
  if (image_rect.Contains(*src_rect))
    return;

  // Compute the src to dst transform
  gfx::SizeF scale(dst_rect->size().width() / src_rect->size().width(),
                   dst_rect->size().height() / src_rect->size().height());
  gfx::PointF scaled_src_location = src_rect->origin();
  scaled_src_location.Scale(scale.width(), scale.height());
  gfx::Vector2dF offset = dst_rect->origin() - scaled_src_location;

  src_rect->Intersect(image_rect);

  // To clip the destination rectangle in the same proportion, transform the
  // clipped src rect
  *dst_rect = *src_rect;
  dst_rect->Scale(scale.width(), scale.height());
  dst_rect->Offset(offset);
}

void BaseRenderingContext2D::drawImage(const V8CanvasImageSource* image_source,
                                       double x,
                                       double y,
                                       ExceptionState& exception_state) {
  CanvasImageSource* image_source_internal =
      ToCanvasImageSource(image_source, exception_state);
  if (!image_source_internal)
    return;
  RespectImageOrientationEnum respect_orientation =
      RespectImageOrientationInternal(image_source_internal);
  gfx::SizeF default_object_size(Width(), Height());
  gfx::SizeF source_rect_size = image_source_internal->ElementSize(
      default_object_size, respect_orientation);
  gfx::SizeF dest_rect_size = image_source_internal->DefaultDestinationSize(
      default_object_size, respect_orientation);
  drawImage(image_source_internal, 0, 0, source_rect_size.width(),
            source_rect_size.height(), x, y, dest_rect_size.width(),
            dest_rect_size.height(), exception_state);
}

void BaseRenderingContext2D::drawImage(const V8CanvasImageSource* image_source,
                                       double x,
                                       double y,
                                       double width,
                                       double height,
                                       ExceptionState& exception_state) {
  CanvasImageSource* image_source_internal =
      ToCanvasImageSource(image_source, exception_state);
  if (!image_source_internal)
    return;
  gfx::SizeF default_object_size(Width(), Height());
  gfx::SizeF source_rect_size = image_source_internal->ElementSize(
      default_object_size,
      RespectImageOrientationInternal(image_source_internal));
  drawImage(image_source_internal, 0, 0, source_rect_size.width(),
            source_rect_size.height(), x, y, width, height, exception_state);
}

void BaseRenderingContext2D::drawImage(const V8CanvasImageSource* image_source,
                                       double sx,
                                       double sy,
                                       double sw,
                                       double sh,
                                       double dx,
                                       double dy,
                                       double dw,
                                       double dh,
                                       ExceptionState& exception_state) {
  CanvasImageSource* image_source_internal =
      ToCanvasImageSource(image_source, exception_state);
  if (!image_source_internal)
    return;
  drawImage(image_source_internal, sx, sy, sw, sh, dx, dy, dw, dh,
            exception_state);
}

bool BaseRenderingContext2D::ShouldDrawImageAntialiased(
    const gfx::RectF& dest_rect) const {
  if (!GetState().ShouldAntialias())
    return false;
  const cc::PaintCanvas* c = GetPaintCanvas();
  DCHECK(c);

  const SkMatrix& ctm = c->getLocalToDevice().asM33();
  // Don't disable anti-aliasing if we're rotated or skewed.
  if (!ctm.rectStaysRect())
    return true;
  // Check if the dimensions of the destination are "small" (less than one
  // device pixel). To prevent sudden drop-outs. Since we know that
  // kRectStaysRect_Mask is set, the matrix either has scale and no skew or
  // vice versa. We can query the kAffine_Mask flag to determine which case
  // it is.
  // FIXME: This queries the CTM while drawing, which is generally
  // discouraged. Always drawing with AA can negatively impact performance
  // though - that's why it's not always on.
  SkScalar width_expansion, height_expansion;
  if (ctm.getType() & SkMatrix::kAffine_Mask) {
    width_expansion = ctm[SkMatrix::kMSkewY];
    height_expansion = ctm[SkMatrix::kMSkewX];
  } else {
    width_expansion = ctm[SkMatrix::kMScaleX];
    height_expansion = ctm[SkMatrix::kMScaleY];
  }
  return dest_rect.width() * fabs(width_expansion) < 1 ||
         dest_rect.height() * fabs(height_expansion) < 1;
}

void BaseRenderingContext2D::DispatchContextLostEvent(TimerBase*) {
  Event* event = Event::CreateCancelable(event_type_names::kContextlost);
  GetCanvasRenderingContextHost()->HostDispatchEvent(event);

  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DContextLostEvent);
  if (event->defaultPrevented()) {
    context_restorable_ = false;
  }

  if (context_restorable_ &&
      (context_lost_mode_ == CanvasRenderingContext::kRealLostContext ||
       context_lost_mode_ == CanvasRenderingContext::kSyntheticLostContext)) {
    try_restore_context_attempt_count_ = 0;
    try_restore_context_event_timer_.StartRepeating(kTryRestoreContextInterval,
                                                    FROM_HERE);
  }
}

void BaseRenderingContext2D::DispatchContextRestoredEvent(TimerBase*) {
  // Since canvas may trigger contextlost event by multiple different ways (ex:
  // gpu crashes and frame eviction), it's possible to triggeer this
  // function while the context is already restored. In this case, we
  // abort it here.
  if (context_lost_mode_ == CanvasRenderingContext::kNotLostContext)
    return;
  ResetInternal();
  context_lost_mode_ = CanvasRenderingContext::kNotLostContext;
  Event* event(Event::Create(event_type_names::kContextrestored));
  GetCanvasRenderingContextHost()->HostDispatchEvent(event);
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DContextRestoredEvent);
}

void BaseRenderingContext2D::DrawImageInternal(
    cc::PaintCanvas* c,
    CanvasImageSource* image_source,
    Image* image,
    const gfx::RectF& src_rect,
    const gfx::RectF& dst_rect,
    const SkSamplingOptions& sampling,
    const cc::PaintFlags* flags) {
  cc::RecordPaintCanvas::DisableFlushCheckScope disable_flush_check_scope(
      static_cast<cc::RecordPaintCanvas*>(c));
  int initial_save_count = c->getSaveCount();
  cc::PaintFlags image_flags = *flags;

  if (flags->getImageFilter()) {
    SkM44 ctm = c->getLocalToDevice();
    SkM44 inv_ctm;
    if (!ctm.invert(&inv_ctm)) {
      // There is an earlier check for invertibility, but the arithmetic
      // in AffineTransform is not exactly identical, so it is possible
      // for SkMatrix to find the transform to be non-invertible at this stage.
      // crbug.com/504687
      return;
    }
    SkRect bounds = gfx::RectFToSkRect(dst_rect);
    ctm.asM33().mapRect(&bounds);
    if (!bounds.isFinite()) {
      // There is an earlier check for the correctness of the bounds, but it is
      // possible that after applying the matrix transformation we get a faulty
      // set of bounds, so we want to catch this asap and avoid sending a draw
      // command. crbug.com/1039125
      // We want to do this before the save command is sent.
      return;
    }
    c->save();
    c->concat(inv_ctm);

    cc::PaintFlags layer_flags;
    layer_flags.setBlendMode(flags->getBlendMode());
    layer_flags.setImageFilter(flags->getImageFilter());

    c->saveLayer(bounds, layer_flags);
    c->concat(ctm);
    image_flags.setBlendMode(SkBlendMode::kSrcOver);
    image_flags.setImageFilter(nullptr);
  }

  if (image_source->IsVideoElement()) {
    c->save();
    c->clipRect(gfx::RectFToSkRect(dst_rect));
    c->translate(dst_rect.x(), dst_rect.y());
    c->scale(dst_rect.width() / src_rect.width(),
             dst_rect.height() / src_rect.height());
    c->translate(-src_rect.x(), -src_rect.y());
    HTMLVideoElement* video = static_cast<HTMLVideoElement*>(image_source);
    video->PaintCurrentFrame(
        c, gfx::Rect(video->videoWidth(), video->videoHeight()), &image_flags);
  } else if (image_source->IsVideoFrame()) {
    VideoFrame* frame = static_cast<VideoFrame*>(image_source);
    auto media_frame = frame->frame();
    bool ignore_transformation =
        RespectImageOrientationInternal(image_source) ==
        kDoNotRespectImageOrientation;
    gfx::RectF corrected_src_rect = src_rect;

    if (!ignore_transformation) {
      auto orientation_enum = VideoTransformationToImageOrientation(
          media_frame->metadata().transformation.value_or(
              media::kNoTransformation));
      if (ImageOrientation(orientation_enum).UsesWidthAsHeight())
        corrected_src_rect = gfx::TransposeRect(src_rect);
    }

    c->save();
    c->clipRect(gfx::RectFToSkRect(dst_rect));
    c->translate(dst_rect.x(), dst_rect.y());
    c->scale(dst_rect.width() / corrected_src_rect.width(),
             dst_rect.height() / corrected_src_rect.height());
    c->translate(-corrected_src_rect.x(), -corrected_src_rect.y());
    DrawVideoFrameIntoCanvas(std::move(media_frame), c, image_flags,
                             ignore_transformation);
  } else {
    // We always use the image-orientation property on the canvas element
    // because the alternative would result in complex rules depending on
    // the source of the image.
    RespectImageOrientationEnum respect_orientation =
        RespectImageOrientationInternal(image_source);
    gfx::RectF corrected_src_rect = src_rect;
    if (respect_orientation == kRespectImageOrientation &&
        !image->HasDefaultOrientation()) {
      corrected_src_rect = image->CorrectSrcRectForImageOrientation(
          image->SizeAsFloat(kRespectImageOrientation), src_rect);
    }
    image_flags.setAntiAlias(ShouldDrawImageAntialiased(dst_rect));
    ImageDrawOptions draw_options;
    draw_options.sampling_options = sampling;
    draw_options.respect_orientation = respect_orientation;
    draw_options.clamping_mode = Image::kDoNotClampImageToSourceRect;
    image->Draw(c, image_flags, dst_rect, corrected_src_rect, draw_options);
  }

  c->restoreToCount(initial_save_count);
}

void BaseRenderingContext2D::SetOriginTaintedByContent() {
  SetOriginTainted();
  origin_tainted_by_content_ = true;
  for (auto& state : state_stack_)
    state->ClearResolvedFilter();
}

void BaseRenderingContext2D::drawImage(CanvasImageSource* image_source,
                                       double sx,
                                       double sy,
                                       double sw,
                                       double sh,
                                       double dx,
                                       double dy,
                                       double dw,
                                       double dh,
                                       ExceptionState& exception_state) {
  if (!GetOrCreatePaintCanvas())
    return;

  scoped_refptr<Image> image;
  gfx::SizeF default_object_size(Width(), Height());
  SourceImageStatus source_image_status = kInvalidSourceImageStatus;
  if (image_source->IsVideoElement()) {
    if (!static_cast<HTMLVideoElement*>(image_source)
             ->HasAvailableVideoFrame()) {
      return;
    }
  } else if (image_source->IsVideoFrame()) {
    if (!static_cast<VideoFrame*>(image_source)->frame()) {
      return;
    }
  } else {
    image = image_source->GetSourceImageForCanvas(
        FlushReason::kDrawImage, &source_image_status, default_object_size,
        kPremultiplyAlpha);
    if (source_image_status == kUndecodableSourceImageStatus) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "The HTMLImageElement provided is in the 'broken' state.");
    }
    if (source_image_status == kLayersOpenInCanvasSource) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "`drawImage()` with a canvas as a source cannot be called while "
          "layers are open in the the source canvas.");
      return;
    }
    if (!image || !image->width() || !image->height())
      return;
  }

  if (!std::isfinite(dx) || !std::isfinite(dy) || !std::isfinite(dw) ||
      !std::isfinite(dh) || !std::isfinite(sx) || !std::isfinite(sy) ||
      !std::isfinite(sw) || !std::isfinite(sh) || !dw || !dh || !sw || !sh)
    return;

  // clamp to float to avoid float cast overflow when used as SkScalar
  AdjustRectForCanvas(sx, sy, sw, sh);
  AdjustRectForCanvas(dx, dy, dw, dh);
  float fsx = ClampTo<float>(sx);
  float fsy = ClampTo<float>(sy);
  float fsw = ClampTo<float>(sw);
  float fsh = ClampTo<float>(sh);
  float fdx = ClampTo<float>(dx);
  float fdy = ClampTo<float>(dy);
  float fdw = ClampTo<float>(dw);
  float fdh = ClampTo<float>(dh);

  gfx::RectF src_rect(fsx, fsy, fsw, fsh);
  gfx::RectF dst_rect(fdx, fdy, fdw, fdh);
  gfx::SizeF image_size = image_source->ElementSize(
      default_object_size, RespectImageOrientationInternal(image_source));

  ClipRectsToImageRect(gfx::RectF(image_size), &src_rect, &dst_rect);

  if (src_rect.IsEmpty())
    return;
  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        CanvasOps::kDrawImage, fsx, fsy, fsw, fsh, fdx, fdy, fdw, fdh,
        image ? image->width() : 0, image ? image->height() : 0);
    identifiability_study_helper_.set_encountered_partially_digested_image();
  }

  ValidateStateStack();

  WillDrawImage(image_source);

  if (!origin_tainted_by_content_ && WouldTaintCanvasOrigin(image_source)) {
    SetOriginTaintedByContent();
  }

  Draw<OverdrawOp::kDrawImage>(
      [this, image_source, image, src_rect, dst_rect](
          cc::PaintCanvas* c, const cc::PaintFlags* flags)  // draw lambda
      {
        SkSamplingOptions sampling =
            cc::PaintFlags::FilterQualityToSkSamplingOptions(
                flags ? flags->getFilterQuality()
                      : cc::PaintFlags::FilterQuality::kNone);
        DrawImageInternal(c, image_source, image.get(), src_rect, dst_rect,
                          sampling, flags);
      },
      [this, dst_rect](const SkIRect& clip_bounds)  // overdraw test lambda
      { return RectContainsTransformedRect(dst_rect, clip_bounds); },
      dst_rect, CanvasRenderingContext2DState::kImagePaintType,
      image_source->IsOpaque() ? CanvasRenderingContext2DState::kOpaqueImage
                               : CanvasRenderingContext2DState::kNonOpaqueImage,
      CanvasPerformanceMonitor::DrawType::kImage);
}

// TODO(b/349835587): This is just a stub for now.
void BaseRenderingContext2D::placeElement(Element* element,
                                          double x,
                                          double y,
                                          ExceptionState& exception_state) {
  HTMLCanvasElement* canvas = HostAsHTMLCanvasElement();
  if (!element->IsDescendantOf(canvas)) {
    exception_state.ThrowTypeError(
        "Only elements that are part of the canvas fallback content subtree "
        "(i.e. children of the <canvas> element) can be used with "
        "placeElement().");
  }

  canvas->SetHasPlacedElements();
}

bool BaseRenderingContext2D::RectContainsTransformedRect(
    const gfx::RectF& rect,
    const SkIRect& transformed_rect) const {
  gfx::QuadF quad(rect);
  gfx::QuadF transformed_quad(
      gfx::RectF(transformed_rect.x(), transformed_rect.y(),
                 transformed_rect.width(), transformed_rect.height()));
  return GetState().GetTransform().MapQuad(quad).ContainsQuad(transformed_quad);
}

CanvasGradient* BaseRenderingContext2D::createLinearGradient(double x0,
                                                             double y0,
                                                             double x1,
                                                             double y1) {
  if (!std::isfinite(x0) || !std::isfinite(y0) || !std::isfinite(x1) ||
      !std::isfinite(y1))
    return nullptr;

  // clamp to float to avoid float cast overflow
  float fx0 = ClampTo<float>(x0);
  float fy0 = ClampTo<float>(y0);
  float fx1 = ClampTo<float>(x1);
  float fy1 = ClampTo<float>(y1);

  auto* gradient = MakeGarbageCollected<CanvasGradient>(gfx::PointF(fx0, fy0),
                                                        gfx::PointF(fx1, fy1));
  gradient->SetExecutionContext(
      identifiability_study_helper_.execution_context());
  return gradient;
}

CanvasGradient* BaseRenderingContext2D::createRadialGradient(
    double x0,
    double y0,
    double r0,
    double x1,
    double y1,
    double r1,
    ExceptionState& exception_state) {
  if (r0 < 0 || r1 < 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Format("The %s provided is less than 0.",
                       r0 < 0 ? "r0" : "r1"));
    return nullptr;
  }

  if (!std::isfinite(x0) || !std::isfinite(y0) || !std::isfinite(r0) ||
      !std::isfinite(x1) || !std::isfinite(y1) || !std::isfinite(r1))
    return nullptr;

  // clamp to float to avoid float cast overflow
  float fx0 = ClampTo<float>(x0);
  float fy0 = ClampTo<float>(y0);
  float fr0 = ClampTo<float>(r0);
  float fx1 = ClampTo<float>(x1);
  float fy1 = ClampTo<float>(y1);
  float fr1 = ClampTo<float>(r1);

  auto* gradient = MakeGarbageCollected<CanvasGradient>(
      gfx::PointF(fx0, fy0), fr0, gfx::PointF(fx1, fy1), fr1);
  gradient->SetExecutionContext(
      identifiability_study_helper_.execution_context());
  return gradient;
}

CanvasGradient* BaseRenderingContext2D::createConicGradient(double startAngle,
                                                            double centerX,
                                                            double centerY) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DConicGradient);
  if (!std::isfinite(startAngle) || !std::isfinite(centerX) ||
      !std::isfinite(centerY))
    return nullptr;
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();

  // clamp to float to avoid float cast overflow
  float a = ClampTo<float>(startAngle);
  float x = ClampTo<float>(centerX);
  float y = ClampTo<float>(centerY);

  // convert |startAngle| from radians to degree and rotate 90 degree, so
  // |startAngle| at 0 starts from x-axis.
  a = Rad2deg(a) + 90;

  auto* gradient = MakeGarbageCollected<CanvasGradient>(a, gfx::PointF(x, y));
  gradient->SetExecutionContext(
      identifiability_study_helper_.execution_context());
  return gradient;
}

CanvasPattern* BaseRenderingContext2D::createPattern(

    const V8CanvasImageSource* image_source,
    const String& repetition_type,
    ExceptionState& exception_state) {
  CanvasImageSource* image_source_internal =
      ToCanvasImageSource(image_source, exception_state);
  if (!image_source_internal) {
    return nullptr;
  }

  return createPattern(image_source_internal, repetition_type, exception_state);
}

CanvasPattern* BaseRenderingContext2D::createPattern(
    CanvasImageSource* image_source,
    const String& repetition_type,
    ExceptionState& exception_state) {
  if (!image_source) {
    return nullptr;
  }

  Pattern::RepeatMode repeat_mode =
      CanvasPattern::ParseRepetitionType(repetition_type, exception_state);
  if (exception_state.HadException())
    return nullptr;

  SourceImageStatus status;

  gfx::SizeF default_object_size(Width(), Height());
  scoped_refptr<Image> image_for_rendering =
      image_source->GetSourceImageForCanvas(FlushReason::kCreatePattern,
                                            &status, default_object_size,
                                            kPremultiplyAlpha);

  switch (status) {
    case kNormalSourceImageStatus:
      break;
    case kZeroSizeCanvasSourceImageStatus:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          String::Format("The canvas %s is 0.",
                         image_source
                                 ->ElementSize(default_object_size,
                                               RespectImageOrientationInternal(
                                                   image_source))
                                 .width()
                             ? "height"
                             : "width"));
      return nullptr;
    case kZeroSizeImageSourceStatus:
      return nullptr;
    case kUndecodableSourceImageStatus:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "Source image is in the 'broken' state.");
      return nullptr;
    case kInvalidSourceImageStatus:
      image_for_rendering = BitmapImage::Create();
      break;
    case kIncompleteSourceImageStatus:
      return nullptr;
    case kLayersOpenInCanvasSource:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidStateError,
          "`createPattern()` with a canvas as a source cannot be called while "
          "layers are open in the source canvas.");
      return nullptr;
    default:
      NOTREACHED();
  }

  if (!image_for_rendering)
    return nullptr;

  bool origin_clean = !WouldTai
"""


```
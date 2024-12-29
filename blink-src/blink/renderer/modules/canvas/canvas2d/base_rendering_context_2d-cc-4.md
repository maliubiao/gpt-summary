Response:
My thought process for analyzing the provided code snippet and generating the comprehensive summary went through the following stages:

1. **Decomposition and Keyword Identification:** I first scanned the code for key function names, class names, and variables that hint at the code's purpose. I noted things like `BaseRenderingContext2D`, `CanvasRenderingContext2DState`, `HTMLCanvasElement`, `TextMetrics`, `Font`, `fillText`, `strokeText`, `measureText`, `transferToGPUTexture`, `transferBackFromGPUTexture`,  and mentions of `javascript`, `html`, `css`, `GPU`, and `WebGPU`. This initial pass provides a high-level understanding.

2. **Function-Level Analysis:** I then examined each significant function individually, focusing on its inputs, actions, and outputs.

    * **`fillText` and `strokeText`:** These clearly deal with rendering text on the canvas. I noted the handling of font styles, text alignment, text direction (RTL/LTR), and the integration with the `TextCluster` object for potentially more complex text layout scenarios. The `identifiability_study_helper_` caught my attention as a non-core functionality, likely for tracking or analytics.

    * **`measureText`:** This function's purpose is self-evident: to calculate the dimensions of a given text string based on the current canvas context's font settings.

    * **`SnapshotStateForFilter`:**  The name suggests capturing the current rendering state, specifically the font, for use with filters.

    * **`setLetterSpacing`, `setWordSpacing`, `setTextRendering*`, `setFontKerning`, `setFontStretch*`, `setFontVariantCaps`:** These are all setters that modify text rendering properties within the `CanvasRenderingContext2DState`. The `UseCounter::Count` lines indicate these features are being tracked for usage statistics.

    * **`getTextureFormat`:** This function retrieves the underlying texture format of the canvas, potentially for interoperability with other graphics APIs like WebGPU.

    * **`transferToGPUTexture`:** This is a significant function. I focused on the steps involved: security checks (origin clean), parameter validation, interaction with `GPUDevice`, flushing the canvas, obtaining a `CanvasResourceProvider`, using `SharedImage` for efficient data transfer to the GPU, creating a `WebGPUMailboxTexture`, and handling potential errors. The logic around discarding previous transfers and ensuring zero-copy was also important.

    * **`transferBackFromGPUTexture`:**  This function reverses the process of `transferToGPUTexture`. I identified the key checks: context validity, previous `transferToGPUTexture` call, no intermediate drawing, and then the steps to restore the `CanvasResourceProvider`, dissociate the WebGPU texture, and signal completion.

3. **Identifying Relationships with Web Technologies:** Based on the function names and parameters, I could directly link many functions to their JavaScript/HTML Canvas API counterparts. For example, `fillText` and `strokeText` directly correspond to the canvas API methods of the same name. The setters for text properties also map directly to their JavaScript equivalents. The `HTMLCanvasElement` interaction is a clear HTML link. The mention of CSS properties like `direction` and `unicode-bidi` provided the CSS connection. The `transferToGPUTexture` and `transferBackFromGPUTexture` functions clearly connect to the WebGPU API.

4. **Logical Inference and Example Generation:**  For functions like `fillText` and `strokeText`, I could infer how different input parameters would affect the output. For example, changing the `textAlign` would shift the text's horizontal position relative to the specified (x, y) coordinates. Similarly, enabling RTL text would flip the text direction. For the GPU transfer functions, the input is the canvas content and the output is a `GPUTexture` object. The reverse is true for `transferBackFromGPUTexture`.

5. **Identifying Potential Usage Errors:** I considered common mistakes developers might make when using these APIs. For example, using invalid or non-finite numbers for coordinates, providing non-positive `maxWidth`, attempting to use the context after it's been lost, or mismanaging the `transferToGPUTexture`/`transferBackFromGPUTexture` workflow.

6. **Debugging Information:** I analyzed the code flow to understand how a user action (like calling `fillText` in JavaScript) could lead to the execution of the code in this file. The interaction between JavaScript, the Canvas API, and the underlying C++ implementation is the key here.

7. **Synthesizing the Summary:** Finally, I organized my findings into the requested sections, starting with a concise overall functionality summary and then elaborating on the specific aspects like JavaScript/HTML/CSS relationships, logical inferences, common errors, debugging, and the overall summary for this part. I used clear and concise language, providing concrete examples where possible. I specifically focused on answering the prompt's questions about each aspect of the code.

**Self-Correction/Refinement during the process:**

* **Initial Focus on Core Rendering:** My initial focus was heavily on the text rendering parts. I realized I needed to give more weight to the WebGPU interaction as it's a significant portion of the code.
* **Clarifying Assumptions:** For the logical inference section, I made sure to explicitly state the assumed input and output for better clarity.
* **Adding Specificity to Errors:** Instead of just saying "using the API incorrectly," I tried to pinpoint common errors with concrete examples related to the specific functions.
* **Improving Debugging Narrative:** I initially had a vague idea of the debugging flow. I refined this by explicitly mentioning the steps from JavaScript calls to the C++ implementation within Blink.
* **Ensuring Completeness for Part 5:** Since this was the final part, I double-checked that the final summary accurately captured the overall functionality of the provided code snippet.

By following these steps, I was able to create a comprehensive and informative summary that addressed all aspects of the prompt.
这是 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 文件的第 5 部分，也是最后一部分。 基于提供的代码片段，我们可以归纳其功能如下：

**归纳功能:**

该代码片段主要集中在 `BaseRenderingContext2D` 类中与 **文本渲染** 和 **与 GPU 纹理交互** 相关的操作。具体来说，它包含了以下功能：

1. **文本渲染的核心逻辑:**  `fillText` 和 `strokeText` 方法实现了在 canvas 上绘制填充或描边文本的功能。这包括：
    * **样式更新:** 确保 canvas 元素的样式是最新的。
    * **获取绘制上下文:** 获取用于绘制的 `cc::PaintCanvas`。
    * **参数校验:** 检查输入坐标和最大宽度是否有效。
    * **可识别性研究支持:**  如果启用，记录绘制文本操作的相关信息。
    * **字体处理:** 获取并使用正确的字体，考虑了 `TextCluster` 中可能存在的字体信息。
    * **文本布局:**  处理文本方向 (LTR/RTL)，对齐方式 (左/中/右/开始/结束)。
    * **文本绘制:**  调用底层的 `Font::DrawBidiText` 方法在 canvas 上绘制文本。
    * **最大宽度处理:**  如果指定了最大宽度，并且文本宽度超过了最大宽度，则会进行缩放以适应。

2. **文本度量:** `measureText` 方法用于测量指定文本在当前 canvas 上渲染后的宽度等信息，返回一个 `TextMetrics` 对象。

3. **快照状态:** `SnapshotStateForFilter` 方法用于在应用滤镜之前捕获当前的渲染状态，特别是字体信息。

4. **文本样式设置:**  提供了一系列方法来设置文本相关的样式属性，例如：
    * `setLetterSpacing`: 设置字母间距。
    * `setWordSpacing`: 设置单词间距。
    * `setTextRenderingAsString` 和 `setTextRendering`: 设置文本渲染方式 (例如，消除锯齿)。
    * `setFontKerning`: 设置字距调整。
    * `setFontStretchAsString` 和 `setFontStretch`: 设置字体拉伸。
    * `setFontVariantCaps`: 设置小型大写字母等变体。

5. **GPU 纹理交互:**  提供了将 canvas 内容传输到 GPU 纹理以及从 GPU 纹理传输回来的功能：
    * `transferToGPUTexture`: 将 canvas 的内容传输到一个 `GPUTexture` 对象，允许 WebGPU 进行访问。这个过程涉及到安全检查、设备验证、资源管理和同步。
    * `transferBackFromGPUTexture`: 将之前传输到 GPU 的纹理内容同步回 canvas。这个过程也需要进行状态检查，确保操作的有效性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这些 C++ 方法是 Canvas 2D API 在 Blink 引擎中的底层实现。开发者在 JavaScript 中调用 canvas 的方法，最终会调用到这里的 C++ 代码。
    * **例子:**  JavaScript 代码 `ctx.fillText("Hello", 10, 50);`  会最终调用到 `BaseRenderingContext2D::fillText` 方法。
    * **例子:**  JavaScript 代码 `const metrics = ctx.measureText("World");` 会调用到 `BaseRenderingContext2D::measureText` 方法。
    * **例子:**  JavaScript 代码 `ctx.letterSpacing = "2px";` 会调用到 `BaseRenderingContext2D::setLetterSpacing` 方法。
    * **例子:**  JavaScript 代码 `canvas.transferToGPUTexture(device);` 会调用到 `BaseRenderingContext2D::transferToGPUTexture` 方法。

* **HTML:** `HTMLCanvasElement` 是 HTML 中 `<canvas>` 标签对应的 DOM 元素。 `BaseRenderingContext2D` 对象通常与一个 `HTMLCanvasElement` 关联。
    * **例子:** 代码中 `HostAsHTMLCanvasElement()` 用于获取与当前渲染上下文关联的 `HTMLCanvasElement` 对象。

* **CSS:**  Canvas 元素的某些样式会影响文本的渲染，例如 `direction` 属性会影响文本的方向 (LTR 或 RTL)。
    * **例子:** 代码中 `ToTextDirection(state.GetDirection(), canvas, &computed_style)` 使用了 CSS 的 `direction` 属性来确定文本方向。

**逻辑推理、假设输入与输出:**

**假设输入 (以 `fillText` 为例):**

* `text`: "Example Text" (字符串)
* `x`: 50.0 (浮点数)
* `y`: 100.0 (浮点数)
* `paint_type`: `CanvasRenderingContext2DState::kFillPaintType` (枚举值，表示填充)
* 当前 canvas 的字体设置为 "16px Arial"
* 当前 canvas 的文本对齐方式设置为 `kLeftTextAlign`

**逻辑推理:**

1. 代码会首先更新 canvas 的样式。
2. 获取用于绘制的 `cc::PaintCanvas`。
3. 检查 `x` 和 `y` 是否是有限数值。
4. 如果启用了可识别性研究，会记录这次 `fillText` 操作。
5. 获取当前 canvas 的字体信息 ("16px Arial")。
6. 根据文本对齐方式 (左对齐)，计算文本绘制的起始 x 坐标。
7. 计算文本的基线位置。
8. 调用底层的字体绘制方法，在 (50, 100) 附近的位置绘制 "Example Text"。

**输出:**

* 在 canvas 上以 "16px Arial" 字体，左对齐的方式，在指定位置填充绘制出 "Example Text"。

**假设输入 (以 `transferToGPUTexture` 为例):**

* 一个已经绘制了一些内容的 `<canvas>` 元素。
* 一个有效的 `GPUDevice` 对象。
* `access_options` 设置了 `usage` 为 `wgpu::TextureUsage::CopySrc | wgpu::TextureUsage::TextureBinding`。

**逻辑推理:**

1. 检查 canvas 的源是否干净 (非跨域污染)。
2. 验证 `GPUDevice` 不为空。
3. 检查是否在 canvas 图层中。
4. 验证 `access_options` 中的 `usage` 标志是否被支持。
5. 刷新 canvas 以确保所有绘制操作都已完成。
6. 获取 canvas 的 `CanvasResourceProvider`。
7. 确保 canvas host 在 GPU 上加速。
8. 获取 canvas 内容的 `SharedImage`。
9. 创建一个由 `SharedImage` 支持的 WebGPU 纹理。
10. 返回创建的 `GPUTexture` 对象。

**输出:**

* 一个表示 canvas 当前内容的 `GPUTexture` 对象，可以在 WebGPU 中使用。

**用户或编程常见的使用错误及举例说明:**

1. **在 `fillText` 或 `strokeText` 中使用无效的坐标:**
   * **错误:** `ctx.fillText("Text", NaN, 50);` 或 `ctx.fillText("Text", 10, Infinity);`
   * **说明:** 代码中会检查坐标是否是有限数值，如果不是则会直接返回，不会绘制任何内容。

2. **在指定 `maxWidth` 时使用非正数或非有限数值:**
   * **错误:** `ctx.fillText("Long Text", 10, 50, -10);` 或 `ctx.fillText("Long Text", 10, 50, NaN);`
   * **说明:** 代码会检查 `maxWidth` 的有效性，如果无效则会直接返回。

3. **在 `transferToGPUTexture` 后修改 canvas 内容，然后尝试 `transferBackFromGPUTexture`:**
   * **错误操作顺序:**
     1. `const texture = canvas.transferToGPUTexture(device);`
     2. `ctx.fillRect(0, 0, 10, 10);` // 修改了 canvas 内容
     3. `canvas.transferBackFromGPUTexture();`
   * **说明:** 代码会检测到在传输到 GPU 后 canvas 内容被修改，`transferBackFromGPUTexture` 会抛出一个 `InvalidStateError` 异常。

4. **多次调用 `transferToGPUTexture` 而不调用 `transferBackFromGPUTexture`:**
   * **错误操作顺序:**
     1. `const texture1 = canvas.transferToGPUTexture(device);`
     2. `const texture2 = canvas.transferToGPUTexture(device);`
   * **说明:**  后续的 `transferToGPUTexture` 调用会放弃之前的传输，并基于当前的 canvas 状态创建一个新的纹理。 开发者可能期望的是保留之前的纹理。

5. **在 `transferToGPUTexture` 之前 canvas 被跨域数据污染，导致安全错误:**
   * **错误操作:**  在 canvas 上绘制了来自不同源的图片，然后尝试 `transferToGPUTexture`。
   * **说明:**  `transferToGPUTexture` 会进行源检查，如果 canvas 被污染，会抛出一个 `SecurityError` 异常。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在网页上与一个使用了 `<canvas>` 元素的页面进行交互。**
2. **JavaScript 代码获取了 canvas 的 2D 渲染上下文 (`ctx = canvas.getContext('2d')`).**
3. **用户触发了某个事件 (例如，点击按钮)。**
4. **与该事件关联的 JavaScript 代码调用了 canvas 2D 上下文的方法，例如 `ctx.fillText("Hello", 10, 50)`。**
5. **浏览器引擎 (Blink) 接收到这个 JavaScript 调用。**
6. **Blink 引擎会将这个 JavaScript 调用转换为对 `BaseRenderingContext2D::fillText` C++ 方法的调用。**
7. **在 `fillText` 方法内部，会执行一系列操作，如更新样式、获取绘制上下文、处理字体、进行文本布局和最终的绘制。**

**调试线索:**

* 如果在 JavaScript 中调用 `fillText` 或 `strokeText` 后，canvas 上没有出现预期的文本，可以设置断点在 `BaseRenderingContext2D::fillText` 或 `BaseRenderingContext2D::strokeText` 的入口处，逐步跟踪代码执行，检查以下内容：
    * 输入参数 `x`, `y`, `text` 的值是否正确。
    * `GetOrCreatePaintCanvas()` 是否返回了有效的绘制上下文。
    * 当前的字体设置是否正确 (`AccessFont(canvas)`).
    * 文本的对齐方式和方向是否符合预期。
    * 是否因为 `max_width` 的限制导致文本未显示。
* 如果在使用 `transferToGPUTexture` 或 `transferBackFromGPUTexture` 时遇到错误，可以断点在这些方法的入口处，检查：
    * `OriginClean()` 的返回值，判断是否是因为跨域问题。
    * `access_options` 的设置是否正确。
    * 在调用 `transferBackFromGPUTexture` 之前，是否修改了 canvas 的内容。
    * `webgpu_access_texture_` 和 `resource_provider_from_webgpu_access_` 的状态，判断调用顺序是否正确。

总而言之，这个代码片段是 Chromium Blink 引擎中 Canvas 2D API 中关于文本渲染和 GPU 纹理交互的核心实现部分，它连接了 JavaScript API 和底层的图形渲染逻辑。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
e to be up to date, but updating style can cause
    // script to run, (e.g. due to autofocus) which can free the canvas (set
    // size to 0, for example), so update style before grabbing the PaintCanvas.
    canvas->GetDocument().UpdateStyleAndLayoutTreeForElement(
        canvas, DocumentUpdateReason::kCanvas);
  }

  // Abort if we don't have a paint canvas (e.g. the context was lost).
  cc::PaintCanvas* paint_canvas = GetOrCreatePaintCanvas();
  if (!paint_canvas) {
    return;
  }

  if (!std::isfinite(x) || !std::isfinite(y)) {
    return;
  }
  if (max_width && (!std::isfinite(*max_width) || *max_width <= 0)) {
    return;
  }

  if (identifiability_study_helper_.ShouldUpdateBuilder()) [[unlikely]] {
    identifiability_study_helper_.UpdateBuilder(
        paint_type == CanvasRenderingContext2DState::kFillPaintType
            ? CanvasOps::kFillText
            : CanvasOps::kStrokeText,
        IdentifiabilitySensitiveStringToken(text), x, y,
        max_width ? *max_width : -1);
    identifiability_study_helper_.set_encountered_sensitive_ops();
  }

  // If rendering a TextCluster that contains a TextMetrics object, use the font
  // stored on that object to recreate the text accurately.
  const Font& font =
      (text_cluster != nullptr && text_cluster->textMetrics() != nullptr)
          ? text_cluster->textMetrics()->GetFont()
          : AccessFont(canvas);
  const SimpleFontData* font_data = font.PrimaryFont();
  DCHECK(font_data);
  if (!font_data) {
    return;
  }

  // FIXME: Need to turn off font smoothing.

  const ComputedStyle* computed_style = nullptr;
  const CanvasRenderingContext2DState& state = GetState();
  TextDirection direction =
      ToTextDirection(state.GetDirection(), canvas, &computed_style);
  bool is_rtl = direction == TextDirection::kRtl;
  bool bidi_override =
      computed_style ? IsOverride(computed_style->GetUnicodeBidi()) : false;

  TextRun text_run(text, direction, bidi_override);
  text_run.SetNormalizeSpace(true);
  // Draw the item text at the correct point.
  gfx::PointF location(ClampTo<float>(x), ClampTo<float>(y));
  gfx::RectF bounds;
  double font_width = 0;
  unsigned run_start = 0, run_end = 0;
  if (text_cluster == nullptr) [[likely]] {
    run_start = 0;
    run_end = text.length();
    font_width = font.Width(text_run, &bounds);
  } else {
    run_start = text_cluster->begin();
    run_end = text_cluster->end();
    font_width = font.SubRunWidth(text_run, run_start, run_end, &bounds);
  }

  bool use_max_width = (max_width && *max_width < font_width);
  double width = use_max_width ? *max_width : font_width;

  TextAlign align = (text_cluster == nullptr) ? state.GetTextAlign()
                                              : text_cluster->GetTextAlign();
  if (align == kStartTextAlign) {
    align = is_rtl ? kRightTextAlign : kLeftTextAlign;
  } else if (align == kEndTextAlign) {
    align = is_rtl ? kLeftTextAlign : kRightTextAlign;
  }

  switch (align) {
    case kCenterTextAlign:
      location.set_x(location.x() - width / 2);
      break;
    case kRightTextAlign:
      location.set_x(location.x() - width);
      break;
    default:
      break;
  }

  if (text_cluster == nullptr) [[likely]] {
    // Use the current ctx baseline.
    location.Offset(0, GetFontBaseline(*font_data));
  } else {
    // Use the baseline passed in the TextCluster.
    location.Offset(0, TextMetrics::GetFontBaseline(
                           text_cluster->GetTextBaseline(), *font_data));
  }

  bounds.Offset(location.x(), location.y());
  if (paint_type == CanvasRenderingContext2DState::kStrokePaintType) {
    InflateStrokeRect(bounds);
  }

  if (use_max_width) {
    paint_canvas->save();
    // We draw when fontWidth is 0 so compositing operations (eg, a "copy" op)
    // still work. As the width of canvas is scaled, so text can be scaled to
    // match the given maxwidth, update text location so it appears on desired
    // place.
    paint_canvas->scale(ClampTo<float>(width / font_width), 1);
    location.set_x(location.x() / ClampTo<float>(width / font_width));
  }

  Draw<OverdrawOp::kNone>(
      [font, text = std::move(text), direction, bidi_override, location,
       run_start, run_end,
       canvas](cc::PaintCanvas* c, const cc::PaintFlags* flags)  // draw lambda
      {
        TextRun text_run(text, direction, bidi_override);
        text_run.SetNormalizeSpace(true);
        TextRunPaintInfo text_run_paint_info(text_run);
        text_run_paint_info.from = run_start;
        text_run_paint_info.to = run_end;
        // Font::DrawType::kGlyphsAndClusters is required for printing to PDF,
        // otherwise the character to glyph mapping will not be reversible,
        // which prevents text data from being extracted from PDF files or
        // from the print preview. This is only needed in vector printing mode
        // (i.e. when rendering inside the beforeprint event listener),
        // because in all other cases the canvas is just a rectangle of pixels.
        // Note: Test coverage for this is assured by manual (non-automated)
        // web test printing/manual/canvas2d-vector-text.html
        // That test should be run manually against CLs that touch this code.
        Font::DrawType draw_type = (canvas && canvas->IsPrinting())
                                       ? Font::DrawType::kGlyphsAndClusters
                                       : Font::DrawType::kGlyphsOnly;
        font.DrawBidiText(c, text_run_paint_info, location,
                          Font::kUseFallbackIfFontNotReady, *flags, draw_type);
      },
      [](const SkIRect& rect)  // overdraw test lambda
      { return false; },
      bounds, paint_type, CanvasRenderingContext2DState::kNoImage,
      CanvasPerformanceMonitor::DrawType::kText);

  if (use_max_width) {
    // Make sure that `paint_canvas` is still valid and active. Calling `Draw`
    // might reset `paint_canvas`. If that happens, `GetOrCreatePaintCanvas`
    // will create a new `paint_canvas` and return a new address. This new
    // canvas won't have the `save()` added above, so it would be invalid to
    // call `restore()` here.
    if (paint_canvas == GetOrCreatePaintCanvas()) {
      paint_canvas->restore();
    }
  }
  ValidateStateStack();
}

TextMetrics* BaseRenderingContext2D::measureText(const String& text) {
  // The style resolution required for fonts is not available in frame-less
  // documents.
  HTMLCanvasElement* canvas = HostAsHTMLCanvasElement();

  if (canvas) {
    if (!canvas->GetDocument().GetFrame()) {
      return MakeGarbageCollected<TextMetrics>();
    }

    canvas->GetDocument().UpdateStyleAndLayoutTreeForElement(
        canvas, DocumentUpdateReason::kCanvas);
  }

  const Font& font = AccessFont(canvas);

  const CanvasRenderingContext2DState& state = GetState();
  TextDirection direction = ToTextDirection(state.GetDirection(), canvas);

  return MakeGarbageCollected<TextMetrics>(
      font, direction, state.GetTextBaseline(), state.GetTextAlign(), text);
}

void BaseRenderingContext2D::SnapshotStateForFilter() {
  auto* canvas = HostAsHTMLCanvasElement();
  // The style resolution required for fonts is not available in frame-less
  // documents.
  if (canvas && !canvas->GetDocument().GetFrame()) {
    return;
  }

  GetState().SetFontForFilter(AccessFont(canvas));
}

void BaseRenderingContext2D::setLetterSpacing(const String& letter_spacing) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DLetterSpacing);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();
  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }

  state.SetLetterSpacing(letter_spacing);
}

void BaseRenderingContext2D::setWordSpacing(const String& word_spacing) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DWordSpacing);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();

  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }

  state.SetWordSpacing(word_spacing);
}

void BaseRenderingContext2D::setTextRenderingAsString(
    const String& text_rendering_string) {
  std::optional<blink::V8CanvasTextRendering> text_value =
      V8CanvasTextRendering::Create(text_rendering_string);

  if (!text_value.has_value()) {
    return;
  }
  setTextRendering(text_value.value());
}

void BaseRenderingContext2D::setTextRendering(
    const V8CanvasTextRendering& text_rendering) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DTextRendering);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();
  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }

  if (state.GetTextRendering() == text_rendering) {
    return;
  }
  state.SetTextRendering(text_rendering, GetFontSelector());
}

void BaseRenderingContext2D::setFontKerning(const String& font_kerning_string) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DFontKerning);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();
  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }
  FontDescription::Kerning kerning;
  if (font_kerning_string == kAutoKerningString) {
    kerning = FontDescription::kAutoKerning;
  } else if (font_kerning_string == kNoneKerningString) {
    kerning = FontDescription::kNoneKerning;
  } else if (font_kerning_string == kNormalKerningString) {
    kerning = FontDescription::kNormalKerning;
  } else {
    return;
  }

  if (state.GetFontKerning() == kerning) {
    return;
  }

  state.SetFontKerning(kerning, GetFontSelector());
}

void BaseRenderingContext2D::setFontStretchAsString(
    const String& font_stretch) {
  std::optional<V8CanvasFontStretch> font_value =
      V8CanvasFontStretch::Create(font_stretch);

  if (!font_value.has_value()) {
    return;
  }
  setFontStretch(font_value.value());
}

void BaseRenderingContext2D::setFontStretch(
    const V8CanvasFontStretch& font_stretch) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DFontStretch);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();
  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }

  if (state.GetFontStretch() == font_stretch) {
    return;
  }
  state.SetFontStretch(font_stretch, GetFontSelector());
}

void BaseRenderingContext2D::setFontVariantCaps(
    const String& font_variant_caps_string) {
  UseCounter::Count(GetTopExecutionContext(),
                    WebFeature::kCanvasRenderingContext2DFontVariantCaps);
  // TODO(crbug.com/1234113): Instrument new canvas APIs.
  identifiability_study_helper_.set_encountered_skipped_ops();
  CanvasRenderingContext2DState& state = GetState();
  if (!state.HasRealizedFont()) {
    setFont(font());
  }
  FontDescription::FontVariantCaps variant_caps;
  if (font_variant_caps_string == kNormalVariantString) {
    variant_caps = FontDescription::kCapsNormal;
  } else if (font_variant_caps_string == kSmallCapsVariantString) {
    variant_caps = FontDescription::kSmallCaps;
  } else if (font_variant_caps_string == kAllSmallCapsVariantString) {
    variant_caps = FontDescription::kAllSmallCaps;
  } else if (font_variant_caps_string == kPetiteVariantString) {
    variant_caps = FontDescription::kPetiteCaps;
  } else if (font_variant_caps_string == kAllPetiteVariantString) {
    variant_caps = FontDescription::kAllPetiteCaps;
  } else if (font_variant_caps_string == kUnicaseVariantString) {
    variant_caps = FontDescription::kUnicase;
  } else if (font_variant_caps_string == kTitlingCapsVariantString) {
    variant_caps = FontDescription::kTitlingCaps;
  } else {
    return;
  }

  if (state.GetFontVariantCaps() == variant_caps) {
    return;
  }

  state.SetFontVariantCaps(variant_caps, GetFontSelector());
}

FontSelector* BaseRenderingContext2D::GetFontSelector() const {
  return nullptr;
}

bool BaseRenderingContext2D::IsAccelerated() const {
  CanvasRenderingContextHost* host = GetCanvasRenderingContextHost();
  if (host) {
    return host->GetRasterMode() == RasterMode::kGPU;
  }
  return false;
}

V8GPUTextureFormat BaseRenderingContext2D::getTextureFormat() const {
  // Query the canvas and return its actual texture format.
  std::optional<V8GPUTextureFormat> format;
  if (const CanvasRenderingContextHost* host =
          GetCanvasRenderingContextHost()) {
    format = FromDawnEnum(
        AsDawnType(host->GetRenderingContextSkColorInfo().colorType()));
  }

  // If that did not work (e.g., the canvas host does not yet exist), we can
  // return the preferred canvas format.
  if (!format.has_value()) {
    format = FromDawnEnum(GPU::preferred_canvas_format());
  }

  // If the preferred canvas format cannot be represented as a GPUTextureFormat,
  // something is wrong; we need to investigate.
  CHECK(format.has_value()) << "GPU::preferred_canvas_format() returned an "
                               "unrecognized texture format";
  return *format;
}

GPUTexture* BaseRenderingContext2D::transferToGPUTexture(
    const Canvas2dGPUTransferOption* access_options,
    ExceptionState& exception_state) {
  if (!OriginClean()) {
    exception_state.ThrowSecurityError(
        "The canvas has been tainted by cross-origin data.");
    return nullptr;
  }

  blink::GPUDevice* blink_device = access_options->getDeviceOr(nullptr);
  if (!blink_device) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "GPUDevice cannot be null.");
    return nullptr;
  }

  // Verify that we are not inside a canvas layer.
  if (layer_count_ > 0) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "A layer is currently active.");
    return nullptr;
  }

  // Verify that the usage flags are supported.
  constexpr wgpu::TextureUsage kSupportedUsageFlags =
      wgpu::TextureUsage::CopySrc | wgpu::TextureUsage::CopyDst |
      wgpu::TextureUsage::TextureBinding | wgpu::TextureUsage::RenderAttachment;

  // If `transferToGPUTexture` is called twice without an intervening call to
  // `transferBackFromGPUTexture`, the semantics are that the current ongoing
  // transfer should be discarded and the new transfer given the 2D canvas in
  // its current state (defined to be blank post-initiation of the first
  // transfer but then incorporating any canvas 2D operations that have
  // subsequently occurred on the canvas). Implement that semantics here.
  // Note that the canvas will have been made blank by the removal of the
  // CanvasResourceProvider at the initiation of the first transfer but will
  // then incorporate any canvas 2D operations that have subsequently occurred
  // on the canvas via the usage of the CanvasResourceProvider that those
  // operations would have caused to be created as the source for the new
  // transfer below.
  if (webgpu_access_texture_) {
    webgpu_access_texture_->destroy();
    webgpu_access_texture_ = nullptr;
    resource_provider_from_webgpu_access_.reset();
  }

  wgpu::TextureUsage tex_usage =
      AsDawnFlags<wgpu::TextureUsage>(access_options->usage());
  if (tex_usage & ~kSupportedUsageFlags) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Usage flags are not supported.");
    return nullptr;
  }

  // Prepare to flush the canvas to a WebGPU texture.
  FinalizeFrame(FlushReason::kWebGPUTexture);

  // We will need to access the canvas' resource provider.
  CanvasRenderingContextHost* host = GetCanvasRenderingContextHost();
  if (!host) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Unable to access canvas image.");
    return nullptr;
  }
  host->SetTransferToGPUTextureWasInvoked();

  // Ensure that the canvas host lives on the GPU. This call is a no-op if the
  // host is already accelerated.
  // TODO(crbug.com/340911120): if the user requested WillReadFrequently, do we
  // want to behave differently here?
  const bool host_is_accelerated = host->EnableAcceleration();

  // A texture needs to exist on the GPU. If we aren't able to enable
  // acceleration, the canvas pixels live on the CPU and we weren't able to
  // transfer them; in that case, WebGPU access is not possible.
  CanvasResourceProvider* provider =
      host->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);
  if (!host_is_accelerated || !provider || !provider->IsAccelerated()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Unable to transfer canvas to GPU.");
    return nullptr;
  }

  // Get the SharedImage backing this canvas resource, signaling that an
  // external write will occur. This call will ensure that a copy occurs if
  // needed for CopyOnWrite or for creation of a SharedImage with WebGPU usage
  // and will end the canvas access.
  gpu::SyncToken canvas_access_sync_token;
  bool performed_copy = false;
  scoped_refptr<gpu::ClientSharedImage> client_si =
      host->ResourceProvider()->GetBackingClientSharedImageForExternalWrite(
          &canvas_access_sync_token,
          gpu::SHARED_IMAGE_USAGE_WEBGPU_READ |
              gpu::SHARED_IMAGE_USAGE_WEBGPU_WRITE,
          &performed_copy);
  if (access_options->requireZeroCopy() && performed_copy) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Transferring canvas to GPU was not zero-copy.");
    return nullptr;
  }

  // If the backing SharedImage is not available (e.g., because the GPU context
  // has been lost), zero-copy transfer is not possible.
  if (!client_si) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Unable to transfer canvas to GPU.");
    return nullptr;
  }

  wgpu::TextureFormat dawn_format =
      AsDawnType(viz::ToClosestSkColorType(true, client_si->format()));
  wgpu::TextureDescriptor desc = {
      .usage = tex_usage,
      .size = {base::checked_cast<uint32_t>(client_si->size().width()),
               base::checked_cast<uint32_t>(client_si->size().height())},
      .format = dawn_format,
  };

  // Create a WebGPU texture backed by the resource's SharedImage.
  scoped_refptr<WebGPUMailboxTexture> texture =
      WebGPUMailboxTexture::FromExistingSharedImage(
          blink_device->GetDawnControlClient(), blink_device->GetHandle(), desc,
          client_si,
          // Ensure that WebGPU waits for the 2D canvas service-side operations
          // on this resource to complete.
          canvas_access_sync_token);

  webgpu_access_texture_ = MakeGarbageCollected<GPUTexture>(
      blink_device, dawn_format, tex_usage, std::move(texture),
      access_options->getLabelOr(String()));

  // We take away the canvas' resource provider here, which will cause the
  // canvas to be treated as a brand new surface if additional draws occur.
  // It also gives us a mechanism to detect post-transfer-out draws, which is
  // used in `transferBackFromWebGPU` to raise an exception.
  resource_provider_from_webgpu_access_ =
      host->ReplaceResourceProvider(nullptr);

  // The user isn't obligated to ever transfer back, which means this resource
  // provider might stick around for while. Jettison any unnecessary resources.
  resource_provider_from_webgpu_access_->ClearRecycledResources();

  return webgpu_access_texture_;
}

void BaseRenderingContext2D::transferBackFromGPUTexture(
    ExceptionState& exception_state) {
  // If the context is lost or doesn't exist, this call should be a no-op.
  // We don't want to throw an exception or attempt any changes if
  // `transferBackFromWebGPU` is called during teardown.
  CanvasRenderingContextHost* host = GetCanvasRenderingContextHost();
  if (!host || isContextLost()) [[unlikely]] {
    return;
  }

  // Prevent unbalanced calls to transferBackFromGPUTexture without an earlier
  // call to transferToGPUTexture.
  if (!webgpu_access_texture_ || !resource_provider_from_webgpu_access_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "This canvas is not currently in use by WebGPU.");
    webgpu_access_texture_ = nullptr;
    resource_provider_from_webgpu_access_ = nullptr;
    return;
  }

  // If this canvas already has a resource provider, this means that drawing has
  // occurred after `transferToWebGPU`. We disallow transferring back in this
  // case, and raise an exception instead.
  if (host->ResourceProvider()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The canvas was touched after transferToGPUTexture.");
    webgpu_access_texture_ = nullptr;
    resource_provider_from_webgpu_access_ = nullptr;
    return;
  }

  // If the caller explicitly destroyed the WebGPU access texture, there is
  // nothing to transfer.
  if (webgpu_access_texture_->Destroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "The texture has been destroyed.");
    webgpu_access_texture_ = nullptr;
    resource_provider_from_webgpu_access_ = nullptr;
    return;
  }

  // Restore the canvas' resource provider back onto the canvas host,
  // surrendering our temporary ownership of the provider.
  CanvasResourceProvider* resource_provider =
      resource_provider_from_webgpu_access_.get();
  host->ReplaceResourceProvider(
      std::move(resource_provider_from_webgpu_access_));
  resource_provider->SetCanvasResourceHost(host);

  // Disassociate the WebGPU texture from the SharedImage to end its
  // SharedImage access.
  gpu::SyncToken webgpu_completion_sync_token =
      webgpu_access_texture_->GetMailboxTexture()->Dissociate();

  // Signal to the resource provider that the external write to the resource has
  // completed to ensure that it waits on the WebGPU service-side operations to
  // complete before any further canvas operations occur.
  resource_provider->EndExternalWrite(webgpu_completion_sync_token);

  // Destroy the WebGPU texture to prevent it from being used after
  // `transferBackFromGPUTexture`.
  webgpu_access_texture_->destroy();

  // We are finished with the WebGPU texture and its associated device.
  webgpu_access_texture_ = nullptr;

  WillDraw(SkIRect::MakeXYWH(0, 0, Width(), Height()),
           CanvasPerformanceMonitor::DrawType::kOther);
}

}  // namespace blink

"""


```
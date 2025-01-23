Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine test file. This is the second part of a five-part request. The goal is to summarize the functionality demonstrated in this specific chunk of code.

The code consists of a series of C++ tests using the Google Test framework. Each test focuses on verifying the behavior of the `CanvasRenderingContext2D` API, particularly in the context of:

1. **`clearRect()`:** How `clearRect()` interacts with other drawing operations (like `fillRect()`) and its impact on overdraw calculations. It explores scenarios with full and partial coverage, within layers (including nested layers), with global alpha, transparent gradients, filters, and transforms applied. It also checks how `clearRect()` behaves when the canvas is clipped.

2. **`drawImage()`:**  Similar to `clearRect()`, it examines the interaction of `drawImage()` with other drawing operations and overdraw calculations. Scenarios include exact, magnified, and partial coverage of the target area. It also covers cases with global alpha, transparent bitmaps, filters, and transforms applied. The tests differentiate between opaque and transparent source bitmaps and destination gradients. Special attention is paid to the "copy" composite operation. Like `clearRect()`, it checks the behavior when the canvas is clipped.

3. **`putImageData()`:** This test checks how `putImageData()` interacts with other drawing operations and resource management. It specifically looks at full and partial coverage scenarios and how they trigger rasterization and pixel writing. It notes that `putImageData` doesn't contribute to the overdraw calculations in the same way as other drawing operations.

4. **Paths:** A test briefly touches on path operations (`rect()` and `fill()`) and notes that the current overdraw detection logic doesn't fully account for paths.

5. **Resource Lifetime:** Tests ensure that `ImageBitmap` objects derived from canvases are properly managed and don't cause issues when the original canvas is destroyed.

6. **GPU Memory Management:** Tests check how the canvas manages GPU memory when switching between accelerated and non-accelerated rendering modes and when dealing with multiple canvases.

7. **Context and Canvas Disposal:** Tests verify that the application doesn't crash when the `CanvasRenderingContext2D` or the `HTMLCanvasElement` is disposed of in different orders.

8. **High Bit Depth PNGs:**  A test examines how the canvas handles drawing and retrieving pixel data from high bit depth PNG images, particularly in wide gamut color spaces.

Therefore, the main functionality demonstrated in this part of the code is **testing the drawing operations of the `CanvasRenderingContext2D` API, particularly `clearRect`, `drawImage`, and `putImageData`, focusing on their interactions with other canvas state and operations and their impact on overdraw detection and GPU memory management.**
这是对 `blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc` 文件的一部分的总结。这部分代码主要关注于 `CanvasRenderingContext2D` 接口中 **清除矩形 (`clearRect`)** 和 **绘制图像 (`drawImage`, `putImageData`)** 功能的测试，并涉及到了一些高级特性如 **图层 (Layers)**, **全局透明度 (globalAlpha)**, **滤镜 (filter)**, **变换 (transform)**, **裁剪 (clip)** 以及 **合成操作 (globalCompositeOperation)** 的影响。 此外，还包括对 **路径 (Path)** 的简单测试，以及对 **图像资源生命周期管理** 和 **GPU 内存管理** 的测试。最后，涉及到 **Canvas 和 Context 的析构顺序** 以及 **高位深 PNG 图片在 Canvas 上的渲染和像素读取** 的测试。

**具体功能归纳:**

1. **`clearRect()` 功能测试:**
   - 验证 `clearRect()` 在完全覆盖和部分覆盖画布区域时的行为，并检查其对 overdraw (过度绘制) 的影响。
   - 测试在图层内部和嵌套图层内部使用 `clearRect()` 的效果。
   - 验证全局透明度、透明渐变和滤镜对 `clearRect()` 的影响。
   - 测试在应用变换后，`clearRect()` 在不同覆盖程度下的行为。
   - 验证 `clearRect()` 是否忽略合成操作的影响。
   - 测试在裁剪区域内使用 `clearRect()` 的效果。

2. **`drawImage()` 功能测试:**
   - 测试 `drawImage()` 在不同覆盖程度（精确覆盖、放大、部分覆盖、完全覆盖）下的行为和 overdraw 情况。
   - 验证全局透明度、透明位图和滤镜对 `drawImage()` 的影响。
   - 测试在应用变换后，`drawImage()` 在不同覆盖程度下的行为。
   - 验证当源图像和目标区域具有不同的透明度特性时 (`TransparenBitmapOpaqueGradient`, `OpaqueBitmapTransparentGradient`) `drawImage()` 的行为。
   - 测试在 `globalCompositeOperation` 设置为 `copy` 时 `drawImage()` 的行为。
   - 测试在裁剪区域内使用 `drawImage()` 的效果。

3. **`putImageData()` 功能测试:**
   - 测试 `putImageData()` 在完全覆盖和部分覆盖画布时的行为。
   - 验证 `putImageData()` 操作如何影响画布的资源提供者 (Resource Provider) 的 `RasterRecord` 和 `WritePixels` 调用。
   - 指出 `putImageData` 的 overdraw 不像其他绘制操作那样被 `BaseRenderingContext2D::CheckOverdraw` 处理。

4. **路径 (`Path`) 功能测试:**
   - 一个简单的测试用例，展示了绘制矩形路径并填充的行为，并指出当前的 overdraw 检测逻辑不完全支持路径。

5. **图像资源生命周期管理测试:**
   - 测试 `ImageBitmap` 对象从 `HTMLCanvasElement` 创建和派生后，其生命周期是否得到正确管理。

6. **GPU 内存管理测试:**
   - 验证在加速 Canvas 和非加速 Canvas 之间切换时，GPU 内存使用情况是否得到正确更新。
   - 测试创建和销毁不同的加速图像缓冲区时，GPU 内存管理是否正常。

7. **Canvas 和 Context 的析构顺序测试:**
   - 测试当 `HTMLCanvasElement` 在其关联的 `CanvasRenderingContext2D` 之前被析构时，是否会发生崩溃。
   - 测试当 `CanvasRenderingContext2D` 在其关联的 `HTMLCanvasElement` 之前被析构时，是否会发生崩溃。

8. **高位深 PNG 图片测试:**
   - 测试在宽色域 Canvas 上绘制高位深 PNG 图片，并获取像素数据，验证颜色空间的转换和像素值的正确性。

**与 JavaScript, HTML, CSS 的功能关系及举例:**

- **JavaScript:** 这些测试直接测试的是通过 JavaScript API 暴露的 Canvas 2D 渲染上下文的方法，例如 `clearRect()`, `fillRect()`, `drawImage()`, `putImageData()`, `setGlobalAlpha()`, `setFilter()`, `translate()`, `clip()`, `setGlobalCompositeOperation()`, `rect()`, `fill()`, `beginLayer()`, `endLayer()` 等。开发者在 JavaScript 中调用这些方法来控制 Canvas 的绘制行为。

  ```javascript
  const canvas = document.getElementById('myCanvas');
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = 'red';
  ctx.fillRect(10, 10, 50, 50); // 对应测试中的 FillFlags()

  ctx.clearRect(0, 0, canvas.width, canvas.height); // 对应测试中的 ClearRectFlags()

  const img = new Image();
  img.onload = function() {
    ctx.drawImage(img, 0, 0); // 对应测试中的 DrawImageRectOp()
  };
  img.src = 'image.png';

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  ctx.putImageData(imageData, 0, 0); // 对应测试中的 putImageData()
  ```

- **HTML:** `<canvas>` 元素是这些功能的基础。测试中通过 `CanvasElement()` 来获取和操作 `<canvas>` 元素，例如设置其大小 (`SetSize`)。

  ```html
  <canvas id="myCanvas" width="200" height="100"></canvas>
  ```

- **CSS:** 虽然这部分测试主要关注 JavaScript API，但 CSS 的样式可以影响 Canvas 的最终渲染结果，例如 Canvas 的尺寸和初始背景色。在实际应用中，开发者可能会使用 CSS 来控制 Canvas 的布局和外观。

**逻辑推理的假设输入与输出:**

这部分代码主要是单元测试，它会预设一些状态和操作，然后验证 Canvas 的输出是否符合预期。例如：

- **假设输入:** 先使用 `fillRect` 绘制一个矩形，然后使用 `clearRect` 清除包含该矩形的区域。
- **预期输出:** `FlushCanvas` 操作应该只包含一个 `DrawRectOp`，并且带有 `ClearRectFlags`，表示清除操作覆盖了之前的绘制。

- **假设输入:**  设置 `globalAlpha` 为 0.5，然后使用 `fillRect` 绘制一个矩形，再使用 `clearRect` 清除覆盖该矩形的区域。
- **预期输出:** `FlushCanvas` 操作应该只包含一个带有 `ClearRectFlags` 的 `DrawRectOp`，即使之前绘制的矩形受到了 `globalAlpha` 的影响。

**用户或编程常见的使用错误举例:**

- **未正确理解 `clearRect` 的作用:** 开发者可能认为 `clearRect` 只是将颜色设置为透明，而不是完全擦除绘制记录。这会导致对 overdraw 的理解出现偏差。测试用例 `ClearRect_PartialCoverage` 和 `ClearRect_CompleteCoverage` 验证了 `clearRect` 的擦除行为。
- **在图层中使用 `clearRect` 的预期错误:** 开发者可能不清楚在图层中使用 `clearRect` 会影响整个图层，而不仅仅是当前绘制的图形。`ClearRect_InsideLayer` 和 `ClearRect_InsideNestedLayer` 测试了这种情况。
- **不了解变换对 `clearRect` 和 `drawImage` 的影响:** 开发者可能没有考虑到变换矩阵会影响 `clearRect` 和 `drawImage` 操作的实际作用范围。 `ClearRect_TransformPartialCoverage` 和 `DrawImage_TransformPartialCoverage` 测试了这些情况。
- **错误地使用 `putImageData` 进行动画或频繁更新:** 由于 `putImageData` 会强制刷新画布，频繁调用可能会导致性能问题。测试用例 `PutImageData_PartialCoverage` 演示了 `putImageData` 如何触发画布刷新。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个包含 Canvas 的网页。**
2. **网页的 JavaScript 代码获取 Canvas 2D 渲染上下文。**
3. **JavaScript 代码调用 `clearRect()`, `drawImage()`, `putImageData()` 等方法进行绘制操作。**
4. **如果 Canvas 的渲染结果不符合预期（例如，图像没有正确显示，部分区域没有被清除），开发者可能会怀疑 Canvas 2D 渲染上下文的实现有问题。**
5. **为了调试，开发者可能会查看浏览器引擎（例如 Blink）的源代码，特别是与 Canvas 2D 渲染相关的部分。**
6. **`blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc` 文件中的测试用例可以帮助开发者理解特定 Canvas API 的行为和实现细节。**
7. **通过阅读和运行这些测试，开发者可以验证他们的理解是否正确，并找到潜在的 Bug 或实现上的偏差。**
8. **如果测试失败，可以提供更精确的线索，指出 Canvas 2D 渲染的哪个环节出现了问题。**

总而言之，这部分测试代码主要验证了 `CanvasRenderingContext2D` 接口中与清除和绘制图像相关的核心功能，并考虑了各种影响因素，确保这些功能在不同场景下的行为符合预期。这些测试对于保证 Canvas API 的正确性和性能至关重要。

### 提示词
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
Coverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 10, 10), ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_PartialCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 9, 9);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 1, 1), FillFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 9, 9),
                                ClearRectFlags()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_InsideLayer) {
  // Overdraw is not currently implemented when layers are opened.
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState no_exception;
  Context2D()->fillRect(1, 1, 1, 1);
  Context2D()->beginLayer(GetScriptState(), BeginLayerOptions::Create(),
                          no_exception);
  Context2D()->fillRect(2, 2, 2, 2);
  Context2D()->clearRect(0, 0, 10, 10);
  Context2D()->fillRect(3, 3, 3, 3);
  Context2D()->endLayer(no_exception);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 1, 1), FillFlags()),
          DrawRecordOpEq(
              PaintOpEq<SaveLayerAlphaOp>(1.0f),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(2, 2, 2, 2), FillFlags()),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 10),
                                    ClearRectFlags()),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 3, 3), FillFlags()),
              PaintOpEq<RestoreOp>()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_InsideNestedLayer) {
  // Overdraw is not currently implemented when layers are opened.
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState no_exception;
  Context2D()->fillRect(1, 1, 1, 1);
  Context2D()->beginLayer(GetScriptState(), BeginLayerOptions::Create(),
                          no_exception);
  Context2D()->fillRect(2, 2, 2, 2);
  Context2D()->beginLayer(GetScriptState(), BeginLayerOptions::Create(),
                          no_exception);
  Context2D()->fillRect(3, 3, 3, 3);
  Context2D()->clearRect(0, 0, 10, 10);
  Context2D()->fillRect(4, 4, 4, 4);
  Context2D()->endLayer(no_exception);
  Context2D()->endLayer(no_exception);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 1, 1), FillFlags()),
          DrawRecordOpEq(
              PaintOpEq<SaveLayerAlphaOp>(1.0f),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(2, 2, 2, 2), FillFlags()),
              PaintOpEq<SaveLayerAlphaOp>(1.0f),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 3, 3), FillFlags()),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 10),
                                    ClearRectFlags()),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(4, 4, 4, 4), FillFlags()),
              PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_GlobalAlpha) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->setGlobalAlpha(0.5f);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 10, 10), ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_TransparentGradient) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  auto* script_state = GetScriptState();
  ScriptState::Scope script_state_scope(script_state);
  SetFillStyleHelper(Context2D(), script_state, AlphaGradient().Get());
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 10, 10), ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_Filter) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  V8UnionCanvasFilterOrString* filter =
      MakeGarbageCollected<V8UnionCanvasFilterOrString>("blur(4px)");
  Context2D()->setFilter(ToScriptStateForMainWorld(GetDocument().GetFrame()),
                         filter);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 10, 10), ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_TransformPartialCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->translate(1, 1);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpIs<TranslateOp>(),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 1, 1), FillFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 10),
                                ClearRectFlags()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_TransformCompleteCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->translate(1, 1);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(-1, -1, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(
                  PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 1,  //
                                               0, 1, 0, 1,  //
                                               0, 0, 1, 0,  //
                                               0, 0, 0, 1)),
                  PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(-1, -1, 10, 10),
                                        ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect,
                            BaseRenderingContext2D::OverdrawOp::kHasTransform));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_IgnoreCompositeOp) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->setGlobalCompositeOperation(String("destination-in"));
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 10, 10), ClearRectFlags()))));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kClearRect));
}

TEST_P(CanvasRenderingContext2DTest, ClearRect_Clipped) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->rect(0, 0, 5, 5);
  Context2D()->clip();
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->clearRect(0, 0, 10, 10);

  EXPECT_THAT(
      Context2D()->FlushCanvas(FlushReason::kTesting),
      Optional(RecordedOpsAre(
          PaintOpIs<ClipRectOp>(),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 1, 1), FillFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 10),
                                ClearRectFlags()))));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_ExactCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kDrawImage));
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_Magnified) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 1, 1, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kDrawImage));
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_GlobalAlpha) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->setGlobalAlpha(0.5f);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_TransparentBitmap) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&alpha_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_Filter) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  V8UnionCanvasFilterOrString* filter =
      MakeGarbageCollected<V8UnionCanvasFilterOrString>("blur(4px)");
  Context2D()->setFilter(ToScriptStateForMainWorld(GetDocument().GetFrame()),
                         filter);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(
                  // Composited DrawRectOp:
                  PaintOpIs<SetMatrixOp>(), PaintOpIs<SaveLayerOp>(),
                  PaintOpIs<SetMatrixOp>(), PaintOpIs<DrawRectOp>(),
                  PaintOpIs<RestoreOp>(), PaintOpIs<SetMatrixOp>(),
                  // Composited DrawImageRectOp:
                  PaintOpIs<SetMatrixOp>(), PaintOpIs<SaveLayerOp>(),
                  PaintOpIs<SetMatrixOp>(), PaintOpIs<DrawImageRectOp>(),
                  PaintOpIs<RestoreOp>(), PaintOpIs<SetMatrixOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_PartialCoverage1) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 1, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_FALSE(exception_state.HadException());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_PartialCoverage2) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 9, 9,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_FullCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 11, 11,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kDrawImage));
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_TransformFullCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->translate(-1, 0);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 1, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<SetMatrixOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kDrawImage,
                            BaseRenderingContext2D::OverdrawOp::kHasTransform));
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_TransformPartialCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->translate(-1, 0);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<TranslateOp>(),  //
                                      PaintOpIs<DrawRectOp>(),   //
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_TransparenBitmapOpaqueGradient) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  auto* script_state = GetScriptState();
  ScriptState::Scope script_state_scope(script_state);
  NonThrowableExceptionState exception_state;
  SetFillStyleHelper(Context2D(), GetScriptState(), OpaqueGradient().Get());
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&alpha_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest,
       DrawImage_OpaqueBitmapTransparentGradient) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  auto* script_state = GetScriptState();
  ScriptState::Scope script_state_scope(script_state);
  NonThrowableExceptionState exception_state;
  SetFillStyleHelper(Context2D(), GetScriptState(), AlphaGradient().Get());
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester,
              OverdrawOpAre(BaseRenderingContext2D::OverdrawOp::kTotal,
                            BaseRenderingContext2D::OverdrawOp::kDrawImage));
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_CopyPartialCoverage) {
  // The 'copy' blend mode no longer trigger the overdraw optimization
  // Reason: low real-world incidence, test overhead not justified.
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->setGlobalCompositeOperation(String("copy"));
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 1, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(
                  // Copy composite op clears the frame before each draw ops.
                  PaintOpIs<DrawColorOp>(), PaintOpIs<DrawRectOp>(),
                  PaintOpIs<DrawColorOp>(), PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_CopyTransformPartialCoverage) {
  // Overdraw optimizations with the 'copy' composite operation are no longer
  // supported. Reason: low real-world incidence, test overhead not justified.
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->setGlobalCompositeOperation(String("copy"));
  Context2D()->translate(1, 1);
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 1, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(
                  PaintOpIs<TranslateOp>(),
                  // Copy composite op clears the frame before each draw ops.
                  PaintOpIs<DrawColorOp>(), PaintOpIs<DrawRectOp>(),
                  PaintOpIs<DrawColorOp>(), PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, DrawImage_Clipped) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  NonThrowableExceptionState exception_state;
  Context2D()->rect(0, 0, 5, 5);
  Context2D()->clip();
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->drawImage(&opaque_bitmap_, 0, 0, 10, 10, 0, 0, 10, 10,
                         exception_state);

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<ClipRectOp>(),  //
                                      PaintOpIs<DrawRectOp>(),  //
                                      PaintOpIs<DrawImageRectOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, PutImageData_FullCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);

  // The recording will be cleared, so nothing will be rastered before
  // `WritePixels` is called.
  InSequence s;
  EXPECT_CALL(*provider, RasterRecord).Times(0);
  EXPECT_CALL(*provider, WritePixels).Times(1);

  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->putImageData(full_image_data_.Get(), 0, 0, exception_state);

  // `putImageData` isn't included in the recording, keeping it empty.
  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Eq(std::nullopt));

  // `putImageData` overdraw isn't handled by
  // `BaseRenderingContext2D::CheckOverdraw` like other draw operations, so the
  // histograms aren't updated.
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, PutImageData_PartialCoverage) {
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  gfx::Size size = CanvasElement().Size();
  auto provider = std::make_unique<FakeCanvasResourceProvider>(
      SkImageInfo::MakeN32Premul(size.width(), size.height()),
      RasterModeHint::kPreferGPU, &CanvasElement(),
      CompositingMode::kSupportsDirectCompositing);

  // `putImageData` forces a flush, so the `fillRect` will get rasterized before
  // `WritePixels` is called.
  InSequence s;
  EXPECT_CALL(*provider, RasterRecord(RecordedOpsAre(PaintOpIs<DrawRectOp>())))
      .Times(1);
  EXPECT_CALL(*provider, WritePixels).Times(1);

  CanvasElement().SetResourceProviderForTesting(std::move(provider), size);

  // `putImageData` forces a flush, which clears the recording.
  NonThrowableExceptionState exception_state;
  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->putImageData(partial_image_data_.Get(), 0, 0, exception_state);

  // `putImageData` isn't included in the recording, keeping it empty.
  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Eq(std::nullopt));

  // `putImageData` overdraw isn't handled by
  // `BaseRenderingContext2D::CheckOverdraw` like other draw operations, so the
  // histograms aren't updated.
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

TEST_P(CanvasRenderingContext2DTest, Path_FullCoverage) {
  // This case is an overdraw but the current detection logic rejects all
  // paths.
  base::HistogramTester histogram_tester;
  CreateContext(kNonOpaque);
  CanvasElement().SetSize(gfx::Size(10, 10));

  Context2D()->fillRect(3, 3, 1, 1);
  Context2D()->rect(-1, -1, 12, 12);
  Context2D()->fill();

  EXPECT_THAT(Context2D()->FlushCanvas(FlushReason::kTesting),
              Optional(RecordedOpsAre(PaintOpIs<DrawRectOp>(),
                                      PaintOpIs<DrawPathOp>())));
  EXPECT_THAT(histogram_tester, OverdrawOpAre());
}

//==============================================================================

TEST_P(CanvasRenderingContext2DTest, ImageResourceLifetime) {
  auto* canvas = To<HTMLCanvasElement>(
      GetDocument().CreateRawElement(html_names::kCanvasTag));
  canvas->SetSize(gfx::Size(40, 40));
  ImageBitmap* image_bitmap_derived = nullptr;
  {
    const ImageBitmapOptions* default_options = ImageBitmapOptions::Create();
    std::optional<gfx::Rect> crop_rect =
        gfx::Rect(0, 0, canvas->width(), canvas->height());
    auto* image_bitmap_from_canvas =
        MakeGarbageCollected<ImageBitmap>(canvas, crop_rect, default_options);
    ASSERT_TRUE(image_bitmap_from_canvas);

    crop_rect = gfx::Rect(0, 0, 20, 20);
    image_bitmap_derived = MakeGarbageCollected<ImageBitmap>(
        image_bitmap_from_canvas, crop_rect, default_options);
    ASSERT_TRUE(image_bitmap_derived);
  }
  CanvasContextCreationAttributesCore attributes;
  CanvasRenderingContext2D* context = static_cast<CanvasRenderingContext2D*>(
      canvas->GetCanvasRenderingContext("2d", attributes));
  DummyExceptionStateForTesting exception_state;
  auto* image_source =
      MakeGarbageCollected<V8CanvasImageSource>(image_bitmap_derived);
  context->drawImage(image_source, 0, 0, exception_state);
}

TEST_P(CanvasRenderingContext2DTest, GPUMemoryUpdateForAcceleratedCanvas) {
  CreateContext(kNonOpaque);

  gfx::Size size(10, 10);
  std::unique_ptr<FakeCanvasResourceProvider> fake_resource_provider =
      std::make_unique<FakeCanvasResourceProvider>(
          SkImageInfo::MakeN32Premul(size.width(), size.height()),
          RasterModeHint::kPreferGPU, &CanvasElement(),
          CompositingMode::kSupportsDirectCompositing);
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().SetResourceProviderForTesting(
      std::move(fake_resource_provider), size);

  // 800 = 10 * 10 * 4 * 2 where 10*10 is canvas size, 4 is num of bytes per
  // pixel per buffer, and 2 is an estimate of num of gpu buffers required

  // Switching accelerated mode to non-accelerated mode
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferCPU);
  CanvasElement().UpdateMemoryUsage();

  // Switching non-accelerated mode to accelerated mode
  CanvasElement().SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  CanvasElement().UpdateMemoryUsage();

  // Creating a different accelerated image buffer
  auto* anotherCanvas =
      To<HTMLCanvasElement>(GetDocument().getElementById(AtomicString("d")));
  CanvasContextCreationAttributesCore attributes;
  anotherCanvas->GetCanvasRenderingContext("2d", attributes);
  gfx::Size size2(10, 5);
  std::unique_ptr<FakeCanvasResourceProvider> fake_resource_provider2 =
      std::make_unique<FakeCanvasResourceProvider>(
          SkImageInfo::MakeN32Premul(size2.width(), size2.height()),
          RasterModeHint::kPreferGPU, &CanvasElement(),
          CompositingMode::kSupportsDirectCompositing);
  anotherCanvas->SetPreferred2DRasterMode(RasterModeHint::kPreferGPU);
  anotherCanvas->SetResourceProviderForTesting(
      std::move(fake_resource_provider2), size2);

  // Tear down the first image buffer that resides in current canvas element
  CanvasElement().SetSize(gfx::Size(20, 20));

  // Tear down the second image buffer
  anotherCanvas->SetSize(gfx::Size(20, 20));
}

TEST_P(CanvasRenderingContext2DTest, CanvasDisposedBeforeContext) {
  CreateContext(kNonOpaque);
  Context2D()->fillRect(0, 0, 1, 1);  // results in task observer registration

  Context2D()->DetachHost();

  // This is the only method that is callable after DetachHost
  // Test passes by not crashing.
  base::PendingTask dummy_pending_task(FROM_HERE, base::OnceClosure());
  Context2D()->DidProcessTask(dummy_pending_task);

  // Test passes by not crashing during teardown
}

TEST_P(CanvasRenderingContext2DTest, ContextDisposedBeforeCanvas) {
  CreateContext(kNonOpaque);

  CanvasElement().DetachContext();
  // Passes by not crashing later during teardown
}

static void TestDrawSingleHighBitDepthPNGOnCanvas(
    String filepath,
    CanvasRenderingContext2D* context,
    PredefinedColorSpace context_color_space,
    Document& document,
    ImageDataSettings* color_setting,
    ScriptState* script_state) {
  std::optional<Vector<char>> pixel_buffer_data = test::ReadFromFile(filepath);
  ASSERT_TRUE(pixel_buffer_data);
  scoped_refptr<SharedBuffer> pixel_buffer =
      SharedBuffer::Create(std::move(*pixel_buffer_data));

  ImageResourceContent* resource_content =
      ImageResourceContent::CreateNotStarted();
  const bool all_data_received = true;
  const bool is_multipart = false;
  ImageResourceContent::UpdateImageResult update_result =
      resource_content->UpdateImage(
          pixel_buffer, ResourceStatus::kPending,
          ImageResourceContent::UpdateImageOption::kUpdateImage,
          all_data_received, is_multipart);
  ASSERT_EQ(ImageResourceContent::UpdateImageResult::kNoDecodeError,
            update_result);

  auto* image_element = MakeGarbageCollected<HTMLImageElement>(document);
  image_element->SetImageForTest(resource_content);

  context->clearRect(0, 0, 2, 2);
  NonThrowableExceptionState exception_state;
  auto* image_union = MakeGarbageCollected<V8CanvasImageSource>(image_element);
  context->drawImage(image_union, 0, 0, exception_state);

  ImageData* image_data =
      context->getImageData(0, 0, 2, 2, color_setting, exception_state);
  const V8ImageDataArray* data_array = image_data->data();
  ASSERT_TRUE(data_array->IsFloat32Array());
  DOMArrayBufferView* buffer_view = data_array->GetAsFloat32Array().Get();
  ASSERT_EQ(16u, buffer_view->byteLength() / buffer_view->TypeSize());
  float* actual_pixels = static_cast<float*>(buffer_view->BaseAddress());

  sk_sp<SkImage> decoded_image =
      resource_content->GetImage()->PaintImageForCurrentFrame().GetSwSkImage();
  ASSERT_EQ(kRGBA_F16_SkColorType, decoded_image->colorType());
  sk_sp<SkImage> color_converted_image = decoded_image->makeColorSpace(
      static_cast<GrDirectContext*>(nullptr),
      PredefinedColorSpaceToSkColorSpace(context_color_space));
  float expected_pixels[16];
  SkImageInfo expected_info_no_color_space = SkImageInfo::Make(
      2, 2, kRGBA_F32_SkColorType, kUnpremul_SkAlphaType, nullptr);
  color_converted_image->readPixels(
      expected_info_no_color_space, expected_pixels,
      expected_info_no_color_space.minRowBytes(), 0, 0);
  ColorCorrectionTestUtils::CompareColorCorrectedPixels(
      actual_pixels, expected_pixels, 4, kPixelFormat_ffff);
}

static void TestDrawHighBitDepthPNGsOnWideGamutCanvas(
    PredefinedColorSpace color_space,
    Document& document,
    Persistent<HTMLCanvasElement> canvas,
    ScriptState* script_state) {
  // Prepare the wide gamut context with the given color space.
  CanvasContextCreationAttributesCore attributes;
  attributes.alpha = true;
  attributes.color_space = color_space;
  attributes.pixel_format = CanvasPixelFormat::kF16;
  CanvasRenderingContext2D* context = static_cast<CanvasRenderingContext2D*>(
      canvas->GetCanvasRenderingContext("2d", attributes));

  // Prepare the png file path and call the test routine
  Vector<String> interlace_status = {"", "_interlaced"};
  Vector<String> color_profiles = {"_sRGB",      "_e-sRGB",   "_AdobeRGB",
                                   "_DisplayP3", "_ProPhoto", "_Rec2020"};
  Vector<String> alpha_status = {"_opaque", "_transparent"};

  StringBuilder path;
  path.Append(test::CoreTestDataPath());
  path.Append("/png-16bit/");
  ImageDataSettings* color_setting = ImageDataSettings::Create();
  color_setting->setStorageFormat(
      ImageDataStorageFormatName(ImageDataStorageFormat::kFloat32));
  color_setting->setColorSpace(PredefinedColorSpaceName(color_space));
  for (auto interlace :
```
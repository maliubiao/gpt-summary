Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a four-part series. The code seems to be testing the `BaseRenderingContext2D` class in the Chromium Blink engine, specifically focusing on how different canvas rendering operations interact with shadows, compositing, transformations, patterns, and layers.

Here's a breakdown of the tasks:

1. **Identify the core functionality:** The tests seem to be verifying the correct sequence of `PaintOp`s generated by the `BaseRenderingContext2D` when various drawing operations are performed with different combinations of effects (shadows, compositing, transforms, patterns, and layers).

2. **Relate to web technologies:** Explain how these tests relate to the functionality of JavaScript's Canvas API, HTML's `<canvas>` element, and CSS styling that can influence canvas rendering (though the direct influence of CSS is less apparent in this specific code, the effects being tested are ultimately triggered by JavaScript).

3. **Illustrate with examples:** Provide concrete examples of JavaScript code that would lead to the execution paths being tested.

4. **Demonstrate logical reasoning:** For tests involving specific combinations of operations, infer the expected `PaintOp` sequence based on the individual effects and their interactions.

5. **Point out common errors:** Identify potential mistakes developers might make when using the Canvas API that these tests are designed to prevent or highlight.

6. **Describe user interaction:** Explain how a user's actions on a webpage could lead to the canvas rendering logic being executed.

7. **Summarize the functionality of this specific part:**  Given this is part 2 of 4, focus on the specific features being tested in this segment of the code. This part seems heavily focused on testing interactions between shadows and other rendering features like compositing, transforms, patterns, and layers.
好的，这是文件 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc` 的第二部分代码。基于你提供的代码片段，我可以归纳出以下功能：

**归纳功能：**

这部分代码主要测试了 `BaseRenderingContext2D` 类在处理 **阴影 (shadow)** 与其他 Canvas 2D API 功能组合时的行为，特别是以下几个方面：

*   **阴影与填充 (`fillRect`) 和变换 (`translate`) 的组合:** 测试在应用变换后，阴影的渲染是否正确，以及在不同合成模式下的表现。
*   **阴影与全局合成操作 (`globalCompositeOperation`) 的组合:** 测试当同时设置阴影和全局合成操作时，渲染引擎如何组织和执行绘制操作，特别是对于需要额外图层的合成模式。
*   **阴影与 CanvasPattern 的组合:** 测试当填充样式是 CanvasPattern 时，阴影的渲染逻辑。
*   **阴影与 `drawImage` 的组合:** 测试在绘制图像时应用阴影的效果，包括有无变换的情况。
*   **阴影、`drawImage` 和全局合成操作的组合:** 测试当 `drawImage` 操作同时应用阴影和需要额外图层的全局合成操作时的渲染流程。
*   **图层 (`beginLayer`, `endLayer`) 功能相关的阴影和合成状态管理:** 测试图层的开始和结束是否正确地重置和恢复了阴影和合成相关的状态。

**与 JavaScript, HTML, CSS 的关系举例：**

这段 C++ 代码测试的是 Blink 引擎中 Canvas 2D API 的底层实现。以下是如何通过 JavaScript 与这些功能产生关联的例子：

*   **阴影与 `fillRect` 和变换:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    ctx.shadowBlur = 10;
    ctx.shadowOffsetX = 5;
    ctx.shadowOffsetY = 5;
    ctx.shadowColor = 'gray';

    ctx.translate(50, 50);
    ctx.fillRect(0, 0, 100, 50);
    ```
    这段 JavaScript 代码会触发测试用例 `ShadowFillRectTransform` 和 `ShadowDstOutTransform` 等。

*   **阴影与全局合成操作:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    ctx.shadowBlur = 5;
    ctx.shadowColor = 'rgba(0, 0, 0, 0.5)';
    ctx.globalCompositeOperation = 'source-in';
    ctx.fillRect(20, 20, 100, 100);
    ```
    这段代码会触发 `ShadowSrcIn` 和 `ShadowSrcInTransform` 等测试用例。

*   **阴影与 CanvasPattern:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    const patternCanvas = document.createElement('canvas');
    const pCtx = patternCanvas.getContext('2d');
    pCtx.fillStyle = 'blue';
    pCtx.fillRect(0, 0, 10, 10);
    const pattern = ctx.createPattern(patternCanvas, 'repeat');

    ctx.shadowBlur = 3;
    ctx.shadowColor = 'red';
    ctx.fillStyle = pattern;
    ctx.fillRect(10, 10, 80, 80);
    ```
    这段代码对应 `ShadowPattern` 和 `ShadowPatternTransform` 测试。

*   **阴影与 `drawImage`:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.onload = function() {
      ctx.shadowBlur = 7;
      ctx.shadowOffsetX = 2;
      ctx.shadowOffsetY = 2;
      ctx.shadowColor = 'green';
      ctx.drawImage(img, 50, 50);
    };
    img.src = 'path/to/image.png';
    ```
    这段代码会触发 `ShadowDrawImage` 和 `ShadowDrawImageTransform` 测试。

*   **图层功能:**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    ctx.shadowBlur = 5;
    ctx.shadowColor = 'red';
    ctx.globalAlpha = 0.7;
    ctx.globalCompositeOperation = 'multiply';

    ctx.beginLayer(); // 开始一个新图层
    ctx.fillStyle = 'blue';
    ctx.fillRect(10, 10, 50, 50);
    ctx.endLayer();   // 结束图层

    ctx.fillRect(70, 70, 50, 50); // 在默认图层绘制
    ```
    这段代码会触发 `BaseRenderingContextLayerTests` 和 `BaseRenderingContextLayerGlobalStateTests` 中的相关测试，例如关于阴影和合成状态的重置与恢复。

**假设输入与输出 (逻辑推理):**

以 `ShadowFillRectTransform` 测试为例：

*   **假设输入:**  JavaScript 代码设置了阴影属性 (`shadowBlur`, `shadowOffsetX`, `shadowOffsetY`, `shadowColor`)，然后应用了一个平移变换 (`translate(4, 5)`)，最后调用 `fillRect(1, 1, 5, 5)`。
*   **预期输出:**  `FlushRecorder()` 捕获到的 `PaintOp` 序列应该包含 `TranslateOp`，然后是两个 `SaveLayerOp` 和对应的 `DrawRectOp` 以及 `RestoreOp`。第一个 `SaveLayerOp` 用于绘制阴影，第二个 `SaveLayerOp` 用于绘制实际的矩形。`SetMatrixOp` 用于设置变换矩阵。

**用户或编程常见的使用错误举例：**

*   **忘记在 `beginLayer()` 之后设置图层的特定属性:** 用户可能期望在调用 `beginLayer()` 后，新图层会继承之前的状态，但实际上，一些状态会被重置。例如，如果在 `beginLayer()` 后直接绘制，而没有重新设置 `fillStyle`，可能会使用默认的黑色填充。测试用例 `BaseRenderingContextLayerGlobalStateTests` 就在验证这种状态的重置和恢复。
*   **在图层内部调用 `putImageData`:**  根据 `BaseRenderingContextLayerTests, putImageDataThrowsInLayer` 测试，在 `beginLayer()` 和 `endLayer()` 之间调用 `putImageData` 会抛出异常。这是因为图层的实现方式与直接在画布上绘制有所不同。

**用户操作如何到达这里 (调试线索):**

1. **用户在网页上与使用了 `<canvas>` 元素的交互:** 例如，用户点击按钮、移动鼠标、滚动页面等操作，这些事件可能会触发 JavaScript 代码的执行。
2. **JavaScript 代码调用 Canvas 2D API:**  事件处理函数中，JavaScript 代码可能会获取 Canvas 元素的 2D 渲染上下文 (`getContext('2d')`)，并调用各种绘图方法，如 `fillRect()`, `drawImage()`, `translate()`, 设置阴影属性等。
3. **Blink 引擎接收 API 调用并执行:**  当 JavaScript 调用 Canvas 2D API 时，这些调用会被传递到 Blink 引擎的相应 C++ 代码中，例如 `BaseRenderingContext2D` 类。
4. **`BaseRenderingContext2D` 记录绘制操作:**  `BaseRenderingContext2D` 类会将这些绘图操作转换为一系列的 `PaintOp`，存储在 `Recorder` 中。
5. **测试验证 `PaintOp` 序列:**  `base_rendering_context_2d_test.cc` 中的测试用例通过模拟不同的 JavaScript 调用序列，然后调用 `FlushRecorder()` 来检查生成的 `PaintOp` 序列是否符合预期。这有助于确保 Blink 引擎正确地实现了 Canvas 2D API 的规范。

总而言之，这部分测试代码专注于验证当 Canvas 2D API 中的阴影效果与其他功能（如变换、合成、图案和图层）结合使用时，Blink 渲染引擎的底层绘制逻辑是否正确无误。这些测试对于保证 Web 开发者在使用 Canvas API 时，能够获得预期且一致的渲染结果至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
                       0, 1, 0, 5,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   shadow_only_flags),
                             PaintOpEq<RestoreOp>(),  //
                             PaintOpEq<SaveLayerOp>(composite_flags),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                          0, 1, 0, 5,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                                   foreground_flags),
                             PaintOpEq<RestoreOp>(),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                          0, 1, 0, 5,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1))));
}

// Tests fillRect with a shadow and a composite op that can be implemented using
// a `DropShadowPaintFilter`.
TEST(BaseRenderingContextCompositingTests, ShadowDstOutTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("destination-out");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags flags = FillFlags();
  flags.setBlendMode(SkBlendMode::kDstOut);
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  draw_looper_builder.AddUnmodifiedContent();
  flags.setLooper(draw_looper_builder.DetachDrawLooper());

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(
                  PaintOpEq<TranslateOp>(4, 5),
                  PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), flags)));
}

// Tests a fillRect with a shadow and a composite op operating on the full
// surface. These ops impact all pixels, even those outside the drawn shape.
TEST(BaseRenderingContextCompositingTests, ShadowSrcIn) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("source-in");
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags shadow_only_flags = FillFlags();
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  shadow_only_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  cc::PaintFlags foreground_flags = FillFlags();

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's
          // already identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                shadow_only_flags),
          PaintOpEq<RestoreOp>(),  //
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), foreground_flags),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a fillRect with a shadow and a composite op operating on the full
// surface. These ops impact all pixels, even those outside the drawn shape.
TEST(BaseRenderingContextCompositingTests, ShadowSrcInTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("source-in");
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  // TODO: crbug.com/364549423 - Remove draw-looper.
  cc::PaintFlags shadow_only_flags = FillFlags();
  DrawLooperBuilder draw_looper_builder;
  draw_looper_builder.AddShadow(/*offset=*/{2, 3}, /*blur=*/2,
                                Color::FromRGB(255, 0, 0),
                                DrawLooperBuilder::kShadowIgnoresTransforms,
                                DrawLooperBuilder::kShadowRespectsAlpha);
  shadow_only_flags.setLooper(draw_looper_builder.DetachDrawLooper());

  cc::PaintFlags foreground_flags = FillFlags();

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          // TODO: crbug.com/364549423 - Undoing the transform has no effect
          // because a draw-looper is used. Without the draw-looper, the shadow
          // would need to be applied on the layer, not the draw op.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5),
                                shadow_only_flags),
          PaintOpEq<RestoreOp>(),  //
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), foreground_flags),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a fillRect with a shadow and a CanvasPattern.
TEST(BaseRenderingContextCompositingTests, ShadowPattern) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  auto* pattern = MakeGarbageCollected<CanvasPattern>(
      Image::NullImage(), Pattern::kRepeatModeXY, /*origin_clean=*/true);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setFillStyle(scope.GetIsolate(),
                        pattern->ToV8(scope.GetScriptState()),
                        scope.GetExceptionState());
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags shadow_flags = FillFlags();
  shadow_flags.setShader(PaintShader::MakeColor(SkColors::kTransparent));

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  // TODO: crbug.com/364549423 - The `ComposePaintFilter`s are useless here.
  sk_sp<cc::PaintFilter> background_filter = sk_make_sp<ComposePaintFilter>(
      sk_make_sp<ComposePaintFilter>(nullptr, shadow_filter), nullptr);
  shadow_flags.setImageFilter(background_filter);

  cc::PaintFlags pattern_flags = FillFlags();
  pattern_flags.setShader(PaintShader::MakeColor(SkColors::kTransparent));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's already
          // identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(shadow_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), pattern_flags),
          PaintOpEq<RestoreOp>(),  //
          // TODO: crbug.com/364549423 - The layer shouldn't be needed here.
          PaintOpEq<SaveLayerOp>(PaintFlags()),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), pattern_flags),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a fillRect with a shadow, a CanvasPattern and a transform.
TEST(BaseRenderingContextCompositingTests, ShadowPatternTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  auto* pattern = MakeGarbageCollected<CanvasPattern>(
      Image::NullImage(), Pattern::kRepeatModeXY, /*origin_clean=*/true);

  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setFillStyle(scope.GetIsolate(),
                        pattern->ToV8(scope.GetScriptState()),
                        scope.GetExceptionState());
  context->translate(4, 5);
  context->fillRect(1, 1, 5, 5);

  cc::PaintFlags shadow_flags = FillFlags();
  shadow_flags.setShader(PaintShader::MakeColor(SkColors::kTransparent));

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  // TODO: crbug.com/364549423 - The `ComposePaintFilter`s are useless here.
  sk_sp<cc::PaintFilter> background_filter = sk_make_sp<ComposePaintFilter>(
      sk_make_sp<ComposePaintFilter>(nullptr, shadow_filter), nullptr);
  shadow_flags.setImageFilter(background_filter);

  cc::PaintFlags pattern_flags = FillFlags();
  pattern_flags.setShader(PaintShader::MakeColor(SkColors::kTransparent));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(shadow_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), pattern_flags),
          PaintOpEq<RestoreOp>(),  //
          // TODO: crbug.com/364549423 - The layer shouldn't be needed here.
          PaintOpEq<SaveLayerOp>(PaintFlags()),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), pattern_flags),
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a drawImage with a shadow.
TEST(BaseRenderingContextCompositingTests, ShadowDrawImage) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  auto* bitmap = MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->drawImage(bitmap, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's already
          // identity.
          PaintOpEq<SaveOp>(),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 0,  //
                                    0, 1, 0, 0,  //
                                    0, 0, 1, 0,  //
                                    0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(SkRect::MakeXYWH(0, 0, 10, 10), shadow_flags),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 0,  //
                                    0, 1, 0, 0,  //
                                    0, 0, 1, 0,  //
                                    0, 0, 0, 1)),
          PaintOpIs<DrawImageRectOp>(),  //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<RestoreOp>()));
}

// Tests a drawImage with a shadow and a transform.
TEST(BaseRenderingContextCompositingTests, ShadowDrawImageTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  auto* bitmap = MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->translate(4, 5);
  context->drawImage(bitmap, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<TranslateOp>(4, 5),  //
                             PaintOpEq<SaveOp>(),
                             PaintOpEq<ConcatOp>(SkM44(1, 0, 0, -4,  //
                                                       0, 1, 0, -5,  //
                                                       0, 0, 1, 0,   //
                                                       0, 0, 0, 1)),
                             PaintOpEq<SaveLayerOp>(
                                 SkRect::MakeXYWH(4, 5, 10, 10), shadow_flags),
                             PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 4,  //
                                                       0, 1, 0, 5,  //
                                                       0, 0, 1, 0,  //
                                                       0, 0, 0, 1)),
                             PaintOpIs<DrawImageRectOp>(),
                             PaintOpEq<RestoreOp>(),  //
                             PaintOpEq<RestoreOp>()));
}

// Tests a drawImage with a shadow and a composite operation requiring an extra
// layer (requires `CompositedDraw`).
TEST(BaseRenderingContextCompositingTests, DrawImageShadowSrcIn) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  auto* bitmap = MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("source-in");
  context->drawImage(bitmap, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // TODO: crbug.com/364549423 - No need to reset matrix, it's already
          // identity.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - Check whether two nested layers are
          // needed here. set and unset right afterwards.
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveOp>(),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 0,  //
                                    0, 1, 0, 0,  //
                                    0, 0, 1, 0,  //
                                    0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(SkRect::MakeXYWH(0, 0, 10, 10), shadow_flags),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 0,  //
                                    0, 1, 0, 0,  //
                                    0, 0, 1, 0,  //
                                    0, 0, 0, 1)),
          PaintOpIs<DrawImageRectOp>(),  //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpIs<DrawImageRectOp>(),  //
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

// Tests a drawImage with a shadow, a transform and a composite operation
// requiring an extra layer (requires `CompositedDraw`).
TEST(BaseRenderingContextCompositingTests, DrawImageShadowSrcInTransform) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  auto* bitmap = MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument());
  context->setShadowBlur(2);
  context->setShadowOffsetX(2);
  context->setShadowOffsetY(3);
  context->setShadowColor("red");
  context->translate(4, 5);
  context->setGlobalCompositeOperation("source-in");
  context->drawImage(bitmap, 0, 0, 10, 10, 0, 0, 10, 10, exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      2.0f, 3.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                       0, 1, 0, 0,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          // TODO: crbug.com/364549423 - Check whether two nested layers are
          // needed here. set and unset right afterwards.
          PaintOpEq<SaveLayerOp>(composite_flags),
          // TODO: crbug.com/364549423 - Matrix shouldn't be set and unset right
          // afterwards.
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveOp>(),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, -4,  //
                                    0, 1, 0, -5,  //
                                    0, 0, 1, 0,   //
                                    0, 0, 0, 1)),
          PaintOpEq<SaveLayerOp>(SkRect::MakeXYWH(4, 5, 10, 10), shadow_flags),
          PaintOpEq<ConcatOp>(SkM44(1, 0, 0, 4,  //
                                    0, 1, 0, 5,  //
                                    0, 0, 1, 0,  //
                                    0, 0, 0, 1)),
          PaintOpIs<DrawImageRectOp>(),  //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<RestoreOp>(),        //
          PaintOpEq<SaveLayerOp>(composite_flags),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpIs<DrawImageRectOp>(),  //
          PaintOpEq<RestoreOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 5,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1))));
}

TEST(BaseRenderingContextLayerTests, ContextLost) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->SetContextLost(true);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  EXPECT_THAT(context->FlushRecorder(), RecordedOpsAre());
}

TEST(BaseRenderingContextLayerTests, ResetsAndRestoresShadowStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(1.0);
  context->setShadowOffsetX(2.0);
  context->setShadowOffsetY(3.0);
  context->setShadowColor("red");

  EXPECT_EQ(context->shadowBlur(), 1.0);
  EXPECT_EQ(context->shadowOffsetX(), 2.0);
  EXPECT_EQ(context->shadowOffsetY(), 3.0);
  EXPECT_EQ(context->shadowColor(), "#ff0000");

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);

  EXPECT_EQ(context->shadowBlur(), 0.0);
  EXPECT_EQ(context->shadowOffsetX(), 0.0);
  EXPECT_EQ(context->shadowOffsetY(), 0.0);
  EXPECT_EQ(context->shadowColor(), "rgba(0, 0, 0, 0)");

  context->endLayer(exception_state);

  EXPECT_EQ(context->shadowBlur(), 1.0);
  EXPECT_EQ(context->shadowOffsetX(), 2.0);
  EXPECT_EQ(context->shadowOffsetY(), 3.0);
  EXPECT_EQ(context->shadowColor(), "#ff0000");
}

TEST(BaseRenderingContextLayerTests, ResetsAndRestoresCompositeStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.7);
  context->setGlobalCompositeOperation("xor");

  EXPECT_EQ(context->globalAlpha(), 0.7);
  EXPECT_EQ(context->globalCompositeOperation(), "xor");

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);

  EXPECT_EQ(context->globalAlpha(), 1.0);
  EXPECT_EQ(context->globalCompositeOperation(), "source-over");

  context->endLayer(exception_state);

  EXPECT_EQ(context->globalAlpha(), 0.7);
  EXPECT_EQ(context->globalCompositeOperation(), "xor");
}

TEST(BaseRenderingContextLayerTests, ResetsAndRestoresFilterStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  V8UnionCanvasFilterOrString* filter = MakeBlurCanvasFilter(20.0f);
  context->setFilter(scope.GetScriptState(), filter);

  ASSERT_TRUE(context->filter()->IsCanvasFilter());
  EXPECT_EQ(context->filter()->GetAsCanvasFilter()->Operations(),
            filter->GetAsCanvasFilter()->Operations());
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  ASSERT_TRUE(context->filter()->IsString());
  EXPECT_EQ(context->filter()->GetAsString(), "none");

  context->endLayer(exception_state);

  ASSERT_TRUE(context->filter()->IsCanvasFilter());
  EXPECT_EQ(context->filter()->GetAsCanvasFilter()->Operations(),
            filter->GetAsCanvasFilter()->Operations());
}

TEST(BaseRenderingContextLayerTests, BeginLayerThrowsOnInvalidFilterParam) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'colorMatrix', values: 'invalid'})"),
      scope.GetExceptionState());

  EXPECT_EQ(scope.GetExceptionState().CodeAs<ESErrorType>(),
            ESErrorType::kTypeError);
  // `beginLayer` should be a no-op if an exception is raised.
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayerTests, putImageDataThrowsInLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  NonThrowableExceptionState no_exception;
  ImageData* image =
      context->createImageData(/*sw=*/10, /*sh=*/10, no_exception);
  // `putImageData` shouldn't throw on it's own.
  context->putImageData(image, /*dx=*/0, /*dy=*/0, no_exception);
  // Make sure the exception isn't caused by calling the function twice.
  context->putImageData(image, /*dx=*/0, /*dy=*/0, no_exception);
  // Calling again inside a layer should throw.
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);
  context->putImageData(image, /*dx=*/0, /*dy=*/0, scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
}

TEST(BaseRenderingContextLayerGlobalStateTests, DefaultRenderingStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerAlphaOp>(1.0f),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlpha) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerAlphaOp>(0.3f),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, BlendingOperation) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setBlendMode(SkBlendMode::kMultiply);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, CompositeOperation) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setBlendMode(SkBlendMode::kSrcIn);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, Shadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlphaAndBlending) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto
"""


```
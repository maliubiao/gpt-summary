Response:
The user wants a summary of the functionalities of the provided C++ code for testing the `BaseRenderingContext2D` class in the Chromium Blink engine. I need to analyze each test case and describe its purpose, highlighting its relation to JavaScript, HTML, and CSS concepts if applicable. For logical deductions, I will explain the input and expected output based on the test logic. I will also identify common user errors that the tests aim to prevent and outline the user actions that lead to the execution of this code. Finally, I need to provide an overall summary of the file's function.

**Plan:**

1. **Iterate through each `TEST` function:**
    *   Describe the test's goal (e.g., testing global state, layer functionality, etc.).
    *   Analyze the setup and actions within the test.
    *   Examine the `EXPECT_THAT` assertions to understand the expected behavior and the paint operations being verified.
    *   Identify any connections to JavaScript APIs (e.g., `globalAlpha`, `setGlobalCompositeOperation`, `beginLayer`, `endLayer`, `save`, `restore`, `reset`, `fillRect`, `clip`, `translate`, `scale`, `setFilter`, `drawMesh`).
    *   Determine if the test relates to HTML canvas elements or CSS styling (e.g., filter effects).
    *   If the test involves logical reasoning (like optimization), explain the assumptions and the resulting paint operations.
    *   Consider potential user errors that the test might catch (e.g., incorrect layer usage, invalid state transitions).
    *   Infer the user actions that would trigger the tested code paths.

2. **Address specific requests:**
    *   Provide concrete examples for the relationship with JavaScript, HTML, and CSS.
    *   Clearly state the assumed input and output for logical deductions.
    *   Illustrate common user errors with examples.
    *   Describe the user interaction flow as debugging clues.

3. **Synthesize a comprehensive summary:** Combine the individual test descriptions into an overarching explanation of the file's functionality.
这是对 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc` 文件功能的总结，该文件是 Chromium Blink 引擎的一部分，专门用于测试 `BaseRenderingContext2D` 类的功能。`BaseRenderingContext2D` 是 Canvas 2D API 的核心实现类。

**功能列表:**

该文件包含了一系列单元测试，用于验证 `BaseRenderingContext2D` 类的各种功能，主要集中在以下几个方面：

1. **全局状态管理:**
    *   测试 `globalAlpha`（全局透明度）的设置和影响。
    *   测试 `globalCompositeOperation`（全局合成操作）的设置和影响，例如 "source-over" 和 "copy"。
    *   测试 `shadowBlur`（阴影模糊）、`shadowColor`（阴影颜色）的设置和影响。
    *   测试 `filter`（滤镜）的设置和影响。
    *   测试在非可逆变换（例如缩放比例为 0）下，全局状态的优化行为。

2. **图层 (Layers) 功能:**
    *   测试 `beginLayer()` 和 `endLayer()` 方法的基本使用，包括创建和结束图层。
    *   测试图层如何隔离全局状态，例如在图层内部设置的 `globalAlpha` 和 `globalCompositeOperation` 不会影响外部。
    *   测试图层与滤镜的结合使用，包括通过 CSS 字符串和对象方式设置滤镜。
    *   测试嵌套图层的行为。
    *   测试在 `copy` 合成操作下创建图层的特殊处理。
    *   测试未关闭的图层在刷新时的行为。
    *   测试带有样式解析宿主（HTMLCanvasElement）和没有样式解析宿主的情况下，使用 `em` 单位设置滤镜的效果。

3. **保存和恢复状态 (Save and Restore):**
    *   测试 `save()` 和 `restore()` 方法的基本使用，确保状态栈的正确管理。
    *   测试 `restore()` 方法如何恢复变换矩阵 (transform)。
    *   测试 `restore()` 方法如何恢复裁剪区域 (clip)。
    *   测试在禁用自动矩阵恢复的情况下手动调用 `RestoreMatrixClipStack()` 的行为。

4. **重置状态 (Reset):**
    *   测试 `reset()` 方法是否能正确地将渲染状态恢复到默认值，并清空待绘制的操作。

5. **方法调用顺序 (Call Order):**
    *   测试 `beginLayer()`, `endLayer()`, `save()`, `restore()` 等方法的各种调用顺序，以及在不正确的调用顺序下是否会抛出异常。

6. **网格绘制 (Mesh Drawing):**
    *   测试 `drawMesh()` 方法，使用顶点缓冲、UV 缓冲和索引缓冲来绘制网格，并使用 `ImageBitmap` 作为纹理。

**与 JavaScript, HTML, CSS 的关系及举例:**

该文件测试的 `BaseRenderingContext2D` 类是 Canvas 2D API 的底层实现，因此与 JavaScript, HTML, CSS 的功能紧密相关。

*   **JavaScript:** 这些测试直接对应于 JavaScript 中 Canvas 2D API 提供的方法和属性。例如：
    *   `context.globalAlpha = 0.5;`  对应测试中的 `context->setGlobalAlpha(0.5);`
    *   `context.globalCompositeOperation = 'source-in';` 对应测试中的 `context->setGlobalCompositeOperation("source-in");`
    *   `context.save();` 对应测试中的 `context->save();`
    *   `context.restore();` 对应测试中的 `context->restore(exception_state);`
    *   `context.beginLayer();` 对应测试中的 `context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(), exception_state);`
    *   `context.endLayer();` 对应测试中的 `context->endLayer(exception_state);`
    *   `context.reset();` 对应测试中的 `context->reset();`
    *   `context.fillRect(10, 20, 30, 40);` 对应测试中的 `context->fillRect(10, 20, 30, 40);`
    *   `context.translate(5, 6);` 对应测试中的 `context->translate(5, 6);`
    *   `context.scale(0, 5);` 对应测试中的 `context->scale(0, 5);`
    *   `context.filter = 'blur(1px)';` (通过 `beginLayer` 传递) 对应测试中的 `FilterOption(scope, "'blur(1px)'")`
    *   `context.drawMesh(vertexBuffer, uvBuffer, indexBuffer, imageBitmap);` 对应测试中的 `context->drawMesh(...)`

*   **HTML:**  Canvas 2D API 是通过 `<canvas>` HTML 元素暴露的。测试中通过 `MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument())` 创建了一个模拟的 Canvas 元素，以便进行一些与样式解析相关的测试。

*   **CSS:**  Canvas 的一些属性可以通过 CSS 来影响，例如 `filter`。测试中使用了 CSS 字符串来设置图层的滤镜，并验证了在有无样式解析宿主的情况下，对于 `em` 单位的处理。

**逻辑推理的假设输入与输出:**

*   **假设输入 (NonInvertibleTransform 测试):**
    *   调用 `context->scale(0, 5)`，设置了一个 x 方向缩放为 0 的非可逆变换。
    *   设置了 `globalAlpha`，`globalCompositeOperation`，`shadowBlur`，`shadowColor` 和一个模糊滤镜。
    *   调用 `beginLayer()` 和 `endLayer()`。
*   **输出:** 由于变换是非可逆的，图层无法被有效地栅格化。因此，阴影、全局透明度、合成操作和滤镜会被优化掉，最终的绘制操作只包含 `ScaleOp` 和一个简单的 `SaveLayerAlphaOp`。

*   **假设输入 (CopyCompositeOpWithOtherStates 测试):**
    *   调用 `context->translate(6, 7)` 设置平移变换。
    *   设置 `globalAlpha` 为 0.4。
    *   设置 `globalCompositeOperation` 为 "copy"。
    *   设置阴影和全局滤镜。
    *   调用 `beginLayer()` 并设置图层自身的滤镜。
    *   调用 `endLayer()`。
*   **输出:** 由于全局合成操作是 "copy"，图层会先绘制成透明色，然后应用全局状态和图层状态的滤镜。输出的 `RecordedOpsAre` 精确地描述了这些绘制操作的顺序和参数。

**用户或编程常见的使用错误及举例:**

*   **不匹配的 `save()` 和 `restore()` 调用:**  如果 `save()` 的次数多于 `restore()`，会导致状态栈中残留状态，可能会影响后续的绘制。反之，如果 `restore()` 的次数多于 `save()`，则会抛出异常。测试用例 `BaseRenderingContextRestoreStackTests::RestoresSaves` 和 `BaseRenderingContextLayersCallOrderTests::SaveRestore` 等覆盖了这种情况。

    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    ctx.save();
    ctx.fillStyle = 'red';
    ctx.fillRect(10, 10, 50, 50);

    // 忘记 restore，后续操作可能受到之前 save 的影响
    ctx.fillStyle = 'blue';
    ctx.fillRect(70, 10, 50, 50);

    // 错误的 restore 次数
    ctx.restore(); // 正常
    ctx.restore(); // 可能会导致错误
    ```

*   **不匹配的 `beginLayer()` 和 `endLayer()` 调用:**  `beginLayer()` 必须与 `endLayer()` 成对出现。如果只调用 `beginLayer()` 而不调用 `endLayer()`，图层将不会被正确地合成。如果调用 `endLayer()` 而没有对应的 `beginLayer()`，则会抛出 `InvalidStateError` 异常。测试用例 `BaseRenderingContextLayersCallOrderTests::LoneBeginLayer`, `BaseRenderingContextLayersCallOrderTests::LoneEndLayer`, 和 `BaseRenderingContextLayersCallOrderTests::BeginLayerEndLayer` 等覆盖了这种情况。

    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    ctx.beginLayer();
    ctx.fillStyle = 'green';
    ctx.fillRect(10, 10, 50, 50);

    // 忘记 endLayer，图层可能不会被正确渲染

    ctx.endLayer(); // 应该在这里调用
    ```

*   **在 `beginLayer()` 之后，`endLayer()` 之前调用 `restore()` 可能会导致错误的状态:**  图层内部的 `restore()` 操作应该谨慎使用，因为它会影响图层的状态。在图层未结束时恢复可能会导致意外的结果或错误。测试用例 `BaseRenderingContextLayersCallOrderTests::BeginLayerRestore` 覆盖了这种情况。

*   **错误地假设非可逆变换下的图层行为:** 用户可能会期望在设置了非可逆变换（例如缩放为 0）后，图层仍然会按照设置的所有属性进行绘制，但实际上，为了优化性能，浏览器可能会跳过某些效果。测试用例 `BaseRenderingContextLayerGlobalStateTests::NonInvertibleTransform` 说明了这一点。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者编写包含 Canvas 2D API 调用的 JavaScript 代码:**  用户（开发者）在 HTML 文件中创建一个 `<canvas>` 元素，并在 JavaScript 代码中使用 `getContext('2d')` 获取 2D 渲染上下文。
2. **调用 Canvas 2D API 的方法:** 开发者在 JavaScript 中调用 `context.globalAlpha`, `context.fillStyle`, `context.fillRect`, `context.save()`, `context.restore()`, `context.beginLayer()`, `context.endLayer()`, `context.filter`, `context.drawMesh()` 等方法来绘制图形和管理状态。
3. **浏览器执行 JavaScript 代码并解析 HTML:** 当浏览器加载包含 Canvas 代码的网页时，JavaScript 引擎会执行这些代码。
4. **Blink 引擎处理 Canvas API 调用:**  当执行到 Canvas 2D API 的调用时，JavaScript 引擎会将这些调用转发到 Blink 引擎的相应模块，即 `blink/renderer/modules/canvas/canvas2d/` 目录下的代码。
5. **`BaseRenderingContext2D` 类执行相应的操作:**  `BaseRenderingContext2D` 类接收到这些调用后，会更新其内部状态（例如全局透明度、变换矩阵、裁剪区域等），并将绘制操作记录到绘图记录器中。
6. **测试文件模拟 API 调用并验证结果:**  `base_rendering_context_2d_test.cc` 文件中的测试用例模拟了各种 JavaScript API 的调用序列和参数，然后断言 `BaseRenderingContext2D` 对象的状态和生成的绘制操作是否符合预期。当开发者报告 Canvas 渲染问题或当 Blink 引擎的开发者修改了 Canvas 2D API 的实现时，可能会运行这些测试来验证代码的正确性。

**归纳一下它的功能 (第4部分):**

作为第 4 部分，该文件（`base_rendering_context_2d_test.cc`）的功能是 **全面测试 Chromium Blink 引擎中 `BaseRenderingContext2D` 类的各种功能和行为，确保 Canvas 2D API 的实现符合规范且稳定可靠。**  它通过一系列细致的单元测试，覆盖了全局状态管理、图层功能、状态保存与恢复、状态重置、方法调用顺序以及网格绘制等关键方面，旨在预防潜在的编程错误和用户误用，并保证 Canvas API 在不同场景下的正确运行。 此外，它也测试了与 HTML 和 CSS 相关的特定功能，例如滤镜效果的应用和解析。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
),
                         PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, NonInvertibleTransform) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->scale(0, 5);
  context->setGlobalAlpha(0.3f);
  context->setGlobalCompositeOperation("source-in");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(scope.GetScriptState(),
                      FilterOption(scope, "'blur(1px)'"), exception_state);
  context->endLayer(exception_state);

  // Because the layer is not rasterizable, the shadow, global alpha,
  // composite op and filter are optimized away.
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<ScaleOp>(0, 5),
                             DrawRecordOpEq(PaintOpEq<SaveLayerAlphaOp>(1.0f),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, CopyCompositeOp) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("copy");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<DrawColorOp>(SkColors::kTransparent, SkBlendMode::kSrc),
          PaintOpEq<SaveLayerAlphaOp>(1.0f), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests,
     CopyCompositeOpWithOtherStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(6, 7);
  context->setGlobalAlpha(0.4);
  context->setGlobalCompositeOperation("copy");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(5.0f));
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags global_flags;
  global_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(5.0f, 5.0f, SkTileMode::kDecal, nullptr));

  cc::PaintFlags layer_flags;
  layer_flags.setAlphaf(0.4f);
  layer_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(6, 7),
          DrawRecordOpEq(
              PaintOpEq<DrawColorOp>(SkColors::kTransparent, SkBlendMode::kSrc),
              PaintOpEq<SaveOp>(),
              PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                           0, 1, 0, 0,  //
                                           0, 0, 1, 0,  //
                                           0, 0, 0, 1)),
              PaintOpEq<SaveLayerOp>(global_flags),
              PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 6,  //
                                           0, 1, 0, 7,  //
                                           0, 0, 1, 0,  //
                                           0, 0, 0, 1)),
              PaintOpEq<SaveLayerOp>(layer_flags), PaintOpEq<RestoreOp>(),
              PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextRestoreStackTests, RestoresSaves) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->save();
  context->save();
  context->save();

  // Disable automatic matrix restore so this test could manually invoke it.
  context->SetRestoreMatrixEnabled(false);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<SaveOp>(), PaintOpEq<SaveOp>(),
                             PaintOpEq<SaveOp>(), PaintOpEq<RestoreOp>(),
                             PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));

  // `FlushRecorder()` flushed the recording canvas, leaving it empty.
  ASSERT_THAT(context->FlushRecorder(), IsEmpty());

  context->RestoreMatrixClipStack(context->GetPaintCanvas());
  context->restore(exception_state);
  context->restore(exception_state);
  context->restore(exception_state);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<SaveOp>(), PaintOpEq<SaveOp>(),
                             PaintOpEq<SaveOp>(), PaintOpEq<RestoreOp>(),
                             PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));
}

TEST(BaseRenderingContextRestoreStackTests, RestoresTransforms) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(10.0, 0.0);
  context->translate(0.0, 20.0);
  context->save();  // No transforms to restore on that level.
  context->save();
  context->translate(15.0, 15.0);

  // Disable automatic matrix restore so this test could manually invoke it.
  context->SetRestoreMatrixEnabled(false);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(PaintOpEq<TranslateOp>(10.0, 0.0),  // Root transforms.
                     PaintOpEq<TranslateOp>(0.0, 20.0),
                     PaintOpEq<SaveOp>(),  // Nested state without transform.
                     PaintOpEq<SaveOp>(),  // Nested state with transform.
                     PaintOpEq<TranslateOp>(15.0, 15.0), PaintOpEq<RestoreOp>(),
                     PaintOpEq<RestoreOp>()));

  // `FlushRecorder()` flushed the recording canvas, leaving it empty.
  ASSERT_THAT(context->FlushRecorder(), IsEmpty());

  context->RestoreMatrixClipStack(context->GetPaintCanvas());
  context->restore(exception_state);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // Root transforms.
          PaintOpEq<SetMatrixOp>(SkM44(1.f, 0.f, 0.f, 10.f, 0.f, 1.f, 0.f, 20.f,
                                       0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 0.f, 1.f)),
          PaintOpEq<SaveOp>(),  // Nested state without transform.
          PaintOpEq<SaveOp>(),  // Nested state with transform.
          PaintOpEq<SetMatrixOp>(SkM44(1.f, 0.f, 0.f, 25.f, 0.f, 1.f, 0.f, 35.f,
                                       0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 0.f, 1.f)),
          PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));
}

TEST(BaseRenderingContextRestoreStackTests, RestoresClip) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  // Clipping from an empty matrix stack. Clip can be restored without having
  // to reset the transform.
  context->beginPath();
  context->rect(0, 0, 100, 100);
  context->clip();

  // Clipping from a nested identity transform. Clip can be restored without
  // having to reset the transform.
  context->save();
  context->translate(10.0, 0.0);
  context->beginPath();
  context->moveTo(100, 100);
  context->lineTo(200, 100);
  context->translate(0.0, 20.0);
  context->lineTo(150, 200);
  context->clip();
  context->translate(15.0, 15.0);

  // Clip nested in a parent transform, restoring clip will require resetting
  // the transform to identity.
  context->save();
  context->translate(3.0, 0.0);
  context->beginPath();
  context->moveTo(150, 50);
  context->lineTo(200, 200);
  context->translate(0.0, 3.0);
  context->lineTo(100, 200);
  context->clip();

  // Disable automatic matrix restore so this test could manually invoke it.
  context->SetRestoreMatrixEnabled(false);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // Root clip, but no transform.
          PaintOpEq<ClipRectOp>(SkRect::MakeLTRB(0, 0, 100, 100),
                                SkClipOp::kIntersect,
                                /*antialias=*/false),
          PaintOpEq<SaveOp>(),  // Nested state with clip and transforms.
          PaintOpEq<TranslateOp>(10.0, 0.0), PaintOpEq<TranslateOp>(0.0, 20.0),
          PaintOpEq<ClipPathOp>(
              SkPath::Polygon({{100, 80}, {200, 80}, {150, 200}},
                              /*isClosed=*/false),
              SkClipOp::kIntersect, /*antialias=*/false,
              /*use_paint_cache=*/UsePaintCache::kDisabled),
          PaintOpEq<TranslateOp>(15.0, 15.0),
          PaintOpEq<SaveOp>(),  // Second nested clip.
          PaintOpEq<TranslateOp>(3.0, 0.0), PaintOpEq<TranslateOp>(0.0, 3.0),
          PaintOpEq<ClipPathOp>(
              SkPath::Polygon({{150, 47}, {200, 197}, {100, 200}},
                              /*isClosed=*/false),
              SkClipOp::kIntersect, /*antialias=*/false,
              /*use_paint_cache=*/UsePaintCache::kDisabled),
          PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));

  // `FlushRecorder()` flushed the recording canvas, leaving it empty.
  ASSERT_THAT(context->FlushRecorder(), IsEmpty());

  context->RestoreMatrixClipStack(context->GetPaintCanvas());
  context->restore(exception_state);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          // Empty matrix stack, no need to reset matrix before setting clip.
          PaintOpEq<ClipRectOp>(SkRect::MakeLTRB(0, 0, 100, 100),
                                SkClipOp::kIntersect,
                                /*antialias=*/false),
          // Current transform is identity, no need to reset matrix either.
          PaintOpEq<SaveOp>(),
          PaintOpEq<ClipPathOp>(
              SkPath::Polygon({{110, 100}, {210, 100}, {160, 220}},
                              /*isClosed=*/false),
              SkClipOp::kIntersect, /*antialias=*/false,
              /*use_paint_cache=*/UsePaintCache::kDisabled),
          PaintOpEq<SetMatrixOp>(SkM44(1.f, 0.f, 0.f, 25.f, 0.f, 1.f, 0.f, 35.f,
                                       0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 0.f, 1.f)),
          // Current transform is not identity, need to reset matrix.
          PaintOpEq<SaveOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1.f, 0.f, 0.f, 0.f, 0.f, 1.f, 0.f, 0.f,
                                       0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 0.f, 1.f)),
          PaintOpEq<ClipPathOp>(
              SkPath::Polygon({{178, 85}, {228, 235}, {128, 238}},
                              /*isClosed=*/false),
              SkClipOp::kIntersect, /*antialias=*/false,
              /*use_paint_cache=*/UsePaintCache::kDisabled),
          PaintOpEq<SetMatrixOp>(SkM44(1.f, 0.f, 0.f, 28.f, 0.f, 1.f, 0.f, 38.f,
                                       0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 0.f, 1.f)),
          PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));
}

TEST(BaseRenderingContextRestoreStackTests, UnclosedLayersAreNotFlushed) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->save();
  context->translate(1, 2);
  context->fillRect(0, 0, 4, 4);
  context->save();
  context->translate(3, 4);
  context->fillRect(1, 1, 5, 5);

  context->setGlobalAlpha(0.4);
  context->setGlobalCompositeOperation("source-in");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->translate(5, 6);
  context->fillRect(2, 2, 6, 6);

  // Only draw ops preceding `beginLayer` gets flushed.
  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<SaveOp>(), PaintOpEq<TranslateOp>(1, 2),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 4, 4), FillFlags()),
          PaintOpEq<SaveOp>(), PaintOpEq<TranslateOp>(3, 4),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 1, 5, 5), FillFlags()),
          PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));

  context->fillRect(3, 3, 7, 7);

  // Matrix stack gets rebuilt, but recording contains no draw calls.
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<SaveOp>(),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 1,  //
                                                          0, 1, 0, 2,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<SaveOp>(),
                             PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                          0, 1, 0, 6,  //
                                                          0, 0, 1, 0,  //
                                                          0, 0, 0, 1)),
                             PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));

  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  cc::PaintFlags filter_flags;
  filter_flags.setAlphaf(0.4f);
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<SaveOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 1,  //
                                       0, 1, 0, 2,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          PaintOpEq<SaveOp>(),
          PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                       0, 1, 0, 6,  //
                                       0, 0, 1, 0,  //
                                       0, 0, 0, 1)),
          DrawRecordOpEq(
              PaintOpEq<SaveOp>(),
              PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                           0, 1, 0, 0,  //
                                           0, 0, 1, 0,  //
                                           0, 0, 0, 1)),
              PaintOpEq<SaveLayerFiltersOp>(
                  std::array{shadow_filter, foreground_filter},
                  composite_flags),
              PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                           0, 1, 0, 6,  //
                                           0, 0, 1, 0,  //
                                           0, 0, 0, 1)),
              PaintOpEq<SaveLayerOp>(filter_flags),
              PaintOpEq<TranslateOp>(5.0f, 6.0f),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(2, 2, 6, 6), FillFlags()),
              PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(3, 3, 7, 7), FillFlags()),
              PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>(),
              PaintOpEq<RestoreOp>()),

          PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>()));
}

TEST(BaseRenderingContextResetTest, DiscardsRenderStates) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalAlpha(0.5);
  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);

  EXPECT_EQ(context->StateStackDepth(), 1);
  EXPECT_EQ(context->OpenedLayerCount(), 1);

  // Discard the rendering states:
  context->reset();

  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);

  // `reset` discards all paint ops and reset the canvas content.
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, context->Width(), context->Height()),
                  ClearRectFlags())));

  // The recording should now be empty:
  ASSERT_THAT(RecordedOpsView(context->FlushRecorder()), IsEmpty());

  // Do some operation and check that the rendering state was reset:
  context->fillRect(1, 2, 3, 4);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(1, 2, 3, 4),
                                                   FillFlags())));
}

TEST(BaseRenderingContextLayersCallOrderTests, LoneBeginLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 1);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, LoneRestore) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->restore(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, LoneEndLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->endLayer(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, SaveRestore) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->save();
  context->restore(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, SaveResetRestore) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->save();
  context->reset();
  context->restore(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, BeginLayerEndLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->endLayer(scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, BeginLayerResetEndLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->reset();
  context->endLayer(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, SaveBeginLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->save();
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 2);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, SaveEndLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->save();
  context->endLayer(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 1);
  EXPECT_EQ(context->OpenedLayerCount(), 0);
}

TEST(BaseRenderingContextLayersCallOrderTests, BeginLayerSave) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->save();
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  EXPECT_EQ(context->StateStackDepth(), 2);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, BeginLayerRestore) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->restore(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 1);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, SaveBeginLayerRestore) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->save();
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->restore(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 2);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, BeginLayerSaveEndLayer) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      scope.GetExceptionState());
  EXPECT_FALSE(scope.GetExceptionState().HadException());
  context->save();
  context->endLayer(scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
  EXPECT_EQ(context->StateStackDepth(), 2);
  EXPECT_EQ(context->OpenedLayerCount(), 1);
}

TEST(BaseRenderingContextLayersCallOrderTests, NestedLayers) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState no_exception;
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);
  EXPECT_EQ(context->StateStackDepth(), 2);
  EXPECT_EQ(context->OpenedLayerCount(), 2);
  context->endLayer(no_exception);
  context->endLayer(no_exception);
  EXPECT_EQ(context->StateStackDepth(), 0);
  EXPECT_EQ(context->OpenedLayerCount(), 0);

  // Nested layers are all stored in the same side recording and drawn as a
  // whole to the main recording.
  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerAlphaOp>(1.0f),  //
                                    PaintOpEq<SaveLayerAlphaOp>(1.0f),  //
                                    PaintOpEq<RestoreOp>(),             //
                                    PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayersCSSTests,
     FilterOperationsWithStyleResolutionHost) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  context->SetHostHTMLCanvas(
      MakeGarbageCollected<HTMLCanvasElement>(scope.GetDocument()));
  context->setFont("10px sans-serif");
  NonThrowableExceptionState exception_state;
  context->beginLayer(scope.GetScriptState(),
                      FilterOption(scope, "'blur(1em)'"), exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(10.0f, 10.0f, SkTileMode::kDecal, nullptr));
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayersCSSTests,
     FilterOperationsWithNoStyleResolutionHost) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;
  context->beginLayer(scope.GetScriptState(),
                      FilterOption(scope, "'blur(1em)'"), exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  // Font sized is assumed to be 16px when no style resolution is available.
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(16.0f, 16.0f, SkTileMode::kDecal, nullptr));
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextMeshTests, DrawMesh) {
  test::TaskEnvironment task_environment;

  scoped_refptr<cc::RefCountedBuffer<SkPoint>> vbuf =
      base::MakeRefCounted<cc::RefCountedBuffer<SkPoint>>(
          std::vector<SkPoint>{{0, 0}, {100, 0}, {100, 100}, {0, 100}});
  scoped_refptr<cc::RefCountedBuffer<SkPoint>> uvbuf =
      base::MakeRefCounted<cc::RefCountedBuffer<SkPoint>>(
          std::vector<SkPoint>{{0, 0}, {1, 0}, {1, 1}, {0, 1}});
  scoped_refptr<cc::RefCountedBuffer<uint16_t>> ibuf =
      base::MakeRefCounted<cc::RefCountedBuffer<uint16_t>>(
          std::vector<uint16_t>{0, 1, 2, 0, 2, 3});

  V8TestingScope scope;
  NonThrowableExceptionState no_exception;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);

  context->drawMesh(
      MakeGarbageCollected<Mesh2DVertexBuffer>(vbuf),
      MakeGarbageCollected<Mesh2DUVBuffer>(uvbuf),
      MakeGarbageCollected<Mesh2DIndexBuffer>(ibuf),
      MakeGarbageCollected<V8CanvasImageSource>(
          MakeGarbageCollected<ImageBitmap>(
              context->createImageData(/*sw=*/10, /*sh=*/10, no_exception),
              /*crop_rect=*/std::nullopt)),
      no_exception);

  PaintFlags flags = FillFlags();
  SkMatrix local_matrix = SkMatrix::Scale(1.0f / 10, 1.0f / 10);
  flags.setShader(PaintShader::MakeImage(PaintImage(), SkTileMode::kClamp,
                                         SkTileMode::kClamp, &local_matrix));
  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(PaintOpEq<DrawVerticesOp>(vbuf, uvbuf, ibuf, flags)));
}

}  // namespace
}  // namespace blink

"""


```
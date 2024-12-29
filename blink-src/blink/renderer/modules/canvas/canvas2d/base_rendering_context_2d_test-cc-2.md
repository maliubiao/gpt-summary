Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine test file. They are particularly interested in its relation to web technologies (JavaScript, HTML, CSS), potential logic, common usage errors, and debugging context.

**Plan:**

1. **Identify the core functionality:** The code uses Google Test to verify the behavior of the `BaseRenderingContext2D` class, specifically its layer management and interaction with global states like alpha, composite operation, shadow, filter, and transforms.
2. **Explain the relationship to web technologies:** Relate the C++ testing to the corresponding Canvas API features in JavaScript, which are used in HTML to draw graphics and styled with CSS.
3. **Analyze the logic and provide examples:** Explain the purpose of each test case and provide hypothetical inputs and expected outputs based on the assertions made in the tests.
4. **Identify common usage errors:** Discuss potential mistakes developers might make when using the Canvas API features being tested.
5. **Describe the user journey for debugging:** Outline the steps a developer might take in a browser to trigger the execution of this code.
6. **Summarize the functionality based on the provided snippet.**

**Step-by-step breakdown:**

*   **Core functionality:** The tests focus on the `beginLayer` and `endLayer` methods of the `BaseRenderingContext2D` class and how they interact with various rendering states. The `EXPECT_THAT` assertions verify that the correct paint operations (`SaveLayerOp`, `SaveLayerAlphaOp`, `SaveLayerFiltersOp`, `RestoreOp`, `TranslateOp`, `SetMatrixOp`) are recorded in the expected order with the correct parameters.
*   **Web technology relationship:** The tests cover JavaScript Canvas API methods like `globalAlpha`, `globalCompositeOperation`, `shadowBlur`, `shadowColor`, `filter`, and transform methods (`translate`). These methods are used in `<canvas>` elements in HTML and sometimes influenced by CSS.
*   **Logic and examples:** Each `TEST` function sets up a specific combination of rendering states and then calls `beginLayer` and `endLayer`. The assertions check the sequence of recorded paint operations. For example, setting `globalAlpha` should result in a `SaveLayerAlphaOp`.
*   **Common usage errors:**  Developers might misuse the order of `beginLayer` and `endLayer`, forget to set necessary properties before calling `beginLayer`, or misunderstand how different global states interact within a layer.
*   **Debugging journey:** A developer might inspect the canvas rendering in the browser's developer tools, notice unexpected behavior related to layering or effects, and then trace the execution to the C++ code responsible for these operations.
*   **Summarization:** Focus on the testing of layer creation and the impact of global rendering states on the generated paint operations.
这是 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc` 文件的第三部分，主要功能是**测试 `BaseRenderingContext2D` 类在创建和管理图形层 (layers) 时，如何与各种全局渲染状态 (global rendering states) 相互作用**。

它主要测试以下方面的组合效果：

*   **变换 (Transforms):** `translate()`
*   **阴影 (Shadow):** `shadowBlur`, `shadowColor`
*   **上下文过滤器 (Context Filter):** `filter` 属性
*   **合成 (Composition):** `globalCompositeOperation`

这些测试验证了当在 `beginLayer()` 和 `endLayer()` 之间设置了不同的全局状态时，底层图形记录器 (recorder) 是否记录了正确的绘制操作 (paint operations)。

**与 JavaScript, HTML, CSS 的功能关系：**

这个 C++ 测试文件直接测试了 Canvas 2D API 的实现，这些 API 在 JavaScript 中暴露给开发者，用于在 HTML `<canvas>` 元素上绘制图形。CSS 可以通过 `filter` 属性影响 Canvas 的渲染，但这里的测试主要关注 JavaScript API 的行为。

*   **JavaScript:**
    *   `context.translate(4, 5)`:  JavaScript 代码调用 `translate()` 方法平移 Canvas 的坐标系。
    *   `context.shadowBlur = 2.0; context.shadowColor = "red";`:  JavaScript 代码设置阴影的模糊半径和颜色。
    *   `context.filter = "blur(5px)";`:  JavaScript 代码设置 Canvas 的全局过滤器。
    *   `context.globalCompositeOperation = "source-in";`: JavaScript 代码设置全局合成操作。
    *   `context.beginLayer(); context.endLayer();`: JavaScript 代码开始和结束一个新的图形层。

*   **HTML:**  `<canvas>` 元素是这些操作的目标。例如：
    ```html
    <canvas id="myCanvas" width="200" height="100"></canvas>
    <script>
      const canvas = document.getElementById('myCanvas');
      const context = canvas.getContext('2d');
      context.translate(4, 5);
      // ... 其他 JavaScript 代码
    </script>
    ```

*   **CSS:** 虽然这里的测试主要关注 JavaScript API，但 CSS 的 `filter` 属性与 Canvas 的 `filter` 属性概念相同，可以影响 Canvas 的渲染效果。

**逻辑推理，假设输入与输出：**

以 `TEST(BaseRenderingContextLayerGlobalStateTests, TransformsAlone)` 为例：

*   **假设输入:** 在 JavaScript 中调用了 `context.translate(4, 5)`，然后执行 `context.beginLayer()` 和 `context.endLayer()`。
*   **预期输出:**  `FlushRecorder()` 应该记录一个 `TranslateOp` 操作，以及一个包含 `SaveLayerAlphaOp` (默认 alpha 为 1.0) 和 `RestoreOp` 的 `DrawRecordOpEq` 操作。这意味着平移操作会影响后续图层的绘制，并且图层会保存其状态。

以 `TEST(BaseRenderingContextLayerGlobalStateTests, TransformsWithShadow)` 为例：

*   **假设输入:** 在 JavaScript 中调用了 `context.translate(4, 5)`，设置了阴影 (`shadowBlur`, `shadowColor`)，然后执行 `context.beginLayer()` 和 `context.endLayer()`。
*   **预期输出:** `FlushRecorder()` 应该记录一个 `TranslateOp` 操作，以及一个复杂的 `DrawRecordOpEq` 操作。这个 `DrawRecordOpEq` 包含：
    *   `SaveOp`: 保存当前图形状态。
    *   `SetMatrixOp`: 设置初始矩阵（单位矩阵）。
    *   `SaveLayerOp`: 创建一个带有阴影效果的图层。
    *   `SetMatrixOp`: 再次设置矩阵，应用之前的平移变换。
    *   `RestoreOp`: 恢复到图层创建前的状态。
    *   `RestoreOp`: 恢复到最开始保存的状态。
    这表明阴影效果是在平移之后应用的，并且需要保存和恢复矩阵状态来正确渲染。

**用户或者编程常见的使用错误：**

*   **忘记在 `beginLayer()` 之前设置状态:** 用户可能在 `beginLayer()` 之后才设置 `translate()`, `shadowBlur` 等属性，导致这些状态没有应用到新的图层上。
    ```javascript
    context.beginLayer();
    context.translate(10, 20); // 错误：变换可能不会应用到这个图层
    context.fillRect(0, 0, 50, 50);
    context.endLayer();
    ```
*   **误解图层的隔离性:** 用户可能认为在 `beginLayer()` 和 `endLayer()` 之间修改的全局状态不会影响到之前的绘制，但实际上某些状态的修改可能会影响到整个 Canvas 的渲染流程。
*   **不匹配的 `beginLayer()` 和 `endLayer()`:**  忘记调用 `endLayer()` 会导致图形上下文状态异常，可能会影响后续的绘制。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者在 HTML 中使用了 `<canvas>` 元素。**
2. **开发者使用 JavaScript 获取了 Canvas 的 2D 渲染上下文 (`canvas.getContext('2d')`)。**
3. **开发者调用 Canvas 2D API 中的方法，例如 `translate()`, `shadowBlur`, `filter`, `globalCompositeOperation` 以及 `beginLayer()` 和 `endLayer()`，来绘制复杂的图形或应用视觉效果。**
4. **在浏览器中渲染页面时，如果 Canvas 的渲染结果不符合预期（例如，变换没有生效，阴影位置错误，或者图层混合出现问题），开发者可能会怀疑是 Canvas 2D API 的实现有问题。**
5. **为了调试这个问题，Blink 引擎的开发者或贡献者可能会查看 `blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc` 这个文件中的测试用例，来了解这些 API 的预期行为。**
6. **通过查看相关的测试用例，例如 `TransformsAlone`, `TransformsWithShadow`, `TransformsWithContextFilter` 等，开发者可以理解当调用 `beginLayer()` 时，各种全局状态是如何被处理和记录的。**
7. **如果测试用例失败，或者与观察到的行为不一致，那么就可能发现了 Blink 引擎中 Canvas 2D API 实现的 bug。**
8. **开发者可以通过修改 C++ 代码，重新编译 Chromium，并在浏览器中复现问题，来验证修复方案。**

**归纳一下它的功能 (基于提供的代码片段):**

这个代码片段的功能是**详细测试 `BaseRenderingContext2D` 类在创建图形层时，如何正确地处理和应用变换、阴影和上下文过滤器等全局渲染状态**。它通过断言图形记录器中记录的绘制操作序列来验证实现的正确性。每个测试用例都针对不同的全局状态组合，确保了 Canvas 2D API 在处理复杂场景时的行为符合预期。 这些测试是确保 Chromium 浏览器中 Canvas 功能正确性和稳定性的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setAlphaf(0.3f);
  flags.setBlendMode(SkBlendMode::kMultiply);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlphaAndComposite) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(composite_flags),
                  PaintOpEq<SaveLayerAlphaOp>(0.3f), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlphaAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalAlpha(0.5);
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(shadow_flags),
                  PaintOpEq<SaveLayerAlphaOp>(0.5f), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlphaBlendingAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalAlpha(0.5);
  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  cc::PaintFlags shadow_flags;
  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerAlphaOp>(0.5f), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, GlobalAlphaCompositeAndShadow) {
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
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerAlphaOp>(0.5f), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, BlendingAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, CompositeAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, Filter) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 10})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(10.0f, 10.0f, SkTileMode::kDecal, nullptr));
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterAndGlobalAlpha) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setAlphaf(0.3f);
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterAndBlending) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));
  flags.setBlendMode(SkBlendMode::kMultiply);
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterAndComposite) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(composite_flags),
                  PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(shadow_flags),
                  PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterGlobalAlphaAndBlending) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->setGlobalCompositeOperation("multiply");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags flags;
  flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));
  flags.setAlphaf(0.3f);
  flags.setBlendMode(SkBlendMode::kMultiply);
  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(flags),
                                            PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterGlobalAlphaAndComposite) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.3);
  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));
  filter_flags.setAlphaf(0.3f);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(composite_flags),
                  PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterGlobalAlphaAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.4);
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  cc::PaintFlags filter_flags;
  filter_flags.setAlphaf(0.4f);
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(shadow_flags),
                  PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests,
     FilterGlobalAlphaBlendingAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.4);
  context->setGlobalCompositeOperation("multiply");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

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
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests,
     FilterGlobalAlphaCompositeAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalAlpha(0.4);
  context->setGlobalCompositeOperation("source-in");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
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
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterBlendingAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("multiply");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kMultiply);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, FilterCompositeAndShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setGlobalCompositeOperation("source-in");
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(),
      FilterOption(scope, "({name: 'gaussianBlur', stdDeviation: 20})"),
      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{shadow_filter, foreground_filter}, composite_flags),
          PaintOpEq<SaveLayerOp>(filter_flags), PaintOpEq<RestoreOp>(),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, ContextFilter) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(20.0f));
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(20.0f, 20.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(PaintOpEq<SaveLayerOp>(filter_flags),
                                    PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, ContextFilterLayerFilter) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(2.0f));
  context->beginLayer(scope.GetScriptState(),
                      FilterOption(scope, "'blur(5px)'"), exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags global_flags;
  cc::PaintFlags layer_flags;
  global_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(2.0f, 2.0f, SkTileMode::kDecal, nullptr));
  layer_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(5.0f, 5.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(DrawRecordOpEq(
                  PaintOpEq<SaveLayerOp>(global_flags),
                  PaintOpEq<SaveLayerOp>(layer_flags), PaintOpEq<RestoreOp>(),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, ContextFilterShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(5.0f));
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags layer_flags;
  sk_sp<cc::PaintFilter> foreground_filter =
      sk_make_sp<BlurPaintFilter>(5.0f, 5.0f, SkTileMode::kDecal, nullptr);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);

  sk_sp<cc::PaintFilter> background_filter =
      sk_make_sp<ComposePaintFilter>(shadow_filter, foreground_filter);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(DrawRecordOpEq(
          PaintOpEq<SaveLayerFiltersOp>(
              std::array{background_filter, foreground_filter}, layer_flags),
          PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, TransformsAlone) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(4, 5);
  context->beginLayer(
      scope.GetScriptState(), BeginLayerOptions::Create(), exception_state);
  context->endLayer(exception_state);

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(
                PaintOpEq<TranslateOp>(4, 5),
                DrawRecordOpEq(
                  PaintOpEq<SaveLayerAlphaOp>(1.0f),
                  PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, TransformsWithShadow) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(4, 5);
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->beginLayer(
      scope.GetScriptState(), BeginLayerOptions::Create(), exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags shadow_flags;
  shadow_flags.setImageFilter(sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowAndForeground, nullptr));

  EXPECT_THAT(context->FlushRecorder(),
              RecordedOpsAre(
                PaintOpEq<TranslateOp>(4, 5),
                DrawRecordOpEq(
                  PaintOpEq<SaveOp>(),
                  PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                               0, 1, 0, 0,  //
                                               0, 0, 1, 0,  //
                                               0, 0, 0, 1)),
                  PaintOpEq<SaveLayerOp>(shadow_flags),
                  PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                               0, 1, 0, 5,  //
                                               0, 0, 1, 0,  //
                                               0, 0, 0, 1)),
                  PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests, TransformsWithContextFilter) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(4, 5);
  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(5.0f));
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags filter_flags;
  filter_flags.setImageFilter(
      sk_make_sp<BlurPaintFilter>(5.0f, 5.0f, SkTileMode::kDecal, nullptr));

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          DrawRecordOpEq(PaintOpEq<SaveOp>(),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                                      0, 1, 0, 0,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)),
                         PaintOpEq<SaveLayerOp>(filter_flags),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                      0, 1, 0, 5,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)),
                         PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests,
     TransformsWithShadowAndCompositedDraw) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(4, 5);
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setGlobalCompositeOperation("source-in");
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags composite_flags;
  composite_flags.setBlendMode(SkBlendMode::kSrcIn);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);
  sk_sp<cc::PaintFilter> foreground_filter = nullptr;

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          DrawRecordOpEq(PaintOpEq<SaveOp>(),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                                      0, 1, 0, 0,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)),
                         PaintOpEq<SaveLayerFiltersOp>(
                             std::array{shadow_filter, foreground_filter},
                             composite_flags),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                      0, 1, 0, 5,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)),
                         PaintOpEq<RestoreOp>(), PaintOpEq<RestoreOp>())));
}

TEST(BaseRenderingContextLayerGlobalStateTests,
     TransformsWithShadowAndContextFilter) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* context = MakeGarbageCollected<TestRenderingContext2D>(scope);
  NonThrowableExceptionState exception_state;

  context->translate(4, 5);
  context->setShadowBlur(2.0);
  context->setShadowColor("red");
  context->setFilter(scope.GetScriptState(), MakeBlurCanvasFilter(5.0f));
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      exception_state);
  context->endLayer(exception_state);

  cc::PaintFlags layer_flags;
  sk_sp<cc::PaintFilter> foreground_filter =
      sk_make_sp<BlurPaintFilter>(5.0f, 5.0f, SkTileMode::kDecal, nullptr);

  sk_sp<cc::PaintFilter> shadow_filter = sk_make_sp<DropShadowPaintFilter>(
      0.0f, 0.0f, 1.0f, 1.0f, SkColors::kRed,
      DropShadowPaintFilter::ShadowMode::kDrawShadowOnly, nullptr);

  sk_sp<cc::PaintFilter> background_filter =
      sk_make_sp<ComposePaintFilter>(shadow_filter, foreground_filter);

  EXPECT_THAT(
      context->FlushRecorder(),
      RecordedOpsAre(
          PaintOpEq<TranslateOp>(4, 5),
          DrawRecordOpEq(PaintOpEq<SaveOp>(),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 0,  //
                                                      0, 1, 0, 0,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)),
                         PaintOpEq<SaveLayerFiltersOp>(
                             std::array{background_filter, foreground_filter},
                             layer_flags),
                         PaintOpEq<SetMatrixOp>(SkM44(1, 0, 0, 4,  //
                                                      0, 1, 0, 5,  //
                                                      0, 0, 1, 0,  //
                                                      0, 0, 0, 1)
"""


```
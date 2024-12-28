Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - The "What":**

The first step is recognizing the file type and its location within the Chromium/Blink codebase. The `.cc` extension signals a C++ source file. The path `blink/renderer/core/html/canvas/html_canvas_element_test.cc` immediately tells us this is a test file specifically for the `HTMLCanvasElement` class within the Blink rendering engine's core HTML canvas functionality. The `_test.cc` suffix is a common convention for unit tests.

**2. High-Level Functionality - The "Why":**

Knowing it's a test file, the core purpose is to verify the correct behavior of the `HTMLCanvasElement` class. This involves checking various aspects of its functionality, edge cases, and interactions with other parts of the engine.

**3. Examining the Includes - The "Dependencies":**

The `#include` directives provide clues about the features being tested and the context in which `HTMLCanvasElement` operates. Key includes and their significance:

* `"third_party/blink/renderer/core/html/canvas/html_canvas_element.h"`:  Confirms the test is for this specific class.
* Includes from `base/`: Indicate interaction with Chromium's base library, likely for utilities like `RunLoop`, string manipulation, and tracing.
* Includes from `cc/`:  Suggests testing related to the Compositor thread, particularly painting (`cc::PaintOp`).
* Includes from `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  Confirms the use of Google Test and Google Mock frameworks for writing tests.
* Includes related to Blink internals (`bindings/core/v8`, `core/html/canvas`, `core/page`, `core/paint`, `core/script`, `core/testing`): Indicate testing of interactions with JavaScript, canvas rendering contexts, page lifecycle, painting mechanisms, and scripting.
* Includes from `platform/testing`:  Suggests paint testing and potentially platform-specific considerations.

**4. Analyzing the Test Structure - The "How":**

* **Test Fixtures:** The presence of `class HTMLCanvasElementTest : public RenderingTest, public PaintTestConfigurations` and `class HTMLCanvasElementWithTracingTest : public RenderingTest` reveals the use of test fixtures. This means each test within these classes will have a consistent setup and teardown environment provided by `RenderingTest` (for basic rendering setup) and `PaintTestConfigurations` (likely for paint-related configurations). The `HTMLCanvasElementWithTracingTest` specifically targets scenarios involving tracing.
* **`INSTANTIATE_PAINT_TEST_SUITE_P`:** This line indicates the use of parameterized tests specifically for paint testing, suggesting different configurations are being tested.
* **Individual `TEST_P` and `TEST` Macros:** These are the core test cases. Each test focuses on a specific aspect of `HTMLCanvasElement` functionality.
* **Assertions and Expectations:**  `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`, `ASSERT_TRUE`, `ASSERT_EQ`, `EXPECT_NE` are standard Google Test/Mock assertions used to verify expected outcomes.

**5. Deeper Dive into Individual Tests - The "Details":**

Now, examine each test case individually to understand its specific purpose:

* **`NoResourceProviderAfterCanvas2DLayerBridgeCreation`:** Tests lazy initialization of `CanvasResourceProvider`. The key idea is to create the canvas and its 2D context but verify that the resource provider isn't created prematurely.
* **`CleanCanvasResizeDoesntClearFrameBuffer`:** Tests that resizing a "clean" canvas (no rendering operations) doesn't clear the framebuffer. This verifies optimization related to unnecessary clears.
* **`CanvasResizeClearsFrameBuffer`:** Tests the opposite scenario – resizing a canvas *after* rendering operations *does* clear the framebuffer to ensure consistency.
* **`CreateLayerUpdatesCompositing`:** Checks that creating a compositing layer for the canvas correctly triggers updates in the rendering pipeline.
* **`CanvasInvalidation`:** Verifies that drawing on a canvas triggers an invalidation event, signaling the need for a repaint.
* **`CanvasNotInvalidatedOnFirstFrameInDOM` and `CanvasNotInvalidatedOnFirstPaint`:**  These test that invalidation doesn't occur prematurely when the canvas is first added to the DOM or painted, preventing unnecessary repaints.
* **`CanvasInvalidationInFrame`:** Checks that canvas invalidation works correctly within iframes.
* **`BrokenCanvasHighRes`:** Tests the handling of "broken" canvases (likely for error scenarios) at different resolutions.
* **`HTMLCanvasElementWithTracingSyncTest` and `HTMLCanvasElementWithTracingAsyncTest`:** These test scenarios where canvas readback operations (`toDataURL`, `getImageData`, `toBlob`, `convertToBlob`) emit tracing events for identifiability purposes. They specifically check for the presence and correct association of these trace events.

**6. Connecting to Web Technologies - The "Relevance":**

At this point, it's crucial to connect the C++ code back to web technologies:

* **JavaScript Interaction:** The tests heavily use JavaScript snippets within `R"JS(...)JS"` to interact with the canvas element, demonstrating how JavaScript manipulates the canvas API.
* **HTML Structure:**  The tests create `<canvas>` elements using `SetBodyInnerHTML`, showing how the canvas element is embedded in HTML.
* **CSS Styling:**  The `CanvasNotInvalidatedOnFirstPaint` test demonstrates the impact of CSS (`display: none`) on canvas rendering and invalidation.

**7. Inferring User/Developer Impact - The "Practicalities":**

Based on the tests, we can infer potential issues:

* **Premature Resource Allocation:** The `NoResourceProviderAfterCanvas2DLayerBridgeCreation` test highlights the importance of lazy initialization for performance.
* **Incorrect Framebuffer Clearing:** The resize tests show how the engine optimizes framebuffer clearing, and a bug here could lead to visual artifacts or performance problems.
* **Compositing Issues:** The `CreateLayerUpdatesCompositing` test relates to how the canvas interacts with the GPU for rendering. Failures here could lead to rendering glitches or performance issues with composited content.
* **Invalidation Bugs:** The invalidation tests are critical for ensuring that the browser correctly repaints the canvas when its content changes. Incorrect invalidation can lead to stale content being displayed.
* **Privacy/Identifiability:** The tracing tests reveal a focus on tracking canvas readback operations, likely for privacy or security reasons. Misconfigurations could lead to information leaks.

**8. Constructing Examples and Scenarios:**

Finally, create concrete examples to illustrate the test scenarios and potential user impact. This involves thinking about how a web developer might use the canvas API and what could go wrong.

This iterative process of understanding the code, its context, and its purpose allows for a comprehensive analysis of the test file and its implications. The key is to connect the low-level C++ code to the higher-level concepts of web development and user experience.
这个文件 `html_canvas_element_test.cc` 是 Chromium Blink 渲染引擎中用于测试 `HTMLCanvasElement` 类的单元测试文件。 它的主要功能是验证 `HTMLCanvasElement` 的各种行为和功能是否符合预期。

以下是它功能的详细列表，并结合 JavaScript、HTML 和 CSS 的关系进行举例说明：

**1. 验证 `HTMLCanvasElement` 的基本属性和方法:**

* **测试 CanvasRenderingContext 的创建:**  验证通过 JavaScript 的 `canvas.getContext('2d')` 或其他上下文类型是否能正确创建 `CanvasRenderingContext` 对象。
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      expect(ctx).not.toBeNull(); // 对应的 C++ 测试会验证 ctx 是否成功创建
      ```
* **测试 Canvas 的尺寸设置:** 验证通过 HTML 属性 `width` 和 `height` 或 JavaScript 的 `canvas.width` 和 `canvas.height` 设置 Canvas 尺寸是否生效。
    * **HTML 例子:**
      ```html
      <canvas id="myCanvas" width="200" height="100"></canvas>
      ```
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      canvas.width = 300;
      canvas.height = 150;
      // 对应的 C++ 测试会验证 canvas 的内部尺寸是否更新
      ```
* **测试 Canvas 内容的清除:** 验证通过 JavaScript 的 `context.clearRect()` 方法是否能正确清除 Canvas 的指定区域。
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = 'red';
      ctx.fillRect(0, 0, 100, 50);
      ctx.clearRect(10, 10, 80, 30);
      // 对应的 C++ 测试会验证清除操作是否正确反映在 Canvas 的绘制记录中
      ```

**2. 验证 Canvas 的渲染和绘制行为:**

* **测试 Canvas 绘制操作的记录:** 验证 Canvas 的绘制操作（例如 `fillRect`, `strokeRect`, `fillText` 等）是否被正确记录，以便后续的渲染和合成。
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = 'blue';
      ctx.fillRect(20, 20, 60, 60);
      // 对应的 C++ 测试会捕获并验证这次绘制操作是否被记录为 `DrawRectOp` 等类型的 PaintOp
      ```
    * **假设输入:**  JavaScript 代码执行 `ctx.fillRect(20, 20, 60, 60)`。
    * **预期输出:** C++ 测试会断言 Canvas 的绘制记录中包含一个 `DrawRectOp`，其参数为位置 (20, 20) 和尺寸 (60, 60)，以及相应的填充颜色。
* **测试 Canvas 的重绘和更新:** 验证当 Canvas 的内容发生变化时，渲染引擎是否能正确触发重绘，并将更新后的内容显示在屏幕上。 这与浏览器的渲染流水线相关。
* **测试离屏 Canvas (`OffscreenCanvas`):**  尽管这个文件主要测试 `HTMLCanvasElement`，但它也可能包含与 `OffscreenCanvas` 相关的测试，因为它们共享一些底层实现。

**3. 验证 Canvas 与浏览器其他功能的交互:**

* **测试 Canvas 的合成 (Compositing):**  验证 Canvas 是否能正确地参与到浏览器的合成过程中，特别是当它被提升为合成层时。这与 CSS 的 `will-change` 或 `transform: translateZ(0)` 等属性有关。
    * **CSS 例子:**
      ```css
      #myCanvas {
        will-change: transform;
      }
      ```
    * **对应的 C++ 测试:** 会验证当 Canvas 应用了导致层合成的 CSS 属性时，它是否创建了相应的 `CanvasLayer` 或类似的合成层对象。
* **测试 Canvas 的可访问性 (Accessibility):**  验证 Canvas 是否能提供一些基本的可访问性信息，例如 ARIA 属性的支持。
* **测试 Canvas 的性能:**  虽然这个文件主要是功能测试，但某些测试可能间接涉及到性能，例如测试不必要的重绘是否发生。
* **测试 Canvas 的安全特性:**  验证 Canvas 是否遵守同源策略，防止跨域的图像或数据泄露。

**4. 处理用户或编程常见的错误:**

* **测试无效的 `getContext()` 参数:**  验证当传入无效的上下文类型（例如 `'webgl2d'`）时，`getContext()` 是否返回 `null` 或抛出异常。
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('webgl2d');
      expect(ctx).toBeNull(); // 对应的 C++ 测试会验证 getContext 的返回值
      ```
* **测试 Canvas 尺寸设置为负数或零:** 验证当 `canvas.width` 或 `canvas.height` 被设置为无效值时，浏览器的行为（通常会忽略或恢复到默认值）。
    * **JavaScript 例子:**
      ```javascript
      const canvas = document.getElementById('myCanvas');
      canvas.width = -10;
      // 对应的 C++ 测试会验证 canvas 的实际宽度是否仍然是有效值
      ```
* **测试在未附加到 DOM 的 Canvas 上下文操作:**  验证在 Canvas 元素还未添加到文档中时，尝试获取其上下文或进行绘制操作的行为（通常不会报错，但可能不会有任何效果）。

**5. 模拟用户操作到达测试代码的步骤:**

虽然这个 C++ 文件本身不直接涉及用户操作，但它测试的代码是用户通过浏览器与网页进行交互时会触发的。 以下是一些可能的步骤：

1. **用户在浏览器中打开一个包含 `<canvas>` 元素的网页。**
2. **网页中的 JavaScript 代码获取 Canvas 元素，例如 `document.getElementById('myCanvas')`。**
3. **JavaScript 代码调用 `canvas.getContext('2d')` 获取 2D 渲染上下文。**
4. **JavaScript 代码使用 Canvas API 进行绘制操作，例如 `ctx.fillRect(10, 10, 50, 50)` 或 `ctx.drawImage(image, 0, 0)`。**
5. **用户可能调整浏览器窗口大小，导致 Canvas 元素的大小需要更新。**
6. **JavaScript 代码可能会动态修改 Canvas 的 `width` 或 `height` 属性。**
7. **某些用户交互（例如鼠标移动）可能会触发 JavaScript 代码在 Canvas 上进行动画或动态绘制。**
8. **如果 Canvas 被 CSS 提升为合成层（例如通过 `will-change`），则浏览器的合成器将负责渲染 Canvas 的内容。**

**文件中的具体测试用例举例说明:**

* **`NoResourceProviderAfterCanvas2DLayerBridgeCreation` 测试:**  模拟了在 JavaScript 中获取 Canvas 2D 上下文，但验证在初始阶段是否会过早地创建 `CanvasResourceProvider`，这涉及到性能优化。
    * **用户操作:** 打开一个包含 `<canvas>` 并执行 `canvas.getContext('2d')` 的网页。
    * **假设输入:**  一个简单的 HTML 页面，包含一个 ID 为 'c' 的 `<canvas>` 元素，以及一段获取其 2D 上下文的 JavaScript 代码。
    * **预期输出:** C++ 测试断言在调用 `GetOrCreateCanvas2DLayerBridge()` 后，`canvas->ResourceProvider()` 返回 `false`，表明 `CanvasResourceProvider` 尚未被创建。
* **`CleanCanvasResizeDoesntClearFrameBuffer` 测试:** 模拟了在 Canvas 上绘制内容后，立即将其尺寸设置为相同值的情况，验证是否会不必要地清除帧缓冲区。
    * **用户操作:** 网页加载后，Canvas 被绘制了一些内容，然后其尺寸被 JavaScript 代码重设为相同的值。
    * **假设输入:**  一个 `<canvas>` 元素，一段 JavaScript 代码先绘制一个蓝色矩形，然后将 `canvas.width` 设置为 10。
    * **预期输出:** C++ 测试断言 `provider->LastRecording()` 仅包含绘制蓝色矩形的 `DrawRectOp`，而不包含清除操作。
* **`CanvasResizeClearsFrameBuffer` 测试:** 模拟了在 Canvas 上绘制内容后，将其尺寸设置为不同的值，验证是否会清除帧缓冲区。
    * **用户操作:** 网页加载后，Canvas 被绘制了一些内容，然后其尺寸被 JavaScript 代码修改。
    * **假设输入:** 一个 `<canvas>` 元素，一段 JavaScript 代码先绘制一个红色矩形并调用 `getImageData` 强制渲染，然后修改 `canvas.width`，最后绘制一个蓝色矩形。
    * **预期输出:** C++ 测试断言 `provider->LastRecording()` 包含一个清除 Canvas 的 `DrawRectOp`，以及绘制蓝色矩形的 `DrawRectOp`。
* **`CanvasInvalidation` 测试:** 模拟了在 Canvas 上进行绘制操作，验证是否会触发浏览器的重绘机制。
    * **用户操作:** 网页加载后，JavaScript 代码在 Canvas 上绘制了一个绿色矩形。
    * **假设输入:**  一个 `<canvas>` 元素，一段 JavaScript 代码获取 2D 上下文并绘制一个绿色矩形。
    * **预期输出:** C++ 测试断言 `GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test()` 在绘制操作后返回 `true`，表明 Canvas 的内容已失效，需要重绘。

总而言之，`html_canvas_element_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎中 `HTMLCanvasElement` 的实现是正确、稳定和高性能的。它通过各种测试用例覆盖了 Canvas 的核心功能和与浏览器其他组件的交互，并且考虑了用户和开发者可能遇到的常见使用场景和错误。

Prompt: 
```
这是目录为blink/renderer/core/html/canvas/html_canvas_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
如果能说明用户操作是如何一步步的到达这里，就更棒了。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"

#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/test/test_trace_processor.h"
#include "base/test/trace_test_utils.h"
#include "build/buildflag.h"
#include "cc/paint/paint_op.h"
#include "cc/test/paint_op_matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/abseil-cpp/absl/status/status.h"
#include "third_party/blink/renderer/bindings/core/v8/script_evaluation_result.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/canvas/recording_test_utils.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"

using ::blink_testing::ClearRectFlags;
using ::blink_testing::FillFlags;
using ::blink_testing::RecordedOpsAre;
using ::cc::DrawRectOp;
using ::cc::PaintOpEq;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::StartsWith;

namespace blink {

class HTMLCanvasElementTest : public RenderingTest,
                              public PaintTestConfigurations {
 public:
  HTMLCanvasElementTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

 protected:
  void TearDown() override;
};

INSTANTIATE_PAINT_TEST_SUITE_P(HTMLCanvasElementTest);

void HTMLCanvasElementTest::TearDown() {
  RenderingTest::TearDown();
  CanvasRenderingContext::GetCanvasPerformanceMonitor().ResetForTesting();
}

// This test enforces that there is no eager creation of
// CanvasResourceProvider for html canvas with 2d context when its
// Canvas2DLayerBridge is initially set up. This enforcement might be changed
// in the future refactoring; but change is seriously warned against because
// certain code paths in canvas 2d (that depend on the existence of
// CanvasResourceProvider) will be changed too, causing bad regressions.
TEST_P(HTMLCanvasElementTest,
       NoResourceProviderAfterCanvas2DLayerBridgeCreation) {
  SetBodyInnerHTML("<canvas id='c' width='10' height='20'></canvas>");

  // The canvas having a 2D context is a prerequisite for calling
  // GetOrCreateCanvas2DLayerBridge().
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('c');
    var ctx = canvas.getContext('2d');
  )JS");
  GetDocument().body()->appendChild(script);

  auto* canvas =
      To<HTMLCanvasElement>(GetDocument().getElementById(AtomicString("c")));
  EXPECT_TRUE(canvas->GetOrCreateCanvas2DLayerBridge());
  EXPECT_FALSE(canvas->ResourceProvider());
}

TEST_P(HTMLCanvasElementTest, CleanCanvasResizeDoesntClearFrameBuffer) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  // Enable printing so that flushes preserve the last recording.
  GetDocument().SetPrinting(Document::kBeforePrinting);
  SetBodyInnerHTML("<canvas id='c' width='10' height='20'></canvas>");

  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('c');
    var ctx = canvas.getContext('2d');
    canvas.width = 10;
    ctx.fillStyle = 'blue';
    ctx.fillRect(0, 0, 5, 5);
  )JS");
  GetDocument().body()->appendChild(script);
  RunDocumentLifecycle();

  auto* canvas =
      To<HTMLCanvasElement>(GetDocument().getElementById(AtomicString("c")));
  CanvasResourceProvider* provider =
      canvas->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);

  cc::PaintFlags fill_flags = FillFlags();
  fill_flags.setColor(SkColors::kBlue);
  EXPECT_THAT(provider->LastRecording(),
              Optional(RecordedOpsAre(PaintOpEq<DrawRectOp>(
                  SkRect::MakeXYWH(0, 0, 5, 5), fill_flags))));
}

TEST_P(HTMLCanvasElementTest, CanvasResizeClearsFrameBuffer) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  // Enable printing so that flushes preserve the last recording.
  GetDocument().SetPrinting(Document::kBeforePrinting);
  SetBodyInnerHTML("<canvas id='c' width='10' height='20'></canvas>");

  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('c');
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = 'red';
    ctx.fillRect(0, 0, 10, 10);
    ctx.getImageData(0, 0, 1, 1);  // Force a frame to be rendered.

    canvas.width = 10;

    ctx.fillStyle = 'blue';
    ctx.fillRect(0, 0, 5, 5);
  )JS");
  GetDocument().body()->appendChild(script);
  RunDocumentLifecycle();

  auto* canvas =
      To<HTMLCanvasElement>(GetDocument().getElementById(AtomicString("c")));
  CanvasResourceProvider* provider =
      canvas->GetOrCreateCanvasResourceProvider(RasterModeHint::kPreferGPU);

  cc::PaintFlags fill_flags = FillFlags();
  fill_flags.setColor(SkColors::kBlue);
  EXPECT_THAT(
      provider->LastRecording(),
      Optional(RecordedOpsAre(
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 10, 20),
                                ClearRectFlags()),
          PaintOpEq<DrawRectOp>(SkRect::MakeXYWH(0, 0, 5, 5), fill_flags))));
}

TEST_P(HTMLCanvasElementTest, CreateLayerUpdatesCompositing) {
  // Enable script so that the canvas will create a LayoutHTMLCanvas.
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<canvas id='canvas'></canvas>");
  auto* canvas = To<HTMLCanvasElement>(
      GetDocument().getElementById(AtomicString("canvas")));
  EXPECT_FALSE(canvas->GetLayoutObject()
                   ->FirstFragment()
                   .PaintProperties()
                   ->PaintOffsetTranslation());

  EXPECT_FALSE(canvas->GetLayoutObject()->NeedsPaintPropertyUpdate());
  auto* painting_layer = GetLayoutObjectByElementId("canvas")->PaintingLayer();
  EXPECT_FALSE(painting_layer->SelfNeedsRepaint());
  canvas->CreateLayer();
  EXPECT_FALSE(canvas->GetLayoutObject()->NeedsPaintPropertyUpdate());
  EXPECT_TRUE(painting_layer->SelfNeedsRepaint());
  UpdateAllLifecyclePhasesForTest();
  ASSERT_EQ(
      painting_layer,
      To<LayoutBoxModelObject>(canvas->GetLayoutObject())->PaintingLayer());
  EXPECT_FALSE(canvas->GetLayoutObject()
                   ->FirstFragment()
                   .PaintProperties()
                   ->PaintOffsetTranslation());
}

TEST_P(HTMLCanvasElementTest, CanvasInvalidation) {
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<canvas id='canvas' width='10px' height='10px'></canvas>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('canvas');
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = 'green';
    ctx.fillRect(0, 0, 10, 10);
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
  RunDocumentLifecycle();
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
}

TEST_P(HTMLCanvasElementTest, CanvasNotInvalidatedOnFirstFrameInDOM) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.createElement('canvas');
    document.body.appendChild(canvas);
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = 'green';
    ctx.fillRect(0, 0, 10, 10);
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
}

TEST_P(HTMLCanvasElementTest, CanvasNotInvalidatedOnFirstPaint) {
  GetDocument().GetSettings()->SetScriptEnabled(true);
  SetBodyInnerHTML("<canvas id='canvas' style='display:none'></canvas>");
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
  RunDocumentLifecycle();
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('canvas');
    canvas.style.display = 'block';
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = 'green';
    ctx.fillRect(0, 0, 10, 10);
  )JS");
  GetDocument().body()->appendChild(script);
  EXPECT_FALSE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
}

TEST_P(HTMLCanvasElementTest, CanvasInvalidationInFrame) {
  SetBodyInnerHTML(R"HTML(
    <iframe id='iframe'></iframe>
  )HTML");
  SetChildFrameHTML(R"HTML(
    <canvas id='canvas' width='10px' height='10px'></canvas>
  )HTML");

  GetDocument().GetSettings()->SetScriptEnabled(true);
  ChildDocument().GetSettings()->SetScriptEnabled(true);
  EXPECT_FALSE(
      ChildDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
  RunDocumentLifecycle();
  auto* script = ChildDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(R"JS(
    var canvas = document.getElementById('canvas');
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = 'green';
    ctx.fillRect(0, 0, 10, 10);
  )JS");
  ChildDocument().body()->appendChild(script);
  EXPECT_TRUE(
      GetDocument().GetPage()->Animator().has_canvas_invalidation_for_test());
}

TEST_P(HTMLCanvasElementTest, BrokenCanvasHighRes) {
  EXPECT_NE(HTMLCanvasElement::BrokenCanvas(2.0).first,
            HTMLCanvasElement::BrokenCanvas(1.0).first);
  EXPECT_EQ(HTMLCanvasElement::BrokenCanvas(2.0).second, 2.0);
  EXPECT_EQ(HTMLCanvasElement::BrokenCanvas(1.0).second, 1.0);
}


class HTMLCanvasElementWithTracingTest : public RenderingTest {
 public:
  HTMLCanvasElementWithTracingTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

 protected:
  void TearDown() override {
    RenderingTest::TearDown();
    CanvasRenderingContext::GetCanvasPerformanceMonitor().ResetForTesting();
  }

  base::test::TracingEnvironment tracing_environment_;
};

class HTMLCanvasElementWithTracingSyncTest
    : public HTMLCanvasElementWithTracingTest,
      public testing::WithParamInterface<const char*> {};

INSTANTIATE_TEST_SUITE_P(All,
                         HTMLCanvasElementWithTracingSyncTest,
                         testing::ValuesIn({R"JS(
          let canvas = document.getElementById('canvas');
          let ctx = canvas.getContext('2d');
          ctx.fillText("abc", 0, 10);
          canvas.toDataURL();)JS",
                                            R"JS(
          let canvas = document.getElementById('canvas');
          let ctx = canvas.getContext('2d');
          ctx.fillText("abc", 0, 10);
          ctx.getImageData(0, 0, 10, 10);)JS"}));

TEST_P(HTMLCanvasElementWithTracingSyncTest,
       CanvasReadbackEmitsIdentifiabilityTraces) {
  // Enable script so that the canvas will create a LayoutHTMLCanvas.
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<canvas id='canvas'></canvas>");

  base::test::TestTraceProcessor test_trace_processor;
  test_trace_processor.StartTrace(
      base::test::DefaultTraceConfig(
          "disabled-by-default-identifiability.high_entropy_api", false),
      perfetto::kInProcessBackend);
  auto* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(String(GetParam()));
  GetDocument().body()->appendChild(script);

  absl::Status status = test_trace_processor.StopAndParseTrace();
  ASSERT_TRUE(status.ok()) << status.message();
  std::string query = R"sql(
    SELECT slice.name, args.display_value FROM slice
      LEFT JOIN args USING (arg_set_id)
      WHERE slice.category =
        'disabled-by-default-identifiability.high_entropy_api'
      AND args.key = 'debug.data_url'
  )sql";
  auto result = test_trace_processor.RunQuery(query);
  ASSERT_TRUE(result.has_value()) << result.error();
  EXPECT_THAT(result.value(),
              Contains(ElementsAre(Eq("CanvasReadback"), StartsWith("data:"))));
}

class HTMLCanvasElementWithTracingAsyncTest
    : public HTMLCanvasElementWithTracingTest,
      public testing::WithParamInterface<std::pair<const char*, const char*>> {
};

INSTANTIATE_TEST_SUITE_P(
    All,
    HTMLCanvasElementWithTracingAsyncTest,
    testing::ValuesIn({std::make_pair(
                           R"JS(
          (async () => {
            let canvas = document.getElementById('canvas');
            let ctx = canvas.getContext('2d');
            ctx.fillText("abc", 0, 10);
            await new Promise(resolve => {canvas.toBlob(resolve)});
          })()
         )JS",
                           "HTMLCanvasElement.toBlob"),
                       std::make_pair(
                           R"JS(
          (async () => {
            let offscreen = new OffscreenCanvas(10, 10);
            let ctx = offscreen.getContext('2d');
            ctx.fillText("abc", 0, 10);
            await new Promise(resolve => {
              offscreen.convertToBlob().then(resolve);
            });
          })()
         )JS",
                           "OffscreenCanvas.convertToBlob")}));

class Resolve final : public ThenCallable<IDLAny, Resolve> {
 public:
  explicit Resolve(base::RepeatingClosure callback)
      : callback_(std::move(callback)) {}

  void React(ScriptState*, ScriptValue) { callback_.Run(); }

 private:
  base::RepeatingClosure callback_;
};

TEST_P(HTMLCanvasElementWithTracingAsyncTest,
       CanvasReadbackEmitsIdentifiabilityTraces) {
  // Enable script so that the canvas will create a LayoutHTMLCanvas.
  GetDocument().GetSettings()->SetScriptEnabled(true);

  SetBodyInnerHTML("<canvas id='canvas'></canvas>");

  base::test::TestTraceProcessor test_trace_processor;
  test_trace_processor.StartTrace(
      base::test::DefaultTraceConfig(
          "disabled-by-default-identifiability.high_entropy_api", false),
      perfetto::kInProcessBackend);

  ScriptState* script_state = ToScriptStateForMainWorld(&GetFrame());
  ScriptState::Scope script_state_scope(script_state);

  base::RunLoop run_loop;
  auto* resolve = MakeGarbageCollected<Resolve>(run_loop.QuitClosure());

  ClassicScript* script = ClassicScript::CreateUnspecifiedScript(
      GetParam().first, ScriptSourceLocationType::kUnknown,
      SanitizeScriptErrors::kSanitize);

  ScriptEvaluationResult script_result =
      script->RunScriptOnScriptStateAndReturnValue(script_state);

  auto promise =
      ToResolvedPromise<IDLAny>(script_state, script_result.GetSuccessValue());
  promise.Then(script_state, resolve, resolve);

  // Avoid the NOTREACHED in CanvasPerformanceMonitor::WillProcessTask().
  CanvasRenderingContext::GetCanvasPerformanceMonitor().ResetForTesting();

  run_loop.Run();

  absl::Status status = test_trace_processor.StopAndParseTrace();
  ASSERT_TRUE(status.ok()) << status.message();

  {
    // Check that there is a flow connecting the CanvasReadback traces emitted
    // by CanvasAsyncBlobCreator.
    std::string query = R"sql(
      SELECT s_in.name, s_out.name
        FROM flow
        LEFT JOIN slice AS s_in ON slice_in = s_in.id
        LEFT JOIN slice AS s_out ON slice_out = s_out.id
        WHERE s_in.category =
            'disabled-by-default-identifiability.high_entropy_api'
          AND s_out.category =
            'disabled-by-default-identifiability.high_entropy_api'
    )sql";
    auto result = test_trace_processor.RunQuery(query);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_THAT(result.value(), Contains(ElementsAre(Eq("CanvasReadback"),
                                                     Eq("CanvasReadback")))
                                    .Times(2));
  }

  {
    // Check that it is possible to join the canvas readback data emitted by
    // CanvasAsyncBlobCreator with the HighEntropyJavaScriptAPICall that was
    // responsible for it.
    std::string query = R"sql(
      WITH RECURSIVE canvas_readback AS (
        SELECT slice_out AS flow_start_id,
          args.display_value AS canvas_data
        FROM flow
        INNER JOIN slice ON slice.id = flow.slice_in
        LEFT JOIN args ON slice.arg_set_id = args.arg_set_id
        WHERE
          slice.category =
            'disabled-by-default-identifiability.high_entropy_api'
          AND slice.name = 'CanvasReadback'
          AND args.key = 'debug.data_url'
      ), ancestors AS (
          SELECT slice.id, slice.parent_id
          FROM slice
          INNER JOIN canvas_readback ON slice.id = canvas_readback.flow_start_id
          UNION ALL
          SELECT ancestors.id, slice.parent_id
          FROM slice
          JOIN ancestors ON slice.id = ancestors.parent_id
          WHERE slice.parent_id IS NOT NULL
      ), data_with_ancestors AS (
        SELECT args.display_value, canvas_data FROM canvas_readback
        LEFT JOIN ancestors ON (canvas_readback.flow_start_id = ancestors.id)
        LEFT JOIN slice on (ancestors.parent_id = slice.id)
        LEFT JOIN args ON args.arg_set_id = slice.arg_set_id
        WHERE
          slice.category =
            'disabled-by-default-identifiability.high_entropy_api'
          AND slice.name =  'HighEntropyJavaScriptAPICall'
          AND args.key = 'high_entropy_api.called_api.identifier'
      ) SELECT * FROM data_with_ancestors
    )sql";
    auto result = test_trace_processor.RunQuery(query);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_THAT(result.value(), Contains(ElementsAre(Eq(GetParam().second),
                                                     StartsWith("data:"))));
  }
}

}  // namespace blink

"""

```
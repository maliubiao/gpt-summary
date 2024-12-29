Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding - What is this?**

The first lines are crucial: `"blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d_test.cc"`. This immediately tells us:

* **Location:** It's within the Blink rendering engine, specifically related to canvas functionality.
* **Module:** It's about `OffscreenCanvasRenderingContext2D`.
* **Type:** It's a test file (`_test.cc`).

This sets the stage. We know it's not the core implementation, but a file that verifies the behavior of the `OffscreenCanvasRenderingContext2D` class.

**2. Examining Includes - What dependencies exist?**

The `#include` directives reveal the key players involved:

* **Self:**  `"third_party/blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.h"` - This confirms we're testing the header file of the target class.
* **Testing Frameworks:** `gmock/gmock.h` and `gtest/gtest.h` - Standard C++ testing libraries, indicating this file contains unit tests.
* **Blink Bindings:** Various `v8_` includes (e.g., `v8_binding_for_testing.h`, `v8_image_bitmap_options.h`, etc.) - This signals interactions with JavaScript and the V8 engine. These bindings are how C++ code exposes functionality to JavaScript.
* **Core Blink:**  Includes like `"third_party/blink/renderer/core/html/canvas/image_data.h"` and `"third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"` point to core Blink classes that the `OffscreenCanvasRenderingContext2D` interacts with.
* **Platform Testing:** `"third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"` and `"third_party/blink/renderer/platform/testing/task_environment.h"` are for setting up the testing environment and controlling features.

**3. Analyzing the Code Structure - How is it organized?**

* **Namespaces:** `namespace blink { namespace { ... } }` - Standard C++ namespacing to avoid naming conflicts. The inner unnamed namespace is common in test files for internal helpers.
* **Helper Function:** `GetContext(V8TestingScope& scope, OffscreenCanvas* host)` - This utility function simplifies getting an `OffscreenCanvasRenderingContext2D` instance, making the tests cleaner. It takes an `OffscreenCanvas` as input.
* **TEST Macros:** The core of the file consists of several `TEST(OffscreenCanvas..., ...)` macros. Each `TEST` represents an individual test case. The naming convention of the tests (e.g., `TransferToOffscreenThrowsErrorsProducedByContext`, `UnclosedLayerConvertToBlob`) is highly descriptive and gives strong clues about what each test verifies.

**4. Understanding the Test Logic - What is being tested?**

By examining the content of each `TEST` function, we can determine the functionality being verified:

* **`TransferToOffscreenThrowsErrorsProducedByContext` and `TransferToOffscreenThrowsUnknownErrorAsFallback`:** These tests check how errors during `transferToImageBitmap` are handled, including specific error types and a fallback for unknown errors.
* **`TransferToOffscreenThrowsInLayers`, `UnclosedLayerConvertToBlob`, `UnclosedLayerCreateImageBitmap`, `UnclosedLayerCreatePattern`, `UnclosedLayerDrawImage`, `UnclosedLayerGetImageData`, `UnclosedLayerPutImageData`, `UnclosedLayerTransferToImageBitmap`:** This large group of tests focuses on the behavior of `OffscreenCanvasRenderingContext2D` methods when called *inside* an unclosed layer (using `beginLayer` without a corresponding `endLayer`). They consistently check that these methods throw an `InvalidStateError`. This strongly suggests that certain operations are restricted within layers.
* **`NoCrashOnDocumentShutdown`:** This test is a regression test, ensuring the code doesn't crash during document shutdown when certain methods are called.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This is where the understanding of Blink's role is crucial. `OffscreenCanvas` is a JavaScript API. The tests directly manipulate `OffscreenCanvas` and its 2D rendering context. We can make the following connections:

* **JavaScript API:** The methods being tested (e.g., `transferToImageBitmap`, `convertToBlob`, `createPattern`, `drawImage`, `getImageData`, `putImageData`, `beginLayer`, `endLayer`) are all part of the JavaScript `OffscreenCanvasRenderingContext2D` API.
* **HTML `<canvas>` element:** While this test is for `OffscreenCanvas`, the underlying drawing concepts are shared with the regular `<canvas>` element in HTML. The same drawing methods exist. The key difference is that `OffscreenCanvas` is not directly tied to the DOM and can be used in worker threads.
* **CSS (Indirectly):** CSS styling can affect how content is drawn onto a canvas (e.g., setting colors). While these *specific* tests don't directly test CSS interaction, the broader canvas functionality is influenced by CSS.

**6. Logical Inference and Examples:**

Based on the tests, we can infer the following logic:

* **Layer Restrictions:**  Certain operations that modify the canvas's state or extract data from it (like `transferToImageBitmap`, `convertToBlob`, etc.) are not allowed while a layer is open. This is likely to maintain the integrity of the layering system and prevent unexpected side effects.

**Hypothetical Input and Output (for Layer Restrictions):**

* **Input (JavaScript):**
  ```javascript
  const canvas = new OffscreenCanvas(100, 100);
  const ctx = canvas.getContext('2d');
  ctx.beginLayer();
  // Attempting restricted operations within the layer:
  canvas.transferToImageBitmap(); // Expecting an error
  ctx.getImageData(0, 0, 10, 10); // Expecting an error
  ctx.endLayer();
  ```
* **Output (Observed Behavior):**  The JavaScript code would throw an `InvalidStateError` when `transferToImageBitmap()` and `getImageData()` are called inside the layer.

**7. Common User/Programming Errors:**

The tests highlight a common error:

* **Forgetting to close layers:**  Users might start a layer using `beginLayer()` and then forget to call `endLayer()`. This can lead to unexpected errors when they try to perform operations that are restricted within layers.

**Example of User Error:**

```javascript
const canvas = new OffscreenCanvas(100, 100);
const ctx = canvas.getContext('2d');
ctx.beginLayer();
ctx.fillStyle = 'red';
ctx.fillRect(10, 10, 50, 50);
// Oops! Forgot to call ctx.endLayer();
const imageData = ctx.getImageData(0, 0, 100, 100); // This will likely throw an error in this test scenario.
```

**8. Debugging Clues - How to Reach This Code:**

A developer investigating an issue related to `OffscreenCanvas` and its 2D rendering context might end up looking at this test file in the following ways:

1. **Stack Trace:** If a JavaScript error like `InvalidStateError` occurs related to an `OffscreenCanvas` method, the stack trace might point to the native C++ implementation.
2. **Code Search:** If a developer suspects a bug in how `transferToImageBitmap` or layer handling works, they might search the Chromium codebase for relevant files, including this test file, to understand the expected behavior and find related code.
3. **Bug Reports:**  A bug report describing unexpected behavior with `OffscreenCanvas` might lead a Chromium developer to examine the relevant test files to reproduce the issue and verify the fix.
4. **Code Reviews:** During code reviews of changes related to `OffscreenCanvas`, reviewers might look at these tests to ensure the changes are well-tested and don't introduce regressions.

This detailed thought process allows for a comprehensive understanding of the test file's purpose, its relationship to web technologies, and how it helps ensure the correctness of the `OffscreenCanvasRenderingContext2D` implementation.
这个C++文件 `offscreen_canvas_rendering_context_2d_test.cc` 是 Chromium Blink 引擎中针对 `OffscreenCanvasRenderingContext2D` 类的单元测试文件。 它的主要功能是验证 `OffscreenCanvasRenderingContext2D` 类的各种行为是否符合预期，特别是针对错误处理和特定场景下的功能限制进行测试。

以下是对其功能的详细列举和说明：

**主要功能：**

1. **测试 `transferToImageBitmap` 的错误处理:**
   - 验证当 `transferToImageBitmap` 方法由于上下文内部错误而失败时，是否会抛出正确的 `InvalidStateError` 类型的异常。
   - 验证当 `transferToImageBitmap` 方法由于未知原因失败时，是否会抛出一个 `UnknownError` 类型的回退异常。

2. **测试在 Layer (图层) 中调用特定方法的限制:**
   - 重点测试在 `beginLayer()` 和 `endLayer()` 之间（即在未关闭的 Layer 中）调用某些方法是否会抛出 `InvalidStateError` 异常。 这些方法包括：
     - `TransferToImageBitmap` (自身的方法和 host 对象的方法)
     - `convertToBlob` (host 对象的方法)
     - `createImageBitmap` (通过 `ImageBitmapFactories` 调用)
     - `createPattern`
     - `drawImage`
     - `getImageData`
     - `putImageData`

3. **回归测试:**
   - 包含一个名为 `NoCrashOnDocumentShutdown` 的测试，用于验证在文档关闭时调用 `measureText` 方法不会导致崩溃。这是一个针对特定 bug (crbug.com/1509382) 的回归测试。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接测试的是 Blink 引擎中 `OffscreenCanvasRenderingContext2D` 的 C++ 实现。 然而，`OffscreenCanvasRenderingContext2D` 是一个与 JavaScript 紧密相关的接口，它在 JavaScript 中暴露给开发者，用于在离屏画布上进行 2D 图形绘制。

* **JavaScript:**  JavaScript 代码会调用 `OffscreenCanvasRenderingContext2D` 实例上的方法，例如 `transferToImageBitmap()`, `convertToBlob()`, `beginLayer()`, `endLayer()`, `drawImage()`, `getImageData()`, `putImageData()`, `createPattern()`, `measureText()`, 等等。  这个测试文件验证了这些方法在各种情况下的行为是否符合 JavaScript API 的规范。

   **举例说明:**

   ```javascript
   // JavaScript 代码
   const offscreenCanvas = new OffscreenCanvas(100, 100);
   const ctx = offscreenCanvas.getContext('2d');

   ctx.beginLayer();
   try {
     offscreenCanvas.transferToImageBitmap(); // 在 Layer 中调用，应该抛出异常
   } catch (e) {
     console.error("Caught expected error:", e.name); // e.name 应该是 "InvalidStateError"
   }
   ctx.endLayer();

   offscreenCanvas.transferToImageBitmap().then(bitmap => {
     // 正常调用
     console.log("ImageBitmap created:", bitmap);
   });
   ```

* **HTML:**  `OffscreenCanvas` 与 HTML 中的 `<canvas>` 元素的概念类似，但它不直接附加到 DOM 树上，可以在 Web Workers 等环境中使用。 这个测试文件验证了离屏画布的 2D 渲染上下文的行为。

* **CSS:**  CSS 可以影响网页的视觉呈现，但它与 `OffscreenCanvasRenderingContext2D` 的关系相对间接。CSS 样式不会直接影响离屏画布的内部状态或这些被测试的方法的行为。  然而，如果离屏画布的内容最终被渲染到屏幕上（例如，通过 `transferToImageBitmap` 创建 `ImageBitmap` 并将其绘制到普通的 `<canvas>` 上），那么 CSS 样式会影响最终的显示效果。

**逻辑推理、假设输入与输出：**

大部分测试用例都基于以下逻辑推理：在特定的状态下（例如，在未关闭的 Layer 中），某些操作是不允许的，并且应该抛出特定的异常。

**假设输入与输出示例 (针对 `UnclosedLayerTransferToImageBitmap` 测试):**

* **假设输入 (C++ 测试代码模拟的场景):**
    1. 创建一个 `OffscreenCanvas` 对象。
    2. 获取其 2D 渲染上下文 `OffscreenCanvasRenderingContext2D`。
    3. 调用 `beginLayer()` 方法开启一个新的 Layer。
    4. 尝试调用 `host->transferToImageBitmap()` 方法。

* **预期输出:**
    - `scope.GetExceptionState().CodeAs<DOMExceptionCode>()` 的值应为 `DOMExceptionCode::kInvalidStateError`。 这意味着调用 `transferToImageBitmap` 应该导致一个 `InvalidStateError` 异常被设置。

**用户或编程常见的使用错误：**

这个测试文件揭示了一些用户或编程时可能犯的错误，尤其是在使用 Layer 功能时：

1. **在 Layer 开启后忘记关闭:**  开发者可能调用了 `beginLayer()`，但在执行完需要在 Layer 中进行的操作后，忘记调用 `endLayer()`。 这会导致后续的一些操作（如 `transferToImageBitmap`, `getImageData` 等）抛出异常，因为它们在未关闭的 Layer 中是不允许的。

   **举例说明:**

   ```javascript
   const offscreenCanvas = new OffscreenCanvas(100, 100);
   const ctx = offscreenCanvas.getContext('2d');

   ctx.beginLayer();
   ctx.fillStyle = 'blue';
   ctx.fillRect(10, 10, 50, 50);

   // 错误：忘记调用 ctx.endLayer();

   offscreenCanvas.transferToImageBitmap(); // 这会抛出 InvalidStateError
   ```

2. **在不应该调用的时候调用受限方法:**  开发者可能不理解 Layer 的工作原理，或者没有仔细阅读文档，在 Layer 开启的情况下调用了那些被限制的方法。

**用户操作是如何一步步的到达这里，作为调试线索：**

当开发者在使用 `OffscreenCanvas` 的 2D 渲染上下文时遇到错误，并尝试调试时，可能会逐步深入到这个测试文件：

1. **JavaScript 代码抛出异常:**  开发者编写的 JavaScript 代码在调用 `OffscreenCanvasRenderingContext2D` 的方法时，可能会因为上述的常见错误（例如，在未关闭的 Layer 中调用受限方法）而抛出 `InvalidStateError` 或其他类型的异常。

2. **查看浏览器控制台错误信息:** 浏览器控制台会显示错误信息，包括异常类型和调用堆栈。如果错误与 `OffscreenCanvas` 或其 2D 渲染上下文有关，开发者可能会开始怀疑是 Blink 引擎的实现问题。

3. **搜索相关代码:**  开发者可能会根据错误信息或怀疑的功能点（例如，`transferToImageBitmap`，`beginLayer`）在 Chromium 的源代码中搜索相关的文件。 搜索关键词可能包括 "OffscreenCanvasRenderingContext2D", "transferToImageBitmap", "beginLayer", "InvalidStateError" 等。

4. **找到测试文件:**  搜索结果可能会包含 `offscreen_canvas_rendering_context_2d_test.cc` 这个测试文件。

5. **阅读测试用例:**  开发者阅读测试文件中的测试用例，可以了解 Blink 引擎对 `OffscreenCanvasRenderingContext2D` 的预期行为，以及哪些操作在特定情况下是被禁止的。  例如，看到 `UnclosedLayerTransferToImageBitmap` 测试用例，开发者就能明白在 `beginLayer()` 和 `endLayer()` 之间调用 `transferToImageBitmap` 是不合法的。

6. **理解错误原因:**  通过阅读测试代码和相关注释，开发者可以更好地理解他们遇到的错误的原因，并找到修复自己代码的方法。

总而言之，这个测试文件是 Blink 引擎确保 `OffscreenCanvasRenderingContext2D` 功能正确性的重要组成部分。它可以帮助开发者理解这个 API 的行为和限制，并作为调试的线索，当他们遇到与 `OffscreenCanvas` 相关的错误时，可以用来查找问题的原因。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_bitmap_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_image_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_begin_layer_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_blob_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_imagedata_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/modules/canvas/imagebitmap/image_bitmap_factories.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

OffscreenCanvasRenderingContext2D* GetContext(V8TestingScope& scope,
                                              OffscreenCanvas* host) {
  CanvasRenderingContext* context = host->GetCanvasRenderingContext(
      scope.GetExecutionContext(),
      CanvasRenderingContext::CanvasRenderingAPI::k2D,
      CanvasContextCreationAttributesCore());
  CHECK(context->IsRenderingContext2D());
  return static_cast<OffscreenCanvasRenderingContext2D*>(context);
}

TEST(OffscreenCanvasHostTest,
     TransferToOffscreenThrowsErrorsProducedByContext) {
  test::TaskEnvironment task_environment_;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/1,
                                       /*height=*/1);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  // Make the context implementation of `transferToImageBitmap` fail by doing
  // an invalid operation (call `transferToImageBitmap` inside a layer).
  NonThrowableExceptionState no_exception;
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);
  host->transferToImageBitmap(scope.GetScriptState(),
                              scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
}

TEST(OffscreenCanvasHostTest, TransferToOffscreenThrowsUnknownErrorAsFallback) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  // Make `transferToImageBitmap` fail by creating the canvas that is too big.
  auto* host =
      OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/100000000,
                              /*height=*/100000000);
  // A context must exist for `transferToImageBitmap` to work.
  GetContext(scope, host);

  host->transferToImageBitmap(scope.GetScriptState(),
                              scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kUnknownError);
}

TEST(OffscreenCanvasRenderingContext2DTest, TransferToOffscreenThrowsInLayers) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);
  NonThrowableExceptionState no_exception;
  // `TransferToImageBitmap` shouldn't throw on it's own.
  context->TransferToImageBitmap(scope.GetScriptState(), no_exception);
  // Make sure the exception isn't caused by calling the function twice.
  context->TransferToImageBitmap(scope.GetScriptState(), no_exception);
  // Calling again inside a layer should throw.
  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);
  context->TransferToImageBitmap(scope.GetScriptState(),
                                 scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);
}

// Checks `convertToBlob` throws an exception if called inside a layer.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerConvertToBlob) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  NonThrowableExceptionState no_exception;
  auto* options = ImageEncodeOptions::Create();

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  host->convertToBlob(scope.GetScriptState(), options,
                      scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  host->convertToBlob(scope.GetScriptState(), options, no_exception);
}

// Checks `CreateImageBitmap` throws an exception if called inside a layer.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerCreateImageBitmap) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  NonThrowableExceptionState no_exception;
  auto* image = MakeGarbageCollected<V8ImageBitmapSource>(host);
  auto* options = ImageBitmapOptions::Create();

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  ImageBitmapFactories::CreateImageBitmap(scope.GetScriptState(), image,
                                          options, scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  ImageBitmapFactories::CreateImageBitmap(scope.GetScriptState(), image,
                                          options, no_exception);
}

// Checks `createPattern` throws an exception the source has unclosed layers.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerCreatePattern) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  NonThrowableExceptionState no_exception;
  auto* image = MakeGarbageCollected<V8CanvasImageSource>(host);

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  context->createPattern(image, "repeat", scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  context->createPattern(image, "repeat", no_exception);
}

// Checks `drawImage` throws an exception the source has unclosed layers.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerDrawImage) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  NonThrowableExceptionState no_exception;
  auto* image = MakeGarbageCollected<V8CanvasImageSource>(host);

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  context->drawImage(image, /*x=*/0, /*y=*/0, scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  context->drawImage(image, /*x=*/0, /*y=*/0, no_exception);
}

// Checks `getImageData` throws an exception if called inside a layer.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerGetImageData) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);
  NonThrowableExceptionState no_exception;

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  context->getImageData(/*sx=*/0, /*sy=*/0, /*sw=*/1, /*sh=*/1,
                        scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  context->getImageData(/*sx=*/0, /*sy=*/0, /*sw=*/1, /*sh=*/1, no_exception);
}

// Checks `putImageData` throws an exception if called inside a layer.
TEST(OffscreenCanvasRenderingContext2DTest, UnclosedLayerPutImageData) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);

  NonThrowableExceptionState no_exception;
  ImageData* image_data =
      ImageData::Create(context->Width(), context->Height(), no_exception);

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  context->putImageData(image_data, /*dx=*/0, /*dy=*/0,
                        scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  context->putImageData(image_data, /*dx=*/0, /*dy=*/0, no_exception);
}

// Checks `transferToImageBitmap` throws an exception if called inside a layer.
TEST(OffscreenCanvasRenderingContext2DTest,
     UnclosedLayerTransferToImageBitmap) {
  test::TaskEnvironment task_environment;
  ScopedCanvas2dLayersForTest layer_feature(/*enabled=*/true);
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);
  NonThrowableExceptionState no_exception;

  context->beginLayer(scope.GetScriptState(), BeginLayerOptions::Create(),
                      no_exception);

  // Throws inside layers:
  host->transferToImageBitmap(scope.GetScriptState(),
                              scope.GetExceptionState());
  EXPECT_EQ(scope.GetExceptionState().CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kInvalidStateError);

  context->endLayer(no_exception);

  // Doesn't throw outside layers:
  host->transferToImageBitmap(scope.GetScriptState(), no_exception);
}

// Regression test for https://crbug.com/1509382.
TEST(OffscreenCanvasRenderingContext2DTest, NoCrashOnDocumentShutdown) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* host = OffscreenCanvas::Create(scope.GetScriptState(), /*width=*/10,
                                       /*height=*/10);
  OffscreenCanvasRenderingContext2D* context = GetContext(scope, host);
  context->setFont("12px Ahem");
  scope.GetDocument().Shutdown();
  context->measureText("hello world");
}

}  // namespace
}  // namespace blink

"""

```
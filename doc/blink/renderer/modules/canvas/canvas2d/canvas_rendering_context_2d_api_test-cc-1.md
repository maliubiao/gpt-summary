Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is the second part of a test file for the Canvas 2D API in the Chromium Blink engine.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Functionality:** The code snippet consists of a series of C++ test cases (`TEST_F`) within a larger test suite (`CanvasRenderingContext2DAPITest`). These tests are designed to verify the behavior of specific methods of the `CanvasRenderingContext2D` API.

2. **Categorize the Tests:**  The test names provide clues about the functionality being tested. Looking at the prefixes:
    * `MAYBE_IdentifiabilityStudyDigest_...`:  These tests seem related to a feature for tracking or identifying canvas drawing operations, potentially for privacy or security analysis. The suffixes indicate the specific canvas API methods being tested (`StrokeStyle`, `FillStyle`, `Combo`, `putImageData`, `drawImage`).
    * `Mesh2DVertexBuffer...`, `Mesh2DUVBuffer...`, `Mesh2DIndexBuffer...`, `DrawMesh`: These tests are clearly related to a "Mesh 2D" feature, likely an extension to the standard Canvas 2D API for rendering more complex geometries. They test the creation of vertex buffers, UV coordinate buffers, index buffers, and the `drawMesh` method itself.

3. **Analyze Individual Tests:**
    * **Identifiability Tests:** These tests generally follow a pattern:
        * Set up a canvas context.
        * Call a specific canvas drawing method (e.g., `setStrokeStyle`, `fillText`, `putImageData`, `drawImage`).
        * Assert that the `IdentifiableTextToken().ToUkmMetricValue()` has a specific expected value. This suggests the tests are verifying how different canvas operations contribute to a unique identifier or "digest."
        * Assert the values of `IdentifiabilityEncounteredSkippedOps()`, `IdentifiabilityEncounteredSensitiveOps()`, and `IdentifiabilityEncounteredPartiallyDigestedImage()`. These likely flag whether certain operations were skipped, deemed sensitive, or involved partially processed images in the identifiability mechanism.
    * **Mesh 2D Buffer Tests:** These tests focus on the `createMesh2DVertexBuffer`, `createMesh2DUVBuffer`, and `createMesh2DIndexBuffer` methods. They test various input scenarios, particularly different numbers of elements in the input arrays, and verify if the methods return valid buffer objects or throw exceptions as expected. The `MATCHER_P(Mesh2dBufferIs, matcher, "")` and `ElementsAre` indicate that the content of the created buffers is being checked.
    * **DrawMesh Test:** This test verifies the `drawMesh` method by creating valid vertex, UV, and index buffers and then calling `drawMesh` with these buffers and an image source. It checks if an exception is thrown.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **Canvas API:** The entire test suite directly relates to the Canvas API, which is exposed to JavaScript through the `<canvas>` HTML element. JavaScript code running in a web browser would use methods like `getContext('2d')`, `strokeStyle`, `fillStyle`, `fillText`, `putImageData`, `drawImage`, and potentially the newer mesh drawing methods.
    * **HTML:** The `<canvas>` element in HTML is the starting point for using the Canvas 2D API.
    * **CSS:** While CSS doesn't directly control the drawing operations within the canvas, it can style the `<canvas>` element itself (e.g., size, border).

5. **Consider User/Programming Errors:**
    * **Incorrect Array Sizes:** The Mesh 2D buffer tests specifically highlight a common error: providing arrays with the wrong number of elements (e.g., an odd number of floats for vertex or UV buffers, or a non-multiple of 3 for triangle indices).
    * **Using Undefined Variables:** Although not explicitly shown in *this* code snippet, a common JavaScript error when working with canvas would be using undefined variables or incorrect data types as arguments to canvas methods.

6. **Infer User Actions for Debugging:** To reach this code during debugging, a developer would likely be:
    * **Investigating Canvas Rendering Issues:** If a web page using the canvas is not rendering correctly, developers might step into the browser's rendering engine code.
    * **Debugging Identifiability Features:** If working on the "identifiability study" feature, developers would be examining how canvas operations are tracked.
    * **Developing or Debugging the Mesh 2D API:** Developers working on extending the Canvas API would be directly involved in this code.

7. **Synthesize the Summary:** Combine the observations into a concise summary of the file's purpose, highlighting the key features being tested and their relation to web technologies and potential errors.

8. **Address the "Part 2" Request:** Acknowledge that this is the second part of the file and reiterate the focus of this specific section. Since the previous part wasn't provided, focus on summarizing the functionality present in the given snippet.
这是对 `blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_api_test.cc` 文件的第二部分的功能归纳。

**功能归纳:**

这部分测试文件主要针对 `CanvasRenderingContext2D` API 中与 **canvas 内容的识别性研究 (Identifiability Study)** 以及 **Mesh 2D 特性** 相关的 API 进行测试。

**1. 识别性研究 (Identifiability Study) 相关测试:**

*   **目标:**  验证在 canvas 上进行特定绘图操作后，系统生成的“可识别文本令牌 (IdentifiableTextToken)” 的值是否符合预期。这可能是 Chromium 正在进行的一项研究，旨在了解 canvas 内容的唯一性，可能用于隐私保护或其他目的。
*   **测试内容:**
    *   测试设置不同的 `strokeStyle` (描边颜色) 后，`IdentifiableTextToken` 的值。
    *   测试设置不同的 `fillStyle` (填充颜色) 后，`IdentifiableTextToken` 的值。
    *   测试一系列组合的绘图操作 (例如 `fillText`, `setFont`, `setTextBaseline`, `setTextAlign`, `fillStyle`, 再次 `fillText`) 后，`IdentifiableTextToken` 的值，并检查是否触发了敏感操作的标记。
    *   测试使用 `putImageData` 方法绘制图像数据后，`IdentifiableTextToken` 的值，并检查是否标记了部分处理的图像。
    *   测试使用 `drawImage` 方法绘制图像 (使用 canvas 自身作为图像源) 后，`IdentifiableTextToken` 的值，并检查是否标记了部分处理的图像。
*   **假设输入与输出 (针对 `MAYBE_IdentifiabilityStudyDigest_StrokeStyle`):**
    *   **假设输入:**  在 JavaScript 中，创建一个 canvas 元素，获取 2D 渲染上下文，并设置 `strokeStyle` 为 "blue"。
    *   **预期输出:**  `Context2D()->IdentifiableTextToken().ToUkmMetricValue()` 的值应该等于 `INT64_C(3577524355478740727)`。 `IdentifiabilityEncounteredSkippedOps`, `IdentifiabilityEncounteredSensitiveOps`, 和 `IdentifiabilityEncounteredPartiallyDigestedImage` 应该都为 `false`。

**2. Mesh 2D 特性相关测试:**

*   **目标:** 测试 `CanvasRenderingContext2D` API 中新增的用于创建和绘制 2D 网格 (Mesh 2D) 的相关方法。
*   **测试内容:**
    *   **`createMesh2DVertexBuffer`:** 测试创建顶点缓冲区 (vertex buffer)。测试了不同数量的浮点数输入，验证了正确的输入能创建缓冲区对象，错误的输入 (如奇数个浮点数) 会抛出异常。
    *   **`createMesh2DUVBuffer`:** 测试创建 UV 坐标缓冲区。 类似于顶点缓冲区的测试，验证了正确的输入能创建缓冲区对象，错误的输入会抛出异常。
    *   **`createMesh2DIndexBuffer`:** 测试创建索引缓冲区 (index buffer)。测试了不同数量的无符号短整型输入，验证了正确的输入能创建缓冲区对象，错误的输入 (如少于 3 个索引，或者非三角形数量的索引) 会抛出异常。
    *   **`drawMesh`:** 测试使用创建的顶点缓冲区、UV 坐标缓冲区、索引缓冲区以及图像源来绘制网格。验证了在正确输入的情况下，`drawMesh` 方法不会抛出异常。
*   **假设输入与输出 (针对 `Mesh2DVertexBuffer2Floats`):**
    *   **假设输入:**  在 JavaScript 中，获取 canvas 2D 上下文，并调用 `createMesh2DVertexBuffer` 方法，传入一个包含两个浮点数 `[101, 102]` 的 `Float32Array`。
    *   **预期输出:**  该方法应该返回一个非空的 `Mesh2dBuffer` 对象，其内部缓冲区的数据应该包含一个 `SkPoint` 对象，其 x 值为 101，y 值为 102。

**与 JavaScript, HTML, CSS 的关系:**

*   **JavaScript:**  这些测试直接对应着 JavaScript 中 Canvas 2D API 的方法。例如：
    *   `SetStrokeStyleString(Context2D(), GetScriptState(), "blue");`  对应 JavaScript 中的 `ctx.strokeStyle = 'blue';`
    *   `SetFillStyleString(Context2D(), GetScriptState(), "blue");` 对应 JavaScript 中的 `ctx.fillStyle = 'blue';`
    *   `Context2D()->fillText("Sensitive message", 1.0, 1.0);` 对应 JavaScript 中的 `ctx.fillText('Sensitive message', 1.0, 1.0);`
    *   `Context2D()->putImageData(image_data, /*dx=*/1, /*dy=*/1, exception_state);` 对应 JavaScript 中的 `ctx.putImageData(imageData, 1, 1);`
    *   `Context2D()->drawImage(image_source, /*x=*/1, /*y=*/1, exception_state);` 对应 JavaScript 中的 `ctx.drawImage(imageSource, 1, 1);`
    *   `ctx->createMesh2DVertexBuffer(CreateFloat32Array({0, 0, 100, 0, 100, 100}), exception_state);` 对应 JavaScript 中的 `ctx.createMesh2DVertexBuffer(new Float32Array([0, 0, 100, 0, 100, 100]));`
    *   `ctx->drawMesh(vert_buffer, uv_buffer, index_buffer, image_source, exception_state);` 对应 JavaScript 中的 `ctx.drawMesh(vertexBuffer, uvBuffer, indexBuffer, imageSource);`
*   **HTML:**  所有的 canvas 操作都基于 HTML 的 `<canvas>` 元素。开发者需要在 HTML 中定义一个 `<canvas>` 元素，然后在 JavaScript 中获取其上下文进行绘图。
*   **CSS:** CSS 可以用来设置 `<canvas>` 元素的大小、边框等样式，但不能直接控制 canvas 内部的绘图操作。

**用户或编程常见的使用错误举例:**

*   **Mesh 2D 缓冲区创建时，数组长度不正确:**
    *   **错误代码 (JavaScript):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.createMesh2DVertexBuffer(new Float32Array([1, 2, 3])); // 错误：应该为偶数
        ctx.createMesh2DUVBuffer(new Float32Array([0.1])); // 错误：应该为偶数
        ctx.createMesh2DIndexBuffer(new Uint16Array([0, 1])); // 错误：应该至少为 3
        ctx.createMesh2DIndexBuffer(new Uint16Array([0, 1, 2, 3])); // 错误：应该为 3 的倍数才能构成完整的三角形
        ```
    *   **说明:** 用户在创建 Mesh 2D 的缓冲区时，可能会忘记顶点和 UV 坐标是成对出现的，索引需要至少三个才能构成一个三角形。
*   **向 `fillText` 传递敏感信息:**
    *   **错误代码 (JavaScript):**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        const secret = getUserSecret();
        ctx.fillText(secret, 10, 10);
        ```
    *   **说明:** 这段代码可能触发了识别性研究中的“敏感操作”标记，因为用户将敏感信息直接绘制到了 canvas 上。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发者正在调试一个使用 Canvas 2D API 的网页，并遇到了以下情况：

1. **Canvas 内容渲染异常:**  网页上的 canvas 元素显示的内容不正确，可能是颜色不对、文字显示错误、图片加载失败或者 Mesh 2D 图形没有正确绘制。
2. **怀疑是 API 调用问题:** 开发者可能会怀疑是 JavaScript 代码中对 Canvas 2D API 的调用出现了问题，例如参数错误或者调用顺序不对。
3. **设置断点进行调试:** 开发者可能会在浏览器开发者工具中，在相关的 JavaScript 代码行设置断点，例如在 `fillRect`, `fillText`, `drawImage` 或者 `drawMesh` 等方法调用的地方。
4. **单步执行代码:** 当代码执行到断点时，开发者可以单步执行代码，查看 canvas 上下文的状态，例如 `strokeStyle`, `fillStyle` 的值，或者传递给 `drawMesh` 的缓冲区对象。
5. **进入 Chromium 源代码:** 如果问题仍然无法定位，开发者可能会更深入地查看浏览器引擎的源代码，例如 Chromium 的 Blink 引擎。他们可能会通过调用栈或者搜索相关的 API 方法名 (例如 `fillText` 的 C++ 实现) 来找到 `canvas_rendering_context_2d_api_test.cc` 这个测试文件。
6. **查看测试用例:** 开发者可以查看这个测试文件中的相关测试用例，例如与 `fillText`，`strokeStyle`，`fillStyle` 或 `drawMesh` 相关的测试，来了解这些 API 方法的预期行为和内部实现逻辑。这有助于他们理解自己代码中的错误可能是什么。
7. **分析 Identifiability Study 的影响:**  如果开发者发现一些 canvas 内容被意外地标记为“敏感”，他们可能会查看与 `IdentifiabilityStudyDigest` 相关的测试，了解哪些操作会被认为是敏感的，从而调整他们的绘图策略。
8. **调试 Mesh 2D 相关问题:** 如果是 Mesh 2D 绘制问题，开发者可能会重点关注 `Mesh2DVertexBuffer`, `Mesh2DUVBuffer`, `Mesh2DIndexBuffer`, 和 `drawMesh` 相关的测试用例，检查他们创建缓冲区的方式是否正确，以及 `drawMesh` 的参数是否符合预期。

总而言之，这个测试文件是 Chromium 开发者用来确保 Canvas 2D API 的功能正确性和稳定性的重要组成部分。当用户在使用 Canvas 2D API 遇到问题时，查看相关的测试用例可以提供有价值的调试线索。

Prompt: 
```
这是目录为blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d_api_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
able.
// TODO(crbug.com/1258605): Fix test on Windows and re-enable.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
#define MAYBE_IdentifiabilityStudyDigest_StrokeStyle \
  DISABLED_IdentifiabilityStudyDigest_StrokeStyle
#else
#define MAYBE_IdentifiabilityStudyDigest_StrokeStyle \
  IdentifiabilityStudyDigest_StrokeStyle
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(CanvasRenderingContext2DAPITest,
       MAYBE_IdentifiabilityStudyDigest_StrokeStyle) {
  v8::HandleScope handle_scope(GetIsolate());
  StudyParticipationRaii study_participation_raii;
  CreateContext(kNonOpaque);

  SetStrokeStyleString(Context2D(), GetScriptState(), "blue");
  EXPECT_EQ(INT64_C(3577524355478740727),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());

  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSkippedOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSensitiveOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredPartiallyDigestedImage());
}

// TODO(crbug.com/1239374): Fix test on Android and re-enable.
// TODO(crbug.com/1258605): Fix test on Windows and re-enable.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
#define MAYBE_IdentifiabilityStudyDigest_FillStyle \
  DISABLED_IdentifiabilityStudyDigest_FillStyle
#else
#define MAYBE_IdentifiabilityStudyDigest_FillStyle \
  IdentifiabilityStudyDigest_FillStyle
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(CanvasRenderingContext2DAPITest,
       MAYBE_IdentifiabilityStudyDigest_FillStyle) {
  v8::HandleScope handle_scope(GetIsolate());
  StudyParticipationRaii study_participation_raii;
  CreateContext(kNonOpaque);

  SetFillStyleString(Context2D(), GetScriptState(), "blue");
  EXPECT_EQ(INT64_C(7953663110297373742),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());

  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSkippedOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSensitiveOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredPartiallyDigestedImage());
}

// TODO(crbug.com/1239374): Fix test on Android and re-enable.
// TODO(crbug.com/1258605): Fix test on Windows and re-enable.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
#define MAYBE_IdentifiabilityStudyDigest_Combo \
  DISABLED_IdentifiabilityStudyDigest_Combo
#else
#define MAYBE_IdentifiabilityStudyDigest_Combo IdentifiabilityStudyDigest_Combo
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(CanvasRenderingContext2DAPITest,
       MAYBE_IdentifiabilityStudyDigest_Combo) {
  v8::HandleScope handle_scope(GetIsolate());
  StudyParticipationRaii study_participation_raii;
  CreateContext(kNonOpaque);

  Context2D()->fillText("Sensitive message", 1.0, 1.0);
  EXPECT_EQ(INT64_C(-7525055925911674050),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());
  Context2D()->setFont("Helvetica");
  Context2D()->setTextBaseline("bottom");
  Context2D()->setTextAlign("right");
  SetFillStyleString(Context2D(), GetScriptState(), "red");
  Context2D()->fillText("Bye", 4.0, 3.0);
  EXPECT_EQ(INT64_C(-7631959002534825456),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());

  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSkippedOps());
  EXPECT_TRUE(Context2D()->IdentifiabilityEncounteredSensitiveOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredPartiallyDigestedImage());
}

// TODO(crbug.com/1239374): Fix test on Android L and re-enable.
// TODO(crbug.com/1258605): Fix test on Windows and re-enable.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
#define MAYBE_IdentifiabilityStudyDigest_putImageData \
  DISABLED_IdentifiabilityStudyDigest_putImageData
#else
#define MAYBE_IdentifiabilityStudyDigest_putImageData \
  IdentifiabilityStudyDigest_putImageData
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(CanvasRenderingContext2DAPITest,
       MAYBE_IdentifiabilityStudyDigest_putImageData) {
  StudyParticipationRaii study_participation_raii;
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;

  ImageData* image_data =
      Context2D()->createImageData(/*sw=*/1, /*sh=*/1, exception_state);
  EXPECT_FALSE(exception_state.HadException());
  Context2D()->putImageData(image_data, /*dx=*/1, /*dy=*/1, exception_state);
  EXPECT_EQ(INT64_C(2821795876044191773),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());

  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSkippedOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSensitiveOps());
  EXPECT_TRUE(Context2D()->IdentifiabilityEncounteredPartiallyDigestedImage());
}

// TODO(crbug.com/1239374): Fix test on Android L and re-enable.
// TODO(crbug.com/1258605): Fix test on Windows and re-enable.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_WIN)
#define MAYBE_IdentifiabilityStudyDigest_drawImage \
  DISABLED_IdentifiabilityStudyDigest_drawImage
#else
#define MAYBE_IdentifiabilityStudyDigest_drawImage \
  IdentifiabilityStudyDigest_drawImage
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(CanvasRenderingContext2DAPITest,
       MAYBE_IdentifiabilityStudyDigest_drawImage) {
  StudyParticipationRaii study_participation_raii;
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;

  // We can use our own canvas as the image source!
  auto* image_source =
      MakeGarbageCollected<V8CanvasImageSource>(&CanvasElement());
  Context2D()->drawImage(image_source, /*x=*/1,
                         /*y=*/1, exception_state);
  EXPECT_EQ(INT64_C(-4851825694092845811),
            Context2D()->IdentifiableTextToken().ToUkmMetricValue());

  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSkippedOps());
  EXPECT_FALSE(Context2D()->IdentifiabilityEncounteredSensitiveOps());
  EXPECT_TRUE(Context2D()->IdentifiabilityEncounteredPartiallyDigestedImage());
}

using testing::ElementsAre;
using testing::IsNull;
using testing::Pointee;

MATCHER_P(Mesh2dBufferIs, matcher, "") {
  return ExplainMatchResult(matcher, arg.GetBuffer()->data(), result_listener);
}

NotShared<DOMFloat32Array> CreateFloat32Array(std::vector<float> array) {
  return NotShared<DOMFloat32Array>(DOMFloat32Array::Create(array));
}

NotShared<DOMUint16Array> CreateUint16Array(std::vector<uint16_t> array) {
  return NotShared<DOMUint16Array>(DOMUint16Array::Create(array));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DVertexBuffer0Floats) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DVertexBuffer(CreateFloat32Array({}),
                                                    exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DVertexBuffer1Float) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DVertexBuffer(CreateFloat32Array({101}),
                                                    exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DVertexBuffer2Floats) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DVertexBuffer(
                  CreateFloat32Array({101, 102}), exception_state),
              Pointee(Mesh2dBufferIs(ElementsAre(SkPoint(101, 102)))));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DVertexBuffer3Floats) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DVertexBuffer(
                  CreateFloat32Array({101, 102, 103}), exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DVertexBuffer4Floats) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DVertexBuffer(
                  CreateFloat32Array({101, 102, 103, 104}), exception_state),
              Pointee(Mesh2dBufferIs(
                  ElementsAre(SkPoint(101, 102), SkPoint(103, 104)))));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer0Floats) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DUVBuffer(CreateFloat32Array({}),
                                                exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer1Float) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DUVBuffer(CreateFloat32Array({101}),
                                                exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer2Floats) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DUVBuffer(CreateFloat32Array({101, 102}),
                                                exception_state),
              Pointee(Mesh2dBufferIs(ElementsAre(SkPoint(101, 102)))));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer3Floats) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DUVBuffer(
                  CreateFloat32Array({101, 102, 103}), exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer4Floats) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DUVBuffer(
                  CreateFloat32Array({101, 102, 103, 104}), exception_state),
              Pointee(Mesh2dBufferIs(
                  ElementsAre(SkPoint(101, 102), SkPoint(103, 104)))));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DIndexBuffer0Uints) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(CreateUint16Array({}),
                                                   exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DIndexBuffer1Uint) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(CreateUint16Array({1}),
                                                   exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DIndexBuffer2Uints) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(CreateUint16Array({1, 2}),
                                                   exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer3Uints) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(CreateUint16Array({1, 2, 3}),
                                                   exception_state),
              Pointee(Mesh2dBufferIs(ElementsAre(1, 2, 3))));
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DIndexBuffer4Uints) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(
                  CreateUint16Array({1, 2, 3, 4}), exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DIndexBuffer5Uints) {
  CreateContext(kNonOpaque);
  DummyExceptionStateForTesting exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(
                  CreateUint16Array({1, 2, 3, 4, 5}), exception_state),
              IsNull());
  EXPECT_TRUE(exception_state.HadException());
}

TEST_F(CanvasRenderingContext2DAPITest, Mesh2DUVBuffer6Uints) {
  CreateContext(kNonOpaque);
  NonThrowableExceptionState exception_state;
  EXPECT_THAT(Context2D()->createMesh2DIndexBuffer(
                  CreateUint16Array({1, 2, 3, 4, 5, 6}), exception_state),
              Pointee(Mesh2dBufferIs(ElementsAre(1, 2, 3, 4, 5, 6))));
}

TEST_F(CanvasRenderingContext2DAPITest, DrawMesh) {
  CreateContext(kNonOpaque);
  CanvasRenderingContext2D* ctx = Context2D();
  V8CanvasImageSource* image_source =
      MakeGarbageCollected<V8CanvasImageSource>(&CanvasElement());

  DummyExceptionStateForTesting exception_state;
  const auto* vert_buffer = ctx->createMesh2DVertexBuffer(
      CreateFloat32Array({0, 0, 100, 0, 100, 100}), exception_state);
  ASSERT_NE(vert_buffer, nullptr);

  const auto* uv_buffer = ctx->createMesh2DUVBuffer(
      CreateFloat32Array({0, 0, 1, 0, 1, 1}), exception_state);
  ASSERT_NE(uv_buffer, nullptr);

  const auto* index_buffer = ctx->createMesh2DIndexBuffer(
      CreateUint16Array({0, 1, 2}), exception_state);
  ASSERT_NE(index_buffer, nullptr);

  ASSERT_FALSE(exception_state.HadException());

  // valid call
  ctx->drawMesh(vert_buffer, uv_buffer, index_buffer, image_source,
                exception_state);
  EXPECT_FALSE(exception_state.HadException());
}

}  // namespace blink

"""


```
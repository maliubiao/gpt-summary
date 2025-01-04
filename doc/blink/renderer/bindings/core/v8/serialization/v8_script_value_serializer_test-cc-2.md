Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This code is a test file for the `V8ScriptValueSerializer` and `V8ScriptValueDeserializer` classes in the Chromium Blink engine. These classes are responsible for serializing and deserializing JavaScript values in a way that can be transferred between different contexts (e.g., different web workers or processes).

Here's a breakdown of the thought process to answer the user's request:

1. **Identify the Core Functionality:** The file name `v8_script_value_serializer_test.cc` strongly suggests that this is a test suite for the serializer and deserializer. The code confirms this by using the `TEST` macro, which is a common practice in C++ unit testing frameworks.

2. **Analyze the Test Cases:**  The code is organized into multiple `TEST` blocks. Each test case focuses on a specific aspect of the serialization/deserialization process. Keywords like `RoundTrip`, `Decode`, `Transfer` are good indicators of the types of tests being performed.

3. **Categorize the Test Subjects:** Look for the types of JavaScript values being tested. The test names and the code itself reveal tests for:
    * Basic JavaScript types (implicitly through `RoundTrip`)
    * `ImageData`
    * `ImageBitmap`
    * `OffscreenCanvas`
    * `Blob`
    * `File`
    * `FileList`
    * `DOMException`
    * `ReadableStream`
    * `TransformStream`
    * `FencedFrameConfig`

4. **Understand "RoundTrip" Tests:** Tests with "RoundTrip" generally involve serializing a value and then immediately deserializing it back. This verifies that the serialization process preserves the value's information.

5. **Understand "Decode" Tests:** Tests with "Decode" usually focus on deserialization from a pre-defined byte sequence. These tests are often used to check error handling (e.g., invalid data) or specific deserialization scenarios.

6. **Understand "Transfer" Tests:** Tests with "Transfer" involve serializing a value and transferring ownership (making the original value unusable). This is relevant for transferable objects like `ImageBitmap` and `OffscreenCanvas`.

7. **Identify Interactions with Web Platform Features:**  Note the connection of the tested types to JavaScript, HTML, and CSS.
    * `ImageData`: Directly related to the `<canvas>` element.
    * `ImageBitmap`: Represents an image that can be drawn to a canvas.
    * `OffscreenCanvas`: A canvas that exists outside the DOM.
    * `Blob`: Represents raw data, used in various web APIs (e.g., file uploads, `URL.createObjectURL`).
    * `File`: Represents a file selected by the user or created programmatically.
    * `FileList`: A collection of `File` objects.
    * `DOMException`: Represents errors that occur during DOM operations.
    * `ReadableStream` and `TransformStream`:  APIs for handling streaming data.
    * `FencedFrameConfig`:  Configuration for fenced frames, a privacy-enhancing web technology.

8. **Look for Error Handling:** Pay attention to tests that intentionally use invalid or malformed input to verify that the deserializer handles errors gracefully (often by returning `null`).

9. **Identify Potential User Errors:** Consider how the tested scenarios could relate to common programming mistakes. For example, failing to provide necessary data handles for deserializing `Blob` or `File` objects.

10. **Consider Debugging Context:** Think about how a developer might end up looking at this test file. This is often when investigating serialization/deserialization issues, especially related to data transfer or persistence.

11. **Infer Assumptions and Outputs:** For "Decode" tests, the input is explicitly given as a byte array. The expected output is often that the deserialized value is `null` (indicating an error) or a specific object type.

12. **Synthesize a Summary:** Combine the observations into a concise description of the file's purpose. Highlight the key functionalities tested and their relevance to web technologies. Since this is part 3 of 4, acknowledge that it's focusing on specific types and error conditions.

By following these steps, we can arrive at the detailed explanation provided in the initial good answer, covering the functionality, relationship to web technologies, examples of logical reasoning, common user errors, and debugging context, as well as a concise summary for this specific part of the test file.
好的，让我们来归纳一下这部分代码的功能。

**功能归纳：**

这部分代码主要集中在测试 `V8ScriptValueDeserializer` 在处理特定类型的序列化数据时，尤其是在遇到**格式错误或数据不完整**的情况下的行为。 它测试了反序列化 `ImageData`、`ImageBitmap`、`OffscreenCanvas`、`Blob`、`File` 和 `FileList` 等对象时，各种异常情况的处理，以及成功反序列化的场景。

**更具体的功能点：**

1. **ImageData 反序列化错误处理:**
   - 测试了 `ImageData` 反序列化时，由于像素数据字节数不足、颜色空间数据错误、像素格式数据错误、原始来源信息错误、预乘信息错误以及像素数据大小声明错误等导致的失败情况。
   - 验证了在这些错误情况下，反序列化器是否会返回 `null`。

2. **ImageBitmap 的传输和反序列化:**
   - 测试了 `ImageBitmap` 对象的序列化和反序列化过程（Round Trip），验证了图像数据是否能够正确地传输和恢复。
   - 重点测试了像素数据的完整性，以及传输后原始 `ImageBitmap` 对象是否被中性化（neutered）。

3. **OffscreenCanvas 的传输和反序列化:**
   - 测试了 `OffscreenCanvas` 对象的序列化和反序列化过程，验证了画布的大小和占位符 ID 是否能够正确传输和恢复。
   - 同样测试了传输后原始 `OffscreenCanvas` 对象是否被中性化。

4. **Blob 的反序列化:**
   - 测试了 `Blob` 对象的完整序列化和反序列化过程（Round Trip），验证了 `Blob` 的类型、大小和 UUID 是否能够正确传输和恢复。
   - 专门测试了在没有提供 Blob 数据句柄的情况下反序列化 `Blob` 的情况，验证了会反序列化失败。
   - 测试了通过索引方式序列化和反序列化 `Blob` 的情况，验证了 `Blob` 信息是否能够正确存储和恢复。
   - 测试了反序列化 `Blob` 索引超出范围的情况，验证了会反序列化失败。

5. **File 的反序列化:**
   - 测试了不同类型的 `File` 对象（例如，本地文件、Blob 支持的文件、快照文件）的序列化和反序列化过程。
   - 专门测试了在没有提供 Blob 数据句柄的情况下反序列化 `File` 的情况，验证了会反序列化失败。
   - 测试了通过索引方式序列化和反序列化 `File` 的情况，验证了 `File` 信息是否能够正确存储和恢复。
   - 测试了反序列化 `File` 索引超出范围的情况，验证了会反序列化失败。

6. **FileList 的反序列化:**
   - 测试了 `FileList` 对象的序列化和反序列化过程。
   - 测试了反序列化空 `FileList` 的情况。
   - 测试了反序列化 `FileList` 时长度信息错误的情况。
   - 专门测试了在没有提供 Blob 数据句柄的情况下反序列化 `FileList` 的情况，验证了会反序列化失败。
   - 测试了通过索引方式序列化和反序列化 `FileList` 的情况，验证了 `FileList` 中的 `File` 信息是否能够正确存储和恢复。
   - 测试了反序列化 `FileList` 索引超出范围的情况，验证了会反序列化失败。

7. **其他反序列化测试:**
   - 测试了硬编码的 `null` 值的反序列化。
   - 测试了使用低效版本信封编码的数据的反序列化，验证了兼容性。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

- **JavaScript:**  所有被测试的对象（`ImageData`、`ImageBitmap`、`OffscreenCanvas`、`Blob`、`File`、`FileList`）都是 JavaScript 中可直接操作的对象。序列化和反序列化使得这些对象可以在不同的 JavaScript 上下文（如 Web Worker、Service Worker、不同的浏览上下文）之间传递。
    ```javascript
    // 例如，在主线程中创建一个 ImageBitmap 并发送给 Web Worker
    const imageBitmap = await createImageBitmap(imageElement);
    worker.postMessage({ image: imageBitmap }, [imageBitmap]);

    // 在 Web Worker 中接收并使用 ImageBitmap
    onmessage = (event) => {
      const receivedImageBitmap = event.data.image;
      // 在 OffscreenCanvas 上绘制 receivedImageBitmap
      offscreenCanvasContext.drawImage(receivedImageBitmap, 0, 0);
    };
    ```
- **HTML:**
    - `ImageData` 通常与 `<canvas>` 元素配合使用，用于获取或设置画布上的像素数据。
    - `ImageBitmap` 可以从 `<img>` 元素、`<video>` 元素或 `<canvas>` 元素创建。
    - `OffscreenCanvas` 是一个脱离 DOM 树的画布，可以通过 JavaScript 创建，但最终可能用于渲染到 HTML 页面中。
    - `File` 对象通常来自 `<input type="file">` 元素，代表用户选择的文件。
    - `FileList` 对象是 `<input type="file">` 元素的 `files` 属性，包含了用户选择的所有文件。
- **CSS:**  CSS 本身不直接参与这些对象的序列化和反序列化过程。但是，这些对象最终可能会影响页面的渲染，而渲染又受到 CSS 的控制。例如，通过 `drawImage` 将 `ImageBitmap` 或 `OffscreenCanvas` 的内容绘制到 `<canvas>` 上，而 `<canvas>` 的样式可以通过 CSS 来设置。

**逻辑推理的假设输入与输出：**

以 `ImageData` 反序列化字节数不足的测试为例：

**假设输入 (SerializedScriptValue 的字节流):**

```
{
    0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02,
    0x03, 0x04, 0x01, 0x05, 0x01, 0x00, 0x02, 0x01, 0x11, // 注意这里声明了 0x11 (17) 字节的像素数据
    0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c, 0x94,
    0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c, 0x00, 0x00
}
```
这里声明了 17 字节的像素数据，但实际提供的字节数可能少于 17。

**预期输出:**

`V8ScriptValueDeserializer(...).Deserialize()` 返回一个表示 `null` 的 V8 值。

**用户或编程常见的使用错误及举例说明：**

1. **反序列化 Blob 或 File 时缺少数据句柄:**  这是最常见的错误。如果尝试在没有正确配置 `blob_info` 的情况下反序列化包含 `Blob` 或 `File` 对象的序列化数据，反序列化将会失败。

   ```javascript
   // 错误示例：尝试反序列化包含 Blob 的数据，但没有提供 Blob 数据
   const serializedData = ...; // 包含 Blob 的序列化数据
   const deserializedValue = await new Promise((resolve, reject) => {
     const reader = new FileReader();
     reader.onload = () => {
       try {
         const result = deserialize(reader.result); // 这里可能会失败
         resolve(result);
       } catch (error) {
         reject(error);
       }
     };
     reader.readAsArrayBuffer(serializedData);
   });
   ```

2. **传递不可序列化的对象:**  尝试序列化无法跨上下文传递的对象（例如，直接包含 DOM 节点的对象）会导致错误。

3. **序列化和反序列化的上下文不匹配:**  虽然 V8 的序列化机制设计为跨平台和跨架构，但在某些极端情况下，如果序列化和反序列化的 V8 版本或配置差异过大，可能会导致反序列化失败。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在网页上遇到了一个与 `Blob` 数据传输相关的问题，导致数据丢失或解析错误。以下是可能的步骤：

1. **用户触发了一个操作:** 例如，点击一个按钮，该按钮会从服务器下载一个文件（作为 `Blob`），然后尝试将这个 `Blob` 通过 `postMessage` 发送给一个 Web Worker。
2. **数据序列化:**  当 `postMessage` 被调用时，浏览器会自动对 `Blob` 对象进行序列化，以便跨线程传递。
3. **数据传输:** 序列化后的数据被发送到 Web Worker。
4. **数据反序列化:** 在 Web Worker 中，当接收到消息时，浏览器会对接收到的数据进行反序列化，尝试还原 `Blob` 对象。
5. **反序列化失败 (可能):** 如果在序列化或反序列化过程中出现问题（例如，数据损坏、缺少必要的元数据），反序列化可能会失败，导致在 Web Worker 中接收到的 `Blob` 对象为空或不完整。

作为调试线索，开发者可能会：

- **检查 `postMessage` 的参数:** 确保传递的是正确的 `Blob` 对象。
- **使用浏览器的开发者工具:** 查看 Network 面板确认文件下载是否成功，以及 Console 面板是否有与序列化/反序列化相关的错误信息。
- **单步调试 Web Worker 代码:**  查看接收到的消息数据，确认反序列化后的 `Blob` 对象的状态。
- **查看 Blink 引擎的源代码 (如本文件):** 如果怀疑是浏览器引擎的 Bug 或需要深入了解序列化/反序列化的内部机制，开发者可能会查看 `v8_script_value_serializer_test.cc` 这样的测试文件，了解各种边缘情况和错误处理方式。

**总结这部分代码的功能：**

这部分测试代码专注于验证 Blink 引擎的 `V8ScriptValueDeserializer` 在处理各种类型的序列化数据时，特别是**错误或不完整数据**时的健壮性和正确性。它涵盖了 `ImageData`、`ImageBitmap`、`OffscreenCanvas`、`Blob` 和 `FileList` 等关键 Web API 对象的反序列化测试，包括成功场景和各种异常情况，旨在确保数据在跨上下文传输时的可靠性。它也通过 "RoundTrip" 测试验证了序列化和反序列化的完整性。

Prompt: 
```
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
0d, 0x5c, 0x67, 0x01, 0x03, 0x02,
                         0x03, 0x04, 0x01, 0x05, 0x01, 0x00, 0x02, 0x01, 0x11,
                         0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c, 0x94,
                         0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c, 0x00, 0x00});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Too few bytes declared in pixel data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue({
        0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x03, 0x04,
        0x01, 0x05, 0x01, 0x00, 0x02, 0x01, 0x0f, 0x94, 0x3a, 0x3f, 0x28,
        0x5f, 0x24, 0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
    });
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for color space data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x05, 0x02, 0x03, 0x04, 0x01,
         0x05, 0x01, 0x00, 0x02, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
         0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for pixel format data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x04, 0x04, 0x01,
         0x05, 0x01, 0x00, 0x02, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
         0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for origin clean data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x03, 0x04, 0x02,
         0x05, 0x01, 0x00, 0x02, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
         0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for premultiplied bit.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x03, 0x04, 0x01,
         0x05, 0x02, 0x00, 0x02, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
         0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Wrong size declared in pixel data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x03, 0x04, 0x01,
         0x05, 0x01, 0x00, 0x03, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
         0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense image serialization tag (kImageDataStorageFormatTag).
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x03, 0x00, 0x00,
                         0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
}

TEST(V8ScriptValueSerializerTest, TransferImageBitmap) {
  test::TaskEnvironment task_environment;
  // More thorough tests exist in web_tests/.
  V8TestingScope scope;

  sk_sp<SkSurface> surface =
      SkSurfaces::Raster(SkImageInfo::MakeN32Premul(10, 7));
  surface->getCanvas()->clear(SK_ColorRED);
  sk_sp<SkImage> image = surface->makeImageSnapshot();
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(image));
  ASSERT_TRUE(image_bitmap->BitmapImage());

  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageBitmap>::ToV8(scope.GetScriptState(), image_bitmap);
  Transferables transferables;
  transferables.image_bitmaps.push_back(image_bitmap);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState(), &transferables);
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  ASSERT_TRUE(new_image_bitmap->BitmapImage());
  ASSERT_EQ(gfx::Size(10, 7), new_image_bitmap->Size());

  // Check that the pixel at (3, 3) is red.
  uint8_t pixel[4] = {};
  sk_sp<SkImage> new_image = new_image_bitmap->BitmapImage()
                                 ->PaintImageForCurrentFrame()
                                 .GetSwSkImage();
  ASSERT_TRUE(new_image->readPixels(
      SkImageInfo::Make(1, 1, kRGBA_8888_SkColorType, kPremul_SkAlphaType),
      &pixel, 4, 3, 3));
  ASSERT_THAT(pixel, testing::ElementsAre(255, 0, 0, 255));

  // Check also that the underlying image contents were transferred.
  EXPECT_EQ(image, new_image);
  EXPECT_TRUE(image_bitmap->IsNeutered());
}

TEST(V8ScriptValueSerializerTest, TransferOffscreenCanvas) {
  test::TaskEnvironment task_environment;
  // More exhaustive tests in web_tests/. This is a sanity check.
  V8TestingScope scope;
  OffscreenCanvas* canvas =
      OffscreenCanvas::Create(scope.GetScriptState(), 10, 7);
  canvas->SetPlaceholderCanvasId(519);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<OffscreenCanvas>::ToV8(scope.GetScriptState(), canvas);
  Transferables transferables;
  transferables.offscreen_canvases.push_back(canvas);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState(), &transferables);
  OffscreenCanvas* new_canvas =
      V8OffscreenCanvas::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_canvas, nullptr);
  EXPECT_EQ(gfx::Size(10, 7), new_canvas->Size());
  EXPECT_EQ(519, new_canvas->PlaceholderCanvasId());
  EXPECT_TRUE(canvas->IsNeutered());
  EXPECT_FALSE(new_canvas->IsNeutered());
}

TEST(V8ScriptValueSerializerTest, RoundTripBlob) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  const char kHelloWorld[] = "Hello world!";
  Blob* blob = Blob::Create(
      base::as_bytes(base::span_with_nul_from_cstring(kHelloWorld)),
      "text/plain");
  String uuid = blob->Uuid();
  EXPECT_FALSE(uuid.empty());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<Blob>::ToV8(scope.GetScriptState(), blob);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  Blob* new_blob = V8Blob::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_blob, nullptr);
  EXPECT_EQ("text/plain", new_blob->type());
  EXPECT_EQ(sizeof(kHelloWorld), new_blob->size());
  EXPECT_EQ(uuid, new_blob->Uuid());
}

// Blob deserialization requires blob data handles.
TEST(V8ScriptValueSerializerTest, DecodeBlobWithoutHandles) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x09, 0x3f, 0x00, 0x62, 0x24, 0x64, 0x38, 0x37, 0x35, 0x64,
       0x66, 0x63, 0x32, 0x2d, 0x34, 0x35, 0x30, 0x35, 0x2d, 0x34, 0x36,
       0x31, 0x62, 0x2d, 0x39, 0x38, 0x66, 0x65, 0x2d, 0x30, 0x63, 0x66,
       0x36, 0x63, 0x63, 0x35, 0x65, 0x61, 0x66, 0x34, 0x34, 0x0a, 0x74,
       0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x0c});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, RoundTripBlobIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  const char kHelloWorld[] = "Hello world!";
  Blob* blob = Blob::Create(
      base::as_bytes(base::span_with_nul_from_cstring(kHelloWorld)),
      "text/plain");
  String uuid = blob->Uuid();
  EXPECT_FALSE(uuid.empty());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<Blob>::ToV8(scope.GetScriptState(), blob);
  WebBlobInfoArray blob_info_array;
  v8::Local<v8::Value> result = RoundTrip(
      wrapper, scope, scope.GetExceptionState(), nullptr, &blob_info_array);

  // As before, the resulting blob should be correct.
  Blob* new_blob = V8Blob::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_blob, nullptr);
  EXPECT_EQ("text/plain", new_blob->type());
  EXPECT_EQ(sizeof(kHelloWorld), new_blob->size());
  EXPECT_EQ(uuid, new_blob->Uuid());

  // The blob info array should also contain the blob details since it was
  // serialized by index into this array.
  ASSERT_EQ(1u, blob_info_array.size());
  const WebBlobInfo& info = blob_info_array[0];
  EXPECT_FALSE(info.IsFile());
  EXPECT_EQ(uuid, String(info.Uuid()));
  EXPECT_EQ("text/plain", info.GetType());
  EXPECT_EQ(sizeof(kHelloWorld), static_cast<size_t>(info.size()));
}

TEST(V8ScriptValueSerializerTest, DecodeBlobIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x69, 0x00});
  WebBlobInfoArray blob_info_array;
  blob_info_array.emplace_back(WebBlobInfo::BlobForTesting(
      "d875dfc2-4505-461b-98fe-0cf6cc5eaf44", "text/plain", 12));
  V8ScriptValueDeserializer::Options options;
  options.blob_info = &blob_info_array;
  V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                         options);
  v8::Local<v8::Value> result = deserializer.Deserialize();
  Blob* new_blob = V8Blob::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_blob, nullptr);
  EXPECT_EQ("d875dfc2-4505-461b-98fe-0cf6cc5eaf44", new_blob->Uuid());
  EXPECT_EQ("text/plain", new_blob->type());
  EXPECT_EQ(12u, new_blob->size());
}

TEST(V8ScriptValueSerializerTest, DecodeBlobIndexOutOfRange) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x69, 0x01});
  {
    V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
  {
    WebBlobInfoArray blob_info_array;
    blob_info_array.emplace_back(WebBlobInfo::BlobForTesting(
        "d875dfc2-4505-461b-98fe-0cf6cc5eaf44", "text/plain", 12));
    V8ScriptValueDeserializer::Options options;
    options.blob_info = &blob_info_array;
    V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                           options);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
}

TEST(V8ScriptValueSerializerTest, RoundTripFileNative) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  FileBackedBlobFactoryTestHelper file_factory_helper(
      scope.GetExecutionContext());
  auto* file =
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path");
  file_factory_helper.FlushForTesting();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_TRUE(new_file->HasBackingFile());
  EXPECT_EQ("/native/path", new_file->GetPath());
  EXPECT_TRUE(new_file->FileSystemURL().IsEmpty());
}

TEST(V8ScriptValueSerializerTest, RoundTripFileBackedByBlob) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  const base::Time kModificationTime = base::Time::UnixEpoch();
  scoped_refptr<BlobDataHandle> blob_data_handle = BlobDataHandle::Create();
  auto* file = MakeGarbageCollected<File>("/native/path", kModificationTime,
                                          blob_data_handle);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_FALSE(new_file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(new_file->FileSystemURL().IsEmpty());
}

TEST(V8ScriptValueSerializerTest, RoundTripFileNativeSnapshot) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  FileMetadata metadata;
  metadata.platform_path = "/native/snapshot";
  auto* context = scope.GetExecutionContext();
  FileBackedBlobFactoryTestHelper helper(context);
  File* file = File::CreateForFileSystemFile(context, "name", metadata,
                                             File::kIsUserVisible);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_TRUE(new_file->HasBackingFile());
  EXPECT_EQ("/native/snapshot", new_file->GetPath());
  EXPECT_TRUE(new_file->FileSystemURL().IsEmpty());
}

TEST(V8ScriptValueSerializerTest, RoundTripFileNonNativeSnapshot) {
  test::TaskEnvironment task_environment;
  // Preserving behavior, filesystem URL is not preserved across cloning.
  KURL url("filesystem:http://example.com/isolated/hash/non-native-file");
  V8TestingScope scope;
  FileMetadata metadata;
  metadata.length = 0;
  File* file = File::CreateForFileSystemFile(
      url, metadata, File::kIsUserVisible, BlobDataHandle::Create());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_FALSE(new_file->HasBackingFile());
  EXPECT_TRUE(file->GetPath().empty());
  EXPECT_TRUE(new_file->FileSystemURL().IsEmpty());
}

// Used for checking that times provided are between now and the current time
// when the checker was constructed, according to base::Time::Now.
class TimeIntervalChecker {
 public:
  TimeIntervalChecker() : start_time_(NowInMilliseconds()) {}

  bool WasAliveAt(int64_t time_in_milliseconds) {
    return start_time_ <= time_in_milliseconds &&
           time_in_milliseconds <= NowInMilliseconds();
  }

 private:
  static int64_t NowInMilliseconds() {
    return (base::Time::Now() - base::Time::UnixEpoch()).InMilliseconds();
  }

  const int64_t start_time_;
};

// Blob deserialization requires blob data handles.
TEST(V8ScriptValueSerializerTest, DecodeFileWithoutHandles) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x08, 0x3f, 0x00, 0x66, 0x04, 'p',  'a',  't',  'h',  0x04, 'n',
       'a',  'm',  'e',  0x03, 'r',  'e',  'l',  0x24, 'f',  '4',  'a',  '6',
       'e',  'd',  'd',  '5',  '-',  '6',  '5',  'a',  'd',  '-',  '4',  'd',
       'c',  '3',  '-',  'b',  '6',  '7',  'c',  '-',  'a',  '7',  '7',  '9',
       'c',  '0',  '2',  'f',  '0',  'f',  'a',  '3',  0x0a, 't',  'e',  'x',
       't',  '/',  'p',  'l',  'a',  'i',  'n',  0x01, 0x80, 0x04, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0xd0, 0xbf, 0x01, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, RoundTripFileIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  FileBackedBlobFactoryTestHelper file_factory_helper(
      scope.GetExecutionContext());
  auto* file =
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path");
  file_factory_helper.FlushForTesting();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<File>::ToV8(scope.GetScriptState(), file);
  WebBlobInfoArray blob_info_array;
  v8::Local<v8::Value> result = RoundTrip(
      wrapper, scope, scope.GetExceptionState(), nullptr, &blob_info_array);

  // As above, the resulting blob should be correct.
  // The only users of the 'blob_info_array' version of serialization is
  // IndexedDB, and the full path is not needed for that system - thus it is not
  // sent in the round trip.
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_FALSE(new_file->HasBackingFile());
  EXPECT_EQ("path", new_file->name());
  EXPECT_TRUE(new_file->FileSystemURL().IsEmpty());

  // The blob info array should also contain the details since it was serialized
  // by index into this array.
  ASSERT_EQ(1u, blob_info_array.size());
  const WebBlobInfo& info = blob_info_array[0];
  EXPECT_TRUE(info.IsFile());
  EXPECT_EQ("path", info.FileName());
  EXPECT_EQ(file->Uuid(), String(info.Uuid()));
}

TEST(V8ScriptValueSerializerTest, DecodeFileIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x65, 0x00});
  WebBlobInfoArray blob_info_array;
  blob_info_array.emplace_back(WebBlobInfo::FileForTesting(
      "d875dfc2-4505-461b-98fe-0cf6cc5eaf44", "path", "text/plain"));
  V8ScriptValueDeserializer::Options options;
  options.blob_info = &blob_info_array;
  V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                         options);
  v8::Local<v8::Value> result = deserializer.Deserialize();
  File* new_file = V8File::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file, nullptr);
  EXPECT_EQ("d875dfc2-4505-461b-98fe-0cf6cc5eaf44", new_file->Uuid());
  EXPECT_EQ("text/plain", new_file->type());
  EXPECT_TRUE(new_file->GetPath().empty());
  EXPECT_EQ("path", new_file->name());
}

TEST(V8ScriptValueSerializerTest, DecodeFileIndexOutOfRange) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x65, 0x01});
  {
    V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
  {
    WebBlobInfoArray blob_info_array;
    blob_info_array.emplace_back(WebBlobInfo::FileForTesting(
        "d875dfc2-4505-461b-98fe-0cf6cc5eaf44", "path", "text/plain"));
    V8ScriptValueDeserializer::Options options;
    options.blob_info = &blob_info_array;
    V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                           options);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
}

// Most of the logic for FileList is shared with File, so the tests here are
// fairly basic.

TEST(V8ScriptValueSerializerTest, RoundTripFileList) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  FileBackedBlobFactoryTestHelper file_factory_helper(
      scope.GetExecutionContext());
  auto* file_list = MakeGarbageCollected<FileList>();
  file_list->Append(
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path"));
  file_list->Append(
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path2"));
  file_factory_helper.FlushForTesting();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<FileList>::ToV8(scope.GetScriptState(), file_list);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  FileList* new_file_list = V8FileList::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file_list, nullptr);
  ASSERT_EQ(2u, new_file_list->length());
  EXPECT_EQ("/native/path", new_file_list->item(0)->GetPath());
  EXPECT_EQ("/native/path2", new_file_list->item(1)->GetPath());
}

TEST(V8ScriptValueSerializerTest, DecodeEmptyFileList) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x6c, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  FileList* new_file_list = V8FileList::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file_list, nullptr);
  EXPECT_EQ(0u, new_file_list->length());
}

TEST(V8ScriptValueSerializerTest, DecodeFileListWithInvalidLength) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x6c, 0x01});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

// Blob deserialization requires blob data handles.
TEST(V8ScriptValueSerializerTest, DecodeFileListWithoutHandles) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  TimeIntervalChecker time_interval_checker;
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x08, 0x3f, 0x00, 0x6c, 0x01, 0x04, 'p', 'a',  't',  'h', 0x04,
       'n',  'a',  'm',  'e',  0x03, 'r',  'e',  'l', 0x24, 'f',  '4', 'a',
       '6',  'e',  'd',  'd',  '5',  '-',  '6',  '5', 'a',  'd',  '-', '4',
       'd',  'c',  '3',  '-',  'b',  '6',  '7',  'c', '-',  'a',  '7', '7',
       '9',  'c',  '0',  '2',  'f',  '0',  'f',  'a', '3',  0x0a, 't', 'e',
       'x',  't',  '/',  'p',  'l',  'a',  'i',  'n', 0x00, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, RoundTripFileListIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  FileBackedBlobFactoryTestHelper file_factory_helper(
      scope.GetExecutionContext());
  auto* file_list = MakeGarbageCollected<FileList>();
  file_list->Append(
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path"));
  file_list->Append(
      MakeGarbageCollected<File>(scope.GetExecutionContext(), "/native/path2"));
  file_factory_helper.FlushForTesting();
  v8::Local<v8::Value> wrapper =
      ToV8Traits<FileList>::ToV8(scope.GetScriptState(), file_list);
  WebBlobInfoArray blob_info_array;
  v8::Local<v8::Value> result = RoundTrip(
      wrapper, scope, scope.GetExceptionState(), nullptr, &blob_info_array);

  // FileList should be produced correctly.
  // The only users of the 'blob_info_array' version of serialization is
  // IndexedDB, and the full path is not needed for that system - thus it is not
  // sent in the round trip.
  FileList* new_file_list = V8FileList::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file_list, nullptr);
  ASSERT_EQ(2u, new_file_list->length());
  EXPECT_EQ("path", new_file_list->item(0)->name());
  EXPECT_EQ("path2", new_file_list->item(1)->name());

  // And the blob info array should be populated.
  ASSERT_EQ(2u, blob_info_array.size());
  EXPECT_TRUE(blob_info_array[0].IsFile());
  EXPECT_EQ("path", blob_info_array[0].FileName());
  EXPECT_TRUE(blob_info_array[1].IsFile());
  EXPECT_EQ("path2", blob_info_array[1].FileName());
}

TEST(V8ScriptValueSerializerTest, DecodeEmptyFileListIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4c, 0x00});
  WebBlobInfoArray blob_info_array;
  V8ScriptValueDeserializer::Options options;
  options.blob_info = &blob_info_array;
  V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                         options);
  v8::Local<v8::Value> result = deserializer.Deserialize();
  FileList* new_file_list = V8FileList::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_file_list, nullptr);
  EXPECT_EQ(0u, new_file_list->length());
}

TEST(V8ScriptValueSerializerTest, DecodeFileListIndexWithInvalidLength) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4c, 0x02});
  WebBlobInfoArray blob_info_array;
  V8ScriptValueDeserializer::Options options;
  options.blob_info = &blob_info_array;
  V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                         options);
  v8::Local<v8::Value> result = deserializer.Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, DecodeFileListIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4c, 0x01, 0x00, 0x00});
  WebBlobInfoArray blob_info_array;
  blob_info_array.emplace_back(WebBlobInfo::FileForTesting(
      "d875dfc2-4505-461b-98fe-0cf6cc5eaf44", "name", "text/plain"));
  V8ScriptValueDeserializer::Options options;
  options.blob_info = &blob_info_array;
  V8ScriptValueDeserializer deserializer(scope.GetScriptState(), input,
                                         options);
  v8::Local<v8::Value> result = deserializer.Deserialize();
  FileList* new_file_list = V8FileList::ToWrappable(scope.GetIsolate(), result);
  EXPECT_EQ(1u, new_file_list->length());
  File* new_file = new_file_list->item(0);
  EXPECT_TRUE(new_file->GetPath().empty());
  EXPECT_EQ("name", new_file->name());
  EXPECT_EQ("d875dfc2-4505-461b-98fe-0cf6cc5eaf44", new_file->Uuid());
  EXPECT_EQ("text/plain", new_file->type());
}

TEST(V8ScriptValueSerializerTest, DecodeHardcodedNullValue) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  EXPECT_TRUE(V8ScriptValueDeserializer(scope.GetScriptState(),
                                        SerializedScriptValue::NullValue())
                  .Deserialize()
                  ->IsNull());
}

// This is not the most efficient way to write a small version, but it's
// technically admissible. We should handle this in a consistent way to avoid
// DCHECK failure. Thus this is "true" encoded slightly strangely.
TEST(V8ScriptValueSerializerTest, DecodeWithInefficientVersionEnvelope) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x90, 0x00, 0xff, 0x09, 0x54});
  EXPECT_TRUE(
      V8ScriptValueDeserializer(scope.GetScriptState(), std::move(input))
          .Deserialize()
          ->IsTrue());
}

// Sanity check for transferring ReadableStreams. This is mostly tested via
// web tests.
TEST(V8ScriptValueSerializerTest, RoundTripReadableStream) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* isolate = scope.GetIsolate();
  auto* script_state = scope.GetScriptState();

  auto* rs = ReadableStream::Create(script_state, ASSERT_NO_EXCEPTION);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<ReadableStream>::ToV8(scope.GetScriptState(), rs);
  HeapVector<ScriptValue> transferable_array = {ScriptValue(isolate, wrapper)};
  Transferables transferables;
  ASSERT_TRUE(SerializedScriptValue::ExtractTransferables(
      isolate, transferable_array, transferables, ASSERT_NO_EXCEPTION));
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, ASSERT_NO_EXCEPTION, &transferables);
  EXPECT_TRUE(result->IsObject());
  ReadableStream* transferred = V8ReadableStream::ToWrappable(isolate, result);
  ASSERT_NE(transferred, nullptr);
  EXPECT_NE(rs, transferred);
  EXPECT_TRUE(rs->locked());
  EXPECT_FALSE(transferred->locked());
}

TEST(V8ScriptValueSerializerTest, TransformStreamIntegerOverflow) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  auto* isolate = scope.GetIsolate();
  auto* script_state = scope.GetScriptState();

  // Create a real SerializedScriptValue so that the MessagePorts are set up
  // properly.
  auto* ts = TransformStream::Create(script_state, ASSERT_NO_EXCEPTION);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<TransformStream>::ToV8(scope.GetScriptState(), ts);
  HeapVector<ScriptValue> transferable_array = {ScriptValue(isolate, wrapper)};
  Transferables transferables;
  ASSERT_TRUE(SerializedScriptValue::ExtractTransferables(
      isolate, transferable_array, transferables, ASSERT_NO_EXCEPTION));

  // Extract message ports and disentangle them.
  Vector<MessagePortChannel> channels = MessagePort::DisentanglePorts(
      scope.GetExecutionContext(), transferables.message_ports,
      ASSERT_NO_EXCEPTION);

  V8ScriptValueSerializer::Options serialize_options;
  serialize_options.transferables = &transferables;
  V8ScriptValueSerializer serializer(script_state, serialize_options);
  scoped_refptr<SerializedScriptValue> serialized_script_value =
      serializer.Serialize(wrapper, ASSERT_NO_EXCEPTION);
  ASSERT_TRUE(serialized_script_value);

  // Now create a corrupted SerializedScriptValue using the same message ports.
  // The final 5 bytes is the offset of the two message ports inside the
  // transferred message port array. In order to trigger integer overflow this
  // is set to 0xffffffff, encoded as a varint.
  uint8_t serialized_value[] = {0xff, 0x14, 0xff, 0x0d, 0x5c, 0x6d,
                                0xff, 0xff, 0xff, 0xff, 0x0f};

  auto corrupted_serialized_script_value =
      SerializedScriptValue::Create(serialized_value);
  corrupted_serialized_script_value->GetStreams() =
      std::move(serialized_script_value->GetStreams());

  // Entangle the message ports.
  MessagePortArray* transferred_message_ports = MessagePort::EntanglePorts(
      *scope.GetExecutionContext(), std::move(channels));

  UnpackedSerializedScriptValue* unpacked = SerializedScriptValue::Unpack(
      std::move(corrupted_serialized_script_value));
  V8ScriptValueDeserializer::Options deserialize_options;
  deserialize_options.message_ports = transferred_message_ports;
  V8ScriptValueDeserializer deserializer(script_state, unpacked,
                                         deserialize_options);
  // If this doesn't crash then the test succeeded.
  v8::Local<v8::Value> result = deserializer.Deserialize();

  // Deserialization should have failed.
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, RoundTripDOMException) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  DOMException* exception =
      DOMException::Create("message", "InvalidStateError");
  v8::Local<v8::Value> wrapper =
      ToV8Traits<DOMException>::ToV8(scope.GetScriptState(), exception);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  DOMException* new_exception =
      V8DOMException::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_exception, nullptr);
  EXPECT_NE(exception, new_exception);
  EXPECT_EQ(exception->code(), new_exception->code());
  EXPECT_EQ(exception->name(), new_exception->name());
  EXPECT_EQ(exception->message(), new_exception->message());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMExceptionWithInvalidNameString) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x13, 0xff, 0x0d, 0x5c, 0x78, 0x01, 0xff, 0x00, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, NoSharedValueConveyor) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x14, 0xff, 0x0f, 'p', 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(scope.GetScriptState(), input).Deserialize();
  EXPECT_TRUE(result->IsNull());
}

TEST(V8ScriptValueSerializerTest, CanDeserializeIn_OldValues) {
  test::TaskEnvironment task_environment;
  // This is `true` serialized in version 9. It should still return true from
  // CanDeserializeIn.
  V8TestingScope scope;
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 'T', 0x00});
  EXPECT_TRUE(input->CanDeserializeIn(scope.GetExecutionContext()));
}

TEST(V8ScriptValueSerializerTest, RoundTripFencedFrameConfig) {
  test::TaskEnvironment task_environment;
  ScopedFencedFramesForTest fenced_frames(true);
  V8TestingScope scope;
  FencedFrameConfig* config = FencedFrameConfig::Create(
      KURL("https://example.com"), "some shared storage context",
      KURL("urn:uuid:37665e6f-f3fd-4393-8429-719d02843a54"), gfx::Size(64, 48),
      gfx::Size(32, 16), FencedFrameConfig::AttributeVisibility::kOpaque, true);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<FencedFrameConfig>::ToV8(scope.GetScriptState(), config);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  FencedFrameConfig* new_config =
      V8FencedFrameConfig::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_config, nullptr);
  EXPECT_NE(config, new_config);
"""


```
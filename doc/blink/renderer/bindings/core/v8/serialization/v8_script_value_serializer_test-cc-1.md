Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the Chromium Blink engine. The file is located at `blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc`.

Based on the test names and the code, the snippet focuses on testing the serialization and deserialization of various JavaScript objects using the `V8ScriptValueSerializer` and `V8ScriptValueDeserializer`. It specifically tests:

- `DOMMatrix` and `DOMMatrixReadOnly`
- `ImageData` (including cases with and without color space information, and detached data)
- `MessagePort` (including transfer and non-transfer scenarios)
- `MojoHandle` (including transfer and non-transfer scenarios)
- `ImageBitmap` (including cases with and without color space information, and different EXIF orientations)

The tests cover both successful serialization/deserialization (round-trip tests) and cases where deserialization should fail (e.g., invalid data or detached objects). It also includes tests for backward compatibility with older serialization formats.

Therefore, the core function of this part of the test file is to verify the correctness of the `V8ScriptValueSerializer` and `V8ScriptValueDeserializer` for specific types of objects.
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc的chromium blink引擎源代码文件的第2部分，主要功能是测试 `V8ScriptValueSerializer` 和 `V8ScriptValueDeserializer` 对于特定类型的 JavaScript 对象的序列化和反序列化功能。

**具体功能归纳：**

* **测试 `DOMMatrix` 和 `DOMMatrixReadOnly` 的序列化和反序列化:**
    * 验证 `DOMMatrix` 对象在序列化和反序列化后，其属性值是否保持不变。
    * 验证 `DOMMatrixReadOnly` 对象在反序列化后，其属性值是否与预期的值一致。
* **测试 `ImageData` 对象的序列化和反序列化:**
    * 验证 `ImageData` 对象在序列化和反序列化后，其尺寸和像素数据是否保持不变。
    * 测试处理已分离的 `ImageData` 对象的情况，预期反序列化会失败。
    * 测试带有色彩空间信息的 `ImageData` 对象的序列化和反序列化，验证色彩空间信息是否被正确保留。
    * 测试解码旧版本的 `ImageData` 序列化数据，以保证向后兼容性。
* **测试 `MessagePort` 对象的序列化和反序列化:**
    * 验证 `MessagePort` 对象作为可转移对象进行序列化和反序列化后，其内部状态（例如，是否已连接）是否正确。
    * 测试尝试序列化已中立化 (neutered) 的 `MessagePort` 对象的情况，预期会抛出 `DataCloneError` 异常。
    * 测试尝试序列化未作为可转移对象传递的 `MessagePort` 对象的情况，预期会抛出 `DataCloneError` 异常。
    * 测试反序列化时提供的 `MessagePort` 索引超出范围的情况，预期反序列化会失败。
* **测试 `MojoHandle` 对象的序列化和反序列化:**
    * 验证 `MojoHandle` 对象作为可转移对象进行序列化和反序列化后，其内部句柄是否被正确转移。
    * 测试尝试序列化未作为可转移对象传递的 `MojoHandle` 对象的情况，预期会抛出 `DataCloneError` 异常。
* **测试 `ImageBitmap` 对象的序列化和反序列化:**
    * 验证 `ImageBitmap` 对象在序列化和反序列化后，其尺寸和像素数据是否保持不变。
    * 测试带有 EXIF 图像方向信息的 `ImageBitmap` 对象的序列化和反序列化，验证方向信息是否被正确保留。
    * 测试带有色彩空间信息的 `ImageBitmap` 对象的序列化和反序列化，验证色彩空间信息是否被正确保留。
    * 测试解码旧版本的 `ImageBitmap` 序列化数据，以保证向后兼容性。
    * 测试反序列化无效的 `ImageBitmap` 序列化数据的情况，预期反序列化会失败。

**与 JavaScript, HTML, CSS 的功能关系举例说明：**

* **JavaScript 和 `DOMMatrix`/`DOMMatrixReadOnly`:**  JavaScript 代码可以使用 `DOMMatrix` 接口创建和操作 2D 或 3D 变换矩阵。例如，可以使用 `DOMMatrix` 来修改元素的 `transform` CSS 属性。这个测试验证了在某些场景下（例如使用 `postMessage` 传递数据），这些矩阵对象可以被正确地序列化和反序列化。

   ```javascript
   // JavaScript 示例
   let matrix = new DOMMatrix([1, 0, 0, 1, 10, 20]); // 创建一个 2D 变换矩阵
   element.style.transform = matrix.toString(); // 将矩阵应用于元素的 transform 属性

   // 假设通过 postMessage 发送 matrix
   postMessage(matrix);
   ```

* **JavaScript 和 `ImageData`:** JavaScript 可以使用 `ImageData` 接口来操作画布 (Canvas) 上的像素数据。例如，可以获取或设置 Canvas 上特定区域的像素颜色。此测试确保了 `ImageData` 对象的内容可以在不同的上下文之间传递和恢复。

   ```javascript
   // JavaScript 示例
   const canvas = document.getElementById('myCanvas');
   const ctx = canvas.getContext('2d');
   const imageData = ctx.getImageData(0, 0, 100, 100); // 获取 Canvas 上的像素数据

   // 假设通过 postMessage 发送 imageData
   postMessage(imageData);
   ```

* **JavaScript 和 `MessagePort`:** `MessagePort` 用于实现 Web Workers 或 iframe 之间的异步通信。这个测试确保了 `MessagePort` 对象可以作为可转移对象进行传递，以便在不同的执行上下文中建立通信通道。

   ```javascript
   // JavaScript 示例 (在 Worker 中)
   onmessage = function(e) {
     const port = e.ports[0]; // 接收传递过来的 MessagePort
     port.postMessage('Hello from worker!');
   }

   // JavaScript 示例 (在主线程中)
   const worker = new Worker('worker.js');
   const channel = new MessageChannel();
   worker.postMessage('Send me a port!', [channel.port2]);
   channel.port1.onmessage = function(e) {
     console.log('Message received:', e.data);
   }
   ```

* **JavaScript 和 `ImageBitmap`:** `ImageBitmap` 表示解码后的图像数据，可以用于在 Canvas 上高效地绘制图像。此测试验证了 `ImageBitmap` 对象可以通过序列化和反序列化在不同的 Web 环境中共享。

   ```javascript
   // JavaScript 示例
   const image = new Image();
   image.src = 'image.png';
   image.onload = async () => {
     const bitmap = await createImageBitmap(image);
     // 假设通过 postMessage 发送 bitmap
     postMessage(bitmap, [bitmap]); // 注意 ImageBitmap 是可转移对象
   };
   ```

**逻辑推理的假设输入与输出：**

**假设输入（`DecodeDOMMatrixReadOnly` 测试）：**

```
SerializedValue({
    0xff, 0x11, 0xff, 0x0d, 0x5c, 0x55, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
    0xf1, 0x3f, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xf3, 0x3f, 0xcd, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xf4, 0x3f, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0xf6, 0x3f, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x40, 0x9a, 0x99,
    0x99, 0x99, 0x99, 0x99, 0x01, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x02, 0x40, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x03, 0x40, 0xcd, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0x08, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
    0x09, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0a, 0x40, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x0b, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x10, 0x40, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x11, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
    0x11, 0x40,
});
```

**预期输出：**

一个 `DOMMatrixReadOnly` 对象，其属性值为：

```
EXPECT_FALSE(matrix->is2D());
EXPECT_EQ(1.1, matrix->m11());
EXPECT_EQ(1.2, matrix->m12());
EXPECT_EQ(1.3, matrix->m13());
EXPECT_EQ(1.4, matrix->m14());
EXPECT_EQ(2.1, matrix->m21());
EXPECT_EQ(2.2, matrix->m22());
EXPECT_EQ(2.3, matrix->m23());
EXPECT_EQ(2.4, matrix->m24());
EXPECT_EQ(3.1, matrix->m31());
EXPECT_EQ(3.2, matrix->m32());
EXPECT_EQ(3.3, matrix->m33());
EXPECT_EQ(3.4, matrix->m34());
EXPECT_EQ(4.1, matrix->m41());
EXPECT_EQ(4.2, matrix->m42());
EXPECT_EQ(4.3, matrix->m43());
EXPECT_EQ(4.4, matrix->m44());
```

**用户或编程常见的使用错误举例说明：**

* **尝试在不支持结构化克隆的环境中传递不可序列化的对象:**  例如，尝试在不支持结构化克隆的旧版浏览器中使用 `postMessage` 传递一个包含循环引用的对象。这将导致数据丢失或错误。
* **忘记将可转移对象标记为可转移:** 当使用 `postMessage` 传递 `ArrayBuffer`，`MessagePort` 或 `ImageBitmap` 等可转移对象时，必须在 `postMessage` 的第二个参数中指定这些对象，否则会进行复制而不是转移，这可能会导致性能问题或意外行为。

   ```javascript
   // 错误示例 - 没有将 ArrayBuffer 标记为可转移
   const buffer = new ArrayBuffer(1024);
   worker.postMessage(buffer); // 这里会进行复制

   // 正确示例
   const buffer = new ArrayBuffer(1024);
   worker.postMessage(buffer, [buffer]); // 这里会进行转移
   ```

* **在反序列化时假设数据格式始终不变:**  如果发送方使用了新版本的序列化器，而接收方使用的是旧版本的反序列化器，则可能会遇到兼容性问题。Chromium 的测试中包含了对旧版本数据的解码测试，以避免此类问题。
* **错误地处理 `DataCloneError` 异常:** 当尝试序列化无法克隆的对象时（例如，未转移的 `MessagePort`），会抛出 `DataCloneError` 异常。开发者需要正确地捕获和处理此异常，以避免程序崩溃。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在网页上进行以下操作：

1. **用户在一个标签页 (Tab A) 的 Canvas 上绘制了一些图形。** 这会导致 `ImageData` 对象的创建和修改。
2. **用户点击了一个按钮，该按钮会创建一个新的标签页 (Tab B)。**
3. **Tab A 中的 JavaScript 代码获取了 Canvas 的 `ImageData` 对象。**
4. **Tab A 中的 JavaScript 代码使用 `postMessage` API 将 `ImageData` 对象发送到 Tab B。**  这时，`V8ScriptValueSerializer` 会被调用来序列化 `ImageData` 对象。
5. **Tab B 中的 JavaScript 代码接收到消息。** `V8ScriptValueDeserializer` 会被调用来反序列化接收到的数据，其中包括 `ImageData` 对象。

如果在反序列化过程中出现问题，调试人员可以检查以下内容：

* **发送方 (Tab A) 的序列化过程:** 检查 `V8ScriptValueSerializer` 是否正确地将 `ImageData` 对象的尺寸和像素数据编码到序列化数据中。
* **接收方 (Tab B) 的反序列化过程:** 检查 `V8ScriptValueDeserializer` 是否能够正确地解析序列化数据，并创建出与原始 `ImageData` 对象相同的对象。
* **序列化数据的格式:** 如果反序列化失败，可以检查实际传输的序列化数据，看是否与预期的格式一致。测试文件中包含了用于解码特定格式数据的测试用例，可以作为参考。
* **版本兼容性:** 如果发送方和接收方运行在不同版本的浏览器上，可能需要检查序列化格式是否发生了变化，以及是否需要进行兼容性处理。

这个测试文件中的用例涵盖了各种 `ImageData` 序列化和反序列化的场景，包括不同版本的数据格式。如果用户在跨标签页传递 `ImageData` 时遇到问题，可以参考这些测试用例来分析问题的根源。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/serialization/v8_script_value_serializer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
_matrix->is2D());
  EXPECT_EQ(matrix->m11(), new_matrix->m11());
  EXPECT_EQ(matrix->m12(), new_matrix->m12());
  EXPECT_EQ(matrix->m13(), new_matrix->m13());
  EXPECT_EQ(matrix->m14(), new_matrix->m14());
  EXPECT_EQ(matrix->m21(), new_matrix->m21());
  EXPECT_EQ(matrix->m22(), new_matrix->m22());
  EXPECT_EQ(matrix->m23(), new_matrix->m23());
  EXPECT_EQ(matrix->m24(), new_matrix->m24());
  EXPECT_EQ(matrix->m31(), new_matrix->m31());
  EXPECT_EQ(matrix->m32(), new_matrix->m32());
  EXPECT_EQ(matrix->m33(), new_matrix->m33());
  EXPECT_EQ(matrix->m34(), new_matrix->m34());
  EXPECT_EQ(matrix->m41(), new_matrix->m41());
  EXPECT_EQ(matrix->m42(), new_matrix->m42());
  EXPECT_EQ(matrix->m43(), new_matrix->m43());
  EXPECT_EQ(matrix->m44(), new_matrix->m44());
}

TEST(V8ScriptValueSerializerTest, DecodeDOMMatrixReadOnly) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff, 0x11, 0xff, 0x0d, 0x5c, 0x55, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0xf1, 0x3f, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0xf3, 0x3f, 0xcd, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0xf4, 0x3f, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0xf6, 0x3f, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x40, 0x9a, 0x99,
      0x99, 0x99, 0x99, 0x99, 0x01, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x02, 0x40, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x03, 0x40, 0xcd, 0xcc,
      0xcc, 0xcc, 0xcc, 0xcc, 0x08, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0x09, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x0a, 0x40, 0x33, 0x33,
      0x33, 0x33, 0x33, 0x33, 0x0b, 0x40, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
      0x10, 0x40, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x40, 0x33, 0x33,
      0x33, 0x33, 0x33, 0x33, 0x11, 0x40, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99,
      0x11, 0x40,

  });
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  DOMMatrixReadOnly* matrix =
      V8DOMMatrixReadOnly::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(matrix, nullptr);
  EXPECT_FALSE(matrix->is2D());
  EXPECT_EQ(1.1, matrix->m11());
  EXPECT_EQ(1.2, matrix->m12());
  EXPECT_EQ(1.3, matrix->m13());
  EXPECT_EQ(1.4, matrix->m14());
  EXPECT_EQ(2.1, matrix->m21());
  EXPECT_EQ(2.2, matrix->m22());
  EXPECT_EQ(2.3, matrix->m23());
  EXPECT_EQ(2.4, matrix->m24());
  EXPECT_EQ(3.1, matrix->m31());
  EXPECT_EQ(3.2, matrix->m32());
  EXPECT_EQ(3.3, matrix->m33());
  EXPECT_EQ(3.4, matrix->m34());
  EXPECT_EQ(4.1, matrix->m41());
  EXPECT_EQ(4.2, matrix->m42());
  EXPECT_EQ(4.3, matrix->m43());
  EXPECT_EQ(4.4, matrix->m44());
}

TEST(V8ScriptValueSerializerTest, RoundTripImageData) {
  test::TaskEnvironment task_environment;
  // ImageData objects should serialize and deserialize correctly.
  V8TestingScope scope;
  ImageData* image_data = ImageData::ValidateAndCreate(
      2, 1, std::nullopt, nullptr, ImageData::ValidateAndCreateParams(),
      ASSERT_NO_EXCEPTION);
  SkPixmap pm = image_data->GetSkPixmap();
  pm.writable_addr32(0, 0)[0] = 200u;
  pm.writable_addr32(1, 0)[0] = 100u;
  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageData>::ToV8(scope.GetScriptState(), image_data);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  ImageData* new_image_data =
      V8ImageData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_data, nullptr);
  EXPECT_NE(image_data, new_image_data);
  EXPECT_EQ(image_data->Size(), new_image_data->Size());
  SkPixmap new_pm = new_image_data->GetSkPixmap();
  EXPECT_EQ(200u, new_pm.addr32(0, 0)[0]);
  EXPECT_EQ(100u, new_pm.addr32(1, 0)[0]);
}

TEST(V8ScriptValueSerializerTest, RoundTripDetachedImageData) {
  test::TaskEnvironment task_environment;
  // If an ImageData is detached, it can be serialized, but will fail when being
  // deserialized.
  V8TestingScope scope;
  ImageData* image_data = ImageData::ValidateAndCreate(
      2, 1, std::nullopt, nullptr, ImageData::ValidateAndCreateParams(),
      ASSERT_NO_EXCEPTION);
  SkPixmap pm = image_data->GetSkPixmap();
  pm.writable_addr32(0, 0)[0] = 200u;
  image_data->data()->GetAsUint8ClampedArray()->BufferBase()->Detach();

  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageData>::ToV8(scope.GetScriptState(), image_data);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  EXPECT_FALSE(V8ImageData::HasInstance(scope.GetIsolate(), result));
}

TEST(V8ScriptValueSerializerTest, RoundTripImageDataWithColorSpaceInfo) {
  test::TaskEnvironment task_environment;
  // ImageData objects with color space information should serialize and
  // deserialize correctly.
  V8TestingScope scope;
  ImageDataSettings* image_data_settings = ImageDataSettings::Create();
  image_data_settings->setColorSpace("display-p3");
  image_data_settings->setStorageFormat("float32");
  ImageData* image_data = ImageData::ValidateAndCreate(
      2, 1, std::nullopt, image_data_settings,
      ImageData::ValidateAndCreateParams(), ASSERT_NO_EXCEPTION);
  SkPixmap pm = image_data->GetSkPixmap();
  EXPECT_EQ(kRGBA_F32_SkColorType, pm.info().colorType());
  static_cast<float*>(pm.writable_addr(0, 0))[0] = 200.f;

  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageData>::ToV8(scope.GetScriptState(), image_data);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  ImageData* new_image_data =
      V8ImageData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_data, nullptr);
  EXPECT_NE(image_data, new_image_data);
  EXPECT_EQ(image_data->Size(), new_image_data->Size());
  ImageDataSettings* new_image_data_settings = new_image_data->getSettings();
  EXPECT_EQ("display-p3", new_image_data_settings->colorSpace());
  EXPECT_EQ("float32", new_image_data_settings->storageFormat());
  SkPixmap new_pm = new_image_data->GetSkPixmap();
  EXPECT_EQ(kRGBA_F32_SkColorType, new_pm.info().colorType());
  EXPECT_EQ(200.f, reinterpret_cast<const float*>(new_pm.addr(0, 0))[0]);
}

TEST(V8ScriptValueSerializerTest, DecodeImageDataV9) {
  test::TaskEnvironment task_environment;
  // Backward compatibility with existing serialized ImageData objects must be
  // maintained. Add more cases if the format changes; don't remove tests for
  // old versions.
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x23, 0x02, 0x01, 0x08, 0xc8,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageData* new_image_data =
      V8ImageData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_data, nullptr);
  EXPECT_EQ(gfx::Size(2, 1), new_image_data->Size());
  SkPixmap new_pm = new_image_data->GetSkPixmap();
  EXPECT_EQ(8u, new_pm.computeByteSize());
  EXPECT_EQ(200u, new_pm.addr32()[0]);
}

TEST(V8ScriptValueSerializerTest, DecodeImageDataV16) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x10, 0xff, 0x0c, 0x23, 0x02, 0x01, 0x08, 0xc8,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageData* new_image_data =
      V8ImageData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_data, nullptr);
  EXPECT_EQ(gfx::Size(2, 1), new_image_data->Size());
  SkPixmap new_pm = new_image_data->GetSkPixmap();
  EXPECT_EQ(kRGBA_8888_SkColorType, new_pm.info().colorType());
  EXPECT_EQ(8u, new_pm.computeByteSize());
  EXPECT_EQ(200u, new_pm.addr32()[0]);
}

TEST(V8ScriptValueSerializerTest, DecodeImageDataV18) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x23, 0x01, 0x03, 0x03, 0x02, 0x00, 0x02,
       0x01, 0x20, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageData* new_image_data =
      V8ImageData::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_data, nullptr);
  EXPECT_EQ(gfx::Size(2, 1), new_image_data->Size());
  ImageDataSettings* new_image_data_settings = new_image_data->getSettings();
  EXPECT_EQ("display-p3", new_image_data_settings->colorSpace());
  EXPECT_EQ("float32", new_image_data_settings->storageFormat());
  SkPixmap new_pm = new_image_data->GetSkPixmap();
  EXPECT_EQ(kRGBA_F32_SkColorType, new_pm.info().colorType());
  EXPECT_EQ(200u, static_cast<const uint8_t*>(new_pm.addr(0, 0))[0]);
}

TEST(V8ScriptValueSerializerTest, InvalidImageDataDecodeV18) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  {
    // Nonsense image serialization tag (kOriginCleanTag).
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x12, 0xff, 0x0d, 0x5c, 0x23, 0x02, 0x00, 0x00,
                         0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
}

MessagePort* MakeMessagePort(ExecutionContext* execution_context,
                             ::MojoHandle* unowned_handle_out = nullptr) {
  auto* port = MakeGarbageCollected<MessagePort>(*execution_context);
  blink::MessagePortDescriptorPair pipe;
  ::MojoHandle unowned_handle = pipe.port0().handle().get().value();
  port->Entangle(pipe.TakePort0(), nullptr);
  EXPECT_TRUE(port->IsEntangled());
  EXPECT_EQ(unowned_handle, port->EntangledHandleForTesting());
  if (unowned_handle_out)
    *unowned_handle_out = unowned_handle;
  return port;
}

TEST(V8ScriptValueSerializerTest, RoundTripMessagePort) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  ::MojoHandle unowned_handle;
  MessagePort* port =
      MakeMessagePort(scope.GetExecutionContext(), &unowned_handle);
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MessagePort>::ToV8(scope.GetScriptState(), port);
  Transferables transferables;
  transferables.message_ports.push_back(port);

  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState(), &transferables);
  MessagePort* new_port =
      V8MessagePort::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_port, nullptr);
  EXPECT_FALSE(port->IsEntangled());
  EXPECT_TRUE(new_port->IsEntangled());
  EXPECT_EQ(unowned_handle, new_port->EntangledHandleForTesting());
}

TEST(V8ScriptValueSerializerTest, NeuteredMessagePortThrowsDataCloneError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  auto* port = MakeGarbageCollected<MessagePort>(*scope.GetExecutionContext());
  EXPECT_TRUE(port->IsNeutered());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MessagePort>::ToV8(scope.GetScriptState(), port);
  Transferables transferables;
  transferables.message_ports.push_back(port);

  RoundTrip(wrapper, scope, PassThroughException(scope.GetIsolate()),
            &transferables);
  ASSERT_TRUE(HadDOMExceptionInCoreTest("DataCloneError",
                                        scope.GetScriptState(), try_catch));
}

TEST(V8ScriptValueSerializerTest,
     UntransferredMessagePortThrowsDataCloneError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  MessagePort* port = MakeMessagePort(scope.GetExecutionContext());
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MessagePort>::ToV8(scope.GetScriptState(), port);
  Transferables transferables;

  RoundTrip(wrapper, scope, PassThroughException(scope.GetIsolate()),
            &transferables);
  ASSERT_TRUE(HadDOMExceptionInCoreTest("DataCloneError",
                                        scope.GetScriptState(), try_catch));
}

TEST(V8ScriptValueSerializerTest, OutOfRangeMessagePortIndex) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x4d, 0x01});
  MessagePort* port1 = MakeMessagePort(scope.GetExecutionContext());
  MessagePort* port2 = MakeMessagePort(scope.GetExecutionContext());
  {
    V8ScriptValueDeserializer deserializer(script_state, input);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
  {
    V8ScriptValueDeserializer::Options options;
    options.message_ports = MakeGarbageCollected<MessagePortArray>();
    V8ScriptValueDeserializer deserializer(script_state, input, options);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
  {
    V8ScriptValueDeserializer::Options options;
    options.message_ports = MakeGarbageCollected<MessagePortArray>();
    options.message_ports->push_back(port1);
    V8ScriptValueDeserializer deserializer(script_state, input, options);
    ASSERT_TRUE(deserializer.Deserialize()->IsNull());
  }
  {
    V8ScriptValueDeserializer::Options options;
    options.message_ports = MakeGarbageCollected<MessagePortArray>();
    options.message_ports->push_back(port1);
    options.message_ports->push_back(port2);
    V8ScriptValueDeserializer deserializer(script_state, input, options);
    v8::Local<v8::Value> result = deserializer.Deserialize();
    EXPECT_EQ(port2, V8MessagePort::ToWrappable(scope.GetIsolate(), result));
  }
}

TEST(V8ScriptValueSerializerTest, RoundTripMojoHandle) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ContextFeatureSettings::From(
      scope.GetExecutionContext(),
      ContextFeatureSettings::CreationMode::kCreateIfNotExists)
      ->EnableMojoJS(true);

  mojo::MessagePipe pipe;
  auto* handle = MakeGarbageCollected<MojoHandle>(
      mojo::ScopedHandle::From(std::move(pipe.handle0)));
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MojoHandle>::ToV8(scope.GetScriptState(), handle);
  Transferables transferables;
  transferables.mojo_handles.push_back(handle);

  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState(), &transferables);
  MojoHandle* new_handle =
      V8MojoHandle::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_handle, nullptr);
  EXPECT_FALSE(handle->TakeHandle().is_valid());
  EXPECT_TRUE(new_handle->TakeHandle().is_valid());
}

TEST(V8ScriptValueSerializerTest, UntransferredMojoHandleThrowsDataCloneError) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  v8::TryCatch try_catch(scope.GetIsolate());

  mojo::MessagePipe pipe;
  auto* handle = MakeGarbageCollected<MojoHandle>(
      mojo::ScopedHandle::From(std::move(pipe.handle0)));
  v8::Local<v8::Value> wrapper =
      ToV8Traits<MojoHandle>::ToV8(scope.GetScriptState(), handle);
  Transferables transferables;

  RoundTrip(wrapper, scope, PassThroughException(scope.GetIsolate()),
            &transferables);
  ASSERT_TRUE(HadDOMExceptionInCoreTest("DataCloneError",
                                        scope.GetScriptState(), try_catch));
}

// Decode tests for backward compatibility are not required for message ports
// and Mojo handles because they cannot be persisted to disk.

// A more exhaustive set of ImageBitmap cases are covered by web tests.
TEST(V8ScriptValueSerializerTest, RoundTripImageBitmap) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;

  // Make a 10x7 red ImageBitmap.
  sk_sp<SkSurface> surface =
      SkSurfaces::Raster(SkImageInfo::MakeN32Premul(10, 7));
  surface->getCanvas()->clear(SK_ColorRED);
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot()));
  ASSERT_TRUE(image_bitmap->BitmapImage());

  // Serialize and deserialize it.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageBitmap>::ToV8(scope.GetScriptState(), image_bitmap);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  ASSERT_TRUE(new_image_bitmap->BitmapImage());
  ASSERT_EQ(gfx::Size(10, 7), new_image_bitmap->Size());

  // Check that the pixel at (3, 3) is red.
  uint8_t pixel[4] = {};
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          SkImageInfo::Make(1, 1, kRGBA_8888_SkColorType, kPremul_SkAlphaType),
          &pixel, 4, 3, 3));
  ASSERT_THAT(pixel, testing::ElementsAre(255, 0, 0, 255));
}

TEST(V8ScriptValueSerializerTest, ImageBitmapEXIFImageOrientation) {
  test::TaskEnvironment task_environment;
  // More complete end-to-end testing is provided by WPT test
  // imagebitmap-replication-exif-orientation.html.
  // The purpose of this complementary test is to get complete code coverage
  // for all possible values of ImageOrientationEnum.
  V8TestingScope scope;
  const uint32_t kImageWidth = 10;
  const uint32_t kImageHeight = 5;
  for (uint8_t i = static_cast<uint8_t>(ImageOrientationEnum::kOriginTopLeft);
       i <= static_cast<uint8_t>(ImageOrientationEnum::kMaxValue); i++) {
    ImageOrientationEnum orientation = static_cast<ImageOrientationEnum>(i);
    sk_sp<SkSurface> surface = SkSurfaces::Raster(
        SkImageInfo::MakeN32Premul(kImageWidth, kImageHeight));
    auto static_image =
        UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot());
    static_image->SetOrientation(orientation);
    auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(static_image);
    ASSERT_TRUE(image_bitmap->BitmapImage());
    // Serialize and deserialize it.
    v8::Local<v8::Value> wrapper =
        ToV8Traits<ImageBitmap>::ToV8(scope.GetScriptState(), image_bitmap);
    v8::Local<v8::Value> result =
        RoundTrip(wrapper, scope, scope.GetExceptionState());
    ImageBitmap* new_image_bitmap =
        V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
    ASSERT_NE(new_image_bitmap, nullptr);
    ASSERT_TRUE(new_image_bitmap->BitmapImage());
    // Ensure image orientation did not confuse (e.g transpose) the image size
    ASSERT_EQ(new_image_bitmap->Size(), image_bitmap->Size());
    ASSERT_EQ(new_image_bitmap->ImageOrientation(), orientation);
  }
}

TEST(V8ScriptValueSerializerTest, RoundTripImageBitmapWithColorSpaceInfo) {
  test::TaskEnvironment task_environment;
  sk_sp<SkColorSpace> p3 =
      SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDisplayP3);
  V8TestingScope scope;
  // Make a 10x7 red ImageBitmap in P3 color space.
  SkImageInfo info =
      SkImageInfo::Make(10, 7, kRGBA_F16_SkColorType, kPremul_SkAlphaType, p3);
  sk_sp<SkSurface> surface = SkSurfaces::Raster(info);
  surface->getCanvas()->clear(SK_ColorRED);
  auto* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      UnacceleratedStaticBitmapImage::Create(surface->makeImageSnapshot()));
  ASSERT_TRUE(image_bitmap->BitmapImage());

  // Serialize and deserialize it.
  v8::Local<v8::Value> wrapper =
      ToV8Traits<ImageBitmap>::ToV8(scope.GetScriptState(), image_bitmap);
  v8::Local<v8::Value> result =
      RoundTrip(wrapper, scope, scope.GetExceptionState());
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  ASSERT_TRUE(new_image_bitmap->BitmapImage());
  ASSERT_EQ(gfx::Size(10, 7), new_image_bitmap->Size());

  // Check the color settings.
  SkImageInfo bitmap_info = new_image_bitmap->GetBitmapSkImageInfo();
  EXPECT_EQ(kRGBA_F16_SkColorType, bitmap_info.colorType());
  EXPECT_TRUE(SkColorSpace::Equals(p3.get(), bitmap_info.colorSpace()));

  // Check that the pixel at (3, 3) is red. We expect red in P3 to be
  // {0x57, 0x3B, 0x68, 0x32, 0x6E, 0x30, 0x00, 0x3C} when each color
  // component is presented as a half float in Skia. However, difference in
  // GPU hardware may result in small differences in lower significant byte in
  // Skia color conversion pipeline. Hence, we use a tolerance of 2 here.
  uint8_t pixel[8] = {};
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          info.makeWH(1, 1), &pixel, 8, 3, 3));
  uint8_t p3_red[8] = {0x57, 0x3B, 0x68, 0x32, 0x6E, 0x30, 0x00, 0x3C};
  bool approximate_match = true;
  uint8_t tolerance = 2;
  for (int i = 0; i < 8; i++) {
    if (std::abs(p3_red[i] - pixel[i]) > tolerance) {
      approximate_match = false;
      break;
    }
  }
  ASSERT_TRUE(approximate_match);
}

TEST(V8ScriptValueSerializerTest, DecodeImageBitmap) {
  test::TaskEnvironment task_environment;
  // Backward compatibility with existing serialized ImageBitmap objects must be
  // maintained. Add more cases if the format changes; don't remove tests for
  // old versions.
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();

// This is checked by platform instead of by SK_PMCOLOR_BYTE_ORDER because
// this test intends to ensure that a platform can decode images it has
// previously written. At format version 9, Android writes RGBA and every
// other platform writes BGRA.
#if BUILDFLAG(IS_ANDROID)
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x67, 0x01, 0x01, 0x02, 0x01,
                       0x08, 0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff});
#else
  scoped_refptr<SerializedScriptValue> input =
      SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x67, 0x01, 0x01, 0x02, 0x01,
                       0x08, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff});
#endif

  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  ASSERT_EQ(gfx::Size(2, 1), new_image_bitmap->Size());

  // Check that the pixels are opaque red and green, respectively.
  uint8_t pixels[8] = {};
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          SkImageInfo::Make(2, 1, kRGBA_8888_SkColorType, kPremul_SkAlphaType),
          &pixels, 8, 0, 0));
  ASSERT_THAT(pixels, testing::ElementsAre(255, 0, 0, 255, 0, 255, 0, 255));
  // Check that orientation is top left (default).
  ASSERT_EQ(new_image_bitmap->ImageOrientation(),
            ImageOrientationEnum::kOriginTopLeft);
}

TEST(V8ScriptValueSerializerTest, DecodeImageBitmapV18) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue(
      {0xff, 0x12, 0xff, 0x0d, 0x5c, 0x67, 0x01, 0x03, 0x02, 0x01, 0x04, 0x01,
       0x05, 0x01, 0x00, 0x02, 0x01, 0x10, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24,
       0x00, 0x3c, 0x94, 0x3a, 0x3f, 0x28, 0x5f, 0x24, 0x00, 0x3c});
  sk_sp<SkColorSpace> p3 =
      SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDisplayP3);

  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  ASSERT_EQ(gfx::Size(2, 1), new_image_bitmap->Size());

  // Check the color settings.
  SkImageInfo bitmap_info = new_image_bitmap->GetBitmapSkImageInfo();
  EXPECT_EQ(kRGBA_F16_SkColorType, bitmap_info.colorType());
  EXPECT_TRUE(SkColorSpace::Equals(p3.get(), bitmap_info.colorSpace()));

  // Check that the pixel at (1, 0) is red.
  uint8_t pixel[8] = {};
  SkImageInfo info =
      SkImageInfo::Make(1, 1, kRGBA_F16_SkColorType, kPremul_SkAlphaType, p3);
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          info, &pixel, 8, 1, 0));
  // The reference values are the hex representation of red in P3 (as stored
  // in half floats by Skia).
  ASSERT_THAT(pixel, testing::ElementsAre(0x94, 0x3A, 0x3F, 0x28, 0x5F, 0x24,
                                          0x0, 0x3C));
  // Check that orientation is top left (default).
  ASSERT_EQ(new_image_bitmap->ImageOrientation(),
            ImageOrientationEnum::kOriginTopLeft);
}

TEST(V8ScriptValueSerializerTest, DecodeImageBitmapV20WithoutImageOrientation) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff,  // kVersionTag
      0x14,  // 20
      0xff,  // Value serializer header
      0x0f,  // Value serializer version 15 (varint format)
      0x5c,  // kHostObjectTag
      0x67,  // kImageBitmapTag
      0x07,  // kParametricColorSpaceTag
      // srgb colorspace
      0x00, 0x00, 0x00, 0x40, 0x33, 0x33, 0x03, 0x40, 0x00, 0x00, 0x00, 0xc0,
      0xed, 0x54, 0xee, 0x3f, 0x00, 0x00, 0x00, 0x20, 0x23, 0xb1, 0xaa, 0x3f,
      0x00, 0x00, 0x00, 0x20, 0x72, 0xd0, 0xb3, 0x3f, 0x00, 0x00, 0x00, 0xc0,
      0xdc, 0xb5, 0xa4, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x80, 0xe8, 0xdb, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x40, 0xa6, 0xd8, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xc2, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x80, 0x7a, 0xcc, 0x3f, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf0, 0xe6, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xaf, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x80, 0x8c, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda, 0xb8, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0xe0, 0xd9, 0xe6, 0x3f, 0x02,
      0x03,        // kCanvasPixelFormatTag kBGRA8
      0x06, 0x00,  // kCanvasOpacityModeTag
      0x04, 0x01,  // kOriginCleanTag
      0x05, 0x01,  // kIsPremultipliedTag
      // Image orientation omitted
      0x0,         // kEndTag
      0x01, 0x01,  // width, height (varint format)
      0x04,        // pixel size (varint format)
      0xee, 0xaa, 0x77, 0xff,
      0x00  // padding: even number of bytes for endianness swapping.
  });

  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  // Check image size
  ASSERT_EQ(gfx::Size(1, 1), new_image_bitmap->Size());
  // Check the color settings.
  SkImageInfo bitmap_info = new_image_bitmap->GetBitmapSkImageInfo();
  EXPECT_EQ(kBGRA_8888_SkColorType, bitmap_info.colorType());
  sk_sp<SkColorSpace> srgb =
      SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kSRGB);
  EXPECT_TRUE(SkColorSpace::Equals(srgb.get(), bitmap_info.colorSpace()));
  // Check that orientation is bottom left.
  ASSERT_EQ(new_image_bitmap->ImageOrientation(),
            ImageOrientationEnum::kOriginTopLeft);
  // Check pixel value
  SkImageInfo info = SkImageInfo::Make(1, 1, kRGBA_8888_SkColorType,
                                       kPremul_SkAlphaType, srgb);
  uint8_t pixel[4] = {};
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          info, &pixel, 4, 0, 0));
  // BGRA encoding, swapped to RGBA
  ASSERT_THAT(pixel, testing::ElementsAre(0x77, 0xaa, 0xee, 0xff));
}

TEST(V8ScriptValueSerializerTest, DecodeImageBitmapV20WithImageOrientation) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  scoped_refptr<SerializedScriptValue> input = SerializedValue({
      0xff,  // kVersionTag
      0x14,  // 20
      0xff,  // Value serializer header
      0x0f,  // Value serializer version 15, varint encoding
      0x5c,  // kHostObjectTag
      0x67,  // kImageBitmapTag
      0x07,  // kParametricColorSpaceTag
      // srgb colorspace
      0x00, 0x00, 0x00, 0x40, 0x33, 0x33, 0x03, 0x40, 0x00, 0x00, 0x00, 0xc0,
      0xed, 0x54, 0xee, 0x3f, 0x00, 0x00, 0x00, 0x20, 0x23, 0xb1, 0xaa, 0x3f,
      0x00, 0x00, 0x00, 0x20, 0x72, 0xd0, 0xb3, 0x3f, 0x00, 0x00, 0x00, 0xc0,
      0xdc, 0xb5, 0xa4, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x80, 0xe8, 0xdb, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x40, 0xa6, 0xd8, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xc2, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x80, 0x7a, 0xcc, 0x3f, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xf0, 0xe6, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xaf, 0x3f, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x80, 0x8c, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda, 0xb8, 0x3f,
      0x00, 0x00, 0x00, 0x00, 0xe0, 0xd9, 0xe6, 0x3f, 0x02,
      0x03,        // kCanvasPixelFormatTag kBGRA8
      0x06, 0x00,  // kCanvasOpacityModeTag
      0x04, 0x01,  // kOriginCleanTag
      0x05, 0x01,  // kIsPremultipliedTag
      0x08, 0x03,  // kImageOrientationTag -> kBottomLeft
      0x0,         // kEndTag
      0x01, 0x01,  // width, height (varint format)
      0x04,        // pixel size (varint format)
      0xee, 0xaa, 0x77, 0xff,
      0x00  // padding: even number of bytes for endianness swapping.
  });

  v8::Local<v8::Value> result =
      V8ScriptValueDeserializer(script_state, input).Deserialize();
  ImageBitmap* new_image_bitmap =
      V8ImageBitmap::ToWrappable(scope.GetIsolate(), result);
  ASSERT_NE(new_image_bitmap, nullptr);
  // Check image size
  ASSERT_EQ(gfx::Size(1, 1), new_image_bitmap->Size());
  // Check the color settings.
  SkImageInfo bitmap_info = new_image_bitmap->GetBitmapSkImageInfo();
  EXPECT_EQ(kBGRA_8888_SkColorType, bitmap_info.colorType());
  sk_sp<SkColorSpace> srgb =
      SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kSRGB);
  EXPECT_TRUE(SkColorSpace::Equals(srgb.get(), bitmap_info.colorSpace()));
  // Check that orientation is bottom left.
  ASSERT_EQ(new_image_bitmap->ImageOrientation(),
            ImageOrientationEnum::kOriginBottomLeft);
  // Check pixel value
  SkImageInfo info = SkImageInfo::Make(1, 1, kRGBA_8888_SkColorType,
                                       kPremul_SkAlphaType, srgb);
  uint8_t pixel[4] = {};
  ASSERT_TRUE(
      new_image_bitmap->BitmapImage()->PaintImageForCurrentFrame().readPixels(
          info, &pixel, 4, 0, 0));
  // BGRA encoding, swapped to RGBA
  ASSERT_THAT(pixel, testing::ElementsAre(0x77, 0xaa, 0xee, 0xff));
}

TEST(V8ScriptValueSerializerTest, InvalidImageBitmapDecode) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  {
    // Too many bytes declared in pixel data.
    scoped_refptr<SerializedScriptValue> input = SerializedValue(
        {0xff, 0x09, 0x3f, 0x00, 0x67, 0x01, 0x01, 0x02, 0x01, 0x09,
         0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0x00});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Too few bytes declared in pixel data.
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x67, 0x01, 0x01, 0x02, 0x01,
                         0x07, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for origin clean data.
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x67, 0x02, 0x01, 0x02, 0x01,
                         0x08, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
  {
    // Nonsense for premultiplied bit.
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x09, 0x3f, 0x00, 0x67, 0x01, 0x02, 0x02, 0x01,
                         0x08, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00, 0xff});
    EXPECT_TRUE(
        V8ScriptValueDeserializer(script_state, input).Deserialize()->IsNull());
  }
}

TEST(V8ScriptValueSerializerTest, InvalidImageBitmapDecodeV18) {
  test::TaskEnvironment task_environment;
  V8TestingScope scope;
  ScriptState* script_state = scope.GetScriptState();
  {
    // Too many bytes declared in pixel data.
    scoped_refptr<SerializedScriptValue> input =
        SerializedValue({0xff, 0x12, 0xff, 0x
```
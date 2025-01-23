Response:
The user wants a summary of the functionality of the provided C++ code file. I need to identify the main purpose of the code and how it interacts with other parts of the Chromium/Blink engine, particularly concerning web technologies like JavaScript, HTML, and CSS.

**Plan:**

1. **Identify the main class being tested:** The filename `image_decoder_external_test.cc` and the included headers suggest the file is testing `ImageDecoderExternal`.
2. **Analyze the test cases:**  The `TEST_F` macros indicate individual test cases. I will examine each test case to understand the specific functionality being verified.
3. **Relate the tested functionality to web technologies:** Determine if the tested functionalities have direct implications for how images are handled in web pages (e.g., decoding, supported formats).
4. **Look for examples of interactions with JavaScript APIs:** The presence of `ScriptPromiseTester` and `V8TestingScope` strongly suggests that the tests are verifying the behavior of JavaScript APIs related to image decoding.
5. **Identify potential user errors or debugging scenarios:**  Consider how the tested functionalities might be affected by incorrect usage or might serve as debugging points.
```
这是目录为blink/renderer/modules/webcodecs/image_decoder_external_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**功能归纳 (基于提供的代码片段):**

该代码文件是一个 C++ 单元测试文件，专门用于测试 `blink::ImageDecoderExternal` 类的功能。`ImageDecoderExternal` 看起来是 Chromium Blink 引擎中 WebCodecs API 的一部分，负责在浏览器中对外部提供的图像数据进行解码。

**具体功能点（基于已提供的测试用例名称和代码）：**

1. **测试 `isTypeSupported()` 方法:**  验证 `ImageDecoderExternal` 能否正确判断给定的 MIME 类型是否支持解码。
2. **测试解码空数据:**  验证尝试解码空数据时是否会抛出异常或返回错误。
3. **测试解码时数据被 "neutered" (转移):** 验证在 `ImageDecoderExternal` 创建或解码过程中，如果提供的数据（ArrayBuffer）被转移（例如通过 `Transfer` API），是否会正确处理并抛出异常。这确保了 `ImageDecoderExternal` 不会在数据所有权转移后尝试访问数据。
4. **测试解码不支持的图像类型:** 验证当尝试解码不支持的图像类型时，相关的 Promise 是否会被拒绝。
5. **测试 MIME 类型的大小写不敏感性:** 验证 `ImageDecoderExternal` 在创建时是否能正确处理大小写混合的 MIME 类型。
6. **测试 GIF 图像的解码:**
    - 验证对 GIF 图像进行解码的基本功能。
    - 验证解码后的 `ImageDecodeResult` 对象包含正确的帧信息（时间戳、持续时间、尺寸等）。
    - 验证尝试解码超出帧数的帧会返回 rejected 的 Promise。
    - 特别测试了帧持续时间为 0 的 GIF 图像的处理。
7. **测试 `completed()` 方法:** 验证 `completed()` 方法返回的 Promise 在图像解码完成后是否会 fulfilled。
8. **测试 `reset()` 方法:** 验证 `reset()` 方法能否重置解码器状态，并允许再次解码。
9. **测试 `close()` 方法:** 验证 `close()` 方法会释放解码器资源，并导致后续的解码操作失败。
10. **测试在 ExecutionContext 被销毁时的处理:** 验证当 JavaScript 的 ExecutionContext 被销毁时，`ImageDecoderExternal` 能否正确清理资源，避免内存泄漏或崩溃。
11. **测试在创建前 ExecutionContext 被销毁的情况:** 验证在创建 `ImageDecoderExternal` 之前，如果 ExecutionContext 被销毁，创建操作是否会失败并抛出异常。
12. **测试使用 ReadableStream 作为数据源进行解码:**
    - 验证 `ImageDecoderExternal` 可以从 JavaScript 的 `ReadableStream` 中读取图像数据进行解码。
    - 验证在数据尚未完全到达时，解码过程的行为。
    - 验证在没有选择 track 的情况下，解码相关的 Promise 会被 rejected。
    - 特别测试了 AVIF 图像通过 `ReadableStream` 解码的场景。
13. **测试解码部分图像数据:** 验证当只提供部分图像数据时，解码操作的行为。
14. **测试在 ReadableStream 传输过程中解码器被关闭的情况:** 验证在通过 `ReadableStream` 接收数据时，如果解码器被关闭，解码操作是否会正确处理。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  `ImageDecoderExternal` 是 WebCodecs API 的一部分，这意味着 JavaScript 代码可以直接与之交互。
    * **示例:** JavaScript 代码可以使用 `new ImageDecoder({ type: 'image/png' })` 创建一个 `ImageDecoder` 实例（在 JavaScript 层面对应 `ImageDecoderExternal`），然后使用 `decode()` 方法解码图像数据。
    * **示例:** `isTypeSupported()` 方法在 JavaScript 中也有对应的 API，可以用来检查浏览器是否支持解码特定类型的图像。
    * **示例:**  通过 `ReadableStream` 提供图像数据是 Web API 中异步数据处理的常见模式，`ImageDecoderExternal` 对此提供了支持。
* **HTML:**  `ImageDecoderExternal` 的解码结果最终可能会被用于在 HTML `<canvas>` 元素上绘制图像，或者作为 `<img>` 标签的 `src` 属性的数据源（例如，通过 `createImageBitmap` API）。
    * **示例:**  解码后的 `VideoFrame` 或 `ImageBitmap` 对象可以在 `<canvas>` 上绘制出来。
* **CSS:**  虽然 `ImageDecoderExternal` 本身不直接与 CSS 交互，但解码后的图像可以作为 CSS 背景图片或其他 CSS 属性的值。
    * **示例:**  解码后的静态图像或动画图像可以被设置为元素的 `background-image`。

**逻辑推理的假设输入与输出：**

* **假设输入:** 一个包含完整 GIF 图像数据的 `ArrayBuffer`，MIME 类型为 `"image/gif"`。
* **预期输出 (对于成功的 `decode()` 调用):**  一个 resolved 的 Promise，其 value 是一个 `ImageDecodeResult` 对象。该对象包含 `complete: true`，以及一个 `image` 属性，该属性是一个 `VideoFrame` 对象，包含了 GIF 图像的当前帧的数据、时间戳、持续时间、尺寸和颜色空间等信息。

* **假设输入:** 一个 MIME 类型为 `"image/svg+xml"` 的字符串。
* **预期输出 (对于 `isTypeSupported()` 调用):** `false` (因为代码中明确测试了 "image/svg+xml" 不被支持)。

**用户或编程常见的使用错误：**

1. **尝试解码不支持的格式:** 用户或开发者可能尝试使用 `ImageDecoder` 解码浏览器不支持的图像格式，例如旧的专有格式。这会导致解码失败。
2. **在数据未完全加载时尝试解码:**  当使用 `ReadableStream` 作为数据源时，开发者可能会在所有图像数据到达之前就调用 `decode()`，导致解码失败或不完整。
3. **多次 `Transfer` ArrayBuffer:** 如果开发者在将 `ArrayBuffer` 传递给 `ImageDecoder` 后，又意外地调用了 `Transfer` 方法，会导致 `ImageDecoder` 尝试访问已被转移的数据，引发错误。
4. **在解码器关闭后尝试解码:** 开发者可能会在调用 `close()` 方法后，仍然尝试使用该解码器进行解码，这将导致操作失败。
5. **不正确的 MIME 类型:**  提供错误的 MIME 类型可能会导致解码器无法正确识别图像格式，从而导致解码失败。

**用户操作到达这里的调试线索：**

当开发者在浏览器中使用 WebCodecs API 的 `ImageDecoder` 功能时，如果遇到图像解码相关的问题，Blink 引擎的开发者可能会需要调试 `ImageDecoderExternal` 的代码。

**可能的调试步骤和线索：**

1. **用户在网页上尝试解码特定格式的图像失败:**  开发者可能会检查 `isTypeSupported()` 的实现和测试，以确认该格式是否应该被支持。
2. **解码大型或复杂的动画图像时出现性能问题或崩溃:** 开发者可能会检查 `ImageDecoderExternal` 的解码流程，包括资源管理和内存使用情况。
3. **使用 `ReadableStream` 解码图像时出现数据丢失或顺序错误:** 开发者可能会检查 `ImageDecoderExternal` 如何从 `ReadableStream` 中读取数据，以及如何处理异步数据到达。
4. **浏览器开发者在添加新的图像格式支持后，需要编写单元测试来验证 `ImageDecoderExternal` 的行为是否正确。**  这个测试文件就是这类单元测试的一部分。

**总结（针对第 1 部分）：**

提供的代码片段展示了 `blink::ImageDecoderExternal` 类的单元测试，涵盖了其基本功能，包括图像类型支持检测、基本解码流程、错误处理（例如空数据、不支持的类型、数据转移）、生命周期管理（重置、关闭）以及与 `ReadableStream` 的集成。这些测试确保了 `ImageDecoderExternal` 能够按照 WebCodecs 规范正确地解码各种图像格式，并在各种异常情况下提供合理的行为，从而保证了 Web 平台上图像处理功能的稳定性和可靠性。
```
### 提示词
```
这是目录为blink/renderer/modules/webcodecs/image_decoder_external_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/image_decoder_external.h"

#include "media/media_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybufferallowshared_arraybufferviewallowshared_readablestream.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decode_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_image_track.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/test_underlying_source.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/image_track.h"
#include "third_party/blink/renderer/modules/webcodecs/image_track_list.h"
#include "third_party/blink/renderer/modules/webcodecs/video_frame.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

class ImageDecoderTest : public testing::Test {
 public:
  ~ImageDecoderTest() override {
    // Force GC before exiting since ImageDecoderExternal will create objects
    // on background threads that will race with the next test's startup. See
    // https://crbug.com/1196376
    ThreadState::Current()->CollectAllGarbageForTesting();
    base::RunLoop().RunUntilIdle();
  }

 protected:
  ImageDecoderExternal* CreateDecoder(V8TestingScope* v8_scope,
                                      const char* file_name,
                                      const char* mime_type) {
    auto* init = MakeGarbageCollected<ImageDecoderInit>();
    init->setType(mime_type);

    init->setData(MakeGarbageCollected<V8ImageBufferSource>(
        DOMArrayBuffer::Create(base::as_byte_span(ReadFile(file_name)))));
    return ImageDecoderExternal::Create(v8_scope->GetScriptState(), init,
                                        v8_scope->GetExceptionState());
  }

  ImageDecodeResult* ToImageDecodeResult(V8TestingScope* v8_scope,
                                         ScriptValue value) {
    return NativeValueTraits<ImageDecodeResult>::NativeValue(
        v8_scope->GetIsolate(), value.V8Value(), v8_scope->GetExceptionState());
  }

  ImageDecodeOptions* MakeOptions(uint32_t frame_index = 0,
                                  bool complete_frames_only = true) {
    auto* options = MakeGarbageCollected<ImageDecodeOptions>();
    options->setFrameIndex(frame_index);
    options->setCompleteFramesOnly(complete_frames_only);
    return options;
  }

  Vector<char> ReadFile(StringView file_name) {
    StringBuilder file_path;
    file_path.Append(test::BlinkWebTestsDir());
    file_path.Append('/');
    file_path.Append(file_name);
    std::optional<Vector<char>> data = test::ReadFromFile(file_path.ToString());
    CHECK(data && data->size()) << "Missing file: " << file_name;
    return std::move(*data);
  }

  bool IsTypeSupported(V8TestingScope* v8_scope, String type) {
    auto promise =
        ImageDecoderExternal::isTypeSupported(v8_scope->GetScriptState(), type);
    ScriptPromiseTester tester(v8_scope->GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_FALSE(tester.IsRejected());

    auto v8_value = tester.Value().V8Value();
    EXPECT_TRUE(v8_value->IsBoolean());
    return v8_value.As<v8::Boolean>()->Value();
  }

  static bool HasAv1Decoder() {
#if BUILDFLAG(ENABLE_AV1_DECODER)
    return true;
#else
    return false;
#endif
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(ImageDecoderTest, IsTypeSupported) {
  V8TestingScope v8_scope;
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/jpeg"));
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/pjpeg"));
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/jpg"));

  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/png"));
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/x-png"));
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/apng"));

  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/gif"));

  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/webp"));

  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/bmp"));
  EXPECT_TRUE(IsTypeSupported(&v8_scope, "image/x-xbitmap"));

  EXPECT_EQ(IsTypeSupported(&v8_scope, "image/avif"), HasAv1Decoder());

  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/x-icon"));
  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/vnd.microsoft.icon"));
  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/svg+xml"));
  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/heif"));
  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/pcx"));
  EXPECT_FALSE(IsTypeSupported(&v8_scope, "image/bpg"));
}

TEST_F(ImageDecoderTest, DecodeEmpty) {
  V8TestingScope v8_scope;

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType("image/png");
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(
      DOMArrayBuffer::Create(SharedBuffer::Create())));
  auto* decoder = ImageDecoderExternal::Create(v8_scope.GetScriptState(), init,
                                               v8_scope.GetExceptionState());
  EXPECT_FALSE(decoder);
  EXPECT_TRUE(v8_scope.GetExceptionState().HadException());
}

TEST_F(ImageDecoderTest, DecodeNeuteredAtConstruction) {
  V8TestingScope v8_scope;

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  auto* buffer = DOMArrayBuffer::Create(SharedBuffer::Create());

  init->setType("image/png");
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(buffer));

  ArrayBufferContents contents;
  ASSERT_TRUE(buffer->Transfer(v8_scope.GetIsolate(), contents,
                               v8_scope.GetExceptionState()));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  auto* decoder = ImageDecoderExternal::Create(v8_scope.GetScriptState(), init,
                                               v8_scope.GetExceptionState());
  EXPECT_FALSE(decoder);
  EXPECT_TRUE(v8_scope.GetExceptionState().HadException());
}

TEST_F(ImageDecoderTest, DecodeNeuteredAtDecodeTime) {
  V8TestingScope v8_scope;

  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);

  constexpr char kTestFile[] = "images/resources/animated.gif";
  Vector<char> data = ReadFile(kTestFile);

  auto* buffer = DOMArrayBuffer::Create(base::as_byte_span(data));

  init->setData(MakeGarbageCollected<V8ImageBufferSource>(buffer));

  auto* decoder = ImageDecoderExternal::Create(v8_scope.GetScriptState(), init,
                                               v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  ArrayBufferContents contents;
  ASSERT_TRUE(buffer->Transfer(v8_scope.GetIsolate(), contents,
                               v8_scope.GetExceptionState()));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  auto promise = decoder->decode(MakeOptions(0, true));
  ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_FALSE(tester.IsRejected());
}

TEST_F(ImageDecoderTest, DecodeUnsupported) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/svg+xml";
  EXPECT_FALSE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/test.svg", kImageType);
  EXPECT_TRUE(decoder);
  EXPECT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }

  {
    auto promise = decoder->decode(MakeOptions(0, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }
}

TEST_F(ImageDecoderTest, DecoderCreationMixedCaseMimeType) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/GiF";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), "image/gif");
}

TEST_F(ImageDecoderTest, DecodeGifZeroDuration) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  {
    auto promise = decoder->decode(MakeOptions(0, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->timestamp(), 0u);
    EXPECT_EQ(frame->duration(), 0u);
    EXPECT_EQ(frame->displayWidth(), 16u);
    EXPECT_EQ(frame->displayHeight(), 16u);
    EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
  }

  {
    auto promise = decoder->decode(MakeOptions(1, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->timestamp(), 0u);
    EXPECT_EQ(frame->duration(), 0u);
    EXPECT_EQ(frame->displayWidth(), 16u);
    EXPECT_EQ(frame->displayHeight(), 16u);
    EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
  }

  // Decoding past the end should result in a rejected promise.
  auto promise = decoder->decode(MakeOptions(3, true));
  ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsRejected());
}

TEST_F(ImageDecoderTest, DecodeGif) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder = CreateDecoder(
      &v8_scope, "images/resources/animated-10color.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  const auto& tracks = decoder->tracks();
  ASSERT_EQ(tracks.length(), 1u);
  EXPECT_EQ(tracks.AnonymousIndexedGetter(0)->animated(), true);
  EXPECT_EQ(tracks.selectedTrack()->animated(), true);

  EXPECT_EQ(decoder->type(), kImageType);
  EXPECT_EQ(tracks.selectedTrack()->frameCount(), 10u);
  EXPECT_EQ(tracks.selectedTrack()->repetitionCount(), INFINITY);
  EXPECT_EQ(decoder->complete(), true);

  {
    auto promise = decoder->decode(MakeOptions(0, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->timestamp(), 0u);
    EXPECT_EQ(frame->duration(), 100000u);
    EXPECT_EQ(frame->displayWidth(), 100u);
    EXPECT_EQ(frame->displayHeight(), 100u);
    EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
  }

  {
    auto promise = decoder->decode(MakeOptions(1, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->timestamp(), 100000u);
    EXPECT_EQ(frame->duration(), 100000u);
    EXPECT_EQ(frame->displayWidth(), 100u);
    EXPECT_EQ(frame->displayHeight(), 100u);
    EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
  }

  // Decoding past the end should result in a rejected promise.
  auto promise = decoder->decode(MakeOptions(11, true));
  ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsRejected());
}

TEST_F(ImageDecoderTest, DecodeCompleted) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->completed(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }
}

TEST_F(ImageDecoderTest, DecodeAborted) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/avif";
  EXPECT_EQ(IsTypeSupported(&v8_scope, kImageType), HasAv1Decoder());

  // Use an expensive-to-decode image to try and ensure work exists to abort.
  auto* decoder = CreateDecoder(
      &v8_scope,
      "images/resources/avif/red-at-12-oclock-with-color-profile-12bpc.avif",
      kImageType);

  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_EQ(tester.IsFulfilled(), HasAv1Decoder());
  }

  // Setup a scenario where there should be work to abort. Since blink tests use
  // real threads with the base::TaskEnvironment, we can't actually be sure that
  // work hasn't completed by the time reset() is called.
  for (int i = 0; i < 10; ++i)
    decoder->decode();
  decoder->reset();

  // There's no way to verify work was aborted, so just ensure nothing explodes.
  base::RunLoop().RunUntilIdle();
}

TEST_F(ImageDecoderTest, DecoderReset) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), "image/gif");
  decoder->reset();

  // Ensure decoding works properly after reset.
  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  const auto& tracks = decoder->tracks();
  ASSERT_EQ(tracks.length(), 1u);
  EXPECT_EQ(tracks.AnonymousIndexedGetter(0)->animated(), true);
  EXPECT_EQ(tracks.selectedTrack()->animated(), true);

  EXPECT_EQ(decoder->type(), kImageType);
  EXPECT_EQ(tracks.selectedTrack()->frameCount(), 2u);
  EXPECT_EQ(tracks.selectedTrack()->repetitionCount(), INFINITY);
  EXPECT_EQ(decoder->complete(), true);

  {
    auto promise = decoder->decode(MakeOptions(0, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->duration(), 0u);
    EXPECT_EQ(frame->displayWidth(), 16u);
    EXPECT_EQ(frame->displayHeight(), 16u);
  }
}

TEST_F(ImageDecoderTest, DecoderClose) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), "image/gif");
  decoder->close();

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }

  {
    auto promise = decoder->decode(MakeOptions(0, true));
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }
}

TEST_F(ImageDecoderTest, DecoderContextDestroyed) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));
  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), "image/gif");

  // Decoder creation will queue metadata decoding which should be counted as
  // pending activity.
  EXPECT_TRUE(decoder->HasPendingActivity());
  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
  }

  // After metadata resolution completes, we should return to no activity.
  EXPECT_FALSE(decoder->HasPendingActivity());

  // Queue some activity.
  decoder->decode();
  EXPECT_TRUE(decoder->HasPendingActivity());

  // Destroying the context should close() the decoder and stop all activity.
  v8_scope.GetExecutionContext()->NotifyContextDestroyed();
  EXPECT_FALSE(decoder->HasPendingActivity());

  // Promises won't resolve or reject now that the context is destroyed, but we
  // should ensure decode() doesn't trigger any issues.
  decoder->decode(MakeOptions(0, true));

  // This will fail if a decode() or metadata decode was queued.
  EXPECT_FALSE(decoder->HasPendingActivity());
}

TEST_F(ImageDecoderTest, DecoderContextDestroyedBeforeCreation) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));

  // Destroying the context prior to construction should fail creation.
  v8_scope.GetExecutionContext()->NotifyContextDestroyed();

  auto* decoder =
      CreateDecoder(&v8_scope, "images/resources/animated.gif", kImageType);
  ASSERT_FALSE(decoder);
  ASSERT_TRUE(v8_scope.GetExceptionState().HadException());
}

TEST_F(ImageDecoderTest, DecoderReadableStream) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));

  Vector<char> data = ReadFile("images/resources/animated-10color.gif");

  Persistent<TestUnderlyingSource> underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(v8_scope.GetScriptState());
  Persistent<ReadableStream> stream =
      ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                      underlying_source, 0);

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(stream));

  Persistent<ImageDecoderExternal> decoder = ImageDecoderExternal::Create(
      v8_scope.GetScriptState(), init, IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), kImageType);

  constexpr size_t kNumChunks = 2;
  const size_t chunk_size = (data.size() + 1) / kNumChunks;
  base::span<const uint8_t> data_span = base::as_byte_span(data);

  v8::Local<v8::Value> v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(
      v8_scope.GetScriptState(),
      DOMUint8Array::Create(data_span.first(chunk_size)));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  underlying_source->Enqueue(ScriptValue(v8_scope.GetIsolate(), v8_data_array));

  // Ensure we have metadata.
  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
  }

  // Deselect the current track.
  ASSERT_TRUE(decoder->tracks().selectedTrack());
  decoder->tracks().selectedTrack()->setSelected(false);

  // Enqueue remaining data.
  v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(
      v8_scope.GetScriptState(), DOMUint8Array::Create(data_span.subspan(
                                     chunk_size, data.size() - chunk_size)));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  underlying_source->Enqueue(ScriptValue(v8_scope.GetIsolate(), v8_data_array));
  underlying_source->Close();

  // Completed will not resolve while we have no selected track.
  auto completed_promise = decoder->completed(v8_scope.GetScriptState());
  ScriptPromiseTester completed_tester(v8_scope.GetScriptState(),
                                       completed_promise);
  EXPECT_FALSE(completed_tester.IsFulfilled());
  EXPECT_FALSE(completed_tester.IsRejected());

  // Metadata should resolve okay while no track is selected.
  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsFulfilled());
  }

  // Decodes should be rejected while no track is selected.
  {
    auto promise = decoder->decode();
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }

  EXPECT_FALSE(completed_tester.IsFulfilled());
  EXPECT_FALSE(completed_tester.IsRejected());

  // Select a track again.
  decoder->tracks().AnonymousIndexedGetter(0)->setSelected(true);

  completed_tester.WaitUntilSettled();
  EXPECT_TRUE(completed_tester.IsFulfilled());

  // Verify a decode completes successfully.
  {
    auto promise = decoder->decode();
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->timestamp(), 0u);
    EXPECT_EQ(*frame->duration(), 100000u);
    EXPECT_EQ(frame->displayWidth(), 100u);
    EXPECT_EQ(frame->displayHeight(), 100u);
    EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
  }
}

TEST_F(ImageDecoderTest, DecoderReadableStreamAvif) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/avif";
  EXPECT_EQ(IsTypeSupported(&v8_scope, kImageType), HasAv1Decoder());

  Vector<char> data = ReadFile("images/resources/avif/star-animated-8bpc.avif");

  Persistent<TestUnderlyingSource> underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(v8_scope.GetScriptState());
  Persistent<ReadableStream> stream =
      ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                      underlying_source, 0);

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(stream));

  Persistent<ImageDecoderExternal> decoder = ImageDecoderExternal::Create(
      v8_scope.GetScriptState(), init, IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), kImageType);

  // Enqueue a single byte and ensure nothing breaks.
  const auto [first, rest] = base::as_byte_span(data).split_at<1>();
  v8::Local<v8::Value> v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(
      v8_scope.GetScriptState(), DOMUint8Array::Create(first));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  underlying_source->Enqueue(ScriptValue(v8_scope.GetIsolate(), v8_data_array));

  auto metadata_promise = decoder->tracks().ready(v8_scope.GetScriptState());
  auto decode_promise = decoder->decode();
  base::RunLoop().RunUntilIdle();

  // One byte shouldn't be enough to decode size or fail, so no promises should
  // be resolved.
  ScriptPromiseTester metadata_tester(v8_scope.GetScriptState(),
                                      metadata_promise);
  EXPECT_FALSE(metadata_tester.IsFulfilled());
  EXPECT_FALSE(metadata_tester.IsRejected());

  ScriptPromiseTester decode_tester(v8_scope.GetScriptState(), decode_promise);
  EXPECT_FALSE(decode_tester.IsFulfilled());
  EXPECT_FALSE(decode_tester.IsRejected());

  // Append the rest of the data.
  v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(v8_scope.GetScriptState(),
                                                  DOMUint8Array::Create(rest));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  underlying_source->Enqueue(ScriptValue(v8_scope.GetIsolate(), v8_data_array));

  // Ensure we have metadata.
  metadata_tester.WaitUntilSettled();
  ASSERT_EQ(metadata_tester.IsFulfilled(), HasAv1Decoder());

  // Verify decode completes successfully.
  decode_tester.WaitUntilSettled();
#if BUILDFLAG(ENABLE_AV1_DECODER)
  ASSERT_TRUE(decode_tester.IsFulfilled());
  auto* result = ToImageDecodeResult(&v8_scope, decode_tester.Value());
  EXPECT_TRUE(result->complete());

  auto* frame = result->image();
  EXPECT_EQ(frame->timestamp(), 0u);
  EXPECT_EQ(*frame->duration(), 100000u);
  EXPECT_EQ(frame->displayWidth(), 159u);
  EXPECT_EQ(frame->displayHeight(), 159u);
  EXPECT_EQ(frame->frame()->ColorSpace(), gfx::ColorSpace::CreateSRGB());
#else
  EXPECT_FALSE(decode_tester.IsFulfilled());
#endif
}

TEST_F(ImageDecoderTest, ReadableStreamAvifStillYuvDecoding) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/avif";
  EXPECT_EQ(IsTypeSupported(&v8_scope, kImageType), HasAv1Decoder());

  Vector<char> data =
      ReadFile("images/resources/avif/red-limited-range-420-8bpc.avif");

  Persistent<TestUnderlyingSource> underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(v8_scope.GetScriptState());
  Persistent<ReadableStream> stream =
      ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                      underlying_source, 0);

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(stream));

  Persistent<ImageDecoderExternal> decoder = ImageDecoderExternal::Create(
      v8_scope.GetScriptState(), init, IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), kImageType);

  // Append all data, but don't mark the stream as complete yet.
  v8::Local<v8::Value> v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(
      v8_scope.GetScriptState(),
      DOMUint8Array::Create(base::as_byte_span(data)));
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  underlying_source->Enqueue(ScriptValue(v8_scope.GetIsolate(), v8_data_array));

  // Wait for metadata so we know the append has occurred.
  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_EQ(tester.IsFulfilled(), HasAv1Decoder());
  }

  // Attempt to decode a frame greater than the first.
  auto bad_promise = decoder->decode(MakeOptions(1, true));
  base::RunLoop().RunUntilIdle();

  // Mark the stream as complete.
  underlying_source->Close();

  // Now that all data is in we see only 1 frame and request should be rejected.
  {
    ScriptPromiseTester tester(v8_scope.GetScriptState(), bad_promise);
    tester.WaitUntilSettled();
    EXPECT_TRUE(tester.IsRejected());
  }

  {
    auto promise = decoder->decode();
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
#if BUILDFLAG(ENABLE_AV1_DECODER)
    ASSERT_TRUE(tester.IsFulfilled());
    auto* result = ToImageDecodeResult(&v8_scope, tester.Value());
    EXPECT_TRUE(result->complete());

    auto* frame = result->image();
    EXPECT_EQ(frame->format(), "I420");
    EXPECT_EQ(frame->timestamp(), 0u);
    EXPECT_EQ(frame->duration(), std::nullopt);
    EXPECT_EQ(frame->displayWidth(), 3u);
    EXPECT_EQ(frame->displayHeight(), 3u);
    EXPECT_EQ(frame->frame()->ColorSpace(),
              gfx::ColorSpace(gfx::ColorSpace::PrimaryID::BT709,
                              gfx::ColorSpace::TransferID::SRGB,
                              gfx::ColorSpace::MatrixID::BT709,
                              gfx::ColorSpace::RangeID::LIMITED));
#else
    EXPECT_FALSE(tester.IsFulfilled());
#endif
  }
}

TEST_F(ImageDecoderTest, DecodePartialImage) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/png";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);

  // Read just enough to get the header and some of the image data.
  Vector<char> data = ReadFile("images/resources/dice.png");
  auto* array_buffer = DOMArrayBuffer::Create(128, 1);
  array_buffer->ByteSpan().copy_from(
      base::as_byte_span(data).first(array_buffer->ByteLength()));

  init->setData(MakeGarbageCollected<V8ImageBufferSource>(array_buffer));
  auto* decoder = ImageDecoderExternal::Create(v8_scope.GetScriptState(), init,
                                               v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  {
    auto promise = decoder->tracks().ready(v8_scope.GetScriptState());
    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  {
    auto promise1 = decoder->decode();
    auto promise2 = decoder->decode(MakeOptions(2, true));

    ScriptPromiseTester tester1(v8_scope.GetScriptState(), promise1);
    ScriptPromiseTester tester2(v8_scope.GetScriptState(), promise2);

    // Order is inverted here to catch a specific issue where out of range
    // resolution is handled ahead of decode. https://crbug.com/1200137.
    tester2.WaitUntilSettled();
    ASSERT_TRUE(tester2.IsRejected());

    tester1.WaitUntilSettled();
    ASSERT_TRUE(tester1.IsRejected());
  }
}

TEST_F(ImageDecoderTest, DecodeClosedDuringReadableStream) {
  V8TestingScope v8_scope;
  constexpr char kImageType[] = "image/gif";
  EXPECT_TRUE(IsTypeSupported(&v8_scope, kImageType));

  Vector<char> data = ReadFile("images/resources/animated-10color.gif");

  Persistent<TestUnderlyingSource> underlying_source =
      MakeGarbageCollected<TestUnderlyingSource>(v8_scope.GetScriptState());
  Persistent<ReadableStream> stream =
      ReadableStream::CreateWithCountQueueingStrategy(v8_scope.GetScriptState(),
                                                      underlying_source, 0);

  auto* init = MakeGarbageCollected<ImageDecoderInit>();
  init->setType(kImageType);
  init->setData(MakeGarbageCollected<V8ImageBufferSource>(stream));

  Persistent<ImageDecoderExternal> decoder = ImageDecoderExternal::Create(
      v8_scope.GetScriptState(), init, IGNORE_EXCEPTION_FOR_TESTING);
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  EXPECT_EQ(decoder->type(), kImageType);

  base::span<const uint8_t> data_span = base::as_byte_span(data);

  v8::Local<v8::Value> v8_data_array = ToV8Traits<DOMUint8Array>::ToV8(
      v8_scope.GetScriptState(),
      DOMUint8Array::Create(data_span.first(data.size() / 2)
```
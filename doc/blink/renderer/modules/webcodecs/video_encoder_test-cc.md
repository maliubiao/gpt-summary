Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `video_encoder_test.cc` immediately suggests it's a test suite for the `VideoEncoder` class. The `#include` directives confirm this, particularly the inclusion of `third_party/blink/renderer/modules/webcodecs/video_encoder.h`.

2. **Understand the Testing Framework:** The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Mock and Google Test for writing the unit tests. This tells us the tests will involve setting up expectations and assertions.

3. **Examine Included Headers (High-Level):**
    * **`base/run_loop.h`:**  Likely used for managing asynchronous operations, which are common in media encoding.
    * **`media/base/mock_filters.h`:** Hints at mocking media-related components.
    * **`media/video/video_encoder_info.h`:** Suggests the tests will interact with video encoder information.
    * **`third_party/blink/public/platform/...`:** Platform-level Blink utilities, possibly for task scheduling.
    * **`third_party/blink/renderer/bindings/...`:**  These are crucial. They indicate interaction with JavaScript bindings. Specifically, the inclusion of `v8_video_encoder_config.h`, `v8_video_encoder_encode_options.h`, `v8_video_encoder_init.h`, and the `Union` type involving various HTML and canvas elements strongly points to testing the WebCodecs API's JavaScript interface.
    * **`third_party/blink/renderer/core/html/canvas/...` and `third_party/blink/renderer/core/imagebitmap/...`:** These indicate testing scenarios involving canvas and ImageBitmap objects as input to the video encoder.
    * **`third_party/blink/renderer/modules/webcodecs/...`:**  Confirms this test file is specifically for the WebCodecs implementation within Blink.
    * **`third_party/blink/renderer/platform/...`:** Platform-level testing utilities.

4. **Analyze the Test Structure:**
    * **Namespaces:**  The code is within the `blink` namespace, and further within an anonymous namespace for internal organization.
    * **Helper Functions:**  The presence of `CreateConfig`, `CreateEncoder`, `CreateMockEncoder`, `CreateInit`, and `MakeVideoFrame` suggests these are utility functions to set up common test scenarios and objects. Pay close attention to what they create – `VideoEncoderConfig`, `VideoEncoderInit`, `VideoFrame`, and mock versions of `VideoEncoder`.
    * **`MockVideoEncoder` Class:** This is a key element. It inherits from `VideoEncoder` and uses `MOCK_METHOD` to define mockable methods for interacting with the underlying media encoder. This is how the tests control and verify the behavior of the real encoder. The `CallOnMediaEncoderInfoChanged` is an interesting workaround due to access restrictions.
    * **`VideoEncoderTest` Class:** This is the main test fixture. It inherits from `testing::Test`, providing the basic setup and teardown for tests. The `task_environment_` member is common in Blink tests for managing asynchronous tasks.
    * **Individual `TEST_F` Macros:** Each `TEST_F` defines a specific test case. Read the names of these tests carefully. They often describe the scenario being tested (e.g., `RejectFlushAfterClose`, `CodecReclamation`, `ConfigureAndEncode_...`).

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript API:** The included binding headers (`v8_...`) are the direct link. The tests are verifying how the C++ `VideoEncoder` interacts with the JavaScript `VideoEncoder` API exposed through WebCodecs. The test names often reflect API methods like `configure`, `encode`, `flush`, and `close`.
    * **HTML Elements:** The `Union_CSSImageValue_HTMLCanvasElement...` header indicates that the JavaScript `VideoEncoder` can accept various HTML elements (like `<canvas>`, `<img>`, `<video>`) as input via methods like `encode`. The `MakeVideoFrame` function demonstrates creating a `VideoFrame` from an `ImageBitmap`, which can originate from a `<canvas>`.
    * **CSS (Indirect):** While not directly tested here, CSS affects the visual presentation of HTML elements like `<canvas>`. The content drawn on a canvas, styled by CSS, can then be encoded by the `VideoEncoder`.

6. **Analyze Individual Test Cases (Examples):**
    * **`RejectFlushAfterClose`:** This test checks that calling `flush()` after `close()` on the JavaScript `VideoEncoder` results in a rejected promise, as expected.
    * **`CodecReclamation`:**  This test focuses on how the `VideoEncoder` interacts with the `CodecPressureManager`. It simulates backgrounding and checks if the encoder correctly applies or releases pressure based on whether a hardware or software encoder is used. This is related to browser resource management and optimization.
    * **`ConfigureAndEncode_...`:** This test verifies that when `configure()` and `encode()` are called on the JavaScript side, the corresponding C++ `VideoEncoder` methods are invoked, including the `VideoEncoderMetricsProvider` for tracking encoder usage. It shows the interaction between JavaScript calls and the underlying C++ implementation.

7. **Identify Potential User Errors:**
    * **Calling `flush()` after `close()`:** The `RejectFlushAfterClose` test directly addresses this. It's a common sequence of operations, and the test ensures the API handles it correctly.
    * **Incorrect configuration:** The tests involving `CreateConfig()` and calls to `configure()` implicitly test that providing valid configurations works. While not explicitly testing *invalid* configurations, the framework is in place to add such tests. A user might provide unsupported codec parameters, invalid dimensions, etc.
    * **Encoding before configuring:** Although not a specific test here, the structure of the tests suggests the correct order of operations is important (`configure` then `encode`). Encoding without configuring would likely lead to errors.

8. **Trace User Operations (Debugging Clues):**
    * To reach the `video_encoder_test.cc` code, a developer would typically be:
        1. **Working on the WebCodecs implementation in Chromium.**
        2. **Implementing new features or fixing bugs related to video encoding.**
        3. **Writing or running unit tests to ensure the `VideoEncoder` class behaves correctly.**
    * A user interacting with WebCodecs through a web page:
        1. **A website uses the JavaScript WebCodecs API (specifically `VideoEncoder`).**
        2. **The JavaScript code creates a `VideoEncoder` object.**
        3. **The website configures the encoder (using `configure()`).** This maps to the `encoder->configure(config, es);` call in the tests.
        4. **The website provides video frames for encoding (using `encode()`).** This maps to `encoder->encode(...)`.
        5. **The encoder outputs encoded video chunks via the `output` callback.** This is tested using `mock_function.ExpectCall()`.
        6. **The website might call `flush()` to ensure all pending frames are encoded.**
        7. **The website might call `close()` to release encoder resources.**

By following these steps, you can gain a comprehensive understanding of the functionality of this test file, its relationship to web technologies, and its role in the development and debugging of the Chromium browser.
这个文件 `video_encoder_test.cc` 是 Chromium Blink 引擎中 WebCodecs API 中 `VideoEncoder` 接口的单元测试文件。它的主要功能是：

**1. 测试 `VideoEncoder` 类的各种功能和行为:**

   - **配置 (configure):** 测试使用不同的配置参数初始化 `VideoEncoder` 是否成功，包括不同的编解码器 (codec)、分辨率 (width, height) 等。
   - **编码 (encode):** 测试向 `VideoEncoder` 提供视频帧 (VideoFrame) 进行编码是否能正常工作，并产生预期的输出。
   - **刷新 (flush):** 测试 `flush` 方法，确保所有待处理的帧都被编码并输出。
   - **关闭 (close):** 测试 `close` 方法，确保释放所有相关资源。
   - **错误处理 (error callback):** 测试在编码过程中发生错误时，错误回调函数是否被正确调用。
   - **事件通知 (output callback):** 测试编码后的数据块是否通过输出回调函数正确地传递给 JavaScript。
   - **编解码器压力管理 (Codec Pressure Manager):** 测试 `VideoEncoder` 如何与编解码器压力管理器交互，在系统资源紧张时释放资源。
   - **指标收集 (VideoEncoderMetricsProvider):** 测试 `VideoEncoder` 是否正确地收集和上报编码相关的指标数据。

**2. 模拟各种场景和边界情况:**

   - 测试在 `close` 之后调用 `flush` 是否会产生预期的行为（例如，Promise 被拒绝）。
   - 测试在后台状态下，`VideoEncoder` 是否能正确处理资源回收。
   - 测试配置失败的情况。
   - 测试没有可用的硬件加速编码器的情况。

**它与 JavaScript, HTML, CSS 的功能关系:**

`VideoEncoder` 是 WebCodecs API 的一部分，这个 API 允许 JavaScript 代码访问底层的音视频编解码能力。因此，`video_encoder_test.cc` 中的测试直接关联到 JavaScript 中 `VideoEncoder` 对象的使用。

**举例说明:**

* **JavaScript:**  JavaScript 代码可以通过 `new VideoEncoder(init)` 创建一个 `VideoEncoder` 实例，并通过 `configure(config)` 方法设置编码参数，使用 `encode(frame, options)` 方法对视频帧进行编码。测试文件中的代码模拟了这些 JavaScript 调用，并验证其行为。

   ```javascript
   // JavaScript 示例
   const encoder = new VideoEncoder({
     output: (chunk) => {
       // 处理编码后的数据块
       console.log('Encoded chunk:', chunk);
     },
     error: (e) => {
       console.error('Encoding error:', e);
     }
   });

   encoder.configure({
     codec: 'vp8',
     width: 80,
     height: 60
   });

   const videoFrame = new VideoFrame(canvasOrVideoElement, { timestamp: 0 });
   encoder.encode(videoFrame);
   videoFrame.close();

   encoder.flush().then(() => {
     encoder.close();
   });
   ```

* **HTML:** HTML 可以提供作为视频源的元素，例如 `<canvas>` 或 `<video>` 元素。JavaScript 可以从这些元素中获取视频帧，并传递给 `VideoEncoder` 进行编码。测试文件中的 `MakeVideoFrame` 函数就模拟了从 `ImageBitmap`（它可以来源于 `<canvas>` 或 `<img>`）创建 `VideoFrame` 的过程。

   ```html
   <!-- HTML 示例 -->
   <canvas id="myCanvas" width="80" height="60"></canvas>
   <script>
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.fillStyle = 'red';
     ctx.fillRect(0, 0, 80, 60);

     const encoder = new VideoEncoder({...});
     encoder.configure({...});
     const frame = new VideoFrame(canvas, { timestamp: 0 });
     encoder.encode(frame);
     frame.close();
   </script>
   ```

* **CSS:** CSS 负责控制 HTML 元素的样式和布局。虽然 CSS 本身不直接与 `VideoEncoder` 交互，但 CSS 样式会影响 `<canvas>` 元素的渲染结果，从而间接影响 `VideoEncoder` 编码的内容。例如，如果使用 CSS 改变了 `<canvas>` 的背景色，那么编码后的视频帧也会反映出这个颜色变化。

**逻辑推理与假设输入输出:**

**例子 1: 测试 `RejectFlushAfterClose`**

* **假设输入:**
    1. 创建一个 `VideoEncoder` 实例。
    2. 配置该编码器。
    3. 对一个视频帧进行编码。
    4. 调用 `close()` 方法关闭编码器。
    5. 再次调用 `flush()` 方法。
* **预期输出:**
    - 第二次 `flush()` 调用返回的 Promise 应该被拒绝 (rejected)。

**例子 2: 测试 `CodecReclamation` (编解码器回收)**

* **假设输入:**
    1. 创建一个 `VideoEncoder` 实例。
    2. 将浏览器窗口切换到后台 (模拟资源紧张)。
    3. 配置编码器使用硬件加速的编解码器。
* **预期输出:**
    - `VideoEncoder` 应该会请求编解码器压力管理器分配资源 (is_applying_codec_pressure() 返回 true)。
    - 当重新配置编码器使用软件编解码器后，`VideoEncoder` 应该释放之前请求的资源 (is_applying_codec_pressure() 返回 false)。

**用户或编程常见的使用错误:**

* **在 `VideoEncoder` 未配置之前调用 `encode`:**  这会导致错误，因为编码器不知道如何处理输入的视频帧。测试代码通常会先调用 `configure` 再调用 `encode` 来模拟正确的用法。
* **在 `close` 之后继续调用 `encode` 或 `flush`:**  `close` 方法会释放资源，之后的操作应该被禁止。`RejectFlushAfterClose` 测试就覆盖了这种情况。
* **提供不支持的编解码器或配置参数:**  `configure` 方法会进行参数校验，如果参数无效，会触发错误回调。测试代码会尝试使用不同的配置来验证这种错误处理机制。
* **忘记处理 `output` 回调返回的编码数据块:**  这是 JavaScript 使用 WebCodecs 时的常见错误。测试代码中的 `mock_function.ExpectCall()` 用于验证输出回调是否被调用。
* **忘记处理 `error` 回调:**  忽略错误回调可能导致应用程序无法感知编码过程中发生的错误。测试代码中的 `mock_function.ExpectNoCall()` 和 `mock_function.ExpectCall()` 用于验证错误回调是否按预期被调用。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个使用 WebCodecs API 的网页。**
2. **网页中的 JavaScript 代码创建了一个 `VideoEncoder` 对象。**
3. **JavaScript 代码调用 `encoder.configure(config)`，传递了编码配置信息。**  如果在这个阶段出现问题，可能是 `video_encoder_test.cc` 中测试配置功能的代码需要被检查。例如，`TEST_F(VideoEncoderTest, CodecReclamation)` 测试了配置过程中的一些逻辑。
4. **JavaScript 代码从 `<canvas>` 或 `<video>` 元素中获取视频帧，并调用 `encoder.encode(videoFrame)` 进行编码。** 如果编码过程出现问题，可能是 `video_encoder_test.cc` 中测试编码功能的代码需要被检查，例如 `TEST_F(VideoEncoderTest, ConfigureAndEncode_CallVideoEncoderMetricsProviderInitializeAndIncrementEncodedFrameCount)`。`MakeVideoFrame` 函数模拟了创建 `VideoFrame` 的过程。
5. **编码完成后，`VideoEncoder` 会调用 JavaScript 代码中 `init` 对象里设置的 `output` 回调函数，传递编码后的数据块。** 如果数据没有正确输出，可能是 `video_encoder_test.cc` 中测试输出回调的部分需要被检查。
6. **如果编码过程中发生错误，`VideoEncoder` 会调用 `error` 回调函数。**  相关的测试用例会验证错误回调是否被正确触发。
7. **JavaScript 代码可能会调用 `encoder.flush()` 来确保所有缓冲的帧都被编码。**  `TEST_F(VideoEncoderTest, RejectFlushAfterClose)` 测试了 `flush` 的行为。
8. **最后，JavaScript 代码会调用 `encoder.close()` 来释放资源。**

当开发者在 Chromium 中开发或调试 WebCodecs 的 `VideoEncoder` 功能时，他们会运行 `video_encoder_test.cc` 中的测试用例来验证他们的代码是否正确工作。如果某个测试用例失败，开发者会查看测试代码，理解失败场景，并检查 `blink/renderer/modules/webcodecs/video_encoder.cc` 中的实现代码，找出错误的原因。测试用例也作为回归测试，防止未来的代码更改引入新的 bug。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"

#include "base/run_loop.h"
#include "media/base/mock_filters.h"
#include "media/video/video_encoder_info.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_cssimagevalue_htmlcanvaselement_htmlimageelement_htmlvideoelement_imagebitmap_offscreencanvas_svgimageelement_videoframe.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_frame_init.h"
#include "third_party/blink/renderer/core/html/canvas/image_data.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager_provider.h"
#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

using testing::_;
using testing::ByMove;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SaveArg;
using testing::WithArgs;

ACTION_P(RunClosure, closure) {
  scheduler::GetSequencedTaskRunnerForTesting()->PostTask(FROM_HERE,
                                                          std::move(closure));
}

class MockVideoEncoder : public VideoEncoder {
 public:
  MockVideoEncoder(ScriptState* script_state,
                   const VideoEncoderInit* init,
                   ExceptionState& exception_state)
      : VideoEncoder(script_state, init, exception_state) {}
  ~MockVideoEncoder() override = default;

  MOCK_METHOD((media::EncoderStatus::Or<std::unique_ptr<media::VideoEncoder>>),
              CreateMediaVideoEncoder,
              (const ParsedConfig& config,
               media::GpuVideoAcceleratorFactories* gpu_factories,
               bool& is_platform_encoder),
              (override));
  MOCK_METHOD(std::unique_ptr<media::VideoEncoderMetricsProvider>,
              CreateVideoEncoderMetricsProvider,
              (),
              (const));

  // CallOnMediaENcoderInfoChanged() is necessary for VideoEncoderTest to call
  // VideoEncoder::OnMediaEncoderInfoChanged() because the function is a private
  // and VideoEncoderTest is not a friend of VideoEncoder.
  void CallOnMediaEncoderInfoChanged(
      const media::VideoEncoderInfo& encoder_info) {
    VideoEncoder::OnMediaEncoderInfoChanged(encoder_info);
  }
};

class VideoEncoderTest : public testing::Test {
 public:
  VideoEncoderTest() = default;
  ~VideoEncoderTest() override = default;
  test::TaskEnvironment task_environment_;
};

constexpr gfx::Size kEncodeSize(80, 60);

VideoEncoderConfig* CreateConfig() {
  auto* config = MakeGarbageCollected<VideoEncoderConfig>();
  config->setCodec("vp8");
  config->setWidth(kEncodeSize.width());
  config->setHeight(kEncodeSize.height());
  return config;
}

VideoEncoder* CreateEncoder(ScriptState* script_state,
                            const VideoEncoderInit* init,
                            ExceptionState& exception_state) {
  return MakeGarbageCollected<VideoEncoder>(script_state, init,
                                            exception_state);
}

MockVideoEncoder* CreateMockEncoder(ScriptState* script_state,
                                    VideoEncoderInit* init,
                                    ExceptionState& exception_state) {
  return MakeGarbageCollected<MockVideoEncoder>(script_state, init,
                                                exception_state);
}

VideoEncoderInit* CreateInit(ScriptState* script_state,
                             ScriptFunction* output_callback,
                             ScriptFunction* error_callback) {
  auto* init = MakeGarbageCollected<VideoEncoderInit>();
  init->setOutput(V8EncodedVideoChunkOutputCallback::Create(
      output_callback->ToV8Function(script_state)));
  init->setError(V8WebCodecsErrorCallback::Create(
      error_callback->ToV8Function(script_state)));
  return init;
}

VideoFrame* MakeVideoFrame(ScriptState* script_state,
                           int width,
                           int height,
                           int timestamp) {
  std::vector<uint8_t> data(width * height * 4);
  NotShared<DOMUint8ClampedArray> data_u8(DOMUint8ClampedArray::Create(data));

  ImageData* image_data =
      ImageData::Create(data_u8, width, IGNORE_EXCEPTION_FOR_TESTING);

  if (!image_data)
    return nullptr;

  ImageBitmap* image_bitmap = MakeGarbageCollected<ImageBitmap>(
      image_data, std::nullopt, ImageBitmapOptions::Create());

  VideoFrameInit* video_frame_init = VideoFrameInit::Create();
  video_frame_init->setTimestamp(timestamp);

  auto* source = MakeGarbageCollected<V8CanvasImageSource>(image_bitmap);

  return VideoFrame::Create(script_state, source, video_frame_init,
                            IGNORE_EXCEPTION_FOR_TESTING);
}

TEST_F(VideoEncoderTest, RejectFlushAfterClose) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);
  auto* init = CreateInit(script_state, mock_function.ExpectNoCall(),
                          mock_function.ExpectNoCall());
  auto* encoder = CreateEncoder(script_state, init, es);
  ASSERT_FALSE(es.HadException());

  auto* config = CreateConfig();
  encoder->configure(config, es);
  ASSERT_FALSE(es.HadException());
  {
    // We need this to make sure that configuration has completed.
    auto promise = encoder->flush(es);
    ScriptPromiseTester tester(script_state, promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  encoder->encode(
      MakeVideoFrame(script_state, config->width(), config->height(), 1),
      MakeGarbageCollected<VideoEncoderEncodeOptions>(), es);

  ScriptPromiseTester tester(script_state, encoder->flush(es));
  ASSERT_FALSE(es.HadException());
  ASSERT_FALSE(tester.IsFulfilled());
  ASSERT_FALSE(tester.IsRejected());

  encoder->close(es);

  ThreadState::Current()->CollectAllGarbageForTesting();

  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsRejected());
}

TEST_F(VideoEncoderTest, CodecReclamation) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);

  auto& pressure_manager_provider =
      CodecPressureManagerProvider::From(*v8_scope.GetExecutionContext());

  auto* decoder_pressure_manager =
      pressure_manager_provider.GetDecoderPressureManager();
  auto* encoder_pressure_manager =
      pressure_manager_provider.GetEncoderPressureManager();

  // Create a video encoder.
  auto* init = CreateInit(script_state, mock_function.ExpectNoCall(),
                          mock_function.ExpectNoCall());
  auto* encoder = CreateMockEncoder(script_state, init, es);
  ASSERT_FALSE(es.HadException());

  // Simulate backgrounding to enable reclamation.
  if (!encoder->is_backgrounded_for_testing()) {
    encoder->SimulateLifecycleStateForTesting(
        scheduler::SchedulingLifecycleState::kHidden);
    DCHECK(encoder->is_backgrounded_for_testing());
  }

  // Make sure VideoEncoder doesn't apply pressure by default.
  EXPECT_FALSE(encoder->is_applying_codec_pressure());
  ASSERT_EQ(0u, encoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());

  auto* config = CreateConfig();
  {
    base::RunLoop run_loop;
    auto media_encoder = std::make_unique<media::MockVideoEncoder>();
    media::MockVideoEncoder* mock_media_encoder = media_encoder.get();

    EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
        .WillOnce(DoAll(Invoke([encoder = encoder]() {
                          media::VideoEncoderInfo info;
                          info.implementation_name = "MockEncoderName";
                          info.is_hardware_accelerated = true;
                          encoder->CallOnMediaEncoderInfoChanged(info);
                        }),
                        Return(ByMove(std::unique_ptr<media::VideoEncoder>(
                            std::move(media_encoder))))));
    EXPECT_CALL(*encoder, CreateVideoEncoderMetricsProvider())
        .WillOnce(Return(ByMove(
            std::make_unique<media::MockVideoEncoderMetricsProvider>())));
    EXPECT_CALL(*mock_media_encoder, Initialize(_, _, _, _, _))
        .WillOnce(WithArgs<4>(
            Invoke([quit_closure = run_loop.QuitWhenIdleClosure()](
                       media::VideoEncoder::EncoderStatusCB done_cb) {
              scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                  FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                           media::EncoderStatus::Codes::kOk));
              scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                  FROM_HERE, std::move(quit_closure));
            })));

    encoder->configure(config, es);
    ASSERT_FALSE(es.HadException());
    run_loop.Run();
  }

  // Make sure VideoEncoders apply pressure when configured with a HW encoder.
  EXPECT_TRUE(encoder->is_applying_codec_pressure());
  ASSERT_EQ(1u, encoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());

  // Change codec to avoid a pure reconfigure.
  config->setCodec("avc1.42001E");
  {
    base::RunLoop run_loop;

    auto media_encoder = std::make_unique<media::MockVideoEncoder>();
    media::MockVideoEncoder* mock_media_encoder = media_encoder.get();

    EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
        .WillOnce(DoAll(Invoke([encoder = encoder]() {
                          media::VideoEncoderInfo info;
                          info.implementation_name = "MockEncoderName";
                          info.is_hardware_accelerated = false;
                          encoder->CallOnMediaEncoderInfoChanged(info);
                        }),
                        Return(ByMove(std::unique_ptr<media::VideoEncoder>(
                            std::move(media_encoder))))));
    EXPECT_CALL(*mock_media_encoder, Initialize(_, _, _, _, _))
        .WillOnce(WithArgs<4>(
            Invoke([quit_closure = run_loop.QuitWhenIdleClosure()](
                       media::VideoEncoder::EncoderStatusCB done_cb) {
              scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                  FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                           media::EncoderStatus::Codes::kOk));
              scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                  FROM_HERE, std::move(quit_closure));
            })));

    encoder->configure(config, es);
    ASSERT_FALSE(es.HadException());
    run_loop.Run();
  }

  // Make sure the pressure is released when reconfigured with a SW encoder.
  EXPECT_FALSE(encoder->is_applying_codec_pressure());
  ASSERT_EQ(0u, encoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());
}

TEST_F(
    VideoEncoderTest,
    ConfigureAndEncode_CallVideoEncoderMetricsProviderInitializeAndIncrementEncodedFrameCount) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);

  // Create a video encoder.
  auto* init = CreateInit(script_state, mock_function.ExpectCall(),
                          mock_function.ExpectNoCall());
  auto* encoder = CreateMockEncoder(script_state, init, es);

  auto* config = CreateConfig();
  base::RunLoop run_loop;
  media::VideoEncoder::OutputCB output_cb;
  auto media_encoder = std::make_unique<media::MockVideoEncoder>();
  media::MockVideoEncoder* mock_media_encoder = media_encoder.get();
  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_encoder_metrics_provider =
      encoder_metrics_provider.get();
  EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
      .WillOnce(DoAll(Invoke([encoder = encoder]() {
                        media::VideoEncoderInfo info;
                        info.implementation_name = "MockEncoderName";
                        info.is_hardware_accelerated = false;
                        encoder->CallOnMediaEncoderInfoChanged(info);
                      }),
                      Return(ByMove(std::unique_ptr<media::VideoEncoder>(
                          std::move(media_encoder))))));
  EXPECT_CALL(*encoder, CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(ByMove(std::move(encoder_metrics_provider))));
  EXPECT_CALL(
      *mock_encoder_metrics_provider,
      MockInitialize(media::VideoCodecProfile::VP8PROFILE_ANY, kEncodeSize,
                     false, media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_media_encoder, Initialize(_, _, _, _, _))
      .WillOnce(DoAll(
          SaveArg<3>(&output_cb),
          WithArgs<4>(Invoke([quit_closure = run_loop.QuitWhenIdleClosure()](
                                 media::VideoEncoder::EncoderStatusCB done_cb) {
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                         media::EncoderStatus::Codes::kOk));
          }))));
  encoder->configure(config, es);
  EXPECT_CALL(*mock_media_encoder, Encode(_, _, _))
      .WillOnce(
          WithArgs<2>(Invoke([output_cb = &output_cb](
                                 media::VideoEncoder::EncoderStatusCB done_cb) {
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                         media::EncoderStatus::Codes::kOk));
            media::VideoEncoderOutput out;
            out.data = base::HeapArray<uint8_t>::Uninit(100);
            out.key_frame = true;
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE,
                WTF::BindOnce(*output_cb, std::move(out), std::nullopt));
          })));

  EXPECT_CALL(*mock_encoder_metrics_provider, MockIncrementEncodedFrameCount())
      .WillOnce([quit_closure = run_loop.QuitWhenIdleClosure()] {
        scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
            FROM_HERE, std::move(quit_closure));
      });
  encoder->encode(
      MakeVideoFrame(script_state, config->width(), config->height(), 1),
      MakeGarbageCollected<VideoEncoderEncodeOptions>(), es);
  run_loop.Run();
}

TEST_F(VideoEncoderTest,
       ConfigureTwice_CallVideoEncoderMetricsProviderInitializeTwice) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);

  // Create a video encoder.
  auto* init = CreateInit(script_state, mock_function.ExpectNoCall(),
                          mock_function.ExpectNoCall());
  auto* encoder = CreateMockEncoder(script_state, init, es);

  auto* config = CreateConfig();
  base::RunLoop run_loop;
  media::VideoEncoder::OutputCB output_cb;
  auto media_encoder = std::make_unique<media::MockVideoEncoder>();
  media::MockVideoEncoder* mock_media_encoder = media_encoder.get();
  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_encoder_metrics_provider =
      encoder_metrics_provider.get();
  EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
      .WillOnce(DoAll(Invoke([encoder = encoder]() {
                        media::VideoEncoderInfo info;
                        info.implementation_name = "MockEncoderName";
                        info.is_hardware_accelerated = false;
                        encoder->CallOnMediaEncoderInfoChanged(info);
                      }),
                      Return(ByMove(std::unique_ptr<media::VideoEncoder>(
                          std::move(media_encoder))))));
  EXPECT_CALL(*encoder, CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(ByMove(std::move(encoder_metrics_provider))));
  EXPECT_CALL(
      *mock_encoder_metrics_provider,
      MockInitialize(media::VideoCodecProfile::VP8PROFILE_ANY, kEncodeSize,
                     false, media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_media_encoder, Initialize(_, _, _, _, _))
      .WillOnce(DoAll(
          SaveArg<3>(&output_cb),
          WithArgs<4>(Invoke([](media::VideoEncoder::EncoderStatusCB done_cb) {
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                         media::EncoderStatus::Codes::kOk));
          }))));
  encoder->configure(config, es);
  EXPECT_CALL(*mock_media_encoder, Flush(_))
      .WillOnce([](media::VideoEncoder::EncoderStatusCB done_cb) {
        scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
            FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                     media::EncoderStatus::Codes::kOk));
      });
  EXPECT_CALL(
      *mock_encoder_metrics_provider,
      MockInitialize(media::VideoCodecProfile::VP8PROFILE_ANY, kEncodeSize,
                     false, media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_media_encoder, ChangeOptions(_, _, _))
      .WillOnce(
          WithArgs<2>(Invoke([quit_closure = run_loop.QuitWhenIdleClosure()](
                                 media::VideoEncoder::EncoderStatusCB done_cb) {
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE, WTF::BindOnce(std::move(done_cb),
                                         media::EncoderStatus::Codes::kOk));
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE, std::move(quit_closure));
          })));
  encoder->configure(config, es);
  run_loop.Run();
}

TEST_F(VideoEncoderTest,
       InitializeFailure_CallVideoEncoderMetricsProviderSetError) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);

  // Create a video encoder.
  auto* init = CreateInit(script_state, mock_function.ExpectNoCall(),
                          mock_function.ExpectCall());
  auto* encoder = CreateMockEncoder(script_state, init, es);

  auto* config = CreateConfig();
  base::RunLoop run_loop;
  media::VideoEncoder::OutputCB output_cb;
  auto media_encoder = std::make_unique<media::MockVideoEncoder>();
  media::MockVideoEncoder* mock_media_encoder = media_encoder.get();
  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_encoder_metrics_provider =
      encoder_metrics_provider.get();
  EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
      .WillOnce(DoAll(Invoke([encoder = encoder]() {
                        media::VideoEncoderInfo info;
                        info.implementation_name = "MockEncoderName";
                        info.is_hardware_accelerated = false;
                        encoder->CallOnMediaEncoderInfoChanged(info);
                      }),
                      Return(ByMove(std::unique_ptr<media::VideoEncoder>(
                          std::move(media_encoder))))));
  EXPECT_CALL(*encoder, CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(ByMove(std::move(encoder_metrics_provider))));
  EXPECT_CALL(
      *mock_encoder_metrics_provider,
      MockInitialize(media::VideoCodecProfile::VP8PROFILE_ANY, kEncodeSize,
                     false, media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_media_encoder, Initialize(_, _, _, _, _))
      .WillOnce(
          WithArgs<4>(Invoke([quit_closure = run_loop.QuitWhenIdleClosure()](
                                 media::VideoEncoder::EncoderStatusCB done_cb) {
            scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
                FROM_HERE,
                WTF::BindOnce(
                    std::move(done_cb),
                    media::EncoderStatus::Codes::kEncoderUnsupportedConfig));
          })));
  EXPECT_CALL(*mock_encoder_metrics_provider, MockSetError(_))
      .WillOnce(RunClosure(run_loop.QuitWhenIdleClosure()));
  encoder->configure(config, es);
  run_loop.Run();
}

TEST_F(VideoEncoderTest, NoAvailableMediaVideoEncoder) {
  V8TestingScope v8_scope;
  auto& es = v8_scope.GetExceptionState();
  auto* script_state = v8_scope.GetScriptState();

  MockFunctionScope mock_function(script_state);

  // Create a video encoder.
  auto* init = CreateInit(script_state, mock_function.ExpectNoCall(),
                          mock_function.ExpectCall());
  auto* encoder = CreateMockEncoder(script_state, init, es);
  auto* config = CreateConfig();
  EXPECT_CALL(*encoder, CreateMediaVideoEncoder(_, _, _))
      .WillOnce(Return(media::EncoderStatus(
          media::EncoderStatus::Codes::kEncoderUnsupportedProfile)));
  encoder->configure(config, es);
}
}  // namespace

}  // namespace blink
```
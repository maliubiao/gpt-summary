Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Understand the Core Purpose:** The filename `video_decoder_test.cc` immediately tells us this file contains tests for a `VideoDecoder` class. Since it's in the `blink/renderer/modules/webcodecs` directory, we know this `VideoDecoder` is related to the WebCodecs API in the Chromium rendering engine.

2. **Identify Key Components:** Scan the `#include` directives and the code within the namespaces (`blink` and the anonymous one). This reveals the key players:
    * `VideoDecoder`: The central class being tested.
    * `VideoDecoderInit`, `VideoDecoderConfig`, `VideoDecoderSupport`:  Configuration and support classes for `VideoDecoder`. These often correspond directly to JavaScript API objects.
    * `FakeVideoDecoder`: A custom mock implementation of `VideoDecoder` used for testing. This is a common pattern in unit testing.
    * `media::MockVideoDecoder`: A mock from the `media` library, indicating that the `VideoDecoder` in WebCodecs interacts with a lower-level media decoding component.
    * `ScriptState`, `V8TestingScope`, `ScriptPromiseTester`:  Tools for testing JavaScript integration.
    * `CodecPressureManager`, `CodecPressureManagerProvider`: Components related to managing resource pressure related to codecs.
    * `testing::gmock`, `testing::gtest`: The Google Mock and Google Test frameworks used for writing the tests.
    * `base::RunLoop`: For managing asynchronous operations in tests.

3. **Analyze the `FakeVideoDecoder`:** This is crucial for understanding the test setup. Notice its methods:
    * `SetupMockHardwareDecoder`: Configures the mock to simulate a hardware decoder.
    * `SetupMockSoftwareDecoder`: Configures the mock to simulate a software decoder.
    * `SetupExpectations`: Sets up expectations on the `media::MockVideoDecoder` (e.g., what methods will be called, what they will return). The `EXPECT_CALL` macros are key here.
    * The overridden `decoder()` method returns the `media::MockVideoDecoder`.

4. **Analyze the Test Fixture (`VideoDecoderTest`):**  This class provides helper methods to create test objects:
    * `CreateFakeDecoder`: Creates instances of the `FakeVideoDecoder`.
    * `CreateVideoDecoderInit`, `CreateVideoConfig`: Create instances of the configuration objects. These likely mirror the JavaScript API.
    * `ToVideoDecoderSupport`: Converts a JavaScript value to a `VideoDecoderSupport` object.

5. **Examine the Individual Tests:** Each `TEST_F` macro defines a test case. Analyze what each test does:
    * `HardwareDecodersApplyPressure`: Tests that using a hardware decoder increases the codec pressure and switching to software releases it. This hints at resource management considerations.
    * `ResetReleasesPressure`: Tests that resetting the decoder, even if the underlying codec isn't immediately released, eventually leads to the release of codec pressure. This suggests asynchronous behavior and resource reclamation.
    * `isConfigureSupportedWithInvalidSWConfig`, `isConfigureSupportedWithInvalidHWConfig`: Tests the `isConfigSupported` static method with invalid codec strings for both software and hardware preferences. This focuses on the API's validation of configuration.

6. **Relate to JavaScript, HTML, CSS:**  Based on the components and tests, make the connections:
    * **JavaScript:** The `VideoDecoder` class and its configuration objects directly correspond to the JavaScript `VideoDecoder` API. The tests use `ScriptState`, `ScriptPromiseTester`, and interact with V8 values, confirming this connection. The callbacks (`output`, `error`) are also JavaScript functions.
    * **HTML:**  While this specific test file doesn't directly interact with HTML, the `VideoDecoder` is used by JavaScript code running within a web page. The decoding process could be triggered by `<video>` elements or other media-related APIs.
    * **CSS:**  CSS doesn't directly control the video *decoding* process. However, CSS *can* affect the *rendering* of the decoded video frames (e.g., sizing, positioning).

7. **Logical Inference and Examples:**  For each test, think about the expected inputs and outputs:
    * **Input:** Configuration objects (codec string, hardware preference), actions like `configure()` and `reset()`.
    * **Output:** Changes in codec pressure, the result of `isConfigSupported` (supported/not supported).

8. **Common Usage Errors:**  Consider how a developer might misuse the `VideoDecoder` API based on the tests:
    * Incorrect codec strings.
    * Not handling asynchronous operations correctly (promises).
    * Misunderstanding resource management (pressure).

9. **User Operations and Debugging:** Trace how a user interaction might lead to this code being executed:
    * User visits a webpage with video content.
    * The browser attempts to decode the video using the `VideoDecoder`.
    * If there are issues, developers might need to debug the configuration, decoding process, and resource usage, potentially leading them to these unit tests to understand the expected behavior.

10. **Refine and Organize:** Structure the analysis logically, covering the functionality, JavaScript relationship, logical inferences, common errors, and debugging aspects. Use clear language and provide concrete examples.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe the tests directly render video frames. **Correction:** The tests focus on the *decoder's* logic, configuration, and resource management, using mocks for the actual decoding. Frame rendering would likely be in other test files.
* **Initial thought:**  The connection to HTML/CSS is very direct. **Correction:** The connection is through the JavaScript API that interacts with the DOM and CSS. The C++ code itself doesn't manipulate HTML or CSS.
* **Ensuring completeness:** Have I covered all the main aspects of the file? Have I provided concrete examples for each point?

By following these steps, combining code analysis with understanding the context of WebCodecs and browser architecture, one can arrive at a comprehensive explanation of the test file's purpose and its connections to the broader web development landscape.
这个文件 `video_decoder_test.cc` 是 Chromium Blink 引擎中 `webcodecs` 模块下的一个 C++ 单元测试文件。它的主要功能是测试 `VideoDecoder` 类的各种功能和行为。

以下是对其功能的详细列举，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、用户错误和调试线索的说明：

**文件功能：**

1. **测试 `VideoDecoder` 的配置 (Configuration):**
   - 测试 `configure()` 方法，验证不同的 `VideoDecoderConfig` 是否能被正确处理，包括硬件加速和软件解码的情况。
   - 测试 `isConfigSupported()` 静态方法，验证其能否正确判断给定的 `VideoDecoderConfig` 是否被支持。
   - 使用 `FakeVideoDecoder` 模拟硬件和软件解码器，来验证配置过程中的行为。

2. **测试资源压力管理 (Codec Pressure Management):**
   - 测试当配置硬件解码器时，`VideoDecoder` 是否会向 `CodecPressureManager` 施加压力。
   - 测试当重新配置为软件解码器时，之前施加的压力是否会被释放。
   - 测试 `reset()` 方法是否能触发压力的释放。
   - 模拟生命周期状态和全局压力标志来触发资源回收，并验证压力释放的行为。

3. **模拟解码过程 (Decoding Simulation):**
   - 使用 `FakeVideoDecoder` 和 `media::MockVideoDecoder` 来模拟实际的解码过程，但并不真正进行视频解码。
   - 设置 `EXPECT_CALL` 来验证在配置和解码过程中，底层的 `media::MockVideoDecoder` 的特定方法是否被调用，并模拟其行为（例如，初始化成功，解码完成）。

4. **测试异步操作:**
   - 使用 `base::RunLoop` 来等待异步操作完成，例如解码器的初始化。
   - 测试基于 Promise 的 `isConfigSupported()` 方法的异步行为。

**与 JavaScript, HTML, CSS 的关系：**

`VideoDecoder` 是 WebCodecs API 的一部分，它直接暴露给 JavaScript。这个测试文件验证了 C++ 层 `VideoDecoder` 的行为，确保其与 JavaScript API 的预期一致。

* **JavaScript:**
    - 用户在 JavaScript 中会创建 `VideoDecoder` 的实例。
    - 使用 `configure()` 方法传入 `VideoDecoderConfig` 对象来配置解码器。
    - 使用 `decode()` 方法传入 `EncodedVideoChunk` 进行解码。
    - 监听 `output` 事件接收解码后的 `VideoFrame`。
    - 监听 `error` 事件处理解码过程中出现的错误。

    **举例说明：**
    ```javascript
    const decoder = new VideoDecoder({
      output(frame) {
        // 处理解码后的帧
        console.log('解码成功', frame);
        frame.close();
      },
      error(e) {
        console.error('解码失败', e);
      }
    });

    const config = {
      codec: 'vp09.00.10.08', // 视频编解码器
      // ...其他配置
    };

    decoder.configure(config);

    // 假设 encodedChunk 是一个 EncodedVideoChunk 对象
    decoder.decode(encodedChunk);
    ```
    这个测试文件中的 `CreateVideoConfig()` 方法创建的 `VideoDecoderConfig` 对象，以及 `VideoDecoderInit` 中设置的 `output` 和 `error` 回调，都直接对应着 JavaScript 中的 `VideoDecoder` 构造函数参数和配置对象。

* **HTML:**
    - `<video>` 元素可以作为解码后视频帧的渲染目标。
    - JavaScript 可以获取视频流数据，然后使用 `VideoDecoder` 进行解码，并将解码后的帧渲染到 `<canvas>` 或 `<video>` 元素上。

    **举例说明：**
    用户操作点击播放按钮，JavaScript 代码获取视频流数据，并通过 `VideoDecoder` 解码，然后将解码后的帧绘制到 `<canvas>` 上。

* **CSS:**
    - CSS 可以用来控制 `<video>` 或 `<canvas>` 元素的样式和布局，从而影响解码后视频的显示效果。
    - CSS 无法直接影响 `VideoDecoder` 的解码过程。

**逻辑推理（假设输入与输出）：**

**测试用例：`HardwareDecodersApplyPressure`**

* **假设输入：**
    1. 创建一个 `FakeVideoDecoder` 实例。
    2. 使用 `SetupMockHardwareDecoder` 设置模拟硬件解码器。
    3. 使用有效的 `VideoDecoderConfig` (例如，`vp09.00.10.08`) 调用 `configure()`。
* **预期输出：**
    1. 配置后，`fake_decoder->is_applying_codec_pressure()` 返回 `true`。
    2. `decoder_pressure_manager->pressure_for_testing()` 的值增加。
    3. 随后，使用 `SetupMockSoftwareDecoder` 设置模拟软件解码器并再次调用 `configure()`。
    4. 重新配置后，`fake_decoder->is_applying_codec_pressure()` 返回 `false`。
    5. `decoder_pressure_manager->pressure_for_testing()` 的值恢复到之前的状态。

**测试用例：`isConfigureSupportedWithInvalidSWConfig`**

* **假设输入：**
    1. 创建一个 `VideoDecoderConfig` 实例，并将 `codec` 设置为无效的值（例如，"invalid video codec"）。
    2. 设置 `hardwareAcceleration` 为 `V8HardwarePreference::Enum::kPreferSoftware`。
    3. 调用 `VideoDecoder::isConfigSupported()`。
* **预期输出：**
    1. `isConfigSupported()` 返回的 Promise 会 resolve。
    2. Promise 的结果 (`VideoDecoderSupport`) 的 `supported()` 属性为 `false`。

**用户或编程常见的使用错误：**

1. **无效的编解码器字符串 (Invalid Codec String):** 用户在 JavaScript 中配置 `VideoDecoder` 时，使用了浏览器不支持的 `codec` 字符串。这会导致 `configure()` 方法抛出错误，或者 `isConfigSupported()` 返回 `false`。
   ```javascript
   const config = { codec: 'unsupported-codec' };
   decoder.configure(config); // 可能抛出异常
   ```
   这个测试文件中的 `isConfigureSupportedWithInvalidSWConfig` 和 `isConfigureSupportedWithInvalidHWConfig` 就模拟了这种情况。

2. **未处理异步操作:**  `configure()` 方法可能涉及异步操作。如果在配置完成前就调用 `decode()`，可能会导致错误或未定义的行为。开发者需要确保在 `configure()` 完成后（例如，在 `output` 或 `error` 回调被调用后）再进行解码操作。

3. **资源泄漏:**  如果 `VideoFrame` 对象在使用后没有调用 `close()` 方法释放资源，可能会导致内存泄漏。虽然这个测试文件不直接测试资源泄漏，但它测试了资源压力管理，这与资源泄漏问题相关。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户访问包含视频的网页:** 用户在浏览器中打开一个包含 `<video>` 元素或者使用 WebCodecs API 进行视频处理的网页。

2. **JavaScript 代码尝试解码视频:** 网页上的 JavaScript 代码使用 `VideoDecoder` API 来解码视频流数据。这可能发生在：
   - `<video>` 元素尝试解码视频源。
   - JavaScript 代码显式创建 `VideoDecoder` 实例并调用其方法。

3. **配置解码器 (`configure()`):** JavaScript 代码调用 `decoder.configure(config)`，将配置信息传递给底层的 C++ `VideoDecoder` 对象。

4. **C++ `VideoDecoder` 的创建和初始化:**  Blink 引擎会创建 `VideoDecoder` 的 C++ 对象，并根据传入的配置信息进行初始化。

5. **选择硬件或软件解码器:** `VideoDecoder` 根据配置和系统能力，可能会选择使用硬件加速解码器或软件解码器。这个测试文件中的 `FakeVideoDecoder` 可以模拟这两种情况。

6. **解码过程 (`decode()`):** JavaScript 代码调用 `decoder.decode(encodedChunk)`，将编码后的视频块传递给 C++ 层进行解码。

7. **测试文件的作用 (调试线索):**
   - **如果用户遇到视频解码失败的问题，开发者可能会怀疑是解码器配置错误或解码过程中的错误。**
   - **开发者可能会查看 `video_decoder_test.cc` 文件，了解 `VideoDecoder` 的预期行为，以及如何正确配置和使用它。**
   - **例如，如果怀疑是编解码器字符串错误导致解码失败，开发者可以参考 `isConfigureSupportedWithInvalidSWConfig` 测试用例，了解对于无效的编解码器，`isConfigSupported()` 应该返回 `false`。**
   - **如果怀疑是资源压力导致解码问题，可以参考 `HardwareDecodersApplyPressure` 和 `ResetReleasesPressure` 测试用例，了解 `VideoDecoder` 如何管理资源压力。**
   - **当开发者在 Chromium 引擎中修改了 `VideoDecoder` 的相关代码后，他们会运行这些单元测试来确保修改没有引入 bug，并且 `VideoDecoder` 的行为仍然符合预期。**

总而言之，`video_decoder_test.cc` 是一个关键的测试文件，用于确保 Chromium 中 `VideoDecoder` 类的功能正确性和稳定性，它直接关系到 WebCodecs API 的正常工作，并为开发者提供了理解和调试视频解码相关问题的线索。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/video_decoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_decoder.h"

#include "base/run_loop.h"
#include "build/build_config.h"
#include "media/base/mock_filters.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_support.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager_provider.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

// For FakeVideoDecoder.
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
#include "media/filters/h264_to_annex_b_bitstream_converter.h"  // nogncheck
#include "media/formats/mp4/box_definitions.h"                  // nogncheck
#endif

namespace blink {

namespace {

using testing::_;
using testing::Unused;

class FakeVideoDecoder : public VideoDecoder {
 public:
  FakeVideoDecoder(ScriptState* script_state,
                   const VideoDecoderInit* init,
                   ExceptionState& exception_state)
      : VideoDecoder(script_state, init, exception_state) {}
  ~FakeVideoDecoder() override = default;

  void SetupMockHardwareDecoder(base::RepeatingClosure quit_closure) {
    mock_decoder_ = std::make_unique<media::MockVideoDecoder>(
        /*is_platform_decoder=*/true, /*supports_decription=*/false,
        /*decoder_id=*/1);
    SetupExpectations(std::move(quit_closure));
  }

  void SetupMockSoftwareDecoder(base::RepeatingClosure quit_closure) {
    mock_decoder_ = std::make_unique<media::MockVideoDecoder>(
        /*is_platform_decoder=*/false, /*supports_decription=*/false,
        /*decoder_id=*/2);
    SetupExpectations(std::move(quit_closure));
  }

 private:
  void SetHardwarePreference(HardwarePreference preference) override {}

  void SetupExpectations(base::RepeatingClosure quit_closure) {
    EXPECT_CALL(*mock_decoder_, GetMaxDecodeRequests())
        .WillRepeatedly(testing::Return(4));

    EXPECT_CALL(*mock_decoder_, Decode_(_, _))
        .WillOnce([](Unused, media::VideoDecoder::DecodeCB& decode_cb) {
          scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
              FROM_HERE,
              WTF::BindOnce(std::move(decode_cb), media::OkStatus()));
        });

    EXPECT_CALL(*mock_decoder_, Initialize_(_, _, _, _, _, _))
        .WillOnce([quit_closure](Unused, Unused, Unused,
                                 media::VideoDecoder::InitCB& init_cb, Unused,
                                 Unused) {
          scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
              FROM_HERE, WTF::BindOnce(std::move(init_cb), media::OkStatus()));
          scheduler::GetSequencedTaskRunnerForTesting()->PostTask(
              FROM_HERE, std::move(quit_closure));
        });
  }

  MediaDecoderType* decoder() override { return mock_decoder_.get(); }

  std::unique_ptr<media::MockVideoDecoder> mock_decoder_;
};

class VideoDecoderTest : public testing::Test {
 public:
  VideoDecoderTest() = default;
  ~VideoDecoderTest() override = default;

  FakeVideoDecoder* CreateFakeDecoder(ScriptState* script_state,
                                      VideoDecoderInit* init,
                                      ExceptionState& exception_state) {
    return MakeGarbageCollected<FakeVideoDecoder>(script_state, init,
                                                  exception_state);
  }

  VideoDecoderInit* CreateVideoDecoderInit(ScriptState* script_state,
                                           MockFunctionScope& mock_functions) {
    auto* init = MakeGarbageCollected<VideoDecoderInit>();
    init->setOutput(V8VideoFrameOutputCallback::Create(
        mock_functions.ExpectNoCall()->ToV8Function(script_state)));
    init->setError(V8WebCodecsErrorCallback::Create(
        mock_functions.ExpectNoCall()->ToV8Function(script_state)));
    return init;
  }

  VideoDecoderConfig* CreateVideoConfig() {
    auto* config = MakeGarbageCollected<VideoDecoderConfig>();
    config->setCodec("vp09.00.10.08");
    return config;
  }

  VideoDecoderSupport* ToVideoDecoderSupport(V8TestingScope* v8_scope,
                                             ScriptValue value) {
    return NativeValueTraits<VideoDecoderSupport>::NativeValue(
        v8_scope->GetIsolate(), value.V8Value(), v8_scope->GetExceptionState());
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(VideoDecoderTest, HardwareDecodersApplyPressure) {
  V8TestingScope v8_scope;
  MockFunctionScope mock_functions(v8_scope.GetScriptState());

  auto& pressure_manager_provider =
      CodecPressureManagerProvider::From(*v8_scope.GetExecutionContext());

  auto* decoder_pressure_manager =
      pressure_manager_provider.GetDecoderPressureManager();
  auto* encoder_pressure_manager =
      pressure_manager_provider.GetEncoderPressureManager();

  auto* fake_decoder = CreateFakeDecoder(
      v8_scope.GetScriptState(),
      CreateVideoDecoderInit(v8_scope.GetScriptState(), mock_functions),
      v8_scope.GetExceptionState());

  ASSERT_TRUE(fake_decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  ASSERT_FALSE(fake_decoder->is_applying_codec_pressure());
  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, encoder_pressure_manager->pressure_for_testing());

  {
    base::RunLoop run_loop;
    fake_decoder->SetupMockHardwareDecoder(run_loop.QuitClosure());

    fake_decoder->configure(CreateVideoConfig(), v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
    run_loop.Run();
  }

  // Make sure VideoDecoders apply pressure when configured with a HW decoder.
  ASSERT_TRUE(fake_decoder->is_applying_codec_pressure());
  ASSERT_EQ(1u, decoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, encoder_pressure_manager->pressure_for_testing());

  {
    base::RunLoop run_loop;
    fake_decoder->SetupMockSoftwareDecoder(run_loop.QuitClosure());

    fake_decoder->configure(CreateVideoConfig(), v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
    run_loop.Run();
  }

  // Make sure the pressure is released when reconfigured with a SW decoder.
  ASSERT_FALSE(fake_decoder->is_applying_codec_pressure());
  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());
  ASSERT_EQ(0u, encoder_pressure_manager->pressure_for_testing());
}

TEST_F(VideoDecoderTest, ResetReleasesPressure) {
  V8TestingScope v8_scope;
  MockFunctionScope mock_functions(v8_scope.GetScriptState());

  auto* fake_decoder = CreateFakeDecoder(
      v8_scope.GetScriptState(),
      CreateVideoDecoderInit(v8_scope.GetScriptState(), mock_functions),
      v8_scope.GetExceptionState());

  ASSERT_TRUE(fake_decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // Create a HW decoder.
  {
    base::RunLoop run_loop;
    fake_decoder->SetupMockHardwareDecoder(run_loop.QuitClosure());

    fake_decoder->configure(CreateVideoConfig(), v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
    run_loop.Run();
  }

  // Make sure VideoDecoders apply pressure when configured with a HW decoder.
  ASSERT_TRUE(fake_decoder->is_applying_codec_pressure());

  // Satisfy reclamation preconditions.
  fake_decoder->SimulateLifecycleStateForTesting(
      scheduler::SchedulingLifecycleState::kHidden);
  fake_decoder->SetGlobalPressureExceededFlag(true);

  // The reclamation timer should be running.
  EXPECT_TRUE(fake_decoder->IsReclamationTimerActiveForTesting());

  // Reset the codec.
  fake_decoder->reset(v8_scope.GetExceptionState());

  // The underlying codec might not be internally released.
  ASSERT_TRUE(fake_decoder->is_applying_codec_pressure());
  EXPECT_TRUE(fake_decoder->IsReclamationTimerActiveForTesting());

  // Reclaiming the codec after a period of inactivity should release pressure.
  fake_decoder->SimulateCodecReclaimedForTesting();
  ASSERT_FALSE(fake_decoder->is_applying_codec_pressure());
  EXPECT_FALSE(fake_decoder->IsReclamationTimerActiveForTesting());
}

TEST_F(VideoDecoderTest, isConfigureSupportedWithInvalidSWConfig) {
  V8TestingScope v8_scope;

  auto* config = MakeGarbageCollected<VideoDecoderConfig>();
  config->setCodec("invalid video codec");
  config->setHardwareAcceleration(V8HardwarePreference::Enum::kPreferSoftware);
  auto promise = VideoDecoder::isConfigSupported(
      v8_scope.GetScriptState(), config, v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());
  auto* result = ToVideoDecoderSupport(&v8_scope, tester.Value());
  EXPECT_FALSE(result->supported());
}

TEST_F(VideoDecoderTest, isConfigureSupportedWithInvalidHWConfig) {
  V8TestingScope v8_scope;

  auto* config = MakeGarbageCollected<VideoDecoderConfig>();
  config->setCodec("invalid video codec");
  config->setHardwareAcceleration(V8HardwarePreference::Enum::kPreferHardware);
  auto promise = VideoDecoder::isConfigSupported(
      v8_scope.GetScriptState(), config, v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
  tester.WaitUntilSettled();
  ASSERT_TRUE(tester.IsFulfilled());
  auto* result = ToVideoDecoderSupport(&v8_scope, tester.Value());
  EXPECT_FALSE(result->supported());
}

}  // namespace

}  // namespace blink

"""

```
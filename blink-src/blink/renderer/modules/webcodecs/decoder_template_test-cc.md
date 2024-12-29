Response:
Let's break down the thought process for analyzing the given C++ test file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `decoder_template_test.cc` file within the Chromium Blink engine. The key is to identify its purpose, its connection to web technologies (JavaScript, HTML, CSS), illustrate its logic with examples, highlight potential user errors, and trace user actions leading to its execution.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to read through the code, looking for keywords and patterns:

* **`TEST` and `TYPED_TEST`:** These immediately indicate that this is a test file using Google Test. The `TYPED_TEST` suggests it's a parameterized test, operating on different types.
* **`AudioDecoder` and `VideoDecoder`:**  These are the types being tested. The file's purpose is clearly related to these decoders.
* **`ConfigType` and `InitType`:** These templates hint at configuration and initialization structures for the decoders.
* **`ScriptState`, `ScriptFunction`, `ScriptPromiseTester`:** These terms strongly point to interaction with JavaScript and the V8 engine (Chromium's JavaScript engine). Callbacks and promises are involved.
* **`V8AudioDataOutputCallback`, `V8VideoFrameOutputCallback`, `V8WebCodecsErrorCallback`:** These confirm the connection to JavaScript callbacks for output and error handling.
* **`configure`, `flush`, `reset`:** These are the core methods of the decoders being tested.
* **`MockFunctionScope`, `MockGpuVideoAcceleratorFactories`:** The use of "Mock" suggests testing with simulated dependencies, likely involving GPU acceleration for video decoding.
* **`webcodecs`:** This namespace confirms the file is part of the WebCodecs API implementation in Blink.

**3. Deconstructing the Test Structure:**

* **`DecoderTemplateTest` Class:**  This is the main test fixture, parameterized by the decoder type (`AudioDecoder` or `VideoDecoder`). It provides helper methods for creating configurations, initialization objects, and the decoders themselves.
* **Type Specializations:** The template specializations for `AudioDecoder` and `VideoDecoder` within `DecoderTemplateTest` show how the generic test framework is adapted for each specific decoder type. This is where specific codecs like "mp3" and "vp09.00.10.08" are mentioned.
* **`DecoderTemplateImplementations`:** This type alias lists the decoder types the tests will run against.
* **Individual Test Cases (`TYPED_TEST`):**  Each `TYPED_TEST` function focuses on testing a specific scenario:
    * `BasicConstruction`:  Checks if the decoder can be created successfully.
    * `ResetDuringFlush`: Tests the behavior of resetting the decoder while a `flush()` operation is pending.
    * `ResetDuringConfigureOnWorker`:  Tests resetting during the asynchronous configuration process, especially relevant for video decoding potentially happening on a separate thread (worker).
    * `DISABLED_NoPressureByDefault`: (Currently disabled)  Tests whether the decoder applies "pressure" on resources by default. This relates to resource management.

**4. Connecting to Web Technologies:**

* **JavaScript:** The presence of `ScriptState`, `ScriptFunction`, and the callback mechanisms clearly shows the test file is verifying the JavaScript API bindings of the `AudioDecoder` and `VideoDecoder`. The callbacks are used to communicate decoding results (audio data or video frames) and errors back to the JavaScript code. The `ScriptPromiseTester` directly interacts with JavaScript promises returned by the `flush()` method.
* **HTML:** While not directly interacting with HTML parsing, the WebCodecs API is used in JavaScript code embedded within HTML pages. The test indirectly ensures the correct behavior of these APIs when called from a web page.
* **CSS:** CSS is less directly related. However, if the decoded video is displayed on a `<video>` element, CSS might be used for styling. The test ensures the decoding process itself functions correctly, regardless of styling.

**5. Inferring Logic and Examples:**

For each test case, I consider what it's trying to achieve and how that translates to hypothetical user actions and JavaScript code:

* **`BasicConstruction`:**  The most basic scenario – just creating the decoder in JavaScript.
* **`ResetDuringFlush`:** Imagine a user quickly trying to stop and restart a decoding process. This test verifies the decoder handles this interruption cleanly.
* **`ResetDuringConfigureOnWorker`:**  Think of a scenario where the browser is still figuring out if the video can be decoded (asynchronously checking codec support). The user might navigate away or try to reload the page while this is happening.
* **`DISABLED_NoPressureByDefault`:** This relates to browser resource management. The test (when enabled) verifies that decoders don't aggressively request more resources than needed initially.

**6. Identifying Potential User Errors:**

I think about common mistakes developers might make when using the WebCodecs API:

* **Incorrect Configuration:** Providing invalid codec parameters, sample rates, etc. While this test doesn't directly check for *invalid* configurations, it sets up valid ones, highlighting the importance of proper configuration.
* **Not Handling Errors:** Forgetting to implement or properly handle the error callback. The test includes error callbacks, showing their expected usage.
* **Calling Methods in the Wrong Order:**  For example, trying to `decode()` before `configure()`. While not explicitly tested here, the `configure` and `flush` sequences demonstrate the expected order.
* **Resource Leaks:**  While not directly a user error in *using* the API, the `DISABLED_NoPressureByDefault` test touches on the underlying resource management, which is important for avoiding browser issues.

**7. Tracing User Actions (Debugging Clues):**

This involves imagining the steps a user might take in a web browser to trigger the code being tested:

1. **Open a web page:** The user navigates to a page containing JavaScript that uses the WebCodecs API.
2. **JavaScript execution:** The JavaScript code creates an `AudioDecoder` or `VideoDecoder` object.
3. **Configuration:** The JavaScript code calls the `configure()` method with a configuration object.
4. **Decoding (not directly in these tests but implied):**  The JavaScript code would eventually feed data to the decoder using `decode()`.
5. **Flushing or Resetting:**  The JavaScript might call `flush()` to ensure all pending data is processed or `reset()` to stop the decoding process.
6. **Error Handling:** If something goes wrong, the error callback defined in the JavaScript would be invoked.

The tests in this file simulate these JavaScript interactions directly in C++, ensuring the underlying C++ implementation behaves as expected. If a user reports a problem with WebCodecs, developers might look at these tests to understand how the API is *supposed* to work and potentially reproduce the issue in a controlled environment.

**8. Refinement and Organization:**

Finally, I organize the information into the requested categories, ensuring clarity and providing specific examples. I use the keywords and patterns identified earlier to support my explanations. I explicitly state assumptions and limitations (e.g., the tests use mock objects).

This systematic approach, combining code reading, keyword analysis, understanding the testing framework, and thinking about user scenarios, allows for a thorough analysis of the given C++ test file.
这个文件 `decoder_template_test.cc` 是 Chromium Blink 引擎中用于测试 `AudioDecoder` 和 `VideoDecoder` 类的模板测试文件。它使用 Google Test 框架 (gtest) 来编写针对这些解码器的单元测试。

**功能总结:**

1. **提供通用的解码器测试框架:**  `DecoderTemplateTest` 是一个模板类，可以用来测试不同类型的解码器（目前是 `AudioDecoder` 和 `VideoDecoder`）。这避免了为每种解码器编写重复的测试代码。
2. **测试解码器的基本生命周期和状态管理:**  测试用例涵盖了解码器的创建、配置、刷新 (flush) 和重置 (reset) 等核心操作。
3. **验证解码器与 JavaScript 的交互:** 测试用例通过模拟 JavaScript 环境（使用 `V8TestingScope` 和 `ScriptFunction` 等）来验证解码器与 JavaScript API 的集成是否正确。这包括测试输出回调和错误回调的机制。
4. **模拟 GPU 加速解码器的行为:**  通过 `MockGpuVideoAcceleratorFactories`，可以模拟 GPU 加速解码器的行为，例如在工作线程上配置解码器以及解码器能力查询等。
5. **测试解码器的资源管理 (压力管理):**  虽然有一个被禁用的测试用例 `DISABLED_NoPressureByDefault`，但它的目的是测试解码器是否默认会施加资源回收压力。这涉及到解码器在资源受限情况下的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个测试文件直接测试的是 WebCodecs API 的 C++ 实现，该 API 暴露给 JavaScript，从而让网页能够进行音视频编解码。

* **JavaScript:**
    * **创建解码器:** JavaScript 代码可以使用 `new AudioDecoder(init)` 或 `new VideoDecoder(init)` 来创建解码器实例。测试文件中的 `CreateDecoder` 方法模拟了这个过程。
        ```javascript
        const audioDecoder = new AudioDecoder({
          output(audioData) {
            // 处理解码后的音频数据
            console.log("Decoded audio:", audioData);
          },
          error(e) {
            console.error("Decoding error:", e);
          }
        });

        const videoDecoder = new VideoDecoder({
          output(frame) {
            // 处理解码后的视频帧
            console.log("Decoded frame:", frame);
          },
          error(e) {
            console.error("Decoding error:", e);
          }
        });
        ```
    * **配置解码器:** JavaScript 代码使用 `decoder.configure(config)` 来配置解码器的参数。测试文件中的 `configure` 方法对应于此。
        ```javascript
        audioDecoder.configure({
          codec: 'mp3',
          samplerate: 48000,
          numberOfChannels: 2
        });

        videoDecoder.configure({
          codec: 'vp09.00.10.08'
        });
        ```
    * **刷新解码器:** JavaScript 代码使用 `decoder.flush()` 来确保所有待处理的数据都被解码。测试文件中的 `flush` 方法测试了这个操作。
        ```javascript
        audioDecoder.flush().then(() => {
          console.log("Audio decoder flushed.");
        });

        videoDecoder.flush().then(() => {
          console.log("Video decoder flushed.");
        });
        ```
    * **重置解码器:** JavaScript 代码使用 `decoder.reset()` 来中止当前的解码过程。测试文件中的 `reset` 方法测试了这个操作。
        ```javascript
        audioDecoder.reset();
        videoDecoder.reset();
        ```
    * **回调函数:** `init` 对象中定义的 `output` 和 `error` 回调函数在解码成功或发生错误时会被调用。测试文件通过 `MockFunctionScope` 模拟这些回调函数的调用，并验证它们是否被按预期调用。

* **HTML:**
    * WebCodecs API 通常在 `<script>` 标签内的 JavaScript 代码中使用。HTML 结构可能包含 `<audio>` 或 `<video>` 元素，用于呈现解码后的音视频数据，但 WebCodecs 本身并不直接操作 HTML 元素。
    * 例如，解码后的 `AudioData` 可以通过 Web Audio API 播放，解码后的 `VideoFrame` 可以绘制到 `<canvas>` 元素或直接显示在 `<video>` 元素上。

* **CSS:**
    * CSS 用于控制网页的样式和布局，与 WebCodecs API 的核心功能（音视频解码）没有直接关系。但是，如果解码后的视频显示在 `<video>` 元素上，CSS 可以用来控制视频播放器的外观和布局。

**逻辑推理、假设输入与输出:**

大多数测试用例主要关注状态转换和方法的调用顺序，而不是具体的解码逻辑。

* **`TYPED_TEST(DecoderTemplateTest, BasicConstruction)`:**
    * **假设输入:** 创建 `AudioDecoder` 或 `VideoDecoder` 的初始化对象 (带有空的回调函数)。
    * **预期输出:** 解码器对象成功创建，没有抛出异常。

* **`TYPED_TEST(DecoderTemplateTest, ResetDuringFlush)`:**
    * **假设输入:** 先配置解码器，然后调用 `flush()`，但在 `flush()` 完成之前调用 `reset()`。
    * **预期输出:** `flush()` 返回的 Promise 被拒绝 (rejected)。这表明在刷新过程中重置了解码器，导致刷新操作失败。

* **`TYPED_TEST(DecoderTemplateTest, ResetDuringConfigureOnWorker)`:**
    * **假设输入 (对于 VideoDecoder):**  配置解码器，这可能会在工作线程上进行（因为涉及到 GPU 加速的初始化），然后在配置完成之前调用 `reset()`。之后再次配置并刷新。
    * **预期输出:**  第一次配置被重置打断。第二次配置成功完成，`flush()` 返回的 Promise 被解决 (fulfilled)。这测试了在异步配置过程中重置解码器的行为。

**用户或编程常见的使用错误举例说明:**

* **未配置解码器就尝试解码:** 用户可能会忘记在调用 `decode()` 方法之前先调用 `configure()` 方法。这会导致解码器处于未初始化状态，从而引发错误。
    ```javascript
    const decoder = new VideoDecoder({ /* ... */ });
    // 缺少 decoder.configure({...});
    // 尝试解码会失败
    // decoder.decode(encodedVideoChunk);
    ```
* **配置信息不完整或错误:**  传递给 `configure()` 方法的配置对象可能缺少必要的参数或参数值不正确，例如 `codec` 字符串拼写错误或不支持的编解码器。
    ```javascript
    decoder.configure({
      code: 'vvp9' // 拼写错误，应该是 'vp9'
    });
    ```
* **未处理错误回调:** 用户可能没有正确实现或忽略了 `error` 回调函数，导致解码过程中发生的错误无法被捕获和处理。
    ```javascript
    const decoder = new AudioDecoder({
      output(audioData) { /* ... */ },
      // 缺少 error 回调函数
    });
    ```
* **在解码器处于非活动状态时调用方法:** 例如，在解码器已经被 `reset()` 之后，或者在 `flush()` 操作尚未完成时，再次调用 `decode()` 或 `configure()` 可能会导致意外行为。测试用例 `ResetDuringFlush` 就在一定程度上验证了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个开发者，在编写和维护使用了 WebCodecs API 的网页时，可能会遇到各种问题，这些问题最终可能指向 Blink 引擎中的 `AudioDecoder` 或 `VideoDecoder` 实现。以下是一个可能的调试路径：

1. **用户报告问题:** 用户在使用网页时遇到了音视频解码相关的问题，例如播放失败、卡顿、花屏、音频失真等。
2. **开发者检查 JavaScript 代码:** 开发者首先会检查自己的 JavaScript 代码，确认 WebCodecs API 的使用方式是否正确，例如：
    * 解码器的创建和配置是否正确。
    * `decode()` 方法的调用是否合理。
    * `output` 和 `error` 回调函数是否正确实现。
    * 是否正确处理了 `flush()` 方法返回的 Promise。
3. **浏览器开发者工具调试:** 开发者可以使用浏览器的开发者工具（例如 Chrome 的 DevTools）来查看 JavaScript 的执行流程，检查变量的值，以及查看控制台输出的错误信息。
4. **网络请求分析:** 如果涉及到从网络加载音视频数据，开发者会检查网络请求是否成功，数据是否完整。
5. **平台或浏览器特定的问题:** 如果问题只在特定的浏览器或操作系统上出现，开发者可能会怀疑是浏览器或底层平台的实现问题。
6. **Blink 引擎源码调试:**  如果怀疑是 Blink 引擎本身的问题，开发者可能会查看 Blink 引擎的源码，例如 `blink/renderer/modules/webcodecs/audio_decoder.cc` 或 `blink/renderer/modules/webcodecs/video_decoder.cc`，以及相关的测试文件 `decoder_template_test.cc`。
7. **查看测试用例:**  `decoder_template_test.cc` 中的测试用例可以帮助开发者理解解码器的预期行为和状态转换。如果用户报告的问题与某个测试用例覆盖的场景类似，那么很可能就是 Blink 引擎在该场景下的实现存在 bug。
8. **断点调试 Blink 源码:**  开发者可以在 Blink 引擎的源码中设置断点，例如在 `AudioDecoder::configure`、`VideoDecoder::decode` 等方法中，来跟踪代码的执行流程，查看内部状态，并找出问题所在。

总而言之，`decoder_template_test.cc` 是一个用于验证 WebCodecs API 的 C++ 实现是否符合预期的重要测试文件。当用户在使用 WebCodecs API 时遇到问题时，这个文件可以作为调试线索，帮助开发者理解 API 的工作原理，排查潜在的错误。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/decoder_template_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_tester.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_data_output_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_decoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_init.h"
#include "third_party/blink/renderer/core/testing/mock_function_scope.h"
#include "third_party/blink/renderer/modules/webcodecs/audio_decoder.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_pressure_manager_provider.h"
#include "third_party/blink/renderer/modules/webcodecs/video_decoder.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

using testing::_;

namespace blink {

namespace {

template <class T>
class DecoderTemplateTest : public testing::Test {
 public:
  DecoderTemplateTest() = default;
  ~DecoderTemplateTest() override = default;

  typename T::ConfigType* CreateConfig();
  typename T::InitType* CreateInit(ScriptState* script_state,
                                   ScriptFunction* output_callback,
                                   ScriptFunction* error_callback);

  T* CreateDecoder(ScriptState*, const typename T::InitType*, ExceptionState&);
  test::TaskEnvironment task_environment_;
};

template <>
AudioDecoderConfig* DecoderTemplateTest<AudioDecoder>::CreateConfig() {
  auto* config = MakeGarbageCollected<AudioDecoderConfig>();
  config->setCodec("mp3");
  config->setSampleRate(48000);
  config->setNumberOfChannels(2);
  return config;
}

template <>
AudioDecoder* DecoderTemplateTest<AudioDecoder>::CreateDecoder(
    ScriptState* script_state,
    const AudioDecoderInit* init,
    ExceptionState& exception_state) {
  return MakeGarbageCollected<AudioDecoder>(script_state, init,
                                            exception_state);
}

template <>
AudioDecoderInit* DecoderTemplateTest<AudioDecoder>::CreateInit(
    ScriptState* script_state,
    ScriptFunction* output_callback,
    ScriptFunction* error_callback) {
  auto* init = MakeGarbageCollected<AudioDecoderInit>();
  init->setOutput(V8AudioDataOutputCallback::Create(
      output_callback->ToV8Function(script_state)));
  init->setError(V8WebCodecsErrorCallback::Create(
      error_callback->ToV8Function(script_state)));
  return init;
}

template <>
VideoDecoderConfig* DecoderTemplateTest<VideoDecoder>::CreateConfig() {
  auto* config = MakeGarbageCollected<VideoDecoderConfig>();
  config->setCodec("vp09.00.10.08");
  return config;
}

template <>
VideoDecoderInit* DecoderTemplateTest<VideoDecoder>::CreateInit(
    ScriptState* script_state,
    ScriptFunction* output_callback,
    ScriptFunction* error_callback) {
  auto* init = MakeGarbageCollected<VideoDecoderInit>();
  init->setOutput(V8VideoFrameOutputCallback::Create(
      output_callback->ToV8Function(script_state)));
  init->setError(V8WebCodecsErrorCallback::Create(
      error_callback->ToV8Function(script_state)));
  return init;
}

template <>
VideoDecoder* DecoderTemplateTest<VideoDecoder>::CreateDecoder(
    ScriptState* script_state,
    const VideoDecoderInit* init,
    ExceptionState& exception_state) {
  return VideoDecoder::Create(script_state, init, exception_state);
}

using DecoderTemplateImplementations =
    testing::Types<AudioDecoder, VideoDecoder>;

class MockGpuFactoriesTestingPlatform : public TestingPlatformSupport {
 public:
  MockGpuFactoriesTestingPlatform() = default;
  ~MockGpuFactoriesTestingPlatform() override = default;

  media::GpuVideoAcceleratorFactories* GetGpuFactories() override {
    return &mock_gpu_factories_;
  }

  media::MockGpuVideoAcceleratorFactories& mock_gpu_factories() {
    return mock_gpu_factories_;
  }

 private:
  media::MockGpuVideoAcceleratorFactories mock_gpu_factories_{nullptr};
};

TYPED_TEST_SUITE(DecoderTemplateTest, DecoderTemplateImplementations);

TYPED_TEST(DecoderTemplateTest, BasicConstruction) {
  V8TestingScope v8_scope;

  MockFunctionScope mock_function(v8_scope.GetScriptState());
  auto* decoder = this->CreateDecoder(
      v8_scope.GetScriptState(),
      this->CreateInit(v8_scope.GetScriptState(), mock_function.ExpectNoCall(),
                       mock_function.ExpectNoCall()),
      v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  EXPECT_FALSE(v8_scope.GetExceptionState().HadException());
}

TYPED_TEST(DecoderTemplateTest, ResetDuringFlush) {
  V8TestingScope v8_scope;

  // Create a decoder.
  MockFunctionScope mock_function(v8_scope.GetScriptState());
  auto* decoder = this->CreateDecoder(
      v8_scope.GetScriptState(),
      this->CreateInit(v8_scope.GetScriptState(), mock_function.ExpectNoCall(),
                       mock_function.ExpectNoCall()),
      v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // Configure the decoder.
  decoder->configure(this->CreateConfig(), v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // flush() to ensure configure completes.
  {
    auto promise = decoder->flush(v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }

  // flush() again but reset() before it gets started.
  {
    auto promise = decoder->flush(v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
    decoder->reset(v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsRejected());
  }
}

TYPED_TEST(DecoderTemplateTest, ResetDuringConfigureOnWorker) {
  V8TestingScope v8_scope;

  ScopedTestingPlatformSupport<MockGpuFactoriesTestingPlatform> platform;
  EXPECT_CALL(platform->mock_gpu_factories(), GetTaskRunner())
      .WillRepeatedly(
          testing::Return(base::SingleThreadTaskRunner::GetCurrentDefault()));
  EXPECT_CALL(platform->mock_gpu_factories(), IsDecoderSupportKnown())
      .WillRepeatedly(testing::Return(false));
  EXPECT_CALL(platform->mock_gpu_factories(), IsDecoderConfigSupported(_))
      .WillRepeatedly(testing::Return(
          media::GpuVideoAcceleratorFactories::Supported::kFalse));
  EXPECT_CALL(platform->mock_gpu_factories(), GetDecoderType())
      .WillRepeatedly(testing::Return(media::VideoDecoderType::kTesting));
  base::OnceClosure notify_cb;
  EXPECT_CALL(platform->mock_gpu_factories(), NotifyDecoderSupportKnown(_))
      .WillRepeatedly(
          [&](base::OnceClosure on_done) { notify_cb = std::move(on_done); });
  // Create a decoder.
  MockFunctionScope mock_function(v8_scope.GetScriptState());
  auto* decoder = this->CreateDecoder(
      v8_scope.GetScriptState(),
      this->CreateInit(v8_scope.GetScriptState(), mock_function.ExpectNoCall(),
                       mock_function.ExpectNoCall()),
      v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // Configure the decoder.
  decoder->configure(this->CreateConfig(), v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // reset() during configure.
  {
    decoder->reset(v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());
  }

  // Only present for video playbacks.
  if (notify_cb) {
    std::move(notify_cb).Run();
  }

  // Configure the decoder again.
  decoder->configure(this->CreateConfig(), v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // flush() to ensure configure completes.
  {
    auto promise = decoder->flush(v8_scope.GetExceptionState());
    ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

    ScriptPromiseTester tester(v8_scope.GetScriptState(), promise);
    tester.WaitUntilSettled();
    ASSERT_TRUE(tester.IsFulfilled());
  }
}

// Ensures codecs do not apply reclamation pressure by default.
// Sheriff 2022/02/25; flaky test crbug/1300845
TYPED_TEST(DecoderTemplateTest, DISABLED_NoPressureByDefault) {
  V8TestingScope v8_scope;

  // Create a decoder.
  MockFunctionScope mock_function(v8_scope.GetScriptState());
  auto* decoder = this->CreateDecoder(
      v8_scope.GetScriptState(),
      this->CreateInit(v8_scope.GetScriptState(), mock_function.ExpectNoCall(),
                       mock_function.ExpectNoCall()),
      v8_scope.GetExceptionState());
  ASSERT_TRUE(decoder);
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // Configure the decoder.
  decoder->configure(this->CreateConfig(), v8_scope.GetExceptionState());
  ASSERT_FALSE(v8_scope.GetExceptionState().HadException());

  // Codecs shouldn't apply pressure by default.
  ASSERT_FALSE(decoder->is_applying_codec_pressure());

  auto* decoder_pressure_manager =
      CodecPressureManagerProvider::From(*v8_scope.GetExecutionContext())
          .GetDecoderPressureManager();

  ASSERT_EQ(0u, decoder_pressure_manager->pressure_for_testing());
}

}  // namespace

}  // namespace blink

"""

```
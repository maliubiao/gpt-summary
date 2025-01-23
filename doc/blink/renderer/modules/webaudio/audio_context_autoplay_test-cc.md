Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Purpose:** The filename `audio_context_autoplay_test.cc` immediately suggests this file is for testing the autoplay behavior of the Web Audio API's `AudioContext`. The presence of "autoplay" is the key indicator.

2. **Examine Includes:** The `#include` directives provide crucial context:
    * `audio_context.h`: This confirms the primary object under test is `AudioContext`.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates this is a Google Test-based unit test file.
    * `base/test/metrics/histogram_tester.h`: Shows the tests involve recording and verifying UMA (User Metrics Analysis) histograms related to autoplay.
    * `third_party/blink/public/platform/...`:  These includes reveal dependencies on Blink's platform layer, particularly related to audio devices and settings.
    * `third_party/blink/renderer/bindings/...`:  Suggests interaction with JavaScript bindings (V8).
    * `third_party/blink/renderer/core/...`:  Points to core Blink rendering components like frames, settings, and the autoplay policy.

3. **Understand the Test Structure:**  The `TEST_P` macros indicate parameterized tests. The `INSTANTIATE_TEST_SUITE_P` line shows the tests are run with different `AutoplayPolicy::Type` values. This is a central aspect of the file's functionality – testing against various autoplay policies.

4. **Analyze the Test Cases (Functions starting with `TEST_P`):** For each test case, identify the core action being tested and the context:
    * **`AutoplayMetrics_CreateNoGesture_*`:**  Creating an `AudioContext` without a user gesture. Distinguish between main frame and cross-origin child frame.
    * **`AutoplayMetrics_CallResumeNoGesture_*`:** Calling `resume()` on an `AudioContext` without a user gesture. Again, differentiate between frames.
    * **`AutoplayMetrics_CreateGesture_*`:** Creating an `AudioContext` *with* a user gesture.
    * **`AutoplayMetrics_CallResumeGesture_*`:** Calling `resume()` *with* a user gesture.
    * **`AutoplayMetrics_NodeStartNoGesture_*`:** Calling `NotifySourceNodeStart()` (simulating starting an audio source) without a gesture.
    * **`AutoplayMetrics_NodeStartGesture_*`:** Calling `NotifySourceNodeStart()` with a gesture.
    * **`AutoplayMetrics_NodeStartNoGestureThenSuccess_*`:**  Starting a node without a gesture, then later allowing playback (e.g., via `resume()` after a gesture).
    * **`AutoplayMetrics_NodeStartGestureThenSucces_*`:** Starting a node with a gesture, then allowing playback.
    * **`AutoplayMetrics_DocumentReceivedGesture_*`:** Checking if a previous user gesture on the *document* allows autoplay.
    * **`AutoplayMetrics_DocumentReceivedGesture_BeforeNavigation`:** Testing if a sticky user activation from a previous navigation allows autoplay.

5. **Infer Functionality from Test Cases:**  The test cases collectively demonstrate the logic for determining whether autoplay is allowed:
    * **User Gesture Requirement:**  The tests explicitly check how different autoplay policies (`kUserGestureRequired`, `kDocumentUserActivationRequired`) are enforced.
    * **Frame Origin:** The distinction between main frames and cross-origin iframes is crucial, highlighting how autoplay policies might differ based on origin.
    * **Timing of Gesture:**  Some tests check if a gesture is needed *at the time of creation* or if a later gesture allows playback.
    * **Histograms:** The tests confirm that UMA histograms (`WebAudio.Autoplay`, `WebAudio.Autoplay.CrossOrigin`) are correctly recorded to track autoplay success/failure.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** The `AudioContext` is a JavaScript API. The tests simulate JavaScript calls to create and control the `AudioContext`.
    * **HTML:** The tests set up iframe structures within HTML to simulate cross-origin scenarios. The autoplay policy is often configured via HTML attributes (though not directly tested *in this file*).
    * **CSS:**  While CSS doesn't directly control autoplay, user interactions that trigger autoplay might be styled with CSS. However, this test file doesn't directly interact with CSS.

7. **Identify Logic and Assumptions:**
    * **Assumption:** The `MockWebAudioDeviceForAutoplayTest` assumes that creating the audio sink always succeeds. This simplifies the tests by focusing solely on autoplay policy.
    * **Logic:** The core logic lies within the `AudioContext` class (not fully visible in this test file) and how it interacts with the `AutoplayPolicy`. The tests verify this logic by checking the recorded histogram values based on different scenarios.

8. **Consider User/Programming Errors:**
    * **User Error:** Trying to play audio without a user gesture when the autoplay policy requires it is a common user "error" (from the browser's perspective, it's intentional blocking).
    * **Programming Error:**  Developers might forget to handle the promise rejection when autoplay is blocked, leading to unexpected behavior in their web applications.

9. **Trace User Operations (Debugging Clues):** The test setup itself provides the debugging clues. By understanding the conditions under which a test fails, developers can narrow down the scenarios where autoplay might be incorrectly blocked or allowed. For example, if the `AutoplayMetrics_CreateNoGesture_Child` test fails under `kUserGestureRequired`, it indicates an issue with how the autoplay policy is being applied in cross-origin iframes without a gesture.

10. **Refine and Structure the Output:** Organize the findings into logical categories (Functionality, Relationship to Web Tech, Logic/Assumptions, Errors, User Operations). Provide concrete examples and code snippets (even if simplified) to illustrate the concepts. Use clear and concise language.

By following these steps, one can systematically analyze the C++ test file and extract comprehensive information about its purpose, functionality, and relevance to web development.
这个C++源代码文件 `audio_context_autoplay_test.cc` 是 Chromium Blink 引擎中用于测试 `blink::AudioContext` 的自动播放策略相关功能的单元测试文件。

**主要功能:**

这个文件的主要目的是验证在不同的自动播放策略下，`AudioContext` 的创建和启动行为是否符合预期。它通过模拟各种场景，包括：

* **有无用户手势 (user gesture):** 测试在需要用户手势才能播放音频的情况下，`AudioContext` 是否正确阻止了自动播放，并在获得用户手势后允许播放。
* **同源和跨域 (same-origin and cross-origin):**  测试自动播放策略在同源和跨域 iframe 中的行为差异。
* **不同的自动播放策略类型:** 测试 Chromium 支持的不同自动播放策略 (`kNoUserGestureRequired`, `kUserGestureRequired`, `kDocumentUserActivationRequired`) 的效果。
* **不同的操作方式:** 测试创建 `AudioContext`、调用 `resume()` 方法以及启动音频源节点等不同操作触发自动播放时的行为。
* **记录性能指标:** 测试是否正确记录了自动播放相关的性能指标（通过 `base::HistogramTester`）。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件虽然是 C++ 代码，但它直接测试了 Web Audio API 的 JavaScript 接口的行为，因此与 JavaScript 和 HTML 紧密相关：

* **JavaScript:** `blink::AudioContext` 是 Web Audio API 的核心接口，开发者在 JavaScript 中使用 `new AudioContext()` 来创建它，并调用其方法（如 `resume()`）。这个测试文件模拟了这些 JavaScript 操作，并验证了底层 C++ 实现的行为是否正确。
    * **示例 JavaScript 代码:**
      ```javascript
      // 创建 AudioContext
      const audioContext = new AudioContext();

      // 尝试播放音频 (可能被自动播放策略阻止)
      const oscillator = audioContext.createOscillator();
      oscillator.connect(audioContext.destination);
      oscillator.start();

      // 在用户交互后尝试恢复 AudioContext
      document.addEventListener('click', () => {
        audioContext.resume();
      });
      ```
* **HTML:**  测试用例中创建了 iframe (`<iframe></iframe>`) 来模拟跨域场景。HTML 结构决定了脚本运行的上下文（主框架或 iframe），以及文档的来源（同源或跨域）。
    * **示例 HTML 代码:**
      ```html
      <!DOCTYPE html>
      <html>
      <head>
        <title>Autoplay Test</title>
      </head>
      <body>
        <iframe src="https://cross-origin.com"></iframe>
        <script>
          // JavaScript 代码创建 AudioContext 并尝试播放
        </script>
      </body>
      </html>
      ```
* **CSS:**  CSS 本身不直接控制自动播放策略，但它可以影响用户交互，而用户交互可能触发允许音频播放的事件。例如，用户点击一个按钮（CSS 可以设置按钮样式），该点击事件可以被用来调用 `audioContext.resume()`。  在这个测试文件中，CSS 的作用是间接的，主要体现在它参与构建用户交互的场景。

**逻辑推理 (假设输入与输出):**

假设我们使用 `AutoplayPolicy::Type::kUserGestureRequired` 策略运行一个测试用例 `AutoplayMetrics_CreateNoGesture_Child`：

* **假设输入:**
    * 自动播放策略设置为 `kUserGestureRequired`。
    * 在一个跨域的 iframe 中尝试创建一个 `AudioContext` 对象。
    * 没有发生任何用户手势。
* **逻辑推理:** 根据 `kUserGestureRequired` 策略，在没有用户手势的情况下，创建 `AudioContext` 并不会立即激活音频输出。测试代码会检查是否记录了 `WebAudio.Autoplay.CrossOrigin` 指标，并且其状态为 `kFailed`。
* **预期输出:**
    * `GetHistogramTester()->ExpectBucketCount(kAutoplayCrossOriginMetric, static_cast<int>(AutoplayStatus::kFailed), 1);`  断言会成功，因为在跨域且无用户手势的情况下，自动播放被阻止。
    * `GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);` 断言会成功，因为记录了一条相关的指标。

**用户或编程常见的使用错误：**

* **用户错误:**  用户可能会在没有与页面进行任何交互的情况下，期望网页上的音频自动播放，但由于浏览器的自动播放策略限制，音频可能无法播放。
* **编程错误:**
    * **忘记处理 `AudioContext.resume()` 返回的 Promise 的 rejection:** 当自动播放被阻止时，`audioContext.resume()` 返回的 Promise 会被 reject。开发者需要正确处理这个 rejection，例如给用户提供一个交互按钮来启动音频。
      ```javascript
      const audioContext = new AudioContext();
      audioContext.resume().catch(error => {
        console.error('AudioContext 无法自动播放:', error);
        // 显示一个按钮，提示用户点击以播放音频
      });
      ```
    * **在不合适的时机尝试创建或启动 `AudioContext`:**  例如，在页面加载完成的瞬间就尝试创建并启动，而此时可能还没有发生任何用户交互。
    * **没有考虑到跨域 iframe 的自动播放限制:** 跨域 iframe 的自动播放限制通常比同源框架更严格。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者在调试一个关于 Web Audio 自动播放的问题，并最终找到了这个测试文件：

1. **用户报告问题:** 用户反馈某个网页的音频在某些情况下无法自动播放。
2. **开发者重现问题:** 开发者尝试复现用户报告的问题，发现自动播放行为不一致，可能在某些浏览器或特定条件下被阻止。
3. **查阅文档和规范:** 开发者查阅 Web Audio API 的文档和浏览器的自动播放策略说明，了解自动播放的限制和最佳实践。
4. **怀疑自动播放策略的实现:** 开发者可能怀疑是浏览器的自动播放策略实现存在问题，或者与预期不符。
5. **搜索 Chromium 源代码:**  开发者可能会搜索 Chromium 的源代码，寻找与 Web Audio 和自动播放相关的代码。可能的搜索关键词包括 "AudioContext", "autoplay", "WebAudio"。
6. **定位到测试文件:** 通过搜索，开发者可能会找到 `audio_context_autoplay_test.cc` 这个测试文件，因为它明确地包含了 "autoplay" 和 "AudioContext"。
7. **分析测试用例:** 开发者会仔细阅读测试文件中的各个测试用例，了解在不同的场景下，`AudioContext` 的预期行为是什么。
8. **理解自动播放策略:** 通过测试用例的设置和断言，开发者可以更深入地理解 Chromium 中不同自动播放策略的具体实现和效果。
9. **对照自己的代码:** 开发者可以将测试用例中的场景和自己的代码进行对照，找出可能导致自动播放失败的原因。例如，是否在没有用户手势的情况下尝试启动音频，或者是否忽略了跨域的限制。
10. **进行本地测试和修改:** 开发者可能会修改测试文件，添加新的测试用例来覆盖自己遇到的特定场景，或者在本地运行这些测试来验证修复后的代码是否符合预期。

总而言之，`audio_context_autoplay_test.cc` 是一个关键的测试文件，用于确保 Chromium 的 Web Audio API 在处理自动播放时能够遵循既定的策略，并为开发者提供了一个了解和调试自动播放相关问题的参考。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_context_autoplay_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webaudio/audio_context.h"

#include <memory>

#include "base/test/metrics/histogram_tester.h"
#include "build/build_config.h"
#include "media/base/output_device_info.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_audio_device.h"
#include "third_party/blink/public/platform/web_audio_latency_hint.h"
#include "third_party/blink/public/platform/web_audio_sink_descriptor.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_audio_context_options.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/frame_types.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/media/autoplay_policy.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/platform/loader/fetch/memory_cache.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

const char* const kAutoplayMetric = "WebAudio.Autoplay";
const char* const kAutoplayCrossOriginMetric = "WebAudio.Autoplay.CrossOrigin";

class MockWebAudioDeviceForAutoplayTest : public WebAudioDevice {
 public:
  explicit MockWebAudioDeviceForAutoplayTest(double sample_rate,
                                             int frames_per_buffer)
      : sample_rate_(sample_rate), frames_per_buffer_(frames_per_buffer) {}
  ~MockWebAudioDeviceForAutoplayTest() override = default;

  void Start() override {}
  void Stop() override {}
  void Pause() override {}
  void Resume() override {}
  double SampleRate() override { return sample_rate_; }
  int FramesPerBuffer() override { return frames_per_buffer_; }
  int MaxChannelCount() override { return 2; }
  void SetDetectSilence(bool detect_silence) override {}
  media::OutputDeviceStatus MaybeCreateSinkAndGetStatus() override {
    // In this test, we assume the sink creation always succeeds.
    return media::OUTPUT_DEVICE_STATUS_OK;
  }

 private:
  double sample_rate_;
  int frames_per_buffer_;
};

class AudioContextAutoplayTestPlatform : public TestingPlatformSupport {
 public:
  std::unique_ptr<WebAudioDevice> CreateAudioDevice(
      const WebAudioSinkDescriptor& sink_descriptor,
      unsigned number_of_output_channels,
      const WebAudioLatencyHint& latency_hint,
      media::AudioRendererSink::RenderCallback*) override {
    return std::make_unique<MockWebAudioDeviceForAutoplayTest>(
        AudioHardwareSampleRate(), AudioHardwareBufferSize());
  }

  double AudioHardwareSampleRate() override { return 44100; }
  size_t AudioHardwareBufferSize() override { return 128; }
};

}  // namespace

class AudioContextAutoplayTest
    : public testing::TestWithParam<AutoplayPolicy::Type> {
 protected:
  using AutoplayStatus = AudioContext::AutoplayStatus;

  void SetUp() override {
    helper_.Initialize();
    frame_test_helpers::LoadHTMLString(helper_.LocalMainFrame(),
                                       "<iframe></iframe>",
                                       WebURL(KURL("https://example.com")));
    frame_test_helpers::LoadHTMLString(
        To<WebLocalFrameImpl>(helper_.LocalMainFrame()->FirstChild()), "",
        WebURL(KURL("https://cross-origin.com")));
    GetWindow().GetFrame()->GetSettings()->SetAutoplayPolicy(GetParam());
    ChildWindow().GetFrame()->GetSettings()->SetAutoplayPolicy(GetParam());

    histogram_tester_ = std::make_unique<base::HistogramTester>();
  }

  void TearDown() override { MemoryCache::Get()->EvictResources(); }

  LocalDOMWindow& GetWindow() {
    return *helper_.LocalMainFrame()->GetFrame()->DomWindow();
  }

  LocalDOMWindow& ChildWindow() {
    return *To<WebLocalFrameImpl>(helper_.LocalMainFrame()->FirstChild())
                ->GetFrame()
                ->DomWindow();
  }

  ScriptState* GetScriptStateFrom(const LocalDOMWindow& window) {
    return ToScriptStateForMainWorld(window.GetFrame());
  }

  void RejectPendingResolvers(AudioContext* audio_context) {
    audio_context->RejectPendingResolvers();
  }

  void RecordAutoplayStatus(AudioContext* audio_context) {
    audio_context->RecordAutoplayMetrics();
  }

  base::HistogramTester* GetHistogramTester() {
    return histogram_tester_.get();
  }

 private:
  test::TaskEnvironment task_environment_;
  ScopedTestingPlatformSupport<AudioContextAutoplayTestPlatform> platform_;
  frame_test_helpers::WebViewHelper helper_;
  std::unique_ptr<base::HistogramTester> histogram_tester_;
};

// Creates an AudioContext without a gesture inside a x-origin child frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CreateNoGesture_Child) {
  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric, static_cast<int>(AutoplayStatus::kFailed),
          1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext without a gesture inside a main frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CreateNoGesture_Main) {
  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then call resume without a gesture in a x-origin
// child frame.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_CallResumeNoGesture_Child) {
  ScriptState::Scope scope(GetScriptStateFrom(ChildWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->resumeContext(GetScriptStateFrom(ChildWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric, static_cast<int>(AutoplayStatus::kFailed),
          1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then call resume without a gesture in a main frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CallResumeNoGesture_Main) {
  ScriptState::Scope scope(GetScriptStateFrom(GetWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->resumeContext(GetScriptStateFrom(ChildWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext with a user gesture inside a x-origin child frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CreateGesture_Child) {
  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext with a user gesture inside a main frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CreateGesture_Main) {
  LocalFrame::NotifyUserActivation(
      GetWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then calls resume with a user gesture inside a
// x-origin child frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CallResumeGesture_Child) {
  ScriptState::Scope scope(GetScriptStateFrom(ChildWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  audio_context->resumeContext(GetScriptStateFrom(ChildWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then calls resume with a user gesture inside a main
// frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_CallResumeGesture_Main) {
  ScriptState::Scope scope(GetScriptStateFrom(GetWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      GetWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  audio_context->resumeContext(GetScriptStateFrom(GetWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then calls start on a node without a gesture inside a
// x-origin child frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_NodeStartNoGesture_Child) {
  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->NotifySourceNodeStart();
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric, static_cast<int>(AutoplayStatus::kFailed),
          1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then calls start on a node without a gesture inside a
// main frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_NodeStartNoGesture_Main) {
  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->NotifySourceNodeStart();
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kFailed), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then calls start on a node with a gesture inside a
// x-origin child frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_NodeStartGesture_Child) {
  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->NotifySourceNodeStart();
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then calls start on a node with a gesture inside a
// main frame.
TEST_P(AudioContextAutoplayTest, AutoplayMetrics_NodeStartGesture_Main) {
  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      GetWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->NotifySourceNodeStart();
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then calls start on a node without a gesture and
// finally allows the AudioContext to produce sound inside x-origin child frame.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_NodeStartNoGestureThenSuccess_Child) {
  ScriptState::Scope scope(GetScriptStateFrom(ChildWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->NotifySourceNodeStart();

  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->resumeContext(GetScriptStateFrom(ChildWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then calls start on a node without a gesture and
// finally allows the AudioContext to produce sound inside a main frame.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_NodeStartNoGestureThenSuccess_Main) {
  ScriptState::Scope scope(GetScriptStateFrom(GetWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  audio_context->NotifySourceNodeStart();

  LocalFrame::NotifyUserActivation(
      GetWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->resumeContext(GetScriptStateFrom(GetWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Creates an AudioContext then calls start on a node with a gesture and
// finally allows the AudioContext to produce sound inside x-origin child frame.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_NodeStartGestureThenSucces_Child) {
  ScriptState::Scope scope(GetScriptStateFrom(ChildWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->NotifySourceNodeStart();
  audio_context->resumeContext(GetScriptStateFrom(ChildWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Creates an AudioContext then calls start on a node with a gesture and
// finally allows the AudioContext to produce sound inside a main frame.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_NodeStartGestureThenSucces_Main) {
  ScriptState::Scope scope(GetScriptStateFrom(GetWindow()));

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);

  LocalFrame::NotifyUserActivation(
      GetWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);
  audio_context->NotifySourceNodeStart();
  audio_context->resumeContext(GetScriptStateFrom(GetWindow()),
                               ASSERT_NO_EXCEPTION);
  RejectPendingResolvers(audio_context);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Attempts to autoplay an AudioContext in a x-origin child frame when the
// document previous received a user gesture.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_DocumentReceivedGesture_Child) {
  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  AudioContext* audio_context = AudioContext::Create(
      &ChildWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayCrossOriginMetric,
          static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 1);
      break;
  }
}

// Attempts to autoplay an AudioContext in a main child frame when the
// document previous received a user gesture.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_DocumentReceivedGesture_Main) {
  LocalFrame::NotifyUserActivation(
      ChildWindow().GetFrame(), mojom::UserActivationNotificationType::kTest);

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

// Attempts to autoplay an AudioContext in a main child frame when the
// document received a user gesture before navigation.
TEST_P(AudioContextAutoplayTest,
       AutoplayMetrics_DocumentReceivedGesture_BeforeNavigation) {
  GetWindow().GetFrame()->SetHadStickyUserActivationBeforeNavigation(true);

  AudioContext* audio_context = AudioContext::Create(
      &GetWindow(), AudioContextOptions::Create(), ASSERT_NO_EXCEPTION);
  RecordAutoplayStatus(audio_context);

  switch (GetParam()) {
    case AutoplayPolicy::Type::kNoUserGestureRequired:
    case AutoplayPolicy::Type::kUserGestureRequired:
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 0);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
    case AutoplayPolicy::Type::kDocumentUserActivationRequired:
      GetHistogramTester()->ExpectBucketCount(
          kAutoplayMetric, static_cast<int>(AutoplayStatus::kSucceeded), 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayMetric, 1);
      GetHistogramTester()->ExpectTotalCount(kAutoplayCrossOriginMetric, 0);
      break;
  }
}

INSTANTIATE_TEST_SUITE_P(
    AudioContextAutoplayTest,
    AudioContextAutoplayTest,
    testing::Values(AutoplayPolicy::Type::kNoUserGestureRequired,
                    AutoplayPolicy::Type::kUserGestureRequired,
                    AutoplayPolicy::Type::kDocumentUserActivationRequired));

}  // namespace blink
```
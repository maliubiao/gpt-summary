Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the File's Purpose:**

The file name `push_pull_fifo_test.cc` immediately suggests it's a test file for a class named `PushPullFIFO`. The `blink/renderer/platform/audio/` path further indicates this FIFO is related to audio processing within the Chromium Blink rendering engine. The `.cc` extension confirms it's C++ source code.

**2. Identifying Key Components and Concepts:**

Scanning the includes at the top reveals important dependencies:

* `#include "third_party/blink/renderer/platform/audio/push_pull_fifo.h"`: This is the header file for the class being tested. It's crucial for understanding the interface of `PushPullFIFO`.
* `#include "testing/gtest/include/gtest/gtest.h"`: This signifies the use of Google Test, a common C++ testing framework. We know the file contains unit tests.
* `#include "third_party/blink/public/platform/platform.h"`: Likely provides general platform-level abstractions.
* `#include "third_party/blink/renderer/platform/audio/audio_utilities.h"`:  Suggests the FIFO deals with audio data in chunks (likely render quanta).
* `#include "third_party/blink/renderer/platform/scheduler/public/thread.h"`:  Hints at potential multi-threading aspects, although the initial tests focus on single-threaded scenarios.
* `scoped_refptr<AudioBus>`:  This is a key data structure for holding audio data. We need to understand that it represents a multi-channel audio buffer.

**3. Analyzing the Test Structure:**

The file uses Google Test macros like `TEST()` and `TEST_P()`.

* `TEST(PushPullFIFOBasicTest, BasicTests)`: This is a simple test suite for basic FIFO contract validation. The name suggests it focuses on fundamental behaviors.
* `TEST_P(PushPullFIFOFeatureTest, FeatureTests)` and `TEST_P(PushPullFIFOEarmarkFramesTest, FeatureTests)`: The `_P` indicates *parameterized tests*. This means the tests are run multiple times with different input data sets. This is a strong indicator of more complex testing scenarios.
* `INSTANTIATE_TEST_SUITE_P(...)`:  This macro is used to provide the parameter sets for the parameterized tests. The `g_feature_test_params` and `g_earmark_test_params` arrays are where the actual test cases are defined.

**4. Deciphering Individual Tests:**

* **`PushPullFIFOBasicTest`:**  Focuses on error handling (`EXPECT_DEATH_IF_SUPPORTED`). It checks if the FIFO correctly rejects invalid input buffer sizes or invalid pull requests. This helps understand the basic constraints of the `PushPullFIFO` class.

* **Helper Functions:**  The `FillBusWithLinearRamp` and `VerifyBusValueAtIndex` functions are utilities to populate audio buffers with predictable data and verify their contents. This is a common pattern in testing audio processing logic.

* **Data Structures for Parameterized Tests:**  The `FIFOAction`, `AudioBusSample`, `FIFOTestSetup`, `FIFOTestExpectedState`, and `FIFOTestParam` structs define the structure of the parameterized test cases. Understanding these structures is crucial to understanding the test scenarios. Notice how they define actions (push/pull), expected FIFO state (read/write pointers, overflow/underflow counts), and expected data within the FIFO and output buffers.

* **`PushPullFIFOFeatureTest`:**  This is the core of the functional testing. It iterates through a series of "push" and "pull" actions defined in the `fifo_actions` vector. It then compares the *actual* state of the FIFO after these actions with the *expected* state. This provides comprehensive testing of the FIFO's behavior under various conditions.

* **`PushPullFIFOEarmarkFramesTest`:** This test suite specifically targets the `SetEarmarkFrames` functionality. The "earmark" concept likely relates to pre-allocating buffer space to avoid underruns. The tests simulate scenarios with underruns and verify how the earmark size is adjusted.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

At this point, we need to leverage our knowledge of web technologies and how they relate to audio processing.

* **JavaScript and the Web Audio API:** The most direct connection is the Web Audio API. JavaScript code uses this API to manipulate audio streams, often involving buffering and processing. The `PushPullFIFO` likely plays a role in the underlying implementation of the Web Audio API within the browser. Specifically, it could be used for:
    * Buffering audio data received from network streams (e.g., `<audio>` or `<video>` elements).
    * Managing audio data within `ScriptProcessorNode` (now deprecated but illustrative) or `AudioWorkletNode`, where JavaScript code directly processes audio.
    * Internal buffering within the browser's audio rendering pipeline.

* **HTML:** The `<audio>` and `<video>` elements in HTML are the primary ways to embed audio and video content. The browser's audio pipeline, which might involve a `PushPullFIFO`, handles the playback of this content.

* **CSS:**  While CSS doesn't directly interact with audio *data*, it can control the visual aspects of audio players or visualizations. There's an indirect relationship in terms of the user interface surrounding audio playback.

**6. Logical Reasoning and Example Inputs/Outputs:**

For the parameterized tests, the `g_feature_test_params` and `g_earmark_test_params` arrays *are* the example inputs. The `expected_state` within each parameter set defines the corresponding expected outputs (FIFO state, buffer contents). To create a *new* example:

* **Hypothetical Input:** Imagine pushing 256 frames and then pulling 128 frames.
* **Expected Output:**  The read index should advance by 128, the write index by 256, no overflows or underflows (assuming the FIFO is large enough), and the output buffer should contain the first 128 frames of the pushed data.

**7. Common Usage Errors:**

By analyzing the `PushPullFIFOBasicTest`, we can infer common usage errors:

* **Incorrect Buffer Size:** Providing an input buffer with a size different from the expected render quantum size.
* **Requesting Too Many Frames:**  Attempting to pull more frames than are available in the FIFO or more than the output buffer can hold.

**8. Iterative Refinement:**

As I go through the code, I would continuously refine my understanding. For example, seeing the "earmark" tests would prompt me to research the purpose of earmarking in audio buffering (likely related to preventing underruns in real-time audio processing). The cross-thread functional includes would remind me that even though the initial tests are single-threaded, the `PushPullFIFO` likely needs to be thread-safe for real-world usage in a browser.

This structured approach, starting with the high-level purpose and gradually drilling down into the details of the code and its connections to broader concepts, is key to effectively analyzing complex source code like this.
这个文件 `push_pull_fifo_test.cc` 是 Chromium Blink 引擎中用于测试 `PushPullFIFO` 类的单元测试文件。 `PushPullFIFO` 类位于 `blink/renderer/platform/audio/push_pull_fifo.h`，它实现了一个推拉式先进先出 (FIFO) 队列，用于音频数据的缓冲和传输。

**功能列举:**

1. **测试 `PushPullFIFO` 的基本操作:**
   - 测试在单线程场景下，`Push` (推送数据到 FIFO) 和 `Pull` (从 FIFO 拉取数据) 操作的基本功能和正确性。
   - 验证了输入和输出缓冲区的长度限制，以及 FIFO 容量的限制。

2. **测试数据完整性:**
   - 通过 `FillBusWithLinearRamp` 函数生成线性增长的音频数据，并将其推入 FIFO。
   - 通过 `VerifyBusValueAtIndex` 函数检查 FIFO 和输出缓冲区中特定位置的数据是否与预期一致，以此验证数据的完整性。

3. **测试 FIFO 的各种状态和边界条件:**
   - **正常操作:** 测试在不同通道数和 FIFO 长度下，正常的推拉操作。
   - **环绕 (Wrapping):** 测试当读写指针达到 FIFO 边界时，是否能正确环绕。
   - **溢出 (Overflow):** 测试当推送的数据超过 FIFO 容量时，溢出计数器是否正确递增，以及读取数据时是否跳过被覆盖的数据。
   - **下溢 (Underflow):** 测试当拉取的数据超过 FIFO 中现有数据量时，下溢计数器是否正确递增，以及拉取到的数据是否被填充为零。
   - **多次从空 FIFO 拉取:** 测试连续从空的 FIFO 拉取数据，验证下溢计数器的正确性以及输出数据的零填充。

4. **测试 `SetEarmarkFrames` 功能:**
   - `SetEarmarkFrames` 允许设置一个 "预留帧数"，用于提前缓冲数据，以应对音频处理中的不确定性。
   - 测试在不同的推送和拉取操作序列下，`GetEarmarkFramesForTest` 能否返回预期的预留帧数。
   - 特别测试了在发生下溢时，预留帧数如何根据回调缓冲区大小进行调整。

**与 JavaScript, HTML, CSS 的关系:**

`PushPullFIFO` 类是 Web Audio API 的底层实现之一，用于管理音频节点之间的数据流。 虽然开发者通常不会直接与 `PushPullFIFO` 交互，但它的正确性和性能直接影响到 Web Audio API 的功能。

* **JavaScript 和 Web Audio API:**
    - 当 JavaScript 代码使用 Web Audio API 创建音频节点（例如 `OscillatorNode`, `GainNode`, `ScriptProcessorNode`, `AudioWorkletNode` 等）并连接它们时，这些节点之间的数据传输可能就会用到类似 `PushPullFIFO` 这样的机制进行缓冲。
    - 例如，一个 `OscillatorNode` 生成音频数据，这些数据被 "推" 入到 `PushPullFIFO` 中。然后，`GainNode` 从这个 FIFO 中 "拉" 取数据进行处理。
    - `ScriptProcessorNode` (已废弃，但概念上相似) 或 `AudioWorkletNode` 允许 JavaScript 代码直接处理音频数据。 `PushPullFIFO` 可以用于在渲染线程和音频工作线程之间安全地传递音频数据。

* **HTML:**
    - 当 HTML 中的 `<audio>` 或 `<video>` 元素播放音频时，浏览器需要解码音频数据并将其送入音频渲染管线。 `PushPullFIFO` 可以用于缓冲解码后的音频数据，以平滑播放并避免卡顿。

* **CSS:**
    - CSS 本身与音频数据的处理没有直接关系。但是，CSS 可以用于创建与音频播放相关的用户界面元素（例如播放按钮、音量滑块、音频可视化效果），这些界面元素会触发 JavaScript 代码来控制 Web Audio API，从而间接地涉及到 `PushPullFIFO` 管理的音频数据流。

**逻辑推理，假设输入与输出:**

**示例 1 (基于 Test Case 0):**

* **假设输入:**
    * FIFO 长度: 512 帧
    * 通道数: 1
    * 操作序列:
        1. 推送 128 帧 (值为 0 到 127)
        2. 推送 128 帧 (值为 128 到 255)
        3. 拉取 256 帧

* **逻辑推理:**
    * 第一次推送后，FIFO 的读指针为 0，写指针为 128。
    * 第二次推送后，FIFO 的读指针为 0，写指针为 256。
    * 拉取 256 帧，将 FIFO 中的所有数据取出。

* **预期输出:**
    * `expected_state.index_read`: 256
    * `expected_state.index_write`: 256
    * `expected_state.overflow_count`: 0
    * `expected_state.underflow_count`: 0
    * `expected_state.fifo_samples`:  索引 0 的值为 0 (因为 FIFO 被完全拉空了)
    * `expected_state.output_samples`: 索引 0 的值为 0，索引 255 的值为 255。

**示例 2 (基于 Test Case 6，溢出):**

* **假设输入:**
    * FIFO 长度: 512 帧
    * 通道数: 3
    * 操作序列:
        1. 推送 128 帧
        2. 推送 128 帧
        3. 推送 128 帧
        4. 推送 128 帧
        5. 推送 128 帧 (此时会发生溢出)
        6. 拉取 256 帧

* **逻辑推理:**
    * 前四次推送共 512 帧，填满 FIFO。
    * 第五次推送的 128 帧会覆盖 FIFO 中最早的 128 帧，导致溢出。读指针会被移动到写指针的位置。
    * 拉取 256 帧，将拉取到覆盖后的数据。

* **预期输出:**
    * `expected_state.index_read`: 384 (写指针在溢出后覆盖的位置)
    * `expected_state.index_write`: 128 (第五次推送后的位置，因为环绕)
    * `expected_state.overflow_count`: 1
    * `expected_state.underflow_count`: 0
    * `expected_state.fifo_samples`: 索引 384 的值为 384 (第五次推送开始的数据)，索引 128 的值为 128 (第五次推送结束的位置)
    * `expected_state.output_samples`: 索引 0 的值为 128 (被覆盖后的新数据开始)，索引 255 的值为 383。

**用户或编程常见的使用错误:**

1. **推送或拉取大小不匹配:**
   - **错误:** 推送的 `AudioBus` 的帧数不是 `audio_utilities::kRenderQuantumFrames` (通常是 128)。
   - **后果:**  可能导致音频处理逻辑错误或崩溃。
   - **代码示例 (基于 `PushPullFIFOBasicTest`):**
     ```c++
     scoped_refptr<AudioBus> input_bus_129_frames =
         AudioBus::Create(2, kRenderQuantumFrames + 1);
     // 错误的推送，导致断言失败
     // test_fifo->Push(input_bus_129_frames.get());
     ```

2. **拉取超出 FIFO 容量的数据:**
   - **错误:** 尝试拉取的帧数大于 FIFO 当前可用的数据量。
   - **后果:**  导致下溢，输出的数据会被填充为零，可能造成音频播放中断或失真。
   - **代码示例 (基于 `PushPullFIFOBasicTest`):**
     ```c++
     scoped_refptr<AudioBus> output_bus_1025_frames = AudioBus::Create(2, 1025);
     // 错误的拉取，导致断言失败
     // test_fifo->Pull(output_bus_1025_frames.get(), 1025);
     ```

3. **在多线程环境下不正确地使用 FIFO:**
   - **错误:**  在没有适当的同步机制的情况下，多个线程同时访问 `PushPullFIFO` 进行推送和拉取操作。
   - **后果:** 可能导致数据竞争，造成数据损坏或程序崩溃。虽然这个测试文件主要是单线程测试，但实际应用中音频处理往往涉及多线程。

4. **未考虑溢出和下溢的情况:**
   - **错误:** 在音频处理逻辑中没有正确处理 FIFO 溢出和下溢的情况。
   - **后果:**  可能导致音频数据丢失、重复或静音。开发者需要根据具体应用场景来处理这些情况，例如通过检查 `overflow_count` 和 `underflow_count` 来判断是否发生了溢出或下溢。

总而言之，`push_pull_fifo_test.cc` 文件通过大量的单元测试用例，全面地验证了 `PushPullFIFO` 类的功能和鲁棒性，确保其在 Chromium 的音频渲染管线中能够正确可靠地工作。 这对于保证 Web Audio API 的稳定性和性能至关重要。

### 提示词
```
这是目录为blink/renderer/platform/audio/push_pull_fifo_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/audio/push_pull_fifo.h"

#include <memory>
#include <vector>

#include "base/logging.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/audio/audio_utilities.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

// Check the basic contract of FIFO. This test only covers the single thread
// scenario.
TEST(PushPullFIFOBasicTest, BasicTests) {
  // This suppresses the multi-thread warning for GTest. Potently it increases
  // the test execution time, but this specific test is very short and simple.
  GTEST_FLAG_SET(death_test_style, "threadsafe");

  const unsigned kRenderQuantumFrames = 128;

  std::unique_ptr<PushPullFIFO> test_fifo =
      std::make_unique<PushPullFIFO>(2, 1024);

  // The input bus length must be |audio_utilities::kRenderQuantumFrames|.
  // i.e.) input_bus->length() == kRenderQuantumFrames
  scoped_refptr<AudioBus> input_bus_129_frames =
      AudioBus::Create(2, kRenderQuantumFrames + 1);
  EXPECT_DEATH_IF_SUPPORTED(test_fifo->Push(input_bus_129_frames.get()), "");
  scoped_refptr<AudioBus> input_bus_127_frames =
      AudioBus::Create(2, kRenderQuantumFrames - 1);
  EXPECT_DEATH_IF_SUPPORTED(test_fifo->Push(input_bus_127_frames.get()), "");

  // Pull request frames cannot exceed the length of output bus.
  // i.e.) frames_requested <= output_bus->length()
  scoped_refptr<AudioBus> output_bus_512_frames = AudioBus::Create(2, 512);
  EXPECT_DEATH_IF_SUPPORTED(test_fifo->Pull(output_bus_512_frames.get(), 513),
                            "");

  // Pull request frames cannot exceed the length of FIFO.
  // i.e.) frames_requested <= fifo_length_
  scoped_refptr<AudioBus> output_bus_1025_frames = AudioBus::Create(2, 1025);
  EXPECT_DEATH_IF_SUPPORTED(test_fifo->Pull(output_bus_1025_frames.get(), 1025),
                            "");
}

// Fills each AudioChannel in an AudioBus with a series of linearly increasing
// values starting from |starting_value| and incrementing by 1. Then return
// value will be |starting_value| + |bus_length|.
size_t FillBusWithLinearRamp(AudioBus* target_bus, size_t starting_value) {
  for (unsigned c = 0; c < target_bus->NumberOfChannels(); ++c) {
    float* bus_channel = target_bus->Channel(c)->MutableData();
    for (size_t i = 0; i < target_bus->Channel(c)->length(); ++i) {
      bus_channel[i] = static_cast<float>(starting_value + i);
    }
  }
  return starting_value + target_bus->length();
}

// Inspect the content of AudioBus with a given set of index and value across
// channels.
bool VerifyBusValueAtIndex(AudioBus* target_bus,
                           int index,
                           float expected_value) {
  for (unsigned c = 0; c < target_bus->NumberOfChannels(); ++c) {
    float* bus_channel = target_bus->Channel(c)->MutableData();
    if (bus_channel[index] != expected_value) {
      LOG(ERROR) << ">> [FAIL] expected " << expected_value << " at index "
                 << index << " but got " << bus_channel[index] << ".";
      return false;
    }
  }
  return true;
}

struct FIFOAction {
  // The type of action; "PUSH" or "PULL".
  const char* action;
  // Number of frames for the operation.
  const size_t number_of_frames;
};

struct AudioBusSample {
  // The frame index of a sample in the bus.
  const size_t index;
  // The value at the |index| above.
  const float value;
};

struct FIFOTestSetup {
  // Length of FIFO to be created for test case.
  const size_t fifo_length;
  // Channel count of FIFO to be created for test case.
  const unsigned number_of_channels;
  // A list of |FIFOAction| entries to be performed in test case.
  const std::vector<FIFOAction> fifo_actions;
};

struct FIFOTestExpectedState {
  // Expected read index in FIFO.
  const size_t index_read;
  // Expected write index in FIFO.
  const size_t index_write;
  // Expected overflow count in FIFO.
  const unsigned overflow_count;
  // Expected underflow count in FIFO.
  const unsigned underflow_count;
  // A list of expected |AudioBusSample| entries for the FIFO bus.
  const std::vector<AudioBusSample> fifo_samples;
  // A list of expected |AudioBusSample| entries for the output bus.
  const std::vector<AudioBusSample> output_samples;
};

// The data structure for the parameterized test cases.
struct FIFOTestParam {
  FIFOTestSetup setup;
  FIFOTestExpectedState expected_state;
};

std::ostream& operator<<(std::ostream& out, const FIFOTestParam& param) {
  out << "fifoLength=" << param.setup.fifo_length
      << " numberOfChannels=" << param.setup.number_of_channels;
  return out;
}

class PushPullFIFOFeatureTest : public testing::TestWithParam<FIFOTestParam> {};

TEST_P(PushPullFIFOFeatureTest, FeatureTests) {
  const FIFOTestSetup setup = GetParam().setup;
  const FIFOTestExpectedState expected_state = GetParam().expected_state;

  // Create a FIFO with a specified configuration.
  std::unique_ptr<PushPullFIFO> fifo = std::make_unique<PushPullFIFO>(
      setup.number_of_channels, setup.fifo_length);

  scoped_refptr<AudioBus> output_bus;

  // Iterate all the scheduled push/pull actions.
  size_t frame_counter = 0;
  for (const auto& action : setup.fifo_actions) {
    if (strcmp(action.action, "PUSH") == 0) {
      scoped_refptr<AudioBus> input_bus =
          AudioBus::Create(setup.number_of_channels, action.number_of_frames);
      frame_counter = FillBusWithLinearRamp(input_bus.get(), frame_counter);
      fifo->Push(input_bus.get());
      LOG(INFO) << "PUSH " << action.number_of_frames
                << " frames (frameCounter=" << frame_counter << ")";
    } else {
      output_bus =
          AudioBus::Create(setup.number_of_channels, action.number_of_frames);
      fifo->Pull(output_bus.get(), action.number_of_frames);
      LOG(INFO) << "PULL " << action.number_of_frames << " frames";
    }
  }

  // Get FIFO config data.
  const PushPullFIFOStateForTest actual_state = fifo->GetStateForTest();

  // Verify the read/write indexes.
  EXPECT_EQ(expected_state.index_read, actual_state.index_read);
  EXPECT_EQ(expected_state.index_write, actual_state.index_write);
  EXPECT_EQ(expected_state.overflow_count, actual_state.overflow_count);
  EXPECT_EQ(expected_state.underflow_count, actual_state.underflow_count);

  // Verify in-FIFO samples.
  for (const auto& sample : expected_state.fifo_samples) {
    EXPECT_TRUE(VerifyBusValueAtIndex(fifo->GetFIFOBusForTest(),
                                      sample.index, sample.value));
  }

  // Verify samples from the most recent output bus.
  for (const auto& sample : expected_state.output_samples) {
    EXPECT_TRUE(
        VerifyBusValueAtIndex(output_bus.get(), sample.index, sample.value));
  }
}

FIFOTestParam g_feature_test_params[] = {
    // Test cases 0 ~ 3: Regular operation on various channel configuration.
    //  - Mono, Stereo, Quad, 5.1.
    //  - FIFO length and pull size are RQ-aligned.
    {{512, 1, {{"PUSH", 128}, {"PUSH", 128}, {"PULL", 256}}},
     {256, 256, 0, 0, {{0, 0}}, {{0, 0}, {255, 255}}}},

    {{512, 2, {{"PUSH", 128}, {"PUSH", 128}, {"PULL", 256}}},
     {256, 256, 0, 0, {{0, 0}}, {{0, 0}, {255, 255}}}},

    {{512, 4, {{"PUSH", 128}, {"PUSH", 128}, {"PULL", 256}}},
     {256, 256, 0, 0, {{0, 0}}, {{0, 0}, {255, 255}}}},

    {{512, 6, {{"PUSH", 128}, {"PUSH", 128}, {"PULL", 256}}},
     {256, 256, 0, 0, {{0, 0}}, {{0, 0}, {255, 255}}}},

    // Test case 4: Pull size less than or equal to 128.
    {{128, 2, {{"PUSH", 128}, {"PULL", 128}, {"PUSH", 128}, {"PULL", 64}}},
     {64, 0, 0, 0, {{64, 192}, {0, 128}}, {{0, 128}, {63, 191}}}},

    // Test case 5: Unusual FIFO and Pull length.
    //  - FIFO and pull length that are not aligned to render quantum.
    //  - Check if the indexes are wrapping around correctly.
    //  - Check if the output bus starts and ends with correct values.
    {{997,
      1,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 449},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 449},
      }},
     // - expectedIndexRead = 898, expectedIndexWrite = 27
     // - overflowCount = 0, underflowCount = 0
     // - FIFO samples (index, expectedValue) = (898, 898), (27, 27)
     // - Output bus samples (index, expectedValue) = (0, 499), (448, 897)
     {898, 27, 0, 0, {{898, 898}, {27, 27}}, {{0, 449}, {448, 897}}}},

    // Test case 6: Overflow
    //  - Check overflow counter.
    //  - After the overflow occurs, the read index must be moved to the write
    //    index. Thus pulled frames must not contain overwritten data.
    {{512,
      3,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 256},
      }},
     // - expectedIndexRead = 384, expectedIndexWrite = 128
     // - overflowCount = 1, underflowCount = 0
     // - FIFO samples (index, expectedValue) = (384, 384), (128, 128)
     // - Output bus samples (index, expectedValue) = (0, 128), (255, 383)
     {384, 128, 1, 0, {{384, 384}, {128, 128}}, {{0, 128}, {255, 383}}}},

    // Test case 7: Overflow in unusual FIFO and pull length.
    //  - Check overflow counter.
    //  - After the overflow occurs, the read index must be moved to the write
    //    index. Thus pulled frames must not contain overwritten data.
    {{577,
      5,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 227},
      }},
     // - expectedIndexRead = 290, expectedIndexWrite = 63
     // - overflowCount = 1, underflowCount = 0
     // - FIFO samples (index, expectedValue) = (63, 63), (290, 290)
     // - Output bus samples (index, expectedValue) = (0, 63), (226, 289)
     {290, 63, 1, 0, {{63, 63}, {290, 290}}, {{0, 63}, {226, 289}}}},

    // Test case 8: Underflow
    //  - Check underflow counter.
    //  - After the underflow occurs, the write index must be moved to the read
    //    index. Frames pulled after FIFO underflows must be zeroed.
    {{512,
      7,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 384},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 384},
      }},
     // - expectedIndexRead = 128, expectedIndexWrite = 128
     // - overflowCount = 0, underflowCount = 1
     // - FIFO samples (index, expectedValue) = (128, 128)
     // - Output bus samples (index, expectedValue) = (0, 384), (255, 639)
     //                                               (256, 0), (383, 0)
     {128,
      128,
      0,
      1,
      {{128, 128}},
      {{0, 384}, {255, 639}, {256, 0}, {383, 0}}}},

    // Test case 9: Underflow in unusual FIFO and pull length.
    //  - Check underflow counter.
    //  - After the underflow occurs, the write index must be moved to the read
    //    index. Frames pulled after FIFO underflows must be zeroed.
    {{523,
      11,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 383},
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 383},
      }},
     // - expectedIndexRead = 117, expectedIndexWrite = 117
     // - overflowCount = 0, underflowCount = 1
     // - FIFO samples (index, expectedValue) = (117, 117)
     // - Output bus samples (index, expectedValue) = (0, 383), (256, 639)
     //                                               (257, 0), (382, 0)
     {117,
      117,
      0,
      1,
      {{117, 117}},
      {{0, 383}, {256, 639}, {257, 0}, {382, 0}}}},

    // Test case 10: Multiple pull from an empty FIFO.
    //  - Check underflow counter.
    //  - After the underflow occurs, the write index must be moved to the read
    //    index. Frames pulled after FIFO underflows must be zeroed.
    {{1024,
      11,
      {
          {"PUSH", 128},
          {"PUSH", 128},
          {"PULL", 440},
          {"PULL", 440},
          {"PULL", 440},
          {"PULL", 440},
          {"PULL", 440},
      }},
     // - expectedIndexRead = 117, expectedIndexWrite = 117
     // - overflowCount = 0, underflowCount = 1
     // - FIFO samples (index, expectedValue) = (117, 117)
     // - Output bus samples (index, expectedValue) = (0, 383), (256, 639)
     //                                               (257, 0), (382, 0)
     {256, 256, 0, 5, {{256, 0}}, {{0, 0}, {439, 0}}}},

    // Test case 11: Multiple pull from an empty FIFO. (zero push)
    {{1024,
      11,
      {
          {"PULL", 144},
          {"PULL", 144},
          {"PULL", 144},
          {"PULL", 144},
      }},
     // - expectedIndexRead = 0, expectedIndexWrite = 0
     // - overflowCount = 0, underflowCount = 4
     // - FIFO samples (index, expectedValue) = (0, 0), (1023, 0)
     // - Output bus samples (index, expectedValue) = (0, 0), (143, 0)
     {0, 0, 0, 4, {{0, 0}, {1023, 0}}, {{0, 0}, {143, 0}}}}};

INSTANTIATE_TEST_SUITE_P(PushPullFIFOFeatureTest,
                         PushPullFIFOFeatureTest,
                         testing::ValuesIn(g_feature_test_params));


struct FIFOEarmarkTestParam {
  FIFOTestSetup setup;
  size_t callback_buffer_size;
  size_t expected_earmark_frames;
};

class PushPullFIFOEarmarkFramesTest
    : public testing::TestWithParam<FIFOEarmarkTestParam> {};

TEST_P(PushPullFIFOEarmarkFramesTest, FeatureTests) {
  const FIFOTestSetup setup = GetParam().setup;
  const size_t callback_buffer_size = GetParam().callback_buffer_size;
  const size_t expected_earmark_frames = GetParam().expected_earmark_frames;

  // Create a FIFO with a specified configuration.
  std::unique_ptr<PushPullFIFO> fifo = std::make_unique<PushPullFIFO>(
      setup.number_of_channels, setup.fifo_length);
  fifo->SetEarmarkFrames(callback_buffer_size);

  scoped_refptr<AudioBus> output_bus;

  // Iterate all the scheduled push/pull actions.
  size_t frame_counter = 0;
  for (const auto& action : setup.fifo_actions) {
    if (strcmp(action.action, "PUSH") == 0) {
      scoped_refptr<AudioBus> input_bus =
          AudioBus::Create(setup.number_of_channels, action.number_of_frames);
      frame_counter = FillBusWithLinearRamp(input_bus.get(), frame_counter);
      fifo->Push(input_bus.get());
      LOG(INFO) << "PUSH " << action.number_of_frames
                << " frames (frameCounter=" << frame_counter << ")";
    } else if (strcmp(action.action, "PULL_EARMARK") == 0) {
      output_bus =
          AudioBus::Create(setup.number_of_channels, action.number_of_frames);
      fifo->PullAndUpdateEarmark(output_bus.get(), action.number_of_frames);
      LOG(INFO) << "PULL_EARMARK " << action.number_of_frames << " frames";
    } else {
      NOTREACHED();
    }
  }

  // Test the earmark frames.
  const size_t actual_earmark_frames = fifo->GetEarmarkFramesForTest();
  EXPECT_EQ(expected_earmark_frames, actual_earmark_frames);
}

FIFOEarmarkTestParam g_earmark_test_params[] = {
  // When there's no underrun, the earmark is equal to the callback size.
  {{8192, 2, {
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 256},
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 256}
    }}, 256, 256},
  // The first underrun increases the earmark by the callback size.
  {{8192, 2, {
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 384}, // udnerrun; updating earmark and skipping pull.
      {"PUSH", 128},
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 384}  // OK
    }}, 384, 768},
  // Simulating "bursty and irregular" callbacks.
  {{8192, 2, {
      {"PUSH", 128},
      {"PUSH", 128},
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 480}, // OK
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 480}, // underrun; updating earmark and skipping pull.
      {"PUSH", 128},
      {"PUSH", 128},
      {"PUSH", 128},
      {"PULL_EARMARK", 480}, // OK
      {"PUSH", 128},
      {"PULL_EARMARK", 480}  // underrun; updating earmark and skipping pull.
    }}, 480, 1440}
};

INSTANTIATE_TEST_SUITE_P(PushPullFIFOEarmarkFramesTest,
                         PushPullFIFOEarmarkFramesTest,
                         testing::ValuesIn(g_earmark_test_params));

}  // namespace

}  // namespace blink
```
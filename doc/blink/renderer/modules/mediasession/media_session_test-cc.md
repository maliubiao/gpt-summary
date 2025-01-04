Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Skim and Purpose Identification:**

* **Keywords:** "test.cc", "MediaSession". These immediately suggest this file contains tests related to the `MediaSession` functionality in Blink.
* **Copyright Notice:** Confirms it's part of the Chromium project.
* **Includes:** Look at the included headers:
    * `<mediasession/media_session.h>`:  This is the core component being tested.
    * `base/test/simple_test_tick_clock.h`: Likely used for mocking time, important for media playback.
    * `mojo/public/cpp/bindings/...`: Indicates interaction with Mojo, Chromium's IPC system. This suggests the `MediaSession` likely communicates with other processes.
    * `testing/gmock/...`:  Confirms the use of Google Mock for creating mock objects.
    * `renderer/bindings/modules/v8/...`:  Points to interactions with JavaScript through V8 bindings related to `MediaPositionState` and `MediaSessionPlaybackState`.
    * `renderer/core/frame/...`: Shows involvement with the DOM and frame structure.
    * `renderer/core/testing/page_test_base.h`:  Indicates this is a standard Blink layout test.
    * `renderer/platform/bindings/exception_state.h`:  Related to handling exceptions in the Blink environment.

* **Overall:**  The file tests the `MediaSession` class, likely focusing on its interaction with external services (via Mojo) and how it reflects state changes (like playback position and state) that might originate from JavaScript.

**2. Identifying Key Components and Their Roles:**

* **`MockMediaSessionService`:**  A mock implementation of the `mojom::blink::MediaSessionService` interface. This is crucial. It isolates the `MediaSession` class being tested from the actual underlying service implementation. This allows testing the logic *within* `MediaSession` without relying on the full, potentially complex, service. The MOCK_METHODs indicate what interactions are being verified.
* **`MediaSessionTest`:** The main test fixture. It sets up the test environment, including:
    * Creating an instance of `MediaSession`.
    * Creating and binding the `MockMediaSessionService`.
    * Using `SimpleTestTickClock` for controlled time manipulation.
* **Helper Methods:** `SetPositionState`, `SetPositionStateThrowsException`, `ClearPositionState`, `SetPlaybackState`. These provide a clean interface for manipulating the `MediaSession` state during tests.
* **`TEST_F` macros:**  Standard Google Test macros defining individual test cases.

**3. Analyzing Individual Test Cases:**

* **Naming Conventions:**  Test names are descriptive (e.g., `PlaybackPositionState_None`, `PositionPlaybackState_Paused_Playing`).
* **Common Pattern:** Most tests follow this pattern:
    1. **`base::RunLoop loop;`**: Creates a message loop to handle asynchronous operations.
    2. **`EXPECT_CALL(service(), SetPositionState(_))`**: Uses Google Mock to set up an expectation that the `SetPositionState` method of the mock service will be called. The `_` is a wildcard matcher.
    3. **`.WillOnce(testing::Invoke([&](auto position_state) { ... }))`**:  Specifies the action to take when the mocked method is called. This is where the actual assertions about the `position_state` are made.
    4. **Setting up the `MediaSession` state**: Calls the helper methods (e.g., `SetPlaybackState`, `SetPositionState`).
    5. **`loop.Run();`**:  Runs the message loop, allowing the expected mock call to occur and the assertions to be checked.
* **Specific Scenarios:**  The tests cover different combinations of playback states (`None`, `Paused`, `Playing`) and position states. They also test edge cases like infinite and NaN duration.

**4. Connecting to JavaScript, HTML, and CSS:**

* **JavaScript Connection:**  The `MediaSession` API is directly exposed to JavaScript. The test indirectly verifies this by checking the behavior of the C++ implementation. JavaScript code would use methods like `navigator.mediaSession.setPositionState()` and `navigator.mediaSession.playbackState = ...`.
* **HTML Connection:**  The `<video>` or `<audio>` elements in an HTML page are the primary drivers for media playback. User interaction with these elements (play, pause, seek) would trigger events that eventually lead to updates in the `MediaSession` state.
* **CSS Connection:** While CSS itself doesn't directly interact with `MediaSession` functionality, it can be used to style media controls. The visual representation of the playback state (e.g., a play/pause button) often reflects the underlying `MediaSession` state.

**5. Logical Reasoning and Input/Output:**

* **Assumption:** The test assumes that when `setPositionState` is called with specific values, the `MockMediaSessionService` will receive a `MediaPositionPtr` with the expected data.
* **Input (Example from `PlaybackPositionState_Paused`):**
    * Calling `SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPaused)`
    * Calling `SetPositionState(10, 5, 1.0)`
* **Output:** The `MockMediaSessionService`'s `SetPositionState` method is called with a `MediaPositionPtr` where:
    * `duration` is 10 seconds.
    * `position` is 5 seconds.
    * `playback_rate` is 0.0 (because the playback state is paused).
    * `last_updated_time` is the current time.

**6. Common User/Programming Errors:**

* **Incorrect Units:**  Providing duration or position in the wrong units (e.g., milliseconds instead of seconds). The test uses doubles representing seconds.
* **Setting Invalid Values:** Trying to set NaN or negative values for duration or position (the test explicitly checks for NaN duration).
* **Race Conditions:** In a real application, there might be race conditions between setting the playback state and the position state. The test aims to verify the correct behavior in these scenarios.

**7. User Operation to Reach the Code:**

* **Scenario:** A user is watching a video on a website.
* **Steps:**
    1. **User opens a webpage containing a `<video>` element.**
    2. **The video starts playing (JavaScript calls `video.play()`).** This might trigger `navigator.mediaSession.playbackState = 'playing'`.
    3. **The video progresses.** The website's JavaScript might periodically call `navigator.mediaSession.setPositionState()` to update the playback position.
    4. **The user pauses the video (clicks a pause button).** This triggers `navigator.mediaSession.playbackState = 'paused'`.
    5. **The user seeks to a different part of the video (drags a seek bar).** This triggers `navigator.mediaSession.setPositionState()` with the new position.

**8. Debugging Clues:**

* **Failing Assertions:** If a test fails, the specific assertion that failed provides a starting point for debugging.
* **Mock Service Calls:** Examining the calls made to the `MockMediaSessionService` (using the `EXPECT_CALL` setup) can help understand what the `MediaSession` class is trying to communicate with the external service.
* **Time Manipulation:** The use of `SimpleTestTickClock` means that time-related issues can be investigated by advancing the clock manually and observing the behavior.

By following these steps, one can systematically analyze the C++ test file and understand its purpose, functionality, relationships with other technologies, and its role in ensuring the correctness of the `MediaSession` implementation.
这个C++源代码文件 `media_session_test.cc` 是 Chromium Blink 引擎中 `MediaSession` 模块的单元测试文件。它的主要功能是**测试 `MediaSession` 类的各种行为和状态管理**。

更具体地说，它测试了以下方面：

**1. `MediaSession` 对象与底层 MediaSessionService 的交互:**

   -  **功能:** 测试 `MediaSession` 对象是否正确地将状态信息（如播放状态和位置信息）传递给底层的 `MediaSessionService`。
   -  **关系:**  `MediaSession` 是 Blink 引擎中暴露给 JavaScript 的接口，而 `MediaSessionService` (通过 Mojo IPC)  是 Chromium 浏览器进程中负责处理媒体会话的核心服务。
   -  **举例说明:**
      -  JavaScript 代码调用 `navigator.mediaSession.playbackState = 'playing'` 时，`MediaSession` 对象应该调用 `MediaSessionService` 的 `SetPlaybackState` 方法。
      -  JavaScript 代码调用 `navigator.mediaSession.setPositionState({ duration: 10, position: 5, playbackRate: 1 })` 时，`MediaSession` 对象应该调用 `MediaSessionService` 的 `SetPositionState` 方法，并将相应的参数传递过去。
   -  **逻辑推理 (假设):**
      -  **假设输入 (JavaScript):** `navigator.mediaSession.playbackState = 'paused'; navigator.mediaSession.setPositionState({ duration: 100, position: 30 })`
      -  **输出 (C++ Mock):**  `MockMediaSessionService::SetPlaybackState` 被调用，参数为 `mojom::blink::MediaSessionPlaybackState::kPaused`。随后 `MockMediaSessionService::SetPositionState` 被调用，参数包含 `duration = 100秒`, `position = 30秒`, `playback_rate` 根据当时的播放状态（暂停时为 0）计算。

**2. 播放位置状态的管理 (`setPositionState`):**

   -  **功能:** 测试 `MediaSession` 如何处理和传递播放位置信息，包括持续时间、当前位置和播放速率。
   -  **关系:**  这直接对应了 JavaScript 中 `navigator.mediaSession.setPositionState()` 方法的功能。
   -  **举例说明:**
      -  测试文件中的 `TEST_F(MediaSessionTest, PlaybackPositionState_None)` 测试了当播放状态为 "none" 时，设置位置状态会将播放速率设置为 1.0。
      -  `TEST_F(MediaSessionTest, PlaybackPositionState_Paused)` 测试了当播放状态为 "paused" 时，设置位置状态会将播放速率设置为 0.0。
   -  **逻辑推理 (假设):**
      -  **假设输入 (C++):** 调用 `SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPlaying)`，然后调用 `SetPositionState(60, 15, 1.5)`。
      -  **输出 (C++ Mock):** `MockMediaSessionService::SetPositionState` 被调用，参数包含 `duration = 60秒`, `position = 15秒`, `playback_rate = 1.5`。

**3. 播放状态的管理 (`setPlaybackState`):**

   -  **功能:** 测试 `MediaSession` 如何处理和传递播放状态的变化 (例如 "playing", "paused", "none")。
   -  **关系:** 这直接对应了 JavaScript 中设置 `navigator.mediaSession.playbackState` 属性的功能。
   -  **举例说明:**
      -  测试文件中的 `TEST_F(MediaSessionTest, PositionPlaybackState_Paused_None)` 测试了先设置位置状态，然后设置播放状态为 "paused"，再设置回 "none" 的场景，验证位置信息的更新和传递。

**4. 异常处理:**

   -  **功能:** 测试当传入无效的播放位置参数时，`MediaSession` 是否会抛出异常。
   -  **关系:**  对应了 JavaScript 中调用 `setPositionState` 时可能抛出的异常。
   -  **举例说明:**
      -  `TEST_F(MediaSessionTest, PlaybackPositionState_NaNDuration)` 测试了当 duration 为 NaN (Not a Number) 时，调用 `setPositionState` 是否会抛出 `TypeError` 异常。
   -  **用户或编程常见的使用错误:**
      -  在 JavaScript 中，开发者可能会错误地将非数字类型的值传递给 `setPositionState` 的 `duration` 或 `position` 属性。例如：
         ```javascript
         navigator.mediaSession.setPositionState({ duration: "abc", position: 10 }); // 应该传递数字
         ```
      -  开发者可能会忘记处理 `setPositionState` 可能抛出的异常。

**5. 时间管理:**

   -  **功能:** 使用 `SimpleTestTickClock` 来模拟时间流逝，以便测试与时间相关的逻辑，例如最后更新时间。
   -  **关系:** 播放位置的更新时间戳 (`last_updated_time`) 用于外部 (如操作系统) 同步媒体会话状态。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在网页上与媒体元素 (例如 `<video>` 或 `<audio>`) 交互:**  用户可能点击了播放按钮、暂停按钮、或者拖动了进度条。

2. **JavaScript 代码捕获用户操作并调用 Media Session API:**
    -  例如，点击播放按钮可能导致 JavaScript 代码调用 `videoElement.play()`。
    -  浏览器内部的媒体框架会响应 `play()` 操作，并可能更新 `navigator.mediaSession.playbackState = 'playing'`.
    -  拖动进度条可能导致 JavaScript 代码计算新的播放位置，并调用 `navigator.mediaSession.setPositionState({ position: newPosition })`.

3. **Blink 引擎接收到 JavaScript 的调用:**
    -  当 JavaScript 代码调用 `navigator.mediaSession.setPositionState()` 或设置 `navigator.mediaSession.playbackState` 时，这些调用会进入 Blink 引擎的 C++ 代码。
    -  具体地，会调用 `blink::MediaSession` 类中的相应方法 (例如 `setPositionState` 或 `setPlaybackState`)。

4. **`blink::MediaSession` 类处理调用并与 `MediaSessionService` 通信:**
    -  `blink::MediaSession` 类会将 JavaScript 传递过来的信息转换成 Mojo 消息，并发送给浏览器进程中的 `MediaSessionService`。
    -  例如，`setPositionState` 的调用会创建一个 `media_session::mojom::blink::MediaPositionPtr` 对象，并通过 Mojo 发送。

5. **调试到 `media_session_test.cc`:**
    -  当开发者怀疑 `MediaSession` 模块的行为不正确时，他们会查看 `media_session_test.cc` 文件中的单元测试。
    -  他们可能会运行特定的测试用例来验证 `MediaSession` 在特定场景下的行为。
    -  如果测试失败，开发者可以使用调试器 (例如 gdb) 来跟踪代码执行流程，从 JavaScript 调用一直到 `blink::MediaSession` 类的内部，并观察 `MockMediaSessionService` 的调用情况，从而找到问题所在。

**总结:**

`media_session_test.cc` 是一个关键的测试文件，它通过模拟 JavaScript 的调用和验证与底层服务的交互，确保了 `MediaSession` 模块功能的正确性。它涵盖了播放状态、位置状态的管理，以及异常处理等关键方面。 理解这个文件有助于理解 Blink 引擎中媒体会话功能的实现和调试。

Prompt: 
```
这是目录为blink/renderer/modules/mediasession/media_session_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediasession/media_session.h"

#include "base/test/simple_test_tick_clock.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_position_state.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_media_session_playback_state.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

using testing::_;

namespace {

class MockMediaSessionService : public mojom::blink::MediaSessionService {
 public:
  MockMediaSessionService() = default;

  HeapMojoRemote<mojom::blink::MediaSessionService> CreateRemoteAndBind(
      ContextLifecycleNotifier* notifier,
      scoped_refptr<base::SequencedTaskRunner> task_runner) {
    HeapMojoRemote<mojom::blink::MediaSessionService> remote(notifier);
    remote.Bind(receiver_.BindNewPipeAndPassRemote(), task_runner);
    return remote;
  }

  void SetClient(
      mojo::PendingRemote<mojom::blink::MediaSessionClient> client) override {}
  void SetPlaybackState(
      mojom::blink::MediaSessionPlaybackState state) override {}
  MOCK_METHOD1(SetPositionState,
               void(media_session::mojom::blink::MediaPositionPtr));
  void SetMetadata(mojom::blink::SpecMediaMetadataPtr metadata) override {}
  void SetMicrophoneState(
      media_session::mojom::MicrophoneState microphone_state) override {}
  void SetCameraState(media_session::mojom::CameraState camera_state) override {
  }
  void EnableAction(
      media_session::mojom::blink::MediaSessionAction action) override {}
  void DisableAction(
      media_session::mojom::blink::MediaSessionAction action) override {}

 private:
  mojo::Receiver<mojom::blink::MediaSessionService> receiver_{this};
};

}  // namespace

class MediaSessionTest : public PageTestBase {
 public:
  MediaSessionTest() = default;

  MediaSessionTest(const MediaSessionTest&) = delete;
  MediaSessionTest& operator=(const MediaSessionTest&) = delete;

  void SetUp() override {
    PageTestBase::SetUp();

    mock_service_ = std::make_unique<MockMediaSessionService>();

    media_session_ =
        MediaSession::mediaSession(*GetFrame().DomWindow()->navigator());
    media_session_->service_ = mock_service_->CreateRemoteAndBind(
        GetFrame().DomWindow(),
        GetFrame().DomWindow()->GetTaskRunner(TaskType::kMiscPlatformAPI));
    media_session_->clock_ = &test_clock_;
  }

  void SetPositionState(double duration,
                        double position,
                        double playback_rate) {
    auto* position_state = MediaPositionState::Create();
    position_state->setDuration(duration);
    position_state->setPosition(position);
    position_state->setPlaybackRate(playback_rate);

    NonThrowableExceptionState exception_state;
    media_session_->setPositionState(position_state, exception_state);
  }

  void SetPositionStateThrowsException(double duration,
                                       double position,
                                       double playback_rate) {
    auto* position_state = MediaPositionState::Create();
    position_state->setDuration(duration);
    position_state->setPosition(position);
    position_state->setPlaybackRate(playback_rate);

    DummyExceptionStateForTesting exception_state;
    media_session_->setPositionState(position_state, exception_state);
    EXPECT_TRUE(exception_state.HadException());
    EXPECT_EQ(ESErrorType::kTypeError, exception_state.CodeAs<ESErrorType>());
  }

  void ClearPositionState() {
    NonThrowableExceptionState exception_state;
    media_session_->setPositionState(MediaPositionState::Create(),
                                     exception_state);
  }

  void SetPlaybackState(V8MediaSessionPlaybackState::Enum state) {
    media_session_->setPlaybackState(V8MediaSessionPlaybackState(state));
  }

  MockMediaSessionService& service() { return *mock_service_.get(); }

  base::SimpleTestTickClock& clock() { return test_clock_; }

 private:
  base::SimpleTestTickClock test_clock_;

  std::unique_ptr<MockMediaSessionService> mock_service_;

  Persistent<MediaSession> media_session_;
};

TEST_F(MediaSessionTest, PlaybackPositionState_None) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::Seconds(10), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(1.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kNone);
  SetPositionState(10, 5, 1.0);
  loop.Run();
}

TEST_F(MediaSessionTest, PlaybackPositionState_Paused) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::Seconds(10), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(0.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPaused);
  SetPositionState(10, 5, 1.0);
  loop.Run();
}

TEST_F(MediaSessionTest, PlaybackPositionState_Playing) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::Seconds(10), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(1.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPlaying);
  SetPositionState(10, 5, 1.0);
  loop.Run();
}

TEST_F(MediaSessionTest, PlaybackPositionState_InfiniteDuration) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::TimeDelta::Max(), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(1.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kNone);
  SetPositionState(std::numeric_limits<double>::infinity(), 5, 1.0);
  loop.Run();
}

TEST_F(MediaSessionTest, PlaybackPositionState_NaNDuration) {
  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kNone);
  SetPositionStateThrowsException(std::nan("10"), 5, 1.0);
}

TEST_F(MediaSessionTest, PlaybackPositionState_Paused_Clear) {
  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Seconds(10), position_state->duration);
          EXPECT_EQ(base::Seconds(5), position_state->position);
          EXPECT_EQ(0.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPaused);
    SetPositionState(10, 5, 1.0);
    loop.Run();
  }

  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_FALSE(position_state);
          loop.Quit();
        }));

    ClearPositionState();
    loop.Run();
  }
}

TEST_F(MediaSessionTest, PositionPlaybackState_None) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::Seconds(10), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(1.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPositionState(10, 5, 1.0);
  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kNone);
  loop.Run();
}

TEST_F(MediaSessionTest, PositionPlaybackState_Paused_None) {
  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(1), position_state->position);
          EXPECT_EQ(1.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPositionState(600, 60, 1.0);
    loop.Run();
  }

  clock().Advance(base::Minutes(1));

  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(2), position_state->position);
          EXPECT_EQ(0.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPaused);
    loop.Run();
  }

  clock().Advance(base::Minutes(1));

  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(2), position_state->position);
          EXPECT_EQ(1.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPlaybackState(V8MediaSessionPlaybackState::Enum::kNone);
    loop.Run();
  }
}

TEST_F(MediaSessionTest, PositionPlaybackState_Paused_Playing) {
  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(1), position_state->position);
          EXPECT_EQ(1.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPositionState(600, 60, 1.0);
    loop.Run();
  }

  clock().Advance(base::Minutes(1));

  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(2), position_state->position);
          EXPECT_EQ(0.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPaused);
    loop.Run();
  }

  clock().Advance(base::Minutes(1));

  {
    base::RunLoop loop;
    EXPECT_CALL(service(), SetPositionState(_))
        .WillOnce(testing::Invoke([&](auto position_state) {
          EXPECT_EQ(base::Minutes(10), position_state->duration);
          EXPECT_EQ(base::Minutes(2), position_state->position);
          EXPECT_EQ(1.0, position_state->playback_rate);
          EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

          loop.Quit();
        }));

    SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPlaying);
    loop.Run();
  }
}

TEST_F(MediaSessionTest, PositionPlaybackState_Playing) {
  base::RunLoop loop;
  EXPECT_CALL(service(), SetPositionState(_))
      .WillOnce(testing::Invoke([&](auto position_state) {
        EXPECT_EQ(base::Seconds(10), position_state->duration);
        EXPECT_EQ(base::Seconds(5), position_state->position);
        EXPECT_EQ(1.0, position_state->playback_rate);
        EXPECT_EQ(clock().NowTicks(), position_state->last_updated_time);

        loop.Quit();
      }));

  SetPositionState(10, 5, 1.0);
  SetPlaybackState(V8MediaSessionPlaybackState::Enum::kPlaying);
  loop.Run();
}

}  // namespace blink

"""

```
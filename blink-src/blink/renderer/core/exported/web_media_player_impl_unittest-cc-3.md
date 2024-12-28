Response:
Let's break down the thought process for analyzing this C++ unittest file for the Chromium Blink engine.

**1. Initial Scan and Keyword Recognition:**

The first step is a quick scan of the file, looking for obvious keywords and structures:

* **`#include` directives:** These tell us the dependencies. Seeing things like `<gtest/gtest.h>`, `media/base/mock_demuxer.h`, and `third_party/blink/renderer/core/exported/web_media_player_impl.h` immediately signals this is a unit test for `WebMediaPlayerImpl`.
* **`TEST_F` macros:** This is the standard Google Test framework. Each `TEST_F` block defines an individual test case.
* **Class names:** `WebMediaPlayerImplTest`, `WebMediaPlayerImplBackgroundBehaviorTest`. This confirms the target class and hints at different test categories.
* **Method names within tests:** `InitializeWebMediaPlayerImpl`, `SetMetadata`, `SetReadyState`, `OnProgress`, `LoadAndWaitForCurrentData`, `CycleThreads`, `SetPreload`, `SetShouldPauseWhenFrameIsHidden`, `BackgroundPlayer`, etc. These are the actions being tested.
* **`EXPECT_...` macros:**  These are assertion macros from Google Test, checking for expected outcomes.
* **Constants:**  `kVideoAudioTestFile`, `kMaxKeyframeDistanceToDisableBackgroundVideo`. These provide context for the tests.
* **Feature flags:**  References to `media::kResumeBackgroundVideo` and `media::kPauseBackgroundMutedAudio` indicate testing of behavior controlled by feature flags.

**2. Understanding the Core Functionality Under Test:**

Based on the included headers and the class name, the central point is `WebMediaPlayerImpl`. We can infer that this class is responsible for:

* **Media playback:**  Loading, starting, pausing, setting metadata, managing ready states.
* **Interaction with lower-level media components:**  Likely interacting with a demuxer (as seen in the `DemuxerOverride` test).
* **Memory management:** The `MemDumpProvidersRegistration` and `MemDumpReporting` tests clearly focus on memory dumping and tracing.
* **Background behavior:** The `WebMediaPlayerImplBackgroundBehaviorTest` suite is explicitly about how the media player behaves when it's in the background (page hidden, frame hidden, Picture-in-Picture, etc.).

**3. Analyzing Individual Test Cases:**

For each `TEST_F` block, I would ask:

* **What is being set up?** (e.g., initializing the player, setting metadata, setting ready state)
* **What action is being performed?** (e.g., calling `OnProgress`, triggering a memory dump, loading a file, hiding the player)
* **What is being asserted?** (e.g., checking the ready state, verifying memory dump registration, checking if video is disabled, checking if playback is paused)
* **What is the expected behavior being tested?**

**Example Breakdown (nProgressClearsStale):**

* **Setup:** Initialize `WebMediaPlayerImpl`, set metadata.
* **Action:** Loop through different ready states, set the delegate to "stale", call `OnProgress`.
* **Assertion:** Check if the delegate is still considered stale based on the ready state.
* **Expected Behavior:**  The `OnProgress` call should clear the "stale" flag if the ready state indicates sufficient data.

**4. Identifying Relationships to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:**  The `WebMediaPlayerImpl` is the underlying C++ implementation for the `<video>` and `<audio>` HTML elements, which are controlled via JavaScript. So, any test involving loading, playback, or metadata directly relates to JavaScript APIs.
* **HTML:** The existence of the `<video>` and `<audio>` elements is the starting point. The tests implicitly cover how the C++ code reacts to events and properties set by the HTML.
* **CSS:** While not directly tested in this *specific* file, CSS can influence the visibility of the video element (e.g., `display: none`, `visibility: hidden`). The `WebMediaPlayerImplBackgroundBehaviorTest` explores the impact of such visibility changes. The test setup simulates these CSS-driven visibility changes.

**5. Inferring Logic and Providing Examples (Assumptions and Outputs):**

For tests involving logic, try to isolate the core condition and its outcome.

**Example Breakdown (nProgressClearsStale - Logic Inference):**

* **Assumption (Input):**  `delegate_.SetStaleForTesting(true);` and `SetReadyState(rs);`
* **Logic:** `OnProgress()` is called.
* **Output:** `EXPECT_EQ(delegate_.IsStale(delegate_.player_id()), rs >= WebMediaPlayer::kReadyStateHaveFutureData);`
* **Explanation:** If the ready state (`rs`) is at least `HaveFutureData`, the `OnProgress()` call should have cleared the stale flag.

**6. Spotting Potential User/Programming Errors:**

Consider how a developer might misuse the APIs or encounter unexpected behavior.

**Example Breakdown (MemDumpProvidersRegistration - Potential Error):**

* **Scenario:** If the `WebMediaPlayerImpl` is not properly destroyed, the memory dump providers might not be unregistered, leading to memory leaks or incorrect reporting. The test verifies the correct registration and unregistration lifecycle.

**7. Tracing User Actions (Debugging Clues):**

Think about the sequence of user interactions that would lead to the execution of this C++ code.

**Example Sequence:**

1. A user opens a web page containing a `<video>` or `<audio>` element.
2. JavaScript code sets the `src` attribute of the media element.
3. The browser's rendering engine (Blink) creates a `WebMediaPlayerImpl` instance to handle the media.
4. The user might interact with the media controls (play, pause, seek).
5. The user might navigate to another tab or minimize the browser window (triggering background behavior logic).
6. The user might enable Picture-in-Picture mode.
7. The browser might trigger memory dumps for debugging or performance analysis.

**8. Summarizing Functionality (Part 4):**

After analyzing all the tests, synthesize a concise summary. Focus on the key responsibilities and the types of scenarios being tested.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  I might initially focus too much on one aspect and need to broaden my perspective as I examine more tests.
* **Clarifying Relationships:**  I might need to refine how I explain the connection between the C++ code and the web technologies. For example, stating that `WebMediaPlayerImpl` *implements* the functionality exposed by the `<video>` and `<audio>` elements is more accurate than just saying it's "related."
* **Improving Examples:** I might need to make the assumptions, logic, and outputs in my examples clearer and more concrete.

By following this structured approach, combining code analysis with an understanding of the underlying web technologies, I can effectively analyze and explain the functionality of a complex C++ unittest file like this one.
这是目录为 `blink/renderer/core/exported/web_media_player_impl_unittest.cc` 的 Chromium Blink 引擎源代码文件的第四部分，总共分为四个部分。基于你提供的代码片段，我们可以归纳一下这部分代码以及整个文件的功能：

**这部分代码的功能归纳：**

这部分代码主要集中在测试 `WebMediaPlayerImpl` 在特定场景下的行为，特别是关于后台播放和内存管理的测试。具体来说：

* **测试 `OnProgress` 方法在不同 ReadyState 下是否正确清除 stale 状态:**  验证了当媒体播放器进入某些就绪状态时，之前可能存在的 "stale"（过时）状态是否被正确清除。
* **测试内存 Dump Provider 的注册和注销:**  验证了当 `WebMediaPlayerImpl` 被创建和销毁时，相关的内存 dump provider 是否被正确注册和注销，确保内存分析工具能够捕捉到媒体播放器的内存使用情况。
* **测试内存 Dump 报告的生成:**  验证了在请求内存 dump 时，`WebMediaPlayerImpl` 能否提供详细的内存使用信息，包括音频、视频、数据源、解复用器等组件的内存占用，以及播放器自身的状态。
* **测试自定义解复用器 (Demuxer) 的使用:** 验证了当提供了自定义的解复用器时，`WebMediaPlayerImpl` 是否会使用它，从而允许开发者替换默认的解复用逻辑。**这个测试被标记为 `DISABLED_DemuxerOverride`，说明它目前是禁用的，可能存在一些不稳定性。**
* **测试 `WebMediaPlayerImpl` 在后台行为的各种场景:**  这是一个参数化测试，涵盖了多种后台行为的组合，例如：
    * 是否启用了媒体暂停 (Media Suspend)。
    * 媒体的持续时间和关键帧距离。
    * 是否启用了后台视频恢复 (Resume Background Video)。
    * 是否处于画中画模式 (Picture-in-Picture)。
    * 是否启用了后台视频播放 (Background Video Playback)。
    * 视频是否正在被捕获 (Video Being Captured)。
    * 页面还是框架被隐藏。
    * 当框架隐藏时是否应该暂停播放。
    该测试用例验证了在不同后台场景下，音频是否应该被静音暂停，视频轨道是否应该被禁用，以及播放是否应该被暂停。

**整个文件的功能归纳 (基于所有四个部分)：**

`web_media_player_impl_unittest.cc` 文件的主要功能是为 `WebMediaPlayerImpl` 类提供全面的单元测试。`WebMediaPlayerImpl` 是 Blink 渲染引擎中负责媒体播放的核心组件。该文件旨在验证 `WebMediaPlayerImpl` 在各种场景下的行为是否符合预期，涵盖了以下方面：

* **生命周期管理:** 包括初始化、加载媒体、播放、暂停、停止、销毁等。
* **状态管理:**  包括 ReadyState、网络状态、播放状态等。
* **事件处理:**  包括 `progress` 事件、错误事件、元数据加载事件等。
* **音频和视频处理:**  包括解码、渲染、静音、音量控制等。
* **后台行为:**  在页面或框架被隐藏、进入画中画模式等情况下的行为。
* **内存管理:**  内存占用报告和资源释放。
* **与其他组件的交互:**  例如与解复用器 (Demuxer)、数据源 (DataSource) 的交互。
* **功能特性测试:**  例如预加载 (Preload)、跨域资源共享 (CORS)、自定义解复用器等。
* **错误处理:**  处理各种媒体加载和播放过程中可能出现的错误。

**与 JavaScript, HTML, CSS 的功能关系：**

`WebMediaPlayerImpl` 是 `<video>` 和 `<audio>` HTML 元素在 Blink 渲染引擎中的底层实现。因此，这个单元测试文件与 JavaScript, HTML, CSS 的功能有着密切的关系：

* **JavaScript:** JavaScript 代码可以通过 `HTMLMediaElement` 接口（例如 `HTMLVideoElement`, `HTMLAudioElement`）来控制媒体的播放，例如设置 `src` 属性加载媒体，调用 `play()`, `pause()` 方法控制播放，监听 `onprogress`, `onerror`, `onloadedmetadata` 等事件。`WebMediaPlayerImpl` 的测试覆盖了这些 JavaScript API 调用后，底层的 C++ 代码的行为是否正确。

    * **例子:**  当 JavaScript 调用 `videoElement.play()` 时，`WebMediaPlayerImpl` 应该开始解码和渲染视频帧。相关的测试会验证在调用 `play()` 后，播放器的状态是否正确切换，是否开始请求媒体数据等。
    * **例子:**  当 JavaScript 监听 `loadedmetadata` 事件时，`WebMediaPlayerImpl` 在成功获取媒体元数据后应该触发该事件。相关的测试会验证元数据是否被正确解析并传递给 JavaScript。

* **HTML:** `<video>` 和 `<audio>` 元素在 HTML 中定义了媒体播放器的基本结构和属性。`WebMediaPlayerImpl` 的测试间接地测试了这些 HTML 元素的功能。

    * **例子:** `<video preload="auto">` 属性会影响 `WebMediaPlayerImpl` 的预加载行为。相关的测试会验证 `SetPreload(WebMediaPlayer::kPreloadAuto)` 是否按预期工作。

* **CSS:** CSS 可以影响媒体元素的外观和可见性。虽然这个单元测试文件主要关注逻辑功能，但部分测试（例如关于后台行为的测试）会考虑到 CSS 导致的隐藏状态。

    * **例子:**  当一个包含 `<video>` 元素的 `div` 被设置为 `display: none` 时，相关的测试会验证 `WebMediaPlayerImpl` 是否正确处理这种隐藏状态，例如暂停播放或禁用视频轨道。

**逻辑推理的假设输入与输出 (基于代码片段)：**

**示例 1: `nProgressClearsStale` 测试**

* **假设输入:**
    1. `WebMediaPlayerImpl` 已初始化。
    2. 元数据已加载 (`SetMetadata(true, true)`)。
    3. Delegate 被设置为 `stale` (`delegate_.SetStaleForTesting(true)`).
    4. ReadyState 从 `kReadyStateHaveNothing` 迭代到 `kReadyStateHaveEnoughData`。
* **逻辑:**  在每个 ReadyState 下调用 `OnProgress()`。
* **输出:**
    * 当 ReadyState 小于 `kReadyStateHaveFutureData` 时，`delegate_.IsStale(delegate_.player_id())` 返回 `true`。
    * 当 ReadyState 大于等于 `kReadyStateHaveFutureData` 时，`delegate_.IsStale(delegate_.player_id())` 返回 `false`。

**示例 2: `WebMediaPlayerImplBackgroundBehaviorTest` 测试 (部分)**

* **假设输入:**
    1. 通过参数化测试设置不同的后台场景组合，例如 `is_media_suspend_enabled=true`, `should_hide_page=true` 等。
    2. 媒体元数据已设置 (`SetMetadata(true, false)` - 音频 only)。
* **逻辑:** 调用 `BackgroundPlayer(background_type_)` 模拟进入后台。
* **输出:**
    * 如果满足特定条件（例如音频 only 且页面隐藏），`ShouldPausePlaybackWhenHidden()` 返回 `true`。
    * `ShouldDisableVideoWhenHidden()` 返回 `false` (因为是音频 only)。

**用户或编程常见的使用错误 (基于代码片段)：**

* **忘记注销内存 Dump Provider:**  如果开发者在某些自定义的媒体播放器实现中忘记在对象销毁时注销内存 dump provider，可能会导致内存泄漏或不准确的内存报告。`MemDumpProvidersRegistration` 测试确保了 `WebMediaPlayerImpl` 正确处理了这种情况。
* **在后台不恰当地进行资源密集型操作:** 用户在后台切换标签页后，如果媒体播放器仍然进行高 CPU 或内存占用的操作，可能会导致性能问题或电量消耗。`WebMediaPlayerImplBackgroundBehaviorTest` 测试了在后台场景下是否采取了适当的优化措施，例如暂停播放或禁用视频轨道。
* **错误地假设自定义解复用器总是被使用:** 开发者可能会错误地认为提供了自定义解复用器就一定会被使用，但可能由于某些条件不满足而导致默认解复用器被使用。虽然 `DemuxerOverride` 测试目前被禁用，但它原本旨在验证自定义解复用器的使用情况。

**用户操作如何一步步的到达这里 (调试线索)：**

当你在 Chromium 浏览器中遇到与媒体播放相关的问题时，例如：

1. **视频播放卡顿或黑屏:**  这可能涉及到 `WebMediaPlayerImpl` 的解码、渲染逻辑，可以查看相关的测试用例，例如测试视频解码和帧处理的用例。
2. **音频播放没有声音:**  可能与音频解码、静音状态控制等有关，可以查看测试音频解码和静音相关的测试用例。
3. **切换标签页后视频仍然播放:**  这涉及到后台播放控制逻辑，可以查看 `WebMediaPlayerImplBackgroundBehaviorTest` 测试用例。
4. **内存占用过高:**  可能与媒体资源的缓存、解码后的帧缓存等有关，可以查看内存管理相关的测试用例，例如 `MemDumpReporting`。
5. **使用了自定义的 `<video>` 功能，但行为不符合预期:**  例如，使用了 Media Source Extensions (MSE) 或 Encrypted Media Extensions (EME)，可以查看相关的测试用例，虽然这个文件没有直接体现 MSE 或 EME，但在其他相关的测试文件中会有。

作为调试线索，开发者可以：

* **查看崩溃堆栈或日志:**  如果崩溃或出现错误日志，可以定位到 `WebMediaPlayerImpl` 相关的代码。
* **使用 Chromium 的 `chrome://media-internals` 工具:**  查看当前播放的媒体信息、状态和事件，这可以帮助理解 `WebMediaPlayerImpl` 的内部状态。
* **运行相关的单元测试:**  如果怀疑是 `WebMediaPlayerImpl` 的某个特定功能有问题，可以尝试运行 `web_media_player_impl_unittest.cc` 中相关的测试用例，看是否能复现问题。
* **设置断点调试:**  在 `WebMediaPlayerImpl` 的代码中设置断点，跟踪代码执行流程，查看变量的值，从而理解问题的根源。

总而言之，`web_media_player_impl_unittest.cc` 是理解和调试 Chromium 浏览器中媒体播放功能的重要资源。通过分析这些测试用例，开发者可以深入了解 `WebMediaPlayerImpl` 的工作原理，并找到潜在的 bug 和性能问题。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_media_player_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
nProgressClearsStale) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);

  for (auto rs = WebMediaPlayer::kReadyStateHaveNothing;
       rs <= WebMediaPlayer::kReadyStateHaveEnoughData;
       rs = static_cast<WebMediaPlayer::ReadyState>(static_cast<int>(rs) + 1)) {
    SetReadyState(rs);
    delegate_.SetStaleForTesting(true);
    OnProgress();
    EXPECT_EQ(delegate_.IsStale(delegate_.player_id()),
              rs >= WebMediaPlayer::kReadyStateHaveFutureData);
  }
}

TEST_F(WebMediaPlayerImplTest, MemDumpProvidersRegistration) {
  auto* dump_manager = base::trace_event::MemoryDumpManager::GetInstance();
  InitializeWebMediaPlayerImpl();

  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);
  auto* main_dumper = GetMainThreadMemDumper();
  EXPECT_TRUE(dump_manager->IsDumpProviderRegisteredForTesting(main_dumper));
  LoadAndWaitForCurrentData(kVideoAudioTestFile);

  auto* media_dumper = GetMediaThreadMemDumper();
  EXPECT_TRUE(dump_manager->IsDumpProviderRegisteredForTesting(media_dumper));
  CycleThreads();

  wmpi_.reset();
  CycleThreads();

  EXPECT_FALSE(dump_manager->IsDumpProviderRegisteredForTesting(main_dumper));
  EXPECT_FALSE(dump_manager->IsDumpProviderRegisteredForTesting(media_dumper));
}

TEST_F(WebMediaPlayerImplTest, MemDumpReporting) {
  InitializeWebMediaPlayerImpl();

  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);
  LoadAndWaitForCurrentData(kVideoAudioTestFile);

  CycleThreads();

  base::trace_event::MemoryDumpRequestArgs args = {
      1 /* dump_guid*/, base::trace_event::MemoryDumpType::kExplicitlyTriggered,
      base::trace_event::MemoryDumpLevelOfDetail::kDetailed};

  int32_t id = media::GetNextMediaPlayerLoggingID() - 1;
  int dump_count = 0;

  auto on_memory_dump_done = base::BindLambdaForTesting(
      [&](bool success, uint64_t dump_guid,
          std::unique_ptr<base::trace_event::ProcessMemoryDump> pmd) {
        ASSERT_TRUE(success);
        const auto& dumps = pmd->allocator_dumps();

        std::vector<const char*> allocations = {"audio", "video", "data_source",
                                                "demuxer"};

        for (const char* name : allocations) {
          auto it = dumps.find(base::StringPrintf(
              "media/webmediaplayer/%s/player_0x%x", name, id));
          ASSERT_NE(dumps.end(), it) << name;
          ASSERT_GT(it->second->GetSizeInternal(), 0u) << name;
        }

        auto it = dumps.find(
            base::StringPrintf("media/webmediaplayer/player_0x%x", id));
        ASSERT_NE(dumps.end(), it);
        auto* player_dump = it->second.get();
        const auto& entries = player_dump->entries();

        ASSERT_TRUE(base::ranges::any_of(entries, [](const auto& e) {
          auto* name = base::trace_event::MemoryAllocatorDump::kNameObjectCount;
          return e.name == name && e.value_uint64 == 1;
        }));

        if (args.level_of_detail ==
            base::trace_event::MemoryDumpLevelOfDetail::kDetailed) {
          ASSERT_TRUE(base::ranges::any_of(entries, [](const auto& e) {
            return e.name == "player_state" && !e.value_string.empty();
          }));
        }
        dump_count++;
      });

  auto* dump_manager = base::trace_event::MemoryDumpManager::GetInstance();

  dump_manager->CreateProcessDump(args, on_memory_dump_done);

  args.level_of_detail =
      base::trace_event::MemoryDumpLevelOfDetail::kBackground;
  args.dump_guid++;
  dump_manager->CreateProcessDump(args, on_memory_dump_done);

  args.level_of_detail = base::trace_event::MemoryDumpLevelOfDetail::kLight;
  args.dump_guid++;
  dump_manager->CreateProcessDump(args, on_memory_dump_done);

  CycleThreads();
  EXPECT_EQ(dump_count, 3);
}

// Verify that a demuxer override is used when specified.
// TODO(https://crbug.com/1084476): This test is flaky.
TEST_F(WebMediaPlayerImplTest, DISABLED_DemuxerOverride) {
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  StrictMock<media::MockDemuxerStream> stream(media::DemuxerStream::AUDIO);
  stream.set_audio_decoder_config(TestAudioConfig::Normal());
  std::vector<media::DemuxerStream*> streams;
  streams.push_back(&stream);

  EXPECT_CALL(stream, SupportsConfigChanges()).WillRepeatedly(Return(false));

  EXPECT_CALL(*demuxer.get(), OnInitialize(_, _))
      .WillOnce(RunOnceCallback<1>(media::PIPELINE_OK));
  EXPECT_CALL(*demuxer.get(), GetAllStreams()).WillRepeatedly(Return(streams));
  // Called when WebMediaPlayerImpl is destroyed.
  EXPECT_CALL(*demuxer.get(), Stop());

  InitializeWebMediaPlayerImpl(std::move(demuxer));

  EXPECT_FALSE(IsSuspended());
  wmpi_->Load(WebMediaPlayer::kLoadTypeURL,
              WebMediaPlayerSource(WebURL(KURL("data://test"))),
              WebMediaPlayer::kCorsModeUnspecified,
              /*is_cache_disabled=*/false);
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(IsSuspended());
}

class WebMediaPlayerImplBackgroundBehaviorTest
    : public WebMediaPlayerImplTest,
      public WebAudioSourceProviderClient,
      public ::testing::WithParamInterface<
          std::tuple<bool, int, int, bool, bool, bool, bool, bool, bool>> {
 public:
  // Indices of the tuple parameters.
  static const int kIsMediaSuspendEnabled = 0;
  static const int kDurationSec = 1;
  static const int kAverageKeyframeDistanceSec = 2;
  static const int kIsResumeBackgroundVideoEnabled = 3;
  static const int kIsPictureInPictureEnabled = 4;
  static const int kIsBackgroundVideoPlaybackEnabled = 5;
  static const int kIsVideoBeingCaptured = 6;
  // If true, the player's page is hidden. Otherwise, the player's frame is
  // hidden.
  static const int kShouldHidePage = 7;
  static const int kShouldPauseWhenFrameIsHidden = 8;

  void SetUp() override {
    WebMediaPlayerImplTest::SetUp();
    SetUpMediaSuspend(IsMediaSuspendOn());
    SetUpBackgroundVideoPlayback(IsBackgroundVideoPlaybackEnabled());

    std::string enabled_features;
    std::string disabled_features;

    if (IsResumeBackgroundVideoEnabled()) {
      if (!enabled_features.empty())
        enabled_features += ",";
      enabled_features += media::kResumeBackgroundVideo.name;
    } else {
      if (!disabled_features.empty())
        disabled_features += ",";
      disabled_features += media::kResumeBackgroundVideo.name;
    }

    feature_list_.InitFromCommandLine(enabled_features, disabled_features);

    if (std::get<kShouldHidePage>(GetParam())) {
      background_type_ = BackgroundBehaviorType::Page;
    } else {
      background_type_ = BackgroundBehaviorType::Frame;
    }

    InitializeWebMediaPlayerImpl();

    // MSE or SRC doesn't matter since we artificially inject pipeline stats.
    SetLoadType(WebMediaPlayer::kLoadTypeURL);

    SetVideoKeyframeDistanceAverage(
        base::Seconds(GetAverageKeyframeDistanceSec()));
    SetDuration(base::Seconds(GetDurationSec()));

    if (IsPictureInPictureOn()) {
      SetPiPExpectations();
      wmpi_->OnSurfaceIdUpdated(surface_id_);
    }

    if (IsVideoBeingCaptured())
      wmpi_->GetCurrentFrameThenUpdate();

    wmpi_->SetShouldPauseWhenFrameIsHidden(GetShouldPauseWhenFrameIsHidden());

    BackgroundPlayer(background_type_);
  }

  void SetVideoKeyframeDistanceAverage(base::TimeDelta value) {
    media::PipelineStatistics statistics;
    statistics.video_keyframe_distance_average = value;
    wmpi_->SetPipelineStatisticsForTest(statistics);
  }

  void SetPiPExpectations() {
    if (!IsPictureInPictureOn())
      return;
    EXPECT_CALL(client_, GetDisplayType())
        .WillRepeatedly(Return(DisplayType::kPictureInPicture));
  }

  bool IsMediaSuspendOn() {
    return std::get<kIsMediaSuspendEnabled>(GetParam());
  }

  bool IsResumeBackgroundVideoEnabled() {
    return std::get<kIsResumeBackgroundVideoEnabled>(GetParam());
  }

  bool IsPictureInPictureOn() {
    return std::get<kIsPictureInPictureEnabled>(GetParam());
  }

  bool IsBackgroundVideoPlaybackEnabled() {
    return std::get<kIsBackgroundVideoPlaybackEnabled>(GetParam());
  }

  bool IsVideoBeingCaptured() {
    return std::get<kIsVideoBeingCaptured>(GetParam());
  }

  bool GetShouldPauseWhenFrameIsHidden() const {
    return std::get<kShouldPauseWhenFrameIsHidden>(GetParam());
  }

  int GetDurationSec() const { return std::get<kDurationSec>(GetParam()); }

  int GetAverageKeyframeDistanceSec() const {
    return std::get<kAverageKeyframeDistanceSec>(GetParam());
  }

  int GetMaxKeyframeDistanceSec() const {
    return WebMediaPlayerImpl::kMaxKeyframeDistanceToDisableBackgroundVideo
        .InSeconds();
  }

  bool ShouldDisableVideoWhenHidden() const {
    return wmpi_->ShouldDisableVideoWhenHidden();
  }

  bool ShouldPausePlaybackWhenHidden() const {
    return wmpi_->ShouldPausePlaybackWhenHidden();
  }

  // We should pause media playback if the media-playback-while-not-visible
  // permission policy is not enabled and the player's frame is hidden.
  bool IsFrameHiddenAndShouldPauseWhenHidden() const {
    return background_type_ == BackgroundBehaviorType::Frame &&
           GetShouldPauseWhenFrameIsHidden();
  }

  std::string PrintValues() {
    std::stringstream stream;
    stream << "is_media_suspend_enabled=" << IsMediaSuspendOn()
           << ", duration_sec=" << GetDurationSec()
           << ", average_keyframe_distance_sec="
           << GetAverageKeyframeDistanceSec()
           << ", is_resume_background_video_enabled="
           << IsResumeBackgroundVideoEnabled()
           << ", is_picture_in_picture=" << IsPictureInPictureOn()
           << ", is_background_video_playback_enabled="
           << IsBackgroundVideoPlaybackEnabled()
           << ", is_video_being_captured=" << IsVideoBeingCaptured()
           << ", should_pause_when_frame_is_hidden="
           << GetShouldPauseWhenFrameIsHidden() << ", should_hide_page="
           << (background_type_ == BackgroundBehaviorType::Page);
    return stream.str();
  }

  MOCK_METHOD2(SetFormat, void(uint32_t numberOfChannels, float sampleRate));

 protected:
  BackgroundBehaviorType background_type_;

 private:
  base::test::ScopedFeatureList feature_list_;
};

TEST_P(WebMediaPlayerImplBackgroundBehaviorTest, AudioOnly) {
  SCOPED_TRACE(testing::Message() << PrintValues());
  if (base::FeatureList::IsEnabled(media::kPauseBackgroundMutedAudio)) {
    // Audio only players should pause if they are muted and not captured.
    EXPECT_CALL(client_, WasAlwaysMuted()).WillRepeatedly(Return(true));
    SetMetadata(true, false);
    EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
    EXPECT_FALSE(ShouldDisableVideoWhenHidden());

    auto provider = wmpi_->GetAudioSourceProvider();
    provider->SetClient(this);
    if (IsFrameHiddenAndShouldPauseWhenHidden()) {
      EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
    } else {
      EXPECT_FALSE(ShouldPausePlaybackWhenHidden());
    }
    EXPECT_FALSE(ShouldDisableVideoWhenHidden());

    provider->SetClient(nullptr);
    EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
    EXPECT_FALSE(ShouldDisableVideoWhenHidden());

    provider->SetCopyAudioCallback(base::DoNothing());
    if (IsFrameHiddenAndShouldPauseWhenHidden()) {
      EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
    } else {
      EXPECT_FALSE(ShouldPausePlaybackWhenHidden());
    }
    EXPECT_FALSE(ShouldDisableVideoWhenHidden());

    provider->ClearCopyAudioCallback();
    EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
    EXPECT_FALSE(ShouldDisableVideoWhenHidden());

    testing::Mock::VerifyAndClearExpectations(&client_);
    SetPiPExpectations();
  } else {
    // Never optimize or pause an audio-only player.
    SetMetadata(true, false);
  }

  if (IsFrameHiddenAndShouldPauseWhenHidden()) {
    EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
  } else {
    EXPECT_FALSE(ShouldPausePlaybackWhenHidden());
  }
  EXPECT_FALSE(ShouldDisableVideoWhenHidden());
}

TEST_P(WebMediaPlayerImplBackgroundBehaviorTest, VideoOnly) {
  SCOPED_TRACE(testing::Message() << PrintValues());

  // Video only -- setting muted should do nothing.
  EXPECT_CALL(client_, WasAlwaysMuted()).WillRepeatedly(Return(true));
  SetMetadata(false, true);

  // Never disable video track for a video only stream.
  EXPECT_FALSE(ShouldDisableVideoWhenHidden());

  // There's no optimization criteria for video only in Picture-in-Picture.
  bool matches_requirements =
      !IsPictureInPictureOn() && !IsVideoBeingCaptured();

  if (IsFrameHiddenAndShouldPauseWhenHidden()) {
    EXPECT_TRUE(ShouldPausePlaybackWhenHidden());
  } else {
    // Video is always paused when suspension is on and only if matches the
    // optimization criteria if the optimization is on.
    bool should_pause = (!IsBackgroundVideoPlaybackEnabled() ||
                         IsMediaSuspendOn() || matches_requirements) &&
                        !IsPictureInPictureOn();
    EXPECT_EQ(should_pause, ShouldPausePlaybackWhenHidden());
  }
}

TEST_P(WebMediaPlayerImplBackgroundBehaviorTest, AudioVideo) {
  SCOPED_TRACE(testing::Message() << PrintValues());

  bool always_pause =
      (!IsBackgroundVideoPlaybackEnabled() ||
       (IsMediaSuspendOn() && IsResumeBackgroundVideoEnabled())) &&
      !IsPictureInPictureOn();

  bool should_pause = !IsPictureInPictureOn() &&
                      (!IsBackgroundVideoPlaybackEnabled() ||
                       IsMediaSuspendOn() || !IsVideoBeingCaptured());

  if (IsFrameHiddenAndShouldPauseWhenHidden()) {
    always_pause = true;
    should_pause = true;
  }

  if (base::FeatureList::IsEnabled(media::kPauseBackgroundMutedAudio)) {
    EXPECT_CALL(client_, WasAlwaysMuted()).WillRepeatedly(Return(true));
    SetMetadata(true, true);
    EXPECT_EQ(should_pause, ShouldPausePlaybackWhenHidden());

    auto provider = wmpi_->GetAudioSourceProvider();
    provider->SetClient(this);
    EXPECT_EQ(always_pause, ShouldPausePlaybackWhenHidden());

    provider->SetClient(nullptr);
    EXPECT_EQ(should_pause, ShouldPausePlaybackWhenHidden());

    provider->SetCopyAudioCallback(base::DoNothing());
    EXPECT_EQ(always_pause, ShouldPausePlaybackWhenHidden());

    provider->ClearCopyAudioCallback();
    EXPECT_EQ(should_pause, ShouldPausePlaybackWhenHidden());

    testing::Mock::VerifyAndClearExpectations(&client_);
    SetPiPExpectations();
  } else {
    SetMetadata(true, true);
  }

  // Only pause audible videos if both media suspend and resume background
  // videos is on and background video playback is disabled. Background video
  // playback is enabled by default. Both media suspend and resume background
  // videos are on by default on Android and off on desktop.
  EXPECT_EQ(always_pause, ShouldPausePlaybackWhenHidden());

  // Optimization requirements are the same for all platforms.
  bool matches_requirements =
      !IsPictureInPictureOn() && !IsVideoBeingCaptured() &&
      ((GetDurationSec() < GetMaxKeyframeDistanceSec()) ||
       (GetAverageKeyframeDistanceSec() < GetMaxKeyframeDistanceSec()));

  EXPECT_EQ(matches_requirements, ShouldDisableVideoWhenHidden());

  if (!matches_requirements || !ShouldDisableVideoWhenHidden() ||
      IsMediaSuspendOn()) {
    return;
  }

  ForegroundPlayer(background_type_);
  EXPECT_FALSE(IsVideoTrackDisabled());
  EXPECT_FALSE(IsDisableVideoTrackPending());

  // Should start background disable timer in case we need to pause media
  // playback, but not disable immediately.
  BackgroundPlayer(background_type_);
  switch (background_type_) {
    case BackgroundBehaviorType::Page:
      if (ShouldPausePlaybackWhenHidden()) {
        EXPECT_FALSE(IsVideoTrackDisabled());
        EXPECT_FALSE(IsDisableVideoTrackPending());
      } else {
        // Testing IsVideoTrackDisabled() leads to flakiness even though there
        // should be a 10 minutes delay until it happens. Given that it doesn't
        // provides much of a benefit at the moment, this is being ignored.
        EXPECT_TRUE(IsDisableVideoTrackPending());
      }
      break;
    case BackgroundBehaviorType::Frame:
      if (!IsFrameHiddenAndShouldPauseWhenHidden()) {
        // Nothing should happen if the frame is not hidden or if the
        // media-playback-while-not-visible permission policy is enabled.
        EXPECT_FALSE(IsVideoTrackDisabled());
        EXPECT_FALSE(IsDisableVideoTrackPending());
      } else {
        // Ignore IsVideoTrackDisabled() for the same reason as above.
        EXPECT_FALSE(IsDisableVideoTrackPending());
      }
      break;
  }
}

INSTANTIATE_TEST_SUITE_P(
    BackgroundBehaviorTestInstances,
    WebMediaPlayerImplBackgroundBehaviorTest,
    ::testing::Combine(
        ::testing::Bool(),
        ::testing::Values(
            WebMediaPlayerImpl::kMaxKeyframeDistanceToDisableBackgroundVideo
                    .InSeconds() -
                1,
            300),
        ::testing::Values(
            WebMediaPlayerImpl::kMaxKeyframeDistanceToDisableBackgroundVideo
                    .InSeconds() -
                1,
            100),
        ::testing::Bool(),
        ::testing::Bool(),
        ::testing::Bool(),
        ::testing::Bool(),
        ::testing::Bool(),
        ::testing::Bool()));

}  // namespace blink

"""


```
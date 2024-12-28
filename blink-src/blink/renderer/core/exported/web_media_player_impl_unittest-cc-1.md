Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive explanation.

1. **Understand the Goal:** The primary goal is to analyze a C++ unit test file for Chromium's Blink rendering engine (`web_media_player_impl_unittest.cc`) and explain its functionality, relationships to web technologies (JavaScript, HTML, CSS), provide examples of logic, user errors, debugging clues, and finally summarize its function in this specific part.

2. **Initial Scan and Identification of Key Elements:**  The first step is a quick scan of the code to identify the major components and patterns:
    * **Includes:**  Notice the use of Chromium/Blink specific includes (`blink/renderer/core/...`, `third_party/blink/renderer/platform/...`) and standard C++ includes (`memory`, `utility`, etc.). This confirms it's indeed part of Blink.
    * **Test Fixture:** The `WebMediaPlayerImplTest` class inheriting from `testing::Test` is a clear indicator of a unit test setup. This immediately tells us the purpose is to test the `WebMediaPlayerImpl` class.
    * **Mock Objects:**  The presence of `NiceMock` and `Mock` classes (e.g., `MockWebMediaPlayerClient`, `MockVideoFrameCompositor`, `MockCdm`) strongly suggests that the tests involve isolating `WebMediaPlayerImpl` and controlling its dependencies.
    * **Member Variables:** Examining the member variables provides insights into the components and states being tested: `wmpi_` (the instance under test), `client_`, `compositor_`, `audio_sink_`, `key_systems_`, `mock_cdm_`, etc.
    * **Helper Functions:**  Functions like `InitializeWebMediaPlayerImpl()`, `LoadAndWaitForCurrentData()`, `SetMetadata()`, and `SetPaused()` are utility functions for setting up specific test scenarios.
    * **`TEST_F` Macros:** These clearly delineate individual test cases, each focusing on a particular aspect of `WebMediaPlayerImpl`'s behavior.

3. **Deconstructing Test Cases (Iterative Approach):**  Now, go through the `TEST_F` blocks one by one. For each test:
    * **Identify the tested functionality:**  What aspect of `WebMediaPlayerImpl` is this test targeting? (e.g., construction/destruction, loading, preload behavior, background suspension, video frame callbacks, play state calculation, streaming, etc.)
    * **Analyze the setup:** How is the test environment configured using the helper functions and mock objects? What preconditions are being established?
    * **Identify the assertions (EXPECT_...):** What specific outcomes are being verified? What are the expected behaviors?
    * **Look for interaction with mocks (EXPECT_CALL):** How are the interactions between `WebMediaPlayerImpl` and its dependencies being tested? What methods on the mock objects are expected to be called, and with what arguments?

4. **Connecting to Web Technologies:** As you analyze the tests, think about how these functionalities relate to user-facing web features:
    * **HTML `<video>` and `<audio>` elements:** The core of `WebMediaPlayerImpl` is managing the playback of these elements.
    * **JavaScript API:**  Methods like `play()`, `pause()`, `load()`, setting `preload`, and event listeners (e.g., `oncanplay`, `oncanplaythrough`) are directly related to the tested functionalities.
    * **CSS:** While less direct, CSS can influence the visibility and layout of media elements, which relates to tests involving background suspension and frame visibility.
    * **Media Source Extensions (MSE) and Encrypted Media Extensions (EME):**  The presence of CDM-related code and tests indicates support for DRM and MSE.

5. **Inferring Logic and Providing Examples:** Based on the test names and the assertions, infer the underlying logic being tested. For example:
    * `LoadPreloadMetadataSuspend`: The logic is that when `preload="metadata"` is set, the media player should load only enough metadata and then suspend to save resources.
    * `ComputePlayState_*`: These tests are about the complex logic that determines the media player's current state based on various factors (playing, paused, hidden, backgrounded, etc.).

6. **Identifying Potential User/Programming Errors:**  Think about how developers or users might misuse the media APIs or encounter issues related to the tested functionalities:
    * Not handling `canplay` or `canplaythrough` events correctly.
    * Incorrectly setting `preload` attributes.
    * Issues with autoplay policies.
    * Not handling errors during media loading.

7. **Tracing User Actions to Code:**  Consider the sequence of user actions that could lead to the execution of the code being tested:
    * Opening a web page with a `<video>` or `<audio>` element.
    * Interacting with media controls (play, pause, seek).
    * The browser tab being backgrounded or hidden.
    * The browser going into fullscreen mode.

8. **Formulating Debugging Clues:**  Think about what information would be useful for a developer debugging issues related to `WebMediaPlayerImpl`:
    * Log messages related to ready state changes, network events, or rendering.
    * Breakpoints in the tested code paths.
    * Examining the state of the mock objects to verify expected interactions.

9. **Summarizing the Function:** After analyzing the individual tests, synthesize a high-level summary of the file's purpose. Focus on the core functionality being tested and its significance. In this case, the focus is on the fundamental lifecycle management of the media player, including loading, preload behavior, background handling, and state transitions.

10. **Refinement and Organization:**  Structure the explanation logically with clear headings and bullet points. Use precise language and avoid jargon where possible, or explain it when necessary. Ensure the examples are concrete and easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  Initially, one might focus too much on the low-level details of the mock objects. The key is to understand *what* the mocks are simulating and *why*.
* **Missing Connections:**  It's important to constantly ask "How does this relate to what a web developer does?" or "How does this impact the user experience?".
* **Insufficient Examples:**  Realize that simply stating a function is related to JavaScript isn't enough. Providing concrete examples of the JavaScript APIs involved is crucial.
* **Overly Technical Language:**  Recognize when the explanation is too technical and simplify the language to be accessible to a broader audience (including those with less C++ experience).

By following these steps, iteratively analyzing the code, and constantly making connections to web technologies and user interactions, you can generate a comprehensive and insightful explanation like the example provided.
好的，让我们来归纳一下这段代码的功能。

这段代码是 `blink/renderer/core/exported/web_media_player_impl_unittest.cc` 文件的一部分，它主要包含了一系列针对 `WebMediaPlayerImpl` 类的单元测试。`WebMediaPlayerImpl` 是 Chromium Blink 引擎中负责管理 HTML `<video>` 和 `<audio>` 元素媒体播放的核心实现类。

**这段代码的主要功能可以归纳为以下几点：**

1. **基础生命周期测试:** 测试 `WebMediaPlayerImpl` 实例的创建和销毁是否正常，确保没有资源泄漏或其他异常情况。
2. **加载测试:**  测试 `WebMediaPlayerImpl` 加载不同类型的媒体资源（URL、Data URL）的能力，并验证加载过程中的状态变化和事件触发是否符合预期。
3. **预加载策略测试:** 详细测试了 `preload` 属性的不同取值（`none`、`metadata`、`auto`）对媒体加载行为的影响，包括何时开始加载数据，加载多少数据，以及是否会进入暂停状态。
4. **延迟加载测试 (Lazy Load):**  测试了在 `preload="metadata"` 情况下，视频资源是否会延迟加载，直到需要渲染首帧时才开始加载完整数据。同时也测试了某些情况下（例如已经请求了首帧回调）会跳过延迟加载的逻辑。
5. **后台挂起和恢复测试:**  测试了在各种条件下（例如页面不可见、帧关闭）媒体播放器是否会进入挂起状态以节省资源，以及在某些条件下是否会恢复播放。
6. **空闲挂起测试 (Idle Suspend):** 测试了当媒体播放器在加载过程中长时间没有进展时，是否会进入挂起状态。
7. **视频帧回调测试:** 测试了请求视频帧回调(`requestVideoFrameCallback`) 和接收到新帧回调(`onNewFramePresentedCallback`) 的功能。
8. **播放状态计算测试:**  通过 `ComputePlayState` 函数，测试了在各种不同的媒体播放器状态下（例如播放、暂停、隐藏、全屏、后台等），媒体会话的委托状态 (`DelegateState`)、空闲状态 (`is_idle`)、挂起状态 (`is_suspended`) 和内存报告启用状态 (`is_memory_reporting_enabled`) 是否计算正确。
9. **流媒体判断测试:**  测试了如何判断一个媒体资源是否为流媒体，主要依据是底层的 Demuxer 是否支持 seek 操作。
10. **恢复播放测试:**  测试了在播放结束后，页面被隐藏然后又恢复显示时，播放器能否正确地恢复播放状态。
11. **静音自动播放测试 (Autoplay Muted):**  这是这部分代码的结尾，预示着下一部分可能涉及自动播放相关的测试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  这段代码测试的功能直接对应 HTML 中的 `<video>` 和 `<audio>` 元素及其属性，例如 `src` (加载 URL)、`preload` (预加载策略)。
    * **举例:** `TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspend)` 测试了当 HTML 中 `<video preload="metadata">` 时，`WebMediaPlayerImpl` 的行为。
* **JavaScript:**  `WebMediaPlayerImpl` 的行为会被 JavaScript API 调用所触发和影响。例如 `play()`、`pause()`、`load()` 方法，以及 `readyState` 属性和各种事件 (如 `canplay`, `canplaythrough`)。
    * **举例:**  `TEST_F(WebMediaPlayerImplTest, NoBufferSizeIncreaseUntilHaveEnough)` 测试了在 `readyState` 达到 `HAVE_ENOUGH_DATA` 之前调用 `play()` 不会立即增加缓冲区大小，这与 JavaScript 调用 `video.play()` 后的行为相关。
* **CSS:**  CSS 可以影响媒体元素的可视性，这与后台挂起和恢复的测试有关。当元素被 CSS 隐藏时，浏览器可能会采取不同的策略来处理媒体播放。
    * **举例:** `TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHidden)` 测试了当包含媒体元素的 frame 被隐藏时，`WebMediaPlayerImpl` 的播放状态。

**逻辑推理及假设输入与输出:**

* **假设输入 (针对 `TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspend)`):**
    * 创建一个 `WebMediaPlayerImpl` 实例。
    * 设置 `preload` 属性为 `WebMediaPlayer::kPreloadMetaData`。
    * 加载一个音频文件 `kAudioOnlyTestFile`。
* **预期输出:**
    * 媒体播放器会加载文件的元数据。
    * 播放器的 `readyState` 会达到 `WebMediaPlayer::kReadyStateHaveMetadata`。
    * 播放器会进入挂起状态 (`IsSuspended()` 返回 `true`)。
    * 除了数据源本身占用的内存外，不会有额外的内存占用。

**用户或编程常见的使用错误及举例说明:**

* **不正确的 `preload` 使用:** 用户可能错误地认为设置 `preload="none"` 会完全阻止媒体加载，但实际上浏览器可能会在某些情况下仍然加载一部分数据。这段测试可以帮助开发者理解不同 `preload` 值的确切行为。
* **未处理 `canplay` 或 `canplaythrough` 事件:** 开发者可能在媒体可以播放后立即尝试播放，而没有等待 `canplay` 或 `canplaythrough` 事件触发，导致播放失败或出现卡顿。这段测试中对 `readyState` 的检查可以帮助理解这些事件的触发时机。
* **在页面不可见时仍然期望视频播放消耗资源:** 用户可能希望在页面不可见时仍然全速播放视频，但这会导致不必要的资源浪费。浏览器的后台挂起机制就是为了解决这个问题，这段测试验证了这种机制的正确性。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开一个包含 `<video>` 或 `<audio>` 标签的网页。**
2. **浏览器解析 HTML，创建对应的 `HTMLMediaElement` 对象。**
3. **`HTMLMediaElement` 对象会创建并关联一个 `WebMediaPlayerImpl` 实例。**
4. **如果 `<video>` 或 `<audio>` 标签设置了 `src` 属性，`WebMediaPlayerImpl` 会开始加载媒体资源。**
5. **`preload` 属性会影响加载的策略，例如 `preload="metadata"` 会触发 `LoadAndWaitForReadyState` 函数，并最终到达 `LoadPreloadMetadataSuspend` 测试所覆盖的代码路径。**
6. **如果用户操作导致页面被最小化或切换到后台，可能会触发后台挂起相关的代码路径，对应 `ComputePlayState_FrameHidden` 等测试。**

**归纳一下这段代码的功能 (作为第 2 部分):**

作为单元测试的第 2 部分，这段代码主要集中在 **`WebMediaPlayerImpl` 的核心加载流程和预加载策略的测试**。它详细验证了不同的 `preload` 属性值对媒体加载行为的影响，以及在加载过程中和加载完成后，媒体播放器状态的正确性。这部分测试对于确保媒体播放器在不同预加载配置下的行为符合预期至关重要，也覆盖了后台挂起和恢复的基础功能。  可以说，这部分奠定了 `WebMediaPlayerImpl` 正确处理媒体加载和资源管理的基础。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_media_player_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
 = std::move(cdm);
    quit_closure.Run();
  }

  void CreateCdm() {
    // Must use a supported key system on a secure context.
    media::CdmConfig cdm_config = {media::kClearKeyKeySystem, false, false,
                                   false};
    auto test_origin = WebSecurityOrigin::CreateFromString(
        WebString::FromUTF8("https://test.origin"));

    if (!key_systems_) {
      key_systems_ =
          std::make_unique<media::KeySystemsImpl>(base::NullCallback());
    }
    base::RunLoop run_loop;
    WebContentDecryptionModuleImpl::Create(
        &mock_cdm_factory_, key_systems_.get(), test_origin, cdm_config,
        WTF::BindOnce(&WebMediaPlayerImplTest::OnCdmCreated,
                      WTF::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    EXPECT_TRUE(web_cdm_);
  }

  void SetCdm() {
    DCHECK(web_cdm_);
    EXPECT_CALL(*mock_cdm_, GetCdmContext())
        .WillRepeatedly(Return(&mock_cdm_context_));
    wmpi_->SetCdmInternal(web_cdm_.get());
  }

  media::MemoryDumpProviderProxy* GetMainThreadMemDumper() {
    return wmpi_->main_thread_mem_dumper_.get();
  }
  media::MemoryDumpProviderProxy* GetMediaThreadMemDumper() {
    return wmpi_->media_thread_mem_dumper_.get();
  }

  test::TaskEnvironment task_environment_;

  // "Media" thread. This is necessary because WMPI destruction waits on a
  // WaitableEvent.
  base::Thread media_thread_;

  // Blink state.
  frame_test_helpers::WebViewHelper web_view_helper_;

  scoped_refptr<viz::TestContextProvider> context_provider_;
  NiceMock<MockVideoFrameCompositor>* compositor_;

  scoped_refptr<NiceMock<media::MockAudioRendererSink>> audio_sink_;
  MockResourceFetchContext mock_resource_fetch_context_;
  std::unique_ptr<UrlIndex> url_index_;

  // Audio hardware configuration.
  media::AudioParameters audio_parameters_;

  bool is_background_suspend_enabled_ = false;
  bool is_background_video_playback_enabled_ = true;

  // The client interface used by |wmpi_|.
  NiceMock<MockWebMediaPlayerClient> client_;
  MockWebMediaPlayerEncryptedMediaClient encrypted_client_;

  std::unique_ptr<media::KeySystemsImpl> key_systems_;

  // Used to create the media::MockCdm to test encrypted playback.
  scoped_refptr<media::MockCdm> mock_cdm_ =
      base::MakeRefCounted<media::MockCdm>();
  media::MockCdmFactory mock_cdm_factory_{mock_cdm_};
  std::unique_ptr<WebContentDecryptionModule> web_cdm_;
  media::MockCdmContext mock_cdm_context_;

  viz::FrameSinkId frame_sink_id_ = viz::FrameSinkId(1, 1);
  viz::LocalSurfaceId local_surface_id_ = viz::LocalSurfaceId(
      11,
      base::UnguessableToken::CreateForTesting(0x111111, 0));
  viz::SurfaceId surface_id_ =
      viz::SurfaceId(frame_sink_id_, local_surface_id_);

  NiceMock<MockWebMediaPlayerDelegate> delegate_;

  // Use NiceMock since most tests do not care about this.
  std::unique_ptr<NiceMock<MockSurfaceLayerBridge>> surface_layer_bridge_;
  NiceMock<MockSurfaceLayerBridge>* surface_layer_bridge_ptr_ = nullptr;

  // Only valid once set by InitializeWebMediaPlayerImpl(), this is for
  // verifying a subset of potential media logs.
  NiceMock<media::MockMediaLog>* media_log_ = nullptr;

  // Raw pointer of the media::RendererFactorySelector owned by |wmpi_|.
  media::RendererFactorySelector* renderer_factory_selector_ = nullptr;

  // default decoder factory for WMPI
  std::unique_ptr<media::DecoderFactory> decoder_factory_;

  // The WebMediaPlayerImpl's media observer.
  NiceMock<MockMediaObserver> mock_observer_;

  // The WebMediaPlayerImpl instance under test.
  std::unique_ptr<WebMediaPlayerImpl> wmpi_;

  std::unique_ptr<base::trace_event::MemoryDumpManager> memory_dump_manager_;
};

TEST_F(WebMediaPlayerImplTest, ConstructAndDestroy) {
  InitializeWebMediaPlayerImpl();
  EXPECT_FALSE(IsSuspended());
}

// Verify LoadAndWaitForCurrentData() functions without issue.
TEST_F(WebMediaPlayerImplTest, LoadAndDestroy) {
  InitializeWebMediaPlayerImpl();
  EXPECT_FALSE(IsSuspended());
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);
  LoadAndWaitForCurrentData(kAudioOnlyTestFile);
  EXPECT_FALSE(IsSuspended());
  CycleThreads();

  // The data source contains the entire file, so subtract it from the memory
  // usage to ensure we're getting audio buffer and demuxer usage too.
  const int64_t data_source_size = GetDataSourceMemoryUsage();
  EXPECT_GT(data_source_size, 0);
  EXPECT_GT(
      task_environment_.isolate()->AdjustAmountOfExternalAllocatedMemory(0),
      data_source_size);
}

// Verify LoadAndWaitForCurrentData() functions without issue.
TEST_F(WebMediaPlayerImplTest, LoadAndDestroyDataUrl) {
  InitializeWebMediaPlayerImpl();
  EXPECT_FALSE(IsSuspended());
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);

  const KURL kMp3DataUrl(
      "data://audio/mp3;base64,SUQzAwAAAAAAFlRFTkMAAAAMAAAAQW1hZGV1cyBQcm//"
      "+5DEAAAAAAAAAAAAAAAAAAAAAABYaW5nAAAADwAAAAwAAAftABwcHBwcHBwcMTExMTExMTFG"
      "RkZGRkZGRlpaWlpaWlpaWm9vb29vb29vhISEhISEhISYmJiYmJiYmJitra2tra2trcLCwsLC"
      "wsLC3t7e3t7e3t7e7+/v7+/v7+///////////"
      "wAAADxMQU1FMy45OHIErwAAAAAudQAANCAkCK9BAAHMAAAHbZV/"
      "jdYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/"
      "+0DEAAABcAOH1AAAIhcbaLc80EgAAAAAAPAAAP/"
      "0QfAAQdBwGBwf8AwGAgAAMBYxgxBgaTANj4NBIJgwVX+"
      "jXKCAMFgC8LgBGBmB3KTAhAT8wIQFjATAWhyLf4TUFdHcW4WkdwwxdMT3EaJEeo4UknR8dww"
      "wlxIj1RZJJ98S0khhhhiaPX/8LqO4YYS4kRhRhf/8nD2HsYj1HqZF4vf9YKiIKgqIlQAMA3/"
      "kQAMHsToyV0cDdv/"
      "7IMQHgEgUaSld4QAg1A0lde4cXDskP7w0MysiKzEUARMCEBQwLQPAwC8VADBwCsOwF+v///"
      "6ydVW3tR1HNzg22xv+3Z9gAAOgA//"
      "pg1gxGG0G6aJdDp5LCgnFycZmDJi0ADQhRrZGzKGQAqP//3t3Xe3pUv19yF6v7FIAAiMAb/"
      "3/"
      "+yDEAwBGpBsprn9gIN0NZOn9lFyAAGa1QaI6ZhLqtGY3QFgnJ4BlymYWTBYNQ4LcX88rfX/"
      "1Yu+8WKLoSm09u7Fd1QADgbfwwBECUMBpB+TDDGAUySsMLO80jP18xowMNGTBgotYkm3gPv/"
      "/6P1v2pspRShZJjXgT7V1AAAoAG/9//"
      "sgxAMCxzRpKa9k5KDODOUR7ihciAAsEwYdoVZqATrn1uJSYowIBg9gKn0MboJlBF3Fh4YAfX"
      "//9+52v6qhZt7o244rX/JfRoADB+B5MPsQ401sRj4pGKOeGUzuJDGwHEhUhAvBuMNAM1b//"
      "t9kSl70NlDrbJecU/t99aoAACMAD//7IMQCggY0Gymuf2Ag7A0k9f2UXPwAAGaFSZ/"
      "7BhFSu4Yy2FjHCYZlKoYQTiEMTLaGxV5nNu/8UddjmtWbl6r/SYAN/pAADACAI8wHQHwMM/"
      "XrDJuAv48nRNEXDHS8w4YMJCy0aSDbgm3//26S0noiIgkPfZn1Sa9V16dNAAAgAA//"
      "+yDEAoBHCGkpr2SkoMgDZXW/cAT4iAA8FEYeASxqGx/H20IYYpYHJg+AHH2GbgBlgl/"
      "1yQ2AFP///YpK32okeasc/f/+xXsAAJ1AA/"
      "9Ntaj1Pc0K7Yzw6FrOHlozEHzFYEEg6NANZbIn9a8p//j7HC6VvlmStt3o+pUAACMADfyA//"
      "sgxAOCRkwbKa5/YCDUDWU1/ZxcAGZVQZ27Zg/KweYuMFmm74hkSqYKUCINS0ZoxZ5XOv/"
      "8X7EgE4lCZDu7fc4AN/6BQHQwG0GpMMAUczI/wpM7iuM9TTGCQwsRMEBi8Cl7yAnv//"
      "2+belL59SGkk1ENqvyagAAKAAP/aAAEBGmGv/"
      "7IMQGAobYaSuvcOLgzA1lNe4cXGDeaOzj56RhnnIBMZrA4GMAKF4GBCJjK4gC+v///"
      "uh3b1WWRQNv2e/syS7ABAADCACBMPUSw0sNqj23G4OZHMzmKjGgLDBMkAzxpMNAE1b///"
      "od72VdCOtlpw1/764AAhwAf/0AAGUkeZb0Bgz/"
      "+yDEB4CGMBsrrn9gINgNJXX9qFxCcAYkOE7GsVJi6QBCEZCEEav2owqE3f4+KbGKLWKN29/"
      "YsAAC0AUAARAL5gMgLQYWGjRGQkBGh1MmZseGKjpgwUYCBoprUgcDlG//7372tX0y/"
      "zl33dN2ugIf/yIADoERhDlqm9CtAfsRzhlK//"
      "tAxAoAB7RpKPXhACHRkia3PPAAEkGL4EUFgCTA3BTMDkAcEgMgoCeefz/////"
      "oxOy73ryRx97nI2//YryIAhX0mveu/"
      "3tEgAAAABh2nnnBAAOYOK6ZtxB4mEYkiaDwX5gzgHGAkAUYGwB0kMGQFaKGBEAwDgHAUAcvP"
      "KwDfJeHEGqcMk3iN5blKocU8c6FA4FxhTqXf/OtXzv37ErkOYWXP/"
      "93kTV91+YNo3Lh8ECwliUABv7/"
      "+xDEAYPIREMrXcMAKAAAP8AAAARfwAADHinN1RU5NKTjkHN1Mc08dTJQjL4GBwgYEAK/"
      "X2a8/1qZjMtcFCUTiSXmteUeFNBWIqEKCioLiKyO10VVTEFNRTMuOTguMlVVVVVVVVVVVf/"
      "7EMQJg8AAAaQAAAAgAAA0gAAABFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
      "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVEFHAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAP8=");

  wmpi_->Load(WebMediaPlayer::kLoadTypeURL,
              WebMediaPlayerSource(WebURL(kMp3DataUrl)),
              WebMediaPlayer::kCorsModeUnspecified,
              /*is_cache_disabled=*/false);

  base::RunLoop().RunUntilIdle();

  // This runs until we reach the have current data state. Attempting to wait
  // for states < kReadyStateHaveCurrentData is unreliable due to asynchronous
  // execution of tasks on the base::test:TaskEnvironment.
  while (wmpi_->GetReadyState() < WebMediaPlayer::kReadyStateHaveCurrentData) {
    base::RunLoop loop;
    EXPECT_CALL(client_, ReadyStateChanged())
        .WillRepeatedly(RunClosure(loop.QuitClosure()));
    loop.Run();

    // Clear the mock so it doesn't have a stale QuitClosure.
    testing::Mock::VerifyAndClearExpectations(&client_);
  }

  EXPECT_FALSE(IsSuspended());
  CycleThreads();
}

// Verify that preload=metadata suspend works properly.
TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspend) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(false));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveMetadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  CycleThreads();
  EXPECT_TRUE(IsSuspended());
  EXPECT_TRUE(ShouldCancelUponDefer());

  // The data source contains the entire file, so subtract it from the memory
  // usage to ensure there's no other memory usage.
  const int64_t data_source_size = GetDataSourceMemoryUsage();
  EXPECT_GT(data_source_size, 0);
  EXPECT_EQ(
      task_environment_.isolate()->AdjustAmountOfExternalAllocatedMemory(0),
      data_source_size);
}

// Verify that Play() before kReadyStateHaveEnough doesn't increase buffer size.
TEST_F(WebMediaPlayerImplTest, NoBufferSizeIncreaseUntilHaveEnough) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(true));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveMetadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  wmpi_->Play();
  EXPECT_FALSE(IsDataSourceMarkedAsPlaying());

  while (wmpi_->GetReadyState() < WebMediaPlayer::kReadyStateHaveEnoughData) {
    // Clear the mock so it doesn't have a stale QuitClosure.
    testing::Mock::VerifyAndClearExpectations(&client_);

    base::RunLoop loop;
    EXPECT_CALL(client_, ReadyStateChanged())
        .WillRepeatedly(RunClosure(loop.QuitClosure()));
    loop.Run();
  }

  EXPECT_TRUE(IsDataSourceMarkedAsPlaying());
}

// Verify that preload=metadata suspend works properly for streaming sources.
TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspendNoStreaming) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(false));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);

  // This test needs a file which is larger than the MultiBuffer block size;
  // otherwise we'll never complete initialization of the MultiBufferDataSource.
  constexpr char kLargeAudioOnlyTestFile[] = "bear_192kHz.wav";
  Load(kLargeAudioOnlyTestFile, LoadType::kStreaming);

  // This runs until we reach the metadata state.
  while (wmpi_->GetReadyState() < WebMediaPlayer::kReadyStateHaveMetadata) {
    base::RunLoop loop;
    EXPECT_CALL(client_, ReadyStateChanged())
        .WillRepeatedly(RunClosure(loop.QuitClosure()));
    loop.Run();

    // Clear the mock so it doesn't have a stale QuitClosure.
    testing::Mock::VerifyAndClearExpectations(&client_);
  }

  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  CycleThreads();
  EXPECT_FALSE(IsSuspended());
}

// Verify that lazy load for preload=metadata works properly.
TEST_F(WebMediaPlayerImplTest, LazyLoadPreloadMetadataSuspend) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(false));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);

  // Don't set poster, but ensure we still reach suspended state.

  LoadAndWaitForReadyState(kVideoOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveMetadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  CycleThreads();
  EXPECT_TRUE(IsSuspended());
  EXPECT_TRUE(wmpi_->DidLazyLoad());
  EXPECT_FALSE(ShouldCancelUponDefer());

  // The data source contains the entire file, so subtract it from the memory
  // usage to ensure there's no other memory usage.
  const int64_t data_source_size = GetDataSourceMemoryUsage();
  EXPECT_GT(data_source_size, 0);
  EXPECT_EQ(
      task_environment_.isolate()->AdjustAmountOfExternalAllocatedMemory(0),
      data_source_size);

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

// Verify that lazy load is skipped when rVFC has been requested.
TEST_F(WebMediaPlayerImplTest, LazyLoadSkippedForRVFC) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(false));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);

  EXPECT_CALL(*compositor_, SetOnFramePresentedCallback(_));
  RequestVideoFrameCallback();

  // Ensure we don't reach the suspended state.
  LoadAndWaitForReadyState(kVideoOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveMetadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  CycleThreads();
  EXPECT_FALSE(IsSuspended());
  EXPECT_FALSE(wmpi_->DidLazyLoad());
}

// Verify that preload=metadata suspend video w/ poster uses zero video memory.
TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspendNoVideoMemoryUsage) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(false));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);
  wmpi_->SetPoster(WebURL(KURL("file://example.com/sample.jpg")));

  LoadAndWaitForReadyState(kVideoOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveMetadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  CycleThreads();
  EXPECT_TRUE(IsSuspended());

  // The data source contains the entire file, so subtract it from the memory
  // usage to ensure there's no other memory usage.
  const int64_t data_source_size = GetDataSourceMemoryUsage();
  EXPECT_GT(data_source_size, 0);
  EXPECT_EQ(
      task_environment_.isolate()->AdjustAmountOfExternalAllocatedMemory(0),
      data_source_size);

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

// Verify that preload=metadata suspend is aborted if we know the element will
// play as soon as we reach kReadyStateHaveFutureData.
TEST_F(WebMediaPlayerImplTest, LoadPreloadMetadataSuspendCouldPlay) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, CouldPlayIfEnoughData()).WillRepeatedly(Return(true));
  wmpi_->SetPreload(WebMediaPlayer::kPreloadMetaData);
  LoadAndWaitForCurrentData(kAudioOnlyTestFile);
  testing::Mock::VerifyAndClearExpectations(&client_);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(AnyNumber());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(IsSuspended());
}

TEST_F(WebMediaPlayerImplTest, IdleSuspendBeforeLoadingBegins) {
  InitializeWebMediaPlayerImpl();
  EXPECT_FALSE(delegate_.ExpireForTesting());
}

TEST_F(WebMediaPlayerImplTest,
       IdleSuspendIsDisabledIfLoadingProgressedRecently) {
  InitializeWebMediaPlayerImpl();
  base::SimpleTestTickClock clock;
  clock.Advance(base::Seconds(1));
  SetTickClock(&clock);
  AddBufferedRanges();
  wmpi_->DidLoadingProgress();
  // Advance less than the loading timeout.
  clock.Advance(base::Seconds(1));
  EXPECT_FALSE(delegate_.ExpireForTesting());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(IsSuspended());
}

TEST_F(WebMediaPlayerImplTest, IdleSuspendIsEnabledIfLoadingHasStalled) {
  InitializeWebMediaPlayerImpl();
  SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
  base::SimpleTestTickClock clock;
  clock.Advance(base::Seconds(1));
  SetTickClock(&clock);
  AddBufferedRanges();
  wmpi_->DidLoadingProgress();
  // Advance more than the loading timeout.
  clock.Advance(base::Seconds(4));
  EXPECT_TRUE(delegate_.ExpireForTesting());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(IsSuspended());
}

TEST_F(WebMediaPlayerImplTest, DidLoadingProgressTriggersResume) {
  // Same setup as IdleSuspendIsEnabledBeforeLoadingBegins.
  InitializeWebMediaPlayerImpl();
  SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
  EXPECT_TRUE(delegate_.ExpireForTesting());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(IsSuspended());

  // Like IdleSuspendIsDisabledIfLoadingProgressedRecently, the idle timeout
  // should be rejected if it hasn't been long enough.
  AddBufferedRanges();
  wmpi_->DidLoadingProgress();
  EXPECT_FALSE(delegate_.ExpireForTesting());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(IsSuspended());
}

TEST_F(WebMediaPlayerImplTest, RequestVideoFrameCallback) {
  InitializeWebMediaPlayerImpl();

  EXPECT_CALL(*compositor_, SetOnFramePresentedCallback(_));
  RequestVideoFrameCallback();
}

TEST_F(WebMediaPlayerImplTest, UpdateFrameIfStale) {
  InitializeWebMediaPlayerImpl();

  base::RunLoop loop;
  EXPECT_CALL(*compositor_,
              UpdateCurrentFrameIfStale(
                  VideoFrameCompositor::UpdateType::kBypassClient))
      .WillOnce(RunClosure(loop.QuitClosure()));

  UpdateFrameIfStale();

  loop.Run();

  testing::Mock::VerifyAndClearExpectations(compositor_);
}

TEST_F(WebMediaPlayerImplTest, GetVideoFramePresentationMetadata) {
  InitializeWebMediaPlayerImpl();

  EXPECT_CALL(*compositor_, GetLastPresentedFrameMetadata());
  GetVideoFramePresentationMetadata();
}

TEST_F(WebMediaPlayerImplTest, OnNewFramePresentedCallback) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(client_, OnRequestVideoFrameCallback());

  OnNewFramePresentedCallback();
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Constructed) {
  InitializeWebMediaPlayerImpl();
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_HaveMetadata) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_HaveFutureData) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

// Ensure memory reporting is not running after an error.
TEST_F(WebMediaPlayerImplTest, ComputePlayState_PlayingError) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
  SetError();
  state = ComputePlayState();
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Playing) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_PlayingVideoOnly) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(false, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Underflow) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  SetReadyState(WebMediaPlayer::kReadyStateHaveCurrentData);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHidden) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);

  WebMediaPlayerImpl::PlayState state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHiddenAudioOnly) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);

  SetMetadata(true, false);
  WebMediaPlayerImpl::PlayState state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHiddenVideoOnly) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(false, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);

  WebMediaPlayerImpl::PlayState state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);

  SetPaused(true);
  state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);

  state = ComputePlayState_FrameHiddenPictureInPicture();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHiddenSuspendNoResume) {
  SetUpMediaSuspend(true);
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(media::kResumeBackgroundVideo);

  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  WebMediaPlayerImpl::PlayState state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);

  SetPaused(true);
  state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameHiddenSuspendWithResume) {
  SetUpMediaSuspend(true);
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(media::kResumeBackgroundVideo);

  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);

  WebMediaPlayerImpl::PlayState state = ComputePlayState_FrameHidden();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_FrameClosed) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  SetWasSuspendedForFrameClosed(true);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_PausedSeek) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetSeeking(true);
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Ended) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(false);
  SetEnded(true);

  // Before Blink pauses us (or seeks for looping content), the media session
  // should be preserved.
  WebMediaPlayerImpl::PlayState state;
  state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PLAYING, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_TRUE(state.is_memory_reporting_enabled);

  SetPaused(true);
  state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_DoesNotStaySuspended) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);

  // Should stay suspended even though not stale or backgrounded.
  WebMediaPlayerImpl::PlayState state = ComputePlayState_Suspended();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_StaysSuspended) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);

  // Should stay suspended even though not stale or backgrounded.
  WebMediaPlayerImpl::PlayState state = ComputePlayState_Suspended();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_ResumeForNeedFirstFrame) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);

  // Should stay suspended even though not stale or backgrounded.
  WebMediaPlayerImpl::PlayState state = ComputePlayState_Suspended();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);

  wmpi_->OnBecameVisible();
  state = ComputePlayState_Suspended();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Flinging) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);

  // Remote media via the FlingingRenderer should not be idle.
  WebMediaPlayerImpl::PlayState state = ComputePlayState_Flinging();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_FALSE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Fullscreen) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetFullscreen(true);
  SetPaused(true);
  delegate_.SetStaleForTesting(true);

  // Fullscreen media is never suspended (Android only behavior).
  WebMediaPlayerImpl::PlayState state = ComputePlayState();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, ComputePlayState_Streaming) {
  InitializeWebMediaPlayerImpl();
  SetMetadata(true, true);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetPaused(true);
  delegate_.SetStaleForTesting(true);

  // Streaming media should not suspend, even if paused, stale, and
  // backgrounded.
  WebMediaPlayerImpl::PlayState state;
  state = ComputePlayState_BackgroundedStreaming();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::PAUSED, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_FALSE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);

  // Streaming media should suspend when the tab is closed, regardless.
  SetWasSuspendedForFrameClosed(true);
  state = ComputePlayState_BackgroundedStreaming();
  EXPECT_EQ(WebMediaPlayerImpl::DelegateState::GONE, state.delegate_state);
  EXPECT_TRUE(state.is_idle);
  EXPECT_TRUE(state.is_suspended);
  EXPECT_FALSE(state.is_memory_reporting_enabled);
}

TEST_F(WebMediaPlayerImplTest, IsStreamingIfDemuxerDoesntSupportSeeking) {
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  ON_CALL(*demuxer, IsSeekable()).WillByDefault(Return(false));
  InitializeWebMediaPlayerImpl(std::move(demuxer));
  Load(kVideoOnlyTestFile);
  EXPECT_TRUE(IsStreaming());
}

TEST_F(WebMediaPlayerImplTest, IsNotStreamingIfDemuxerSupportsSeeking) {
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  ON_CALL(*demuxer, IsSeekable()).WillByDefault(Return(true));
  InitializeWebMediaPlayerImpl(std::move(demuxer));
  Load(kVideoOnlyTestFile);
  EXPECT_FALSE(IsStreaming());
}

TEST_F(WebMediaPlayerImplTest, ResumeEnded) {
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  metadata.has_audio = true;
  metadata.audio_decoder_config = TestAudioConfig::Normal();

  SetUpMediaSuspend(true);
  InitializeWebMediaPlayerImpl();

  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, true, true, _)).Times(2);

  OnMetadata(metadata);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  Play();
  // Cause PlayerGone
  Pause();
  BackgroundPlayer(BackgroundBehaviorType::Page);

  testing::Mock::VerifyAndClearExpectations(&delegate_);

  // DidMediaMetadataChange should be called again after player gone.
  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, true, true, _));

  ForegroundPlayer(BackgroundBehaviorType::Page);
  Play();
}

TEST_F(WebMediaPlayerImplTest, AutoplayMuted) {
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  metadata.has_audio = true;
  metadata.a
"""


```
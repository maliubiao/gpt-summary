Response:
The user wants a summary of the functionality of the provided C++ code snippet. The code is a unit test file for `WebMediaPlayerImpl` in the Chromium Blink engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name `web_media_player_impl_unittest.cc` clearly indicates this is a unit test file. The core purpose is to test the functionality of `WebMediaPlayerImpl`.

2. **Examine the includes:** The included headers provide clues about the areas being tested. Look for key classes and concepts:
    * `third_party/blink/renderer/platform/media/web_media_player_impl.h`: This confirms the target class being tested.
    * Includes from `media/base`, `media/filters`, `media/mojo`: Suggests testing media playback functionalities, potentially involving demuxing, decoding, rendering, and interactions with the media service.
    * Includes from `third_party/blink/public/platform/media`:  Indicates testing the public API of `WebMediaPlayerImpl`.
    * Includes from `testing/gmock` and `testing/gtest`: Confirms the use of Google Mock and Google Test frameworks for unit testing.

3. **Analyze the test structure:** The code defines a test fixture `WebMediaPlayerImplTest` which inherits from `testing::Test`. This is a standard practice in gtest. The fixture sets up the necessary environment for testing `WebMediaPlayerImpl`.

4. **Identify key components and mocks:** The test fixture instantiates several mock objects:
    * `MockWebMediaPlayerClient`: Represents the client of `WebMediaPlayerImpl`, handling notifications and callbacks.
    * `MockWebMediaPlayerEncryptedMediaClient`:  Deals with encrypted media playback.
    * `MockWebMediaPlayerDelegate`: Manages the overall lifecycle and coordination of media players.
    * `MockSurfaceLayerBridge`:  Handles the integration with the compositing layer.
    * `MockVideoFrameCompositor`:  Manages the presentation of video frames.
    * `NiceMock<media::MockMediaLog>`:  Tracks media-related events and logs.
    * `NiceMock<media::MockAudioRendererSink>`:  Simulates an audio output sink.
    * Mock resource fetch related classes: Used for simulating network requests and responses.

5. **Infer the testing scope:**  The presence of these mocks suggests the tests cover various aspects of `WebMediaPlayerImpl`, including:
    * Basic playback controls (play, pause, seek).
    * Handling of media metadata.
    * Network state management.
    * Ready state transitions.
    * Error handling.
    * Interactions with the client (notifications).
    * Encrypted media support (through `MockWebMediaPlayerEncryptedMediaClient`).
    * Integration with the rendering pipeline (through `MockSurfaceLayerBridge` and `MockVideoFrameCompositor`).
    * Background playback behavior.

6. **Relate to web technologies (JavaScript, HTML, CSS):** Consider how the functionalities being tested relate to web development:
    * **JavaScript:**  JavaScript code interacts with the `<video>` or `<audio>` HTML elements, which are backed by `WebMediaPlayerImpl`. JavaScript calls methods like `play()`, `pause()`, sets `currentTime`, and listens for events like `loadedmetadata`, `play`, `pause`, `error`. The tests likely simulate these interactions through the mock client.
    * **HTML:** The `<video>` and `<audio>` tags define the media element and its attributes (e.g., `src`, `controls`, `autoplay`). The tests verify how `WebMediaPlayerImpl` handles different HTML configurations.
    * **CSS:** CSS can style the media elements. While the core media playback logic isn't directly CSS-related, the integration with the rendering pipeline (through `MockSurfaceLayerBridge`) is relevant to how the video is displayed on the page.

7. **Consider debugging aspects:** The tests, by their nature, help identify issues in `WebMediaPlayerImpl`. Understanding how a user's actions might lead to a specific code path is crucial for debugging. User actions like loading a video, playing/pausing, seeking, and encountering errors are all covered by these tests.

8. **Structure the summary:** Organize the findings into logical sections. Start with the main function, then delve into specific functionalities, and finally connect to web technologies and debugging. Use clear and concise language.

9. **Address the specific instructions:** Ensure the summary addresses all parts of the prompt, including the relationship to JavaScript, HTML, and CSS, and the debugging aspect.

10. **Review and refine:**  Read through the summary to ensure accuracy and completeness. Check for any jargon that might need clarification.

By following these steps, we can generate a comprehensive and informative summary of the provided code snippet's functionality.
好的，这是对`blink/renderer/core/exported/web_media_player_impl_unittest.cc` 文件功能的归纳：

**功能归纳:**

`web_media_player_impl_unittest.cc` 是 Chromium Blink 引擎中的一个单元测试文件，专门用于测试 `WebMediaPlayerImpl` 类的各项功能。`WebMediaPlayerImpl` 是 Blink 中负责处理 HTML5 `<video>` 和 `<audio>` 标签媒体播放的核心实现类。

该测试文件的主要目的是验证 `WebMediaPlayerImpl` 在各种场景下的行为是否符合预期，包括但不限于：

* **媒体加载和生命周期管理:** 测试媒体资源的加载、卸载、以及播放器的创建和销毁过程。
* **播放控制:** 测试播放、暂停、停止、快进、快退、设置播放速率等基本播放控制功能。
* **状态管理:** 测试播放器的各种状态变化，如网络状态 (NetworkState)、就绪状态 (ReadyState)、播放状态 (playing, paused, ended) 等。
* **事件处理:** 测试 `WebMediaPlayerImpl` 如何触发和处理各种媒体相关的事件，并通知其客户端 (通常是渲染引擎中的媒体元素)。
* **错误处理:** 测试在媒体加载、解码或播放过程中发生错误时的处理逻辑。
* **音视频轨道管理:** 测试音轨和视频轨道的添加、移除和选择功能。
* **加密媒体支持 (EME):** 测试与加密媒体相关的流程，例如接收加密数据、通知加密媒体客户端等。
* **全屏和画中画:** 测试全屏播放和画中画模式的切换和管理。
* **后台行为:** 测试在页面或 frame 进入后台时的行为，例如暂停播放、释放资源等。
* **性能指标收集:** 测试与媒体性能指标收集相关的逻辑。
* **与渲染流程的集成:** 测试 `WebMediaPlayerImpl` 如何与渲染流程集成，例如创建和管理视频图层 (cc::Layer)。
* **与其他组件的交互:** 测试 `WebMediaPlayerImpl` 与其他 Blink 组件的交互，例如资源加载器 (WebAssociatedURLLoader)、媒体解码器等。

**与 Javascript, HTML, CSS 的关系举例说明:**

`WebMediaPlayerImpl` 的功能直接支持了 HTML5 的 `<video>` 和 `<audio>` 元素，而这些元素可以通过 Javascript 和 CSS 进行控制和样式化。

* **Javascript:**
    * 当 Javascript 代码调用 `videoElement.play()` 时，最终会调用到 `WebMediaPlayerImpl` 的相应方法来启动播放。测试用例可能会模拟这个过程，例如调用 `wmpi_->Play()` 并验证播放器状态是否变为 playing。
    * 当 Javascript 监听 `videoElement.onloadedmetadata` 事件时，`WebMediaPlayerImpl` 在成功获取媒体元数据后，会通知其客户端，最终触发 Javascript 事件。测试用例可能会模拟媒体元数据加载完成，并验证客户端是否收到了相应的通知 (`client_.ReadyStateChanged()` 被调用)。
    * Javascript 可以通过 `videoElement.currentTime` 设置或获取当前播放时间，这会调用到 `WebMediaPlayerImpl` 中管理播放时间的方法。测试用例可能会设置不同的播放时间，并验证 `WebMediaPlayerImpl` 是否正确处理。

* **HTML:**
    * HTML 的 `<video src="myvideo.mp4">` 标签指定了要播放的媒体资源。测试用例可能会模拟加载不同 `src` 的资源，并验证 `WebMediaPlayerImpl` 是否正确发起网络请求。
    * `<video controls>` 属性指示浏览器显示默认的播放控制栏。`WebMediaPlayerImpl` 的某些功能可能与这些默认控件的交互有关，例如控制播放/暂停状态。

* **CSS:**
    * CSS 可以设置 `<video>` 元素的尺寸、边框、定位等样式。虽然 CSS 不直接影响 `WebMediaPlayerImpl` 的核心播放逻辑，但 `WebMediaPlayerImpl` 需要将视频内容渲染到指定尺寸的区域。测试用例可能会验证视频的尺寸是否与 CSS 设置的相符。

**逻辑推理的假设输入与输出:**

假设我们测试 `WebMediaPlayerImpl::Play()` 方法：

* **假设输入:**
    * 播放器当前状态为暂停 (paused)。
    * 媒体资源已加载并准备好播放 (readyState >= HAVE_CURRENT_DATA)。
* **预期输出:**
    * 播放器状态变为播放中 (playing)。
    * 客户端收到 `DidPlayerStartPlaying()` 的通知。
    * 播放时间开始递增。

测试用例中可能会有类似的断言来验证这些预期输出。

**涉及用户或编程常见的使用错误举例说明:**

* **用户操作错误:**
    * 用户在媒体未加载完成时点击播放按钮：测试用例可能会模拟这种情况，验证 `WebMediaPlayerImpl` 是否正确处理，例如将网络状态设置为加载中，并等待媒体数据。
    * 用户在网络断开的情况下尝试播放：测试用例可能会模拟网络错误，验证 `WebMediaPlayerImpl` 是否正确设置网络状态并通知客户端。

* **编程错误:**
    * 开发者在 Javascript 中过早地调用 `play()` 方法，在媒体元数据尚未加载完成时：测试用例可能会模拟这种情况，验证 `WebMediaPlayerImpl` 是否能够正确处理，例如在元数据加载完成后才开始播放。
    * 开发者没有正确处理媒体错误事件：测试用例可能会模拟各种媒体错误，验证 `WebMediaPlayerImpl` 是否触发了相应的错误事件，并允许开发者捕获和处理。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器中打开一个包含 `<video>` 或 `<audio>` 标签的网页。**
2. **浏览器解析 HTML，创建对应的 DOM 元素。**
3. **当浏览器遇到 `<video>` 或 `<audio>` 标签时，会创建 `HTMLMediaElement` 对象。**
4. **`HTMLMediaElement` 对象会创建并关联一个 `WebMediaPlayerImpl` 对象来处理底层的媒体播放逻辑。**
5. **用户通过点击播放按钮、设置 `src` 属性、或者通过 Javascript 调用相关方法来操作媒体元素。**
6. **这些操作会最终调用到 `WebMediaPlayerImpl` 对象的相应方法。**

如果用户在使用过程中遇到媒体播放问题，例如播放失败、卡顿、无法加载等，开发者可能会需要调试 `WebMediaPlayerImpl` 的代码来找出问题原因。该单元测试文件可以作为调试的参考和验证工具，帮助开发者理解 `WebMediaPlayerImpl` 在各种情况下的行为。 通过阅读相关的测试用例，开发者可以了解特定的用户操作如何触发 `WebMediaPlayerImpl` 中的代码路径。

**这是第1部分的功能归纳。**  总结来说，`web_media_player_impl_unittest.cc`  是 `WebMediaPlayerImpl` 类的综合性单元测试，旨在确保这个核心媒体播放组件的正确性和稳定性。 它覆盖了媒体播放的各个方面，并模拟了各种用户操作和潜在的错误场景。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_media_player_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/web_media_player_impl.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "base/trace_event/memory_dump_manager.h"
#include "build/build_config.h"
#include "cc/layers/layer.h"
#include "components/viz/test/test_context_provider.h"
#include "media/base/decoder_buffer.h"
#include "media/base/key_systems_impl.h"
#include "media/base/media_content_type.h"
#include "media/base/media_log.h"
#include "media/base/media_observer.h"
#include "media/base/media_switches.h"
#include "media/base/memory_dump_provider_proxy.h"
#include "media/base/mock_audio_renderer_sink.h"
#include "media/base/mock_filters.h"
#include "media/base/mock_media_log.h"
#include "media/base/test_data_util.h"
#include "media/base/test_helpers.h"
#include "media/cdm/clear_key_cdm_common.h"
#include "media/filters/pipeline_controller.h"
#include "media/mojo/services/media_metrics_provider.h"
#include "media/mojo/services/video_decode_stats_recorder.h"
#include "media/mojo/services/watch_time_recorder.h"
#include "media/renderers/default_decoder_factory.h"
#include "media/renderers/renderer_impl_factory.h"
#include "mojo/public/cpp/bindings/pending_associated_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/platform/media/web_media_player_builder.h"
#include "third_party/blink/public/platform/media/web_media_player_delegate.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_media_player_encrypted_media_client.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_surface_layer_bridge.h"
#include "third_party/blink/public/platform/web_url_response.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_testing_support.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/public/web/web_widget.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/platform/media/buffered_data_source_host_impl.h"
#include "third_party/blink/renderer/platform/media/media_player_client.h"
#include "third_party/blink/renderer/platform/media/power_status_helper.h"
#include "third_party/blink/renderer/platform/media/resource_multi_buffer_data_provider.h"
#include "third_party/blink/renderer/platform/media/testing/mock_resource_fetch_context.h"
#include "third_party/blink/renderer/platform/media/testing/mock_web_associated_url_loader.h"
#include "third_party/blink/renderer/platform/media/video_decode_stats_reporter.h"
#include "third_party/blink/renderer/platform/media/web_audio_source_provider_client.h"
#include "third_party/blink/renderer/platform/media/web_content_decryption_module_impl.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

namespace {

using ::base::test::RunClosure;
using ::base::test::RunOnceCallback;
using ::media::TestAudioConfig;
using ::media::TestVideoConfig;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;
using ::testing::WithArg;
using ::testing::WithoutArgs;

constexpr char kAudioOnlyTestFile[] = "sfx-opus-441.webm";
constexpr char kVideoOnlyTestFile[] = "bear-320x240-video-only.webm";
constexpr char kVideoAudioTestFile[] = "bear-320x240-16x9-aspect.webm";
constexpr char kEncryptedVideoOnlyTestFile[] = "bear-320x240-av_enc-v.webm";

constexpr base::TimeDelta kAudioOnlyTestFileDuration = base::Milliseconds(296);

enum class BackgroundBehaviorType { Page, Frame };

MATCHER(WmpiDestroyed, "") {
  return CONTAINS_STRING(arg, "{\"event\":\"kWebMediaPlayerDestroyed\"}");
}

MATCHER_P2(PlaybackRateChanged, old_rate_string, new_rate_string, "") {
  return CONTAINS_STRING(arg, "Effective playback rate changed from " +
                                  std::string(old_rate_string) + " to " +
                                  std::string(new_rate_string));
}

class MockMediaObserver : public media::MediaObserver {
 public:
  MOCK_METHOD1(OnBecameDominantVisibleContent, void(bool));
  MOCK_METHOD1(OnMetadataChanged, void(const media::PipelineMetadata&));
  MOCK_METHOD1(OnRemotePlaybackDisabled, void(bool));
  MOCK_METHOD0(OnMediaRemotingRequested, void());
  MOCK_METHOD0(OnHlsManifestDetected, void());
  MOCK_METHOD0(OnPlaying, void());
  MOCK_METHOD0(OnPaused, void());
  MOCK_METHOD0(OnFrozen, void());
  MOCK_METHOD1(OnDataSourceInitialized, void(const GURL&));
  MOCK_METHOD1(SetClient, void(media::MediaObserverClient*));

  base::WeakPtr<MediaObserver> AsWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  base::WeakPtrFactory<MediaObserver> weak_ptr_factory_{this};
};

class MockWebMediaPlayerClient : public MediaPlayerClient {
 public:
  MockWebMediaPlayerClient() = default;

  MockWebMediaPlayerClient(const MockWebMediaPlayerClient&) = delete;
  MockWebMediaPlayerClient& operator=(const MockWebMediaPlayerClient&) = delete;

  MOCK_METHOD0(NetworkStateChanged, void());
  MOCK_METHOD0(ReadyStateChanged, void());
  MOCK_METHOD0(TimeChanged, void());
  MOCK_METHOD0(Repaint, void());
  MOCK_METHOD0(DurationChanged, void());
  MOCK_METHOD0(SizeChanged, void());
  MOCK_METHOD1(SetCcLayer, void(cc::Layer*));
  MOCK_METHOD1(AddMediaTrack, void(const media::MediaTrack& track));
  MOCK_METHOD1(RemoveMediaTrack, void(const media::MediaTrack&));
  MOCK_METHOD1(MediaSourceOpened, void(std::unique_ptr<WebMediaSource>));
  MOCK_METHOD2(RemotePlaybackCompatibilityChanged, void(const KURL&, bool));
  MOCK_METHOD0(WasAlwaysMuted, bool());
  MOCK_METHOD0(HasSelectedVideoTrack, bool());
  MOCK_METHOD0(GetSelectedVideoTrackId, WebMediaPlayer::TrackId());
  MOCK_METHOD0(HasNativeControls, bool());
  MOCK_METHOD0(IsAudioElement, bool());
  MOCK_CONST_METHOD0(GetDisplayType, DisplayType());
  MOCK_CONST_METHOD0(IsInAutoPIP, bool());
  MOCK_METHOD1(MediaRemotingStarted, void(const WebString&));
  MOCK_METHOD1(MediaRemotingStopped, void(int));
  MOCK_METHOD0(PictureInPictureStopped, void());
  MOCK_METHOD0(OnPictureInPictureStateChange, void());
  MOCK_CONST_METHOD0(CouldPlayIfEnoughData, bool());
  MOCK_METHOD0(ResumePlayback, void());
  MOCK_METHOD1(PausePlayback, void(MediaPlayerClient::PauseReason));
  MOCK_METHOD0(DidPlayerStartPlaying, void());
  MOCK_METHOD1(DidPlayerPaused, void(bool));
  MOCK_METHOD1(DidPlayerMutedStatusChange, void(bool));
  MOCK_METHOD6(DidMediaMetadataChange,
               void(bool,
                    bool,
                    media::AudioCodec,
                    media::VideoCodec,
                    media::MediaContentType,
                    bool));
  MOCK_METHOD4(DidPlayerMediaPositionStateChange,
               void(double,
                    base::TimeDelta,
                    base::TimeDelta position,
                    bool end_of_media));
  MOCK_METHOD0(DidDisableAudioOutputSinkChanges, void());
  MOCK_METHOD1(DidUseAudioServiceChange, void(bool uses_audio_service));
  MOCK_METHOD1(DidPlayerSizeChange, void(const gfx::Size&));
  MOCK_METHOD1(OnRemotePlaybackDisabled, void(bool));
  MOCK_METHOD0(DidBufferUnderflow, void());
  MOCK_METHOD0(DidSeek, void());
  MOCK_METHOD2(OnFirstFrame, void(base::TimeTicks, size_t));
  MOCK_METHOD0(OnRequestVideoFrameCallback, void());
  MOCK_METHOD0(GetElementId, int());
};

class MockWebMediaPlayerEncryptedMediaClient
    : public WebMediaPlayerEncryptedMediaClient {
 public:
  MockWebMediaPlayerEncryptedMediaClient() = default;

  MockWebMediaPlayerEncryptedMediaClient(
      const MockWebMediaPlayerEncryptedMediaClient&) = delete;
  MockWebMediaPlayerEncryptedMediaClient& operator=(
      const MockWebMediaPlayerEncryptedMediaClient&) = delete;

  MOCK_METHOD3(Encrypted,
               void(media::EmeInitDataType, const unsigned char*, unsigned));
  MOCK_METHOD0(DidBlockPlaybackWaitingForKey, void());
  MOCK_METHOD0(DidResumePlaybackBlockedForKey, void());
};

class MockWebMediaPlayerDelegate : public WebMediaPlayerDelegate {
 public:
  MockWebMediaPlayerDelegate() = default;
  ~MockWebMediaPlayerDelegate() override = default;

  // WebMediaPlayerDelegate implementation.
  int AddObserver(Observer* observer) override {
    DCHECK_EQ(nullptr, observer_);
    observer_ = observer;
    return player_id_;
  }

  void RemoveObserver(int player_id) override {
    DCHECK_EQ(player_id_, player_id);
    observer_ = nullptr;
  }

  MOCK_METHOD4(DidMediaMetadataChange,
               void(int, bool, bool, media::MediaContentType));

  void DidPlay(int player_id) override { DCHECK_EQ(player_id_, player_id); }

  void DidPause(int player_id, bool reached_end_of_stream) override {
    DCHECK_EQ(player_id_, player_id);
  }

  void PlayerGone(int player_id) override { DCHECK_EQ(player_id_, player_id); }

  void SetIdle(int player_id, bool is_idle) override {
    DCHECK_EQ(player_id_, player_id);
    is_idle_ = is_idle;
    is_stale_ &= is_idle;
  }

  bool IsIdle(int player_id) override {
    DCHECK_EQ(player_id_, player_id);
    return is_idle_;
  }

  void ClearStaleFlag(int player_id) override {
    DCHECK_EQ(player_id_, player_id);
    is_stale_ = false;
  }

  bool IsStale(int player_id) override {
    DCHECK_EQ(player_id_, player_id);
    return is_stale_;
  }

  bool IsPageHidden() override { return is_page_hidden_; }

  bool IsFrameHidden() override { return is_frame_hidden_; }

  void SetIdleForTesting(bool is_idle) { is_idle_ = is_idle; }

  void SetStaleForTesting(bool is_stale) {
    is_idle_ |= is_stale;
    is_stale_ = is_stale;
  }

  // Returns true if the player does in fact expire.
  bool ExpireForTesting() {
    if (is_idle_ && !is_stale_) {
      is_stale_ = true;
      observer_->OnIdleTimeout();
    }

    return is_stale_;
  }

  void SetPageHiddenForTesting(bool is_page_hidden) {
    is_page_hidden_ = is_page_hidden;
  }

  void SetFrameHiddenForTesting(bool is_frame_hidden) {
    is_frame_hidden_ = is_frame_hidden;
  }

  int player_id() { return player_id_; }

 private:
  Observer* observer_ = nullptr;
  int player_id_ = 1234;
  bool is_idle_ = false;
  bool is_stale_ = false;
  bool is_page_hidden_ = false;
  bool is_frame_hidden_ = false;
};

class MockSurfaceLayerBridge : public WebSurfaceLayerBridge {
 public:
  MOCK_CONST_METHOD0(GetCcLayer, cc::Layer*());
  MOCK_CONST_METHOD0(GetFrameSinkId, const viz::FrameSinkId&());
  MOCK_CONST_METHOD0(GetSurfaceId, const viz::SurfaceId&());
  MOCK_METHOD0(ClearSurfaceId, void());
  MOCK_METHOD1(SetContentsOpaque, void(bool));
  MOCK_METHOD0(CreateSurfaceLayer, void());
  MOCK_METHOD0(ClearObserver, void());
  MOCK_METHOD0(RegisterFrameSinkHierarchy, void());
  MOCK_METHOD0(UnregisterFrameSinkHierarchy, void());
};

class MockVideoFrameCompositor : public VideoFrameCompositor {
 public:
  MockVideoFrameCompositor(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner)
      : VideoFrameCompositor(task_runner, nullptr) {}
  ~MockVideoFrameCompositor() override = default;

  // MOCK_METHOD doesn't like OnceCallback.
  MOCK_METHOD1(SetOnFramePresentedCallback, void(OnNewFramePresentedCB));
  MOCK_METHOD1(SetIsPageVisible, void(bool));
  MOCK_METHOD0(
      GetLastPresentedFrameMetadata,
      std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata>());
  MOCK_METHOD0(GetCurrentFrameOnAnyThread, scoped_refptr<media::VideoFrame>());
  MOCK_METHOD1(UpdateCurrentFrameIfStale,
               void(VideoFrameCompositor::UpdateType));
  MOCK_METHOD3(EnableSubmission,
               void(const viz::SurfaceId&, media::VideoTransformation, bool));
};

}  // namespace

class WebMediaPlayerImplTest
    : public testing::Test,
      private WebTestingSupport::WebScopedMockScrollbars {
 public:
  WebMediaPlayerImplTest()
      : media_thread_("MediaThreadForTest"),
        context_provider_(viz::TestContextProvider::Create()),
        audio_parameters_(media::TestAudioParameters::Normal()),
        memory_dump_manager_(
            base::trace_event::MemoryDumpManager::CreateInstanceForTesting()) {
    web_view_helper_.Initialize();
    media_thread_.StartAndWaitForTesting();
  }

  void InitializeSurfaceLayerBridge() {
    surface_layer_bridge_ =
        std::make_unique<NiceMock<MockSurfaceLayerBridge>>();
    surface_layer_bridge_ptr_ = surface_layer_bridge_.get();

    EXPECT_CALL(client_, SetCcLayer(_)).Times(0);
    ON_CALL(*surface_layer_bridge_ptr_, GetSurfaceId())
        .WillByDefault(ReturnRef(surface_id_));
  }

  WebMediaPlayerImplTest(const WebMediaPlayerImplTest&) = delete;
  WebMediaPlayerImplTest& operator=(const WebMediaPlayerImplTest&) = delete;

  ~WebMediaPlayerImplTest() override {
    if (!wmpi_)
      return;
    EXPECT_CALL(client_, SetCcLayer(nullptr));
    EXPECT_CALL(client_, MediaRemotingStopped(_));

    // Destruct WebMediaPlayerImpl and pump the message loop to ensure that
    // objects passed to the message loop for destruction are released.
    //
    // NOTE: This should be done before any other member variables are
    // destructed since WMPI may reference them during destruction.
    wmpi_.reset();

    CycleThreads();
  }

 protected:
  void InitializeWebMediaPlayerImpl(
      std::unique_ptr<media::Demuxer> demuxer_override = nullptr) {
    auto media_log = std::make_unique<NiceMock<media::MockMediaLog>>();
    InitializeSurfaceLayerBridge();

    // Retain a raw pointer to |media_log| for use by tests. Meanwhile, give its
    // ownership to |wmpi_|. Reject attempts to reinitialize to prevent orphaned
    // expectations on previous |media_log_|.
    ASSERT_FALSE(media_log_) << "Reinitialization of media_log_ is disallowed";
    media_log_ = media_log.get();

    auto factory_selector = std::make_unique<media::RendererFactorySelector>();
    renderer_factory_selector_ = factory_selector.get();
    decoder_factory_ = std::make_unique<media::DefaultDecoderFactory>(nullptr);
    media::MediaPlayerLoggingID player_id =
        media::GetNextMediaPlayerLoggingID();
#if BUILDFLAG(IS_ANDROID)
    factory_selector->AddBaseFactory(
        media::RendererType::kRendererImpl,
        std::make_unique<media::RendererImplFactory>(
            media_log.get(), decoder_factory_.get(),
            media::RendererImplFactory::GetGpuFactoriesCB(), player_id));
    factory_selector->StartRequestRemotePlayStateCB(base::DoNothing());
#else
    factory_selector->AddBaseFactory(
        media::RendererType::kRendererImpl,
        std::make_unique<media::RendererImplFactory>(
            media_log.get(), decoder_factory_.get(),
            media::RendererImplFactory::GetGpuFactoriesCB(), player_id,
            nullptr));
#endif

    mojo::Remote<media::mojom::MediaMetricsProvider> provider;
    media::MediaMetricsProvider::Create(
        media::MediaMetricsProvider::BrowsingMode::kNormal,
        media::MediaMetricsProvider::FrameStatus::kNotTopFrame,
        ukm::kInvalidSourceId, media::learning::FeatureValue(0),
        media::VideoDecodePerfHistory::SaveCallback(),
        media::MediaMetricsProvider::GetLearningSessionCallback(),
        WTF::BindRepeating(&WebMediaPlayerImplTest::IsShuttingDown,
                           WTF::Unretained(this)),
        provider.BindNewPipeAndPassReceiver());

    // Initialize provider since none of the tests below actually go through the
    // full loading/pipeline initialize phase. If this ever changes the provider
    // will start DCHECK failing.
    provider->Initialize(false, media::mojom::MediaURLScheme::kHttp,
                         media::mojom::MediaStreamType::kNone);

    audio_sink_ =
        base::WrapRefCounted(new NiceMock<media::MockAudioRendererSink>());

    url_index_ = std::make_unique<UrlIndex>(&mock_resource_fetch_context_,
                                            media_thread_.task_runner());

    auto compositor = std::make_unique<NiceMock<MockVideoFrameCompositor>>(
        media_thread_.task_runner());
    compositor_ = compositor.get();

    wmpi_ = std::make_unique<WebMediaPlayerImpl>(
        GetWebLocalFrame(), &client_, &encrypted_client_, &delegate_,
        std::move(factory_selector), url_index_.get(), std::move(compositor),
        std::move(media_log), player_id, WebMediaPlayerBuilder::DeferLoadCB(),
        audio_sink_, media_thread_.task_runner(), media_thread_.task_runner(),
        media_thread_.task_runner(), media_thread_.task_runner(), nullptr,
        media::RequestRoutingTokenCallback(), mock_observer_.AsWeakPtr(), false,
        false, provider.Unbind(),
        WTF::BindOnce(&WebMediaPlayerImplTest::CreateMockSurfaceLayerBridge,
                      base::Unretained(this)),
        viz::TestContextProvider::Create(),
        /*use_surface_layer=*/true, is_background_suspend_enabled_,
        is_background_video_playback_enabled_, true,
        std::move(demuxer_override), nullptr);
  }

  std::unique_ptr<WebSurfaceLayerBridge> CreateMockSurfaceLayerBridge(
      WebSurfaceLayerBridgeObserver*,
      cc::UpdateSubmissionStateCB) {
    return std::move(surface_layer_bridge_);
  }

  WebLocalFrame* GetWebLocalFrame() {
    return web_view_helper_.LocalMainFrame();
  }

  void SetNetworkState(WebMediaPlayer::NetworkState state) {
    EXPECT_CALL(client_, NetworkStateChanged());
    wmpi_->SetNetworkState(state);
  }

  void SetReadyState(WebMediaPlayer::ReadyState state) {
    EXPECT_CALL(client_, ReadyStateChanged());
    wmpi_->SetReadyState(state);
  }

  void SetDuration(base::TimeDelta value) {
    wmpi_->SetPipelineMediaDurationForTest(value);
    wmpi_->OnDurationChange();
  }

  MOCK_METHOD(bool, IsShuttingDown, ());

  base::TimeDelta GetCurrentTimeInternal() {
    return wmpi_->GetCurrentTimeInternal();
  }

  void SetPaused(bool is_paused) { wmpi_->paused_ = is_paused; }
  void SetSeeking(bool is_seeking) { wmpi_->seeking_ = is_seeking; }
  void SetEnded(bool is_ended) { wmpi_->ended_ = is_ended; }
  void SetTickClock(const base::TickClock* clock) {
    wmpi_->SetTickClockForTest(clock);
  }
  void SetWasSuspendedForFrameClosed(bool is_suspended) {
    wmpi_->was_suspended_for_frame_closed_ = is_suspended;
  }

  void SetFullscreen(bool is_fullscreen) {
    wmpi_->overlay_enabled_ = is_fullscreen;
    wmpi_->overlay_info_.is_fullscreen = is_fullscreen;
  }

  void SetMetadata(bool has_audio, bool has_video) {
    wmpi_->SetNetworkState(WebMediaPlayer::kNetworkStateLoaded);

    EXPECT_CALL(client_, ReadyStateChanged());
    wmpi_->SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);
    wmpi_->pipeline_metadata_.has_audio = has_audio;
    wmpi_->pipeline_metadata_.has_video = has_video;

    if (has_video) {
      wmpi_->pipeline_metadata_.video_decoder_config =
          TestVideoConfig::Normal();
    }

    if (has_audio) {
      wmpi_->pipeline_metadata_.audio_decoder_config =
          TestAudioConfig::Normal();
    }
  }

  void SetError(media::PipelineStatus status = media::PIPELINE_ERROR_DECODE) {
    wmpi_->OnError(status);
  }

  void OnMetadata(const media::PipelineMetadata& metadata) {
    wmpi_->OnMetadata(metadata);
  }

  void OnWaiting(media::WaitingReason reason) { wmpi_->OnWaiting(reason); }

  void OnVideoNaturalSizeChange(const gfx::Size& size) {
    wmpi_->OnVideoNaturalSizeChange(size);
  }

  void OnVideoConfigChange(const media::VideoDecoderConfig& config) {
    wmpi_->OnVideoConfigChange(config);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState() {
    return wmpi_->UpdatePlayState_ComputePlayState(false, true, false, false,
                                                   false);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState_FrameHidden() {
    return wmpi_->UpdatePlayState_ComputePlayState(false, true, false, true,
                                                   false);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState_Suspended() {
    return wmpi_->UpdatePlayState_ComputePlayState(false, true, true, false,
                                                   false);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState_Flinging() {
    return wmpi_->UpdatePlayState_ComputePlayState(true, true, false, false,
                                                   false);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState_BackgroundedStreaming() {
    return wmpi_->UpdatePlayState_ComputePlayState(false, false, false, true,
                                                   false);
  }

  WebMediaPlayerImpl::PlayState ComputePlayState_FrameHiddenPictureInPicture() {
    return wmpi_->UpdatePlayState_ComputePlayState(false, true, false, true,
                                                   true);
  }

  bool IsSuspended() { return wmpi_->pipeline_controller_->IsSuspended(); }

  bool IsStreaming() const { return wmpi_->IsStreaming(); }

  int64_t GetDataSourceMemoryUsage() const {
    return wmpi_->demuxer_manager_->GetDataSourceMemoryUsage();
  }

  void AddBufferedRanges() {
    wmpi_->buffered_data_source_host_->AddBufferedByteRange(0, 1);
  }

  void SetDelegateState(WebMediaPlayerImpl::DelegateState state) {
    wmpi_->SetDelegateState(state, false);
  }

  void SetUpMediaSuspend(bool enable) {
    is_background_suspend_enabled_ = enable;
  }

  void SetUpBackgroundVideoPlayback(bool enable) {
    is_background_video_playback_enabled_ = enable;
  }

  bool IsVideoLockedWhenPausedWhenHidden() const {
    return wmpi_->video_locked_when_paused_when_hidden_;
  }

  bool IsPausedBecausePageHidden() const {
    return wmpi_->IsPausedBecausePageHidden();
  }

  bool IsPausedBecauseFrameHidden() const {
    return wmpi_->IsPausedBecauseFrameHidden();
  }

  void HidePlayerPage() {
    base::RunLoop loop;
    EXPECT_CALL(*compositor_, SetIsPageVisible(false))
        .WillOnce(RunClosure(loop.QuitClosure()));

    delegate_.SetPageHiddenForTesting(true);
    SetWasSuspendedForFrameClosed(false);

    wmpi_->OnPageHidden();

    loop.Run();

    // Clear the mock so it doesn't have a stale QuitClosure.
    testing::Mock::VerifyAndClearExpectations(compositor_);
  }

  void ShowPlayerPage() {
    base::RunLoop loop;
    EXPECT_CALL(*compositor_, SetIsPageVisible(true))
        .WillOnce(RunClosure(loop.QuitClosure()));

    delegate_.SetPageHiddenForTesting(false);
    SetWasSuspendedForFrameClosed(false);

    wmpi_->OnPageShown();

    loop.Run();

    // Clear the mock so it doesn't have a stale QuitClosure.
    testing::Mock::VerifyAndClearExpectations(compositor_);
  }

  void HidePlayerFrame() {
    delegate_.SetFrameHiddenForTesting(true);
    SetWasSuspendedForFrameClosed(false);
    wmpi_->OnFrameHidden();
  }

  void ShowPlayerFrame() {
    delegate_.SetFrameHiddenForTesting(false);
    SetWasSuspendedForFrameClosed(false);
    wmpi_->OnFrameShown();
  }

  void BackgroundPlayer(BackgroundBehaviorType type) {
    switch (type) {
      case BackgroundBehaviorType::Page:
        HidePlayerPage();
        return;
      case BackgroundBehaviorType::Frame:
        HidePlayerFrame();
        return;
    }

    NOTREACHED();
  }

  void ForegroundPlayer(BackgroundBehaviorType type) {
    switch (type) {
      case BackgroundBehaviorType::Page:
        ShowPlayerPage();
        return;
      case BackgroundBehaviorType::Frame:
        ShowPlayerFrame();
        return;
    }

    NOTREACHED();
  }

  void Play() { wmpi_->Play(); }

  void Pause() { wmpi_->Pause(); }

  void ScheduleIdlePauseTimer() { wmpi_->ScheduleIdlePauseTimer(); }
  void FireIdlePauseTimer() { wmpi_->background_pause_timer_.FireNow(); }

  bool IsIdlePauseTimerRunning() {
    return wmpi_->background_pause_timer_.IsRunning();
  }

  void SetSuspendState(bool is_suspended) {
    wmpi_->SetSuspendState(is_suspended);
  }

  void SetLoadType(WebMediaPlayer::LoadType load_type) {
    wmpi_->load_type_ = load_type;
  }

  bool IsVideoTrackDisabled() const { return wmpi_->video_track_disabled_; }

  bool IsDisableVideoTrackPending() const {
    return !wmpi_->is_background_status_change_cancelled_;
  }

  gfx::Size GetNaturalSize() const {
    return wmpi_->pipeline_metadata_.natural_size;
  }

  VideoDecodeStatsReporter* GetVideoStatsReporter() const {
    return wmpi_->video_decode_stats_reporter_.get();
  }

  media::VideoCodecProfile GetVideoStatsReporterCodecProfile() const {
    DCHECK(GetVideoStatsReporter());
    return GetVideoStatsReporter()->codec_profile_;
  }

  bool ShouldCancelUponDefer() const {
    auto* ds = wmpi_->demuxer_manager_->GetDataSourceForTesting();
    CHECK_NE(ds, nullptr);
    CHECK_NE(ds->GetAsCrossOriginDataSource(), nullptr);
    // Right now, the only implementation of DataSource that WMPI can get
    // which returns non-null from GetAsCrossOriginDataSource is
    // MultiBufferDataSource, so the CHECKs above allow us to be safe casting
    // this here.
    // TODO(crbug/1377053): Can we add |cancel_on_defer_for_testing| to
    // CrossOriginDataSource? We can't do a |GetAsMultiBufferDataSource| since
    // MBDS is in blink, and we can't import that into media.
    return static_cast<const MultiBufferDataSource*>(ds)
        ->cancel_on_defer_for_testing();
  }

  bool IsDataSourceMarkedAsPlaying() const {
    auto* ds = wmpi_->demuxer_manager_->GetDataSourceForTesting();
    CHECK_NE(ds, nullptr);
    CHECK_NE(ds->GetAsCrossOriginDataSource(), nullptr);
    // See comment in |ShouldCancelUponDefer|.
    return static_cast<const MultiBufferDataSource*>(ds)->media_has_played();
  }

  scoped_refptr<media::VideoFrame> CreateFrame() {
    gfx::Size size(8, 8);
    return media::VideoFrame::CreateFrame(media::PIXEL_FORMAT_I420, size,
                                          gfx::Rect(size), size,
                                          base::TimeDelta());
  }

  void RequestVideoFrameCallback() { wmpi_->RequestVideoFrameCallback(); }
  void GetVideoFramePresentationMetadata() {
    wmpi_->GetVideoFramePresentationMetadata();
  }
  void UpdateFrameIfStale() { wmpi_->UpdateFrameIfStale(); }

  void OnNewFramePresentedCallback() { wmpi_->OnNewFramePresentedCallback(); }

  scoped_refptr<media::VideoFrame> GetCurrentFrameFromCompositor() {
    return wmpi_->GetCurrentFrameFromCompositor();
  }

  enum class LoadType { kFullyBuffered, kStreaming };
  void Load(std::string data_file,
            LoadType load_type = LoadType::kFullyBuffered) {
    const bool is_streaming = load_type == LoadType::kStreaming;

    // The URL is used by MultiBufferDataSource to determine if it should assume
    // the resource is fully buffered locally. We can use a fake one here since
    // we're injecting the response artificially. It's value is unknown to the
    // underlying demuxer.
    const KURL kTestURL(
        String::FromUTF8(std::string(is_streaming ? "http" : "file") +
                         "://example.com/sample.webm"));

    // This block sets up a fetch context which ultimately provides us a pointer
    // to the WebAssociatedURLLoaderClient handed out by the DataSource after it
    // requests loading of a resource. We then use that client as if we are the
    // network stack and "serve" an in memory file to the DataSource.
    const bool should_have_client =
        !wmpi_->demuxer_manager_->HasDemuxerOverride();
    WebAssociatedURLLoaderClient* client = nullptr;
    if (should_have_client) {
      EXPECT_CALL(mock_resource_fetch_context_, CreateUrlLoader(_))
          .WillRepeatedly(
              Invoke([&client](const WebAssociatedURLLoaderOptions&) {
                auto a =
                    std::make_unique<NiceMock<MockWebAssociatedURLLoader>>();
                EXPECT_CALL(*a, LoadAsynchronously(_, _))
                    .WillRepeatedly(testing::SaveArg<1>(&client));
                return a;
              }));
    }

    wmpi_->Load(WebMediaPlayer::kLoadTypeURL,
                WebMediaPlayerSource(WebURL(kTestURL)),
                WebMediaPlayer::kCorsModeUnspecified,
                /*is_cache_disabled=*/false);

    base::RunLoop().RunUntilIdle();
    if (!should_have_client) {
      return;
    }
    EXPECT_TRUE(client);

    // Load a real media file into memory.
    scoped_refptr<media::DecoderBuffer> data =
        media::ReadTestDataFile(data_file);

    // "Serve" the file to the DataSource. Note: We respond with 200 okay, which
    // will prevent range requests or partial responses from being used. For
    // streaming responses, we'll pretend we don't know the content length.
    WebURLResponse response(kTestURL);
    response.SetHttpHeaderField(
        WebString::FromUTF8("Content-Length"),
        WebString::FromUTF8(is_streaming ? "-1"
                                         : base::NumberToString(data->size())));
    response.SetExpectedContentLength(is_streaming ? -1 : data->size());
    response.SetHttpStatusCode(200);
    client->DidReceiveResponse(response);

    // Copy over the file data.
    client->DidReceiveData(base::as_chars(data->AsSpan()));

    // If we're pretending to be a streaming resource, don't complete the load;
    // otherwise the DataSource will not be marked as streaming.
    if (!is_streaming)
      client->DidFinishLoading();
  }

  // This runs until we reach the |ready_state_|. Attempting to wait for ready
  // states < kReadyStateHaveCurrentData in non-startup-suspend test cases is
  // unreliable due to asynchronous execution of tasks on the
  // base::test:TaskEnvironment.
  void LoadAndWaitForReadyState(std::string data_file,
                                WebMediaPlayer::ReadyState ready_state) {
    Load(data_file);
    while (wmpi_->GetReadyState() < ready_state) {
      base::RunLoop loop;
      EXPECT_CALL(client_, ReadyStateChanged())
          .WillRepeatedly(RunClosure(loop.QuitClosure()));
      loop.Run();

      // Clear the mock so it doesn't have a stale QuitClosure.
      testing::Mock::VerifyAndClearExpectations(&client_);
    }

    // Verify we made it through pipeline startup.
    EXPECT_TRUE(wmpi_->demuxer_manager_->HasDataSource());
    EXPECT_TRUE(wmpi_->demuxer_manager_->HasDemuxer());

    if (ready_state > WebMediaPlayer::kReadyStateHaveCurrentData)
      EXPECT_FALSE(wmpi_->seeking_);
  }

  void LoadAndWaitForCurrentData(std::string data_file) {
    LoadAndWaitForReadyState(data_file,
                             WebMediaPlayer::kReadyStateHaveCurrentData);
  }

  void CycleThreads() {
    // Ensure any tasks waiting to be posted to the media thread are posted.
    base::RunLoop().RunUntilIdle();

    // Flush all media tasks.
    media_thread_.FlushForTesting();

    // Cycle anything that was posted back from the media thread.
    base::RunLoop().RunUntilIdle();
  }

  void OnProgress() { wmpi_->OnProgress(); }

  void OnCdmCreated(base::RepeatingClosure quit_closure,
                    std::unique_ptr<WebContentDecryptionModule> cdm,
                    media::CreateCdmStatus status) {
    LOG_IF(ERROR, status != media::CreateCdmStatus::kSuccess)
        << "status = " << static_cast<int>(status);
    EXPECT_TRUE(cdm);
    web_cdm_
"""


```
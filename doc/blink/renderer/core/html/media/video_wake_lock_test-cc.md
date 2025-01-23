Response:
The user wants to understand the functionality of the `video_wake_lock_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose. It appears to be a test file (`_test.cc`) for the `VideoWakeLock` class.

Here's a breakdown of the functionalities I should cover:

1. **Primary Function:**  Testing the `VideoWakeLock` class.
2. **Relation to Web Technologies:**  How `VideoWakeLock` interacts with HTML (`<video>`), JavaScript (event handling), and CSS (visibility).
3. **Logic and Assumptions:** Identify the test scenarios, the expected inputs (simulated events, states), and outputs (wake lock status).
4. **Common Usage Errors:**  Consider developer mistakes in using or understanding wake locks.
`blink/renderer/core/html/media/video_wake_lock_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `VideoWakeLock` 类的功能。 `VideoWakeLock` 类的作用是管理视频播放时阻止设备进入休眠状态（保持屏幕常亮）的机制。

**核心功能:**

* **测试 `VideoWakeLock` 类在各种场景下的行为:**  这个测试文件模拟了各种可能影响视频唤醒锁状态的情况，例如视频的播放、暂停、页面可见性、画中画模式、远程播放、视频大小、静音状态等等。
* **验证唤醒锁的正确获取和释放:**  通过断言 (`EXPECT_TRUE`, `EXPECT_FALSE`) 来验证在特定的条件下，视频唤醒锁是否被正确地激活或释放。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`VideoWakeLock` 的行为与网页中的 `<video>` 元素以及通过 JavaScript 对视频元素的操作密切相关。CSS 可以影响视频元素的可见性，这也会影响唤醒锁的状态。

* **HTML (`<video>`):**
    * **功能:**  测试文件创建并操作一个 `<video>` 元素 (`video_`) 来模拟视频播放的场景。
    * **例子:** 测试用例会设置视频的 `src` 属性来模拟加载视频 (`video_->SetSrc(AtomicString("http://example.com/foo.mp4"));`)。
* **JavaScript (事件):**
    * **功能:**  测试文件通过模拟 JavaScript 事件（例如 `playing`, `pause`, `enterpictureinpicture`, `leavepictureinpicture`）来触发 `VideoWakeLock` 的逻辑。
    * **例子:** `SimulatePlaying()` 函数模拟了 `playing` 事件的触发，这会触发 `VideoWakeLock` 尝试获取唤醒锁。
* **CSS (可见性):**
    * **功能:** 测试文件使用 CSS 的 `display` 属性来模拟视频元素的隐藏和显示，以测试可见性对唤醒锁的影响。
    * **例子:** `HideVideo()` 函数将视频元素的 `display` 属性设置为 `none`，模拟视频被隐藏的情况。

**逻辑推理、假设输入与输出:**

以下列举几个测试用例及其背后的逻辑推理：

1. **测试用例:** `PlayingVideoRequestsLock`
   * **假设输入:** 调用 `SimulatePlaying()` 模拟视频开始播放。
   * **逻辑推理:** 当视频开始播放时，并且满足其他条件（例如页面可见），`VideoWakeLock` 应该会请求获取设备的唤醒锁。
   * **预期输出:** `HasWakeLock()` 返回 `true`，表示唤醒锁被激活。

2. **测试用例:** `PausingVideoCancelsLock`
   * **假设输入:** 先调用 `SimulatePlaying()`，然后调用 `SimulatePause()` 模拟视频暂停。
   * **逻辑推理:** 当视频暂停播放时，不再需要保持屏幕常亮，`VideoWakeLock` 应该释放唤醒锁。
   * **预期输出:** `HasWakeLock()` 先返回 `true`（播放时），后返回 `false`（暂停时）。

3. **测试用例:** `HiddingPageCancelsLock`
   * **假设输入:** 先调用 `SimulatePlaying()`，然后调用 `GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden, false)` 模拟页面被隐藏。
   * **逻辑推理:** 当页面被隐藏时，用户不太可能继续观看视频，因此应该释放唤醒锁以节省电量。
   * **预期输出:** `HasWakeLock()` 先返回 `true`（播放时），后返回 `false`（页面隐藏时）。

4. **测试用例:** `PictureInPictureLocksWhenPageNotVisible`
   * **假设输入:** 先调用 `SimulatePlaying()`，然后调用 `GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden, false)` 模拟页面被隐藏，最后调用 `SimulateEnterPictureInPicture()` 模拟进入画中画模式。
   * **逻辑推理:** 即使页面不可见，但当视频进入画中画模式时，用户仍然在观看视频，因此应该保持唤醒锁。
   * **预期输出:** `HasWakeLock()` 先返回 `false`（页面隐藏但未进入画中画），后返回 `true`（进入画中画模式）。

**用户或者编程常见的使用错误举例:**

虽然 `VideoWakeLock` 的管理是在浏览器引擎内部完成的，但开发者对视频元素的操作会影响其行为。以下是一些可能导致开发者困惑的情况：

1. **假设在视频不可见时也会持有唤醒锁:**  如果开发者认为即使视频被 CSS 隐藏 (`display: none;`) 或者部分不可见时，只要视频在播放就会持有唤醒锁，这是一个常见的误解。测试用例 `MutedHiddenVideoDoesNotTakeLock` 和 `MutedVideoTooFarOffscreenDoesNotTakeLock` 验证了这种情况。

2. **忘记处理画中画模式对唤醒锁的影响:**  开发者可能没有意识到进入画中画模式会影响唤醒锁的状态。测试用例 `PictureInPictureLocksWhenPageNotVisible`  说明了即使页面不可见，画中画模式也会请求唤醒锁。

3. **没有考虑到远程播放状态:**  当视频进行远程播放时，本地设备的唤醒锁可能不再需要。测试用例 `ActiveRemotePlaybackCancelsLock` 验证了这一点。

4. **混淆了 `muted` 属性和音频轨道是否存在:**  即使视频被静音 (`muted=true`)，但如果视频仍然有音频轨道，在某些情况下（例如可见时），仍然可能持有唤醒锁。 测试用例 `MutedHiddenVideoDoesNotTakeLock` 和 `AudibleHiddenVideoTakesLock` 区分了这两种情况。

**总结:**

`video_wake_lock_test.cc` 是一个关键的测试文件，它确保了 `VideoWakeLock` 能够正确地管理视频播放时的屏幕唤醒状态。通过各种测试用例，它验证了在不同场景下，唤醒锁是否按照预期被获取和释放，这对于提供良好的用户体验和节省设备电量至关重要。开发者可以通过理解这些测试用例，更好地理解浏览器引擎如何处理视频唤醒锁。

### 提示词
```
这是目录为blink/renderer/core/html/media/video_wake_lock_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/video_wake_lock.h"

#include <memory>
#include <utility>

#include "cc/layers/layer.h"
#include "media/mojo/mojom/media_player.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/picture_in_picture/picture_in_picture.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_test_helper.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/testing/wait_for_event.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/media/media_player_client.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

constexpr gfx::Size kWindowSize(800, 600);
constexpr gfx::Size kNormalVideoSize(640, 480);
constexpr gfx::Size kSmallVideoSize(320, 240);  // Too small to take wake lock.

// The VideoWakeLockPictureInPictureSession implements a PictureInPicture
// session in the same process as the test and guarantees that the callbacks are
// called in order for the events to be fired.
class VideoWakeLockPictureInPictureSession final
    : public mojom::blink::PictureInPictureSession {
 public:
  explicit VideoWakeLockPictureInPictureSession(
      mojo::PendingReceiver<mojom::blink::PictureInPictureSession> receiver)
      : receiver_(this, std::move(receiver)) {}
  ~VideoWakeLockPictureInPictureSession() override = default;

  void Stop(StopCallback callback) override { std::move(callback).Run(); }
  void Update(uint32_t player_id,
              mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
                  player_remote,
              const viz::SurfaceId&,
              const gfx::Size&,
              bool show_play_pause_button) override {}

 private:
  mojo::Receiver<mojom::blink::PictureInPictureSession> receiver_;
};

// The VideoWakeLockPictureInPictureService implements the PictureInPicture
// service in the same process as the test and guarantees that the callbacks are
// called in order for the events to be fired.
class VideoWakeLockPictureInPictureService final
    : public mojom::blink::PictureInPictureService {
 public:
  VideoWakeLockPictureInPictureService() : receiver_(this) {}
  ~VideoWakeLockPictureInPictureService() override = default;

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<mojom::blink::PictureInPictureService>(
        std::move(handle)));
  }

  void StartSession(
      uint32_t,
      mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>,
      const viz::SurfaceId&,
      const gfx::Size&,
      bool,
      mojo::PendingRemote<mojom::blink::PictureInPictureSessionObserver>,
      const gfx::Rect&,
      StartSessionCallback callback) override {
    mojo::PendingRemote<mojom::blink::PictureInPictureSession> session_remote;
    session_ = std::make_unique<VideoWakeLockPictureInPictureSession>(
        session_remote.InitWithNewPipeAndPassReceiver());

    std::move(callback).Run(std::move(session_remote), gfx::Size());
  }

 private:
  mojo::Receiver<mojom::blink::PictureInPictureService> receiver_;
  std::unique_ptr<VideoWakeLockPictureInPictureSession> session_;
};

class VideoWakeLockMediaPlayer final : public EmptyWebMediaPlayer {
 public:
  ReadyState GetReadyState() const override { return kReadyStateHaveMetadata; }
  void OnRequestPictureInPicture() override {
    // Use a fake but valid viz::SurfaceId.
    surface_id_ = viz::SurfaceId(
        viz::FrameSinkId(1, 1),
        viz::LocalSurfaceId(
            11, base::UnguessableToken::CreateForTesting(0x111111, 0)));
  }
  std::optional<viz::SurfaceId> GetSurfaceId() override { return surface_id_; }

  bool HasAudio() const override { return has_audio_; }
  void SetHasAudio(bool has_audio) { has_audio_ = has_audio; }
  bool HasVideo() const override { return has_video_; }
  void SetHasVideo(bool has_video) { has_video_ = has_video; }

  gfx::Size NaturalSize() const override { return size_; }
  gfx::Size VisibleSize() const override { return size_; }
  void SetSize(const gfx::Size& size) { size_ = size; }

 private:
  bool has_audio_ = true;
  bool has_video_ = true;
  gfx::Size size_ = kNormalVideoSize;
  std::optional<viz::SurfaceId> surface_id_;
};

class VideoWakeLockFrameClient : public test::MediaStubLocalFrameClient {
 public:
  explicit VideoWakeLockFrameClient(std::unique_ptr<WebMediaPlayer> player)
      : test::MediaStubLocalFrameClient(std::move(player)) {}
  VideoWakeLockFrameClient(const VideoWakeLockFrameClient&) = delete;
  VideoWakeLockFrameClient& operator=(const VideoWakeLockFrameClient&) = delete;
};

class VideoWakeLockTestWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  explicit VideoWakeLockTestWebFrameClient(
      std::unique_ptr<WebMediaPlayer> web_media_player)
      : web_media_player_(std::move(web_media_player)) {}

  std::unique_ptr<WebMediaPlayer> CreateMediaPlayer(
      const WebMediaPlayerSource&,
      WebMediaPlayerClient* client,
      blink::MediaInspectorContext*,
      WebMediaPlayerEncryptedMediaClient*,
      WebContentDecryptionModule*,
      const WebString& sink_id,
      const cc::LayerTreeSettings* settings,
      scoped_refptr<base::TaskRunner> compositor_worker_task_runner) override {
    media_player_client_ = static_cast<MediaPlayerClient*>(client);
    return std::move(web_media_player_);
  }

  MediaPlayerClient* media_player_client() const {
    return media_player_client_;
  }

  void SetWebMediaPlayer(std::unique_ptr<WebMediaPlayer> web_media_player) {
    web_media_player_ = std::move(web_media_player);
  }

 private:
  MediaPlayerClient* media_player_client_ = nullptr;
  std::unique_ptr<WebMediaPlayer> web_media_player_;
};

class VideoWakeLockTest : public testing::Test {
 public:
  void SetUp() override {
    auto media_player = std::make_unique<VideoWakeLockMediaPlayer>();
    media_player_ = media_player.get();
    client_ = std::make_unique<VideoWakeLockTestWebFrameClient>(
        std::move(media_player));

    helper_.Initialize(client_.get());
    helper_.Resize(kWindowSize);

    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::PictureInPictureService::Name_,
        WTF::BindRepeating(&VideoWakeLockPictureInPictureService::Bind,
                           WTF::Unretained(&pip_service_)));

    fake_layer_ = cc::Layer::Create();

    GetDocument().body()->setInnerHTML(
        "<body><div></div><video></video></body>");
    video_ = To<HTMLVideoElement>(
        GetDocument().QuerySelector(AtomicString("video")));
    div_ = To<HTMLDivElement>(GetDocument().QuerySelector(AtomicString("div")));
    SetFakeCcLayer(fake_layer_.get());
    video_->SetReadyState(HTMLMediaElement::ReadyState::kHaveMetadata);
    video_wake_lock_ = MakeGarbageCollected<VideoWakeLock>(*video_.Get());
    video_->SetSrc(AtomicString("http://example.com/foo.mp4"));
    test::RunPendingTasks();

    GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kVisible,
                                 true);
  }

  void TearDown() override {
    GetFrame().GetBrowserInterfaceBroker().SetBinderForTesting(
        mojom::blink::PictureInPictureService::Name_, {});
  }

  HTMLVideoElement* Video() const { return video_.Get(); }
  VideoWakeLock* GetVideoWakeLock() const { return video_wake_lock_.Get(); }
  VideoWakeLockMediaPlayer* GetMediaPlayer() const { return media_player_; }
  MediaPlayerClient* GetMediaPlayerClient() const {
    return client_->media_player_client();
  }

  LocalFrame& GetFrame() const { return *helper_.LocalMainFrame()->GetFrame(); }
  Page& GetPage() const { return *GetDocument().GetPage(); }

  void UpdateAllLifecyclePhasesForTest() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  Document& GetDocument() const { return *GetFrame().GetDocument(); }

  void SetFakeCcLayer(cc::Layer* layer) { video_->SetCcLayer(layer); }

  void SimulatePlaying() {
    video_wake_lock_->Invoke(GetFrame().DomWindow(),
                             Event::Create(event_type_names::kPlaying));
  }

  void SimulatePause() {
    video_wake_lock_->Invoke(GetFrame().DomWindow(),
                             Event::Create(event_type_names::kPause));
  }

  void SimulateEnterPictureInPicture() {
    PictureInPictureController::From(GetDocument())
        .EnterPictureInPicture(Video(), /*promise=*/nullptr);

    MakeGarbageCollected<WaitForEvent>(
        video_.Get(), event_type_names::kEnterpictureinpicture);
  }

  void SimulateLeavePictureInPicture() {
    PictureInPictureController::From(GetDocument())
        .ExitPictureInPicture(Video(), nullptr);

    MakeGarbageCollected<WaitForEvent>(
        video_.Get(), event_type_names::kLeavepictureinpicture);
  }

  void SimulateContextPause() {
    GetFrame().DomWindow()->SetLifecycleState(
        mojom::FrameLifecycleState::kPaused);
  }

  void SimulateContextRunning() {
    GetFrame().DomWindow()->SetLifecycleState(
        mojom::FrameLifecycleState::kRunning);
  }

  void SimulateContextDestroyed() { GetFrame().DomWindow()->FrameDestroyed(); }

  void SimulateNetworkState(HTMLMediaElement::NetworkState network_state) {
    video_->SetNetworkState(network_state);
  }

  void ProcessEvents() { test::RunPendingTasks(); }

  void UpdateObservers() {
    UpdateAllLifecyclePhasesForTest();
    test::RunPendingTasks();
  }

  void HideVideo() {
    video_->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone);
  }

  void ShowVideo() {
    video_->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kBlock);
  }

  bool HasWakeLock() { return GetVideoWakeLock()->active_for_tests(); }

  void SetDivHeight(double height_in_pixels) {
    div_->SetInlineStyleProperty(CSSPropertyID::kHeight, height_in_pixels,
                                 CSSPrimitiveValue::UnitType::kPixels);
    div_->SetInlineStyleProperty(CSSPropertyID::kWidth, kWindowSize.width(),
                                 CSSPrimitiveValue::UnitType::kPixels);
  }

  HTMLDivElement* div() { return div_; }
  HTMLVideoElement* video() { return video_; }

  void RecreateWebMediaPlayer() {
    auto media_player = std::make_unique<VideoWakeLockMediaPlayer>();
    media_player_ = media_player.get();
    client_->SetWebMediaPlayer(std::move(media_player));
  }

 private:
  test::TaskEnvironment task_environment_;
  std::unique_ptr<VideoWakeLockTestWebFrameClient> client_;
  Persistent<HTMLDivElement> div_;
  Persistent<HTMLVideoElement> video_;
  Persistent<VideoWakeLock> video_wake_lock_;

  VideoWakeLockMediaPlayer* media_player_ = nullptr;
  scoped_refptr<cc::Layer> fake_layer_;

  VideoWakeLockPictureInPictureService pip_service_;
  frame_test_helpers::WebViewHelper helper_;
};

TEST_F(VideoWakeLockTest, NoLockByDefault) {
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PlayingVideoRequestsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PausingVideoCancelsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  SimulatePause();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, HiddingPageCancelsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PlayingWhileHiddenDoesNotRequestLock) {
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, ShowingPageRequestsLock) {
  SimulatePlaying();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  EXPECT_FALSE(HasWakeLock());

  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kVisible,
                               false);
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, ShowingPageDoNotRequestsLockIfPaused) {
  SimulatePlaying();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  EXPECT_FALSE(HasWakeLock());

  SimulatePause();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kVisible,
                               false);
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, RemotePlaybackDisconnectedDoesNotCancelLock) {
  SimulatePlaying();
  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CLOSED);
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, RemotePlaybackConnectingDoesNotCancelLock) {
  SimulatePlaying();
  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CONNECTING);
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, ActiveRemotePlaybackCancelsLock) {
  SimulatePlaying();
  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CLOSED);
  EXPECT_TRUE(HasWakeLock());

  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CONNECTED);
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, LeavingRemotePlaybackResumesLock) {
  SimulatePlaying();
  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CONNECTED);
  EXPECT_FALSE(HasWakeLock());

  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CLOSED);
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PictureInPictureLocksWhenPageNotVisible) {
  SimulatePlaying();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  EXPECT_FALSE(HasWakeLock());

  SimulateEnterPictureInPicture();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PictureInPictureDoesNoLockWhenPaused) {
  SimulatePlaying();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  EXPECT_FALSE(HasWakeLock());

  SimulatePause();
  SimulateEnterPictureInPicture();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, LeavingPictureInPictureCancelsLock) {
  SimulatePlaying();
  GetPage().SetVisibilityState(mojom::blink::PageVisibilityState::kHidden,
                               false);
  SimulateEnterPictureInPicture();
  EXPECT_TRUE(HasWakeLock());

  SimulateLeavePictureInPicture();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, RemotingVideoInPictureInPictureDoesNotRequestLock) {
  SimulatePlaying();
  SimulateEnterPictureInPicture();
  GetVideoWakeLock()->OnRemotePlaybackStateChanged(
      mojom::blink::PresentationConnectionState::CONNECTED);
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, PausingContextCancelsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  SimulateContextPause();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, ResumingContextResumesLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  SimulateContextPause();
  EXPECT_FALSE(HasWakeLock());

  SimulateContextRunning();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, DestroyingContextCancelsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  SimulateContextDestroyed();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, LoadingCancelsLock) {
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  // The network state has to be non-empty for the resetting to actually kick.
  SimulateNetworkState(HTMLMediaElement::kNetworkIdle);

  Video()->SetSrc(g_empty_atom);
  test::RunPendingTasks();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, MutedHiddenVideoDoesNotTakeLock) {
  Video()->setMuted(true);
  HideVideo();
  UpdateObservers();

  SimulatePlaying();

  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, AudibleHiddenVideoTakesLock) {
  Video()->setMuted(false);
  HideVideo();
  UpdateObservers();

  SimulatePlaying();

  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, UnmutingHiddenVideoTakesLock) {
  Video()->setMuted(true);
  HideVideo();
  UpdateObservers();

  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());

  Video()->setMuted(false);
  test::RunPendingTasks();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, MutingHiddenVideoReleasesLock) {
  Video()->setMuted(false);
  HideVideo();
  UpdateObservers();

  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  Video()->setMuted(true);
  test::RunPendingTasks();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, HidingAudibleVideoDoesNotReleaseLock) {
  Video()->setMuted(false);
  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  HideVideo();
  UpdateObservers();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, HidingMutedVideoReleasesLock) {
  Video()->setMuted(true);
  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  HideVideo();
  UpdateObservers();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, HiddenMutedVideoAlwaysVisibleInPictureInPicture) {
  Video()->setMuted(true);
  HideVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());

  SimulateEnterPictureInPicture();
  EXPECT_TRUE(HasWakeLock());

  SimulateLeavePictureInPicture();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, VideoWithNoFramesReleasesLock) {
  GetMediaPlayer()->SetHasVideo(false);
  SimulatePlaying();

  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, VideoWithFramesTakesLock) {
  GetMediaPlayer()->SetHasVideo(true);
  SimulatePlaying();

  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, HidingVideoOnlyReleasesLock) {
  GetMediaPlayer()->SetHasAudio(false);
  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  HideVideo();
  UpdateObservers();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, SmallMutedVideoDoesNotTakeLock) {
  ASSERT_LT(
      kSmallVideoSize.Area64() / static_cast<double>(kWindowSize.Area64()),
      GetVideoWakeLock()->GetSizeThresholdForTests());
  ASSERT_GT(
      kNormalVideoSize.Area64() / static_cast<double>(kWindowSize.Area64()),
      GetVideoWakeLock()->GetSizeThresholdForTests());

  // Set player to take less than 20% of the page and mute it.
  GetMediaPlayer()->SetSize(kSmallVideoSize);
  Video()->setMuted(true);

  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());

  // Unmuting the video should take the lock.
  Video()->setMuted(false);
  ProcessEvents();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, SizeChangeTakesLock) {
  // Set player to take less than 20% of the page and mute it.
  GetMediaPlayer()->SetSize(kSmallVideoSize);
  Video()->setMuted(true);

  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());

  // Resizing the video should take the lock.
  GetMediaPlayer()->SetSize(kNormalVideoSize);
  GetMediaPlayerClient()->SizeChanged();
  UpdateObservers();
  EXPECT_TRUE(HasWakeLock());

  // Getting too small should release the lock.
  GetMediaPlayer()->SetSize(kSmallVideoSize);
  GetMediaPlayerClient()->SizeChanged();
  UpdateObservers();
  EXPECT_FALSE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, MutedVideoTooFarOffscreenDoesNotTakeLock) {
  Video()->setMuted(true);

  // Move enough of the video off screen to not take the lock.
  const auto kThreshold = GetVideoWakeLock()->visibility_threshold_for_tests();
  SetDivHeight(kWindowSize.height() - kNormalVideoSize.height() +
               (1 - kThreshold) * kNormalVideoSize.height());

  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_FALSE(HasWakeLock());

  // Scroll video far enough back on screen.
  SetDivHeight(kWindowSize.height() - kNormalVideoSize.height() +
               (1 - kThreshold * 1.10) * kNormalVideoSize.height());
  UpdateObservers();
  EXPECT_TRUE(HasWakeLock());
}

TEST_F(VideoWakeLockTest, WakeLockTracksDocumentsPage) {
  // Create a document that has no Page.
  auto* another_document = Document::Create(GetDocument());
  ASSERT_FALSE(another_document->GetPage());

  // Move the video there, and notify our wake lock.
  another_document->AppendChild(video());
  GetVideoWakeLock()->ElementDidMoveToNewDocument();
  EXPECT_FALSE(GetVideoWakeLock()->GetPage());

  // Move the video back to the main page and verify that the wake lock notices.
  div()->AppendChild(video());
  GetVideoWakeLock()->ElementDidMoveToNewDocument();
  EXPECT_EQ(GetVideoWakeLock()->GetPage(), video()->GetDocument().GetPage());
}

TEST_F(VideoWakeLockTest, VideoOnlyMediaStreamAlwaysTakesLock) {
  // Default player is consumed on the first src=file load, so we must provide a
  // new one for the MediaStream load below.
  RecreateWebMediaPlayer();

  // The "with audio" case is the same as the src=file case, so we only test the
  // video only MediaStream case here.
  GetMediaPlayer()->SetHasAudio(false);

  MediaStreamComponentVector dummy_components;
  auto* descriptor = MakeGarbageCollected<MediaStreamDescriptor>(
      dummy_components, dummy_components);
  Video()->SetSrcObjectVariant(descriptor);
  test::RunPendingTasks();

  ASSERT_EQ(Video()->GetLoadType(), WebMediaPlayer::kLoadTypeMediaStream);
  EXPECT_FALSE(HasWakeLock());

  GetMediaPlayer()->SetSize(kNormalVideoSize);
  ShowVideo();
  UpdateObservers();
  SimulatePlaying();
  EXPECT_TRUE(HasWakeLock());

  // Set player to take less than 20% of the page and ensure wake lock is held.
  GetMediaPlayer()->SetSize(kSmallVideoSize);
  GetMediaPlayerClient()->SizeChanged();
  UpdateObservers();
  EXPECT_TRUE(HasWakeLock());

  // Ensure normal wake lock release.
  SimulatePause();
  EXPECT_FALSE(HasWakeLock());
}

}  // namespace blink
```
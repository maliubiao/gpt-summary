Response:
The user wants me to analyze a C++ test file for the Chromium Blink engine, specifically `html_media_element_test.cc`.

Here's a breakdown of the request and how I'll address it:

1. **List its functions:** I need to identify the primary purpose of this test file by examining its includes, class names, and the general structure of the code.
2. **Relationship with JavaScript, HTML, and CSS:** I need to determine how this C++ code interacts with front-end technologies. This involves looking for code that manipulates DOM elements, handles events, or tests features related to media elements, which are integral to HTML.
3. **Logical Reasoning (Hypothetical Input/Output):**  Since this is a *test* file, I should be able to identify test cases that demonstrate specific behaviors. I can infer the inputs (e.g., setting attributes of a media element) and the expected outputs (e.g., the media player entering a specific state).
4. **Common User/Programming Errors:** Test files often validate error handling. I should look for tests that check how the media element behaves in response to invalid or unexpected conditions, which might correspond to common mistakes.
5. **Summarize Functionality (Part 1 of 3):**  For this first part, I will provide a high-level overview of the file's purpose based on the provided code snippet.

**Mental Sandbox:**

* **Includes:** The included headers (`html_media_element.h`, `html_audio_element.h`, `html_video_element.h`) strongly suggest this file tests the functionality of HTML media elements (`<audio>` and `<video>`). The presence of `gtest` confirms it's a unit test file.
* **Mocking:** The use of `gmock` and the `MockWebMediaPlayer` class indicates that the tests are likely isolating the `HTMLMediaElement` logic by simulating the underlying media player implementation.
* **Test Structure:** The `HTMLMediaElementTest` class with parameterized tests (`INSTANTIATE_TEST_SUITE_P`) suggests that the tests cover both audio and video elements.
* **JavaScript/HTML/CSS Connection:**  Media elements are fundamental HTML elements. The tests will likely involve setting attributes (HTML), checking how the element behaves based on those attributes, and verifying events that would be triggered in a real browser environment (accessible via JavaScript). CSS might be relevant in terms of default styling or how the element renders, but the focus here seems more on the core media playback logic.
* **Hypothetical Input/Output:**  A test might set the `src` attribute of an `<audio>` element to a specific URL (input) and then assert that the `networkState` changes to `kLoading` (output). Another could set `autoplay` and expect playback to start under certain conditions.
* **User/Programming Errors:** Tests might check how the element handles an invalid `src` URL, or attempting to play a media file that's not supported.

**Confidence Score:** 5/5 - I'm quite confident I can address all aspects of the request based on the provided code.

**Strategizing complete.** I will now generate the response following the outlined steps.
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/html_media_element.h"

#include "base/run_loop.h"
#include "base/test/gtest_util.h"
#include "media/base/media_content_type.h"
#include "media/base/media_switches.h"
#include "media/base/media_track.h"
#include "media/mojo/mojom/media_player.mojom-blink.h"
#include "services/media_session/public/mojom/media_session.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/autoplay/autoplay.mojom-blink.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/media/media_error.h"
#party/blink/renderer/core/html/media/media_video_visibility_tracker.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state_scopes.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::NanSensitiveDoubleEq;
using ::testing::Return;

namespace blink {

namespace {

enum class TestURLScheme {
  kHttp,
  kHttps,
  kFtp,
  kFile,
  kData,
  kBlob,
};

AtomicString SrcSchemeToURL(TestURLScheme scheme) {
  switch (scheme) {
    case TestURLScheme::kHttp:
      return AtomicString("http://example.com/foo.mp4");
    case TestURLScheme::kHttps:
      return AtomicString("https://example.com/foo.mp4");
    case TestURLScheme::kFtp:
      return AtomicString("ftp://example.com/foo.mp4");
    case TestURLScheme::kFile:
      return AtomicString("file:///foo/bar.mp4");
    case TestURLScheme::kData:
      return AtomicString("data:video/mp4;base64,XXXXXXX");
    case TestURLScheme::kBlob:
      return AtomicString(
          "blob:http://example.com/00000000-0000-0000-0000-000000000000");
    default:
      NOTREACHED();
  }
}

class MockWebMediaPlayer : public EmptyWebMediaPlayer {
 public:
  MOCK_METHOD0(OnTimeUpdate, void());
  MOCK_CONST_METHOD0(Seekable, WebTimeRanges());
  MOCK_METHOD0(OnFrozen, void());
  MOCK_CONST_METHOD0(HasAudio, bool());
  MOCK_CONST_METHOD0(HasVideo, bool());
  MOCK_CONST_METHOD0(Duration, double());
  MOCK_CONST_METHOD0(CurrentTime, double());
  MOCK_CONST_METHOD0(IsEnded, bool());
  MOCK_CONST_METHOD0(GetNetworkState, NetworkState());
  MOCK_CONST_METHOD0(WouldTaintOrigin, bool());
  MOCK_METHOD1(SetLatencyHint, void(double));
  MOCK_METHOD1(SetWasPlayedWithUserActivationAndHighMediaEngagement,
               void(bool));
  MOCK_METHOD1(EnabledAudioTracksChanged, void(const WebVector<TrackId>&));
  MOCK_METHOD1(SelectedVideoTrackChanged, void(std::optional<TrackId>));
  MOCK_METHOD4(
      Load,
      WebMediaPlayer::LoadTiming(LoadType load_type,
                                 const blink::WebMediaPlayerSource& source,
                                 CorsMode cors_mode,
                                 bool is_cache_disabled));
  MOCK_CONST_METHOD0(DidLazyLoad, bool());

  MOCK_METHOD0(GetSrcAfterRedirects, GURL());
};

class WebMediaStubLocalFrameClient : public EmptyLocalFrameClient {
 public:
  explicit WebMediaStubLocalFrameClient(std::unique_ptr<WebMediaPlayer> player)
      : player_(std::move(player)) {}

  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient* client) override {
    DCHECK(player_) << " Empty injected player - already used?";
    return std::move(player_);
  }

 private:
  std::unique_ptr<WebMediaPlayer> player_;
};

class FullscreenMockChromeClient : public EmptyChromeClient {
 public:
  // ChromeClient overrides:
  void EnterFullscreen(LocalFrame& frame,
                       const FullscreenOptions*,
                       FullscreenRequestType) override {
    Fullscreen::DidResolveEnterFullscreenRequest(*frame.GetDocument(),
                                                 true /* granted */);
  }
  void ExitFullscreen(LocalFrame& frame) override {
    Fullscreen::DidExitFullscreen(*frame.GetDocument());
  }
};

// Helper class to mock `RequestVisibility` callbacks.
class RequestVisibilityWaiter {
 public:
  RequestVisibilityWaiter() : run_loop_(std::make_unique<base::RunLoop>()) {}

  RequestVisibilityWaiter(const RequestVisibilityWaiter&) = delete;
  RequestVisibilityWaiter(RequestVisibilityWaiter&&) = delete;
  RequestVisibilityWaiter& operator=(const RequestVisibilityWaiter&) = delete;

  HTMLMediaElement::RequestVisibilityCallback VisibilityCallback() {
    // base::Unretained() is safe since no further tasks can run after
    // RunLoop::Run() returns.
    return base::BindOnce(&RequestVisibilityWaiter::RequestVisibility,
                          base::Unretained(this));
  }

  void WaitUntilDone() {
    run_loop_->Run();
    run_loop_ = std::make_unique<base::RunLoop>();
  }

  bool MeetsVisibility() { return meets_visibility_; }

 private:
  void RequestVisibility(bool meets_visibility) {
    meets_visibility_ = meets_visibility;
    run_loop_->Quit();
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  bool meets_visibility_ = false;
};

// Helper class that provides an implementation of the MediaPlayerObserver mojo
// interface to allow checking that messages sent over mojo are received with
// the right values in the other end.
class TestMediaPlayerObserver final
    : public media::mojom::blink::MediaPlayerObserver {
 public:
  struct OnMetadataChangedResult {
    bool has_audio;
    bool has_video;
    media::MediaContentType media_content_type;
  };

  // Needs to be called from tests after invoking a method from the MediaPlayer
  // mojo interface, so that we have enough time to process the message.
  void WaitUntilReceivedMessage() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
    run_loop_.reset();
  }

  // media::mojom::blink::MediaPlayerObserver implementation.
  void OnMediaPlaying() override {
    received_media_playing_ = true;
    run_loop_->Quit();
  }

  void OnMediaPaused(bool stream_ended) override {
    received_media_paused_stream_ended_ = stream_ended;
    run_loop_->Quit();
  }

  void OnMutedStatusChanged(bool muted) override {
    received_muted_status_type_ = muted;
    run_loop_->Quit();
  }

  void OnMediaMetadataChanged(bool has_audio,
                              bool has_video,
                              media::MediaContentType content_type) override {
    // struct OnMetadataChangedResult result{has_audio, has_video,
    // content_type};
    received_metadata_changed_result_ =
        OnMetadataChangedResult{has_audio, has_video, content_type};
    run_loop_->Quit();
  }

  void OnMediaPositionStateChanged(
      ::media_session::mojom::blink::MediaPositionPtr) override {}

  void OnMediaEffectivelyFullscreenChanged(
      blink::WebFullscreenVideoStatus status) override {}

  void OnMediaSizeChanged(const gfx::Size& size) override {
    received_media_size_ = size;
    run_loop_->Quit();
  }

  void OnPictureInPictureAvailabilityChanged(bool available) override {}

  void OnAudioOutputSinkChanged(const WTF::String& hashed_device_id) override {}

  void OnUseAudioServiceChanged(bool uses_audio_service) override {
    received_uses_audio_service_ = uses_audio_service;
    run_loop_->Quit();
  }

  void OnAudioOutputSinkChangingDisabled() override {}

  void OnRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) override {
    received_remote_playback_metadata_ = std::move(remote_playback_metadata);
    run_loop_->Quit();
  }

  void OnVideoVisibilityChanged(bool meets_visibility_threshold) override {}

  // Getters used from HTMLMediaElementTest.
  bool received_media_playing() const { return received_media_playing_; }

  const std::optional<bool>& received_media_paused_stream_ended() const {
    return received_media_paused_stream_ended_;
  }

  const std::optional<bool>& received_muted_status() const {
    return received_muted_status_type_;
  }

  const std::optional<OnMetadataChangedResult>&
  received_metadata_changed_result() const {
    return received_metadata_changed_result_;
  }

  gfx::Size received_media_size() const { return received_media_size_; }

  bool received_use_audio_service_changed(bool uses_audio_service) const {
    return received_uses_audio_service_.value() == uses_audio_service;
  }

  bool received_remote_playback_metadata(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) const {
    return received_remote_playback_metadata_ == remote_playback_metadata;
  }

 private:
  std::unique_ptr<base::RunLoop> run_loop_;
  bool received_media_playing_{false};
  std::optional<bool> received_media_paused_stream_ended_;
  std::optional<bool> received_muted_status_type_;
  std::optional<OnMetadataChangedResult> received_metadata_changed_result_;
  gfx::Size received_media_size_{0, 0};
  std::optional<bool> received_uses_audio_service_;
  media_session::mojom::blink::RemotePlaybackMetadataPtr
      received_remote_playback_metadata_;
};

class TestMediaPlayerHost final : public media::mojom::blink::MediaPlayerHost {
 public:
  void WaitForPlayer() { run_loop_.Run(); }

  // media::mojom::MediaPlayerHost
  void OnMediaPlayerAdded(
      mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
      /*media_player*/,
      mojo::PendingAssociatedReceiver<media::mojom::blink::MediaPlayerObserver>
          media_player_observer,
      int32_t /*player_id*/) override {
    receiver_.Bind(std::move(media_player_observer));
    run_loop_.Quit();
  }

  TestMediaPlayerObserver& observer() { return observer_; }

 private:
  TestMediaPlayerObserver observer_;
  mojo::AssociatedReceiver<media::mojom::blink::MediaPlayerObserver> receiver_{
      &observer_};
  base::RunLoop run_loop_;
};

enum class MediaTestParam { kAudio, kVideo };

}  // namespace

class HTMLMediaElementTest : public testing::TestWithParam<MediaTestParam> {
 protected:
  void SetUp() override {
    // Sniff the media player pointer to facilitate mocking.
    auto mock_media_player = std::make_unique<MockWebMediaPlayer>();
    media_player_weak_ = mock_media_player->AsWeakPtr();
    media_player_ = mock_media_player.get();

    // Most tests do not care about this call, nor its return value. Those that
    // do will clear this expectation and set custom expectations/returns.
    EXPECT_CALL(*mock_media_player, Seekable())
        .WillRepeatedly(Return(WebTimeRanges()));
    EXPECT_CALL(*mock_media_player, HasAudio()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, HasVideo()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, Duration()).WillRepeatedly(Return(1.0));
    EXPECT_CALL(*mock_media_player, CurrentTime()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mock_media_player, Load(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(WebMediaPlayer::LoadTiming::kImmediate));
    EXPECT_CALL(*mock_media_player, DidLazyLoad).WillRepeatedly(Return(false));
    EXPECT_CALL(*mock_media_player, WouldTaintOrigin)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, GetNetworkState)
        .WillRepeatedly(Return(WebMediaPlayer::kNetworkStateIdle));
    EXPECT_CALL(*mock_media_player, SetLatencyHint(_)).Times(AnyNumber());

    chrome_client_ = MakeGarbageCollected<FullscreenMockChromeClient>();
    dummy_page_holder_ = std::make_unique<DummyPageHolder>(
        gfx::Size(), chrome_client_,
        MakeGarbageCollected<WebMediaStubLocalFrameClient>(
            std::move(mock_media_player)));

    if (GetParam() == MediaTestParam::kAudio) {
      media_ = MakeGarbageCollected<HTMLAudioElement>(
          dummy_page_holder_->GetDocument());
    } else {
      media_ = MakeGarbageCollected<HTMLVideoElement>(
          dummy_page_holder_->GetDocument());
    }

    media_->SetMediaPlayerHostForTesting(
        media_player_host_receiver_.BindNewEndpointAndPassDedicatedRemote());

    UpdateLifecyclePhases();
  }

  void UpdateLifecyclePhases() {
    dummy_page_holder_->GetFrameView().UpdateAllLifecyclePhasesForTest();
  }

  void WaitForPlayer() {
    Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
    Media()->Play();
    media_player_host_.WaitForPlayer();
  }

  HTMLMediaElement* Media() const { return media_.Get(); }
  void SetCurrentSrc(const AtomicString& src) {
    KURL url(src);
    Media()->current_src_.SetSource(
        url, HTMLMediaElement::SourceMetadata::SourceVisibility::kVisibleToApp);
  }

  MockWebMediaPlayer* MockMediaPlayer() { return media_player_; }

  bool WasAutoplayInitiated() { return Media()->WasAutoplayInitiated(); }

  bool CouldPlayIfEnoughData() { return Media()->CouldPlayIfEnoughData(); }

  bool PotentiallyPlaying() { return Media()->PotentiallyPlaying(); }

  bool ShouldDelayLoadEvent() { return Media()->should_delay_load_event_; }

  void SetReadyState(HTMLMediaElement::ReadyState state) {
    Media()->SetReadyState(state);
  }

  void SetNetworkState(WebMediaPlayer::NetworkState state) {
    Media()->SetNetworkState(state);
  }

  bool MediaIsPlaying() const { return Media()->playing_; }

  void ResetWebMediaPlayer() const { Media()->web_media_player_.reset(); }

  void MediaContextLifecycleStateChanged(mojom::FrameLifecycleState state) {
    Media()->ContextLifecycleStateChanged(state);
  }

  bool MediaShouldBeOpaque() const { return Media()->MediaShouldBeOpaque(); }

  void SetError(MediaError* err) { Media()->MediaEngineError(err); }

  void SimulateHighMediaEngagement() {
    Media()->GetDocument().GetPage()->AddAutoplayFlags(
        mojom::blink::kAutoplayFlagHighMediaEngagement);
  }

  bool HasLazyLoadObserver() const {
    return !!Media()->lazy_load_intersection_observer_;
  }

  bool ControlsVisible() const { return Media()->ShouldShowControls(); }

  bool MediaShouldShowAllControls() const {
    return Media()->ShouldShowAllControls();
  }

  ExecutionContext* GetExecutionContext() const {
    return dummy_page_holder_->GetFrame().DomWindow();
  }

  LocalDOMWindow* GetDomWindow() const {
    return dummy_page_holder_->GetFrame().DomWindow();
  }

  void TimeChanged() { Media()->TimeChanged(); }

  void ContextDestroyed() { Media()->ContextDestroyed(); }

  MediaVideoVisibilityTracker* VideoVisibilityTracker() {
    auto* video = DynamicTo<HTMLVideoElement>(Media());
    return video ? video->visibility_tracker_for_tests() : nullptr;
  }

  MediaVideoVisibilityTracker::TrackerAttachedToDocument
  VideoVisibilityTrackerAttachedToDocument(HTMLVideoElement* video) const {
    DCHECK(video->visibility_tracker_for_tests());
    return video->visibility_tracker_for_tests()->tracker_attached_to_document_;
  }

  void RequestVisibility(HTMLMediaElement::RequestVisibilityCallback
                             request_visibility_callback) const {
    Media()->RequestVisibility(std::move(request_visibility_callback));
  }

  void ClearMediaPlayer() { Media()->ClearMediaPlayer(); }

 protected:
  // Helpers to call MediaPlayerObserver mojo methods and check their results.
  void NotifyMediaPlaying() {
    media_->DidPlayerStartPlaying();
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaPlaying() {
    return media_player_observer().received_media_playing();
  }

  void NotifyMediaPaused(bool stream_ended) {
    media_->DidPlayerPaused(stream_ended);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaPaused(bool stream_ended) {
    return media_player_observer().received_media_paused_stream_ended() ==
           stream_ended;
  }

  void NotifyMutedStatusChange(bool muted) {
    media_->DidPlayerMutedStatusChange(muted);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMutedStatusChange(bool muted) {
    return media_player_observer().received_muted_status() == muted;
  }

  void NotifyMediaMetadataChanged(bool has_audio,
                                  bool has_video,
                                  media::AudioCodec audio_codec,
                                  media::VideoCodec video_codec,
                                  media::MediaContentType media_content_type,
                                  bool is_encrypted_media) {
    media_->DidMediaMetadataChange(has_audio, has_video, audio_codec,
                                   video_codec, media_content_type,
                                   is_encrypted_media);
    media_player_observer().WaitUntilReceivedMessage();
    // wait for OnRemotePlaybackMetadataChange() to be called.
      media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaMetadataChanged(
      bool has_audio,
      bool has_video,
      media::MediaContentType media_content_type) {
    const auto& result =
        media_player_observer().received_metadata_changed_result();
    return result->has_audio == has_audio && result->has_video == has_video &&
           result->media_content_type == media_content_type;
  }

  void NotifyMediaSizeChange(const gfx::Size& size) {
    media_->DidPlayerSizeChange(size);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaSizeChange(const gfx::Size& size) {
    return media_player_observer().received_media_size() == size;
  }

  void NotifyUseAudioServiceChanged(bool uses_audio_service) {
    media_->DidUseAudioServiceChange(uses_audio_service);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageUseAudioServiceChanged(bool uses_audio_service) {
    return media_player_observer().received_use_audio_service_changed(
        uses_audio_service);
  }

  void NotifyRemotePlaybackDisabled(bool is_remote_playback_disabled) {
    media_->OnRemotePlaybackDisabled(is_remote_playback_disabled);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) {
    return media_player_observer().received_remote_playback_metadata(
        std::move(remote_playback_metadata));
  }

  bool WasPlayerDestroyed() const { return !media_player_weak_; }

  // Create a dummy page holder with the given security origin.
  std::unique_ptr<DummyPageHolder> CreatePageWithSecurityOrigin(
      const char* origin,
      bool is_picture_in_picture) {
    // Make another document with the same security origin.

    auto dummy_page_holder = std::make_unique<DummyPageHolder>(
        gfx::Size(), nullptr,
        MakeGarbageCollected<WebMediaStubLocalFrameClient>(
            /*player=*/nullptr));
    Document& document = dummy_page_holder->GetDocument();
    document.domWindow()->GetSecurityContext().SetSecurityOriginForTesting(
        SecurityOrigin::CreateFromString(origin));
    document.domWindow()->set_is_picture_in_picture_window_for_testing(
        is_picture_in_picture);

    return dummy_page_holder;
  }

  // Set the security origin of our window.
  void SetSecurityOrigin(const char* origin) {
    Media()
        ->GetDocument()
        .domWindow()
        ->GetSecurityContext()
        .SetSecurityOriginForTesting(SecurityOrigin::CreateFromString(origin));
  }

  // Move Media() from a document in `old_origin` to  one in `new_origin`, and
  // expect that `should_destroy` matches whether the player is destroyed. If
  // the player should not be destroyed, then we also move it back to the
  // original document and verify that it works in both directions.
  void MoveElementAndTestPlayerDestruction(
      const char* old_origin,
      const char* new_origin,
      bool should_destroy,
      bool is_new_document_picture_in_picture,
      bool is_old_document_picture_in_picture,
      bool is_new_document_opener,
      bool is_old_document_opener) {
    // The two documents cannot both be opener.
    EXPECT_FALSE(is_new_document_opener && is_old_document_opener);

    SetSecurityOrigin(old_origin);
    WaitForPlayer();
    // Player should not be destroyed yet.
    EXPECT_FALSE(WasPlayerDestroyed());

    auto& original_document = Media()->GetDocument();
    if (is_old_document_picture_in_picture) {
      original_document.domWindow()
          ->set_is_picture_in_picture_window_for_testing(
              is_old_document_picture_in_picture);
    }

    // Make another document with the correct security origin.
    auto new_dummy_page_holder = CreatePageWithSecurityOrigin(
        new_origin, is_new_document_picture_in_picture);
    Document& new_document = new_dummy_page_holder->GetDocument();

    if (is_old_document_opener) {
      new_document.GetFrame()->SetOpener(original_document.GetFrame());
    } else if (is_new_document_opener) {
      original_document.GetFrame()->SetOpener(new_document.GetFrame());
    }

    // Move the element.
    new_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
    EXPECT_EQ(should_destroy, WasPlayerDestroyed());

    // If the player should be destroyed, then that's everything.
    if (should_destroy)
      return;

    // The move should always work in zero or two directions, so move it back
    // and make sure that the player is retained.
    original_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
    EXPECT_FALSE(WasPlayerDestroyed());
  }

  bool HasEventListenerRegistered(EventTarget& target,
                                  const AtomicString& event_type,
                                  const EventListener* listener) const {
    EventListenerVector* listeners = target.GetEventListeners(event_type);
    if (!listeners) {
      return false;
    }

    for (const auto& registered_listener : *listeners) {
      if (registered_listener->Callback() == listener) {
        return true;
      }
    }

    return false;
  }

  void SimulateEnterFullscreen(Element* element) {
    {
      LocalFrame::NotifyUserActivation(
          element->GetDocument().GetFrame(),
          mojom::UserActivationNotificationType::kTest);
      Fullscreen::RequestFullscreen(*element);
    }
    test::RunPendingTasks();
    UpdateLifecyclePhases();

    if (auto* video = DynamicTo<HTMLVideoElement>(element); video) {
      video->DidEnterFullscreen();
      EXPECT_TRUE(video->IsFullscreen());
    }

    element->GetDocument().DispatchEvent(
        *Event::Create(event_type_names::kFullscreenchange));
    EXPECT_EQ(element,
              Fullscreen::FullscreenElementFrom(element->GetDocument()));
  }

  void SimulateExitFullscreen(Element* element) {
    Fullscreen::FullyExitFullscreen(element->GetDocument());

    if (auto* video = DynamicTo<HTMLVideoElement>(element); video) {
      video->DidExitFullscreen();
      EXPECT_FALSE(video->IsFullscreen());
    }

    element->GetDocument().DispatchEvent(
        *Event::Create(event_type_names::kFullscreenchange));
    EXPECT_EQ(nullptr,
              Fullscreen::FullscreenElementFrom(element->GetDocument()));
  }

  test::TaskEnvironment task_environment_;
  CSSDefaultStyleSheets::TestingScope ua_style_sheets_scope_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;

 private:
  TestMediaPlayerObserver& media_player_observer() {
    return media_player_host_.observer();
  }

  Persistent<HTMLMediaElement> media_;
  Persistent<FullscreenMockChromeClient> chrome_client_;

  // Owned by WebMediaStubLocalFrameClient.
  MockWebMediaPlayer* media_player_;
  base::WeakPtr<WebMediaPlayer> media_player_weak_;

  TestMediaPlayerHost media_player_host_;
  mojo::AssociatedReceiver<media::mojom::blink::MediaPlayerHost>
      media_player_host_receiver_{&media_player_host_};
};

INSTANTIATE_TEST_SUITE_P(Audio,
                         HTMLMediaElementTest,
                         testing::Values(MediaTestParam::kAudio));
INSTANTIATE_TEST_SUITE_P(Video,
                         HTMLMediaElementTest,
                         testing::Values(MediaTestParam::kVideo));

TEST_P(HTMLMediaElementTest, effectiveMediaVolume) {
  struct TestData {
    double volume;
    bool muted;
    double effective_volume;
  } test_data[] = {
      {0.0, false, 0.0}, {0.5, false, 0.5}, {1.0, false, 1.0},
      {0.0, true, 0.0},  {0.5, true, 0.0},  {1.0, true, 0.0},
  };

  for (const auto& data : test_data) {
    Media()->setVolume(data.volume);
    Media()->setMuted(data.muted);
    EXPECT_EQ(data.effective_volume, Media()->EffectiveMediaVolume());
  }
}

TEST_P(HTMLMediaElementTest, preloadType) {
  AtomicString auto_string("auto");
  AtomicString none_string("none");
  AtomicString metadata_string("metadata");
  struct TestData {
    bool data_saver_enabled;
    bool is_cellular;
    TestURLScheme src_scheme;
    AtomicString preload_to_set;
    AtomicString preload_expected;
  } test_data[] = {
      // Tests for conditions in which preload type should be overridden to
      // none_string.
      {false, false, TestURLScheme::kHttp, auto_string, auto_string},
      {true, false, TestURLScheme::kHttps, auto_string, auto_string},
      {true, false, TestURLScheme::kFtp, metadata_string, metadata_string},
      {false, false, TestURLScheme::kHttps, auto_string, auto_string},
      {false, false, TestURLScheme::kFile, auto_string, auto_string},
      {false, false, TestURLScheme::kData, metadata_string, metadata_string},
      {false, false, TestURLScheme::kBlob, auto
### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/media/html_media_element.h"

#include "base/run_loop.h"
#include "base/test/gtest_util.h"
#include "media/base/media_content_type.h"
#include "media/base/media_switches.h"
#include "media/base/media_track.h"
#include "media/mojo/mojom/media_player.mojom-blink.h"
#include "services/media_session/public/mojom/media_session.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/autoplay/autoplay.mojom-blink.h"
#include "third_party/blink/public/platform/web_media_player.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/renderer/core/css/css_default_style_sheets.h"
#include "third_party/blink/renderer/core/dom/dom_implementation.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/html/media/media_error.h"
#include "third_party/blink/renderer/core/html/media/media_video_visibility_tracker.h"
#include "third_party/blink/renderer/core/html/time_ranges.h"
#include "third_party/blink/renderer/core/html/track/audio_track_list.h"
#include "third_party/blink/renderer/core/html/track/video_track_list.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state_scopes.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/empty_web_media_player.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/size.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::NanSensitiveDoubleEq;
using ::testing::Return;

namespace blink {

namespace {

enum class TestURLScheme {
  kHttp,
  kHttps,
  kFtp,
  kFile,
  kData,
  kBlob,
};

AtomicString SrcSchemeToURL(TestURLScheme scheme) {
  switch (scheme) {
    case TestURLScheme::kHttp:
      return AtomicString("http://example.com/foo.mp4");
    case TestURLScheme::kHttps:
      return AtomicString("https://example.com/foo.mp4");
    case TestURLScheme::kFtp:
      return AtomicString("ftp://example.com/foo.mp4");
    case TestURLScheme::kFile:
      return AtomicString("file:///foo/bar.mp4");
    case TestURLScheme::kData:
      return AtomicString("data:video/mp4;base64,XXXXXXX");
    case TestURLScheme::kBlob:
      return AtomicString(
          "blob:http://example.com/00000000-0000-0000-0000-000000000000");
    default:
      NOTREACHED();
  }
}

class MockWebMediaPlayer : public EmptyWebMediaPlayer {
 public:
  MOCK_METHOD0(OnTimeUpdate, void());
  MOCK_CONST_METHOD0(Seekable, WebTimeRanges());
  MOCK_METHOD0(OnFrozen, void());
  MOCK_CONST_METHOD0(HasAudio, bool());
  MOCK_CONST_METHOD0(HasVideo, bool());
  MOCK_CONST_METHOD0(Duration, double());
  MOCK_CONST_METHOD0(CurrentTime, double());
  MOCK_CONST_METHOD0(IsEnded, bool());
  MOCK_CONST_METHOD0(GetNetworkState, NetworkState());
  MOCK_CONST_METHOD0(WouldTaintOrigin, bool());
  MOCK_METHOD1(SetLatencyHint, void(double));
  MOCK_METHOD1(SetWasPlayedWithUserActivationAndHighMediaEngagement,
               void(bool));
  MOCK_METHOD1(EnabledAudioTracksChanged, void(const WebVector<TrackId>&));
  MOCK_METHOD1(SelectedVideoTrackChanged, void(std::optional<TrackId>));
  MOCK_METHOD4(
      Load,
      WebMediaPlayer::LoadTiming(LoadType load_type,
                                 const blink::WebMediaPlayerSource& source,
                                 CorsMode cors_mode,
                                 bool is_cache_disabled));
  MOCK_CONST_METHOD0(DidLazyLoad, bool());

  MOCK_METHOD0(GetSrcAfterRedirects, GURL());
};

class WebMediaStubLocalFrameClient : public EmptyLocalFrameClient {
 public:
  explicit WebMediaStubLocalFrameClient(std::unique_ptr<WebMediaPlayer> player)
      : player_(std::move(player)) {}

  std::unique_ptr<WebMediaPlayer> CreateWebMediaPlayer(
      HTMLMediaElement&,
      const WebMediaPlayerSource&,
      WebMediaPlayerClient* client) override {
    DCHECK(player_) << " Empty injected player - already used?";
    return std::move(player_);
  }

 private:
  std::unique_ptr<WebMediaPlayer> player_;
};

class FullscreenMockChromeClient : public EmptyChromeClient {
 public:
  // ChromeClient overrides:
  void EnterFullscreen(LocalFrame& frame,
                       const FullscreenOptions*,
                       FullscreenRequestType) override {
    Fullscreen::DidResolveEnterFullscreenRequest(*frame.GetDocument(),
                                                 true /* granted */);
  }
  void ExitFullscreen(LocalFrame& frame) override {
    Fullscreen::DidExitFullscreen(*frame.GetDocument());
  }
};

// Helper class to mock `RequestVisibility` callbacks.
class RequestVisibilityWaiter {
 public:
  RequestVisibilityWaiter() : run_loop_(std::make_unique<base::RunLoop>()) {}

  RequestVisibilityWaiter(const RequestVisibilityWaiter&) = delete;
  RequestVisibilityWaiter(RequestVisibilityWaiter&&) = delete;
  RequestVisibilityWaiter& operator=(const RequestVisibilityWaiter&) = delete;

  HTMLMediaElement::RequestVisibilityCallback VisibilityCallback() {
    // base::Unretained() is safe since no further tasks can run after
    // RunLoop::Run() returns.
    return base::BindOnce(&RequestVisibilityWaiter::RequestVisibility,
                          base::Unretained(this));
  }

  void WaitUntilDone() {
    run_loop_->Run();
    run_loop_ = std::make_unique<base::RunLoop>();
  }

  bool MeetsVisibility() { return meets_visibility_; }

 private:
  void RequestVisibility(bool meets_visibility) {
    meets_visibility_ = meets_visibility;
    run_loop_->Quit();
  }

  std::unique_ptr<base::RunLoop> run_loop_;
  bool meets_visibility_ = false;
};

// Helper class that provides an implementation of the MediaPlayerObserver mojo
// interface to allow checking that messages sent over mojo are received with
// the right values in the other end.
class TestMediaPlayerObserver final
    : public media::mojom::blink::MediaPlayerObserver {
 public:
  struct OnMetadataChangedResult {
    bool has_audio;
    bool has_video;
    media::MediaContentType media_content_type;
  };

  // Needs to be called from tests after invoking a method from the MediaPlayer
  // mojo interface, so that we have enough time to process the message.
  void WaitUntilReceivedMessage() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
    run_loop_.reset();
  }

  // media::mojom::blink::MediaPlayerObserver implementation.
  void OnMediaPlaying() override {
    received_media_playing_ = true;
    run_loop_->Quit();
  }

  void OnMediaPaused(bool stream_ended) override {
    received_media_paused_stream_ended_ = stream_ended;
    run_loop_->Quit();
  }

  void OnMutedStatusChanged(bool muted) override {
    received_muted_status_type_ = muted;
    run_loop_->Quit();
  }

  void OnMediaMetadataChanged(bool has_audio,
                              bool has_video,
                              media::MediaContentType content_type) override {
    // struct OnMetadataChangedResult result{has_audio, has_video,
    // content_type};
    received_metadata_changed_result_ =
        OnMetadataChangedResult{has_audio, has_video, content_type};
    run_loop_->Quit();
  }

  void OnMediaPositionStateChanged(
      ::media_session::mojom::blink::MediaPositionPtr) override {}

  void OnMediaEffectivelyFullscreenChanged(
      blink::WebFullscreenVideoStatus status) override {}

  void OnMediaSizeChanged(const gfx::Size& size) override {
    received_media_size_ = size;
    run_loop_->Quit();
  }

  void OnPictureInPictureAvailabilityChanged(bool available) override {}

  void OnAudioOutputSinkChanged(const WTF::String& hashed_device_id) override {}

  void OnUseAudioServiceChanged(bool uses_audio_service) override {
    received_uses_audio_service_ = uses_audio_service;
    run_loop_->Quit();
  }

  void OnAudioOutputSinkChangingDisabled() override {}

  void OnRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) override {
    received_remote_playback_metadata_ = std::move(remote_playback_metadata);
    run_loop_->Quit();
  }

  void OnVideoVisibilityChanged(bool meets_visibility_threshold) override {}

  // Getters used from HTMLMediaElementTest.
  bool received_media_playing() const { return received_media_playing_; }

  const std::optional<bool>& received_media_paused_stream_ended() const {
    return received_media_paused_stream_ended_;
  }

  const std::optional<bool>& received_muted_status() const {
    return received_muted_status_type_;
  }

  const std::optional<OnMetadataChangedResult>&
  received_metadata_changed_result() const {
    return received_metadata_changed_result_;
  }

  gfx::Size received_media_size() const { return received_media_size_; }

  bool received_use_audio_service_changed(bool uses_audio_service) const {
    return received_uses_audio_service_.value() == uses_audio_service;
  }

  bool received_remote_playback_metadata(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) const {
    return received_remote_playback_metadata_ == remote_playback_metadata;
  }

 private:
  std::unique_ptr<base::RunLoop> run_loop_;
  bool received_media_playing_{false};
  std::optional<bool> received_media_paused_stream_ended_;
  std::optional<bool> received_muted_status_type_;
  std::optional<OnMetadataChangedResult> received_metadata_changed_result_;
  gfx::Size received_media_size_{0, 0};
  std::optional<bool> received_uses_audio_service_;
  media_session::mojom::blink::RemotePlaybackMetadataPtr
      received_remote_playback_metadata_;
};

class TestMediaPlayerHost final : public media::mojom::blink::MediaPlayerHost {
 public:
  void WaitForPlayer() { run_loop_.Run(); }

  // media::mojom::MediaPlayerHost
  void OnMediaPlayerAdded(
      mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayer>
      /*media_player*/,
      mojo::PendingAssociatedReceiver<media::mojom::blink::MediaPlayerObserver>
          media_player_observer,
      int32_t /*player_id*/) override {
    receiver_.Bind(std::move(media_player_observer));
    run_loop_.Quit();
  }

  TestMediaPlayerObserver& observer() { return observer_; }

 private:
  TestMediaPlayerObserver observer_;
  mojo::AssociatedReceiver<media::mojom::blink::MediaPlayerObserver> receiver_{
      &observer_};
  base::RunLoop run_loop_;
};

enum class MediaTestParam { kAudio, kVideo };

}  // namespace

class HTMLMediaElementTest : public testing::TestWithParam<MediaTestParam> {
 protected:
  void SetUp() override {
    // Sniff the media player pointer to facilitate mocking.
    auto mock_media_player = std::make_unique<MockWebMediaPlayer>();
    media_player_weak_ = mock_media_player->AsWeakPtr();
    media_player_ = mock_media_player.get();

    // Most tests do not care about this call, nor its return value. Those that
    // do will clear this expectation and set custom expectations/returns.
    EXPECT_CALL(*mock_media_player, Seekable())
        .WillRepeatedly(Return(WebTimeRanges()));
    EXPECT_CALL(*mock_media_player, HasAudio()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, HasVideo()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, Duration()).WillRepeatedly(Return(1.0));
    EXPECT_CALL(*mock_media_player, CurrentTime()).WillRepeatedly(Return(0));
    EXPECT_CALL(*mock_media_player, Load(_, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(WebMediaPlayer::LoadTiming::kImmediate));
    EXPECT_CALL(*mock_media_player, DidLazyLoad).WillRepeatedly(Return(false));
    EXPECT_CALL(*mock_media_player, WouldTaintOrigin)
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mock_media_player, GetNetworkState)
        .WillRepeatedly(Return(WebMediaPlayer::kNetworkStateIdle));
    EXPECT_CALL(*mock_media_player, SetLatencyHint(_)).Times(AnyNumber());

    chrome_client_ = MakeGarbageCollected<FullscreenMockChromeClient>();
    dummy_page_holder_ = std::make_unique<DummyPageHolder>(
        gfx::Size(), chrome_client_,
        MakeGarbageCollected<WebMediaStubLocalFrameClient>(
            std::move(mock_media_player)));

    if (GetParam() == MediaTestParam::kAudio) {
      media_ = MakeGarbageCollected<HTMLAudioElement>(
          dummy_page_holder_->GetDocument());
    } else {
      media_ = MakeGarbageCollected<HTMLVideoElement>(
          dummy_page_holder_->GetDocument());
    }

    media_->SetMediaPlayerHostForTesting(
        media_player_host_receiver_.BindNewEndpointAndPassDedicatedRemote());

    UpdateLifecyclePhases();
  }

  void UpdateLifecyclePhases() {
    dummy_page_holder_->GetFrameView().UpdateAllLifecyclePhasesForTest();
  }

  void WaitForPlayer() {
    Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
    Media()->Play();
    media_player_host_.WaitForPlayer();
  }

  HTMLMediaElement* Media() const { return media_.Get(); }
  void SetCurrentSrc(const AtomicString& src) {
    KURL url(src);
    Media()->current_src_.SetSource(
        url, HTMLMediaElement::SourceMetadata::SourceVisibility::kVisibleToApp);
  }

  MockWebMediaPlayer* MockMediaPlayer() { return media_player_; }

  bool WasAutoplayInitiated() { return Media()->WasAutoplayInitiated(); }

  bool CouldPlayIfEnoughData() { return Media()->CouldPlayIfEnoughData(); }

  bool PotentiallyPlaying() { return Media()->PotentiallyPlaying(); }

  bool ShouldDelayLoadEvent() { return Media()->should_delay_load_event_; }

  void SetReadyState(HTMLMediaElement::ReadyState state) {
    Media()->SetReadyState(state);
  }

  void SetNetworkState(WebMediaPlayer::NetworkState state) {
    Media()->SetNetworkState(state);
  }

  bool MediaIsPlaying() const { return Media()->playing_; }

  void ResetWebMediaPlayer() const { Media()->web_media_player_.reset(); }

  void MediaContextLifecycleStateChanged(mojom::FrameLifecycleState state) {
    Media()->ContextLifecycleStateChanged(state);
  }

  bool MediaShouldBeOpaque() const { return Media()->MediaShouldBeOpaque(); }

  void SetError(MediaError* err) { Media()->MediaEngineError(err); }

  void SimulateHighMediaEngagement() {
    Media()->GetDocument().GetPage()->AddAutoplayFlags(
        mojom::blink::kAutoplayFlagHighMediaEngagement);
  }

  bool HasLazyLoadObserver() const {
    return !!Media()->lazy_load_intersection_observer_;
  }

  bool ControlsVisible() const { return Media()->ShouldShowControls(); }

  bool MediaShouldShowAllControls() const {
    return Media()->ShouldShowAllControls();
  }

  ExecutionContext* GetExecutionContext() const {
    return dummy_page_holder_->GetFrame().DomWindow();
  }

  LocalDOMWindow* GetDomWindow() const {
    return dummy_page_holder_->GetFrame().DomWindow();
  }

  void TimeChanged() { Media()->TimeChanged(); }

  void ContextDestroyed() { Media()->ContextDestroyed(); }

  MediaVideoVisibilityTracker* VideoVisibilityTracker() {
    auto* video = DynamicTo<HTMLVideoElement>(Media());
    return video ? video->visibility_tracker_for_tests() : nullptr;
  }

  MediaVideoVisibilityTracker::TrackerAttachedToDocument
  VideoVisibilityTrackerAttachedToDocument(HTMLVideoElement* video) const {
    DCHECK(video->visibility_tracker_for_tests());
    return video->visibility_tracker_for_tests()->tracker_attached_to_document_;
  }

  void RequestVisibility(HTMLMediaElement::RequestVisibilityCallback
                             request_visibility_callback) const {
    Media()->RequestVisibility(std::move(request_visibility_callback));
  }

  void ClearMediaPlayer() { Media()->ClearMediaPlayer(); }

 protected:
  // Helpers to call MediaPlayerObserver mojo methods and check their results.
  void NotifyMediaPlaying() {
    media_->DidPlayerStartPlaying();
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaPlaying() {
    return media_player_observer().received_media_playing();
  }

  void NotifyMediaPaused(bool stream_ended) {
    media_->DidPlayerPaused(stream_ended);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaPaused(bool stream_ended) {
    return media_player_observer().received_media_paused_stream_ended() ==
           stream_ended;
  }

  void NotifyMutedStatusChange(bool muted) {
    media_->DidPlayerMutedStatusChange(muted);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMutedStatusChange(bool muted) {
    return media_player_observer().received_muted_status() == muted;
  }

  void NotifyMediaMetadataChanged(bool has_audio,
                                  bool has_video,
                                  media::AudioCodec audio_codec,
                                  media::VideoCodec video_codec,
                                  media::MediaContentType media_content_type,
                                  bool is_encrypted_media) {
    media_->DidMediaMetadataChange(has_audio, has_video, audio_codec,
                                   video_codec, media_content_type,
                                   is_encrypted_media);
    media_player_observer().WaitUntilReceivedMessage();
    // wait for OnRemotePlaybackMetadataChange() to be called.
      media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaMetadataChanged(
      bool has_audio,
      bool has_video,
      media::MediaContentType media_content_type) {
    const auto& result =
        media_player_observer().received_metadata_changed_result();
    return result->has_audio == has_audio && result->has_video == has_video &&
           result->media_content_type == media_content_type;
  }

  void NotifyMediaSizeChange(const gfx::Size& size) {
    media_->DidPlayerSizeChange(size);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageMediaSizeChange(const gfx::Size& size) {
    return media_player_observer().received_media_size() == size;
  }

  void NotifyUseAudioServiceChanged(bool uses_audio_service) {
    media_->DidUseAudioServiceChange(uses_audio_service);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedMessageUseAudioServiceChanged(bool uses_audio_service) {
    return media_player_observer().received_use_audio_service_changed(
        uses_audio_service);
  }

  void NotifyRemotePlaybackDisabled(bool is_remote_playback_disabled) {
    media_->OnRemotePlaybackDisabled(is_remote_playback_disabled);
    media_player_observer().WaitUntilReceivedMessage();
  }

  bool ReceivedRemotePlaybackMetadataChange(
      media_session::mojom::blink::RemotePlaybackMetadataPtr
          remote_playback_metadata) {
    return media_player_observer().received_remote_playback_metadata(
        std::move(remote_playback_metadata));
  }

  bool WasPlayerDestroyed() const { return !media_player_weak_; }

  // Create a dummy page holder with the given security origin.
  std::unique_ptr<DummyPageHolder> CreatePageWithSecurityOrigin(
      const char* origin,
      bool is_picture_in_picture) {
    // Make another document with the same security origin.

    auto dummy_page_holder = std::make_unique<DummyPageHolder>(
        gfx::Size(), nullptr,
        MakeGarbageCollected<WebMediaStubLocalFrameClient>(
            /*player=*/nullptr));
    Document& document = dummy_page_holder->GetDocument();
    document.domWindow()->GetSecurityContext().SetSecurityOriginForTesting(
        SecurityOrigin::CreateFromString(origin));
    document.domWindow()->set_is_picture_in_picture_window_for_testing(
        is_picture_in_picture);

    return dummy_page_holder;
  }

  // Set the security origin of our window.
  void SetSecurityOrigin(const char* origin) {
    Media()
        ->GetDocument()
        .domWindow()
        ->GetSecurityContext()
        .SetSecurityOriginForTesting(SecurityOrigin::CreateFromString(origin));
  }

  // Move Media() from a document in `old_origin` to  one in `new_origin`, and
  // expect that `should_destroy` matches whether the player is destroyed.  If
  // the player should not be destroyed, then we also move it back to the
  // original document and verify that it works in both directions.
  void MoveElementAndTestPlayerDestruction(
      const char* old_origin,
      const char* new_origin,
      bool should_destroy,
      bool is_new_document_picture_in_picture,
      bool is_old_document_picture_in_picture,
      bool is_new_document_opener,
      bool is_old_document_opener) {
    // The two documents cannot both be opener.
    EXPECT_FALSE(is_new_document_opener && is_old_document_opener);

    SetSecurityOrigin(old_origin);
    WaitForPlayer();
    // Player should not be destroyed yet.
    EXPECT_FALSE(WasPlayerDestroyed());

    auto& original_document = Media()->GetDocument();
    if (is_old_document_picture_in_picture) {
      original_document.domWindow()
          ->set_is_picture_in_picture_window_for_testing(
              is_old_document_picture_in_picture);
    }

    // Make another document with the correct security origin.
    auto new_dummy_page_holder = CreatePageWithSecurityOrigin(
        new_origin, is_new_document_picture_in_picture);
    Document& new_document = new_dummy_page_holder->GetDocument();

    if (is_old_document_opener) {
      new_document.GetFrame()->SetOpener(original_document.GetFrame());
    } else if (is_new_document_opener) {
      original_document.GetFrame()->SetOpener(new_document.GetFrame());
    }

    // Move the element.
    new_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
    EXPECT_EQ(should_destroy, WasPlayerDestroyed());

    // If the player should be destroyed, then that's everything.
    if (should_destroy)
      return;

    // The move should always work in zero or two directions, so move it back
    // and make sure that the player is retained.
    original_document.adoptNode(Media(), ASSERT_NO_EXCEPTION);
    EXPECT_FALSE(WasPlayerDestroyed());
  }

  bool HasEventListenerRegistered(EventTarget& target,
                                  const AtomicString& event_type,
                                  const EventListener* listener) const {
    EventListenerVector* listeners = target.GetEventListeners(event_type);
    if (!listeners) {
      return false;
    }

    for (const auto& registered_listener : *listeners) {
      if (registered_listener->Callback() == listener) {
        return true;
      }
    }

    return false;
  }

  void SimulateEnterFullscreen(Element* element) {
    {
      LocalFrame::NotifyUserActivation(
          element->GetDocument().GetFrame(),
          mojom::UserActivationNotificationType::kTest);
      Fullscreen::RequestFullscreen(*element);
    }
    test::RunPendingTasks();
    UpdateLifecyclePhases();

    if (auto* video = DynamicTo<HTMLVideoElement>(element); video) {
      video->DidEnterFullscreen();
      EXPECT_TRUE(video->IsFullscreen());
    }

    element->GetDocument().DispatchEvent(
        *Event::Create(event_type_names::kFullscreenchange));
    EXPECT_EQ(element,
              Fullscreen::FullscreenElementFrom(element->GetDocument()));
  }

  void SimulateExitFullscreen(Element* element) {
    Fullscreen::FullyExitFullscreen(element->GetDocument());

    if (auto* video = DynamicTo<HTMLVideoElement>(element); video) {
      video->DidExitFullscreen();
      EXPECT_FALSE(video->IsFullscreen());
    }

    element->GetDocument().DispatchEvent(
        *Event::Create(event_type_names::kFullscreenchange));
    EXPECT_EQ(nullptr,
              Fullscreen::FullscreenElementFrom(element->GetDocument()));
  }

  test::TaskEnvironment task_environment_;
  CSSDefaultStyleSheets::TestingScope ua_style_sheets_scope_;
  std::unique_ptr<DummyPageHolder> dummy_page_holder_;

 private:
  TestMediaPlayerObserver& media_player_observer() {
    return media_player_host_.observer();
  }

  Persistent<HTMLMediaElement> media_;
  Persistent<FullscreenMockChromeClient> chrome_client_;

  // Owned by WebMediaStubLocalFrameClient.
  MockWebMediaPlayer* media_player_;
  base::WeakPtr<WebMediaPlayer> media_player_weak_;

  TestMediaPlayerHost media_player_host_;
  mojo::AssociatedReceiver<media::mojom::blink::MediaPlayerHost>
      media_player_host_receiver_{&media_player_host_};
};

INSTANTIATE_TEST_SUITE_P(Audio,
                         HTMLMediaElementTest,
                         testing::Values(MediaTestParam::kAudio));
INSTANTIATE_TEST_SUITE_P(Video,
                         HTMLMediaElementTest,
                         testing::Values(MediaTestParam::kVideo));

TEST_P(HTMLMediaElementTest, effectiveMediaVolume) {
  struct TestData {
    double volume;
    bool muted;
    double effective_volume;
  } test_data[] = {
      {0.0, false, 0.0}, {0.5, false, 0.5}, {1.0, false, 1.0},
      {0.0, true, 0.0},  {0.5, true, 0.0},  {1.0, true, 0.0},
  };

  for (const auto& data : test_data) {
    Media()->setVolume(data.volume);
    Media()->setMuted(data.muted);
    EXPECT_EQ(data.effective_volume, Media()->EffectiveMediaVolume());
  }
}

TEST_P(HTMLMediaElementTest, preloadType) {
  AtomicString auto_string("auto");
  AtomicString none_string("none");
  AtomicString metadata_string("metadata");
  struct TestData {
    bool data_saver_enabled;
    bool is_cellular;
    TestURLScheme src_scheme;
    AtomicString preload_to_set;
    AtomicString preload_expected;
  } test_data[] = {
      // Tests for conditions in which preload type should be overridden to
      // none_string.
      {false, false, TestURLScheme::kHttp, auto_string, auto_string},
      {true, false, TestURLScheme::kHttps, auto_string, auto_string},
      {true, false, TestURLScheme::kFtp, metadata_string, metadata_string},
      {false, false, TestURLScheme::kHttps, auto_string, auto_string},
      {false, false, TestURLScheme::kFile, auto_string, auto_string},
      {false, false, TestURLScheme::kData, metadata_string, metadata_string},
      {false, false, TestURLScheme::kBlob, auto_string, auto_string},
      {false, false, TestURLScheme::kFile, none_string, none_string},
      // Tests for conditions in which preload type should be overridden to
      // metadata_string.
      {false, true, TestURLScheme::kHttp, auto_string, metadata_string},
      {false, true, TestURLScheme::kHttp, AtomicString("scheme"),
       metadata_string},
      {false, true, TestURLScheme::kHttp, none_string, none_string},
      // Tests that the preload is overridden to metadata_string.
      {false, false, TestURLScheme::kHttp, AtomicString("foo"),
       metadata_string},
  };

  int index = 0;
  for (const auto& data : test_data) {
    GetNetworkStateNotifier().SetSaveDataEnabledOverride(
        data.data_saver_enabled);
    if (data.is_cellular) {
      GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
          true, WebConnectionType::kWebConnectionTypeCellular3G,
          WebEffectiveConnectionType::kTypeUnknown, 1.0, 2.0);
    } else {
      GetNetworkStateNotifier().ClearOverride();
    }
    SetCurrentSrc(SrcSchemeToURL(data.src_scheme));
    Media()->setPreload(data.preload_to_set);

    EXPECT_EQ(data.preload_expected, Media()->preload())
        << "preload type differs at index" << index;
    ++index;
  }
}

TEST_P(HTMLMediaElementTest, CouldPlayIfEnoughDataRespondsToPlay) {
  EXPECT_FALSE(CouldPlayIfEnoughData());
  Media()->Play();
  EXPECT_TRUE(CouldPlayIfEnoughData());
}

TEST_P(HTMLMediaElementTest, CouldPlayIfEnoughDataRespondsToEnded) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();

  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(Media()->GetWebMediaPlayer());
  ASSERT_NE(mock_wmpi, nullptr);
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(false));
  EXPECT_TRUE(CouldPlayIfEnoughData());

  // Playback can only end once the ready state is above kHaveMetadata.
  SetReadyState(HTMLMediaElement::kHaveFutureData);
  EXPECT_FALSE(Media()->paused());
  EXPECT_FALSE(Media()->ended());
  EXPECT_TRUE(CouldPlayIfEnoughData());

  // Now advance current time to duration and verify ended state.
  testing::Mock::VerifyAndClearExpectations(mock_wmpi);
  EXPECT_CALL(*mock_wmpi, CurrentTime())
      .WillRepeatedly(Return(Media()->duration()));
  EXPECT_CALL(*mock_wmpi, IsEnded()).WillRepeatedly(Return(true));
  EXPECT_FALSE(CouldPlayIfEnoughData());
  EXPECT_TRUE(Media()->ended());
}

TEST_P(HTMLMediaElementTest, CouldPlayIfEnoughDataRespondsToError) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();

  test::RunPendingTasks();

  MockWebMediaPlayer* mock_wmpi =
      reinterpret_cast<MockWebMediaPlayer*>(Media()->GetWebMediaPlayer());
  EXPECT_NE(mock_wmpi, nullptr);
  EXPECT_TRUE(CouldPlayIfEnoughData());

  SetReadyState(HTMLMediaElement::kHaveMetadata);
  EXPECT_FALSE(Media()->paused());
  EXPECT_FALSE(Media()->ended());
  EXPECT_TRUE(CouldPlayIfEnoughData());

  SetError(MakeGarbageCollected<MediaError>(MediaError::kMediaErrDecode, ""));
  EXPECT_FALSE(CouldPlayIfEnoughData());
}

TEST_P(HTMLMediaElementTest, SetLatencyHint) {
  const double kNan = std::numeric_limits<double>::quiet_NaN();

  // Initial value.
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  EXPECT_CALL(*MockMediaPlayer(), SetLatencyHint(NanSensitiveDoubleEq(kNan)));

  test::RunPendingTasks();
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // Valid value.
  EXPECT_CALL(*MockMediaPlayer(), SetLatencyHint(NanSensitiveDoubleEq(1.0)));
  Media()->setLatencyHint(1.0);

  test::RunPendingTasks();
  testing::Mock::VerifyAndClearExpectations(MockMediaPlayer());

  // Invalid value.
  EXPECT_CALL(*MockMediaPlayer(), SetLatencyHint(NanSensitiveDoubleEq(kNan)));
  Media()->setLatencyHint(-1.0);
}

TEST_P(HTMLMediaElementTest, CouldPlayIfEnoughDataInfiniteStreamNeverEnds) {
  Media()->SetSrc(SrcSchemeToURL(TestURLScheme::kHttp));
  Media()->Play();

  test::RunPendingTasks();

  EXPECT_CALL(*MockMediaPlayer(), Duration())
      .WillRepeatedly(Return(std::numeric_limits<double>::infinity()));
  EXPECT_CALL(*MockMediaPlayer(), CurrentTime())
      .WillRepeatedly(Return(std::numeric_limits<double>::infinity()));

  SetReadyState(HTMLMediaElement::kHaveMetadata);
  EXPECT_FALSE(Media()->paused());
  EXPECT_FALSE(Media()->ended());
  EXPECT_TRUE(CouldPlayIfEnoughData());
}

TEST_P(HTMLMediaElementTest, AutoplayInitiated_DocumentActivation_Low_Gesture) {
  // Setup is the following:
  // - Policy: DocumentUserActivation (aka. unified autoplay)
  // - MEI: low;
  // - Frame received user gesture.
  ScopedMediaEngagementBypassAutoplayPoliciesForTest scoped_feature(true);
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kDocumentUserActivationRequired);
  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  Media()->Play();

  EXPECT_FALSE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest,
       AutoplayInitiated_DocumentActivation_High_Gesture) {
  // Setup is the following:
  // - Policy: DocumentUserActivation (aka. unified autoplay)
  // - MEI: high;
  // - Frame received user gesture.
  ScopedMediaEngagementBypassAutoplayPoliciesForTest scoped_feature(true);
  Media()->GetDocument().GetSettings()->SetAutoplayPolicy(
      AutoplayPolicy::Type::kDocumentUserActivationRequired);
  SimulateHighMediaEngagement();
  LocalFrame::NotifyUserActivation(
      Media()->GetDocument().GetFrame(),
      mojom::UserActivationNotificationType::kTest);

  Media()->Play();

  EXPECT_FALSE(WasAutoplayInitiated());
}

TEST_P(HTMLMediaElementTest,
```
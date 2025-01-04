Response:
My thinking process for analyzing the provided code snippet goes through these stages:

1. **Identify the Core Functionality:** The file name `user_media_client_test.cc` immediately signals that this is a *test file*. It's designed to test the functionality of `UserMediaClient`, which is evident from the `#include` directives and the numerous test cases involving `UserMediaClient` and related classes.

2. **Scan for Key Classes and Methods:**  I look for the central class being tested (`UserMediaClient`) and the auxiliary classes used for setting up the test environment and mocking dependencies. Key classes I noticed:
    * `UserMediaClient` (the class under test)
    * `UserMediaProcessor` (a dependency of `UserMediaClient`)
    * `MockMojoMediaStreamDispatcherHost` (a mock for a communication interface)
    * `MockMediaStreamVideoSource`, `MockLocalMediaStreamAudioSource` (mocks for media sources)
    * `UserMediaRequest` (representing a getUserMedia call)
    * Various `mojom` interfaces (defining communication protocols)

3. **Understand the Test Structure:** I observe the use of Google Test (`TEST_F`, `EXPECT_EQ`, `EXPECT_TRUE`, etc.), which is standard for Chromium testing. I also see helper classes like `DummyPageHolder` to create a minimal rendering context.

4. **Infer the Purpose of Mock Objects:** The "Mock" prefix in class names like `MockMojoMediaStreamDispatcherHost` indicates these are mock objects. Their purpose is to simulate the behavior of real dependencies, allowing focused testing of `UserMediaClient` without relying on the full complexity of those dependencies.

5. **Analyze Individual Test Cases (High-Level):** While the provided snippet doesn't contain explicit `TEST_F` blocks yet, I can infer the kinds of things being tested by looking at the helper functions and setup logic:
    * Requesting user media (audio and video)
    * Handling constraints on media devices (device IDs, facing mode, resolution, frame rate)
    * Simulating successful and failed media requests
    * Testing interaction with `MediaStreamDispatcherHost`
    * Testing the lifecycle of media sources and tracks

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  I know that `getUserMedia` is a JavaScript API. The code relates to this API by testing the underlying Blink implementation that handles the `getUserMedia` call. I think about how JavaScript code would initiate a `getUserMedia` request with constraints, and how this test code simulates that process and verifies the outcomes.

7. **Consider Logic and Data Flow:** I trace the flow of a `getUserMedia` request through the test setup:
    * A `UserMediaRequest` is created, representing the JavaScript call.
    * `UserMediaClient::RequestUserMedia` is called.
    * `UserMediaClient` interacts with `UserMediaProcessor`.
    * `UserMediaProcessor` may interact with `MediaDevicesDispatcherHost` (via the mock).
    * Mocks simulate device enumeration and source creation.
    * The test verifies the resulting `MediaStreamDescriptor` or error conditions.

8. **Think about Potential Errors:**  I consider common user or programming errors related to `getUserMedia`:
    * Invalid device IDs in constraints.
    * Conflicting or unsupported constraints.
    * Permissions issues (though this test focuses on the logic after permission is granted/assumed).
    * Incorrect handling of asynchronous operations.

9. **Relate to Debugging:**  I imagine how this test file would be used for debugging: If a bug is suspected in the `getUserMedia` implementation, developers could:
    * Write new test cases to reproduce the bug.
    * Run existing tests to see if they expose the issue.
    * Step through the test code and the `UserMediaClient` implementation to understand the problem.

10. **Focus on the "Part 1" Request:** The prompt explicitly asks for a summary of the functionality covered in this *part*. Therefore, I synthesize the observations into a concise summary that captures the key aspects of testing `UserMediaClient`'s core behavior in handling `getUserMedia` requests, particularly concerning device enumeration and source creation.

**Self-Correction/Refinement during thought process:**

* Initially, I might focus too much on the low-level details of individual functions. I need to step back and see the bigger picture: what *aspect* of `UserMediaClient` is being tested.
* I should avoid making assumptions about parts of the code that aren't presented. The prompt restricts the analysis to the given snippet.
* It's crucial to explicitly connect the C++ code to the corresponding web technologies (JavaScript, HTML) to fulfill that part of the request.

By following these steps, I arrive at a comprehensive understanding of the code's functionality and its relevance within the Chromium project, enabling me to generate a detailed and accurate summary.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "media/audio/audio_device_description.h"
#include "media/capture/mojom/video_capture_types.mojom-blink.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/mediastream/media_device_id.h"
#include "third_party/blink/public/common/mediastream/media_devices.h"
#include "third_party/blink/public/mojom/media/capture_handle_config.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_source.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_stream_device_observer.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_request.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_track_platform.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/display/screen_info.h"

using media::mojom::SubCaptureTargetType;
using ::testing::_;
using ::testing::Mock;

namespace blink {

using EchoCancellationType =
    blink::AudioProcessingProperties::EchoCancellationType;

namespace {

MediaConstraints CreateDefaultConstraints() {
  blink::MockConstraintFactory factory;
  factory.AddAdvanced();
  return factory.CreateMediaConstraints();
}

MediaConstraints CreateDeviceConstraints(
    const String& basic_exact_value,
    const String& basic_ideal_value = g_empty_string,
    const String& advanced_exact_value = g_empty_string) {
  blink::MockConstraintFactory factory;
  if (!basic_exact_value.empty()) {
    factory.basic().device_id.SetExact(basic_exact_value);
  }
  if (!basic_ideal_value.empty()) {
    factory.basic().device_id.SetIdeal(Vector({basic_ideal_value}));
  }

  auto& advanced = factory.AddAdvanced();
  if (!advanced_exact_value.empty()) {
    advanced.device_id.SetExact(advanced_exact_value);
  }

  return factory.CreateMediaConstraints();
}

MediaConstraints CreateFacingModeConstraints(
    const char* basic_exact_value,
    const char* basic_ideal_value = nullptr,
    const char* advanced_exact_value = nullptr) {
  blink::MockConstraintFactory factory;
  if (basic_exact_value) {
    factory.basic().facing_mode.SetExact(String::FromUTF8(basic_exact_value));
  }
  if (basic_ideal_value) {
    factory.basic().device_id.SetIdeal(Vector<String>({basic_ideal_value}));
  }

  auto& advanced = factory.AddAdvanced();
  if (advanced_exact_value) {
    String value = String::FromUTF8(advanced_exact_value);
    advanced.device_id.SetExact(value);
  }

  return factory.CreateMediaConstraints();
}

void CheckVideoSource(blink::MediaStreamVideoSource* source,
                      int expected_source_width,
                      int expected_source_height,
                      double expected_source_frame_rate) {
  EXPECT_TRUE(source->IsRunning());
  EXPECT_TRUE(source->GetCurrentFormat().has_value());
  media::VideoCaptureFormat format = *source->GetCurrentFormat();
  EXPECT_EQ(format.frame_size.width(), expected_source_width);
  EXPECT_EQ(format.frame_size.height(), expected_source_height);
  EXPECT_EQ(format.frame_rate, expected_source_frame_rate);
}

void CheckVideoSourceAndTrack(blink::MediaStreamVideoSource* source,
                              int expected_source_width,
                              int expected_source_height,
                              double expected_source_frame_rate,
                              MediaStreamComponent* component,
                              int expected_track_width,
                              int expected_track_height,
                              double expected_track_frame_rate) {
  CheckVideoSource(source, expected_source_width, expected_source_height,
                   expected_source_frame_rate);
  EXPECT_EQ(component->GetReadyState(), MediaStreamSource::kReadyStateLive);
  MediaStreamVideoTrack* track = MediaStreamVideoTrack::From(component);
  EXPECT_EQ(track->source(), source);

  MediaStreamTrackPlatform::Settings settings;
  track->GetSettings(settings);
  EXPECT_EQ(settings.width, expected_track_width);
  EXPECT_EQ(settings.height, expected_track_height);
  EXPECT_EQ(settings.frame_rate, expected_track_frame_rate);
}

class MockLocalMediaStreamAudioSource : public blink::MediaStreamAudioSource {
 public:
  MockLocalMediaStreamAudioSource()
      : blink::MediaStreamAudioSource(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            true /* is_local_source */) {}

  MOCK_METHOD0(EnsureSourceIsStopped, void());

  void ChangeSourceImpl(const blink::MediaStreamDevice& new_device) override {
    EnsureSourceIsStopped();
  }
};

class MockMediaStreamVideoCapturerSource
    : public blink::MockMediaStreamVideoSource {
 public:
  MockMediaStreamVideoCapturerSource(const blink::MediaStreamDevice& device,
                                     SourceStoppedCallback stop_callback)
      : blink::MockMediaStreamVideoSource() {
    SetDevice(device);
    SetStopCallback(std::move(stop_callback));
  }

  MOCK_METHOD1(ChangeSourceImpl,
               void(const blink::MediaStreamDevice& new_device));
};

String MakeValidDeviceId(std::string_view id) {
  std::string padding =
      base::ToLowerASCII(base::HexEncode(base::RandBytesAsVector(32)));
  std::string padded_id = base::StrCat({id, padding}).substr(0, 64);
  CHECK(blink::IsValidMediaDeviceId(padded_id));
  return String(padded_id);
}

class FakeDeviceIds {
 public:
  static FakeDeviceIds* GetInstance() {
    return base::Singleton<FakeDeviceIds>::get();
  }

  const String invalid_device = MakeValidDeviceId("invalid");
  const String audio_input_1 = MakeValidDeviceId("fakeaudioinput1");
  const String audio_input_2 = MakeValidDeviceId("fakeaudioinput2");
  const String video_input_1 = MakeValidDeviceId("fakevideoinput1");
  const String video_input_2 = MakeValidDeviceId("fakevideoinput2");
  const String video_input_3 = MakeValidDeviceId("fakevideoinput3");
};

class MediaDevicesDispatcherHostMock
    : public mojom::blink::MediaDevicesDispatcherHost {
 public:
  explicit MediaDevicesDispatcherHostMock() {}
  void EnumerateDevices(bool request_audio_input,
                        bool request_video_input,
                        bool request_audio_output,
                        bool request_video_input_capabilities,
                        bool request_audio_input_capabilities,
                        EnumerateDevicesCallback callback) override {
    NOTREACHED();
  }

  void GetVideoInputCapabilities(
      GetVideoInputCapabilitiesCallback client_callback) override {
    NOTREACHED();
  }

  void GetAudioInputCapabilities(
      GetAudioInputCapabilitiesCallback client_callback) override {
    NOTREACHED();
  }

  void SelectAudioOutput(const String& device_id,
                         SelectAudioOutputCallback callback) override {
    NOTREACHED();
  }

  void AddMediaDevicesListener(
      bool subscribe_audio_input,
      bool subscribe_video_input,
      bool subscribe_audio_output,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesListener> listener)
      override {
    NOTREACHED();
  }

  void SetCaptureHandleConfig(mojom::blink::CaptureHandleConfigPtr) override {
    NOTREACHED();
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void CloseFocusWindowOfOpportunity(const String& label) override {
    NOTREACHED();
  }

  void ProduceSubCaptureTargetId(
      SubCaptureTargetType type,
      ProduceSubCaptureTargetIdCallback callback) override {
    NOTREACHED();
  }
#endif

  void GetAllVideoInputDeviceFormats(
      const String& device_id,
      GetAllVideoInputDeviceFormatsCallback callback) override {
    devices_count_++;
  }

  void GetAvailableVideoInputDeviceFormats(
      const String& device_id,
      GetAvailableVideoInputDeviceFormatsCallback callback) override {
    devices_count_++;
  }

  size_t devices_count() const { return devices_count_; }

 private:
  size_t devices_count_ = 0;
};

class MockMediaDevicesDispatcherHost
    : public mojom::blink::MediaDevicesDispatcherHost {
 public:
  MockMediaDevicesDispatcherHost() {}
  void EnumerateDevices(bool request_audio_input,
                        bool request_video_input,
                        bool request_audio_output,
                        bool request_video_input_capabilities,
                        bool request_audio_input_capabilities,
                        EnumerateDevicesCallback callback) override {
    NOTREACHED();
  }

  void SetVideoInputCapabilities(
      Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>
          capabilities) {
    video_input_capabilities_ = std::move(capabilities);
  }

  void GetVideoInputCapabilities(
      GetVideoInputCapabilitiesCallback client_callback) override {
    if (!video_input_capabilities_.empty()) {
      // blink::mojom::blink::VideoInputDeviceCapabilitiesPtr disallows copy so
      // we move our capabilities.
      std::move(client_callback).Run(std::move(video_input_capabilities_));
      // Clear moved `video_input_capabilities_`.
      video_input_capabilities_ =
          Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>();
      return;
    }
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->video_input_1;
    device->group_id = String("dummy");
    device->facing_mode = mojom::blink::FacingMode::kUser;
    if (!video_source_ || !video_source_->IsRunning() ||
        !video_source_->GetCurrentFormat()) {
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_I420));
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(800, 600), 30.0f, media::PIXEL_FORMAT_I420));
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(1024, 768), 20.0f, media::PIXEL_FORMAT_I420));
    } else {
      device->formats.push_back(*video_source_->GetCurrentFormat());
    }
    Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr> result;
    result.push_back(std::move(device));

    device = blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->video_input_2;
    device->group_id = String("dummy");
    device->facing_mode = mojom::blink::FacingMode::kEnvironment;
    device->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_I420));
    result.push_back(std::move(device));

    std::move(client_callback).Run(std::move(result));
  }

  void GetAudioInputCapabilities(
      GetAudioInputCapabilitiesCallback client_callback) override {
    Vector<blink::mojom::blink::AudioInputDeviceCapabilitiesPtr> result;
    blink::mojom::blink::AudioInputDeviceCapabilitiesPtr device =
        blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = media::AudioDeviceDescription::kDefaultDeviceId;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    device = blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->audio_input_1;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    device = blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->audio_input_2;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    std::move(client_callback).Run(std::move(result));
  }

  media::AudioParameters& AudioParameters() { return audio_parameters_; }

  void ResetAudioParameters() {
    audio_parameters_ = media::AudioParameters::UnavailableDeviceParams();
  }

  void AddMediaDevicesListener(
      bool subscribe_audio_input,
      bool subscribe_video_input,
      bool subscribe_audio_output,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesListener> listener)
      override {
    NOTREACHED();
  }

  void SelectAudioOutput(const String& device_id,
                         SelectAudioOutputCallback callback) override {
    NOTREACHED();
  }

  void SetCaptureHandleConfig(mojom::blink::CaptureHandleConfigPtr) override {
    NOTREACHED();
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void CloseFocusWindowOfOpportunity(const String& label) override {
    NOTREACHED();
  }

  void ProduceSubCaptureTargetId(
      SubCaptureTargetType type,
      ProduceSubCaptureTargetIdCallback callback) override {
    std::move(callback).Run("");
  }
#endif

  void GetAllVideoInputDeviceFormats(
      const String&,
      GetAllVideoInputDeviceFormatsCallback callback) override {
    Vector<media::VideoCaptureFormat> formats;
    formats.push_back(media::VideoCaptureFormat(gfx::Size(640, 480), 30.0f,
                                                media::PIXEL_FORMAT_I420));
    formats.push_back(media::VideoCaptureFormat(gfx::Size(800, 600), 30.0f,
                                                media::PIXEL_FORMAT_I420));
    formats.push_back(media::VideoCaptureFormat(gfx::Size(1024, 768), 20.0f,
                                                media::PIXEL_FORMAT_I420));
    std::move(callback).Run(formats);
  }

  void GetAvailableVideoInputDeviceFormats(
      const String& device_id,
      GetAvailableVideoInputDeviceFormatsCallback callback) override {
    if (!video_source_ || !video_source_->IsRunning() ||
        !video_source_->GetCurrentFormat()) {
      GetAllVideoInputDeviceFormats(device_id, std::move(callback));
      return;
    }

    Vector<media::VideoCaptureFormat> formats;
    formats.push_back(*video_source_->GetCurrentFormat());
    std::move(callback).Run(formats);
  }

  void SetVideoSource(blink::MediaStreamVideoSource* video_source) {
    video_source_ = video_source;
  }

 private:
  media::AudioParameters audio_parameters_ =
      media::AudioParameters::UnavailableDeviceParams();
  raw_ptr<blink::MediaStreamVideoSource, DanglingUntriaged> video_source_ =
      nullptr;
  // If set, overrides the default ones otherwise returned by
  // GetVideoInputCapabilities()
  Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>
      video_input_capabilities_;
};

enum RequestState {
  kRequestNotStarted,
  kRequestNotComplete,
  kRequestSucceeded,
  kRequestFailed,
};

class UserMediaProcessorUnderTest : public UserMediaProcessor {
 public:
  UserMediaProcessorUnderTest(
      LocalFrame* frame,
      std::unique_ptr<blink::WebMediaStreamDeviceObserver>
          media_stream_device_observer,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesDispatcherHost>
          media_devices_dispatcher,
      RequestState* state)
      : UserMediaProcessor(
            frame,
            WTF::BindRepeating(
                // Note: this uses a lambda because binding a non-static method
                // with a weak receiver triggers special cancellation handling,
                // which cannot handle non-void return types.
                [](UserMediaProcessorUnderTest* processor)
                    -> blink::mojom::blink::MediaDevicesDispatcherHost* {
                  // In a test, `processor` should always be kept alive.
                  CHECK(processor);
                  return processor->media_devices_dispatcher_.get();
                },
                WrapWeakPersistent(this)),
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        media_stream_device_observer_(std::move(media_stream_device_observer)),
        media_devices_dispatcher_(frame->DomWindow()),
        state_(state) {
    media_devices_dispatcher_.Bind(
        std::move(media_devices_dispatcher),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
    SetMediaStreamDeviceObserverForTesting(media_stream_device_observer_.get());
  }

  MockMediaStreamVideoCapturerSource* last_created_video_source() const {
    return video_source_;
  }
  MockLocalMediaStreamAudioSource* last_created_local_audio_source() const {
    return local_audio_source_;
  }

  void SetCreateSourceThatFails(bool should_fail) {
    create_source_that_fails_ = should_fail;
  }

  MediaStreamDescriptor* last_generated_descriptor() {
    return last_generated_descriptor_.Get();
  }
  void ClearLastGeneratedStream() { last_generated_descriptor_ = nullptr; }

  blink::AudioCaptureSettings AudioSettings() const {
    return AudioCaptureSettingsForTesting();
  }
  const Vector<blink::AudioCaptureSettings>& EligibleAudioSettings() const {
    return EligibleAudioCaptureSettingsForTesting();
  }
  blink::VideoCaptureSettings VideoSettings() const {
    return VideoCaptureSettingsForTesting();
  }
  const Vector<blink::VideoCaptureSettings> EligibleVideoSettings() const {
    return EligibleVideoCaptureSettingsForTesting();
  }

  blink::mojom::blink::MediaStreamRequestResult error_reason() const {
    return result_;
  }
  String constraint_name() const { return constraint_name_; }

  // UserMediaProcessor overrides.
  std::unique_ptr<blink::MediaStreamVideoSource> CreateVideoSource(
      const blink::MediaStreamDevice& device,
      blink::WebPlatformMediaStreamSource::SourceStoppedCallback stop_callback)
      override {
    video_source_ = new MockMediaStreamVideoCapturerSource(
        device, std::move(stop_callback));
    return base::WrapUnique(video_source_.get());
  }

  std::unique_ptr<blink::MediaStreamAudioSource> CreateAudioSource(
      const blink::MediaStreamDevice& device,
      blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback
          source_ready) override {
    std::unique_ptr<blink::MediaStreamAudioSource> source;
    if (create_source_that_fails_) {
      class FailedAtLifeAudioSource : public blink::MediaStreamAudioSource {
       public:
        FailedAtLifeAudioSource()
            : blink::MediaStreamAudioSource(
                  blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
                  true) {}
        ~FailedAtLifeAudioSource() override {}

       protected:
        bool EnsureSourceIsStarted() override { return false; }
      };
      source = std::make_unique<FailedAtLifeAudioSource>();
    } else if (blink::IsDesktopCaptureMediaType(device.type)) {
      local_audio_source_ = new MockLocalMediaStreamAudioSource();
      source = base::WrapUnique(local_audio_source_.get());
    } else {
      source = std::make_unique<blink::MediaStreamAudioSource>(
          blink::scheduler::GetSingleThreadTaskRunnerForTesting(), true);
    }

    source->SetDevice(device);

    if (!create_source_that_fails_) {
      // RunUntilIdle is required for this task to complete.
      blink::scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
          FROM_HERE,
          base::BindOnce(&UserMediaProcessorUnderTest::SignalSourceReady,
                         std::move(source_ready), source.get()));
    }

    return source;
  }

  void GetUserMediaRequestSucceeded(MediaStreamDescriptorVector* descriptors,
                                    UserMediaRequest* request_info) override {
    // TODO(crbug.com/1300883): Generalize to multiple streams.
    DCHECK_EQ(descriptors->size(), 1u);
    last_generated_descriptor_ = (*descriptors)[0];
    *state_ = kRequestSucceeded;
  }

  void GetUserMediaRequestFailed(
      blink::mojom::blink::MediaStreamRequestResult result,
      const String& constraint_name) override {
    last_generated_descriptor_ = nullptr;
    *state_ = kRequestFailed;
    result_ = result;
    constraint_name_ = constraint_name;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(media_devices_dispatcher_);
    visitor->Trace(last_generated_descriptor_);
    UserMediaProcessor::Trace(visitor);
  }

 private:
  static void SignalSourceReady(
      blink::WebPlatformMediaStreamSource::ConstraintsOnceCallback source_ready,
      blink::WebPlatformMediaStreamSource* source) {
    std::move(source_ready)
        .Run(source, blink::mojom::blink::MediaStreamRequestResult::OK, "");
  }

  std::unique_ptr<WebMediaStreamDeviceObserver> media_stream_device_observer_;
  HeapMojoRemote<blink::mojom::blink::MediaDevicesDispatcherHost>
      media_devices_dispatcher_;
  raw_ptr<MockMediaStreamVideoCapturerSource, DanglingUntriaged> video_source_ =
      nullptr;
  raw_ptr<MockLocalMediaStreamAudioSource, DanglingUntriaged>
      local_audio_source_ = nullptr;
  bool create_source_that_fails_ = false;
  Member<MediaStreamDescriptor> last_generated_descriptor_;
  blink::mojom::blink::MediaStreamRequestResult result_ =
      blink::mojom::blink::MediaStreamRequestResult::NUM_MEDIA_REQUEST_RESULTS;
  String constraint_name_;
  raw_ptr<RequestState> state_;
};

class UserMediaClientUnderTest : public UserMediaClient {
 public:
  UserMediaClientUnderTest(LocalFrame* frame,
                           UserMediaProcessor* user_media_processor,
                           UserMediaProcessor* display_user_media_processor,
                           RequestState* state)
      : UserMediaClient(
            frame,
            user_media_processor,
            display_user_media_processor,
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        state_(state) {}

  void RequestUserMediaForTest(UserMediaRequest* user_media_request) {
    *state_ = kRequestNotComplete;
    RequestUserMedia(user_media_request);
    base::RunLoop().RunUntilIdle();
  }

  void RequestUserMediaForTest() {
    UserMediaRequest* user_media_request = UserMediaRequest::CreateForTesting(
        CreateDefaultConstraints(), CreateDefaultConstraints());
    RequestUserMediaForTest(user_media_request);
  }

 private:
  raw_ptr<RequestState> state_;
};

class UserMediaChromeClient : public EmptyChromeClient {
 public:
  UserMediaChromeClient() {
    screen_info_.rect = gfx::Rect(blink::kDefaultScreenCastWidth,
                                  blink::kDefaultScreenCastHeight);
  }
  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    return screen_info_;
  }

 private:
  display::ScreenInfo screen_info_;
};

}  // namespace

class UserMediaClientTest : public ::testing::Test {
 public:
  UserMediaClientTest()
      : user_media_processor_receiver_(&media_devices_dispatcher_),
        display_user_media_processor_receiver_(&media_devices_dispatcher_),
        user_media_client_receiver_(&media_devices_dispatcher_) {}

  void SetUp() override {
    // Create our test object.
    auto* msd_observer = new blink::WebMediaStreamDeviceObserver(nullptr);

    ChromeClient* chrome_client = MakeGarbageCollected<UserMediaChromeClient>();
    dummy_page_holder_ =
        std::make_unique<DummyPageHolder>(gfx::Size(1, 1), chrome_client);

    user_media_processor_ = MakeGarbageCollected<UserMediaProcessorUnderTest>(
        &(dummy_page_holder_->GetFrame()), base::WrapUnique(msd_observer),
        user_media_processor_receiver_.BindNewPipeAndPassRemote(), &state_);
    user_media_processor_->set_media_stream_dispatcher_host_for_testing(
        mock_dispatcher_host_.CreatePendingRemoteAndBind());

    auto* display_msd_observer =
        new blink::WebMediaStreamDeviceObserver(nullptr);
Prompt: 
```
这是目录为blink/renderer/modules/mediastream/user_media_client_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "media/audio/audio_device_description.h"
#include "media/capture/mojom/video_capture_types.mojom-blink.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/mediastream/media_device_id.h"
#include "third_party/blink/public/common/mediastream/media_devices.h"
#include "third_party/blink/public/mojom/media/capture_handle_config.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_devices.mojom-blink.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_source.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/platform/web_vector.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_stream_device_observer.h"
#include "third_party/blink/public/web/web_heap.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_content.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/modules/mediastream/mock_constraint_factory.h"
#include "third_party/blink/renderer/modules/mediastream/mock_media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_request.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_processor_options.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_source.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_track_platform.h"
#include "third_party/blink/renderer/platform/testing/io_task_runner_testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/display/screen_info.h"

using media::mojom::SubCaptureTargetType;
using ::testing::_;
using ::testing::Mock;

namespace blink {

using EchoCancellationType =
    blink::AudioProcessingProperties::EchoCancellationType;

namespace {

MediaConstraints CreateDefaultConstraints() {
  blink::MockConstraintFactory factory;
  factory.AddAdvanced();
  return factory.CreateMediaConstraints();
}

MediaConstraints CreateDeviceConstraints(
    const String& basic_exact_value,
    const String& basic_ideal_value = g_empty_string,
    const String& advanced_exact_value = g_empty_string) {
  blink::MockConstraintFactory factory;
  if (!basic_exact_value.empty()) {
    factory.basic().device_id.SetExact(basic_exact_value);
  }
  if (!basic_ideal_value.empty()) {
    factory.basic().device_id.SetIdeal(Vector({basic_ideal_value}));
  }

  auto& advanced = factory.AddAdvanced();
  if (!advanced_exact_value.empty()) {
    advanced.device_id.SetExact(advanced_exact_value);
  }

  return factory.CreateMediaConstraints();
}

MediaConstraints CreateFacingModeConstraints(
    const char* basic_exact_value,
    const char* basic_ideal_value = nullptr,
    const char* advanced_exact_value = nullptr) {
  blink::MockConstraintFactory factory;
  if (basic_exact_value) {
    factory.basic().facing_mode.SetExact(String::FromUTF8(basic_exact_value));
  }
  if (basic_ideal_value) {
    factory.basic().device_id.SetIdeal(Vector<String>({basic_ideal_value}));
  }

  auto& advanced = factory.AddAdvanced();
  if (advanced_exact_value) {
    String value = String::FromUTF8(advanced_exact_value);
    advanced.device_id.SetExact(value);
  }

  return factory.CreateMediaConstraints();
}

void CheckVideoSource(blink::MediaStreamVideoSource* source,
                      int expected_source_width,
                      int expected_source_height,
                      double expected_source_frame_rate) {
  EXPECT_TRUE(source->IsRunning());
  EXPECT_TRUE(source->GetCurrentFormat().has_value());
  media::VideoCaptureFormat format = *source->GetCurrentFormat();
  EXPECT_EQ(format.frame_size.width(), expected_source_width);
  EXPECT_EQ(format.frame_size.height(), expected_source_height);
  EXPECT_EQ(format.frame_rate, expected_source_frame_rate);
}

void CheckVideoSourceAndTrack(blink::MediaStreamVideoSource* source,
                              int expected_source_width,
                              int expected_source_height,
                              double expected_source_frame_rate,
                              MediaStreamComponent* component,
                              int expected_track_width,
                              int expected_track_height,
                              double expected_track_frame_rate) {
  CheckVideoSource(source, expected_source_width, expected_source_height,
                   expected_source_frame_rate);
  EXPECT_EQ(component->GetReadyState(), MediaStreamSource::kReadyStateLive);
  MediaStreamVideoTrack* track = MediaStreamVideoTrack::From(component);
  EXPECT_EQ(track->source(), source);

  MediaStreamTrackPlatform::Settings settings;
  track->GetSettings(settings);
  EXPECT_EQ(settings.width, expected_track_width);
  EXPECT_EQ(settings.height, expected_track_height);
  EXPECT_EQ(settings.frame_rate, expected_track_frame_rate);
}

class MockLocalMediaStreamAudioSource : public blink::MediaStreamAudioSource {
 public:
  MockLocalMediaStreamAudioSource()
      : blink::MediaStreamAudioSource(
            blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
            true /* is_local_source */) {}

  MOCK_METHOD0(EnsureSourceIsStopped, void());

  void ChangeSourceImpl(const blink::MediaStreamDevice& new_device) override {
    EnsureSourceIsStopped();
  }
};

class MockMediaStreamVideoCapturerSource
    : public blink::MockMediaStreamVideoSource {
 public:
  MockMediaStreamVideoCapturerSource(const blink::MediaStreamDevice& device,
                                     SourceStoppedCallback stop_callback)
      : blink::MockMediaStreamVideoSource() {
    SetDevice(device);
    SetStopCallback(std::move(stop_callback));
  }

  MOCK_METHOD1(ChangeSourceImpl,
               void(const blink::MediaStreamDevice& new_device));
};

String MakeValidDeviceId(std::string_view id) {
  std::string padding =
      base::ToLowerASCII(base::HexEncode(base::RandBytesAsVector(32)));
  std::string padded_id = base::StrCat({id, padding}).substr(0, 64);
  CHECK(blink::IsValidMediaDeviceId(padded_id));
  return String(padded_id);
}

class FakeDeviceIds {
 public:
  static FakeDeviceIds* GetInstance() {
    return base::Singleton<FakeDeviceIds>::get();
  }

  const String invalid_device = MakeValidDeviceId("invalid");
  const String audio_input_1 = MakeValidDeviceId("fakeaudioinput1");
  const String audio_input_2 = MakeValidDeviceId("fakeaudioinput2");
  const String video_input_1 = MakeValidDeviceId("fakevideoinput1");
  const String video_input_2 = MakeValidDeviceId("fakevideoinput2");
  const String video_input_3 = MakeValidDeviceId("fakevideoinput3");
};

class MediaDevicesDispatcherHostMock
    : public mojom::blink::MediaDevicesDispatcherHost {
 public:
  explicit MediaDevicesDispatcherHostMock() {}
  void EnumerateDevices(bool request_audio_input,
                        bool request_video_input,
                        bool request_audio_output,
                        bool request_video_input_capabilities,
                        bool request_audio_input_capabilities,
                        EnumerateDevicesCallback callback) override {
    NOTREACHED();
  }

  void GetVideoInputCapabilities(
      GetVideoInputCapabilitiesCallback client_callback) override {
    NOTREACHED();
  }

  void GetAudioInputCapabilities(
      GetAudioInputCapabilitiesCallback client_callback) override {
    NOTREACHED();
  }

  void SelectAudioOutput(const String& device_id,
                         SelectAudioOutputCallback callback) override {
    NOTREACHED();
  }

  void AddMediaDevicesListener(
      bool subscribe_audio_input,
      bool subscribe_video_input,
      bool subscribe_audio_output,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesListener> listener)
      override {
    NOTREACHED();
  }

  void SetCaptureHandleConfig(mojom::blink::CaptureHandleConfigPtr) override {
    NOTREACHED();
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void CloseFocusWindowOfOpportunity(const String& label) override {
    NOTREACHED();
  }

  void ProduceSubCaptureTargetId(
      SubCaptureTargetType type,
      ProduceSubCaptureTargetIdCallback callback) override {
    NOTREACHED();
  }
#endif

  void GetAllVideoInputDeviceFormats(
      const String& device_id,
      GetAllVideoInputDeviceFormatsCallback callback) override {
    devices_count_++;
  }

  void GetAvailableVideoInputDeviceFormats(
      const String& device_id,
      GetAvailableVideoInputDeviceFormatsCallback callback) override {
    devices_count_++;
  }

  size_t devices_count() const { return devices_count_; }

 private:
  size_t devices_count_ = 0;
};

class MockMediaDevicesDispatcherHost
    : public mojom::blink::MediaDevicesDispatcherHost {
 public:
  MockMediaDevicesDispatcherHost() {}
  void EnumerateDevices(bool request_audio_input,
                        bool request_video_input,
                        bool request_audio_output,
                        bool request_video_input_capabilities,
                        bool request_audio_input_capabilities,
                        EnumerateDevicesCallback callback) override {
    NOTREACHED();
  }

  void SetVideoInputCapabilities(
      Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>
          capabilities) {
    video_input_capabilities_ = std::move(capabilities);
  }

  void GetVideoInputCapabilities(
      GetVideoInputCapabilitiesCallback client_callback) override {
    if (!video_input_capabilities_.empty()) {
      // blink::mojom::blink::VideoInputDeviceCapabilitiesPtr disallows copy so
      // we move our capabilities.
      std::move(client_callback).Run(std::move(video_input_capabilities_));
      // Clear moved `video_input_capabilities_`.
      video_input_capabilities_ =
          Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>();
      return;
    }
    blink::mojom::blink::VideoInputDeviceCapabilitiesPtr device =
        blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->video_input_1;
    device->group_id = String("dummy");
    device->facing_mode = mojom::blink::FacingMode::kUser;
    if (!video_source_ || !video_source_->IsRunning() ||
        !video_source_->GetCurrentFormat()) {
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_I420));
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(800, 600), 30.0f, media::PIXEL_FORMAT_I420));
      device->formats.push_back(media::VideoCaptureFormat(
          gfx::Size(1024, 768), 20.0f, media::PIXEL_FORMAT_I420));
    } else {
      device->formats.push_back(*video_source_->GetCurrentFormat());
    }
    Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr> result;
    result.push_back(std::move(device));

    device = blink::mojom::blink::VideoInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->video_input_2;
    device->group_id = String("dummy");
    device->facing_mode = mojom::blink::FacingMode::kEnvironment;
    device->formats.push_back(media::VideoCaptureFormat(
        gfx::Size(640, 480), 30.0f, media::PIXEL_FORMAT_I420));
    result.push_back(std::move(device));

    std::move(client_callback).Run(std::move(result));
  }

  void GetAudioInputCapabilities(
      GetAudioInputCapabilitiesCallback client_callback) override {
    Vector<blink::mojom::blink::AudioInputDeviceCapabilitiesPtr> result;
    blink::mojom::blink::AudioInputDeviceCapabilitiesPtr device =
        blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = media::AudioDeviceDescription::kDefaultDeviceId;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    device = blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->audio_input_1;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    device = blink::mojom::blink::AudioInputDeviceCapabilities::New();
    device->device_id = FakeDeviceIds::GetInstance()->audio_input_2;
    device->group_id = String("dummy");
    device->parameters = audio_parameters_;
    result.push_back(std::move(device));

    std::move(client_callback).Run(std::move(result));
  }

  media::AudioParameters& AudioParameters() { return audio_parameters_; }

  void ResetAudioParameters() {
    audio_parameters_ = media::AudioParameters::UnavailableDeviceParams();
  }

  void AddMediaDevicesListener(
      bool subscribe_audio_input,
      bool subscribe_video_input,
      bool subscribe_audio_output,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesListener> listener)
      override {
    NOTREACHED();
  }

  void SelectAudioOutput(const String& device_id,
                         SelectAudioOutputCallback callback) override {
    NOTREACHED();
  }

  void SetCaptureHandleConfig(mojom::blink::CaptureHandleConfigPtr) override {
    NOTREACHED();
  }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void CloseFocusWindowOfOpportunity(const String& label) override {
    NOTREACHED();
  }

  void ProduceSubCaptureTargetId(
      SubCaptureTargetType type,
      ProduceSubCaptureTargetIdCallback callback) override {
    std::move(callback).Run("");
  }
#endif

  void GetAllVideoInputDeviceFormats(
      const String&,
      GetAllVideoInputDeviceFormatsCallback callback) override {
    Vector<media::VideoCaptureFormat> formats;
    formats.push_back(media::VideoCaptureFormat(gfx::Size(640, 480), 30.0f,
                                                media::PIXEL_FORMAT_I420));
    formats.push_back(media::VideoCaptureFormat(gfx::Size(800, 600), 30.0f,
                                                media::PIXEL_FORMAT_I420));
    formats.push_back(media::VideoCaptureFormat(gfx::Size(1024, 768), 20.0f,
                                                media::PIXEL_FORMAT_I420));
    std::move(callback).Run(formats);
  }

  void GetAvailableVideoInputDeviceFormats(
      const String& device_id,
      GetAvailableVideoInputDeviceFormatsCallback callback) override {
    if (!video_source_ || !video_source_->IsRunning() ||
        !video_source_->GetCurrentFormat()) {
      GetAllVideoInputDeviceFormats(device_id, std::move(callback));
      return;
    }

    Vector<media::VideoCaptureFormat> formats;
    formats.push_back(*video_source_->GetCurrentFormat());
    std::move(callback).Run(formats);
  }

  void SetVideoSource(blink::MediaStreamVideoSource* video_source) {
    video_source_ = video_source;
  }

 private:
  media::AudioParameters audio_parameters_ =
      media::AudioParameters::UnavailableDeviceParams();
  raw_ptr<blink::MediaStreamVideoSource, DanglingUntriaged> video_source_ =
      nullptr;
  // If set, overrides the default ones otherwise returned by
  // GetVideoInputCapabilities()
  Vector<blink::mojom::blink::VideoInputDeviceCapabilitiesPtr>
      video_input_capabilities_;
};

enum RequestState {
  kRequestNotStarted,
  kRequestNotComplete,
  kRequestSucceeded,
  kRequestFailed,
};

class UserMediaProcessorUnderTest : public UserMediaProcessor {
 public:
  UserMediaProcessorUnderTest(
      LocalFrame* frame,
      std::unique_ptr<blink::WebMediaStreamDeviceObserver>
          media_stream_device_observer,
      mojo::PendingRemote<blink::mojom::blink::MediaDevicesDispatcherHost>
          media_devices_dispatcher,
      RequestState* state)
      : UserMediaProcessor(
            frame,
            WTF::BindRepeating(
                // Note: this uses a lambda because binding a non-static method
                // with a weak receiver triggers special cancellation handling,
                // which cannot handle non-void return types.
                [](UserMediaProcessorUnderTest* processor)
                    -> blink::mojom::blink::MediaDevicesDispatcherHost* {
                  // In a test, `processor` should always be kept alive.
                  CHECK(processor);
                  return processor->media_devices_dispatcher_.get();
                },
                WrapWeakPersistent(this)),
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        media_stream_device_observer_(std::move(media_stream_device_observer)),
        media_devices_dispatcher_(frame->DomWindow()),
        state_(state) {
    media_devices_dispatcher_.Bind(
        std::move(media_devices_dispatcher),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
    SetMediaStreamDeviceObserverForTesting(media_stream_device_observer_.get());
  }

  MockMediaStreamVideoCapturerSource* last_created_video_source() const {
    return video_source_;
  }
  MockLocalMediaStreamAudioSource* last_created_local_audio_source() const {
    return local_audio_source_;
  }

  void SetCreateSourceThatFails(bool should_fail) {
    create_source_that_fails_ = should_fail;
  }

  MediaStreamDescriptor* last_generated_descriptor() {
    return last_generated_descriptor_.Get();
  }
  void ClearLastGeneratedStream() { last_generated_descriptor_ = nullptr; }

  blink::AudioCaptureSettings AudioSettings() const {
    return AudioCaptureSettingsForTesting();
  }
  const Vector<blink::AudioCaptureSettings>& EligibleAudioSettings() const {
    return EligibleAudioCaptureSettingsForTesting();
  }
  blink::VideoCaptureSettings VideoSettings() const {
    return VideoCaptureSettingsForTesting();
  }
  const Vector<blink::VideoCaptureSettings> EligibleVideoSettings() const {
    return EligibleVideoCaptureSettingsForTesting();
  }

  blink::mojom::blink::MediaStreamRequestResult error_reason() const {
    return result_;
  }
  String constraint_name() const { return constraint_name_; }

  // UserMediaProcessor overrides.
  std::unique_ptr<blink::MediaStreamVideoSource> CreateVideoSource(
      const blink::MediaStreamDevice& device,
      blink::WebPlatformMediaStreamSource::SourceStoppedCallback stop_callback)
      override {
    video_source_ = new MockMediaStreamVideoCapturerSource(
        device, std::move(stop_callback));
    return base::WrapUnique(video_source_.get());
  }

  std::unique_ptr<blink::MediaStreamAudioSource> CreateAudioSource(
      const blink::MediaStreamDevice& device,
      blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback
          source_ready) override {
    std::unique_ptr<blink::MediaStreamAudioSource> source;
    if (create_source_that_fails_) {
      class FailedAtLifeAudioSource : public blink::MediaStreamAudioSource {
       public:
        FailedAtLifeAudioSource()
            : blink::MediaStreamAudioSource(
                  blink::scheduler::GetSingleThreadTaskRunnerForTesting(),
                  true) {}
        ~FailedAtLifeAudioSource() override {}

       protected:
        bool EnsureSourceIsStarted() override { return false; }
      };
      source = std::make_unique<FailedAtLifeAudioSource>();
    } else if (blink::IsDesktopCaptureMediaType(device.type)) {
      local_audio_source_ = new MockLocalMediaStreamAudioSource();
      source = base::WrapUnique(local_audio_source_.get());
    } else {
      source = std::make_unique<blink::MediaStreamAudioSource>(
          blink::scheduler::GetSingleThreadTaskRunnerForTesting(), true);
    }

    source->SetDevice(device);

    if (!create_source_that_fails_) {
      // RunUntilIdle is required for this task to complete.
      blink::scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
          FROM_HERE,
          base::BindOnce(&UserMediaProcessorUnderTest::SignalSourceReady,
                         std::move(source_ready), source.get()));
    }

    return source;
  }

  void GetUserMediaRequestSucceeded(MediaStreamDescriptorVector* descriptors,
                                    UserMediaRequest* request_info) override {
    // TODO(crbug.com/1300883): Generalize to multiple streams.
    DCHECK_EQ(descriptors->size(), 1u);
    last_generated_descriptor_ = (*descriptors)[0];
    *state_ = kRequestSucceeded;
  }

  void GetUserMediaRequestFailed(
      blink::mojom::blink::MediaStreamRequestResult result,
      const String& constraint_name) override {
    last_generated_descriptor_ = nullptr;
    *state_ = kRequestFailed;
    result_ = result;
    constraint_name_ = constraint_name;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(media_devices_dispatcher_);
    visitor->Trace(last_generated_descriptor_);
    UserMediaProcessor::Trace(visitor);
  }

 private:
  static void SignalSourceReady(
      blink::WebPlatformMediaStreamSource::ConstraintsOnceCallback source_ready,
      blink::WebPlatformMediaStreamSource* source) {
    std::move(source_ready)
        .Run(source, blink::mojom::blink::MediaStreamRequestResult::OK, "");
  }

  std::unique_ptr<WebMediaStreamDeviceObserver> media_stream_device_observer_;
  HeapMojoRemote<blink::mojom::blink::MediaDevicesDispatcherHost>
      media_devices_dispatcher_;
  raw_ptr<MockMediaStreamVideoCapturerSource, DanglingUntriaged> video_source_ =
      nullptr;
  raw_ptr<MockLocalMediaStreamAudioSource, DanglingUntriaged>
      local_audio_source_ = nullptr;
  bool create_source_that_fails_ = false;
  Member<MediaStreamDescriptor> last_generated_descriptor_;
  blink::mojom::blink::MediaStreamRequestResult result_ =
      blink::mojom::blink::MediaStreamRequestResult::NUM_MEDIA_REQUEST_RESULTS;
  String constraint_name_;
  raw_ptr<RequestState> state_;
};

class UserMediaClientUnderTest : public UserMediaClient {
 public:
  UserMediaClientUnderTest(LocalFrame* frame,
                           UserMediaProcessor* user_media_processor,
                           UserMediaProcessor* display_user_media_processor,
                           RequestState* state)
      : UserMediaClient(
            frame,
            user_media_processor,
            display_user_media_processor,
            blink::scheduler::GetSingleThreadTaskRunnerForTesting()),
        state_(state) {}

  void RequestUserMediaForTest(UserMediaRequest* user_media_request) {
    *state_ = kRequestNotComplete;
    RequestUserMedia(user_media_request);
    base::RunLoop().RunUntilIdle();
  }

  void RequestUserMediaForTest() {
    UserMediaRequest* user_media_request = UserMediaRequest::CreateForTesting(
        CreateDefaultConstraints(), CreateDefaultConstraints());
    RequestUserMediaForTest(user_media_request);
  }

 private:
  raw_ptr<RequestState> state_;
};

class UserMediaChromeClient : public EmptyChromeClient {
 public:
  UserMediaChromeClient() {
    screen_info_.rect = gfx::Rect(blink::kDefaultScreenCastWidth,
                                  blink::kDefaultScreenCastHeight);
  }
  const display::ScreenInfo& GetScreenInfo(LocalFrame&) const override {
    return screen_info_;
  }

 private:
  display::ScreenInfo screen_info_;
};

}  // namespace

class UserMediaClientTest : public ::testing::Test {
 public:
  UserMediaClientTest()
      : user_media_processor_receiver_(&media_devices_dispatcher_),
        display_user_media_processor_receiver_(&media_devices_dispatcher_),
        user_media_client_receiver_(&media_devices_dispatcher_) {}

  void SetUp() override {
    // Create our test object.
    auto* msd_observer = new blink::WebMediaStreamDeviceObserver(nullptr);

    ChromeClient* chrome_client = MakeGarbageCollected<UserMediaChromeClient>();
    dummy_page_holder_ =
        std::make_unique<DummyPageHolder>(gfx::Size(1, 1), chrome_client);

    user_media_processor_ = MakeGarbageCollected<UserMediaProcessorUnderTest>(
        &(dummy_page_holder_->GetFrame()), base::WrapUnique(msd_observer),
        user_media_processor_receiver_.BindNewPipeAndPassRemote(), &state_);
    user_media_processor_->set_media_stream_dispatcher_host_for_testing(
        mock_dispatcher_host_.CreatePendingRemoteAndBind());

    auto* display_msd_observer =
        new blink::WebMediaStreamDeviceObserver(nullptr);
    display_user_media_processor_ =
        MakeGarbageCollected<UserMediaProcessorUnderTest>(
            &(dummy_page_holder_->GetFrame()),
            base::WrapUnique(display_msd_observer),
            display_user_media_processor_receiver_.BindNewPipeAndPassRemote(),
            &state_);
    display_user_media_processor_->set_media_stream_dispatcher_host_for_testing(
        display_mock_dispatcher_host_.CreatePendingRemoteAndBind());

    user_media_client_impl_ = MakeGarbageCollected<UserMediaClientUnderTest>(
        &(dummy_page_holder_->GetFrame()), user_media_processor_,
        display_user_media_processor_, &state_);

    user_media_client_impl_->SetMediaDevicesDispatcherForTesting(
        user_media_client_receiver_.BindNewPipeAndPassRemote());
  }

  void TearDown() override {
    user_media_client_impl_->ContextDestroyed();
    user_media_client_impl_ = nullptr;

    blink::WebHeap::CollectAllGarbageForTesting();
  }

  void LoadNewDocumentInFrame() {
    user_media_client_impl_->ContextDestroyed();
    base::RunLoop().RunUntilIdle();
  }

  MediaStreamDescriptor* RequestLocalMediaStream() {
    user_media_client_impl_->RequestUserMediaForTest();
    StartMockedVideoSource(user_media_processor_);

    EXPECT_EQ(kRequestSucceeded, request_state());

    MediaStreamDescriptor* desc =
        user_media_processor_->last_generated_descriptor();
    auto audio_components = desc->AudioComponents();
    auto video_components = desc->VideoComponents();

    EXPECT_EQ(1u, audio_components.size());
    EXPECT_EQ(1u, video_components.size());
    EXPECT_NE(audio_components[0]->Id(), video_components[0]->Id());
    return desc;
  }

  MediaStreamTrack* RequestLocalVideoTrack() {
    UserMediaRequest* user_media_request = UserMediaRequest::CreateForTesting(
        MediaConstraints(), CreateDefaultConstraints());
    user_media_client_impl_->RequestUserMediaForTest(user_media_request);
    StartMockedVideoSource(user_media_processor_);
    EXPECT_EQ(kRequestSucceeded, request_state());

    MediaStreamDescriptor* descriptor =
        user_media_processor_->last_generated_descriptor();
    auto audio_components = descriptor->AudioComponents();
    auto video_components = descriptor->VideoComponents();

    EXPECT_EQ(audio_components.size(), 0U);
    EXPECT_EQ(video_components.size(), 1U);

    return MakeGarbageCollected<MediaStreamTrackImpl>(
        /*execution_context=*/nullptr, video_components[0]);
  }

  MediaStreamComponent* RequestLocalAudioTrackWithAssociatedSink(
      bool render_to_associated_sink) {
    blink::MockConstraintFactory constraint_factory;
    constraint_factory.basic().render_to_associated_sink.SetExact(
        render_to_associated_sink);
    UserMediaRequest* user_media_request = UserMediaRequest::CreateForTesting(
        constraint_factory.CreateMediaConstraints(), MediaConstraints());
    user_media_client_impl_->RequestUserMediaForTest(user_media_request);

    EXPECT_EQ(kRequestSucceeded, request_state());

    MediaStreamDescriptor* desc =
        user_media_processor_->last_generated_descriptor();
    auto audio_components = desc->AudioComponents();
    auto video_components = desc->VideoComponents();

    EXPECT_EQ(audio_components.size(), 1u);
    EXPECT_TRUE(video_components.empty());

    return audio_components[0].Get();
  }

  void StartMockedVideoSource(
      UserMediaProcessorUnderTest* user_media_processor) {
    MockMediaStreamVideoCapturerSource* video_source =
        user_media_processor->last_created_video_source();
    if (video_source->SourceHasAttemptedToStart())
      video_source->StartMockedSource();
  }

  void FailToStartMockedVideoSource() {
    MockMediaStreamVideoCapturerSource* video_source =
        user_media_processor_->last_created_video_source();
    if (video_source->SourceHasAttemptedToStart())
      video_source->FailToStartMockedSource();
    blink::WebHeap::CollectGarbageForTesting();
  }

  void TestValidRequestWithConstraints(
      const MediaConstraints& audio_constraints,
      const MediaConstraints& video_constraints,
      const String& expected_audio_device_id,
      const String& expected_video_device_id) {
    DCHECK(!audio_constraints.IsNull());
    DCHECK(!video_constraints.IsNull());
    UserMediaRequest* request = UserMediaRequest::CreateForTesting(
        audio_constraints, video_constraints);
    user_media_client_impl_->RequestUserMediaForTest(request);
    StartMockedVideoSource(user_media_processor_);

    EXPECT_EQ(kRequestSucceeded, request_state());
    EXPECT_NE(std::nullopt, mock_dispatcher_host_.devices().audio_device);
    EXPECT_NE(std::nullopt, mock_dispatcher_host_.devices().video_device);
    EXPECT_EQ(expected_audio_device_id.Ascii(),
              mock_dispatcher_host_.devices().audio_device.value().id);
    EXPECT_EQ(expected_video_device_id.Ascii(),
              mock_dispatcher_host_.devices().video_device.value().id);
  }

  void ApplyConstraintsVideoMode(
      MediaStreamTrack* track,
      int width,
      int height,
      const std::optional<double>& frame_rate = std::optional<double>()) {
    blink::MockConstraintFactory factory;
    factory.basic().width.SetExact(width);
    factory.basic().height.SetExact(height);
    if (frame_rate)
      factory.basic().frame_rate.SetExact(*frame_rate);

    auto* apply_constraints_request =
        MakeGarbageCollected<ApplyConstraintsRequest>(
            track, factory.CreateMediaConstraints(), nullptr);
    user_media_client_impl_->ApplyConstraints(apply_constraints_request);
    base::RunLoop().RunUntilIdle();
  }

  RequestState request_state() const { return state_; }

  UserMediaProcessorUnderTest* UserMediaProcessorForDisplayCapture() {
    return display_user_media_processor_;
  }

  const MockMojoMediaStreamDispatcherHost&
  MediaStreamDispatcherHostForDisplayCapture() {
    return display_mock_dispatcher_host_;
  }

 protected:
  ScopedTestingPlatformSupport<IOTaskRunnerTestingPlatformSupport>
      testing_platform_;
  test::TaskEnvironment task_environment_;
  MockMojoMediaStreamDispatcherHost mock_dispatcher_host_;
  MockMojoMediaStreamDispatcherHost display_mock_dispatcher_host_;
  MockMediaDevicesDispatcherHost media_devices_dispatcher_;
  mojo::Receiver<blink::mojom::blink::MediaDevicesDispatcherHost>
      user_media_processor_receiver_;
  mojo::Receiver<blink::mojom::blink::MediaDevicesDispatcherHost>
      display_user_media_processor_receiver_;
  mojo::Receiver<blink::mojom::blink::MediaDevicesDispatcherHost>
      user_media_client_receiver_;

  std::unique_ptr<DummyPageHolder> dummy_page_holder_;
  WeakPersistent<UserMed
"""


```
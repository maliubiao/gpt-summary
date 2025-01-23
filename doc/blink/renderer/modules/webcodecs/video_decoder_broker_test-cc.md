Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding - The Core Purpose:**

The file name `video_decoder_broker_test.cc` immediately suggests this is a test file for a component called `VideoDecoderBroker`. The `_test.cc` convention is a strong indicator in Chromium. Therefore, the primary goal is to understand what `VideoDecoderBroker` does and how this file tests it.

**2. Deconstructing the Imports:**

The `#include` statements are crucial. They provide a roadmap of the dependencies and the functionalities being tested:

* **`video_decoder_broker.h`:** This confirms the test is for the `VideoDecoderBroker` class.
* **Standard C++ Libraries (`memory`, `vector`):**  Basic data structures and memory management.
* **`base/...`:**  Core Chromium base library functionalities like `RunLoop` (for asynchronous testing), task runners, threads, and time. This hints at the asynchronous nature of video decoding.
* **`build/build_config.h`:**  Build system configuration, likely used for platform-specific tests.
* **`gpu/...`:**  GPU-related components, especially `mailbox_holder`, suggest interaction with the graphics pipeline for hardware decoding.
* **`media/base/...`:**  Fundamental media concepts like `DecoderBuffer`, `DecoderStatus`, `VideoFrame`, and test data utilities. This is central to video decoding.
* **`media/filters/...`:** `FakeVideoDecoder` is a key import, indicating the use of mock objects for testing different decoder scenarios.
* **`media/mojo/...`:**  Mojo interfaces (`mojom`) and services are involved. This signifies inter-process communication, a common pattern in Chromium for security and stability.
* **`media/video/...`:** `MockGpuVideoAcceleratorFactories` is another crucial mock, particularly relevant for testing how the `VideoDecoderBroker` interacts with hardware acceleration.
* **`mojo/public/cpp/...`:** Core Mojo bindings for inter-process communication.
* **`testing/gmock/...` and `testing/gtest/...`:**  The standard Google testing and mocking frameworks.
* **`third_party/blink/public/...`:**  Blink-specific interfaces, including the `BrowserInterfaceBrokerProxy`. This indicates the `VideoDecoderBroker` interacts with higher-level browser services.
* **`third_party/blink/renderer/...`:**  Blink-specific classes like `V8TestingScope` (for JavaScript context simulation) and the task environment.

**3. Identifying Key Test Structures and Mock Objects:**

* **`FakeGpuVideoDecoder`:**  This class simulates a hardware video decoder. It's essential for testing scenarios where hardware acceleration is involved. Key features are the mailbox creation in `MakeVideoFrame` and the overrides indicating it's a platform decoder needing bitstream conversion.
* **`FakeMojoMediaClient`:** This simulates a client that can create `FakeGpuVideoDecoder` instances when the `VideoDecoderBroker` requests one through Mojo.
* **`FakeInterfaceFactory`:** This mocks the Mojo interface factory responsible for creating media-related services, including the video decoder. It ties the `VideoDecoderBroker` to the fake decoder implementations.
* **`VideoDecoderBrokerTest`:** The main test fixture. It sets up the testing environment, creates the `VideoDecoderBroker`, and defines helper methods for common test actions (initializing, decoding, resetting). The `MOCK_METHOD` macros are clear indicators of mocked dependencies.

**4. Analyzing Individual Tests:**

Go through each `TEST_F` function and understand its purpose:

* **`Decode_Uninitialized`:** Tests the behavior when decoding is attempted before initialization. Expected failure.
* **`Decode_NoMojoDecoder`:** Tests the scenario when a non-Mojo (likely software) decoder is used.
* **`Init_RequireAcceleration`:** Tests the case where hardware acceleration is explicitly requested, and verifies that a software decoder isn't used if hardware isn't available.
* **`Init_DenyAcceleration` (with `ENABLE_MOJO_VIDEO_DECODER`):** Tests that software decoding is preferred even when Mojo/hardware decoding is possible.
* **`Decode_MultipleAccelerationPreferences` (with `ENABLE_MOJO_VIDEO_DECODER`):** Tests switching between different hardware/software preference settings and verifies the correct decoder type is selected.
* **`Decode_WithMojoDecoder` (with `ENABLE_MOJO_VIDEO_DECODER`):** Tests the successful usage of a Mojo-based (simulated hardware) decoder.

**5. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Think about how the `VideoDecoderBroker` fits into the larger web platform.

* **JavaScript:** The WebCodecs API exposes video decoding functionality to JavaScript. The `VideoDecoderBroker` is a lower-level component that the JavaScript API relies on. A JavaScript `VideoDecoder` instance would eventually interact with the `VideoDecoderBroker`.
* **HTML:** The `<video>` element is the primary way to display video in HTML. When a `<video>` element needs to decode video, it uses the browser's media pipeline, which includes components like the `VideoDecoderBroker`.
* **CSS:** CSS affects the presentation of the `<video>` element but doesn't directly interact with the decoding process itself. However, CSS properties like `object-fit` might influence how decoded frames are displayed.

**6. Logical Reasoning and Input/Output Examples:**

For each test, consider:

* **Input:**  The configuration passed to `InitializeDecoder`, the decoder buffers passed to `DecodeBuffer`, and the hardware preference settings.
* **Expected Output:** The `DecoderStatus` returned, the number of output frames, and the type of decoder selected (`GetDecoderType`).

**7. User/Programming Errors:**

Think about common mistakes developers or users might make when dealing with video decoding:

* Not initializing the decoder before using it.
* Providing unsupported video configurations.
* Expecting hardware decoding to always be available.

**8. Tracing User Operations (Debugging Clues):**

Imagine a user playing a video in a web browser:

1. User opens a webpage with a `<video>` element.
2. The browser requests the video resource.
3. The browser's media pipeline starts processing the video data.
4. The `VideoDecoderBroker` is instantiated to manage the video decoding process.
5. JavaScript (using the WebCodecs API) might configure the decoder.
6. The `VideoDecoderBroker` selects an appropriate decoder (software or hardware).
7. Video frames are decoded and passed to the rendering pipeline.
8. The decoded frames are displayed in the `<video>` element.

By following this process for each section of the code and connecting it to the larger context, you can effectively understand the functionality and testing approach of this Chromium source file. The key is to start with the overall purpose and progressively drill down into the details of the implementation and tests.
This C++ source file, `video_decoder_broker_test.cc`, within the Chromium Blink engine, contains unit tests for the `VideoDecoderBroker` class. The `VideoDecoderBroker` is a crucial component in the WebCodecs API, responsible for managing and selecting the actual video decoder implementation used by the browser.

Here's a breakdown of its functionality:

**Core Functionality Being Tested:**

1. **Initialization:** Tests how the `VideoDecoderBroker` initializes with different video configurations and hardware acceleration preferences. This includes scenarios where initialization should succeed or fail.
2. **Decoder Selection:** Verifies the logic used by `VideoDecoderBroker` to choose between different video decoder implementations (software vs. hardware accelerated, potentially Mojo-based). This is heavily influenced by the `HardwarePreference` setting.
3. **Decoding:** Checks the basic decoding process, ensuring that when a valid decoder is selected, decoding buffers (representing encoded video data) results in output video frames. It also tests error handling for scenarios like decoding before initialization.
4. **Resetting:** Tests the ability to reset the decoder to a clean state, allowing for decoding of new video streams or configurations.
5. **Interaction with Mojo:** If the `ENABLE_MOJO_VIDEO_DECODER` flag is enabled, the tests verify the interaction with Mojo Video Decoder services. This involves testing the creation and usage of video decoders running in a separate process (GPU process).
6. **Handling Hardware Preferences:** Tests how the `VideoDecoderBroker` respects the `HardwarePreference` setting (prefer hardware, prefer software, no preference) when selecting a decoder.
7. **Error Handling:** Checks how the `VideoDecoderBroker` handles errors, such as trying to decode before initialization or with an unsupported configuration.
8. **Asynchronous Operations:** The tests utilize `base::RunLoop` to handle the asynchronous nature of decoder initialization, decoding, and resetting.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** The `VideoDecoderBroker` is a backend component that directly supports the WebCodecs API's `VideoDecoder` interface in JavaScript. When a JavaScript developer creates a `VideoDecoder` object and calls its `decode()` method, the underlying `VideoDecoderBroker` in the renderer process handles the actual decoding process.
    * **Example:**  A JavaScript application might use the WebCodecs API to decode video frames from a webcam stream or a downloaded video file. The `VideoDecoderBroker` would be involved in selecting and managing the decoder used for this task.

* **HTML:** While not directly interacting with HTML, the `VideoDecoderBroker` is crucial for the `<video>` element's ability to play video. When the `<video>` element encounters a video stream, the browser's media pipeline, including the `VideoDecoderBroker`, is responsible for decoding the video frames for rendering.
    * **Example:** When a user plays an H.264 video embedded in an HTML page using the `<video>` tag, the `VideoDecoderBroker` will be involved in decoding the H.264 stream.

* **CSS:** CSS primarily deals with the styling and layout of HTML elements. It doesn't directly influence the video decoding process managed by `VideoDecoderBroker`. However, CSS properties can affect how the decoded video frames are displayed within the `<video>` element (e.g., `width`, `height`, `object-fit`).

**Logical Reasoning with Hypothetical Input/Output:**

Let's consider the `Decode_WithMojoDecoder` test case:

* **Hypothetical Input:**
    * `HardwarePreference` is not explicitly set (defaults to no preference).
    * A "extra-large" video configuration is used (`media::TestVideoConfig::ExtraLarge()`). This might trigger the preference for hardware decoding if available.
    * A fake video buffer is passed to the `DecodeBuffer` method.
    * An EOS (End-of-Stream) buffer is passed to signal the end of the decoding sequence.

* **Expected Output:**
    * `GetDecoderType()` should return `media::VideoDecoderType::kTesting` (indicating the use of the mocked Mojo decoder).
    * The `OnOutput` callback should be invoked at least once with a valid `media::VideoFrame`.
    * `IsPlatformDecoder()` should return `true` (as the fake Mojo decoder simulates a hardware decoder).
    * `NeedsBitstreamConversion()` should return `true` (as configured in the `FakeGpuVideoDecoder`).
    * `CanReadWithoutStalling()` should return `false` (as configured in the `FakeGpuVideoDecoder`).
    * `GetMaxDecodeRequests()` should return `13` (as configured in the `FakeGpuVideoDecoder`).

**User/Programming Common Usage Errors:**

1. **Decoding Before Initialization:** A common error is attempting to decode video data before the decoder has been properly initialized with a valid video configuration. The `Decode_Uninitialized` test specifically targets this scenario.
    * **Example:** In JavaScript, forgetting to call `videoDecoder.configure(config)` before calling `videoDecoder.decode(chunk)`.

2. **Providing Unsupported Configurations:**  Passing a video configuration that the underlying decoders cannot handle will lead to initialization or decoding errors. The tests with `expect_success = false` in `InitializeDecoder` demonstrate this.
    * **Example:**  Trying to decode a video with a codec that the browser doesn't support or without the necessary hardware acceleration capabilities.

3. **Incorrect Buffer Handling:** Providing malformed or incomplete decoder buffers can cause decoding failures. While not explicitly tested in this file with malformed data, the framework is in place to handle such scenarios.
    * **Example:** In JavaScript, providing a `EncodedVideoChunk` with incorrect `data` or `timestamp`.

4. **Not Handling Asynchronous Operations Correctly:** Video decoding operations are asynchronous. Failing to use Promises or callbacks correctly to handle the results of `decode()` calls can lead to issues. The tests use `base::RunLoop` to synchronize these asynchronous operations for testing purposes.

**User Operations Leading to This Code (Debugging Clues):**

Imagine a user is watching a video online:

1. **User Navigates to a Website with Video:** The user opens a webpage containing a `<video>` element or a JavaScript application that uses the WebCodecs API to play video.
2. **Video Playback Starts:** The browser begins fetching the video data.
3. **Media Pipeline Initialization:** The browser's media pipeline is initialized to handle the video playback. This involves creating components like the `VideoDecoderBroker`.
4. **JavaScript Interaction (Optional):** If the website uses the WebCodecs API directly, JavaScript code might create and configure a `VideoDecoder` object. This would trigger the `VideoDecoderBroker` to be used internally.
5. **Decoder Selection:** The `VideoDecoderBroker` analyzes the video configuration and the user's system capabilities (including hardware acceleration) to choose the most appropriate video decoder. The `HardwarePreference` setting in the browser might influence this choice.
6. **Decoding Process:** As the video data arrives, the `VideoDecoderBroker` feeds encoded video buffers to the selected decoder.
7. **Frame Output:** The decoder outputs decoded video frames, which are then passed to the rendering pipeline for display.

**As a debugging clue:** If a user reports issues with video playback (e.g., stuttering, artifacts, high CPU usage), a developer might investigate the decoder selection process. Looking at the logs related to `VideoDecoderBroker` and the chosen decoder type could provide insights. For example, if hardware acceleration was expected but a software decoder is being used, that could indicate a problem with the GPU drivers or browser configuration. The tests in this file help ensure that the `VideoDecoderBroker` makes the correct decisions based on the available information.

In summary, `video_decoder_broker_test.cc` plays a vital role in ensuring the reliability and correctness of the `VideoDecoderBroker`, a fundamental component for video playback functionality in the Chromium browser, both for the `<video>` element and the more advanced WebCodecs API.

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_decoder_broker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_decoder_broker.h"

#include <memory>
#include <vector>

#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "gpu/command_buffer/common/mailbox_holder.h"
#include "media/base/decoder_buffer.h"
#include "media/base/decoder_status.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/test_data_util.h"
#include "media/base/test_helpers.h"
#include "media/base/video_frame.h"
#include "media/filters/fake_video_decoder.h"
#include "media/mojo/buildflags.h"
#include "media/mojo/mojom/interface_factory.mojom.h"
#include "media/mojo/mojom/video_decoder.mojom.h"
#include "media/mojo/services/interface_factory_impl.h"
#include "media/mojo/services/mojo_cdm_service_context.h"
#include "media/mojo/services/mojo_video_decoder_service.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace blink {

namespace {

// Fake decoder intended to simulate platform specific hw accelerated decoders
// running in the GPU process.
// * Initialize() will succeed for any given config.
// * MakeVideoFrame() is overridden to create frames frame with a mailbox and
//   power_efficient flag. This simulates hw decoder output and satisfies
//   requirements of MojoVideoDecoder.
class FakeGpuVideoDecoder : public media::FakeVideoDecoder {
 public:
  FakeGpuVideoDecoder()
      : FakeVideoDecoder(0 /* decoder_id */,
                         0 /* decoding_delay */,
                         13 /* max_parallel_decoding_requests */,
                         media::BytesDecodedCB()) {}
  ~FakeGpuVideoDecoder() override = default;

  scoped_refptr<media::VideoFrame> MakeVideoFrame(
      const media::DecoderBuffer& buffer) override {
    scoped_refptr<gpu::ClientSharedImage> shared_image =
        gpu::ClientSharedImage::CreateForTesting();
    scoped_refptr<media::VideoFrame> frame = media::VideoFrame::WrapSharedImage(
        media::PIXEL_FORMAT_ARGB, shared_image, gpu::SyncToken(),
        media::VideoFrame::ReleaseMailboxCB(), current_config_.coded_size(),
        current_config_.visible_rect(), current_config_.natural_size(),
        buffer.timestamp());
    frame->metadata().power_efficient = true;
    return frame;
  }

  // Override these methods to provide non-default values for testing.
  bool IsPlatformDecoder() const override { return true; }
  bool NeedsBitstreamConversion() const override { return true; }
  bool CanReadWithoutStalling() const override { return false; }
};

// Client to MojoVideoDecoderService vended by FakeInterfaceFactory. Creates a
// FakeGpuVideoDecoder when requested.
class FakeMojoMediaClient : public media::MojoMediaClient {
 public:
  // MojoMediaClient implementation.
  std::unique_ptr<media::VideoDecoder> CreateVideoDecoder(
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      media::MediaLog* media_log,
      media::mojom::CommandBufferIdPtr command_buffer_id,
      media::RequestOverlayInfoCB request_overlay_info_cb,
      const gfx::ColorSpace& target_color_space,
      mojo::PendingRemote<media::stable::mojom::StableVideoDecoder>
          oop_video_decoder) override {
    return std::make_unique<FakeGpuVideoDecoder>();
  }
};

// Other end of remote InterfaceFactory requested by VideoDecoderBroker. Used
// to create our (fake) media::mojom::VideoDecoder.
class FakeInterfaceFactory : public media::mojom::InterfaceFactory {
 public:
  FakeInterfaceFactory() = default;
  ~FakeInterfaceFactory() override = default;

  void BindRequest(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(mojo::PendingReceiver<media::mojom::InterfaceFactory>(
        std::move(handle)));
    receiver_.set_disconnect_handler(WTF::BindOnce(
        &FakeInterfaceFactory::OnConnectionError, base::Unretained(this)));
  }

  void OnConnectionError() { receiver_.reset(); }

  // Implement this one interface from mojom::InterfaceFactory. Using the real
  // MojoVideoDecoderService allows us to reuse buffer conversion code. The
  // FakeMojoMediaClient will create a FakeGpuVideoDecoder.
  void CreateVideoDecoder(
      mojo::PendingReceiver<media::mojom::VideoDecoder> receiver,
      mojo::PendingRemote<media::stable::mojom::StableVideoDecoder>
          dst_video_decoder) override {
    video_decoder_receivers_.Add(
        std::make_unique<media::MojoVideoDecoderService>(
            &mojo_media_client_, &cdm_service_context_,
            mojo::PendingRemote<media::stable::mojom::StableVideoDecoder>()),
        std::move(receiver));
  }

#if BUILDFLAG(ALLOW_OOP_VIDEO_DECODER)
  void CreateStableVideoDecoder(
      mojo::PendingReceiver<media::stable::mojom::StableVideoDecoder>
          video_decoder) override {
    // TODO(b/327268445): we'll need to complete this for GTFO OOP-VD testing.
  }
#endif  // BUILDFLAG(ALLOW_OOP_VIDEO_DECODER)

  // Stub out other mojom::InterfaceFactory interfaces.
  void CreateAudioDecoder(
      mojo::PendingReceiver<media::mojom::AudioDecoder> receiver) override {}
  void CreateAudioEncoder(
      mojo::PendingReceiver<media::mojom::AudioEncoder> receiver) override {}
  void CreateDefaultRenderer(
      const std::string& audio_device_id,
      mojo::PendingReceiver<media::mojom::Renderer> receiver) override {}
#if BUILDFLAG(ENABLE_CAST_RENDERER)
  void CreateCastRenderer(
      const base::UnguessableToken& overlay_plane_id,
      mojo::PendingReceiver<media::mojom::Renderer> receiver) override {}
#endif
#if BUILDFLAG(IS_ANDROID)
  void CreateMediaPlayerRenderer(
      mojo::PendingRemote<media::mojom::MediaPlayerRendererClientExtension>
          client_extension_remote,
      mojo::PendingReceiver<media::mojom::Renderer> receiver,
      mojo::PendingReceiver<media::mojom::MediaPlayerRendererExtension>
          renderer_extension_receiver) override {}
  void CreateFlingingRenderer(
      const std::string& presentation_id,
      mojo::PendingRemote<media::mojom::FlingingRendererClientExtension>
          client_extension,
      mojo::PendingReceiver<media::mojom::Renderer> receiver) override {}
#endif  // BUILDFLAG(IS_ANDROID)
  void CreateCdm(const media::CdmConfig& cdm_config,
                 CreateCdmCallback callback) override {
    std::move(callback).Run(mojo::NullRemote(), nullptr,
                            media::CreateCdmStatus::kCdmNotSupported);
  }

#if BUILDFLAG(IS_WIN)
  void CreateMediaFoundationRenderer(
      mojo::PendingRemote<media::mojom::MediaLog> media_log_remote,
      mojo::PendingReceiver<media::mojom::Renderer> receiver,
      mojo::PendingReceiver<media::mojom::MediaFoundationRendererExtension>
          renderer_extension_receiver,
      mojo::PendingRemote<
          ::media::mojom::MediaFoundationRendererClientExtension>
          client_extension_remote) override {}
#endif  // BUILDFLAG(IS_WIN)
 private:
  media::MojoCdmServiceContext cdm_service_context_;
  FakeMojoMediaClient mojo_media_client_;
  mojo::Receiver<media::mojom::InterfaceFactory> receiver_{this};
  mojo::UniqueReceiverSet<media::mojom::VideoDecoder> video_decoder_receivers_;
};

}  // namespace

class VideoDecoderBrokerTest : public testing::Test {
 public:
  VideoDecoderBrokerTest() = default;

  ~VideoDecoderBrokerTest() override {
    // Clean up this override, or else we we fail or DCHECK in SetupMojo().
    Platform::Current()->GetBrowserInterfaceBroker()->SetBinderForTesting(
        media::mojom::InterfaceFactory::Name_,
        base::RepeatingCallback<void(mojo::ScopedMessagePipeHandle)>());

    // `decoder_broker` schedules deletion of internal data including decoders
    // which keep pointers to `gpu_factories_`. The deletion is scheduled in
    // `media_thread_`, wait for completion of all its tasks.
    decoder_broker_.reset();
    if (media_thread_) {
      media_thread_->FlushForTesting();
    }
  }

  void OnInitWithClosure(base::RepeatingClosure done_cb,
                         media::DecoderStatus status) {
    OnInit(status);
    done_cb.Run();
  }
  void OnDecodeDoneWithClosure(base::RepeatingClosure done_cb,
                               media::DecoderStatus status) {
    OnDecodeDone(std::move(status));
    done_cb.Run();
  }

  void OnResetDoneWithClosure(base::RepeatingClosure done_cb) {
    OnResetDone();
    done_cb.Run();
  }

  MOCK_METHOD1(OnInit, void(media::DecoderStatus status));
  MOCK_METHOD1(OnDecodeDone, void(media::DecoderStatus));
  MOCK_METHOD0(OnResetDone, void());

  void OnOutput(scoped_refptr<media::VideoFrame> frame) {
    output_frames_.push_back(std::move(frame));
  }

  void SetupMojo(ExecutionContext& execution_context) {
    // Register FakeInterfaceFactory as impl for media::mojom::InterfaceFactory
    // required by MojoVideoDecoder. The factory will vend FakeGpuVideoDecoders
    // that simulate gpu-accelerated decode.
    interface_factory_ = std::make_unique<FakeInterfaceFactory>();
    EXPECT_TRUE(
        Platform::Current()->GetBrowserInterfaceBroker()->SetBinderForTesting(
            media::mojom::InterfaceFactory::Name_,
            WTF::BindRepeating(&FakeInterfaceFactory::BindRequest,
                               base::Unretained(interface_factory_.get()))));

    // |gpu_factories_| requires API calls be made using it's GetTaskRunner().
    // We use a separate |media_thread_| (as opposed to a separate task runner
    // on the main thread) to simulate cross-thread production behavior.
    media_thread_ = std::make_unique<base::Thread>("media_thread");
    media_thread_->Start();

    // |gpu_factories_| is a dependency of MojoVideoDecoder (and associated code
    // paths). Setup |gpu_factories_| to say "yes" to any decoder config to
    // ensure MojoVideoDecoder will be selected as the underlying decoder upon
    // VideoDecoderBroker::Initialize(). The
    gpu_factories_ =
        std::make_unique<media::MockGpuVideoAcceleratorFactories>(nullptr);
    EXPECT_CALL(*gpu_factories_, GetTaskRunner())
        .WillRepeatedly(Return(media_thread_->task_runner()));
    EXPECT_CALL(*gpu_factories_, IsDecoderConfigSupported(_))
        .WillRepeatedly(
            Return(media::GpuVideoAcceleratorFactories::Supported::kTrue));
    EXPECT_CALL(*gpu_factories_, GetChannelToken(_))
        .WillRepeatedly(
            Invoke([](base::OnceCallback<void(const base::UnguessableToken&)>
                          callback) {
              std::move(callback).Run(base::UnguessableToken());
            }));
  }

  void ConstructDecoder(ExecutionContext& execution_context) {
    decoder_broker_ = std::make_unique<VideoDecoderBroker>(
        execution_context, gpu_factories_.get(), &null_media_log_);
  }

  void InitializeDecoder(media::VideoDecoderConfig config,
                         bool expect_success = true) {
    base::RunLoop run_loop;
    if (expect_success) {
      EXPECT_CALL(*this, OnInit(media::SameStatusCode(media::DecoderStatus(
                             media::DecoderStatus::Codes::kOk))));
    } else {
      EXPECT_CALL(*this,
                  OnInit(media::SameStatusCode(media::DecoderStatus(
                      media::DecoderStatus::Codes::kUnsupportedConfig))));
    }
    decoder_broker_->Initialize(
        config, false /*low_delay*/, nullptr /* cdm_context */,
        WTF::BindOnce(&VideoDecoderBrokerTest::OnInitWithClosure,
                      WTF::Unretained(this), run_loop.QuitClosure()),
        WTF::BindRepeating(&VideoDecoderBrokerTest::OnOutput,
                           WTF::Unretained(this)),
        media::WaitingCB());
    run_loop.Run();
    testing::Mock::VerifyAndClearExpectations(this);
  }

  void DecodeBuffer(scoped_refptr<media::DecoderBuffer> buffer,
                    media::DecoderStatus::Codes expected_status =
                        media::DecoderStatus::Codes::kOk) {
    base::RunLoop run_loop;
    EXPECT_CALL(*this, OnDecodeDone(HasStatusCode(expected_status)));
    decoder_broker_->Decode(
        buffer, WTF::BindOnce(&VideoDecoderBrokerTest::OnDecodeDoneWithClosure,
                              WTF::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    testing::Mock::VerifyAndClearExpectations(this);
  }

  void ResetDecoder() {
    base::RunLoop run_loop;
    EXPECT_CALL(*this, OnResetDone());
    decoder_broker_->Reset(
        WTF::BindOnce(&VideoDecoderBrokerTest::OnResetDoneWithClosure,
                      WTF::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    testing::Mock::VerifyAndClearExpectations(this);
  }

  media::VideoDecoderType GetDecoderType() {
    return decoder_broker_->GetDecoderType();
  }

  bool IsPlatformDecoder() { return decoder_broker_->IsPlatformDecoder(); }

  bool NeedsBitstreamConversion() {
    return decoder_broker_->NeedsBitstreamConversion();
  }

  bool CanReadWithoutStalling() {
    return decoder_broker_->CanReadWithoutStalling();
  }

  int GetMaxDecodeRequests() { return decoder_broker_->GetMaxDecodeRequests(); }

 protected:
  media::NullMediaLog null_media_log_;
  std::unique_ptr<base::Thread> media_thread_;
  // `gpu_factories_` must outlive `decoder_broker_` because it's stored as a
  // raw_ptr.
  std::unique_ptr<media::MockGpuVideoAcceleratorFactories> gpu_factories_;
  std::unique_ptr<VideoDecoderBroker> decoder_broker_;
  std::vector<scoped_refptr<media::VideoFrame>> output_frames_;
  std::unique_ptr<FakeInterfaceFactory> interface_factory_;

  test::TaskEnvironment task_environment_;
};

TEST_F(VideoDecoderBrokerTest, Decode_Uninitialized) {
  V8TestingScope v8_scope;

  ConstructDecoder(*v8_scope.GetExecutionContext());
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  // No call to Initialize. Other APIs should fail gracefully.

  DecodeBuffer(media::ReadTestDataFile("vp8-I-frame-320x120"),
               media::DecoderStatus::Codes::kNotInitialized);
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer(),
               media::DecoderStatus::Codes::kNotInitialized);
  ASSERT_EQ(0U, output_frames_.size());

  ResetDecoder();
}

TEST_F(VideoDecoderBrokerTest, Decode_NoMojoDecoder) {
  V8TestingScope v8_scope;

  ConstructDecoder(*v8_scope.GetExecutionContext());
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  InitializeDecoder(media::TestVideoConfig::Normal(media::VideoCodec::kVP8));
  EXPECT_NE(GetDecoderType(), media::VideoDecoderType::kBroker);

  DecodeBuffer(media::ReadTestDataFile("vp8-I-frame-320x120"));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(1U, output_frames_.size());

  ResetDecoder();

  DecodeBuffer(media::ReadTestDataFile("vp8-I-frame-320x120"));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(2U, output_frames_.size());

  ResetDecoder();
}

// Makes sure that no software decoder is returned if we required acceleration,
// even if this means that no decoder is selected.
TEST_F(VideoDecoderBrokerTest, Init_RequireAcceleration) {
  V8TestingScope v8_scope;

  ConstructDecoder(*v8_scope.GetExecutionContext());
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  decoder_broker_->SetHardwarePreference(HardwarePreference::kPreferHardware);

  InitializeDecoder(media::TestVideoConfig::Normal(media::VideoCodec::kVP8),
                    /*expect_success*/ false);
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);
}

#if BUILDFLAG(ENABLE_MOJO_VIDEO_DECODER)
TEST_F(VideoDecoderBrokerTest, Init_DenyAcceleration) {
  V8TestingScope v8_scope;
  ExecutionContext* execution_context = v8_scope.GetExecutionContext();

  SetupMojo(*execution_context);
  ConstructDecoder(*execution_context);
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  decoder_broker_->SetHardwarePreference(HardwarePreference::kPreferSoftware);

  // Use an extra-large video to push us towards a hardware decoder.
  media::VideoDecoderConfig config = media::TestVideoConfig::ExtraLarge();
  InitializeDecoder(config);
  EXPECT_FALSE(IsPlatformDecoder());
}

TEST_F(VideoDecoderBrokerTest, Decode_MultipleAccelerationPreferences) {
  V8TestingScope v8_scope;
  ExecutionContext* execution_context = v8_scope.GetExecutionContext();

  SetupMojo(*execution_context);
  ConstructDecoder(*execution_context);
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  // Make sure we can decode software only.
  decoder_broker_->SetHardwarePreference(HardwarePreference::kPreferSoftware);
  InitializeDecoder(media::TestVideoConfig::Normal(media::VideoCodec::kVP8));
  DecodeBuffer(media::ReadTestDataFile("vp8-I-frame-320x120"));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(1U, output_frames_.size());

  // Make sure we can decoder with hardware only.
  decoder_broker_->SetHardwarePreference(HardwarePreference::kPreferHardware);

  // Use an extra-large video to ensure we don't get a software decoder.
  media::VideoDecoderConfig large_config = media::TestVideoConfig::ExtraLarge();
  InitializeDecoder(large_config);
  DecodeBuffer(media::CreateFakeVideoBufferForTest(
      large_config, base::TimeDelta(), base::Milliseconds(33)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(2U, output_frames_.size());

  // Make sure we can decode with both HW or SW as appropriate.
  decoder_broker_->SetHardwarePreference(HardwarePreference::kNoPreference);

  // Use a large frame to force hardware decode.
  InitializeDecoder(large_config);
  DecodeBuffer(media::CreateFakeVideoBufferForTest(
      large_config, base::TimeDelta(), base::Milliseconds(33)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(3U, output_frames_.size());
  EXPECT_TRUE(IsPlatformDecoder());

  auto normal_config = media::TestVideoConfig::Normal(media::VideoCodec::kVP8);
  InitializeDecoder(normal_config);
  // VideoDecoderBroker doesn't have any inherent preference for software
  // decoders based on resolution, so we'll still end up with a hardware
  // decoder even though this is a small size clip.
  // TODO(crbug.com/361823989): We should update the VideoDecoderBroker to
  // always enable resolution based priority in DecoderSelector.
  DecodeBuffer(media::CreateFakeVideoBufferForTest(
      normal_config, base::TimeDelta(), base::Milliseconds(33)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(4U, output_frames_.size());

  ResetDecoder();
}

TEST_F(VideoDecoderBrokerTest, Decode_WithMojoDecoder) {
  V8TestingScope v8_scope;
  ExecutionContext* execution_context = v8_scope.GetExecutionContext();

  SetupMojo(*execution_context);
  ConstructDecoder(*execution_context);
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kBroker);

  // Use an extra-large video to ensure we don't get a software decoder.
  media::VideoDecoderConfig config = media::TestVideoConfig::ExtraLarge();
  InitializeDecoder(config);
  EXPECT_EQ(GetDecoderType(), media::VideoDecoderType::kTesting);

  DecodeBuffer(media::CreateFakeVideoBufferForTest(config, base::TimeDelta(),
                                                   base::Milliseconds(33)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  ASSERT_EQ(1U, output_frames_.size());

  // Backing FakeVideoDecoder will return interesting values for these APIs.
  EXPECT_TRUE(IsPlatformDecoder());
  EXPECT_TRUE(NeedsBitstreamConversion());
  EXPECT_FALSE(CanReadWithoutStalling());
  EXPECT_EQ(GetMaxDecodeRequests(), 13);

  ResetDecoder();
}
#endif  // BUILDFLAG(ENABLE_MOJO_VIDEO_DECODER)

}  // namespace blink
```
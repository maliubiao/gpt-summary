Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed explanation.

1. **Understand the Core Purpose:** The filename `audio_decoder_broker_test.cc` immediately suggests this is a test file for a class named `AudioDecoderBroker`. The `.cc` extension indicates C++ source code. The `test` suffix strongly implies unit testing.

2. **Identify the Tested Class:**  The `#include "third_party/blink/renderer/modules/webcodecs/audio_decoder_broker.h"` confirms the class under scrutiny is `AudioDecoderBroker`.

3. **Determine the Testing Strategy:** Look for common testing patterns and frameworks. The inclusion of `<gmock/gmock.h>` and `<gtest/gtest.h>` reveals that Google Mock and Google Test are being used for mocking dependencies and writing test assertions, respectively.

4. **Analyze the Includes:**  The included headers provide valuable context about the `AudioDecoderBroker`'s dependencies and functionalities. Key includes include:
    * **`media/...`:**  Indicates interaction with the Chromium media pipeline. This likely involves audio codecs, decoder configurations, and audio buffer management.
    * **`mojo/...`:**  Points to the use of Mojo, Chromium's inter-process communication system. This suggests `AudioDecoderBroker` might interact with audio decoders running in a separate process (out-of-process decoding).
    * **`third_party/blink/...`:**  Confirms this code belongs to the Blink rendering engine. Includes like `v8/v8_binding_for_testing.h` and `platform/testing/task_environment.h` indicate integration with the V8 JavaScript engine and a testing environment.

5. **Examine the Test Fixture:** The `class AudioDecoderBrokerTest : public testing::Test` defines the test fixture. Key elements to analyze within the fixture are:
    * **Member Variables:** `decoder_broker_`, `output_buffers_`, `interface_factory_`. These represent the object being tested, a way to capture output, and a mechanism for simulating dependencies (specifically the Mojo interface factory).
    * **Mock Methods:** `OnInit`, `OnDecodeDone`, `OnResetDone`. These use Google Mock to set expectations on how the test interacts with the `AudioDecoderBroker`.
    * **Helper Methods:**  `OnInitWithClosure`, `OnDecodeDoneWithClosure`, `OnResetDoneWithClosure`, `OnOutput`, `SetupMojo`, `ConstructDecoder`, `InitializeDecoder`, `DecodeBuffer`, `ResetDecoder`, `GetDecoderType`, `IsPlatformDecoder`, `SupportsDecryption`. These methods encapsulate common setup and interaction patterns for testing the `AudioDecoderBroker`.

6. **Analyze Individual Test Cases:** Each `TEST_F(AudioDecoderBrokerTest, ...)` represents a specific test scenario. Break down what each test does:
    * **`Decode_Uninitialized`:** Tests the behavior when attempting to decode without initializing the decoder.
    * **`Decode_NoMojoDecoder`:**  Tests the case where a separate Mojo-based decoder is *not* used (likely falling back to an in-process decoder like FFmpeg).
    * **`Decode_WithMojoDecoder`:** Tests the scenario where a Mojo-based decoder is used. Pay attention to how the `FakeInterfaceFactory` is used to inject a mock Mojo decoder.

7. **Identify Key Concepts and Relationships:** Based on the code and the includes, identify the core concepts and how they relate:
    * **`AudioDecoderBroker`:** The central class being tested, responsible for managing the selection and interaction with audio decoders (either in-process or out-of-process via Mojo).
    * **Mojo:** Used for out-of-process communication with audio decoders. The `FakeInterfaceFactory` plays a crucial role in simulating this.
    * **`media::AudioDecoder`:** The abstract interface for audio decoders. The tests use `FakeAudioDecoder` (a mock) and potentially a real `MojoAudioDecoderService` indirectly.
    * **`media::AudioDecoderConfig`:**  Specifies the configuration for the audio decoder (codec, sample format, etc.).
    * **`media::DecoderBuffer`:** Represents the input and output audio data.
    * **FFmpeg:**  A common in-process audio decoder used by Chromium. The tests implicitly check fallback to FFmpeg.

8. **Connect to Web Technologies (JavaScript, HTML, CSS):** Consider how the `AudioDecoderBroker` fits into the browser context:
    * **JavaScript WebCodecs API:** The directory name `webcodecs` strongly suggests this is part of the implementation for the WebCodecs API, which allows JavaScript to access low-level audio and video encoding/decoding functionalities.
    * **`<audio>` and `<video>` elements:**  While this specific test doesn't directly interact with these elements, the `AudioDecoderBroker` is part of the underlying implementation that makes audio playback in these elements possible.

9. **Infer User Actions and Debugging:**  Think about how a user might trigger this code and how a developer might use these tests for debugging:
    * **User Actions:** Playing audio on a website using `<audio>` or `<video>` elements, or using JavaScript code via the WebCodecs API to decode audio.
    * **Debugging:**  If audio decoding is failing, developers might look at the `AudioDecoderBroker` to understand how the decoder is being selected and if the communication with the decoder is working correctly. These tests provide specific scenarios to isolate and debug potential issues.

10. **Formulate the Explanation:**  Organize the findings into a clear and structured explanation, covering the requested points: functionality, relationship to web technologies, logical reasoning (input/output), common errors, and debugging. Use clear language and provide examples where possible. Start with a high-level overview and then delve into the specifics.

11. **Review and Refine:**  Read through the explanation to ensure accuracy, completeness, and clarity. Correct any errors or ambiguities. Ensure the language is appropriate for the intended audience. For instance, explaining Mojo as "Chromium's inter-process communication system" is more helpful than just saying "it uses Mojo."
这个文件 `audio_decoder_broker_test.cc` 是 Chromium Blink 引擎中 `webcodecs` 模块的一部分，专门用于测试 `AudioDecoderBroker` 类的功能。 `AudioDecoderBroker` 的作用是管理音频解码器的选择和生命周期，它可能会根据不同的情况选择使用不同的音频解码器实现（例如，基于 FFmpeg 的软件解码器或基于 Mojo 的硬件加速解码器）。

以下是该文件的功能分解：

**1. 测试 AudioDecoderBroker 的核心功能:**

   * **初始化 (Initialize):** 测试 `AudioDecoderBroker` 如何初始化底层的音频解码器，并处理成功或失败的情况。
   * **解码 (Decode):** 测试 `AudioDecoderBroker` 如何将编码后的音频数据（`DecoderBuffer`）传递给底层的解码器，并接收解码后的音频数据（`AudioBuffer`）。
   * **重置 (Reset):** 测试 `AudioDecoderBroker` 如何重置底层的音频解码器状态。
   * **处理未初始化状态:** 测试在没有正确初始化的情况下调用解码等操作时的行为。
   * **解码器类型选择:** 测试 `AudioDecoderBroker` 如何根据配置选择合适的解码器（例如，当 Mojo 音频解码器可用时使用它，否则回退到 FFmpeg）。

**2. 模拟不同的音频解码器场景:**

   * **FakeAudioDecoder:**  文件中定义了一个 `FakeAudioDecoder` 类，它是一个模拟的音频解码器，用于简化测试。它可以快速地返回成功状态，并且可以模拟生成解码后的音频数据。这允许测试 `AudioDecoderBroker` 的控制逻辑，而无需依赖真实的音频解码器的复杂性。
   * **Mojo 音频解码器:**  测试中使用了 Mojo (Chromium 的进程间通信机制) 来模拟与运行在独立进程中的音频解码器进行通信。 `FakeInterfaceFactory` 用于模拟 Mojo 接口工厂，它可以创建 `MojoAudioDecoderService`，而后者又会使用 `FakeMojoMediaClient` 创建 `FakeAudioDecoder`。这模拟了使用硬件加速音频解码器的场景。

**3. 使用 Google Test 和 Google Mock 进行测试:**

   * **Google Test (`TEST_F`)**:  用于编写独立的测试用例，例如 `Decode_Uninitialized`, `Decode_NoMojoDecoder`, `Decode_WithMojoDecoder`。
   * **Google Mock (`EXPECT_CALL`, `MOCK_METHOD`)**: 用于模拟和验证测试过程中发生的函数调用和状态变化。例如，使用 `EXPECT_CALL` 来验证 `OnInit`, `OnDecodeDone`, `OnResetDone` 回调函数是否被正确调用，以及调用时的参数是否符合预期。

**与 JavaScript, HTML, CSS 的关系：**

`AudioDecoderBroker` 本身并不直接与 JavaScript, HTML, CSS 代码交互，它位于 Blink 引擎的更底层。然而，它为 WebCodecs API 提供了音频解码的基础设施，而 WebCodecs API 可以被 JavaScript 代码调用。

* **JavaScript (WebCodecs API):**
   - JavaScript 代码可以使用 `AudioDecoder` 接口来解码音频流。当 JavaScript 调用 `decode()` 方法时，Blink 引擎会使用 `AudioDecoderBroker` 来选择和管理底层的音频解码器。
   - **举例说明:**  假设 JavaScript 代码使用 WebCodecs API 解码一个 Vorbis 音频文件：
     ```javascript
     const decoder = new AudioDecoder({
       output: (buffer) => { console.log("Decoded audio data:", buffer); },
       error: (e) => { console.error("Decoding error:", e); }
     });

     fetch('audio.ogg')
       .then(response => response.arrayBuffer())
       .then(data => {
         decoder.configure({
           codec: 'vorbis',
           // ... 其他配置
         });
         const chunk = new EncodedAudioChunk({
           type: 'key',
           timestamp: 0,
           data: data
         });
         decoder.decode(chunk);
       });
     ```
     在这个过程中，`AudioDecoderBroker` 负责根据 `codec` 配置（'vorbis'）选择合适的解码器，并将 `EncodedAudioChunk` 中的数据传递给底层的解码器进行处理。

* **HTML (`<audio>` 元素):**
   - 当 HTML 中的 `<audio>` 元素播放音频时，浏览器也会使用底层的音频解码器来解码音频数据。虽然 `<audio>` 元素的解码流程可能比 WebCodecs API 更复杂，但 `AudioDecoderBroker` 仍然可能参与到解码器的管理和选择中。
   - **举例说明:**  一个简单的 HTML 页面播放 Vorbis 音频：
     ```html
     <audio controls src="audio.ogg"></audio>
     ```
     当浏览器加载并播放 `audio.ogg` 时，Blink 引擎会根据音频文件的格式选择相应的解码器，`AudioDecoderBroker` 可能会参与到这个选择过程中。

* **CSS:** CSS 与音频解码没有直接关系。

**逻辑推理 (假设输入与输出):**

假设我们运行 `AudioDecoderBrokerTest` 中的 `Decode_NoMojoDecoder` 测试用例：

**假设输入:**

* **初始化配置:**  一个 Vorbis 音频解码配置 (通过 `MakeVorbisConfig()` 创建)，包含 Vorbis 编码的额外数据。
* **解码输入:** 三个包含 Vorbis 音频数据的 `DecoderBuffer` 对象 (`vorbis-packet-0`, `vorbis-packet-1`, `vorbis-packet-2`)，以及一个表示流结束的 `DecoderBuffer::CreateEOSBuffer()`。

**预期输出:**

* **初始化成功:** `OnInit` 回调函数被调用，状态为 `media::DecoderStatus::Codes::kOk`。
* **解码成功:** 对于每个非 EOS 的 `DecoderBuffer`，`OnDecodeDone` 回调函数被调用，状态为 `media::DecoderStatus::Codes::kOk`。
* **解码后的音频数据:**  对于成功解码的音频包，`OnOutput` 回调函数会被调用，并将解码后的 `AudioBuffer` 存储到 `output_buffers_` 中。由于 FFmpeg 解码器通常会有一定的缓冲和延迟，可能前几个输入包不会立即产生输出。在这个测试中，预期的输出缓冲数量是 2。
* **重置成功:** `OnResetDone` 回调函数被调用。

**用户或编程常见的使用错误:**

* **在未配置的情况下尝试解码:**  JavaScript 代码可能在没有调用 `decoder.configure()` 的情况下就调用 `decoder.decode()`。这会导致 `AudioDecoderBroker` 无法选择合适的解码器，从而导致错误。
   - **测试用例覆盖:**  `Decode_Uninitialized` 测试用例模拟了这种情况。
* **提供不支持的编解码器类型:**  JavaScript 代码可能配置了一个浏览器不支持的 `codec` 值。这会导致 `AudioDecoderBroker` 找不到合适的解码器，并抛出错误。
* **发送损坏的或不完整的音频数据:**  如果 JavaScript 代码传递给解码器的 `EncodedAudioChunk` 数据损坏，底层的解码器可能会返回错误，`AudioDecoderBroker` 会将这些错误传递给 JavaScript 的错误回调。
* **过早地调用 `close()` 或 `reset()`:** 在解码过程仍在进行时，过早地关闭或重置解码器可能会导致数据丢失或状态不一致。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上触发音频播放:** 用户点击了一个包含音频的 `<audio>` 或 `<video>` 元素，或者通过 JavaScript 代码（例如，使用 Web Audio API 或 WebCodecs API）开始播放音频。
2. **浏览器请求音频资源:** 浏览器向服务器请求音频文件。
3. **浏览器接收音频数据:** 浏览器接收到编码后的音频数据。
4. **Blink 引擎开始解码:** Blink 引擎中的音频渲染管道需要解码音频数据才能播放。
5. **WebCodecs API (如果使用):** 如果网页使用了 WebCodecs API 的 `AudioDecoder`，JavaScript 代码会将编码后的音频数据传递给解码器。
6. **AudioDecoderBroker 被调用:**  无论是 `<audio>` 元素还是 WebCodecs API，Blink 引擎都会使用 `AudioDecoderBroker` 来管理音频解码器的选择和操作。
7. **解码器选择:** `AudioDecoderBroker` 根据音频的编码格式、系统支持的解码器等因素选择合适的解码器实现（例如，FFmpeg 或 Mojo 音频解码器）。
8. **解码过程:** 选择的解码器被初始化，并接收编码后的音频数据进行解码。
9. **测试代码介入 (调试时):**  当开发者怀疑音频解码过程存在问题时，他们可能会运行 `audio_decoder_broker_test.cc` 中的测试用例来验证 `AudioDecoderBroker` 的行为是否符合预期。
10. **例如，调试 Mojo 解码器问题:**  开发者可能会关注 `Decode_WithMojoDecoder` 测试用例，来检查与 Mojo 音频解码器的通信和交互是否正确。如果测试失败，可以帮助定位 `AudioDecoderBroker` 在处理 Mojo 解码器时的逻辑错误。
11. **例如，调试基本解码功能:** 开发者可能会运行 `Decode_NoMojoDecoder` 来检查基本的 FFmpeg 解码流程是否正常工作。

总之，`audio_decoder_broker_test.cc` 是一个关键的测试文件，用于确保 `AudioDecoderBroker` 能够正确地管理音频解码器，处理各种输入和状态，并为 WebCodecs API 和 HTML 音频播放提供可靠的解码基础设施。通过模拟不同的场景和使用 Mock 对象，它可以有效地隔离和测试 `AudioDecoderBroker` 的核心逻辑。

Prompt: 
```
这是目录为blink/renderer/modules/webcodecs/audio_decoder_broker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/audio_decoder_broker.h"

#include <memory>
#include <optional>
#include <vector>

#include "base/files/file_util.h"
#include "base/run_loop.h"
#include "build/build_config.h"
#include "media/base/audio_codecs.h"
#include "media/base/channel_layout.h"
#include "media/base/decoder_buffer.h"
#include "media/base/decoder_status.h"
#include "media/base/media_util.h"
#include "media/base/mock_filters.h"
#include "media/base/sample_format.h"
#include "media/base/test_data_util.h"
#include "media/base/test_helpers.h"
#include "media/mojo/buildflags.h"
#include "media/mojo/mojom/audio_decoder.mojom.h"
#include "media/mojo/mojom/interface_factory.mojom.h"
#include "media/mojo/services/interface_factory_impl.h"
#include "media/mojo/services/mojo_audio_decoder_service.h"
#include "media/mojo/services/mojo_cdm_service_context.h"
#include "media/mojo/services/mojo_media_client.h"
#include "mojo/public/cpp/bindings/unique_receiver_set.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using ::testing::_;
using ::testing::Return;

namespace blink {

namespace {

// Constants to specify the type of audio data used.
constexpr media::AudioCodec kCodec = media::AudioCodec::kVorbis;
constexpr media::SampleFormat kSampleFormat = media::kSampleFormatPlanarF32;
constexpr media::ChannelLayout kChannelLayout = media::CHANNEL_LAYOUT_STEREO;
constexpr int kChannels = 2;
constexpr int kSamplesPerSecond = 44100;
constexpr int kInputFramesChunk = 256;

// FakeAudioDecoder is very agreeable.
// - any configuration is supported
// - all decodes immediately succeed
// - non EOS decodes produce an output
// - reset immediately succeeds.
class FakeAudioDecoder : public media::MockAudioDecoder {
 public:
  FakeAudioDecoder() : MockAudioDecoder() {}
  ~FakeAudioDecoder() override = default;

  void Initialize(const media::AudioDecoderConfig& config,
                  media::CdmContext* cdm_context,
                  InitCB init_cb,
                  const OutputCB& output_cb,
                  const media::WaitingCB& waiting_cb) override {
    output_cb_ = output_cb;
    std::move(init_cb).Run(media::DecoderStatus::Codes::kOk);
  }

  void Decode(scoped_refptr<media::DecoderBuffer> buffer,
              DecodeCB done_cb) override {
    DCHECK(output_cb_);

    std::move(done_cb).Run(media::DecoderStatus::Codes::kOk);

    if (!buffer->end_of_stream()) {
      output_cb_.Run(MakeAudioBuffer(kSampleFormat, kChannelLayout, kChannels,
                                     kSamplesPerSecond, 1.0f, 0.0f,
                                     kInputFramesChunk, buffer->timestamp()));
    }
  }

  void Reset(base::OnceClosure closure) override { std::move(closure).Run(); }

 private:
  OutputCB output_cb_;
};

class FakeMojoMediaClient : public media::MojoMediaClient {
 public:
  FakeMojoMediaClient() = default;
  FakeMojoMediaClient(const FakeMojoMediaClient&) = delete;
  FakeMojoMediaClient& operator=(const FakeMojoMediaClient&) = delete;

  std::unique_ptr<media::AudioDecoder> CreateAudioDecoder(
      scoped_refptr<base::SequencedTaskRunner> task_runner,
      std::unique_ptr<media::MediaLog> media_log) override {
    return std::make_unique<FakeAudioDecoder>();
  }
};

// Other end of remote InterfaceFactory requested by AudioDecoderBroker. Used
// to create our (fake) media::mojom::AudioDecoder.
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
  // MojoAudioDecoderService allows us to reuse buffer conversion code. The
  // FakeMojoMediaClient will create a FakeGpuAudioDecoder.
  void CreateAudioDecoder(
      mojo::PendingReceiver<media::mojom::AudioDecoder> receiver) override {
    audio_decoder_receivers_.Add(
        std::make_unique<media::MojoAudioDecoderService>(
            &mojo_media_client_, &cdm_service_context_,
            base::SingleThreadTaskRunner::GetCurrentDefault()),
        std::move(receiver));
  }
  void CreateAudioEncoder(
      mojo::PendingReceiver<media::mojom::AudioEncoder> receiver) override {}

  // Stub out other mojom::InterfaceFactory interfaces.
  void CreateVideoDecoder(
      mojo::PendingReceiver<media::mojom::VideoDecoder> receiver,
      mojo::PendingRemote<media::stable::mojom::StableVideoDecoder>
          dst_video_decoder) override {}
#if BUILDFLAG(ALLOW_OOP_VIDEO_DECODER)
  void CreateStableVideoDecoder(
      mojo::PendingReceiver<media::stable::mojom::StableVideoDecoder>
          video_decoder) override {}
#endif  // BUILDFLAG(ALLOW_OOP_VIDEO_DECODER)
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
  FakeMojoMediaClient mojo_media_client_;
  media::MojoCdmServiceContext cdm_service_context_;
  mojo::Receiver<media::mojom::InterfaceFactory> receiver_{this};
  mojo::UniqueReceiverSet<media::mojom::AudioDecoder> audio_decoder_receivers_;
};

}  // namespace

class AudioDecoderBrokerTest : public testing::Test {
 public:
  AudioDecoderBrokerTest() = default;
  ~AudioDecoderBrokerTest() override = default;

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

  void OnOutput(scoped_refptr<media::AudioBuffer> buffer) {
    output_buffers_.push_back(std::move(buffer));
  }

  void SetupMojo(ExecutionContext& execution_context) {
    // Register FakeInterfaceFactory as impl for media::mojom::InterfaceFactory
    // required by MojoAudioDecoder. The factory will vend FakeGpuAudioDecoders
    // that simulate gpu-accelerated decode.
    interface_factory_ = std::make_unique<FakeInterfaceFactory>();
    EXPECT_TRUE(
        Platform::Current()->GetBrowserInterfaceBroker()->SetBinderForTesting(
            media::mojom::InterfaceFactory::Name_,
            WTF::BindRepeating(&FakeInterfaceFactory::BindRequest,
                               base::Unretained(interface_factory_.get()))));
  }

  void ConstructDecoder(ExecutionContext& execution_context) {
    decoder_broker_ = std::make_unique<AudioDecoderBroker>(&null_media_log_,
                                                           execution_context);
  }

  void InitializeDecoder(media::AudioDecoderConfig config) {
    base::RunLoop run_loop;
    EXPECT_CALL(*this, OnInit(media::SameStatusCode(media::DecoderStatus(
                           media::DecoderStatus::Codes::kOk))));
    decoder_broker_->Initialize(
        config, nullptr /* cdm_context */,
        WTF::BindOnce(&AudioDecoderBrokerTest::OnInitWithClosure,
                      WTF::Unretained(this), run_loop.QuitClosure()),
        WTF::BindRepeating(&AudioDecoderBrokerTest::OnOutput,
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
        buffer, WTF::BindOnce(&AudioDecoderBrokerTest::OnDecodeDoneWithClosure,
                              WTF::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    testing::Mock::VerifyAndClearExpectations(this);
  }

  void ResetDecoder() {
    base::RunLoop run_loop;
    EXPECT_CALL(*this, OnResetDone());
    decoder_broker_->Reset(
        WTF::BindOnce(&AudioDecoderBrokerTest::OnResetDoneWithClosure,
                      WTF::Unretained(this), run_loop.QuitClosure()));
    run_loop.Run();
    testing::Mock::VerifyAndClearExpectations(this);
  }

  media::AudioDecoderType GetDecoderType() {
    return decoder_broker_->GetDecoderType();
  }

  bool IsPlatformDecoder() { return decoder_broker_->IsPlatformDecoder(); }
  bool SupportsDecryption() { return decoder_broker_->SupportsDecryption(); }

 protected:
  test::TaskEnvironment task_environment_;
  media::NullMediaLog null_media_log_;
  std::unique_ptr<AudioDecoderBroker> decoder_broker_;
  std::vector<scoped_refptr<media::AudioBuffer>> output_buffers_;
  std::unique_ptr<FakeInterfaceFactory> interface_factory_;
};

TEST_F(AudioDecoderBrokerTest, Decode_Uninitialized) {
  V8TestingScope v8_scope;

  ConstructDecoder(*v8_scope.GetExecutionContext());
  EXPECT_EQ(GetDecoderType(), media::AudioDecoderType::kBroker);

  // No call to Initialize. Other APIs should fail gracefully.

  DecodeBuffer(media::ReadTestDataFile("vorbis-packet-0"),
               media::DecoderStatus::Codes::kNotInitialized);
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer(),
               media::DecoderStatus::Codes::kNotInitialized);
  ASSERT_EQ(0U, output_buffers_.size());

  ResetDecoder();
}

media::AudioDecoderConfig MakeVorbisConfig() {
  std::string extradata_name = "vorbis-extradata";
  base::FilePath extradata_path = media::GetTestDataFilePath(extradata_name);
  std::optional<int64_t> tmp = base::GetFileSize(extradata_path);
  CHECK(tmp.has_value()) << "Failed to get file size for '" << extradata_name
                         << "'";
  int file_size = base::checked_cast<int>(tmp.value());
  std::vector<uint8_t> extradata(file_size);
  CHECK_EQ(file_size,
           base::ReadFile(extradata_path,
                          reinterpret_cast<char*>(&extradata[0]), file_size))
      << "Failed to read '" << extradata_name << "'";

  return media::AudioDecoderConfig(kCodec, kSampleFormat, kChannelLayout,
                                   kSamplesPerSecond, std::move(extradata),
                                   media::EncryptionScheme::kUnencrypted);
}

TEST_F(AudioDecoderBrokerTest, Decode_NoMojoDecoder) {
  V8TestingScope v8_scope;

  ConstructDecoder(*v8_scope.GetExecutionContext());
  EXPECT_EQ(GetDecoderType(), media::AudioDecoderType::kBroker);

  InitializeDecoder(MakeVorbisConfig());
  EXPECT_EQ(GetDecoderType(), media::AudioDecoderType::kFFmpeg);

  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-0", base::Milliseconds(0)));
  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-1", base::Milliseconds(1)));
  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-2", base::Milliseconds(2)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  // 2, not 3, because the first frame doesn't generate an output.
  ASSERT_EQ(2U, output_buffers_.size());

  ResetDecoder();

  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-0", base::Milliseconds(0)));
  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-1", base::Milliseconds(1)));
  DecodeBuffer(
      media::ReadTestDataFile("vorbis-packet-2", base::Milliseconds(2)));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  // 2 more than last time.
  ASSERT_EQ(4U, output_buffers_.size());

  ResetDecoder();
}

#if BUILDFLAG(ENABLE_MOJO_AUDIO_DECODER)
TEST_F(AudioDecoderBrokerTest, Decode_WithMojoDecoder) {
  V8TestingScope v8_scope;
  ExecutionContext* execution_context = v8_scope.GetExecutionContext();

  SetupMojo(*execution_context);
  ConstructDecoder(*execution_context);
  EXPECT_EQ(GetDecoderType(), media::AudioDecoderType::kBroker);
  EXPECT_FALSE(IsPlatformDecoder());
  EXPECT_FALSE(SupportsDecryption());

  // Use an MpegH config to prevent FFmpeg from being selected.
  InitializeDecoder(media::AudioDecoderConfig(
      media::AudioCodec::kMpegHAudio, kSampleFormat, kChannelLayout,
      kSamplesPerSecond, media::EmptyExtraData(),
      media::EncryptionScheme::kUnencrypted));
  EXPECT_EQ(GetDecoderType(), media::AudioDecoderType::kTesting);

  // Using vorbis buffer here because its easy and the fake decoder generates
  // output regardless of the input details.
  DecodeBuffer(media::ReadTestDataFile("vorbis-packet-0"));
  DecodeBuffer(media::DecoderBuffer::CreateEOSBuffer());
  // Our fake decoder immediately generates output for any input.
  ASSERT_EQ(1U, output_buffers_.size());

  // True for MojoAudioDecoder.
  EXPECT_TRUE(IsPlatformDecoder());
  // True for for MojoVideoDecoder on Android, but WebCodecs doesn't do
  // decryption, so this is hard-coded to false.
  EXPECT_FALSE(SupportsDecryption());

  ResetDecoder();
}
#endif  // BUILDFLAG(ENABLE_MOJO_AUDIO_DECODER)
}  // namespace blink

"""

```
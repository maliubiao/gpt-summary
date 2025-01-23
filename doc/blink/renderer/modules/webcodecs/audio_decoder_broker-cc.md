Response:
Let's break down the thought process for analyzing this `audio_decoder_broker.cc` file. The request is quite comprehensive, asking for functionality, relationships to web technologies, logical inferences, common errors, and debugging information. Here's a possible thought process:

1. **Understand the Core Purpose:** The filename `audio_decoder_broker.cc` immediately suggests a component responsible for managing audio decoding. The `Broker` part implies it's not doing the direct decoding itself, but rather coordinating or delegating it. The namespace `blink::webcodecs` confirms it's part of the WebCodecs API implementation within the Blink rendering engine.

2. **Identify Key Classes and Structures:**  Scan the file for class definitions and significant data structures. We see `AudioDecoderBroker` (the main class), `MediaAudioTaskWrapper`, and `DecoderDetails`. These are likely central to the file's operation.

3. **Analyze `AudioDecoderBroker`:** This is the entry point, so start here. Look at its public methods:
    * `AudioDecoderBroker` (constructor/destructor): Handles initialization and cleanup, likely involving thread management.
    * `GetDecoderType`, `IsPlatformDecoder`, `NeedsBitstreamConversion`: Provide information about the selected decoder.
    * `Initialize`:  Sets up the decoder with configuration. Note the callbacks (`InitCB`, `OutputCB`, `WaitingCB`).
    * `Decode`:  Sends data for decoding. Takes a `DecodeCB`.
    * `Reset`: Resets the decoder. Takes a `OnceClosure`.
    * `OnInitialize`, `OnDecodeDone`, `OnReset`, `OnDecodeOutput`: These look like callbacks from the decoding process.
    * `CreateCallbackId`:  Manages unique IDs for asynchronous operations.

4. **Analyze `MediaAudioTaskWrapper`:** This class seems crucial for managing the decoding process on a separate thread. Notice:
    * It's constructed on the main thread but operates primarily on `media_task_runner_`. This suggests cross-thread communication.
    * Methods like `Initialize`, `Decode`, and `Reset` mirror those in `AudioDecoderBroker`, implying delegation.
    * `BindOnTaskRunner` handles setting up Mojo communication on the media thread.
    * `OnCreateDecoders` and `OnDecoderSelected` deal with selecting the actual decoder implementation.
    * `OnDecodeOutput`, `OnDecodeDone`, `OnReset` are callbacks to the main thread.

5. **Trace Data Flow and Threading:**  Observe how data and control flow between the main thread and the media thread.
    * `AudioDecoderBroker` (main thread) receives calls from the WebCodecs API.
    * It creates `MediaAudioTaskWrapper` and posts tasks to `media_task_runner_`.
    * `MediaAudioTaskWrapper` performs decoder selection and interacts with the actual decoder.
    * Results are sent back to `AudioDecoderBroker` on the main thread via callbacks.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):** Consider how this fits into the Web platform.
    * **JavaScript:**  The WebCodecs API is exposed to JavaScript. The `AudioDecoder` interface in JS would use this broker internally. Think about how a JS developer would use the `decode()` method and how that maps to the C++ `Decode`.
    * **HTML:**  The `<audio>` or `<video>` elements might indirectly trigger this if WebCodecs is used for playback. The `src` attribute or Media Source Extensions (MSE) could lead to decoding.
    * **CSS:** CSS has no direct relationship to audio decoding.

7. **Logical Inferences and Assumptions:**  Look for areas where the code makes decisions or handles different scenarios.
    * **Decoder Selection:** The `WebCodecsAudioDecoderSelector` suggests a mechanism to choose the best decoder based on the configuration. Assume it considers factors like codec, platform support, and performance.
    * **Error Handling:** The use of `media::DecoderStatus` indicates a way to communicate decoding errors.
    * **Asynchronous Operations:** The callbacks and `pending_decode_cb_map_`/`pending_reset_cb_map_` clearly show asynchronous behavior.

8. **Identify Potential User/Programming Errors:** Think about how a developer might misuse the WebCodecs API or how the browser implementation might have flaws.
    * **Incorrect Configuration:** Providing an unsupported audio configuration would lead to decoder selection failure.
    * **Decoding Before Initialization:** Calling `decode()` before `initialize()` would result in an error.
    * **Resource Management:**  Not properly handling `DecoderBuffer` objects could lead to issues.

9. **Consider Debugging:** How would a developer or browser engineer track down issues?
    * **Breakpoints:**  Setting breakpoints in `AudioDecoderBroker::Decode`, `MediaAudioTaskWrapper::Decode`, and the callback functions would be useful.
    * **Logging:** The `DVLOG` statements are crucial for tracing execution.
    * **Tracing Tools:** Chromium's tracing infrastructure could be used to visualize the interaction between threads.

10. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: Functionality, Relationships to Web Technologies, Logical Inferences, User Errors, and Debugging. Use clear and concise language, and provide concrete examples where possible.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have focused too much on the Mojo details, but the prompt emphasizes the connection to higher-level web technologies. Refining would involve balancing the technical details with the user-facing implications.

By following this thought process, we can systematically analyze the code and address all aspects of the request effectively. The key is to move from the general purpose to the specific details, while constantly connecting the code back to its role within the larger web platform.
好的，让我们来分析一下 `blink/renderer/modules/webcodecs/audio_decoder_broker.cc` 这个文件。

**文件功能概述:**

`AudioDecoderBroker` 的主要功能是作为 WebCodecs API 中音频解码器的代理或中介。它负责以下关键任务：

1. **管理音频解码器的生命周期:**  包括解码器的创建、初始化、解码、重置和销毁。
2. **选择合适的音频解码器:**  根据提供的音频配置（例如，编解码器、采样率等），它会选择一个合适的解码器来处理解码任务。这个选择过程可能涉及到硬件加速解码器的偏好。
3. **跨线程管理解码操作:** 音频解码是一个计算密集型任务，通常在独立的线程上执行，以避免阻塞浏览器的主线程。`AudioDecoderBroker` 负责将解码任务调度到专门的媒体线程，并管理与该线程的通信。
4. **处理解码回调:** 当解码器完成解码操作后，`AudioDecoderBroker` 会接收解码后的音频数据，并通过回调函数将其传递给 WebCodecs API 的调用者（通常是 JavaScript 代码）。
5. **处理错误和状态更新:** 它负责接收和传递解码过程中出现的错误信息和状态更新。

**与 JavaScript, HTML, CSS 的关系：**

`AudioDecoderBroker` 是 WebCodecs API 的底层实现部分，因此它与 JavaScript 有着直接的关系。HTML 和 CSS 本身不直接与音频解码过程交互，但它们可以触发需要音频解码的场景。

* **JavaScript:**
    * **直接交互:**  JavaScript 代码通过 `AudioDecoder` 接口来使用音频解码功能。当 JavaScript 调用 `AudioDecoder.decode()` 方法时，最终会触发 `AudioDecoderBroker::Decode()` 方法。
    * **WebCodecs API:**  `AudioDecoderBroker` 是 `blink` 引擎中实现 WebCodecs API 的关键组件之一。JavaScript 使用的 `AudioDecoder` 对象在底层会与 `AudioDecoderBroker` 实例进行交互。

    **举例说明:**

    ```javascript
    const decoder = new AudioDecoder({
      output: (frame) => {
        // 处理解码后的音频帧
        console.log("Decoded audio frame:", frame);
      },
      error: (e) => {
        console.error("Decoder error:", e);
      }
    });

    const config = {
      codec: 'opus',
      sampleRate: 48000,
      numberOfChannels: 2
    };
    decoder.configure(config);

    // encodedAudioData 是包含编码音频数据的 ArrayBuffer
    decoder.decode(encodedAudioData);
    ```

    在这个 JavaScript 例子中：
    1. `new AudioDecoder(...)` 会在 Blink 引擎中创建一个与 `AudioDecoderBroker` 关联的对象。
    2. `decoder.configure(config)` 会导致 `AudioDecoderBroker` 选择并初始化合适的解码器。
    3. `decoder.decode(encodedAudioData)` 会触发 `AudioDecoderBroker::Decode()`，将编码数据传递给选定的解码器进行解码。
    4. `output` 回调函数对应于 `AudioDecoderBroker::OnDecodeOutput()` 将解码后的音频数据传递回 JavaScript。

* **HTML:**
    * **间接触发:** HTML 中的 `<audio>` 或 `<video>` 元素可以播放音频内容。如果这些元素使用了 Media Source Extensions (MSE) 并且 JavaScript 代码通过 MSE 将编码的音频数据送入，那么 `AudioDecoderBroker` 就会被用于解码这些数据。

    **举例说明:**

    一个使用 MSE 的场景，JavaScript 从网络获取音频数据，并通过 `SourceBuffer` 送入 `<audio>` 元素，这个过程中可能用到 WebCodecs API 和 `AudioDecoderBroker`：

    ```html
    <audio id="myAudio" controls></audio>
    <script>
      const audio = document.getElementById('myAudio');
      const mediaSource = new MediaSource();
      audio.src = URL.createObjectURL(mediaSource);

      mediaSource.addEventListener('sourceopen', async () => {
        const sourceBuffer = mediaSource.addSourceBuffer('audio/webm; codecs="opus"');

        // 从网络获取音频数据 (encodedAudioData)
        const response = await fetch('audio.opus');
        const encodedAudioData = await response.arrayBuffer();

        // 这里可能会使用 WebCodecs API 的 AudioDecoder 来解码 'encodedAudioData'
        // 并将解码后的数据送入 SourceBuffer (简化示例，实际可能更复杂)
        // 或者，如果浏览器支持直接解码，MSE 内部可能会使用类似 AudioDecoderBroker 的机制

        sourceBuffer.appendBuffer(encodedAudioData);
      });
    </script>
    ```

* **CSS:**
    * **无直接关系:** CSS 负责页面的样式和布局，与音频解码过程没有直接的功能性关系。

**逻辑推理、假设输入与输出：**

假设输入：

* **`Initialize`:**
    * `config`: 一个 `media::AudioDecoderConfig` 对象，描述了音频的编解码器、采样率、声道数等信息。例如，`{ codec: 'opus', sampleRate: 48000, numberOfChannels: 2 }`。
    * `cdm_context`: 通常为 `nullptr`，因为 WebCodecs 不直接处理加密媒体 (DRM)。
    * `init_cb`: 一个在解码器初始化完成后调用的回调函数。

* **`Decode`:**
    * `buffer`: 一个 `media::DecoderBuffer` 对象，包含了需要解码的编码音频数据。
    * `decode_cb`: 一个在解码完成后调用的回调函数。

假设输出：

* **`Initialize` 完成后:**  `init_cb` 被调用，并传递一个 `media::DecoderStatus` 对象，指示初始化是否成功。如果成功，可能会设置内部状态，以便后续的 `Decode` 调用可以正常工作。
* **`Decode` 完成后:** `decode_cb` 被调用，并传递一个 `media::DecoderStatus` 对象，指示解码是否成功。如果成功，解码后的音频数据会通过 `output_cb_` (在 `Initialize` 中设置) 传递出去。`OnDecodeOutput` 方法会将解码后的 `media::AudioBuffer` 传递给 JavaScript 回调。

**用户或编程常见的使用错误：**

1. **在 `configure` 之前调用 `decode`:**  用户（开发者）需要在调用 `decode` 之前先使用正确的配置调用 `configure` 方法，否则解码器可能未初始化或配置错误。
    * **假设输入:** 直接调用 `decoder.decode(encodedData)` 而没有先调用 `decoder.configure(config)`。
    * **可能结果:** `AudioDecoderBroker::Decode` 中会检查 `decoder_` 是否已初始化，如果未初始化，可能会调用 `OnDecodeDone` 并返回一个表示未初始化的错误状态 (`media::DecoderStatus::Codes::kNotInitialized`)。JavaScript 的 `error` 回调会被触发。

2. **提供不支持的编解码器配置:**  用户提供的音频配置与浏览器支持的解码器不匹配。
    * **假设输入:**  `config = { codec: 'unsupported-codec', ... }`。
    * **可能结果:** 在 `AudioDecoderBroker::Initialize` 中，解码器选择器 (`WebCodecsAudioDecoderSelector`) 可能找不到合适的解码器。`OnDecoderSelected` 会收到一个空的解码器指针，然后 `OnInitialize` 会被调用，并传递一个表示不支持配置的错误状态 (`media::DecoderStatus::Codes::kUnsupportedConfig`)。JavaScript 的 `error` 回调会被触发。

3. **重复调用 `configure` 而没有先销毁或重置解码器:**  虽然代码中没有显式禁止，但这可能导致资源泄漏或意外行为。

4. **在解码过程中销毁 `AudioDecoder` 对象:** 如果 JavaScript 在解码操作进行中就销毁了 `AudioDecoder` 对象，可能会导致回调无法正常执行或出现悬挂指针问题。文件中的 `weak_factory_` 和弱指针 `weak_client_` 用于避免这种情况。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在网页上执行了与音频解码相关的 JavaScript 代码:** 例如，通过 `new AudioDecoder(...)` 创建了一个音频解码器实例，并调用了 `configure` 和 `decode` 方法。

2. **JavaScript 调用触发了 Blink 引擎中的 WebCodecs API 实现:** 当 JavaScript 调用 `decoder.configure(config)`,  会进入到 `blink` 引擎中 `AudioDecoder` 接口的实现。

3. **`AudioDecoder::configure()` 方法创建或获取 `AudioDecoderBroker` 实例:**  `AudioDecoderBroker` 负责实际的解码器管理。

4. **`AudioDecoder::configure()` 调用 `AudioDecoderBroker::Initialize()`:**  将音频配置信息传递给 broker，以便其选择和初始化合适的解码器。

5. **当 JavaScript 调用 `decoder.decode(encodedAudioData)`:**

6. **`AudioDecoder::decode()` 方法调用 `AudioDecoderBroker::Decode()`:** 将编码的音频数据传递给 broker。

7. **`AudioDecoderBroker::Decode()` 将解码任务 पोस्ट 到媒体线程:**  使用 `media_task_runner_` 将实际的解码操作委托给在独立线程上运行的 `MediaAudioTaskWrapper`。

8. **媒体线程上的 `MediaAudioTaskWrapper` 调用底层的音频解码器进行解码。**

9. **解码完成后，底层解码器将解码后的音频数据传递给 `MediaAudioTaskWrapper`。**

10. **`MediaAudioTaskWrapper` 调用 `AudioDecoderBroker::OnDecodeOutput()` (或错误回调)。**

11. **`AudioDecoderBroker::OnDecodeOutput()` 将解码后的数据传递回 JavaScript 的 `output` 回调函数。**

**调试线索:**

* **在 `AudioDecoderBroker` 的关键方法（如 `Initialize`, `Decode`, `OnDecodeOutput`）中设置断点:**  可以跟踪代码的执行流程，查看配置信息、编码数据以及解码后的数据。
* **检查 `media_task_runner_` 上的任务队列:**  查看解码任务是否被正确 पोस्ट 到媒体线程。
* **使用 Chromium 的 `chrome://webrtc-internals` 工具:**  可以查看 WebRTC 和 WebCodecs 相关的内部状态和事件，包括音频解码器的信息。
* **查看控制台输出的错误信息:**  JavaScript 的 `error` 回调函数会输出解码过程中发生的错误信息。
* **使用 `DVLOG` 进行更详细的日志输出:** 开发者可以通过修改代码并重新编译 Chromium 来启用更详细的日志信息，以便深入了解解码过程的细节。

总而言之，`audio_decoder_broker.cc` 是 WebCodecs 音频解码功能的核心组件，它充当 JavaScript API 和底层音频解码器之间的桥梁，负责管理解码器的生命周期和跨线程操作。理解其功能有助于理解 WebCodecs API 的内部工作原理以及排查音频解码相关的问题。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/audio_decoder_broker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/webcodecs/audio_decoder_broker.h"

#include <limits>
#include <memory>
#include <string>

#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "build/buildflag.h"
#include "media/base/audio_decoder_config.h"
#include "media/base/decoder_factory.h"
#include "media/base/media_log.h"
#include "media/mojo/buildflags.h"
#include "media/mojo/clients/mojo_decoder_factory.h"
#include "media/mojo/mojom/interface_factory.mojom.h"
#include "media/renderers/default_decoder_factory.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/modules/webcodecs/decoder_selector.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using DecoderDetails = blink::AudioDecoderBroker::DecoderDetails;

namespace WTF {

template <>
struct CrossThreadCopier<media::AudioDecoderConfig>
    : public CrossThreadCopierPassThrough<media::AudioDecoderConfig> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<media::DecoderStatus>
    : public CrossThreadCopierPassThrough<media::DecoderStatus> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<std::optional<DecoderDetails>>
    : public CrossThreadCopierPassThrough<std::optional<DecoderDetails>> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

// Wrapper class for state and API calls that must be made from the
// |media_task_runner_|. Construction must happen on blink main thread to safely
// make use of ExecutionContext and Document. These GC blink types must not be
// stored/referenced by any other method.
class MediaAudioTaskWrapper {
 public:
  using CrossThreadOnceInitCB =
      WTF::CrossThreadOnceFunction<void(media::DecoderStatus status,
                                        std::optional<DecoderDetails>)>;
  using CrossThreadOnceDecodeCB =
      WTF::CrossThreadOnceFunction<void(media::DecoderStatus)>;
  using CrossThreadOnceResetCB = WTF::CrossThreadOnceClosure;

  MediaAudioTaskWrapper(
      base::WeakPtr<CrossThreadAudioDecoderClient> weak_client,
      ExecutionContext& execution_context,
      std::unique_ptr<media::MediaLog> media_log,
      scoped_refptr<base::SequencedTaskRunner> media_task_runner,
      scoped_refptr<base::SequencedTaskRunner> main_task_runner)
      : weak_client_(std::move(weak_client)),
        media_task_runner_(std::move(media_task_runner)),
        main_task_runner_(std::move(main_task_runner)),
        media_log_(std::move(media_log)) {
    DVLOG(2) << __func__;
    DETACH_FROM_SEQUENCE(sequence_checker_);

    // TODO(chcunningham): set_disconnect_handler?
    // Mojo connection setup must occur here on the main thread where its safe
    // to use |execution_context| APIs.
    mojo::PendingRemote<media::mojom::InterfaceFactory> media_interface_factory;
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        media_interface_factory.InitWithNewPipeAndPassReceiver());

    // Mojo remote must be bound on media thread where it will be used.
    //|Unretained| is safe because |this| must be destroyed on the media task
    // runner.
    PostCrossThreadTask(
        *media_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&MediaAudioTaskWrapper::BindOnTaskRunner,
                                 WTF::CrossThreadUnretained(this),
                                 std::move(media_interface_factory)));
  }

  virtual ~MediaAudioTaskWrapper() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  }

  MediaAudioTaskWrapper(const MediaAudioTaskWrapper&) = delete;
  MediaAudioTaskWrapper& operator=(const MediaAudioTaskWrapper&) = delete;

  void Initialize(const media::AudioDecoderConfig& config) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    selector_ = std::make_unique<WebCodecsAudioDecoderSelector>(
        media_task_runner_,
        // TODO(chcunningham): Its ugly that we don't use a WeakPtr here, but
        // its not possible because the callback returns non-void. It happens
        // to be safe given the way the callback is called (never posted), but
        // we should refactor the return to be an out-param so we can be
        // consistent in using weak pointers.
        WTF::BindRepeating(&MediaAudioTaskWrapper::OnCreateDecoders,
                           WTF::Unretained(this)),
        WTF::BindRepeating(&MediaAudioTaskWrapper::OnDecodeOutput,
                           weak_factory_.GetWeakPtr()));

    selector_->SelectDecoder(
        config, /*low_delay=*/false,
        WTF::BindOnce(&MediaAudioTaskWrapper::OnDecoderSelected,
                      weak_factory_.GetWeakPtr()));
  }

  void Decode(scoped_refptr<media::DecoderBuffer> buffer, int cb_id) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    if (!decoder_) {
      OnDecodeDone(cb_id, media::DecoderStatus::Codes::kNotInitialized);
      return;
    }

    decoder_->Decode(std::move(buffer),
                     WTF::BindOnce(&MediaAudioTaskWrapper::OnDecodeDone,
                                   weak_factory_.GetWeakPtr(), cb_id));
  }

  void Reset(int cb_id) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    if (!decoder_) {
      OnReset(cb_id);
      return;
    }

    decoder_->Reset(WTF::BindOnce(&MediaAudioTaskWrapper::OnReset,
                                  weak_factory_.GetWeakPtr(), cb_id));
  }

 private:
  void BindOnTaskRunner(
      mojo::PendingRemote<media::mojom::InterfaceFactory> interface_factory) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    media_interface_factory_.Bind(std::move(interface_factory));

    // Bind the |interface_factory_| above before passing to
    // |external_decoder_factory|.
    std::unique_ptr<media::DecoderFactory> external_decoder_factory;
#if BUILDFLAG(ENABLE_MOJO_AUDIO_DECODER)
    external_decoder_factory = std::make_unique<media::MojoDecoderFactory>(
        media_interface_factory_.get());
#endif
    decoder_factory_ = std::make_unique<media::DefaultDecoderFactory>(
        std::move(external_decoder_factory));
  }

  std::vector<std::unique_ptr<media::AudioDecoder>> OnCreateDecoders() {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    std::vector<std::unique_ptr<media::AudioDecoder>> audio_decoders;
    decoder_factory_->CreateAudioDecoders(media_task_runner_, media_log_.get(),
                                          &audio_decoders);

    return audio_decoders;
  }

  void OnDecoderSelected(std::unique_ptr<media::AudioDecoder> decoder) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    // We're done with it.
    DCHECK(selector_);
    selector_.reset();

    decoder_ = std::move(decoder);

    media::DecoderStatus status = media::DecoderStatus::Codes::kOk;
    std::optional<DecoderDetails> decoder_details = std::nullopt;
    if (decoder_) {
      decoder_details = DecoderDetails({decoder_->GetDecoderType(),
                                        decoder_->IsPlatformDecoder(),
                                        decoder_->NeedsBitstreamConversion()});
    } else {
      status = media::DecoderStatus::Codes::kUnsupportedConfig;
    }

    // Fire |init_cb|.
    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadAudioDecoderClient::OnInitialize,
                                 weak_client_, status, decoder_details));
  }

  void OnDecodeOutput(scoped_refptr<media::AudioBuffer> buffer) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadAudioDecoderClient::OnDecodeOutput,
                                 weak_client_, std::move(buffer)));
  }

  void OnDecodeDone(int cb_id, media::DecoderStatus status) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadAudioDecoderClient::OnDecodeDone,
                                 weak_client_, cb_id, std::move(status)));
  }

  void OnReset(int cb_id) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadAudioDecoderClient::OnReset,
                                 weak_client_, cb_id));
  }

  base::WeakPtr<CrossThreadAudioDecoderClient> weak_client_;
  scoped_refptr<base::SequencedTaskRunner> media_task_runner_;
  scoped_refptr<base::SequencedTaskRunner> main_task_runner_;
  mojo::Remote<media::mojom::InterfaceFactory> media_interface_factory_;
  std::unique_ptr<WebCodecsAudioDecoderSelector> selector_;
  std::unique_ptr<media::DefaultDecoderFactory> decoder_factory_;
  std::unique_ptr<media::AudioDecoder> decoder_;
  gfx::ColorSpace target_color_space_;

  std::unique_ptr<media::MediaLog> media_log_;

  SEQUENCE_CHECKER(sequence_checker_);

  // Using unretained for decoder/selector callbacks is generally not safe /
  // fragile. Some decoders (e.g. those that offload) will call the output
  // callback after destruction.
  base::WeakPtrFactory<MediaAudioTaskWrapper> weak_factory_{this};
};

AudioDecoderBroker::AudioDecoderBroker(media::MediaLog* media_log,
                                       ExecutionContext& execution_context)
    // Use a worker task runner to avoid scheduling decoder
    // work on the main thread.
    : media_task_runner_(worker_pool::CreateSequencedTaskRunner({})) {
  DVLOG(2) << __func__;
  media_tasks_ = std::make_unique<MediaAudioTaskWrapper>(
      weak_factory_.GetWeakPtr(), execution_context, media_log->Clone(),
      media_task_runner_,
      execution_context.GetTaskRunner(TaskType::kInternalMedia));
}

AudioDecoderBroker::~AudioDecoderBroker() {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  media_task_runner_->DeleteSoon(FROM_HERE, std::move(media_tasks_));
}

media::AudioDecoderType AudioDecoderBroker::GetDecoderType() const {
  return decoder_details_ ? decoder_details_->decoder_type
                          : media::AudioDecoderType::kBroker;
}

bool AudioDecoderBroker::IsPlatformDecoder() const {
  return decoder_details_ ? decoder_details_->is_platform_decoder : false;
}

void AudioDecoderBroker::Initialize(const media::AudioDecoderConfig& config,
                                    media::CdmContext* cdm_context,
                                    InitCB init_cb,
                                    const OutputCB& output_cb,
                                    const media::WaitingCB& waiting_cb) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!init_cb_) << "Initialize already pending";

  // The following are not currently supported in WebCodecs.
  DCHECK(!cdm_context);
  DCHECK(!waiting_cb);

  init_cb_ = std::move(init_cb);
  output_cb_ = output_cb;

  // Clear details from previously initialized decoder. New values will arrive
  // via OnInitialize().
  decoder_details_.reset();

  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaAudioTaskWrapper::Initialize,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               config));
}

int AudioDecoderBroker::CreateCallbackId() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // 0 and -1 are reserved by wtf::HashMap ("empty" and "deleted").
  while (++last_callback_id_ == 0 ||
         last_callback_id_ == std::numeric_limits<uint32_t>::max() ||
         pending_decode_cb_map_.Contains(last_callback_id_) ||
         pending_reset_cb_map_.Contains(last_callback_id_))
    ;

  return last_callback_id_;
}

void AudioDecoderBroker::OnInitialize(media::DecoderStatus status,
                                      std::optional<DecoderDetails> details) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  decoder_details_ = details;
  std::move(init_cb_).Run(status);
}

void AudioDecoderBroker::Decode(scoped_refptr<media::DecoderBuffer> buffer,
                                DecodeCB decode_cb) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const int callback_id = CreateCallbackId();
  pending_decode_cb_map_.insert(callback_id, std::move(decode_cb));

  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaAudioTaskWrapper::Decode,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               buffer, callback_id));
}

void AudioDecoderBroker::OnDecodeDone(int cb_id, media::DecoderStatus status) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(pending_decode_cb_map_.Contains(cb_id));

  auto iter = pending_decode_cb_map_.find(cb_id);
  DecodeCB decode_cb = std::move(iter->value);
  pending_decode_cb_map_.erase(cb_id);

  // Do this last. Caller may destruct |this| in response to the callback while
  // this method is still on the stack.
  std::move(decode_cb).Run(std::move(status));
}

void AudioDecoderBroker::Reset(base::OnceClosure reset_cb) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const int callback_id = CreateCallbackId();
  pending_reset_cb_map_.insert(callback_id, std::move(reset_cb));

  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaAudioTaskWrapper::Reset,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               callback_id));
}

bool AudioDecoderBroker::NeedsBitstreamConversion() const {
  // No known scenarios where this is needed by WebCodecs. See
  // https://crbug.com/1119947
  DCHECK(!decoder_details_ || !decoder_details_->needs_bitstream_conversion);

  return decoder_details_ ? decoder_details_->needs_bitstream_conversion
                          : false;
}

void AudioDecoderBroker::OnReset(int cb_id) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(pending_reset_cb_map_.Contains(cb_id));

  auto iter = pending_reset_cb_map_.find(cb_id);
  base::OnceClosure reset_cb = std::move(iter->value);
  pending_reset_cb_map_.erase(cb_id);

  // Do this last. Caller may destruct |this| in response to the callback while
  // this method is still on the stack.
  std::move(reset_cb).Run();
}

void AudioDecoderBroker::OnDecodeOutput(
    scoped_refptr<media::AudioBuffer> buffer) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(output_cb_);

  output_cb_.Run(std::move(buffer));
}

}  // namespace blink
```
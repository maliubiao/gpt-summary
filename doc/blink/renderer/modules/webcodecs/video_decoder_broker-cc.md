Response:
Let's break down the request and the provided code to construct a comprehensive answer.

**1. Understanding the Core Task:**

The request asks for an analysis of `video_decoder_broker.cc`. Specifically, it wants to know its function, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user errors, and a debugging path.

**2. Initial Code Scan and Key Components Identification:**

My first pass at the code identifies these key elements:

* **Headers:**  A lot of Chromium and media-related headers (`media/base/...`, `media/mojo/...`, etc.) indicating this is a low-level component interacting with the browser's media pipeline.
* **Namespaces:** `blink` and `WTF`. `blink` signifies the rendering engine, and `WTF` (Web Template Framework) points to foundational utilities.
* **`VideoDecoderBroker` Class:** This is the central class, suggesting its role is to manage video decoding.
* **`MediaVideoTaskWrapper` Class:**  This nested class hints at managing tasks on a separate thread (likely the media thread). The cross-thread communication mechanisms are evident in its methods and member variables.
* **Callbacks and Futures:** The use of `OnceCallback`, `RepeatingCallback`, and the `InitCB`, `DecodeCB`, `OutputCB` types suggests asynchronous operations and communication with other parts of the system.
* **`media::VideoDecoderConfig`, `media::DecoderBuffer`, `media::VideoFrame`:** These are core media types indicating the handling of video data.
* **`WebCodecsVideoDecoderSelector`:**  This points to a mechanism for choosing the appropriate video decoder.
* **Hardware Preference:** The `HardwarePreference` enum and related logic suggest control over whether hardware or software decoding is preferred.
* **Mojo Integration:** The presence of `media::mojom::InterfaceFactory` and related code indicates interaction with other processes or components via Mojo, Chromium's inter-process communication system.
* **Threading:**  The extensive use of `scoped_refptr<base::SequencedTaskRunner>` and `PostCrossThreadTask` confirms the involvement of multiple threads.

**3. Functionality Deduction:**

Based on the identified components, I can infer the following main functions:

* **Abstraction Layer:** The `VideoDecoderBroker` acts as an intermediary between the higher-level WebCodecs API and the lower-level video decoding infrastructure.
* **Decoder Selection:**  It uses `WebCodecsVideoDecoderSelector` to choose the best decoder based on the video configuration and hardware preferences.
* **Thread Management:**  It handles the complexity of executing decoding tasks on the media thread while interacting with the main Blink thread.
* **Mojo Communication:**  It communicates with the browser process or other services via Mojo to obtain decoder factories.
* **Hardware Acceleration Control:** It allows for specifying a preference for hardware or software decoding.
* **Asynchronous Operations:** It manages the asynchronous nature of decoding through callbacks.
* **Resource Management:**  It manages the lifecycle of the underlying `media::VideoDecoder`.

**4. Relationship to Web Technologies:**

This is where I connect the backend code to the frontend:

* **JavaScript:** The `VideoDecoderBroker` is part of the implementation for the WebCodecs API, which is directly accessible from JavaScript. I need to provide an example of how a JavaScript application would use `VideoDecoder`.
* **HTML:**  While not directly involved in rendering, video decoding is essential for the `<video>` element. WebCodecs can be used to process video data before or after it's displayed in a `<video>` element.
* **CSS:** CSS indirectly relates to video through styling the `<video>` element. However, the `VideoDecoderBroker` itself doesn't directly interact with CSS.

**5. Logical Reasoning and Examples:**

I look for conditional logic and data transformations. The `Initialize` method with decoder selection is a prime example. I need to create a scenario with different input configurations and predict the output (which decoder is selected). The hardware preference logic is another good example.

**6. Common User/Programming Errors:**

This requires thinking about how developers might misuse the WebCodecs API or how the underlying asynchronous nature can lead to errors. Incorrect configuration, forgetting to handle errors, and improper sequencing of calls are typical issues.

**7. Debugging Clues:**

I need to trace the execution flow, starting from a user action. The journey from a JavaScript `decode()` call to the `VideoDecoderBroker::Decode()` method and its subsequent interactions with the media thread is crucial.

**8. Structuring the Answer:**

Finally, I organize the information into logical sections, using headings and bullet points for clarity. I ensure the language is precise and avoids overly technical jargon where possible, while still being accurate. I incorporate the specific request elements like "if it relates to...", "if logical reasoning...", etc. to ensure all aspects are addressed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the Mojo details. **Correction:**  Balance the Mojo aspects with the broader functionality and its connection to WebCodecs.
* **Initial thought:**  Provide very low-level C++ debugging steps. **Correction:**  Focus on the user's perspective and how they trigger the code, providing a higher-level debugging path.
* **Initial thought:**  Overcomplicate the logical reasoning examples. **Correction:**  Keep the examples simple and illustrate the core decision-making processes.
* **Initial thought:**  Assume the user is deeply familiar with Chromium internals. **Correction:** Explain concepts like Mojo and task runners briefly for better understanding.

By following these steps and constantly refining my understanding of the code and the request, I can produce a comprehensive and helpful answer.
好的，让我们来分析一下 `blink/renderer/modules/webcodecs/video_decoder_broker.cc` 这个 Chromium Blink 引擎的源代码文件。

**功能概述:**

`VideoDecoderBroker` 的主要功能是作为 WebCodecs API 中 `VideoDecoder` 的一个中间层或代理。它负责以下关键任务：

1. **解码器选择和创建：** 它使用 `WebCodecsVideoDecoderSelector` 来选择合适的底层视频解码器实现。这可能涉及到选择硬件加速解码器或软件解码器。
2. **线程管理：**  视频解码操作通常需要在独立的线程上执行，以避免阻塞 Blink 主线程。`VideoDecoderBroker` 管理将解码任务调度到媒体线程 (`media_task_runner_`) 上执行。
3. **跨线程通信：** 它负责在 Blink 主线程和媒体线程之间传递解码请求、解码结果以及其他控制信息。
4. **解码器生命周期管理：**  它管理底层视频解码器的初始化、解码、重置和销毁。
5. **硬件加速控制：**  它允许设置硬件加速的偏好（例如，优先使用硬件解码器）。
6. **错误处理：**  它处理解码过程中可能出现的错误，并将错误状态报告给上层。
7. **与 Media Pipeline 集成：** 它与 Chromium 的媒体管道集成，以便使用底层的解码能力。

**与 JavaScript, HTML, CSS 的关系：**

`VideoDecoderBroker` 本身不是直接由 JavaScript、HTML 或 CSS 代码调用的。相反，它是 WebCodecs API 的底层实现部分，而 WebCodecs API 才是可以直接从 JavaScript 访问的。

* **JavaScript:**  JavaScript 代码通过 `VideoDecoder` 接口与 `VideoDecoderBroker` 间接交互。

   **例子：**  假设以下 JavaScript 代码创建并使用了一个 `VideoDecoder`:

   ```javascript
   const decoder = new VideoDecoder({
     output: (frame) => {
       // 处理解码后的视频帧
       console.log('Decoded frame:', frame);
       frame.close();
     },
     error: (e) => {
       console.error('Decoder error:', e);
     }
   });

   const config = {
     codec: 'vp8',
     // ... 其他配置
   };
   decoder.configure(config);

   // 接收到视频数据
   const chunk = new EncodedVideoChunk({
     type: 'key',
     timestamp: 0,
     duration: 1000,
     data: videoData // Uint8Array 包含编码的视频数据
   });
   decoder.decode(chunk);
   ```

   当 JavaScript 调用 `decoder.configure(config)` 时，Blink 引擎内部会创建 `VideoDecoderBroker` 的实例，并调用其 `Initialize` 方法，将解码配置传递给它。当 JavaScript 调用 `decoder.decode(chunk)` 时，会调用 `VideoDecoderBroker` 的 `Decode` 方法，将编码后的视频数据传递给它，并将其调度到媒体线程进行解码。解码完成后，解码后的帧数据会通过回调传递回 JavaScript。

* **HTML:** HTML 通过 `<video>` 元素与视频解码间接相关。虽然 `VideoDecoderBroker` 不直接处理 `<video>` 元素，但 WebCodecs API 可以用来处理视频数据，然后将处理后的帧渲染到 `<canvas>` 或其他上下文中，或者可以用于修改 `<video>` 元素的播放行为。

   **例子：**  一个使用 WebCodecs 处理视频帧并将结果绘制到 canvas 的场景：

   ```html
   <!DOCTYPE html>
   <html>
   <head>
     <title>WebCodecs Example</title>
   </head>
   <body>
     <video id="myVideo" src="my-video.mp4" controls></video>
     <canvas id="myCanvas" width="640" height="480"></canvas>
     <script>
       const video = document.getElementById('myVideo');
       const canvas = document.getElementById('myCanvas');
       const ctx = canvas.getContext('2d');

       video.onplay = async () => {
         const reader = video.captureStream().getVideoTracks()[0].getReader();
         const decoder = new VideoDecoder({
           output: (frame) => {
             ctx.drawImage(frame, 0, 0);
             frame.close();
           },
           error: (e) => {
             console.error('Decoder error:', e);
           }
         });

         const config = {
           codec: 'avc1.42E01E', // 假设视频是 H.264 编码
           codedWidth: video.videoWidth,
           codedHeight: video.videoHeight
         };
         decoder.configure(config);

         while (true) {
           const { value, done } = await reader.read();
           if (done) break;
           decoder.decode(value);
         }
       };
     </script>
   </body>
   </html>
   ```
   在这个例子中，JavaScript 代码使用了 `VideoDecoder` 来解码从 `<video>` 元素捕获的视频帧，并将解码后的帧绘制到 canvas 上。 `VideoDecoderBroker` 在幕后处理实际的解码操作。

* **CSS:** CSS 主要负责样式和布局，与 `VideoDecoderBroker` 没有直接的功能关联。

**逻辑推理的例子：**

假设输入以下配置和编码数据：

* **输入配置 (`media::VideoDecoderConfig`)：**
    * `codec`: `vp9`
    * `profile`: `PROFILE_MAIN`
    * `coded_size`: `640x480`
    * `color_space`: `BT709`
    * `hardware_preference`: `kPreferHardware` (假设在 JavaScript 中设置了硬件加速偏好)

* **假设解码器选择逻辑：** `WebCodecsVideoDecoderSelector` 会根据配置和系统能力选择最佳解码器。如果系统支持 VP9 硬件解码，且 `hardware_preference` 设置为 `kPreferHardware`，则会优先选择硬件解码器。

* **输出 (`std::optional<DecoderDetails>`)：**

   如果成功选择了硬件 VP9 解码器，`OnInitialize` 回调函数可能会收到如下 `DecoderDetails`:

   ```
   DecoderDetails({
       decoder_id: media::VideoDecoderType::kVpx, // 或其他表示硬件 VP9 解码器的类型
       is_platform_decoder: true,
       needs_bitstream_conversion: false,
       max_decode_requests: 16 // 假设硬件解码器支持更高的并行解码请求
   })
   ```

   如果由于某种原因（例如，硬件不支持）无法选择硬件解码器，可能会选择软件解码器：

   ```
   DecoderDetails({
       decoder_id: media::VideoDecoderType::kVpx, // 可能仍然是 VPX，但表示软件实现
       is_platform_decoder: false,
       needs_bitstream_conversion: false,
       max_decode_requests: 4 // 假设软件解码器并行度较低
   })
   ```

   如果完全不支持 VP9 解码，`OnInitialize` 回调函数的 `status` 参数将指示错误，并且 `details` 可能为空。

**用户或编程常见的使用错误：**

1. **配置不正确的解码器：**  JavaScript 代码提供的 `VideoDecoderConfig` 与实际的视频流不匹配，例如 `codec` 字段错误，导致解码器初始化失败。

   **例子：**  视频流实际上是 H.264 编码，但 JavaScript 代码配置 `codec: 'vp8'`。`VideoDecoderBroker` 在尝试选择解码器时会找不到匹配的解码器，导致初始化失败。

2. **过早调用 `decode()`：**  在 `VideoDecoder` 完成配置之前（即 `configure()` 方法的回调尚未触发），就调用 `decode()` 方法，可能导致解码器尚未初始化完成，从而引发错误。

3. **忘记处理错误回调：**  JavaScript 代码没有正确实现 `error` 回调函数，导致解码过程中发生的错误被忽略，应用程序无法正确处理解码失败的情况。

4. **资源管理不当：**  解码后的 `VideoFrame` 对象需要调用 `close()` 方法来释放资源。如果 JavaScript 代码忘记调用 `frame.close()`，可能会导致内存泄漏。

5. **在不支持的平台上使用硬件加速：**  JavaScript 代码强制使用硬件加速，但在当前平台上硬件解码器不可用，导致解码失败。`VideoDecoderBroker` 会尝试回退到软件解码，但如果软件解码器也存在问题，则会失败。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户打开一个包含使用 WebCodecs 的网页：** 用户在浏览器中访问一个网页，该网页的 JavaScript 代码使用了 `VideoDecoder` API 来解码视频数据。

2. **JavaScript 创建 `VideoDecoder` 实例：** 网页的 JavaScript 代码执行，创建了一个 `VideoDecoder` 对象，并设置了 `output` 和 `error` 回调函数。

3. **JavaScript 调用 `decoder.configure(config)`：**  JavaScript 代码使用特定的配置参数调用 `configure` 方法。这会触发 Blink 内部创建一个 `VideoDecoderBroker` 实例，并将配置信息传递给它。

4. **`VideoDecoderBroker` 进行解码器选择：** `VideoDecoderBroker` 使用 `WebCodecsVideoDecoderSelector`，根据配置和系统能力选择合适的底层视频解码器。这可能涉及到与浏览器进程或 GPU 进程的通信。

5. **`VideoDecoderBroker` 初始化选定的解码器：**  一旦选择了解码器，`VideoDecoderBroker` 会在媒体线程上初始化该解码器。

6. **JavaScript 接收到编码的视频数据：**  网页通过网络或其他方式接收到编码的视频数据，并将其封装成 `EncodedVideoChunk` 对象。

7. **JavaScript 调用 `decoder.decode(chunk)`：**  JavaScript 代码将编码的视频块传递给 `VideoDecoder` 的 `decode` 方法。

8. **`VideoDecoderBroker` 将解码请求发送到媒体线程：**  `VideoDecoderBroker` 将解码请求和编码数据发送到媒体线程，在媒体线程上实际的解码器会处理这些数据。

9. **底层解码器执行解码操作：**  媒体线程上的解码器执行解码操作，生成解码后的视频帧。

10. **解码后的帧通过回调返回到 Blink 主线程：**  解码后的视频帧数据被传递回 Blink 主线程。

11. **Blink 主线程调用 JavaScript 的 `output` 回调：** Blink 主线程执行 JavaScript 代码中 `VideoDecoder` 构造函数中提供的 `output` 回调函数，并将解码后的 `VideoFrame` 对象作为参数传递给它。

12. **JavaScript 处理解码后的帧：**  JavaScript 代码在 `output` 回调函数中处理解码后的视频帧，例如将其绘制到 canvas 上或进行其他操作。

**调试线索：**

* **断点设置：** 在 `VideoDecoderBroker` 的关键方法（例如 `Initialize`、`Decode`、`OnInitialize`、`OnDecodeDone`）设置断点，可以跟踪解码请求的流向和状态。
* **日志输出：**  查看 Chromium 的日志输出（例如使用 `--enable-logging=stderr --vmodule=*media*=2,*webcodecs*=2` 启动浏览器），可以了解解码器选择过程、错误信息等。
* **WebCodecs API 的事件监听：**  在 JavaScript 代码中监听 `VideoDecoder` 的 `error` 事件，可以捕获解码过程中发生的错误。
* **DevTools 的性能面板：** 使用 Chrome DevTools 的性能面板可以查看解码操作在不同线程上的执行情况，以及是否存在性能瓶颈。
* **检查 `chrome://media-internals`：** 这个页面提供了关于媒体管道的详细信息，包括解码器的状态、配置和统计信息。

希望以上分析能够帮助你理解 `blink/renderer/modules/webcodecs/video_decoder_broker.cc` 的功能以及它在 WebCodecs API 中的作用。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_decoder_broker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include <limits>
#include <memory>
#include <string>

#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "build/buildflag.h"
#include "media/base/decoder_factory.h"
#include "media/base/decoder_status.h"
#include "media/base/media_util.h"
#include "media/base/video_decoder_config.h"
#include "media/mojo/buildflags.h"
#include "media/mojo/clients/mojo_decoder_factory.h"
#include "media/mojo/mojom/interface_factory.mojom.h"
#include "media/renderers/default_decoder_factory.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/webcodecs/decoder_selector.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_pool.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_mojo.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/color_space.h"

#if BUILDFLAG(IS_FUCHSIA)
#include "media/fuchsia/video/fuchsia_decoder_factory.h"
#endif

using DecoderDetails = blink::VideoDecoderBroker::DecoderDetails;

namespace WTF {

template <>
struct CrossThreadCopier<media::VideoDecoderConfig>
    : public CrossThreadCopierPassThrough<media::VideoDecoderConfig> {
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
class MediaVideoTaskWrapper {
 public:
  using CrossThreadOnceInitCB =
      WTF::CrossThreadOnceFunction<void(media::DecoderStatus status,
                                        std::optional<DecoderDetails>)>;
  using CrossThreadOnceDecodeCB =
      WTF::CrossThreadOnceFunction<void(const media::DecoderStatus&)>;
  using CrossThreadOnceResetCB = WTF::CrossThreadOnceClosure;

  MediaVideoTaskWrapper(
      base::WeakPtr<CrossThreadVideoDecoderClient> weak_client,
      ExecutionContext& execution_context,
      media::GpuVideoAcceleratorFactories* gpu_factories,
      std::unique_ptr<media::MediaLog> media_log,
      scoped_refptr<base::SequencedTaskRunner> media_task_runner,
      scoped_refptr<base::SequencedTaskRunner> main_task_runner)
      : weak_client_(std::move(weak_client)),
        media_task_runner_(std::move(media_task_runner)),
        main_task_runner_(std::move(main_task_runner)),
        gpu_factories_(gpu_factories),
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
    // |Unretained| is safe because |this| must be destroyed on the media task
    // runner.
    PostCrossThreadTask(
        *media_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&MediaVideoTaskWrapper::BindOnTaskRunner,
                                 WTF::CrossThreadUnretained(this),
                                 std::move(media_interface_factory)));

#if BUILDFLAG(IS_FUCHSIA)
    execution_context.GetBrowserInterfaceBroker().GetInterface(
        fuchsia_media_codec_provider_.InitWithNewPipeAndPassReceiver());
#endif

    // TODO(sandersd): Target color space is used by DXVA VDA to pick an
    // efficient conversion for FP16 HDR content, and for no other purpose.
    // For <video>, we use the document's colorspace, but for WebCodecs we can't
    // infer that frames will be rendered to a document (there might not even be
    // a document). If this is relevant for WebCodecs, we should make it a
    // configuration hint.
    target_color_space_ = gfx::ColorSpace::CreateSRGB();
  }

  virtual ~MediaVideoTaskWrapper() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  }

  MediaVideoTaskWrapper(const MediaVideoTaskWrapper&) = delete;
  MediaVideoTaskWrapper& operator=(const MediaVideoTaskWrapper&) = delete;

  void Initialize(const media::VideoDecoderConfig& config, bool low_delay) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    selector_ = std::make_unique<WebCodecsVideoDecoderSelector>(
        media_task_runner_,
        // TODO(chcunningham): Its ugly that we don't use a WeakPtr here, but
        // its not possible because the callback returns non-void. It happens
        // to be safe given the way the callback is called (never posted), but
        // we should refactor the return to be an out-param so we can be
        // consistent in using weak pointers.
        WTF::BindRepeating(&MediaVideoTaskWrapper::OnCreateDecoders,
                           WTF::Unretained(this)),
        WTF::BindRepeating(&MediaVideoTaskWrapper::OnDecodeOutput,
                           weak_factory_.GetWeakPtr()));

    selector_->SelectDecoder(
        config, low_delay,
        WTF::BindOnce(&MediaVideoTaskWrapper::OnDecoderSelected,
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
                     WTF::BindOnce(&MediaVideoTaskWrapper::OnDecodeDone,
                                   weak_factory_.GetWeakPtr(), cb_id));
  }

  void Reset(int cb_id) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    if (!decoder_) {
      OnReset(cb_id);
      return;
    }

    decoder_->Reset(WTF::BindOnce(&MediaVideoTaskWrapper::OnReset,
                                  weak_factory_.GetWeakPtr(), cb_id));
  }

  void UpdateHardwarePreference(HardwarePreference preference) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    if (hardware_preference_ != preference) {
      hardware_preference_ = preference;
      decoder_factory_needs_update_ = true;
    }
  }

 private:
  void BindOnTaskRunner(
      mojo::PendingRemote<media::mojom::InterfaceFactory> interface_factory) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    media_interface_factory_.Bind(std::move(interface_factory));
  }

  void UpdateDecoderFactory() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    DCHECK(decoder_factory_needs_update_);

    decoder_factory_needs_update_ = false;

    // Bind the |interface_factory_| above before passing to
    // |external_decoder_factory|.
    std::unique_ptr<media::DecoderFactory> external_decoder_factory;
    if (hardware_preference_ != HardwarePreference::kPreferSoftware) {
#if BUILDFLAG(ENABLE_MOJO_VIDEO_DECODER)
      external_decoder_factory = std::make_unique<media::MojoDecoderFactory>(
          media_interface_factory_.get());
#elif BUILDFLAG(IS_FUCHSIA)
      DCHECK(fuchsia_media_codec_provider_);
      external_decoder_factory = std::make_unique<media::FuchsiaDecoderFactory>(
          std::move(fuchsia_media_codec_provider_),
          /*allow_overlays=*/false);
#endif
    }

    if (hardware_preference_ == HardwarePreference::kPreferHardware) {
      decoder_factory_ = std::move(external_decoder_factory);
      return;
    }

    decoder_factory_ = std::make_unique<media::DefaultDecoderFactory>(
        std::move(external_decoder_factory));
  }

  void OnRequestOverlayInfo(bool decoder_requires_restart_for_overlay,
                            media::ProvideOverlayInfoCB overlay_info_cb) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    // Android overlays are not supported.
    if (overlay_info_cb)
      std::move(overlay_info_cb).Run(media::OverlayInfo());
  }

  std::vector<std::unique_ptr<media::VideoDecoder>> OnCreateDecoders() {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    if (decoder_factory_needs_update_)
      UpdateDecoderFactory();

    std::vector<std::unique_ptr<media::VideoDecoder>> video_decoders;

    // We can end up with a null |decoder_factory_| if
    // |hardware_preference_| filtered out all available factories.
    if (decoder_factory_) {
      decoder_factory_->CreateVideoDecoders(
          media_task_runner_, gpu_factories_, media_log_.get(),
          WTF::BindRepeating(&MediaVideoTaskWrapper::OnRequestOverlayInfo,
                             weak_factory_.GetWeakPtr()),
          target_color_space_, &video_decoders);
    }

    return video_decoders;
  }

  void OnDecoderSelected(std::unique_ptr<media::VideoDecoder> decoder) {
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
                                        decoder_->NeedsBitstreamConversion(),
                                        decoder_->GetMaxDecodeRequests()});
    } else {
      status = media::DecoderStatus::Codes::kUnsupportedConfig;
    }

    // Fire |init_cb|.
    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadVideoDecoderClient::OnInitialize,
                                 weak_client_, status, decoder_details));
  }

  void OnDecodeOutput(scoped_refptr<media::VideoFrame> frame) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadVideoDecoderClient::OnDecodeOutput,
                                 weak_client_, std::move(frame),
                                 decoder_->CanReadWithoutStalling()));
  }

  void OnDecodeDone(int cb_id, media::DecoderStatus status) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadVideoDecoderClient::OnDecodeDone,
                                 weak_client_, cb_id, std::move(status)));
  }

  void OnReset(int cb_id) {
    DVLOG(2) << __func__;
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    PostCrossThreadTask(
        *main_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(&CrossThreadVideoDecoderClient::OnReset,
                                 weak_client_, cb_id));
  }

  base::WeakPtr<CrossThreadVideoDecoderClient> weak_client_;
  scoped_refptr<base::SequencedTaskRunner> media_task_runner_;
  scoped_refptr<base::SequencedTaskRunner> main_task_runner_;
  raw_ptr<media::GpuVideoAcceleratorFactories, DanglingUntriaged>
      gpu_factories_;
  std::unique_ptr<media::MediaLog> media_log_;
  mojo::Remote<media::mojom::InterfaceFactory> media_interface_factory_;
  std::unique_ptr<WebCodecsVideoDecoderSelector> selector_;
  std::unique_ptr<media::DecoderFactory> decoder_factory_;
  std::unique_ptr<media::VideoDecoder> decoder_;
  gfx::ColorSpace target_color_space_;
  HardwarePreference hardware_preference_ = HardwarePreference::kNoPreference;
  bool decoder_factory_needs_update_ = true;

#if BUILDFLAG(IS_FUCHSIA)
  mojo::PendingRemote<media::mojom::FuchsiaMediaCodecProvider>
      fuchsia_media_codec_provider_;
#endif

  SEQUENCE_CHECKER(sequence_checker_);

  // Using unretained for decoder/selector callbacks is generally not safe /
  // fragile. Some decoders (e.g. those that offload) will call the output
  // callback after destruction.
  base::WeakPtrFactory<MediaVideoTaskWrapper> weak_factory_{this};
};

VideoDecoderBroker::VideoDecoderBroker(
    ExecutionContext& execution_context,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    media::MediaLog* media_log)
    : media_task_runner_(
          gpu_factories
              // GpuFactories requires we use its task runner when available.
              ? gpu_factories->GetTaskRunner()
              // Otherwise, use a worker task runner to avoid scheduling decoder
              // work on the main thread.
              : worker_pool::CreateSequencedTaskRunner({base::MayBlock()})) {
  DVLOG(2) << __func__;
  media_tasks_ = std::make_unique<MediaVideoTaskWrapper>(
      weak_factory_.GetWeakPtr(), execution_context, gpu_factories,
      media_log->Clone(), media_task_runner_,
      execution_context.GetTaskRunner(TaskType::kInternalMedia));
}

VideoDecoderBroker::~VideoDecoderBroker() {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  media_task_runner_->DeleteSoon(FROM_HERE, std::move(media_tasks_));
}

media::VideoDecoderType VideoDecoderBroker::GetDecoderType() const {
  return decoder_details_ ? decoder_details_->decoder_id
                          : media::VideoDecoderType::kBroker;
}

bool VideoDecoderBroker::IsPlatformDecoder() const {
  return decoder_details_ ? decoder_details_->is_platform_decoder : false;
}

void VideoDecoderBroker::SetHardwarePreference(
    HardwarePreference hardware_preference) {
  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaVideoTaskWrapper::UpdateHardwarePreference,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               hardware_preference));
}

void VideoDecoderBroker::Initialize(const media::VideoDecoderConfig& config,
                                    bool low_delay,
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
      WTF::CrossThreadBindOnce(&MediaVideoTaskWrapper::Initialize,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               config, low_delay));
}

int VideoDecoderBroker::CreateCallbackId() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // 0 and -1 are reserved by wtf::HashMap ("empty" and "deleted").
  while (++last_callback_id_ == 0 ||
         last_callback_id_ == std::numeric_limits<uint32_t>::max() ||
         pending_decode_cb_map_.Contains(last_callback_id_) ||
         pending_reset_cb_map_.Contains(last_callback_id_))
    ;

  return last_callback_id_;
}

void VideoDecoderBroker::OnInitialize(media::DecoderStatus status,
                                      std::optional<DecoderDetails> details) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(init_cb_);
  decoder_details_ = details;
  std::move(init_cb_).Run(status);
}

void VideoDecoderBroker::Decode(scoped_refptr<media::DecoderBuffer> buffer,
                                DecodeCB decode_cb) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const int callback_id = CreateCallbackId();
  pending_decode_cb_map_.insert(callback_id, std::move(decode_cb));

  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaVideoTaskWrapper::Decode,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               buffer, callback_id));
}

void VideoDecoderBroker::OnDecodeDone(int cb_id, media::DecoderStatus status) {
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

void VideoDecoderBroker::Reset(base::OnceClosure reset_cb) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const int callback_id = CreateCallbackId();
  pending_reset_cb_map_.insert(callback_id, std::move(reset_cb));

  PostCrossThreadTask(
      *media_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(&MediaVideoTaskWrapper::Reset,
                               WTF::CrossThreadUnretained(media_tasks_.get()),
                               callback_id));
}

bool VideoDecoderBroker::NeedsBitstreamConversion() const {
  return decoder_details_ ? decoder_details_->needs_bitstream_conversion
                          : false;
}

bool VideoDecoderBroker::CanReadWithoutStalling() const {
  return can_read_without_stalling_;
}

int VideoDecoderBroker::GetMaxDecodeRequests() const {
  return decoder_details_ ? decoder_details_->max_decode_requests : 1;
}

void VideoDecoderBroker::OnReset(int cb_id) {
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

void VideoDecoderBroker::OnDecodeOutput(scoped_refptr<media::VideoFrame> frame,
                                        bool can_read_without_stalling) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(output_cb_);

  can_read_without_stalling_ = can_read_without_stalling;

  output_cb_.Run(std::move(frame));
}

}  // namespace blink
```
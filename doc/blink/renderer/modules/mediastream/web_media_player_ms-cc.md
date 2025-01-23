Response:
The user wants to understand the functionality of the `web_media_player_ms.cc` file in the Chromium Blink engine. They are particularly interested in:

1. **Functionality:** A general overview of what the code does.
2. **Relationship to web technologies:** How it interacts with JavaScript, HTML, and CSS.
3. **Logic and data flow:** Hypothetical inputs and outputs.
4. **Common user/programming errors:** Mistakes that might lead to issues with this code.
5. **User journey:** Steps a user might take in a browser that would trigger this code.
6. **Debugging clues:** How this code can aid in debugging media-related issues.
7. **Summary:** A concise recap of the file's purpose.

Based on the provided code snippet, which primarily deals with handling media streams, I can infer the following:

*   **Core Functionality:** This file implements `WebMediaPlayerMS`, a class responsible for playing media streams within the Chromium rendering engine. It manages the interaction between the media pipeline and the web page.
*   **JavaScript Interaction:** JavaScript code using the `HTMLMediaElement` API (e.g., `<video>` or `<audio>`) with a `MediaStream` as its source will interact with this code.
*   **HTML Interaction:** The presence of `<video>` or `<audio>` elements in an HTML document is the primary trigger for this code to be used when the source is a `MediaStream`.
*   **CSS Interaction:** While not directly managing CSS styles, the output of this code (video frames) is rendered within the bounds and according to the CSS styling applied to the corresponding HTML media element.
*   **Data Flow:** It receives `MediaStream` data, decodes it (potentially via `MediaStreamVideoRenderer` and `MediaStreamAudioRenderer`), and delivers video frames to the compositor for rendering.
*   **Error Handling:** The code includes mechanisms for handling audio rendering errors.
*   **Threading:** The code utilizes multiple threads (main render thread, video thread, compositor thread, media thread, worker thread) and carefully manages data transfer between them.
*   **Performance:** It uses `GpuMemoryBufferVideoFramePool` to potentially improve performance by utilizing GPU memory for video frames.
这是 `blink/renderer/modules/mediastream/web_media_player_ms.cc` 文件的第一部分。根据代码内容，其主要功能是实现 `WebMediaPlayerMS` 类，该类是 Blink 渲染引擎中用于播放 `MediaStream` 类型的媒体的 WebMediaPlayer 的具体实现。

以下是该文件功能的详细列举：

1. **`MediaStream` 播放核心:** `WebMediaPlayerMS` 负责处理通过 JavaScript `MediaStream` API 获取的媒体流的播放。这包括管理音频和视频轨道的渲染、同步和状态。

2. **生命周期管理:** 它管理 `MediaStream` 播放器的生命周期，包括加载 (Load)、播放 (Play)、暂停 (Pause)、停止 (Stop) 以及资源释放。

3. **多线程处理:**  该类涉及到多个线程的管理，包括主渲染线程 (main_render_task_runner_)、视频解码线程 (video_task_runner_)、合成线程 (compositor_task_runner_)、媒体线程 (media_task_runner_) 和 worker 线程 (worker_task_runner_)。它使用这些线程来处理不同的任务，例如视频帧的解码、渲染和合成。

4. **视频渲染:**
    *   它使用 `MediaStreamVideoRenderer` 从 `MediaStream` 中获取视频帧。
    *   它通过 `FrameDeliverer` 类将解码后的视频帧传递给合成器 (compositor_)。
    *   `FrameDeliverer` 可能会使用 `GpuMemoryBufferVideoFramePool` 来优化视频帧的内存管理，尤其是在支持 GPU 内存缓冲区的平台上。
    *   它与 `cc::VideoLayer` 或 `WebSurfaceLayerBridge` 结合，将视频内容渲染到页面上。

5. **音频渲染:**
    *   它使用 `MediaStreamAudioRenderer` 从 `MediaStream` 中渲染音频。
    *   它可以设置音频的输出设备 ID。
    *   它处理音频渲染过程中可能出现的错误。

6. **状态管理:** 它维护和更新播放器的各种状态，例如网络状态 (`network_state_`) 和就绪状态 (`ready_state_`)，并通知客户端 (例如，HTMLMediaElement) 这些状态的变化。

7. **与合成器的交互:** 它使用 `WebMediaPlayerMSCompositor` 类来处理视频帧的合成和渲染。

8. **性能优化:**  通过使用 GPU 内存缓冲区 (GpuMemoryBuffer) 来存储视频帧，可以减少 CPU 拷贝，提高渲染性能。这在 `FrameDeliverer` 中有所体现。

9. **媒体指标收集:**  它与 `media::MediaLog` 和 `WatchTimeReporter` 结合，用于记录和上报媒体播放的统计信息。

10. **`MediaStream` 事件监听:** 它监听 `MediaStream` 的添加和移除轨道以及激活状态变化等事件，并做出相应的处理，例如重新加载渲染器。

**与 JavaScript, HTML, CSS 的功能关系及举例说明:**

*   **JavaScript:**
    *   **关系:** JavaScript 代码通过 `HTMLMediaElement` (如 `<video>` 或 `<audio>`) 的 `srcObject` 属性将 `MediaStream` 对象赋值给媒体元素，从而触发 `WebMediaPlayerMS` 的加载和播放。
    *   **举例:**
        ```javascript
        const videoElement = document.getElementById('myVideo');
        navigator.mediaDevices.getUserMedia({ video: true, audio: true })
          .then(stream => {
            videoElement.srcObject = stream;
            videoElement.play();
          });
        ```
        在这个例子中，`videoElement.srcObject = stream;` 将 `MediaStream` 对象 `stream` 传递给 `<video>` 元素，Blink 引擎会创建并使用 `WebMediaPlayerMS` 来处理这个媒体流的播放。

*   **HTML:**
    *   **关系:**  HTML 中的 `<video>` 或 `<audio>` 元素是媒体播放的容器。当这些元素的 `srcObject` 属性被设置为 `MediaStream` 时，就会用到 `WebMediaPlayerMS`。
    *   **举例:**
        ```html
        <video id="myVideo" autoplay controls></video>
        ```
        这个 `<video>` 元素一旦通过 JavaScript 设置了 `srcObject` 为 `MediaStream`，`WebMediaPlayerMS` 就会负责渲染来自该流的视频。

*   **CSS:**
    *   **关系:** CSS 用于控制 `<video>` 或 `<audio>` 元素的样式、尺寸、定位等。`WebMediaPlayerMS` 负责提供视频帧，而 CSS 决定这些帧在页面上的呈现方式。
    *   **举例:**
        ```css
        #myVideo {
          width: 640px;
          height: 480px;
          object-fit: contain; /* 控制视频内容如何适应容器 */
        }
        ```
        CSS 样式定义了 `#myVideo` 元素的尺寸和内容适配方式，`WebMediaPlayerMS` 提供的视频帧会按照这些样式进行渲染。

**逻辑推理，假设输入与输出:**

*   **假设输入:** 一个包含音频和视频轨道的 `MediaStream` 对象被设置为 `<video>` 元素的 `srcObject`。
*   **输出:**
    *   `WebMediaPlayerMS` 被创建并加载这个 `MediaStream`。
    *   `MediaStreamVideoRenderer` 开始解码视频轨道的数据。
    *   `MediaStreamAudioRenderer` 开始解码音频轨道的数据。
    *   视频帧通过 `FrameDeliverer` 传递给 `WebMediaPlayerMSCompositor`。
    *   `WebMediaPlayerMSCompositor` 将视频帧合成到渲染层。
    *   音频数据被传递到音频输出设备进行播放。
    *   `<video>` 元素开始在页面上播放音频和视频内容。
    *   相关的媒体事件 (如 `play`, `playing`, `loadedmetadata` 等) 被触发。

**涉及用户或者编程常见的使用错误，举例说明:**

*   **错误 1 (编程):** 在 `MediaStream` 还没有准备好（例如，`readyState` 不是 `live`）时就尝试将其赋值给媒体元素的 `srcObject`。
    *   **后果:** 可能会导致播放失败或出现错误，因为 `WebMediaPlayerMS` 无法获取有效的媒体数据。
*   **错误 2 (用户/编程):**  `MediaStream` 的轨道在播放过程中突然被移除或停止，但没有正确处理这种情况。
    *   **后果:**  可能导致播放中断、画面卡住或音频停止，需要重新加载或采取其他错误处理措施。代码中的 `TrackAdded` 和 `TrackRemoved` 函数就是用来处理这种情况的。
*   **错误 3 (编程):**  在多线程环境下访问或修改 `WebMediaPlayerMS` 的状态时没有进行正确的同步。
    *   **后果:** 可能导致数据竞争和未定义的行为。Chromium 使用了各种线程模型和消息传递机制来避免这种情况。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户打开一个网页:** 用户在浏览器中打开一个包含使用 `getUserMedia` API 获取本地摄像头和麦克风视频流并在 `<video>` 元素中显示的网页。
2. **JavaScript 获取 `MediaStream`:** 网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true, audio: true })` 来请求访问用户的摄像头和麦克风。
3. **用户授权:** 用户在浏览器提示中允许网页访问其摄像头和麦克风。
4. **`MediaStream` 创建:**  `getUserMedia` 成功后，会返回一个包含音视频轨道的 `MediaStream` 对象。
5. **设置 `srcObject`:** JavaScript 代码将这个 `MediaStream` 对象赋值给 `<video>` 元素的 `srcObject` 属性。
6. **Blink 创建 `WebMediaPlayerMS`:**  Blink 渲染引擎检测到 `<video>` 元素的 `srcObject` 被设置为 `MediaStream`，从而创建 `WebMediaPlayerMS` 的实例来处理这个媒体流。
7. **加载和播放:** `WebMediaPlayerMS` 开始加载 `MediaStream`，并创建相应的音频和视频渲染器。视频帧通过 `FrameDeliverer` 和 `WebMediaPlayerMSCompositor` 进行处理和渲染，最终显示在页面上。

**作为调试线索:** 如果在播放 `MediaStream` 时出现问题 (例如，画面卡顿、无声音、播放失败)，可以关注以下几点：

*   **网络状态和就绪状态:** 检查 `network_state_` 和 `ready_state_` 的变化，以了解加载和播放的进度以及是否发生网络或解码错误。
*   **日志消息:**  查看代码中 `SendLogMessage` 输出的日志，可以了解 `WebMediaPlayerMS` 的内部执行流程和状态变化。
*   **`MediaStream` 事件:** 检查 `TrackAdded`、`TrackRemoved` 和 `ActiveStateChanged` 等事件是否被正确触发和处理，这可以帮助诊断由于轨道变化引起的问题。
*   **线程切换:**  由于涉及到多线程，需要确保相关的操作在正确的线程上执行。断点调试时需要注意线程的上下文。
*   **`FrameDeliverer` 和合成器:**  如果视频渲染出现问题，可以检查 `FrameDeliverer` 是否正确传递了视频帧，以及合成器是否正常工作。

**功能归纳:**

`WebMediaPlayerMS` 是 Chromium Blink 引擎中用于播放 `MediaStream` 类型媒体的核心组件。它负责管理 `MediaStream` 的加载、解码、渲染和状态，协调音频和视频轨道的播放，并与合成器交互以将视频内容显示在页面上。它还处理 `MediaStream` 的动态变化，例如轨道的添加和移除。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/public/web/modules/mediastream/web_media_player_ms.h"

#include <stddef.h>

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/sequence_checker.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/layers/video_frame_provider_client_impl.h"
#include "cc/layers/video_layer.h"
#include "media/base/media_content_type.h"
#include "media/base/media_log.h"
#include "media/base/media_track.h"
#include "media/base/video_frame.h"
#include "media/base/video_transformation.h"
#include "media/base/video_types.h"
#include "media/mojo/mojom/media_metrics_provider.mojom.h"
#include "media/video/gpu_memory_buffer_video_frame_pool.h"
#include "services/viz/public/cpp/gpu/context_provider_command_buffer.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/url_conversion.h"
#include "third_party/blink/public/platform/web_media_player_source.h"
#include "third_party/blink/public/platform/web_surface_layer_bridge.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_renderer.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_local_frame_wrapper.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_renderer_factory.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_renderer.h"
#include "third_party/blink/renderer/modules/mediastream/web_media_player_ms_compositor.h"
#include "third_party/blink/renderer/platform/media/media_player_client.h"
#include "third_party/blink/renderer/platform/media/media_player_util.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_descriptor.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_media.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace WTF {

template <>
struct CrossThreadCopier<viz::SurfaceId>
    : public CrossThreadCopierPassThrough<viz::SurfaceId> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

enum class RendererReloadAction {
  KEEP_RENDERER,
  REMOVE_RENDERER,
  NEW_RENDERER
};

bool IsPlayableTrack(MediaStreamComponent* component) {
  return component && component->Source() &&
         component->GetReadyState() != MediaStreamSource::kReadyStateEnded;
}

const char* LoadTypeToString(WebMediaPlayer::LoadType type) {
  switch (type) {
    case WebMediaPlayer::kLoadTypeURL:
      return "URL";
    case WebMediaPlayer::kLoadTypeMediaSource:
      return "MediaSource";
    case WebMediaPlayer::kLoadTypeMediaStream:
      return "MediaStream";
  }
}

const char* ReadyStateToString(WebMediaPlayer::ReadyState state) {
  switch (state) {
    case WebMediaPlayer::kReadyStateHaveNothing:
      return "HaveNothing";
    case WebMediaPlayer::kReadyStateHaveMetadata:
      return "HaveMetadata";
    case WebMediaPlayer::kReadyStateHaveCurrentData:
      return "HaveCurrentData";
    case WebMediaPlayer::kReadyStateHaveFutureData:
      return "HaveFutureData";
    case WebMediaPlayer::kReadyStateHaveEnoughData:
      return "HaveEnoughData";
  }
}

const char* NetworkStateToString(WebMediaPlayer::NetworkState state) {
  switch (state) {
    case WebMediaPlayer::kNetworkStateEmpty:
      return "Empty";
    case WebMediaPlayer::kNetworkStateIdle:
      return "Idle";
    case WebMediaPlayer::kNetworkStateLoading:
      return "Loading";
    case WebMediaPlayer::kNetworkStateLoaded:
      return "Loaded";
    case WebMediaPlayer::kNetworkStateFormatError:
      return "FormatError";
    case WebMediaPlayer::kNetworkStateNetworkError:
      return "NetworkError";
    case WebMediaPlayer::kNetworkStateDecodeError:
      return "DecodeError";
  }
}

media::VideoTransformation GetFrameTransformation(
    scoped_refptr<media::VideoFrame> frame) {
  return frame ? frame->metadata().transformation.value_or(
                     media::kNoTransformation)
               : media::kNoTransformation;
}

base::TimeDelta GetFrameTime(scoped_refptr<media::VideoFrame> frame) {
  return frame ? frame->timestamp() : base::TimeDelta();
}

constexpr base::TimeDelta kForceBeginFramesTimeout = base::Seconds(1);
}  // namespace

#if BUILDFLAG(IS_WIN)
// Since we do not have native GMB support in Windows, using GMBs can cause a
// CPU regression. This is more apparent and can have adverse affects in lower
// resolution content which are defined by these thresholds, see
// https://crbug.com/835752.
// static
const gfx::Size WebMediaPlayerMS::kUseGpuMemoryBufferVideoFramesMinResolution =
    gfx::Size(1920, 1080);
#endif  // BUILDFLAG(IS_WIN)

// FrameDeliverer is responsible for delivering frames received on
// the video task runner by calling of EnqueueFrame() method of |compositor_|.
//
// It is created on the main thread, but methods should be called and class
// should be destructed on the video task runner.
class WebMediaPlayerMS::FrameDeliverer {
 public:
  using RepaintCB = WTF::CrossThreadRepeatingFunction<
      void(scoped_refptr<media::VideoFrame> frame, bool is_copy)>;
  FrameDeliverer(const base::WeakPtr<WebMediaPlayerMS>& player,
                 RepaintCB enqueue_frame_cb,
                 scoped_refptr<base::SequencedTaskRunner> media_task_runner,
                 scoped_refptr<base::TaskRunner> worker_task_runner,
                 media::GpuVideoAcceleratorFactories* gpu_factories)
      : main_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
        player_(player),
        enqueue_frame_cb_(std::move(enqueue_frame_cb)),
        media_task_runner_(media_task_runner),
        worker_task_runner_(worker_task_runner),
        gpu_factories_(gpu_factories) {
    DETACH_FROM_SEQUENCE(video_sequence_checker_);

    CreateGpuMemoryBufferPoolIfNecessary();
  }

  FrameDeliverer(const FrameDeliverer&) = delete;
  FrameDeliverer& operator=(const FrameDeliverer&) = delete;

  ~FrameDeliverer() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
    FreeGpuMemoryBufferPool();
  }

  void OnVideoFrame(scoped_refptr<media::VideoFrame> frame) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

// On Android, stop passing frames.
#if BUILDFLAG(IS_ANDROID)
    if (render_frame_suspended_)
      return;
#endif  // BUILDFLAG(IS_ANDROID)

    if (!gpu_memory_buffer_pool_) {
      const media::VideoFrame::ID original_frame_id = frame->unique_id();
      EnqueueFrame(original_frame_id, std::move(frame));
      return;
    }

    // If |render_frame_suspended_|, we can keep passing the frames to keep the
    // latest frame in compositor up to date. However, creating GMB backed
    // frames is unnecessary, because the frames are not going to be shown for
    // the time period.
    bool skip_creating_gpu_memory_buffer = render_frame_suspended_;

#if BUILDFLAG(IS_WIN)
    skip_creating_gpu_memory_buffer |=
        frame->visible_rect().width() <
            kUseGpuMemoryBufferVideoFramesMinResolution.width() ||
        frame->visible_rect().height() <
            kUseGpuMemoryBufferVideoFramesMinResolution.height();
#endif  // BUILDFLAG(IS_WIN)

    if (skip_creating_gpu_memory_buffer) {
      media::VideoFrame::ID original_frame_id = frame->unique_id();
      EnqueueFrame(original_frame_id, std::move(frame));
      // If there are any existing MaybeCreateHardwareFrame() calls, we do not
      // want those frames to be placed after the current one, so just drop
      // them.
      DropCurrentPoolTasks();
      return;
    }

    const media::VideoFrame::ID original_frame_id = frame->unique_id();

    // |gpu_memory_buffer_pool_| deletion is going to be posted to
    // |media_task_runner_|. base::Unretained() usage is fine since
    // |gpu_memory_buffer_pool_| outlives the task.
    //
    // TODO(crbug.com/964947): Converting this to PostCrossThreadTask requires
    // re-binding a CrossThreadOnceFunction instance.
    media_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            &media::GpuMemoryBufferVideoFramePool::MaybeCreateHardwareFrame,
            base::Unretained(gpu_memory_buffer_pool_.get()), std::move(frame),
            base::BindPostTaskToCurrentDefault(base::BindOnce(
                &FrameDeliverer::EnqueueFrame,
                weak_factory_for_pool_.GetWeakPtr(), original_frame_id))));
  }

  void SetRenderFrameSuspended(bool render_frame_suspended) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
    render_frame_suspended_ = render_frame_suspended;
    if (render_frame_suspended_) {
      // Drop GpuMemoryBuffer pool to free memory.
      FreeGpuMemoryBufferPool();
    } else {
      CreateGpuMemoryBufferPoolIfNecessary();
    }
  }

  WTF::CrossThreadRepeatingFunction<
      void(scoped_refptr<media::VideoFrame> frame)>
  GetRepaintCallback() {
    return CrossThreadBindRepeating(&FrameDeliverer::OnVideoFrame,
                                    weak_factory_.GetWeakPtr());
  }

 private:
  friend class WebMediaPlayerMS;

  void CreateGpuMemoryBufferPoolIfNecessary() {
    if (!gpu_memory_buffer_pool_ && gpu_factories_ &&
        gpu_factories_->ShouldUseGpuMemoryBuffersForVideoFrames(
            true /* for_media_stream */)) {
      gpu_memory_buffer_pool_ =
          std::make_unique<media::GpuMemoryBufferVideoFramePool>(
              media_task_runner_, worker_task_runner_, gpu_factories_);
    }
  }

  void FreeGpuMemoryBufferPool() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

    if (gpu_memory_buffer_pool_) {
      DropCurrentPoolTasks();
      media_task_runner_->DeleteSoon(FROM_HERE,
                                     gpu_memory_buffer_pool_.release());
    }
  }

  void EnqueueFrame(media::VideoFrame::ID original_frame_id,
                    scoped_refptr<media::VideoFrame> frame) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

    {
      bool tracing_enabled = false;
      TRACE_EVENT_CATEGORY_GROUP_ENABLED("media", &tracing_enabled);
      if (tracing_enabled) {
        if (frame->metadata().reference_time.has_value()) {
          TRACE_EVENT1("media", "EnqueueFrame", "Ideal Render Instant",
                       frame->metadata().reference_time->ToInternalValue());
        } else {
          TRACE_EVENT0("media", "EnqueueFrame");
        }
      }
    }

    bool is_copy = original_frame_id != frame->unique_id();
    enqueue_frame_cb_.Run(std::move(frame), is_copy);
  }

  void DropCurrentPoolTasks() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
    DCHECK(gpu_memory_buffer_pool_);

    if (!weak_factory_for_pool_.HasWeakPtrs())
      return;

    //  |gpu_memory_buffer_pool_| deletion is going to be posted to
    //  |media_task_runner_|. CrossThreadUnretained() usage is fine since
    //  |gpu_memory_buffer_pool_| outlives the task.
    PostCrossThreadTask(
        *media_task_runner_, FROM_HERE,
        CrossThreadBindOnce(
            &media::GpuMemoryBufferVideoFramePool::Abort,
            CrossThreadUnretained(gpu_memory_buffer_pool_.get())));
    weak_factory_for_pool_.InvalidateWeakPtrs();
  }

  bool render_frame_suspended_ = false;

  const scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  const base::WeakPtr<WebMediaPlayerMS> player_;
  RepaintCB enqueue_frame_cb_;

  // Pool of GpuMemoryBuffers and resources used to create hardware frames.
  std::unique_ptr<media::GpuMemoryBufferVideoFramePool> gpu_memory_buffer_pool_;
  const scoped_refptr<base::SequencedTaskRunner> media_task_runner_;
  const scoped_refptr<base::TaskRunner> worker_task_runner_;

  const raw_ptr<media::GpuVideoAcceleratorFactories> gpu_factories_;

  // Used for DCHECKs to ensure method calls are executed on the correct thread.
  SEQUENCE_CHECKER(video_sequence_checker_);

  base::WeakPtrFactory<FrameDeliverer> weak_factory_for_pool_{this};
  base::WeakPtrFactory<FrameDeliverer> weak_factory_{this};
};

WebMediaPlayerMS::WebMediaPlayerMS(
    WebLocalFrame* frame,
    WebMediaPlayerClient* client,
    WebMediaPlayerDelegate* delegate,
    std::unique_ptr<media::MediaLog> media_log,
    scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner,
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner,
    scoped_refptr<base::SequencedTaskRunner> media_task_runner,
    scoped_refptr<base::TaskRunner> worker_task_runner,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    const WebString& sink_id,
    CreateSurfaceLayerBridgeCB create_bridge_callback,
    std::unique_ptr<WebVideoFrameSubmitter> submitter,
    bool use_surface_layer)
    : internal_frame_(std::make_unique<MediaStreamInternalFrameWrapper>(frame)),
      network_state_(WebMediaPlayer::kNetworkStateEmpty),
      ready_state_(WebMediaPlayer::kReadyStateHaveNothing),
      buffered_(static_cast<size_t>(0)),
      client_(static_cast<MediaPlayerClient*>(client)),
      delegate_(delegate),
      delegate_id_(0),
      paused_(true),
      media_log_(std::move(media_log)),
      renderer_factory_(std::make_unique<MediaStreamRendererFactory>()),
      main_render_task_runner_(std::move(main_render_task_runner)),
      video_task_runner_(std::move(video_task_runner)),
      compositor_task_runner_(std::move(compositor_task_runner)),
      media_task_runner_(std::move(media_task_runner)),
      worker_task_runner_(std::move(worker_task_runner)),
      gpu_factories_(gpu_factories),
      initial_audio_output_device_id_(sink_id),
      volume_(1.0),
      volume_multiplier_(1.0),
      should_play_upon_shown_(false),
      create_bridge_callback_(std::move(create_bridge_callback)),
      stop_force_begin_frames_timer_(
          std::make_unique<TaskRunnerTimer<WebMediaPlayerMS>>(
              main_render_task_runner_,
              this,
              &WebMediaPlayerMS::StopForceBeginFrames)),
      submitter_(std::move(submitter)),
      use_surface_layer_(use_surface_layer) {
  DCHECK(client);
  DCHECK(delegate_);
  weak_this_ = weak_factory_.GetWeakPtr();
  delegate_id_ = delegate_->AddObserver(this);
  SendLogMessage(String::Format(
      "%s({delegate_id=%d}, {is_audio_element=%s}, {sink_id=%s})", __func__,
      delegate_id_, client_->IsAudioElement() ? "true" : "false",
      sink_id.Utf8().c_str()));

  // TODO(tmathmeyer) WebMediaPlayerImpl gets the URL from the WebLocalFrame.
  // doing that here causes a nullptr deref.
  media_log_->AddEvent<media::MediaLogEvent::kWebMediaPlayerCreated>();
}

WebMediaPlayerMS::~WebMediaPlayerMS() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(
      String::Format("%s() [delegate_id=%d]", __func__, delegate_id_));

  if (!web_stream_.IsNull()) {
    web_stream_.RemoveObserver(this);
  }

  // Destruct compositor resources in the proper order.
  get_client()->SetCcLayer(nullptr);
  if (video_layer_) {
    DCHECK(!use_surface_layer_);
    video_layer_->StopUsingProvider();
  }

  if (frame_deliverer_) {
    video_task_runner_->DeleteSoon(FROM_HERE, std::move(frame_deliverer_));
  }

  if (video_frame_provider_) {
    video_frame_provider_->Stop();
  }

  // This must be destroyed before `compositor_` since it will grab a couple of
  // final metrics during destruction.
  watch_time_reporter_.reset();

  if (compositor_) {
    // `compositor_` receives frames on `video_task_runner_` from
    // `frame_deliverer_` and operates on the `compositor_task_runner_`, so
    // must trampoline through both to ensure a safe destruction.
    PostCrossThreadTask(
        *video_task_runner_, FROM_HERE,
        WTF::CrossThreadBindOnce(
            [](scoped_refptr<base::SingleThreadTaskRunner> task_runner,
               std::unique_ptr<WebMediaPlayerMSCompositor> compositor) {
              task_runner->DeleteSoon(FROM_HERE, std::move(compositor));
            },
            compositor_task_runner_, std::move(compositor_)));
  }

  if (audio_renderer_) {
    audio_renderer_->Stop();
  }

  media_log_->AddEvent<media::MediaLogEvent::kWebMediaPlayerDestroyed>();

  delegate_->PlayerGone(delegate_id_);
  delegate_->RemoveObserver(delegate_id_);
}

void WebMediaPlayerMS::OnAudioRenderErrorCallback() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (watch_time_reporter_)
    watch_time_reporter_->OnError(media::AUDIO_RENDERER_ERROR);

  if (ready_state_ == WebMediaPlayer::kReadyStateHaveNothing) {
    // Any error that occurs before reaching ReadyStateHaveMetadata should
    // be considered a format error.
    SetNetworkState(WebMediaPlayer::kNetworkStateFormatError);
  } else {
    SetNetworkState(WebMediaPlayer::kNetworkStateDecodeError);
  }
}

WebMediaPlayer::LoadTiming WebMediaPlayerMS::Load(
    LoadType load_type,
    const WebMediaPlayerSource& source,
    CorsMode /*cors_mode*/,
    bool is_cache_disabled) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s({load_type=%s})", __func__,
                                LoadTypeToString(load_type)));

  // TODO(acolwell): Change this to DCHECK_EQ(load_type, LoadTypeMediaStream)
  // once Blink-side changes land.
  DCHECK_NE(load_type, kLoadTypeMediaSource);
  web_stream_ = source.GetAsMediaStream();
  if (!web_stream_.IsNull())
    web_stream_.AddObserver(this);

  watch_time_reporter_.reset();

  compositor_ = std::make_unique<WebMediaPlayerMSCompositor>(
      compositor_task_runner_, video_task_runner_, web_stream_,
      std::move(submitter_), use_surface_layer_, weak_this_);

  // We can receive a call to RequestVideoFrameCallback() before |compositor_|
  // is created. In that case, we suspend the request, and wait until now to
  // reiniate it.
  if (pending_rvfc_request_) {
    RequestVideoFrameCallback();
    pending_rvfc_request_ = false;
  }

  SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
  SetReadyState(WebMediaPlayer::kReadyStateHaveNothing);
  std::string stream_id =
      web_stream_.IsNull() ? std::string() : web_stream_.Id().Utf8();
  media_log_->AddEvent<media::MediaLogEvent::kLoad>(stream_id);
  SendLogMessage(
      String::Format("%s => (stream_id=%s)", __func__, stream_id.c_str()));

  frame_deliverer_ = std::make_unique<WebMediaPlayerMS::FrameDeliverer>(
      weak_this_,
      CrossThreadBindRepeating(&WebMediaPlayerMSCompositor::EnqueueFrame,
                               CrossThreadUnretained(compositor_.get())),
      media_task_runner_, worker_task_runner_, gpu_factories_);
  video_frame_provider_ = renderer_factory_->GetVideoRenderer(
      web_stream_,
      ConvertToBaseRepeatingCallback(frame_deliverer_->GetRepaintCallback()),
      video_task_runner_, main_render_task_runner_);

  if (internal_frame_->web_frame()) {
    WebURL url = source.GetAsURL();
    // Report UMA metrics.
    ReportMetrics(load_type, url, media_log_.get());
  }

  audio_renderer_ = renderer_factory_->GetAudioRenderer(
      web_stream_, internal_frame_->web_frame(),
      initial_audio_output_device_id_,
      WTF::BindRepeating(&WebMediaPlayerMS::OnAudioRenderErrorCallback,
                         weak_factory_.GetWeakPtr()));

  if (!video_frame_provider_ && !audio_renderer_) {
    SetNetworkState(WebMediaPlayer::kNetworkStateNetworkError);
    SendLogMessage(String::Format(
        "%s => (ERROR: WebMediaPlayer::kNetworkStateNetworkError)", __func__));
    return WebMediaPlayer::LoadTiming::kImmediate;
  }

  if (audio_renderer_) {
    audio_renderer_->SetVolume(volume_);
    audio_renderer_->Start();

    if (!web_stream_.IsNull()) {
      MediaStreamDescriptor& descriptor = *web_stream_;
      auto audio_components = descriptor.AudioComponents();
      // Store the ID of audio track being played in |current_audio_track_id_|.
      DCHECK_GT(audio_components.size(), 0U);
      current_audio_track_id_ = WebString(audio_components[0]->Id());
      SendLogMessage(String::Format("%s => (audio_track_id=%s)", __func__,
                                    current_audio_track_id_.Utf8().c_str()));
      // Report the media track information to blink. Only the first audio track
      // is enabled by default to match blink logic.
      bool is_first_audio_track = true;
      for (auto component : audio_components) {
        client_->AddMediaTrack(media::MediaTrack::CreateAudioTrack(
            component->Id().Utf8(), media::MediaTrack::AudioKind::kMain,
            component->GetSourceName().Utf8(), /*language=*/"",
            is_first_audio_track));
        is_first_audio_track = false;
      }
    }
  }

  if (video_frame_provider_) {
    video_frame_provider_->Start();

    if (!web_stream_.IsNull()) {
      MediaStreamDescriptor& descriptor = *web_stream_;
      auto video_components = descriptor.VideoComponents();
      // Store the ID of video track being played in |current_video_track_id_|.
      DCHECK_GT(video_components.size(), 0U);
      current_video_track_id_ = WebString(video_components[0]->Id());
      SendLogMessage(String::Format("%s => (video_track_id=%s)", __func__,
                                    current_video_track_id_.Utf8().c_str()));
      // Report the media track information to blink. Only the first video track
      // is enabled by default to match blink logic.
      bool is_first_video_track = true;
      for (auto component : video_components) {
        client_->AddMediaTrack(media::MediaTrack::CreateVideoTrack(
            component->Id().Utf8(), media::MediaTrack::VideoKind::kMain,
            component->GetSourceName().Utf8(), /*language=*/"",
            is_first_video_track));
        is_first_video_track = false;
      }
    }
  }
  // When associated with an <audio> element, we don't want to wait for the
  // first video frame to become available as we do for <video> elements
  // (<audio> elements can also be assigned video tracks).
  // For more details, see https://crbug.com/738379
  if (audio_renderer_ &&
      (client_->IsAudioElement() || !video_frame_provider_)) {
    SendLogMessage(String::Format("%s => (audio only mode)", __func__));
    SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);
    SetReadyState(WebMediaPlayer::kReadyStateHaveEnoughData);
    MaybeCreateWatchTimeReporter();
  }

  client_->DidMediaMetadataChange(
      HasAudio(), HasVideo(), media::AudioCodec::kUnknown,
      media::VideoCodec::kUnknown, media::MediaContentType::kOneShot,
      /* is_encrypted_media */ false);
  delegate_->DidMediaMetadataChange(delegate_id_, HasAudio(), HasVideo(),
                                    media::MediaContentType::kOneShot);

  return WebMediaPlayer::LoadTiming::kImmediate;
}

void WebMediaPlayerMS::OnWebLayerUpdated() {}

void WebMediaPlayerMS::RegisterContentsLayer(cc::Layer* layer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(bridge_);

  bridge_->SetContentsOpaque(opaque_);
  client_->SetCcLayer(layer);
}

void WebMediaPlayerMS::UnregisterContentsLayer(cc::Layer* layer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // |client_| will unregister its cc::Layer if given a nullptr.
  client_->SetCcLayer(nullptr);
}

void WebMediaPlayerMS::OnSurfaceIdUpdated(viz::SurfaceId surface_id) {
  // TODO(726619): Handle the behavior when Picture-in-Picture mode is
  // disabled.
  // The viz::SurfaceId may be updated when the video begins playback or when
  // the size of the video changes.
  if (client_ && !client_->IsAudioElement()) {
    client_->OnPictureInPictureStateChange();
  }
}

void WebMediaPlayerMS::TrackAdded(const WebString& track_id) {
  SendLogMessage(
      String::Format("%s({track_id=%s})", __func__, track_id.Utf8().c_str()));
  Reload();
}

void WebMediaPlayerMS::TrackRemoved(const WebString& track_id) {
  SendLogMessage(
      String::Format("%s({track_id=%s})", __func__, track_id.Utf8().c_str()));
  Reload();
}

void WebMediaPlayerMS::ActiveStateChanged(bool is_active) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s({is_active=%s})", __func__,
                                is_active ? "true" : "false"));
  // The case when the stream becomes active is handled by TrackAdded().
  if (is_active)
    return;

  // This makes the media element eligible to be garbage collected. Otherwise,
  // the element will be considered active and will never be garbage
  // collected.
  SetNetworkState(kNetworkStateIdle);

  // Stop the audio renderer to free up resources that are not required for an
  // inactive stream. This is useful if the media element is not garbage
  // collected.
  // Note that the video renderer should not be stopped because the ended video
  // track is expected to produce a black frame after becoming inactive.
  if (audio_renderer_)
    audio_renderer_->Stop();
}

int WebMediaPlayerMS::GetDelegateId() {
  return delegate_id_;
}

std::optional<viz::SurfaceId> WebMediaPlayerMS::GetSurfaceId() {
  if (bridge_)
    return bridge_->GetSurfaceId();
  return std::nullopt;
}

base::WeakPtr<WebMediaPlayer> WebMediaPlayerMS::AsWeakPtr() {
  return weak_this_;
}

void WebMediaPlayerMS::Reload() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (web_stream_.IsNull())
    return;

  ReloadVideo();
  ReloadAudio();
}

void WebMediaPlayerMS::ReloadVideo() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!web_stream_.IsNull());
  MediaStreamDescriptor& descriptor = *web_stream_;
  auto video_components = descriptor.VideoComponents();

  RendererReloadAction renderer_action = RendererReloadAction::KEEP_RENDERER;
  if (video_components.empty()) {
    if (video_frame_provider_)
      renderer_action = RendererReloadAction::REMOVE_RENDERER;
    current_video_track_id_ = WebString();
  } else if (WebString(video_components[0]->Id()) != current_video_track_id_ &&
             IsPlayableTrack(video_components[0])) {
    renderer_action = RendererReloadAction::NEW_RENDERER;
    current_video_track_id_ = video_components[0]->Id();
  }

  switch (renderer_action) {
    case RendererReloadAction::NEW_RENDERER:
      if (video_frame_provider_)
        video_frame_provider_->Stop();

      SetNetworkState(kNetworkStateLoading);
      video_frame_provider_ = renderer_factory_->GetVideoRenderer(
          web_stream_,
          ConvertToBaseRepeatingCallback(
              frame_deliverer_->GetRepaintCallback()),
          video_task_runner_, main_render_task_runner_);
      DCHECK(video_frame_provider_);
      video_frame_provider_->Start();
      break;

    case RendererReloadAction::REMOVE_RENDERER:
      video_frame_provider_->Stop();
      video_frame_provider_ = nullptr;
      break;

    default:
      return;
  }

  DCHECK_NE(renderer_action, RendererReloadAction::KEEP_RENDERER);
  if (!paused_) {
    client_->DidPlayerSizeChange(NaturalSize());
    if (watch_time_reporter_)
      UpdateWatchTimeReporterSecondaryProperties();
  }

  // TODO(perkj, magjed): We use OneShot focus type here so that it takes
  // audio focus once it starts, and then will not respond to further audio
  // focus changes. See https://crbug.com/596516 for more details.
  client_->DidMediaMetadataChange(
      HasAudio(), HasVideo(), media::AudioCodec::kUnknown,
      media::VideoCodec::kUnknown, media::MediaContentType::kOneShot,
      /* is_encrypted_media */ false);
  delegate_->DidMediaMetadataChange(delegate_id_, HasAudio(), HasVideo(),
                                    media::MediaContentType::kOneShot);
}

void WebMediaPlayerMS::ReloadAudio() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!web_stream_.IsNull());
  if (!internal_frame_->web_frame())
    return;
  SendLogMessage(String::Format("%s()", __func__));

  MediaStreamDescriptor& descriptor = *web_stream_;
  auto audio_components = descriptor.AudioComponents();

  RendererReloadAction renderer_action = RendererReloadAction::KEEP_RENDERER;
  if (audio_components.empty()) {
    if (audio_renderer_)
      renderer_action = RendererReloadAction::REMOVE_RENDERER;
    current_audio_track_id_ = WebString();
  } else if (WebString(audio_components[0]->Id()) != current_audio_track_id_ &&
             IsPlayableTrack(audio_components[0])) {
    renderer_action = RendererReloadAction::NEW_RENDERER;
    current_audio_track_id_ = audio_components[0]->Id();
  }

  switch (renderer_action) {
    case RendererReloadAction::NEW_RENDERER:
      if (audio_renderer_)
        audio_renderer_->Stop();

      SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
      audio_renderer_ = renderer_factory_->GetAudioRenderer(
          web_stream_, internal_frame_->web_frame(),
          initial_audio_output_device_id_,
          WTF::BindRepeating(&WebMediaPlayerMS::OnAudioRenderErrorCallback,
                             weak_factory_.GetWeakPtr()));

      // |audio_renderer_| can be null in tests.
      if (!audio_renderer_)
        break;

      audio_renderer_->SetVolume(volume_);
      audio_renderer_->Start();
      audio_renderer_->Play();
      break;

    case RendererReloadAction::REMOVE_RENDERER:
      audio_renderer_->Stop();
      audio_renderer_ = nullptr;
      break;

    default:
      break;
  }

  // TODO(perkj, magjed): We use OneShot focus type here so that it takes
  // audio focus once it starts, and then will not respond to further audio
  // focus changes. See https://crbug.com/596516 for more details.
  client_->DidMediaMetadataChange(
      HasAudio(), HasVideo(), media::AudioCodec::kUnknown,
      media::VideoCodec::kUnknown, media::MediaContentType::kOneShot,
      /* is_encrypted_media */ false);
  delegate_->DidMediaMetadataChange(delegate_id_, HasAudio(), HasVideo(),
                                    media::MediaContentType::kOneShot);
}

void WebMediaPlayerMS::Play() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s()", __func__));

  media_log_->AddEvent<media::MediaLogEvent::kPlay>();
  if (!paused_)
    return;

  if (video_frame_provider_)
    video_frame_provider_->Resume();

  compositor_->StartRendering();

  if (audio_renderer_)
    audio_renderer_->Play();

  if (watch_time_reporter_) {
    watch_time_reporter_->SetAutoplayInitiated(client_->WasAutoplayInitiated());
    watch_time_reporter_->OnPlaying();
  }

  if (HasVideo()) {
    client_->DidPlayerSizeChange(NaturalSize());
    if (watch_time_reporter_)
      UpdateWatchTimeReporterSecondaryProperties();
  }

  client_->DidPlayerStartPlaying();
  delegate_->DidPlay(delegate_id_);

  delegate_->SetIdle(delegate_id_, false);
  paused_ = false;
}

void WebMediaPlayerMS::Pause() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s()", __func__));

  should_play_upon_shown_ = false;
  media_log_->AddEvent<media::MediaLogEvent::kPause>();
  if (paused_)
    return;

  if (video_frame_provider_)
    video_frame_provider_->Pause();

  compositor_->StopRendering();

  // Bounce this call off of video task runner to since there might still be
  // frames passed on video task runner.
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      WTF::CrossThreadBindOnce(
          [](scoped_refptr<base::SingleThreadTaskRunner> task_runner,
             WTF::CrossThreadOnceClosure copy_cb) {
            PostCrossThreadTask(*task_runner, FROM_HERE, std::move(copy_cb));
          },
          main_render_task_runner_,
          WTF::CrossThreadBindOnce(
              &WebMediaPlayerMS::ReplaceCurrentFrameWithACopy, weak_this_)));

  if (audio_renderer_)
    audio_renderer_->Pause();

  client_->DidPlayerPaused(/* stream_ended = */ false);
  if (watch_time_reporter_)
    watch_time_reporter_->OnPaused();

  delegate_->DidPause(delegate_id_, /* reached_e
```
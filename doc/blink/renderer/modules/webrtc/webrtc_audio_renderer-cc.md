Response:
My goal is to analyze the provided C++ code snippet and summarize its functionality, focusing on its role within the Chromium Blink engine, its interactions with web technologies, and potential error scenarios. Since this is part 1 of a 2-part analysis, I need to ensure the summary is comprehensive for the provided code but acknowledges that the full picture might emerge in part 2.

Here's a breakdown of the thought process:

1. **Identify the Core Class:** The primary class is `WebRtcAudioRenderer`. The filename confirms this. Understanding its purpose is central.

2. **Analyze Includes:** The included headers provide clues about the class's responsibilities:
    * `third_party/blink/renderer/modules/webrtc/webrtc_audio_renderer.h`:  The class definition itself.
    * `<utility>`, `<vector>`: Standard library for utilities and dynamic arrays.
    * `base/...`: Chromium base library for threading, logging, metrics, etc. This hints at asynchronous operations and performance tracking.
    * `media/audio/...`, `media/base/...`:  Media-related classes like `AudioBus`, `AudioParameters`, `AudioRendererSink`. This confirms the audio rendering role.
    * `third_party/blink/public/platform/modules/webrtc/...`: WebRTC platform interfaces.
    * `third_party/blink/public/platform/platform.h`:  Platform abstraction layer.
    * `third_party/blink/public/web/...`: WebKit-related interfaces, particularly `WebLocalFrame`. This links it to the browser's rendering process.
    * `third_party/blink/renderer/core/frame/...`: Core rendering engine frame concepts.
    * `third_party/blink/renderer/modules/mediastream/...`:  MediaStream API integration.
    * `third_party/blink/renderer/platform/...`: Platform-specific utilities.
    * `third_party/webrtc/api/...`:  WebRTC API.

3. **Examine Class Members:**  The class members reveal important state and dependencies:
    * `task_runner_`: For running tasks on the rendering thread.
    * `state_`:  Represents the current state of the renderer (uninitialized, playing, paused).
    * `source_frame_`:  The web frame the renderer is associated with.
    * `session_id_`, `media_stream_descriptor_`, `media_stream_descriptor_id_`:  Identifiers related to the media stream.
    * `source_`: A pointer to the `WebRtcAudioRendererSource` (the audio data provider).
    * `play_ref_count_`, `start_ref_count_`: Reference counts for managing play/start states, essential for shared usage.
    * `sink_params_`:  Audio parameters for the output device.
    * `output_device_id_`:  The selected audio output device.
    * `sink_`: A pointer to the `AudioRendererSink` (the actual audio output).
    * `speech_recognition_client_`:  Optional integration with speech recognition.
    * `audio_stream_tracker_`:  For monitoring the audio stream's activity.
    * `audio_fifo_`:  A FIFO buffer for managing audio data.
    * `audio_delay_`: The current audio output delay.
    * `current_time_`: The current rendering time.
    * `max_render_time_`:  Maximum time spent in `SourceCallback`.
    * `source_playing_states_`: Tracks the playing states of different audio sources.
    * `on_render_error_callback_`:  Callback for handling rendering errors.

4. **Analyze Key Methods:**  Focus on the public interface and important internal methods:
    * `Initialize()`: Sets up the renderer with a source and audio sink.
    * `CreateSharedAudioRendererProxy()`: Creates a wrapper for shared use, handling individual play/pause states. This is crucial for understanding how multiple web pages/elements can use the same underlying renderer.
    * `Start()`, `Play()`, `Pause()`, `Stop()`: Control the playback state. The distinction between `Start`/`Stop` and `Play`/`Pause` is important.
    * `SetVolume()`: Adjusts the output volume.
    * `SwitchOutputDevice()`:  Changes the audio output device.
    * `Render()`: The core method where audio data is processed and sent to the sink. This is called by the audio output device.
    * `SourceCallback()`: Called by the `AudioPullFifo` (or directly in some cases) to request audio data from the `source_`.
    * `OnPlayStateChanged()`, `OnPlayStateRemoved()`: Handle changes in the playback state of individual audio tracks within the stream. This is critical for managing multiple remote audio sources.
    * `PrepareSink()`: Configures the audio sink based on device capabilities.

5. **Identify Functionality:** Based on the above analysis, the primary functionalities are:
    * **Receiving and rendering audio data** from a `WebRtcAudioRendererSource`.
    * **Managing playback state** (playing, paused, stopped).
    * **Switching audio output devices.**
    * **Adjusting volume.**
    * **Integrating with the WebRTC framework.**
    * **Potentially interacting with speech recognition.**
    * **Monitoring audio stream health and performance.**
    * **Supporting shared usage** through the `SharedAudioRenderer` proxy.

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:**  The `WebRtcAudioRenderer` is the underlying engine for the Web Audio API and the `<audio>` element when used with WebRTC. JavaScript code using these APIs indirectly controls the behavior of this C++ class (play, pause, volume, output device selection).
    * **HTML:**  The `<audio>` element with a `MediaStream` as its source will utilize this renderer for WebRTC audio.
    * **CSS:** CSS doesn't directly interact with this class's core functionality, although it can style the visual controls associated with audio playback.

7. **Hypothesize Input and Output (Logical Reasoning):**
    * **Input:** Audio data from a remote peer, user actions (play, pause, volume changes), output device selection.
    * **Output:**  Audio played through the selected output device. Logging messages and metrics for debugging and monitoring. Callbacks for error handling.

8. **Identify User/Programming Errors:**
    * Calling `Play()` before `Start()`.
    * Incorrectly managing the lifecycle of the `SharedAudioRenderer` proxy.
    * Attempting to switch to an invalid audio output device.
    * Not handling render errors.

9. **Trace User Operations (Debugging Clues):**
    * A user initiates a WebRTC call in a web application.
    * The web application uses JavaScript to create a `RTCPeerConnection` and receives a remote audio stream.
    * The received `MediaStreamTrack` is assigned to an `<audio>` element or processed using the Web Audio API.
    * The browser's internal plumbing connects the `MediaStreamTrack` to the `WebRtcAudioRenderer`.
    * User clicks the "play" button on the audio controls, triggering JavaScript calls that eventually lead to `WebRtcAudioRenderer::Play()`.

10. **Summarize Functionality (Part 1 Focus):**  Focus on the capabilities evident in the provided code:  It initializes and manages the rendering of WebRTC audio, handles playback control, supports shared usage, and interacts with the audio output system. Acknowledge that the source of the audio and other details might be more apparent in part 2.

By following these steps, I can construct a detailed and accurate summary of the provided code, covering its core functionalities, interactions with web technologies, potential issues, and its role in the overall WebRTC audio rendering process. The separation into steps helps organize the analysis and ensures all key aspects are considered.
这是 Chromium Blink 引擎中 `blink/renderer/modules/webrtc/webrtc_audio_renderer.cc` 文件的第一部分，其主要功能是 **负责渲染来自 WebRTC 连接的音频流到用户的音频输出设备**。 它扮演着连接 WebRTC 音频源和底层音频输出系统的桥梁角色。

下面对它的功能进行更详细的列举和说明：

**主要功能:**

1. **音频流接收和处理:**
   - 接收来自 `WebRtcAudioRendererSource` 的音频数据。`WebRtcAudioRendererSource` 通常代表一个来自远程 PeerConnection 的音频轨道。
   - 管理接收到的音频数据，可能包括缓冲（通过 `audio_fifo_`）。
   - 处理音频延迟和抖动。

2. **音频输出管理:**
   - 与底层的音频渲染管道 (`media::AudioRendererSink`) 交互，将处理后的音频数据传递给系统进行播放。
   - 管理音频输出设备的选择和切换 (`SwitchOutputDevice`)。
   - 配置音频输出参数，例如采样率、声道布局等 (`PrepareSink`)。

3. **播放状态管理:**
   - 维护音频渲染器的播放状态 (`kUninitialized`, `kPlaying`, `kPaused`)。
   - 提供 `Play()`, `Pause()`, `Stop()` 方法来控制音频的播放。
   - 使用引用计数 (`play_ref_count_`, `start_ref_count_`) 来管理共享的渲染器实例的生命周期和播放状态。

4. **音量控制:**
   - 提供 `SetVolume()` 方法来调整音频的输出音量。

5. **性能监控和日志:**
   - 使用 UMA (User Metrics Analysis) 记录音频渲染相关的性能指标，例如渲染时间。
   - 提供日志记录功能 (`SendLogMessage`) 用于调试和跟踪。
   - 使用 `AudioStreamTracker` 监控音频流的活跃状态。

6. **与 WebRTC 集成:**
   - 与 `WebRtcAudioRendererSource` 紧密合作，接收来自 WebRTC 连接的音频数据。
   - 响应 WebRTC 音频源的播放状态变化 (`OnPlayStateChanged`, `OnPlayStateRemoved`)。

7. **共享渲染器实例:**
   - 提供 `CreateSharedAudioRendererProxy()` 方法，允许在多个地方共享同一个 `WebRtcAudioRenderer` 实例，并独立管理各自的播放状态。

**与 JavaScript, HTML, CSS 的关系：**

`WebRtcAudioRenderer` 本身是用 C++ 编写的，直接与 JavaScript, HTML, CSS 没有直接的语法上的交互。但是，它的功能是 WebRTC API 的底层实现，因此与这些技术有着密切的功能关系：

* **JavaScript:**
    - JavaScript 代码通过 WebRTC API（例如 `RTCPeerConnection`, `MediaStreamTrack`）控制音频流的接收和播放。
    - 当 JavaScript 调用 `audioTrack.enabled = true` 或将 `MediaStreamTrack` 设置为 `<audio>` 元素的 `srcObject` 时，会间接触发 `WebRtcAudioRenderer` 的初始化和播放。
    - JavaScript 可以调用 `audio.play()` 和 `audio.pause()` 方法，这些操作会最终影响 `WebRtcAudioRenderer` 的播放状态。
    - JavaScript 可以通过 `HTMLMediaElement.volume` 属性来设置音量，这会最终调用 `WebRtcAudioRenderer::SetVolume()`。
    - JavaScript 可以使用 `navigator.mediaDevices.selectAudioOutput()` 来选择音频输出设备，这会触发 `WebRtcAudioRenderer::SwitchOutputDevice()`。

    **举例说明 (假设输入与输出):**
    - **假设输入 (JavaScript):**  用户在网页上点击了 "播放" 按钮，触发 JavaScript 代码 `audioElement.play()`，其中 `audioElement` 的 `srcObject` 是一个来自 WebRTC 连接的音频流。
    - **对应输出 (C++):** 这会最终导致 `WebRtcAudioRenderer` 的 `Play()` 方法被调用，将渲染器的状态设置为 `kPlaying`，并开始从 `WebRtcAudioRendererSource` 获取音频数据进行渲染。

* **HTML:**
    - `<audio>` 元素可以用来播放来自 WebRTC 的音频流。当 `<audio>` 元素的 `srcObject` 属性设置为一个包含 WebRTC 音频轨道的 `MediaStream` 时，浏览器内部会将这个音频轨道连接到 `WebRtcAudioRenderer` 进行渲染。

    **举例说明:**
    ```html
    <audio id="remoteAudio" autoplay></audio>
    <script>
      const remoteAudio = document.getElementById('remoteAudio');
      // ... 从 RTCPeerConnection 获取 remoteStream ...
      remoteAudio.srcObject = remoteStream;
    </script>
    ```
    当 `remoteAudio.srcObject` 被设置时，Blink 引擎会创建或获取一个 `WebRtcAudioRenderer` 实例来渲染 `remoteStream` 中的音频轨道。

* **CSS:**
    - CSS 主要负责控制网页的样式和布局，与 `WebRtcAudioRenderer` 的核心功能没有直接关系。但是，CSS 可以用来美化与音频播放相关的控制元素（例如播放/暂停按钮，音量滑块）。

**逻辑推理和假设输入与输出:**

该文件中的逻辑主要围绕着音频流的处理和状态管理。

**假设输入:**

1. **`Initialize(source)`:** 接收一个 `WebRtcAudioRendererSource` 指针作为音频数据的来源。
   - **输出:** 如果初始化成功，内部 `source_` 指针会被设置为传入的 `source`，并且音频 sink (`sink_`) 会被创建和启动。返回 `true`。
2. **`Play()`:** 被调用以开始播放。
   - **假设当前状态:**  渲染器处于 `kPaused` 状态。
   - **输出:** 内部状态会变为 `kPlaying`，开始从 `WebRtcAudioRendererSource` 请求音频数据，并通过音频 sink 进行播放。
3. **`Render(delay, delay_timestamp, glitch_info, audio_bus)`:**  接收音频延迟信息和一个空的 `audio_bus`。
   - **假设输入:**  渲染器处于 `kPlaying` 状态，`source_` 指针有效。
   - **输出:** 调用 `source_->RenderData()` 从音频源获取数据填充 `audio_bus`，返回填充的音频帧数。如果渲染器不在 `kPlaying` 状态，则 `audio_bus` 会被清零，返回 0。

**用户或编程常见的使用错误:**

1. **在 `Initialize()` 之前调用 `Play()`:**  会导致渲染器无法正常工作，因为没有音频源。
2. **忘记调用 `Start()`:** `Start()` 方法增加了 `start_ref_count_`，这对于管理渲染器的生命周期很重要。如果在没有调用 `Start()` 的情况下直接调用 `Play()`，可能会导致断言失败或行为异常。
3. **在渲染器被销毁后仍然尝试使用它:** 这会导致访问已释放的内存。`SharedAudioRenderer` 的设计旨在帮助管理这种情况，但如果直接使用 `WebRtcAudioRenderer`，则需要小心管理其生命周期。
4. **没有正确处理 `SwitchOutputDevice` 的回调:**  `SwitchOutputDevice` 是异步操作，需要通过回调来获取操作结果。如果忽略回调，可能无法正确处理设备切换的失败情况。
5. **假设音频数据始终可用:**  网络状况不佳时，可能会出现音频数据丢失或延迟，需要在上层做好处理。

**用户操作到达此处的调试线索:**

1. **用户在浏览器中打开一个支持 WebRTC 的网页。**
2. **网页上的 JavaScript 代码通过 `getUserMedia()` 获取用户的本地媒体流，或者通过 `RTCPeerConnection` 连接到远程用户。**
3. **建立 WebRTC 连接后，远程用户的音频轨道会被添加到本地的 `RTCPeerConnection`。**
4. **网页上的 JavaScript 代码可能将远程音频轨道设置为一个 `<audio>` 元素的 `srcObject`，或者使用 Web Audio API 进行处理。**
5. **当 `<audio>` 元素尝试播放音频时，或者 Web Audio API 需要音频数据时，Blink 引擎会创建 `WebRtcAudioRenderer` 实例来渲染来自远程音频轨道的音频数据。**
6. **在渲染过程中，音频 sink 会定期调用 `Render()` 方法来获取音频数据。**

**功能归纳 (针对第 1 部分):**

`WebRtcAudioRenderer` 的主要功能是作为 Chromium Blink 引擎中 WebRTC 音频渲染的核心组件。它负责接收、处理来自 WebRTC 音频源的音频数据，并将其输出到用户的音频设备。它管理音频播放状态、音量，并提供设备切换功能。其设计支持共享实例以优化资源利用。 这部分代码涵盖了渲染器的初始化、播放控制、音频数据的处理和输出管理的基本框架。后续部分可能涉及更细节的音频处理逻辑或者与其他模块的交互。

Prompt: 
```
这是目录为blink/renderer/modules/webrtc/webrtc_audio_renderer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_renderer.h"

#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/ranges/algorithm.h"
#include "base/task/bind_post_task.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "build/build_config.h"
#include "media/audio/audio_sink_parameters.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_capturer_source.h"
#include "media/base/audio_latency.h"
#include "media/base/audio_parameters.h"
#include "media/base/audio_timestamp_helper.h"
#include "media/base/channel_layout.h"
#include "media/base/sample_rates.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_audio_renderer.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/webrtc/peer_connection_remote_audio_source.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/webrtc/api/media_stream_interface.h"

namespace WTF {

template <typename T>
struct CrossThreadCopier<rtc::scoped_refptr<T>> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = rtc::scoped_refptr<T>;
  static Type Copy(Type pointer) { return pointer; }
};

}  // namespace WTF

namespace blink {

namespace {

// Audio parameters that don't change.
const media::AudioParameters::Format kFormat =
    media::AudioParameters::AUDIO_PCM_LOW_LATENCY;

// Time constant for AudioPowerMonitor. See See AudioPowerMonitor ctor comments
// for details.
constexpr base::TimeDelta kPowerMeasurementTimeConstant =
    base::Milliseconds(10);

// Time in seconds between two successive measurements of audio power levels.
constexpr base::TimeDelta kPowerMonitorLogInterval = base::Seconds(15);

// Used for UMA histograms.
const int kRenderTimeHistogramMinMicroseconds = 100;
const int kRenderTimeHistogramMaxMicroseconds = 1 * 1000 * 1000;  // 1 second

const char* OutputDeviceStatusToString(media::OutputDeviceStatus status) {
  switch (status) {
    case media::OUTPUT_DEVICE_STATUS_OK:
      return "OK";
    case media::OUTPUT_DEVICE_STATUS_ERROR_NOT_FOUND:
      return "ERROR_NOT_FOUND";
    case media::OUTPUT_DEVICE_STATUS_ERROR_NOT_AUTHORIZED:
      return "ERROR_NOT_AUTHORIZED";
    case media::OUTPUT_DEVICE_STATUS_ERROR_TIMED_OUT:
      return "ERROR_TIMED_OUT";
    case media::OUTPUT_DEVICE_STATUS_ERROR_INTERNAL:
      return "ERROR_INTERNAL";
  }
}

const char* StateToString(WebRtcAudioRenderer::State state) {
  switch (state) {
    case WebRtcAudioRenderer::kUninitialized:
      return "UNINITIALIZED";
    case WebRtcAudioRenderer::kPlaying:
      return "PLAYING";
    case WebRtcAudioRenderer::kPaused:
      return "PAUSED";
  }
}

// This is a simple wrapper class that's handed out to users of a shared
// WebRtcAudioRenderer instance.  This class maintains the per-user 'playing'
// and 'started' states to avoid problems related to incorrect usage which
// might violate the implementation assumptions inside WebRtcAudioRenderer
// (see the play reference count).
class SharedAudioRenderer : public MediaStreamAudioRenderer {
 public:
  // Callback definition for a callback that is called when when Play(), Pause()
  // or SetVolume are called (whenever the internal |playing_state_| changes).
  using OnPlayStateChanged =
      base::RepeatingCallback<void(MediaStreamDescriptor*,
                                   WebRtcAudioRenderer::PlayingState*)>;

  // Signals that the PlayingState* is about to become invalid, see comment in
  // OnPlayStateRemoved.
  using OnPlayStateRemoved =
      base::OnceCallback<void(WebRtcAudioRenderer::PlayingState*)>;

  SharedAudioRenderer(const scoped_refptr<MediaStreamAudioRenderer>& delegate,
                      MediaStreamDescriptor* media_stream_descriptor,
                      const OnPlayStateChanged& on_play_state_changed,
                      OnPlayStateRemoved on_play_state_removed)
      : delegate_(delegate),
        media_stream_descriptor_(media_stream_descriptor),
        started_(false),
        on_play_state_changed_(on_play_state_changed),
        on_play_state_removed_(std::move(on_play_state_removed)) {
    DCHECK(!on_play_state_changed_.is_null());
    DCHECK(media_stream_descriptor_);
  }

 protected:
  ~SharedAudioRenderer() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    DVLOG(1) << __func__;
    Stop();
    std::move(on_play_state_removed_).Run(&playing_state_);
  }

  void Start() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    if (started_)
      return;
    started_ = true;
    delegate_->Start();
  }

  void Play() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    if (!started_ || playing_state_.playing())
      return;
    playing_state_.set_playing(true);
    on_play_state_changed_.Run(media_stream_descriptor_, &playing_state_);
  }

  void Pause() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    if (!started_ || !playing_state_.playing())
      return;
    playing_state_.set_playing(false);
    on_play_state_changed_.Run(media_stream_descriptor_, &playing_state_);
  }

  void Stop() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    if (!started_)
      return;
    Pause();
    started_ = false;
    delegate_->Stop();
  }

  void SetVolume(float volume) override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    DCHECK(volume >= 0.0f && volume <= 1.0f);
    playing_state_.set_volume(volume);
    on_play_state_changed_.Run(media_stream_descriptor_, &playing_state_);
  }

  void SwitchOutputDevice(const std::string& device_id,
                          media::OutputDeviceStatusCB callback) override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    return delegate_->SwitchOutputDevice(device_id, std::move(callback));
  }

  base::TimeDelta GetCurrentRenderTime() override {
    DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    return delegate_->GetCurrentRenderTime();
  }

 private:
  THREAD_CHECKER(thread_checker_);
  const scoped_refptr<MediaStreamAudioRenderer> delegate_;
  Persistent<MediaStreamDescriptor> media_stream_descriptor_;
  bool started_;
  WebRtcAudioRenderer::PlayingState playing_state_;
  OnPlayStateChanged on_play_state_changed_;
  OnPlayStateRemoved on_play_state_removed_;
};

}  // namespace

WebRtcAudioRenderer::AudioStreamTracker::AudioStreamTracker(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    WebRtcAudioRenderer* renderer,
    int sample_rate)
    : task_runner_(std::move(task_runner)),
      renderer_(renderer),
      start_time_(base::TimeTicks::Now()),
      render_callbacks_started_(false),
      check_alive_timer_(task_runner_,
                         this,
                         &WebRtcAudioRenderer::AudioStreamTracker::CheckAlive),
      power_monitor_(sample_rate, kPowerMeasurementTimeConstant),
      last_audio_level_log_time_(base::TimeTicks::Now()) {
  weak_this_ = weak_factory_.GetWeakPtr();
  // CheckAlive() will look to see if |render_callbacks_started_| is true
  // after the timeout expires and log this. If the stream is paused/closed
  // before the timer fires, a warning is logged instead.
  check_alive_timer_.StartOneShot(base::Seconds(5), FROM_HERE);
}

WebRtcAudioRenderer::AudioStreamTracker::~AudioStreamTracker() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(renderer_);
  const auto duration = base::TimeTicks::Now() - start_time_;
  renderer_->SendLogMessage(
      String::Format("%s => (media stream duration=%" PRId64 " seconds)",
                     __func__, duration.InSeconds()));
}

void WebRtcAudioRenderer::AudioStreamTracker::OnRenderCallbackCalled() {
  DCHECK(renderer_->CurrentThreadIsRenderingThread());
  // Indicate that render callbacks has started as expected and within a
  // reasonable time. Since this thread is the only writer of
  // |render_callbacks_started_| once the thread starts, it's safe to compare
  // and then change the state once.
  if (!render_callbacks_started_)
    render_callbacks_started_ = true;
}

void WebRtcAudioRenderer::AudioStreamTracker::MeasurePower(
    const media::AudioBus& buffer,
    int frames) {
  DCHECK(renderer_->CurrentThreadIsRenderingThread());
  // Update the average power estimate on the rendering thread to avoid posting
  // a task which also has to copy the audio bus. According to comments in
  // AudioPowerMonitor::Scan(), it should be safe. Note that, we only check the
  // power once every ten seconds (on the |task_runner_| thread) and the result
  // is only used for logging purposes.
  power_monitor_.Scan(buffer, frames);
  const auto now = base::TimeTicks::Now();
  if ((now - last_audio_level_log_time_) > kPowerMonitorLogInterval) {
    // Log the current audio level but avoid using the render thread to reduce
    // its load and to ensure that |power_monitor_| is mainly accessed on one
    // thread. |weak_ptr_factory_| ensures that the task is canceled when
    // |this| is destroyed since we can't guarantee that |this| outlives the
    // task.
    PostCrossThreadTask(
        *task_runner_, FROM_HERE,
        CrossThreadBindOnce(&AudioStreamTracker::LogAudioPowerLevel,
                            weak_this_));
    last_audio_level_log_time_ = now;
  }
}

void WebRtcAudioRenderer::AudioStreamTracker::LogAudioPowerLevel() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::pair<float, bool> power_and_clip =
      power_monitor_.ReadCurrentPowerAndClip();
  renderer_->SendLogMessage(String::Format(
      "%s => (average audio level=%.2f dBFS)", __func__, power_and_clip.first));
}

void WebRtcAudioRenderer::AudioStreamTracker::CheckAlive(TimerBase*) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(renderer_);
  renderer_->SendLogMessage(String::Format(
      "%s => (%s)", __func__,
      render_callbacks_started_ ? "stream is alive"
                                : "WARNING: stream is not alive"));
}

WebRtcAudioRenderer::WebRtcAudioRenderer(
    const scoped_refptr<base::SingleThreadTaskRunner>& signaling_thread,
    MediaStreamDescriptor* media_stream_descriptor,
    WebLocalFrame& web_frame,
    const base::UnguessableToken& session_id,
    const String& device_id,
    base::RepeatingCallback<void()> on_render_error_callback)
    : task_runner_(web_frame.GetTaskRunner(TaskType::kInternalMediaRealTime)),
      state_(kUninitialized),
      source_frame_(To<LocalFrame>(WebFrame::ToCoreFrame(web_frame))),
      session_id_(session_id),
      signaling_thread_(signaling_thread),
      media_stream_descriptor_(media_stream_descriptor),
      media_stream_descriptor_id_(media_stream_descriptor_->Id()),
      source_(nullptr),
      play_ref_count_(0),
      start_ref_count_(0),
      sink_params_(kFormat, media::ChannelLayoutConfig::Stereo(), 0, 0),
      output_device_id_(device_id),
      on_render_error_callback_(std::move(on_render_error_callback)) {
  if (web_frame.Client()) {
    speech_recognition_client_ =
        web_frame.Client()->CreateSpeechRecognitionClient();
  }

  SendLogMessage(
      String::Format("%s({session_id=%s}, {device_id=%s})", __func__,
                     session_id.is_empty() ? "" : session_id.ToString().c_str(),
                     device_id.Utf8().c_str()));
}

WebRtcAudioRenderer::~WebRtcAudioRenderer() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(state_, kUninitialized);
}

bool WebRtcAudioRenderer::Initialize(WebRtcAudioRendererSource* source) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(source);
  DCHECK(!sink_.get());
  {
    base::AutoLock auto_lock(lock_);
    DCHECK_EQ(state_, kUninitialized);
    DCHECK(!source_);
  }
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));

  media::AudioSinkParameters sink_params(session_id_, output_device_id_.Utf8());
  sink_ = Platform::Current()->NewAudioRendererSink(
      WebAudioDeviceSourceType::kWebRtc,
      static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(source_frame_)),
      sink_params);

  media::OutputDeviceStatus sink_status =
      sink_->GetOutputDeviceInfo().device_status();
  UMA_HISTOGRAM_ENUMERATION("Media.Audio.WebRTCAudioRenderer.DeviceStatus",
                            sink_status, media::OUTPUT_DEVICE_STATUS_MAX + 1);
  SendLogMessage(String::Format("%s => (sink device_status=%s)", __func__,
                                OutputDeviceStatusToString(sink_status)));
  if (sink_status != media::OUTPUT_DEVICE_STATUS_OK) {
    SendLogMessage(String::Format("%s => (ERROR: invalid output device status)",
                                  __func__));
    sink_->Stop();
    return false;
  }

  PrepareSink();
  {
    // No need to reassert the preconditions because the other thread
    // accessing the fields only reads them.
    base::AutoLock auto_lock(lock_);
    source_ = source;

    // User must call Play() before any audio can be heard.
    state_ = kPaused;
  }
  source_->SetOutputDeviceForAec(output_device_id_);
  sink_->Start();
  sink_->Play();  // Not all the sinks play on start.

  return true;
}

scoped_refptr<MediaStreamAudioRenderer>
WebRtcAudioRenderer::CreateSharedAudioRendererProxy(
    MediaStreamDescriptor* media_stream_descriptor) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SharedAudioRenderer::OnPlayStateChanged on_play_state_changed =
      WTF::BindRepeating(&WebRtcAudioRenderer::OnPlayStateChanged,
                         WrapRefCounted(this));
  SharedAudioRenderer::OnPlayStateRemoved on_play_state_removed = WTF::BindOnce(
      &WebRtcAudioRenderer::OnPlayStateRemoved, WrapRefCounted(this));
  return base::MakeRefCounted<SharedAudioRenderer>(
      this, media_stream_descriptor, std::move(on_play_state_changed),
      std::move(on_play_state_removed));
}

bool WebRtcAudioRenderer::IsStarted() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return start_ref_count_ != 0;
}

bool WebRtcAudioRenderer::CurrentThreadIsRenderingThread() {
  return sink_->CurrentThreadIsRenderingThread();
}

void WebRtcAudioRenderer::Start() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));
  ++start_ref_count_;
}

void WebRtcAudioRenderer::Play() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));
  if (playing_state_.playing())
    return;

  playing_state_.set_playing(true);

  OnPlayStateChanged(media_stream_descriptor_, &playing_state_);
}

void WebRtcAudioRenderer::EnterPlayState() {
  DVLOG(1) << "WebRtcAudioRenderer::EnterPlayState()";
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_GT(start_ref_count_, 0) << "Did you forget to call Start()?";
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));
  base::AutoLock auto_lock(lock_);
  if (state_ == kUninitialized)
    return;

  DCHECK(play_ref_count_ == 0 || state_ == kPlaying);
  ++play_ref_count_;

  if (state_ != kPlaying) {
    state_ = kPlaying;

    audio_stream_tracker_.emplace(task_runner_, this,
                                  sink_params_.sample_rate());

    if (audio_fifo_) {
      audio_delay_ = base::TimeDelta();
      audio_fifo_->Clear();
    }
  }
  SendLogMessage(
      String::Format("%s => (state=%s)", __func__, StateToString(state_)));
}

void WebRtcAudioRenderer::Pause() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));
  if (!playing_state_.playing())
    return;

  playing_state_.set_playing(false);

  OnPlayStateChanged(media_stream_descriptor_, &playing_state_);
}

void WebRtcAudioRenderer::EnterPauseState() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_GT(start_ref_count_, 0) << "Did you forget to call Start()?";
  SendLogMessage(
      String::Format("%s([state=%s])", __func__, StateToString(state_)));
  base::AutoLock auto_lock(lock_);
  if (state_ == kUninitialized)
    return;

  DCHECK_EQ(state_, kPlaying);
  DCHECK_GT(play_ref_count_, 0);
  if (!--play_ref_count_)
    state_ = kPaused;
  SendLogMessage(
      String::Format("%s => (state=%s)", __func__, StateToString(state_)));
}

void WebRtcAudioRenderer::Stop() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  {
    SendLogMessage(
        String::Format("%s([state=%s])", __func__, StateToString(state_)));
    base::AutoLock auto_lock(lock_);
    if (state_ == kUninitialized)
      return;

    if (--start_ref_count_)
      return;

    audio_stream_tracker_.reset();
    source_->RemoveAudioRenderer(this);
    source_ = nullptr;
    state_ = kUninitialized;
  }

  // Apart from here, |max_render_time_| is only accessed in SourceCallback(),
  // which is guaranteed to not run after |source_| has been set to null, and
  // not before this function has returned.
  // If |max_render_time_| is zero, no render call has been made.
  if (!max_render_time_.is_zero()) {
    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "Media.Audio.Render.GetSourceDataTimeMax.WebRTC",
        static_cast<int>(max_render_time_.InMicroseconds()),
        kRenderTimeHistogramMinMicroseconds,
        kRenderTimeHistogramMaxMicroseconds, 50);
    SendLogMessage(String::Format("%s => (max_render_time=%.3f ms)", __func__,
                                  max_render_time_.InMillisecondsF()));
    max_render_time_ = base::TimeDelta();
  }

  // Make sure to stop the sink while _not_ holding the lock since the Render()
  // callback may currently be executing and trying to grab the lock while we're
  // stopping the thread on which it runs.
  sink_->Stop();
}

void WebRtcAudioRenderer::SetVolume(float volume) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(volume >= 0.0f && volume <= 1.0f);
  SendLogMessage(String::Format("%s({volume=%.2f})", __func__, volume));

  playing_state_.set_volume(volume);
  OnPlayStateChanged(media_stream_descriptor_, &playing_state_);
}

base::TimeDelta WebRtcAudioRenderer::GetCurrentRenderTime() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  base::AutoLock auto_lock(lock_);
  return current_time_;
}

void WebRtcAudioRenderer::SwitchOutputDevice(
    const std::string& device_id,
    media::OutputDeviceStatusCB callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s({device_id=%s} [state=%s])", __func__,
                                device_id.c_str(), StateToString(state_)));
  if (!source_) {
    SendLogMessage(String::Format(
        "%s => (ERROR: OUTPUT_DEVICE_STATUS_ERROR_INTERNAL)", __func__));
    std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_ERROR_INTERNAL);
    return;
  }

  {
    base::AutoLock auto_lock(lock_);
    DCHECK_NE(state_, kUninitialized);
  }

  auto* web_frame =
      static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(source_frame_));
  if (!web_frame) {
    SendLogMessage(String::Format("%s => (ERROR: No Frame)", __func__));
    std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_ERROR_INTERNAL);
    return;
  }

  if (sink_ && output_device_id_ == String::FromUTF8(device_id)) {
    std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_OK);
    return;
  }

  media::AudioSinkParameters sink_params(session_id_, device_id);
  scoped_refptr<media::AudioRendererSink> new_sink =
      Platform::Current()->NewAudioRendererSink(
          WebAudioDeviceSourceType::kWebRtc, web_frame, sink_params);
  media::OutputDeviceStatus status =
      new_sink->GetOutputDeviceInfo().device_status();
  UMA_HISTOGRAM_ENUMERATION(
      "Media.Audio.WebRTCAudioRenderer.SwitchDeviceStatus", status,
      media::OUTPUT_DEVICE_STATUS_MAX + 1);
  SendLogMessage(String::Format("%s => (sink device_status=%s)", __func__,
                                OutputDeviceStatusToString(status)));

  if (status != media::OUTPUT_DEVICE_STATUS_OK) {
    SendLogMessage(
        String::Format("%s => (ERROR: invalid sink device status)", __func__));
    new_sink->Stop();
    std::move(callback).Run(status);
    return;
  }

  // Make sure to stop the sink while _not_ holding the lock since the Render()
  // callback may currently be executing and trying to grab the lock while we're
  // stopping the thread on which it runs.
  sink_->Stop();
  sink_ = new_sink;
  output_device_id_ = String::FromUTF8(device_id);
  {
    base::AutoLock auto_lock(lock_);
    source_->AudioRendererThreadStopped();
  }
  source_->SetOutputDeviceForAec(output_device_id_);
  PrepareSink();
  sink_->Start();
  sink_->Play();  // Not all the sinks play on start.

  std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_OK);
}

int WebRtcAudioRenderer::Render(base::TimeDelta delay,
                                base::TimeTicks delay_timestamp,
                                const media::AudioGlitchInfo& glitch_info,
                                media::AudioBus* audio_bus) {
  TRACE_EVENT("audio", "WebRtcAudioRenderer::Render", "playout_delay (ms)",
              delay.InMillisecondsF(), "delay_timestamp (ms)",
              (delay_timestamp - base::TimeTicks()).InMillisecondsF());
  DCHECK(sink_->CurrentThreadIsRenderingThread());
  DCHECK_LE(sink_params_.channels(), 8);
  base::AutoLock auto_lock(lock_);
  if (!source_)
    return 0;

  audio_delay_ = delay;
  glitch_info_accumulator_.Add(glitch_info);

  // Pull the data we will deliver.
  if (audio_fifo_)
    audio_fifo_->Consume(audio_bus, audio_bus->frames());
  else
    SourceCallback(0, audio_bus);

  if (state_ == kPlaying && audio_stream_tracker_) {
    // Mark the stream as alive the first time this method is called.
    audio_stream_tracker_->OnRenderCallbackCalled();
    audio_stream_tracker_->MeasurePower(*audio_bus, audio_bus->frames());
  }

  if (speech_recognition_client_) {
    speech_recognition_client_->AddAudio(*audio_bus);
  }

  return (state_ == kPlaying) ? audio_bus->frames() : 0;
}

void WebRtcAudioRenderer::OnRenderError() {
  DCHECK(on_render_error_callback_);
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebRtcAudioRenderer::OnRenderErrorCrossThread,
                          WrapRefCounted(this)));
}

void WebRtcAudioRenderer::OnRenderErrorCrossThread() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  on_render_error_callback_.Run();
}

// Called by AudioPullFifo when more data is necessary.
void WebRtcAudioRenderer::SourceCallback(int fifo_frame_delay,
                                         media::AudioBus* audio_bus) {
  TRACE_EVENT("audio", "WebRtcAudioRenderer::SourceCallback", "delay (frames)",
              fifo_frame_delay);
  DCHECK(sink_->CurrentThreadIsRenderingThread());
  base::TimeTicks start_time = base::TimeTicks::Now();
  DVLOG(2) << "WRAR::SourceCallback(" << fifo_frame_delay << ", "
           << audio_bus->channels() << ", " << audio_bus->frames() << ")";

  const base::TimeDelta output_delay =
      audio_delay_ + media::AudioTimestampHelper::FramesToTime(
                         fifo_frame_delay, sink_params_.sample_rate());
  DVLOG(2) << "output_delay (ms): " << output_delay.InMillisecondsF();

  // We need to keep render data for the |source_| regardless of |state_|,
  // otherwise the data will be buffered up inside |source_|.
  source_->RenderData(audio_bus, sink_params_.sample_rate(), output_delay,
                      &current_time_, glitch_info_accumulator_.GetAndReset());

  // Avoid filling up the audio bus if we are not playing; instead
  // return here and ensure that the returned value in Render() is 0.
  if (state_ != kPlaying)
    audio_bus->Zero();

  // Measure the elapsed time for this function and log it to UMA. Store the max
  // value. Don't do this for low resolution clocks to not skew data.
  if (base::TimeTicks::IsHighResolution()) {
    base::TimeDelta elapsed = base::TimeTicks::Now() - start_time;
    UMA_HISTOGRAM_CUSTOM_COUNTS("Media.Audio.Render.GetSourceDataTime.WebRTC",
                                static_cast<int>(elapsed.InMicroseconds()),
                                kRenderTimeHistogramMinMicroseconds,
                                kRenderTimeHistogramMaxMicroseconds, 50);

    if (elapsed > max_render_time_)
      max_render_time_ = elapsed;
  }
}

void WebRtcAudioRenderer::UpdateSourceVolume(
    webrtc::AudioSourceInterface* source) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Note: If there are no playing audio renderers, then the volume will be
  // set to 0.0.
  float volume = 0.0f;

  auto entry = source_playing_states_.find(source);
  if (entry != source_playing_states_.end()) {
    PlayingStates& states = entry->second;
    for (PlayingStates::const_iterator it = states.begin(); it != states.end();
         ++it) {
      if ((*it)->playing())
        volume += (*it)->volume();
    }
  }

  // The valid range for volume scaling of a remote webrtc source is
  // 0.0-10.0 where 1.0 is no attenuation/boost.
  DCHECK(volume >= 0.0f);
  if (volume > 10.0f)
    volume = 10.0f;

  SendLogMessage(String::Format("%s => (source volume changed to %.2f)",
                                __func__, volume));
  if (!signaling_thread_->BelongsToCurrentThread()) {
    // Libjingle hands out proxy objects in most cases, but the audio source
    // object is an exception (bug?).  So, to work around that, we need to make
    // sure we call SetVolume on the signaling thread.
    PostCrossThreadTask(
        *signaling_thread_, FROM_HERE,
        CrossThreadBindOnce(
            &webrtc::AudioSourceInterface::SetVolume,
            rtc::scoped_refptr<webrtc::AudioSourceInterface>(source), volume));
  } else {
    source->SetVolume(volume);
  }
}

bool WebRtcAudioRenderer::AddPlayingState(webrtc::AudioSourceInterface* source,
                                          PlayingState* state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(state->playing());
  // Look up or add the |source| to the map.
  PlayingStates& array = source_playing_states_[source];
  if (base::Contains(array, state))
    return false;

  array.push_back(state);
  SendLogMessage(String::Format("%s => (number of playing audio sources=%d)",
                                __func__, static_cast<int>(array.size())));

  return true;
}

bool WebRtcAudioRenderer::RemovePlayingState(
    webrtc::AudioSourceInterface* source,
    PlayingState* state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!state->playing());
  auto found = source_playing_states_.find(source);
  if (found == source_playing_states_.end())
    return false;

  PlayingStates& array = found->second;
  auto state_it = base::ranges::find(array, state);
  if (state_it == array.end())
    return false;

  array.erase(state_it);

  if (array.empty())
    source_playing_states_.erase(found);

  return true;
}

void WebRtcAudioRenderer::OnPlayStateChanged(
    MediaStreamDescriptor* media_stream_descriptor,
    PlayingState* state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const HeapVector<Member<MediaStreamComponent>>& components =
      media_stream_descriptor->AudioComponents();

  for (auto component : components) {
    // WebRtcAudioRenderer can only render audio tracks received from a remote
    // peer. Since the actual MediaStream is mutable from JavaScript, we need
    // to make sure |component| is actually a remote track.
    PeerConnectionRemoteAudioTrack* const remote_track =
        PeerConnectionRemoteAudioTrack::From(
            MediaStreamAudioTrack::From(component.Get()));
    if (!remote_track)
      continue;
    webrtc::AudioSourceInterface* source =
        remote_track->track_interface()->GetSource();
    DCHECK(source);
    if (!state->playing()) {
      if (RemovePlayingState(source, state))
        EnterPauseState();
    } else if (AddPlayingState(source, state)) {
      EnterPlayState();
    }
    UpdateSourceVolume(source);
  }
}

void WebRtcAudioRenderer::OnPlayStateRemoved(PlayingState* state) {
  // It is possible we associated |state| to a source for a track that is no
  // longer easily reachable. We iterate over |source_playing_states_| to
  // ensure there are no dangling pointers to |state| there. See
  // crbug.com/697256.
  // TODO(maxmorin): Clean up cleanup code in this and related classes so that
  // this hack isn't necessary.
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (auto it = source_playing_states_.begin();
       it != source_playing_states_.end();) {
    PlayingStates& states = it->second;
    // We cannot use RemovePlayingState as it might invalidate |it|.
    std::erase(states, state);
    if (states.empty())
      it = source_playing_states_.erase(it);
    else
      ++it;
  }
}

void WebRtcAudioRenderer::PrepareSink() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s()", __func__));
  media::AudioParameters new_sink_params;
  {
    base::AutoLock lock(lock_);
    new_sink_params = sink_params_;
  }

  const media::OutputDeviceInfo& device_info = sink_->GetOutputDeviceInfo();
  DCHECK_EQ(device_info.device_status(), media::OUTPUT_DEVICE_STATUS_OK);
  SendLogMessage(String::Format(
      "%s => (hardware parameters=[%s])", __func__,
      device_info.output_params().AsHumanReadableString().c_str()));

  // WebRTC does not yet support higher rates than 192000 on the client side
  // and 48000 is the preferred sample rate. Therefore, if 192000 is detected,
  // we change the rate to 48000 instead. The consequence is that the native
  // layer will be opened up at 192kHz but WebRTC will provide data at 48kHz
  // which will then be resampled by the audio converted on the browser side
  // to match the native audio layer.
  int sample_rate = device_info.output_params().sample_rate();
  if (sample_rate >= 192000) {
    SendLogMessage(
        String::Format("%s => (WARNING: WebRTC provides audio at 48kHz and "
                       "resampling takes place to match %dHz)",
                       __func__, sample_rate));
    sample_rate = 48000;
  }
  DVLOG(1) << "WebRtcAudioRenderer::PrepareSink sample_rate " << sample_rate;

  media::AudioSampleRate asr;
  if (media::ToAudioSampleRate(sample_rate, &asr)) {
    UMA_HISTOGRAM_ENUMERATION("WebRTC.AudioOutputSampleRate", asr,
                              media::kAudioSampleRateMax + 1);
  } else {
    UMA_HISTOGRAM_COUNTS_1M("WebRTC.AudioOutputSampleRateUnexpected",
                            sample_rate);
  }

  // Calculate the frames per buffer for the source, i.e. the WebRTC client. We
  // use 10 ms of data since the WebRTC client only supports multiples of 10 ms
  // as buffer size where 10 ms is preferred for lowest possible delay.
  const int source_frames_per_buffer = (sample_rate / 100);
  SendLogMessage(String::Format("%s => (source_frames_per_buffer=%d)", __func__,
                                source_frames_per_buffer));

  // Setup sink parameters using same channel configuration as the source.
  // This sink is an AudioRendererSink which is implemented by an
  // AudioOutputDevice. Note that we used to use hard-coded settings for
  // stereo here but this has been changed since crbug.com/982276.
  constexpr int kMaxChannels = 8;
  int channels = device_info.output_params().channels();
  media::ChannelLayout channel_layout =
      device_info.output_params().channel_layout();
  if (channels > kMaxChannels) {
    // WebRTC does not support channel remixing for more than 8 channels (7.1).
    // This is an attempt to "support" more than 8 channels by falling back to
    // stereo instead. See crbug.com/1003735.
    SendLogMessage(
        String::Format("%s => (WARNING: sink falls back to stereo)", __func__));
    channels = 2;
    channel_layout = media::CHANNE
"""


```
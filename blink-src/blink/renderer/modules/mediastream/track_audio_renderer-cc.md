Response:
Let's break down the thought process for analyzing this `TrackAudioRenderer.cc` file.

**1. Initial Understanding of the Purpose:**

The filename `track_audio_renderer.cc` immediately suggests its primary function: rendering audio for a specific media track. The `blink/renderer/modules/mediastream` path confirms it's related to media streams within the Blink rendering engine.

**2. Identifying Key Components and Responsibilities (Skimming the Code):**

A quick scan reveals several important elements:

* **`TrackAudioRenderer` class:** This is the central class, responsible for managing the audio rendering pipeline.
* **`media::AudioRendererSink`:**  This suggests an interface for outputting the rendered audio to a system audio device.
* **`media::AudioShifter`:** This hints at a component responsible for managing audio timing, potentially handling differences between the source's time and the playback time.
* **`WebMediaStreamAudioSink`:** This indicates it *receives* audio data from a source.
* **`MediaStreamComponent` and `MediaStreamAudioTrack`:**  These confirm its connection to the broader media stream architecture.
* **`PendingData` and `PendingReconfig`:** These structures suggest handling asynchronous operations or buffering during reconfiguration.
* **Synchronization primitives (`base::Lock`)**:  This signals multi-threading concerns, likely between the main rendering thread and a separate audio processing thread.

**3. Deciphering the Functionality (More Detailed Reading):**

Now, we delve into the methods and their interactions.

* **`TrackAudioRenderer` Constructor:**  Initializes dependencies like the audio component and the output device ID.
* **`Start()`:**  Connects the `TrackAudioRenderer` as a sink to the audio track and creates an `AudioRendererSink`.
* **`Stop()`:**  Disconnects from the audio track and stops the `AudioRendererSink`.
* **`Play()` and `Pause()`:** Control the playback state of the sink.
* **`SetVolume()`:**  Adjusts the output volume.
* **`OnData()`:** This is crucial. It's the entry point for incoming audio data. The logic here handles buffering during reconfiguration and pushing data into the `AudioShifter`.
* **`OnSetFormat()`:**  Handles changes in the audio format. This triggers the potentially complex `ReconfigureSink()` process.
* **`Render()`:** This is the *output* side. The `AudioRendererSink` calls this to get audio data. It pulls data from the `AudioShifter`.
* **`ReconfigureSink()`:**  Deals with changing the audio format. It stops and restarts the `AudioRendererSink` and manages the `AudioShifter`. The handling of `pending_reconfigs_` is key here.
* **`CreateAudioShifter()`:** Creates and initializes the `AudioShifter`.
* **`HaltAudioFlow_Locked()`:** Resets the `AudioShifter` and updates timing information.
* **`SwitchOutputDevice()`:**  Allows changing the audio output device.

**4. Identifying Relationships with Web Technologies:**

* **JavaScript:** The `MediaStream` API in JavaScript is the primary way developers interact with media streams. This C++ code is the *implementation* of the audio rendering part of that API. JavaScript code using `getUserMedia()` or accessing tracks from a `<video>` element with audio will eventually lead to data flowing through this renderer.
* **HTML:** The `<audio>` and `<video>` elements are the primary HTML interfaces for media playback. When these elements play audio tracks, the underlying rendering process utilizes components like `TrackAudioRenderer`.
* **CSS:**  While CSS doesn't directly control the *functionality* of audio rendering, CSS can style the `<audio>` and `<video>` elements, which in turn trigger the use of this renderer.

**5. Logical Reasoning and Assumptions:**

* **Input:** Audio data (as `media::AudioBus`) and timing information (`base::TimeTicks`) coming from a `MediaStreamAudioTrack`. Also, format information (`media::AudioParameters`).
* **Processing:** The `TrackAudioRenderer` manages buffering, time synchronization (using `AudioShifter`), and outputting the audio through the `AudioRendererSink`.
* **Output:** Rendered audio data requested by the system's audio pipeline via the `Render()` method.

**6. Common Usage Errors and Debugging:**

* **Incorrect Device ID:**  Trying to switch to a non-existent or unavailable output device.
* **Format Mismatches:**  Issues arising from incompatible audio formats between the source and the sink.
* **Timing Issues:** Problems with audio synchronization, stuttering, or gaps, which might be related to the `AudioShifter`.
* **Multiple Reconfigurations:**  Rapidly changing audio formats can lead to race conditions or inefficient reconfiguration.

**7. User Operations and Debugging:**

The debugging section involves tracing the user's actions that lead to this code being executed. The key is to follow the flow of audio data:

1. **User Action:** User interacts with a web page (e.g., clicks "play" on an audio element, a website uses `getUserMedia()`).
2. **JavaScript API:**  JavaScript code uses the `MediaStream` API to access or create an audio track.
3. **Blink Engine Processing:** The Blink engine manages the lifecycle of the media stream and its tracks. For audio tracks, this involves creating a `MediaStreamAudioTrack`.
4. **`TrackAudioRenderer` Creation:** When an audio track needs to be rendered, a `TrackAudioRenderer` is created.
5. **Data Flow:** Audio data flows from the source (microphone, remote stream, etc.) to the `MediaStreamAudioTrack` and then to the `TrackAudioRenderer` via `OnData()`.
6. **Rendering and Output:** The `TrackAudioRenderer` processes the audio and sends it to the system's audio output via the `AudioRendererSink`.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too heavily on just the `Render()` method. Realizing the importance of `OnData()` and `OnSetFormat()` is crucial for understanding the data flow and configuration aspects.
*  The role of the `AudioShifter` might not be immediately clear. Recognizing it handles timing synchronization is key.
* Understanding the locking mechanisms is important for grasping the multi-threaded nature of audio processing.

By systematically dissecting the code, considering its context within the browser, and anticipating potential problems, we can arrive at a comprehensive understanding of the `TrackAudioRenderer.cc` file's functionality.
这个文件 `blink/renderer/modules/mediastream/track_audio_renderer.cc` 是 Chromium Blink 引擎中负责**渲染（播放）来自 `MediaStreamTrack` 的音频**的核心组件。它接收来自音频源（例如用户的麦克风、远程流）的音频数据，并将其传递到系统的音频输出设备进行播放。

以下是该文件的主要功能分解：

**核心功能:**

1. **接收音频数据:**  实现了 `WebMediaStreamAudioSink` 接口，通过 `OnData()` 方法接收来自 `MediaStreamAudioTrack` 的音频数据（以 `media::AudioBus` 的形式）。
2. **音频格式管理:**  通过 `OnSetFormat()` 方法接收音频数据的格式信息 (`media::AudioParameters`)，并在格式发生变化时触发重新配置。
3. **音频重采样和时间校正:** 使用 `media::AudioShifter` 组件来管理音频的播放时间，处理由于网络延迟或本地处理导致的音频时间偏差，确保音频的平滑播放。
4. **音频输出:** 使用 `media::AudioRendererSink` 接口将处理后的音频数据传递到操作系统进行播放。这涉及到选择合适的音频输出设备。
5. **播放控制:**  提供 `Start()`, `Stop()`, `Play()`, `Pause()` 等方法来控制音频的播放状态。
6. **音量控制:** 提供 `SetVolume()` 方法来设置音频的播放音量。
7. **输出设备切换:** 提供 `SwitchOutputDevice()` 方法来切换音频的输出设备。
8. **错误处理:**  通过 `on_render_error_callback_` 报告渲染过程中发生的错误。
9. **性能监控:** 使用宏例如 `TRACE_EVENT` 和 `UMA_HISTOGRAM_ENUMERATION` 来进行性能追踪和统计。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    * **`getUserMedia()`:**  当 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 获取用户麦克风权限并获得音频流时，Blink 引擎会创建一个 `MediaStreamTrack` 对象。`TrackAudioRenderer` 就负责渲染这个 track 产生的音频数据。
    * **`<audio>` 和 `<video>` 元素:** 当 HTML 中的 `<audio>` 或 `<video>` 元素关联到一个包含音频轨道的 `MediaStream` 对象时，Blink 引擎会创建 `TrackAudioRenderer` 来播放这些音频轨道。
    * **Web Audio API:**  虽然这个文件本身不直接是 Web Audio API 的一部分，但通过 `MediaStreamSourceNode`，来自 `getUserMedia()` 的音频流可以被连接到 Web Audio API 图形中进行进一步处理。`TrackAudioRenderer` 负责将原始音频数据提供给这个节点。
    * **示例:**  假设以下 JavaScript 代码获取了麦克风音频并将其设置为一个 `<audio>` 元素的 `srcObject`：
      ```javascript
      navigator.mediaDevices.getUserMedia({ audio: true })
        .then(stream => {
          const audio = document.querySelector('audio');
          audio.srcObject = stream;
          audio.play();
        });
      ```
      在这个场景下，`TrackAudioRenderer` 会被创建来渲染 `stream` 中的音频轨道。

* **HTML:**
    *  如上所述，`<audio>` 和 `<video>` 元素是触发 `TrackAudioRenderer` 工作的关键 HTML 元素。

* **CSS:**
    * CSS 不直接影响 `TrackAudioRenderer` 的核心功能。然而，CSS 可以用来样式化 `<audio>` 和 `<video>` 元素，从而影响用户与这些媒体元素的交互，间接导致 `TrackAudioRenderer` 的创建和使用。

**逻辑推理和假设输入输出:**

**假设输入:**

1. **音频数据:** 一系列 `media::AudioBus` 对象，每个对象包含一定数量的音频帧。
2. **时间戳:** 每个 `media::AudioBus` 对象关联一个 `base::TimeTicks` 类型的参考时间，指示音频数据应该被播放的时间点。
3. **音频格式:**  `media::AudioParameters` 对象，描述音频数据的采样率、通道数、布局等。
4. **播放状态:**  `playing_` 布尔变量，指示音频是否应该播放。
5. **音量:** `volume_` 浮点数，表示播放音量。
6. **输出设备 ID:**  字符串 `output_device_id_`，指定音频输出设备。

**逻辑推理:**

* 当 `OnData()` 接收到音频数据时：
    * 如果正在进行重配置（`pending_reconfigs_` 不为空），则将数据缓存起来。
    * 否则，将数据推送到 `audio_shifter_` 进行时间校正和缓冲。
* 当 `OnSetFormat()` 接收到新的音频格式时：
    * 如果新格式与当前格式不兼容，则发起重配置过程，可能需要停止并重新初始化音频输出 sink。
* 当 `Render()` 方法被调用请求音频数据时：
    * 从 `audio_shifter_` 中拉取指定时间点的音频数据。
* 当 `Play()` 被调用时：
    * 如果 sink 已经初始化且格式已知，则开始 sink 的播放。
* 当 `Pause()` 被调用时：
    * 停止 sink 的播放。
* 当 `SwitchOutputDevice()` 被调用时：
    * 停止当前的 sink，创建一个新的 sink 并使用新的设备 ID 进行初始化。

**假设输出:**

1. **渲染的音频:** 通过 `media::AudioRendererSink` 输出到系统的音频流。
2. **渲染时间:**  `GetCurrentRenderTime()` 返回当前已渲染的音频时间。

**用户或编程常见的使用错误:**

1. **尝试在 `TrackAudioRenderer` 未启动前播放:** 用户或代码可能会尝试调用 `Play()` 方法，但在 `Start()` 方法被调用之前，`sink_` 可能尚未创建，导致播放失败。
2. **频繁切换输出设备:**  过于频繁地调用 `SwitchOutputDevice()` 可能会导致音频播放中断或性能问题，因为每次切换都需要重新初始化音频 sink。
3. **假设音频格式不会改变:** 开发者可能会假设音频流的格式是固定的，但实际上音频源的格式可能会动态改变，如果 `TrackAudioRenderer` 没有正确处理 `OnSetFormat()`，可能会导致播放错误。
4. **不处理渲染错误:**  `on_render_error_callback_` 用于报告渲染错误，如果开发者没有正确监听和处理这些错误，可能无法及时发现和解决音频播放问题。
5. **在错误的线程调用方法:**  许多方法需要在特定的线程（通常是主渲染线程）上调用，如果在错误的线程调用可能会导致崩溃或未定义的行为。例如，直接在接收音频数据的线程上操作 UI 元素。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户正在观看一个包含音频轨道的在线视频：

1. **用户打开网页:** 用户在浏览器中打开包含 `<video>` 标签的网页。
2. **视频加载:** 浏览器开始加载网页资源，包括视频文件（或者通过网络流传输）。
3. **创建 MediaStreamTrack:**  当视频文件包含音频轨道时，Blink 引擎会为该音频轨道创建一个 `MediaStreamTrack` 对象。
4. **创建 TrackAudioRenderer:** 为了播放这个音频轨道，Blink 引擎会创建一个 `TrackAudioRenderer` 对象，并将该音频 track 与之关联。
5. **音频数据接收 (OnData):**  随着视频的播放，解码后的音频数据会通过 `MediaStreamAudioTrack` 的机制传递到 `TrackAudioRenderer` 的 `OnData()` 方法。
6. **音频格式设置 (OnSetFormat):** 在开始接收音频数据之前或期间，`TrackAudioRenderer` 会通过 `OnSetFormat()` 方法接收到音频轨道的格式信息。
7. **音频 Sink 初始化 (MaybeStartSink):** 当音频格式已知且播放状态为 "play" 时，`TrackAudioRenderer` 会初始化并启动 `media::AudioRendererSink`，准备将音频数据输出到系统。
8. **音频渲染 (Render):**  操作系统或音频驱动程序会定期调用 `TrackAudioRenderer` 的 `Render()` 方法来请求要播放的音频数据。
9. **音频输出:**  `TrackAudioRenderer` 从 `audio_shifter_` 中取出音频数据，并通过 `media::AudioRendererSink` 将其传递到系统的音频输出设备。
10. **用户操作导致状态变化:**
    * **用户点击 "播放" 按钮:**  触发 JavaScript 代码调用 `<video>` 元素的 `play()` 方法，最终会调用 `TrackAudioRenderer` 的 `Play()` 方法。
    * **用户调整音量:**  触发 JavaScript 代码调整 `<video>` 元素的音量属性，最终会调用 `TrackAudioRenderer` 的 `SetVolume()` 方法。
    * **用户插拔耳机:**  操作系统可能会发出设备变更通知，浏览器会响应该通知，可能导致 `TrackAudioRenderer` 调用 `SwitchOutputDevice()` 方法来切换音频输出设备。
    * **网络波动导致音频格式变化:**  在网络流媒体场景下，网络状况的变化可能导致音频流的格式发生改变，`MediaStreamTrack` 会通知 `TrackAudioRenderer`，触发 `OnSetFormat()`。

**调试线索:**

* **查看日志:**  该文件中的 `DVLOG` 和 `TRACE_EVENT` 宏会输出调试信息，可以帮助追踪音频数据的流向和状态变化。
* **断点调试:**  在关键方法如 `OnData()`, `OnSetFormat()`, `Render()`, `MaybeStartSink()` 中设置断点，可以观察变量的值和代码的执行流程。
* **检查 `media::AudioShifter` 的状态:** 观察 `audio_shifter_` 中缓冲的音频数据量，可以帮助诊断时间同步问题。
* **检查 `media::AudioRendererSink` 的状态:**  查看 sink 的初始化状态、输出设备信息等，可以帮助诊断音频输出问题。
* **分析用户操作:**  理解用户执行了哪些操作，以及这些操作如何影响 JavaScript 代码和 Blink 引擎的状态，是定位问题的关键。例如，如果用户在网络不稳定的情况下观看在线视频，音频播放出现卡顿，那么问题可能与网络延迟或音频格式切换有关。

总而言之，`track_audio_renderer.cc` 是 Blink 引擎中负责音频渲染的核心模块，它连接了来自 Web API 的音频流和底层的音频输出系统，处理了音频数据接收、格式管理、时间同步、播放控制和设备切换等关键任务。 理解这个文件的功能对于调试与网页音频播放相关的 bug 非常重要。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/track_audio_renderer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/track_audio_renderer.h"

#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/synchronization/lock.h"
#include "base/trace_event/trace_event.h"
#include "media/audio/audio_sink_parameters.h"
#include "media/base/audio_bus.h"
#include "media/base/audio_latency.h"
#include "media/base/audio_shifter.h"
#include "third_party/blink/public/platform/modules/mediastream/web_media_stream_track.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_audio_track.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

namespace WTF {

template <>
struct CrossThreadCopier<media::AudioParameters> {
  STATIC_ONLY(CrossThreadCopier);
  using Type = media::AudioParameters;
  static Type Copy(Type pointer) { return pointer; }
};

}  // namespace WTF

namespace blink {

namespace {

// Translates |num_samples_rendered| into a TimeDelta duration and adds it to
// |prior_elapsed_render_time|.
base::TimeDelta ComputeTotalElapsedRenderTime(
    base::TimeDelta prior_elapsed_render_time,
    int64_t num_samples_rendered,
    int sample_rate) {
  return prior_elapsed_render_time +
         base::Microseconds(num_samples_rendered *
                            base::Time::kMicrosecondsPerSecond / sample_rate);
}

WebLocalFrame* ToWebLocalFrame(LocalFrame* frame) {
  if (!frame)
    return nullptr;

  return static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(frame));
}

bool RequiresSinkReconfig(const media::AudioParameters& old_format,
                          const media::AudioParameters& new_format) {
  // Always favor |new_format| if our current params are invalid. This avoids
  // the edge case where |current_params| is valid except for 0
  // frames_per_buffer(), and never gets replaced by an almost identical
  // |new_format| with a valid frames_per_buffer().
  if (!old_format.IsValid())
    return true;

  // Ignore frames_per_buffer(), since the AudioRendererSink and the
  // AudioShifter handle those variations adequately.
  media::AudioParameters new_format_copy = new_format;
  new_format_copy.set_frames_per_buffer(old_format.frames_per_buffer());

  return !old_format.Equals(new_format_copy);
}

}  // namespace

TrackAudioRenderer::PendingData::PendingData(const media::AudioBus& audio_bus,
                                             base::TimeTicks ref_time)
    : reference_time(ref_time),
      audio(media::AudioBus::Create(audio_bus.channels(), audio_bus.frames())) {
  audio_bus.CopyTo(audio.get());
}

TrackAudioRenderer::PendingReconfig::PendingReconfig(
    const media::AudioParameters& format,
    int reconfig_number)
    : reconfig_number(reconfig_number), format(format) {}

// media::AudioRendererSink::RenderCallback implementation
int TrackAudioRenderer::Render(base::TimeDelta delay,
                               base::TimeTicks delay_timestamp,
                               const media::AudioGlitchInfo& glitch_info,
                               media::AudioBus* audio_bus) {
  TRACE_EVENT("audio", "TrackAudioRenderer::Render", "playout_delay (ms)",
              delay.InMillisecondsF(), "delay_timestamp (ms)",
              (delay_timestamp - base::TimeTicks()).InMillisecondsF());
  base::AutoLock auto_lock(thread_lock_);

  if (!audio_shifter_) {
    audio_bus->Zero();
    return 0;
  }

  const base::TimeTicks playout_time = delay_timestamp + delay;
  DVLOG(2) << "Pulling audio out of shifter to be played "
           << delay.InMilliseconds() << " ms from now.";
  audio_shifter_->Pull(audio_bus, playout_time);
  num_samples_rendered_ += audio_bus->frames();
  return audio_bus->frames();
}

void TrackAudioRenderer::OnRenderErrorCrossThread() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  on_render_error_callback_.Run();
}

void TrackAudioRenderer::OnRenderError() {
  DCHECK(on_render_error_callback_);

  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&TrackAudioRenderer::OnRenderErrorCrossThread,
                          WrapRefCounted(this)));
}

// WebMediaStreamAudioSink implementation
void TrackAudioRenderer::OnData(const media::AudioBus& audio_bus,
                                base::TimeTicks reference_time) {
  TRACE_EVENT("audio", "TrackAudioRenderer::OnData", "capture_time (ms)",
              (reference_time - base::TimeTicks()).InMillisecondsF(),
              "capture_delay (ms)",
              (base::TimeTicks::Now() - reference_time).InMillisecondsF());

  base::AutoLock auto_lock(thread_lock_);

  // There is a pending ReconfigureSink() call. Copy |audio_bus| so it can be
  // pushed in to the |audio_shifter_| (or dropped later).
  if (!pending_reconfigs_.empty()) {
    // Copies |audio_bus| internally.
    pending_reconfigs_.back().data.emplace_back(audio_bus, reference_time);
    return;
  }

  if (!audio_shifter_)
    return;

  std::unique_ptr<media::AudioBus> audio_data(
      media::AudioBus::Create(audio_bus.channels(), audio_bus.frames()));
  audio_bus.CopyTo(audio_data.get());
  // Note: For remote audio sources, |reference_time| is the local playout time,
  // the ideal point-in-time at which the first audio sample should be played
  // out in the future.  For local sources, |reference_time| is the
  // point-in-time at which the first audio sample was captured in the past.  In
  // either case, AudioShifter will auto-detect and do the right thing when
  // audio is pulled from it.
  PushDataIntoShifter_Locked(std::move(audio_data), reference_time);
}

void TrackAudioRenderer::OnSetFormat(const media::AudioParameters& params) {
  DVLOG(1) << "TrackAudioRenderer::OnSetFormat: "
           << params.AsHumanReadableString();

  // Don't attempt call ReconfigureSink() if the |last_reconfig_format_|
  // is compatible (e.g. identical, or varies only by frames_per_buffer()).
  if (!RequiresSinkReconfig(last_reconfig_format_, params))
    return;

  int reconfig_number;
  {
    base::AutoLock lock(thread_lock_);
    // Keep track of how many ReconfigureSink() calls we have made. This allows
    // us to drop all but the latest ReconfigureSink() calls on the main thread.
    reconfig_number = ++sink_reconfig_count_;

    // As long as there is an entry in |pending_reconfigs_|, we save data
    // instead of dropping it, or pushing it into |audio_shifter_|. This queue
    // entry is popped in ReconfigureSink().
    pending_reconfigs_.push_back(PendingReconfig(params, reconfig_number));
  }

  // Post a task on the main render thread to reconfigure the |sink_| with the
  // new format.
  PostCrossThreadTask(
      *task_runner_, FROM_HERE,
      CrossThreadBindOnce(&TrackAudioRenderer::ReconfigureSink,
                          WrapRefCounted(this), params, reconfig_number));

  last_reconfig_format_ = params;
}

TrackAudioRenderer::TrackAudioRenderer(
    MediaStreamComponent* audio_component,
    LocalFrame& playout_frame,
    const String& device_id,
    base::RepeatingClosure on_render_error_callback)
    : audio_component_(audio_component),
      playout_frame_(playout_frame),
      task_runner_(
          playout_frame.GetTaskRunner(blink::TaskType::kInternalMedia)),
      on_render_error_callback_(std::move(on_render_error_callback)),
      output_device_id_(device_id) {
  DCHECK(MediaStreamAudioTrack::From(audio_component_.Get()));
  DCHECK(task_runner_->BelongsToCurrentThread());
  DVLOG(1) << "TrackAudioRenderer::TrackAudioRenderer()";
}

TrackAudioRenderer::~TrackAudioRenderer() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(!sink_);
  DVLOG(1) << "TrackAudioRenderer::~TrackAudioRenderer()";
}

void TrackAudioRenderer::Start() {
  DVLOG(1) << "TrackAudioRenderer::Start()";
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK_EQ(playing_, false);

  // We get audio data from |audio_component_|...
  WebMediaStreamAudioSink::AddToAudioTrack(
      this, WebMediaStreamTrack(audio_component_.Get()));
  // ...and |sink_| will get audio data from us.
  DCHECK(!sink_);
  sink_ = Platform::Current()->NewAudioRendererSink(
      WebAudioDeviceSourceType::kNonRtcAudioTrack,
      ToWebLocalFrame(playout_frame_),
      {base::UnguessableToken(), output_device_id_.Utf8()});

  base::AutoLock auto_lock(thread_lock_);
  prior_elapsed_render_time_ = base::TimeDelta();
  num_samples_rendered_ = 0;
}

void TrackAudioRenderer::Stop() {
  DVLOG(1) << "TrackAudioRenderer::Stop()";
  DCHECK(task_runner_->BelongsToCurrentThread());

  Pause();

  // Stop the output audio stream, i.e, stop asking for data to render.
  // It is safer to call Stop() on the |sink_| to clean up the resources even
  // when the |sink_| is never started.
  if (sink_) {
    sink_->Stop();
    sink_ = nullptr;
  }

  sink_started_ = false;

  // Ensure that the capturer stops feeding us with captured audio.
  WebMediaStreamAudioSink::RemoveFromAudioTrack(
      this, WebMediaStreamTrack(audio_component_.Get()));
}

void TrackAudioRenderer::Play() {
  DVLOG(1) << "TrackAudioRenderer::Play()";
  DCHECK(task_runner_->BelongsToCurrentThread());

  if (!sink_)
    return;

  playing_ = true;

  MaybeStartSink();
}

void TrackAudioRenderer::Pause() {
  DVLOG(1) << "TrackAudioRenderer::Pause()";
  DCHECK(task_runner_->BelongsToCurrentThread());

  if (!sink_)
    return;

  playing_ = false;

  base::AutoLock auto_lock(thread_lock_);
  HaltAudioFlow_Locked();
}

void TrackAudioRenderer::SetVolume(float volume) {
  DVLOG(1) << "TrackAudioRenderer::SetVolume(" << volume << ")";
  DCHECK(task_runner_->BelongsToCurrentThread());

  // Cache the volume.  Whenever |sink_| is re-created, call SetVolume() with
  // this cached volume.
  volume_ = volume;
  if (sink_)
    sink_->SetVolume(volume);
}

base::TimeDelta TrackAudioRenderer::GetCurrentRenderTime() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  base::AutoLock auto_lock(thread_lock_);
  if (source_params_.IsValid()) {
    return ComputeTotalElapsedRenderTime(prior_elapsed_render_time_,
                                         num_samples_rendered_,
                                         source_params_.sample_rate());
  }
  return prior_elapsed_render_time_;
}

void TrackAudioRenderer::SwitchOutputDevice(
    const std::string& device_id,
    media::OutputDeviceStatusCB callback) {
  DVLOG(1) << "TrackAudioRenderer::SwitchOutputDevice()";
  DCHECK(task_runner_->BelongsToCurrentThread());

  {
    base::AutoLock auto_lock(thread_lock_);
    HaltAudioFlow_Locked();
  }

  scoped_refptr<media::AudioRendererSink> new_sink =
      Platform::Current()->NewAudioRendererSink(
          WebAudioDeviceSourceType::kNonRtcAudioTrack,
          ToWebLocalFrame(playout_frame_),
          {base::UnguessableToken(), device_id});

  media::OutputDeviceStatus new_sink_status =
      new_sink->GetOutputDeviceInfo().device_status();
  UMA_HISTOGRAM_ENUMERATION("Media.Audio.TrackAudioRenderer.SwitchDeviceStatus",
                            new_sink_status,
                            media::OUTPUT_DEVICE_STATUS_MAX + 1);
  if (new_sink_status != media::OUTPUT_DEVICE_STATUS_OK) {
    new_sink->Stop();
    std::move(callback).Run(new_sink_status);
    return;
  }

  output_device_id_ = String(device_id);
  bool was_sink_started = sink_started_;

  if (sink_)
    sink_->Stop();

  sink_started_ = false;
  sink_ = new_sink;
  if (was_sink_started)
    MaybeStartSink();

  std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_OK);
}

void TrackAudioRenderer::MaybeStartSink(bool reconfiguring) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DVLOG(1) << "TrackAudioRenderer::MaybeStartSink()";

  if (!sink_ || !source_params_.IsValid() || !playing_)
    return;

  // Re-create the AudioShifter to drop old audio data and reset to a starting
  // state.  MaybeStartSink() is always called in a situation where either the
  // source or sink has changed somehow and so all of AudioShifter's internal
  // time-sync state is invalid.
  CreateAudioShifter(reconfiguring);

  if (sink_started_)
    return;

  const media::OutputDeviceInfo& device_info = sink_->GetOutputDeviceInfo();
  UMA_HISTOGRAM_ENUMERATION("Media.Audio.TrackAudioRenderer.DeviceStatus",
                            device_info.device_status(),
                            media::OUTPUT_DEVICE_STATUS_MAX + 1);
  if (device_info.device_status() != media::OUTPUT_DEVICE_STATUS_OK)
    return;

  // Output parameters consist of the same channel layout and sample rate as the
  // source, but having the buffer duration preferred by the hardware.
  const media::AudioParameters& hardware_params = device_info.output_params();
  media::AudioParameters sink_params(
      hardware_params.format(), source_params_.channel_layout_config(),
      source_params_.sample_rate(),
      media::AudioLatency::GetRtcBufferSize(
          source_params_.sample_rate(), hardware_params.frames_per_buffer()));
  if (sink_params.channel_layout() == media::CHANNEL_LAYOUT_DISCRETE) {
    DCHECK_LE(source_params_.channels(), 2);
  }
  DVLOG(1) << ("TrackAudioRenderer::MaybeStartSink() -- Starting sink.  "
               "source_params={")
           << source_params_.AsHumanReadableString() << "}, hardware_params={"
           << hardware_params.AsHumanReadableString() << "}, sink parameters={"
           << sink_params.AsHumanReadableString() << '}';

  // Specify the latency info to be passed to the browser side.
  sink_params.set_latency_tag(Platform::Current()->GetAudioSourceLatencyType(
      WebAudioDeviceSourceType::kNonRtcAudioTrack));

  sink_->Initialize(sink_params, this);
  sink_->Start();
  sink_->SetVolume(volume_);
  sink_->Play();  // Not all the sinks play on start.
  sink_started_ = true;
}

void TrackAudioRenderer::ReconfigureSink(
    const media::AudioParameters new_format,
    int reconfig_number) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  {
    base::AutoLock lock(thread_lock_);
    DCHECK(!pending_reconfigs_.empty());
    DCHECK_EQ(pending_reconfigs_.front().reconfig_number, reconfig_number);

    // ReconfigureSink() is only posted by OnSetFormat() when an incoming format
    // is incompatible with |last_reconfig_format_|. A mismatch between
    // |reconfig_number| and |sink_reconfig_count_| means there is at least
    // one more pending ReconfigureSink() call, which is definitively
    // incompatible with |new_format|. If so, ignore this reconfiguration, to
    // avoid creating a sink which would be immediately destroyed by the next
    // ReconfigureSink() call.
    if (reconfig_number != sink_reconfig_count_) {
      // Drop any pending data for this |reconfig_number|, as we won't have
      // an |audio_shifter_| or a |sink_| configured to ingest this data.
      pending_reconfigs_.pop_front();
      return;
    }

    // The |new_format| is compatible with the existing one. Skip this
    // reconfiguration.
    if (!RequiresSinkReconfig(source_params_, new_format)) {
      // Push pending data into |audio_shifter_|, if we have one, or clear
      // the entry corresponding to this |reconfig_number|.
      if (audio_shifter_)
        ConsumePendingReconfigsFront_Locked();
      else
        pending_reconfigs_.pop_front();

      return;
    }

    // If we need to reconfigure, drop all existing |audio_shifter_| data, as it
    // won't be compatible with the new shifter and data in
    // |pending_reconfigs_.front()|.
    if (audio_shifter_)
      HaltAudioFlow_Locked();
  }

  source_params_ = new_format;

  if (!sink_)
    return;  // TrackAudioRenderer has not yet been started.

  // Stop |sink_| and re-create a new one to be initialized with different audio
  // parameters.  Then, invoke MaybeStartSink() to restart everything again.
  sink_->Stop();
  sink_started_ = false;
  sink_ = Platform::Current()->NewAudioRendererSink(
      WebAudioDeviceSourceType::kNonRtcAudioTrack,
      ToWebLocalFrame(playout_frame_),
      {base::UnguessableToken(), output_device_id_.Utf8()});
  MaybeStartSink(/*reconfiguring=*/true);

  {
    base::AutoLock lock(thread_lock_);
    // We may have never created |audio_shifter_| (e.g. if the sink isn't
    // playing). Clear the corresponding |pending_reconfigs_| entry, so
    // we start dropping incoming data in OnData().
    if (!audio_shifter_)
      pending_reconfigs_.pop_front();
  }
}

void TrackAudioRenderer::CreateAudioShifter(bool reconfiguring) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // Note 1: The max buffer is fairly large to cover the case where
  // remotely-sourced audio is delivered well ahead of its scheduled playout
  // time (e.g., content streaming with a very large end-to-end
  // latency). However, there is no penalty for making it large in the
  // low-latency use cases since AudioShifter will discard data as soon as it is
  // no longer needed.
  //
  // Note 2: The clock accuracy is set to 20ms because clock accuracy is
  // ~15ms on Windows machines without a working high-resolution clock.  See
  // comments in base/time/time.h for details.
  media::AudioShifter* const new_shifter = new media::AudioShifter(
      base::Seconds(5), base::Milliseconds(20), base::Seconds(20),
      source_params_.sample_rate(), source_params_.channels());

  base::AutoLock auto_lock(thread_lock_);
  audio_shifter_.reset(new_shifter);

  // There might be pending data that needs to be pushed into |audio_shifter_|.
  if (reconfiguring)
    ConsumePendingReconfigsFront_Locked();
}

void TrackAudioRenderer::HaltAudioFlow_Locked() {
  thread_lock_.AssertAcquired();

  audio_shifter_.reset();

  if (source_params_.IsValid()) {
    prior_elapsed_render_time_ = ComputeTotalElapsedRenderTime(
        prior_elapsed_render_time_, num_samples_rendered_,
        source_params_.sample_rate());
    num_samples_rendered_ = 0;
  }
}

void TrackAudioRenderer::ConsumePendingReconfigsFront_Locked() {
  thread_lock_.AssertAcquired();
  DCHECK(audio_shifter_);

  PendingReconfig& current_reconfig = pending_reconfigs_.front();
  DCHECK(!RequiresSinkReconfig(source_params_, current_reconfig.format));

  auto& pending_data = current_reconfig.data;
  for (auto& data : pending_data)
    PushDataIntoShifter_Locked(std::move(data.audio), data.reference_time);

  // Once |pending_reconfigs_| is empty, new data will be pushed directly
  // into |audio_shifter_|. If it isn't empty, there is another
  // ReconfigureSink() in flight.
  pending_reconfigs_.pop_front();
}

void TrackAudioRenderer::PushDataIntoShifter_Locked(
    std::unique_ptr<media::AudioBus> data,
    base::TimeTicks reference_time) {
  thread_lock_.AssertAcquired();
  DCHECK(audio_shifter_);
  total_frames_pushed_for_testing_ += data->frames();
  audio_shifter_->Push(std::move(data), reference_time);
}

int TrackAudioRenderer::TotalFramesPushedForTesting() const {
  base::AutoLock auto_lock(thread_lock_);
  return total_frames_pushed_for_testing_;
}

int TrackAudioRenderer::FramesInAudioShifterForTesting() const {
  base::AutoLock auto_lock(thread_lock_);
  return audio_shifter_ ? audio_shifter_->frames_pushed_for_testing() : 0;
}

}  // namespace blink

"""

```
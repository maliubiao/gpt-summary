Response: Let's break down the thought process for analyzing the `VideoDecodeStatsReporter.cc` file and generating the explanation.

**1. Understanding the Core Purpose:**

The very name `VideoDecodeStatsReporter` strongly suggests its primary function: gathering and reporting statistics related to video decoding. The presence of `recorder_remote_` of type `media::mojom::VideoDecodeStatsRecorder` reinforces this, indicating communication with another component responsible for actually *storing* these stats.

**2. Deconstructing the Constructor:**

The constructor provides crucial initial information:

*   `recorder_remote_`:  Confirms the reporting purpose and the interaction with a recording service.
*   `get_pipeline_stats_cb_`:  Shows how the reporter gets the raw decoding statistics. This is a key dependency.
*   `codec_profile_`, `natural_size_`, `cdm_config`: These parameters point to the context of the video being decoded. They'll likely be part of the reported data. The bucketing of `natural_size_` is an important detail.
*   `task_runner_`, `tick_clock_`: These suggest the reporter operates asynchronously and needs precise timing. The `stats_cb_timer_` confirms periodic tasks.

**3. Analyzing Key Methods:**

*   **Lifecycle Methods (`OnPlaying`, `OnPaused`, `OnHidden`, `OnShown`):** These are standard media playback states. The fact that the stats reporting starts and stops based on these states is a core piece of functionality. The "hidden" state is particularly important for understanding background activity.
*   **`MatchesBucketedNaturalSize`:** A utility for checking size changes.
*   **`RunStatsTimerAtInterval`:**  Handles the periodic execution of the stats update logic. The timing aspect is crucial.
*   **`StartNewRecord`:**  Indicates the beginning of a new reporting session. The data passed (`codec_profile_`, `natural_size_`, etc.) becomes the context for the subsequent statistics. The bucketing is re-emphasized here.
*   **`ResetFrameRateState`:**  Suggests a process of monitoring and stabilizing frame rate before starting to report accurate stats.
*   **`ShouldBeReporting`:**  A gatekeeper function that combines various conditions to determine if reporting should be active. This is vital for efficiency.
*   **`OnIpcConnectionError`:** Deals with communication failures.
*   **`UpdateDecodeProgress`:** A preliminary check to see if any decoding has happened since the last check. This prevents unnecessary processing.
*   **`UpdateFrameRateStability`:** This is a complex but vital part. It explains the logic for determining if the frame rate is stable enough to start accurate reporting. The logic around "tiny FPS windows" and maximum unstable changes is interesting.
*   **`UpdateStats`:** The heart of the reporting logic. It retrieves the raw stats, checks for progress and stability, and then sends the calculated differences to the recorder. The capping of the frame counts is a defensive programming measure.

**4. Identifying Relationships with Web Technologies:**

*   **JavaScript:** The `OnPlaying`, `OnPaused` events directly correspond to events in the HTML5 `<video>` element's JavaScript API. The statistics being reported are useful for JavaScript-based media players to monitor performance.
*   **HTML:** The `<video>` element itself is the trigger for the video decoding process. The `natural_size` of the video comes from the video metadata exposed through the HTML API.
*   **CSS:** While less direct, CSS can influence the rendering of the video, which *might* indirectly affect decoding performance in some edge cases (e.g., very heavy CSS animations). However, the direct link is weaker than with JavaScript and HTML.

**5. Considering Logic and Assumptions:**

*   **Assumption:** The reporter assumes the `get_pipeline_stats_cb_` provides accurate and up-to-date decoding statistics.
*   **Input (to `UpdateStats`):**  The raw `media::PipelineStatistics` struct.
*   **Output (from `UpdateStats`):** A `media::mojom::PredictionTargets` object sent via IPC.
*   **Logic:** The frame rate stabilization logic is a key piece of inference. It assumes that a stable frame rate is necessary for meaningful statistics.

**6. Identifying Potential Usage Errors:**

*   **Not handling connection errors:**  If the IPC connection to the recorder is lost and not handled gracefully in other parts of the system, the statistics won't be recorded.
*   **Incorrect `get_pipeline_stats_cb_` implementation:** If this callback returns incorrect data, the reported statistics will be wrong.
*   **Misinterpreting the "stable FPS" logic:**  Users of this data need to understand that statistics might not be reported immediately upon playback start.

**7. Structuring the Explanation:**

Finally, the information needs to be organized logically. Starting with the core function, then detailing the individual methods, explaining the web technology connections, and finally addressing logic and potential errors provides a comprehensive understanding. Using examples and clear language is crucial.

**(Self-Correction during the process):**

Initially, I might have focused too much on the individual data members. Realizing that the methods are the key to understanding the *behavior* led to a more effective analysis. Also, making sure to connect the technical details back to the user experience and web developer context (via JavaScript, HTML, CSS) is important for fulfilling the prompt's requirements. The frame rate stabilization logic was a particularly complex part that needed careful explanation.
这个文件 `blink/renderer/platform/media/video_decode_stats_reporter.cc` 的主要功能是 **收集和报告视频解码的统计信息**。它跟踪视频解码过程中的各种指标，例如解码的帧数、丢弃的帧数、解码是否使用了硬件加速等，并将这些信息报告给一个外部的记录器服务。

以下是其更详细的功能点：

**1. 统计信息的收集：**

*   **解码帧数 (Decoded Frames):**  记录成功解码的视频帧的总数。
*   **丢弃帧数 (Dropped Frames):** 记录由于各种原因（例如解码速度不足、资源限制等）而被丢弃的视频帧的总数。
*   **高效解码帧数 (Power-Efficient Decoded Frames):** 记录使用更节能的方式（通常是硬件加速）解码的视频帧的总数。
*   **帧率 (Frame Rate):**  监测视频播放的帧率，并尝试判断帧率是否稳定。
*   **编解码器配置 (Codec Profile):**  记录正在解码的视频流的编解码器配置信息。
*   **视频尺寸 (Natural Size):** 记录视频的原始分辨率。
*   **加密信息 (Key System, Use Hardware Secure Codecs):** 如果视频是加密的，则记录使用的加密系统以及是否使用了硬件安全编解码器。

**2. 统计信息的报告：**

*   **与外部记录器通信:** 通过 Mojo IPC (Inter-Process Communication) 与一个实现了 `media::mojom::VideoDecodeStatsRecorder` 接口的服务进行通信。
*   **报告时机:**
    *   在视频播放开始时 (`OnPlaying`) 启动报告。
    *   在视频暂停 (`OnPaused`) 或隐藏 (`OnHidden`) 时停止报告。
    *   当视频从隐藏状态恢复 (`OnShown`) 或恢复播放时，可能会重新启动报告。
    *   定期地 (`kRecordingInterval`) 更新统计信息并发送到记录器。
    *   当检测到稳定的帧率时，开始一个新的记录周期 (`StartNewRecord`)。
*   **报告内容:**  报告的信息包括编解码器配置、视频尺寸、帧率、加密信息以及解码和丢帧的计数。

**3. 帧率稳定性的判断：**

*   该类会尝试判断视频的帧率是否稳定。只有当帧率被认为稳定后，才会开始记录并报告统计信息。
*   使用滑动窗口和阈值来判断帧率的稳定性 (`kRequiredStableFpsSamples`, `kTinyFpsWindowDuration`, `kMaxTinyFpsWindows`, `kMaxUnstableFpsChanges`)。
*   如果帧率频繁变化，可能会停止报告，认为统计信息不可靠。

**4. 与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件位于 Blink 渲染引擎的底层，直接处理视频解码过程。它不直接与 JavaScript, HTML, CSS 代码交互，而是为浏览器提供解码统计信息，这些信息可能会被更高层的 JavaScript API 使用。

**举例说明：**

*   **JavaScript:**  HTML5 `<video>` 元素的 JavaScript API 提供了 `getVideoPlaybackQuality()` 方法，可以获取一些视频播放质量的指标。 虽然这个 C++ 文件不直接参与 `getVideoPlaybackQuality()` 的实现，但它收集的解码统计信息（如丢帧数）很可能是该方法返回信息的一部分。JavaScript 代码可能会使用这些信息来监控视频播放质量，并根据需要采取措施，例如向用户显示警告或调整视频质量。

    ```javascript
    const video = document.querySelector('video');
    setInterval(() => {
      const quality = video.getVideoPlaybackQuality();
      console.log(`Dropped frames: ${quality.droppedVideoFrames}`);
      // 可以根据 droppedVideoFrames 的值来判断播放质量并采取行动
    }, 1000);
    ```

*   **HTML:** HTML 的 `<video>` 标签声明了视频元素。当浏览器解析 HTML 并遇到 `<video>` 标签时，会创建相应的视频播放器对象，并启动视频资源的加载和解码过程。 `VideoDecodeStatsReporter`  在这个解码过程中默默地工作，收集相关的统计信息。

    ```html
    <video src="my-video.mp4" controls></video>
    ```

*   **CSS:** CSS 主要负责视频元素的样式和布局。虽然 CSS 的更改可能会在某些极端情况下间接影响渲染性能，从而可能影响解码器的压力，但 `VideoDecodeStatsReporter`  本身并不直接与 CSS 交互。

**逻辑推理与假设输入输出：**

假设输入：

*   一个正在播放的 30fps 的 MP4 视频。
*   解码器在初始阶段由于缓冲不足导致短暂的丢帧。
*   用户在播放 10 秒后暂停视频。

输出（可能报告的统计信息）：

1. **初始阶段 (帧率不稳定)：** `VideoDecodeStatsReporter` 会检测到帧率不稳定，暂时不会发送统计信息。
2. **帧率稳定后：**
    *   `StartNewRecord` 被调用，开始记录新的统计周期。
    *   `codec_profile_`: 视频的编解码器配置 (例如 `H264 High`)。
    *   `natural_size_`: 视频的分辨率 (例如 `1920x1080`)。
    *   `last_observed_fps_`: `30`。
    *   `key_system_`: 如果视频未加密，则为空字符串。
    *   `use_hw_secure_codecs_`:  `false` (假设未使用硬件安全编解码器)。
3. **播放过程中：**
    *   `UpdateStats` 定期被调用，并发送更新后的统计信息。
    *   `frames_decoded`:  随着时间增加，例如在播放 10 秒后可能接近 `300`（假设没有持续丢帧）。
    *   `frames_dropped`:  可能在初始阶段有少量丢帧，例如 `5`。后续播放稳定后可能不再增加。
    *   `frames_power_efficient`: 如果使用了硬件加速，则会接近 `frames_decoded` 的值。
4. **暂停时：**
    *   `OnPaused` 被调用，`stats_cb_timer_` 停止，不再发送统计信息。

**用户或编程常见的使用错误：**

1. **依赖于立即获取统计信息：**  开发者可能会错误地认为在视频播放开始后就能立即获取到准确的统计信息。实际上，由于帧率稳定性的判断，可能会有一个延迟。

2. **忽略连接错误：** 如果与 `VideoDecodeStatsRecorder` 的 IPC 连接断开，`VideoDecodeStatsReporter` 会停止报告，但如果没有适当的错误处理，上层代码可能不会意识到统计信息丢失。

3. **误解统计信息的含义：**  例如，可能会错误地将 `frames_dropped` 完全归咎于解码器性能问题，而忽略了其他可能的原因，例如网络延迟导致的缓冲不足。

4. **不考虑浏览器隐身模式：** 在隐身模式下，某些浏览器功能可能被禁用，包括统计信息的记录。如果代码没有考虑到这种情况，可能会出现预料之外的行为。

总而言之，`VideoDecodeStatsReporter` 是 Blink 渲染引擎中一个关键的底层组件，负责收集和报告视频解码的性能数据，这些数据对于监控和优化视频播放体验至关重要。虽然它不直接与前端技术交互，但其收集的数据可以被 JavaScript 等技术利用。

### 提示词
```
这是目录为blink/renderer/platform/media/video_decode_stats_reporter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/video_decode_stats_reporter.h"

#include <cmath>
#include <limits>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/single_thread_task_runner.h"
#include "media/capabilities/bucket_utility.h"
#include "media/mojo/mojom/media_types.mojom.h"

namespace blink {

VideoDecodeStatsReporter::VideoDecodeStatsReporter(
    mojo::PendingRemote<media::mojom::VideoDecodeStatsRecorder> recorder_remote,
    GetPipelineStatsCB get_pipeline_stats_cb,
    media::VideoCodecProfile codec_profile,
    const gfx::Size& natural_size,
    std::optional<media::CdmConfig> cdm_config,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const base::TickClock* tick_clock)
    : kRecordingInterval(base::Milliseconds(kRecordingIntervalMs)),
      kTinyFpsWindowDuration(base::Milliseconds(kTinyFpsWindowMs)),
      recorder_remote_(std::move(recorder_remote)),
      get_pipeline_stats_cb_(std::move(get_pipeline_stats_cb)),
      codec_profile_(codec_profile),
      natural_size_(media::GetSizeBucket(natural_size)),
      key_system_(cdm_config ? cdm_config->key_system : ""),
      use_hw_secure_codecs_(cdm_config ? cdm_config->use_hw_secure_codecs
                                       : false),
      tick_clock_(tick_clock),
      stats_cb_timer_(tick_clock_) {
  DCHECK(recorder_remote_.is_bound());
  DCHECK(get_pipeline_stats_cb_);
  DCHECK_NE(media::VIDEO_CODEC_PROFILE_UNKNOWN, codec_profile_);

  recorder_remote_.set_disconnect_handler(base::BindOnce(
      &VideoDecodeStatsReporter::OnIpcConnectionError, base::Unretained(this)));
  stats_cb_timer_.SetTaskRunner(task_runner);
}

VideoDecodeStatsReporter::~VideoDecodeStatsReporter() = default;

void VideoDecodeStatsReporter::OnPlaying() {
  DVLOG(2) << __func__;

  if (is_playing_)
    return;
  is_playing_ = true;

  DCHECK(!stats_cb_timer_.IsRunning());

  if (ShouldBeReporting()) {
    RunStatsTimerAtInterval(kRecordingInterval);
  }
}

void VideoDecodeStatsReporter::OnPaused() {
  DVLOG(2) << __func__;

  if (!is_playing_)
    return;
  is_playing_ = false;

  // Stop timer until playing resumes.
  stats_cb_timer_.Stop();
}

void VideoDecodeStatsReporter::OnHidden() {
  DVLOG(2) << __func__;

  if (is_backgrounded_)
    return;

  is_backgrounded_ = true;

  // Stop timer until no longer hidden.
  stats_cb_timer_.Stop();
}

void VideoDecodeStatsReporter::OnShown() {
  DVLOG(2) << __func__;

  if (!is_backgrounded_)
    return;

  is_backgrounded_ = false;

  // Only start a new record below if stable FPS has been detected. If FPS is
  // later detected, a new record will be started at that time.
  if (num_stable_fps_samples_ >= kRequiredStableFpsSamples) {
    // Dropped frames are not reported during background rendering. Start a new
    // record to avoid reporting background stats.
    media::PipelineStatistics stats = get_pipeline_stats_cb_.Run();
    StartNewRecord(stats.video_frames_decoded, stats.video_frames_dropped,
                   stats.video_frames_decoded_power_efficient);
  }

  if (ShouldBeReporting())
    RunStatsTimerAtInterval(kRecordingInterval);
}

bool VideoDecodeStatsReporter::MatchesBucketedNaturalSize(
    const gfx::Size& natural_size) const {
  // Stored natural size should always be bucketed.
  DCHECK(natural_size_ == media::GetSizeBucket(natural_size_));
  return media::GetSizeBucket(natural_size) == natural_size_;
}

void VideoDecodeStatsReporter::RunStatsTimerAtInterval(
    base::TimeDelta interval) {
  DVLOG(2) << __func__ << " " << interval.InMicroseconds() << " us";
  DCHECK(ShouldBeReporting());

  // NOTE: Avoid optimizing with early returns  if the timer is already running
  // at |milliseconds|. Calling Start below resets the timer clock and some
  // callers (e.g. OnVideoConfigChanged) rely on that behavior behavior.
  stats_cb_timer_.Start(FROM_HERE, interval, this,
                        &VideoDecodeStatsReporter::UpdateStats);
}

void VideoDecodeStatsReporter::StartNewRecord(
    uint32_t frames_decoded_offset,
    uint32_t frames_dropped_offset,
    uint32_t frames_decoded_power_efficient_offset) {
  DVLOG(2) << __func__ << " "
           << " profile:" << codec_profile_
           << " size:" << natural_size_.ToString()
           << " fps:" << last_observed_fps_ << " key_system:" << key_system_
           << " use_hw_secure_codecs:" << use_hw_secure_codecs_;

  // Size and frame rate should always be bucketed.
  DCHECK(natural_size_ == media::GetSizeBucket(natural_size_));
  DCHECK_EQ(last_observed_fps_, media::GetFpsBucket(last_observed_fps_));

  // New records decoded and dropped counts should start at zero.
  // These should never move backward.
  DCHECK_GE(frames_decoded_offset, frames_decoded_offset_);
  DCHECK_GE(frames_dropped_offset, frames_dropped_offset_);
  DCHECK_GE(frames_decoded_power_efficient_offset,
            frames_decoded_power_efficient_offset_);
  frames_decoded_offset_ = frames_decoded_offset;
  frames_dropped_offset_ = frames_dropped_offset;
  frames_decoded_power_efficient_offset_ =
      frames_decoded_power_efficient_offset;

  bool use_hw_secure_codecs = use_hw_secure_codecs_;
  auto features = media::mojom::PredictionFeatures::New(
      codec_profile_, natural_size_, last_observed_fps_, key_system_,
      use_hw_secure_codecs);

  recorder_remote_->StartNewRecord(std::move(features));
}

void VideoDecodeStatsReporter::ResetFrameRateState() {
  // Reinitialize all frame rate state. The next UpdateStats() call will detect
  // the frame rate.
  last_observed_fps_ = 0;
  num_stable_fps_samples_ = 0;
  num_unstable_fps_changes_ = 0;
  num_consecutive_tiny_fps_windows_ = 0;
  fps_stabilization_failed_ = false;
  last_fps_stabilized_ticks_ = base::TimeTicks();
}

bool VideoDecodeStatsReporter::ShouldBeReporting() const {
  return is_playing_ && !is_backgrounded_ && !fps_stabilization_failed_ &&
         !natural_size_.IsEmpty() && is_ipc_connected_;
}

void VideoDecodeStatsReporter::OnIpcConnectionError() {
  // For incognito, the IPC will fail via this path because the recording
  // service is unavailable. Otherwise, errors are unexpected.
  DVLOG(2) << __func__ << " IPC disconnected. Stopping reporting.";
  is_ipc_connected_ = false;
  stats_cb_timer_.Stop();
}

bool VideoDecodeStatsReporter::UpdateDecodeProgress(
    const media::PipelineStatistics& stats) {
  DCHECK_GE(stats.video_frames_decoded, last_frames_decoded_);
  DCHECK_GE(stats.video_frames_dropped, last_frames_dropped_);

  // Check if additional frames decoded since last stats update.
  if (stats.video_frames_decoded == last_frames_decoded_) {
    // Relax timer if its set to a short interval for frame rate stabilization.
    if (stats_cb_timer_.GetCurrentDelay() < kRecordingInterval) {
      DVLOG(2) << __func__ << " No decode progress; slowing the timer";
      RunStatsTimerAtInterval(kRecordingInterval);
    }
    return false;
  }

  last_frames_decoded_ = stats.video_frames_decoded;
  last_frames_dropped_ = stats.video_frames_dropped;

  return true;
}

bool VideoDecodeStatsReporter::UpdateFrameRateStability(
    const media::PipelineStatistics& stats) {
  // When (re)initializing, the pipeline may momentarily return an average frame
  // duration of zero. Ignore it and wait for a real frame rate.
  if (stats.video_frame_duration_average.is_zero())
    return false;

  // Bucket frame rate to simplify metrics aggregation.
  int frame_rate =
      media::GetFpsBucket(1 / stats.video_frame_duration_average.InSecondsF());

  if (frame_rate != last_observed_fps_) {
    DVLOG(2) << __func__ << " fps changed: " << last_observed_fps_ << " -> "
             << frame_rate;
    last_observed_fps_ = frame_rate;
    bool was_stable = num_stable_fps_samples_ >= kRequiredStableFpsSamples;
    num_stable_fps_samples_ = 1;
    num_unstable_fps_changes_++;

    // FrameRate just destabilized. Check if last stability window was "tiny".
    if (was_stable) {
      if (tick_clock_->NowTicks() - last_fps_stabilized_ticks_ <
          kTinyFpsWindowDuration) {
        num_consecutive_tiny_fps_windows_++;
        DVLOG(2) << __func__ << " Last FPS window was 'tiny'. num_tiny:"
                 << num_consecutive_tiny_fps_windows_;

        // Stop reporting if FPS moves around a lot. Stats may be noisy.
        if (num_consecutive_tiny_fps_windows_ >= kMaxTinyFpsWindows) {
          DVLOG(2) << __func__ << " Too many tiny fps windows. Stopping timer";
          fps_stabilization_failed_ = true;
          stats_cb_timer_.Stop();
          return false;
        }
      } else {
        num_consecutive_tiny_fps_windows_ = 0;
      }
    }

    if (num_unstable_fps_changes_ >= kMaxUnstableFpsChanges) {
      // Looks like VFR video. Wait for some stream property (e.g. decoder
      // config) to change before trying again.
      DVLOG(2) << __func__ << " Unable to stabilize FPS. Stopping timer.";
      fps_stabilization_failed_ = true;
      stats_cb_timer_.Stop();
      return false;
    }

    // Increase the timer frequency to quickly stabilize frame rate. 3x the
    // frame duration is used as this should be enough for a few more frames to
    // be decoded, while also being much faster (for typical frame rates) than
    // the regular stats polling interval.
    RunStatsTimerAtInterval(3 * stats.video_frame_duration_average);
    return false;
  }

  // FrameRate matched last observed!
  num_unstable_fps_changes_ = 0;
  num_stable_fps_samples_++;

  // Wait for steady frame rate to begin recording stats.
  if (num_stable_fps_samples_ < kRequiredStableFpsSamples) {
    DVLOG(2) << __func__ << " fps held, awaiting stable ("
             << num_stable_fps_samples_ << ")";
    return false;
  } else if (num_stable_fps_samples_ == kRequiredStableFpsSamples) {
    DVLOG(2) << __func__ << " fps stabilized at " << frame_rate;
    last_fps_stabilized_ticks_ = tick_clock_->NowTicks();

    // FPS is locked in. Start a new record, and set timer to reporting
    // interval.
    StartNewRecord(stats.video_frames_decoded, stats.video_frames_dropped,
                   stats.video_frames_decoded_power_efficient);
    RunStatsTimerAtInterval(kRecordingInterval);
  }
  return true;
}

void VideoDecodeStatsReporter::UpdateStats() {
  DCHECK(ShouldBeReporting());

  media::PipelineStatistics stats = get_pipeline_stats_cb_.Run();
  DVLOG(2) << __func__ << " Raw stats -- dropped:" << stats.video_frames_dropped
           << "/" << stats.video_frames_decoded
           << " power efficient:" << stats.video_frames_decoded_power_efficient
           << "/" << stats.video_frames_decoded
           << " dur_avg:" << stats.video_frame_duration_average;

  // Evaluate decode progress and update various internal state. Bail if decode
  // is not progressing.
  if (!UpdateDecodeProgress(stats))
    return;

  // Check frame rate for changes. Bail if frame rate needs more samples to
  // stabilize.
  if (!UpdateFrameRateStability(stats))
    return;

  // Don't bother recording the first record immediately after stabilization.
  // Counts of zero don't add value.
  if (stats.video_frames_decoded == frames_decoded_offset_)
    return;

  // Cap all counts to |frames_decoded|. We should never exceed this cap, but
  // we have some hard to track bug where we accumulate 1 extra dropped frame
  // in a tiny minority of cases. Dropping all frames is a strong signal we
  // don't want to discard, so just sanitize the data and carry on.
  uint32_t frames_decoded = stats.video_frames_decoded - frames_decoded_offset_;
  uint32_t frames_dropped = std::min(
      stats.video_frames_dropped - frames_dropped_offset_, frames_decoded);
  uint32_t frames_power_efficient =
      std::min(stats.video_frames_decoded_power_efficient -
                   frames_decoded_power_efficient_offset_,
               frames_decoded);

  auto targets = media::mojom::PredictionTargets::New(
      frames_decoded, frames_dropped, frames_power_efficient);

  DVLOG(2) << __func__ << " Recording -- dropped:" << targets->frames_dropped
           << "/" << targets->frames_decoded
           << " power efficient:" << targets->frames_power_efficient << "/"
           << targets->frames_decoded;
  recorder_remote_->UpdateRecord(std::move(targets));
}

}  // namespace blink
```
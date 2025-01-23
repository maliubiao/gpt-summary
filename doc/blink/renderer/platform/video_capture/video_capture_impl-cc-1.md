Response:
Let's break down the thought process for analyzing the `VideoCaptureImpl.cc` code and generating the summary.

**1. Understanding the Core Request:**

The fundamental goal is to understand what the `VideoCaptureImpl` class *does*. The prompt specifically asks about its functionality, relationship to web technologies, logical reasoning, potential errors, and then a concise summary of its purpose. The fact that this is "part 2 of 2" suggests the earlier part likely dealt with setup or related concepts, but we should treat this part as self-contained for analysis.

**2. Initial Scan and Keyword Identification:**

I'd start by quickly scanning the code for important keywords and patterns. This helps establish the general domain and identify key operations. Some initial observations:

* **"VideoCapture"**:  This is obviously central. The class name itself strongly suggests it's involved in capturing video.
* **State management (VIDEO_CAPTURE_STATE_*)**:  The code explicitly manages different states (STARTING, STARTED, STOPPED, ERROR, etc.). This implies a lifecycle.
* **Client interaction**:  Mentions of `clients_`, `StartCapture`, `StopCapture`, and callbacks like `state_update_cb` and `deliver_frame_cb` suggest this class manages multiple consumers of the video stream.
* **Buffer management (`client_buffers_`, `OnNewBuffer`, `OnBufferReady`, `ReleaseBuffer`)**:  This indicates the class handles the flow of video data.
* **Format negotiation (`GetDeviceSupportedFormats`, `GetDeviceFormatsInUse`)**:  The class interacts with the underlying video capture device to understand its capabilities.
* **Error handling**:  Specific error states and logging (`OnLog`) point to robustness.
* **Asynchronous operations and threading (`io_thread_checker_`, `media_task_runner_`, `main_task_runner_`)**: This indicates the class likely interacts with system-level video capture, which is often asynchronous.
* **GpuMemoryBuffer**:  This suggests optimization for GPU processing of video frames.
* **`RequestRefreshFrame`**: Hints at mechanisms for ensuring a fresh frame is delivered.
* **Metrics and Tracing (`TRACE_EVENT_INSTANT2`, UMA histograms)**:  The class collects performance and error data.

**3. Deeper Dive into Key Methods:**

After the initial scan, I'd focus on the most important methods to understand their roles:

* **`StartCapture`**: How does a client initiate capture?  What parameters are involved? How does it handle different existing states?
* **`StopCapture`**: How does a client stop capture? How does it handle multiple clients?
* **`OnStateChanged`**:  This is crucial for understanding the state transitions and how the class reacts to events from the underlying video capture device.
* **`OnNewBuffer` and `OnBufferReady`**: These methods handle the incoming video data. How are buffers allocated and made available to clients?
* **`OnVideoFrameReady`**: What happens when a video frame is ready for consumption?  How is it delivered to clients?
* **Error handling paths in `OnStateChanged`**: How are different errors propagated to clients?

**4. Identifying Relationships with Web Technologies:**

The prompt specifically asks about JavaScript, HTML, and CSS. While this C++ code *itself* doesn't directly manipulate these, its purpose is to *enable* their functionality.

* **JavaScript `getUserMedia()` API:** This is the primary entry point for web pages to access camera video. `VideoCaptureImpl` is a core part of the implementation behind this API. It handles the low-level interaction with the camera.
* **HTML `<video>` element:** The captured video frames are ultimately rendered in a `<video>` element. `VideoCaptureImpl` provides the video data that feeds into the rendering pipeline.
* **CSS (indirectly):** While CSS doesn't directly interact with `VideoCaptureImpl`, it's used to style the `<video>` element and control its layout on the web page.

**5. Logical Reasoning and Hypothetical Inputs/Outputs:**

To illustrate the class's behavior, I would create simple scenarios:

* **Scenario 1: Successful Start:**
    * Input: `StartCapture` called with valid parameters.
    * Output: State transitions to STARTING -> STARTED, clients receive `VIDEO_CAPTURE_STATE_STARTED`. Eventually, clients receive video frames via `deliver_frame_cb`.
* **Scenario 2: Start Failure (Permission Denied):**
    * Input: `StartCapture` called, but system permissions are missing.
    * Output: State transitions to ERROR_SYSTEM_PERMISSIONS_DENIED, clients receive the corresponding error state.
* **Scenario 3: Multiple Clients:**
    * Input: `StartCapture` called by multiple clients with potentially different resolution requests.
    * Output: The class negotiates a suitable resolution, and all clients receive the video stream. When one client stops, the capture might continue for other clients.

**6. Identifying Common Usage Errors:**

Thinking about how developers might misuse the API helps identify potential pitfalls:

* **Starting capture without proper permissions:** The browser will handle this, but `VideoCaptureImpl` reflects this error.
* **Not handling error states:**  JavaScript code needs to listen for and handle the various error states emitted by the `VideoCaptureImpl` (via the higher-level browser APIs).
* **Resource leaks (though less likely to be directly *caused* by the user of this *internal* class):**  While this C++ code handles memory management, improper use of the higher-level JavaScript APIs could lead to resource leaks if streams aren't closed correctly.

**7. Synthesizing the Summary:**

Finally, I'd synthesize the information gathered into a concise summary, focusing on the key responsibilities:

* Managing the lifecycle of video capture.
* Interacting with the underlying video capture device.
* Handling multiple clients.
* Delivering video frames to clients.
* Managing errors and state transitions.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the low-level buffer management details.
* **Correction:** While important, the higher-level functionality of managing the capture lifecycle and client interactions is more central to understanding the class's purpose.
* **Initial thought:**  Assume the user of this class is a web developer.
* **Correction:** Recognize this is an internal Chromium class. The *users* are other Chromium components, and ultimately the web developer interacts with higher-level JavaScript APIs that *use* this class.
* **Ensuring clear examples:**  Make sure the examples for JavaScript/HTML/CSS are clear and directly related to the functionality of `VideoCaptureImpl`.

By following this structured approach, including initial exploration, focused analysis, and then synthesis, it's possible to create a comprehensive and accurate summary of the `VideoCaptureImpl` class's functionality.
好的，这是对 `blink/renderer/platform/video_capture/video_capture_impl.cc` 文件功能的归纳总结。

**功能归纳:**

`VideoCaptureImpl` 类是 Chromium Blink 引擎中负责管理和控制单个视频捕获会话的核心组件。 它的主要职责包括：

1. **管理视频捕获设备的生命周期:**
   - 启动和停止与底层视频捕获设备的连接 (`StartCaptureInternal`, `StopDevice`).
   - 处理设备状态变化通知 (`OnStateChanged`)，例如设备启动、停止、暂停、恢复、出错等。
   - 在设备停止后根据需要重启捕获 (`RestartCapture`).
   - 处理捕获启动超时的情况 (`OnStartTimedout`).

2. **处理来自视频捕获设备的数据流:**
   - 接收新分配的缓冲区 (`OnNewBuffer`).
   - 接收填充了视频帧数据的缓冲区 (`OnBufferReady`).
   - 将接收到的缓冲区数据转换为 `media::VideoFrame` 对象，供 Blink 渲染引擎使用。这可能涉及到 GPU 内存缓冲区的处理 (`CreateVideoFrameInitData`, 与 `gpu::GpuMemoryBufferSupport` 交互).
   - 跟踪已分配的客户端缓冲区 (`client_buffers_`).
   - 在客户端使用完缓冲区后释放缓冲区 (`OnAllClientsFinishedConsumingFrame`, 与 `GetVideoCaptureHost()->ReleaseBuffer` 交互).
   - 处理缓冲区被销毁的通知 (`OnBufferDestroyed`).

3. **与视频捕获客户端进行交互:**
   - 维护连接到此 `VideoCaptureImpl` 实例的客户端列表 (`clients_`, `clients_pending_on_restart_`).
   - 向客户端发送状态更新通知 (`state_update_cb`).
   - 将捕获到的视频帧数据传递给客户端 (`deliver_frame_cb`).
   - 向客户端通知帧被丢弃的情况 (`frame_dropped_cb`).
   - 向客户端通知新的子捕获目标版本 (`sub_capture_target_version_cb`).

4. **处理视频捕获参数和配置:**
   - 存储和管理视频捕获参数 (`params_`)，例如请求的帧大小和帧率。
   - 获取设备支持的格式 (`GetDeviceSupportedFormats`).
   - 获取设备当前正在使用的格式 (`GetDeviceFormatsInUse`).

5. **错误处理和日志记录:**
   - 记录错误和状态信息 (`OnLog`).
   - 向客户端报告各种错误状态 (`VIDEO_CAPTURE_STATE_ERROR`, `VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED` 等).
   - 记录视频捕获启动的结果 (成功或失败) 到 UMA 统计 (`RecordStartOutcomeUMA`).

6. **性能优化和反馈机制:**
   - 可以请求刷新帧 (`RequestRefreshFrame`).
   - 处理来自下层的反馈信息 (`ProcessFeedback`).
   - 支持预映射帧 (`require_premapped_frames_`)，这是一种优化策略。

7. **与其他 Chromium 组件的交互:**
   - 通过 `VideoCaptureHost` 接口与更底层的视频捕获服务进行通信 (`GetVideoCaptureHost`).
   - 使用 `media::VideoFrame` 对象与渲染引擎进行数据交换。
   - 可能涉及到与 GPU 相关的组件进行交互以处理 GPU 内存缓冲区。

**总结:**

`VideoCaptureImpl` 作为一个核心的中间层，负责连接 Blink 渲染引擎的视频捕获请求和底层的操作系统或硬件视频捕获能力。它管理着视频捕获的整个流程，包括设备的启动、数据的接收和处理、以及与客户端的通信和状态管理。它确保了视频数据能够正确、高效地传输到 Web 页面中。

### 提示词
```
这是目录为blink/renderer/platform/video_capture/video_capture_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
lient_info;
      params_ = params;
      params_.requested_format.frame_rate =
          std::min(params_.requested_format.frame_rate,
                   static_cast<float>(media::limits::kMaxFramesPerSecond));

      DVLOG(1) << "StartCapture: starting with first resolution "
               << params_.requested_format.frame_size.ToString();
      OnLog("VideoCaptureImpl starting capture.");
      StartCaptureInternal();
      return;
    case VIDEO_CAPTURE_STATE_ERROR:
      OnLog("VideoCaptureImpl is in error state.");
      state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_ERROR);
      return;
    case VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED:
      OnLog("VideoCaptureImpl is in system permissions error state.");
      state_update_cb.Run(
          blink::VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED);
      return;
    case VIDEO_CAPTURE_STATE_ERROR_CAMERA_BUSY:
      OnLog("VideoCaptureImpl is in camera busy error state.");
      state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_ERROR_CAMERA_BUSY);
      return;
    case VIDEO_CAPTURE_STATE_ERROR_START_TIMEOUT:
      OnLog("VideoCaptureImpl is in timeout error state.");
      state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_ERROR_START_TIMEOUT);
      return;
    case VIDEO_CAPTURE_STATE_PAUSED:
    case VIDEO_CAPTURE_STATE_RESUMED:
      // The internal |state_| is never set to PAUSED/RESUMED since
      // VideoCaptureImpl is not modified by those.
      NOTREACHED();
  }
}

void VideoCaptureImpl::StopCapture(int client_id) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  // A client ID can be in only one client list.
  // If this ID is in any client list, we can just remove it from
  // that client list and don't have to run the other following RemoveClient().
  if (!RemoveClient(client_id, &clients_pending_on_restart_)) {
    RemoveClient(client_id, &clients_);
  }

  if (!clients_.empty())
    return;
  DVLOG(1) << "StopCapture: No more client, stopping ...";
  StopDevice();
  client_buffers_.clear();
  weak_factory_.InvalidateWeakPtrs();
}

void VideoCaptureImpl::RequestRefreshFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  GetVideoCaptureHost()->RequestRefreshFrame(device_id_);
}

void VideoCaptureImpl::GetDeviceSupportedFormats(
    VideoCaptureDeviceFormatsCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  GetVideoCaptureHost()->GetDeviceSupportedFormats(
      device_id_, session_id_,
      base::BindOnce(&VideoCaptureImpl::OnDeviceSupportedFormats,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void VideoCaptureImpl::GetDeviceFormatsInUse(
    VideoCaptureDeviceFormatsCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  GetVideoCaptureHost()->GetDeviceFormatsInUse(
      device_id_, session_id_,
      base::BindOnce(&VideoCaptureImpl::OnDeviceFormatsInUse,
                     weak_factory_.GetWeakPtr(), std::move(callback)));
}

void VideoCaptureImpl::OnLog(const String& message) {
  GetVideoCaptureHost()->OnLog(device_id_, message);
}

void VideoCaptureImpl::SetGpuMemoryBufferSupportForTesting(
    std::unique_ptr<gpu::GpuMemoryBufferSupport> gpu_memory_buffer_support) {
  gpu_memory_buffer_support_ = std::move(gpu_memory_buffer_support);
}

void VideoCaptureImpl::OnStateChanged(
    media::mojom::blink::VideoCaptureResultPtr result) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  // Stop the startup deadline timer as something has happened.
  startup_timeout_.Stop();

  if (result->which() ==
      media::mojom::blink::VideoCaptureResult::Tag::kErrorCode) {
    DVLOG(1) << __func__ << " Failed with an error.";
    if (result->get_error_code() ==
        media::VideoCaptureError::kWinMediaFoundationSystemPermissionDenied) {
      state_ = VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED;
      OnLog(
          "VideoCaptureImpl changing state to "
          "VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED");
    } else if (result->get_error_code() ==
               media::VideoCaptureError::kWinMediaFoundationCameraBusy) {
      state_ = VIDEO_CAPTURE_STATE_ERROR_CAMERA_BUSY;
      OnLog(
          "VideoCaptureImpl changing state to "
          "VIDEO_CAPTURE_STATE_ERROR_CAMERA_BUSY");
    } else if (result->get_error_code() ==
               media::VideoCaptureError::kVideoCaptureImplTimedOutOnStart) {
      state_ = VIDEO_CAPTURE_STATE_ERROR_START_TIMEOUT;
      OnLog(
          "VideoCaptureImpl changing state to "
          "VIDEO_CAPTURE_STATE_ERROR_START_TIMEOUT");
    } else {
      state_ = VIDEO_CAPTURE_STATE_ERROR;
      OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_ERROR");
    }
    for (const auto& client : clients_)
      client.second.state_update_cb.Run(state_);
    clients_.clear();
    RecordStartOutcomeUMA(result->get_error_code());
    return;
  }

  media::mojom::VideoCaptureState state = result->get_state();
  DVLOG(1) << __func__ << " state: " << state;
  switch (state) {
    case media::mojom::VideoCaptureState::STARTED:
      OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_STARTED");
      state_ = VIDEO_CAPTURE_STATE_STARTED;
      for (const auto& client : clients_)
        client.second.state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_STARTED);
      // In case there is any frame dropped before STARTED, always request for
      // a frame refresh to start the video call with.
      // Capture device will make a decision if it should refresh a frame.
      RequestRefreshFrame();
      RecordStartOutcomeUMA(media::VideoCaptureError::kNone);
      break;
    case media::mojom::VideoCaptureState::STOPPED:
      OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_STOPPED");
      state_ = VIDEO_CAPTURE_STATE_STOPPED;
      client_buffers_.clear();
      weak_factory_.InvalidateWeakPtrs();
      if (!clients_.empty() || !clients_pending_on_restart_.empty()) {
        OnLog("VideoCaptureImpl restarting capture");
        RestartCapture();
      }
      break;
    case media::mojom::VideoCaptureState::PAUSED:
      for (const auto& client : clients_)
        client.second.state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_PAUSED);
      break;
    case media::mojom::VideoCaptureState::RESUMED:
      for (const auto& client : clients_)
        client.second.state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_RESUMED);
      break;
    case media::mojom::VideoCaptureState::ENDED:
      OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_ENDED");
      // We'll only notify the client that the stream has stopped.
      for (const auto& client : clients_)
        client.second.state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_STOPPED);
      clients_.clear();
      state_ = VIDEO_CAPTURE_STATE_ENDED;
      break;
  }
}

void VideoCaptureImpl::OnNewBuffer(
    int32_t buffer_id,
    media::mojom::blink::VideoBufferHandlePtr buffer_handle) {
  DVLOG(1) << __func__ << " buffer_id: " << buffer_id;
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  const bool inserted =
      client_buffers_
          .emplace(buffer_id, base::MakeRefCounted<BufferContext>(
                                  std::move(buffer_handle), media_task_runner_))
          .second;
  DCHECK(inserted);
}

void VideoCaptureImpl::OnBufferReady(
    media::mojom::blink::ReadyBufferPtr buffer) {
  DVLOG(1) << __func__ << " buffer_id: " << buffer->buffer_id;
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  if (state_ != VIDEO_CAPTURE_STATE_STARTED) {
    OnFrameDropped(
        media::VideoCaptureFrameDropReason::kVideoCaptureImplNotInStartedState);
    GetVideoCaptureHost()->ReleaseBuffer(device_id_, buffer->buffer_id,
                                         DefaultFeedback());
    return;
  }

  base::TimeTicks reference_time = *buffer->info->metadata.reference_time;

  if (first_frame_ref_time_.is_null()) {
    first_frame_ref_time_ = reference_time;
    if (num_first_frame_logs_ < kMaxFirstFrameLogs) {
      OnLog("First frame received for this VideoCaptureImpl instance");
      num_first_frame_logs_++;
    } else if (num_first_frame_logs_ == kMaxFirstFrameLogs) {
      OnLog(
          "First frame received for this VideoCaptureImpl instance. This will "
          "not be logged anymore for this VideoCaptureImpl instance.");
      num_first_frame_logs_++;
    }
  }

  // If the timestamp is not prepared, we use reference time to make a rough
  // estimate. e.g. ThreadSafeCaptureOracle::DidCaptureFrame().
  if (buffer->info->timestamp.is_zero())
    buffer->info->timestamp = reference_time - first_frame_ref_time_;

  // If the capture_begin_time was not set use the reference time. This ensures
  // there is a captureTime available for local sources for
  // requestVideoFrameCallback.
  if (!buffer->info->metadata.capture_begin_time)
    buffer->info->metadata.capture_begin_time = reference_time;

  // TODO(qiangchen): Change the metric name to "reference_time" and
  // "timestamp", so that we have consistent naming everywhere.
  // Used by chrome/browser/media/cast_mirroring_performance_browsertest.cc
  TRACE_EVENT_INSTANT2("cast_perf_test", "OnBufferReceived",
                       TRACE_EVENT_SCOPE_THREAD, "timestamp",
                       (reference_time - base::TimeTicks()).InMicroseconds(),
                       "time_delta", buffer->info->timestamp.InMicroseconds());

  const int buffer_id = buffer->buffer_id;
  // Convert `buffer` into a media::VideoFrame or a gfx::GpuMemoryBuffer.
  std::optional<VideoFrameInitData> video_frame_init_data =
      CreateVideoFrameInitData(std::move(buffer));
  if (!video_frame_init_data.has_value()) {
    // Error during initialization of the frame or buffer.
    OnFrameDropped(media::VideoCaptureFrameDropReason::
                       kVideoCaptureImplFailedToWrapDataAsMediaVideoFrame);
    GetVideoCaptureHost()->ReleaseBuffer(device_id_, buffer_id,
                                         DefaultFeedback());
    return;
  }

  if (absl::holds_alternative<std::unique_ptr<gfx::GpuMemoryBuffer>>(
          video_frame_init_data->frame_or_buffer)) {
    // To make the frame ready we must convert gfx::GpuMemoryBuffer to
    // media::VideoFrame on the media task runner.
    media_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](media::GpuVideoAcceleratorFactories* gpu_factories,
                          VideoFrameInitData video_frame_init_data,
                          base::OnceCallback<void(VideoFrameInitData)>
                              on_frame_ready_callback,
                          base::OnceCallback<void()> on_gpu_context_lost,
                          base::OnceCallback<void()> on_gmb_not_supported) {
                         if (!VideoCaptureImpl::BindVideoFrameOnMediaTaskRunner(
                                 gpu_factories, video_frame_init_data,
                                 std::move(on_gmb_not_supported))) {
                           // Bind failed.
                           std::move(on_gpu_context_lost).Run();
                           // Proceed to invoke |on_frame_ready_callback| even
                           // though we failed - it takes care of reporting the
                           // frame as dropped when it is set to null.
                           video_frame_init_data.frame_or_buffer =
                               scoped_refptr<media::VideoFrame>(nullptr);
                         }
                         std::move(on_frame_ready_callback)
                             .Run(std::move(video_frame_init_data));
                       },
                       gpu_factories_, std::move(*video_frame_init_data),
                       base::BindPostTaskToCurrentDefault(base::BindOnce(
                           &VideoCaptureImpl::OnVideoFrameReady,
                           weak_factory_.GetWeakPtr(), reference_time)),
                       base::BindPostTask(
                           main_task_runner_,
                           base::BindOnce(&VideoCaptureImpl::OnGpuContextLost,
                                          weak_factory_.GetWeakPtr())),
                       base::BindPostTaskToCurrentDefault(
                           base::BindOnce(&VideoCaptureImpl::OnGmbNotSupported,
                                          weak_factory_.GetWeakPtr()))));
    return;
  }

  // No round-trip to media task runner needed.
  CHECK(absl::holds_alternative<scoped_refptr<media::VideoFrame>>(
      video_frame_init_data->frame_or_buffer));
  OnVideoFrameReady(reference_time, std::move(*video_frame_init_data));
}

void VideoCaptureImpl::OnVideoFrameReady(
    base::TimeTicks reference_time,
    VideoFrameInitData video_frame_init_data) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  CHECK(absl::holds_alternative<scoped_refptr<media::VideoFrame>>(
      video_frame_init_data.frame_or_buffer));
  scoped_refptr<media::VideoFrame> video_frame =
      absl::get<scoped_refptr<media::VideoFrame>>(
          video_frame_init_data.frame_or_buffer);

  // If we don't have a media::VideoFrame here then we've failed to convert the
  // gfx::GpuMemoryBuffer, dropping frame.
  if (!video_frame) {
    OnFrameDropped(media::VideoCaptureFrameDropReason::
                       kVideoCaptureImplFailedToWrapDataAsMediaVideoFrame);
    GetVideoCaptureHost()->ReleaseBuffer(
        device_id_, video_frame_init_data.ready_buffer->buffer_id,
        DefaultFeedback());
    return;
  }

  // Ensure the buffer is released when no longer needed by wiring up
  // DidFinishConsumingFrame() as a destruction observer.
  video_frame->AddDestructionObserver(
      base::BindOnce(&VideoCaptureImpl::DidFinishConsumingFrame,
                     base::BindPostTaskToCurrentDefault(base::BindOnce(
                         &VideoCaptureImpl::OnAllClientsFinishedConsumingFrame,
                         weak_factory_.GetWeakPtr(),
                         video_frame_init_data.ready_buffer->buffer_id,
                         std::move(video_frame_init_data.buffer_context)))));
  if (video_frame_init_data.ready_buffer->info->color_space.IsValid()) {
    video_frame->set_color_space(
        video_frame_init_data.ready_buffer->info->color_space);
  }
  video_frame->metadata().MergeMetadataFrom(
      video_frame_init_data.ready_buffer->info->metadata);

  // TODO(qiangchen): Dive into the full code path to let frame metadata hold
  // reference time rather than using an extra parameter.
  for (const auto& client : clients_) {
    client.second.deliver_frame_cb.Run(video_frame, reference_time);
  }
}

void VideoCaptureImpl::OnBufferDestroyed(int32_t buffer_id) {
  DVLOG(1) << __func__ << " buffer_id: " << buffer_id;
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  const auto& cb_iter = client_buffers_.find(buffer_id);
  if (cb_iter != client_buffers_.end()) {
    // If the BufferContext is non-null, the GpuMemoryBuffer-backed frames can
    // have more than one reference (held by MailboxHolderReleased). Otherwise,
    // only one reference should be held.
    DCHECK(!cb_iter->second.get() ||
           cb_iter->second->buffer_type() ==
               VideoFrameBufferHandleType::kGpuMemoryBufferHandle ||
           cb_iter->second->HasOneRef())
        << "Instructed to delete buffer we are still using.";
    client_buffers_.erase(cb_iter);
  }
}

void VideoCaptureImpl::OnFrameDropped(
    media::VideoCaptureFrameDropReason reason) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  for (const auto& client : clients_) {
    client.second.frame_dropped_cb.Run(reason);
  }
}

void VideoCaptureImpl::OnNewSubCaptureTargetVersion(
    uint32_t sub_capture_target_version) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  for (const auto& client : clients_) {
    client.second.sub_capture_target_version_cb.Run(sub_capture_target_version);
  }
}

constexpr base::TimeDelta VideoCaptureImpl::kCaptureStartTimeout;

void VideoCaptureImpl::OnAllClientsFinishedConsumingFrame(
    int buffer_id,
    scoped_refptr<BufferContext> buffer_context) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

// Subtle race note: It's important that the |buffer_context| argument be
// std::move()'ed to this method and never copied. This is so that the caller,
// DidFinishConsumingFrame(), does not implicitly retain a reference while it
// is running the trampoline callback on another thread. This is necessary to
// ensure the reference count on the BufferContext will be correct at the time
// OnBufferDestroyed() is called. http://crbug.com/797851
#if DCHECK_IS_ON()
  // The BufferContext should have exactly two references to it at this point,
  // one is this method's second argument and the other is from
  // |client_buffers_|.
  DCHECK(!buffer_context->HasOneRef());
  BufferContext* const buffer_raw_ptr = buffer_context.get();
  buffer_context = nullptr;
  // For non-GMB case, there should be only one reference, from
  // |client_buffers_|. This DCHECK is invalid for GpuMemoryBuffer backed
  // frames, because MailboxHolderReleased may hold on to a reference to
  // |buffer_context|.
  if (buffer_raw_ptr->buffer_type() !=
      VideoFrameBufferHandleType::kGpuMemoryBufferHandle) {
    DCHECK(buffer_raw_ptr->HasOneRef());
  }
#else
  buffer_context = nullptr;
#endif

  if (require_premapped_frames_) {
    feedback_.require_mapped_frame = true;
  }
  GetVideoCaptureHost()->ReleaseBuffer(device_id_, buffer_id, feedback_);
  feedback_ = media::VideoCaptureFeedback();
}

void VideoCaptureImpl::StopDevice() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  if (state_ != VIDEO_CAPTURE_STATE_STARTING &&
      state_ != VIDEO_CAPTURE_STATE_STARTED)
    return;
  state_ = VIDEO_CAPTURE_STATE_STOPPING;
  OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_STOPPING");
  GetVideoCaptureHost()->Stop(device_id_);
  params_.requested_format.frame_size.SetSize(0, 0);
}

void VideoCaptureImpl::RestartCapture() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  DCHECK_EQ(state_, VIDEO_CAPTURE_STATE_STOPPED);

  int width = 0;
  int height = 0;
  clients_.insert(clients_pending_on_restart_.begin(),
                  clients_pending_on_restart_.end());
  clients_pending_on_restart_.clear();
  for (const auto& client : clients_) {
    width = std::max(width,
                     client.second.params.requested_format.frame_size.width());
    height = std::max(
        height, client.second.params.requested_format.frame_size.height());
  }
  params_.requested_format.frame_size.SetSize(width, height);
  DVLOG(1) << __func__ << " " << params_.requested_format.frame_size.ToString();
  StartCaptureInternal();
}

void VideoCaptureImpl::StartCaptureInternal() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  state_ = VIDEO_CAPTURE_STATE_STARTING;
  OnLog("VideoCaptureImpl changing state to VIDEO_CAPTURE_STATE_STARTING");

  if (base::FeatureList::IsEnabled(kTimeoutHangingVideoCaptureStarts)) {
    startup_timeout_.Start(FROM_HERE, kCaptureStartTimeout,
                           base::BindOnce(&VideoCaptureImpl::OnStartTimedout,
                                          base::Unretained(this)));
  }
  start_outcome_reported_ = false;
  base::UmaHistogramBoolean("Media.VideoCapture.Start", true);

  GetVideoCaptureHost()->Start(device_id_, session_id_, params_,
                               observer_receiver_.BindNewPipeAndPassRemote());
}

void VideoCaptureImpl::OnStartTimedout() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  OnLog("VideoCaptureImpl timed out during starting");

  OnStateChanged(media::mojom::blink::VideoCaptureResult::NewErrorCode(
      media::VideoCaptureError::kVideoCaptureImplTimedOutOnStart));
}

void VideoCaptureImpl::OnDeviceSupportedFormats(
    VideoCaptureDeviceFormatsCallback callback,
    const Vector<media::VideoCaptureFormat>& supported_formats) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  std::move(callback).Run(supported_formats);
}

void VideoCaptureImpl::OnDeviceFormatsInUse(
    VideoCaptureDeviceFormatsCallback callback,
    const Vector<media::VideoCaptureFormat>& formats_in_use) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  std::move(callback).Run(formats_in_use);
}

bool VideoCaptureImpl::RemoveClient(int client_id, ClientInfoMap* clients) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);

  const ClientInfoMap::iterator it = clients->find(client_id);
  if (it == clients->end())
    return false;

  it->second.state_update_cb.Run(blink::VIDEO_CAPTURE_STATE_STOPPED);
  clients->erase(it);
  return true;
}

media::mojom::blink::VideoCaptureHost* VideoCaptureImpl::GetVideoCaptureHost() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  if (video_capture_host_for_testing_)
    return video_capture_host_for_testing_;

  if (!video_capture_host_.is_bound())
    video_capture_host_.Bind(std::move(pending_video_capture_host_));
  return video_capture_host_.get();
}

void VideoCaptureImpl::RecordStartOutcomeUMA(
    media::VideoCaptureError error_code) {
  // Record the success or failure of starting only the first time we transition
  // into such a state, not eg when resuming after pausing.
  if (!start_outcome_reported_) {
    VideoCaptureStartOutcome outcome;
    switch (error_code) {
      case media::VideoCaptureError::kNone:
        outcome = VideoCaptureStartOutcome::kStarted;
        break;
      case media::VideoCaptureError::kVideoCaptureImplTimedOutOnStart:
        outcome = VideoCaptureStartOutcome::kTimedout;
        break;
      default:
        outcome = VideoCaptureStartOutcome::kFailed;
        break;
    }
    base::UmaHistogramEnumeration("Media.VideoCapture.StartOutcome", outcome);
    base::UmaHistogramEnumeration("Media.VideoCapture.StartErrorCode",
                                  error_code);
    start_outcome_reported_ = true;
  }
}

// static
void VideoCaptureImpl::DidFinishConsumingFrame(
    BufferFinishedCallback callback_to_io_thread) {
  // Note: This function may be called on any thread by the VideoFrame
  // destructor.  |metadata| is still valid for read-access at this point.
  std::move(callback_to_io_thread).Run();
}

void VideoCaptureImpl::ProcessFeedback(
    const media::VideoCaptureFeedback& feedback) {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  feedback_ = feedback;
}

void VideoCaptureImpl::OnGmbNotSupported() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  RequirePremappedFrames();
  gmb_not_supported_ = true;
}

void VideoCaptureImpl::RequirePremappedFrames() {
  DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  require_premapped_frames_ = true;
}

media::VideoCaptureFeedback VideoCaptureImpl::DefaultFeedback() {
  media::VideoCaptureFeedback feedback;
  feedback.require_mapped_frame = require_premapped_frames_;
  return feedback;
}

base::WeakPtr<VideoCaptureImpl> VideoCaptureImpl::GetWeakPtr() {
  return weak_this_;
}

}  // namespace blink
```
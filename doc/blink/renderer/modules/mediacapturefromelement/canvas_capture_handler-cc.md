Response:
Let's break down the thought process for analyzing the `canvas_capture_handler.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file name `canvas_capture_handler.cc` and the directory `blink/renderer/modules/mediacapturefromelement/` immediately suggest that this code handles capturing the content of a `<canvas>` element for use in media streams (like WebRTC). The "handler" part implies it's managing the process rather than being the core drawing logic.

**2. Scanning for Key Classes and Structures:**

I looked for the main classes defined in the file:

* `CanvasCaptureHandler`: This is clearly the central class.
* `CanvasVideoCapturerSource`:  The name suggests this is a source of video data, specific to canvas, that fits into the broader media capture framework. The inheritance from `VideoCapturerSource` confirms this.
* `CanvasCaptureHandler::CanvasCaptureHandlerDelegate`:  The nested class structure and "Delegate" suffix point to a helper class, likely managing interactions with another thread or system.

**3. Analyzing `CanvasCaptureHandler`'s Responsibilities:**

I read through the methods of `CanvasCaptureHandler` to understand its lifecycle and interactions:

* **Constructor:** Takes size, frame rate, task runners, and a `MediaStreamComponent**`. This points to it being integrated into the Media Streams API.
* **`CreateCanvasCaptureHandler` (static):**  The typical pattern for creating instances of classes within Blink. The `UpdateWebRTCMethodCount` call confirms its usage within WebRTC scenarios.
* **`GetNewFrameCallback`:**  This is crucial. It returns a callback. The name suggests this is the mechanism by which the canvas content is delivered to the handler. The logic around `pending_send_new_frame_calls_` and the decrementing closure hints at asynchronous operations.
* **`OnNewFrameCallback`:** This is the callback returned by `GetNewFrameCallback`. It processes the received video frame.
* **`NeedsNewFrame`:** A simple getter, likely used to determine if the handler needs to request the next frame from the canvas.
* **`StartVideoCapture`:**  Sets up the capture process, takes capture parameters and a callback to deliver frames. Creates the `CanvasCaptureHandlerDelegate`.
* **`RequestRefreshFrame`:** Triggers sending the latest captured frame again. Handles a potential deferral if a new frame is already being processed.
* **`StopVideoCapture`:**  Cleans up resources and stops the capture.
* **`SendFrame`:**  The core logic for packaging the received video frame and sending it to the delegate for delivery.
* **`AddVideoCapturerSourceToVideoTrack` (static):**  This method ties the `CanvasVideoCapturerSource` into the broader Media Streams framework, creating a `MediaStreamTrack`.
* **`SendRefreshFrame`:** Sends the last captured frame again, used when a refresh is explicitly requested.

**4. Analyzing `CanvasVideoCapturerSource`:**

I looked at `CanvasVideoCapturerSource`'s methods, understanding it as the "glue" between `CanvasCaptureHandler` and the `MediaStreamVideoCapturerSource`:

* **Constructor:** Takes a `WeakPtr` to the `CanvasCaptureHandler`, size, and frame rate.
* **`GetPreferredFormats`:** Defines the video formats (resolution and frame rate) this source can provide.
* **`StartCapture`, `RequestRefreshFrame`, `StopCapture`, `SetCanDiscardAlpha`:** These methods delegate directly to the corresponding methods in `CanvasCaptureHandler`. This strongly indicates that `CanvasVideoCapturerSource` is acting as an intermediary, adapting the `VideoCapturerSource` interface to the specific needs of canvas capture.

**5. Analyzing `CanvasCaptureHandlerDelegate`:**

This class appears to manage the delivery of video frames on the IO thread:

* **Constructor:** Takes the frame delivery callback.
* **`SendNewFrameOnIOThread`:**  This method is called on the IO thread and executes the frame delivery callback. The thread checkers confirm its role in cross-thread communication.

**6. Identifying Relationships with Web Technologies:**

* **JavaScript:** The creation of the `CanvasCaptureHandler` is likely triggered by JavaScript using the `captureStream()` method on a `<canvas>` element. The `UpdateWebRTCMethodCount(RTCAPIName::kCanvasCaptureStream)` call directly links it to a JavaScript API.
* **HTML:** The `<canvas>` element itself is the source of the captured content.
* **CSS:** While not directly involved in the capture logic *within this file*, CSS styling affects how the canvas is rendered, and therefore, what content is captured.

**7. Inferring the User Interaction Flow:**

Based on the code and understanding of Web APIs, I reconstructed the likely sequence of user actions and code execution leading to this handler:

1. **User interacts with a web page containing a `<canvas>` element.**
2. **JavaScript code calls `canvas.captureStream(frameRate)`.**
3. **Blink's JavaScript bindings translate this call into native code, eventually leading to the creation of a `CanvasCaptureHandler`.**
4. **The `CanvasCaptureHandler` starts requesting frames from the canvas.**
5. **The canvas rendering logic (not in this file) provides the image data.**
6. **`CanvasCaptureHandler` processes this data into video frames and sends them to the `MediaStreamTrack`.**
7. **The `MediaStreamTrack` can then be used in WebRTC (e.g., `getUserMedia`) or other media contexts.**

**8. Considering Potential Issues and Error Scenarios:**

I thought about common mistakes developers might make or potential edge cases:

* **Incorrect `frameRate`:** Specifying a very high frame rate might lead to performance issues.
* **Canvas size changes:**  The handler might need to adapt to changes in the canvas dimensions.
* **Disposing the canvas:**  The handler needs to handle the case where the canvas element is removed from the DOM while capture is active.
* **Concurrency issues:**  The asynchronous nature of frame delivery and the involvement of different threads could introduce race conditions if not handled carefully.

**9. Formulating Hypotheses and Examples:**

I created specific examples of JavaScript code, HTML, and CSS to illustrate how these technologies interact with the `CanvasCaptureHandler`. I also formulated hypothetical input and output scenarios for the `SendFrame` method to demonstrate its functionality.

**10. Structuring the Explanation:**

Finally, I organized the information into logical sections: Core Functionality, Relationships with Web Technologies, User Interaction Flow, Potential Issues, etc., to present a clear and comprehensive explanation of the code.

This iterative process of reading the code, identifying key components, understanding their interactions, and relating them to broader web technologies allows for a thorough analysis of the `canvas_capture_handler.cc` file.
这个文件 `blink/renderer/modules/mediacapturefromelement/canvas_capture_handler.cc` 是 Chromium Blink 引擎中用于处理从 HTML `<canvas>` 元素捕获媒体流的功能的核心组件。 它的主要功能是：

**核心功能:**

1. **从 `<canvas>` 元素捕获视频帧:**  `CanvasCaptureHandler` 负责接收来自 `<canvas>` 元素的图像数据，并将其转换为视频帧，以便可以作为媒体流的一部分进行传输。

2. **控制帧率:**  它允许指定捕获视频流的帧率。

3. **与 `MediaStream` API 集成:**  它将捕获的视频帧提供给 `MediaStream` API，使其可以被用于 WebRTC 或其他需要媒体流的应用场景。

4. **管理视频捕获的生命周期:**  负责启动、停止和管理从 `<canvas>` 捕获视频的过程。

5. **处理帧的请求和发送:**  当需要新帧时，它会请求 `<canvas>` 提供最新的图像数据，并将接收到的数据转换成视频帧并发送出去。

6. **线程管理:**  使用主渲染线程（Main Render thread）和 IO 线程进行协作，确保性能和响应性。图像处理可能在 IO 线程上进行，而与 DOM 的交互和控制逻辑在主渲染线程上。

**与 JavaScript, HTML, CSS 的关系 (及举例说明):**

* **JavaScript:**
    * **启动捕获:** JavaScript 使用 `HTMLCanvasElement.captureStream()` 方法来启动从 `<canvas>` 元素的视频捕获。 这会触发 Blink 引擎创建 `CanvasCaptureHandler` 的实例。
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const stream = canvas.captureStream(30); // 请求 30 帧/秒 的视频流
        ```
    * **使用捕获的流:**  获取到的 `MediaStream` 对象可以被传递给其他 Web API，例如 `getUserMedia` 中使用的 `MediaStreamTrack`，用于 WebRTC 通信或录制。
        ```javascript
        const video = document.getElementById('remoteVideo');
        video.srcObject = stream;
        ```
    * **控制捕获参数:**  `captureStream()` 方法可以接收帧率作为参数，影响 `CanvasCaptureHandler` 的配置。

* **HTML:**
    * **`<canvas>` 元素是捕获的源头:**  `CanvasCaptureHandler` 的作用是捕获 `<canvas>` 元素渲染的内容。
        ```html
        <canvas id="myCanvas" width="500" height="300"></canvas>
        ```
    * **Canvas 内容的绘制:**  通过 JavaScript 在 `<canvas>` 上绘制的内容会被 `CanvasCaptureHandler` 捕获。

* **CSS:**
    * **影响 Canvas 的渲染结果:** CSS 样式会影响 `<canvas>` 元素的显示效果，从而影响 `CanvasCaptureHandler` 捕获的内容。 例如，通过 CSS 变换或缩放 `<canvas>`，捕获到的视频流也会反映这些变化。
        ```css
        #myCanvas {
          border: 1px solid black;
          transform: scale(0.5);
        }
        ```

**逻辑推理 (假设输入与输出):**

假设输入：

* **HTML:**  一个 ID 为 `myCanvas` 的 `<canvas>` 元素，其上通过 JavaScript 绘制了一个红色的圆形。
* **JavaScript:** 调用了 `document.getElementById('myCanvas').captureStream(10)`，请求帧率为 10 的视频流。

逻辑推理：

1. `captureStream(10)` 会创建一个 `CanvasCaptureHandler` 实例，并将目标 `<canvas>` 元素和请求的帧率 (10) 传递给它。
2. `CanvasCaptureHandler` 会定期（大约每 1/10 秒）请求 `<canvas>` 的当前内容。
3. `<canvas>` 会提供其当前渲染状态的图像数据，即一个红色圆形。
4. `CanvasCaptureHandler` 将这些图像数据转换为视频帧。
5. 输出： `CanvasCaptureHandler` 会产生一个 `MediaStreamTrack`，其中包含一系列视频帧，每一帧都显示一个红色的圆形。 视频流的帧率为 10 帧/秒。

**用户或编程常见的使用错误 (举例说明):**

1. **忘记在 `<canvas>` 上绘制内容:**  如果在调用 `captureStream()` 之前或期间，没有在 `<canvas>` 上绘制任何东西，那么捕获到的视频流将是空白的。
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const stream = canvas.captureStream();
    // 错误：此时 canvas 上可能没有绘制任何内容
    ```

2. **请求过高的帧率:**  如果请求的帧率过高，例如 `canvas.captureStream(60)`，而实际 `<canvas>` 内容的更新速度跟不上，或者硬件性能不足，可能会导致性能问题，例如卡顿或丢帧。

3. **在 `captureStream()` 之后修改 canvas 的大小:**  如果在调用 `captureStream()` 之后，动态地修改了 `<canvas>` 元素的 `width` 或 `height` 属性，可能会导致捕获到的视频流出现问题，例如比例失调或内容截断。 应该在调用 `captureStream()` 之前设置好 canvas 的大小。

4. **未正确处理 `MediaStream` 的生命周期:**  如果 `captureStream()` 返回的 `MediaStream` 对象没有被正确地使用或管理，例如没有将其赋值给 `video.srcObject` 或将其添加到 WebRTC 连接中，那么捕获到的数据将无法被利用。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户访问包含 `<canvas>` 元素的网页。**
2. **网页上的 JavaScript 代码执行，调用了 `<canvas>` 元素的 `captureStream()` 方法。**  这通常发生在用户触发某个操作之后，例如点击按钮或执行特定流程。
3. **Blink 引擎接收到 `captureStream()` 的调用，并开始创建相应的对象，包括 `CanvasCaptureHandler`。**
4. **`CanvasCaptureHandler` 初始化，并开始监听 `<canvas>` 的绘制事件或定期请求新的帧数据。**
5. **如果 JavaScript 代码将 `captureStream()` 返回的 `MediaStream` 对象用于创建 `MediaStreamTrack` 并添加到 WebRTC 的 `RTCPeerConnection` 中，那么这个视频流会被发送到远端。**
6. **在调试时，可以通过以下方式追踪到 `CanvasCaptureHandler` 的执行：**
    * **在 Blink 渲染引擎的源代码中设置断点:**  在 `canvas_capture_handler.cc` 相关的函数（例如构造函数、`StartVideoCapture`、`SendFrame` 等）设置断点。
    * **查看 Chrome 的 `chrome://webrtc-internals` 页面:**  这个页面会显示当前活动的 WebRTC 会话和媒体流，可以帮助确认是否成功创建了从 canvas 捕获的视频轨道。
    * **使用开发者工具的 "Sources" 面板进行 JavaScript 代码调试:**  追踪 `captureStream()` 的调用栈，可以了解代码是如何执行到 Blink 引擎的。
    * **查看控制台的日志输出:**  Blink 引擎可能会在控制台中输出与媒体捕获相关的调试信息。

总而言之，`CanvasCaptureHandler` 是 Blink 引擎中连接 HTML `<canvas>` 元素和媒体流 API 的关键桥梁，它使得开发者能够轻松地将 canvas 上的动态内容集成到各种媒体应用中。

Prompt: 
```
这是目录为blink/renderer/modules/mediacapturefromelement/canvas_capture_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediacapturefromelement/canvas_capture_handler.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/rand_util.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "media/base/limits.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_to_video_frame_copier.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/size.h"

namespace blink {

// Implementation VideoCapturerSource that is owned by
// MediaStreamVideoCapturerSource and delegates the Start/Stop calls to
// CanvasCaptureHandler.
// This class is single threaded and pinned to main render thread.
class CanvasVideoCapturerSource : public VideoCapturerSource {
 public:
  CanvasVideoCapturerSource(base::WeakPtr<CanvasCaptureHandler> canvas_handler,
                            const gfx::Size& size,
                            double frame_rate)
      : size_(size),
        frame_rate_(static_cast<float>(
            std::min(static_cast<double>(media::limits::kMaxFramesPerSecond),
                     frame_rate))),
        canvas_handler_(std::move(canvas_handler)) {
    DCHECK_LE(0, frame_rate_);
  }

 protected:
  media::VideoCaptureFormats GetPreferredFormats() override {
    DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
    media::VideoCaptureFormats formats;
    formats.push_back(media::VideoCaptureFormat(gfx::Size(size_), frame_rate_,
                                                media::PIXEL_FORMAT_I420));
    formats.push_back(media::VideoCaptureFormat(gfx::Size(size_), frame_rate_,
                                                media::PIXEL_FORMAT_I420A));
    return formats;
  }
  void StartCapture(const media::VideoCaptureParams& params,
                    const blink::VideoCaptureDeliverFrameCB& frame_callback,
                    const VideoCaptureSubCaptureTargetVersionCB&
                        sub_capture_target_version_callback,
                    // Canvas capture does not report frame drops.
                    const VideoCaptureNotifyFrameDroppedCB&,
                    const RunningCallback& running_callback) override {
    DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
    if (canvas_handler_.get()) {
      canvas_handler_->StartVideoCapture(params, frame_callback,
                                         running_callback);
    }
  }
  void RequestRefreshFrame() override {
    DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
    if (canvas_handler_.get())
      canvas_handler_->RequestRefreshFrame();
  }
  void StopCapture() override {
    DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
    if (canvas_handler_.get())
      canvas_handler_->StopVideoCapture();
  }
  void SetCanDiscardAlpha(bool can_discard_alpha) override {
    DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
    if (canvas_handler_.get())
      canvas_handler_->SetCanDiscardAlpha(can_discard_alpha);
  }

 private:
  const gfx::Size size_;
  const float frame_rate_;
  // Bound to Main Render thread.
  THREAD_CHECKER(main_render_thread_checker_);
  // CanvasCaptureHandler is owned by CanvasDrawListener in blink. It is
  // guaranteed to be destroyed on Main Render thread and it would happen
  // independently of this class. Therefore, WeakPtr should always be checked
  // before use.
  base::WeakPtr<CanvasCaptureHandler> canvas_handler_;
};

class CanvasCaptureHandler::CanvasCaptureHandlerDelegate {
 public:
  explicit CanvasCaptureHandlerDelegate(
      VideoCaptureDeliverFrameCB new_frame_callback)
      : new_frame_callback_(new_frame_callback) {
    DETACH_FROM_THREAD(io_thread_checker_);
  }

  CanvasCaptureHandlerDelegate(const CanvasCaptureHandlerDelegate&) = delete;
  CanvasCaptureHandlerDelegate& operator=(const CanvasCaptureHandlerDelegate&) =
      delete;

  ~CanvasCaptureHandlerDelegate() {
    DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
  }

  void SendNewFrameOnIOThread(scoped_refptr<media::VideoFrame> video_frame,
                              base::TimeTicks current_time) {
    DCHECK_CALLED_ON_VALID_THREAD(io_thread_checker_);
    new_frame_callback_.Run(std::move(video_frame), current_time);
  }

  base::WeakPtr<CanvasCaptureHandlerDelegate> GetWeakPtrForIOThread() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  const VideoCaptureDeliverFrameCB new_frame_callback_;
  // Bound to IO thread.
  THREAD_CHECKER(io_thread_checker_);
  base::WeakPtrFactory<CanvasCaptureHandlerDelegate> weak_ptr_factory_{this};
};

CanvasCaptureHandler::CanvasCaptureHandler(
    LocalFrame* frame,
    const gfx::Size& size,
    double frame_rate,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    MediaStreamComponent** component)
    : io_task_runner_(std::move(io_task_runner)) {
  std::unique_ptr<VideoCapturerSource> video_source(
      new CanvasVideoCapturerSource(weak_ptr_factory_.GetWeakPtr(), size,
                                    frame_rate));
  AddVideoCapturerSourceToVideoTrack(std::move(main_task_runner), frame,
                                     std::move(video_source), component);
}

CanvasCaptureHandler::~CanvasCaptureHandler() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  io_task_runner_->DeleteSoon(FROM_HERE, delegate_.release());
}

// static
std::unique_ptr<CanvasCaptureHandler>
CanvasCaptureHandler::CreateCanvasCaptureHandler(
    LocalFrame* frame,
    const gfx::Size& size,
    double frame_rate,
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
    MediaStreamComponent** component) {
  // Save histogram data so we can see how much CanvasCapture is used.
  // The histogram counts the number of calls to the JS API.
  UpdateWebRTCMethodCount(RTCAPIName::kCanvasCaptureStream);

  return std::unique_ptr<CanvasCaptureHandler>(new CanvasCaptureHandler(
      frame, size, frame_rate, std::move(main_task_runner),
      std::move(io_task_runner), component));
}

CanvasCaptureHandler::NewFrameCallback
CanvasCaptureHandler::GetNewFrameCallback() {
  // Increment the number of pending calls, and create a ScopedClosureRunner
  // to ensure that it be decremented even if the returned callback is dropped
  // instead of being run.
  pending_send_new_frame_calls_ += 1;
  auto decrement_closure = WTF::BindOnce(
      [](base::WeakPtr<CanvasCaptureHandler> handler) {
        if (handler)
          handler->pending_send_new_frame_calls_ -= 1;
      },
      weak_ptr_factory_.GetWeakPtr());

  return WTF::BindOnce(&CanvasCaptureHandler::OnNewFrameCallback,
                       weak_ptr_factory_.GetWeakPtr(),
                       base::ScopedClosureRunner(std::move(decrement_closure)),
                       base::TimeTicks::Now(), gfx::ColorSpace());
}

void CanvasCaptureHandler::OnNewFrameCallback(
    base::ScopedClosureRunner decrement_runner,
    base::TimeTicks this_frame_ticks,
    const gfx::ColorSpace& color_space,
    scoped_refptr<media::VideoFrame> video_frame) {
  DCHECK_GT(pending_send_new_frame_calls_, 0u);
  decrement_runner.RunAndReset();

  if (video_frame)
    SendFrame(this_frame_ticks, color_space, video_frame);

  if (!pending_send_new_frame_calls_ && deferred_request_refresh_frame_)
    SendRefreshFrame();
}

bool CanvasCaptureHandler::NeedsNewFrame() const {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  return ask_for_new_frame_;
}

void CanvasCaptureHandler::StartVideoCapture(
    const media::VideoCaptureParams& params,
    const VideoCaptureDeliverFrameCB& new_frame_callback,
    const VideoCapturerSource::RunningCallback& running_callback) {
  DVLOG(3) << __func__ << " requested "
           << media::VideoCaptureFormat::ToString(params.requested_format);
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DCHECK(params.requested_format.IsValid());
  capture_format_ = params.requested_format;
  delegate_ =
      std::make_unique<CanvasCaptureHandlerDelegate>(new_frame_callback);
  DCHECK(delegate_);
  ask_for_new_frame_ = true;
  running_callback.Run(RunState::kRunning);
}

void CanvasCaptureHandler::RequestRefreshFrame() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (last_frame_ && delegate_) {
    // If we're currently reading out pixels from GL memory, we risk
    // emitting frames with non-incrementally increasing timestamps.
    // Defer sending the refresh frame until we have completed those async
    // reads.
    if (pending_send_new_frame_calls_) {
      deferred_request_refresh_frame_ = true;
      return;
    }
    SendRefreshFrame();
  }
}

void CanvasCaptureHandler::StopVideoCapture() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  ask_for_new_frame_ = false;
  io_task_runner_->DeleteSoon(FROM_HERE, delegate_.release());
}

void CanvasCaptureHandler::SendFrame(
    base::TimeTicks this_frame_ticks,
    const gfx::ColorSpace& color_space,
    scoped_refptr<media::VideoFrame> video_frame) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  // If this function is called asynchronously, |delegate_| might have been
  // released already in StopVideoCapture().
  if (!delegate_ || !video_frame)
    return;

  if (!first_frame_ticks_)
    first_frame_ticks_ = this_frame_ticks;
  video_frame->set_timestamp(this_frame_ticks - *first_frame_ticks_);
  if (color_space.IsValid())
    video_frame->set_color_space(color_space);

  last_frame_ = video_frame;
  PostCrossThreadTask(*io_task_runner_, FROM_HERE,
                      WTF::CrossThreadBindOnce(
                          &CanvasCaptureHandler::CanvasCaptureHandlerDelegate::
                              SendNewFrameOnIOThread,
                          delegate_->GetWeakPtrForIOThread(),
                          std::move(video_frame), this_frame_ticks));
}

void CanvasCaptureHandler::AddVideoCapturerSourceToVideoTrack(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    LocalFrame* frame,
    std::unique_ptr<VideoCapturerSource> source,
    MediaStreamComponent** component) {
  uint8_t track_id_bytes[64];
  base::RandBytes(track_id_bytes);
  String track_id = Base64Encode(track_id_bytes);
  media::VideoCaptureFormats preferred_formats = source->GetPreferredFormats();
  auto stream_video_source = std::make_unique<MediaStreamVideoCapturerSource>(
      main_task_runner, frame,
      WebPlatformMediaStreamSource::SourceStoppedCallback(), std::move(source));
  auto* stream_video_source_ptr = stream_video_source.get();
  auto* stream_source = MakeGarbageCollected<MediaStreamSource>(
      track_id, MediaStreamSource::kTypeVideo, track_id, false,
      std::move(stream_video_source));
  stream_source->SetCapabilities(ComputeCapabilitiesForVideoSource(
      track_id, preferred_formats, mojom::blink::FacingMode::kNone,
      false /* is_device_capture */));

  *component = MakeGarbageCollected<MediaStreamComponentImpl>(
      stream_source,
      std::make_unique<MediaStreamVideoTrack>(
          stream_video_source_ptr,
          MediaStreamVideoSource::ConstraintsOnceCallback(), true));
}

void CanvasCaptureHandler::SendRefreshFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DCHECK_EQ(pending_send_new_frame_calls_, 0u);
  if (last_frame_ && delegate_) {
    io_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&CanvasCaptureHandler::CanvasCaptureHandlerDelegate::
                           SendNewFrameOnIOThread,
                       delegate_->GetWeakPtrForIOThread(), last_frame_,
                       base::TimeTicks::Now()));
  }
  deferred_request_refresh_frame_ = false;
}

}  // namespace blink

"""

```
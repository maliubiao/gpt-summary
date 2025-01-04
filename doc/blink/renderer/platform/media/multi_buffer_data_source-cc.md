Response: Let's break down the thought process to analyze the provided C++ code for `multi_buffer_data_source.cc`.

1. **Understand the Goal:** The primary request is to understand the *functionality* of this specific Chromium Blink engine file. Beyond that, it asks for connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), and common usage errors (user/programmer).

2. **Initial Code Scan (High-Level):**
    * **Includes:**  The `#include` directives are crucial. They tell us what other components this code interacts with. I see:
        * `third_party/blink/...`:  Confirms it's part of Blink.
        * `media/base/...`:  Indicates media handling.
        * `net/base/...`:  Suggests network interactions.
        * `base/...`: Core Chromium utilities (threading, containers, etc.).
    * **Namespace:** `namespace blink { namespace { ... } namespace }`  This confirms its place within the Blink rendering engine. The anonymous namespace `{}` holds helper functions/constants local to this file.
    * **Class Definition:**  `class MultiBufferDataSource : public media::DataSource`. This is the core of the file. It inherits from `media::DataSource`, which implies it's responsible for providing media data.
    * **Member Variables:** Briefly scanning the member variables gives hints about the state it manages: `total_bytes_`, `streaming_`, `loading_`, `failed_`, `url_data_`, `reader_`, `preload_`, `bitrate_`, etc. These give clues about its purpose (managing a data source, handling loading, preloading, etc.).
    * **Member Functions:**  Looking at the public methods like `Initialize`, `Read`, `Stop`, `SetPreload`, `SetBitrate`, `GetSize`, `IsStreaming` provides a good overview of the API.

3. **Deconstruct Functionality (Method by Method):**  Now, I'll go through the methods, focusing on what each one *does*:
    * **Constructor/Destructor:** Sets up initial state and cleans up. Notice the use of `UrlData`.
    * **`SetReader`:** Manages the `MultiBufferReader`, which is likely the core component for actually retrieving data.
    * **`CreateResourceLoader`:**  Instantiates the `MultiBufferReader`. Pay attention to the parameters passed to the reader (start/end positions, callbacks).
    * **`Initialize`:**  Sets up the initial data loading. It uses `reader_->Wait()`, suggesting asynchronous operations. The callbacks (`StartCallback`) are important.
    * **`OnRedirected`:** Handles HTTP redirects. Crucial for understanding how the data source adapts to changing URLs.
    * **`SetPreload`:**  Configures how much data to load in advance. This is directly related to media playback performance.
    * **`HasSingleOrigin`, `IsCorsCrossOrigin`, etc.:**  Deals with security and cross-origin resource sharing (CORS), vital for web security.
    * **`OnMediaPlaybackRateChanged`, `OnMediaIsPlaying`:**  Adapts the buffering strategy based on playback state.
    * **`Stop`, `Abort`:**  Manages the lifecycle of the data source. Understand the difference between these two.
    * **`SetBitrate`:**  Provides a hint to the data source about the network conditions.
    * **`OnBufferingHaveEnough`:**  A signal from the media player that enough data is buffered.
    * **`GetMemoryUsage`:**  Reports memory usage.
    * **`GetUrlAfterRedirects`:**  Gets the final URL.
    * **`Read`:** The core method for requesting data. Notice the use of a `ReadOperation` and the attempt to read from the cache first.
    * **`GetSize`, `IsStreaming`:**  Provides information about the data source.
    * **`ReadTask`, `SeekTask`:** These are internal tasks, likely run on a separate thread, that handle the actual data retrieval and seeking. Pay attention to the locking mechanisms (`base::AutoLock`).
    * **Callbacks (`StartCallback`, `ProgressCallback`):**  These are crucial for communication between the `MultiBufferDataSource` and its clients.
    * **`UpdateLoadingState_Locked`, `UpdateProgress`, `UpdateBufferSizes`:** Internal methods for managing the data loading process and buffering strategies. The constants at the top of the file (`kMinBufferPreload`, `kMaxBufferPreload`, etc.) are important here.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML `<video>` and `<audio>` elements:**  These elements are the primary consumers of media data. This `MultiBufferDataSource` is directly involved in fetching and providing the data for them.
    * **JavaScript Media API (e.g., `HTMLMediaElement`):**  JavaScript code interacts with the media elements, controlling playback, setting the `src` attribute (which triggers the use of this data source), and listening for events like `canplaythrough`.
    * **CSS (indirectly):** While CSS doesn't directly interact with data loading, it styles the media controls and the overall page layout, impacting the user experience related to media playback.

5. **Logical Reasoning (Input/Output Examples):**  Think about specific scenarios:
    * **Initial Load:** Input: A URL to a video file. Output:  The video starts playing after some initial buffering.
    * **Seeking:** Input: User seeks to a different part of the video. Output:  The video jumps to the new position, potentially with a brief loading delay.
    * **Slow Network:** Input:  A slow internet connection. Output:  More frequent buffering, lower video quality (if adaptive streaming is involved, though not directly in this file).
    * **Redirect:** Input: A URL that redirects to another URL. Output: The video loads from the final URL.

6. **Common Usage Errors (User/Programmer):**
    * **User Errors:**  Interrupted network connection, trying to play a corrupted file, insufficient bandwidth.
    * **Programmer Errors:** Setting incorrect preload values, not handling errors correctly in JavaScript media event handlers, issues with CORS configuration on the server.

7. **Refine and Organize:**  Structure the analysis clearly, using headings and bullet points. Explain the purpose of each significant part of the code. Provide concrete examples for the web technology connections and usage errors. Make sure the input/output examples are specific and illustrate the behavior of the `MultiBufferDataSource`.

8. **Review and Verify:**  Read through the analysis to ensure accuracy and completeness. Double-check the understanding of key concepts like buffering, preloading, and CORS.

Self-Correction/Refinement during the process:

* **Initial thought:** Focus heavily on the `Read` method. **Correction:** Realize that the `Initialize` method and the buffering strategies are equally important to understand the overall functionality.
* **Initial thought:** Directly link CSS. **Correction:**  Recognize that the link is more indirect, primarily affecting the user interface around the media player.
* **Initial thought:**  Oversimplify the input/output examples. **Correction:**  Make the examples more specific and tie them directly to the actions of the `MultiBufferDataSource`.
* **Initial thought:**  Focus only on programmer errors. **Correction:** Include common user-related issues that can impact media playback.

By following these steps, including the self-correction, I could arrive at a comprehensive and accurate analysis of the provided C++ code.
这个 `multi_buffer_data_source.cc` 文件是 Chromium Blink 渲染引擎中用于处理多缓冲媒体数据源的核心组件。 它的主要功能是 **管理和提供从网络或本地读取的媒体数据 (如音频和视频) 给媒体播放器**。  它通过使用 `MultiBufferReader` 与底层的 `UrlData` 交互来高效地读取和缓存数据。

以下是它的主要功能点的详细说明：

**核心功能:**

1. **数据获取和缓冲:**
   - **从 `UrlData` 读取数据:**  它使用 `MultiBufferReader` 从 `UrlData` 对象中读取媒体数据。 `UrlData`  封装了实际的网络请求和缓存机制。
   - **多缓冲管理:**  名称中的 "multi-buffer" 暗示了它管理多个数据缓冲区，以便实现更流畅的播放和高效的预加载。
   - **预加载 (Preloading):**  根据 `preload` 设置 (auto, metadata, none)，它会预先加载一定量的数据到缓冲区，以减少播放过程中的卡顿。 预加载的大小会根据网络速度、媒体时长等因素动态调整。
   - **缓存管理:**  虽然主要的缓存逻辑可能在 `UrlData` 中，但 `MultiBufferDataSource` 会根据播放进度和预加载策略，告知 `MultiBufferReader` 需要缓存哪些数据，以及可以释放哪些数据。

2. **数据提供:**
   - **实现 `media::DataSource` 接口:**  它实现了 Chromium 媒体框架定义的 `media::DataSource` 接口，使得媒体播放器可以通过标准的 `Read` 方法来获取数据。
   - **按需读取:**  当媒体播放器请求特定位置和大小的数据时，`MultiBufferDataSource` 会从其管理的缓冲区中或底层数据源中读取并返回。

3. **状态管理:**
   - **跟踪加载状态:**  维护 `loading_` 标志来表示当前是否正在加载数据。
   - **跟踪流式传输状态:**  维护 `streaming_` 标志来表示资源是否为流式传输 (例如，未知总大小)。
   - **错误处理:**  处理网络错误、读取错误等，并通过回调通知媒体播放器。
   - **重定向处理:**  处理 HTTP 重定向，并更新内部状态和 `UrlData`。
   - **大小信息:**  跟踪媒体的总大小 (`total_bytes_`)，并在可用时通知媒体播放器。

4. **性能优化:**
   - **Seek 优化:**  通过延迟实际的底层数据源的 seek 操作 (`SeekTask`)，并在短时间内多次 seek 时进行合并，来优化 seek 性能。
   - **根据播放速率调整缓冲:**  根据当前的播放速率 (`playback_rate_`) 动态调整预加载和缓冲大小。
   - **根据网络状况调整缓冲:**  虽然代码中看起来主要是通过 `bitrate_` 来估算，但实际上底层的 `UrlData` 和网络栈也会影响缓冲策略。

5. **安全性和跨域处理:**
   - **同源策略 (Same-Origin Policy):**  跟踪资源是否始终来自同一个源 (`single_origin_`)，这对于某些安全检查很重要。
   - **CORS (Cross-Origin Resource Sharing):**  检查资源是否是跨域的，并处理相关的安全策略 (`IsCorsCrossOrigin`, `HasAccessControl`, `PassedTimingAllowOriginCheck`, `WouldTaintOrigin`).

**与 JavaScript, HTML, CSS 的关系举例:**

- **HTML:**  HTML 中的 `<video>` 或 `<audio>` 元素是媒体播放器的宿主。 当设置了元素的 `src` 属性后，浏览器会创建一个相应的 `MultiBufferDataSource` (或其他类型的 `DataSource`) 来获取媒体数据。
  ```html
  <video src="https://example.com/video.mp4"></video>
  ```
  在这个例子中，当视频元素开始加载时，`MultiBufferDataSource` 可能会被创建来处理 `video.mp4` 的数据。

- **JavaScript:**  JavaScript 可以通过 Media API 与 HTML 媒体元素交互，例如控制播放、暂停、设置播放速率等。 这些操作会间接地影响 `MultiBufferDataSource` 的行为。
  ```javascript
  const video = document.querySelector('video');
  video.play(); // 触发数据读取
  video.playbackRate = 2.0; //  会调用 MultiBufferDataSource::OnMediaPlaybackRateChanged
  ```
  - 调用 `video.play()` 会触发媒体播放器开始请求数据，导致 `MultiBufferDataSource` 开始读取和缓冲数据。
  - 设置 `video.playbackRate` 会调用 `MultiBufferDataSource::OnMediaPlaybackRateChanged`，从而调整缓冲策略。

- **CSS:** CSS 主要负责媒体元素的样式和布局，与 `MultiBufferDataSource` 的数据获取功能没有直接关系。 但是，CSS 可以通过控制媒体控件的可见性等方式，间接影响用户的播放行为，从而影响数据的加载。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **`Initialize` 调用:**  提供一个指向网络视频文件的 URL。
2. **`Read` 调用:** 媒体播放器请求从位置 1024 开始读取 2048 字节的数据。
3. **预加载设置为 `AUTO`。**
4. **网络速度较快。**

**逻辑推理与输出:**

- **`Initialize`:**
    - `MultiBufferDataSource` 会创建 `MultiBufferReader`，并开始从 URL 下载数据。
    - 由于预加载设置为 `AUTO` 且网络速度较快，它可能会预先加载相对较多的数据到缓冲区。
    - 当有足够的数据可以开始播放时，会调用 `init_cb_` 回调，通知媒体播放器初始化完成。
- **`Read`:**
    - `MultiBufferDataSource` 会检查请求的数据是否已在缓冲区中。
    - 如果在缓冲区中，则直接从缓冲区读取并返回数据。
    - 如果不在缓冲区中，则 `MultiBufferReader` 会请求从网络加载相应的数据，加载完成后再返回给媒体播放器。
- **预加载的影响:**  如果用户在播放到接近缓冲区的末尾时，`MultiBufferDataSource` 会继续预加载后续的数据，以减少播放卡顿的可能性。

**涉及用户或编程常见的使用错误举例:**

1. **用户错误:**
   - **网络连接不稳定:**  如果用户的网络连接不稳定，导致数据下载中断或速度过慢，`MultiBufferDataSource` 可能会频繁地进入加载状态，导致播放卡顿。
   - **尝试播放不支持的媒体格式:**  如果 `MultiBufferDataSource` 底层的解码器不支持特定的媒体格式，播放会失败。

2. **编程错误:**
   - **不正确的 `preload` 设置:**  如果开发者将 `preload` 设置为 `none`，可能会导致播放开始时需要等待较长时间才能缓冲足够的数据。 反之，设置为过大的值可能会浪费带宽和内存。
   - **CORS 配置错误:**  如果服务器没有正确配置 CORS 头信息，当尝试播放跨域资源时，`MultiBufferDataSource` 会阻止加载，导致播放失败。
   - **过早地调用 `Stop()` 或 `Abort()`:**  如果在媒体播放器还没有完成初始化或正在进行关键数据加载时调用 `Stop()` 或 `Abort()`，可能会导致播放异常或资源泄漏。
   - **假设数据总是立即可用:**  开发者在编写媒体播放器代码时，不能假设 `Read` 调用会立即返回数据，需要处理异步加载的情况。

总而言之，`multi_buffer_data_source.cc` 是 Blink 引擎中一个复杂且关键的组件，负责高效、可靠地从网络或本地获取和管理媒体数据，以支持 HTML5 媒体元素的播放功能。 它涉及到网络请求、缓存管理、预加载策略、错误处理以及与媒体播放器的协同工作。

Prompt: 
```
这是目录为blink/renderer/platform/media/multi_buffer_data_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/media/multi_buffer_data_source.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/containers/adapters.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "media/base/media_log.h"
#include "net/base/net_errors.h"
#include "third_party/blink/renderer/platform/media/buffered_data_source_host_impl.h"
#include "third_party/blink/renderer/platform/media/multi_buffer_reader.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"

namespace blink {
namespace {

// Minimum preload buffer.
const int64_t kMinBufferPreload = 2 << 20;  // 2 Mb
// Maxmimum preload buffer.
const int64_t kMaxBufferPreload = 50 << 20;  // 50 Mb

// If preload_ == METADATA, preloading size will be
// shifted down this many bits. This shift turns
// one Mb into one 32k block.
// This seems to be the smallest amount of preload we can do without
// ending up repeatedly closing and re-opening the connection
// due to read calls after OnBufferingHaveEnough have been called.
const int64_t kMetadataShift = 6;

// Preload this much extra, then stop preloading until we fall below the
// preload_seconds_.value().
const int64_t kPreloadHighExtra = 1 << 20;  // 1 Mb

// Default pin region size.
// Note that we go over this if preload is calculated high enough.
const int64_t kDefaultPinSize = 25 << 20;  // 25 Mb

// If bitrate is not known, use this.
const int64_t kDefaultBitrate = 200 * 8 << 10;  // 200 Kbps.

// Maximum bitrate for buffer calculations.
const int64_t kMaxBitrate = 20 * 8 << 20;  // 20 Mbps.

// Maximum playback rate for buffer calculations.
const double kMaxPlaybackRate = 25.0;

// Extra buffer accumulation speed, in terms of download buffer.
const int kSlowPreloadPercentage = 10;

// Update buffer sizes every 32 progress updates.
const int kUpdateBufferSizeFrequency = 32;

// How long to we delay a seek after a read?
constexpr base::TimeDelta kSeekDelay = base::Milliseconds(20);

}  // namespace

class MultiBufferDataSource::ReadOperation {
 public:
  ReadOperation() = delete;
  ReadOperation(int64_t position,
                int size,
                uint8_t* data,
                media::DataSource::ReadCB callback);
  ReadOperation(const ReadOperation&) = delete;
  ReadOperation& operator=(const ReadOperation&) = delete;
  ~ReadOperation();

  // Runs |callback_| with the given |result|, deleting the operation
  // afterwards.
  static void Run(std::unique_ptr<ReadOperation> read_op, int result);

  int64_t position() { return position_; }
  int size() { return size_; }
  uint8_t* data() { return data_; }

 private:
  const int64_t position_;
  const int size_;
  raw_ptr<uint8_t, DanglingUntriaged> data_;
  media::DataSource::ReadCB callback_;
};

MultiBufferDataSource::ReadOperation::ReadOperation(
    int64_t position,
    int size,
    uint8_t* data,
    media::DataSource::ReadCB callback)
    : position_(position),
      size_(size),
      data_(data),
      callback_(std::move(callback)) {
  DCHECK(!callback_.is_null());
}

MultiBufferDataSource::ReadOperation::~ReadOperation() {
  DCHECK(callback_.is_null());
}

// static
void MultiBufferDataSource::ReadOperation::Run(
    std::unique_ptr<ReadOperation> read_op,
    int result) {
  std::move(read_op->callback_).Run(result);
}

MultiBufferDataSource::MultiBufferDataSource(
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner,
    scoped_refptr<UrlData> url_data_arg,
    media::MediaLog* media_log,
    BufferedDataSourceHost* host,
    DownloadingCB downloading_cb)
    : total_bytes_(kPositionNotSpecified),
      streaming_(false),
      loading_(false),
      failed_(false),
      render_task_runner_(task_runner),
      url_data_(std::move(url_data_arg)),
      stop_signal_received_(false),
      media_has_played_(false),
      single_origin_(true),
      cancel_on_defer_(false),
      preload_(AUTO),
      bitrate_(0),
      playback_rate_(0.0),
      media_log_(media_log->Clone()),
      host_(host),
      downloading_cb_(std::move(downloading_cb)) {
  weak_ptr_ = weak_factory_.GetWeakPtr();
  DCHECK(host_);
  DCHECK(downloading_cb_);
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  DCHECK(url_data_.get());
  url_data_->Use();
  url_data_->OnRedirect(
      base::BindOnce(&MultiBufferDataSource::OnRedirected, weak_ptr_));
}

MultiBufferDataSource::~MultiBufferDataSource() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
}

bool MultiBufferDataSource::media_has_played() const {
  return media_has_played_;
}

bool MultiBufferDataSource::AssumeFullyBuffered() const {
  DCHECK(url_data_);
  return !url_data_->url().ProtocolIsInHTTPFamily();
}

void MultiBufferDataSource::SetReader(
    std::unique_ptr<MultiBufferReader> reader) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  base::AutoLock auto_lock(lock_);
  reader_ = std::move(reader);
}

void MultiBufferDataSource::CreateResourceLoader(int64_t first_byte_position,
                                                 int64_t last_byte_position) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  SetReader(std::make_unique<MultiBufferReader>(
      url_data_->multibuffer(), first_byte_position, last_byte_position,
      is_client_audio_element_,
      base::BindRepeating(&MultiBufferDataSource::ProgressCallback, weak_ptr_),
      render_task_runner_));
  UpdateBufferSizes();
}

void MultiBufferDataSource::CreateResourceLoader_Locked(
    int64_t first_byte_position,
    int64_t last_byte_position) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  lock_.AssertAcquired();

  reader_ = std::make_unique<MultiBufferReader>(
      url_data_->multibuffer(), first_byte_position, last_byte_position,
      is_client_audio_element_,
      base::BindRepeating(&MultiBufferDataSource::ProgressCallback, weak_ptr_),
      render_task_runner_);
  UpdateBufferSizes();
}

void MultiBufferDataSource::Initialize(InitializeCB init_cb) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  DCHECK(init_cb);
  DCHECK(!reader_.get());

  init_cb_ = std::move(init_cb);

  CreateResourceLoader(0, kPositionNotSpecified);

  // We're not allowed to call Wait() if data is already available.
  if (reader_->Available()) {
    render_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MultiBufferDataSource::StartCallback, weak_ptr_));

    // When the entire file is already in the cache, we won't get any more
    // progress callbacks, which breaks some expectations. Post a task to
    // make sure that the client gets at least one call each for the progress
    // and loading callbacks.
    render_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&MultiBufferDataSource::UpdateProgress,
                                  weak_factory_.GetWeakPtr()));
  } else {
    reader_->Wait(
        1, base::BindOnce(&MultiBufferDataSource::StartCallback, weak_ptr_));
  }
}

void MultiBufferDataSource::OnRedirected(
    const scoped_refptr<UrlData>& new_destination) {
  if (!new_destination || !url_data_) {
    // A failure occurred.
    failed_ = true;
    if (init_cb_) {
      render_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&MultiBufferDataSource::StartCallback, weak_ptr_));
    } else {
      base::AutoLock auto_lock(lock_);
      StopInternal_Locked();
    }
    StopLoader();
    return;
  }
  if (!SecurityOrigin::AreSameOrigin(url_data_->url(),
                                     new_destination->url())) {
    single_origin_ = false;
  }
  SetReader(nullptr);
  url_data_ = std::move(new_destination);

  url_data_->OnRedirect(
      base::BindOnce(&MultiBufferDataSource::OnRedirected, weak_ptr_));

  if (init_cb_) {
    CreateResourceLoader(0, kPositionNotSpecified);
    if (reader_->Available()) {
      render_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&MultiBufferDataSource::StartCallback, weak_ptr_));
    } else {
      reader_->Wait(
          1, base::BindOnce(&MultiBufferDataSource::StartCallback, weak_ptr_));
    }
  } else if (read_op_) {
    CreateResourceLoader(read_op_->position(), kPositionNotSpecified);
    if (reader_->Available()) {
      render_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&MultiBufferDataSource::ReadTask, weak_ptr_));
    } else {
      reader_->Wait(
          1, base::BindOnce(&MultiBufferDataSource::ReadTask, weak_ptr_));
    }
  }

  // The "redirect" may just be `reader_` being merged into an existing UrlData,
  // in this case we need to ensure we report the buffered byte ranges from the
  // existing UrlData instance.
  UpdateProgress();

  if (redirect_cb_)
    redirect_cb_.Run();
}

void MultiBufferDataSource::SetPreload(media::DataSource::Preload preload) {
  DVLOG(1) << __func__ << "(" << preload << ")";
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  preload_ = preload;
  UpdateBufferSizes();
}

bool MultiBufferDataSource::HasSingleOrigin() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  // Before initialization completes there is no risk of leaking data. Callers
  // are required to order checks such that this isn't a race.
  return single_origin_;
}

bool MultiBufferDataSource::IsCorsCrossOrigin() const {
  return url_data_->is_cors_cross_origin();
}

void MultiBufferDataSource::OnRedirect(RedirectCB callback) {
  redirect_cb_ = std::move(callback);
}

bool MultiBufferDataSource::HasAccessControl() const {
  return url_data_->has_access_control();
}

bool MultiBufferDataSource::PassedTimingAllowOriginCheck() {
  return url_data_->passed_timing_allow_origin_check();
}

bool MultiBufferDataSource::WouldTaintOrigin() {
  // When the resource is redirected to another origin we think of it as
  // tainted. This is actually not specified, and is under discussion.
  // See https://github.com/whatwg/fetch/issues/737.
  if (!HasSingleOrigin() && cors_mode() == UrlData::CORS_UNSPECIFIED)
    return true;
  return IsCorsCrossOrigin();
}

UrlData::CorsMode MultiBufferDataSource::cors_mode() const {
  return url_data_->cors_mode();
}

void MultiBufferDataSource::OnMediaPlaybackRateChanged(double playback_rate) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  if (playback_rate < 0 || playback_rate == playback_rate_)
    return;

  playback_rate_ = playback_rate;
  cancel_on_defer_ = false;
  UpdateBufferSizes();
}

void MultiBufferDataSource::OnMediaIsPlaying() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  // Always clear this since it can be set by OnBufferingHaveEnough() calls at
  // any point in time.
  cancel_on_defer_ = false;

  if (media_has_played_)
    return;

  media_has_played_ = true;

  // Once we start playing, we need preloading.
  preload_ = AUTO;
  UpdateBufferSizes();
}

/////////////////////////////////////////////////////////////////////////////
// DataSource implementation.
void MultiBufferDataSource::Stop() {
  {
    base::AutoLock auto_lock(lock_);
    StopInternal_Locked();

    // Cleanup resources immediately if we're already on the right thread.
    if (render_task_runner_->BelongsToCurrentThread()) {
      reader_.reset();
      url_data_.reset();
      return;
    }
  }

  render_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&MultiBufferDataSource::StopLoader,
                                weak_factory_.GetWeakPtr()));
}

void MultiBufferDataSource::Abort() {
  base::AutoLock auto_lock(lock_);
  DCHECK(!init_cb_);
  if (read_op_)
    ReadOperation::Run(std::move(read_op_), kAborted);

  // Abort does not call StopLoader() since it is typically called prior to a
  // seek or suspend. Let the loader logic make the decision about whether a new
  // loader is necessary upon the seek or resume.
}

void MultiBufferDataSource::SetBitrate(int bitrate) {
  render_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&MultiBufferDataSource::SetBitrateTask,
                                weak_factory_.GetWeakPtr(), bitrate));
}

void MultiBufferDataSource::OnBufferingHaveEnough(bool always_cancel) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  if (reader_ && (always_cancel || (preload_ == METADATA &&
                                    !media_has_played_ && !IsStreaming()))) {
    cancel_on_defer_ = true;
    if (!loading_) {
      base::AutoLock auto_lock(lock_);
      if (read_op_) {
        // We can't destroy the reader if a read operation is pending.
        // UpdateLoadingState_Locked will take care of it after the
        // operation is done.
        return;
      }
      // Already locked, no need to use SetReader().
      reader_.reset(nullptr);
    }
  }
}

int64_t MultiBufferDataSource::GetMemoryUsage() {
  // TODO(hubbe): Make more accurate when url_data_ is shared.
  return base::checked_cast<int64_t>(url_data_->CachedSize())
         << url_data_->multibuffer()->block_size_shift();
}

GURL MultiBufferDataSource::GetUrlAfterRedirects() const {
  return GURL(url_data_->url());
}

void MultiBufferDataSource::Read(int64_t position,
                                 int size,
                                 uint8_t* data,
                                 media::DataSource::ReadCB read_cb) {
  DVLOG(1) << "Read: " << position << " offset, " << size << " bytes";
  // Reading is not allowed until after initialization.
  DCHECK(!init_cb_);
  DCHECK(read_cb);

  {
    base::AutoLock auto_lock(lock_);
    DCHECK(!read_op_);

    if (stop_signal_received_) {
      std::move(read_cb).Run(kReadError);
      return;
    }

    // Optimization: Try reading from the cache here to get back to
    // muxing as soon as possible. This works because TryReadAt is
    // thread-safe.
    if (reader_) {
      int64_t bytes_read = reader_->TryReadAt(position, data, size);
      if (bytes_read > 0) {
        bytes_read_ += bytes_read;
        seek_positions_.push_back(position + bytes_read);
        if (seek_positions_.size() == 1) {
          render_task_runner_->PostDelayedTask(
              FROM_HERE,
              base::BindOnce(&MultiBufferDataSource::SeekTask,
                             weak_factory_.GetWeakPtr()),
              kSeekDelay);
        }

        std::move(read_cb).Run(static_cast<int>(bytes_read));
        return;
      }
    }
    read_op_ = std::make_unique<ReadOperation>(position, size, data,
                                               std::move(read_cb));
  }

  render_task_runner_->PostTask(FROM_HERE,
                                base::BindOnce(&MultiBufferDataSource::ReadTask,
                                               weak_factory_.GetWeakPtr()));
}

bool MultiBufferDataSource::GetSize(int64_t* size_out) {
  base::AutoLock auto_lock(lock_);
  if (total_bytes_ != kPositionNotSpecified) {
    *size_out = total_bytes_;
    return true;
  }
  *size_out = 0;
  return false;
}

bool MultiBufferDataSource::IsStreaming() {
  return streaming_;
}

/////////////////////////////////////////////////////////////////////////////
// This method is the place where actual read happens,
void MultiBufferDataSource::ReadTask() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  base::AutoLock auto_lock(lock_);
  if (stop_signal_received_ || !read_op_)
    return;
  DCHECK(read_op_->size());

  if (!reader_)
    CreateResourceLoader_Locked(read_op_->position(), kPositionNotSpecified);

  int64_t available = reader_->AvailableAt(read_op_->position());
  if (available < 0) {
    // A failure has occured.
    ReadOperation::Run(std::move(read_op_), kReadError);
    return;
  }
  if (available) {
    int64_t bytes_read = std::min<int64_t>(available, read_op_->size());
    bytes_read =
        reader_->TryReadAt(read_op_->position(), read_op_->data(), bytes_read);

    bytes_read_ += bytes_read;
    seek_positions_.push_back(read_op_->position() + bytes_read);

    if (bytes_read == 0 && total_bytes_ == kPositionNotSpecified) {
      // We've reached the end of the file and we didn't know the total size
      // before. Update the total size so Read()s past the end of the file will
      // fail like they would if we had known the file size at the beginning.
      total_bytes_ = read_op_->position() + bytes_read;
      if (total_bytes_ != kPositionNotSpecified)
        host_->SetTotalBytes(total_bytes_);
    }

    ReadOperation::Run(std::move(read_op_), static_cast<int>(bytes_read));

    SeekTask_Locked();
  } else {
    reader_->Seek(read_op_->position());
    reader_->Wait(1, base::BindOnce(&MultiBufferDataSource::ReadTask,
                                    weak_factory_.GetWeakPtr()));
    UpdateLoadingState_Locked(false);
  }
}

void MultiBufferDataSource::SeekTask() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  base::AutoLock auto_lock(lock_);
  SeekTask_Locked();
}

void MultiBufferDataSource::SeekTask_Locked() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  lock_.AssertAcquired();

  if (stop_signal_received_)
    return;

  // A read operation is pending, which will call SeekTask_Locked when
  // it's done. We'll defer any seeking until the read op is done.
  if (read_op_)
    return;

  url_data_->AddBytesRead(bytes_read_);
  bytes_read_ = 0;

  if (reader_) {
    // If we're seeking to a new location, (not just slightly further
    // in the file) and we have more data buffered in that new location
    // than in our current location, then we don't actually seek anywhere.
    // Instead we keep preloading at the old location a while longer.

    int64_t pos = reader_->Tell();
    int64_t available = reader_->Available();

    // Iterate backwards, because if two positions have the same
    // amount of buffered data, we probably want to prefer the latest
    // one in the array.
    for (const auto& new_pos : base::Reversed(seek_positions_)) {
      int64_t available_at_new_pos = reader_->AvailableAt(new_pos);

      if (total_bytes_ != kPositionNotSpecified) {
        if (new_pos + available_at_new_pos >= total_bytes_) {
          // Buffer reaches end of file, no need to seek here.
          continue;
        }
      }
      if (available_at_new_pos < available) {
        pos = new_pos;
        available = available_at_new_pos;
      }
    }
    reader_->Seek(pos);
  }
  seek_positions_.clear();

  UpdateLoadingState_Locked(false);
}

void MultiBufferDataSource::StopInternal_Locked() {
  lock_.AssertAcquired();
  if (stop_signal_received_)
    return;

  stop_signal_received_ = true;

  // Initialize() isn't part of the DataSource interface so don't call it in
  // response to Stop().
  init_cb_.Reset();

  if (read_op_)
    ReadOperation::Run(std::move(read_op_), kReadError);
}

void MultiBufferDataSource::StopLoader() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  SetReader(nullptr);
}

void MultiBufferDataSource::SetBitrateTask(int bitrate) {
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  bitrate_ = bitrate;
  UpdateBufferSizes();
}

/////////////////////////////////////////////////////////////////////////////
// BufferedResourceLoader callback methods.
void MultiBufferDataSource::StartCallback() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  // TODO(scherkus): we shouldn't have to lock to signal host(), see
  // http://crbug.com/113712 for details.
  base::AutoLock auto_lock(lock_);
  if (stop_signal_received_) {
    return;
  }

  if (!init_cb_) {
    // Can't call SetReader(nullptr) since we are holding the lock.
    reader_.reset(nullptr);
    return;
  }

  // All responses must be successful. Resources that are assumed to be fully
  // buffered must have a known content length.
  bool success =
      reader_ && reader_->Available() > 0 && url_data_ &&
      (!AssumeFullyBuffered() || url_data_->length() != kPositionNotSpecified);

  if (success) {
    total_bytes_ = url_data_->length();
    streaming_ =
        !AssumeFullyBuffered() && (total_bytes_ == kPositionNotSpecified ||
                                   !url_data_->range_supported());

    media_log_->SetProperty<media::MediaLogProperty::kTotalBytes>(total_bytes_);
    media_log_->SetProperty<media::MediaLogProperty::kIsStreaming>(streaming_);
  } else {
    // Can't call SetReader(nullptr) since we are holding the lock.
    reader_.reset(nullptr);
  }

  if (success) {
    if (total_bytes_ != kPositionNotSpecified) {
      host_->SetTotalBytes(total_bytes_);
      if (AssumeFullyBuffered())
        host_->AddBufferedByteRange(0, total_bytes_);
    }

    // Progress callback might be called after the start callback,
    // make sure that we update single_origin_ now.
    media_log_->SetProperty<media::MediaLogProperty::kIsSingleOrigin>(
        single_origin_);
    media_log_->SetProperty<media::MediaLogProperty::kIsRangeHeaderSupported>(
        url_data_->range_supported());
  }

  render_task_runner_->PostTask(FROM_HERE,
                                base::BindOnce(std::move(init_cb_), success));

  UpdateBufferSizes();

  // Even if data is cached, say that we're loading at this point for
  // compatibility.
  UpdateLoadingState_Locked(true);
}

void MultiBufferDataSource::ProgressCallback(int64_t begin, int64_t end) {
  DVLOG(1) << __func__ << "(" << begin << ", " << end << ")";
  DCHECK(render_task_runner_->BelongsToCurrentThread());

  base::AutoLock auto_lock(lock_);
  if (stop_signal_received_)
    return;

  if (AssumeFullyBuffered())
    return;

  if (end > begin)
    host_->AddBufferedByteRange(begin, end);

  if (buffer_size_update_counter_ > 0)
    buffer_size_update_counter_--;
  else
    UpdateBufferSizes();

  UpdateLoadingState_Locked(false);
}

void MultiBufferDataSource::UpdateLoadingState_Locked(bool force_loading) {
  DVLOG(1) << __func__;
  lock_.AssertAcquired();
  if (AssumeFullyBuffered())
    return;
  // Update loading state.
  bool is_loading = !!reader_ && reader_->IsLoading();
  if (force_loading || is_loading != loading_) {
    bool loading = is_loading || force_loading;

    if (!loading && cancel_on_defer_) {
      if (read_op_) {
        // We can't destroy the reader if a read operation is pending.
        // UpdateLoadingState_Locked will be called again when the read
        // operation is done.
        return;
      }
      // Already locked, no need to use SetReader().
      reader_.reset(nullptr);
    }

    loading_ = loading;
    downloading_cb_.Run(loading_);
  }
}

void MultiBufferDataSource::UpdateProgress() {
  DCHECK(render_task_runner_->BelongsToCurrentThread());
  if (reader_) {
    uint64_t available = reader_->Available();
    uint64_t pos = reader_->Tell();
    ProgressCallback(pos, pos + available);
  }
}

void MultiBufferDataSource::UpdateBufferSizes() {
  DVLOG(1) << __func__;
  if (!reader_)
    return;

  buffer_size_update_counter_ = kUpdateBufferSizeFrequency;

  // Use a default bit rate if unknown and clamp to prevent overflow.
  int64_t bitrate = std::clamp<int64_t>(bitrate_, 0, kMaxBitrate);
  if (bitrate == 0)
    bitrate = kDefaultBitrate;

  // Only scale the buffer window for playback rates greater than 1.0 in
  // magnitude and clamp to prevent overflow.
  double playback_rate = playback_rate_;

  playback_rate = std::max(playback_rate, 1.0);
  playback_rate = std::min(playback_rate, kMaxPlaybackRate);

  int64_t bytes_per_second = (bitrate / 8.0) * playback_rate;

  // Preload 10 seconds of data, clamped to some min/max value.
  int64_t preload = std::clamp(preload_seconds_.value() * bytes_per_second,
                               kMinBufferPreload, kMaxBufferPreload);

  // Increase buffering slowly at a rate of 10% of data downloaded so
  // far, maxing out at the preload size.
  int64_t extra_buffer = std::min(
      preload, url_data_->BytesReadFromCache() * kSlowPreloadPercentage / 100);

  // Add extra buffer to preload.
  preload += extra_buffer;

  // We preload this much, then we stop unil we read |preload| before resuming.
  int64_t preload_high = preload + kPreloadHighExtra;

  // We pin a few seconds of data behind the current reading position.
  int64_t pin_backward =
      std::clamp(keep_after_playback_seconds_.value() * bytes_per_second,
                 kMinBufferPreload, kMaxBufferPreload);

  // We always pin at least kDefaultPinSize ahead of the read position.
  // Normally, the extra space between preload_high and kDefaultPinSize will
  // not actually have any data in it, but if it does, we don't want to throw it
  // away right before we need it.
  int64_t pin_forward = std::max(preload_high, kDefaultPinSize);

  // Note that the buffer size is advisory as only non-pinned data is allowed
  // to be thrown away. Most of the time we pin a region that is larger than
  // |buffer_size|, which only makes sense because most of the time, some of
  // the data in pinned region is not present in the cache.
  int64_t buffer_size = std::min(
      (preload_seconds_.value() + keep_after_playback_seconds_.value()) *
              bytes_per_second +
          extra_buffer * 3,
      preload_high + pin_backward + extra_buffer);

  if (url_data_->FullyCached() ||
      (url_data_->length() != kPositionNotSpecified &&
       url_data_->length() < kDefaultPinSize)) {
    // We just make pin_forwards/backwards big enough to encompass the
    // whole file regardless of where we are, with some extra margins.
    pin_forward = std::max(pin_forward, url_data_->length() * 2);
    pin_backward = std::max(pin_backward, url_data_->length() * 2);
    buffer_size = url_data_->length();
  }

  reader_->SetMaxBuffer(buffer_size);
  reader_->SetPinRange(pin_backward, pin_forward);

  if (preload_ == METADATA) {
    preload_high >>= kMetadataShift;
    preload >>= kMetadataShift;
  }
  reader_->SetPreload(preload_high, preload);
}

}  // namespace blink

"""

```
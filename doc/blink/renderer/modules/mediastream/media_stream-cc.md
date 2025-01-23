Response:
Let's break down the thought process for analyzing the `media_stream.cc` file.

**1. Initial Understanding - What is this file about?**

The filename `media_stream.cc` and the directory `blink/renderer/modules/mediastream` immediately suggest this file is a core part of the WebRTC implementation within the Blink rendering engine. The "media stream" part points to handling audio and video data flows on the web. The comments at the top confirm this is related to the `MediaStream` API.

**2. Deconstructing the Code - Identifying Key Functionalities:**

I'd then start reading through the code, paying attention to:

* **Class Definition:** The central class is `MediaStream`. This is the main entity we need to understand.
* **Creation Methods:**  Look for `Create` methods. These tell us how `MediaStream` objects are instantiated and with what kinds of initial data (e.g., `ExecutionContext`, existing streams, track vectors, descriptors). The variety of `Create` methods hints at the flexibility of this class.
* **Data Members:** What data does the `MediaStream` class hold?  Key members I'd identify early are `audio_tracks_`, `video_tracks_`, and `descriptor_`. These are fundamental to the purpose of the class. The `scheduled_event_timer_` and `scheduled_events_` also stand out as important for asynchronous operations.
* **Methods Related to Tracks:**  Methods like `addTrack`, `removeTrack`, `getTracks`, `getTrackById` clearly manage the collection of `MediaStreamTrack` objects within the stream.
* **Lifecycle Methods:**  Methods like `TrackEnded`, `StreamEnded` suggest the class handles the state changes of the media stream.
* **Event Handling:** The presence of `ScheduleDispatchEvent`, `ScheduledEventTimerFired`, and the interaction with `EventTarget` indicate the class emits events to notify other parts of the system about changes.
* **Observer Pattern:** The `RegisterObserver` and `UnregisterObserver` methods suggest a way for other objects to be notified of changes in the `MediaStream`.
* **Relationship to Descriptors:** The `MediaStreamDescriptor` appears to be a crucial associated object, responsible for describing the stream's characteristics.

**3. Connecting to Web Standards (JavaScript, HTML, CSS):**

At this point, I'd start thinking about how these C++ concepts relate to web development:

* **JavaScript API:**  The `MediaStream` class in C++ directly corresponds to the `MediaStream` interface in JavaScript. The methods in C++ (like `addTrack`, `removeTrack`, `getTracks`) have direct counterparts in the JavaScript API.
* **HTML `<video>` and `<audio>` elements:**  `MediaStream` objects are often used as the source for these elements, allowing the browser to render the media. The connection here is that the C++ code manages the underlying data that the HTML elements display.
* **`getUserMedia()`:** This JavaScript API is the primary way to obtain a `MediaStream` from the user's camera and microphone. The C++ code would be involved in handling the results of `getUserMedia()`.
* **Events:** The events dispatched by the `MediaStream` in C++ (like `addtrack`, `removetrack`, `active`, `inactive`) are the same events that JavaScript developers can listen for on a `MediaStream` object.

**4. Logical Reasoning and Assumptions:**

Here's where I'd start making inferences:

* **Input/Output of Methods:**  For functions like `addTrack`, I'd assume the input is a `MediaStreamTrack` object, and the output is either void (with potential side effects) or a boolean indicating success/failure. For `getTracks`, the input is implicit (the `MediaStream` object itself), and the output is a vector of `MediaStreamTrack` objects.
* **State Management:** I'd infer that the `active()` state is likely tied to whether the stream has active (not ended) tracks.
* **Asynchronous Operations:** The timer suggests that certain operations, particularly event dispatching, might be asynchronous to avoid blocking the main thread.

**5. Identifying Common Usage Errors:**

Thinking from a developer's perspective, I'd consider common mistakes:

* **Adding the same track twice:** The code explicitly checks for this (`getTrackById`).
* **Adding a track of the wrong type:** While the C++ code checks the `kind()`, a JavaScript developer might mistakenly try to add an audio track to a video-only stream (although the JavaScript API is more forgiving here).
* **Removing a non-existent track:** The C++ code handles this gracefully.
* **Incorrectly handling events:** Developers might forget to listen for `active` or `inactive` events to manage the lifecycle of the stream.

**6. Tracing User Operations (Debugging Clues):**

To understand how a user's actions lead to this code, I'd think about common WebRTC scenarios:

* **`getUserMedia()`:** This is a primary entry point. Granting camera/microphone permission will trigger the creation of a `MediaStream` object in C++.
* **Manipulating tracks:**  JavaScript code calling `addTrack()` or `removeTrack()` on a `MediaStream` object will directly call the corresponding C++ methods.
* **Setting the `srcObject` of a video element:** Assigning a `MediaStream` to a `<video>` element's `srcObject` property will involve this C++ code managing the flow of data to the video renderer.
* **Peer-to-peer communication:** In WebRTC, `MediaStream` objects are sent between peers. The C++ code would be involved in encoding and decoding the media data.

**7. Iterative Refinement:**

My initial understanding might be incomplete. As I delve deeper into the code and documentation (if available), I'd refine my understanding. For instance, realizing the role of `MediaStreamDescriptor` in detail or understanding the exact purpose of the `TransferredMediaStreamTrack`.

By following these steps, I can systematically analyze the C++ source code and explain its functionality in relation to web technologies, common usage, and debugging scenarios. The key is to connect the low-level C++ implementation to the high-level JavaScript APIs and user interactions that developers work with.
这个C++源代码文件 `media_stream.cc` 是 Chromium Blink 渲染引擎中 `MediaStream` 接口的核心实现。`MediaStream` 是 WebRTC API 的关键部分，用于表示媒体流，通常包含音频和/或视频轨道。

以下是 `media_stream.cc` 的主要功能：

**1. `MediaStream` 对象的创建和管理:**

* **多种创建方式:** 提供了多种静态 `Create` 方法，用于以不同的方式创建 `MediaStream` 对象：
    * 空的 `MediaStream`。
    * 基于现有的 `MediaStream` 克隆。
    * 基于 `MediaStreamTrack` 对象的列表。
    * 基于 `MediaStreamDescriptor` 对象（描述媒体流的元数据）。
    * 在跨进程传递 `MediaStreamTrack` 时创建。
* **内部构造:**  `MediaStream` 类的构造函数负责初始化内部状态，例如：
    * 存储音频和视频轨道 (`audio_tracks_`, `video_tracks_`)。
    * 关联一个 `MediaStreamDescriptor` 对象 (`descriptor_`)，用于描述媒体流的属性。
    * 设置事件调度定时器 (`scheduled_event_timer_`)，用于异步发送事件。
* **生命周期管理:**  跟踪 `MediaStream` 的活动状态，并在轨道添加、移除或结束时更新状态。

**2. 管理 `MediaStreamTrack` 对象:**

* **添加轨道 (`addTrack`):**  允许向 `MediaStream` 添加音频或视频轨道。
    * 检查轨道是否已存在。
    * 将轨道添加到相应的轨道列表中 (`audio_tracks_` 或 `video_tracks_`)。
    * 注册 `MediaStream` 作为轨道的观察者。
    * 更新 `MediaStreamDescriptor`。
    * 如果 `MediaStream` 从非活动状态变为活动状态，则触发 `active` 事件。
* **移除轨道 (`removeTrack`):** 允许从 `MediaStream` 移除音频或视频轨道。
    * 查找并移除相应的轨道。
    * 取消注册 `MediaStream` 作为轨道的观察者。
    * 更新 `MediaStreamDescriptor`。
    * 如果 `MediaStream` 从活动状态变为非活动状态，则触发 `inactive` 事件。
* **获取轨道 (`getTracks`, `getTrackById`):**  提供方法获取所有轨道或根据 ID 获取特定轨道。

**3. 处理 `MediaStream` 的活动状态:**

* **`active()`:** 返回 `MediaStream` 是否处于活动状态（至少有一个未结束的轨道）。
* **`StreamEnded()`:** 当所有轨道都结束时调用，将 `MediaStream` 标记为非活动，并触发 `inactive` 事件。

**4. 事件处理:**

* **事件调度:** 使用 `ScheduleDispatchEvent` 方法将事件添加到队列中，并使用定时器异步发送。
* **支持的事件:**
    * `addtrack`: 当向 `MediaStream` 添加轨道时触发。
    * `removetrack`: 当从 `MediaStream` 移除轨道时触发。
    * `active`: 当 `MediaStream` 变为活动状态时触发。
    * `inactive`: 当 `MediaStream` 变为非活动状态时触发。

**5. 与其他 Blink 组件的交互:**

* **`ExecutionContext`:** 用于获取任务执行器，例如用于事件调度。
* **`MediaStreamTrackImpl`:** 表示单个媒体轨道，`MediaStream` 包含多个 `MediaStreamTrackImpl` 对象。
* **`MediaStreamDescriptor`:** 用于描述 `MediaStream` 的属性，例如包含的音频和视频组件。
* **`MediaStreamObserver`:** 允许其他对象观察 `MediaStream` 的状态变化（例如，添加或移除轨道）。

**与 JavaScript, HTML, CSS 的关系：**

`media_stream.cc` 的功能直接映射到 WebRTC JavaScript API 中的 `MediaStream` 接口。

* **JavaScript:**
    * **创建 `MediaStream` 对象:** JavaScript 代码可以使用 `new MediaStream()` 构造函数或通过 `getUserMedia()` 等 API 获取 `MediaStream` 对象。 这些操作最终会调用 `media_stream.cc` 中的 `Create` 方法。
    * **添加/移除轨道:** JavaScript 的 `addTrack()` 和 `removeTrack()` 方法对应于 `media_stream.cc` 中的 `addTrack()` 和 `removeTrack()` 方法。
    * **获取轨道:** JavaScript 的 `getTracks()` 和 `getTrackById()` 方法对应于 `media_stream.cc` 中的 `getTracks()` 和 `getTrackById()` 方法。
    * **监听事件:** JavaScript 代码可以监听 `addtrack`, `removetrack`, `active`, `inactive` 等事件。这些事件是由 `media_stream.cc` 中的事件调度机制触发的。

    ```javascript
    // JavaScript 示例
    navigator.mediaDevices.getUserMedia({ audio: true, video: true })
      .then(function(stream) {
        console.log('Got a MediaStream:', stream);

        // 添加一个新的音频轨道到 stream
        let audioTrack = ...; // 获取一个 MediaStreamTrack
        stream.addTrack(audioTrack);

        // 监听 addtrack 事件
        stream.addEventListener('addtrack', function(event) {
          console.log('Track added:', event.track);
        });
      });
    ```

* **HTML:**
    * **`<video>` 和 `<audio>` 元素:**  可以将 `MediaStream` 对象设置为 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，从而将媒体流渲染到 HTML 页面上。`media_stream.cc` 负责管理这个媒体流的数据。

    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>MediaStream Example</title>
    </head>
    <body>
      <video id="myVideo" autoplay></video>
      <script>
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(function(stream) {
            const videoElement = document.getElementById('myVideo');
            videoElement.srcObject = stream; // 将 MediaStream 赋值给 video 元素
          });
      </script>
    </body>
    </html>
    ```

* **CSS:** CSS 可以用于样式化包含媒体流的 `<video>` 和 `<audio>` 元素，但与 `media_stream.cc` 的核心功能没有直接的逻辑关系。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码执行以下操作：

**假设输入:**

1. 调用 `navigator.mediaDevices.getUserMedia({ audio: true })` 并成功获取一个包含音频轨道的 `MediaStream` 对象 `stream1`。
2. 创建一个新的空 `MediaStream` 对象 `stream2`。
3. 调用 `stream2.addTrack(stream1.getAudioTracks()[0])`。

**逻辑推理过程:**

*   当 `getUserMedia` 成功时，Blink 引擎会在内部创建一个 `MediaStream` 对象（由 `media_stream.cc` 管理），并包含一个 `MediaStreamTrack` 对象。
*   `stream2.addTrack()` 的调用会映射到 `media_stream.cc` 的 `addTrack()` 方法。
*   `addTrack()` 方法会检查要添加的轨道是否已经存在于 `stream2` 中（在本例中不存在）。
*   `addTrack()` 方法会将 `stream1` 的音频轨道添加到 `stream2` 的 `audio_tracks_` 列表中。
*   如果 `stream2` 最初是空的，并且添加的轨道未结束，`addTrack()` 可能会触发 `active` 事件。

**预期输出:**

*   `stream2` 现在包含一个与 `stream1` 相同的音频轨道。
*   如果 `stream2` 从非活动状态变为活动状态，会触发 `active` 事件。

**用户或编程常见的使用错误:**

1. **尝试添加同一个轨道两次:**  如果 JavaScript 代码尝试向同一个 `MediaStream` 对象添加已经存在的轨道，`media_stream.cc` 的 `addTrack()` 方法会检查并忽略该操作，不会重复添加。

    ```javascript
    // 错误示例
    navigator.mediaDevices.getUserMedia({ audio: true })
      .then(function(stream) {
        let audioTrack = stream.getAudioTracks()[0];
        stream.addTrack(audioTrack); // 第一次添加
        stream.addTrack(audioTrack); // 第二次尝试添加，会被忽略
      });
    ```

2. **在轨道结束后尝试添加:** 如果尝试添加一个已经结束 (`ended` 状态为 true) 的 `MediaStreamTrack`，虽然技术上可以添加，但这个轨道不会产生任何媒体流，并且可能不会导致 `MediaStream` 变为活动状态。

3. **类型错误:**  尽管 `MediaStream` 可以同时包含音频和视频轨道，但错误地尝试将视频轨道添加到一个只处理音频的上下文中，或者反之，可能会导致逻辑错误或意外行为。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页，该网页包含使用 WebRTC 的 JavaScript 代码。**
2. **JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 或 `new MediaStream()`。** 这会导致 Blink 引擎创建 `MediaStream` 对象，并调用 `media_stream.cc` 中的 `Create` 方法。
3. **如果用户允许访问其摄像头和/或麦克风，`getUserMedia()` 会成功返回一个包含音视频轨道的 `MediaStream` 对象。**  这些轨道对应的 `MediaStreamTrack` 对象也会被创建和关联。
4. **JavaScript 代码可能进一步操作 `MediaStream` 对象，例如：**
    *   使用 `addTrack()` 或 `removeTrack()` 添加或移除轨道。这些操作会调用 `media_stream.cc` 中相应的方法。
    *   将 `MediaStream` 对象赋值给 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，以便在页面上显示媒体。这会触发 Blink 引擎处理媒体流的渲染。
    *   在 WebRTC P2P 连接中，将 `MediaStream` 对象添加到 `RTCPeerConnection`，以便将其发送到远程 peer。
5. **当轨道结束时（例如，用户停止共享摄像头），会调用 `media_stream.cc` 中的 `TrackEnded()` 方法。** 如果所有轨道都结束，会调用 `StreamEnded()`，并将 `MediaStream` 标记为非活动状态，并触发 `inactive` 事件。

**调试线索:**

*   **检查 JavaScript 代码中 `MediaStream` 对象的创建和操作。**
*   **使用 Chrome 开发者工具的 "Media" 选项卡可以查看当前活动的 `MediaStream` 对象及其轨道的状态。**
*   **在 `media_stream.cc` 中添加日志输出或断点，以跟踪 `MediaStream` 对象的创建、轨道添加/移除、状态变化和事件触发过程。**  例如，可以打印 `audio_tracks_.size()` 和 `video_tracks_.size()` 的变化，以及 `active()` 的返回值。
*   **检查 `MediaStreamDescriptor` 对象的内容，以了解媒体流的配置。**
*   **查看是否有相关的错误或警告信息输出到控制台。**

总而言之，`media_stream.cc` 是 Chromium Blink 引擎中 `MediaStream` API 的核心实现，负责管理媒体流的生命周期、包含的轨道以及相关的事件，是 WebRTC 功能的基础组成部分。理解其功能有助于理解 WebRTC 在浏览器中的工作原理，并为调试相关的 Web 应用提供线索。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
 * Copyright (C) 2011, 2012 Ericsson AB. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream.h"

#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_event.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_track_impl.h"
#include "third_party/blink/renderer/modules/mediastream/transferred_media_stream_track.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"

namespace blink {

static bool ContainsTrack(MediaStreamTrackVector& track_vector,
                          MediaStreamTrack* media_stream_track) {
  for (MediaStreamTrack* track : track_vector) {
    if (media_stream_track->id() == track->id())
      return true;
  }
  return false;
}

static void ProcessTrack(MediaStreamTrack* track,
                         MediaStreamTrackVector& track_vector) {
  if (!ContainsTrack(track_vector, track))
    track_vector.push_back(track);
}

MediaStream* MediaStream::Create(ExecutionContext* context) {
  MediaStreamTrackVector audio_tracks;
  MediaStreamTrackVector video_tracks;

  DCHECK(context);
  return MakeGarbageCollected<MediaStream>(context, audio_tracks, video_tracks);
}

MediaStream* MediaStream::Create(ExecutionContext* context,
                                 MediaStream* stream) {
  DCHECK(context);
  DCHECK(stream);

  MediaStreamTrackVector audio_tracks;
  MediaStreamTrackVector video_tracks;

  for (MediaStreamTrack* track : stream->audio_tracks_)
    ProcessTrack(track, audio_tracks);

  for (MediaStreamTrack* track : stream->video_tracks_)
    ProcessTrack(track, video_tracks);

  return MakeGarbageCollected<MediaStream>(context, audio_tracks, video_tracks);
}

MediaStream* MediaStream::Create(ExecutionContext* context,
                                 const MediaStreamTrackVector& tracks) {
  MediaStreamTrackVector audio_tracks;
  MediaStreamTrackVector video_tracks;

  DCHECK(context);
  for (MediaStreamTrack* track : tracks) {
    ProcessTrack(track, track->kind() == "audio" ? audio_tracks : video_tracks);
  }

  return MakeGarbageCollected<MediaStream>(context, audio_tracks, video_tracks);
}

MediaStream* MediaStream::Create(ExecutionContext* context,
                                 MediaStreamDescriptor* stream_descriptor) {
  return MakeGarbageCollected<MediaStream>(context, stream_descriptor, nullptr,
                                           /*callback=*/base::DoNothing());
}

void MediaStream::Create(ExecutionContext* context,
                         MediaStreamDescriptor* stream_descriptor,
                         TransferredMediaStreamTrack* track,
                         base::OnceCallback<void(MediaStream*)> callback) {
  DCHECK(track == nullptr ||
         stream_descriptor->NumberOfAudioComponents() +
                 stream_descriptor->NumberOfVideoComponents() ==
             1);

  MakeGarbageCollected<MediaStream>(context, stream_descriptor, track,
                                    std::move(callback));
}

MediaStream* MediaStream::Create(ExecutionContext* context,
                                 MediaStreamDescriptor* stream_descriptor,
                                 const MediaStreamTrackVector& audio_tracks,
                                 const MediaStreamTrackVector& video_tracks) {
  return MakeGarbageCollected<MediaStream>(context, stream_descriptor,
                                           audio_tracks, video_tracks);
}

MediaStream::MediaStream(ExecutionContext* context,
                         MediaStreamDescriptor* stream_descriptor,
                         TransferredMediaStreamTrack* transferred_track,
                         base::OnceCallback<void(MediaStream*)> callback)
    : ExecutionContextClient(context),
      ActiveScriptWrappable<MediaStream>({}),
      descriptor_(stream_descriptor),
      media_stream_initialized_callback_(std::move(callback)),
      scheduled_event_timer_(
          context->GetTaskRunner(TaskType::kMediaElementEvent),
          this,
          &MediaStream::ScheduledEventTimerFired) {
  descriptor_->SetClient(this);

  uint32_t number_of_audio_tracks = descriptor_->NumberOfAudioComponents();
  audio_tracks_.reserve(number_of_audio_tracks);
  for (uint32_t i = 0; i < number_of_audio_tracks; i++) {
    auto* new_track = MakeGarbageCollected<MediaStreamTrackImpl>(
        context, descriptor_->AudioComponent(i));
    new_track->RegisterMediaStream(this);
    audio_tracks_.push_back(new_track);
    if (transferred_track) {
      DCHECK(!transferred_track->HasImplementation());
      transferred_track->SetImplementation(new_track);
    }
  }

  uint32_t number_of_video_tracks = descriptor_->NumberOfVideoComponents();
  video_tracks_.reserve(number_of_video_tracks);
  for (uint32_t i = 0; i < number_of_video_tracks; i++) {
    MediaStreamTrack* const new_track = MediaStreamTrackImpl::Create(
        context, descriptor_->VideoComponent(i),
        WTF::BindOnce(&MediaStream::OnMediaStreamTrackInitialized,
                      WrapPersistent(this)));
    new_track->RegisterMediaStream(this);
    video_tracks_.push_back(new_track);
    if (transferred_track) {
      DCHECK(!transferred_track->HasImplementation());
      transferred_track->SetImplementation(new_track);
    }
  }

  if (EmptyOrOnlyEndedTracks()) {
    descriptor_->SetActive(false);
  }

  if (number_of_video_tracks == 0) {
    context->GetTaskRunner(TaskType::kInternalMedia)
        ->PostTask(FROM_HERE,
                   WTF::BindOnce(std::move(media_stream_initialized_callback_),
                                 WrapPersistent(this)));
  }
}

void MediaStream::OnMediaStreamTrackInitialized() {
  if (++number_of_video_tracks_initialized_ ==
      descriptor_->NumberOfVideoComponents()) {
    std::move(media_stream_initialized_callback_).Run(this);
  }
}

MediaStream::MediaStream(ExecutionContext* context,
                         MediaStreamDescriptor* stream_descriptor,
                         const MediaStreamTrackVector& audio_tracks,
                         const MediaStreamTrackVector& video_tracks)
    : ExecutionContextClient(context),
      ActiveScriptWrappable<MediaStream>({}),
      descriptor_(stream_descriptor),
      scheduled_event_timer_(
          context->GetTaskRunner(TaskType::kMediaElementEvent),
          this,
          &MediaStream::ScheduledEventTimerFired) {
  descriptor_->SetClient(this);

  audio_tracks_.reserve(audio_tracks.size());
  for (MediaStreamTrack* audio_track : audio_tracks) {
    DCHECK_EQ("audio", audio_track->kind());
    audio_track->RegisterMediaStream(this);
    audio_tracks_.push_back(audio_track);
  }
  video_tracks_.reserve(video_tracks.size());
  for (MediaStreamTrack* video_track : video_tracks) {
    DCHECK_EQ("video", video_track->kind());
    video_track->RegisterMediaStream(this);
    video_tracks_.push_back(video_track);
  }
  DCHECK(TracksMatchDescriptor());

  if (EmptyOrOnlyEndedTracks()) {
    descriptor_->SetActive(false);
  }
}

MediaStream::MediaStream(ExecutionContext* context,
                         const MediaStreamTrackVector& audio_tracks,
                         const MediaStreamTrackVector& video_tracks)
    : ExecutionContextClient(context),
      ActiveScriptWrappable<MediaStream>({}),
      scheduled_event_timer_(
          context->GetTaskRunner(TaskType::kMediaElementEvent),
          this,
          &MediaStream::ScheduledEventTimerFired) {
  MediaStreamComponentVector audio_components;
  MediaStreamComponentVector video_components;

  MediaStreamTrackVector::const_iterator iter;
  for (iter = audio_tracks.begin(); iter != audio_tracks.end(); ++iter) {
    (*iter)->RegisterMediaStream(this);
    audio_components.push_back((*iter)->Component());
  }
  for (iter = video_tracks.begin(); iter != video_tracks.end(); ++iter) {
    (*iter)->RegisterMediaStream(this);
    video_components.push_back((*iter)->Component());
  }

  descriptor_ = MakeGarbageCollected<MediaStreamDescriptor>(audio_components,
                                                            video_components);
  descriptor_->SetClient(this);

  audio_tracks_ = audio_tracks;
  video_tracks_ = video_tracks;
  if (EmptyOrOnlyEndedTracks()) {
    descriptor_->SetActive(false);
  }
}

MediaStream::~MediaStream() = default;

bool MediaStream::HasPendingActivity() const {
  return !scheduled_events_.empty();
}

bool MediaStream::EmptyOrOnlyEndedTracks() {
  if (!audio_tracks_.size() && !video_tracks_.size()) {
    return true;
  }
  for (MediaStreamTrackVector::iterator iter = audio_tracks_.begin();
       iter != audio_tracks_.end(); ++iter) {
    if (!iter->Get()->Ended())
      return false;
  }
  for (MediaStreamTrackVector::iterator iter = video_tracks_.begin();
       iter != video_tracks_.end(); ++iter) {
    if (!iter->Get()->Ended())
      return false;
  }
  return true;
}

bool MediaStream::TracksMatchDescriptor() {
  if (audio_tracks_.size() != descriptor_->NumberOfAudioComponents())
    return false;
  for (wtf_size_t i = 0; i < audio_tracks_.size(); i++) {
    if (audio_tracks_[i]->Component() != descriptor_->AudioComponent(i))
      return false;
  }
  if (video_tracks_.size() != descriptor_->NumberOfVideoComponents())
    return false;
  for (wtf_size_t i = 0; i < video_tracks_.size(); i++) {
    if (video_tracks_[i]->Component() != descriptor_->VideoComponent(i))
      return false;
  }
  return true;
}

MediaStreamTrackVector MediaStream::getTracks() {
  MediaStreamTrackVector tracks;
  for (MediaStreamTrackVector::iterator iter = audio_tracks_.begin();
       iter != audio_tracks_.end(); ++iter)
    tracks.push_back(iter->Get());
  for (MediaStreamTrackVector::iterator iter = video_tracks_.begin();
       iter != video_tracks_.end(); ++iter)
    tracks.push_back(iter->Get());
  return tracks;
}

void MediaStream::addTrack(MediaStreamTrack* track,
                           ExceptionState& exception_state) {
  if (!track) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTypeMismatchError,
        "The MediaStreamTrack provided is invalid.");
    return;
  }

  if (getTrackById(track->id()))
    return;

  switch (track->Component()->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      audio_tracks_.push_back(track);
      break;
    case MediaStreamSource::kTypeVideo:
      video_tracks_.push_back(track);
      break;
  }
  track->RegisterMediaStream(this);
  descriptor_->AddComponent(track->Component());

  if (!active() && !track->Ended()) {
    descriptor_->SetActive(true);
    ScheduleDispatchEvent(Event::Create(event_type_names::kActive));
  }

  for (auto& observer : observers_) {
    // If processing by the observer failed, it is most likely because it was
    // not necessary and it became a no-op. The exception can be suppressed,
    // there is nothing to do.
    observer->OnStreamAddTrack(this, track, IGNORE_EXCEPTION);
  }
}

void MediaStream::removeTrack(MediaStreamTrack* track,
                              ExceptionState& exception_state) {
  if (!track) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kTypeMismatchError,
        "The MediaStreamTrack provided is invalid.");
    return;
  }

  wtf_size_t pos = kNotFound;
  switch (track->Component()->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      pos = audio_tracks_.Find(track);
      if (pos != kNotFound)
        audio_tracks_.EraseAt(pos);
      break;
    case MediaStreamSource::kTypeVideo:
      pos = video_tracks_.Find(track);
      if (pos != kNotFound)
        video_tracks_.EraseAt(pos);
      break;
  }

  if (pos == kNotFound)
    return;
  track->UnregisterMediaStream(this);
  descriptor_->RemoveComponent(track->Component());

  if (active() && EmptyOrOnlyEndedTracks()) {
    descriptor_->SetActive(false);
    ScheduleDispatchEvent(Event::Create(event_type_names::kInactive));
  }

  for (auto& observer : observers_) {
    // If processing by the observer failed, it is most likely because it was
    // not necessary and it became a no-op. The exception can be suppressed,
    // there is nothing to do.
    observer->OnStreamRemoveTrack(this, track, IGNORE_EXCEPTION);
  }
}

MediaStreamTrack* MediaStream::getTrackById(String id) {
  for (MediaStreamTrackVector::iterator iter = audio_tracks_.begin();
       iter != audio_tracks_.end(); ++iter) {
    if ((*iter)->id() == id)
      return iter->Get();
  }

  for (MediaStreamTrackVector::iterator iter = video_tracks_.begin();
       iter != video_tracks_.end(); ++iter) {
    if ((*iter)->id() == id)
      return iter->Get();
  }

  return nullptr;
}

MediaStream* MediaStream::clone(ScriptState* script_state) {
  MediaStreamTrackVector tracks;
  ExecutionContext* context = ExecutionContext::From(script_state);
  for (MediaStreamTrackVector::iterator iter = audio_tracks_.begin();
       iter != audio_tracks_.end(); ++iter)
    tracks.push_back((*iter)->clone(ExecutionContext::From(script_state)));
  for (MediaStreamTrackVector::iterator iter = video_tracks_.begin();
       iter != video_tracks_.end(); ++iter)
    tracks.push_back((*iter)->clone(ExecutionContext::From(script_state)));
  return MediaStream::Create(context, tracks);
}

void MediaStream::TrackEnded() {
  for (MediaStreamTrackVector::iterator iter = audio_tracks_.begin();
       iter != audio_tracks_.end(); ++iter) {
    if (!(*iter)->Ended())
      return;
  }

  for (MediaStreamTrackVector::iterator iter = video_tracks_.begin();
       iter != video_tracks_.end(); ++iter) {
    if (!(*iter)->Ended())
      return;
  }

  StreamEnded();
}

void MediaStream::RegisterObserver(MediaStreamObserver* observer) {
  DCHECK(observer);
  observers_.insert(observer);
}

void MediaStream::UnregisterObserver(MediaStreamObserver* observer) {
  observers_.erase(observer);
}

void MediaStream::StreamEnded() {
  if (!GetExecutionContext())
    return;

  if (active()) {
    descriptor_->SetActive(false);
    ScheduleDispatchEvent(Event::Create(event_type_names::kInactive));
  }
}

bool MediaStream::AddEventListenerInternal(
    const AtomicString& event_type,
    EventListener* listener,
    const AddEventListenerOptionsResolved* options) {
  if (event_type == event_type_names::kActive) {
    UseCounter::Count(GetExecutionContext(), WebFeature::kMediaStreamOnActive);
  } else if (event_type == event_type_names::kInactive) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kMediaStreamOnInactive);
  }

  return EventTarget::AddEventListenerInternal(event_type, listener, options);
}

const AtomicString& MediaStream::InterfaceName() const {
  return event_target_names::kMediaStream;
}

void MediaStream::AddTrackByComponentAndFireEvents(
    MediaStreamComponent* component,
    DispatchEventTiming event_timing) {
  DCHECK(component);
  if (!GetExecutionContext())
    return;
  auto* track = MakeGarbageCollected<MediaStreamTrackImpl>(
      GetExecutionContext(), component);
  AddTrackAndFireEvents(track, event_timing);
}

void MediaStream::RemoveTrackByComponentAndFireEvents(
    MediaStreamComponent* component,
    DispatchEventTiming event_timing) {
  DCHECK(component);
  if (!GetExecutionContext())
    return;

  MediaStreamTrackVector* tracks = nullptr;
  switch (component->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      tracks = &audio_tracks_;
      break;
    case MediaStreamSource::kTypeVideo:
      tracks = &video_tracks_;
      break;
  }

  wtf_size_t index = kNotFound;
  for (wtf_size_t i = 0; i < tracks->size(); ++i) {
    if ((*tracks)[i]->Component() == component) {
      index = i;
      break;
    }
  }
  if (index == kNotFound)
    return;

  descriptor_->RemoveComponent(component);

  MediaStreamTrack* track = (*tracks)[index];
  track->UnregisterMediaStream(this);
  tracks->EraseAt(index);

  bool became_inactive = false;
  if (active() && EmptyOrOnlyEndedTracks()) {
    descriptor_->SetActive(false);
    became_inactive = true;
  }

  // Fire events synchronously or asynchronously.
  if (event_timing == DispatchEventTiming::kImmediately) {
    DispatchEvent(*MakeGarbageCollected<MediaStreamTrackEvent>(
        event_type_names::kRemovetrack, track));
    if (became_inactive)
      DispatchEvent(*Event::Create(event_type_names::kInactive));
  } else {
    ScheduleDispatchEvent(MakeGarbageCollected<MediaStreamTrackEvent>(
        event_type_names::kRemovetrack, track));
    if (became_inactive)
      ScheduleDispatchEvent(Event::Create(event_type_names::kInactive));
  }
}

void MediaStream::AddTrackAndFireEvents(MediaStreamTrack* track,
                                        DispatchEventTiming event_timing) {
  DCHECK(track);
  switch (track->Component()->GetSourceType()) {
    case MediaStreamSource::kTypeAudio:
      audio_tracks_.push_back(track);
      break;
    case MediaStreamSource::kTypeVideo:
      video_tracks_.push_back(track);
      break;
  }
  track->RegisterMediaStream(this);
  descriptor_->AddComponent(track->Component());

  bool became_active = false;
  if (!active() && !track->Ended()) {
    descriptor_->SetActive(true);
    became_active = true;
  }

  // Fire events synchronously or asynchronously.
  if (event_timing == DispatchEventTiming::kImmediately) {
    DispatchEvent(*MakeGarbageCollected<MediaStreamTrackEvent>(
        event_type_names::kAddtrack, track));
    if (became_active)
      DispatchEvent(*Event::Create(event_type_names::kActive));
  } else {
    ScheduleDispatchEvent(MakeGarbageCollected<MediaStreamTrackEvent>(
        event_type_names::kAddtrack, track));
    if (became_active)
      ScheduleDispatchEvent(Event::Create(event_type_names::kActive));
  }
}

void MediaStream::RemoveTrackAndFireEvents(MediaStreamTrack* track,
                                           DispatchEventTiming event_timing) {
  DCHECK(track);
  RemoveTrackByComponentAndFireEvents(track->Component(), event_timing);
}

void MediaStream::ScheduleDispatchEvent(Event* event) {
  scheduled_events_.push_back(event);

  if (!scheduled_event_timer_.IsActive())
    scheduled_event_timer_.StartOneShot(base::TimeDelta(), FROM_HERE);
}

void MediaStream::ScheduledEventTimerFired(TimerBase*) {
  if (!GetExecutionContext())
    return;

  HeapVector<Member<Event>> events;
  events.swap(scheduled_events_);

  HeapVector<Member<Event>>::iterator it = events.begin();
  for (; it != events.end(); ++it)
    DispatchEvent(*it->Release());

  events.clear();
}

void MediaStream::Trace(Visitor* visitor) const {
  visitor->Trace(audio_tracks_);
  visitor->Trace(video_tracks_);
  visitor->Trace(descriptor_);
  visitor->Trace(observers_);
  visitor->Trace(scheduled_event_timer_);
  visitor->Trace(scheduled_events_);
  EventTarget::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
  MediaStreamDescriptorClient::Trace(visitor);
}

MediaStream* ToMediaStream(MediaStreamDescriptor* descriptor) {
  return static_cast<MediaStream*>(descriptor->Client());
}

}  // namespace blink
```
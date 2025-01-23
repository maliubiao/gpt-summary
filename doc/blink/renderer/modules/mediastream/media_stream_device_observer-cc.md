Response:
Let's break down the thought process for analyzing the `media_stream_device_observer.cc` file and generating the comprehensive explanation.

**1. Initial Understanding & Goal:**

The first step is to understand the *purpose* of the file. The name itself, "MediaStreamDeviceObserver," strongly suggests it's responsible for watching and reacting to changes in media devices (like cameras and microphones). The directory `blink/renderer/modules/mediastream/` confirms this context within the Chromium rendering engine. The request specifically asks for functionalities, relationships with web technologies, logic, potential errors, and debugging clues. This sets the stage for a multi-faceted analysis.

**2. Core Functionality Identification (Scanning the Code):**

The next step involves reading through the code, identifying key classes, methods, and data structures. Looking for keywords like "On...", "Add...", "Remove...", "Get...", and data structures like `label_stream_map_` are crucial.

*   **`MediaStreamDeviceObserver` Class:** This is the main class, the core of our analysis. It's responsible for managing and observing media devices.
*   **`label_stream_map_`:**  This `HashMap` is a central data structure, mapping labels (likely associated with `getUserMedia` calls or similar) to a collection of `Stream` objects. This immediately suggests the file is tracking devices related to specific media streams.
*   **`Stream` Struct:**  This nested structure holds lists of audio and video devices, along with callbacks for various device events. This highlights the event-driven nature of the observer.
*   **`OnDeviceStopped`, `OnDeviceChanged`, `OnDeviceRequestStateChange`, etc.:** These methods clearly indicate the observer's role in reacting to device-related events. The `DVLOG` statements confirm these are handlers for platform-level notifications.
*   **`AddStreams`, `AddStream`, `RemoveStreams`, `RemoveStreamDevice`:** These methods indicate how devices are added and removed from the observer's tracking.
*   **`GetNonScreenCaptureDevices`, `GetAudioSessionId`, `GetVideoSessionId`:** These provide ways to retrieve information about the tracked devices.

**3. Relating to Web Technologies (HTML, CSS, JavaScript):**

Now, the task is to connect the internal workings to the external web technologies.

*   **JavaScript and `getUserMedia()`:** This is the primary entry point for accessing media devices in the browser. The "label" concept strongly ties to the MediaStream object returned by `getUserMedia()`. When a user grants permission, the browser provides access to the requested devices, and this observer likely plays a role in managing those devices.
*   **HTML `<video>` and `<audio>` elements:** These elements are where the media streams are ultimately rendered. While this file doesn't directly manipulate these elements, it manages the underlying device information that feeds into them.
*   **CSS (Indirectly):** CSS can style the `<video>` and `<audio>` elements. While this file doesn't directly interact with CSS, the availability and state of media devices (managed by this observer) influence what can be displayed and how it can be styled.

**4. Logic and Reasoning (Input/Output Examples):**

To understand the logic, creating simple scenarios is helpful.

*   **Scenario: Device Unplugged:**  If a camera is being used in a web page and is unplugged, the `OnDeviceStopped` method will be triggered. The input is the device information and the associated stream label. The output is the removal of that device from the internal data structures and potentially triggering a JavaScript callback.
*   **Scenario: Device Changed (e.g., switching camera):**  The `OnDeviceChanged` method handles this. The input is the old and new device information. The output is updating the internal device lists and potentially triggering a JavaScript callback.

**5. Common User/Programming Errors:**

Consider how developers might misuse the APIs or encounter issues related to device management.

*   **Race conditions:** The comments within the code hint at potential race conditions when a device is stopped both from JavaScript and at the system level simultaneously. This leads to the example of calling `stop()` in JS while the device is unplugged.
*   **Incorrect device IDs:**  If a developer tries to access a device with an invalid ID, this observer would not find it in its tracked list.

**6. Debugging Clues and User Steps:**

To provide debugging context, trace the user's actions that lead to this code.

*   **`getUserMedia()` Call:**  The starting point is a website using `navigator.mediaDevices.getUserMedia()`.
*   **Permission Grant:** The user grants permission for the website to access their camera/microphone.
*   **Device Enumeration/Selection:** The browser enumerates available devices, and the user might select a specific one.
*   **Device Events:** Actions like plugging/unplugging devices, changing camera settings, or stopping media tracks trigger events that reach this observer.

**7. Code Snippets and Examples:**

Providing small, concrete examples of JavaScript interacting with media devices makes the explanation more tangible. Showing how `getUserMedia()` and `MediaStreamTrack.stop()` relate is essential.

**8. Structure and Clarity:**

Finally, organize the information logically. Use headings, bullet points, and clear language. Start with the overall function, then delve into specifics, and finally connect it back to the user experience and debugging. The initial thought process might be a bit scattered, but the final output needs to be well-structured.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on the C++ implementation details. The request emphasizes the connection to web technologies, so I need to balance the technical explanation with practical examples.
*   I need to pay attention to the comments in the code, as they often provide valuable insights into potential issues and edge cases (like the race condition example).
*   Ensuring the input/output examples are clear and directly related to the explained functionality is crucial.
*   The debugging section should guide someone trying to understand *how* they ended up in this part of the Chromium code, linking user actions to internal events.

By following these steps, iteratively refining the analysis, and focusing on the different aspects requested in the prompt, a comprehensive and helpful explanation can be generated.
好的，让我们来分析一下 `blink/renderer/modules/mediastream/media_stream_device_observer.cc` 这个文件。

**功能概述:**

`MediaStreamDeviceObserver` 的主要功能是 **观察和管理与特定网页的 `MediaStream` 相关的媒体设备（例如摄像头、麦克风）的状态变化**。 它可以跟踪设备的添加、移除、变更、请求状态变化、捕获配置变化、捕获句柄变化以及缩放级别变化。

更具体地说，它做了以下几件事：

1. **跟踪媒体设备与 `MediaStream` 的关联:**  当网页通过 `getUserMedia` 或 `getDisplayMedia` 获取媒体流时，`MediaStreamDeviceObserver` 会记录这些流所使用的音频和视频设备。它使用一个 `label_stream_map_` 的哈希表来存储这些信息，其中键是 `MediaStream` 的标签 (label)，值是一个包含该流所有相关设备的 `Stream` 对象向量。
2. **监听设备状态变化:** 它实现了 `mojom::blink::MediaStreamDeviceObserver` 接口，接收来自 Chromium 媒体栈的通知，例如设备被停止、设备被替换、设备请求状态改变（例如静音/取消静音）、设备捕获配置改变（例如分辨率、帧率）、设备捕获句柄改变（主要用于屏幕共享）以及设备缩放级别改变。
3. **通知 JavaScript 层:** 当观察到设备状态变化时，它会调用事先注册的回调函数（通过 `WebMediaStreamDeviceObserver::StreamCallbacks` 传递），从而通知 JavaScript 层。这些回调函数允许网页响应这些变化，例如禁用/启用 UI 元素，或者更新显示信息。
4. **提供设备信息查询:** 它提供了 `GetNonScreenCaptureDevices` 方法，可以获取当前网页正在使用的非屏幕捕获设备列表。
5. **管理设备会话 ID:** 它提供了 `GetAudioSessionId` 和 `GetVideoSessionId` 方法，用于获取与特定 `MediaStream` 相关的音频和视频设备的会话 ID。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`MediaStreamDeviceObserver` 是 Blink 渲染引擎的一部分，负责处理底层的媒体设备管理逻辑。它与 JavaScript, HTML, CSS 的关系主要体现在以下几个方面：

*   **JavaScript (`getUserMedia`, `getDisplayMedia`, `MediaStreamTrack`):**
    *   **`getUserMedia` 和 `getDisplayMedia`:** 当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 或 `navigator.mediaDevices.getDisplayMedia()` 请求访问用户的摄像头、麦克风或屏幕时，Chromium 会创建相应的 `MediaStream` 对象。`MediaStreamDeviceObserver` 会跟踪这些 `MediaStream` 对象所使用的设备。
    *   **`MediaStreamTrack`:** `MediaStream` 对象包含 `MediaStreamTrack` 对象，代表音频或视频轨道。当一个 `MediaStreamTrack` 因为底层设备被移除或停止而停止时，`MediaStreamDeviceObserver::OnDeviceStopped` 会被调用，并通过回调通知 JavaScript 层。
    *   **事件处理:** JavaScript 可以监听 `MediaStreamTrack` 上的 `ended` 事件，这通常是因为设备被移除或停止。`MediaStreamDeviceObserver` 的作用是确保这些事件能够被正确触发。

    **举例:**

    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true, audio: true })
      .then(function(stream) {
        const videoTracks = stream.getVideoTracks();
        const audioTracks = stream.getAudioTracks();

        videoTracks.forEach(track => {
          track.onended = function() {
            console.log('Video track ended because the device was stopped.');
          };
        });

        audioTracks.forEach(track => {
          track.onended = function() {
            console.log('Audio track ended because the device was stopped.');
          };
        });

        // ... 将流显示在 <video> 元素中
      })
      .catch(function(err) {
        console.error('Error accessing media devices:', err);
      });
    ```

    在这个例子中，当用户拔出摄像头或麦克风时，`MediaStreamDeviceObserver` 会检测到设备停止，并最终导致 `MediaStreamTrack` 的 `ended` 事件被触发。

*   **HTML (`<video>`, `<audio>`):**
    *   `MediaStream` 对象通常会被赋值给 HTML 的 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，以显示或播放媒体流。`MediaStreamDeviceObserver` 确保了当底层设备发生变化时，这些元素能够反映最新的状态（例如，如果摄像头被移除，视频流会停止）。

    **举例:**

    ```html
    <video id="myVideo" autoplay playsinline></video>
    <script>
      navigator.mediaDevices.getUserMedia({ video: true })
        .then(function(stream) {
          document.getElementById('myVideo').srcObject = stream;
        });
    </script>
    ```

    如果用户在使用这个网页时拔掉了摄像头，`MediaStreamDeviceObserver` 会通知到 JavaScript 层，虽然这个例子没有显式处理，但通常浏览器会停止播放视频，或者触发 `ended` 事件。

*   **CSS (间接关系):**
    *   CSS 可以用来控制 `<video>` 和 `<audio>` 元素的样式。虽然 `MediaStreamDeviceObserver` 不直接与 CSS 交互，但设备状态的变化（例如设备停止）可能会导致 JavaScript 修改 HTML 结构或 CSS 类，从而改变元素的显示方式。

    **举例:**

    ```html
    <video id="myVideo" class="active" autoplay playsinline></video>
    <script>
      const videoElement = document.getElementById('myVideo');
      navigator.mediaDevices.getUserMedia({ video: true })
        .then(function(stream) {
          videoElement.srcObject = stream;
          stream.getVideoTracks()[0].onended = function() {
            videoElement.classList.remove('active');
            videoElement.classList.add('inactive');
          };
        });
    </script>
    <style>
      .active { /* 摄像头正常工作时的样式 */ }
      .inactive { /* 摄像头停止时的样式 */ }
    </style>
    ```

    在这个例子中，当摄像头停止时，JavaScript 代码会移除 `active` 类并添加 `inactive` 类，从而改变视频元素的显示样式。

**逻辑推理 (假设输入与输出):**

假设用户在一个正在使用摄像头的网页上执行以下操作：

**假设输入:**

1. 网页通过 `getUserMedia({ video: true })` 获取了一个 `MediaStream`，其 label 为 "stream-1"，使用了摄像头设备 "camera-1"。
2. `label_stream_map_` 中存储了 {"stream-1": [{audio_devices: [], video_devices: ["camera-1"], ...}]}
3. 用户突然拔掉了摄像头 "camera-1"。

**逻辑推理过程:**

1. 操作系统或 Chromium 媒体栈检测到摄像头设备 "camera-1" 被移除。
2. Chromium 媒体栈会通知 Blink 渲染进程的 `MediaStreamDeviceObserver`，调用其 `OnDeviceStopped("stream-1", camera-1_device_object)`.
3. `OnDeviceStopped` 方法会查找 `label_stream_map_` 中 label 为 "stream-1" 的条目。
4. 它会遍历该条目下的所有 `Stream` 对象，并在其 `video_devices` 列表中找到并移除 "camera-1"。
5. 如果该 `Stream` 对象注册了 `on_device_stopped_cb` 回调函数，则会执行该回调，将 `camera-1_device_object` 作为参数传递。
6. `OnDeviceStopped` 还会检查该 `Stream` 对象是否还有其他设备（音频或视频）。如果所有设备都被移除，则该 `Stream` 对象可能会从 `label_stream_map_` 中移除。

**预期输出:**

1. `label_stream_map_` 中 "stream-1" 对应的 `Stream` 对象的 `video_devices` 列表将不再包含 "camera-1"。
2. 如果 JavaScript 层为该 `MediaStream` 注册了设备停止的回调函数，该函数将被调用，并接收到关于 "camera-1" 被停止的信息。
3. 最终，与 "stream-1" 关联的 `MediaStreamTrack` 的 `onended` 事件会被触发，通知 JavaScript 层该视频轨道已结束。

**用户或编程常见的使用错误及举例说明:**

1. **未处理设备移除事件:** 开发者可能没有正确监听 `MediaStreamTrack` 的 `ended` 事件，或者没有实现相应的错误处理逻辑。当设备突然被移除时，网页可能会出现异常或停止响应。

    **举例:** 网页一直期望摄像头数据存在，没有处理 `ended` 事件，导致在摄像头被拔出后尝试访问不存在的数据而报错。

2. **假设设备 ID 不变:** 开发者可能会错误地缓存设备 ID，并在之后尝试使用该 ID。然而，设备 ID 可能会发生变化（例如，在系统重启后）。

    **举例:**  网页保存了用户上次使用的摄像头 ID，下次加载时直接使用该 ID 请求 `getUserMedia`，但如果该 ID 对应的设备已不存在或 ID 已变更，则会导致请求失败。

3. **并发操作导致竞态条件:**  在 JavaScript 中停止一个 `MediaStreamTrack` 的同时，底层设备可能也在被移除。`MediaStreamDeviceObserver` 的代码中已经考虑到了这种情况，并进行了处理，但开发者也需要注意避免此类并发操作导致的潜在问题。

    **举例:**  用户点击了 "停止摄像头" 按钮，JavaScript 代码调用 `track.stop()`，几乎同时，用户拔掉了摄像头。如果没有适当的同步和状态管理，可能会导致一些意外的行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

要理解用户操作如何一步步触发 `MediaStreamDeviceObserver` 的相关逻辑，可以考虑以下调试线索：

1. **用户打开一个需要访问摄像头或麦克风的网页。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 或 `navigator.mediaDevices.getDisplayMedia()`。** 这会导致浏览器向用户请求权限。
3. **用户授予了摄像头或麦克风的访问权限。**
4. **Chromium 创建 `MediaStream` 对象，并将其与特定的媒体设备关联。** `MediaStreamDeviceObserver` 会在 `AddStreams` 或 `AddStream` 方法中记录这些关联。
5. **用户正常使用网页，摄像头或麦克风数据被用于网页的功能。**
6. **以下用户操作可能会触发 `MediaStreamDeviceObserver` 的事件处理方法:**
    *   **拔出摄像头或麦克风:**  触发 `OnDeviceStopped`。
    *   **更换摄像头或麦克风 (如果系统支持热插拔):** 触发 `OnDeviceChanged`。
    *   **在系统设置中禁用或启用摄像头/麦克风:** 可能会触发 `OnDeviceRequestStateChange`。
    *   **对于屏幕共享，切换共享的窗口或屏幕:** 可能会触发 `OnDeviceCaptureHandleChange`。
    *   **调整摄像头的缩放级别 (如果 API 支持):** 触发 `OnZoomLevelChange`。
    *   **网页 JavaScript 代码调用 `track.stop()` 手动停止某个轨道:** 这最终也会导致 `OnDeviceStopped` 被调用。
7. **`MediaStreamDeviceObserver` 接收到来自 Chromium 媒体栈的设备状态变化通知。**
8. **`MediaStreamDeviceObserver` 调用相应的事件处理方法，更新内部状态，并执行注册的回调函数，通知 JavaScript 层。**
9. **JavaScript 层根据接收到的通知，更新 UI 或执行其他操作 (例如，禁用相关的按钮，显示错误信息)。**
10. **如果涉及到错误或异常，开发者可以通过查看浏览器控制台的日志、断点调试 JavaScript 代码，以及查看 Chromium 的内部日志 (chrome://webrtc-internals) 来追踪问题。**  `DVLOG` 语句的存在表明开发者可以使用详细日志级别来查看 `MediaStreamDeviceObserver` 的运行情况。

总而言之，`MediaStreamDeviceObserver` 是 Blink 渲染引擎中一个关键的组件，它充当了媒体设备状态变化和 JavaScript 层之间的桥梁，确保网页能够及时响应设备状态的变化，提供稳定可靠的媒体体验。理解其功能和工作原理对于开发和调试 WebRTC 相关的应用至关重要。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_device_observer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_device_observer.h"

#include <stddef.h>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/user_media_processor.h"

namespace blink {

namespace {

bool RemoveStreamDeviceFromArray(const MediaStreamDevice& device,
                                 MediaStreamDevices* devices) {
  for (auto device_it = devices->begin(); device_it != devices->end();
       ++device_it) {
    if (device_it->IsSameDevice(device)) {
      devices->erase(device_it);
      return true;
    }
  }
  return false;
}

}  // namespace

MediaStreamDeviceObserver::MediaStreamDeviceObserver(LocalFrame* frame) {
  // There is no frame on unit tests.
  if (frame) {
    frame->GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
        &MediaStreamDeviceObserver::BindMediaStreamDeviceObserverReceiver,
        weak_factory_.GetWeakPtr()));
  }
}

MediaStreamDeviceObserver::~MediaStreamDeviceObserver() = default;

MediaStreamDevices MediaStreamDeviceObserver::GetNonScreenCaptureDevices() {
  MediaStreamDevices video_devices;
  for (const auto& stream_it : label_stream_map_) {
    for (const auto& stream : stream_it.value) {
      for (const auto& video_device : stream.video_devices) {
        if (!IsScreenCaptureMediaType(video_device.type))
          video_devices.push_back(video_device);
      }
    }
  }
  return video_devices;
}

void MediaStreamDeviceObserver::OnDeviceStopped(
    const String& label,
    const MediaStreamDevice& device) {
  DVLOG(1) << __func__ << " label=" << label << " device_id=" << device.id;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    // This can happen if a user stops a device from JS at the same
    // time as the underlying media device is unplugged from the system.
    return;
  }

  for (Stream& stream : it->value) {
    if (IsAudioInputMediaType(device.type)) {
      RemoveStreamDeviceFromArray(device, &stream.audio_devices);
    } else {
      RemoveStreamDeviceFromArray(device, &stream.video_devices);
    }
    if (stream.on_device_stopped_cb) {
      // Running `stream.on_device_stopped_cb` can destroy `this`. Use a weak
      // pointer to detect that condition, and stop processing if it happens.
      base::WeakPtr<MediaStreamDeviceObserver> weak_this =
          weak_factory_.GetWeakPtr();
      stream.on_device_stopped_cb.Run(device);
      if (!weak_this) {
        return;
      }
    }
  }

  // |it| could have already been invalidated in the function call above. So we
  // need to check if |label| is still in |label_stream_map_| again.
  // Note: this is a quick fix to the crash caused by erasing the invalidated
  // iterator from |label_stream_map_| (https://crbug.com/616884). Future work
  // needs to be done to resolve this re-entrancy issue.
  it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    return;
  }

  Vector<Stream>& streams = it->value;
  auto stream_it = streams.begin();
  while (stream_it != it->value.end()) {
    Stream& stream = *stream_it;
    if (stream.audio_devices.empty() && stream.video_devices.empty()) {
      stream_it = it->value.erase(stream_it);
    } else {
      ++stream_it;
    }
  }

  if (it->value.empty())
    label_stream_map_.erase(it);
}

void MediaStreamDeviceObserver::OnDeviceChanged(
    const String& label,
    const MediaStreamDevice& old_device,
    const MediaStreamDevice& new_device) {
  DVLOG(1) << __func__ << " old_device_id=" << old_device.id
           << " new_device_id=" << new_device.id;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    // This can happen if a user stops a device from JS at the same
    // time as the underlying media device is unplugged from the system.
    return;
  }
  // OnDeviceChanged cannot only happen in combination with getAllScreensMedia,
  // which is the only API that handles multiple streams at once.
  DCHECK_EQ(1u, it->value.size());

  Stream* stream = &it->value[0];
  if (stream->on_device_changed_cb) {
    // Running `stream->on_device_changed_cb` can destroy `this`. Use a weak
    // pointer to detect that condition, and stop processing if it happens.
    base::WeakPtr<MediaStreamDeviceObserver> weak_this =
        weak_factory_.GetWeakPtr();
    stream->on_device_changed_cb.Run(old_device, new_device);
    if (!weak_this) {
      return;
    }
  }

  // Update device list only for device changing. Removing device will be
  // handled in its own callback.
  if (old_device.type != mojom::MediaStreamType::NO_SERVICE &&
      new_device.type != mojom::MediaStreamType::NO_SERVICE) {
    if (RemoveStreamDeviceFromArray(old_device, &stream->audio_devices) ||
        RemoveStreamDeviceFromArray(old_device, &stream->video_devices)) {
      if (IsAudioInputMediaType(new_device.type))
        stream->audio_devices.push_back(new_device);
      else
        stream->video_devices.push_back(new_device);
    }
  }
}

void MediaStreamDeviceObserver::OnDeviceRequestStateChange(
    const String& label,
    const MediaStreamDevice& device,
    const mojom::blink::MediaStreamStateChange new_state) {
  DVLOG(1) << __func__ << " label=" << label << " device_id=" << device.id;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    // This can happen if a user stops a device from JS at the same
    // time as the underlying media device is unplugged from the system.
    return;
  }

  for (Stream& stream : it->value) {
    if (stream.ContainsDevice(device) &&
        stream.on_device_request_state_change_cb) {
      stream.on_device_request_state_change_cb.Run(device, new_state);
      break;
    }
  }
}

void MediaStreamDeviceObserver::OnDeviceCaptureConfigurationChange(
    const String& label,
    const MediaStreamDevice& device) {
  DVLOG(1) << __func__ << " label=" << label << " device_id=" << device.id;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    // This can happen if a user stops a device from JS at the same
    // time as the underlying media device is unplugged from the system.
    return;
  }

  for (Stream& stream : it->value) {
    if (stream.ContainsDevice(device) &&
        stream.on_device_capture_configuration_change_cb) {
      stream.on_device_capture_configuration_change_cb.Run(device);
      break;
    }
  }
}

void MediaStreamDeviceObserver::OnDeviceCaptureHandleChange(
    const String& label,
    const MediaStreamDevice& device) {
  DVLOG(1) << __func__ << " label=" << label << " device_id=" << device.id;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    // This can happen if a user stops a device from JS at the same
    // time as the underlying media device is unplugged from the system.
    return;
  }
  // OnDeviceCaptureHandleChange cannot only happen in combination with
  // getAllScreensMedia, which is the only API that handles multiple streams
  // at once.
  DCHECK_EQ(1u, it->value.size());

  Stream* stream = &it->value[0];
  if (stream->on_device_capture_handle_change_cb) {
    stream->on_device_capture_handle_change_cb.Run(device);
  }
}

void MediaStreamDeviceObserver::OnZoomLevelChange(
    const String& label,
    const MediaStreamDevice& device,
    int zoom_level) {
  DVLOG(1) << __func__ << " label=" << label << " device_id=" << device.id;
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK_GT(zoom_level, 0);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end()) {
    return;
  }

  Vector<Stream>& streams = it->value;
  if (streams.size() != 1u) {
    return;
  }

  Stream* stream = &streams[0];
  if (!stream) {
    return;
  }

  if (stream->on_zoom_level_change_cb) {
    stream->on_zoom_level_change_cb.Run(device, zoom_level);
  }
#endif
}

void MediaStreamDeviceObserver::BindMediaStreamDeviceObserverReceiver(
    mojo::PendingReceiver<mojom::blink::MediaStreamDeviceObserver> receiver) {
  receiver_.reset();
  receiver_.Bind(std::move(receiver));
}

void MediaStreamDeviceObserver::AddStreams(
    const String& label,
    const mojom::blink::StreamDevicesSet& stream_devices_set,
    const WebMediaStreamDeviceObserver::StreamCallbacks& stream_callbacks) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  Vector<Stream> streams;
  for (const mojom::blink::StreamDevicesPtr& stream_devices_ptr :
       stream_devices_set.stream_devices) {
    const mojom::blink::StreamDevices& stream_devices = *stream_devices_ptr;
    Stream stream;
    stream.on_device_stopped_cb = stream_callbacks.on_device_stopped_cb;
    stream.on_device_changed_cb = stream_callbacks.on_device_changed_cb;
    stream.on_device_request_state_change_cb =
        stream_callbacks.on_device_request_state_change_cb;
    stream.on_device_capture_configuration_change_cb =
        stream_callbacks.on_device_capture_configuration_change_cb;
    stream.on_device_capture_handle_change_cb =
        stream_callbacks.on_device_capture_handle_change_cb;
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
    stream.on_zoom_level_change_cb = stream_callbacks.on_zoom_level_change_cb;
#endif
    if (stream_devices.audio_device.has_value()) {
      stream.audio_devices.push_back(stream_devices.audio_device.value());
    }
    if (stream_devices.video_device.has_value()) {
      stream.video_devices.push_back(stream_devices.video_device.value());
    }
    streams.emplace_back(std::move(stream));
  }
  label_stream_map_.Set(label, streams);
}

void MediaStreamDeviceObserver::AddStream(const String& label,
                                          const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  Stream stream;
  if (IsAudioInputMediaType(device.type)) {
    stream.audio_devices.push_back(device);
  } else if (IsVideoInputMediaType(device.type)) {
    stream.video_devices.push_back(device);
  } else {
    NOTREACHED();
  }

  label_stream_map_.Set(label, Vector<Stream>{std::move(stream)});
}

bool MediaStreamDeviceObserver::RemoveStreams(const String& label) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end())
    return false;

  label_stream_map_.erase(it);
  return true;
}

void MediaStreamDeviceObserver::RemoveStreamDevice(
    const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Remove |device| from all streams in |label_stream_map_|.
  bool device_found = false;
  Vector<String> streams_to_remove;
  for (auto& entry : label_stream_map_) {
    for (auto stream_it = entry.value.begin();
         stream_it != entry.value.end();) {
      Stream& stream = *stream_it;
      MediaStreamDevices& audio_devices = stream.audio_devices;
      MediaStreamDevices& video_devices = stream.video_devices;
      if (RemoveStreamDeviceFromArray(device, &audio_devices) ||
          RemoveStreamDeviceFromArray(device, &video_devices)) {
        device_found = true;
      }
      if (audio_devices.empty() && video_devices.empty()) {
        stream_it = entry.value.erase(stream_it);
      } else {
        ++stream_it;
      }
    }

    if (device_found && entry.value.size() == 0) {
      streams_to_remove.push_back(entry.key);
    }
  }
  for (const String& label : streams_to_remove) {
    label_stream_map_.erase(label);
  }
}

base::UnguessableToken MediaStreamDeviceObserver::GetAudioSessionId(
    const String& label) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end() || it->value.empty() ||
      it->value[0].audio_devices.empty())
    return base::UnguessableToken();

  // It is assumed that all devices belong to the same request and
  // therefore have the same session id.
  return it->value[0].audio_devices[0].session_id();
}

base::UnguessableToken MediaStreamDeviceObserver::GetVideoSessionId(
    const String& label) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  auto it = label_stream_map_.find(label);
  if (it == label_stream_map_.end() || it->value.empty() ||
      it->value[0].video_devices.empty())
    return base::UnguessableToken();

  // It is assumed that all devices belong to the same request and
  // therefore have the same session id.
  return it->value[0].video_devices[0].session_id();
}

bool MediaStreamDeviceObserver::Stream::ContainsDevice(
    const MediaStreamDevice& device) const {
  for (blink::MediaStreamDevice stream_device : audio_devices) {
    if (device.IsSameDevice(stream_device)) {
      return true;
    }
  }

  for (blink::MediaStreamDevice stream_device : video_devices) {
    if (device.IsSameDevice(stream_device)) {
      return true;
    }
  }

  return false;
}

}  // namespace blink
```
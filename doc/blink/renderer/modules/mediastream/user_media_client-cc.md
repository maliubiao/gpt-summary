Response:
Let's break down the thought process for analyzing this `UserMediaClient.cc` file.

1. **Understand the Goal:** The request asks for the file's functionalities, its relation to web technologies (JS, HTML, CSS), examples of logical reasoning, common usage errors, and debugging hints.

2. **Initial Code Scan - Identify Key Components:**  Read through the file to get a high-level understanding. Spot the major classes and data structures:
    * `UserMediaClient`: The main class.
    * `RequestQueue`: Manages pending requests.
    * `Request`: Represents a single request (getUserMedia, applyConstraints, stopTrack).
    * `UserMediaProcessor`: Likely handles the core media capturing logic.
    * `ApplyConstraintsProcessor`: Handles applying constraints to media tracks.
    * `MediaDevicesDispatcher`:  Likely interacts with the browser process for device enumeration and permission handling.

3. **Deconstruct Functionality by Class/Section:**  Go through the code section by section, focusing on what each part does.

    * **`namespace blink::` and anonymous namespace:**  Standard C++ for organization and internal helpers. The anonymous namespace has `g_next_request_id` for request tracking and `UpdateAPICount` for metrics.

    * **`RequestQueue`:**
        * **Purpose:**  Manages a queue of media-related requests (getUserMedia, applyConstraints, stopTrack). Processes them sequentially to avoid conflicts.
        * **Key Methods:** `EnqueueAndMaybeProcess`, `CancelUserMediaRequest`, `DeleteAllUserMediaRequests`, `KeepDeviceAliveForTransfer`.
        * **Relationship to `UserMediaProcessor` and `ApplyConstraintsProcessor`:** It uses these to actually handle the processing of different types of requests.

    * **`UserMediaClient`:**
        * **Purpose:**  The central point for handling user media requests in a frame. It acts as an intermediary between JavaScript and the lower-level media capturing mechanisms.
        * **Key Methods:** `RequestUserMedia`, `ApplyConstraints`, `StopTrack`, `CancelUserMediaRequest`, `DeleteAllUserMediaRequests`.
        * **Request Handling Logic:**  It decides which `RequestQueue` to use (device or display) based on the media type.
        * **Interaction with Browser:**  Uses `MediaDevicesDispatcher` to communicate with the browser process (for permissions, device enumeration, etc.).
        * **Lifecycle Management:** Handles setup and teardown when the frame/window is created/destroyed.

    * **`Request`:** A simple data structure to hold different types of requests.

4. **Identify Connections to Web Technologies:** Think about how the functionalities map to JavaScript, HTML, and CSS:

    * **JavaScript:** The most direct connection is through the `getUserMedia()`, `getDisplayMedia()`, `MediaStreamTrack.applyConstraints()`, and `MediaStreamTrack.stop()` JavaScript APIs. The `UserMediaClient` handles the underlying processing triggered by these APIs.
    * **HTML:**  While not directly interacting with HTML elements, the media streams obtained through this process are often used with HTML elements like `<video>` and `<audio>`.
    * **CSS:**  CSS might be used to style video elements displaying the captured media.

5. **Logical Reasoning Examples:** Consider scenarios and trace the flow:

    * **getUserMedia:**  What happens when `navigator.mediaDevices.getUserMedia()` is called?  A `UserMediaRequest` is created in JavaScript, passed to Blink, and the `UserMediaClient` enqueues it. The `UserMediaProcessor` then handles the actual media acquisition. Consider successful and error scenarios.
    * **applyConstraints:** How does `track.applyConstraints()` work?  An `ApplyConstraintsRequest` is created and processed by the `ApplyConstraintsProcessor`.

6. **Common Usage Errors:**  Think about mistakes developers might make:

    * Not checking for errors after calling `getUserMedia()`.
    * Trying to apply invalid constraints.
    * Not properly stopping tracks when they are no longer needed.

7. **Debugging Hints:** Trace the execution path:

    * Start with the JavaScript API call.
    * Follow the code into Blink, where `UserMediaClient` is involved.
    * Note the use of logging (`blink::WebRtcLogMessage`).
    * Understand the role of the `RequestQueue` and the processors.

8. **Structure the Output:** Organize the information clearly using headings and bullet points as in the example answer. Start with a summary, then go into details for each aspect. Use code snippets where helpful (like the JavaScript examples).

9. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any missing connections or unclear explanations. For instance, explicitly mentioning the asynchronous nature of the operations is important.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on `getUserMedia`.
* **Correction:** Realize that `applyConstraints` and `stopTrack` are also handled by this client.
* **Initial thought:**  Only consider successful scenarios.
* **Correction:** Include error handling and potential user errors.
* **Initial thought:**  Explain the code linearly.
* **Correction:**  Group functionalities by class and then explain the interaction between classes. This makes it easier to understand the overall architecture.
* **Initial thought:**  Not enough connection to web technologies.
* **Correction:**  Explicitly link the code to the JavaScript APIs and how the resulting media streams are used in HTML.

By following this structured approach, combining code analysis with an understanding of web technologies and common usage patterns, it's possible to generate a comprehensive and informative explanation of the `UserMediaClient.cc` file.
This C++ source code file, `user_media_client.cc`, located within the Chromium Blink rendering engine, is a crucial component for handling user media requests, primarily those initiated by JavaScript's `getUserMedia()` and `getDisplayMedia()` APIs. It acts as a central coordinator for managing the lifecycle of these requests within a specific web page (represented by a `LocalFrame`).

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Receiving and Queuing User Media Requests:**
   - When JavaScript code in a web page calls `navigator.mediaDevices.getUserMedia()` or `navigator.mediaDevices.getDisplayMedia()`, the request eventually reaches this `UserMediaClient`.
   - It maintains separate queues (`pending_device_requests_` and `pending_display_requests_`) for different types of media requests (camera/microphone vs. screen capture). This allows concurrent processing of different types of requests while handling similar requests sequentially.

2. **Managing the Lifecycle of User Media Requests:**
   - It creates and manages `UserMediaRequest` objects, which encapsulate the details of each request (audio and video constraints, success and error callbacks, etc.).
   - It assigns unique IDs to each request for tracking.

3. **Interacting with the Browser Process:**
   - It uses a `MediaDevicesDispatcher` to communicate with the browser process. This communication is essential for:
     - Requesting permissions from the user to access media devices.
     - Enumerating available media devices (cameras, microphones, screens).
     - Receiving device access grants or rejections.

4. **Processing User Media Requests:**
   - It utilizes `UserMediaProcessor` objects (one for regular media devices and one for display media) to handle the core logic of acquiring media streams based on the requested constraints.
   - The `UserMediaProcessor` interacts with platform-specific media capture mechanisms.

5. **Applying Constraints to Media Tracks:**
   - It uses an `ApplyConstraintsProcessor` to handle calls to `MediaStreamTrack.applyConstraints()`. This allows JavaScript to dynamically change the settings of an already active media track.

6. **Stopping Media Tracks:**
   - It handles requests to stop media tracks (when `MediaStreamTrack.stop()` is called).

7. **Tracking Active Capturing:**
   - It keeps track of whether the frame is currently capturing media, which can be used to display indicators in the browser UI.

8. **Maintaining Device Liveliness for Transfers (e.g., Screen Sharing Handoff):**
   - It provides a mechanism (`KeepDeviceAliveForTransfer`) to keep media devices active even when a media stream is being transferred to another process or context, preventing interruptions during scenarios like screen sharing handoffs in WebRTC.

**Relationship with JavaScript, HTML, and CSS:**

* **JavaScript:**  This is the primary interface point.
    - **Example:** When JavaScript calls `navigator.mediaDevices.getUserMedia({ video: true })`, the `UserMediaClient::RequestUserMedia` method is eventually invoked. This method parses the constraints, creates a `UserMediaRequest`, and queues it for processing.
    - **Example:**  When JavaScript calls `track.applyConstraints({ frameRate: 30 })`, the `UserMediaClient::ApplyConstraints` method is called, which uses the `ApplyConstraintsProcessor` to attempt to change the track's frame rate.
    - **Example:** When JavaScript calls `track.stop()`, the `UserMediaClient::StopTrack` method is called, which signals the underlying media capture to stop.

* **HTML:**  While not directly manipulating HTML, the media streams obtained through this process are typically used with HTML elements like `<video>` and `<audio>` to display or play the media. The `UserMediaClient` ensures these streams are available when requested.

* **CSS:** CSS can be used to style the `<video>` or `<audio>` elements that display the media obtained through `getUserMedia` or `getDisplayMedia`. The `UserMediaClient` itself doesn't directly interact with CSS.

**Logical Reasoning Examples:**

Let's consider the scenario when a web page requests both audio and video:

**Assumptions:**

* **Input:** JavaScript calls `navigator.mediaDevices.getUserMedia({ audio: true, video: true })`.
* **Implicit:** The user grants permission for both audio and video.

**Logical Steps in `UserMediaClient`:**

1. `RequestUserMedia` is called with a `UserMediaRequest` object containing audio and video constraints.
2. The request is added to the `pending_device_requests_` queue.
3. The `RequestQueue` starts processing the request.
4. The `UserMediaProcessor` is invoked to handle the request.
5. The `UserMediaProcessor` communicates with the browser process (via `MediaDevicesDispatcher`) to acquire access to the audio and video devices.
6. The platform-specific media capture mechanisms are initiated.
7. Media streams for audio and video are created.
8. Success callbacks in the original JavaScript promise are invoked with the `MediaStream` containing the audio and video tracks.

**Output:** The JavaScript code receives a `MediaStream` object containing both audio and video tracks.

**User or Programming Common Usage Errors:**

1. **Not Handling Permissions:** A very common error is not properly handling the promise rejection from `getUserMedia` when the user denies permission.
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(stream) {
       // Use the stream
     })
     .catch(function(err) {
       console.error("Error accessing media devices:", err); // Missing error handling
     });
   ```

2. **Applying Invalid Constraints:** Trying to apply constraints that are not supported by the device or browser. This can lead to errors or unexpected behavior.
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { width: { min: 10000 } } }) // Unrealistic width
     .catch(function(err) {
       console.error("Error:", err);
     });
   ```

3. **Not Stopping Tracks:** Forgetting to call `track.stop()` on the individual tracks or the entire `MediaStream` when they are no longer needed. This can lead to the camera or microphone remaining active unnecessarily, potentially impacting privacy and performance.
   ```javascript
   let stream;
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(function(s) {
       stream = s;
       // ... use the stream ...
     });
   // ... later, forgetting to stop the stream
   // stream.getTracks().forEach(track => track.stop());
   ```

**User Operation Steps to Reach Here (as a Debugging Clue):**

1. **User interacts with a web page:** The user navigates to a website or interacts with a web application.
2. **JavaScript code execution:** The website's JavaScript code executes, potentially triggered by a user action (e.g., clicking a button for video call, starting a screen share).
3. **`getUserMedia()` or `getDisplayMedia()` call:** The JavaScript code calls `navigator.mediaDevices.getUserMedia()` or `navigator.mediaDevices.getDisplayMedia()` with specific constraints.
4. **Browser receives the request:** The browser's rendering engine (Blink) intercepts this JavaScript call.
5. **Request reaches `UserMediaClient`:**  The call is routed to the appropriate `UserMediaClient` instance associated with the frame.
6. **`RequestUserMedia` (or similar) is invoked:** The `UserMediaClient`'s method to handle the request is called.
7. **Queueing and processing:** The request is queued, and the `UserMediaProcessor` and `MediaDevicesDispatcher` are engaged to acquire the media.

**Debugging Scenario Example:**

Imagine a user reports that their camera isn't turning on when they click the "Start Video" button on a web conferencing application. As a developer, you might:

1. **Check JavaScript console:** Look for any errors or rejections from the `getUserMedia()` promise.
2. **Set breakpoints in JavaScript:** Place breakpoints in the JavaScript code where `getUserMedia()` is called and in the success and error handlers.
3. **Step through JavaScript code:** Observe the flow of execution and the values of variables.
4. **If the error originates in the browser or media acquisition:** You might need to delve into the Blink rendering engine's code.
5. **Set breakpoints in `user_media_client.cc`:** Place breakpoints in methods like `RequestUserMedia`, `ProcessRequest` (in `UserMediaProcessor`), or in the communication with `MediaDevicesDispatcher`.
6. **Observe the flow in C++:** Track how the request is being processed, whether permissions are being requested correctly, and if any errors occur during device enumeration or access.
7. **Check WebRTC logs:** Chromium often has detailed WebRTC logs that can provide insights into the media acquisition process.

In essence, `user_media_client.cc` is a vital bridge between the web's JavaScript media APIs and the underlying platform's media capabilities, managing the complex process of obtaining and controlling user media streams within a web page.

### 提示词
```
这是目录为blink/renderer/modules/mediastream/user_media_client.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/mediastream/user_media_client.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "base/location.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_stream_device_observer.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/apply_constraints_processor.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {
namespace {

static int32_t g_next_request_id = 0;

// The histogram counts the number of calls to the JS APIs
// getUserMedia() and getDisplayMedia().
void UpdateAPICount(UserMediaRequestType media_type) {
  RTCAPIName api_name = RTCAPIName::kGetUserMedia;
  switch (media_type) {
    case UserMediaRequestType::kUserMedia:
      api_name = RTCAPIName::kGetUserMedia;
      break;
    case UserMediaRequestType::kDisplayMedia:
      api_name = RTCAPIName::kGetDisplayMedia;
      break;
    case UserMediaRequestType::kAllScreensMedia:
      api_name = RTCAPIName::kGetAllScreensMedia;
      break;
  }
  UpdateWebRTCMethodCount(api_name);
}

}  // namespace

// RequestQueue holds a queue of pending requests that can be processed
// independently from other types of requests. It keeps individual processor
// objects so that the processing state is kept separated between requests that
// are processed in parallel.
class UserMediaClient::RequestQueue final
    : public GarbageCollected<UserMediaClient::RequestQueue> {
 public:
  RequestQueue(LocalFrame* frame,
               UserMediaProcessor* user_media_processor,
               UserMediaClient* user_media_client,
               scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  ~RequestQueue();

  void EnqueueAndMaybeProcess(Request* request);
  bool IsCapturing() { return user_media_processor_->HasActiveSources(); }

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  void FocusCapturedSurface(const String& label, bool focus) {
    user_media_processor_->FocusCapturedSurface(label, focus);
  }
#endif

  void CancelUserMediaRequest(UserMediaRequest* user_media_request);
  void DeleteAllUserMediaRequests();
  void KeepDeviceAliveForTransfer(
      base::UnguessableToken session_id,
      base::UnguessableToken transfer_id,
      UserMediaProcessor::KeepDeviceAliveForTransferCallback keep_alive_cb);

  void Trace(Visitor* visitor) const;

 private:
  void MaybeProcessNextRequestInfo();
  void CurrentRequestCompleted();

  WeakMember<LocalFrame> frame_;
  Member<UserMediaProcessor> user_media_processor_;
  Member<ApplyConstraintsProcessor> apply_constraints_processor_;

  // UserMedia requests enqueued on the same RequestQueue are processed
  // sequentially. |is_processing_request_| is a flag that indicates if a
  // request is being processed at a given time, and |pending_request_infos_| is
  // a list of the queued requests.
  bool is_processing_request_ = false;

  HeapDeque<Member<Request>> pending_requests_;
  THREAD_CHECKER(thread_checker_);
};

UserMediaClient::RequestQueue::RequestQueue(
    LocalFrame* frame,
    UserMediaProcessor* user_media_processor,
    UserMediaClient* user_media_client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : frame_(frame),
      user_media_processor_(user_media_processor),
      apply_constraints_processor_(
          MakeGarbageCollected<ApplyConstraintsProcessor>(
              frame,
              WTF::BindRepeating(
                  [](UserMediaClient* client)
                      -> mojom::blink::MediaDevicesDispatcherHost* {
                    // |client| is guaranteed to be not null because |client|
                    // transitively owns this ApplyConstraintsProcessor.
                    DCHECK(client);
                    return client->GetMediaDevicesDispatcher();
                  },
                  WrapWeakPersistent(user_media_client)),
              std::move(task_runner))) {
  DCHECK(frame_);
  DCHECK(user_media_processor_);
}

UserMediaClient::RequestQueue::~RequestQueue() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Ensure that ContextDestroyed() gets called before the destructor.
  DCHECK(!is_processing_request_);
}

void UserMediaClient::RequestQueue::EnqueueAndMaybeProcess(Request* request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  pending_requests_.push_back(request);
  if (!is_processing_request_)
    MaybeProcessNextRequestInfo();
}

void UserMediaClient::RequestQueue::CancelUserMediaRequest(
    UserMediaRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  {
    // TODO(guidou): Remove this conditional logging. https://crbug.com/764293
    UserMediaRequest* request = user_media_processor_->CurrentRequest();
    if (request == user_media_request) {
      blink::WebRtcLogMessage(
          base::StringPrintf("UMCI::CancelUserMediaRequest. request_id=%d",
                             request->request_id()));
    }
  }

  if (!user_media_processor_->DeleteUserMediaRequest(user_media_request)) {
    for (auto it = pending_requests_.begin(); it != pending_requests_.end();
         ++it) {
      if ((*it)->IsUserMedia() &&
          (*it)->user_media_request() == user_media_request) {
        pending_requests_.erase(it);
        break;
      }
    }
  }
}

void UserMediaClient::RequestQueue::DeleteAllUserMediaRequests() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  user_media_processor_->StopAllProcessing();
  is_processing_request_ = false;
  pending_requests_.clear();
}

void UserMediaClient::RequestQueue::KeepDeviceAliveForTransfer(
    base::UnguessableToken session_id,
    base::UnguessableToken transfer_id,
    UserMediaProcessor::KeepDeviceAliveForTransferCallback keep_alive_cb) {
  // KeepDeviceAliveForTransfer is safe to call even during an ongoing request,
  // so doesn't need to be queued
  user_media_processor_->KeepDeviceAliveForTransfer(session_id, transfer_id,
                                                    std::move(keep_alive_cb));
}

void UserMediaClient::RequestQueue::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(user_media_processor_);
  visitor->Trace(apply_constraints_processor_);
  visitor->Trace(pending_requests_);
}

void UserMediaClient::RequestQueue::MaybeProcessNextRequestInfo() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (is_processing_request_ || pending_requests_.empty())
    return;

  auto current_request = std::move(pending_requests_.front());
  pending_requests_.pop_front();
  is_processing_request_ = true;

  if (current_request->IsUserMedia()) {
    user_media_processor_->ProcessRequest(
        current_request->MoveUserMediaRequest(),
        WTF::BindOnce(&UserMediaClient::RequestQueue::CurrentRequestCompleted,
                      WrapWeakPersistent(this)));
  } else if (current_request->IsApplyConstraints()) {
    apply_constraints_processor_->ProcessRequest(
        current_request->apply_constraints_request(),
        WTF::BindOnce(&UserMediaClient::RequestQueue::CurrentRequestCompleted,
                      WrapWeakPersistent(this)));
  } else {
    DCHECK(current_request->IsStopTrack());
    MediaStreamTrackPlatform* track = MediaStreamTrackPlatform::GetTrack(
        WebMediaStreamTrack(current_request->track_to_stop()));
    if (track) {
      track->StopAndNotify(
          WTF::BindOnce(&UserMediaClient::RequestQueue::CurrentRequestCompleted,
                        WrapWeakPersistent(this)));
    } else {
      CurrentRequestCompleted();
    }
  }
}

void UserMediaClient::RequestQueue::CurrentRequestCompleted() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  is_processing_request_ = false;
  if (!pending_requests_.empty()) {
    frame_->GetTaskRunner(blink::TaskType::kInternalMedia)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(
                &UserMediaClient::RequestQueue::MaybeProcessNextRequestInfo,
                WrapWeakPersistent(this)));
  }
}

UserMediaClient::Request::Request(UserMediaRequest* user_media_request)
    : user_media_request_(user_media_request) {
  DCHECK(user_media_request_);
  DCHECK(!apply_constraints_request_);
  DCHECK(!track_to_stop_);
}

UserMediaClient::Request::Request(blink::ApplyConstraintsRequest* request)
    : apply_constraints_request_(request) {
  DCHECK(apply_constraints_request_);
  DCHECK(!user_media_request_);
  DCHECK(!track_to_stop_);
}

UserMediaClient::Request::Request(MediaStreamComponent* track_to_stop)
    : track_to_stop_(track_to_stop) {
  DCHECK(track_to_stop_);
  DCHECK(!user_media_request_);
  DCHECK(!apply_constraints_request_);
}

UserMediaClient::Request::~Request() = default;

UserMediaRequest* UserMediaClient::Request::MoveUserMediaRequest() {
  auto user_media_request = user_media_request_;
  user_media_request_ = nullptr;
  return user_media_request.Get();
}

UserMediaClient::UserMediaClient(
    LocalFrame* frame,
    UserMediaProcessor* user_media_processor,
    UserMediaProcessor* display_user_media_processor,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : Supplement<LocalDOMWindow>(*frame->DomWindow()),
      ExecutionContextLifecycleObserver(frame->DomWindow()),
      frame_(frame),
      media_devices_dispatcher_(frame->DomWindow()),
      pending_device_requests_(
          MakeGarbageCollected<RequestQueue>(frame,
                                             user_media_processor,
                                             this,
                                             task_runner)),
      pending_display_requests_(
          MakeGarbageCollected<RequestQueue>(frame,
                                             display_user_media_processor,
                                             this,
                                             task_runner)) {
  CHECK(frame_);

  // WrapWeakPersistent is safe because the |frame_| owns UserMediaClient.
  frame_->SetIsCapturingMediaCallback(WTF::BindRepeating(
      [](UserMediaClient* client) { return client && client->IsCapturing(); },
      WrapWeakPersistent(this)));
}

UserMediaClient::UserMediaClient(
    LocalFrame* frame,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : UserMediaClient(
          frame,
          MakeGarbageCollected<UserMediaProcessor>(
              frame,
              WTF::BindRepeating(
                  [](UserMediaClient* client)
                      -> mojom::blink::MediaDevicesDispatcherHost* {
                    // |client| is guaranteed to be not null because |client|
                    // owns transitively this UserMediaProcessor.
                    DCHECK(client);
                    return client->GetMediaDevicesDispatcher();
                  },
                  WrapWeakPersistent(this)),
              frame->GetTaskRunner(blink::TaskType::kInternalMedia)),
          MakeGarbageCollected<UserMediaProcessor>(
              frame,
              WTF::BindRepeating(
                  [](UserMediaClient* client)
                      -> mojom::blink::MediaDevicesDispatcherHost* {
                    // |client| is guaranteed to be not null because
                    // |client| transitively owns this UserMediaProcessor.
                    DCHECK(client);
                    return client->GetMediaDevicesDispatcher();
                  },
                  WrapWeakPersistent(this)),
              frame->GetTaskRunner(blink::TaskType::kInternalMedia)),
          std::move(task_runner)) {}

void UserMediaClient::RequestUserMedia(UserMediaRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(user_media_request);
  DCHECK(user_media_request->Audio() || user_media_request->Video());
  // GetWindow() may be null if we are in a test.
  // In that case, it's OK to not check frame().
  DCHECK(!user_media_request->GetWindow() ||
         frame_ == user_media_request->GetWindow()->GetFrame());

  // Save histogram data so we can see how much GetUserMedia is used.
  UpdateAPICount(user_media_request->MediaRequestType());

  int32_t request_id = g_next_request_id++;
  blink::WebRtcLogMessage(base::StringPrintf(
      "UMCI::RequestUserMedia({request_id=%d}, {audio constraints=%s}, "
      "{video constraints=%s})",
      request_id,
      user_media_request->AudioConstraints().ToString().Utf8().c_str(),
      user_media_request->VideoConstraints().ToString().Utf8().c_str()));

  // The value returned by HasTransientUserActivation() is used by the browser
  // to make decisions about the permissions UI. Its value can be lost while
  // switching threads, so saving its value here.
  //
  // TODO(mustaq): The description above seems specific to pre-UAv2 stack-based
  // tokens.  Perhaps we don't need to preserve this bit?
  bool has_transient_user_activation = false;
  if (LocalDOMWindow* window = user_media_request->GetWindow()) {
    has_transient_user_activation =
        LocalFrame::HasTransientUserActivation(window->GetFrame());
  }
  user_media_request->set_request_id(request_id);

  // TODO(crbug.com/787254): Communicate directly with the
  // PeerConnectionTrackerHost mojo object once it is available from Blink.
  if (auto* window = user_media_request->GetWindow()) {
    if (user_media_request->MediaRequestType() ==
        UserMediaRequestType::kUserMedia) {
      PeerConnectionTracker::From(*window).TrackGetUserMedia(
          user_media_request);
    } else {
      PeerConnectionTracker::From(*window).TrackGetDisplayMedia(
          user_media_request);
    }
  }

  user_media_request->set_has_transient_user_activation(
      has_transient_user_activation);
  mojom::blink::MediaStreamType type =
      user_media_request->Video() ? user_media_request->VideoMediaStreamType()
                                  : user_media_request->AudioMediaStreamType();
  auto* queue = GetRequestQueue(type);
  queue->EnqueueAndMaybeProcess(
      MakeGarbageCollected<Request>(user_media_request));
}

void UserMediaClient::ApplyConstraints(
    blink::ApplyConstraintsRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(user_media_request);
  DCHECK(user_media_request->Track());
  DCHECK(user_media_request->Track()->Source());
  DCHECK(user_media_request->Track()->Source()->GetPlatformSource());
  auto* queue = GetRequestQueue(user_media_request->Track()
                                    ->Source()
                                    ->GetPlatformSource()
                                    ->device()
                                    .type);
  queue->EnqueueAndMaybeProcess(
      MakeGarbageCollected<Request>(user_media_request));
}

void UserMediaClient::StopTrack(MediaStreamComponent* track) {
  DCHECK(track);
  DCHECK(track->Source());
  DCHECK(track->Source()->GetPlatformSource());
  auto* queue =
      GetRequestQueue(track->Source()->GetPlatformSource()->device().type);
  queue->EnqueueAndMaybeProcess(MakeGarbageCollected<Request>(track));
}

bool UserMediaClient::IsCapturing() {
  return pending_device_requests_->IsCapturing() ||
         pending_display_requests_->IsCapturing();
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void UserMediaClient::FocusCapturedSurface(const String& label, bool focus) {
  pending_display_requests_->FocusCapturedSurface(label, focus);
}
#endif

void UserMediaClient::CancelUserMediaRequest(
    UserMediaRequest* user_media_request) {
  pending_device_requests_->CancelUserMediaRequest(user_media_request);
  pending_display_requests_->CancelUserMediaRequest(user_media_request);
}

void UserMediaClient::DeleteAllUserMediaRequests() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (frame_)
    frame_->SetIsCapturingMediaCallback(LocalFrame::IsCapturingMediaCallback());
  pending_device_requests_->DeleteAllUserMediaRequests();
  pending_display_requests_->DeleteAllUserMediaRequests();
}

void UserMediaClient::ContextDestroyed() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Cancel all outstanding UserMediaRequests.
  DeleteAllUserMediaRequests();
}

void UserMediaClient::Trace(Visitor* visitor) const {
  Supplement<LocalDOMWindow>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  visitor->Trace(frame_);
  visitor->Trace(media_devices_dispatcher_);
  visitor->Trace(pending_device_requests_);
  visitor->Trace(pending_display_requests_);
}

void UserMediaClient::SetMediaDevicesDispatcherForTesting(
    mojo::PendingRemote<blink::mojom::blink::MediaDevicesDispatcherHost>
        media_devices_dispatcher) {
  media_devices_dispatcher_.Bind(
      std::move(media_devices_dispatcher),
      frame_->GetTaskRunner(blink::TaskType::kInternalMedia));
}

blink::mojom::blink::MediaDevicesDispatcherHost*
UserMediaClient::GetMediaDevicesDispatcher() {
  if (!media_devices_dispatcher_.is_bound()) {
    frame_->GetBrowserInterfaceBroker().GetInterface(
        media_devices_dispatcher_.BindNewPipeAndPassReceiver(
            frame_->GetTaskRunner(blink::TaskType::kInternalMedia)));
  }

  return media_devices_dispatcher_.get();
}

const char UserMediaClient::kSupplementName[] = "UserMediaClient";

UserMediaClient* UserMediaClient::From(LocalDOMWindow* window) {
  if (!window) {
    return nullptr;
  }
  auto* client = Supplement<LocalDOMWindow>::From<UserMediaClient>(window);
  if (!client) {
    if (!window->GetFrame()) {
      return nullptr;
    }
    client = MakeGarbageCollected<UserMediaClient>(
        window->GetFrame(), window->GetTaskRunner(TaskType::kInternalMedia));
    Supplement<LocalDOMWindow>::ProvideTo(*window, client);
  }
  return client;
}

void UserMediaClient::KeepDeviceAliveForTransfer(
    base::UnguessableToken session_id,
    base::UnguessableToken transfer_id,
    UserMediaProcessor::KeepDeviceAliveForTransferCallback keep_alive_cb) {
  pending_display_requests_->KeepDeviceAliveForTransfer(
      session_id, transfer_id, std::move(keep_alive_cb));
}

UserMediaClient::RequestQueue* UserMediaClient::GetRequestQueue(
    mojom::blink::MediaStreamType media_stream_type) {
  if (IsScreenCaptureMediaType(media_stream_type) ||
      media_stream_type ==
          mojom::blink::MediaStreamType::DISPLAY_AUDIO_CAPTURE) {
    return pending_display_requests_.Get();
  } else {
    return pending_device_requests_.Get();
  }
}

}  // namespace blink
```
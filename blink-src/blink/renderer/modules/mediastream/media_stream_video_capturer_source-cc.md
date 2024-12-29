Response:
Let's break down the thought process for analyzing this C++ file and generating the comprehensive explanation.

**1. Initial Skim and Identification of Core Purpose:**

The first step is a quick read-through to grasp the general function. Keywords like "MediaStreamVideoCapturerSource," "VideoCapture," "frame_callback," "StartCapture," "StopCapture," and "MediaStreamVideoSource" immediately jump out. This points to the file being responsible for managing video capture within the context of MediaStreams in the Blink rendering engine. The file extension `.cc` confirms it's C++ source code.

**2. Deeper Dive into Key Classes and Methods:**

Next, I'd focus on understanding the main class `MediaStreamVideoCapturerSource` and its critical methods.

* **Constructors:**  Notice the two constructors. One takes a pre-existing `VideoCapturerSource`, suggesting it can wrap an existing capture mechanism. The other takes a `MediaStreamDevice` and a `DeviceCapturerFactoryCallback`, hinting at creating a `VideoCapturerSource` based on device information. This suggests different ways this class can be instantiated.

* **`StartSourceImpl`:**  This is clearly the method that initiates the video capture process. Pay attention to the arguments: `frame_callback`, `encoded_frame_callback`, etc. These are callbacks, indicating asynchronous behavior and how the captured video data is delivered.

* **`StopSourceImpl`:**  The counterpart to `StartSourceImpl`, responsible for halting the capture.

* **`RestartSourceImpl`:**  Handles restarting capture, potentially with new format parameters.

* **`ChangeSourceImpl`:** Allows switching to a different video capture device.

* **`OnRunStateChanged`:** This method seems crucial for handling state transitions of the underlying `VideoCapturerSource`. The `switch` statement and the different `kStarting`, `kStarted`, `kStopping...` states are strong indicators of state management.

* **Methods like `SetDeviceCapturerFactoryCallbackForTesting`, `GetSourceForTesting`:** These suggest the code is designed to be testable.

* **Inheritance:**  Note that `MediaStreamVideoCapturerSource` inherits from `MediaStreamVideoSource`. This implies it's part of a larger hierarchy dealing with media stream sources.

**3. Identifying Relationships with JavaScript/HTML/CSS:**

This is where connecting the C++ backend to the frontend comes in.

* **MediaStream API:** The name "MediaStream" is a direct link to the JavaScript MediaStream API (`getUserMedia`). This API is used to request access to the user's camera and microphone.

* **HTML `<video>` element:**  The captured video data ultimately needs to be displayed. The `<video>` element is the primary way to render video in HTML.

* **JavaScript interaction:**  JavaScript code using `getUserMedia` triggers the underlying browser mechanisms, eventually leading to the creation and use of `MediaStreamVideoCapturerSource`. JavaScript also controls the `<video>` element's `srcObject` to display the stream.

* **CSS (indirect):** While CSS doesn't directly interact with this C++ file, it's used to style the `<video>` element, control its size, position, etc.

**4. Logical Reasoning and Hypothetical Inputs/Outputs:**

Think about the flow of data and the expected behavior.

* **Input:** A JavaScript call to `navigator.mediaDevices.getUserMedia({ video: true })`. This is the initial request.

* **Processing:** The browser handles the permission prompt, selects a video device, and creates a `MediaStreamTrack` backed by a `MediaStreamVideoCapturerSource`. `StartSourceImpl` is called, which internally starts the `VideoCapturerSource`. Video frames are captured.

* **Output:**  The `frame_callback_` (a C++ callback) is invoked with the captured video frames. These frames are then passed up to the rendering engine and eventually become the data displayed in the `<video>` element.

* **Error Scenarios:**  What happens if the user denies permission?  What if the camera is already in use? The `OnRunStateChanged` method with its error handling provides clues.

**5. User and Programming Errors:**

Consider common mistakes developers and users might make.

* **User denying permissions:**  A common user action that directly affects this code.
* **Camera already in use:** Another frequent scenario.
* **Incorrect constraints:** If the JavaScript `getUserMedia` call specifies unsupported video constraints, this could lead to errors.
* **Not handling errors in JavaScript:**  A developer might forget to catch errors returned by `getUserMedia`.

**6. Tracing User Operations to the Code:**

This is about connecting the user's actions to the execution of this specific C++ file.

1. **User opens a webpage:** The process starts with a user navigating to a web page.
2. **Webpage requests camera access:** The webpage's JavaScript uses `navigator.mediaDevices.getUserMedia({ video: true })`.
3. **Browser permission prompt:** The browser displays a permission prompt to the user.
4. **User grants/denies permission:** The user's choice is crucial.
5. **Blink processes the request:** If permission is granted, Blink (the rendering engine) starts the process of accessing the camera.
6. **`MediaStreamVideoCapturerSource` is created:**  This class is instantiated to manage the video capture.
7. **`StartSourceImpl` is called:**  The capture process begins.
8. **Video frames are captured:** The `VideoCapturerSource` (managed by this class) starts receiving frames from the camera.
9. **Frames are passed to JavaScript:**  The `frame_callback_` delivers the frames.
10. **Frames are displayed in `<video>`:** The JavaScript sets the `srcObject` of a `<video>` element.

**7. Structuring the Explanation:**

Finally, organize the information logically using headings, bullet points, and code snippets (where appropriate). Start with a high-level overview and then delve into the details. Be clear and concise, explaining technical terms where necessary. Use examples to illustrate the connections to JavaScript, HTML, and CSS. Address all the points raised in the prompt.

This systematic approach ensures that all aspects of the file's functionality are covered, its relationship to the frontend is explained, potential errors are identified, and the path from user interaction to the code is traced.
This C++ file, `media_stream_video_capturer_source.cc`, within the Chromium Blink rendering engine plays a crucial role in **capturing video from various sources and making it available as part of a MediaStream**. Think of it as the bridge between the underlying video capture mechanisms (like camera drivers or screen capture) and the web's MediaStream API.

Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Abstraction of Video Sources:** It acts as an intermediary, abstracting away the specifics of different video capture sources. This allows the higher-level MediaStream infrastructure to interact with video capture in a consistent manner, regardless of whether the source is a physical camera, a screen capture, or some other virtual source.

2. **Managing the Video Capturer:** It manages the lifecycle of a `VideoCapturerSource` object (defined in `third_party/blink/renderer/platform/video_capture/video_capturer_source.h`). This includes starting and stopping the capture process.

3. **Handling Start and Stop Requests:** It receives requests to start and stop video capture, triggered by the MediaStream API.

4. **Delivering Video Frames:**  It receives raw video frames from the underlying `VideoCapturerSource` and makes them available to the MediaStream pipeline. This involves using callbacks like `VideoCaptureDeliverFrameCB`.

5. **Managing Capture Parameters:** It handles video capture parameters like resolution, frame rate, and other constraints specified by the web application through the `getUserMedia` API.

6. **Handling Device Changes:** It allows for dynamically changing the video source (e.g., switching between different cameras) after a MediaStream has been established.

7. **Providing Feedback:** It provides feedback to the underlying capture source, such as whether there are active consumers for the video stream. This allows the capture source to optimize its behavior (e.g., pausing when no one is listening).

8. **Security Considerations:** It interacts with the browser's MediaStream dispatcher to signal whether the capturing link is secure, influencing the security indicators in the browser UI.

9. **Sub-capture Target Management (Screen Sharing):** For screen sharing scenarios, it manages the concept of a "sub-capture target," which allows the web application to select a specific window or screen to capture. It handles versioning and applying these targets.

**Relationship with JavaScript, HTML, and CSS:**

This C++ file is a backend component and doesn't directly interact with JavaScript, HTML, or CSS in the sense of manipulating DOM elements or styles. However, it's a critical piece in the implementation of the MediaStream API, which is extensively used in web development.

**Examples:**

* **JavaScript:** When a web application uses `navigator.mediaDevices.getUserMedia({ video: true })`, the browser (specifically the Blink rendering engine) will eventually create a `MediaStreamVideoCapturerSource` to manage the video track of the resulting MediaStream. The constraints specified in `getUserMedia` (e.g., resolution, frame rate) are passed down to this C++ class to configure the underlying video capturer.

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: { width: 1280, height: 720 } })
     .then(function(stream) {
       const videoElement = document.getElementById('myVideo');
       videoElement.srcObject = stream;
     })
     .catch(function(err) {
       console.error("Error accessing the camera:", err);
     });
   ```

* **HTML:** The captured video stream is typically displayed in an HTML `<video>` element. The `srcObject` attribute of the `<video>` element is set to the MediaStream object obtained from `getUserMedia`.

   ```html
   <video id="myVideo" autoplay playsinline></video>
   ```

* **CSS:** CSS can be used to style the `<video>` element (e.g., setting its size, position, applying filters). However, CSS doesn't directly interact with the video capture logic implemented in `media_stream_video_capturer_source.cc`.

**Logical Reasoning and Hypothetical Inputs/Outputs:**

Let's consider a scenario where a user grants camera access to a website:

* **Hypothetical Input:**
    * JavaScript calls `navigator.mediaDevices.getUserMedia({ video: true })`.
    * The browser prompts the user for permission, and the user grants it.
    * The system has a default webcam capable of 640x480 resolution at 30fps.

* **Internal Processing (within this file):**
    * A `MediaStreamVideoCapturerSource` is created, potentially using a `DeviceCapturerFactoryCallback` to instantiate a suitable `VideoCapturerSource` for the webcam.
    * The `StartSourceImpl` method is called.
    * The underlying `VideoCapturerSource` starts capturing frames from the webcam.
    * The `frame_callback_` (a member of `MediaStreamVideoCapturerSource`) receives captured video frames.

* **Hypothetical Output:**
    * The `OnStartDone` method is called with `MediaStreamRequestResult::OK`, signaling successful capture initiation.
    * Video frames are made available to the MediaStream track, which can then be displayed in a `<video>` element.

**User or Programming Common Usage Errors:**

1. **User Denies Camera Permission:** If the user denies the camera permission prompt, the `OnStartDone` method will be called with a result like `MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED`. The JavaScript `getUserMedia` promise will be rejected, and the web application needs to handle this error gracefully.

   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(/* ... */)
     .catch(function(err) {
       if (err.name === 'NotAllowedError') {
         console.error("Camera access was denied by the user.");
       }
     });
   ```

2. **Camera Already in Use:** If the requested camera is already being used by another application, the `OnRunStateChanged` method might be called with `RunState::kCameraBusyError`, leading to `OnStartDone` being called with `MediaStreamRequestResult::DEVICE_IN_USE`.

3. **Invalid Constraints:** If the JavaScript code specifies video constraints that the available camera doesn't support (e.g., a very high resolution), the `StartCapture` call might fail, and `OnStartDone` could be called with `MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO`.

4. **Forgetting to Handle Errors in JavaScript:**  A common programming error is not properly catching and handling the errors returned by `getUserMedia`. This can lead to unexpected behavior if camera access fails.

**User Operation Steps Leading to This Code (Debugging Clues):**

1. **User Opens a Webpage:** The user navigates to a website that requests camera access.
2. **Website Requests Camera Access:** The website's JavaScript code calls `navigator.mediaDevices.getUserMedia({ video: true })`.
3. **Browser Receives the Request:** The browser's rendering engine (Blink) intercepts this request.
4. **Permission Check and Prompt:** Blink checks if the website has permission to access the camera. If not, it prompts the user.
5. **User Grants Permission:** The user clicks "Allow" in the permission prompt.
6. **MediaStream Creation:** Blink starts the process of creating a MediaStream. For the video track, it will likely create a `MediaStreamVideoCapturerSource`.
7. **Source Initialization:** The constructor of `MediaStreamVideoCapturerSource` is called, potentially using a factory to create the underlying `VideoCapturerSource` based on the selected camera device.
8. **Starting Capture:** The `StartSourceImpl` method is invoked, initiating the video capture process from the camera.
9. **Frame Delivery:**  As the camera captures frames, they are delivered through the `VideoCapturerSource` to the `MediaStreamVideoCapturerSource`.
10. **MediaStream Track Receives Frames:** The `MediaStreamVideoCapturerSource` makes these frames available to the corresponding video track of the MediaStream.
11. **Displaying in `<video>`:** The JavaScript code might then set the `srcObject` of a `<video>` element to this MediaStream, causing the captured video to be displayed on the webpage.

**Debugging Scenarios:**

* **Camera not working:** If the user reports that the camera is not working on a website, a developer might look at the logs and see if the `OnStartDone` method was called with an error result. They might also investigate the underlying `VideoCapturerSource` to see if it encountered any issues communicating with the camera driver.
* **Incorrect video resolution:** If the displayed video has the wrong resolution, the developer might check the constraints passed to `getUserMedia` and how they are handled within the `MediaStreamVideoCapturerSource` and the underlying `VideoCapturerSource`.
* **Switching cameras issues:** If switching between different cameras fails, debugging might involve looking at the `ChangeSourceImpl` method and how it manages the transition between different `VideoCapturerSource` instances.

In summary, `media_stream_video_capturer_source.cc` is a vital backend component in Blink that manages the complexities of video capture for the web's MediaStream API. It bridges the gap between low-level capture mechanisms and the high-level JavaScript API, handling starting, stopping, configuring, and delivering video frames to web applications.

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_capturer_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_video_capturer_source.h"

#include <utility>

#include "base/functional/callback.h"
#include "base/task/single_thread_task_runner.h"
#include "base/token.h"
#include "build/build_config.h"
#include "media/capture/mojom/video_capture_types.mojom-blink.h"
#include "media/capture/video_capture_types.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/video_capture/video_capturer_source.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using mojom::blink::MediaStreamRequestResult;

MediaStreamVideoCapturerSource::MediaStreamVideoCapturerSource(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    LocalFrame* frame,
    SourceStoppedCallback stop_callback,
    std::unique_ptr<VideoCapturerSource> source)
    : MediaStreamVideoSource(std::move(main_task_runner)),
      frame_(frame),
      source_(std::move(source)) {
  media::VideoCaptureFormats preferred_formats = source_->GetPreferredFormats();
  if (!preferred_formats.empty())
    capture_params_.requested_format = preferred_formats.front();
  SetStopCallback(std::move(stop_callback));
}

MediaStreamVideoCapturerSource::MediaStreamVideoCapturerSource(
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    LocalFrame* frame,
    SourceStoppedCallback stop_callback,
    const MediaStreamDevice& device,
    const media::VideoCaptureParams& capture_params,
    DeviceCapturerFactoryCallback device_capturer_factory_callback)
    : MediaStreamVideoSource(std::move(main_task_runner)),
      frame_(frame),
      source_(device_capturer_factory_callback.Run(device.session_id())),
      capture_params_(capture_params),
      device_capturer_factory_callback_(
          std::move(device_capturer_factory_callback)) {
  DCHECK(!device.session_id().is_empty());
  SetStopCallback(std::move(stop_callback));
  SetDevice(device);
  SetDeviceRotationDetection(true /* enabled */);
}

MediaStreamVideoCapturerSource::~MediaStreamVideoCapturerSource() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void MediaStreamVideoCapturerSource::SetDeviceCapturerFactoryCallbackForTesting(
    DeviceCapturerFactoryCallback testing_factory_callback) {
  device_capturer_factory_callback_ = std::move(testing_factory_callback);
}

void MediaStreamVideoCapturerSource::OnSourceCanDiscardAlpha(
    bool can_discard_alpha) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_->SetCanDiscardAlpha(can_discard_alpha);
}

void MediaStreamVideoCapturerSource::RequestRefreshFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_->RequestRefreshFrame();
}

void MediaStreamVideoCapturerSource::OnLog(const std::string& message) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_->OnLog(message);
}

void MediaStreamVideoCapturerSource::OnHasConsumers(bool has_consumers) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (has_consumers)
    source_->Resume();
  else
    source_->MaybeSuspend();
}

void MediaStreamVideoCapturerSource::OnCapturingLinkSecured(bool is_secure) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!frame_ || !frame_->Client())
    return;
  GetMediaStreamDispatcherHost()->SetCapturingLinkSecured(
      device().serializable_session_id(),
      static_cast<mojom::blink::MediaStreamType>(device().type), is_secure);
}

void MediaStreamVideoCapturerSource::StartSourceImpl(
    VideoCaptureDeliverFrameCB frame_callback,
    EncodedVideoFrameCB encoded_frame_callback,
    VideoCaptureSubCaptureTargetVersionCB sub_capture_target_version_callback,
    VideoCaptureNotifyFrameDroppedCB frame_dropped_callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  state_ = kStarting;
  frame_callback_ = std::move(frame_callback);
  sub_capture_target_version_callback_ =
      std::move(sub_capture_target_version_callback);
  frame_dropped_callback_ = std::move(frame_dropped_callback);

  source_->StartCapture(
      capture_params_, frame_callback_, sub_capture_target_version_callback_,
      frame_dropped_callback_,
      WTF::BindRepeating(&MediaStreamVideoCapturerSource::OnRunStateChanged,
                         weak_factory_.GetWeakPtr(), capture_params_));
}

media::VideoCaptureFeedbackCB
MediaStreamVideoCapturerSource::GetFeedbackCallback() const {
  return source_->GetFeedbackCallback();
}

void MediaStreamVideoCapturerSource::StopSourceImpl() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_->StopCapture();
}

void MediaStreamVideoCapturerSource::StopSourceForRestartImpl() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (state_ != kStarted) {
    OnStopForRestartDone(false);
    return;
  }
  state_ = kStoppingForRestart;
  source_->StopCapture();

  // Force state update for nondevice sources, since they do not
  // automatically update state after StopCapture().
  if (device().type == mojom::blink::MediaStreamType::NO_SERVICE)
    OnRunStateChanged(capture_params_, RunState::kStopped);
}

void MediaStreamVideoCapturerSource::RestartSourceImpl(
    const media::VideoCaptureFormat& new_format) {
  DCHECK(new_format.IsValid());
  media::VideoCaptureParams new_capture_params = capture_params_;
  new_capture_params.requested_format = new_format;
  state_ = kRestarting;
  source_->StartCapture(
      new_capture_params, frame_callback_, sub_capture_target_version_callback_,
      frame_dropped_callback_,
      WTF::BindRepeating(&MediaStreamVideoCapturerSource::OnRunStateChanged,
                         weak_factory_.GetWeakPtr(), new_capture_params));
}

std::optional<media::VideoCaptureFormat>
MediaStreamVideoCapturerSource::GetCurrentFormat() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return capture_params_.requested_format;
}

void MediaStreamVideoCapturerSource::ChangeSourceImpl(
    const MediaStreamDevice& new_device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(device_capturer_factory_callback_);

  if (state_ != kStarted && state_ != kStoppedForRestart) {
    return;
  }

  if (state_ == kStarted) {
    state_ = kStoppingForChangeSource;
    source_->StopCapture();
  } else {
    DCHECK_EQ(state_, kStoppedForRestart);
    state_ = kRestartingAfterSourceChange;
  }
  SetDevice(new_device);
  source_ = device_capturer_factory_callback_.Run(new_device.session_id());
  source_->StartCapture(
      capture_params_, frame_callback_, sub_capture_target_version_callback_,
      frame_dropped_callback_,
      WTF::BindRepeating(&MediaStreamVideoCapturerSource::OnRunStateChanged,
                         weak_factory_.GetWeakPtr(), capture_params_));
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void MediaStreamVideoCapturerSource::ApplySubCaptureTarget(
    media::mojom::blink::SubCaptureTargetType type,
    const base::Token& sub_capture_target,
    uint32_t sub_capture_target_version,
    base::OnceCallback<void(media::mojom::ApplySubCaptureTargetResult)>
        callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const std::optional<base::UnguessableToken>& session_id =
      device().serializable_session_id();
  if (!session_id.has_value()) {
    std::move(callback).Run(
        media::mojom::ApplySubCaptureTargetResult::kErrorGeneric);
    return;
  }
  GetMediaStreamDispatcherHost()->ApplySubCaptureTarget(
      session_id.value(), type, sub_capture_target, sub_capture_target_version,
      std::move(callback));
}

std::optional<uint32_t>
MediaStreamVideoCapturerSource::GetNextSubCaptureTargetVersion() {
  if (NumTracks() != 1) {
    return std::nullopt;
  }
  return ++current_sub_capture_target_version_;
}
#endif

uint32_t MediaStreamVideoCapturerSource::GetSubCaptureTargetVersion() const {
  return current_sub_capture_target_version_;
}

base::WeakPtr<MediaStreamVideoSource>
MediaStreamVideoCapturerSource::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

void MediaStreamVideoCapturerSource::OnRunStateChanged(
    const media::VideoCaptureParams& new_capture_params,
    RunState run_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  bool is_running = (run_state == RunState::kRunning);
  switch (state_) {
    case kStarting:
      source_->OnLog("MediaStreamVideoCapturerSource sending OnStartDone");
      if (is_running) {
        state_ = kStarted;
        DCHECK(capture_params_ == new_capture_params);
        OnStartDone(MediaStreamRequestResult::OK);
      } else {
        state_ = kStopped;
        MediaStreamRequestResult result;
        switch (run_state) {
          case RunState::kSystemPermissionsError:
            result = MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED;
            break;
          case RunState::kCameraBusyError:
            result = MediaStreamRequestResult::DEVICE_IN_USE;
            break;
          case RunState::kStartTimeoutError:
            result = MediaStreamRequestResult::START_TIMEOUT;
            break;
          default:
            result = MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO;
        }
        OnStartDone(result);
      }
      break;
    case kStarted:
      if (!is_running) {
        state_ = kStopped;
        StopSource();
      }
      break;
    case kStoppingForRestart:
      source_->OnLog(
          "MediaStreamVideoCapturerSource sending OnStopForRestartDone");
      state_ = is_running ? kStarted : kStoppedForRestart;
      OnStopForRestartDone(!is_running);
      break;
    case kStoppingForChangeSource:
      state_ = is_running ? kStarted : kStopped;
      break;
    case kRestarting:
      if (is_running) {
        state_ = kStarted;
        capture_params_ = new_capture_params;
      } else {
        state_ = kStoppedForRestart;
      }
      source_->OnLog("MediaStreamVideoCapturerSource sending OnRestartDone");
      OnRestartDone(is_running);
      break;
    case kRestartingAfterSourceChange:
      if (is_running) {
        state_ = kStarted;
        capture_params_ = new_capture_params;
      } else {
        state_ = kStoppedForRestart;
      }
      source_->OnLog("MediaStreamVideoCapturerSource sending OnRestartDone");
      OnRestartBySourceSwitchDone(is_running);
      break;
    case kStopped:
    case kStoppedForRestart:
      break;
  }
}

mojom::blink::MediaStreamDispatcherHost*
MediaStreamVideoCapturerSource::GetMediaStreamDispatcherHost() {
  DCHECK(frame_);
  if (!host_) {
    frame_->GetBrowserInterfaceBroker().GetInterface(
        host_.BindNewPipeAndPassReceiver());
  }
  return host_.get();
}

void MediaStreamVideoCapturerSource::SetMediaStreamDispatcherHostForTesting(
    mojo::PendingRemote<mojom::blink::MediaStreamDispatcherHost> host) {
  host_.Bind(std::move(host));
}

VideoCapturerSource* MediaStreamVideoCapturerSource::GetSourceForTesting() {
  return source_.get();
}

}  // namespace blink

"""

```
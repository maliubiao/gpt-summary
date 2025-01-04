Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Class Under Test:** The filename `media_stream_device_observer_test.cc` and the `#include "third_party/blink/renderer/modules/mediastream/media_stream_device_observer.h"` immediately tell us the central focus is the `MediaStreamDeviceObserver` class. The `TEST_F(MediaStreamDeviceObserverTest, ...)` macros confirm this.

2. **Understand the Purpose of a Test File:** Test files in software development are designed to verify the functionality of a specific unit of code (in this case, the `MediaStreamDeviceObserver` class). They do this by setting up various scenarios, calling methods of the class under test, and then asserting that the results match the expected behavior.

3. **Examine the Test Fixture (`MediaStreamDeviceObserverTest`):**  This class sets up the environment for the tests.
    * **Constructor:**  It initializes the `MediaStreamDeviceObserver` with `nullptr` (likely because the tests don't need a "real" parent object).
    * **Helper Methods:**  The methods like `OnDeviceOpened`, `AddStreams`, `CheckStreamDeviceIds`, `GetStreams`, `GetStream`, and `SetupMultiStreams` are crucial. They provide controlled ways to interact with the `MediaStreamDeviceObserver` during the tests. Notice how `OnDeviceOpened` simulates a successful device opening, storing the label and device. `AddStreams` simulates adding multiple devices associated with a label.
    * **Member Variables:**  `task_environment_`, `stream_label_`, `mock_dispatcher_host_`, `observer_`, and `current_device_` are used to manage the test environment and store data during the tests. The `mock_dispatcher_host_` is a key hint – it suggests that the `MediaStreamDeviceObserver` interacts with some external system (likely via Mojo), and this mock allows for isolated testing.

4. **Analyze Individual Test Cases (`TEST_F` blocks):**  Each test case focuses on a specific aspect of the `MediaStreamDeviceObserver`'s functionality. For each test, consider:
    * **What is being tested?** (Read the test name).
    * **How is the test set up?** (Look at the initializations and calls to helper methods).
    * **What actions are performed on the `MediaStreamDeviceObserver`?** (Calls to its methods like `AddStream`, `RemoveStreams`, `OnDeviceStopped`, `OnDeviceChanged`, `OnDeviceRequestStateChange`).
    * **What are the assertions?** (The `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_EQ` macros). These are the core of the test, verifying the expected outcomes.

5. **Identify Relationships to Web Technologies:**  Look for keywords and types that hint at connections to JavaScript, HTML, and CSS:
    * **`MediaStream`:** This is a fundamental JavaScript API for accessing media devices. The presence of this term strongly indicates a connection.
    * **Device Enumeration/Selection:**  The tests involve adding and removing media devices. This directly relates to the user selecting cameras and microphones in a browser.
    * **`OnDeviceStopped`, `OnDeviceChanged`, `OnDeviceRequestStateChange`:** These methods suggest events that can happen during a media stream's lifecycle, which are often reflected in the user interface and handled by JavaScript.
    * **`zoom_level`:** This directly corresponds to a camera control that can be manipulated through JavaScript.
    * **Mojo:** The use of Mojo indicates inter-process communication, often used within Chromium to communicate between the renderer (where Blink resides) and the browser process. This is a more internal implementation detail but relevant to understanding how this component fits into the larger system.

6. **Infer Logical Reasoning:** Consider the flow of data and the conditions being tested. For example, in `GetNonScreenCaptureDevices`, the test logic is: open two devices (one regular video, one screen capture), then verify only the regular video device is returned by `GetNonScreenCaptureDevices`. This is a clear logical check based on device types.

7. **Consider Potential User Errors:** Think about how a user interacts with media streams in a browser. What could go wrong from their perspective?  How might the code handle those errors?  The tests that check `OnDeviceStopped` and `OnDeviceChanged` are relevant here – what happens if a device is physically disconnected or becomes unavailable?

8. **Trace User Actions (Debugging Clues):** Imagine a user encountering a problem with their camera. How might their actions lead to this code being executed?  Consider scenarios like:
    * User opens a webpage that requests camera access.
    * User grants or denies permission.
    * User selects a specific camera.
    * User starts or stops the stream.
    * User changes the selected camera.
    * The system detects a device being plugged in or unplugged.

By systematically analyzing the code structure, the test cases, and the terminology used, we can build a comprehensive understanding of the file's purpose and its connections to the broader web platform. The mock objects are key to understanding the boundaries of the unit being tested and its dependencies.
This C++ source code file, `media_stream_device_observer_test.cc`, is a **unit test file** for the `MediaStreamDeviceObserver` class within the Chromium Blink rendering engine. Its primary function is to **verify the correct behavior of the `MediaStreamDeviceObserver` class** through various test scenarios.

Here's a breakdown of its functionality and connections:

**Core Functionality Being Tested:**

The `MediaStreamDeviceObserver` class is responsible for **observing changes in media devices** (like cameras and microphones) and managing the state of media streams within the renderer process. The test file focuses on verifying how this observer handles events such as:

* **Adding new media streams and their associated devices.**
* **Removing media streams and devices.**
* **Device being stopped (e.g., user stops the stream or the device is disconnected).**
* **Device properties changing (e.g., a different camera is selected, or camera settings change).**
* **Device request state changes (e.g., pausing or playing a track).**
* **Zoom level changes on video devices.**

**Relationship to JavaScript, HTML, and CSS:**

While this C++ file doesn't directly contain JavaScript, HTML, or CSS code, it's a crucial part of the underlying implementation that **enables the Web APIs related to media streams**. Here's how it connects:

* **JavaScript `getUserMedia()` API:** When a website uses `navigator.mediaDevices.getUserMedia()` in JavaScript to request access to the user's camera or microphone, this request eventually interacts with components like `MediaStreamDeviceObserver`. The observer helps track which devices are in use and notifies the browser when device availability changes.
    * **Example:** A JavaScript call like `navigator.mediaDevices.getUserMedia({ video: true })` might lead to the creation of a media stream. The `MediaStreamDeviceObserver` would be involved in tracking the selected video device for this stream.
* **JavaScript `MediaStream` and `MediaStreamTrack` APIs:** The `MediaStreamDeviceObserver` manages the underlying device information associated with `MediaStream` and `MediaStreamTrack` objects in JavaScript. When a device is stopped or changed, the observer helps propagate these changes to the JavaScript API.
    * **Example:** If a user has a website using their camera, and they then unplug the camera, the `MediaStreamDeviceObserver` would detect this "device stopped" event. This information would then be conveyed to the JavaScript `MediaStreamTrack`, potentially triggering events that the website can handle.
* **HTML `<video>` and `<audio>` elements:**  While not directly involved in the device observation logic, these elements are where the media streams obtained through JavaScript are typically displayed or played. The `MediaStreamDeviceObserver` ensures that the correct device is associated with the stream being rendered in these elements.
* **CSS:** CSS is not directly related to the core functionality of device observation. However, CSS might be used to style the user interface elements that control media stream interactions (e.g., buttons to start/stop the camera).

**Logical Reasoning with Assumptions and Input/Output:**

Let's take the `TEST_F(MediaStreamDeviceObserverTest, GetNonScreenCaptureDevices)` test as an example of logical reasoning:

* **Assumption:** The `MediaStreamDeviceObserver` can distinguish between regular video capture devices and screen capture devices based on their `MediaStreamType`.
* **Input:**
    1. An "open device" request for a regular video capture device (`DEVICE_VIDEO_CAPTURE`).
    2. An "open device" request for a screen capture device (`GUM_DESKTOP_VIDEO_CAPTURE`).
* **Steps:**
    1. The test simulates these requests using `mock_dispatcher_host_.OpenDevice()`.
    2. The `OnDeviceOpened` callback adds these devices to the observer's internal tracking.
    3. The test calls `observer_->GetNonScreenCaptureDevices()`.
* **Expected Output:** The `GetNonScreenCaptureDevices()` method should return a list containing only the regular video capture device, not the screen capture device. The `EXPECT_EQ` assertions verify this.

**User and Programming Usage Errors:**

While this test file doesn't directly expose user-facing errors, it helps prevent programming errors within the Blink engine. Here are some potential issues the `MediaStreamDeviceObserver` (and thus these tests) helps avoid:

* **Incorrectly tracking device state:** If the observer doesn't correctly track which devices are active for which streams, it could lead to issues like:
    * Trying to use a device that has been stopped.
    * Not releasing a device when a stream is closed, potentially blocking other applications.
    * Incorrectly notifying web pages about device changes.
* **Race conditions:**  Device availability and state can change asynchronously. The observer needs to handle these changes correctly to avoid race conditions where different parts of the code have inconsistent views of the device state.
* **Memory leaks:**  The observer needs to properly manage the lifecycle of the media stream and device objects it tracks. Failing to do so could lead to memory leaks.

**User Operation Steps Leading Here (Debugging Clues):**

Imagine a user is on a website using their webcam for a video call, and they encounter a problem. Here's how their actions might lead to the execution of code related to `MediaStreamDeviceObserver`:

1. **User opens a website:** The browser loads the HTML, CSS, and JavaScript for the website.
2. **Website requests camera access:** The JavaScript code calls `navigator.mediaDevices.getUserMedia({ video: true })`.
3. **Browser prompts for permission:** The user is asked to grant permission to use their camera.
4. **User grants permission:**
    * The browser (specifically the browser process) communicates with the renderer process (where Blink and `MediaStreamDeviceObserver` reside).
    * The renderer process and `MediaStreamDeviceObserver` start monitoring available video capture devices.
    * A `MediaStreamTrack` object is created in JavaScript, representing the video stream.
5. **User starts the video call:** The website might start streaming the video obtained from the `MediaStreamTrack`. The `MediaStreamDeviceObserver` is keeping track of the active camera device.
6. **Potential issues and how they might relate to the code:**
    * **Camera suddenly stops working:** This could trigger the `OnDeviceStopped` method in `MediaStreamDeviceObserver`. The test `TEST_F(MediaStreamDeviceObserverTest, OnDeviceStopped)` verifies this scenario.
    * **User selects a different camera:** This could trigger the `OnDeviceChanged` method. The test `TEST_F(MediaStreamDeviceObserverTest, OnDeviceChanged)` verifies how the observer handles device changes.
    * **User mutes/unmutes the video:** This could trigger the `OnDeviceRequestStateChange` method, although typically this is handled at a higher level. The test `TEST_F(MediaStreamDeviceObserverTest, OnDeviceRequestStateChange)` checks this.
    * **User adjusts the camera zoom (if supported):** This could trigger the `OnZoomLevelChange` method. The test `TEST_F(MediaStreamDeviceObserverTest, OnZoomLevelChange)` covers this.

By understanding the user's actions and the potential issues they might encounter, developers can use these tests to ensure that the `MediaStreamDeviceObserver` is robust and handles various scenarios correctly, leading to a better user experience with web-based media applications.

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_device_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/mediastream/media_stream_device_observer.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/mediastream/media_stream_request.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/renderer/modules/mediastream/capture_controller.h"
#include "third_party/blink/renderer/modules/mediastream/mock_mojo_media_stream_dispatcher_host.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class MediaStreamDeviceObserverTest : public ::testing::Test {
 public:
  MediaStreamDeviceObserverTest()
      : observer_(std::make_unique<MediaStreamDeviceObserver>(nullptr)) {}

  void OnDeviceOpened(base::OnceClosure quit_closure,
                      bool success,
                      const String& label,
                      const blink::MediaStreamDevice& device) {
    if (success) {
      stream_label_ = label;
      current_device_ = device;
      observer_->AddStream(label, device);
    }

    std::move(quit_closure).Run();
  }

  void AddStreams(
      const WTF::String& streams_label,
      WebMediaStreamDeviceObserver::OnDeviceStoppedCb device_stopped_callback,
      WebMediaStreamDeviceObserver::OnDeviceRequestStateChangeCb
          request_state_change_callback) {
    WTF::wtf_size_t previous_stream_size = observer_->label_stream_map_.size();
    blink::mojom::blink::StreamDevicesSet stream_devices_set;
    stream_devices_set.stream_devices.push_back(
        blink::mojom::blink::StreamDevices::New(
            std::nullopt,
            MediaStreamDevice(
                blink::mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET,
                "device_0_id", "device_0_name")));
    stream_devices_set.stream_devices.push_back(
        blink::mojom::blink::StreamDevices::New(
            std::nullopt,
            MediaStreamDevice(
                blink::mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET,
                "device_1_id", "device_1_name")));

    observer_->AddStreams(
        streams_label, stream_devices_set,
        {
            .on_device_stopped_cb = device_stopped_callback,
            .on_device_changed_cb = base::DoNothing(),
            .on_device_request_state_change_cb = request_state_change_callback,
            .on_device_capture_configuration_change_cb = base::DoNothing(),
            .on_device_capture_handle_change_cb = base::DoNothing(),
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
            .on_zoom_level_change_cb = base::DoNothing(),
#endif
        });
    EXPECT_EQ(observer_->label_stream_map_.size(), previous_stream_size + 1);
  }

  void CheckStreamDeviceIds(
      const WTF::Vector<MediaStreamDeviceObserver::Stream>& streams,
      const std::vector<std::string>& expected_labels) const {
    EXPECT_EQ(streams.size(), expected_labels.size());
    for (size_t stream_index = 0; stream_index < streams.size();
         ++stream_index) {
      EXPECT_EQ(streams[static_cast<WTF::wtf_size_t>(stream_index)]
                    .video_devices.size(),
                1u);
      EXPECT_EQ(streams[static_cast<WTF::wtf_size_t>(stream_index)]
                    .video_devices[0]
                    .id,
                expected_labels[stream_index]);
    }
  }

  const WTF::Vector<MediaStreamDeviceObserver::Stream>& GetStreams(
      const WTF::String& label) const {
    auto streams_iterator = observer_->label_stream_map_.find(label);
    EXPECT_NE(streams_iterator, observer_->label_stream_map_.end());
    return streams_iterator->value;
  }

  const MediaStreamDeviceObserver::Stream& GetStream(
      const WTF::String& label,
      WTF::wtf_size_t stream_index) const {
    return GetStreams(label)[stream_index];
  }

  void SetupMultiStreams(
      WebMediaStreamDeviceObserver::OnDeviceStoppedCb device_stopped_callback,
      WebMediaStreamDeviceObserver::OnDeviceRequestStateChangeCb
          request_state_change_callback) {
    const WTF::String streams_0_label = "label_0";
    AddStreams(streams_0_label, std::move(device_stopped_callback),
               std::move(request_state_change_callback));
    const WTF::Vector<MediaStreamDeviceObserver::Stream>& streams_0 =
        GetStreams(streams_0_label);
    CheckStreamDeviceIds(streams_0, {"device_0_id", "device_1_id"});
  }

 protected:
  test::TaskEnvironment task_environment_;
  String stream_label_;
  MockMojoMediaStreamDispatcherHost mock_dispatcher_host_;
  std::unique_ptr<MediaStreamDeviceObserver> observer_;
  blink::MediaStreamDevice current_device_;
};

TEST_F(MediaStreamDeviceObserverTest, GetNonScreenCaptureDevices) {
  const int kRequestId1 = 5;
  const int kRequestId2 = 7;

  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  // OpenDevice request 1
  base::RunLoop run_loop1;
  mock_dispatcher_host_.OpenDevice(
      kRequestId1, "device_path",
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
      base::BindOnce(&MediaStreamDeviceObserverTest::OnDeviceOpened,
                     base::Unretained(this), run_loop1.QuitClosure()));
  run_loop1.Run();
  String stream_label1 = stream_label_;

  // OpenDevice request 2
  base::RunLoop run_loop2;
  mock_dispatcher_host_.OpenDevice(
      kRequestId2, "screen_capture",
      blink::mojom::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE,
      base::BindOnce(&MediaStreamDeviceObserverTest::OnDeviceOpened,
                     base::Unretained(this), run_loop2.QuitClosure()));
  run_loop2.Run();
  String stream_label2 = stream_label_;

  EXPECT_EQ(observer_->label_stream_map_.size(), 2u);

  // Only the device with type
  // blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE will be returned.
  blink::MediaStreamDevices video_devices =
      observer_->GetNonScreenCaptureDevices();
  EXPECT_EQ(video_devices.size(), 1u);
  EXPECT_EQ(video_devices[0].type,
            blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE);

  // Close the device from request 2.
  observer_->RemoveStreams(stream_label2);
  EXPECT_TRUE(observer_->GetVideoSessionId(stream_label2).is_empty());

  // Close the device from request 1.
  observer_->RemoveStreams(stream_label1);
  EXPECT_TRUE(observer_->GetVideoSessionId(stream_label1).is_empty());

  // Verify that the request have been completed.
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);
}

TEST_F(MediaStreamDeviceObserverTest, OnDeviceStopped) {
  const int kRequestId = 5;

  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  // OpenDevice request.
  base::RunLoop run_loop1;
  mock_dispatcher_host_.OpenDevice(
      kRequestId, "device_path",
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
      base::BindOnce(&MediaStreamDeviceObserverTest::OnDeviceOpened,
                     base::Unretained(this), run_loop1.QuitClosure()));
  run_loop1.Run();

  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);

  observer_->OnDeviceStopped(stream_label_, current_device_);

  // Verify that the request have been completed.
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);
}

TEST_F(MediaStreamDeviceObserverTest, OnDeviceChanged) {
  const int kRequestId1 = 5;
  const base::UnguessableToken kSessionId = base::UnguessableToken::Create();
  const String example_video_id1 = "fake_video_device1";
  const String example_video_id2 = "fake_video_device2";

  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  // OpenDevice request.
  base::RunLoop run_loop1;
  mock_dispatcher_host_.OpenDevice(
      kRequestId1, example_video_id1,
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
      base::BindOnce(&MediaStreamDeviceObserverTest::OnDeviceOpened,
                     base::Unretained(this), run_loop1.QuitClosure()));
  run_loop1.Run();

  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);
  blink::MediaStreamDevices video_devices =
      observer_->GetNonScreenCaptureDevices();
  EXPECT_EQ(video_devices.size(), 1u);
  EXPECT_EQ(video_devices[0].id, example_video_id1.Utf8());

  // OnDeviceChange request.
  blink::MediaStreamDevice fake_video_device(
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
      example_video_id2.Utf8(), "Fake Video Device");
  fake_video_device.set_session_id(kSessionId);
  observer_->OnDeviceChanged(stream_label_, current_device_, fake_video_device);

  // Verify that the device has been changed to the new |fake_video_device|.
  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);
  video_devices = observer_->GetNonScreenCaptureDevices();
  EXPECT_EQ(video_devices.size(), 1u);
  EXPECT_EQ(video_devices[0].id, example_video_id2.Utf8());
  EXPECT_EQ(video_devices[0].session_id(), kSessionId);

  // Close the device from request.
  observer_->RemoveStreams(stream_label_);
  EXPECT_TRUE(observer_->GetVideoSessionId(stream_label_).is_empty());

  // Verify that the request have been completed.
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);
}

TEST_F(MediaStreamDeviceObserverTest, OnDeviceChangedChangesDeviceAfterRebind) {
  const String kStreamLabel = "stream_label";
  const std::string kDeviceName = "Video Device";
  const blink::mojom::MediaStreamType kDeviceType =
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE;

  // Add a device to the |observer_|, to be changed using OnChangedDevice().
  blink::MediaStreamDevice initial_device(kDeviceType, "initial_device",
                                          kDeviceName);
  observer_->AddStream(kStreamLabel, initial_device);

  // Call the |observer_|'s bind callback and check that its internal
  // |receiver_| is bound.
  mojo::Remote<mojom::blink::MediaStreamDeviceObserver> remote_observer;
  EXPECT_FALSE(observer_->receiver_.is_bound());
  observer_->BindMediaStreamDeviceObserverReceiver(
      remote_observer.BindNewPipeAndPassReceiver());
  EXPECT_TRUE(observer_->receiver_.is_bound());

  // Send an OnDeviceChanged() message using the remote mojo pipe, and verify
  // that the device is changed.
  blink::MediaStreamDevice changed_device =
      blink::MediaStreamDevice(kDeviceType, "video_device-123", kDeviceName);
  remote_observer->OnDeviceChanged(kStreamLabel, initial_device,
                                   changed_device);
  base::RunLoop().RunUntilIdle();
  blink::MediaStreamDevices video_devices =
      observer_->GetNonScreenCaptureDevices();
  ASSERT_EQ(video_devices.size(), 1u);
  EXPECT_EQ(video_devices[0].id, "video_device-123");

  // Reset the remote end of the mojo pipe, then rebind it, and verify that
  // OnDeviceChanged() changes the device after rebind.
  remote_observer.reset();
  observer_->BindMediaStreamDeviceObserverReceiver(
      remote_observer.BindNewPipeAndPassReceiver());
  remote_observer->OnDeviceChanged(
      kStreamLabel, changed_device,
      blink::MediaStreamDevice(kDeviceType, "video_device-456", kDeviceName));
  base::RunLoop().RunUntilIdle();
  video_devices = observer_->GetNonScreenCaptureDevices();
  ASSERT_EQ(video_devices.size(), 1u);
  EXPECT_EQ(video_devices[0].id, "video_device-456");
}

TEST_F(MediaStreamDeviceObserverTest, OnDeviceRequestStateChange) {
  const int kRequestId = 5;

  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  // OpenDevice request.
  base::RunLoop run_loop1;
  mock_dispatcher_host_.OpenDevice(
      kRequestId, "device_path",
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE,
      base::BindOnce(&MediaStreamDeviceObserverTest::OnDeviceOpened,
                     base::Unretained(this), run_loop1.QuitClosure()));
  run_loop1.Run();

  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);

  observer_->OnDeviceRequestStateChange(
      stream_label_, current_device_,
      mojom::blink::MediaStreamStateChange::PAUSE);

  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);

  observer_->OnDeviceRequestStateChange(
      stream_label_, current_device_,
      mojom::blink::MediaStreamStateChange::PLAY);

  EXPECT_EQ(observer_->label_stream_map_.size(), 1u);
}

TEST_F(MediaStreamDeviceObserverTest, MultiCaptureAddAndRemoveStreams) {
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  const WTF::String streams_label = "label_0";
  std::string latest_stopped_device_id;
  SetupMultiStreams(
      /*device_stopped_callback=*/base::BindLambdaForTesting(
          [&latest_stopped_device_id](const MediaStreamDevice& device) {
            latest_stopped_device_id = device.id;
          }),
      /*request_state_change_callback=*/base::DoNothing());

  MediaStreamDevice stopped_device_0(
      blink::mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET,
      "device_0_id", "device_0_name");
  observer_->OnDeviceStopped(streams_label, stopped_device_0);
  const WTF::Vector<MediaStreamDeviceObserver::Stream>& streams =
      GetStreams(streams_label);
  CheckStreamDeviceIds(streams, {"device_1_id"});
  EXPECT_EQ(latest_stopped_device_id, "device_0_id");

  MediaStreamDevice stopped_device_1(
      blink::mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET,
      "device_1_id", "device_1_name");
  observer_->OnDeviceStopped(streams_label, stopped_device_1);
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);
  EXPECT_EQ(latest_stopped_device_id, "device_1_id");
}

TEST_F(MediaStreamDeviceObserverTest, MultiCaptureChangeDeviceRequestState) {
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  const WTF::String streams_label = "label_0";
  std::string latest_changed_device_id;
  blink::mojom::blink::MediaStreamStateChange latest_device_state =
      blink::mojom::blink::MediaStreamStateChange::PAUSE;
  SetupMultiStreams(
      /*device_stopped_callback=*/base::DoNothing(),
      /*request_state_change_callback=*/base::BindLambdaForTesting(
          [&latest_changed_device_id, &latest_device_state](
              const MediaStreamDevice& device,
              const mojom::MediaStreamStateChange new_state) {
            latest_changed_device_id = device.id;
            latest_device_state = new_state;
          }));
  EXPECT_EQ(latest_changed_device_id, "");

  observer_->OnDeviceRequestStateChange(
      streams_label, GetStream(streams_label, 0).video_devices[0],
      blink::mojom::blink::MediaStreamStateChange::PLAY);
  EXPECT_EQ(latest_changed_device_id, "device_0_id");
  EXPECT_EQ(latest_device_state,
            blink::mojom::blink::MediaStreamStateChange::PLAY);

  observer_->OnDeviceRequestStateChange(
      streams_label, GetStream(streams_label, 1).video_devices[0],
      blink::mojom::blink::MediaStreamStateChange::PAUSE);
  EXPECT_EQ(latest_changed_device_id, "device_1_id");
  EXPECT_EQ(latest_device_state,
            blink::mojom::blink::MediaStreamStateChange::PAUSE);
}

TEST_F(MediaStreamDeviceObserverTest, MultiCaptureRemoveStreamDevice) {
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);

  SetupMultiStreams(/*device_stopped_callback=*/base::DoNothing(),
                    /*request_state_change_callback=*/base::DoNothing());

  const WTF::String streams_1_label = "label_1";
  AddStreams(streams_1_label, /*device_stopped_callback=*/base::DoNothing(),
             /*request_state_change_callback=*/base::DoNothing());
  const WTF::Vector<MediaStreamDeviceObserver::Stream>& streams_1 =
      GetStreams(streams_1_label);
  CheckStreamDeviceIds(streams_1, {"device_0_id", "device_1_id"});

  MediaStreamDevice device_0 = streams_1[0].video_devices[0];
  MediaStreamDevice device_1 = streams_1[1].video_devices[0];
  observer_->RemoveStreamDevice(device_0);
  EXPECT_EQ(streams_1.size(), 1u);
  EXPECT_EQ(streams_1[0].video_devices.size(), 1u);
  EXPECT_EQ(streams_1[0].video_devices[0].id, "device_1_id");

  observer_->RemoveStreamDevice(device_1);
  EXPECT_EQ(observer_->label_stream_map_.size(), 0u);
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
TEST_F(MediaStreamDeviceObserverTest, OnZoomLevelChange) {
  const String kStreamLabel = "stream_label";
  blink::MediaStreamDevice device(
      blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE, "device_id",
      "device_name");

  blink::mojom::blink::StreamDevicesSet stream_devices_set;
  stream_devices_set.stream_devices.push_back(
      blink::mojom::blink::StreamDevices::New(std::nullopt, device));
  observer_->AddStreams(
      kStreamLabel, stream_devices_set,
      {
          .on_device_stopped_cb = base::DoNothing(),
          .on_device_changed_cb = base::DoNothing(),
          .on_device_request_state_change_cb = base::DoNothing(),
          .on_device_capture_configuration_change_cb = base::DoNothing(),
          .on_device_capture_handle_change_cb = base::DoNothing(),
          .on_zoom_level_change_cb = base::BindRepeating(
              [](const MediaStreamDevice& device, int zoom_level) {
                EXPECT_EQ(device.type,
                          blink::mojom::MediaStreamType::DEVICE_VIDEO_CAPTURE);
                EXPECT_EQ(device.id, "device_id");
                EXPECT_EQ(device.name, "device_name");
                EXPECT_EQ(zoom_level,
                          CaptureController::getSupportedZoomLevels()[0]);
              }),
      });
  static_cast<mojom::blink::MediaStreamDeviceObserver*>(observer_.get())
      ->OnZoomLevelChange(kStreamLabel, device,
                          CaptureController::getSupportedZoomLevels()[0]);
}
#endif

}  // namespace blink

"""

```
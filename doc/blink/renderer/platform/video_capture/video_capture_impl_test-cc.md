Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name `video_capture_impl_test.cc` immediately suggests this is a unit test file for the `VideoCaptureImpl` class. The `_test.cc` suffix is a common convention for test files in Chromium and many other C++ projects.

2. **Scan Includes for Clues:** The included headers provide vital information about the functionalities being tested and the dependencies involved. Keywords like "video_capture," "media," "mojom," "gpu," "shared_memory," and "testing" stand out.

    * `video_capture_impl.h`: This confirms we are testing the implementation of the `VideoCaptureImpl` class.
    * `media/capture/mojom/...`: These include files indicate interaction with the Media Capture service, likely through Mojo interfaces. This suggests asynchronous communication and a client-server model.
    * `gpu/...`:  Suggests testing scenarios involving GPU resources and potentially hardware acceleration.
    * `base/...`:  Indicates the use of Chromium's base library for utilities like task scheduling, memory management, and testing infrastructure.
    * `testing/gmock/gmock.h` and `testing/gtest/gtest.h`:  Confirms the use of Google Mock and Google Test frameworks for setting up test fixtures, defining expectations, and asserting results.
    * `third_party/blink/public/platform/...`: Points to interactions with Blink's platform layer, hinting at integration within the rendering engine.

3. **Look for the Test Fixture:** The class `VideoCaptureImplTest` inheriting from `::testing::Test` is the test fixture. This class sets up the environment for each test case.

4. **Analyze Member Variables:**  The member variables of the test fixture are crucial:

    * `video_capture_impl_`: This is the instance of the class being tested.
    * `mock_video_capture_host_`: A mock object implementing the `media::mojom::blink::VideoCaptureHost` interface. This is key for isolating the `VideoCaptureImpl` and controlling the behavior of its dependencies. The "Mock" prefix is a strong indicator.
    * `params_small_`, `params_large_`:  Represent different video capture parameters, suggesting tests with varying configurations.
    * `task_environment_`:  Used for controlling the execution of asynchronous tasks, essential for testing asynchronous operations.
    * `platform_`: Likely related to simulating platform-specific behavior, possibly concerning GPU integration.

5. **Examine Mock Objects and Actions:** The `MockMojoVideoCaptureHost` class is vital. It defines mocked methods that `VideoCaptureImpl` interacts with. Pay attention to the `EXPECT_CALL` statements within the test cases. These specify the expected interactions with the mock object. Actions like `InvokeWithoutArgs`, `SaveArg`, and `DoNothing` control the mocked behavior.

6. **Study Test Cases (TEST_F Macros):** Each `TEST_F` defines a specific test scenario. Break down each test case into its actions:

    * **Setup:** Initializing the test environment (e.g., creating the `VideoCaptureImpl`, setting up mocks).
    * **Stimulus:**  Calling methods on the `VideoCaptureImpl` (e.g., `StartCapture`, `StopCapture`, `OnNewBuffer`).
    * **Expectations:** Using `EXPECT_CALL` to verify interactions with the mock host and `EXPECT_...` assertions to check the state of the `VideoCaptureImpl` or the results of callbacks.
    * **Verification:**  Checking the outcomes using assertions.

7. **Identify Key Functionalities Being Tested:** Based on the test case names and the actions within them, create a list of the functionalities being tested:

    * Starting and stopping capture.
    * Handling different capture parameters.
    * Getting supported and in-use device formats.
    * Receiving and processing video buffers (shared memory, read-only shared memory, GPU memory buffers).
    * Handling frame drops.
    * Handling errors and state changes.
    * Dealing with buffers received after stopping.
    * Handling cases where capture is already started.
    * Testing timeouts during the start process.
    * Testing scenarios where errors occur before or during startup.
    * Testing fallback mechanisms for GPU memory buffers.
    * Testing specific platform error handling (Windows).

8. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how these functionalities relate to web APIs:

    * **`getUserMedia()`:** The core JavaScript API for accessing camera and microphone. This test file is testing the underlying implementation within Blink that supports `getUserMedia()`.
    * **`<video>` element:**  The captured video frames are ultimately rendered in a `<video>` element. The tested code is responsible for getting those frames to the renderer.
    * **Media Streams API:** The broader set of APIs that `getUserMedia()` belongs to.

9. **Logical Reasoning (Input/Output):**  For each test case, think about the input to the `VideoCaptureImpl` (e.g., `StartCapture` with specific parameters, `OnNewBuffer` with a buffer) and the expected output or side effects (e.g., calls to the mock host, state changes, callbacks invoked). While the tests are explicit, try to generalize the patterns.

10. **Common Usage Errors:**  Think about how developers using the corresponding JavaScript APIs might misuse them or encounter issues. The test cases often implicitly cover these:

    * Starting capture multiple times without stopping.
    * Not handling errors correctly.
    * Relying on specific timing of asynchronous events.

11. **Structure and Organization:** Note the clear structure of the test file: includes, mock class, test fixture, and individual test cases. This reflects good testing practices.

By following these steps, you can systematically analyze a C++ test file like this and extract its essential information, even without deep knowledge of the specific codebase. The key is to focus on the structure, the purpose of the different components, and the interactions being tested.
这个文件是 Chromium Blink 引擎中 `VideoCaptureImpl` 类的单元测试文件。它的主要功能是测试 `VideoCaptureImpl` 类的各种行为和状态转换，以确保视频捕获功能的正确性和稳定性。

以下是它功能的详细列表，并解释了它与 JavaScript, HTML, CSS 的关系，以及逻辑推理、用户/编程常见错误示例：

**功能列表:**

1. **启动和停止视频捕获:**
   - 测试在不同参数下启动 (`StartCapture`) 和停止 (`StopCapture`) 视频捕获流程。
   - 验证与 `media::mojom::blink::VideoCaptureHost` 的交互，例如调用 `DoStart` 和 `Stop` 方法。
   - 验证 `VideoCaptureImpl` 的状态转换（例如，从 `STOPPED` 到 `STARTED`）。

2. **处理不同的视频捕获参数:**
   - 测试使用不同 `media::VideoCaptureParams` (例如，不同的分辨率) 启动捕获。
   - 验证不同的参数是否正确传递给 `media::mojom::blink::VideoCaptureHost`。

3. **获取设备支持的格式:**
   - 测试请求获取设备支持的视频格式 (`GetDeviceSupportedFormats`) 的流程。
   - 验证是否调用了 `media::mojom::blink::VideoCaptureHost` 的 `GetDeviceSupportedFormatsMock` 方法。
   - 验证回调函数 `OnDeviceSupportedFormats` 是否被正确调用。

4. **获取设备正在使用的格式:**
   - 测试请求获取设备当前正在使用的视频格式 (`GetDeviceFormatsInUse`) 的流程。
   - 验证是否调用了 `media::mojom::blink::VideoCaptureHost` 的 `GetDeviceFormatsInUseMock` 方法。
   - 验证回调函数 `OnDeviceFormatsInUse` 是否被正确调用。

5. **接收和处理视频缓冲区:**
   - 测试接收不同类型的视频缓冲区 (`OnNewBuffer`)：共享内存 (`UnsafeSharedMemoryRegion`)、只读共享内存 (`ReadOnlySharedMemoryRegion`)、GPU 内存缓冲区 (`gfx::GpuMemoryBufferHandle`)。
   - 测试接收到就绪的缓冲区 (`OnBufferReady`) 后，是否会调用帧就绪回调 (`OnFrameReady`)。
   - 测试在停止捕获后接收到缓冲区时，是否会释放缓冲区 (`ReleaseBuffer`)。

6. **处理帧丢失:**
   - 测试 `OnFrameDropped` 方法是否被正确调用，并通知监听器。

7. **处理状态变化和错误:**
   - 测试接收到状态变化通知 (`OnStateChanged`) 后，`VideoCaptureImpl` 的状态是否正确更新。
   - 测试处理不同错误状态（例如，`ENDED`, `ERROR`, 特定平台错误）的流程。
   - 测试捕获启动超时的情况。

8. **处理缓冲区在启动前接收到的情况:**
   - 测试在 `VideoCaptureImpl` 收到 "started" 状态之前接收到缓冲区的情况，验证是否会先释放缓冲区，并在启动后请求刷新帧。

9. **测试并发场景:**
   - 测试多个客户端同时或顺序启动/停止捕获的情况。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件位于 Blink 渲染引擎的底层，它直接支持 Web 平台提供的视频捕获 API，主要是 `getUserMedia()`。

* **JavaScript:** `getUserMedia()` 是 JavaScript 中用于请求访问用户摄像头和麦克风的 API。当 JavaScript 代码调用 `getUserMedia()` 时，浏览器内部会调用 Blink 引擎中相应的 C++ 代码，最终会涉及到 `VideoCaptureImpl` 的创建和操作。这个测试文件测试的就是 `VideoCaptureImpl` 如何响应这些 JavaScript 请求。
* **HTML:**  HTML 中的 `<video>` 元素用于展示捕获到的视频流。`VideoCaptureImpl` 负责捕获视频数据，并将其传递给渲染引擎，最终渲染到 `<video>` 元素上。
* **CSS:** CSS 可以用于样式化 `<video>` 元素，但与 `VideoCaptureImpl` 的核心功能没有直接关系。`VideoCaptureImpl` 主要负责数据捕获和管理，不涉及 UI 渲染。

**举例说明:**

假设以下 JavaScript 代码：

```javascript
navigator.mediaDevices.getUserMedia({ video: true })
  .then(function(stream) {
    const video = document.querySelector('video');
    video.srcObject = stream;
    video.play();
  })
  .catch(function(err) {
    console.log("发生错误: " + err);
  });
```

当这段代码执行时，浏览器内部会发生以下与 `VideoCaptureImpl` 相关的活动：

1. Blink 接收到来自 JavaScript 的 `getUserMedia` 请求。
2. 创建一个 `VideoCaptureImpl` 实例（或重用现有的实例）。
3. `VideoCaptureImpl` 通过 `MockMojoVideoCaptureHost` (在测试中) 或实际的 Mojo 接口与浏览器进程中的视频捕获服务进行通信。
4. `VideoCaptureImpl` 调用 `DoStart` 方法，通知浏览器进程开始捕获视频。
5. 浏览器进程开始从摄像头捕获视频帧，并将缓冲区数据发送回 Blink。
6. `VideoCaptureImpl` 的 `OnNewBuffer` 和 `OnBufferReady` 方法被调用，处理接收到的视频缓冲区。
7. `VideoCaptureImpl` 将视频帧数据传递给渲染引擎。
8. 渲染引擎将视频帧渲染到 HTML 中的 `<video>` 元素上。

**逻辑推理 (假设输入与输出):**

**场景 1: 启动捕获**

* **假设输入:**  JavaScript 调用 `getUserMedia({ video: true })`，触发 `VideoCaptureImpl::StartCapture`，并传入 `params_small_`。
* **预期输出:**
    * `mock_video_capture_host_` 的 `DoStart` 方法被调用，传入正确的设备 ID、会话 ID 和 `params_small_`。
    * `OnStateUpdate` 回调被调用，状态为 `blink::VIDEO_CAPTURE_STATE_STARTED`。
    * 如果之后接收到视频帧，`OnFrameReady` 回调会被调用。

**场景 2: 接收到缓冲区**

* **假设输入:**  `VideoCaptureImpl` 处于 `STARTED` 状态，并接收到 `SimulateBufferReceived` 传递的 `BufferDescription`。
* **预期输出:**
    * `OnFrameReady` 回调被调用，传入包含视频帧数据的 `media::VideoFrame` 和时间戳。

**场景 3: 停止捕获后接收到缓冲区**

* **假设输入:**  `VideoCaptureImpl` 已经调用 `StopCapture`，但之后又接收到 `SimulateBufferReceived` 传递的 `BufferDescription`。
* **预期输出:**
    * `OnFrameReady` 回调**不会**被调用。
    * `mock_video_capture_host_` 的 `ReleaseBuffer` 方法被调用，释放该缓冲区。

**用户或编程常见的使用错误示例:**

1. **多次调用 `getUserMedia` 而不关闭之前的流:**  这可能导致资源泄漏或意外行为。测试中的 `TwoClientsInSequence` 和 `AlreadyStarted` 测试就覆盖了这种情况，验证 `VideoCaptureImpl` 能正确处理。
2. **没有正确处理 `getUserMedia` 的 Promise 失败情况:** 如果用户拒绝权限或摄像头不可用，`getUserMedia` 会返回一个 rejected Promise。开发者需要妥善处理这些错误。测试中的错误处理场景（例如，`ErrorBeforeStop`, `ErrorBeforeStart`) 模拟了这些情况。
3. **在视频捕获启动完成之前就尝试操作视频流:** 例如，在 `getUserMedia` 的 Promise resolve 之前就尝试播放视频。测试中的 `BufferReceivedBeforeOnStarted` 模拟了缓冲区在启动完成前到达的情况，验证 `VideoCaptureImpl` 的处理逻辑，避免 race condition。
4. **忘记调用 `stream.getTracks().forEach(track => track.stop())` 来释放摄像头资源:** 这会导致摄像头被占用，影响其他应用使用。虽然这个测试文件不直接测试 JavaScript API 的使用，但它通过测试 `VideoCaptureImpl` 的 `StopCapture` 行为，确保了底层资源的释放。
5. **假设视频捕获总是能成功启动:**  由于各种原因（权限被拒绝、摄像头故障等），视频捕获可能启动失败。测试中的启动超时 (`StartTimeout`) 和启动前错误 (`ErrorBeforeStart`) 覆盖了这些场景。

总而言之，`blink/renderer/platform/video_capture/video_capture_impl_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中视频捕获功能的核心组件 `VideoCaptureImpl` 的正确性和健壮性，从而为 Web 平台上可靠的 `getUserMedia` API 提供了保障。

Prompt: 
```
这是目录为blink/renderer/platform/video_capture/video_capture_impl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/video_capture/video_capture_impl.h"

#include <stddef.h>

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/read_only_shared_memory_region.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/token.h"
#include "build/build_config.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/shared_image_capabilities.h"
#include "media/capture/mojom/video_capture.mojom-blink.h"
#include "media/capture/mojom/video_capture_buffer.mojom-blink.h"
#include "media/capture/mojom/video_capture_types.mojom-blink.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"
#include "third_party/blink/renderer/platform/video_capture/gpu_memory_buffer_test_support.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Mock;
using ::testing::SaveArg;
using ::testing::WithArgs;

namespace blink {

void RunEmptyFormatsCallback(
    media::mojom::blink::VideoCaptureHost::GetDeviceSupportedFormatsCallback&
        callback) {
  Vector<media::VideoCaptureFormat> formats;
  std::move(callback).Run(formats);
}

ACTION(DoNothing) {}

// Mock implementation of the Mojo Host service.
class MockMojoVideoCaptureHost : public media::mojom::blink::VideoCaptureHost {
 public:
  MockMojoVideoCaptureHost() : released_buffer_count_(0) {
    ON_CALL(*this, GetDeviceSupportedFormatsMock(_, _, _))
        .WillByDefault(WithArgs<2>(Invoke(RunEmptyFormatsCallback)));
    ON_CALL(*this, GetDeviceFormatsInUseMock(_, _, _))
        .WillByDefault(WithArgs<2>(Invoke(RunEmptyFormatsCallback)));
    ON_CALL(*this, ReleaseBuffer(_, _, _))
        .WillByDefault(InvokeWithoutArgs(
            this, &MockMojoVideoCaptureHost::increase_released_buffer_count));
  }
  MockMojoVideoCaptureHost(const MockMojoVideoCaptureHost&) = delete;
  MockMojoVideoCaptureHost& operator=(const MockMojoVideoCaptureHost&) = delete;

  // Start() can't be mocked directly due to move-only |observer|.
  void Start(const base::UnguessableToken& device_id,
             const base::UnguessableToken& session_id,
             const media::VideoCaptureParams& params,
             mojo::PendingRemote<media::mojom::blink::VideoCaptureObserver>
                 observer) override {
    DoStart(device_id, session_id, params);
  }
  MOCK_METHOD3(DoStart,
               void(const base::UnguessableToken&,
                    const base::UnguessableToken&,
                    const media::VideoCaptureParams&));
  MOCK_METHOD1(Stop, void(const base::UnguessableToken&));
  MOCK_METHOD1(Pause, void(const base::UnguessableToken&));
  MOCK_METHOD3(Resume,
               void(const base::UnguessableToken&,
                    const base::UnguessableToken&,
                    const media::VideoCaptureParams&));
  MOCK_METHOD1(RequestRefreshFrame, void(const base::UnguessableToken&));
  MOCK_METHOD3(ReleaseBuffer,
               void(const base::UnguessableToken&,
                    int32_t,
                    const media::VideoCaptureFeedback&));
  MOCK_METHOD3(GetDeviceSupportedFormatsMock,
               void(const base::UnguessableToken&,
                    const base::UnguessableToken&,
                    GetDeviceSupportedFormatsCallback&));
  MOCK_METHOD3(GetDeviceFormatsInUseMock,
               void(const base::UnguessableToken&,
                    const base::UnguessableToken&,
                    GetDeviceFormatsInUseCallback&));
  MOCK_METHOD2(OnFrameDropped,
               void(const base::UnguessableToken&,
                    media::VideoCaptureFrameDropReason));
  MOCK_METHOD2(OnLog, void(const base::UnguessableToken&, const String&));

  void GetDeviceSupportedFormats(
      const base::UnguessableToken& arg1,
      const base::UnguessableToken& arg2,
      GetDeviceSupportedFormatsCallback arg3) override {
    GetDeviceSupportedFormatsMock(arg1, arg2, arg3);
  }

  void GetDeviceFormatsInUse(const base::UnguessableToken& arg1,
                             const base::UnguessableToken& arg2,
                             GetDeviceFormatsInUseCallback arg3) override {
    GetDeviceFormatsInUseMock(arg1, arg2, arg3);
  }

  int released_buffer_count() const { return released_buffer_count_; }
  void increase_released_buffer_count() { released_buffer_count_++; }

 private:
  int released_buffer_count_;
};

// This class encapsulates a VideoCaptureImpl under test and the necessary
// accessory classes, namely:
// - a MockMojoVideoCaptureHost, mimicking the RendererHost;
// - a few callbacks that are bound when calling operations of VideoCaptureImpl
//  and on which we set expectations.
class VideoCaptureImplTest : public ::testing::Test {
 public:
  struct BufferDescription {
    BufferDescription(
        int buffer_id,
        gfx::Size size,
        media::VideoPixelFormat pixel_format = media::PIXEL_FORMAT_I420)
        : buffer_id(buffer_id),
          size(std::move(size)),
          pixel_format(pixel_format) {}

    media::mojom::blink::ReadyBufferPtr ToReadyBuffer(
        const base::TimeTicks now) const {
      media::mojom::blink::VideoFrameInfoPtr info =
          media::mojom::blink::VideoFrameInfo::New();
      media::VideoFrameMetadata metadata;
      metadata.reference_time = now;
      info->timestamp = now - base::TimeTicks();
      info->pixel_format = pixel_format;
      info->coded_size = size;
      info->visible_rect = gfx::Rect(size);
      info->color_space = gfx::ColorSpace();
      info->metadata = metadata;
      return media::mojom::blink::ReadyBuffer::New(buffer_id, std::move(info));
    }

    int buffer_id;
    gfx::Size size;
    media::VideoPixelFormat pixel_format;
  };

  VideoCaptureImplTest()
      : video_capture_impl_(new VideoCaptureImpl(
            session_id_,
            scheduler::GetSingleThreadTaskRunnerForTesting(),
            GetEmptyBrowserInterfaceBroker())) {
    params_small_.requested_format = media::VideoCaptureFormat(
        gfx::Size(176, 144), 30, media::PIXEL_FORMAT_I420);
    params_large_.requested_format = media::VideoCaptureFormat(
        gfx::Size(320, 240), 30, media::PIXEL_FORMAT_I420);

    video_capture_impl_->SetVideoCaptureHostForTesting(
        &mock_video_capture_host_);

    ON_CALL(mock_video_capture_host_, DoStart(_, _, _))
        .WillByDefault(InvokeWithoutArgs([this]() {
          video_capture_impl_->OnStateChanged(
              media::mojom::blink::VideoCaptureResult::NewState(
                  media::mojom::VideoCaptureState::STARTED));
        }));

    platform_->SetGpuCapabilities(&fake_capabilities_);

    video_capture_impl_->SetGpuMemoryBufferSupportForTesting(
        std::make_unique<FakeGpuMemoryBufferSupport>());
  }
  VideoCaptureImplTest(const VideoCaptureImplTest&) = delete;
  VideoCaptureImplTest& operator=(const VideoCaptureImplTest&) = delete;

 protected:
  // These four mocks are used to create callbacks for the different operations.
  MOCK_METHOD2(OnFrameReady,
               void(scoped_refptr<media::VideoFrame>, base::TimeTicks));
  MOCK_METHOD1(OnFrameDropped, void(media::VideoCaptureFrameDropReason));
  MOCK_METHOD1(OnStateUpdate, void(VideoCaptureState));
  MOCK_METHOD1(OnDeviceFormatsInUse,
               void(const Vector<media::VideoCaptureFormat>&));
  MOCK_METHOD1(OnDeviceSupportedFormats,
               void(const Vector<media::VideoCaptureFormat>&));

  void StartCapture(int client_id, const media::VideoCaptureParams& params) {
    const auto state_update_callback = WTF::BindRepeating(
        &VideoCaptureImplTest::OnStateUpdate, base::Unretained(this));
    const auto frame_ready_callback = WTF::BindRepeating(
        &VideoCaptureImplTest::OnFrameReady, base::Unretained(this));
    const auto frame_dropped_callback = WTF::BindRepeating(
        &VideoCaptureImplTest::OnFrameDropped, base::Unretained(this));

    video_capture_impl_->StartCapture(
        client_id, params, state_update_callback, frame_ready_callback,
        /*sub_capture_target_version_cb=*/base::DoNothing(),
        frame_dropped_callback);
  }

  void StopCapture(int client_id) {
    video_capture_impl_->StopCapture(client_id);
  }

  void SimulateOnBufferCreated(int buffer_id,
                               const base::UnsafeSharedMemoryRegion& region) {
    video_capture_impl_->OnNewBuffer(
        buffer_id, media::mojom::blink::VideoBufferHandle::NewUnsafeShmemRegion(
                       region.Duplicate()));
  }

  void SimulateReadOnlyBufferCreated(int buffer_id,
                                     base::ReadOnlySharedMemoryRegion region) {
    video_capture_impl_->OnNewBuffer(
        buffer_id,
        media::mojom::blink::VideoBufferHandle::NewReadOnlyShmemRegion(
            std::move(region)));
  }

  void SimulateGpuMemoryBufferCreated(int buffer_id,
                                      gfx::GpuMemoryBufferHandle gmb_handle) {
    video_capture_impl_->OnNewBuffer(
        buffer_id,
        media::mojom::blink::VideoBufferHandle::NewGpuMemoryBufferHandle(
            std::move(gmb_handle)));
  }

  void SimulateBufferReceived(BufferDescription buffer_description) {
    video_capture_impl_->OnBufferReady(
        buffer_description.ToReadyBuffer(base::TimeTicks::Now()));
  }

  void SimulateBufferDestroyed(int buffer_id) {
    video_capture_impl_->OnBufferDestroyed(buffer_id);
  }

  void GetDeviceSupportedFormats() {
    video_capture_impl_->GetDeviceSupportedFormats(
        WTF::BindOnce(&VideoCaptureImplTest::OnDeviceSupportedFormats,
                      base::Unretained(this)));
  }

  void GetDeviceFormatsInUse() {
    video_capture_impl_->GetDeviceFormatsInUse(WTF::BindOnce(
        &VideoCaptureImplTest::OnDeviceFormatsInUse, base::Unretained(this)));
  }

  void SetSharedImageCapabilities(bool shared_image_d3d) {
    gpu::SharedImageCapabilities shared_image_caps;
    shared_image_caps.shared_image_d3d = shared_image_d3d;
    platform_->SetSharedImageCapabilities(shared_image_caps);
  }

  const base::UnguessableToken session_id_ = base::UnguessableToken::Create();
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  ScopedTestingPlatformSupport<TestingPlatformSupportForGpuMemoryBuffer>
      platform_;
  std::unique_ptr<VideoCaptureImpl> video_capture_impl_;
  MockMojoVideoCaptureHost mock_video_capture_host_;
  media::VideoCaptureParams params_small_;
  media::VideoCaptureParams params_large_;
  base::test::ScopedFeatureList feature_list_;

  gpu::Capabilities fake_capabilities_;
};

TEST_F(VideoCaptureImplTest, Simple) {
  base::HistogramTester histogram_tester;
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_small_);
  StopCapture(0);

  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartOutcome",
                                      VideoCaptureStartOutcome::kStarted, 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartErrorCode",
                                      media::VideoCaptureError::kNone, 1);
}

TEST_F(VideoCaptureImplTest, TwoClientsInSequence) {
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED))
      .Times(2);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_small_);
  StopCapture(0);
  StartCapture(1, params_small_);
  StopCapture(1);
}

TEST_F(VideoCaptureImplTest, LargeAndSmall) {
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED))
      .Times(2);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_large_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_large_);
  StopCapture(0);
  StartCapture(1, params_small_);
  StopCapture(1);
}

TEST_F(VideoCaptureImplTest, SmallAndLarge) {
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED))
      .Times(2);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_small_);
  StopCapture(0);
  StartCapture(1, params_large_);
  StopCapture(1);
}

// Checks that a request to GetDeviceSupportedFormats() ends up eventually in
// the provided callback.
TEST_F(VideoCaptureImplTest, GetDeviceFormats) {
  EXPECT_CALL(*this, OnDeviceSupportedFormats(_));
  EXPECT_CALL(mock_video_capture_host_,
              GetDeviceSupportedFormatsMock(_, session_id_, _));

  GetDeviceSupportedFormats();
}

// Checks that two requests to GetDeviceSupportedFormats() end up eventually
// calling the provided callbacks.
TEST_F(VideoCaptureImplTest, TwoClientsGetDeviceFormats) {
  EXPECT_CALL(*this, OnDeviceSupportedFormats(_)).Times(2);
  EXPECT_CALL(mock_video_capture_host_,
              GetDeviceSupportedFormatsMock(_, session_id_, _))
      .Times(2);

  GetDeviceSupportedFormats();
  GetDeviceSupportedFormats();
}

// Checks that a request to GetDeviceFormatsInUse() ends up eventually in the
// provided callback.
TEST_F(VideoCaptureImplTest, GetDeviceFormatsInUse) {
  EXPECT_CALL(*this, OnDeviceFormatsInUse(_));
  EXPECT_CALL(mock_video_capture_host_,
              GetDeviceFormatsInUseMock(_, session_id_, _));

  GetDeviceFormatsInUse();
}

TEST_F(VideoCaptureImplTest, BufferReceived) {
  const int kArbitraryBufferId = 11;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
  base::UnsafeSharedMemoryRegion region =
      base::UnsafeSharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(region.IsValid());

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_, ReleaseBuffer(_, kArbitraryBufferId, _))
      .Times(0);

  StartCapture(0, params_small_);
  SimulateOnBufferCreated(kArbitraryBufferId, region);
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size));
  StopCapture(0);
  SimulateBufferDestroyed(kArbitraryBufferId);

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 0);
}

TEST_F(VideoCaptureImplTest, BufferReceived_ReadOnlyShmemRegion) {
  const int kArbitraryBufferId = 11;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
  base::MappedReadOnlyRegion shm =
      base::ReadOnlySharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(shm.IsValid());

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_, ReleaseBuffer(_, kArbitraryBufferId, _))
      .Times(0);

  StartCapture(0, params_small_);
  SimulateReadOnlyBufferCreated(kArbitraryBufferId, std::move(shm.region));
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size));
  StopCapture(0);
  SimulateBufferDestroyed(kArbitraryBufferId);

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 0);
}

TEST_F(VideoCaptureImplTest, BufferReceived_GpuMemoryBufferHandle) {
  const int kArbitraryBufferId = 11;

  // With GpuMemoryBufferHandle, the buffer handle is received on the IO thread
  // and passed to a media thread to create a SharedImage. After the SharedImage
  // is created and wrapped in a video frame, we pass the video frame back to
  // the IO thread to pass to the clients by calling their frame-ready
  // callbacks.
  base::Thread testing_io_thread("TestingIOThread");
  base::WaitableEvent frame_ready_event;
  scoped_refptr<media::VideoFrame> frame;

  SetSharedImageCapabilities(/* shared_image_d3d = */ true);
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _))
      .WillOnce(
          Invoke([&](scoped_refptr<media::VideoFrame> f, base::TimeTicks t) {
            // Hold on a reference to the video frame to emulate that we're
            // actively using the buffer.
            frame = f;
            frame_ready_event.Signal();
          }));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_, ReleaseBuffer(_, kArbitraryBufferId, _))
      .Times(0);

  // The first half of the test: Create and queue the GpuMemoryBufferHandle.
  // VideoCaptureImpl would:
  //   1. create a GpuMemoryBuffer out of the handle on |testing_io_thread|
  //   2. create a SharedImage from the GpuMemoryBuffer on |media_thread_|
  //   3. invoke OnFrameReady callback on |testing_io_thread|
  auto create_and_queue_buffer = [&]() {
    gfx::GpuMemoryBufferHandle gmb_handle;
    gmb_handle.type = gfx::NATIVE_PIXMAP;
    gmb_handle.id = gfx::GpuMemoryBufferId(kArbitraryBufferId);

    StartCapture(0, params_small_);
    SimulateGpuMemoryBufferCreated(kArbitraryBufferId, std::move(gmb_handle));
    SimulateBufferReceived(BufferDescription(
        kArbitraryBufferId, params_small_.requested_format.frame_size,
        media::PIXEL_FORMAT_NV12));
  };

  // The second half of the test: Stop capture and destroy the buffer.
  // Everything should happen on |testing_io_thread| here.
  auto stop_capture_and_destroy_buffer = [&]() {
    StopCapture(0);
    SimulateBufferDestroyed(kArbitraryBufferId);
    // Explicitly destroy |video_capture_impl_| to make sure it's destroyed on
    // the right thread.
    video_capture_impl_.reset();
  };

  testing_io_thread.Start();
  testing_io_thread.task_runner()->PostTask(
      FROM_HERE, base::BindLambdaForTesting(create_and_queue_buffer));

  // Wait until OnFrameReady is called on |testing_io_thread|.
  EXPECT_TRUE(frame_ready_event.TimedWait(base::Seconds(3)));

  testing_io_thread.task_runner()->PostTask(
      FROM_HERE, base::BindLambdaForTesting(stop_capture_and_destroy_buffer));
  testing_io_thread.Stop();

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 0);
}

TEST_F(VideoCaptureImplTest, OnFrameDropped) {
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(*this, OnFrameDropped(_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_small_);
  video_capture_impl_->OnFrameDropped(
      media::VideoCaptureFrameDropReason::kBufferPoolMaxBufferCountExceeded);
  StopCapture(0);
}

TEST_F(VideoCaptureImplTest, BufferReceivedAfterStop) {
  const int kArbitraryBufferId = 12;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_large_.requested_format.frame_size);
  base::UnsafeSharedMemoryRegion region =
      base::UnsafeSharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(region.IsValid());

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _)).Times(0);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_large_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));

  StartCapture(0, params_large_);
  SimulateOnBufferCreated(kArbitraryBufferId, region);
  StopCapture(0);
  // A buffer received after StopCapture() triggers an instant ReleaseBuffer().
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_large_.requested_format.frame_size));
  SimulateBufferDestroyed(kArbitraryBufferId);

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 1);
}

TEST_F(VideoCaptureImplTest, BufferReceivedAfterStop_ReadOnlyShmemRegion) {
  const int kArbitraryBufferId = 12;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_large_.requested_format.frame_size);
  base::MappedReadOnlyRegion shm =
      base::ReadOnlySharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(shm.IsValid());

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _)).Times(0);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_large_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));

  StartCapture(0, params_large_);
  SimulateReadOnlyBufferCreated(kArbitraryBufferId, std::move(shm.region));
  StopCapture(0);
  // A buffer received after StopCapture() triggers an instant ReleaseBuffer().
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_large_.requested_format.frame_size));
  SimulateBufferDestroyed(kArbitraryBufferId);

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 1);
}

TEST_F(VideoCaptureImplTest, BufferReceivedAfterStop_GpuMemoryBufferHandle) {
  const int kArbitraryBufferId = 12;

  gfx::GpuMemoryBufferHandle gmb_handle;
  gmb_handle.type = gfx::NATIVE_PIXMAP;
  gmb_handle.id = gfx::GpuMemoryBufferId(kArbitraryBufferId);

  SetSharedImageCapabilities(/* shared_image_d3d = */ true);
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(*this, OnFrameReady(_, _)).Times(0);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_large_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));

  StartCapture(0, params_large_);
  SimulateGpuMemoryBufferCreated(kArbitraryBufferId, std::move(gmb_handle));
  StopCapture(0);
  // A buffer received after StopCapture() triggers an instant ReleaseBuffer().
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size,
      media::PIXEL_FORMAT_NV12));
  SimulateBufferDestroyed(kArbitraryBufferId);

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 1);
}

TEST_F(VideoCaptureImplTest, AlreadyStarted) {
  base::HistogramTester histogram_tester;

  media::VideoCaptureParams params = {};
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED))
      .Times(2);
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_))
      .WillOnce(DoAll(InvokeWithoutArgs([this]() {
                        video_capture_impl_->OnStateChanged(
                            media::mojom::blink::VideoCaptureResult::NewState(
                                media::mojom::VideoCaptureState::STARTED));
                      }),
                      SaveArg<2>(&params)));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));

  StartCapture(0, params_small_);
  StartCapture(1, params_large_);
  StopCapture(0);
  StopCapture(1);
  DCHECK(params.requested_format == params_small_.requested_format);

  histogram_tester.ExpectTotalCount("Media.VideoCapture.Start", 1);
  histogram_tester.ExpectTotalCount("Media.VideoCapture.StartOutcome", 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartErrorCode",
                                      media::VideoCaptureError::kNone, 1);
}

TEST_F(VideoCaptureImplTest, EndedBeforeStop) {
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));

  StartCapture(0, params_small_);

  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::ENDED));

  StopCapture(0);
}

TEST_F(VideoCaptureImplTest, ErrorBeforeStop) {
  base::HistogramTester histogram_tester;

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_ERROR));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));

  StartCapture(0, params_small_);

  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewErrorCode(
          media::VideoCaptureError::kIntentionalErrorRaisedByUnitTest));

  StopCapture(0);

  histogram_tester.ExpectTotalCount("Media.VideoCapture.Start", 1);
  // Successful start before the error, so StartOutcome is kStarted.
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartOutcome",
                                      VideoCaptureStartOutcome::kStarted, 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartErrorCode",
                                      media::VideoCaptureError::kNone, 1);
}

TEST_F(VideoCaptureImplTest, WinSystemPermissionsErrorUpdatesCorrectState) {
  EXPECT_CALL(*this,
              OnStateUpdate(
                  blink::VIDEO_CAPTURE_STATE_ERROR_SYSTEM_PERMISSIONS_DENIED));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewErrorCode(
          media::VideoCaptureError::kWinMediaFoundationSystemPermissionDenied));

  StartCapture(0, params_small_);
  StopCapture(0);
}

TEST_F(VideoCaptureImplTest, BufferReceivedBeforeOnStarted) {
  const int kArbitraryBufferId = 16;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
  base::UnsafeSharedMemoryRegion region =
      base::UnsafeSharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(region.IsValid());

  InSequence s;
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_))
      .WillOnce(DoNothing());
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));
  StartCapture(0, params_small_);
  SimulateOnBufferCreated(kArbitraryBufferId, region);
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size));

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  // Additional STARTED will cause RequestRefreshFrame a second time.
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  StopCapture(0);
}

TEST_F(VideoCaptureImplTest,
       BufferReceivedBeforeOnStarted_ReadOnlyShmemRegion) {
  const int kArbitraryBufferId = 16;

  const size_t frame_size = media::VideoFrame::AllocationSize(
      media::PIXEL_FORMAT_I420, params_small_.requested_format.frame_size);
  base::MappedReadOnlyRegion shm =
      base::ReadOnlySharedMemoryRegion::Create(frame_size);
  ASSERT_TRUE(shm.IsValid());

  InSequence s;
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_))
      .WillOnce(DoNothing());
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));
  StartCapture(0, params_small_);
  SimulateReadOnlyBufferCreated(kArbitraryBufferId, std::move(shm.region));
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size));

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  // Additional STARTED will cause RequestRefreshFrame a second time.
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  StopCapture(0);
}

TEST_F(VideoCaptureImplTest,
       BufferReceivedBeforeOnStarted_GpuMemoryBufferHandle) {
  const int kArbitraryBufferId = 16;

  gfx::GpuMemoryBufferHandle gmb_handle;
  gmb_handle.type = gfx::NATIVE_PIXMAP;
  gmb_handle.id = gfx::GpuMemoryBufferId(kArbitraryBufferId);

  InSequence s;
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_))
      .WillOnce(DoNothing());
  EXPECT_CALL(mock_video_capture_host_,
              ReleaseBuffer(_, kArbitraryBufferId, _));
  StartCapture(0, params_small_);
  SimulateGpuMemoryBufferCreated(kArbitraryBufferId, std::move(gmb_handle));
  SimulateBufferReceived(BufferDescription(
      kArbitraryBufferId, params_small_.requested_format.frame_size,
      media::PIXEL_FORMAT_NV12));

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  // Additional STARTED will cause RequestRefreshFrame a second time.
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(mock_video_capture_host_, RequestRefreshFrame(_));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));
  Mock::VerifyAndClearExpectations(this);
  Mock::VerifyAndClearExpectations(&mock_video_capture_host_);

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  StopCapture(0);
}

TEST_F(VideoCaptureImplTest, StartTimeout) {
  base::HistogramTester histogram_tester;

  EXPECT_CALL(*this,
              OnStateUpdate(blink::VIDEO_CAPTURE_STATE_ERROR_START_TIMEOUT));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));

  ON_CALL(mock_video_capture_host_, DoStart(_, _, _))
      .WillByDefault(InvokeWithoutArgs([]() {
        // Do nothing.
      }));

  StartCapture(0, params_small_);
  task_environment_.FastForwardBy(VideoCaptureImpl::kCaptureStartTimeout);

  histogram_tester.ExpectTotalCount("Media.VideoCapture.Start", 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartOutcome",
                                      VideoCaptureStartOutcome::kTimedout, 1);
  histogram_tester.ExpectUniqueSample(
      "Media.VideoCapture.StartErrorCode",
      media::VideoCaptureError::kVideoCaptureImplTimedOutOnStart, 1);
}

TEST_F(VideoCaptureImplTest, StartTimeout_FeatureDisabled) {
  base::HistogramTester histogram_tester;
  feature_list_.InitAndDisableFeature(kTimeoutHangingVideoCaptureStarts);

  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  ON_CALL(mock_video_capture_host_, DoStart(_, _, _))
      .WillByDefault(InvokeWithoutArgs([]() {
        // Do nothing.
      }));

  StartCapture(0, params_small_);
  // Wait past the deadline, nothing should happen.
  task_environment_.FastForwardBy(2 * VideoCaptureImpl::kCaptureStartTimeout);

  // Finally callback that the capture has started, should respond.
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewState(
          media::mojom::VideoCaptureState::STARTED));

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  StopCapture(0);

  histogram_tester.ExpectTotalCount("Media.VideoCapture.Start", 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartOutcome",
                                      VideoCaptureStartOutcome::kStarted, 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartErrorCode",
                                      media::VideoCaptureError::kNone, 1);
}

TEST_F(VideoCaptureImplTest, ErrorBeforeStart) {
  base::HistogramTester histogram_tester;

  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_ERROR));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  ON_CALL(mock_video_capture_host_, DoStart(_, _, _))
      .WillByDefault(InvokeWithoutArgs([this]() {
        // Go straight to Failed. Do not pass Go. Do not collect £200.
        video_capture_impl_->OnStateChanged(
            media::mojom::blink::VideoCaptureResult::NewErrorCode(
                media::VideoCaptureError::kIntentionalErrorRaisedByUnitTest));
      }));

  StartCapture(0, params_small_);

  histogram_tester.ExpectTotalCount("Media.VideoCapture.Start", 1);
  histogram_tester.ExpectUniqueSample("Media.VideoCapture.StartOutcome",
                                      VideoCaptureStartOutcome::kFailed, 1);
  histogram_tester.ExpectUniqueSample(
      "Media.VideoCapture.StartErrorCode",
      media::VideoCaptureError::kIntentionalErrorRaisedByUnitTest, 1);
}

#if BUILDFLAG(IS_WIN)
// This is windows-only scenario.
TEST_F(VideoCaptureImplTest, FallbacksToPremappedGmbsWhenNotSupported) {
  const int kArbitraryBufferId = 11;

  // With GpuMemoryBufferHandle, the buffer handle is received on the IO thread
  // and passed to a media thread to create a SharedImage. After the SharedImage
  // is created and wrapped in a video frame, we pass the video frame back to
  // the IO thread to pass to the clients by calling their frame-ready
  // callbacks.
  base::Thread testing_io_thread("TestingIOThread");
  base::WaitableEvent frame_ready_event;
  media::VideoCaptureFeedback feedback;

  SetSharedImageCapabilities(/* shared_image_d3d = */ false);
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STARTED));
  EXPECT_CALL(*this, OnStateUpdate(blink::VIDEO_CAPTURE_STATE_STOPPED));
  EXPECT_CALL(mock_video_capture_host_, DoStart(_, session_id_, params_small_));
  EXPECT_CALL(mock_video_capture_host_, Stop(_));
  EXPECT_CALL(mock_video_capture_host_, ReleaseBuffer(_, kArbitraryBufferId, _))
      .WillOnce(
          Invoke([&](const base::UnguessableToken& device_id, int32_t buffer_id,
                     const media::VideoCaptureFeedback& fb) {
            // Hold on a reference to the video frame to emulate that we're
            // actively using the buffer.
            feedback = fb;
            frame_ready_event.Signal();
          }));

  // The first half of the test: Create and queue the GpuMemoryBufferHandle.
  // VideoCaptureImpl would:
  //   1. create a GpuMemoryBuffer out of the handle on |testing_io_thread|
  //   2. create a SharedImage from the GpuMemoryBuffer on |media_thread_|
  //   3. invoke OnFrameReady callback on |testing_io_thread|
  auto create_and_queue_buffer = [&]() {
    gfx::GpuMemoryBufferHandle gmb_handle;
    gmb_handle.type = gfx::NATIVE_PIXMAP;
    gmb_handle.id = gfx::GpuMemoryBufferId(kArbitraryBufferId);

    StartCapture(0, params_small_);
    SimulateGpuMemoryBufferCreated(kArbitraryBufferId, std::move(gmb_handle));
    SimulateBufferReceived(BufferDescription(
        kArbitraryBufferId, params_small_.requested_format.frame_size,
        media::PIXEL_FORMAT_NV12));
  };

  // The second half of the test: Stop capture and destroy the buffer.
  // Everything should happen on |testing_io_thread| here.
  auto stop_capture_and_destroy_buffer = [&]() {
    StopCapture(0);
    SimulateBufferDestroyed(kArbitraryBufferId);
    // Explicitly destroy |video_capture_impl_| to make sure it's destroyed on
    // the right thread.
    video_capture_impl_.reset();
  };

  testing_io_thread.Start();
  testing_io_thread.task_runner()->PostTask(
      FROM_HERE, base::BindLambdaForTesting(create_and_queue_buffer));

  // Wait until OnFrameReady is called on |testing_io_thread|.
  EXPECT_TRUE(frame_ready_event.TimedWait(base::Seconds(3)));

  EXPECT_TRUE(feedback.require_mapped_frame);

  testing_io_thread.task_runner()->PostTask(
      FROM_HERE, base::BindLambdaForTesting(stop_capture_and_destroy_buffer));
  testing_io_thread.Stop();

  EXPECT_EQ(mock_video_capture_host_.released_buffer_count(), 0);
}
#endif

TEST_F(VideoCaptureImplTest, WinCameraBusyErrorUpdatesCorrectState) {
  EXPECT_CALL(*this,
              OnStateUpdate(blink::VIDEO_CAPTURE_STATE_ERROR_CAMERA_BUSY));
  video_capture_impl_->OnStateChanged(
      media::mojom::blink::VideoCaptureResult::NewErrorCode(
          media::VideoCaptureError::kWinMediaFoundationCameraBusy));

  StartCapture(0, params_small_);
  StopCapture(0);
}

}  // namespace blink

"""

```
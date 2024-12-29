Response:
The user is asking for a summary of the functionality of the provided C++ source code file `peer_connection_dependency_factory.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The file name itself, `peer_connection_dependency_factory.cc`, strongly suggests that this code is responsible for creating and managing dependencies for the WebRTC PeerConnection implementation in Chromium. The term "factory" is a common design pattern for creating objects.

2. **Scan the includes:**  The included header files provide clues about the functionalities involved. Keywords like "peerconnection", "webrtc", "mediastream", "p2p", "audio", "video", "network", and "platform" are highly relevant.

3. **Look for key classes and methods:** The code defines a class `PeerConnectionDependencyFactory`. The presence of methods like `CreateRTCPeerConnectionHandler`, `GetPcFactory`, and `CreatePeerConnectionFactory` reinforces the factory idea. The `StaticDeps` class suggests management of global, process-wide dependencies.

4. **Analyze the `CreatePeerConnectionFactory` method:** This method seems crucial for setting up the WebRTC infrastructure. It initializes threads (signaling, worker, network), sets up SSL, creates network managers, and ultimately creates the `webrtc::PeerConnectionFactoryInterface`.

5. **Examine the dependencies:**  The code initializes various factories like `AudioEncoderFactory`, `AudioDecoderFactory`, `VideoEncoderFactory`, and `VideoDecoderFactory`. This confirms its role in setting up the media processing pipeline. The inclusion of `IpcPacketSocketFactory` and `MdnsResponderAdapter` indicates involvement in networking and local IP address handling.

6. **Consider threading:** The code explicitly manages different threads for signaling, network, and worker tasks. This is a key characteristic of WebRTC and needs to be mentioned in the summary.

7. **Identify relationships with web technologies:**  The inclusion of headers like `third_party/blink/public/web/` hints at the integration with the Blink rendering engine and its interaction with JavaScript APIs (`RTCPeerConnectionHandler`).

8. **Infer potential user impact:** While the C++ code itself isn't directly interacted with by users, it underpins the functionality of the WebRTC API. Therefore, its correctness and efficiency impact the performance and reliability of WebRTC-based web applications.

9. **Formulate the summary:** Based on the above analysis, construct a concise summary highlighting the core responsibilities of the `PeerConnectionDependencyFactory`. Emphasize its role as a central point for creating and managing WebRTC components and its crucial role in enabling PeerConnection functionality within the Blink rendering engine. Mention the management of threads and the creation of various factories.
## 功能归纳：blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc (第 1 部分)

这个文件的主要功能是**创建一个工厂类 `PeerConnectionDependencyFactory`，负责管理和创建 WebRTC PeerConnection 功能所需的各种依赖项**。

更具体地说，它负责：

1. **管理 WebRTC 的线程模型：**
   - 创建和管理 WebRTC 使用的独立线程，包括 **Signaling 线程**、**Worker 线程**和 **Network 线程**。
   - 确保这些线程的初始化和启动。
   - 提供获取这些线程对象的接口。
   - 收集和记录这些线程上的任务延迟和执行时间。

2. **创建和持有 WebRTC PeerConnection 工厂 (`webrtc::PeerConnectionFactoryInterface`)：**
   - 这是创建 `RTCPeerConnection` 对象的核心组件。
   - 文件中包含了创建和初始化这个工厂的逻辑，包括设置音视频编解码器工厂、音频设备模块（ADM）、事件日志工厂等。

3. **创建网络相关的组件：**
   - 创建 `IpcPacketSocketFactory` 用于创建网络套接字。
   - 根据配置创建 `FilteringNetworkManager` 或 `IpcNetworkManager` 来管理网络连接。
   - 可能创建 `MdnsResponderAdapter` 来处理 mDNS 以隐藏本地 IP 地址。

4. **创建音视频相关的组件：**
   - 使用 `blink::CreateWebrtcAudioEncoderFactory` 和 `blink::CreateWebrtcAudioDecoderFactory` 创建音频编解码器工厂。
   - 使用 `blink::CreateWebrtcVideoEncoderFactory` 和 `blink::CreateWebrtcVideoDecoderFactory` 创建视频编解码器工厂。这些工厂可能会使用 GPU 加速。
   - 管理 `WebRtcAudioDeviceImpl` 作为音频设备模块。
   - 管理视频性能报告器 `WebrtcVideoPerfReporter` 来收集和上报视频编码和解码的性能数据。
   - 管理用于音视频同步的节拍器 (`Metronome`)。

5. **提供创建 `RTCPeerConnectionHandler` 的接口：**
   - `RTCPeerConnectionHandler` 是 Blink 渲染引擎中 `RTCPeerConnection` JavaScript API 的实现后端。
   - 工厂类负责创建 `RTCPeerConnectionHandler` 实例，并注入所需的依赖项。

6. **处理 WebRTC 的全局初始化：**
   - 初始化 SSL。
   - 根据 Feature Flag 决定是否禁用 H.264 支持。

7. **与 Chromium 基础设施集成：**
   - 使用 Blink 提供的平台抽象层 (`Platform::Current()`)。
   - 使用 Chromium 的线程和任务运行器 (`base::Thread`, `base::SingleThreadTaskRunner`)。
   - 使用 Chromium 的 Feature Flag 机制来控制某些功能的启用和禁用。
   - 通过 Mojo 与浏览器进程进行通信，获取例如视频编码器性能指标提供器等服务。

8. **提供 DevTools 集成支持：**
    - 提供获取 DevTools Token 的机制，可能用于调试 WebRTC 连接。

**与 javascript, html, css 的关系举例说明：**

- **JavaScript:** 当 JavaScript 代码调用 `new RTCPeerConnection()` 时，Blink 渲染引擎会最终调用到 `PeerConnectionDependencyFactory::CreateRTCPeerConnectionHandler` 方法，创建一个 `RTCPeerConnectionHandler` 的实例来处理 JavaScript 的请求。
  ```javascript
  // JavaScript 代码
  const pc = new RTCPeerConnection();
  ```
  这里的 `PeerConnectionDependencyFactory` 负责提供创建这个 `pc` 对象背后 C++ 实现所需的各种组件。

- **HTML:** HTML 中可能包含触发创建 `RTCPeerConnection` 的 JavaScript 代码，例如在一个按钮的点击事件中。
  ```html
  <button onclick="startPeerConnection()">Start</button>
  <script>
    function startPeerConnection() {
      const pc = new RTCPeerConnection();
      // ... 其他 WebRTC 相关代码
    }
  </script>
  ```
  用户点击按钮的操作会触发 JavaScript 代码的执行，最终导致 `PeerConnectionDependencyFactory` 的参与。

- **CSS:** CSS 本身不直接与 `PeerConnectionDependencyFactory` 交互。但是，CSS 可能会影响 Web 页面布局，从而间接地影响用户何时以及如何触发创建 `RTCPeerConnection` 的 JavaScript 代码。例如，一个隐藏的按钮在用户滚动到特定位置后显示，用户点击该按钮后才创建 `RTCPeerConnection`。

**逻辑推理的假设输入与输出：**

**假设输入：** 用户在 JavaScript 中调用 `new RTCPeerConnection()`。

**输出：**
1. Blink 渲染引擎调用 `PeerConnectionDependencyFactory::CreateRTCPeerConnectionHandler`。
2. `PeerConnectionDependencyFactory` 确保 WebRTC 的线程已启动。
3. `PeerConnectionDependencyFactory` 从其管理的 `pc_factory_` (如果已创建) 获取 `webrtc::PeerConnectionFactoryInterface` 的实例，或者先创建它。
4. `PeerConnectionDependencyFactory` 创建并返回一个 `RTCPeerConnectionHandler` 的实例，并将必要的依赖项（例如 `this` 指针）传递给它。
5. `RTCPeerConnectionHandler` 使用 `webrtc::PeerConnectionFactoryInterface` 创建底层的 `webrtc::PeerConnection` 对象。

**涉及用户或者编程常见的使用错误，举例说明：**

- **错误地在未初始化的上下文中调用 WebRTC API:** 如果 `PeerConnectionDependencyFactory` 相关的上下文（例如 `ExecutionContext`）尚未初始化完成，就尝试创建 `RTCPeerConnection`，可能会导致崩溃或未定义的行为。
  **用户操作:** 用户过早地执行了创建 `RTCPeerConnection` 的 JavaScript 代码，例如在页面加载的早期阶段，Blink 内部的初始化尚未完成。
- **在错误的线程上调用 WebRTC 相关方法:**  WebRTC 的某些操作必须在特定的线程上执行（例如 Signaling 线程）。如果在错误的线程上调用，会导致错误或崩溃。
  **编程错误:** 开发者可能没有正确地使用任务运行器 (`TaskRunner`) 将任务调度到正确的 WebRTC 线程。
- **依赖项缺失或配置错误:** 如果创建 `PeerConnectionFactory` 所需的某些依赖项（例如音频设备）初始化失败或配置错误，可能会导致 `RTCPeerConnection` 创建失败。
  **用户操作:** 这通常不是直接的用户操作错误，而是底层系统配置或浏览器自身的问题。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个包含 WebRTC 功能的网页。**
2. **网页上的 JavaScript 代码执行，可能响应用户的交互（例如点击按钮），调用了 `new RTCPeerConnection()`。**
3. **浏览器内核（Blink 渲染引擎）接收到这个 JavaScript 调用。**
4. **Blink 内部会将这个调用路由到对应的 C++ 实现，即 `modules/peerconnection/` 目录下的相关代码。**
5. **`RTCPeerConnection` 的 JavaScript API 会委托给 `RTCPeerConnectionHandler` 类。**
6. **为了创建 `RTCPeerConnectionHandler` 实例，Blink 会调用 `PeerConnectionDependencyFactory::CreateRTCPeerConnectionHandler`。**
7. **在这个过程中，`PeerConnectionDependencyFactory` 可能会确保 WebRTC 的底层线程和工厂已经初始化。**
8. **如果需要创建 `webrtc::PeerConnectionFactoryInterface`，会执行 `PeerConnectionDependencyFactory::CreatePeerConnectionFactory` 方法。**
9. **在这个方法中，会涉及到创建网络、音频、视频相关的各种子模块。**

**调试线索:**  如果调试 WebRTC 相关的问题，可以从 JavaScript 的 `new RTCPeerConnection()` 调用开始，逐步追踪到 Blink 内部的 C++ 代码，重点关注 `PeerConnectionDependencyFactory` 的创建和依赖项的初始化过程。查看日志输出，特别是关于线程创建、工厂创建和依赖项注入的信息，可以帮助定位问题。

**功能归纳（针对第 1 部分）：**

这个文件的第 1 部分主要定义了 `PeerConnectionDependencyFactory` 类，并包含了**管理 WebRTC 线程模型、创建核心的 `webrtc::PeerConnectionFactoryInterface`、以及初始化网络和部分音视频相关组件**的逻辑。它为后续创建 `RTCPeerConnectionHandler` 奠定了基础，并与 Chromium 的线程模型和 Feature Flag 机制紧密结合。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_forward.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "build/build_config.h"
#include "components/webrtc/thread_wrapper.h"
#include "crypto/openssl_util.h"
#include "media/base/media_permission.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "net/net_buildflags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/peerconnection/webrtc_ip_handling_policy.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_source.h"
#include "third_party/blink/public/web/web_document.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/public/web/web_view.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"
#include "third_party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/modules/mediastream/media_constraints.h"
#include "third_party/blink/renderer/modules/peerconnection/adapters/web_rtc_cross_thread_copier.h"
#include "third_party/blink/renderer/modules/peerconnection/intercepting_network_controller.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_error_util.h"
#include "third_party/blink/renderer/modules/peerconnection/rtc_peer_connection_handler.h"
#include "third_party/blink/renderer/modules/webrtc/webrtc_audio_device_impl.h"
#include "third_party/blink/renderer/platform/graphics/video_frame_sink_bundle.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mediastream/webrtc_uma_histograms.h"
#include "third_party/blink/renderer/platform/mojo/mojo_binding_context.h"
#include "third_party/blink/renderer/platform/p2p/empty_network_manager.h"
#include "third_party/blink/renderer/platform/p2p/filtering_network_manager.h"
#include "third_party/blink/renderer/platform/p2p/ipc_network_manager.h"
#include "third_party/blink/renderer/platform/p2p/ipc_socket_factory.h"
#include "third_party/blink/renderer/platform/p2p/mdns_responder_adapter.h"
#include "third_party/blink/renderer/platform/p2p/port_allocator.h"
#include "third_party/blink/renderer/platform/p2p/socket_dispatcher.h"
#include "third_party/blink/renderer/platform/peerconnection/audio_codec_factory.h"
#include "third_party/blink/renderer/platform/peerconnection/video_codec_factory.h"
#include "third_party/blink/renderer/platform/peerconnection/vsync_provider.h"
#include "third_party/blink/renderer/platform/peerconnection/vsync_tick_provider.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_gfx.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/webrtc/api/enable_media.h"
#include "third_party/webrtc/api/peer_connection_interface.h"
#include "third_party/webrtc/api/rtc_event_log/rtc_event_log_factory.h"
#include "third_party/webrtc/api/transport/goog_cc_factory.h"
#include "third_party/webrtc/api/video_track_source_proxy_factory.h"
#include "third_party/webrtc/media/engine/fake_video_codec_factory.h"
#include "third_party/webrtc/modules/video_coding/codecs/h264/include/h264.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "third_party/webrtc/rtc_base/ssl_adapter.h"
#include "third_party/webrtc_overrides/metronome_source.h"
#include "third_party/webrtc_overrides/task_queue_factory.h"
#include "third_party/webrtc_overrides/timer_based_tick_provider.h"

namespace WTF {
template <>
struct CrossThreadCopier<base::RepeatingCallback<void(base::TimeDelta)>>
    : public CrossThreadCopierPassThrough<
          base::RepeatingCallback<void(base::TimeDelta)>> {
  STATIC_ONLY(CrossThreadCopier);
};
}  // namespace WTF

namespace blink {
namespace {

using PassKey = base::PassKey<PeerConnectionDependencyFactory>;

enum WebRTCIPHandlingPolicy {
  kDefault,
  kDefaultPublicAndPrivateInterfaces,
  kDefaultPublicInterfaceOnly,
  kDisableNonProxiedUdp,
};

WebRTCIPHandlingPolicy GetWebRTCIPHandlingPolicy(const String& preference) {
  if (preference == kWebRTCIPHandlingDefaultPublicAndPrivateInterfaces)
    return kDefaultPublicAndPrivateInterfaces;
  if (preference == kWebRTCIPHandlingDefaultPublicInterfaceOnly)
    return kDefaultPublicInterfaceOnly;
  if (preference == kWebRTCIPHandlingDisableNonProxiedUdp)
    return kDisableNonProxiedUdp;
  return kDefault;
}

bool IsValidPortRange(uint16_t min_port, uint16_t max_port) {
  DCHECK(min_port <= max_port);
  return min_port != 0 && max_port != 0;
}

scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
CreateMojoVideoEncoderMetricsProviderFactory(LocalFrame* local_frame) {
  CHECK(local_frame);
  mojo::PendingRemote<media::mojom::VideoEncoderMetricsProvider>
      video_encoder_metrics_provider;
  local_frame->GetBrowserInterfaceBroker().GetInterface(
      video_encoder_metrics_provider.InitWithNewPipeAndPassReceiver());
  return base::MakeRefCounted<media::MojoVideoEncoderMetricsProviderFactory>(
      media::mojom::VideoEncoderUseCase::kWebRTC,
      std::move(video_encoder_metrics_provider));
}

// PeerConnectionDependencies wants to own the factory, so we provide a simple
// object that delegates calls to the IpcPacketSocketFactory.
// TODO(zstein): Move the creation logic from IpcPacketSocketFactory in to this
// class.
class ProxyAsyncDnsResolverFactory final
    : public webrtc::AsyncDnsResolverFactoryInterface {
 public:
  explicit ProxyAsyncDnsResolverFactory(IpcPacketSocketFactory* ipc_psf)
      : ipc_psf_(ipc_psf) {
    DCHECK(ipc_psf);
  }

  std::unique_ptr<webrtc::AsyncDnsResolverInterface> Create() override {
    return ipc_psf_->CreateAsyncDnsResolver();
  }
  std::unique_ptr<webrtc::AsyncDnsResolverInterface> CreateAndResolve(
      const rtc::SocketAddress& addr,
      absl::AnyInvocable<void()> callback) override {
    auto temp = Create();
    temp->Start(addr, std::move(callback));
    return temp;
  }
  std::unique_ptr<webrtc::AsyncDnsResolverInterface> CreateAndResolve(
      const rtc::SocketAddress& addr,
      int family,
      absl::AnyInvocable<void()> callback) override {
    auto temp = Create();
    temp->Start(addr, family, std::move(callback));
    return temp;
  }

 private:
  raw_ptr<IpcPacketSocketFactory, DanglingUntriaged> ipc_psf_;
};

std::string WorkerThreadName() {
  if (base::FeatureList::IsEnabled(
          features::kWebRtcCombinedNetworkAndWorkerThread)) {
    return "WebRTC_W_and_N";
  }
  return "WebRTC_Worker";
}

// Encapsulates process-wide static dependencies used by
// `PeerConnectionDependencyFactory`, namely the threads used by WebRTC. This
// avoids allocating multiple threads per factory instance, as they are
// "heavy-weight" and we don't want to create them per frame.
class PeerConnectionStaticDeps {
 public:
  PeerConnectionStaticDeps()
      : chrome_signaling_thread_("WebRTC_Signaling"),
        chrome_worker_thread_(WorkerThreadName()) {
    if (!base::FeatureList::IsEnabled(
            features::kWebRtcCombinedNetworkAndWorkerThread)) {
      chrome_network_thread_.emplace("WebRTC_Network");
    }
  }

  ~PeerConnectionStaticDeps() {
    if (chrome_worker_thread_.IsRunning()) {
      chrome_worker_thread_.task_runner()->DeleteSoon(
          FROM_HERE, std::move(decode_metronome_source_));

      if (encode_metronome_source_) {
        chrome_worker_thread_.task_runner()->DeleteSoon(
            FROM_HERE, std::move(encode_metronome_source_));
      }
    }
  }

  std::unique_ptr<webrtc::Metronome> CreateDecodeMetronome() {
    CHECK(decode_metronome_source_);
    return decode_metronome_source_->CreateWebRtcMetronome();
  }

  std::unique_ptr<webrtc::Metronome> MaybeCreateEncodeMetronome() {
    if (encode_metronome_source_) {
      return encode_metronome_source_->CreateWebRtcMetronome();
    } else {
      return nullptr;
    }
  }

  void EnsureVsyncProvider(ExecutionContext& context) {
    if (!vsync_tick_provider_) {
      vsync_provider_.emplace(
          Platform::Current()->VideoFrameCompositorTaskRunner(),
          To<LocalDOMWindow>(context)
              .GetFrame()
              ->GetPage()
              ->GetChromeClient()
              .GetFrameSinkId(To<LocalDOMWindow>(context).GetFrame())
              .client_id());
      vsync_tick_provider_ = VSyncTickProvider::Create(
          *vsync_provider_, chrome_worker_thread_.task_runner(),
          base::MakeRefCounted<TimerBasedTickProvider>(
              features::kVSyncDecodingHiddenOccludedTickDuration.Get()));
    }
  }

  void EnsureChromeThreadsStarted(ExecutionContext& context) {
    base::ThreadType thread_type = base::ThreadType::kDefault;
    if (base::FeatureList::IsEnabled(
            features::kWebRtcThreadsUseResourceEfficientType)) {
      thread_type = base::ThreadType::kResourceEfficient;
    }
    if (!chrome_signaling_thread_.IsRunning()) {
      chrome_signaling_thread_.StartWithOptions(
          base::Thread::Options(thread_type));
    }
    if (chrome_network_thread_ && !chrome_network_thread_->IsRunning()) {
      chrome_network_thread_->StartWithOptions(
          base::Thread::Options(thread_type));
    }

    if (!chrome_worker_thread_.IsRunning()) {
      chrome_worker_thread_.StartWithOptions(
          base::Thread::Options(thread_type));
    }
    // To allow sending to the signaling/worker threads.
    webrtc::ThreadWrapper::EnsureForCurrentMessageLoop();
    webrtc::ThreadWrapper::current()->set_send_allowed(true);
    if (!decode_metronome_source_) {
      if (base::FeatureList::IsEnabled(features::kVSyncDecoding)) {
        EnsureVsyncProvider(context);
        decode_metronome_source_ =
            std::make_unique<MetronomeSource>(vsync_tick_provider_);
      } else {
        auto tick_provider = base::MakeRefCounted<TimerBasedTickProvider>(
            TimerBasedTickProvider::kDefaultPeriod);
        decode_metronome_source_ =
            std::make_unique<MetronomeSource>(std::move(tick_provider));
      }
    }
    if (base::FeatureList::IsEnabled(features::kVSyncEncoding) &&
        !encode_metronome_source_) {
      EnsureVsyncProvider(context);
      encode_metronome_source_ =
          std::make_unique<MetronomeSource>(vsync_tick_provider_);
    }
  }

  base::WaitableEvent& InitializeWorkerThread() {
    if (!worker_thread_) {
      PostCrossThreadTask(
          *chrome_worker_thread_.task_runner(), FROM_HERE,
          CrossThreadBindOnce(
              &PeerConnectionStaticDeps::InitializeOnThread,
              CrossThreadUnretained(&worker_thread_),
              CrossThreadUnretained(&init_worker_event),
              ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                  PeerConnectionStaticDeps::LogTaskLatencyWorker)),
              ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                  PeerConnectionStaticDeps::LogTaskDurationWorker))));
    }
    return init_worker_event;
  }

  base::WaitableEvent& InitializeNetworkThread() {
    if (!network_thread_) {
      if (chrome_network_thread_) {
        PostCrossThreadTask(
            *chrome_network_thread_->task_runner(), FROM_HERE,
            CrossThreadBindOnce(
                &PeerConnectionStaticDeps::InitializeOnThread,
                CrossThreadUnretained(&network_thread_),
                CrossThreadUnretained(&init_network_event),
                ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                    PeerConnectionStaticDeps::LogTaskLatencyNetwork)),
                ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                    PeerConnectionStaticDeps::LogTaskDurationNetwork))));
      } else {
        init_network_event.Signal();
      }
    }
    return init_network_event;
  }

  base::WaitableEvent& InitializeSignalingThread() {
    if (!signaling_thread_) {
      PostCrossThreadTask(
          *chrome_signaling_thread_.task_runner(), FROM_HERE,
          CrossThreadBindOnce(
              &PeerConnectionStaticDeps::InitializeOnThread,
              CrossThreadUnretained(&signaling_thread_),
              CrossThreadUnretained(&init_signaling_event),
              ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                  PeerConnectionStaticDeps::LogTaskLatencySignaling)),
              ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
                  PeerConnectionStaticDeps::LogTaskDurationSignaling))));
    }
    return init_signaling_event;
  }

  rtc::Thread* GetSignalingThread() { return signaling_thread_; }
  rtc::Thread* GetWorkerThread() { return worker_thread_; }
  rtc::Thread* GetNetworkThread() {
    return chrome_network_thread_ ? network_thread_ : worker_thread_;
  }
  base::Thread& GetChromeSignalingThread() { return chrome_signaling_thread_; }
  base::Thread& GetChromeWorkerThread() { return chrome_worker_thread_; }
  base::Thread& GetChromeNetworkThread() {
    return chrome_network_thread_ ? *chrome_network_thread_
                                  : chrome_worker_thread_;
  }

 private:
  static void LogTaskLatencyWorker(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Latency.Worker", sample, base::Microseconds(1),
        base::Seconds(10), 50);
  }
  static void LogTaskDurationWorker(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Duration.Worker", sample, base::Microseconds(1),
        base::Seconds(10), 50);
  }
  static void LogTaskLatencyNetwork(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Latency.Network", sample, base::Microseconds(1),
        base::Seconds(10), 50);
  }
  static void LogTaskDurationNetwork(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Duration.Network", sample, base::Microseconds(1),
        base::Seconds(10), 50);
  }
  static void LogTaskLatencySignaling(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Latency.Signaling", sample,
        base::Microseconds(1), base::Seconds(10), 50);
  }
  static void LogTaskDurationSignaling(base::TimeDelta sample) {
    UMA_HISTOGRAM_CUSTOM_MICROSECONDS_TIMES(
        "WebRTC.PeerConnection.Duration.Signaling", sample,
        base::Microseconds(1), base::Seconds(10), 50);
  }

  static void InitializeOnThread(
      raw_ptr<rtc::Thread>* thread,
      base::WaitableEvent* event,
      base::RepeatingCallback<void(base::TimeDelta)> latency_callback,
      base::RepeatingCallback<void(base::TimeDelta)> duration_callback) {
    webrtc::ThreadWrapper::EnsureForCurrentMessageLoop();
    webrtc::ThreadWrapper::current()->set_send_allowed(true);
    webrtc::ThreadWrapper::current()->SetLatencyAndTaskDurationCallbacks(
        std::move(latency_callback), std::move(duration_callback));
    if (!*thread) {
      *thread = webrtc::ThreadWrapper::current();
      event->Signal();
    }
  }

  // PeerConnection threads. signaling_thread_ is created from the "current"
  // (main) chrome thread.
  raw_ptr<rtc::Thread> signaling_thread_ = nullptr;
  raw_ptr<rtc::Thread> worker_thread_ = nullptr;
  raw_ptr<rtc::Thread> network_thread_ = nullptr;
  base::Thread chrome_signaling_thread_;
  base::Thread chrome_worker_thread_;
  std::optional<base::Thread> chrome_network_thread_;

  // Metronome source used for driving decoding and encoding, created from
  // renderer main thread, always used and destroyed on `chrome_worker_thread_`.
  std::unique_ptr<MetronomeSource> decode_metronome_source_;
  std::unique_ptr<MetronomeSource> encode_metronome_source_;

  // WaitableEvents for observing thread initialization.
  base::WaitableEvent init_signaling_event{
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED};
  base::WaitableEvent init_worker_event{
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED};
  base::WaitableEvent init_network_event{
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED};

  // Generates VSync ticks, these two are always allocated together.
  std::optional<VSyncProviderImpl> vsync_provider_;
  scoped_refptr<MetronomeSource::TickProvider> vsync_tick_provider_;

  THREAD_CHECKER(thread_checker_);
};

PeerConnectionStaticDeps& StaticDeps() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(PeerConnectionStaticDeps, instance, ());
  return instance;
}

rtc::Thread* GetSignalingThread() {
  return StaticDeps().GetSignalingThread();
}
rtc::Thread* GetWorkerThread() {
  return StaticDeps().GetWorkerThread();
}
rtc::Thread* GetNetworkThread() {
  return StaticDeps().GetNetworkThread();
}
base::Thread& GetChromeSignalingThread() {
  return StaticDeps().GetChromeSignalingThread();
}
base::Thread& GetChromeWorkerThread() {
  return StaticDeps().GetChromeWorkerThread();
}
base::Thread& GetChromeNetworkThread() {
  return StaticDeps().GetChromeNetworkThread();
}

class InterceptingNetworkControllerFactory
    : public webrtc::NetworkControllerFactoryInterface {
 public:
  InterceptingNetworkControllerFactory(
      scoped_refptr<base::SequencedTaskRunner> context_task_runner,
      RTCRtpTransport* rtp_transport)
      : context_task_runner_(context_task_runner),
        rtp_transport_(rtp_transport) {
    CHECK(rtp_transport);
  }

  // Note: Called on a webrtc thread.
  std::unique_ptr<webrtc::NetworkControllerInterface> Create(
      webrtc::NetworkControllerConfig config) override {
    return std::make_unique<InterceptingNetworkController>(
        goog_cc_factory_->Create(config), rtp_transport_, context_task_runner_);
  }

  // Note: Called on a webrtc thread.
  webrtc::TimeDelta GetProcessInterval() const override {
    return goog_cc_factory_->GetProcessInterval();
  }

 private:
  const std::unique_ptr<webrtc::GoogCcNetworkControllerFactory>
      goog_cc_factory_ =
          std::make_unique<webrtc::GoogCcNetworkControllerFactory>();
  const scoped_refptr<base::SequencedTaskRunner> context_task_runner_;
  // Store just a CrossThreadWeakHandle pointing at an RTCRtpTransport, to be
  // used on a webrtc thread when creating InterceptingNetworkController
  // instances.
  const CrossThreadWeakHandle<RTCRtpTransport> rtp_transport_;
};

}  // namespace

// static
const char PeerConnectionDependencyFactory::kSupplementName[] =
    "PeerConnectionDependencyFactory";

PeerConnectionDependencyFactory& PeerConnectionDependencyFactory::From(
    ExecutionContext& context) {
  CHECK(!context.IsContextDestroyed());
  auto* supplement =
      Supplement<ExecutionContext>::From<PeerConnectionDependencyFactory>(
          context);
  if (!supplement) {
    supplement = MakeGarbageCollected<PeerConnectionDependencyFactory>(
        context, PassKey());
    ProvideTo(context, supplement);
  }
  return *supplement;
}

PeerConnectionDependencyFactory::PeerConnectionDependencyFactory(
    ExecutionContext& context,
    PassKey)
    : Supplement(context),
      ExecutionContextLifecycleObserver(&context),
      context_task_runner_(
          context.GetTaskRunner(TaskType::kInternalMediaRealTime)),
      network_manager_(nullptr),
      p2p_socket_dispatcher_(P2PSocketDispatcher::From(context)) {
  // Initialize mojo pipe for encode/decode performance stats data collection.
  mojo::PendingRemote<media::mojom::blink::WebrtcVideoPerfRecorder>
      perf_recorder;
  context.GetBrowserInterfaceBroker().GetInterface(
      perf_recorder.InitWithNewPipeAndPassReceiver());

  webrtc_video_perf_reporter_ = MakeGarbageCollected<WebrtcVideoPerfReporter>(
      context.GetTaskRunner(TaskType::kInternalMedia), &context,
      std::move(perf_recorder));
}

PeerConnectionDependencyFactory::PeerConnectionDependencyFactory()
    : Supplement(nullptr), ExecutionContextLifecycleObserver(nullptr) {}

PeerConnectionDependencyFactory::~PeerConnectionDependencyFactory() = default;

std::unique_ptr<RTCPeerConnectionHandler>
PeerConnectionDependencyFactory::CreateRTCPeerConnectionHandler(
    RTCPeerConnectionHandlerClient* client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    bool encoded_insertable_streams) {
  // Save histogram data so we can see how much PeerConnection is used.
  // The histogram counts the number of calls to the JS API
  // RTCPeerConnection.
  UpdateWebRTCMethodCount(RTCAPIName::kRTCPeerConnection);

  return std::make_unique<RTCPeerConnectionHandler>(client, this, task_runner,
                                                    encoded_insertable_streams);
}

const rtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface>&
PeerConnectionDependencyFactory::GetPcFactory() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!pc_factory_)
    CreatePeerConnectionFactory();
  CHECK(pc_factory_);
  return pc_factory_;
}

void PeerConnectionDependencyFactory::CreatePeerConnectionFactory() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!pc_factory_.get());
  DCHECK(!network_manager_);
  DCHECK(!socket_factory_);

  DVLOG(1) << "PeerConnectionDependencyFactory::CreatePeerConnectionFactory()";

  StaticDeps().EnsureChromeThreadsStarted(
      *ExecutionContextLifecycleObserver::GetExecutionContext());
  base::WaitableEvent& worker_thread_started_event =
      StaticDeps().InitializeWorkerThread();
  StaticDeps().InitializeNetworkThread();
  StaticDeps().InitializeSignalingThread();

// TODO(crbug.com/355256378): OpenH264 for encoding and FFmpeg for H264 decoding
// should be detangled such that software decoding can be enabled without
// software encoding.
#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
  // Building /w |rtc_use_h264|, is the corresponding run-time feature enabled?
  if (!base::FeatureList::IsEnabled(
          blink::features::kWebRtcH264WithOpenH264FFmpeg)) {
    // Feature is to be disabled.
    webrtc::DisableRtcUseH264();
  }
#else
  webrtc::DisableRtcUseH264();
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)

  EnsureWebRtcAudioDeviceImpl();

  // Init SSL, which will be needed by PeerConnection.
  // TODO: https://issues.webrtc.org/issues/339300437 - remove once
  // BoringSSL no longer requires this after
  // https://bugs.chromium.org/p/boringssl/issues/detail?id=35
  if (!rtc::InitializeSSL()) {
    NOTREACHED() << "Failed on InitializeSSL.";
  }

  base::WaitableEvent create_network_manager_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  std::unique_ptr<MdnsResponderAdapter> mdns_responder;
#if BUILDFLAG(ENABLE_MDNS)
  if (base::FeatureList::IsEnabled(
          blink::features::kWebRtcHideLocalIpsWithMdns)) {
    // Note that MdnsResponderAdapter is created on the main thread to have
    // access to the connector to the service manager.
    mdns_responder =
        std::make_unique<MdnsResponderAdapter>(*GetSupplementable());
  }
#endif  // BUILDFLAG(ENABLE_MDNS)
  PostCrossThreadTask(
      *GetWebRtcNetworkTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(&PeerConnectionDependencyFactory::
                              CreateIpcNetworkManagerOnNetworkThread,
                          WrapCrossThreadPersistent(this),
                          CrossThreadUnretained(&create_network_manager_event),
                          std::move(mdns_responder)));

  create_network_manager_event.Wait();
  CHECK(GetNetworkThread());

  // Wait for the worker thread, since `InitializeSignalingThread` needs to
  // refer to `worker_thread_`.
  worker_thread_started_event.Wait();
  CHECK(GetWorkerThread());

  // Only the JS main thread can establish mojo connection with a browser
  // process against RendererFrameHost. RTCVideoEncoderFactory and
  // RTCVideoEncoders run in the webrtc encoder thread. Therefore, we create
  // MojoVideoEncoderMetricsProviderFactory, establish the mojo connection here
  // and pass it to RTCVideoEncoder. VideoEncoderMetricsProviders created by
  // MojoVideoEncoderMetricsProviderFactory::CreateVideoEncoderMetricsProvider()
  // use the mojo connection. The factory will be destroyed in gpu task runner.
  base::WaitableEvent start_signaling_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  PostCrossThreadTask(
      *GetChromeSignalingThread().task_runner(), FROM_HERE,
      CrossThreadBindOnce(
          &PeerConnectionDependencyFactory::InitializeSignalingThread,
          WrapCrossThreadPersistent(this),
          Platform::Current()->GetRenderingColorSpace(),
          CrossThreadUnretained(Platform::Current()->GetGpuFactories()),
          CreateMojoVideoEncoderMetricsProviderFactory(DomWindow()->GetFrame()),
          CrossThreadUnretained(&start_signaling_event)));

  start_signaling_event.Wait();

  CHECK(pc_factory_);
  CHECK(socket_factory_);
  CHECK(GetSignalingThread());
}

void PeerConnectionDependencyFactory::InitializeSignalingThread(
    const gfx::ColorSpace& render_color_space,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
        video_encoder_metrics_provider_factory,
    base::WaitableEvent* event) {
  DCHECK(GetChromeSignalingThread().task_runner()->BelongsToCurrentThread());
  DCHECK(GetNetworkThread());
  // The task to initialize `signaling_thread_` was posted to the same thread,
  // so there is no need to wait on its event.
  DCHECK(GetSignalingThread());
  DCHECK(p2p_socket_dispatcher_);

  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("webrtc_peer_connection", R"(
        semantics {
          sender: "WebRTC"
          description:
            "WebRTC is an API that provides web applications with Real Time "
            "Communication (RTC) capabilities. It is used to establish a "
            "secure session with a remote peer, transmitting and receiving "
            "audio, video and potentially other data."
          trigger:
            "Application creates an RTCPeerConnection and connects it to a "
            "remote peer by exchanging an SDP offer and answer."
          data:
            "Media encrypted using DTLS-SRTP, and protocol-level messages for "
            "the various subprotocols employed by WebRTC (including ICE, DTLS, "
            "RTCP, etc.). Note that ICE connectivity checks may leak the "
            "user's IP address(es), subject to the restrictions/guidance in "
            "https://datatracker.ietf.org/doc/draft-ietf-rtcweb-ip-handling."
          destination: OTHER
          destination_other:
            "A destination determined by the web application that created the "
            "connection."
        }
        policy {
          cookies_allowed: NO
          setting:
            "This feature cannot be disabled in settings, but it won't be used "
            "unless the application creates an RTCPeerConnection. Media can "
            "only be captured with user's consent, but data may be sent "
            "withouth that."
          policy_exception_justification:
            "Not implemented. 'WebRtcUdpPortRange' policy can limit the range "
            "of ports used by WebRTC, but there is no policy to generally "
            "block it."
        }
    )");
  // TODO(crbug.com/40265716): remove batch_udp_packets parameter.
  socket_factory_ = std::make_unique<IpcPacketSocketFactory>(
      WTF::CrossThreadBindRepeating(
          &PeerConnectionDependencyFactory::DoGetDevtoolsToken,
          WrapCrossThreadWeakPersistent(this)),
      p2p_socket_dispatcher_.Get(), traffic_annotation, /*batch_udp_packets=*/
      false);

  gpu_factories_ = gpu_factories;
  // WrapCrossThreadWeakPersistent is safe below, because
  // PeerConnectionDependencyFactory (that holds `webrtc_video_perf_reporter_`)
  // outlives the encoders and decoders that are using the callback. The
  // lifetime of PeerConnectionDependencyFactory is tied to the ExecutionContext
  // and the destruction of the encoders and decoders is triggered by a call to
  // RTCPeerConnection::ContextDestroyed() which happens just before the
  // ExecutionContext is destroyed.
  std::unique_ptr<webrtc::VideoEncoderFactory> webrtc_encoder_factory =
      blink::CreateWebrtcVideoEncoderFactory(
          gpu_factories, std::move(video_encoder_metrics_provider_factory),
          base::BindRepeating(&WebrtcVideoPerfReporter::StoreWebrtcVideoStats,
                              WrapCrossThreadWeakPersistent(
                                  webrtc_video_perf_reporter_.Get())));
  std::unique_ptr<webrtc::VideoDecoderFactory> webrtc_decoder_factory =
      blink::CreateWebrtcVideoDecoderFactory(
          gpu_factories, render_color_space,
          base::BindRepeating(&WebrtcVideoPerfReporter::StoreWebrtcVideoStats,
                              WrapCrossThreadWeakPersistent(
                                  webrtc_video_perf_reporter_.Get())));

  if (blink::Platform::Current()->UsesFakeCodecForPeerConnection()) {
    webrtc_encoder_factory =
        std::make_unique<webrtc::FakeVideoEncoderFactory>();
    webrtc_decoder_factory =
        std::make_unique<webrtc::FakeVideoDecoderFactory>();
  }

  webrtc::PeerConnectionFactoryDependencies pcf_deps;
  pcf_deps.worker_thread = GetWorkerThread();
  pcf_deps.signaling_thread = GetSignalingThread();
  pcf_deps.network_thread = GetNetworkThread();
  if (pcf_deps.worker_thread == pcf_deps.network_thread) {
    LOG(INFO) << "Running WebRTC with a combined Network and Worker thread.";
  }
  pcf_deps.task_queue_factory = CreateWebRtcTaskQueueFactory();
  pcf_deps.decode_metronome = StaticDeps().CreateDecodeMetronome();
  pcf_deps.encode_metronome = StaticDeps().MaybeCreateEncodeMetronome();
  pcf_deps.event_log_factory = std::make_unique<webrtc::RtcEventLogFactory>();
  pcf_deps.adm = audio_device_.get();
  pcf_deps.audio_encoder_factory = blink::CreateWebrtcAudioEncoderFactory();
  pcf_deps.audio_decoder_factory = blink::CreateWebrtcAudioDecoderFactory();
  pcf_deps.video_encoder_factory = std::move(webrtc_encoder_factory);
  pcf_deps.video_decoder_factory = std::move(webrtc_decoder_factory);

  // Audio Processing Module (APM) instances are owned and handled by the Blink
  // media stream module.
  DCHECK_EQ(pcf_deps.audio_processing_builder, nullptr);
  webrtc::EnableMedia(pcf_deps);
  pc_factory_ = webrtc::CreateModularPeerConnectionFactory(std::move(pcf_deps));
  CHECK(pc_factory_.get());

  webrtc::PeerConnectionFactoryInterface::Options factory_options;
  factory_options.disable_encryption =
      !blink::Platform::Current()->IsWebRtcEncryptionEnabled();
  pc_factory_->SetOptions(factory_options);

  event->Signal();
}

void PeerConnectionDependencyFactory::DoGetDevtoolsT
"""


```
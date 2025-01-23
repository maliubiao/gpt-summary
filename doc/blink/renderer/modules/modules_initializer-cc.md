Response:
Let's break down the thought process to analyze the `modules_initializer.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies (JavaScript, HTML, CSS), examples, debugging information, and potential errors.

2. **Initial Scan and Keywords:**  Quickly read through the code, looking for important keywords and patterns. Keywords like "Initialize," "Register," "Create," "Bind," and class names like "HTMLCanvasElement," "LocalFrame," "Document," "Navigator," "Inspector," "Media," "Storage" jump out. Includes like `<memory>`, `<vector>`, and `#include` also provide context. The presence of `mojom` indicates interaction with Chromium's Mojo IPC system.

3. **Identify Core Functionality - The `Initialize` Methods:**  The presence of `ModulesInitializer::Initialize()` and other `Init*` methods (like `InitLocalFrame`) strongly suggests this class is responsible for setting up various modules within the Blink rendering engine. This involves:
    * **Static Initialization:** `Initialize()` likely handles global or per-isolate setup, including registering factories and initializing strings.
    * **Per-Frame Initialization:** `InitLocalFrame()` likely handles setup specific to each frame (the individual browsing context).

4. **Categorize Functionality:**  Group the identified functionalities based on the code. Looking at the included headers and the methods called, key categories emerge:
    * **JavaScript Bindings:**  The inclusion of `ModuleBindingsInitializer.h` and the registration of many browser APIs with `LocalFrame` point towards making JavaScript APIs available.
    * **Canvas and Graphics:**  The registration of different `CanvasRenderingContext` types clearly indicates functionality related to the `<canvas>` element.
    * **Media:** Headers and method names relating to `HTMLMediaElement`, `WebMediaPlayer`, and `RemotePlayback` signify media handling.
    * **Storage:**  References to `DOMWindowStorage`, `StorageNamespace`, `IndexedDB`, and `WebDatabase` point to browser storage mechanisms.
    * **Device APIs:** Includes related to `DeviceMotion`, `DeviceOrientation`, and `NavigatorGamepad` suggest integration with device sensors.
    * **Service Workers and Web Workers:** References to `NavigatorServiceWorker`, `WebSharedWorkerImpl`, and `WebEmbeddedWorkerImpl` indicate support for background scripting.
    * **Accessibility:** `AXObjectCacheImpl` and `InspectorAccessibilityAgent` relate to accessibility support.
    * **Developer Tools (Inspector):** The numerous `Inspector*Agent` classes clearly show this file plays a role in enabling debugging and inspection features.
    * **Filesystem:** `FileSystemDispatcher` and related classes point to filesystem access.
    * **Other Modules:** Identify other less prominent modules like `AppBannerController`, `Presentation`, etc.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** For each identified category, explain how it relates to the core web technologies:
    * **JavaScript:**  Emphasize the registration of APIs that JavaScript code can call.
    * **HTML:**  Highlight the connection to HTML elements like `<canvas>` and `<video>` and their corresponding JavaScript APIs.
    * **CSS:**  Explain how the registration of `CSSPaintImageGenerator` relates to CSS custom paint.

6. **Provide Examples:**  For each connection to web technologies, provide concrete examples of how these functionalities are used in web development. This helps illustrate the abstract concepts.

7. **Logical Reasoning (Hypothetical Input/Output):**  Focus on the *initialization* aspect. A reasonable input is the creation of a new `LocalFrame`. The output is the registration of various services and APIs with that frame, making them accessible to the web content within that frame.

8. **User/Programming Errors:** Think about common mistakes developers or users might make that could lead to issues related to the functionalities initialized here:
    * Incorrectly using canvas APIs.
    * Expecting certain APIs to be available without checking for browser support.
    * Issues related to permissions for device APIs.
    * Errors in service worker registration or usage.

9. **Debugging Clues (User Operations to Reach the Code):**  Trace back how a user's actions in a browser could lead to the execution of code within this file. Think about the page lifecycle:
    * Navigating to a page.
    * Using JavaScript to interact with APIs (canvas, media, storage, etc.).
    * Opening developer tools.

10. **Structure and Refine:** Organize the information logically with clear headings and bullet points. Ensure the language is clear and concise. Review for accuracy and completeness. For instance, initially, I might not have explicitly mentioned the role of `mojom`, but upon further review, realizing its importance for inter-process communication, I would add it. Similarly, explaining "supplements" requires some thought about how Blink extends the functionality of core objects.

11. **Self-Correction Example:**  Initially, I might broadly state "handles various modules."  However, the request asks for *specific* functionality. So, I would refine this by listing the concrete modules being initialized (canvas, media, storage, etc.). I'd also ensure I'm not just listing class names but explaining what those classes *do*.

By following these steps, the detailed analysis provided in the initial good answer can be generated. The process involves understanding the code's purpose, categorizing its functions, connecting it to relevant web technologies, providing illustrative examples, and considering practical implications for users and developers.
这个文件 `blink/renderer/modules/modules_initializer.cc` 在 Chromium Blink 渲染引擎中扮演着至关重要的角色，它的主要功能是**初始化和注册各种与 Web 平台 API 相关的模块和功能**。 可以将其视为一个模块注册中心，负责将 Blink 的核心功能与各种扩展模块连接起来，使得网页能够使用 JavaScript、HTML 和 CSS 中定义的各种高级功能。

**具体功能列表:**

1. **模块注册:** 负责注册各种模块，这些模块实现了 Web 平台的各种 API，例如 Canvas 2D/WebGL, Web Audio, IndexedDB, Service Workers, Device Orientation, Media Capabilities 等。  它通过调用各个模块的 `Init` 方法或者提供工厂方法来完成注册。

2. **接口绑定:** 将 Blink 内部的实现类与通过 Mojo 定义的接口绑定起来。Mojo 是 Chromium 的跨进程通信机制，使得渲染进程可以与浏览器进程或其他进程进行通信，获取系统服务或执行某些操作。例如，绑定 `mojom::blink::FileSystemManager` 接口。

3. **补充功能安装 (Supplements):**  为 `LocalFrame` (代表一个文档的渲染上下文) 安装各种补充功能，例如 `InspectorAccessibilityAgent` (用于开发者工具的辅助功能检查) 和 `ImageDownloaderImpl` (用于下载图片)。

4. **创建特定对象:** 提供创建某些特定 Web API 对象的方法，例如 `CreateMediaControls` (为 `<video>` 或 `<audio>` 元素创建默认的媒体控件)，`CreatePictureInPictureController` (创建画中画控制器)。

5. **初始化 Inspector 代理:**  在开发者工具会话初始化时，创建和添加各种 Inspector 代理，用于调试和检查 Web 应用，例如 `InspectorIndexedDBAgent`, `InspectorDOMStorageAgent`, `InspectorWebAudioAgent` 等。

6. **清理 Window 对象:** 在主世界（main world，即执行网页 JavaScript 的环境）的 Window 对象被清理时执行一些操作，例如初始化某些单例对象或服务。

7. **创建 WebMediaPlayer:**  为 `<video>` 或 `<audio>` 元素创建底层的媒体播放器实现 `WebMediaPlayer`。

8. **提供模块到 Page:**  为 `Page` 对象 (代表一个标签页) 提供各种模块和功能，例如 `DatabaseClient` (用于 Web SQL Database) 和 `StorageNamespace` (用于 Session Storage)。

9. **控制 WebGL 上下文创建:**  提供测试用的方法，可以强制下一次 WebGL 上下文创建失败。

10. **管理 Session Storage:** 提供克隆和清除 Session Storage 缓存数据的功能。

11. **通知 Manifest 和屏幕变化:**  在 Manifest 文件更新或屏幕信息变化时通知相应的模块。

12. **设置 Local 和 Session Storage Area:**  接收来自浏览器进程的 Mojo 消息，设置 LocalStorage 和 SessionStorage 的底层存储区域。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件虽然是 C++ 代码，但其核心目的是为了支持 JavaScript、HTML 和 CSS 的功能。它就像一个幕后工作者，确保当你在前端代码中使用某个 Web API 时，背后有相应的 C++ 代码在支撑。

* **JavaScript:**  `modules_initializer.cc` 中注册的许多模块都直接对应着 JavaScript 可以调用的 API。
    * **例子 1 (Canvas):**  当 JavaScript 代码中使用 `document.getElementById('myCanvas').getContext('2d')` 获取 2D 渲染上下文时，`ModulesInitializer::Initialize()` 中 `HTMLCanvasElement::RegisterRenderingContextFactory(std::make_unique<CanvasRenderingContext2D::Factory>())` 的注册使得 Blink 知道如何创建和管理这个 2D 上下文对象，从而让 JavaScript 能够绘制图形。
    * **例子 2 (Device Orientation):** 当 JavaScript 代码中使用 `window.addEventListener('devicemotion', ...)` 监听设备运动事件时，`ModulesInitializer::OnClearWindowObjectInMainWorld()` 中 `DeviceMotionController::From(window)` 的调用确保了 `DeviceMotionController` 对象的初始化，该对象负责与底层操作系统通信获取设备运动数据，并将其传递给 JavaScript。
    * **例子 3 (Service Workers):** 当 JavaScript 代码中使用 `navigator.serviceWorker.register(...)` 注册 Service Worker 时，`ModulesInitializer::OnClearWindowObjectInMainWorld()` 中 `NavigatorServiceWorker::From(window)` 的调用确保了 `NavigatorServiceWorker` 对象的初始化，该对象负责管理 Service Worker 的生命周期和通信。

* **HTML:**  `modules_initializer.cc` 中的一些功能与特定的 HTML 元素直接相关。
    * **例子 1 (`<video>` 和 `<audio>`):** 当 HTML 中包含 `<video>` 或 `<audio>` 元素时，`ModulesInitializer::CreateMediaControls()` 会被调用，为这些元素创建默认的播放控制界面。`ModulesInitializer::CreateWebMediaPlayer()` 则负责创建底层的媒体播放器，处理视频和音频的解码、渲染等操作。
    * **例子 2 (`<canvas>`):**  正如 JavaScript 的例子中提到的，`ModulesInitializer::Initialize()` 中对 `HTMLCanvasElement` 的上下文工厂注册是 `<canvas>` 元素能够正常工作的基础。

* **CSS:** 尽管这个文件与 CSS 的联系不如 JavaScript 和 HTML 那么直接，但也有一些关联。
    * **例子 1 (CSS Paint API):** `ModulesInitializer::Initialize()` 中对 `CSSPaintImageGenerator` 的注册与 CSS Paint API 相关。当 CSS 中使用 `paint()` 函数引用自定义的 Paint Worklet 时，Blink 会使用这里注册的生成器来处理自定义绘制逻辑。

**逻辑推理 (假设输入与输出):**

假设输入：一个包含 `<canvas id="myCanvas"></canvas>` 标签的 HTML 文档被加载。

输出：

1. 当 Blink 解析到 `<canvas>` 标签时，会创建一个 `HTMLCanvasElement` 对象。
2. 当 JavaScript 代码执行 `document.getElementById('myCanvas').getContext('2d')` 时，Blink 会查找已注册的 `CanvasRenderingContext2D::Factory`。
3. 使用该工厂创建一个 `CanvasRenderingContext2D` 对象，并将其返回给 JavaScript。
4. JavaScript 代码现在可以使用这个 2D 渲染上下文进行绘图操作。

**用户或编程常见的使用错误及举例说明:**

* **错误使用 Canvas API:** 用户可能尝试获取一个未注册的 Canvas 上下文类型，例如 `canvas.getContext('unsupported-context')`。由于 `ModulesInitializer` 中没有注册名为 `unsupported-context` 的工厂，这个调用将返回 `null`，导致 JavaScript 代码出错。
* **期望 API 立即可用:** 开发者可能在文档加载完成之前就尝试访问某些需要异步初始化的 API，例如 Service Workers。如果在 Service Worker 注册完成之前就调用 `navigator.serviceWorker.ready`，可能会得到一个未解决的 Promise。这与 `ModulesInitializer` 中 Service Worker 模块的初始化时机有关。
* **设备权限问题:**  使用需要设备权限的 API (例如 Device Orientation) 时，如果用户拒绝了权限请求，相关的模块可能无法获取数据，导致 JavaScript 代码无法正常工作。这与 `ModulesInitializer` 中设备相关模块的初始化和数据获取流程有关。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接，导航到一个新的网页。**
2. **浏览器进程接收到请求，下载 HTML、CSS 和 JavaScript 资源。**
3. **浏览器进程将 HTML 数据传递给渲染进程。**
4. **渲染进程开始解析 HTML，构建 DOM 树。**
5. **当遇到需要特定模块支持的 HTML 元素 (例如 `<canvas>`, `<video>`) 或 JavaScript API 调用 (例如 `navigator.serviceWorker.register()`) 时，渲染引擎会检查相应的模块是否已经初始化。**
6. **如果模块尚未初始化，或者需要进行一些与模块相关的设置，`ModulesInitializer` 中相应的方法会被调用。** 例如，当首次遇到 `<canvas>` 元素并需要获取 2D 上下文时，会触发 `HTMLCanvasElement::RegisterRenderingContextFactory` 中注册的工厂的调用。当 JavaScript 调用 `navigator.serviceWorker.register()` 时，可能会触发 `ModulesInitializer::OnClearWindowObjectInMainWorld` 中 `NavigatorServiceWorker::From(window)` 的调用。
7. **对于涉及到跨进程通信的 API，例如文件系统访问，`ModulesInitializer` 中注册的 Mojo 接口绑定会被使用，以便渲染进程可以与浏览器进程通信，请求文件系统服务。**
8. **当开发者打开浏览器开发者工具时，`ModulesInitializer::InitInspectorAgentSession` 会被调用，初始化各种 Inspector 代理，以便开发者可以检查和调试网页的各种功能。**

总而言之，`modules_initializer.cc` 是 Blink 引擎中一个核心的配置和注册中心，它确保了 Web 平台各种功能的正确初始化和可用性，使得前端开发者能够使用 JavaScript、HTML 和 CSS 构建丰富的 Web 应用。当你在使用各种 Web API 时，背后很可能就涉及到这个文件中定义的初始化逻辑。理解这个文件有助于深入理解 Blink 引擎的工作原理。

### 提示词
```
这是目录为blink/renderer/modules/modules_initializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/modules_initializer.h"

#include <memory>

#include "base/feature_list.h"
#include "base/task/thread_pool.h"
#include "build/android_buildflags.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/binder_map.h"
#include "third_party/blink/public/mojom/dom_storage/session_storage_namespace.mojom-blink.h"
#include "third_party/blink/public/mojom/filesystem/file_system.mojom-blink.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/web_security_origin.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_view_client.h"
#include "third_party/blink/renderer/bindings/modules/v8/module_bindings_initializer.h"
#include "third_party/blink/renderer/core/css/background_color_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/clip_path_paint_image_generator.h"
#include "third_party/blink/renderer/core/css/css_paint_image_generator.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/editing/suggestion/text_suggestion_backend_impl.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/exported/web_shared_worker_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/inspector/devtools_session.h"
#include "third_party/blink/renderer/core/inspector/inspector_media_context_impl.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/offscreencanvas/offscreen_canvas.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scheduler/task_attribution_tracker_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/inspector_accessibility_agent.h"
#include "third_party/blink/renderer/modules/app_banner/app_banner_controller.h"
#include "third_party/blink/renderer/modules/audio_output_devices/html_media_element_audio_output_device.h"
#include "third_party/blink/renderer/modules/cache_storage/inspector_cache_storage_agent.h"
#include "third_party/blink/renderer/modules/canvas/canvas2d/canvas_rendering_context_2d.h"
#include "third_party/blink/renderer/modules/canvas/imagebitmap/image_bitmap_rendering_context.h"
#include "third_party/blink/renderer/modules/canvas/offscreencanvas2d/offscreen_canvas_rendering_context_2d.h"
#include "third_party/blink/renderer/modules/content_extraction/inner_html_agent.h"
#include "third_party/blink/renderer/modules/content_extraction/inner_text_agent.h"
#include "third_party/blink/renderer/modules/csspaint/css_paint_image_generator_impl.h"
#include "third_party/blink/renderer/modules/csspaint/nativepaint/background_color_paint_image_generator_impl.h"
#include "third_party/blink/renderer/modules/csspaint/nativepaint/clip_path_paint_image_generator_impl.h"
#include "third_party/blink/renderer/modules/device_orientation/device_motion_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_absolute_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_controller.h"
#include "third_party/blink/renderer/modules/device_orientation/device_orientation_inspector_agent.h"
#include "third_party/blink/renderer/modules/document_metadata/document_metadata_server.h"
#include "third_party/blink/renderer/modules/document_picture_in_picture/picture_in_picture_controller_impl.h"
#include "third_party/blink/renderer/modules/encryptedmedia/html_media_element_encrypted_media.h"
#include "third_party/blink/renderer/modules/event_interface_modules_names.h"
#include "third_party/blink/renderer/modules/event_modules_factory.h"
#include "third_party/blink/renderer/modules/event_target_modules_names.h"
#include "third_party/blink/renderer/modules/exported/web_embedded_worker_impl.h"
#include "third_party/blink/renderer/modules/file_system_access/bucket_file_system_agent.h"
#include "third_party/blink/renderer/modules/filesystem/dragged_isolated_file_system_impl.h"
#include "third_party/blink/renderer/modules/filesystem/file_system_dispatcher.h"
#include "third_party/blink/renderer/modules/gamepad/navigator_gamepad.h"
#include "third_party/blink/renderer/modules/image_downloader/image_downloader_impl.h"
#include "third_party/blink/renderer/modules/indexed_db_names.h"
#include "third_party/blink/renderer/modules/indexeddb/inspector_indexed_db_agent.h"
#include "third_party/blink/renderer/modules/installation/installation_service_impl.h"
#include "third_party/blink/renderer/modules/launch/web_launch_service_impl.h"
#include "third_party/blink/renderer/modules/manifest/manifest_manager.h"
#include "third_party/blink/renderer/modules/media/audio/audio_renderer_sink_cache.h"
#include "third_party/blink/renderer/modules/media_capabilities_names.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/modules/mediasource/media_source_registry_impl.h"
#include "third_party/blink/renderer/modules/peerconnection/peer_connection_tracker.h"
#include "third_party/blink/renderer/modules/presentation/presentation.h"
#include "third_party/blink/renderer/modules/push_messaging/push_messaging_client.h"
#include "third_party/blink/renderer/modules/remoteplayback/html_media_element_remote_playback.h"
#include "third_party/blink/renderer/modules/remoteplayback/remote_playback.h"
#include "third_party/blink/renderer/modules/screen_details/screen_details.h"
#include "third_party/blink/renderer/modules/screen_details/window_screen_details.h"
#include "third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.h"
#include "third_party/blink/renderer/modules/service_worker/navigator_service_worker.h"
#include "third_party/blink/renderer/modules/speech/speech_synthesis.h"
#include "third_party/blink/renderer/modules/storage/dom_window_storage.h"
#include "third_party/blink/renderer/modules/storage/dom_window_storage_controller.h"
#include "third_party/blink/renderer/modules/storage/inspector_dom_storage_agent.h"
#include "third_party/blink/renderer/modules/storage/storage_namespace.h"
#include "third_party/blink/renderer/modules/webaudio/audio_graph_tracer.h"
#include "third_party/blink/renderer/modules/webaudio/inspector_web_audio_agent.h"
#include "third_party/blink/renderer/modules/webdatabase/database_client.h"
#include "third_party/blink/renderer/modules/webdatabase/inspector_database_agent.h"
#include "third_party/blink/renderer/modules/webdatabase/web_database_host.h"
#include "third_party/blink/renderer/modules/webdatabase/web_database_impl.h"
#include "third_party/blink/renderer/modules/webgl/webgl2_rendering_context.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_canvas_context.h"
#include "third_party/blink/renderer/modules/worklet/animation_and_paint_worklet_thread.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/widget/compositing/blink_categorized_worker_pool_delegate.h"
#include "third_party/blink/renderer/platform/widget/frame_widget.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/webrtc_overrides/init_webrtc.h"
#include "ui/accessibility/accessibility_features.h"

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/public/platform/modules/video_capture/web_video_capture_impl_manager.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/modules/mediastream/web_media_stream_device_observer.h"
#include "third_party/blink/renderer/core/page/page_visibility_observer.h"
#include "third_party/blink/renderer/modules/remote_objects/remote_object_gateway_impl.h"
#endif

namespace blink {
namespace {

// Serves as a kill switch.
BASE_FEATURE(kBlinkEnableInnerTextAgent,
             "BlinkEnableInnerTextAgent",
             base::FEATURE_ENABLED_BY_DEFAULT);

// Serves as a kill switch.
BASE_FEATURE(kBlinkEnableInnerHtmlAgent,
             "BlinkEnableInnerHtmlAgent",
             base::FEATURE_ENABLED_BY_DEFAULT);

#if BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_DESKTOP_ANDROID)

class SuspendCaptureObserver : public GarbageCollected<SuspendCaptureObserver>,
                               public Supplement<Page>,
                               public PageVisibilityObserver {
 public:
  static const char kSupplementName[];

  explicit SuspendCaptureObserver(Page& page)
      : Supplement<Page>(page), PageVisibilityObserver(&page) {}

  // PageVisibilityObserver overrides:
  void PageVisibilityChanged() override {
    // TODO(crbug.com/487935): We don't yet suspend video capture devices for
    // OOPIFs.
    WebLocalFrameImpl* frame = WebLocalFrameImpl::FromFrame(
        DynamicTo<LocalFrame>(GetPage()->MainFrame()));
    if (!frame)
      return;
    WebMediaStreamDeviceObserver* media_stream_device_observer =
        frame->Client()->MediaStreamDeviceObserver();
    if (!media_stream_device_observer)
      return;
    // Don't suspend media capture devices if page visibility is
    // PageVisibilityState::kHiddenButPainting (e.g. Picture-in-Picture).
    // TODO(crbug.com/1339252): Add tests.
    bool suspend = (GetPage()->GetVisibilityState() ==
                    mojom::blink::PageVisibilityState::kHidden);
    MediaStreamDevices video_devices =
        media_stream_device_observer->GetNonScreenCaptureDevices();
    Platform::Current()->GetVideoCaptureImplManager()->SuspendDevices(
        video_devices, suspend);
  }

  void Trace(Visitor* visitor) const override {
    Supplement<Page>::Trace(visitor);
    PageVisibilityObserver::Trace(visitor);
  }
};

const char SuspendCaptureObserver::kSupplementName[] = "SuspendCaptureObserver";
#endif  // BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_DESKTOP_ANDROID)

}  // namespace

void ModulesInitializer::Initialize() {
  // Strings must be initialized before calling CoreInitializer::init().
  const unsigned kModulesStaticStringsCount =
      event_interface_names::kModulesNamesCount +
      event_target_names::kModulesNamesCount + indexed_db_names::kNamesCount;
  StringImpl::ReserveStaticStringsCapacityForSize(
      kModulesStaticStringsCount + StringImpl::AllStaticStrings().size());

  event_interface_names::InitModules();
  event_target_names::InitModules();
  Document::RegisterEventFactory(EventModulesFactory::Create());
  ModuleBindingsInitializer::Init();
  indexed_db_names::Init();
  media_capabilities_names::Init();
  AXObjectCache::Init(AXObjectCacheImpl::Create);
  DraggedIsolatedFileSystem::Init(
      DraggedIsolatedFileSystemImpl::PrepareForDataObject);
  CSSPaintImageGenerator::Init(CSSPaintImageGeneratorImpl::Create);
  BackgroundColorPaintImageGenerator::Init(
      BackgroundColorPaintImageGeneratorImpl::Create);
  ClipPathPaintImageGenerator::Init(ClipPathPaintImageGeneratorImpl::Create);
  WebDatabaseHost::GetInstance().Init();
  MediaSourceRegistryImpl::Init();
  if (::features::IsTextBasedAudioDescriptionEnabled())
    SpeechSynthesisBase::Init(SpeechSynthesis::Create);

  CoreInitializer::Initialize();

  // Canvas context types must be registered with the HTMLCanvasElement.
  HTMLCanvasElement::RegisterRenderingContextFactory(
      std::make_unique<CanvasRenderingContext2D::Factory>());
  HTMLCanvasElement::RegisterRenderingContextFactory(
      std::make_unique<WebGLRenderingContext::Factory>());
  HTMLCanvasElement::RegisterRenderingContextFactory(
      std::make_unique<WebGL2RenderingContext::Factory>());
  HTMLCanvasElement::RegisterRenderingContextFactory(
      std::make_unique<ImageBitmapRenderingContext::Factory>());
  HTMLCanvasElement::RegisterRenderingContextFactory(
      std::make_unique<GPUCanvasContext::Factory>());

  // OffscreenCanvas context types must be registered with the OffscreenCanvas.
  OffscreenCanvas::RegisterRenderingContextFactory(
      std::make_unique<OffscreenCanvasRenderingContext2D::Factory>());
  OffscreenCanvas::RegisterRenderingContextFactory(
      std::make_unique<WebGLRenderingContext::Factory>());
  OffscreenCanvas::RegisterRenderingContextFactory(
      std::make_unique<WebGL2RenderingContext::Factory>());
  OffscreenCanvas::RegisterRenderingContextFactory(
      std::make_unique<ImageBitmapRenderingContext::Factory>());
  OffscreenCanvas::RegisterRenderingContextFactory(
      std::make_unique<GPUCanvasContext::Factory>());

  V8PerIsolateData::SetTaskAttributionTrackerFactory(
      &scheduler::TaskAttributionTrackerImpl::Create);

  ::InitializeWebRtcModule();
}

void ModulesInitializer::InitLocalFrame(LocalFrame& frame) const {
  if (frame.IsMainFrame()) {
    frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
        &DocumentMetadataServer::BindReceiver, WrapWeakPersistent(&frame)));
  }
  frame.GetInterfaceRegistry()->AddAssociatedInterface(WTF::BindRepeating(
      &WebLaunchServiceImpl::BindReceiver, WrapWeakPersistent(&frame)));

  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &InstallationServiceImpl::BindReceiver, WrapWeakPersistent(&frame)));
  // TODO(dominickn): This interface should be document-scoped rather than
  // frame-scoped, as the resulting banner event is dispatched to
  // frame()->document().
  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &AppBannerController::BindReceiver, WrapWeakPersistent(&frame)));
  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &TextSuggestionBackendImpl::Bind, WrapWeakPersistent(&frame)));
#if BUILDFLAG(IS_ANDROID)
  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &RemoteObjectGatewayFactoryImpl::Bind, WrapWeakPersistent(&frame)));
#endif  // BUILDFLAG(IS_ANDROID)

  frame.GetInterfaceRegistry()->AddInterface(
      WTF::BindRepeating(&PeerConnectionTracker::BindToFrame,
                         WrapCrossThreadWeakPersistent(&frame)));

  if (base::FeatureList::IsEnabled(kBlinkEnableInnerTextAgent)) {
    frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
        &InnerTextAgent::BindReceiver, WrapWeakPersistent(&frame)));
  }

  if (base::FeatureList::IsEnabled(kBlinkEnableInnerHtmlAgent)) {
    frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
        &InnerHtmlAgent::BindReceiver, WrapWeakPersistent(&frame)));
  }
}

void ModulesInitializer::InstallSupplements(LocalFrame& frame) const {
  DCHECK(WebLocalFrameImpl::FromFrame(&frame)->Client());
  InspectorAccessibilityAgent::ProvideTo(&frame);
  ImageDownloaderImpl::ProvideTo(frame);
  AudioRendererSinkCache::InstallWindowObserver(*frame.DomWindow());
}

MediaControls* ModulesInitializer::CreateMediaControls(
    HTMLMediaElement& media_element,
    ShadowRoot& shadow_root) const {
  return MediaControlsImpl::Create(media_element, shadow_root);
}

PictureInPictureController*
ModulesInitializer::CreatePictureInPictureController(Document& document) const {
  return MakeGarbageCollected<PictureInPictureControllerImpl>(document);
}

void ModulesInitializer::InitInspectorAgentSession(
    DevToolsSession* session,
    bool allow_view_agents,
    InspectorDOMAgent* dom_agent,
    InspectedFrames* inspected_frames,
    Page* page) const {
  session->CreateAndAppend<InspectorIndexedDBAgent>(inspected_frames,
                                                    session->V8Session());
  session->CreateAndAppend<DeviceOrientationInspectorAgent>(inspected_frames);
  session->CreateAndAppend<InspectorDOMStorageAgent>(inspected_frames);
  session->CreateAndAppend<InspectorAccessibilityAgent>(inspected_frames,
                                                        dom_agent);
  session->CreateAndAppend<InspectorWebAudioAgent>(page);
  session->CreateAndAppend<InspectorCacheStorageAgent>(inspected_frames);
  session->CreateAndAppend<BucketFileSystemAgent>(inspected_frames);
  if (allow_view_agents) {
    session->CreateAndAppend<InspectorDatabaseAgent>(page);
  }
}

void ModulesInitializer::OnClearWindowObjectInMainWorld(
    Document& document,
    const Settings& settings) const {
  LocalDOMWindow& window = *document.domWindow();
  DeviceMotionController::From(window);
  DeviceOrientationController::From(window);
  DeviceOrientationAbsoluteController::From(window);
  NavigatorGamepad::From(*window.navigator());

  // TODO(nhiroki): Figure out why ServiceWorkerContainer needs to be eagerly
  // initialized.
  if (!document.IsInitialEmptyDocument())
    NavigatorServiceWorker::From(window);

  DOMWindowStorageController::From(window);
  if (RuntimeEnabledFeatures::PresentationEnabled() &&
      settings.GetPresentationReceiver()) {
    // We eagerly create Presentation and associated PresentationReceiver so
    // that the frame creating the presentation can offer a connection to the
    // presentation receiver.
    Presentation::presentation(*window.navigator());
  }
  ManifestManager::From(window);

#if BUILDFLAG(IS_ANDROID)
  LocalFrame* frame = window.GetFrame();
  DCHECK(frame);
  if (auto* gateway = RemoteObjectGatewayImpl::From(*frame))
    gateway->OnClearWindowObjectInMainWorld();
#endif  // BUILDFLAG(IS_ANDROID)
}

std::unique_ptr<WebMediaPlayer> ModulesInitializer::CreateWebMediaPlayer(
    WebLocalFrameClient* web_frame_client,
    HTMLMediaElement& html_media_element,
    const WebMediaPlayerSource& source,
    WebMediaPlayerClient* media_player_client) const {
  HTMLMediaElementEncryptedMedia& encrypted_media =
      HTMLMediaElementEncryptedMedia::From(html_media_element);
  WebString sink_id(
      HTMLMediaElementAudioOutputDevice::sinkId(html_media_element));
  MediaInspectorContextImpl* context_impl = MediaInspectorContextImpl::From(
      *To<LocalDOMWindow>(html_media_element.GetExecutionContext()));
  FrameWidget* frame_widget =
      html_media_element.GetDocument().GetFrame()->GetWidgetForLocalRoot();
  return web_frame_client->CreateMediaPlayer(
      source, media_player_client, context_impl, &encrypted_media,
      encrypted_media.ContentDecryptionModule(), sink_id,
      frame_widget->GetLayerTreeSettings(),
      base::ThreadPool::CreateTaskRunner(base::TaskTraits{}));
}

RemotePlaybackClient* ModulesInitializer::CreateRemotePlaybackClient(
    HTMLMediaElement& html_media_element) const {
  return &RemotePlayback::From(html_media_element);
}

void ModulesInitializer::ProvideModulesToPage(
    Page& page,
    const SessionStorageNamespaceId& namespace_id) const {
  page.ProvideSupplement(MakeGarbageCollected<DatabaseClient>(page));
  StorageNamespace::ProvideSessionStorageNamespaceTo(page, namespace_id);
  AudioGraphTracer::ProvideAudioGraphTracerTo(page);
#if BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_DESKTOP_ANDROID)
  page.ProvideSupplement(MakeGarbageCollected<SuspendCaptureObserver>(page));
#endif  // BUILDFLAG(IS_ANDROID)  && !BUILDFLAG(IS_DESKTOP_ANDROID)
}

void ModulesInitializer::ForceNextWebGLContextCreationToFail() const {
  WebGLRenderingContext::ForceNextWebGLContextCreationToFail();
}

void ModulesInitializer::
    CollectAllGarbageForAnimationAndPaintWorkletForTesting() const {
  AnimationAndPaintWorkletThread::CollectAllGarbageForTesting();
}

void ModulesInitializer::CloneSessionStorage(
    Page* clone_from_page,
    const SessionStorageNamespaceId& clone_to_namespace) {
  StorageNamespace* storage_namespace = StorageNamespace::From(clone_from_page);
  if (storage_namespace)
    storage_namespace->CloneTo(WebString::FromLatin1(clone_to_namespace));
}

void ModulesInitializer::EvictSessionStorageCachedData(Page* page) {
  StorageNamespace* storage_namespace = StorageNamespace::From(page);
  if (storage_namespace)
    storage_namespace->EvictSessionStorageCachedData();
}

void ModulesInitializer::DidChangeManifest(LocalFrame& frame) {
  ManifestManager::From(*frame.DomWindow())->DidChangeManifest();
}

void ModulesInitializer::NotifyOrientationChanged(LocalFrame& frame) {
  ScreenOrientationController::From(*frame.DomWindow())
      ->NotifyOrientationChanged();
}

void ModulesInitializer::DidUpdateScreens(
    LocalFrame& frame,
    const display::ScreenInfos& screen_infos) {
  auto* window = frame.DomWindow();
  if (auto* supplement =
          Supplement<LocalDOMWindow>::From<WindowScreenDetails>(window)) {
    // screen_details() may be null if permission has not been granted.
    if (auto* screen_details = supplement->screen_details()) {
      screen_details->UpdateScreenInfos(window, screen_infos);
    }
  }
}

void ModulesInitializer::SetLocalStorageArea(
    LocalFrame& frame,
    mojo::PendingRemote<mojom::blink::StorageArea> local_storage_area) {
  if (!frame.DomWindow())
    return;
  DOMWindowStorage::From(*frame.DomWindow())
      .InitLocalStorage(std::move(local_storage_area));
}

void ModulesInitializer::SetSessionStorageArea(
    LocalFrame& frame,
    mojo::PendingRemote<mojom::blink::StorageArea> session_storage_area) {
  if (!frame.DomWindow())
    return;
  DOMWindowStorage::From(*frame.DomWindow())
      .InitSessionStorage(std::move(session_storage_area));
}

mojom::blink::FileSystemManager& ModulesInitializer::GetFileSystemManager(
    ExecutionContext* context) {
  return FileSystemDispatcher::From(context).GetFileSystemManager();
}

void ModulesInitializer::RegisterInterfaces(mojo::BinderMap& binders) {
  DCHECK(Platform::Current());
  binders.Add<mojom::blink::WebDatabase>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&WebDatabaseImpl::Bind)),
      Platform::Current()->GetIOTaskRunner());
}

}  // namespace blink
```
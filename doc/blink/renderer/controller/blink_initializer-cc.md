Response:
Let's break down the thought process for analyzing this `blink_initializer.cc` file.

1. **Understand the Goal:** The request asks for the function of the file, its relation to web technologies, examples, logical reasoning, potential errors, and debugging information.

2. **High-Level Overview (Skimming the Code):**
    * The file name `blink_initializer.cc` strongly suggests it's responsible for setting up and initializing parts of the Blink rendering engine.
    * The includes reveal dependencies on platform abstractions (`Platform.h`), core Blink components (`Document.h`, `LocalFrame.h`), JavaScript integration (`V8Initializer.h`), and some system-level functionalities (`base`, `mojo`).
    * The copyright notice indicates Google and their contributors.

3. **Identify Key Classes and Functions:**
    * The `BlinkInitializer` class itself is the central point. Its methods (`Initialize`, `RegisterInterfaces`, `RegisterMemoryWatchers`, `InitLocalFrame`, etc.) are the actions it performs.
    * Functions like `Initialize`, `CreateMainThreadAndInitialize` are exported and likely used by the embedding browser (e.g., Chromium).
    * Classes related to specific features like `DevToolsFrontendImpl`, `OomInterventionImpl`, `MemoryUsageMonitorPosix`, etc., hint at specific functionalities being initialized.

4. **Analyze Functionality by Sections:**

    * **Initialization:** Focus on `Initialize`, `CreateMainThreadAndInitialize`, and `InitializeCommon`. Notice the order of operations: Platform initialization, V8 initialization, registering interfaces, registering memory watchers. This establishes a boot-up sequence. The inclusion of `V8Initializer` strongly ties this to JavaScript.

    * **Interface Registration:**  The `RegisterInterfaces` method using `mojo::BinderMap` clearly deals with setting up communication channels between different parts of the browser process (renderer and others). The bound interfaces (`OomIntervention`, `CrashMemoryMetricsReporter`, etc.) represent specific services the renderer provides.

    * **Memory Management:** `RegisterMemoryWatchers` and the included headers like `MemoryTracer.h`, `HighestPmfReporter.h`, and discussions of `WTF::Partitions` point towards memory monitoring and management as a key function.

    * **Frame Initialization:** `InitLocalFrame` is crucial for understanding how the rendering engine sets up individual web page frames. The registration of interfaces like `DisplayCutoutClientImpl` and `DevToolsFrontendImpl` directly relates to browser features.

    * **Service Worker Initialization:** `InitServiceWorkerGlobalScope` shows how Blink sets up the environment for service workers, a core web technology.

    * **Clearing Window Object:** `OnClearWindowObjectInMainWorld` is related to the lifecycle of a web page and how the JavaScript environment is reset. The mention of `DevToolsFrontendImpl` is significant.

    * **Foreground/Background Handling:** `OnProcessForegrounded` and `OnProcessBackgrounded` indicate how Blink adjusts its memory management based on the visibility of the browser window.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **JavaScript:** The strong dependency on `V8Initializer` is the primary connection. The initialization of the V8 JavaScript engine is a core function. The `JavaScriptCallStackGenerator` also explicitly relates to JavaScript debugging. `OnClearWindowObjectInMainWorld` directly affects the JavaScript global scope.

    * **HTML:** The initialization of `LocalFrame` is directly tied to the rendering of HTML documents. The `Document` class is central to the HTML DOM.

    * **CSS:** While not as explicit as JavaScript, the `LocalFrame` initialization and the broader rendering pipeline implicitly involve CSS processing. The file doesn't directly initialize CSS engines, but it sets up the context where CSS will be used.

6. **Logical Reasoning and Examples:**

    * **Assumption:** The code initializes the JavaScript engine.
    * **Input:** Browser starts, needs to render a webpage.
    * **Output:** V8 is initialized, allowing execution of `<script>` tags and JavaScript events.

7. **User/Programming Errors:**

    * **Incorrect Platform Initialization:**  Failing to properly initialize the platform before calling Blink initialization functions would be a major error.
    * **Missing Bindings:** If a required interface isn't registered in `RegisterInterfaces`, features relying on that interface would break.

8. **Debugging and User Actions:**

    * **User Action:** Opening a new tab or navigating to a website.
    * **Path:** Browser process -> Renderer process creation -> Blink initialization (`Initialize` or `CreateMainThreadAndInitialize`). Stepping through the initialization functions in a debugger would lead to this file.

9. **Refine and Structure the Answer:**  Organize the findings into clear sections (Functions, Relationships, Examples, Errors, Debugging). Use precise language and refer to specific code elements where possible.

10. **Review and Enhance:** Read through the generated answer, check for clarity, accuracy, and completeness. Are there any other relevant details that could be added?  For instance, emphasizing the role of Mojo in inter-process communication.

Self-Correction during the Process:

* **Initial thought:** Focus solely on JavaScript. **Correction:** Realize the file's broader role in initializing the *rendering engine* and its dependencies on platform and core Blink components.
* **Initial thought:** Only list obvious connections to web tech. **Correction:**  Think about *how* the initializations relate to the execution of JavaScript, parsing of HTML, and application of CSS.
* **Initial thought:** Focus on the code in isolation. **Correction:** Consider the context – how is this file called? What are the consequences of its actions?

By following these steps, including the self-correction, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析 `blink/renderer/controller/blink_initializer.cc` 这个文件。

**功能概述**

`blink_initializer.cc` 文件的核心功能是 **初始化 Blink 渲染引擎** 的各个子系统和服务。它负责在渲染进程启动时，进行一系列关键的设置和注册，以便让 Blink 能够正常工作，处理网页内容，执行 JavaScript，以及与浏览器进程进行通信。

**具体功能列表：**

1. **平台初始化:** 调用 `Platform::InitializeMainThread` 或 `Platform::CreateMainThreadAndInitialize` 来初始化与底层操作系统交互的平台层。
2. **V8 JavaScript 引擎初始化:** 调用 `V8Initializer::InitializeIsolateHolder` 和 `V8Initializer::InitializeMainThread` 来初始化 V8 JavaScript 引擎，这是 Blink 中执行 JavaScript 代码的关键组件。
3. **接口注册 (Interface Registration):**  通过 `mojo::BinderMap` 注册一系列的 Mojo 接口。这些接口定义了渲染进程可以提供的服务，以及它可以与浏览器进程和其他进程进行通信的方式。
4. **内存监视器注册 (Memory Watcher Registration):** 注册用于监控内存使用情况的组件，例如 `MemoryTracer` 和 `HighestPmfReporter`。
5. **本地 Frame 初始化 (LocalFrame Initialization):** 当创建新的本地 Frame（通常对应于一个 HTML 文档）时，会调用 `InitLocalFrame` 进行初始化，例如注册与开发者工具前端的连接、显示裁剪区域客户端等。
6. **Service Worker 全局作用域初始化 (ServiceWorkerGlobalScope Initialization):** 当创建 Service Worker 的全局作用域时，会调用 `InitServiceWorkerGlobalScope` 进行初始化。
7. **窗口对象清除处理 (Window Object Clearing):** 当一个文档的 window 对象被清除时（例如页面刷新），会调用 `OnClearWindowObjectInMainWorld` 来通知相关的组件，例如开发者工具前端。
8. **进程前后台状态处理 (Process Foreground/Background Handling):**  提供 `OnProcessForegrounded` 和 `OnProcessBackgrounded` 函数，用于在渲染进程切换到前台或后台时调整内存分配策略。
9. **扩展初始化:** 如果启用了特定的扩展（如 ChromeOS 或 WebView 扩展），会调用相应的初始化函数。
10. **命令开关处理:**  读取命令行参数，例如 JavaScript 标志，并传递给相应的组件。
11. **内存分区初始化:** 初始化用于 ArrayBuffer 等的内存分区。

**与 JavaScript, HTML, CSS 的关系及举例说明**

`blink_initializer.cc` 的功能与 JavaScript, HTML, 和 CSS 都有着密切的关系，因为它负责初始化支撑这些技术运行的基础设施。

* **JavaScript:**
    * **初始化 V8 引擎:**  这是最直接的关系。`V8Initializer::InitializeIsolateHolder` 和 `V8Initializer::InitializeMainThread` 确保了 JavaScript 代码可以在 Blink 中被解析、编译和执行。
        * **假设输入:**  渲染进程启动。
        * **输出:**  V8 引擎完成初始化，可以创建和执行 JavaScript 上下文。
    * **`JavaScriptCallStackGenerator` 接口:** 这个接口允许其他进程请求当前渲染进程的 JavaScript 调用栈信息，这对于调试和性能分析至关重要。
        * **用户操作:** 在开发者工具中打开 "Sources" 面板，尝试断点调试或查看调用栈。
        * **机制:** 开发者工具前端通过 Mojo 调用渲染进程的 `JavaScriptCallStackGenerator::Bind` 注册的接口，请求调用栈信息。
    * **`OnClearWindowObjectInMainWorld`:** 当页面刷新或导航到新页面时，旧页面的 JavaScript 环境需要被清理。这个函数会被调用，通知相关组件进行清理工作。
        * **用户操作:** 点击浏览器的刷新按钮或输入新的网址并回车。
        * **机制:**  Blink 内部在文档卸载流程中调用此函数，开发者工具前端接收到通知后会清理相关的调试信息。

* **HTML:**
    * **`InitLocalFrame`:**  当浏览器加载 HTML 页面时，会创建一个 `LocalFrame` 对象来表示该页面的框架。`InitLocalFrame` 会注册一些与 Frame 相关的服务，这些服务可以影响 HTML 文档的加载、渲染和交互。
        * **假设输入:**  浏览器接收到一个 HTML 文档。
        * **输出:**  创建一个 `LocalFrame` 对象，并调用 `InitLocalFrame` 进行初始化，例如注册 `DisplayCutoutClientImpl` 来处理显示裁剪区域。
    * **接口注册:**  注册的某些接口可能直接用于处理 HTML 相关的操作，例如加载资源、处理表单等。

* **CSS:**
    * 虽然 `blink_initializer.cc` 没有直接初始化 CSS 解析器或渲染引擎，但它为这些组件的运行提供了必要的环境。例如，`LocalFrame` 的初始化是渲染 CSS 的前提。
    * **内存管理:**  对内存的有效管理对于处理复杂的 CSS 样式至关重要。`blink_initializer.cc` 中注册的内存监视器可以帮助检测和解决与 CSS 相关的内存问题。

**逻辑推理的假设输入与输出**

* **假设输入:**  在命令行中指定了特定的 JavaScript 标志，例如 `--js-flags="--expose-gc" `。
* **输出:** `V8Initializer::InitializeIsolateHolder` 函数会读取这些标志，并将它们传递给 V8 引擎，从而启用 V8 的垃圾回收器暴露接口。

**用户或编程常见的使用错误**

* **没有正确初始化 Platform:**  如果 embedding 应用（如 Chromium）没有在调用 Blink 的初始化函数之前正确初始化 `Platform` 对象，会导致 Blink 无法获取必要的系统服务，从而崩溃或功能异常。
    * **错误示例:**  忘记调用 `Platform::Initialize` 或提供了错误的平台实现。
* **Mojo 接口绑定错误:**  如果在 `RegisterInterfaces` 中绑定 Mojo 接口时出现错误，例如绑定了错误的实现或使用了错误的线程，会导致跨进程通信失败，功能受损。
    * **错误示例:**  在非主线程上绑定了需要访问主线程数据的接口实现。

**用户操作如何一步步到达这里 (作为调试线索)**

1. **用户启动浏览器:** 当用户启动 Chrome 或其他基于 Chromium 的浏览器时，浏览器进程会启动。
2. **浏览器进程创建渲染进程:** 当浏览器需要加载一个网页时，它会创建一个新的渲染进程（或重用一个已有的）。
3. **渲染进程初始化:**  在渲染进程启动的早期阶段，会调用 Blink 的初始化代码。入口点通常在 `content/renderer/renderer_main.cc` 或类似的文件中。
4. **调用 `blink::Initialize` 或 `blink::CreateMainThreadAndInitialize`:**  在渲染进程的主线程上，会调用 `blink::Initialize` 或 `blink::CreateMainThreadAndInitialize` 函数，这是 `blink_initializer.cc` 中定义的。
5. **执行初始化步骤:**  `blink_initializer.cc` 中的代码会按顺序执行上述的各种初始化步骤，例如初始化平台、V8 引擎、注册接口等。

**调试线索:**

* **渲染进程崩溃或启动失败:** 如果在浏览器启动或加载网页时遇到渲染进程崩溃的问题，可以考虑 `blink_initializer.cc` 中的初始化过程是否存在问题。
* **JavaScript 功能异常:** 如果 JavaScript 代码无法正常执行，或者开发者工具无法连接到渲染进程，可能与 V8 引擎的初始化或 `JavaScriptCallStackGenerator` 接口的注册有关。
* **跨进程通信问题:** 如果渲染进程与其他进程之间的通信出现问题，可以检查 `RegisterInterfaces` 函数中 Mojo 接口的绑定是否正确。

**总结**

`blink_initializer.cc` 是 Blink 渲染引擎启动的基石，它负责初始化各种核心组件和服务，为网页的加载、渲染和交互提供了必要的支持。理解它的功能对于调试渲染引擎的问题至关重要。通过分析其代码和关联的接口，我们可以更好地理解 Blink 的内部运作机制。

### 提示词
```
这是目录为blink/renderer/controller/blink_initializer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/controller/blink_initializer.h"

#include <memory>
#include <utility>

#include "base/command_line.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "build/build_config.h"
#include "mojo/public/cpp/bindings/binder_map.h"
#include "partition_alloc/page_allocator.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/switches.h"
#include "third_party/blink/public/platform/interface_registry.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_context_snapshot.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_initializer.h"
#include "third_party/blink/renderer/controller/blink_leak_detector.h"
#include "third_party/blink/renderer/controller/dev_tools_frontend_impl.h"
#include "third_party/blink/renderer/controller/javascript_call_stack_generator.h"
#include "third_party/blink/renderer/controller/memory_tracer.h"
#include "third_party/blink/renderer/controller/performance_manager/renderer_resource_coordinator_impl.h"
#include "third_party/blink/renderer/controller/performance_manager/v8_detailed_memory_reporter_impl.h"
#include "third_party/blink/renderer/core/animation/animation_clock.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/display_cutout_client_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/loader_factory_for_frame.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/disk_data_allocator.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "v8/include/v8.h"

#if defined(USE_BLINK_EXTENSIONS_CHROMEOS)
#include "third_party/blink/renderer/extensions/chromeos/chromeos_extensions.h"
#endif

#if defined(USE_BLINK_EXTENSIONS_WEBVIEW)
#include "third_party/blink/renderer/extensions/webview/webview_extensions.h"
#endif

#if BUILDFLAG(IS_ANDROID)
#include "third_party/blink/renderer/controller/crash_memory_metrics_reporter_impl.h"
#include "third_party/blink/renderer/controller/oom_intervention_impl.h"
#include "third_party/blink/renderer/controller/private_memory_footprint_provider.h"
#endif

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#include "third_party/blink/renderer/controller/memory_usage_monitor_posix.h"
#endif

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID) || \
    BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_WIN)
#include "third_party/blink/renderer/controller/highest_pmf_reporter.h"
#include "third_party/blink/renderer/controller/user_level_memory_pressure_signal_generator.h"
#endif

// #if expression should match the one in InitializeCommon
#if !defined(ARCH_CPU_X86_64) && !defined(ARCH_CPU_ARM64) && BUILDFLAG(IS_WIN)
#include <windows.h>
#endif

namespace blink {

namespace {

class EndOfTaskRunner : public Thread::TaskObserver {
 public:
  void WillProcessTask(const base::PendingTask&, bool) override {
    AnimationClock::NotifyTaskStart();
  }
  void DidProcessTask(const base::PendingTask& pending_task) override {}
};

Thread::TaskObserver* g_end_of_task_runner = nullptr;

BlinkInitializer& GetBlinkInitializer() {
  DEFINE_STATIC_LOCAL(std::unique_ptr<BlinkInitializer>, initializer,
                      (std::make_unique<BlinkInitializer>()));
  return *initializer;
}

void InitializeCommon(Platform* platform, mojo::BinderMap* binders) {
// #if expression should match the one around #include <windows.h>
#if !defined(ARCH_CPU_X86_64) && !defined(ARCH_CPU_ARM64) && BUILDFLAG(IS_WIN)
  // Reserve address space on 32 bit Windows, to make it likelier that large
  // array buffer allocations succeed.
  BOOL is_wow_64 = -1;
  if (!IsWow64Process(GetCurrentProcess(), &is_wow_64)) {
    is_wow_64 = FALSE;
  }
  if (!is_wow_64) {
    // Try to reserve as much address space as we reasonably can.
    const size_t kMB = 1024 * 1024;
    for (size_t size = 512 * kMB; size >= 32 * kMB; size -= 16 * kMB) {
      if (partition_alloc::ReserveAddressSpace(size)) {
        break;
      }
    }
  }
#endif  // !defined(ARCH_CPU_X86_64) && !defined(ARCH_CPU_ARM64) &&
        // BUILDFLAG(IS_WIN)

  // These Initialize() methods for renderer extensions initialize strings which
  // must be done before calling CoreInitializer::Initialize() which is called
  // by GetBlinkInitializer().Initialize() below.
#if defined(USE_BLINK_EXTENSIONS_CHROMEOS)
  ChromeOSExtensions::Initialize();
#endif
#if defined(USE_BLINK_EXTENSIONS_WEBVIEW)
  WebViewExtensions::Initialize();
#endif

  // BlinkInitializer::Initialize() must be called before InitializeMainThread
  GetBlinkInitializer().Initialize();

  blink::V8Initializer::InitializeIsolateHolder(
      blink::V8ContextSnapshot::GetReferenceTable(),
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          blink::switches::kJavaScriptFlags));

  GetBlinkInitializer().RegisterInterfaces(*binders);

  DCHECK(!g_end_of_task_runner);
  g_end_of_task_runner = new EndOfTaskRunner;
  Thread::Current()->AddTaskObserver(g_end_of_task_runner);

  GetBlinkInitializer().RegisterMemoryWatchers(platform);

  // Initialize performance manager.
  RendererResourceCoordinatorImpl::MaybeInitialize();

  // The ArrayBuffer partition is placed inside V8's virtual memory cage if it
  // is enabled. For that reason, the partition can only be initialized after V8
  // has been initialized.
  WTF::Partitions::InitializeArrayBufferPartition();
}

}  // namespace

// Function defined in third_party/blink/public/web/blink.h.
void Initialize(Platform* platform,
                mojo::BinderMap* binders,
                scheduler::WebThreadScheduler* main_thread_scheduler) {
  DCHECK(binders);
  Platform::InitializeMainThread(platform, main_thread_scheduler);
  InitializeCommon(platform, binders);
  V8Initializer::InitializeMainThread();
}

// Function defined in third_party/blink/public/web/blink.h.
void CreateMainThreadAndInitialize(Platform* platform,
                                   mojo::BinderMap* binders) {
  DCHECK(binders);
  Platform::CreateMainThreadAndInitialize(platform);
  InitializeCommon(platform, binders);
}

void InitializeWithoutIsolateForTesting(
    Platform* platform,
    mojo::BinderMap* binders,
    scheduler::WebThreadScheduler* main_thread_scheduler) {
  Platform::InitializeMainThread(platform, main_thread_scheduler);
  InitializeCommon(platform, binders);
}

v8::Isolate* CreateMainThreadIsolate() {
  return V8Initializer::InitializeMainThread();
}

// Function defined in third_party/blink/public/web/blink.h.
void SetIsCrossOriginIsolated(bool value) {
  Agent::SetIsCrossOriginIsolated(value);
}

// Function defined in third_party/blink/public/web/blink.h.
void SetIsWebSecurityDisabled(bool value) {
  Agent::SetIsWebSecurityDisabled(value);
}

// Function defined in third_party/blink/public/web/blink.h.
void SetIsIsolatedContext(bool value) {
  Agent::SetIsIsolatedContext(value);
}

// Function defined in third_party/blink/public/web/blink.h.
bool IsIsolatedContext() {
  return Agent::IsIsolatedContext();
}

// Function defined in third_party/blink/public/web/blink.h.
void SetCorsExemptHeaderList(
    const WebVector<WebString>& web_cors_exempt_header_list) {
  Vector<String> cors_exempt_header_list(
      base::checked_cast<wtf_size_t>(web_cors_exempt_header_list.size()));
  base::ranges::transform(web_cors_exempt_header_list,
                          cors_exempt_header_list.begin(),
                          &WebString::operator WTF::String);
  LoaderFactoryForFrame::SetCorsExemptHeaderList(
      std::move(cors_exempt_header_list));
}

void BlinkInitializer::RegisterInterfaces(mojo::BinderMap& binders) {
  ModulesInitializer::RegisterInterfaces(binders);
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner =
      Thread::MainThread()->GetTaskRunner(MainThreadTaskRunnerRestricted());
  CHECK(main_thread_task_runner);

#if BUILDFLAG(IS_ANDROID)
  binders.Add<mojom::blink::OomIntervention>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&OomInterventionImpl::BindReceiver,
                                   WTF::RetainedRef(main_thread_task_runner))),
      main_thread_task_runner);

  binders.Add<mojom::blink::CrashMemoryMetricsReporter>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&CrashMemoryMetricsReporterImpl::Bind)),
      main_thread_task_runner);
#endif

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  binders.Add<mojom::blink::MemoryUsageMonitorLinux>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&MemoryUsageMonitorPosix::Bind)),
      main_thread_task_runner);
#endif

  binders.Add<mojom::blink::LeakDetector>(
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &BlinkLeakDetector::Bind, WTF::RetainedRef(main_thread_task_runner))),
      main_thread_task_runner);

  binders.Add<mojom::blink::DiskAllocator>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&DiskDataAllocator::Bind)),
      main_thread_task_runner);

  binders.Add<mojom::blink::V8DetailedMemoryReporter>(
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&V8DetailedMemoryReporterImpl::Bind)),
      main_thread_task_runner);

    DCHECK(Platform::Current());
    // We need to use the IO task runner here because the call stack generator
    // should work even when the main thread is blocked.
    binders.Add<mojom::blink::CallStackGenerator>(
        ConvertToBaseRepeatingCallback(
            CrossThreadBindRepeating(&JavaScriptCallStackGenerator::Bind)),
        Platform::Current()->GetIOTaskRunner());
}

void BlinkInitializer::RegisterMemoryWatchers(Platform* platform) {
  scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner =
      Thread::MainThread()->GetTaskRunner(MainThreadTaskRunnerRestricted());
#if BUILDFLAG(IS_ANDROID)
  // Initialize CrashMemoryMetricsReporterImpl in order to assure that memory
  // allocation does not happen in OnOOMCallback.
  CrashMemoryMetricsReporterImpl::Instance();

  // Initialize UserLevelMemoryPressureSignalGenerator so it starts monitoring.
  if (platform->IsUserLevelMemoryPressureSignalEnabled()) {
    UserLevelMemoryPressureSignalGenerator::Initialize(platform,
                                                       main_thread_task_runner);
  }
#endif

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID) || \
    BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_WIN)
  // Start reporting the highest private memory footprint after the first
  // navigation.
  HighestPmfReporter::Initialize(main_thread_task_runner);

  // And tracing memory metrics to "system_metrics" when enabled.
  MemoryTracer::Initialize();
#endif

#if BUILDFLAG(IS_ANDROID)
  // Initialize PrivateMemoryFootprintProvider to start providing the value
  // for the browser process.
  PrivateMemoryFootprintProvider::Initialize(main_thread_task_runner);
#endif
}

void BlinkInitializer::InitLocalFrame(LocalFrame& frame) const {
  if (RuntimeEnabledFeatures::DisplayCutoutAPIEnabled()) {
    frame.GetInterfaceRegistry()->AddAssociatedInterface(
        WTF::BindRepeating(&DisplayCutoutClientImpl::BindMojoReceiver,
                           WrapWeakPersistent(&frame)));
  }
  frame.GetInterfaceRegistry()->AddAssociatedInterface(WTF::BindRepeating(
      &DevToolsFrontendImpl::BindMojoRequest, WrapWeakPersistent(&frame)));

  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &LocalFrame::PauseSubresourceLoading, WrapWeakPersistent(&frame)));

  frame.GetInterfaceRegistry()->AddInterface(WTF::BindRepeating(
      &AnnotationAgentContainerImpl::BindReceiver, WrapWeakPersistent(&frame)));
  ModulesInitializer::InitLocalFrame(frame);
}

void BlinkInitializer::InitServiceWorkerGlobalScope(
    ServiceWorkerGlobalScope& worker_global_scope) const {
#if defined(USE_BLINK_EXTENSIONS_CHROMEOS)
  ChromeOSExtensions::InitServiceWorkerGlobalScope(worker_global_scope);
#endif
}

void BlinkInitializer::OnClearWindowObjectInMainWorld(
    Document& document,
    const Settings& settings) const {
  if (DevToolsFrontendImpl* devtools_frontend =
          DevToolsFrontendImpl::From(document.GetFrame())) {
    devtools_frontend->DidClearWindowObject();
  }
  ModulesInitializer::OnClearWindowObjectInMainWorld(document, settings);
}

// Function defined in third_party/blink/public/web/blink.h.
void OnProcessForegrounded() {
  WTF::Partitions::AdjustPartitionsForForeground();
}

// Function defined in third_party/blink/public/web/blink.h.
void OnProcessBackgrounded() {
  WTF::Partitions::AdjustPartitionsForBackground();
}

}  // namespace blink
```
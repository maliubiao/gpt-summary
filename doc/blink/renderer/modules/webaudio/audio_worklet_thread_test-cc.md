Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The request asks for the functionality of `audio_worklet_thread_test.cc`, its relation to web technologies (JavaScript, HTML, CSS), logical inferences, common errors, and debugging information. The key is to understand *what* this code tests and *how*.

2. **Identify the Core Subject:** The filename itself, `audio_worklet_thread_test.cc`, immediately points to the central theme: testing the behavior of audio worklet threads within the Chromium/Blink engine.

3. **Scan for Key Classes and Namespaces:**  A quick skim reveals important namespaces and classes:
    * `blink`: This is the core Blink rendering engine namespace.
    * `webaudio`: This confirms the focus is on Web Audio API.
    * `AudioWorkletThreadTest`: The main test fixture class.
    * `WorkerThread`: A fundamental class representing a separate execution thread.
    * `RealtimeAudioWorkletThread`, `OfflineAudioWorkletThread`, `SemiRealtimeAudioWorkletThread`: Specific types of audio worklet threads, hinting at different operational modes.
    * `AudioWorkletMessagingProxy`:  Suggests inter-thread communication.
    * `ScriptController`, `ModuleRecord`:  Indicates interaction with JavaScript execution.
    * `PageTestBase`, `ModuleTestBase`:  Base classes for testing, providing infrastructure.

4. **Analyze the `AudioWorkletThreadTest` Class:** This class sets up the test environment:
    * `SetUp()` and `TearDown()`: Standard test fixture setup and cleanup. Note the clearing of shared backing threads – this is important for managing resources across tests.
    * `CreateAudioWorkletThread()`: A crucial method for creating different types of audio worklet threads based on parameters like `has_realtime_constraint` and `is_top_level_frame`. This immediately tells us these are key differentiators.
    * `CheckWorkletCanExecuteScript()`: Verifies basic JavaScript execution within the worklet thread.
    * `StartBackingThreadAndWaitUntilInit()`: Handles the initialization of the worker thread, involving setting up global scope, script loading, etc. The waiting mechanism is essential for synchronization.
    * `ExecuteScriptInWorklet()`:  Actually runs a simple JavaScript snippet within the worklet. The compilation and instantiation of a module are key steps.

5. **Examine the Test Cases:** Each `TEST_F` or `TEST_P` function focuses on specific aspects:
    * `Basic`: Simple creation and execution.
    * `CreateDifferentWorkletThreadsAndTerminate_1/2`: Verifies that different types of worklets (real-time vs. offline) or worklets from different frames run on separate threads. This is a core requirement for performance and isolation.
    * `AudioWorkletThreadInteractionTest`: Explores the lifecycle and interaction of multiple worklet threads, including creation order and termination. The parameterized tests (`INSTANTIATE_TEST_SUITE_P`) indicate different combinations of real-time constraints and frame levels are being tested.
    * `AudioWorkletThreadPriorityTest`: Focuses on the thread priority of audio worklet threads, considering real-time constraints and feature flags. The platform-specific `#if` block is important to notice.
    * `AudioWorkletRealtimePeriodTestMac`:  (Specific to macOS) Tests the real-time period configuration of threads.

6. **Connect to Web Technologies:**
    * **JavaScript:** The code directly deals with executing JavaScript within the worklet (`ExecuteScriptInWorklet`). The example script `var counter = 0; ++counter;` is simple but demonstrates the capability.
    * **HTML:** The test setup navigates to a URL (`NavigateTo(KURL("https://example.com/"))`). The concept of "top-level frame" is directly related to HTML structure. AudioWorklets are created and managed by JavaScript within a web page loaded in an HTML document.
    * **CSS:**  While not directly involved in *this specific test file*, CSS could indirectly influence audio worklets if, for example, heavy visual rendering on the main thread interfered with the performance required by real-time audio processing. However, this test focuses on the internal thread management.

7. **Infer Logical Relationships and Examples:** Based on the tests, we can infer:
    * Real-time audio worklets often get dedicated threads for low-latency processing.
    * The frame's context (top-level vs. subframe) can influence thread allocation.
    * Feature flags can control certain behaviors (like thread priority).
    * There's a mechanism for sharing threads in some scenarios to optimize resource usage.

8. **Identify Potential User/Programming Errors:**  Think about how developers might misuse the Audio Worklet API:
    * **Incorrect script:** Syntax errors or logic problems in the worklet script.
    * **Performance issues:**  Overly complex processing within the worklet, leading to glitches.
    * **Incorrect thread assumptions:**  Relying on worklets always being on separate threads when it's not guaranteed in all scenarios.
    * **Resource leaks:** Not properly terminating worklets.

9. **Trace User Actions to Code:** Consider the sequence of actions a user would take to trigger this code:
    1. Open a web page containing JavaScript that uses the `AudioWorklet` API.
    2. The JavaScript would register an audio processor by fetching and adding a module using `audioWorklet.addModule()`.
    3. The browser would then create an `AudioWorkletNode` that utilizes the registered processor.
    4. This node (and the associated processor) runs within an audio worklet thread.
    5. The tests in this file simulate this process programmatically to verify the underlying thread management and execution.

10. **Structure the Answer:** Organize the findings into clear sections based on the prompt's requirements: functionality, relationship to web technologies, logical inferences, errors, and debugging. Use concrete examples where possible.

By following these steps, we can systematically analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The process involves understanding the code's purpose, identifying key components, connecting them to relevant concepts, and reasoning about potential use cases and errors.
好的，我们来分析一下 `blink/renderer/modules/webaudio/audio_worklet_thread_test.cc` 这个文件的功能。

**文件功能概述:**

`audio_worklet_thread_test.cc` 是 Chromium Blink 引擎中用于测试 `AudioWorklet` 线程相关功能的单元测试文件。它的主要目的是验证不同类型的 AudioWorklet 在不同的场景下，是否按照预期地创建、管理和销毁线程，以及这些线程是否能够正确执行 JavaScript 代码。

**详细功能点:**

1. **测试不同类型的 AudioWorklet 线程创建:**
   - 测试在有实时性约束 (real-time constraint) 和没有实时性约束的情况下，是否分别创建了 `RealtimeAudioWorkletThread` 和 `OfflineAudioWorkletThread`。
   - 测试从主框架 (top-level frame) 和子框架 (sub-frame) 创建 AudioWorklet 时，线程的创建和管理是否符合预期。
   - 测试 `SemiRealtimeAudioWorkletThread` 的创建和行为（尽管代码中直接创建此类型的线程较少，但测试覆盖了相关逻辑）。

2. **测试 AudioWorklet 线程的生命周期管理:**
   - 测试线程的启动、执行 JavaScript 代码和终止过程是否正常。
   - 测试多个 AudioWorklet 线程的并发创建和销毁，以及它们之间的隔离性。
   - 测试在先创建一个 AudioWorklet 线程，然后再创建第二个，然后销毁第一个线程的情况下，第二个线程是否能正常运行。
   - 测试先销毁一个 AudioWorklet 线程，然后再创建一个新的线程，新的线程是否能正常创建和运行。

3. **测试 AudioWorklet 线程的隔离性:**
   - 验证具有不同实时性约束或来自不同框架的 AudioWorklet 是否在不同的线程上运行。
   - 验证在实时性约束的场景下，多个 AudioWorklet 实例在一定数量后会共享同一个后台线程。

4. **测试 AudioWorklet 线程的优先级:**
   - 测试在启用或禁用 `AudioWorkletThreadRealtimePriority` 特性标志的情况下，实时 AudioWorklet 线程的优先级是否正确设置（例如，在 macOS 上设置为 `kRealtimeAudio`）。
   - 测试离线 AudioWorklet 线程的优先级是否为 `kNormal`。

5. **(macOS 特有) 测试 AudioWorklet 线程的实时周期 (Realtime Period):**
   - 验证在 macOS 上，实时 AudioWorklet 线程的实时周期是否根据配置的缓冲区时长正确设置。

**与 JavaScript, HTML, CSS 的关系:**

这个测试文件主要关注 Blink 引擎内部的线程管理，与 JavaScript、HTML 和 CSS 的交互主要体现在以下方面：

* **JavaScript:**
    - **功能关系：** AudioWorklet 是通过 JavaScript API 来创建和使用的。开发者需要在 JavaScript 中调用 `audioContext.audioWorklet.addModule()` 来加载 AudioWorklet 处理器代码，并使用 `new AudioWorkletNode()` 创建节点。这个测试文件验证了执行这些 JavaScript 代码后，底层线程的创建和管理是否正确。
    - **举例说明：**  测试用例中使用了 `CheckWorkletCanExecuteScript` 函数，它会在 AudioWorklet 线程中执行一段简单的 JavaScript 代码 (`var counter = 0; ++counter;`)，以此来验证线程是否能够正常运行 JavaScript。

* **HTML:**
    - **功能关系：**  AudioWorklet 的使用通常发生在网页加载后，通过 JavaScript 在 HTML 文档的上下文中创建。测试中区分了 "top-level frame" 和非 top-level frame，这对应于 HTML 的 iframe 结构。
    - **举例说明：**  测试用例 `CreateDifferentWorkletThreadsAndTerminate_2` 模拟了从主框架和子框架分别创建 AudioWorklet 的场景，这与在 HTML 中使用 iframe 加载子页面并分别在主页面和 iframe 中使用 AudioWorklet 的情况相对应。

* **CSS:**
    - **功能关系：**  CSS 本身与 AudioWorklet 线程的直接管理关系不大。然而，CSS 渲染引起的性能问题可能会影响到需要实时处理的 AudioWorklet 的性能。这个测试文件主要关注线程的正确性，而不是性能。
    - **举例说明：**  虽然 CSS 不直接影响这里的测试，但在实际应用中，如果一个网页有复杂的 CSS 动画导致主线程繁忙，可能会间接影响到 AudioContext 和 AudioWorklet 的性能。

**逻辑推理、假设输入与输出:**

**假设输入：**
- `has_realtime_constraint = true`, `is_top_level_frame = true`
- JavaScript 代码成功加载并添加到 AudioContext 的 AudioWorklet 中。

**逻辑推理：**
根据 AudioWorklet 的设计，当 `has_realtime_constraint` 为 `true` 且从 top-level frame 创建时，系统应该创建一个专用的 `RealtimeAudioWorkletThread` 来保证音频处理的低延迟。

**预期输出：**
- 测试代码会断言确实创建了一个 `RealtimeAudioWorkletThread` 实例。
- 测试代码会断言该线程能够成功执行 JavaScript 代码。
- 测试代码会断言该线程的优先级被设置为适合实时音频处理的优先级。

**用户或编程常见的使用错误:**

1. **在不支持 AudioWorklet 的浏览器中使用:**  用户如果使用旧版本的浏览器，可能会遇到 `AudioWorklet` API 未定义或功能不完整的问题。
    - **错误示例 (JavaScript):**
      ```javascript
      if (audioContext.audioWorklet) {
        audioContext.audioWorklet.addModule('my-processor.js').then(() => {
          const oscillator = new OscillatorNode(audioContext);
          const workletNode = new AudioWorkletNode(audioContext, 'my-processor');
          oscillator.connect(workletNode).connect(audioContext.destination);
          oscillator.start();
        });
      } else {
        console.error('AudioWorklet is not supported in this browser.');
      }
      ```

2. **AudioWorklet 处理器代码中存在错误:**  如果 `my-processor.js` 中包含 JavaScript 语法错误或逻辑错误，AudioWorklet 线程虽然能创建，但处理器可能无法正常工作，导致音频处理出现问题。
    - **错误示例 (my-processor.js):**
      ```javascript
      class MyProcessor extends AudioWorkletProcessor {
        process(inputs, outputs, parameters) {
          // 错误：变量名拼写错误
          consoleLog('Processing audio');
          return true;
        }
      }
      registerProcessor('my-processor', MyProcessor);
      ```
    - **调试线索：** 浏览器的开发者工具控制台会显示来自 AudioWorklet 线程的错误信息。

3. **在不合适的场景下使用实时 AudioWorklet:**  如果对延迟不敏感的音频处理也使用实时 AudioWorklet，可能会不必要地占用系统资源。
    - **调试线索：**  可以通过浏览器的性能分析工具观察到过多的实时线程或较高的 CPU 占用。

4. **忘记正确终止 AudioWorklet 相关的资源:**  虽然这个测试主要关注线程本身，但在实际应用中，不正确地管理 AudioNode 的连接或忘记调用 `disconnect()` 可能会导致资源泄漏。

**用户操作如何一步步到达这里 (作为调试线索):**

假设开发者在开发一个使用 AudioWorklet 的网页应用，并且遇到了音频处理方面的问题，例如：

1. **开发者编写了 JavaScript 代码，使用了 `AudioContext` 和 `audioWorklet.addModule()` 加载了一个自定义的 AudioWorkletProcessor。**
   ```javascript
   const audioContext = new AudioContext();
   audioContext.audioWorklet.addModule('my-processor.js').then(() => {
     const oscillator = new OscillatorNode(audioContext);
     const workletNode = new AudioWorkletNode(audioContext, 'my-processor');
     oscillator.connect(workletNode).connect(audioContext.destination);
     oscillator.start();
   });
   ```

2. **在 `my-processor.js` 中实现了音频处理逻辑。**
   ```javascript
   class MyProcessor extends AudioWorkletProcessor {
     process(inputs, outputs, parameters) {
       // 音频处理逻辑
       return true;
     }
   }
   registerProcessor('my-processor', MyProcessor);
   ```

3. **用户在浏览器中打开了这个网页。**

4. **如果出现问题，比如音频处理不稳定、有杂音、或者性能不佳，开发者可能会开始调试。**

5. **作为调试线索，开发者可能会：**
   - **查看浏览器的开发者工具控制台，** 查找是否有 JavaScript 错误或来自 AudioWorklet 的错误消息。
   - **使用浏览器的性能分析工具，** 查看 CPU 使用情况、线程活动，以判断 AudioWorklet 线程是否按预期工作。
   - **如果怀疑是 Blink 引擎内部的问题，或者需要深入了解 AudioWorklet 线程的管理机制，开发者可能会查看 Blink 的源代码，** 这就可能涉及到 `audio_worklet_thread_test.cc` 这样的测试文件，以了解 Blink 是如何测试和管理这些线程的。查看测试代码可以帮助理解 AudioWorklet 线程在不同场景下的行为，从而更好地定位问题。

**总结:**

`audio_worklet_thread_test.cc` 是一个关键的测试文件，用于确保 Chromium Blink 引擎能够正确地创建、管理和销毁 AudioWorklet 线程。它覆盖了多种场景，包括不同类型的 AudioWorklet、不同的框架上下文以及线程优先级等。理解这个文件的功能有助于理解 AudioWorklet 的底层实现，并在遇到相关问题时提供调试思路。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_worklet_thread_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <memory>
#include <tuple>

#include "base/feature_list.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/module_record.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/worker_devtools_params.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/script/js_module_script.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/module_test_base.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread.h"
#include "third_party/blink/renderer/core/workers/worker_or_worklet_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/core/workers/worker_thread.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet_messaging_proxy.h"
#include "third_party/blink/renderer/modules/webaudio/cross_thread_audio_worklet_processor_info.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_worklet_thread.h"
#include "third_party/blink/renderer/modules/webaudio/realtime_audio_worklet_thread.h"
#include "third_party/blink/renderer/modules/webaudio/semi_realtime_audio_worklet_thread.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

class AudioWorkletThreadTest : public PageTestBase, public ModuleTestBase {
 public:
  void SetUp() override {
    ModuleTestBase::SetUp();
    PageTestBase::SetUp(gfx::Size());
    NavigateTo(KURL("https://example.com/"));
    reporting_proxy_ = std::make_unique<WorkerReportingProxy>();
  }

  void TearDown() override {
    OfflineAudioWorkletThread::ClearSharedBackingThread();
    WorkletThreadHolder<RealtimeAudioWorkletThread>::ClearInstance();
    SemiRealtimeAudioWorkletThread::ClearSharedBackingThread();
    ModuleTestBase::TearDown();
  }

  std::unique_ptr<WorkerThread> CreateAudioWorkletThread(
      bool has_realtime_constraint,
      bool is_top_level_frame,
      base::TimeDelta realtime_buffer_duration = base::Milliseconds(3)) {
    std::unique_ptr<WorkerThread> thread =
        AudioWorkletMessagingProxy::CreateWorkletThreadWithConstraints(
            *reporting_proxy_,
            has_realtime_constraint
                ? std::optional<base::TimeDelta>(realtime_buffer_duration)
                : std::nullopt,
            is_top_level_frame);
    StartBackingThreadAndWaitUntilInit(thread.get());
    return thread;
  }

  // Attempts to run some simple script for `thread`.
  void CheckWorkletCanExecuteScript(WorkerThread* thread) {
    base::WaitableEvent wait_event;
    PostCrossThreadTask(
        *thread->GetWorkerBackingThread().BackingThread().GetTaskRunner(),
        FROM_HERE,
        CrossThreadBindOnce(&AudioWorkletThreadTest::ExecuteScriptInWorklet,
                            CrossThreadUnretained(this),
                            CrossThreadUnretained(thread),
                            CrossThreadUnretained(&wait_event)));
    wait_event.Wait();
  }

 private:
  void StartBackingThreadAndWaitUntilInit(WorkerThread* thread) {
    LocalDOMWindow* window = GetFrame().DomWindow();
    thread->Start(
        std::make_unique<GlobalScopeCreationParams>(
            window->Url(), mojom::blink::ScriptType::kModule, "AudioWorklet",
            window->UserAgent(),
            window->GetFrame()->Loader().UserAgentMetadata(),
            nullptr /* web_worker_fetch_context */,
            Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
            Vector<network::mojom::blink::ContentSecurityPolicyPtr>(),
            window->GetReferrerPolicy(), window->GetSecurityOrigin(),
            window->IsSecureContext(), window->GetHttpsState(),
            nullptr /* worker_clients */, nullptr /* content_settings_client */,
            OriginTrialContext::GetInheritedTrialFeatures(window).get(),
            base::UnguessableToken::Create(), nullptr /* worker_settings */,
            mojom::blink::V8CacheOptions::kDefault,
            MakeGarbageCollected<WorkletModuleResponsesMap>(),
            mojo::NullRemote() /* browser_interface_broker */,
            window->GetFrame()->Loader().CreateWorkerCodeCacheHost(),
            window->GetFrame()->GetBlobUrlStorePendingRemote(),
            BeginFrameProviderParams(), nullptr /* parent_permissions_policy */,
            window->GetAgentClusterID(), ukm::kInvalidSourceId,
            window->GetExecutionContextToken()),
        std::optional(WorkerBackingThreadStartupData::CreateDefault()),
        std::make_unique<WorkerDevToolsParams>());

    // Wait until the cross-thread initialization is completed.
    base::WaitableEvent completion_event;
    PostCrossThreadTask(
        *thread->GetWorkerBackingThread().BackingThread().GetTaskRunner(),
        FROM_HERE,
        CrossThreadBindOnce(&base::WaitableEvent::Signal,
                            CrossThreadUnretained(&completion_event)));
    completion_event.Wait();
  }

  void ExecuteScriptInWorklet(WorkerThread* thread,
                              base::WaitableEvent* wait_event) {
    ScriptState* script_state =
        thread->GlobalScope()->ScriptController()->GetScriptState();
    EXPECT_TRUE(script_state);
    ScriptState::Scope scope(script_state);
    KURL js_url("https://example.com/worklet.js");
    v8::Local<v8::Module> module = ModuleTestBase::CompileModule(
        script_state, "var counter = 0; ++counter;", js_url);
    EXPECT_FALSE(module.IsEmpty());
    ScriptValue exception =
        ModuleRecord::Instantiate(script_state, module, js_url);
    EXPECT_TRUE(exception.IsEmpty());
    ScriptEvaluationResult result =
        JSModuleScript::CreateForTest(Modulator::From(script_state), module,
                                      js_url)
            ->RunScriptOnScriptStateAndReturnValue(script_state);
    EXPECT_EQ(result.GetResultType(),
              ScriptEvaluationResult::ResultType::kSuccess);
    wait_event->Signal();
  }

  std::unique_ptr<WorkerReportingProxy> reporting_proxy_;
};

TEST_F(AudioWorkletThreadTest, Basic) {
  std::unique_ptr<WorkerThread> audio_worklet_thread =
      CreateAudioWorkletThread(true, true);
  CheckWorkletCanExecuteScript(audio_worklet_thread.get());
  audio_worklet_thread->Terminate();
  audio_worklet_thread->WaitForShutdownForTesting();
}

// Creates 2 different AudioWorkletThreads with different RT constraints.
// Checks if they are running on a different thread.
TEST_F(AudioWorkletThreadTest, CreateDifferentWorkletThreadsAndTerminate_1) {
  // Create RealtimeAudioWorkletThread.
  std::unique_ptr<WorkerThread> first_worklet_thread =
      CreateAudioWorkletThread(true, true);
  Thread* first_backing_thread =
      &first_worklet_thread->GetWorkerBackingThread().BackingThread();
  v8::Isolate* first_isolate = first_worklet_thread->GetIsolate();

  // Create OfflineAudioWorkletThread.
  std::unique_ptr<WorkerThread> second_worklet_thread =
      CreateAudioWorkletThread(false, true);
  Thread* second_backing_thread =
      &second_worklet_thread->GetWorkerBackingThread().BackingThread();
  v8::Isolate* second_isolate = second_worklet_thread->GetIsolate();

  // Check if they are two different threads, and two different v8::isolates.
  ASSERT_NE(first_backing_thread, second_backing_thread);
  ASSERT_NE(first_isolate, second_isolate);

  first_worklet_thread->Terminate();
  first_worklet_thread->WaitForShutdownForTesting();
  second_worklet_thread->Terminate();
  second_worklet_thread->WaitForShutdownForTesting();
}

// Creates 2 AudioWorkletThreads with RT constraint from 2 different
// originating frames. Checks if they are running on a different thread.
TEST_F(AudioWorkletThreadTest, CreateDifferentWorkletThreadsAndTerminate_2) {
  // Create an AudioWorkletThread from a main frame with RT constraint.
  std::unique_ptr<WorkerThread> first_worklet_thread =
      CreateAudioWorkletThread(true, true);
  Thread* first_backing_thread =
      &first_worklet_thread->GetWorkerBackingThread().BackingThread();
  v8::Isolate* first_isolate = first_worklet_thread->GetIsolate();

  // Create an AudioWorkletThread from a sub frame with RT constraint.
  std::unique_ptr<WorkerThread> second_worklet_thread =
      CreateAudioWorkletThread(true, false);
  Thread* second_backing_thread =
      &second_worklet_thread->GetWorkerBackingThread().BackingThread();
  v8::Isolate* second_isolate = second_worklet_thread->GetIsolate();

  // Check if they are two different threads, and two different v8::isolates.
  ASSERT_NE(first_backing_thread, second_backing_thread);
  ASSERT_NE(first_isolate, second_isolate);

  first_worklet_thread->Terminate();
  first_worklet_thread->WaitForShutdownForTesting();
  second_worklet_thread->Terminate();
  second_worklet_thread->WaitForShutdownForTesting();
}

class AudioWorkletThreadInteractionTest
    : public AudioWorkletThreadTest,
      public testing::WithParamInterface<std::tuple<bool, bool>> {
 public:
  AudioWorkletThreadInteractionTest()
      : has_realtime_constraint_(std::get<0>(GetParam())),
        is_top_level_frame_(std::get<1>(GetParam())) {}

 protected:
  const bool has_realtime_constraint_;
  const bool is_top_level_frame_;
};

TEST_P(AudioWorkletThreadInteractionTest, CreateSecondAndTerminateFirst) {
  // Create the first worklet and wait until it is initialized.
  std::unique_ptr<WorkerThread> first_worklet_thread =
      CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
  Thread* first_backing_thread =
      &first_worklet_thread->GetWorkerBackingThread().BackingThread();
  CheckWorkletCanExecuteScript(first_worklet_thread.get());
  v8::Isolate* first_isolate = first_worklet_thread->GetIsolate();
  ASSERT_TRUE(first_isolate);

  // Create the second worklet and immediately destroy the first worklet.
  std::unique_ptr<WorkerThread> second_worklet_thread =
      CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
  Thread* second_backing_thread =
      &second_worklet_thread->GetWorkerBackingThread().BackingThread();
  CheckWorkletCanExecuteScript(second_worklet_thread.get());
  v8::Isolate* second_isolate = second_worklet_thread->GetIsolate();
  ASSERT_TRUE(second_isolate);

  // We don't use terminateAndWait here to avoid forcible termination.
  first_worklet_thread->Terminate();
  first_worklet_thread->WaitForShutdownForTesting();

  // Wait until the second worklet is initialized. Verify the equality of the
  // thread and the isolate of two instances; if it's for a real-time
  // BaseAudioContext and it's from a top-level frame, it should use different,
  // dedicated backing threads.
  if (has_realtime_constraint_ && is_top_level_frame_) {
    ASSERT_NE(first_backing_thread, second_backing_thread);
    ASSERT_NE(first_isolate, second_isolate);
  } else {
    ASSERT_EQ(first_backing_thread, second_backing_thread);
    ASSERT_EQ(first_isolate, second_isolate);
  }

  second_worklet_thread->Terminate();
  second_worklet_thread->WaitForShutdownForTesting();
}

TEST_P(AudioWorkletThreadInteractionTest, TerminateFirstAndCreateSecond) {
  // Create the first worklet, wait until it is initialized, and terminate it.
  std::unique_ptr<WorkerThread> worklet_thread =
      CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
  Thread* first_backing_thread =
      &worklet_thread->GetWorkerBackingThread().BackingThread();
  CheckWorkletCanExecuteScript(worklet_thread.get());

  // We don't use terminateAndWait here to avoid forcible termination.
  worklet_thread->Terminate();
  worklet_thread->WaitForShutdownForTesting();

  // Create the second worklet. The backing thread is same.
  worklet_thread =
      CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
  Thread* second_backing_thread =
      &worklet_thread->GetWorkerBackingThread().BackingThread();
  CheckWorkletCanExecuteScript(worklet_thread.get());

  if (has_realtime_constraint_ && is_top_level_frame_) {
    ASSERT_NE(first_backing_thread, second_backing_thread);
  } else {
    ASSERT_EQ(first_backing_thread, second_backing_thread);
  }

  worklet_thread->Terminate();
  worklet_thread->WaitForShutdownForTesting();
}

TEST_P(AudioWorkletThreadInteractionTest,
       ThreadManagementSystemForRealtimeAndTopLevelFrame) {
  // Creates 5 AudioWorkletThreads; based on the configuration (RT constraint,
  // frame level) they could be either RealtimeAudioWorkletThread,
  // SemiRealtimeAudioWorkletThread, or OfflineAudioWorkletThread with
  // different backing threads.
  constexpr int number_of_threads = 5;
  std::unique_ptr<WorkerThread> worklet_threads[number_of_threads];
  Thread* worklet_backing_threads[number_of_threads];
  for (int i = 0; i < number_of_threads; i++) {
    worklet_threads[i] =
        CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
    worklet_backing_threads[i] =
        &worklet_threads[i]->GetWorkerBackingThread().BackingThread();
  }

  if (has_realtime_constraint_ && is_top_level_frame_) {
    // For realtime contexts on a top-level frame, the first 3 worklet backing
    // threads are unique and do not share a backing thread.
    ASSERT_NE(worklet_backing_threads[0], worklet_backing_threads[1]);
    ASSERT_NE(worklet_backing_threads[0], worklet_backing_threads[2]);
    ASSERT_NE(worklet_backing_threads[1], worklet_backing_threads[2]);
    // They also differ from the 4th worklet backing thread, which is shared by
    // all subsequent AudioWorklet instances.
    ASSERT_NE(worklet_backing_threads[0], worklet_backing_threads[3]);
    ASSERT_NE(worklet_backing_threads[1], worklet_backing_threads[3]);
    ASSERT_NE(worklet_backing_threads[2], worklet_backing_threads[3]);
  } else {
    // For all other cases, a single worklet backing thread is shared by
    // multiple AudioWorklets.
    ASSERT_EQ(worklet_backing_threads[0], worklet_backing_threads[1]);
    ASSERT_EQ(worklet_backing_threads[0], worklet_backing_threads[2]);
    ASSERT_EQ(worklet_backing_threads[0], worklet_backing_threads[3]);
  }

  // In any case, all AudioWorklets after 4th instance will shared a single
  // backing thread.
  ASSERT_EQ(worklet_backing_threads[3], worklet_backing_threads[4]);

  if (has_realtime_constraint_ && is_top_level_frame_) {
    // Shut down the 3rd thread and verify 2 other dedicated threads are still
    // running.
    worklet_backing_threads[2] = nullptr;
    worklet_threads[2]->Terminate();
    worklet_threads[2]->WaitForShutdownForTesting();
    worklet_threads[2].reset();

    ASSERT_EQ(worklet_threads[0]->GetExitCodeForTesting(),
              WorkerThread::ExitCode::kNotTerminated);
    ASSERT_EQ(worklet_threads[1]->GetExitCodeForTesting(),
              WorkerThread::ExitCode::kNotTerminated);

    // Create a new thread and verify if 3 dedicated threads are running.
    std::unique_ptr<WorkerThread> new_worklet_thread =
        CreateAudioWorkletThread(has_realtime_constraint_, is_top_level_frame_);
    Thread* new_worklet_backing_thread =
          &new_worklet_thread->GetWorkerBackingThread().BackingThread();

    ASSERT_NE(worklet_backing_threads[0], new_worklet_backing_thread);
    ASSERT_NE(worklet_backing_threads[1], new_worklet_backing_thread);

    // It also should be different from a shared backing thread.
    ASSERT_NE(worklet_backing_threads[3], new_worklet_backing_thread);

    new_worklet_thread->Terminate();
    new_worklet_thread->WaitForShutdownForTesting();
  }

  // Shutting down one of worklet threads on a shared backing thread should not
  // affect other worklet threads.
  worklet_backing_threads[4] = nullptr;
  worklet_threads[4]->Terminate();
  worklet_threads[4]->WaitForShutdownForTesting();
  worklet_threads[4].reset();

  ASSERT_EQ(worklet_threads[3]->GetExitCodeForTesting(),
            WorkerThread::ExitCode::kNotTerminated);

  // Cleaning up remaining worklet threads.
  for (auto& worklet_thread : worklet_threads) {
    if (worklet_thread.get()) {
      worklet_thread->Terminate();
      worklet_thread->WaitForShutdownForTesting();
    }
  }
}

INSTANTIATE_TEST_SUITE_P(AudioWorkletThreadInteractionTestGroup,
                         AudioWorkletThreadInteractionTest,
                         testing::Combine(testing::Bool(), testing::Bool()));

struct ThreadPriorityTestParam {
  const bool has_realtime_constraint;
  const bool is_top_level_frame;
  const bool is_enabled_by_finch;
  const base::ThreadPriorityForTest expected_priority;
};

constexpr ThreadPriorityTestParam kThreadPriorityTestParams[] = {
    // RT thread enabled by Finch.
    {true, true, true, base::ThreadPriorityForTest::kRealtimeAudio},

    // RT thread disabled by Finch.
    {true, true, false, base::ThreadPriorityForTest::kNormal},

    // Non-main frame, RT thread enabled by Finch.
    {true, false, true, base::ThreadPriorityForTest::kDisplay},

    // Non-main frame, RT thread disabled by Finch.
    {true, false, false, base::ThreadPriorityForTest::kNormal},

    // The OfflineAudioContext always uses a NORMAL priority thread.
    {false, true, true, base::ThreadPriorityForTest::kNormal},
    {false, true, false, base::ThreadPriorityForTest::kNormal},
    {false, false, true, base::ThreadPriorityForTest::kNormal},
    {false, false, false, base::ThreadPriorityForTest::kNormal},
};

class AudioWorkletThreadPriorityTest
    : public AudioWorkletThreadTest,
      public testing::WithParamInterface<ThreadPriorityTestParam> {
 public:
  void InitWithRealtimePrioritySettings(bool is_enabled_by_finch) {
    std::vector<base::test::FeatureRef> enabled;
    std::vector<base::test::FeatureRef> disabled;
    if (is_enabled_by_finch) {
      enabled.push_back(features::kAudioWorkletThreadRealtimePriority);
    } else {
      disabled.push_back(features::kAudioWorkletThreadRealtimePriority);
    }
    feature_list_.InitWithFeatures(enabled, disabled);
  }

  void CreateCheckThreadPriority(
      bool has_realtime_constraint,
      bool is_top_level_frame,
      base::ThreadPriorityForTest expected_priority) {
    std::unique_ptr<WorkerThread> audio_worklet_thread =
        CreateAudioWorkletThread(has_realtime_constraint, is_top_level_frame);
    WorkerThread* thread = audio_worklet_thread.get();
    base::WaitableEvent wait_event;
    PostCrossThreadTask(
        *thread->GetWorkerBackingThread().BackingThread().GetTaskRunner(),
        FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletThreadPriorityTest::CheckThreadPriorityOnWorkerThread,
            CrossThreadUnretained(this),
            CrossThreadUnretained(thread),
            expected_priority,
            CrossThreadUnretained(&wait_event)));
    wait_event.Wait();
    audio_worklet_thread->Terminate();
    audio_worklet_thread->WaitForShutdownForTesting();
  }

 private:
  void CheckThreadPriorityOnWorkerThread(
      WorkerThread* thread,
      base::ThreadPriorityForTest expected_priority,
      base::WaitableEvent* wait_event) {
    ASSERT_TRUE(thread->IsCurrentThread());
    base::ThreadPriorityForTest actual_priority =
        base::PlatformThread::GetCurrentThreadPriorityForTest();

    // TODO(crbug.com/1022888): The worklet thread priority is always NORMAL
    // on OS_LINUX and OS_CHROMEOS regardless of the thread priority setting.
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
    if (expected_priority == base::ThreadPriorityForTest::kRealtimeAudio ||
        expected_priority == base::ThreadPriorityForTest::kDisplay) {
      EXPECT_EQ(actual_priority, base::ThreadPriorityForTest::kNormal);
    } else {
      EXPECT_EQ(actual_priority, expected_priority);
    }
#else
    EXPECT_EQ(actual_priority, expected_priority);
#endif

    wait_event->Signal();
  }
  base::test::ScopedFeatureList feature_list_;
};

TEST_P(AudioWorkletThreadPriorityTest, CheckThreadPriority) {
  const auto& test_param = GetParam();
  InitWithRealtimePrioritySettings(test_param.is_enabled_by_finch);
  CreateCheckThreadPriority(test_param.has_realtime_constraint,
                            test_param.is_top_level_frame,
                            test_param.expected_priority);
}

INSTANTIATE_TEST_SUITE_P(AudioWorkletThreadPriorityTestGroup,
                         AudioWorkletThreadPriorityTest,
                         testing::ValuesIn(kThreadPriorityTestParams));

}  // namespace blink

#if BUILDFLAG(IS_APPLE)

namespace WTF {
template <>
struct CrossThreadCopier<base::TimeDelta>
    : public CrossThreadCopierPassThrough<base::TimeDelta> {
  STATIC_ONLY(CrossThreadCopier);
};
}  // namespace WTF

namespace blink {

class AudioWorkletRealtimePeriodTestMac : public AudioWorkletThreadTest {
 public:
  std::unique_ptr<WorkerThread> CreateThreadAndCheckRealtimePeriod(
      base::TimeDelta realtime_buffer_duration,
      base::TimeDelta expected_realtime_period) {
    std::unique_ptr<WorkerThread> audio_worklet_thread =
        CreateAudioWorkletThread(/*has_realtime_constraint=*/true,
                                 /*is_top_level_frame=*/true,
                                 realtime_buffer_duration);
    WorkerThread* thread = audio_worklet_thread.get();
    base::WaitableEvent wait_event;
    PostCrossThreadTask(
        *thread->GetWorkerBackingThread().BackingThread().GetTaskRunner(),
        FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletRealtimePeriodTestMac::
                CheckThreadRealtimePeriodOnWorkerThread,
            CrossThreadUnretained(this), CrossThreadUnretained(thread),
            expected_realtime_period, CrossThreadUnretained(&wait_event)));
    wait_event.Wait();
    return audio_worklet_thread;
  }

 private:
  void CheckThreadRealtimePeriodOnWorkerThread(
      WorkerThread* thread,
      base::TimeDelta expected_realtime_period,
      base::WaitableEvent* wait_event) {
    ASSERT_TRUE(thread->IsCurrentThread());

    base::ThreadPriorityForTest actual_priority =
        base::PlatformThread::GetCurrentThreadPriorityForTest();

    base::TimeDelta actual_realtime_period =
        base::PlatformThread::GetCurrentThreadRealtimePeriodForTest();

    EXPECT_EQ(actual_priority, base::ThreadPriorityForTest::kRealtimeAudio);
    EXPECT_EQ(actual_realtime_period, expected_realtime_period);

    wait_event->Signal();
  }
};

TEST_F(AudioWorkletRealtimePeriodTestMac, CheckRealtimePeriod) {
  // Creates 5 realtime AudioWorkletThreads with different realtime buffer
  // durations; the last two will be sharing the same backing thread.
  base::TimeDelta realtime_buffer_durations[] = {
      base::Milliseconds(10), base::Milliseconds(20), base::Milliseconds(30),
      base::Milliseconds(40), base::Milliseconds(50)};

  std::vector<std::unique_ptr<WorkerThread>> worklet_threads;
  worklet_threads.push_back(CreateThreadAndCheckRealtimePeriod(
      realtime_buffer_durations[0], realtime_buffer_durations[0]));
  worklet_threads.push_back(CreateThreadAndCheckRealtimePeriod(
      realtime_buffer_durations[1], realtime_buffer_durations[1]));
  worklet_threads.push_back(CreateThreadAndCheckRealtimePeriod(
      realtime_buffer_durations[2], realtime_buffer_durations[2]));
  worklet_threads.push_back(CreateThreadAndCheckRealtimePeriod(
      realtime_buffer_durations[3], realtime_buffer_durations[3]));
  // Note: we expect that the last two worklets share the same backng thread, so
  // the should have the same realtime period.
  worklet_threads.push_back(CreateThreadAndCheckRealtimePeriod(
      realtime_buffer_durations[4], realtime_buffer_durations[3]));

  for (auto& worklet_thread : worklet_threads) {
    if (worklet_thread.get()) {
      worklet_thread->Terminate();
      worklet_thread->WaitForShutdownForTesting();
    }
  }
}

}  // namespace blink

#endif  // BUILDFLAG(IS_APPLE)
```
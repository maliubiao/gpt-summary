Response:
Let's break down the thought process for analyzing this C++ test file for Chromium's Blink engine.

**1. Understanding the Goal:**

The primary goal is to understand what this specific test file (`audio_worklet_global_scope_test.cc`) does. This involves identifying its purpose, the functionalities it tests, and how it relates to the broader web platform features.

**2. Initial Scan and Keyword Identification:**

A quick skim of the code immediately reveals some key terms and structures:

* `"third_party/blink/renderer/modules/webaudio/audio_worklet_global_scope.h"`:  This is the header file for the class being tested. It tells us the core subject is `AudioWorkletGlobalScope`.
* `testing/gtest/include/gtest/gtest.h`: This confirms it's a unit test using the Google Test framework.
* `AudioWorkletProcessor`, `registerProcessor`, `process`:  These terms point to the core functionality of Web Audio Worklets.
* `OfflineAudioWorkletThread`: This indicates the tests are being run in a non-real-time context, likely for ease of testing and without the constraints of a live audio stream.
* `ScriptState`, `v8::Isolate`, `ExpectEvaluateScriptModule`:  These are related to JavaScript execution within the worklet.
* `parameterDescriptors`:  This suggests testing the ability to define custom audio parameters.

**3. Deconstructing the Test Structure:**

The code is organized into a test fixture (`AudioWorkletGlobalScopeTest`) which inherits from `PageTestBase` and `ModuleTestBase`. This indicates the tests require a simulated page environment and access to Blink's module system.

Within the fixture, we see several helper methods:

* `CreateAudioWorkletThread()`:  Sets up the environment for running the audio worklet.
* `RunBasicTest`, `RunSimpleProcessTest`, `RunParsingTest`, `RunParsingParameterDescriptorTest`: These are the individual test cases, each focusing on a specific aspect.
* `ExpectEvaluateScriptModule()`:  A crucial helper for running JavaScript code within the worklet's context and checking for success or failure.
* `Run...OnWorkletThread()`: These methods are executed on the separate thread created for the worklet, allowing for isolated testing.

**4. Analyzing Individual Test Cases:**

* **`Basic`:** This test focuses on the fundamental setup. It checks if the `AudioWorkletGlobalScope` and its associated V8 environment (ScriptState, Isolate) are created correctly. It also tests the basic registration of an `AudioWorkletProcessor`. The key is the successful call to `registerProcessor` and the subsequent creation of a processor instance.

* **`Parsing`:** This test delves into the syntax of registering processors. It checks if different valid and invalid JavaScript class definitions are handled correctly by the `registerProcessor` method. This is important for ensuring the worklet API is robust against different coding styles.

* **`BufferProcessing`:** This test verifies the core functionality of processing audio data. It defines a simple processor that adds a constant to the input buffer and checks if the output buffer contains the expected result. This test directly exercises the `process()` method of the `AudioWorkletProcessor`. The input and output setup (filling with '1' and zeroing out respectively) are crucial for setting up a controlled scenario.

* **`ParsingParameterDescriptor`:** This test focuses on the `parameterDescriptors` static getter. It verifies that the worklet can define custom audio parameters with specific properties (name, default value, min/max values). This is essential for controlling the behavior of audio processors from the main thread.

**5. Connecting to Web Platform Concepts:**

At this point, it's important to relate these tests back to how Web Audio Worklets are used in web development:

* **JavaScript:** The tests heavily involve JavaScript code that defines the audio processing logic. The `registerProcessor` function is a core part of the Web Audio API.
* **HTML:**  While this specific test doesn't directly interact with HTML, in a real-world scenario, the audio worklet would be created and controlled from JavaScript running within an HTML page.
* **CSS:** CSS is generally not directly involved with the core logic of Web Audio Worklets.

**6. Inferring User Actions and Debugging:**

Based on the tests, we can infer user actions that might lead to this code being executed:

* A web developer using the Web Audio API to create and use an `AudioWorkletNode`.
* The developer provides JavaScript code to be executed within the audio worklet's global scope.
* The JavaScript code uses `registerProcessor` to define custom audio processors.
* The browser (Chromium in this case) then executes this JavaScript code within the `AudioWorkletGlobalScope`.

For debugging, if a developer encounters issues with their audio worklet:

* **Incorrect Processor Registration:** The "Parsing" test highlights potential errors in the class definition provided to `registerProcessor`.
* **Faulty Audio Processing Logic:** The "BufferProcessing" test demonstrates how incorrect logic in the `process()` method can lead to unexpected audio output.
* **Parameter Definition Issues:** The "ParsingParameterDescriptor" test shows how errors in the `parameterDescriptors` definition can affect the control of the processor.

**7. Refining and Organizing the Output:**

Finally, the information gathered needs to be structured logically and clearly. This involves:

* Starting with a concise summary of the file's purpose.
* Listing the specific functionalities being tested.
* Providing concrete examples of how the tests relate to web technologies (JavaScript).
* Formulating hypothetical input/output scenarios for the tests.
* Identifying common user errors and providing examples.
* Detailing the user actions that trigger this code, outlining a debugging path.

This iterative process of scanning, analyzing, connecting concepts, and refining the output allows for a comprehensive understanding of the given C++ test file and its significance within the Chromium browser.
这个C++源代码文件 `audio_worklet_global_scope_test.cc` 是 Chromium Blink 引擎中用于测试 `AudioWorkletGlobalScope` 类的单元测试文件。`AudioWorkletGlobalScope` 是 Web Audio API 中 `AudioWorklet` 的全局作用域，它允许开发者在独立的线程上使用 JavaScript 代码进行低延迟的音频处理。

**它的主要功能是：**

1. **测试 `AudioWorkletGlobalScope` 的基本功能:**  例如，测试全局作用域是否能够正确创建和初始化，是否能访问必要的对象和方法。
2. **测试 JavaScript 代码的执行:**  测试在 `AudioWorkletGlobalScope` 中执行 JavaScript 代码的能力，特别是与定义和注册 `AudioWorkletProcessor` 相关的代码。
3. **测试 `registerProcessor()` 方法:**  验证 `registerProcessor()` 方法能否正确注册自定义的 `AudioWorkletProcessor` 类。这包括解析 JavaScript 代码，检查类定义的有效性，以及存储处理器定义。
4. **测试 `AudioWorkletProcessor` 的实例化:**  验证可以通过已注册的名称创建 `AudioWorkletProcessor` 的实例。
5. **测试 `AudioWorkletProcessor` 的 `process()` 方法:**  模拟音频处理过程，调用 `AudioWorkletProcessor` 的 `process()` 方法，并验证输入和输出音频缓冲区的处理是否正确。
6. **测试 `AudioWorkletProcessor` 的 `parameterDescriptors` 静态属性:** 验证能否正确解析和存储 `parameterDescriptors` 中定义的音频参数信息，包括名称、默认值、最小值和最大值。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:** 该测试文件直接测试了在 `AudioWorkletGlobalScope` 中执行 JavaScript 代码的功能。`AudioWorklet` 的核心就是允许开发者编写 JavaScript 代码来处理音频。测试中使用了 `registerProcessor()` 方法，这是 Web Audio API 中定义的 JavaScript 方法。
    * **举例:** 测试用例中使用了 JavaScript 的 class 语法来定义 `AudioWorkletProcessor`，例如：
      ```javascript
      class TestProcessor extends AudioWorkletProcessor {
        constructor () { super(); }
        process () {}
      }
      registerProcessor('testProcessor', TestProcessor);
      ```
      这段代码在 `AudioWorkletGlobalScope` 中执行，测试会验证 `registerProcessor()` 是否成功将 `TestProcessor` 注册。
* **HTML:** 虽然这个测试文件本身是 C++ 代码，并不直接涉及 HTML，但在实际应用中，`AudioWorklet` 是通过 HTML 页面中的 JavaScript 代码创建和使用的。例如，在 HTML 页面的 `<script>` 标签中，开发者会使用 `AudioWorkletNode` 来加载和运行音频工作器脚本。
    * **举例:**  一个 HTML 页面可能包含以下 JavaScript 代码来使用 `AudioWorklet`:
      ```javascript
      const audioContext = new AudioContext();
      audioContext.audioWorklet.addModule('my-processor.js').then(() => {
        const myNode = new AudioWorkletNode(audioContext, 'my-processor');
        // 连接音频节点
        myNode.connect(audioContext.destination);
      });
      ```
      这里的 `my-processor.js` 中就可能包含类似测试用例中的 `registerProcessor()` 调用。
* **CSS:** CSS 与 `AudioWorklet` 的功能没有直接关系。`AudioWorklet` 主要关注音频处理，而 CSS 负责页面的样式和布局。

**逻辑推理、假设输入与输出:**

**场景 1：测试基本的处理器注册**

* **假设输入 (JavaScript 代码):**
  ```javascript
  class SimpleProcessor extends AudioWorkletProcessor {
    constructor() { super(); }
    process(inputs, outputs, parameters) { return true; }
  }
  registerProcessor('simple-processor', SimpleProcessor);
  ```
* **逻辑推理:** 测试代码会加载这段 JavaScript 代码到 `AudioWorkletGlobalScope` 中并执行。然后检查 `AudioWorkletGlobalScope` 是否成功存储了名为 "simple-processor" 的处理器定义。
* **预期输出:** 测试断言 `global_scope->FindDefinition("simple-processor")` 返回一个有效的 `AudioWorkletProcessorDefinition` 指针。

**场景 2：测试 `process()` 方法的调用**

* **假设输入 (JavaScript 代码):**
  ```javascript
  class AddOneProcessor extends AudioWorkletProcessor {
    constructor() { super(); }
    process(inputs, outputs, parameters) {
      const inputChannel = inputs[0][0];
      const outputChannel = outputs[0][0];
      for (let i = 0; i < outputChannel.length; ++i) {
        outputChannel[i] = inputChannel[i] + 1;
      }
      return true;
    }
  }
  registerProcessor('add-one-processor', AddOneProcessor);
  ```
* **逻辑推理:** 测试代码会创建一个 `add-one-processor` 的实例，并提供输入音频数据。然后调用该实例的 `process()` 方法。
* **预期输出:** 输出音频数据中的每个采样值都比输入音频数据中对应的采样值大 1。测试断言会比较输出缓冲区的内容是否符合预期。

**用户或编程常见的使用错误示例:**

1. **忘记调用 `super()` 在 `AudioWorkletProcessor` 的构造函数中:**
   ```javascript
   class MyBadProcessor extends AudioWorkletProcessor {
     constructor() {
       // 忘记调用 super();
     }
     process(inputs, outputs, parameters) { return true; }
   }
   registerProcessor('bad-processor', MyBadProcessor);
   ```
   **错误:**  这会导致 JavaScript 运行时错误，因为 `AudioWorkletProcessor` 的基类构造函数没有被正确调用。测试框架可能会捕获到这个错误，或者在实际使用中会导致 `AudioWorkletNode` 创建失败或运行异常。

2. **`process()` 方法返回非布尔值:**
   ```javascript
   class BadReturnProcessor extends AudioWorkletProcessor {
     constructor() { super(); }
     process(inputs, outputs, parameters) {
       return "not a boolean"; // 应该返回 true 或 false
     }
   }
   registerProcessor('bad-return-processor', BadReturnProcessor);
   ```
   **错误:**  `process()` 方法必须返回一个布尔值来指示是否需要保持音频处理器的活跃状态。返回非布尔值可能导致未定义的行为。

3. **在 `parameterDescriptors` 中定义了无效的参数属性:**
   ```javascript
   class InvalidParamProcessor extends AudioWorkletProcessor {
     static get parameterDescriptors() {
       return [{
         name: 'gain',
         defaultValue: "not a number", // defaultValue 应该是数字
       }];
     }
     constructor() { super(); }
     process(inputs, outputs, parameters) { return true; }
   }
   registerProcessor('invalid-param-processor', InvalidParamProcessor);
   ```
   **错误:**  `parameterDescriptors` 中定义的属性值必须符合规范。例如，`defaultValue` 应该是数字。测试框架可能会捕获到这种错误，或者在实际使用中会导致参数信息解析失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者编写了一个使用了 `AudioWorklet` 的 Web 应用。**  他们可能创建了一个 HTML 文件，并在其中的 `<script>` 标签中编写了 JavaScript 代码。
2. **JavaScript 代码中，开发者使用 `audioContext.audioWorklet.addModule()` 方法加载了一个包含 `registerProcessor()` 调用的 JavaScript 文件。** 这个文件定义了一个或多个自定义的 `AudioWorkletProcessor`。
3. **开发者创建了一个 `AudioWorkletNode` 实例，并指定了注册的处理器名称。**
4. **当 `AudioWorkletNode` 开始处理音频时，Blink 引擎会创建一个 `AudioWorkletGlobalScope` 的实例。**
5. **加载的 JavaScript 代码会在该 `AudioWorkletGlobalScope` 中执行，包括 `registerProcessor()` 的调用。**  这就是 `audio_worklet_global_scope_test.cc` 所测试的场景。
6. **如果开发者在编写 `AudioWorkletProcessor` 的代码时犯了错误（如上述示例），可能会导致 `registerProcessor()` 调用失败或 `process()` 方法执行异常。**
7. **为了调试这些问题，Chromium 的开发者会编写像 `audio_worklet_global_scope_test.cc` 这样的单元测试来验证 `AudioWorkletGlobalScope` 的核心功能是否正常。**  如果测试失败，就意味着 `AudioWorkletGlobalScope` 的实现存在问题，需要修复。
8. **当用户在浏览器中运行包含错误 `AudioWorklet` 代码的网页时，浏览器可能会抛出错误信息到开发者控制台。** 这些错误信息可以帮助开发者定位问题。如果问题涉及到 Blink 引擎内部的错误，开发者可能会提交一个 bug 报告，Chromium 的开发者会根据报告进行调试，并可能需要查看和修改像 `audio_worklet_global_scope_test.cc` 这样的测试文件来理解问题和验证修复方案。

总而言之，`audio_worklet_global_scope_test.cc` 是 Blink 引擎中一个关键的测试文件，用于确保 `AudioWorklet` 的核心功能（特别是 JavaScript 代码的执行和处理器注册）能够正常工作，从而为 Web Audio API 的可靠性提供保障。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_worklet_global_scope_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/webaudio/audio_worklet_global_scope.h"

#include <memory>

#include "base/synchronization/waitable_event.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/module_record.h"
#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_gc_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/worker_devtools_params.h"
#include "third_party/blink/renderer/core/loader/modulescript/module_script_creation_params.h"
#include "third_party/blink/renderer/core/messaging/message_channel.h"
#include "third_party/blink/renderer/core/messaging/message_port.h"
#include "third_party/blink/renderer/core/origin_trials/origin_trial_context.h"
#include "third_party/blink/renderer/core/script/js_module_script.h"
#include "third_party/blink/renderer/core/script/script.h"
#include "third_party/blink/renderer/core/testing/module_test_base.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/modules/webaudio/audio_buffer.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet_processor.h"
#include "third_party/blink/renderer/modules/webaudio/audio_worklet_processor_definition.h"
#include "third_party/blink/renderer/modules/webaudio/offline_audio_worklet_thread.h"
#include "third_party/blink/renderer/platform/audio/audio_bus.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/source_location.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding_macros.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"

namespace blink {

namespace {

constexpr size_t kRenderQuantumFrames = 128;

}  // namespace

// The test uses OfflineAudioWorkletThread because the test does not have a
// strict real-time constraint.
class AudioWorkletGlobalScopeTest : public PageTestBase, public ModuleTestBase {
 public:
  void SetUp() override {
    ModuleTestBase::SetUp();
    PageTestBase::SetUp(gfx::Size());
    NavigateTo(KURL("https://example.com/"));
    reporting_proxy_ = std::make_unique<WorkerReportingProxy>();
  }

  void TearDown() override {
    PageTestBase::TearDown();
    ModuleTestBase::TearDown();
  }

  std::unique_ptr<OfflineAudioWorkletThread> CreateAudioWorkletThread() {
    std::unique_ptr<OfflineAudioWorkletThread> thread =
        std::make_unique<OfflineAudioWorkletThread>(*reporting_proxy_);
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
        std::nullopt, std::make_unique<WorkerDevToolsParams>());
    return thread;
  }

  void RunBasicTest(WorkerThread* thread) {
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletGlobalScopeTest::RunBasicTestOnWorkletThread,
            CrossThreadUnretained(this), CrossThreadUnretained(thread),
            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();
  }

  void RunSimpleProcessTest(WorkerThread* thread) {
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletGlobalScopeTest::RunSimpleProcessTestOnWorkletThread,
            CrossThreadUnretained(this), CrossThreadUnretained(thread),
            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();
  }

  void RunParsingTest(WorkerThread* thread) {
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletGlobalScopeTest::RunParsingTestOnWorkletThread,
            CrossThreadUnretained(this), CrossThreadUnretained(thread),
            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();
  }

  void RunParsingParameterDescriptorTest(WorkerThread* thread) {
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(
            &AudioWorkletGlobalScopeTest::
                RunParsingParameterDescriptorTestOnWorkletThread,
            CrossThreadUnretained(this), CrossThreadUnretained(thread),
            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();
  }

 private:
  void ExpectEvaluateScriptModule(AudioWorkletGlobalScope* global_scope,
                                  const String& source_code,
                                  bool expect_success) {
    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();
    EXPECT_TRUE(script_state);
    KURL js_url("https://example.com/worklet.js");
    v8::Local<v8::Module> module =
        ModuleTestBase::CompileModule(script_state, source_code, js_url);
    EXPECT_FALSE(module.IsEmpty());
    ScriptValue exception =
        ModuleRecord::Instantiate(script_state, module, js_url);
    EXPECT_TRUE(exception.IsEmpty());

    ScriptEvaluationResult result =
        JSModuleScript::CreateForTest(Modulator::From(script_state), module,
                                      js_url)
            ->RunScriptOnScriptStateAndReturnValue(script_state);
    if (expect_success) {
      EXPECT_FALSE(GetResult(script_state, std::move(result)).IsEmpty());
    } else {
      EXPECT_FALSE(GetException(script_state, std::move(result)).IsEmpty());
    }
  }

  // Test if AudioWorkletGlobalScope and V8 components (ScriptState, Isolate)
  // are properly instantiated. Runs a simple processor registration and check
  // if the class definition is correctly registered, then instantiate an
  // AudioWorkletProcessor instance from the definition.
  void RunBasicTestOnWorkletThread(WorkerThread* thread,
                                   base::WaitableEvent* wait_event) {
    EXPECT_TRUE(thread->IsCurrentThread());

    auto* global_scope = To<AudioWorkletGlobalScope>(thread->GlobalScope());

    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();
    EXPECT_TRUE(script_state);

    v8::Isolate* isolate = script_state->GetIsolate();
    EXPECT_TRUE(isolate);

    ScriptState::Scope scope(script_state);

    String source_code =
        R"JS(
          class TestProcessor extends AudioWorkletProcessor {
            constructor () { super(); }
            process () {}
          }
          registerProcessor('testProcessor', TestProcessor);
        )JS";
    ExpectEvaluateScriptModule(global_scope, source_code, true);

    AudioWorkletProcessorDefinition* definition =
        global_scope->FindDefinition("testProcessor");
    EXPECT_TRUE(definition);
    EXPECT_EQ(definition->GetName(), "testProcessor");
    auto* channel = MakeGarbageCollected<MessageChannel>(thread->GlobalScope());
    MessagePortChannel dummy_port_channel = channel->port2()->Disentangle();

    AudioWorkletProcessor* processor =
        global_scope->CreateProcessor("testProcessor",
                                      dummy_port_channel,
                                      SerializedScriptValue::NullValue());
    EXPECT_TRUE(processor);
    EXPECT_EQ(processor->Name(), "testProcessor");
    v8::Local<v8::Value> processor_value =
        ToV8Traits<AudioWorkletProcessor>::ToV8(script_state, processor);
    EXPECT_TRUE(processor_value->IsObject());

    wait_event->Signal();
  }

  // Test if various class definition patterns are parsed correctly.
  void RunParsingTestOnWorkletThread(WorkerThread* thread,
                                     base::WaitableEvent* wait_event) {
    EXPECT_TRUE(thread->IsCurrentThread());

    auto* global_scope = To<AudioWorkletGlobalScope>(thread->GlobalScope());

    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();
    EXPECT_TRUE(script_state);

    ScriptState::Scope scope(script_state);

    {
      // registerProcessor() with a valid class definition should define a
      // processor. Note that these classes will fail at the construction time
      // because they're not valid AudioWorkletProcessor.
      String source_code =
          R"JS(
            var class1 = function () {};
            class1.prototype.process = function () {};
            registerProcessor('class1', class1);

            var class2 = function () {};
            class2.prototype = { process: function () {} };
            registerProcessor('class2', class2);
          )JS";
      ExpectEvaluateScriptModule(global_scope, source_code, true);
      EXPECT_TRUE(global_scope->FindDefinition("class1"));
      EXPECT_TRUE(global_scope->FindDefinition("class2"));
    }

    {
      // registerProcessor() with an invalid class definition should fail to
      // define a processor.
      String source_code =
          R"JS(
            var class3 = function () {};
            Object.defineProperty(class3, 'prototype', {
                get: function () {
                  return {
                    process: function () {}
                  };
                }
              });
            registerProcessor('class3', class3);
          )JS";
      ExpectEvaluateScriptModule(global_scope, source_code, false);
      EXPECT_FALSE(global_scope->FindDefinition("class3"));
    }

    wait_event->Signal();
  }

  // Test if the invocation of process() method in AudioWorkletProcessor and
  // AudioWorkletGlobalScope is performed correctly.
  void RunSimpleProcessTestOnWorkletThread(WorkerThread* thread,
                                           base::WaitableEvent* wait_event) {
    EXPECT_TRUE(thread->IsCurrentThread());

    auto* global_scope = To<AudioWorkletGlobalScope>(thread->GlobalScope());
    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();

    ScriptState::Scope scope(script_state);
    v8::Isolate* isolate = script_state->GetIsolate();
    EXPECT_TRUE(isolate);
    v8::MicrotasksScope microtasks_scope(
        isolate, ToMicrotaskQueue(script_state),
        v8::MicrotasksScope::kDoNotRunMicrotasks);

    String source_code =
        R"JS(
          class TestProcessor extends AudioWorkletProcessor {
            constructor () {
              super();
              this.constant_ = 1;
            }
            process (inputs, outputs) {
              let inputChannel = inputs[0][0];
              let outputChannel = outputs[0][0];
              for (let i = 0; i < outputChannel.length; ++i) {
                outputChannel[i] = inputChannel[i] + this.constant_;
              }
            }
          }
          registerProcessor('testProcessor', TestProcessor);
        )JS";
    ExpectEvaluateScriptModule(global_scope, source_code, true);

    auto* channel = MakeGarbageCollected<MessageChannel>(thread->GlobalScope());
    MessagePortChannel dummy_port_channel = channel->port2()->Disentangle();
    AudioWorkletProcessor* processor =
        global_scope->CreateProcessor("testProcessor",
                                      dummy_port_channel,
                                      SerializedScriptValue::NullValue());
    EXPECT_TRUE(processor);

    Vector<scoped_refptr<AudioBus>> input_buses;
    Vector<scoped_refptr<AudioBus>> output_buses;
    HashMap<String, std::unique_ptr<AudioFloatArray>> param_data_map;
    scoped_refptr<AudioBus> input_bus =
        AudioBus::Create(1, kRenderQuantumFrames);
    scoped_refptr<AudioBus> output_bus =
        AudioBus::Create(1, kRenderQuantumFrames);
    AudioChannel* input_channel = input_bus->Channel(0);
    AudioChannel* output_channel = output_bus->Channel(0);

    input_buses.push_back(input_bus.get());
    output_buses.push_back(output_bus.get());

    // Fill `input_channel` with 1 and zero out `output_bus`.
    std::fill(input_channel->MutableData(),
              input_channel->MutableData() + input_channel->length(), 1);
    output_bus->Zero();

    // Then invoke the process() method to perform JS buffer manipulation. The
    // output buffer should contain a constant value of 2.
    processor->Process(input_buses, output_buses, param_data_map);
    for (unsigned i = 0; i < output_channel->length(); ++i) {
      EXPECT_EQ(output_channel->Data()[i], 2);
    }

    wait_event->Signal();
  }

  void RunParsingParameterDescriptorTestOnWorkletThread(
      WorkerThread* thread,
      base::WaitableEvent* wait_event) {
    EXPECT_TRUE(thread->IsCurrentThread());

    auto* global_scope = To<AudioWorkletGlobalScope>(thread->GlobalScope());
    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();

    ScriptState::Scope scope(script_state);

    String source_code =
        R"JS(
          class TestProcessor extends AudioWorkletProcessor {
            static get parameterDescriptors () {
              return [{
                name: 'gain',
                defaultValue: 0.707,
                minValue: 0.0,
                maxValue: 1.0
              }];
            }
            constructor () { super(); }
            process () {}
          }
          registerProcessor('testProcessor', TestProcessor);
        )JS";
    ExpectEvaluateScriptModule(global_scope, source_code, true);

    AudioWorkletProcessorDefinition* definition =
        global_scope->FindDefinition("testProcessor");
    EXPECT_TRUE(definition);
    EXPECT_EQ(definition->GetName(), "testProcessor");

    const Vector<String> param_names =
        definition->GetAudioParamDescriptorNames();
    EXPECT_EQ(param_names[0], "gain");

    const AudioParamDescriptor* descriptor =
        definition->GetAudioParamDescriptor(param_names[0]);
    EXPECT_EQ(descriptor->defaultValue(), 0.707f);
    EXPECT_EQ(descriptor->minValue(), 0.0f);
    EXPECT_EQ(descriptor->maxValue(), 1.0f);

    wait_event->Signal();
  }

  std::unique_ptr<WorkerReportingProxy> reporting_proxy_;
};

TEST_F(AudioWorkletGlobalScopeTest, Basic) {
  std::unique_ptr<OfflineAudioWorkletThread> thread
      = CreateAudioWorkletThread();
  RunBasicTest(thread.get());
  thread->Terminate();
  thread->WaitForShutdownForTesting();
}

TEST_F(AudioWorkletGlobalScopeTest, Parsing) {
  std::unique_ptr<OfflineAudioWorkletThread> thread
      = CreateAudioWorkletThread();
  RunParsingTest(thread.get());
  thread->Terminate();
  thread->WaitForShutdownForTesting();
}

TEST_F(AudioWorkletGlobalScopeTest, BufferProcessing) {
  std::unique_ptr<OfflineAudioWorkletThread> thread
      = CreateAudioWorkletThread();
  RunSimpleProcessTest(thread.get());
  thread->Terminate();
  thread->WaitForShutdownForTesting();
}

TEST_F(AudioWorkletGlobalScopeTest, ParsingParameterDescriptor) {
  std::unique_ptr<OfflineAudioWorkletThread> thread
      = CreateAudioWorkletThread();
  RunParsingParameterDescriptorTest(thread.get());
  thread->Terminate();
  thread->WaitForShutdownForTesting();
}

}  // namespace blink
```
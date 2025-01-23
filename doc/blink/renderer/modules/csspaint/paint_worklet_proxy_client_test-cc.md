Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The file name, `paint_worklet_proxy_client_test.cc`, strongly suggests it's a test file for the `PaintWorkletProxyClient` class. The `test.cc` suffix is a common convention. The `blink/renderer/modules/csspaint/` path further confirms its connection to CSS Paint Worklets within the Blink rendering engine.

2. **Scan for Key Classes and Functions:** Look for class definitions and test macros.
    *  `PaintWorkletProxyClientTest`: This is the main test fixture class, inheriting from `RenderingTest`. This indicates it's setting up a rendering environment for testing.
    *  `PaintWorkletProxyClient`: This is the class being tested.
    *  `TEST_F`: This is a Google Test macro indicating individual test cases within the fixture. Each `TEST_F` block tests a specific aspect of `PaintWorkletProxyClient`.
    *  Helper classes like `FakeTaskRunner`, `ScopedOffMainThreadCSSPaintForTest`, and the anonymous namespace with `ScopedFakeMainThreadTaskRunner` suggest handling asynchronous operations and thread management during testing.

3. **Analyze Individual Test Cases:** Go through each `TEST_F` block to understand its specific goal.

    *   **`PaintWorkletProxyClientConstruction`:**  This is straightforward. It checks if the `PaintWorkletProxyClient` object is created correctly, particularly if the `worklet_id_` and `paint_dispatcher_` members are initialized as expected, both with and without a dispatcher.

    *   **`AddGlobalScopes`:** This test deals with the concept of "global scopes."  The code explicitly creates worker threads and attempts to add global scopes. The `EXPECT_FALSE` and `EXPECT_TRUE` checks related to `compositor_task_runner->task_posted_` are crucial. This indicates it's testing when and how the proxy client registers with the compositor thread. The comment about `kNumGlobalScopesPerThread` gives a hint about the underlying logic.

    *   **`Paint`:** This test is about invoking the `Paint` method of the `PaintWorkletProxyClient`. It involves registering a paint function using `registerPaint` and then calling `proxy_client->Paint`. The `EXPECT_FALSE(record.empty())` confirms that the paint operation produces some output.

    *   **`DefinitionsMustBeCompatible`:** This test delves into the consistency of paint function definitions across different "global scopes." It registers paint functions with varying `inputProperties` and `contextOptions` on different scopes and checks if the `DocumentDefinitionMapForTesting` reflects these inconsistencies. This highlights the requirement for consistent definitions.

    *   **`AllDefinitionsMustBeRegisteredBeforePosting`:** This test uses the `ScopedFakeMainThreadTaskRunner` to control and observe task posting to the main thread. It checks that the proxy client only posts to the main thread *after* all global scopes have registered the same paint function.

4. **Identify Relationships to Web Technologies:**

    *   **JavaScript:** The use of `registerPaint` within the test cases directly connects to the CSS Paint API, which is exposed to JavaScript. The code snippets passed to `ClassicScript::CreateUnspecifiedScript` are JavaScript code.
    *   **CSS:** The concept of "input properties" (`inputProperties`) directly relates to CSS properties that can be accessed within a paint worklet. The test for compatible definitions highlights how different CSS property dependencies can lead to inconsistencies.
    *   **HTML:** While not directly manipulated in *this specific test*, the Paint Worklet API is used to render elements in an HTML document. The test sets up a rendering environment, implying the broader context of HTML.

5. **Infer Logical Reasoning and Assumptions:**

    *   The test setup with multiple worker threads and global scopes suggests that the `PaintWorkletProxyClient` needs to handle scenarios where paint functions are defined in different execution contexts.
    *   The checks for task posting indicate that communication between the worklet thread and the main/compositor thread is a critical part of the functionality.
    *   The compatibility checks imply that the rendering engine needs to ensure consistency in paint function definitions to avoid unexpected behavior.

6. **Consider User/Developer Errors:**

    *   **Inconsistent `registerPaint` calls:** Defining the same paint function with different input properties or context options across different parts of the code (potentially in different JavaScript files or at different times) could lead to errors, and this test specifically checks for this.
    *   **Incorrect asynchronous handling:**  If the `PaintWorkletProxyClient` doesn't correctly manage asynchronous communication between threads, it could lead to race conditions or incorrect rendering. The `FakeTaskRunner` helps simulate and test this.

7. **Trace User Operations (Debugging Clues):**

    *   A user adds a `<script>` tag to their HTML that includes a `registerPaint` call.
    *   The browser parses this script and registers the paint function within a worklet thread.
    *   The browser encounters a CSS style that uses `paint(myPainter)`.
    *   The browser needs to execute the `myPainter` function. This involves the `PaintWorkletProxyClient` coordinating with the worklet thread to invoke the paint function.
    *   If the `PaintWorkletProxyClient` isn't functioning correctly (as these tests verify), the paint function might not be executed, might be executed with incorrect data, or might cause crashes. Debugging would involve looking at the communication between the main thread and the worklet thread, the registration of paint functions, and the data being passed to the paint function.

8. **Structure the Explanation:** Organize the findings into logical sections like "Functionality," "Relationship to Web Technologies," "Logic and Assumptions," "User Errors," and "Debugging Clues."  Use examples and clear language.

By following these steps, one can systematically analyze a complex C++ test file and extract its essential information and implications. The key is to look for patterns, understand the purpose of the code, and connect it back to the broader context of web development.
This C++ file, `paint_worklet_proxy_client_test.cc`, contains unit tests for the `PaintWorkletProxyClient` class in the Chromium Blink rendering engine. The `PaintWorkletProxyClient` acts as an intermediary, or proxy, between the main rendering thread and the worklet thread where CSS Paint Worklets are executed.

Here's a breakdown of its functionality and relationships:

**Functionality of `paint_worklet_proxy_client_test.cc`:**

1. **Testing `PaintWorkletProxyClient` Construction:** Verifies that instances of `PaintWorkletProxyClient` can be created correctly, including setting the worklet ID and handling the optional `PaintWorkletPaintDispatcher`.

2. **Testing Global Scope Management:**  `PaintWorkletProxyClient` manages multiple "global scopes" within the worklet thread. These tests ensure:
   - Global scopes can be added correctly.
   - The proxy client only registers with the compositor thread (via `PaintWorkletPaintDispatcher`) after all expected global scopes are present. This is crucial for ensuring all paint function definitions are available before rendering.

3. **Testing the `Paint` Method:**  Confirms that the `Paint` method of `PaintWorkletProxyClient` correctly triggers the execution of a registered paint function within the worklet and returns a valid `PaintRecord`. This simulates the actual painting process initiated by the browser.

4. **Enforcing Compatible Definitions:** The tests verify that if the same paint function name is registered in different global scopes within the same worklet, their definitions (specifically `inputProperties` and `contextOptions`) must be compatible. If they are not, the `PaintWorkletProxyClient` should not register the paint function, preventing potential inconsistencies and errors during rendering.

5. **Ensuring All Definitions are Registered Before Posting:** The tests check that the `PaintWorkletProxyClient` only informs the compositor thread about registered paint functions *after* all global scopes have registered their definitions. This prevents the compositor from attempting to use a paint function that hasn't been fully defined across all its potential execution contexts.

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This file directly tests the integration of JavaScript-defined CSS Paint Worklets with the rendering engine. The tests use `ClassicScript::CreateUnspecifiedScript` to execute JavaScript code (specifically `registerPaint`) within the worklet thread. The `registerPaint` function is a JavaScript API that developers use to define custom paint functions.

   **Example:** The test code uses JavaScript like this:
   ```javascript
   registerPaint('foo', class { paint() { } });
   ```
   This JavaScript code, when executed in the worklet, registers a paint function named 'foo'. The C++ tests verify how `PaintWorkletProxyClient` handles this registration.

* **CSS:** CSS Paint Worklets are invoked through CSS. The `inputProperties` and `contextOptions` in the JavaScript `registerPaint` calls are directly related to how the paint function interacts with CSS properties. The "Definitions Must Be Compatible" test specifically checks how the `PaintWorkletProxyClient` handles different `inputProperties` declared for the same paint function name across different global scopes.

   **Example:** A CSS rule might look like this:
   ```css
   .my-element {
     background-image: paint(foo);
   }
   ```
   This CSS rule tells the browser to use the JavaScript-defined paint function named 'foo' to draw the background of elements with the class `my-element`. The C++ tests ensure the `PaintWorkletProxyClient` correctly manages the execution of this 'foo' function.

* **HTML:** While this C++ file doesn't directly manipulate HTML, the functionality it tests is crucial for rendering HTML content that utilizes CSS Paint Worklets. The paint functions defined in JavaScript and invoked via CSS are ultimately used to visually represent parts of the HTML document.

**Logical Reasoning and Examples:**

* **Assumption:** Paint Worklets execute in a separate thread (the worklet thread) from the main rendering thread. Communication between these threads needs a proxy.
* **Input (Hypothetical):**  JavaScript code registers a paint function named 'myPainter' with `inputProperties: ['--my-color']` in one global scope and with `inputProperties: ['width']` in another global scope within the same worklet.
* **Output:** The `DefinitionsMustBeCompatible` test would expect the `PaintWorkletProxyClient` to *not* register 'myPainter' in its internal map, because the definitions are incompatible. This prevents the browser from potentially using the wrong definition when rendering.

**User/Programming Common Usage Errors:**

* **Inconsistent `inputProperties`:** A common mistake is to define the same paint function name with different `inputProperties` in different JavaScript files or at different times. This can lead to unpredictable rendering behavior depending on which definition the browser happens to use. The "Definitions Must Be Compatible" test is designed to catch this type of error at a lower level.

   **Example:**
   ```javascript
   // File 1.js
   registerPaint('myPainter', class {
     static get inputProperties() { return ['--my-color']; }
     paint(ctx, geom, properties) {
       const color = properties.get('--my-color').toString();
       // ... use color ...
     }
   });

   // File 2.js
   registerPaint('myPainter', class {
     static get inputProperties() { return ['width']; }
     paint(ctx, geom, properties) {
       const width = properties.get('width').value;
       // ... use width ...
     }
   });
   ```
   If both these scripts are loaded, the browser might pick either definition for `myPainter`. The `PaintWorkletProxyClient`'s compatibility check aims to prevent this ambiguity.

* **Registering Paint Functions After Initial Rendering:** If a paint function is registered on the worklet thread *after* the initial rendering pass has started or completed, the compositor thread might not be aware of this new function. The tests around ensuring all definitions are registered before posting address this by verifying the correct timing of communication.

**User Operation and Debugging Clues:**

Let's trace how a user's action might lead to this code being relevant for debugging:

1. **User adds a `<style>` tag or a `<link>` to a CSS file that uses a CSS Paint Worklet:**
   ```css
   .my-element {
     background-image: paint(myCustomPaint);
     --my-paint-color: red;
   }
   ```

2. **The browser's HTML parser and CSS parser encounter this rule.**

3. **The CSS engine recognizes the `paint(myCustomPaint)` function call.**

4. **The browser checks if a paint function named `myCustomPaint` is registered.** This involves interacting with the `PaintWorkletProxyClient`.

5. **If the paint function is not registered or if there are compatibility issues (as tested in this C++ file), the rendering might fail or produce unexpected results.**

**Debugging Steps Leading to this Code:**

* **Rendering issues with a CSS Paint Worklet:**  The user might see a blank area where the painted content should be, or the painted content might look wrong.
* **Browser DevTools inspection:**  The developer might inspect the element in the browser's DevTools and see that the `background-image` property is set to `paint(myCustomPaint)`, but no actual painting occurred.
* **Console errors:**  The browser console might show errors related to the paint worklet, such as "CSS Paint Worklet 'myCustomPaint' not found" or warnings about incompatible definitions.
* **Investigating the Blink rendering engine:** Developers working on the Chromium project or investigating rendering bugs would then look into the code responsible for handling CSS Paint Worklets. `paint_worklet_proxy_client_test.cc` becomes relevant because it tests the core logic of how the browser interacts with the worklet thread and manages paint function definitions.
* **Setting breakpoints and tracing execution:**  A developer might set breakpoints in the `PaintWorkletProxyClient` code (the actual implementation, not just the tests) and step through the execution to see if the paint function is being registered correctly, if the compatibility checks are passing, and if the communication with the worklet thread is happening as expected. They might then refer to the test file to understand the intended behavior and how different scenarios are handled.

In summary, `paint_worklet_proxy_client_test.cc` is a vital part of ensuring the correct and consistent behavior of CSS Paint Worklets in the Chromium browser. It tests the core intermediary class responsible for managing communication and ensuring the integrity of paint function definitions between the main rendering thread and the worklet thread.

### 提示词
```
这是目录为blink/renderer/modules/csspaint/paint_worklet_proxy_client_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/csspaint/paint_worklet_proxy_client.h"

#include <memory>
#include <utility>

#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/test_simple_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_style_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_paint_worklet_input.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet.h"
#include "third_party/blink/renderer/modules/csspaint/paint_worklet_global_scope.h"
#include "third_party/blink/renderer/modules/worklet/worklet_thread_test_common.h"
#include "third_party/blink/renderer/platform/graphics/paint_worklet_paint_dispatcher.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"

namespace blink {

// We inject a fake task runner in multiple tests, to avoid actually posting
// tasks cross-thread whilst still being able to know if they have been posted.
class FakeTaskRunner : public base::SingleThreadTaskRunner {
 public:
  FakeTaskRunner() : task_posted_(false) {}

  bool PostNonNestableDelayedTask(const base::Location& from_here,
                                  base::OnceClosure task,
                                  base::TimeDelta delay) override {
    task_posted_ = true;
    return true;
  }
  bool PostDelayedTask(const base::Location& from_here,
                       base::OnceClosure task,
                       base::TimeDelta delay) override {
    task_posted_ = true;
    return true;
  }
  bool RunsTasksInCurrentSequence() const override { return true; }

  bool task_posted_;

 protected:
  ~FakeTaskRunner() override {}
};

class PaintWorkletProxyClientTest : public RenderingTest {
 public:
  PaintWorkletProxyClientTest() = default;

  void SetUp() override {
    RenderingTest::SetUp();
    paint_worklet_ =
        MakeGarbageCollected<PaintWorklet>(*GetFrame().DomWindow());
    dispatcher_ = std::make_unique<PaintWorkletPaintDispatcher>();
    fake_compositor_thread_runner_ = base::MakeRefCounted<FakeTaskRunner>();
    proxy_client_ = MakeGarbageCollected<PaintWorkletProxyClient>(
        1, paint_worklet_, GetFrame().GetTaskRunner(TaskType::kInternalDefault),
        dispatcher_->GetWeakPtr(), fake_compositor_thread_runner_);
    reporting_proxy_ = std::make_unique<WorkerReportingProxy>();
  }

  void AddGlobalScopeOnWorkletThread(WorkerThread* worker_thread,
                                     PaintWorkletProxyClient* proxy_client,
                                     base::WaitableEvent* waitable_event) {
    // The natural flow for PaintWorkletGlobalScope is to be registered with the
    // proxy client during its first registerPaint call. Rather than circumvent
    // this with a specialised AddGlobalScopeForTesting method, we just use the
    // standard flow.
    ClassicScript::CreateUnspecifiedScript(
        "registerPaint('add_global_scope', class { paint() { } });")
        ->RunScriptOnScriptState(
            worker_thread->GlobalScope()->ScriptController()->GetScriptState());
    waitable_event->Signal();
  }

  using TestCallback = void (*)(WorkerThread*,
                                PaintWorkletProxyClient*,
                                base::WaitableEvent*);

  void RunMultipleGlobalScopeTestsOnWorklet(TestCallback callback) {
    // PaintWorklet is stateless, and this is enforced via having multiple
    // global scopes (which are switched between). To mimic the real world,
    // create multiple WorkerThread for this. Note that the underlying thread
    // may be shared even though they are unique WorkerThread instances!
    Vector<std::unique_ptr<WorkerThread>> worklet_threads;
    for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; i++) {
      worklet_threads.push_back(CreateThreadAndProvidePaintWorkletProxyClient(
          &GetDocument(), reporting_proxy_.get(), proxy_client_));
    }

    // Add the global scopes. This must happen on the worklet thread.
    for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; i++) {
      base::WaitableEvent waitable_event;
      PostCrossThreadTask(
          *worklet_threads[i]->GetTaskRunner(TaskType::kInternalTest),
          FROM_HERE,
          CrossThreadBindOnce(
              &PaintWorkletProxyClientTest::AddGlobalScopeOnWorkletThread,
              CrossThreadUnretained(this),
              CrossThreadUnretained(worklet_threads[i].get()),
              CrossThreadPersistent<PaintWorkletProxyClient>(proxy_client_),
              CrossThreadUnretained(&waitable_event)));
      waitable_event.Wait();
    }

    // Now let the test actually run. We only run the test on the first worklet
    // thread currently; this suffices since they share the proxy.
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *worklet_threads[0]->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(
            callback, CrossThreadUnretained(worklet_threads[0].get()),
            CrossThreadPersistent<PaintWorkletProxyClient>(proxy_client_),
            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();

    // And finally clean up.
    for (wtf_size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread; i++) {
      worklet_threads[i]->Terminate();
      worklet_threads[i]->WaitForShutdownForTesting();
    }
  }

  std::unique_ptr<PaintWorkletPaintDispatcher> dispatcher_;
  Persistent<PaintWorklet> paint_worklet_;
  scoped_refptr<FakeTaskRunner> fake_compositor_thread_runner_;
  Persistent<PaintWorkletProxyClient> proxy_client_;
  std::unique_ptr<WorkerReportingProxy> reporting_proxy_;
};

TEST_F(PaintWorkletProxyClientTest, PaintWorkletProxyClientConstruction) {
  PaintWorkletProxyClient* proxy_client =
      MakeGarbageCollected<PaintWorkletProxyClient>(
          1, nullptr, GetFrame().GetTaskRunner(TaskType::kInternalDefault),
          nullptr, nullptr);
  EXPECT_EQ(proxy_client->worklet_id_, 1);
  EXPECT_EQ(proxy_client->paint_dispatcher_, nullptr);

  auto dispatcher = std::make_unique<PaintWorkletPaintDispatcher>();

  proxy_client = MakeGarbageCollected<PaintWorkletProxyClient>(
      1, nullptr, GetFrame().GetTaskRunner(TaskType::kInternalDefault),
      dispatcher->GetWeakPtr(), nullptr);
  EXPECT_EQ(proxy_client->worklet_id_, 1);
  EXPECT_NE(proxy_client->paint_dispatcher_, nullptr);
}

void RunAddGlobalScopesTestOnWorklet(
    WorkerThread* thread,
    PaintWorkletProxyClient* proxy_client,
    scoped_refptr<FakeTaskRunner> compositor_task_runner,
    base::WaitableEvent* waitable_event) {
  // For this test, we cheat and reuse the same global scope object from a
  // single WorkerThread. In real code these would be different global scopes.

  // First, add all but one of the global scopes. The proxy client should not
  // yet register itself.
  for (size_t i = 0; i < PaintWorklet::kNumGlobalScopesPerThread - 1; i++) {
    proxy_client->AddGlobalScope(To<WorkletGlobalScope>(thread->GlobalScope()));
  }

  EXPECT_EQ(proxy_client->GetGlobalScopesForTesting().size(),
            PaintWorklet::kNumGlobalScopesPerThread - 1);
  EXPECT_FALSE(compositor_task_runner->task_posted_);

  // Now add the final global scope. This should trigger the registration.
  proxy_client->AddGlobalScope(To<WorkletGlobalScope>(thread->GlobalScope()));
  EXPECT_EQ(proxy_client->GetGlobalScopesForTesting().size(),
            PaintWorklet::kNumGlobalScopesPerThread);
  EXPECT_TRUE(compositor_task_runner->task_posted_);

  waitable_event->Signal();
}

TEST_F(PaintWorkletProxyClientTest, AddGlobalScopes) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  // Global scopes must be created on worker threads.
  std::unique_ptr<WorkerThread> worklet_thread =
      CreateThreadAndProvidePaintWorkletProxyClient(
          &GetDocument(), reporting_proxy_.get(), proxy_client_);

  EXPECT_TRUE(proxy_client_->GetGlobalScopesForTesting().empty());

  base::WaitableEvent waitable_event;
  PostCrossThreadTask(
      *worklet_thread->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(
          &RunAddGlobalScopesTestOnWorklet,
          CrossThreadUnretained(worklet_thread.get()),
          CrossThreadPersistent<PaintWorkletProxyClient>(proxy_client_),
          fake_compositor_thread_runner_,
          CrossThreadUnretained(&waitable_event)));
  waitable_event.Wait();

  worklet_thread->Terminate();
  worklet_thread->WaitForShutdownForTesting();
}

void RunPaintTestOnWorklet(WorkerThread* thread,
                           PaintWorkletProxyClient* proxy_client,
                           base::WaitableEvent* waitable_event) {
  // Assert that all global scopes have been registered. Note that we don't
  // use ASSERT_EQ here as that would crash the worklet thread and the test
  // would timeout rather than fail.
  EXPECT_EQ(proxy_client->GetGlobalScopesForTesting().size(),
            PaintWorklet::kNumGlobalScopesPerThread);

  // Register the painter on all global scopes.
  for (const auto& global_scope : proxy_client->GetGlobalScopesForTesting()) {
    ClassicScript::CreateUnspecifiedScript(
        "registerPaint('foo', class { paint() { } });")
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());
  }

  PaintWorkletStylePropertyMap::CrossThreadData data;
  Vector<std::unique_ptr<CrossThreadStyleValue>> input_arguments;
  std::vector<cc::PaintWorkletInput::PropertyKey> property_keys;
  scoped_refptr<CSSPaintWorkletInput> input =
      base::MakeRefCounted<CSSPaintWorkletInput>(
          "foo", gfx::SizeF(100, 100), 1.0f, 1, std::move(data),
          std::move(input_arguments), std::move(property_keys));
  PaintRecord record = proxy_client->Paint(input.get(), {});
  EXPECT_FALSE(record.empty());

  waitable_event->Signal();
}

TEST_F(PaintWorkletProxyClientTest, Paint) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  RunMultipleGlobalScopeTestsOnWorklet(&RunPaintTestOnWorklet);
}

void RunDefinitionsMustBeCompatibleTestOnWorklet(
    WorkerThread* thread,
    PaintWorkletProxyClient* proxy_client,
    base::WaitableEvent* waitable_event) {
  // Assert that all global scopes have been registered. Note that we don't
  // use ASSERT_EQ here as that would crash the worklet thread and the test
  // would timeout rather than fail.
  EXPECT_EQ(proxy_client->GetGlobalScopesForTesting().size(),
            PaintWorklet::kNumGlobalScopesPerThread);

  // This test doesn't make sense if there's only one global scope!
  EXPECT_GT(PaintWorklet::kNumGlobalScopesPerThread, 1u);

  const Vector<CrossThreadPersistent<PaintWorkletGlobalScope>>& global_scopes =
      proxy_client->GetGlobalScopesForTesting();

  // Things that can be different: alpha different, native properties
  // different, custom properties different, input type args different.
  const HashMap<String, std::unique_ptr<DocumentPaintDefinition>>&
      document_definition_map = proxy_client->DocumentDefinitionMapForTesting();

  // Differing native properties.
  ClassicScript::CreateUnspecifiedScript(R"JS(registerPaint('test1', class {
        static get inputProperties() { return ['border-image', 'color']; }
        paint() { }
      });)JS")
      ->RunScriptOnScriptState(
          global_scopes[0]->ScriptController()->GetScriptState());
  EXPECT_NE(document_definition_map.at("test1"), nullptr);
  ClassicScript::CreateUnspecifiedScript(R"JS(registerPaint('test1', class {
        static get inputProperties() { return ['left']; }
        paint() { }
      });)JS")
      ->RunScriptOnScriptState(
          global_scopes[1]->ScriptController()->GetScriptState());
  EXPECT_EQ(document_definition_map.at("test1"), nullptr);

  // Differing custom properties.
  ClassicScript::CreateUnspecifiedScript(R"JS(registerPaint('test2', class {
        static get inputProperties() { return ['--foo', '--bar']; }
        paint() { }
      });)JS")
      ->RunScriptOnScriptState(
          global_scopes[0]->ScriptController()->GetScriptState());
  EXPECT_NE(document_definition_map.at("test2"), nullptr);
  ClassicScript::CreateUnspecifiedScript(R"JS(registerPaint('test2', class {
        static get inputProperties() { return ['--zoinks']; }
        paint() { }
      });)JS")
      ->RunScriptOnScriptState(
          global_scopes[1]->ScriptController()->GetScriptState());
  EXPECT_EQ(document_definition_map.at("test2"), nullptr);

  // Differing alpha values. The default is 'true'.
  ClassicScript::CreateUnspecifiedScript(
      "registerPaint('test3', class { paint() { } });")
      ->RunScriptOnScriptState(
          global_scopes[0]->ScriptController()->GetScriptState());
  EXPECT_NE(document_definition_map.at("test3"), nullptr);
  ClassicScript::CreateUnspecifiedScript(R"JS(registerPaint('test3', class {
        static get contextOptions() { return {alpha: false}; }
        paint() { }
      });)JS")
      ->RunScriptOnScriptState(
          global_scopes[1]->ScriptController()->GetScriptState());
  EXPECT_EQ(document_definition_map.at("test3"), nullptr);

  waitable_event->Signal();
}

TEST_F(PaintWorkletProxyClientTest, DefinitionsMustBeCompatible) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  RunMultipleGlobalScopeTestsOnWorklet(
      &RunDefinitionsMustBeCompatibleTestOnWorklet);
}

namespace {
// Calling registerPaint can cause the PaintWorkletProxyClient to post back from
// the worklet thread to the main thread. This is safe in the general case,
// since the task will just queue up to run after the test has finished, but
// the following tests want to know whether or not the task has posted; this
// class provides that information.
class ScopedFakeMainThreadTaskRunner {
 public:
  ScopedFakeMainThreadTaskRunner(PaintWorkletProxyClient* proxy_client)
      : proxy_client_(proxy_client), fake_task_runner_(new FakeTaskRunner) {
    original_task_runner_ = proxy_client->MainThreadTaskRunnerForTesting();
    proxy_client_->SetMainThreadTaskRunnerForTesting(fake_task_runner_);
  }

  ~ScopedFakeMainThreadTaskRunner() {
    proxy_client_->SetMainThreadTaskRunnerForTesting(original_task_runner_);
  }

  void ResetTaskHasBeenPosted() { fake_task_runner_->task_posted_ = false; }
  bool TaskHasBeenPosted() const { return fake_task_runner_->task_posted_; }

 private:
  // The PaintWorkletProxyClient is held on the main test thread, but we are
  // constructed on the worklet thread so we have to hold the client reference
  // in a CrossThreadPersistent.
  CrossThreadPersistent<PaintWorkletProxyClient> proxy_client_;
  scoped_refptr<FakeTaskRunner> fake_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> original_task_runner_;
};
}  // namespace

void RunAllDefinitionsMustBeRegisteredBeforePostingTestOnWorklet(
    WorkerThread* thread,
    PaintWorkletProxyClient* proxy_client,
    base::WaitableEvent* waitable_event) {
  ScopedFakeMainThreadTaskRunner fake_runner(proxy_client);

  // Assert that all global scopes have been registered. Note that we don't
  // use ASSERT_EQ here as that would crash the worklet thread and the test
  // would timeout rather than fail.
  EXPECT_EQ(proxy_client->GetGlobalScopesForTesting().size(),
            PaintWorklet::kNumGlobalScopesPerThread);

  // Register a new paint function on all but one global scope. They should not
  // end up posting a task to the PaintWorklet.
  const Vector<CrossThreadPersistent<PaintWorkletGlobalScope>>& global_scopes =
      proxy_client->GetGlobalScopesForTesting();
  for (wtf_size_t i = 0; i < global_scopes.size() - 1; i++) {
    ClassicScript::CreateUnspecifiedScript(
        "registerPaint('foo', class { paint() { } });")
        ->RunScriptOnScriptState(
            global_scopes[i]->ScriptController()->GetScriptState());
    EXPECT_FALSE(fake_runner.TaskHasBeenPosted());
  }

  // Now register the final one; the task should then be posted.
  ClassicScript::CreateUnspecifiedScript(
      "registerPaint('foo', class { paint() { } });")
      ->RunScriptOnScriptState(
          global_scopes.back()->ScriptController()->GetScriptState());
  EXPECT_TRUE(fake_runner.TaskHasBeenPosted());

  waitable_event->Signal();
}

TEST_F(PaintWorkletProxyClientTest,
       AllDefinitionsMustBeRegisteredBeforePosting) {
  ScopedOffMainThreadCSSPaintForTest off_main_thread_css_paint(true);
  RunMultipleGlobalScopeTestsOnWorklet(
      &RunAllDefinitionsMustBeRegisteredBeforePostingTestOnWorklet);
}

}  // namespace blink
```
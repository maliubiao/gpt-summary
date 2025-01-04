Response:
Let's break down the thought process for analyzing the given C++ test file.

1. **Identify the Core Purpose:** The filename `animation_worklet_global_scope_test.cc` immediately tells us this is a test file. The "animation worklet global scope" part pinpoints the specific component being tested. The `.cc` extension signifies C++ source code.

2. **Understand the Testing Framework:** The presence of `#include "testing/gtest/include/gtest/gtest.h"` indicates the use of Google Test (gtest) for writing unit tests. This means we should expect to see `TEST_F` macros defining individual test cases.

3. **Scan for Key Classes and Methods:** Look for the main class being tested. In this case, it's `AnimationWorkletGlobalScope`. Then, identify the methods of this class that are being exercised by the tests. Keywords like `registerAnimator`, `animate`, `state`, and internal methods like `FindDefinitionForTest`, `GetAnimatorsSizeForTest`, `ScriptController()->GetScriptState()` are good starting points.

4. **Analyze Individual Test Cases:** Go through each `TEST_F` function:
    * **`BasicParsing`:** The code inside this test registers an animator with a valid and an invalid class definition. It checks if the `registerAnimator` function works as expected. This immediately connects to JavaScript as `registerAnimator` is a JavaScript API.
    * **`ConstructAndAnimate`:** This test registers an animator with a `constructor` and an `animate` method. It then simulates triggering the animation and checks if these methods are called. Again, JavaScript is central here.
    * **`StateExistence`:**  This test focuses on whether the registered animator class has a `state()` method. This is related to the concept of stateful vs. stateless animators, a design choice within the Animation Worklet API.
    * **`AnimationOutput`:** This test registers an animator that modifies the `effect.localTime` in its `animate` method. It verifies if this output is correctly captured. This directly links to the output of the animation process, relevant to CSS animation effects.
    * **`AnimatorInstanceCreation`:** This test is about the lifecycle of animator instances. It checks if an animator instance is created only when an animation is *added*, not just *updated* or *removed*. This is an important implementation detail.
    * **`AnimatorInstanceUpdate`:**  Similar to the previous test, but focuses on the update and removal of animator instances.
    * **`ShouldRegisterItselfAfterFirstAnimatorRegistration`:** This test checks an internal mechanism: whether the `AnimationWorkletGlobalScope` registers itself with a proxy client after the first animator is registered. This is related to inter-process communication or management within the Chromium architecture.

5. **Identify Relationships to Web Technologies:**  Consider how the tested code interacts with JavaScript, HTML, and CSS.
    * **JavaScript:** The `registerAnimator` function is a JavaScript API. The test code uses `ClassicScript::CreateUnspecifiedScript` to execute JavaScript code within the worklet. The animator definitions are written in JavaScript classes.
    * **HTML:** While not directly tested here, Animation Worklets are used to create custom animations that can be applied to HTML elements. The test setup includes creating a `PageTestBase` which inherently involves a document context.
    * **CSS:** The `animate` method in the JavaScript animator can modify animation properties (like `effect.localTime`), which directly impact the visual rendering driven by CSS.

6. **Look for Logic and Assumptions:** Pay attention to how the tests are structured. The `ProxyClientMutate` function simulates the interaction between the worklet and the main thread. The `AnimationWorkletInput` and `AnimationWorkletOutput` structures represent data exchanged between these components. The tests make assumptions about the order of execution and the expected behavior of the system.

7. **Consider User/Developer Errors:** Think about how a developer might misuse the Animation Worklet API and how these tests might catch such errors. For example, providing a `null` animator definition, not defining the `animate` method, or expecting animators to run without proper registration.

8. **Trace User Actions (Debugging Context):** Imagine the steps a user or developer would take to trigger the execution path leading to this code. This involves creating an HTML page, including a `<script>` tag to register an animation worklet, and then applying that worklet to an element.

9. **Structure the Explanation:** Organize the findings into logical categories: file functionality, relationships to web technologies, logical reasoning, common errors, and debugging clues. Use clear and concise language.

10. **Review and Refine:** Read through the explanation to ensure accuracy and clarity. Check for any missing points or areas that could be explained better. For example, initially, I might have missed the significance of the `MockAnimationWorkletProxyClient`, but realizing it's used in the last test case helps to understand a specific aspect of the system's architecture. Similarly, connecting the `effect.localTime` modification to CSS animation is a crucial refinement.
这个文件 `animation_worklet_global_scope_test.cc` 是 Chromium Blink 渲染引擎中 **Animation Worklet** 功能的 **单元测试** 文件。它的主要功能是 **测试 `AnimationWorkletGlobalScope` 类的各种行为和功能是否符合预期**。

让我们更详细地分解它的功能和与其他 Web 技术的关系：

**1. 核心功能：测试 `AnimationWorkletGlobalScope`**

* **`AnimationWorkletGlobalScope` 是什么？**  它是在 Animation Worklet 中执行 JavaScript 代码的全局作用域。 类似于 Web Worker 的全局作用域，但专门用于动画相关的任务。它提供了一些特定的 API，例如 `registerAnimator()`，用于注册自定义动画类。

* **测试内容：**  这个测试文件通过模拟各种场景，验证 `AnimationWorkletGlobalScope` 的以下方面：
    * **注册动画器 (`registerAnimator`)：**
        * 能否正确注册有效的动画器类。
        * 处理无效的注册，例如传递 `null`。
        * 能否找到已注册的动画器。
    * **动画器的构造和执行：**
        * 当触发动画时，能否正确地创建动画器实例并执行其 `animate()` 方法。
        * 构造函数是否被调用。
    * **动画器状态 (`state`)：**
        * 能否正确判断动画器是否定义了 `state()` 方法（用于表示有状态的动画器）。
    * **动画输出：**
        * 动画器在 `animate()` 方法中修改 `effect` 对象（例如设置 `localTime`）后，这些修改能否正确传递出去。
    * **动画器实例的生命周期管理：**
        * 何时创建新的动画器实例（当有新的动画添加时）。
        * 何时更新现有动画器实例。
        * 何时移除动画器实例（当动画移除时）。
    * **生命周期事件：**
        * 测试 `AnimationWorkletGlobalScope` 在首次注册动画器时是否会向其代理客户端注册自己。

**2. 与 JavaScript, HTML, CSS 的关系及举例说明**

Animation Worklet 的核心是 JavaScript，因为它允许开发者使用 JavaScript 定义自定义的动画逻辑。

* **JavaScript:**
    * **`registerAnimator('test', class { ... });`**:  这是在 Worklet 内部执行的 JavaScript 代码，用于注册名为 'test' 的动画器类。这个类必须包含一个 `animate()` 方法。
    * **`constructor () { constructed = true; }`**:  JavaScript 的构造函数，用于在动画器实例创建时执行初始化逻辑。
    * **`animate (currentTime, effect) { effect.localTime = 123; }`**:  核心的动画逻辑方法。`currentTime` 是当前时间，`effect` 对象允许你修改动画效果的属性，例如 `localTime`（对应 CSS 动画的 `animation-timeline`）。

* **HTML:**
    * 虽然这个测试文件本身不直接操作 HTML，但 Animation Worklet 的最终目的是 **驱动 HTML 元素的动画**。
    * 开发者会在 HTML 中使用 CSS 属性（例如 `animation-timeline: worklet(my-animation);`) 来指定使用某个 Animation Worklet 定义的动画。

* **CSS:**
    * **`effect.localTime = 123;`**:  在 JavaScript 的 `animate()` 方法中设置 `effect.localTime` 会 **直接影响 CSS 动画的时间线**。这使得开发者可以使用 JavaScript 来动态控制动画的进度。
    * 其他可能的 `effect` 属性可能对应 CSS 的其他动画属性，例如 `transform`，允许开发者完全自定义动画的视觉效果。

**举例说明：**

假设我们在 HTML 中有以下元素：

```html
<div id="myElement" style="animation-timeline: worklet(my-animation);"></div>
```

并且在 JavaScript 中注册了一个 Animation Worklet：

```javascript
// 在单独的 .js 文件中注册 Worklet
registerAnimator('my-animation', class {
  animate(currentTime, effect) {
    effect.localTime = currentTime / 1000; // 根据当前时间设置动画进度
    effect.transform = `translateX(${currentTime / 10}px)`; // 动态设置元素的 transform
  }
});
```

当浏览器渲染 `myElement` 时，会调用名为 'my-animation' 的 Animation Worklet。`animation_worklet_global_scope_test.cc` 中的测试确保了 `registerAnimator` 能正确注册这个类，并且 `animate` 方法能被正确调用，并且 `effect.localTime` 和 `effect.transform` 的修改能传递到渲染引擎，从而驱动 `myElement` 的动画。

**3. 逻辑推理、假设输入与输出**

测试代码中经常进行逻辑推理，例如：

* **假设输入：** 调用 `registerAnimator('test', class { animate() {} });`
* **预期输出：** `global_scope->FindDefinitionForTest("test")` 返回一个非空的 `AnimatorDefinition` 指针。

* **假设输入：** 调用 `registerAnimator('null', null);`
* **预期输出：** `global_scope->FindDefinitionForTest("null")` 返回 `nullptr`。

* **假设输入：**  一个包含新动画 ID 的 `AnimationWorkletInput` 传递给 `ProxyClientMutate`。
* **预期输出：** `global_scope` 中会创建一个新的 `Animator` 实例，并且 `output->animations` 包含相应的动画信息。

**4. 用户或编程常见的使用错误**

* **未定义 `animate()` 方法：**  用户忘记在注册的动画器类中定义 `animate()` 方法。这会导致动画无法执行。测试会验证在这种情况下不会创建有效的动画器。
* **注册时传递无效的类定义：** 用户可能传递 `null` 或其他非类的对象给 `registerAnimator`。测试会验证这种情况被正确处理。
* **假设动画会立即执行：** 用户可能期望在注册动画器后立即看到动画效果，但实际上需要通过 CSS 或 JavaScript 将其应用到元素上。
* **在 `animate()` 中访问不存在的 `effect` 属性：**  用户可能会尝试修改 `effect` 对象上不存在的属性，这可能导致错误或意想不到的行为。

**5. 用户操作如何一步步到达这里 (调试线索)**

当开发者在使用 Animation Worklet 时遇到问题，或者 Chromium 工程师在开发和维护 Animation Worklet 功能时，可能会触发到这里的测试。以下是一个可能的调试路径：

1. **开发者编写使用了 Animation Worklet 的网页。** 例如，定义了一个自定义动画并通过 CSS 应用到一个元素。
2. **浏览器尝试渲染该页面。**  渲染引擎会尝试加载和执行 Animation Worklet 的 JavaScript 代码。
3. **如果 Animation Worklet 的代码存在错误，或者 Blink 引擎的 Animation Worklet 实现存在 Bug，动画可能无法正常工作。**
4. **开发者或工程师可能会尝试调试。** 这可能包括：
    * **查看控制台错误消息：**  如果 JavaScript 代码有语法错误或运行时错误，控制台会显示相关信息。
    * **使用开发者工具的 Performance 面板：**  查看动画帧是否正常渲染，是否存在性能瓶颈。
    * **查看 Blink 引擎的日志：**  Blink 引擎会输出一些调试信息，可以帮助定位问题。
5. **如果怀疑是 Blink 引擎的实现问题，工程师可能会运行相关的单元测试。**  `animation_worklet_global_scope_test.cc` 就是这样一个测试文件。
6. **运行特定的测试用例，例如 `BasicParsing` 或 `ConstructAndAnimate`，可以验证 `AnimationWorkletGlobalScope` 的核心功能是否正常。**
7. **如果某个测试用例失败，工程师可以分析失败的原因，查看代码，修复 Bug，并确保修复后的代码通过所有相关的测试。**

总而言之，`animation_worklet_global_scope_test.cc` 是确保 Chromium Blink 引擎中 Animation Worklet 功能正确性和稳定性的重要组成部分。它通过单元测试的方式，覆盖了 `AnimationWorkletGlobalScope` 类的关键行为，并间接验证了 Animation Worklet 与 JavaScript、HTML 和 CSS 的集成是否按预期工作。

Prompt: 
```
这是目录为blink/renderer/modules/animationworklet/animation_worklet_global_scope_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/animationworklet/animation_worklet_global_scope.h"

#include "base/synchronization/waitable_event.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/v8_cache_options.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_url_request.h"
#include "third_party/blink/renderer/bindings/core/v8/module_record.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/script/classic_script.h"
#include "third_party/blink/renderer/core/testing/page_test_base.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/core/workers/worklet_module_responses_map.h"
#include "third_party/blink/renderer/modules/animationworklet/animation_worklet.h"
#include "third_party/blink/renderer/modules/animationworklet/animation_worklet_proxy_client.h"
#include "third_party/blink/renderer/modules/animationworklet/animator.h"
#include "third_party/blink/renderer/modules/animationworklet/animator_definition.h"
#include "third_party/blink/renderer/modules/worklet/worklet_thread_test_common.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader_options.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"

#include <memory>

namespace blink {
namespace {

class MockAnimationWorkletProxyClient : public AnimationWorkletProxyClient {
 public:
  MockAnimationWorkletProxyClient()
      : AnimationWorkletProxyClient(0, nullptr, nullptr, nullptr, nullptr),
        did_add_global_scope_(false) {}
  void AddGlobalScope(WorkletGlobalScope*) override {
    did_add_global_scope_ = true;
  }
  void SynchronizeAnimatorName(const String&) override {}
  bool did_add_global_scope() { return did_add_global_scope_; }

 private:
  bool did_add_global_scope_;
};

std::unique_ptr<AnimationWorkletOutput> ProxyClientMutate(
    AnimationWorkletInput& state,
    AnimationWorkletGlobalScope* global_scope) {
  std::unique_ptr<AnimationWorkletOutput> output =
      std::make_unique<AnimationWorkletOutput>();
  global_scope->UpdateAnimatorsList(state);
  global_scope->UpdateAnimators(state, output.get(),
                                [](Animator*) { return true; });
  return output;
}

std::unique_ptr<WorkletAnimationEffectTimings> CreateEffectTimings() {
  auto timings = base::MakeRefCounted<base::RefCountedData<Vector<Timing>>>();
  timings->data.push_back(Timing());
  auto normalized_timings = base::MakeRefCounted<
      base::RefCountedData<Vector<Timing::NormalizedTiming>>>();
  normalized_timings->data.push_back(Timing::NormalizedTiming());
  return std::make_unique<WorkletAnimationEffectTimings>(
      std::move(timings), std::move(normalized_timings));
}

}  // namespace

class AnimationWorkletGlobalScopeTest : public PageTestBase {
 public:
  AnimationWorkletGlobalScopeTest() = default;

  void SetUp() override {
    PageTestBase::SetUp(gfx::Size());
    NavigateTo(KURL("https://example.com/"));
    reporting_proxy_ = std::make_unique<WorkerReportingProxy>();
  }

  using TestCalback = void (
      AnimationWorkletGlobalScopeTest::*)(WorkerThread*, base::WaitableEvent*);
  // Create a new animation worklet and run the callback task on it. Terminate
  // the worklet once the task completion is signaled.
  void RunTestOnWorkletThread(TestCalback callback) {
    std::unique_ptr<WorkerThread> worklet =
        CreateThreadAndProvideAnimationWorkletProxyClient(
            &GetDocument(), reporting_proxy_.get());
    base::WaitableEvent waitable_event;
    PostCrossThreadTask(
        *worklet->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
        CrossThreadBindOnce(callback, CrossThreadUnretained(this),
                            CrossThreadUnretained(worklet.get()),
                            CrossThreadUnretained(&waitable_event)));
    waitable_event.Wait();

    worklet->Terminate();
    worklet->WaitForShutdownForTesting();
  }

  void RunScriptOnWorklet(String source_code,
                          WorkerThread* thread,
                          base::WaitableEvent* waitable_event) {
    ASSERT_TRUE(thread->IsCurrentThread());
    auto* global_scope = To<AnimationWorkletGlobalScope>(thread->GlobalScope());
    ClassicScript::CreateUnspecifiedScript(source_code)
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    waitable_event->Signal();
  }

  void RunBasicParsingTestOnWorklet(WorkerThread* thread,
                                    base::WaitableEvent* waitable_event) {
    ASSERT_TRUE(thread->IsCurrentThread());
    auto* global_scope = To<AnimationWorkletGlobalScope>(thread->GlobalScope());

    {
      // registerAnimator() with a valid class definition should define an
      // animator.
      String source_code =
          R"JS(
            registerAnimator('test', class {
              constructor () {}
              animate () {}
            });
          )JS";
      ClassicScript::CreateUnspecifiedScript(source_code)
          ->RunScriptOnScriptState(
              global_scope->ScriptController()->GetScriptState());

      AnimatorDefinition* definition =
          global_scope->FindDefinitionForTest("test");
      ASSERT_TRUE(definition);
    }

    {
      // registerAnimator() with a null class definition should fail to define
      // an animator.
      String source_code = "registerAnimator('null', null);";
      ClassicScript::CreateUnspecifiedScript(source_code)
          ->RunScriptOnScriptState(
              global_scope->ScriptController()->GetScriptState());
      EXPECT_FALSE(global_scope->FindDefinitionForTest("null"));
    }

    EXPECT_FALSE(global_scope->FindDefinitionForTest("non-existent"));

    waitable_event->Signal();
  }

  static bool RunScriptAndGetBoolean(AnimationWorkletGlobalScope* global_scope,
                                     const String& script) {
    ScriptState* script_state =
        global_scope->ScriptController()->GetScriptState();
    DCHECK(script_state);
    v8::Isolate* isolate = script_state->GetIsolate();
    DCHECK(isolate);
    v8::HandleScope scope(isolate);

    ClassicScript* classic_script =
        ClassicScript::CreateUnspecifiedScript(script);

    ScriptEvaluationResult result =
        classic_script->RunScriptOnScriptStateAndReturnValue(script_state);
    DCHECK_EQ(result.GetResultType(),
              ScriptEvaluationResult::ResultType::kSuccess);
    return ToBoolean(isolate, result.GetSuccessValue(), ASSERT_NO_EXCEPTION);
  }

  void RunConstructAndAnimateTestOnWorklet(
      WorkerThread* thread,
      base::WaitableEvent* waitable_event) {
    ASSERT_TRUE(thread->IsCurrentThread());
    auto* global_scope = To<AnimationWorkletGlobalScope>(thread->GlobalScope());

    String source_code =
        R"JS(
            // Worklet doesn't have a reference to the global object. Instead,
            // retrieve it in a tricky way.
            var global_object = Function('return this')();
            global_object.constructed = false;
            global_object.animated = false;

            registerAnimator('test', class {
              constructor () {
                constructed = true;
              }
              animate () {
                animated = true;
              }
            });
        )JS";
    ClassicScript::CreateUnspecifiedScript(source_code)
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    EXPECT_FALSE(RunScriptAndGetBoolean(
        global_scope, "Function('return this')().constructed"))
        << "constructor is not invoked";

    EXPECT_FALSE(RunScriptAndGetBoolean(global_scope,
                                        "Function('return this')().animated"))
        << "animate function is invoked early";

    // Passing a new input state with a new animation id should cause the
    // worklet to create and animate an animator.
    cc::WorkletAnimationId animation_id = {1, 1};
    AnimationWorkletInput state;
    std::unique_ptr<WorkletAnimationEffectTimings> effect_timings =
        CreateEffectTimings();
    state.added_and_updated_animations.emplace_back(
        animation_id, "test", 5000, nullptr, std::move(effect_timings));

    std::unique_ptr<AnimationWorkletOutput> output =
        ProxyClientMutate(state, global_scope);
    EXPECT_EQ(output->animations.size(), 1ul);

    EXPECT_TRUE(RunScriptAndGetBoolean(global_scope,
                                       "Function('return this')().constructed"))
        << "constructor is not invoked";

    EXPECT_TRUE(RunScriptAndGetBoolean(global_scope,
                                       "Function('return this')().animated"))
        << "animate function is not invoked";

    waitable_event->Signal();
  }

  void RunStateExistenceTestOnWorklet(WorkerThread* thread,
                                      base::WaitableEvent* waitable_event) {
    ASSERT_TRUE(thread->IsCurrentThread());
    auto* global_scope = To<AnimationWorkletGlobalScope>(thread->GlobalScope());
    String source_code =
        R"JS(
            class Stateful {
              animate () {}
              state () {}
            }

            class Stateless {
              animate () {}
            }

            class Foo {
              animate () {}
            }
            Foo.prototype.state = function() {};

            registerAnimator('stateful_animator', Stateful);
            registerAnimator('stateless_animator', Stateless);
            registerAnimator('foo', Foo);
        )JS";
    ClassicScript::CreateUnspecifiedScript(source_code)
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    AnimatorDefinition* first_definition =
        global_scope->FindDefinitionForTest("stateful_animator");
    EXPECT_TRUE(first_definition->IsStateful());
    AnimatorDefinition* second_definition =
        global_scope->FindDefinitionForTest("stateless_animator");
    EXPECT_FALSE(second_definition->IsStateful());
    AnimatorDefinition* third_definition =
        global_scope->FindDefinitionForTest("foo");
    EXPECT_TRUE(third_definition->IsStateful());

    waitable_event->Signal();
  }

  void RunAnimateOutputTestOnWorklet(WorkerThread* thread,
                                     base::WaitableEvent* waitable_event) {
    AnimationWorkletGlobalScope* global_scope =
        static_cast<AnimationWorkletGlobalScope*>(thread->GlobalScope());
    ASSERT_TRUE(global_scope);
    ASSERT_TRUE(global_scope->IsAnimationWorkletGlobalScope());
    ClassicScript::CreateUnspecifiedScript(R"JS(
            registerAnimator('test', class {
              animate (currentTime, effect) {
                effect.localTime = 123;
              }
            });
          )JS")
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    // Passing a new input state with a new animation id should cause the
    // worklet to create and animate an animator.
    cc::WorkletAnimationId animation_id = {1, 1};
    AnimationWorkletInput state;
    std::unique_ptr<WorkletAnimationEffectTimings> effect_timings =
        CreateEffectTimings();
    state.added_and_updated_animations.emplace_back(
        animation_id, "test", 5000, nullptr, std::move(effect_timings));

    std::unique_ptr<AnimationWorkletOutput> output =
        ProxyClientMutate(state, global_scope);

    EXPECT_EQ(output->animations.size(), 1ul);
    EXPECT_EQ(output->animations[0].local_times[0], base::Milliseconds(123));

    waitable_event->Signal();
  }

  // This test verifies that an animator instance is not created if
  // MutatorInputState does not have an animation in
  // added_and_updated_animations.
  void RunAnimatorInstanceCreationTestOnWorklet(
      WorkerThread* thread,
      base::WaitableEvent* waitable_event) {
    AnimationWorkletGlobalScope* global_scope =
        static_cast<AnimationWorkletGlobalScope*>(thread->GlobalScope());
    ASSERT_TRUE(global_scope);
    ASSERT_TRUE(global_scope->IsAnimationWorkletGlobalScope());
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 0u);
    ClassicScript::CreateUnspecifiedScript(R"JS(
            registerAnimator('test', class {
              animate (currentTime, effect) {
                effect.localTime = 123;
              }
            });
          )JS")
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    cc::WorkletAnimationId animation_id = {1, 1};
    AnimationWorkletInput state;
    state.updated_animations.push_back({animation_id, 5000});
    EXPECT_EQ(state.added_and_updated_animations.size(), 0u);
    EXPECT_EQ(state.updated_animations.size(), 1u);

    std::unique_ptr<AnimationWorkletOutput> output =
        ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 0u);

    state.removed_animations.push_back(animation_id);
    EXPECT_EQ(state.added_and_updated_animations.size(), 0u);
    EXPECT_EQ(state.removed_animations.size(), 1u);

    output = ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 0u);

    std::unique_ptr<WorkletAnimationEffectTimings> effect_timings =
        CreateEffectTimings();
    state.added_and_updated_animations.push_back(
        {animation_id, "test", 5000, nullptr, std::move(effect_timings)});
    EXPECT_EQ(state.added_and_updated_animations.size(), 1u);

    output = ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 1u);
    waitable_event->Signal();
  }

  // This test verifies that an animator instance is created and removed
  // properly.
  void RunAnimatorInstanceUpdateTestOnWorklet(
      WorkerThread* thread,
      base::WaitableEvent* waitable_event) {
    AnimationWorkletGlobalScope* global_scope =
        static_cast<AnimationWorkletGlobalScope*>(thread->GlobalScope());
    ASSERT_TRUE(global_scope);
    ASSERT_TRUE(global_scope->IsAnimationWorkletGlobalScope());
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 0u);
    ClassicScript::CreateUnspecifiedScript(R"JS(
            registerAnimator('test', class {
              animate (currentTime, effect) {
                effect.localTime = 123;
              }
            });
          )JS")
        ->RunScriptOnScriptState(
            global_scope->ScriptController()->GetScriptState());

    cc::WorkletAnimationId animation_id = {1, 1};
    AnimationWorkletInput state;
    std::unique_ptr<WorkletAnimationEffectTimings> effect_timings =
        CreateEffectTimings();
    state.added_and_updated_animations.push_back(
        {animation_id, "test", 5000, nullptr, std::move(effect_timings)});
    EXPECT_EQ(state.added_and_updated_animations.size(), 1u);

    std::unique_ptr<AnimationWorkletOutput> output =
        ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 1u);

    state.added_and_updated_animations.clear();
    state.updated_animations.push_back({animation_id, 6000});
    EXPECT_EQ(state.added_and_updated_animations.size(), 0u);
    EXPECT_EQ(state.updated_animations.size(), 1u);

    output = ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 1u);

    state.updated_animations.clear();
    state.removed_animations.push_back(animation_id);
    EXPECT_EQ(state.updated_animations.size(), 0u);
    EXPECT_EQ(state.removed_animations.size(), 1u);

    output = ProxyClientMutate(state, global_scope);
    EXPECT_EQ(global_scope->GetAnimatorsSizeForTest(), 0u);

    waitable_event->Signal();
  }

  std::unique_ptr<WorkerReportingProxy> reporting_proxy_;
};

TEST_F(AnimationWorkletGlobalScopeTest, BasicParsing) {
  RunTestOnWorkletThread(
      &AnimationWorkletGlobalScopeTest::RunBasicParsingTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest, ConstructAndAnimate) {
  RunTestOnWorkletThread(
      &AnimationWorkletGlobalScopeTest::RunConstructAndAnimateTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest, StateExistence) {
  RunTestOnWorkletThread(
      &AnimationWorkletGlobalScopeTest::RunStateExistenceTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest, AnimationOutput) {
  RunTestOnWorkletThread(
      &AnimationWorkletGlobalScopeTest::RunAnimateOutputTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest, AnimatorInstanceCreation) {
  RunTestOnWorkletThread(&AnimationWorkletGlobalScopeTest::
                             RunAnimatorInstanceCreationTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest, AnimatorInstanceUpdate) {
  RunTestOnWorkletThread(
      &AnimationWorkletGlobalScopeTest::RunAnimatorInstanceUpdateTestOnWorklet);
}

TEST_F(AnimationWorkletGlobalScopeTest,
       ShouldRegisterItselfAfterFirstAnimatorRegistration) {
  MockAnimationWorkletProxyClient* proxy_client =
      MakeGarbageCollected<MockAnimationWorkletProxyClient>();
  std::unique_ptr<WorkerThread> worklet =
      CreateThreadAndProvideAnimationWorkletProxyClient(
          &GetDocument(), reporting_proxy_.get(), proxy_client);
  // Animation worklet global scope (AWGS) should not register itself upon
  // creation.
  EXPECT_FALSE(proxy_client->did_add_global_scope());

  base::WaitableEvent waitable_event;
  String source_code =
      R"JS(
        registerAnimator('test', class {
          constructor () {}
          animate () {}
        });
      )JS";
  PostCrossThreadTask(
      *worklet->GetTaskRunner(TaskType::kInternalTest), FROM_HERE,
      CrossThreadBindOnce(&AnimationWorkletGlobalScopeTest::RunScriptOnWorklet,
                          CrossThreadUnretained(this), std::move(source_code),
                          CrossThreadUnretained(worklet.get()),
                          CrossThreadUnretained(&waitable_event)));
  waitable_event.Wait();

  // AWGS should register itself first time an animator is registered with it.
  EXPECT_TRUE(proxy_client->did_add_global_scope());

  worklet->Terminate();
  worklet->WaitForShutdownForTesting();
}

}  // namespace blink

"""

```
Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Initial Understanding & Goal:**

The first step is to understand the core purpose of the request: analyze the `v8_per_isolate_data.cc` file in Chromium's Blink engine. The goal is to identify its functionality and explain its relevance to JavaScript, HTML, and CSS. Furthermore, it needs examples of logical reasoning, potential user/programming errors.

**2. Skimming and Identifying Key Components:**

I'd start by skimming the code, paying attention to:

* **Include directives:**  These tell us the dependencies and thus hints at the functionality. Seeing things like `v8.h`, `bindings/`, `platform/`, and `heap/` immediately points to V8 integration, binding mechanisms, and memory management.
* **Class name:** `V8PerIsolateData` strongly suggests this class manages data specific to a V8 isolate. An "isolate" in V8 is essentially an independent V8 runtime environment.
* **Member variables:**  These hold the state of the object and are crucial for understanding its responsibilities. I'd look for things like `isolate_holder_`, `string_cache_`, `private_property_`, `v8_template_map_*`,  `script_regexp_script_state_`, etc.
* **Methods:**  Functions define the actions the class can perform. Methods like `Initialize`, `Destroy`, `FindV8Template`, `AddV8Template`, `EnsureScriptRegexpContext` provide direct clues about its roles.
* **Static methods and members:**  These often indicate global or shared resources related to the class. `From(isolate)` is a common pattern in Blink for accessing per-isolate data.

**3. Deep Dive into Key Functionality:**

Based on the initial skim, I'd focus on the major areas of responsibility:

* **V8 Isolate Management (`isolate_holder_`):**  The presence of `gin::IsolateHolder` is a strong indicator that this class is responsible for managing the lifecycle of a V8 isolate within Blink. This includes creation, initialization, and shutdown.
* **Template Caching (`v8_template_map_*`):** The `V8TemplateMap` suggests a mechanism for storing and retrieving V8 templates. Templates are fundamental to how native C++ objects are exposed to JavaScript. The distinction between `_for_main_world_` and `_for_non_main_worlds_` is also important, pointing to different contexts (main document vs. workers/extensions).
* **String Caching (`string_cache_`):**  String interning is a common optimization in JavaScript engines. This likely aims to reduce memory usage by sharing identical strings.
* **Private Properties (`private_property_`):** V8 private properties allow associating data with JavaScript objects in a way that's not directly accessible from JavaScript.
* **Regular Expressions (`script_regexp_script_state_`):**  The code clearly creates and manages a separate V8 context specifically for regular expression operations. This is a performance optimization and potentially for security reasons.
* **Garbage Collection Callbacks:** The `prologue_callback_` and `epilogue_callback_` members and their associated methods indicate involvement in tracking garbage collection within V8.
* **Crash Reporting (AddCrashKey):** This function clearly deals with setting up crash reporting information related to the V8 isolate.
* **Task Attribution (`task_attribution_tracker_`):** The presence of this member and related feature flag suggests involvement in tracking the origin of tasks executed by V8.

**4. Connecting to JavaScript, HTML, and CSS:**

Once I have a good grasp of the internal functionality, I'd think about how these features relate to the web technologies:

* **JavaScript:** This is the most direct connection. V8 *is* the JavaScript engine. The template caching is essential for making C++ browser APIs available to JavaScript. Private properties can be used for internal implementation details not exposed to scripts. The regex context is directly used by JavaScript's `RegExp` object.
* **HTML:**  HTML elements are represented as objects in the browser's DOM. These objects are often exposed to JavaScript through the mechanisms managed by `V8PerIsolateData`. For instance, accessing `document.getElementById()` returns a JavaScript object that wraps a C++ `HTMLElement` object.
* **CSS:**  While less direct, CSS properties and values can be manipulated via JavaScript. The objects representing CSS rules and styles would also be exposed to JavaScript using the same binding mechanisms.

**5. Logical Reasoning and Examples:**

Here, I'd consider the "if-then" scenarios and potential data flow:

* **Template Lookup:**  If JavaScript code tries to access a property of a DOM element, the engine needs to find the corresponding C++ getter/setter. The template cache helps speed up this process.
* **String Interning:** If the same string literal appears multiple times in JavaScript code, the cache ensures only one copy exists in memory.
* **Private Properties:** If a browser API needs to store internal state associated with a JavaScript object without exposing it directly, private properties are used.

**6. User and Programming Errors:**

I'd think about common mistakes developers make when interacting with JavaScript and how this code might be relevant:

* **Incorrect Type Checks:**  Using `instanceof` incorrectly might stem from a misunderstanding of the underlying object hierarchy and how templates are set up.
* **Memory Leaks (Indirectly):** While `V8PerIsolateData` is involved in memory management, misuse of JavaScript objects or forgetting to break circular references can lead to leaks that V8's GC tries to handle.
* **Performance Issues:** Excessive string creation or inefficient regular expressions can be amplified if the underlying caching or regex mechanisms aren't efficient.

**7. Structuring the Output:**

Finally, I'd organize the information logically with clear headings and examples, as demonstrated in the provided good answer. Using bullet points and code snippets makes the explanation easier to understand. The key is to connect the low-level C++ implementation details to the observable behavior in web development.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about V8."  **Correction:** Realize it's about the *integration* of V8 with the rest of the Blink rendering engine, especially the binding layer.
* **Initial thought:** "The string cache is just an optimization." **Refinement:**  Recognize that string interning has security implications as well (e.g., preventing certain types of injection attacks).
* **Initial thought:**  Focus solely on the technical details. **Refinement:**  Make sure to clearly explain the *why* and the connection to web development concepts.

By following these steps, combining code analysis with knowledge of web technologies and common developer practices, one can arrive at a comprehensive and helpful explanation like the example provided.
好的，让我们详细分析一下 `blink/renderer/platform/bindings/v8_per_isolate_data.cc` 文件的功能。

**文件功能概览:**

`v8_per_isolate_data.cc` 文件定义了 `V8PerIsolateData` 类，这个类在 Chromium 的 Blink 渲染引擎中扮演着至关重要的角色。它的主要功能是 **管理与特定 V8 隔离区（Isolate）相关的数据和资源**。

V8 Isolate 是 V8 JavaScript 引擎中的一个独立执行环境。每个 Isolate 拥有自己的堆、全局对象等，彼此隔离。`V8PerIsolateData` 作为一个中心化的管理点，为 Blink 引擎提供了一种安全且高效的方式来存储和访问与特定 V8 Isolate 相关的各种数据。

**核心功能分解:**

1. **V8 Isolate 生命周期管理:**
   - `Initialize()`:  负责创建和初始化 V8 Isolate。它会设置 Isolate 的各种参数，例如是否允许原子操作、是否创建快照等。
   - `Destroy()`:  负责清理和销毁 V8 Isolate 相关的资源。这包括清除缓存、解除回调等。
   - `WillBeDestroyed()`: 在 Isolate 即将被销毁前执行一些清理操作，例如解除线程与 Isolate 的关联。

2. **模板缓存 (Template Caching):**
   - `FindV8Template()`, `AddV8Template()`:  管理 V8 模板的缓存。模板是 V8 中用于创建 JavaScript 对象和函数的蓝图。通过缓存模板，可以避免重复创建，提高性能。
   - 区分了主世界 (main world) 和非主世界 (non-main worlds) 的模板缓存，这是因为不同的 JavaScript 执行上下文（例如主文档、Web Workers）可能需要不同的模板。
   - `FindV8DictionaryTemplate()`, `AddV8DictionaryTemplate()`:  管理字典模板的缓存，用于创建具有动态属性的 JavaScript 对象。

3. **字符串缓存 (String Caching):**
   - `string_cache_`:  存储已创建的 JavaScript 字符串，避免重复创建相同的字符串，节省内存并提高性能。

4. **私有属性管理 (Private Property Management):**
   - `private_property_`:  用于管理 V8 私有属性。私有属性是只能在特定上下文中访问的属性，用于封装实现细节。

5. **正则表达式上下文管理 (Regular Expression Context Management):**
   - `EnsureScriptRegexpContext()`, `ClearScriptRegexpContext()`:  为了提高正则表达式的执行效率和安全性，Blink 会创建一个独立的 V8 上下文 (Context) 来处理正则表达式。这个功能负责管理这个专用上下文的生命周期。

6. **垃圾回收回调 (Garbage Collection Callbacks):**
   - `SetGCCallbacks()`:  允许 Blink 注册在 V8 垃圾回收开始和结束时执行的回调函数。这使得 Blink 能够跟踪垃圾回收事件并执行必要的清理工作。

7. **崩溃报告集成 (Crash Reporting Integration):**
   - `AddCrashKey()`:  在发生崩溃时，将与 V8 Isolate 相关的关键信息添加到崩溃报告中，帮助开发人员诊断问题。

8. **线程调试器 (Thread Debugger):**
   - `SetThreadDebugger()`:  允许设置与 Isolate 关联的线程调试器，用于调试 JavaScript 代码。

9. **密码正则表达式 (Password Regular Expression):**
   - `SetPasswordRegexp()`, `GetPasswordRegexp()`:  存储用于密码验证的正则表达式。

10. **任务归因跟踪 (Task Attribution Tracking):**
    - 与 `kTaskAttributionInfrastructureDisabledForTesting` 特性标志相关，用于跟踪 JavaScript 任务的来源，以便进行性能分析和调试。

11. **直方图支持 (Histogram Support):**
    - `CreateHistogram()`, `AddHistogramSample()`:  提供创建和记录 V8 相关性能指标直方图的功能，用于性能分析。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`V8PerIsolateData` 与 JavaScript 的关系最为紧密，因为它直接管理 V8 Isolate 这个 JavaScript 引擎的运行环境。它也间接地与 HTML 和 CSS 相关，因为 JavaScript 可以操作 DOM (HTML 结构) 和 CSS 样式。

**JavaScript:**

* **模板缓存:** 当 JavaScript 代码尝试创建一个新的 DOM 元素，例如 `document.createElement('div')`，Blink 需要在 C++ 层创建一个对应的 `HTMLDivElement` 对象。`V8PerIsolateData` 管理的模板缓存存储了 `HTMLDivElement` 的 V8 模板，V8 基于这个模板创建 JavaScript 对象，并将 C++ 对象包装起来，使得 JavaScript 代码可以操作这个元素。
  * **假设输入:** JavaScript 代码执行 `document.createElement('p')`。
  * **逻辑推理:** Blink 会查找 `V8PerIsolateData` 中 `HTMLParagraphElement` 的模板。如果找到，则使用该模板创建 JavaScript 对象；否则，可能需要先创建模板。
  * **输出:** 返回一个代表 `<p>` 元素的 JavaScript 对象。

* **字符串缓存:** 当 JavaScript 代码中多次使用相同的字符串字面量，例如 `"hello"`，`V8PerIsolateData` 的字符串缓存会确保在 V8 Isolate 中只存在一份该字符串的拷贝，从而节省内存。
  * **假设输入:** JavaScript 代码中存在多个 `"world"` 字符串字面量。
  * **逻辑推理:** 当 V8 遇到 `"world"` 时，会先检查字符串缓存中是否已存在该字符串。
  * **输出:** 如果存在，则返回缓存中的字符串引用；否则，创建新字符串并添加到缓存。

* **私有属性:** 某些浏览器 API 可能使用 V8 私有属性来存储 JavaScript 对象内部的实现细节，这些细节不应该被 JavaScript 代码直接访问。例如，某个 DOM 元素的内部状态或关联的 C++ 对象指针。

* **正则表达式上下文:** 当 JavaScript 执行正则表达式操作，例如 ` /abc/.test("abcdef") `，V8 会在 `V8PerIsolateData` 管理的专用正则表达式上下文中执行该操作，与其他 JavaScript 代码的执行环境隔离，提高性能和安全性。

**HTML:**

* `V8PerIsolateData` 管理的模板使得 JavaScript 能够与 HTML 元素进行交互。例如，当 JavaScript 代码访问 `element.className` 时，实际上是通过 V8 模板定义的 getter 访问了 C++ `HTMLElement` 对象的 `className` 属性。

**CSS:**

* 类似地，当 JavaScript 代码操作 CSS 样式，例如 `element.style.color = 'red'`，`V8PerIsolateData` 管理的模板使得 JavaScript 可以访问和修改与 HTML 元素关联的 CSS 样式对象。

**用户或编程常见的使用错误举例:**

* **错误地使用 `instanceof` 进行类型检查:**  开发者可能会错误地假设不同 Isolate 中创建的对象可以使用 `instanceof` 进行比较。由于每个 Isolate 拥有独立的模板，跨 Isolate 的 `instanceof` 检查可能会返回意外的结果。
    * **场景:**  一个主页面和一个 iframe 各自运行在不同的 V8 Isolate 中。
    * **错误代码:**  在主页面中创建了一个元素 `mainElement`，然后在 iframe 中尝试 `mainElement instanceof iframe.contentWindow.Element`。
    * **预期结果:**  由于 `Element` 构造函数在不同的 Isolate 中，`instanceof` 可能会返回 `false`，即使 `mainElement` 确实是一个 DOM 元素。

* **忘记清理跨 Isolate 的对象引用:** 如果在不同的 V8 Isolate 之间传递对象引用，开发者需要小心管理这些引用，避免内存泄漏。`V8PerIsolateData` 本身虽然不直接处理跨 Isolate 引用，但其管理的资源是理解跨 Isolate 交互的基础。

* **假设全局对象在所有 Isolate 中都相同:**  每个 V8 Isolate 拥有独立的全局对象。开发者不能假设在一个 Isolate 中定义的全局变量或函数可以在另一个 Isolate 中直接访问。这与 `V8PerIsolateData` 管理的 Isolate 隔离性直接相关。

**总结:**

`v8_per_isolate_data.cc` 中定义的 `V8PerIsolateData` 类是 Blink 引擎中连接 JavaScript (通过 V8) 和浏览器内部实现的桥梁。它负责管理 V8 Isolate 的生命周期、缓存关键数据结构（如模板和字符串）、管理正则表达式上下文，以及提供与垃圾回收和崩溃报告集成的能力。理解 `V8PerIsolateData` 的功能有助于深入理解 Blink 如何执行 JavaScript 并与网页内容 (HTML, CSS) 进行交互。

### 提示词
```
这是目录为blink/renderer/platform/bindings/v8_per_isolate_data.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"

#include <memory>
#include <utility>

#include "base/debug/crash_logging.h"
#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "gin/public/v8_idle_task_runner.h"
#include "partition_alloc/oom.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/blink.h"
#include "third_party/blink/renderer/platform/bindings/active_script_wrappable_base.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/thread_debugger.h"
#include "third_party/blink/renderer/platform/bindings/v8_binding.h"
#include "third_party/blink/renderer/platform/bindings/v8_histogram_accumulator.h"
#include "third_party/blink/renderer/platform/bindings/v8_object_constructor.h"
#include "third_party/blink/renderer/platform/bindings/v8_private_property.h"
#include "third_party/blink/renderer/platform/bindings/v8_value_cache.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state_scopes.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/leak_annotations.h"

namespace blink {

BASE_FEATURE(kTaskAttributionInfrastructureDisabledForTesting,
             "TaskAttributionInfrastructureDisabledForTesting",
             base::FEATURE_DISABLED_BY_DEFAULT);

namespace {

void AddCrashKey(v8::CrashKeyId id, const std::string& value) {
  using base::debug::AllocateCrashKeyString;
  using base::debug::CrashKeySize;
  using base::debug::SetCrashKeyString;

  switch (id) {
    case v8::CrashKeyId::kIsolateAddress:
      static auto* const isolate_address =
          AllocateCrashKeyString("v8_isolate_address", CrashKeySize::Size32);
      SetCrashKeyString(isolate_address, value);
      break;
    case v8::CrashKeyId::kReadonlySpaceFirstPageAddress:
      static auto* const ro_space_firstpage_address = AllocateCrashKeyString(
          "v8_ro_space_firstpage_address", CrashKeySize::Size32);
      SetCrashKeyString(ro_space_firstpage_address, value);
      break;
    case v8::CrashKeyId::kMapSpaceFirstPageAddress:
      static auto* const map_space_firstpage_address = AllocateCrashKeyString(
          "v8_map_space_firstpage_address", CrashKeySize::Size32);
      SetCrashKeyString(map_space_firstpage_address, value);
      break;
    case v8::CrashKeyId::kCodeSpaceFirstPageAddress:
      static auto* const code_space_firstpage_address = AllocateCrashKeyString(
          "v8_code_space_firstpage_address", CrashKeySize::Size32);
      SetCrashKeyString(code_space_firstpage_address, value);
      break;
    case v8::CrashKeyId::kDumpType:
      static auto* const dump_type =
          AllocateCrashKeyString("dump-type", CrashKeySize::Size32);
      SetCrashKeyString(dump_type, value);
      break;
    default:
      // Doing nothing for new keys is a valid option. Having this case allows
      // to introduce new CrashKeyId's without triggering a build break.
      break;
  }
}

V8PerIsolateData::TaskAttributionTrackerFactoryPtr
    task_attribution_tracker_factory = nullptr;

}  // namespace

static void BeforeCallEnteredCallback(v8::Isolate* isolate) {
  CHECK(!ScriptForbiddenScope::IsScriptForbidden());
}

static bool AllowAtomicWaits(
    V8PerIsolateData::V8ContextSnapshotMode v8_context_snapshot_mode) {
  return !IsMainThread() ||
         v8_context_snapshot_mode ==
             V8PerIsolateData::V8ContextSnapshotMode::kTakeSnapshot;
}

V8PerIsolateData::V8PerIsolateData(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> user_visible_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> best_effort_task_runner,
    V8ContextSnapshotMode v8_context_snapshot_mode,
    v8::CreateHistogramCallback create_histogram_callback,
    v8::AddHistogramSampleCallback add_histogram_sample_callback)
    : v8_context_snapshot_mode_(v8_context_snapshot_mode),
      isolate_holder_(
          std::move(task_runner),
          gin::IsolateHolder::kSingleThread,
          AllowAtomicWaits(v8_context_snapshot_mode)
              ? gin::IsolateHolder::kAllowAtomicsWait
              : gin::IsolateHolder::kDisallowAtomicsWait,
          IsMainThread() ? gin::IsolateHolder::IsolateType::kBlinkMainThread
                         : gin::IsolateHolder::IsolateType::kBlinkWorkerThread,
          v8_context_snapshot_mode ==
                  V8PerIsolateData::V8ContextSnapshotMode::kTakeSnapshot
              ? gin::IsolateHolder::IsolateCreationMode::kCreateSnapshot
              : gin::IsolateHolder::IsolateCreationMode::kNormal,
          create_histogram_callback,
          add_histogram_sample_callback,
          std::move(user_visible_task_runner),
          std::move(best_effort_task_runner)),
      string_cache_(std::make_unique<StringCache>(GetIsolate())),
      private_property_(std::make_unique<V8PrivateProperty>()),
      constructor_mode_(ConstructorMode::kCreateNewObject),
      runtime_call_stats_(base::DefaultTickClock::GetInstance()) {
  if (v8_context_snapshot_mode == V8ContextSnapshotMode::kTakeSnapshot) {
    // Snapshot should only execute on the main thread. SnapshotCreator enters
    // the isolate, so we don't call Isolate::Enter() here.
    CHECK(IsMainThread());
  } else {
    // FIXME: Remove once all v8::Isolate::GetCurrent() calls are gone.
    GetIsolate()->Enter();
    GetIsolate()->AddBeforeCallEnteredCallback(&BeforeCallEnteredCallback);
  }
  if (IsMainThread()) {
    GetIsolate()->SetAddCrashKeyCallback(AddCrashKey);
    main_world_ =
        DOMWrapperWorld::Create(GetIsolate(), DOMWrapperWorld::WorldType::kMain,
                                /*is_default_world_of_isolate=*/true);
    if (!base::FeatureList::IsEnabled(
            kTaskAttributionInfrastructureDisabledForTesting)) {
      CHECK(task_attribution_tracker_factory);
      task_attribution_tracker_ =
          task_attribution_tracker_factory(GetIsolate());
    }
  }
}

V8PerIsolateData::~V8PerIsolateData() = default;

v8::Isolate* V8PerIsolateData::Initialize(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> user_visible_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> best_effort_task_runner,
    V8ContextSnapshotMode context_mode,
    v8::CreateHistogramCallback create_histogram_callback,
    v8::AddHistogramSampleCallback add_histogram_sample_callback) {
  TRACE_EVENT1("v8", "V8PerIsolateData::Initialize", "V8ContextSnapshotMode",
               context_mode);
  V8PerIsolateData* data = new V8PerIsolateData(
      std::move(task_runner), std::move(user_visible_task_runner),
      std::move(best_effort_task_runner), context_mode,
      create_histogram_callback, add_histogram_sample_callback);
  DCHECK(data);

  v8::Isolate* isolate = data->GetIsolate();
  isolate->SetData(gin::kEmbedderBlink, data);
  return isolate;
}

void V8PerIsolateData::EnableIdleTasks(
    v8::Isolate* isolate,
    std::unique_ptr<gin::V8IdleTaskRunner> task_runner) {
  From(isolate)->isolate_holder_.EnableIdleTasks(std::move(task_runner));
}

// willBeDestroyed() clear things that should be cleared before
// ThreadState::detach() gets called.
void V8PerIsolateData::WillBeDestroyed(v8::Isolate* isolate) {
  V8PerIsolateData* data = From(isolate);

  data->thread_debugger_.reset();

  for (auto& item : data->user_data_) {
    if (item) {
      item->WillBeDestroyed();
    }
  }

  data->ClearScriptRegexpContext();

  ThreadState::Current()->DetachFromIsolate();

  data->active_script_wrappable_manager_.Clear();
  // Callbacks can be removed as they only cover single events (e.g. atomic
  // pause) and they cannot get out of sync.
  DCHECK_EQ(0u, data->gc_callback_depth_);
  isolate->RemoveGCPrologueCallback(data->prologue_callback_);
  isolate->RemoveGCEpilogueCallback(data->epilogue_callback_);
}

void V8PerIsolateData::SetGCCallbacks(
    v8::Isolate* isolate,
    v8::Isolate::GCCallback prologue_callback,
    v8::Isolate::GCCallback epilogue_callback) {
  prologue_callback_ = prologue_callback;
  epilogue_callback_ = epilogue_callback;
  isolate->AddGCPrologueCallback(prologue_callback_);
  isolate->AddGCEpilogueCallback(epilogue_callback_);
}

// destroy() clear things that should be cleared after ThreadState::detach()
// gets called but before the Isolate exits.
void V8PerIsolateData::Destroy(v8::Isolate* isolate) {
  isolate->RemoveBeforeCallEnteredCallback(&BeforeCallEnteredCallback);
  V8PerIsolateData* data = From(isolate);

  // Clear everything before exiting the Isolate.
  if (data->script_regexp_script_state_) {
    data->script_regexp_script_state_->DisposePerContextData();
  }
  data->private_property_.reset();
  data->string_cache_->Dispose();
  data->string_cache_.reset();
  data->v8_template_map_for_main_world_.clear();
  data->v8_template_map_for_non_main_worlds_.clear();

  // FIXME: Remove once all v8::Isolate::GetCurrent() calls are gone.
  isolate->Exit();
  delete data;
}

v8::Local<v8::Template> V8PerIsolateData::FindV8Template(
    const DOMWrapperWorld& world,
    const void* key) {
  auto& map = SelectV8TemplateMap(world);
  auto result = map.find(key);
  if (result != map.end())
    return result->value.Get(GetIsolate());
  return v8::Local<v8::Template>();
}

void V8PerIsolateData::AddV8Template(const DOMWrapperWorld& world,
                                     const void* key,
                                     v8::Local<v8::Template> value) {
  auto& map = SelectV8TemplateMap(world);
  auto result = map.insert(key, v8::Eternal<v8::Template>(GetIsolate(), value));
  DCHECK(result.is_new_entry);
}

v8::MaybeLocal<v8::DictionaryTemplate>
V8PerIsolateData::FindV8DictionaryTemplate(const void* key) {
  auto it = v8_dict_template_map_.find(key);
  return it != v8_dict_template_map_.end()
             ? it->value.Get(GetIsolate())
             : v8::MaybeLocal<v8::DictionaryTemplate>();
}

void V8PerIsolateData::AddV8DictionaryTemplate(
    const void* key,
    v8::Local<v8::DictionaryTemplate> value) {
  auto result = v8_dict_template_map_.insert(
      key, v8::Eternal<v8::DictionaryTemplate>(GetIsolate(), value));
  DCHECK(result.is_new_entry);
}

bool V8PerIsolateData::HasInstance(const WrapperTypeInfo* wrapper_type_info,
                                   v8::Local<v8::Value> untrusted_value) {
  RUNTIME_CALL_TIMER_SCOPE(GetIsolate(),
                           RuntimeCallStats::CounterId::kHasInstance);
  return HasInstance(wrapper_type_info, untrusted_value,
                     v8_template_map_for_main_world_) ||
         HasInstance(wrapper_type_info, untrusted_value,
                     v8_template_map_for_non_main_worlds_);
}

bool V8PerIsolateData::HasInstance(const WrapperTypeInfo* wrapper_type_info,
                                   v8::Local<v8::Value> untrusted_value,
                                   const V8TemplateMap& map) {
  auto result = map.find(wrapper_type_info);
  if (result == map.end())
    return false;
  v8::Local<v8::Template> v8_template = result->value.Get(GetIsolate());
  DCHECK(v8_template->IsFunctionTemplate());
  return v8_template.As<v8::FunctionTemplate>()->HasInstance(untrusted_value);
}

bool V8PerIsolateData::HasInstanceOfUntrustedType(
    const WrapperTypeInfo* untrusted_wrapper_type_info,
    v8::Local<v8::Value> untrusted_value) {
  RUNTIME_CALL_TIMER_SCOPE(GetIsolate(),
                           RuntimeCallStats::CounterId::kHasInstance);
  return HasInstanceOfUntrustedType(untrusted_wrapper_type_info,
                                    untrusted_value,
                                    v8_template_map_for_main_world_) ||
         HasInstanceOfUntrustedType(untrusted_wrapper_type_info,
                                    untrusted_value,
                                    v8_template_map_for_non_main_worlds_);
}

bool V8PerIsolateData::HasInstanceOfUntrustedType(
    const WrapperTypeInfo* untrusted_wrapper_type_info,
    v8::Local<v8::Value> untrusted_value,
    const V8TemplateMap& map) {
  auto result = map.find(untrusted_wrapper_type_info);
  if (result == map.end())
    return false;
  v8::Local<v8::Template> v8_template = result->value.Get(GetIsolate());
  if (!v8_template->IsFunctionTemplate())
    return false;
  return v8_template.As<v8::FunctionTemplate>()->HasInstance(untrusted_value);
}

V8PerIsolateData::V8TemplateMap& V8PerIsolateData::SelectV8TemplateMap(
    const DOMWrapperWorld& world) {
  return world.IsMainWorld() ? v8_template_map_for_main_world_
                             : v8_template_map_for_non_main_worlds_;
}

void V8PerIsolateData::ClearPersistentsForV8ContextSnapshot() {
  v8_template_map_for_main_world_.clear();
  v8_template_map_for_non_main_worlds_.clear();
  eternal_name_cache_.clear();
  private_property_.reset();
}

const base::span<const v8::Eternal<v8::Name>>
V8PerIsolateData::FindOrCreateEternalNameCache(
    const void* lookup_key,
    base::span<const std::string_view> names) {
  auto it = eternal_name_cache_.find(lookup_key);
  const Vector<v8::Eternal<v8::Name>>* vector = nullptr;
  if (it == eternal_name_cache_.end()) [[unlikely]] {
    v8::Isolate* isolate = GetIsolate();
    Vector<v8::Eternal<v8::Name>> new_vector(
        base::checked_cast<wtf_size_t>(names.size()));
    base::ranges::transform(
        names, new_vector.begin(), [isolate](std::string_view name) {
          return v8::Eternal<v8::Name>(
              isolate,
              V8AtomicString(
                  isolate,
                  StringView(name.data(), static_cast<unsigned>(name.size()))));
        });
    vector = &eternal_name_cache_.Set(lookup_key, std::move(new_vector))
                  .stored_value->value;
  } else {
    vector = &it->value;
  }
  DCHECK_EQ(vector->size(), names.size());
  return base::span<const v8::Eternal<v8::Name>>(vector->data(),
                                                 vector->size());
}

v8::Local<v8::Context> V8PerIsolateData::EnsureScriptRegexpContext() {
  if (!script_regexp_script_state_) {
    LEAK_SANITIZER_DISABLED_SCOPE;
    v8::Local<v8::Context> context(v8::Context::New(GetIsolate()));
    script_regexp_script_state_ = ScriptState::Create(
        context,
        DOMWrapperWorld::Create(GetIsolate(),
                                DOMWrapperWorld::WorldType::kRegExp),
        /* execution_context = */ nullptr);
  }
  return script_regexp_script_state_->GetContext();
}

void V8PerIsolateData::ClearScriptRegexpContext() {
  if (script_regexp_script_state_) {
    script_regexp_script_state_->DisposePerContextData();
    script_regexp_script_state_->DissociateContext();
  }
  script_regexp_script_state_ = nullptr;
}

void V8PerIsolateData::SetThreadDebugger(
    std::unique_ptr<ThreadDebugger> thread_debugger) {
  DCHECK(!thread_debugger_);
  thread_debugger_ = std::move(thread_debugger);
}

void V8PerIsolateData::SetPasswordRegexp(ScriptRegexp* password_regexp) {
  password_regexp_ = password_regexp;
}

ScriptRegexp* V8PerIsolateData::GetPasswordRegexp() {
  return password_regexp_;
}

void V8PerIsolateData::SetTaskAttributionTrackerFactory(
    TaskAttributionTrackerFactoryPtr factory) {
  CHECK(!task_attribution_tracker_factory);
  CHECK(IsMainThread());
  task_attribution_tracker_factory = factory;
}

void* CreateHistogram(const char* name, int min, int max, size_t buckets) {
  // Each histogram has an implicit '0' bucket (for underflow), so we can always
  // bump the minimum to 1.
  DCHECK_LE(0, min);
  min = std::max(1, min);

  // For boolean histograms, always include an overflow bucket [2, infinity).
  if (max == 1 && buckets == 2) {
    max = 2;
    buckets = 3;
  }

  const std::string histogram_name =
      Platform::Current()->GetNameForHistogram(name);
  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      histogram_name, min, max, static_cast<uint32_t>(buckets),
      base::Histogram::kUmaTargetedHistogramFlag);

  return V8HistogramAccumulator::GetInstance()->RegisterHistogram(
      histogram, histogram_name);
}

void AddHistogramSample(void* hist, int sample) {
  V8HistogramAccumulator::GetInstance()->AddSample(hist, sample);
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing this V8 source code snippet.

**1. Initial Scan and Keywords:**

First, I'd quickly scan the code, looking for recognizable keywords and structures. Things that jump out are:

* `Copyright`, `BSD-style license`: Standard boilerplate for open-source projects.
* `#include`:  Immediately tells you this is C++ code and lists dependencies. The includes themselves give hints about functionality (e.g., `src/ic/ic.h`, `src/objects/js-array-inl.h`). The `.h` files suggest there are related header files defining interfaces.
* `namespace v8`, `namespace internal`:  Indicates this is part of the internal implementation of the V8 JavaScript engine.
* `InlineCacheState`:  A key enum suggesting this code is related to optimizing property access.
* `IC::TraceIC`: A function likely used for logging or debugging the inline cache.
* `IC::Load`, `LoadIC::Load`, `LoadGlobalIC::Load`:  Strong indicators that this code handles property access (getting values).
* `UpdateState`, `UpdateCaches`, `SetCache`:  Functions for managing the state and data within the inline cache.
* `ConfigureVectorState`:  Likely involves setting up the internal representation of the inline cache's knowledge.
* `LookupIterator`: A class for traversing the prototype chain during property lookups.
* `StubCache`:  Another caching mechanism used in V8 for compiled code related to property access.
* `MigrateDeprecated`: Suggests handling of object migration during engine updates.
* `TypeError`, `ReferenceError`: Standard JavaScript error types, indicating how errors are handled.

**2. Inferring Core Functionality - The "IC" Theme:**

The presence of `InlineCacheState` and the file path `v8/src/ic/ic.cc` strongly suggest this file is central to the *Inline Cache* (IC) mechanism in V8. The IC is a crucial optimization for speeding up property access in JavaScript.

**3. Analyzing Key Functions and Structures:**

* **`InlineCacheState` Enum:** The different states (`NO_FEEDBACK`, `UNINITIALIZED`, `MONOMORPHIC`, etc.) represent the learning process of the IC. It starts with no information and gradually specializes based on observed access patterns.
* **`IC::TraceIC`:** This confirms that the IC's behavior is being tracked for performance analysis and debugging. The various parameters (`type`, `name`, `old_state`, `new_state`) indicate what information is being logged.
* **`IC::Load` and its specializations:** These functions handle the core logic of retrieving a property value. The different versions (general `Load`, `LoadIC`, `LoadGlobalIC`) suggest different scenarios for property access.
* **`UpdateState`, `UpdateCaches`, `SetCache`, `ConfigureVectorState`:** These are the mechanisms by which the IC learns and stores information about successful property accesses. They update the internal state of the IC to optimize future lookups.
* **`LookupIterator`:** This class is fundamental to how V8 finds properties. It traverses the prototype chain, which is essential for understanding JavaScript's inheritance model.
* **`StubCache`:** This indicates that the IC uses cached compiled code (stubs) for fast property access after it has learned about access patterns.

**4. Connecting to JavaScript Concepts:**

At this point, I'd start thinking about how the code relates to JavaScript's behavior:

* **Property Access:** The `Load` functions directly correspond to how you access properties in JavaScript (e.g., `object.property`, `object['property']`).
* **Prototype Chain:** The `LookupIterator` directly relates to how JavaScript resolves property accesses by searching up the prototype chain.
* **`this` binding:** The `receiver` parameter in `LoadIC::Load` is likely related to the `this` value during a method call or property access.
* **Global Objects:** `LoadGlobalIC::Load` specifically handles looking up variables in the global scope.
* **`in` operator:** The mention of `IsAnyHas()` and the `kInvalidInOperatorUse` error clearly connects to the `in` operator in JavaScript.
* **Error Handling:**  The `TypeError` and `ReferenceError` functions show how JavaScript's runtime errors are handled during property access.
* **Performance Optimization:** The entire IC mechanism is about making JavaScript code run faster.

**5. Formulating Examples and Hypotheses:**

Now I would start generating examples to illustrate the concepts:

* **Monomorphic:**  Accessing the same property on objects of the same type repeatedly.
* **Polymorphic:** Accessing the same property on objects of different types.
* **Megamorphic:** Accessing the same property on a large variety of object types.
* **Prototype Chain Lookup:** Demonstrating how the `LookupIterator` would traverse the chain.
* **Error Scenarios:** Showing how accessing properties on `null` or `undefined` leads to errors.

**6. Considering "Torque" and File Extensions:**

The prompt mentions `.tq` files. Knowing that Torque is V8's internal language for generating built-in functions, I'd note that `.cc` indicates C++ and is the *implementation*. The prompt's statement about `.tq` is a good reminder to keep an eye out for related technologies within V8.

**7. Structuring the Output:**

Finally, I would organize the information into logical sections as requested by the prompt:

* **Core Functionality:**  A concise summary of the IC's role.
* **Torque:**  Address the prompt's specific question about `.tq`.
* **JavaScript Relationship:**  Provide concrete JavaScript examples.
* **Logic Inference:** Create input/output scenarios.
* **Common Errors:**  Illustrate typical JavaScript mistakes related to property access.
* **Summary:**  A brief recap of the file's purpose.

This iterative process of scanning, inferring, analyzing, connecting, and exemplifying allows for a comprehensive understanding of the V8 source code snippet. Even without deep knowledge of the entire V8 codebase, focusing on keywords, structures, and their relationship to JavaScript concepts provides a solid foundation for analysis.
好的，让我们来分析一下 `v8/src/ic/ic.cc` 这个文件的功能。

**核心功能归纳:**

`v8/src/ic/ic.cc` 文件是 V8 JavaScript 引擎中 **Inline Cache (IC)** 机制的核心实现。它的主要功能是：

1. **优化属性访问:**  通过在运行时观察属性访问模式，动态地为属性查找和调用生成优化的代码（称为“handlers”），从而提高 JavaScript 代码的执行速度。
2. **管理 IC 的状态:**  维护和更新 IC 的状态，例如 `UNINITIALIZED`（未初始化）、`MONOMORPHIC`（单态）、`POLYMORPHIC`（多态）、`MEGAMORPHIC`（巨态）等，这些状态反映了 IC 观察到的属性访问模式的复杂程度。
3. **处理不同类型的属性访问:**  支持不同类型的属性访问操作，例如加载属性（LoadIC）、存储属性（StoreIC）、检查属性是否存在（HasIC）等。
4. **与反馈向量 (Feedback Vector) 交互:**  IC 利用反馈向量来存储和检索关于属性访问的信息，例如访问过的对象的类型（Map）和对应的处理器 (handler)。
5. **与 Stub Cache 交互:**  对于某些状态（例如巨态），IC 将优化的处理器存储在 Stub Cache 中，以便在后续访问中快速查找和执行。
6. **处理原型链查找:**  IC 需要处理 JavaScript 中复杂的原型链查找机制，并根据原型链上的对象类型生成相应的优化代码。
7. **处理访问检查 (Access Checks):**  对于需要进行访问权限检查的属性访问，IC 能够进行相应的处理。
8. **处理已弃用的对象 (Deprecated Objects):**  当遇到使用已弃用 Map 的对象时，IC 能够触发对象的迁移。
9. **生成错误信息:**  在属性访问失败时，例如访问 `null` 或 `undefined` 的属性，IC 负责生成 `TypeError`。
10. **与代码生成和分层编译集成:**  IC 的优化结果会影响 V8 的代码生成和分层编译过程，帮助引擎生成更高效的机器码。
11. **MegaDOM IC 支持:** 包含对 MegaDOM IC 的支持，这是一种针对特定 DOM 访问模式的优化。

**关于文件扩展名和 Torque:**

* `v8/src/ic/ic.cc` 的 `.cc` 扩展名表明这是一个 **C++ 源代码文件**。
* 如果 `v8/src/ic/ic.cc` 以 `.tq` 结尾，那么它的确会是 V8 Torque 源代码。Torque 是 V8 内部使用的一种领域特定语言，用于生成高效的内置函数和运行时代码。**目前这个文件是 `.cc`，所以它是 C++ 代码。**  不过，在 V8 的 `src/ic/` 目录下可能存在以 `.tq` 结尾的文件，用于定义与 IC 相关的内置函数。

**与 JavaScript 功能的关系及示例:**

IC 机制直接影响着 JavaScript 中属性访问的性能。以下是一些 JavaScript 示例以及 IC 如何对其进行优化：

**示例 1: 单态 (Monomorphic) 优化**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

const p1 = new Point(1, 2);
const p2 = new Point(3, 4);

// 多次访问相同类型对象的相同属性
console.log(p1.x); // 第一次访问，IC 可能处于 UNINITIALIZED 状态
console.log(p2.x); // 第二次访问，IC 观察到是 Point 类型的对象访问 .x 属性，可能转变为 MONOMORPHIC 状态
console.log(p1.x); // 后续访问，IC 可以直接使用为 Point 类型和 .x 属性生成的优化代码
```

在这个例子中，当第一次访问 `p1.x` 时，IC 可能还不知道对象的类型。但当第二次访问 `p2.x` 时，IC 可能会观察到这是对 `Point` 类型对象的 `x` 属性的访问，并生成针对 `Point` 类型和 `x` 属性的优化处理器。后续对 `p1.x` 的访问就可以直接使用这个优化后的处理器，从而更快地获取属性值。

**示例 2: 多态 (Polymorphic) 优化**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

function ColorPoint(x, y, color) {
  this.x = x;
  this.y = y;
  this.color = color;
}

const p1 = new Point(1, 2);
const cp1 = new ColorPoint(3, 4, 'red');

console.log(p1.x); // 访问 Point 对象的 x 属性
console.log(cp1.x); // 访问 ColorPoint 对象的 x 属性，IC 观察到多种类型访问 .x 属性，可能转变为 POLYMORPHIC 状态
console.log(p1.x); // 后续访问，IC 需要处理多种类型的对象
```

这里，`p1` 和 `cp1` 是不同类型的对象，但都访问了 `x` 属性。IC 会观察到这种多态性，并生成能够处理多种对象类型的优化处理器。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个 LoadIC 实例，正在处理以下 JavaScript 代码：

```javascript
const obj = { a: 1 };
console.log(obj.a);
```

**假设输入:**

* `lookup_start_object`: 指向 `{ a: 1 }` 对象的指针。
* `name`: 指向字符串 `"a"` 的指针。
* IC 的当前状态为 `UNINITIALIZED`。

**代码逻辑推理 (简化):**

1. **`IC::Load` 被调用:** LoadIC 的 `Load` 方法会被调用。
2. **查找属性:**  IC 内部会使用 `LookupIterator` 来查找对象 `obj` 的属性 `"a"`。
3. **计算 Handler:**  由于是第一次遇到这种类型的访问，IC 会计算出一个适合的处理器 (handler)，这个 handler 知道如何高效地访问具有 `"a"` 属性的对象。
4. **更新缓存 (`SetCache`)**:
   * IC 的状态会从 `UNINITIALIZED` 更新为 `MONOMORPHIC`。
   * 反馈向量 (Feedback Vector) 中会记录下 `obj` 的 Map 和计算出的 handler，以及属性名 `"a"`。
5. **执行 Handler:**  计算出的 handler 会被执行，返回属性值 `1`。

**假设输出:**

* 控制台输出 `1`。
* IC 的状态变为 `MONOMORPHIC`，并且反馈向量中存储了关于 `obj` 的 Map 和对应的 handler。

**用户常见的编程错误:**

1. **在 `null` 或 `undefined` 上访问属性:**

   ```javascript
   let obj = null;
   console.log(obj.a); // TypeError: Cannot read properties of null (reading 'a')
   ```
   IC 会在尝试访问 `null` 的属性时触发 `TypeError`。

2. **拼写错误导致属性查找失败:**

   ```javascript
   const obj = { name: 'Alice' };
   console.log(obj.nmae); // 输出 undefined，因为属性名拼写错误
   ```
   IC 会查找名为 `"nmae"` 的属性，但由于对象上不存在，会返回 `undefined`。这会导致后续代码可能出现意外行为。

3. **假设对象总是具有某个属性，但实际情况并非如此:**

   ```javascript
   function processObject(obj) {
     console.log(obj.data.value); // 如果 obj 没有 data 属性，或者 data 不是对象，会报错
   }

   processObject({ data: { value: 10 } }); // 正常工作
   processObject({}); // TypeError: Cannot read properties of undefined (reading 'value')
   ```
   IC 可能会为 `processObject` 中的属性访问生成优化代码，但如果传入的对象结构不一致，会导致运行时错误。

**第 1 部分功能归纳:**

这个代码片段（`v8/src/ic/ic.cc` 的开头部分）主要定义了 `IC` 类的基础结构、枚举类型、辅助函数以及一些核心功能的入口点，例如：

* **IC 状态的定义和转换:**  定义了 `InlineCacheState` 枚举及其转换函数。
* **跟踪 IC 事件:** 提供了 `TraceIC` 函数用于记录 IC 的行为，方便性能分析和调试。
* **IC 类的构造函数:**  初始化 `IC` 对象，并根据反馈向量设置初始状态。
* **查找属性的辅助函数:** 提供了 `LookupForRead` 函数用于在对象上查找属性。
* **判断是否需要重新计算 Handler:** `ShouldRecomputeHandler` 函数用于确定是否需要为当前的属性访问重新生成优化代码。
* **错误处理:**  提供了 `TypeError` 和 `ReferenceError` 函数用于生成相应的 JavaScript 错误。
* **反馈更新通知:**  `OnFeedbackChanged` 函数用于通知其他 V8 组件（如分层编译管理器）IC 的状态发生了变化。
* **处理已弃用对象:** 包含了 `MigrateDeprecated` 函数用于处理使用已弃用 Map 的对象。
* **配置反馈向量状态:**  `ConfigureVectorState` 函数用于更新反馈向量中的信息，例如记录单态或多态的属性访问模式。
* **LoadIC 的入口:**  `LoadIC::Load` 函数是加载属性操作的入口点，负责处理各种情况下的属性访问。
* **LoadGlobalIC 的入口:** `LoadGlobalIC::Load` 函数是加载全局变量的入口点。

总而言之，这部分代码是 V8 引擎中内联缓存机制的基石，为后续的属性访问优化奠定了基础。它定义了 IC 的基本概念、状态管理和与 JavaScript 语义相关的核心操作。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/ic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/ic.h"

#include <optional>
#include <tuple>

#include "src/api/api-arguments-inl.h"
#include "src/ast/ast.h"
#include "src/base/logging.h"
#include "src/builtins/accessors.h"
#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/arguments-inl.h"
#include "src/execution/execution.h"
#include "src/execution/frames-inl.h"
#include "src/execution/isolate-inl.h"
#include "src/execution/isolate.h"
#include "src/execution/protectors-inl.h"
#include "src/execution/tiering-manager.h"
#include "src/handles/handles-inl.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/heap-layout-inl.h"
#include "src/ic/call-optimization.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/ic/handler-configuration.h"
#include "src/ic/ic-inl.h"
#include "src/ic/ic-stats.h"
#include "src/ic/stub-cache.h"
#include "src/numbers/conversions.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/field-type.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-array-inl.h"
#include "src/objects/megadom-handler.h"
#include "src/objects/property-descriptor.h"
#include "src/objects/prototype.h"
#include "src/runtime/runtime.h"
#include "src/tracing/trace-event.h"
#include "src/tracing/tracing-category-observer.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/struct-types.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

// Aliases to avoid having to repeat the class.
// With C++20 we can use "using" to introduce scoped enums.
constexpr InlineCacheState NO_FEEDBACK = InlineCacheState::NO_FEEDBACK;
constexpr InlineCacheState UNINITIALIZED = InlineCacheState::UNINITIALIZED;
constexpr InlineCacheState MONOMORPHIC = InlineCacheState::MONOMORPHIC;
constexpr InlineCacheState RECOMPUTE_HANDLER =
    InlineCacheState::RECOMPUTE_HANDLER;
constexpr InlineCacheState POLYMORPHIC = InlineCacheState::POLYMORPHIC;
constexpr InlineCacheState MEGAMORPHIC = InlineCacheState::MEGAMORPHIC;
constexpr InlineCacheState MEGADOM = InlineCacheState::MEGADOM;
constexpr InlineCacheState GENERIC = InlineCacheState::GENERIC;

char IC::TransitionMarkFromState(IC::State state) {
  switch (state) {
    case NO_FEEDBACK:
      return 'X';
    case UNINITIALIZED:
      return '0';
    case MONOMORPHIC:
      return '1';
    case RECOMPUTE_HANDLER:
      return '^';
    case POLYMORPHIC:
      return 'P';
    case MEGAMORPHIC:
      return 'N';
    case MEGADOM:
      return 'D';
    case GENERIC:
      return 'G';
  }
  UNREACHABLE();
}

namespace {

const char* GetModifier(KeyedAccessLoadMode mode) {
  switch (mode) {
    case KeyedAccessLoadMode::kHandleOOB:
      return ".OOB";
    case KeyedAccessLoadMode::kHandleHoles:
      return ".HOLES";
    case KeyedAccessLoadMode::kHandleOOBAndHoles:
      return ".OOB+HOLES";
    case KeyedAccessLoadMode::kInBounds:
      return "";
  }
}

const char* GetModifier(KeyedAccessStoreMode mode) {
  switch (mode) {
    case KeyedAccessStoreMode::kHandleCOW:
      return ".COW";
    case KeyedAccessStoreMode::kGrowAndHandleCOW:
      return ".STORE+COW";
    case KeyedAccessStoreMode::kIgnoreTypedArrayOOB:
      return ".IGNORE_OOB";
    case KeyedAccessStoreMode::kInBounds:
      return "";
  }
  UNREACHABLE();
}

}  // namespace

void IC::TraceIC(const char* type, DirectHandle<Object> name) {
  if (V8_LIKELY(!TracingFlags::is_ic_stats_enabled())) return;
  State new_state =
      (state() == NO_FEEDBACK) ? NO_FEEDBACK : nexus()->ic_state();
  TraceIC(type, name, state(), new_state);
}

void IC::TraceIC(const char* type, DirectHandle<Object> name, State old_state,
                 State new_state) {
  if (V8_LIKELY(!TracingFlags::is_ic_stats_enabled())) return;

  Handle<Map> map = lookup_start_object_map();  // Might be empty.

  const char* modifier = "";
  if (state() == NO_FEEDBACK) {
    modifier = "";
  } else if (IsKeyedLoadIC()) {
    KeyedAccessLoadMode mode = nexus()->GetKeyedAccessLoadMode();
    modifier = GetModifier(mode);
  } else if (IsKeyedStoreIC() || IsStoreInArrayLiteralIC() ||
             IsDefineKeyedOwnIC()) {
    KeyedAccessStoreMode mode = nexus()->GetKeyedAccessStoreMode();
    modifier = GetModifier(mode);
  }

  bool keyed_prefix = is_keyed() && !IsStoreInArrayLiteralIC();

  if (!(TracingFlags::ic_stats.load(std::memory_order_relaxed) &
        v8::tracing::TracingCategoryObserver::ENABLED_BY_TRACING)) {
    LOG(isolate(), ICEvent(type, keyed_prefix, map, name,
                           TransitionMarkFromState(old_state),
                           TransitionMarkFromState(new_state), modifier,
                           slow_stub_reason_));
    return;
  }

  JavaScriptStackFrameIterator it(isolate());
  JavaScriptFrame* frame = it.frame();

  DisallowGarbageCollection no_gc;
  Tagged<JSFunction> function = frame->function();

  ICStats::instance()->Begin();
  ICInfo& ic_info = ICStats::instance()->Current();
  ic_info.type = keyed_prefix ? "Keyed" : "";
  ic_info.type += type;

  int code_offset = 0;
  Tagged<AbstractCode> code;
  std::tie(code, code_offset) = frame->GetActiveCodeAndOffset();
  JavaScriptFrame::CollectFunctionAndOffsetForICStats(isolate(), function, code,
                                                      code_offset);

  // Reserve enough space for IC transition state, the longest length is 17.
  ic_info.state.reserve(17);
  ic_info.state = "(";
  ic_info.state += TransitionMarkFromState(old_state);
  ic_info.state += "->";
  ic_info.state += TransitionMarkFromState(new_state);
  ic_info.state += modifier;
  ic_info.state += ")";
  if (!map.is_null()) {
    ic_info.map = reinterpret_cast<void*>(map->ptr());
    ic_info.is_dictionary_map = map->is_dictionary_map();
    ic_info.number_of_own_descriptors = map->NumberOfOwnDescriptors();
    ic_info.instance_type = std::to_string(map->instance_type());
  } else {
    ic_info.map = nullptr;
  }
  // TODO(lpy) Add name as key field in ICStats.
  ICStats::instance()->End();
}

IC::IC(Isolate* isolate, Handle<FeedbackVector> vector, FeedbackSlot slot,
       FeedbackSlotKind kind)
    : isolate_(isolate),
      vector_set_(false),
      kind_(kind),
      target_maps_set_(false),
      slow_stub_reason_(nullptr),
      nexus_(isolate, vector, slot) {
  DCHECK_IMPLIES(!vector.is_null(), kind_ == nexus_.kind());
  state_ = (vector.is_null()) ? NO_FEEDBACK : nexus_.ic_state();
  old_state_ = state_;
}

static void LookupForRead(LookupIterator* it, bool is_has_property) {
  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::JSPROXY:
      case LookupIterator::WASM_OBJECT:
        return;
      case LookupIterator::INTERCEPTOR: {
        // If there is a getter, return; otherwise loop to perform the lookup.
        DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
        if (!IsUndefined(holder->GetNamedInterceptor()->getter(),
                         it->isolate())) {
          return;
        }
        if (is_has_property &&
            !IsUndefined(holder->GetNamedInterceptor()->query(),
                         it->isolate())) {
          return;
        }
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        // ICs know how to perform access checks on global proxies.
        if (it->GetHolder<JSObject>().is_identical_to(
                it->isolate()->global_proxy()) &&
            !it->isolate()->global_object()->IsDetached()) {
          continue;
        }
        return;
      case LookupIterator::ACCESSOR:
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      case LookupIterator::DATA:
      case LookupIterator::NOT_FOUND:
        return;
    }
    UNREACHABLE();
  }
}

bool IC::ShouldRecomputeHandler(DirectHandle<String> name) {
  if (!RecomputeHandlerForName(name)) return false;

  // This is a contextual access, always just update the handler and stay
  // monomorphic.
  if (IsGlobalIC()) return true;

  MaybeObjectHandle maybe_handler =
      nexus()->FindHandlerForMap(lookup_start_object_map());

  // The current map wasn't handled yet. There's no reason to stay monomorphic,
  // *unless* we're moving from a deprecated map to its replacement, or
  // to a more general elements kind.
  // TODO(verwaest): Check if the current map is actually what the old map
  // would transition to.
  if (maybe_handler.is_null()) {
    if (!IsJSObjectMap(*lookup_start_object_map())) return false;
    Tagged<Map> first_map = FirstTargetMap();
    if (first_map.is_null()) return false;
    DirectHandle<Map> old_map(first_map, isolate());
    if (old_map->is_deprecated()) return true;
    return IsMoreGeneralElementsKindTransition(
        old_map->elements_kind(), lookup_start_object_map()->elements_kind());
  }

  return true;
}

bool IC::RecomputeHandlerForName(DirectHandle<Object> name) {
  if (is_keyed()) {
    // Determine whether the failure is due to a name failure.
    if (!IsName(*name)) return false;
    Tagged<Name> stub_name = nexus()->GetName();
    if (*name != stub_name) return false;
  }

  return true;
}

void IC::UpdateState(DirectHandle<Object> lookup_start_object,
                     Handle<Object> name) {
  if (state() == NO_FEEDBACK) return;
  update_lookup_start_object_map(lookup_start_object);
  if (!IsString(*name)) return;
  if (state() != MONOMORPHIC && state() != POLYMORPHIC) return;
  if (IsNullOrUndefined(*lookup_start_object, isolate())) return;

  // Remove the target from the code cache if it became invalid
  // because of changes in the prototype chain to avoid hitting it
  // again.
  if (ShouldRecomputeHandler(Cast<String>(name))) {
    MarkRecomputeHandler(name);
  }
}

MaybeHandle<Object> IC::TypeError(MessageTemplate index, Handle<Object> object,
                                  Handle<Object> key) {
  HandleScope scope(isolate());
  THROW_NEW_ERROR(isolate(), NewTypeError(index, key, object));
}

MaybeHandle<Object> IC::ReferenceError(Handle<Name> name) {
  HandleScope scope(isolate());
  THROW_NEW_ERROR(isolate(),
                  NewReferenceError(MessageTemplate::kNotDefined, name));
}

void IC::OnFeedbackChanged(const char* reason) {
  vector_set_ = true;
  Tagged<FeedbackVector> vector = nexus()->vector();
  FeedbackSlot slot = nexus()->slot();
  OnFeedbackChanged(isolate(), vector, slot, reason);
}

// static
void IC::OnFeedbackChanged(Isolate* isolate, Tagged<FeedbackVector> vector,
                           FeedbackSlot slot, const char* reason) {
#ifdef V8_TRACE_FEEDBACK_UPDATES
  if (v8_flags.trace_feedback_updates) {
    FeedbackVector::TraceFeedbackChange(isolate, vector, slot, reason);
  }
#endif

  isolate->tiering_manager()->NotifyICChanged(vector);
}

namespace {

bool MigrateDeprecated(Isolate* isolate, Handle<Object> object) {
  if (!IsJSObject(*object)) return false;
  DirectHandle<JSObject> receiver = Cast<JSObject>(object);
  if (!receiver->map()->is_deprecated()) return false;
  JSObject::MigrateInstance(isolate, receiver);
  return true;
}

}  // namespace

bool IC::ConfigureVectorState(IC::State new_state, DirectHandle<Object> key) {
  DCHECK_EQ(MEGAMORPHIC, new_state);
  DCHECK_IMPLIES(!is_keyed(), IsName(*key));
  bool changed = nexus()->ConfigureMegamorphic(
      IsName(*key) ? IcCheckType::kProperty : IcCheckType::kElement);
  if (changed) {
    OnFeedbackChanged("Megamorphic");
  }
  return changed;
}

void IC::ConfigureVectorState(Handle<Name> name, DirectHandle<Map> map,
                              Handle<Object> handler) {
  ConfigureVectorState(name, map, MaybeObjectHandle(handler));
}

void IC::ConfigureVectorState(Handle<Name> name, DirectHandle<Map> map,
                              const MaybeObjectHandle& handler) {
  if (IsGlobalIC()) {
    nexus()->ConfigureHandlerMode(handler);
  } else {
    // Non-keyed ICs don't track the name explicitly.
    if (!is_keyed()) name = Handle<Name>::null();
    nexus()->ConfigureMonomorphic(name, map, handler);
  }

  OnFeedbackChanged(IsLoadGlobalIC() ? "LoadGlobal" : "Monomorphic");
}

void IC::ConfigureVectorState(Handle<Name> name, MapHandlesSpan maps,
                              MaybeObjectHandles* handlers) {
  DCHECK(!IsGlobalIC());
  std::vector<MapAndHandler> maps_and_handlers;
  maps_and_handlers.reserve(maps.size());
  DCHECK_EQ(maps.size(), handlers->size());
  for (size_t i = 0; i < maps.size(); i++) {
    maps_and_handlers.push_back(MapAndHandler(maps[i], handlers->at(i)));
  }
  ConfigureVectorState(name, maps_and_handlers);
}

void IC::ConfigureVectorState(
    Handle<Name> name, std::vector<MapAndHandler> const& maps_and_handlers) {
  DCHECK(!IsGlobalIC());
  // Non-keyed ICs don't track the name explicitly.
  if (!is_keyed()) name = Handle<Name>::null();
  nexus()->ConfigurePolymorphic(name, maps_and_handlers);

  OnFeedbackChanged("Polymorphic");
}

MaybeHandle<Object> LoadIC::Load(Handle<JSAny> object, Handle<Name> name,
                                 bool update_feedback, Handle<JSAny> receiver) {
  bool use_ic = (state() != NO_FEEDBACK) && v8_flags.use_ic && update_feedback;

  if (receiver.is_null()) {
    receiver = object;
  }

  // If the object is undefined or null it's illegal to try to get any
  // of its properties; throw a TypeError in that case.
  if (IsAnyHas() ? !IsJSReceiver(*object)
                 : IsNullOrUndefined(*object, isolate())) {
    if (use_ic) {
      // Ensure the IC state progresses.
      TRACE_HANDLER_STATS(isolate(), LoadIC_NonReceiver);
      update_lookup_start_object_map(object);
      SetCache(name, LoadHandler::LoadSlow(isolate()));
      TraceIC("LoadIC", name);
    }

    if (*name == ReadOnlyRoots(isolate()).iterator_symbol()) {
      isolate()->Throw(*ErrorUtils::NewIteratorError(isolate(), object));
      return MaybeHandle<Object>();
    }

    if (IsAnyHas()) {
      return TypeError(MessageTemplate::kInvalidInOperatorUse, object, name);
    } else {
      DCHECK(IsNullOrUndefined(*object, isolate()));
      ErrorUtils::ThrowLoadFromNullOrUndefined(isolate(), object, name);
      return MaybeHandle<Object>();
    }
  }

  // If we encounter an object with a deprecated map, we want to update the
  // feedback vector with the migrated map.
  // Mark ourselves as RECOMPUTE_HANDLER so that we don't turn megamorphic due
  // to seeing the same map and handler.
  if (MigrateDeprecated(isolate(), object)) {
    UpdateState(object, name);
  }

  JSObject::MakePrototypesFast(object, kStartAtReceiver, isolate());
  update_lookup_start_object_map(object);

  PropertyKey key(isolate(), name);
  LookupIterator it = LookupIterator(isolate(), receiver, key, object);

  // Named lookup in the object.
  LookupForRead(&it, IsAnyHas());

  if (it.IsFound() || !ShouldThrowReferenceError()) {
    // Update inline cache and stub cache.
    if (use_ic) {
      UpdateCaches(&it);
    } else if (state() == NO_FEEDBACK) {
      // Tracing IC stats
      IsLoadGlobalIC() ? TraceIC("LoadGlobalIC", name)
                       : TraceIC("LoadIC", name);
    }

    if (IsAnyHas()) {
      // Named lookup in the object.
      Maybe<bool> maybe = JSReceiver::HasProperty(&it);
      if (maybe.IsNothing()) return MaybeHandle<Object>();
      return isolate()->factory()->ToBoolean(maybe.FromJust());
    }

    // Get the property.
    Handle<Object> result;

    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               Object::GetProperty(&it, IsLoadGlobalIC()));
    if (it.IsFound()) {
      return result;
    } else if (!ShouldThrowReferenceError()) {
      return result;
    }
  }
  return ReferenceError(name);
}

MaybeHandle<Object> LoadGlobalIC::Load(Handle<Name> name,
                                       bool update_feedback) {
  Handle<JSGlobalObject> global = isolate()->global_object();

  if (IsString(*name)) {
    // Look up in script context table.
    Handle<String> str_name = Cast<String>(name);
    DirectHandle<ScriptContextTable> script_contexts(
        global->native_context()->script_context_table(), isolate());

    VariableLookupResult lookup_result;
    if (script_contexts->Lookup(str_name, &lookup_result)) {
      DirectHandle<Context> script_context(
          script_contexts->get(lookup_result.context_index), isolate());
      Handle<Object> result(script_context->get(lookup_result.slot_index),
                            isolate());

      if (IsTheHole(*result, isolate())) {
        // Do not install stubs and stay pre-monomorphic for
        // uninitialized accesses.
        THROW_NEW_ERROR(
            isolate(),
            NewReferenceError(MessageTemplate::kAccessedUninitializedVariable,
                              name));
      }

      bool use_ic =
          (state() != NO_FEEDBACK) && v8_flags.use_ic && update_feedback;
      if (use_ic) {
        // 'const' Variables are mutable if REPL mode is enabled. This disables
        // compiler inlining for all 'const' variables declared in REPL mode.
        if (nexus()->ConfigureLexicalVarMode(
                lookup_result.context_index, lookup_result.slot_index,
                (IsImmutableLexicalVariableMode(lookup_result.mode) &&
                 !lookup_result.is_repl_mode))) {
          TRACE_HANDLER_STATS(isolate(), LoadGlobalIC_LoadScriptContextField);
        } else {
          // Given combination of indices can't be encoded, so use slow stub.
          TRACE_HANDLER_STATS(isolate(), LoadGlobalIC_SlowStub);
          SetCache(name, LoadHandler::LoadSlow(isolate()));
        }
        TraceIC("LoadGlobalIC", name);
      } else if (state() == NO_FEEDBACK) {
        TraceIC("LoadGlobalIC", name);
      }
      if (v8_flags.script_context_mutable_heap_number) {
        return handle(
            *Context::LoadScriptContextElement(
                script_context, lookup_result.slot_index, result, isolate()),
            isolate());
      }
      return result;
    }
  }
  return LoadIC::Load(global, name, update_feedback);
}

namespace {

bool AddOneReceiverMapIfMissing(MapHandles* receiver_maps,
                                Handle<Map> new_receiver_map) {
  DCHECK(!new_receiver_map.is_null());
  for (Handle<Map> map : *receiver_maps) {
    if (!map.is_null() && map.is_identical_to(new_receiver_map)) {
      return false;
    }
  }
  receiver_maps->push_back(new_receiver_map);
  return true;
}

bool AddOneReceiverMapIfMissing(
    std::vector<MapAndHandler>* receiver_maps_and_handlers,
    Handle<Map> new_receiver_map) {
  DCHECK(!new_receiver_map.is_null());
  if (new_receiver_map->is_deprecated()) return false;
  for (MapAndHandler map_and_handler : *receiver_maps_and_handlers) {
    Handle<Map> map = map_and_handler.first;
    if (!map.is_null() && map.is_identical_to(new_receiver_map)) {
      return false;
    }
  }
  receiver_maps_and_handlers->push_back(
      MapAndHandler(new_receiver_map, MaybeObjectHandle()));
  return true;
}

Handle<NativeContext> GetAccessorContext(
    const CallOptimization& call_optimization, Tagged<Map> holder_map,
    Isolate* isolate) {
  std::optional<Tagged<NativeContext>> maybe_context =
      call_optimization.GetAccessorContext(holder_map);

  // Holders which are remote objects are not expected in the IC system.
  CHECK(maybe_context.has_value());
  return handle(maybe_context.value(), isolate);
}

}  // namespace

bool IC::UpdateMegaDOMIC(const MaybeObjectHandle& handler,
                         DirectHandle<Name> name) {
  if (!v8_flags.mega_dom_ic) return false;

  // TODO(gsathya): Enable fuzzing once this feature is more stable.
  if (v8_flags.fuzzing) return false;

  // TODO(gsathya): Support KeyedLoadIC, StoreIC and KeyedStoreIC.
  if (!IsLoadIC()) return false;

  // Check if DOM protector cell is valid.
  if (!Protectors::IsMegaDOMIntact(isolate())) return false;

  // Check if current lookup object is an API object
  Handle<Map> map = lookup_start_object_map();
  if (!InstanceTypeChecker::IsJSApiObject(map->instance_type())) return false;

  Handle<Object> accessor_obj;
  // TODO(gsathya): Check if there are overloads possible for this accessor and
  // transition only if it isn't possible.
  if (!accessor().ToHandle(&accessor_obj)) return false;

  // TODO(gsathya): This is also created in IC::ComputeHandler, find a way to
  // reuse it here.
  CallOptimization call_optimization(isolate(), accessor_obj);

  // Check if accessor is an API function
  if (!call_optimization.is_simple_api_call()) return false;

  // Check if accessor requires access checks
  if (call_optimization.accept_any_receiver()) return false;

  // Check if accessor requires signature checks
  if (!call_optimization.requires_signature_check()) return false;

  // Check if the receiver is the holder
  CallOptimization::HolderLookup holder_lookup;
  call_optimization.LookupHolderOfExpectedType(isolate(), map, &holder_lookup);
  if (holder_lookup != CallOptimization::kHolderIsReceiver) return false;

  Handle<NativeContext> accessor_context =
      GetAccessorContext(call_optimization, *map, isolate());

  Handle<FunctionTemplateInfo> fti;
  if (IsJSFunction(*accessor_obj)) {
    fti = handle(Cast<JSFunction>(*accessor_obj)->shared()->api_func_data(),
                 isolate());
  } else {
    fti = Cast<FunctionTemplateInfo>(accessor_obj);
  }

  Handle<MegaDomHandler> new_handler = isolate()->factory()->NewMegaDomHandler(
      MaybeObjectHandle::Weak(fti), MaybeObjectHandle::Weak(accessor_context));
  nexus()->ConfigureMegaDOM(MaybeObjectHandle(new_handler));
  return true;
}

bool IC::UpdatePolymorphicIC(Handle<Name> name,
                             const MaybeObjectHandle& handler) {
  DCHECK(IsHandler(*handler));
  if (is_keyed() && state() != RECOMPUTE_HANDLER) {
    if (nexus()->GetName() != *name) return false;
  }
  Handle<Map> map = lookup_start_object_map();

  std::vector<MapAndHandler> maps_and_handlers;
  maps_and_handlers.reserve(v8_flags.max_valid_polymorphic_map_count);
  int deprecated_maps = 0;
  int handler_to_overwrite = -1;

  {
    DisallowGarbageCollection no_gc;
    int i = 0;
    for (FeedbackIterator it(nexus()); !it.done(); it.Advance()) {
      if (it.handler().IsCleared()) continue;
      MaybeObjectHandle existing_handler = handle(it.handler(), isolate());
      Handle<Map> existing_map = handle(it.map(), isolate());

      maps_and_handlers.push_back(
          MapAndHandler(existing_map, existing_handler));

      if (existing_map->is_deprecated()) {
        // Filter out deprecated maps to ensure their instances get migrated.
        deprecated_maps++;
      } else if (map.is_identical_to(existing_map)) {
        // If both map and handler stayed the same (and the name is also the
        // same as checked above, for keyed accesses), we're not progressing
        // in the lattice and need to go MEGAMORPHIC instead. There's one
        // exception to this rule, which is when we're in RECOMPUTE_HANDLER
        // state, there we allow to migrate to a new handler.
        if (handler.is_identical_to(existing_handler) &&
            state() != RECOMPUTE_HANDLER) {
          return false;
        }

        // If the receiver type is already in the polymorphic IC, this indicates
        // there was a prototoype chain failure. In that case, just overwrite
        // the handler.
        handler_to_overwrite = i;
      } else if (handler_to_overwrite == -1 &&
                 IsTransitionOfMonomorphicTarget(*existing_map, *map)) {
        handler_to_overwrite = i;
      }

      i++;
    }
    DCHECK_LE(i, maps_and_handlers.size());
  }

  int number_of_maps = static_cast<int>(maps_and_handlers.size());
  int number_of_valid_maps =
      number_of_maps - deprecated_maps - (handler_to_overwrite != -1);

  if (number_of_valid_maps >= v8_flags.max_valid_polymorphic_map_count) {
    return false;
  }
  if (deprecated_maps >= v8_flags.max_valid_polymorphic_map_count) {
    return false;
  }
  if (number_of_maps == 0 && state() != MONOMORPHIC && state() != POLYMORPHIC) {
    return false;
  }

  number_of_valid_maps++;
  if (number_of_valid_maps == 1) {
    ConfigureVectorState(name, lookup_start_object_map(), handler);
  } else {
    if (is_keyed() && nexus()->GetName() != *name) return false;
    if (handler_to_overwrite >= 0) {
      maps_and_handlers[handler_to_overwrite].second = handler;
      if (!map.is_identical_to(
              maps_and_handlers.at(handler_to_overwrite).first)) {
        maps_and_handlers[handler_to_overwrite].first = map;
      }
    } else {
      maps_and_handlers.push_back(MapAndHandler(map, handler));
    }

    ConfigureVectorState(name, maps_and_handlers);
  }

  return true;
}

void IC::UpdateMonomorphicIC(const MaybeObjectHandle& handler,
                             Handle<Name> name) {
  DCHECK(IsHandler(*handler));
  ConfigureVectorState(name, lookup_start_object_map(), handler);
}

void IC::CopyICToMegamorphicCache(DirectHandle<Name> name) {
  std::vector<MapAndHandler> maps_and_handlers;
  nexus()->ExtractMapsAndHandlers(&maps_and_handlers);
  for (const MapAndHandler& map_and_handler : maps_and_handlers) {
    UpdateMegamorphicCache(map_and_handler.first, name, map_and_handler.second);
  }
}

bool IC::IsTransitionOfMonomorphicTarget(Tagged<Map> source_map,
                                         Tagged<Map> target_map) {
  if (source_map.is_null()) return true;
  if (target_map.is_null()) return false;
  if (source_map->is_abandoned_prototype_map()) return false;
  ElementsKind target_elements_kind = target_map->elements_kind();
  bool more_general_transition = IsMoreGeneralElementsKindTransition(
      source_map->elements_kind(), target_elements_kind);
  Tagged<Map> transitioned_map;
  if (more_general_transition) {
    Handle<Map> single_map[1] = {handle(target_map, isolate_)};
    transitioned_map = source_map->FindElementsKindTransitionedMap(
        isolate(), single_map, ConcurrencyMode::kSynchronous);
  }
  return transitioned_map == target_map;
}

void IC::SetCache(Handle<Name> name, Handle<Object> handler) {
  SetCache(name, MaybeObjectHandle(handler));
}

void IC::SetCache(Handle<Name> name, const MaybeObjectHandle& handler) {
  DCHECK(IsHandler(*handler));
  // Currently only load and store ICs support non-code handlers.
  DCHECK(IsAnyLoad() || IsAnyStore() || IsAnyHas());
  switch (state()) {
    case NO_FEEDBACK:
      UNREACHABLE();
    case UNINITIALIZED:
      UpdateMonomorphicIC(handler, name);
      break;
    case RECOMPUTE_HANDLER:
    case MONOMORPHIC:
      if (IsGlobalIC()) {
        UpdateMonomorphicIC(handler, name);
        break;
      }
      [[fallthrough]];
    case POLYMORPHIC:
      if (UpdatePolymorphicIC(name, handler)) break;
      if (UpdateMegaDOMIC(handler, name)) break;
      if (!is_keyed() || state() == RECOMPUTE_HANDLER) {
        CopyICToMegamorphicCache(name);
      }
      [[fallthrough]];
    case MEGADOM:
      ConfigureVectorState(MEGAMORPHIC, name);
      [[fallthrough]];
    case MEGAMORPHIC:
      UpdateMegamorphicCache(lookup_start_object_map(), name, handler);
      // Indicate that we've handled this case.
      vector_set_ = true;
      break;
    case GENERIC:
      UNREACHABLE();
  }
}

void LoadIC::UpdateCaches(LookupIterator* lookup) {
  MaybeObjectHandle handler;
  if (lookup->state() == LookupIterator::ACCESS_CHECK) {
    handler = MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
  } else if (!lookup->IsFound()) {
    if (lookup->IsPrivateName()) {
      handler = MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
    } else {
      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNonexistentDH);
      Handle<Smi> smi_handler = LoadHandler::LoadNonExistent(isolate());
      handler = MaybeObjectHandle(LoadHandler::LoadFullChain(
          isolate(), lookup_start_object_map(),
          MaybeObjectHandle(isolate()->factory()->null_value()), smi_handler));
    }
  } else if (IsLoadGlobalIC() && lookup->state() == LookupIterator::JSPROXY) {
    // If there is proxy just install the slow stub since we need to call the
    // HasProperty trap for global loads. The ProxyGetProperty builtin doesn't
    // handle this case.
    handler = MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
  } else {
    if (IsLoadGlobalIC()) {
      if (lookup->TryLookupCachedProperty()) {
        DCHECK_EQ(LookupIterator::DATA, lookup->state());
      }
      if (lookup->state() == LookupIterator::DATA &&
          lookup->GetReceiver().is_identical_to(lookup->GetHolder<Object>())) {
        DCHECK(IsJSGlobalObject(*lookup->GetReceiver()));
        // Now update the cell in the feedback vector.
        nexus()->ConfigurePropertyCellMode(lookup->GetPropertyCell());
        TraceIC("LoadGlobalIC", lookup->name());
        return;
      }
    }
    handler = ComputeHandler(lookup);
    auto holder = lookup->GetHolder<Object>();
    CHECK(*holder == *(lookup->lookup_start_object()) ||
          LoadHandler::CanHandleHolderNotLookupStart(*handler.object()) ||
          IsJSPrimitiveWrapper(*holder));
  }
  // Can't use {lookup->name()} because the LookupIterator might be in
  // "elements" mode for keys that are strings representing integers above
  // JSArray::kMaxIndex.
  SetCache(lookup->GetName(), handler);
  TraceIC("LoadIC", lookup->GetName());
}

StubCache* IC::stub_cache() {
  // HasICs and each of the store own ICs require its own stub cache.
  // Until we create them, don't allow accessing the load/store stub caches.
  DCHECK(!IsAnyHas());
  if (IsAnyLoad()) {
    return isolate()->load_stub_cache();
  } else if (IsAnyDefineOwn()) {
    return isolate()->define_own_stub_cache();
  } else {
    DCHECK(IsAnyStore());
    return isolate()->store_stub_cache();
  }
}

void IC::UpdateMegamorphicCache(DirectHandle<Map> map, DirectHandle<Name> name,
                                const MaybeObjectHandle& handler) {
  if (!IsAnyHas()) {
    stub_cache()->Set(*name, *map, *handler);
  }
}

MaybeObjectHandle LoadIC::ComputeHandler(LookupIterator* lookup) {
  DirectHandle<Object> receiver = lookup->GetReceiver();
  ReadOnlyRoots roots(isolate());

  Handle<Object> lookup_start_object = lookup->lookup_start_object();
  // `in` cannot be called on strings, and will always return true for string
  // wrapper length and function prototypes. The latter two cases are given
  // LoadHandler::LoadNativeDataProperty below.
  if (!IsAnyHas() && !lookup->IsElement()) {
    if (IsString(*lookup_start_object) &&
        *lookup->name() == roots.length_string()) {
      TRACE_HANDLER_STATS(isolate(), LoadIC_StringLength);
      return MaybeObjectHandle(BUILTIN_CODE(isolate(), LoadIC_StringLength));
    }

    if (IsStringWrapper(*lookup_start_object) &&
        *lookup->name() == roots.length_string()) {
      TRACE_HANDLER_STATS(isolate(), LoadIC_StringWrapperLength);
      return MaybeObjectHandle(
          BUILTIN_CODE(isolate(), LoadIC_StringWrapperLength));
    }

    // Use specialized code for getting prototype of functions.
    if (IsJSFunction(*lookup_start_object) &&
        *lookup->name() == roots.prototype_string() &&
        !Cast<JSFunction>(*lookup_start_object)
             ->PrototypeRequiresRuntimeLookup()) {
      TRACE_HANDLER_STATS(isolate(), LoadIC_FunctionPrototypeStub);
      return MaybeObjectHandle(
          BUILTIN_CODE(isolate(), LoadIC_FunctionPrototype));
    }
  }

  Handle<Map> map = lookup_start_object_map();
  bool holder_is_lookup_start_object =
      lookup_start_object.is_identical_to(lookup->GetHolder<JSReceiver>());

  switch (lookup->state()) {
    case LookupIterator::INTERCEPTOR: {
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      Handle<Smi> smi_handler = LoadHandler::LoadInterceptor(isolate());

      if (holder->GetNamedInterceptor()->non_masking()) {
        MaybeObjectHandle holder_ref(isolate()->factory()->null_value());
        if (!holder_is_lookup_start_object || IsLoadGlobalIC()) {
          holder_ref = MaybeObjectHandle::Weak(holder);
        }
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNonMaskingInterceptorDH);
        return MaybeObjectHandle(LoadHandler::LoadFullChain(
            isolate(), map, holder_ref, smi_handler));
      }

      if (holder_is_lookup_start_object) {
        DCHECK(map->has_named_interceptor());
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadInterceptorDH);
        return MaybeObjectHandle(smi_handler);
      }

      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadInterceptorFromPrototypeDH);
      return MaybeObjectHandle(
          LoadHandler::LoadFromPrototype(isolate(), map, holder, *smi_handler));
    }
"""


```
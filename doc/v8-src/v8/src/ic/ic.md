Response: The user wants a summary of the functionality of the C++ source code file `v8/src/ic/ic.cc`. The request specifies that this is the first of three parts and asks to identify the file's purpose and illustrate its connection to JavaScript using examples.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Concept:** The filename `ic.cc` strongly suggests this file is related to "Inline Caching" (IC). The comments within the code reinforce this by frequently mentioning "IC", "handler", and various IC states (MONOMORPHIC, POLYMORPHIC, etc.).

2. **Determine the Primary Goal of IC:** Inline caching is an optimization technique. The goal is to speed up property access (loads and stores) in JavaScript. This is achieved by remembering the type and location of properties accessed previously.

3. **Analyze the Included Headers:** The `#include` directives provide clues about the file's dependencies and related functionalities:
    * `src/ic/ic.h`, `src/ic/ic-inl.h`, `src/ic/stub-cache.h`, `src/ic/handler-configuration.h`, `src/ic/handler-configuration-inl.h`, `src/ic/ic-stats.h`: These confirm the focus on inline caching and its internal structures (handlers, stub cache, statistics).
    * `src/objects/`: Indicates interaction with V8's object model (JSObject, Map, etc.).
    * `src/execution/`: Suggests involvement in the execution process.
    * `src/codegen/`:  Likely relates to generating optimized code.
    * `src/handles/`:  Deals with managing object references.
    * `src/runtime/runtime.h`: Points to interactions with runtime functions.

4. **Examine the Defined Enums and Constants:** The code defines an `InlineCacheState` enum, which lists the different states an IC can be in (NO_FEEDBACK, UNINITIALIZED, MONOMORPHIC, etc.). This highlights the state-machine nature of the IC system, transitioning between optimization levels as it gathers more information.

5. **Identify Key Functions and Methods:**  Skimming through the code reveals important functions like `TraceIC`, `UpdateState`, `UpdateCaches`, `ComputeHandler`, `SetCache`, `UpdateMonomorphicIC`, `UpdatePolymorphicIC`, and `UpdateMegamorphicCache`. These functions clearly relate to the lifecycle of an IC: tracking its state, updating its internal caches, and determining the appropriate optimized handler.

6. **Focus on the Interaction with JavaScript:** The code deals with JavaScript concepts like property access (`LoadIC`, `StoreIC`, `KeyedLoadIC`, `KeyedStoreIC`), prototypes, and object types. The comments explicitly mention handling different object types and property lookups. The mention of "feedback vectors" hints at how the IC system learns from past executions.

7. **Formulate the Summary:** Based on the above analysis, construct a concise summary:
    * Start by stating the file's primary purpose: implementing inline caching for property access.
    * Explain *how* it achieves this: by storing information about previous accesses (object types, property locations) in "feedback vectors" and transitioning through different IC states.
    * Mention the optimization goal: to avoid slow runtime lookups.
    * List key aspects handled by the code: managing IC state, updating caches, determining handlers, and dealing with different access types.

8. **Create JavaScript Examples:**  To illustrate the connection, provide simple JavaScript code snippets demonstrating scenarios where ICs come into play:
    * Basic property access (`object.property`).
    * Accessing properties on objects with different shapes (leading to polymorphic ICs).
    * Repeated access to the same property (leading to monomorphic ICs).
    * Accessing array elements (keyed access).

9. **Refine the Summary and Examples:** Review the summary and examples for clarity, accuracy, and conciseness. Ensure the examples directly demonstrate the concepts mentioned in the summary. For instance,  showing how repeated access can lead to optimization is key.

10. **Address the "Part 1 of 3" Aspect:** Acknowledge that this is only the first part and that subsequent parts likely handle more specific details of the IC system.

This structured approach helps to understand the complex C++ code by focusing on the high-level purpose and gradually drilling down into the key mechanisms. The inclusion of JavaScript examples makes the connection between the C++ implementation and the end-user language more tangible.
这个C++源代码文件 `ic.cc` (位于 `v8/src/ic/` 目录中) 的主要功能是**实现了 V8 JavaScript 引擎中的 Inline Cache (IC) 机制**。

**Inline Cache (IC)** 是一种用于优化 JavaScript 对象属性访问（包括读取和写入）的关键技术。 它的核心思想是：

* **缓存之前的查找结果：** 当访问一个对象的属性时，IC 会记录下这次访问的对象类型（更具体地说是对象的 `Map`）以及属性的位置或处理方式（例如，是一个直接的数据属性、一个访问器属性、位于原型链的哪个位置等）。
* **加速后续的相同访问：** 当再次访问相同对象的相同属性时，IC 可以根据缓存的信息快速判断属性的位置或处理方式，而无需重新进行完整的属性查找过程。

**具体来说，这个文件中的代码负责以下方面：**

* **定义 IC 的状态：**  例如 `NO_FEEDBACK`, `UNINITIALIZED`, `MONOMORPHIC`, `POLYMORPHIC`, `MEGAMORPHIC` 等。 这些状态表示 IC 对特定属性访问模式的了解程度。
    * `MONOMORPHIC` 表示 IC 只观察到一种对象类型访问该属性，此时可以生成最优化、最快速的代码。
    * `POLYMORPHIC` 表示 IC 观察到多种对象类型访问该属性，需要处理不同的情况。
    * `MEGAMORPHIC` 表示 IC 观察到非常多的对象类型访问该属性，优化效果降低，可能会退化到更通用的处理方式。
* **跟踪属性访问的反馈：**  通过 `FeedbackVector` 和 `FeedbackSlot` 来存储和更新 IC 的状态和缓存信息。
* **计算和更新 IC 的 "handler"：**  "handler" 是一个代码片段或数据结构，包含了针对特定属性访问模式的优化逻辑。  例如，如果一个属性总是直接存在于特定类型的对象上，handler 可能就包含直接读取该属性的代码。
* **处理不同类型的属性访问：**  例如，命名的属性访问 (`object.property`) 和索引属性访问 (`object[index]`)。
* **处理原型链的查找：**  IC 能够记住属性是在哪个原型对象上找到的。
* **处理访问器属性（getter/setter）：**  IC 能够缓存访问器属性的处理逻辑。
* **处理拦截器（interceptors）：**  一种动态控制属性访问的机制。
* **处理全局对象的属性访问。**
* **处理 `in` 操作符 (`'property' in object`) 和 `hasOwnProperty` 方法。**
* **与 StubCache 交互：**  StubCache 是 V8 中用于缓存生成的机器码的机制，IC 会利用 StubCache 来缓存其生成的优化代码。
* **收集和输出 IC 的统计信息。**

**与 JavaScript 功能的关系和示例：**

IC 的目标是加速 JavaScript 代码的执行，对于开发者来说是透明的。  它直接影响 JavaScript 中属性访问的性能。

**JavaScript 示例：**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

const p1 = new Point(1, 2);
const p2 = new Point(3, 4);

// 第一次访问 p1.x，IC 处于 UNINITIALIZED 状态，会进行完整的属性查找
console.log(p1.x);

// 第二次访问 p1.x，IC 可能会变成 MONOMORPHIC 状态，因为它只看到 Point 类型的对象访问 x 属性
// 它可以缓存 p1.x 的访问方式，下次访问会更快
console.log(p1.x);

// 访问 p2.x，由于 p2 也是 Point 类型的，IC 仍然可以利用之前的 MONOMORPHIC 缓存
console.log(p2.x);

const obj = { x: 5, z: 6 };
// 访问 obj.x，IC 发现访问 x 属性的对象类型不再只有 Point，可能会变成 POLYMORPHIC 状态
console.log(obj.x);

const manyObjects = [];
for (let i = 0; i < 100; i++) {
  manyObjects.push({ x: i });
}

// 循环访问 manyObjects 中不同对象的 x 属性，IC 可能会变成 MEGAMORPHIC 状态
for (const o of manyObjects) {
  console.log(o.x);
}

const arr = [10, 20, 30];
// 访问数组元素，属于 keyed access
console.log(arr[0]);
console.log(arr[1]);
```

**解释示例：**

* **Monomorphic IC:**  当多次访问 `p1.x` 时，IC 会学习到 `x` 属性总是存在于 `Point` 类型的对象上，从而优化后续对 `Point` 对象的 `x` 属性访问。
* **Polymorphic IC:** 当访问 `obj.x` 后，IC 发现除了 `Point` 类型，还有其他类型的对象（例如 `obj`）也具有 `x` 属性。IC 需要处理多种对象类型的情况，效率会略低于 Monomorphic IC。
* **Megamorphic IC:** 当访问 `manyObjects` 中大量不同对象的 `x` 属性时，IC 发现访问模式非常多样，很难进行有效的优化，可能会退化到更通用的查找方式。
* **Keyed Access:** 访问数组元素 `arr[0]` 是 keyed access 的一个例子，IC 也会对这类访问进行优化。

**总结一下，`v8/src/ic/ic.cc` 文件是 V8 引擎中实现高性能属性访问的关键组件，它通过缓存之前的访问信息来加速 JavaScript 代码的执行。** 这是理解 V8 如何优化 JavaScript 代码的重要组成部分。

Prompt: 
```
这是目录为v8/src/ic/ic.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能

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

    case LookupIterator::ACCESSOR: {
      Handle<JSObject> holder = lookup->GetHolder<JSObject>();
      // Use simple field loads for some well-known callback properties.
      // The method will only return true for absolute truths based on the
      // lookup start object maps.
      FieldIndex field_index;
      if (Accessors::IsJSObjectFieldAccessor(isolate(), map, lookup->name(),
                                             &field_index)) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldDH);
        return MaybeObjectHandle(
            LoadHandler::LoadField(isolate(), field_index));
      }
      if (IsJSModuleNamespace(*holder)) {
        DirectHandle<ObjectHashTable> exports(
            Cast<JSModuleNamespace>(holder)->module()->exports(), isolate());
        InternalIndex entry =
            exports->FindEntry(isolate(), roots, lookup->name(),
                               Smi::ToInt(Object::GetHash(*lookup->name())));
        // We found the accessor, so the entry must exist.
        DCHECK(entry.is_found());
        int value_index = ObjectHashTable::EntryToValueIndex(entry);
        Handle<Smi> smi_handler =
            LoadHandler::LoadModuleExport(isolate(), value_index);
        if (holder_is_lookup_start_object) {
          return MaybeObjectHandle(smi_handler);
        }
        return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
            isolate(), map, holder, *smi_handler));
      }

      Handle<Object> accessors = lookup->GetAccessors();
      if (IsAccessorPair(*accessors)) {
        Handle<AccessorPair> accessor_pair = Cast<AccessorPair>(accessors);
        if (lookup->TryLookupCachedProperty(accessor_pair)) {
          DCHECK_EQ(LookupIterator::DATA, lookup->state());
          return MaybeObjectHandle(ComputeHandler(lookup));
        }

        Handle<Object> getter(accessor_pair->getter(), isolate());
        if (!IsCallableJSFunction(*getter) &&
            !IsFunctionTemplateInfo(*getter)) {
          // TODO(jgruber): Update counter name.
          TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
          return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
        }
        set_accessor(getter);

        if ((IsFunctionTemplateInfo(*getter) &&
             Cast<FunctionTemplateInfo>(*getter)->BreakAtEntry(isolate())) ||
            (IsJSFunction(*getter) &&
             Cast<JSFunction>(*getter)->shared()->BreakAtEntry(isolate()))) {
          // Do not install an IC if the api function has a breakpoint.
          TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
          return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
        }

        Handle<Smi> smi_handler;

        CallOptimization call_optimization(isolate(), getter);
        if (call_optimization.is_simple_api_call()) {
          CallOptimization::HolderLookup holder_lookup;
          Handle<JSObject> api_holder =
              call_optimization.LookupHolderOfExpectedType(isolate(), map,
                                                           &holder_lookup);

          if (!call_optimization.IsCompatibleReceiverMap(api_holder, holder,
                                                         holder_lookup) ||
              !holder->HasFastProperties()) {
            TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
            return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
          }

          smi_handler = LoadHandler::LoadApiGetter(
              isolate(), holder_lookup == CallOptimization::kHolderIsReceiver);

          Handle<NativeContext> accessor_context =
              GetAccessorContext(call_optimization, holder->map(), isolate());

          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadApiGetterFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(call_optimization.api_call_info()),
              MaybeObjectHandle::Weak(accessor_context)));
        }

        if (holder->HasFastProperties()) {
          DCHECK(IsCallableJSFunction(*getter));
          if (holder_is_lookup_start_object) {
            TRACE_HANDLER_STATS(isolate(), LoadIC_LoadAccessorDH);
            return MaybeObjectHandle::Weak(accessor_pair);
          }
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadAccessorFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder,
              *LoadHandler::LoadAccessorFromPrototype(isolate()),
              MaybeObjectHandle::Weak(getter)));
        }

        if (IsJSGlobalObject(*holder)) {
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadGlobalFromPrototypeDH);
          smi_handler = LoadHandler::LoadGlobal(isolate());
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(lookup->GetPropertyCell())));
        } else {
          smi_handler = LoadHandler::LoadNormal(isolate());
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalDH);
          if (holder_is_lookup_start_object)
            return MaybeObjectHandle(smi_handler);
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalFromPrototypeDH);
        }

        return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
            isolate(), map, holder, *smi_handler));
      }

      DirectHandle<AccessorInfo> info = Cast<AccessorInfo>(accessors);

      if (info->replace_on_access()) {
        set_slow_stub_reason(
            "getter needs to be reconfigured to data property");
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }

      if (!info->has_getter(isolate()) || !holder->HasFastProperties() ||
          (info->is_sloppy() && !IsJSReceiver(*receiver))) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }

      Handle<Smi> smi_handler = LoadHandler::LoadNativeDataProperty(
          isolate(), lookup->GetAccessorIndex());
      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNativeDataPropertyDH);
      if (holder_is_lookup_start_object) return MaybeObjectHandle(smi_handler);
      TRACE_HANDLER_STATS(isolate(),
                          LoadIC_LoadNativeDataPropertyFromPrototypeDH);
      return MaybeObjectHandle(
          LoadHandler::LoadFromPrototype(isolate(), map, holder, *smi_handler));
    }

    case LookupIterator::DATA: {
      Handle<JSReceiver> holder = lookup->GetHolder<JSReceiver>();
      DCHECK_EQ(PropertyKind::kData, lookup->property_details().kind());
      Handle<Smi> smi_handler;
      if (lookup->is_dictionary_holder()) {
        if (IsJSGlobalObject(*holder, isolate())) {
          // TODO(verwaest): Also supporting the global object as receiver is a
          // workaround for code that leaks the global object.
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadGlobalDH);
          smi_handler = LoadHandler::LoadGlobal(isolate());
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler,
              MaybeObjectHandle::Weak(lookup->GetPropertyCell())));
        }
        smi_handler = LoadHandler::LoadNormal(isolate());
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalDH);
        if (holder_is_lookup_start_object)
          return MaybeObjectHandle(smi_handler);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadNormalFromPrototypeDH);
      } else if (lookup->IsElement(*holder)) {
        TRACE_HANDLER_STATS(isolate(), LoadIC_SlowStub);
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      } else {
        DCHECK_EQ(PropertyLocation::kField,
                  lookup->property_details().location());
        DCHECK(IsJSObject(*holder, isolate()));
        FieldIndex field = lookup->GetFieldIndex();
        smi_handler = LoadHandler::LoadField(isolate(), field);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldDH);
        if (holder_is_lookup_start_object)
          return MaybeObjectHandle(smi_handler);
        TRACE_HANDLER_STATS(isolate(), LoadIC_LoadFieldFromPrototypeDH);
      }
      if (lookup->constness() == PropertyConstness::kConst &&
          !holder_is_lookup_start_object) {
        DCHECK_IMPLIES(!V8_DICT_PROPERTY_CONST_TRACKING_BOOL,
                       !lookup->is_dictionary_holder());

        DirectHandle<Object> value = lookup->GetDataValue();

        if (IsThinString(*value)) {
          value = handle(Cast<ThinString>(*value)->actual(), isolate());
        }

        // Non internalized strings could turn into thin/cons strings
        // when internalized. Weak references to thin/cons strings are
        // not supported in the GC. If concurrent marking is running
        // and the thin/cons string is marked but the actual string is
        // not, then the weak reference could be missed.
        if (!IsString(*value) ||
            (IsString(*value) && IsInternalizedString(*value))) {
          MaybeObjectHandle weak_value =
              IsSmi(*value) ? MaybeObjectHandle(*value, isolate())
                            : MaybeObjectHandle::Weak(*value, isolate());

          smi_handler = LoadHandler::LoadConstantFromPrototype(isolate());
          TRACE_HANDLER_STATS(isolate(), LoadIC_LoadConstantFromPrototypeDH);
          return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
              isolate(), map, holder, *smi_handler, weak_value));
        }
      }
      return MaybeObjectHandle(
          LoadHandler::LoadFromPrototype(isolate(), map, holder, *smi_handler));
    }
    case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
      TRACE_HANDLER_STATS(isolate(), LoadIC_LoadIntegerIndexedExoticDH);
      return MaybeObjectHandle(LoadHandler::LoadNonExistent(isolate()));

    case LookupIterator::JSPROXY: {
      // Private names on JSProxy is currently not supported.
      if (lookup->name()->IsPrivate()) {
        return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
      }
      Handle<Smi> smi_handler = LoadHandler::LoadProxy(isolate());
      if (holder_is_lookup_start_object) return MaybeObjectHandle(smi_handler);

      Handle<JSProxy> holder_proxy = lookup->GetHolder<JSProxy>();
      return MaybeObjectHandle(LoadHandler::LoadFromPrototype(
          isolate(), map, holder_proxy, *smi_handler));
    }

    case LookupIterator::WASM_OBJECT:
      return MaybeObjectHandle(LoadHandler::LoadSlow(isolate()));
    case LookupIterator::ACCESS_CHECK:
    case LookupIterator::NOT_FOUND:
    case LookupIterator::TRANSITION:
      UNREACHABLE();
  }

  return MaybeObjectHandle(Handle<InstructionStream>::null());
}

KeyedAccessLoadMode KeyedLoadIC::GetKeyedAccessLoadModeFor(
    DirectHandle<Map> receiver_map) const {
  const MaybeObjectHandle& handler = nexus()->FindHandlerForMap(receiver_map);
  if (handler.is_null()) return KeyedAccessLoadMode::kInBounds;
  return LoadHandler::GetKeyedAccessLoadMode(*handler);
}

// Returns whether the load mode transition is allowed.
bool AllowedHandlerChange(KeyedAccessLoadMode old_mode,
                          KeyedAccessLoadMode new_mode) {
  // Only allow transitions to allow OOB or allow converting a hole to
  // undefined.
  using T = std::underlying_type<KeyedAccessLoadMode>::type;
  return ((static_cast<T>(old_mode) ^
           static_cast<T>(GeneralizeKeyedAccessLoadMode(old_mode, new_mode))) &
          0b11) != 0;
}

void KeyedLoadIC::UpdateLoadElement(Handle<HeapObject> receiver,
                                    const KeyedAccessLoadMode new_load_mode) {
  Handle<Map> receiver_map(receiver->map(), isolate());
  DCHECK(receiver_map->instance_type() !=
         JS_PRIMITIVE_WRAPPER_TYPE);  // Checked by caller.
  MapHandles target_receiver_maps;
  TargetMaps(&target_receiver_maps);

  if (target_receiver_maps.empty()) {
    Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
    return ConfigureVectorState(Handle<Name>(), receiver_map, handler);
  }

  for (Handle<Map> map : target_receiver_maps) {
    if (map.is_null()) continue;
    if (map->instance_type() == JS_PRIMITIVE_WRAPPER_TYPE) {
      set_slow_stub_reason("JSPrimitiveWrapper");
      return;
    }
    if (map->instance_type() == JS_PROXY_TYPE) {
      set_slow_stub_reason("JSProxy");
      return;
    }
  }

  // The first time a receiver is seen that is a transitioned version of the
  // previous monomorphic receiver type, assume the new ElementsKind is the
  // monomorphic type. This benefits global arrays that only transition
  // once, and all call sites accessing them are faster if they remain
  // monomorphic. If this optimistic assumption is not true, the IC will
  // miss again and it will become polymorphic and support both the
  // untransitioned and transitioned maps.
  if (state() == MONOMORPHIC) {
    if ((IsJSObject(*receiver) &&
         IsMoreGeneralElementsKindTransition(
             target_receiver_maps.at(0)->elements_kind(),
             Cast<JSObject>(receiver)->GetElementsKind())) ||
        IsWasmObject(*receiver)) {
      Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
      return ConfigureVectorState(Handle<Name>(), receiver_map, handler);
    }
  }

  DCHECK(state() != GENERIC);

  // Determine the list of receiver maps that this call site has seen,
  // adding the map that was just encountered.
  KeyedAccessLoadMode old_load_mode = KeyedAccessLoadMode::kInBounds;
  if (!AddOneReceiverMapIfMissing(&target_receiver_maps, receiver_map)) {
    old_load_mode = GetKeyedAccessLoadModeFor(receiver_map);
    if (!AllowedHandlerChange(old_load_mode, new_load_mode)) {
      set_slow_stub_reason("same map added twice");
      return;
    }
  }

  // If the maximum number of receiver maps has been exceeded, use the generic
  // version of the IC.
  if (static_cast<int>(target_receiver_maps.size()) >
      v8_flags.max_valid_polymorphic_map_count) {
    set_slow_stub_reason("max polymorph exceeded");
    return;
  }

  MaybeObjectHandles handlers;
  handlers.reserve(target_receiver_maps.size());
  KeyedAccessLoadMode load_mode =
      GeneralizeKeyedAccessLoadMode(old_load_mode, new_load_mode);
  LoadElementPolymorphicHandlers(&target_receiver_maps, &handlers, load_mode);
  if (target_receiver_maps.empty()) {
    Handle<Object> handler = LoadElementHandler(receiver_map, new_load_mode);
    ConfigureVectorState(Handle<Name>(), receiver_map, handler);
  } else if (target_receiver_maps.size() == 1) {
    ConfigureVectorState(Handle<Name>(), target_receiver_maps[0], handlers[0]);
  } else {
    ConfigureVectorState(Handle<Name>(),
                         MapHandlesSpan(target_receiver_maps.begin(),
                                        target_receiver_maps.end()),
                         &handlers);
  }
}

namespace {

bool AllowConvertHoleElementToUndefined(Isolate* isolate,
                                        DirectHandle<Map> receiver_map) {
  if (IsJSTypedArrayMap(*receiver_map)) {
    // For JSTypedArray we never lookup elements in the prototype chain.
    return true;
  }

  // For other {receiver}s we need to check the "no elements" protector.
  if (Protectors::IsNoElementsIntact(isolate)) {
    if (IsStringMap(*receiver_map)) {
      return true;
    }
    if (IsJSObjectMap(*receiver_map)) {
      // For other JSObjects (including JSArrays) we can only continue if
      // the {receiver}s prototype is either the initial Object.prototype
      // or the initial Array.prototype, which are both guarded by the
      // "no elements" protector checked above.
      DirectHandle<HeapObject> receiver_prototype(receiver_map->prototype(),
                                                  isolate);
      InstanceType prototype_type = receiver_prototype->map()->instance_type();
      if (prototype_type == JS_OBJECT_PROTOTYPE_TYPE ||
          (prototype_type == JS_ARRAY_TYPE &&
           isolate->IsInCreationContext(
               Cast<JSObject>(*receiver_prototype),
               Context::INITIAL_ARRAY_PROTOTYPE_INDEX))) {
        return true;
      }
    }
  }

  return false;
}

bool IsOutOfBoundsAccess(DirectHandle<Object> receiver, size_t index) {
  size_t length;
  if (IsJSArray(*receiver)) {
    length = Object::NumberValue(Cast<JSArray>(*receiver)->length());
  } else if (IsJSTypedArray(*receiver)) {
    length = Cast<JSTypedArray>(*receiver)->GetLength();
  } else if (IsJSObject(*receiver)) {
    length = Cast<JSObject>(*receiver)->elements()->length();
  } else if (IsString(*receiver)) {
    length = Cast<String>(*receiver)->length();
  } else {
    return false;
  }
  return index >= length;
}

bool AllowReadingHoleElement(ElementsKind elements_kind) {
  return IsHoleyElementsKind(elements_kind);
}

KeyedAccessLoadMode GetNewKeyedLoadMode(Isolate* isolate,
                                        Handle<HeapObject> receiver,
                                        size_t index, bool is_found) {
  DirectHandle<Map> receiver_map(Cast<HeapObject>(receiver)->map(), isolate);
  if (!AllowConvertHoleElementToUndefined(isolate, receiver_map)) {
    return KeyedAccessLoadMode::kInBounds;
  }

  // Always handle holes when the elements kind is HOLEY_ELEMENTS, since the
  // optimizer compilers can not benefit from this information to narrow the
  // type. That is, the load type will always just be a generic tagged value.
  // This avoid an IC miss if we see a hole.
  ElementsKind elements_kind = receiver_map->elements_kind();
  bool always_handle_holes = (elements_kind == HOLEY_ELEMENTS);

  // In bound access and did not read a hole.
  if (is_found) {
    return always_handle_holes ? KeyedAccessLoadMode::kHandleHoles
                               : KeyedAccessLoadMode::kInBounds;
  }

  // OOB access.
  bool is_oob_access = IsOutOfBoundsAccess(receiver, index);
  if (is_oob_access) {
    return always_handle_holes ? KeyedAccessLoadMode::kHandleOOBAndHoles
                               : KeyedAccessLoadMode::kHandleOOB;
  }

  // Read a hole.
  DCHECK(!is_found && !is_oob_access);
  bool handle_hole = AllowReadingHoleElement(elements_kind);
  DCHECK_IMPLIES(always_handle_holes, handle_hole);
  return handle_hole ? KeyedAccessLoadMode::kHandleHoles
                     : KeyedAccessLoadMode::kInBounds;
}

KeyedAccessLoadMode GetUpdatedLoadModeForMap(Isolate* isolate,
                                             DirectHandle<Map> map,
                                             KeyedAccessLoadMode load_mode) {
  // If we are not allowed to convert a hole to undefined, then we should not
  // handle OOB nor reading holes.
  if (!AllowConvertHoleElementToUndefined(isolate, map)) {
    return KeyedAccessLoadMode::kInBounds;
  }
  // Check if the elements kind allow reading a hole.
  bool allow_reading_hole_element =
      AllowReadingHoleElement(map->elements_kind());
  switch (load_mode) {
    case KeyedAccessLoadMode::kInBounds:
    case KeyedAccessLoadMode::kHandleOOB:
      return load_mode;
    case KeyedAccessLoadMode::kHandleHoles:
      return allow_reading_hole_element ? KeyedAccessLoadMode::kHandleHoles
                                        : KeyedAccessLoadMode::kInBounds;
    case KeyedAccessLoadMode::kHandleOOBAndHoles:
      return allow_reading_hole_element
                 ? KeyedAccessLoadMode::kHandleOOBAndHoles
                 : KeyedAccessLoadMode::kHandleOOB;
  }
}

}  // namespace

Handle<Object> KeyedLoadIC::LoadElementHandler(
    DirectHandle<Map> receiver_map, KeyedAccessLoadMode new_load_mode) {
  // Has a getter interceptor, or is any has and has a query interceptor.
  if (receiver_map->has_indexed_interceptor() &&
      (!IsUndefined(receiver_map->GetIndexedInterceptor()->getter(),
                    isolate()) ||
       (IsAnyHas() &&
        !IsUndefined(receiver_map->GetIndexedInterceptor()->query(),
                     isolate()))) &&
      !receiver_map->GetIndexedInterceptor()->non_masking()) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadIndexedInterceptorStub);
    return IsAnyHas() ? BUILTIN_CODE(isolate(), HasIndexedInterceptorIC)
                      : BUILTIN_CODE(isolate(), LoadIndexedInterceptorIC);
  }

  InstanceType instance_type = receiver_map->instance_type();
  if (instance_type < FIRST_NONSTRING_TYPE) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadIndexedStringDH);
    if (IsAnyHas()) return LoadHandler::LoadSlow(isolate());
    return LoadHandler::LoadIndexedString(isolate(), new_load_mode);
  }
  if (instance_type < FIRST_JS_RECEIVER_TYPE) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_SlowStub);
    return LoadHandler::LoadSlow(isolate());
  }
  if (instance_type == JS_PROXY_TYPE) {
    return LoadHandler::LoadProxy(isolate());
  }
#if V8_ENABLE_WEBASSEMBLY
  if (InstanceTypeChecker::IsWasmObject(instance_type)) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_SlowStub);
    return LoadHandler::LoadSlow(isolate());
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  ElementsKind elements_kind = receiver_map->elements_kind();
  if (IsSloppyArgumentsElementsKind(elements_kind)) {
    // TODO(jgruber): Update counter name.
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_KeyedLoadSloppyArgumentsStub);
    return IsAnyHas() ? BUILTIN_CODE(isolate(), KeyedHasIC_SloppyArguments)
                      : BUILTIN_CODE(isolate(), KeyedLoadIC_SloppyArguments);
  }
  bool is_js_array = instance_type == JS_ARRAY_TYPE;
  if (elements_kind == DICTIONARY_ELEMENTS) {
    TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadElementDH);
    return LoadHandler::LoadElement(isolate(), elements_kind, is_js_array,
                                    new_load_mode);
  }
  DCHECK(IsFastElementsKind(elements_kind) ||
         IsAnyNonextensibleElementsKind(elements_kind) ||
         IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind));
  DCHECK_IMPLIES(
      LoadModeHandlesHoles(new_load_mode),
      AllowReadingHoleElement(elements_kind) &&
          AllowConvertHoleElementToUndefined(isolate(), receiver_map));
  TRACE_HANDLER_STATS(isolate(), KeyedLoadIC_LoadElementDH);
  return LoadHandler::LoadElement(isolate(), elements_kind, is_js_array,
                                  new_load_mode);
}

void KeyedLoadIC::LoadElementPolymorphicHandlers(
    MapHandles* receiver_maps, MaybeObjectHandles* handlers,
    KeyedAccessLoadMode new_load_mode) {
  // Filter out deprecated maps to ensure their instances get migrated.
  receiver_maps->erase(
      std::remove_if(
          receiver_maps->begin(), receiver_maps->end(),
          [](const DirectHandle<Map>& map) { return map->is_deprecated(); }),
      receiver_maps->end());

  for (DirectHandle<Map> receiver_map : *receiver_maps) {
    // Mark all stable receiver maps that have elements kind transition map
    // among receiver_maps as unstable because the optimizing compilers may
    // generate an elements kind transition for this kind of receivers.
    if (receiver_map->is_stable()) {
      Tagged<Map> tmap = receiver_map->FindElementsKindTransitionedMap(
          isolate(),
          MapHandlesSpan(receiver_maps->begin(), receiver_maps->end()),
          ConcurrencyMode::kSynchronous);
      if (!tmap.is_null()) {
        receiver_map->NotifyLeafMapLayoutChange(isolate());
      }
    }
    handlers->push_back(MaybeObjectHandle(LoadElementHandler(
        receiver_map,
        GetUpdatedLoadModeForMap(isolate(), receiver_map, new_load_mode))));
  }
}

namespace {

enum KeyType { kIntPtr, kName, kBailout };

// The cases where kIntPtr is returned must match what
// CodeStubAssembler::TryToIntptr can handle!
KeyType TryConvertKey(Handle<Object> key, Isolate* isolate, intptr_t* index_out,
                      Handle<Name>* name_out) {
  if (IsSmi(*key)) {
    *index_out = Smi::ToInt(*key);
    return kIntPtr;
  }
  if (IsHeapNumber(*key)) {
    double num = Cast<HeapNumber>(*key)->value();
    if (!(num >= -kMaxSafeInteger)) return kBailout;
    if (num > kMaxSafeInteger) return kBailout;
    *index_out = static_cast<intptr_t>(num);
    if (*index_out != num) return kBailout;
    return kIntPtr;
  }
  if (IsString(*key)) {
    key = isolate->factory()->InternalizeString(Cast<String>(key));
    uint32_t maybe_array_index;
    if (Cast<String>(*key)->AsArrayIndex(&maybe_array_index)) {
      if (maybe_array_index <= INT_MAX) {
        *index_out = static_cast<intptr_t>(maybe_array_index);
        return kIntPtr;
      }
      // {key} is a string representation of an array index beyond the range
      // that the IC could handle. Don't try to take the named-property path.
      return kBailout;
    }
    *name_out = Cast<String>(key);
    return kName;
  }
  if (IsSymbol(*key)) {
    *name_out = Cast<Symbol>(key);
    return kName;
  }
  return kBailout;
}

bool IntPtrKeyToSize(intptr_t index, DirectHandle<HeapObject> receiver,
                     size_t* out) {
  if (index < 0) {
    if (IsJSTypedArray(*receiver)) {
      // For JSTypedArray receivers, we can support negative keys, which we
      // just map to a very large value. This is valid because all OOB accesses
      // (negative or positive) are handled the same way, and size_t::max is
      // guaranteed to be an OOB access.
      *out = std::numeric_limits<size_t>::max();
      return true;
    }
    return false;
  }
#if V8_HOST_ARCH_64_BIT
  if (index > JSObject::kMaxElementIndex && !IsJSTypedArray(*receiver)) {
    return false;
  }
#else
  // On 32-bit platforms, any intptr_t is less than kMaxElementIndex.
  static_assert(
      static_cast<double>(std::numeric_limits<decltype(index)>::max()) <=
      static_cast<double>(JSObject::kMaxElementIndex));
#endif
  *out = static_cast<size_t>(index);
  return true;
}

bool CanCache(DirectHandle<Object> receiver, InlineCacheState state) {
  if (!v8_flags.use_ic || state == NO_FEEDBACK) return false;
  if (!IsJSReceiver(*receiver) && !IsString(*receiver)) return false;
  return !IsAccessCheckNeeded(*receiver) && !IsJSPrimitiveWrapper(*receiver);
}

}  // namespace

MaybeHandle<Object> KeyedLoadIC::RuntimeLoad(Handle<JSAny> object,
                                             Handle<Object> key,
                                             bool* is_found) {
  Handle<Object> result;

  if (IsKeyedLoadIC()) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        Runtime::GetObjectProperty(isolate(), object, key, Handle<JSAny>(),
                                   is_found));
  } else {
    DCHECK(IsKeyedHasIC());
    ASSIGN_RETURN_ON_EXCEPTION(isolate(), result,
                               Runtime::HasProperty(isolate(), object, key));
  }
  return result;
}

MaybeHandle<Object> KeyedLoadIC::LoadName(Handle<JSAny> object,
                                          DirectHandle<Object> key,
                                          Handle<Name> name) {
  Handle<Object> load_handle;
  ASSIGN_RETURN_ON_EXCEPTION(isolate(), load_handle,
                             LoadIC::Load(object, name));

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
    TraceIC("LoadIC", key);
  }

  DCHECK(!load_handle.is_null());
  return load_handle;
}

MaybeHandle<Object> KeyedLoadIC::Load(Handle<JSAny> object,
                                      Handle<Object> key) {
  if (MigrateDeprecated(isolate(), object)) {
    return RuntimeLoad(object, key);
  }

  intptr_t maybe_index;
  Handle<Name> maybe_name;
  KeyType key_type = TryConvertKey(key, isolate(), &maybe_index, &maybe_name);

  if (key_type == kName) return LoadName(object, key, maybe_name);

  bool is_found = false;
  MaybeHandle<Object> result = RuntimeLoad(object, key, &is_found);

  size_t index;
  if (key_type == kIntPtr && CanCache(object, state()) &&
      IntPtrKeyToSize(maybe_index, Cast<HeapObject>(object), &index)) {
    Handle<HeapObject> receiver = Cast<HeapObject>(object);
    KeyedAccessLoadMode load_mode =
        GetNewKeyedLoadMode(isolate(), receiver, index, is_found);
    UpdateLoadElement(receiver, load_mode);
    if (is_vector_set()) {
      TraceIC("LoadIC", key);
    }
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
    TraceIC("LoadIC", key);
  }

  return result;
}

bool StoreIC::LookupForWrite(LookupIterator* it, DirectHandle<Object> value,
                             StoreOrigin store_origin) {
  // Disable ICs for non-JSObjects for now.
  Handle<Object> object = it->GetReceiver();
  if (IsJSProxy(*object)) return true;
  if (!IsJSObject(*object)) return false;
  Handle<JSObject> receiver = Cast<JSObject>(object);
  DCHECK(!receiver->map()->is_deprecated());

  for (;; it->Next()) {
    switch (it->state()) {
      case LookupIterator::TRANSITION:
        UNREACHABLE();
      case LookupIterator::WASM_OBJECT:
        return false;
      case LookupIterator::JSPROXY:
        return true;
      case LookupIterator::INTERCEPTOR: {
        DirectHandle<JSObject> holder = it->GetHolder<JSObject>();
        Tagged<InterceptorInfo> info = holder->GetNamedInterceptor();
        if (it->HolderIsReceiverOrHiddenPrototype() ||
            !IsUndefined(info->getter(), isolate()) ||
            !IsUndefined(info->query(), isolate())) {
          return true;
        }
        continue;
      }
      case LookupIterator::ACCESS_CHECK:
        if (IsAccessCheckNeeded(*it->GetHolder<JSObject>())) return false;
        continue;
      case LookupIterator::ACCESSOR:
        return !it->IsReadOnly();
      case LookupIterator::TYPED_ARRAY_INDEX_NOT_FOUND:
        return false;
      case LookupIterator::DATA: {
        if (it->IsReadOnly()) return false;
        if (IsAnyDefineOwn() && it->property_attributes() != NONE) {
          // IC doesn't support reconfiguration of property attributes,
          // so just bail out to the slow handler.
          return false;
        }
        Handle<JSObject> holder = it->GetHolder<JSObject>();
        if (receiver.is_identical_to(holder)) {
          it->PrepareForDataProperty(value);
          // The previous receiver map might just have been deprecated,
          // so reload it.
          update_lookup_start_object_map(receiver);
          return true;
        }

        // Receiver != holder.
        if (IsJSGlobalProxy(*receiver)) {
          PrototypeIterator iter(isolate(), receiver);
          return it->GetHolder<Object>().is_identical_to(
              PrototypeIterator::GetCurrent(iter));
        }

        if (it->HolderIsReceiverOrHiddenPrototype()) return false;

        if (it->ExtendingNonExtensible(receiver)) return false;
        it->PrepareTransitionToDataProperty(receiver, value, NONE,
                                            store_origin);
        return it->IsCacheableTransition();
      }
      case LookupIterator::NOT_FOUND:
        // If we are in StoreGlobal then check if we should throw on
        // non-existent properties.
        if (IsStoreGlobalIC() &&
            (GetShouldThrow(it->isolate(), Nothing<ShouldThrow>()) ==
             ShouldThrow::kThrowOnError)) {
          // ICs typically does the store in two steps: prepare receiver for the
          // transition followed by the actual store. For global objects we
          // create a property cell when preparing for transition and install
          // this cell in the handler. In strict mode, we throw and never
          // initialize this property cell. The IC handler assumes that the
          // property cell it is holding is for a property that is existing.
          // This case violates this assumption. If we happen to invalidate this
          // property cell later, it leads to incorrect behaviour. For now just
          // use a slow stub and don't install the property cell for these
          // cases. Hopefully these cases are not frequent enough to impact
          // performance.
          //
          // TODO(mythria): If we find this to be happening often, we could
          // install a new kind of handler for non-existent properties. These
          // handlers can then miss to runtime if the value is not hole (i.e.
          // cell got invalidated) and handle these stores correctly.
          return false;
        }
        receiver = it->GetStoreTarget<JSObject>();
        if (it->ExtendingNonExtensible(receiver)) return false;
        it->PrepareTransitionToDataProperty(receiver, value, NONE,
                                            store_origin);
        return it->IsCacheableTransition();
    }
    UNREACHABLE();
  }
}

MaybeHandle<Object> StoreGlobalIC::Store(Handle<Name> name,
                                         Handle<Object> value) {
  DCHECK(IsString(*name));

  
"""


```
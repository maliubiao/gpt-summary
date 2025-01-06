Response: Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The filename `test-js-weak-refs.cc` immediately points to the topic: JavaScript Weak References. This is the central theme.

2. **Scan the Includes:**  The `#include` directives provide clues about the functionalities being tested. Key includes are:
    * `src/execution/isolate.h`:  Indicates interaction with the V8 isolate, the runtime environment for JavaScript.
    * `src/handles/handles-inl.h`: Suggests manipulation of V8 handles, which are smart pointers for managing V8 objects.
    * `src/heap/factory-inl.h` and `src/heap/heap-inl.h`:  Clearly related to V8's memory management and object creation.
    * `src/objects/js-objects.h` and `src/objects/js-weak-refs-inl.h`: Directly confirm the focus on JavaScript objects and specifically weak references and their related structures.
    * `test/cctest/cctest.h`:  Identifies this as a CCTests file, V8's internal testing framework.

3. **Analyze the Namespaces:** The code is within the `v8::internal` namespace, which is typical for V8's internal implementation details. The anonymous namespace `namespace { ... }` is common for helper functions within a single compilation unit.

4. **Examine Helper Functions in the Anonymous Namespace:** These functions are crucial for understanding how the tests are set up and what operations are being performed:
    * `ConstructJSFinalizationRegistry`:  Creates an instance of `FinalizationRegistry`. This strongly suggests testing the `FinalizationRegistry` API.
    * `ConstructJSWeakRef`: Creates an instance of `WeakRef`. This confirms the focus on testing `WeakRef`.
    * `CreateKey`:  Creates a simple JavaScript object to be used as a key, indicating testing scenarios involving keys in weak references or finalization registries.
    * `FinalizationRegistryRegister`:  Simulates the `register` method of `FinalizationRegistry`, linking a target object, held value, and unregister token.
    * Overloaded `FinalizationRegistryRegister`:  A simpler version without held value or unregister token.
    * `NullifyWeakCell`: Directly manipulates the internal `WeakCell` state, likely simulating garbage collection effects.
    * `PopClearedCellHoldings`:  Mimics the internal logic of retrieving finalized values from the `FinalizationRegistry`.
    * `VerifyWeakCellChain` and `VerifyWeakCellKeyChain`: These are verification functions, confirming the internal linked-list structures are maintained correctly. This is a strong indicator that the tests are checking the *internal implementation details* of how V8 manages these weak references.
    * `MakeWeakRefAndKeepDuringJob`: Shows how to keep an object alive during a microtask job, suggesting testing the interaction of weak references with the microtask queue and object lifecycle.

5. **Review the Test Functions (Functions starting with `TEST`):**  Each test function name gives a high-level idea of what's being tested:
    * `TestRegister`: Basic registration with `FinalizationRegistry`.
    * `TestRegisterWithKey`: Registration using a key.
    * `TestWeakCellNullify1/2`: How nullifying a `WeakCell` affects internal lists.
    * `TestJSFinalizationRegistryPopClearedCellHoldings1/2`: Testing the retrieval of finalized values.
    * `TestUnregisterActiveCells/ActiveAndClearedCells/Twice/Popped/NonexistentKey`:  Comprehensive testing of the `unregister` functionality.
    * `TestJSWeakRef`: Basic `WeakRef` behavior during garbage collection.
    * `TestJSWeakRefIncrementalMarking`: Testing with incremental garbage collection.
    * `TestJSWeakRefKeepDuringJob/IncrementalMarking`: Testing the `keepDuringJob` mechanism.
    * `TestRemoveUnregisterToken`: Testing the removal of unregister tokens.
    * `JSWeakRefScavengedInWorklist/TenuredInWorklist`: Testing how weak references are handled during different phases of garbage collection.
    * `UnregisterTokenHeapVerifier/UnregisteredAndUnclearedCellHeapVerifier`: These sound like tests specifically designed to catch memory corruption or inconsistencies during garbage collection, likely related to internal verifiers.

6. **Connect to JavaScript Functionality:** Based on the C++ function names and the test scenarios, it's possible to map them back to their corresponding JavaScript features:
    * `FinalizationRegistry`: The core JavaScript API for registering objects for finalization.
    * `WeakRef`: The JavaScript API for creating weak references to objects.
    * The "register" method in C++ directly corresponds to the `FinalizationRegistry.prototype.register()` method in JavaScript.
    * The "unregister" method in C++ corresponds to `FinalizationRegistry.prototype.unregister()` in JavaScript.
    * The behavior of weak references becoming `undefined` after garbage collection is a fundamental aspect of the JavaScript `WeakRef` API.

7. **Construct the Summary:**  Synthesize the information gathered in the previous steps. Focus on the main purpose of the file, the specific functionalities being tested (both `WeakRef` and `FinalizationRegistry`), and the level of detail (testing internal data structures).

8. **Create JavaScript Examples:**  Translate the C++ test concepts into concrete JavaScript code snippets to illustrate the corresponding JavaScript behavior. Focus on demonstrating the core functionality being tested in the C++ code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just tests `WeakRef` and `FinalizationRegistry`."
* **Refinement:** "It tests them, but also delves into the *internal implementation* by verifying linked lists and internal states. The helper functions like `VerifyWeakCellChain` confirm this."
* **Initial thought about examples:**  Just show basic `WeakRef` and `FinalizationRegistry` usage.
* **Refinement:** The C++ tests emphasize scenarios like registration with keys, unregistration, and the timing of garbage collection. The JavaScript examples should reflect these more specific scenarios.
* **Understanding "KeepDuringJob":**  Initially, might not fully grasp the purpose of `MakeWeakRefAndKeepDuringJob`. Further analysis of the test cases reveals its connection to microtasks and ensuring objects survive within a microtask's execution. The JavaScript example should demonstrate this.

By following this structured approach, moving from high-level observations to detailed analysis, and constantly connecting the C++ code to its JavaScript counterparts, a comprehensive and accurate summary can be generated.
这个C++源代码文件 `v8/test/cctest/test-js-weak-refs.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 **JavaScript 的 WeakRef 和 FinalizationRegistry 这两个功能**。

**功能归纳:**

该文件通过一系列的 C++ 测试用例，验证了 V8 引擎中 WeakRef 和 FinalizationRegistry 的实现是否符合预期。具体来说，它测试了以下方面：

* **WeakRef 的创建和垃圾回收行为:**
    * 创建 `WeakRef` 对象，并观察其指向的目标对象在垃圾回收后是否会被清除。
    * 测试在不同的垃圾回收策略（如 Major GC 和 Incremental Marking）下 `WeakRef` 的行为。
    * 测试 `KeepDuringJob` 机制如何影响 `WeakRef` 指向的目标对象的生命周期。
* **FinalizationRegistry 的注册、注销和清理行为:**
    * 使用 `FinalizationRegistry` 注册目标对象和关联的 held 值。
    * 测试在目标对象被垃圾回收后，关联的 held 值是否会被放入清理队列。
    * 测试 `register` 方法使用不同参数（如提供 unregister token）时的行为。
    * 测试 `unregister` 方法，包括注销存在和不存在的 token。
    * 测试 `unregister` 对 active 和 cleared 的 WeakCell 的影响。
    * 测试 `PopClearedCellHoldings` 方法，用于从清理队列中取出 held 值。
* **内部数据结构的正确性:**
    * 验证 `FinalizationRegistry` 内部维护的 `active_cells` 和 `cleared_cells` 链表的结构和状态。
    * 验证使用 unregister token 时，内部维护的 `key_map` 的结构和状态。
* **并发和垃圾回收的交互:**
    * 测试在并发垃圾回收场景下 `WeakRef` 和 `FinalizationRegistry` 的正确性。
* **边界情况和错误处理:**
    * 测试注销不存在的 token 等边界情况。
* **Heap 验证:**
    * 使用 Heap 验证机制，检查在 `WeakRef` 和 `FinalizationRegistry` 操作过程中是否存在内存泄漏或其他内存错误。

**与 JavaScript 功能的关系及 JavaScript 示例:**

该 C++ 文件测试的正是 JavaScript 中 `WeakRef` 和 `FinalizationRegistry` 这两个内置对象的功能。

**JavaScript 示例:**

**WeakRef:**

```javascript
let target = { value: 1 };
let weakRef = new WeakRef(target);

// 稍后，当 target 没有其他强引用时，可能会被垃圾回收

// 可以通过 weakRef.deref() 获取目标对象，但如果目标已被回收，则返回 undefined
let dereferenced = weakRef.deref();
console.log(dereferenced?.value); // 可能输出 1，也可能输出 undefined
```

**FinalizationRegistry:**

```javascript
let target = { name: "myObject" };
let heldValue = "Object was collected";
let registry = new FinalizationRegistry(held => {
  console.log(held); // 当 target 被回收后，可能会输出 "Object was collected"
});

registry.register(target, heldValue);

// 将 target 的所有强引用移除，使其可以被垃圾回收
target = null;

// 触发垃圾回收（这是一个手动触发，实际情况由 V8 决定）
if (global.gc) {
  global.gc();
}
```

**带有 unregister token 的 FinalizationRegistry:**

```javascript
let target1 = { id: 1 };
let target2 = { id: 2 };
let token = "myToken";
let registry = new FinalizationRegistry(held => {
  console.log("清理:", held);
});

registry.register(target1, "target1 collected", token);
registry.register(target2, "target2 collected", token);

// 注销所有使用该 token 注册的回调
registry.unregister(token);

target1 = null;
target2 = null;

if (global.gc) {
  global.gc();
}

// 由于已注销，即使 target1 和 target2 被回收，也不会触发回调
```

**总结:**

`test-js-weak-refs.cc` 文件是 V8 引擎中至关重要的测试文件，它通过底层的 C++ 代码，确保了 JavaScript 中 `WeakRef` 和 `FinalizationRegistry` 这两个用于处理弱引用和对象终结化的功能能够按照规范正确运行。这些测试覆盖了各种使用场景、垃圾回收策略和内部实现细节，保证了 V8 引擎的稳定性和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/test-js-weak-refs.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/heap/factory-inl.h"
#include "src/heap/heap-inl.h"
#include "src/objects/js-objects.h"
#include "src/objects/js-weak-refs-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {

namespace {

Handle<JSFinalizationRegistry> ConstructJSFinalizationRegistry(
    Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<String> finalization_registry_name =
      factory->NewStringFromStaticChars("FinalizationRegistry");
  Handle<JSGlobalObject> global =
      handle(isolate->native_context()->global_object(), isolate);
  Handle<JSFunction> finalization_registry_fun = Cast<JSFunction>(
      Object::GetProperty(isolate, global, finalization_registry_name)
          .ToHandleChecked());
  auto finalization_registry = Cast<JSFinalizationRegistry>(
      JSObject::New(finalization_registry_fun, finalization_registry_fun,
                    Handle<AllocationSite>::null())
          .ToHandleChecked());

  // JSObject::New filled all of the internal fields with undefined. Some of
  // them have more restrictive types, so set those now.
  finalization_registry->set_native_context(*isolate->native_context());
  finalization_registry->set_cleanup(
      isolate->native_context()->empty_function());
  finalization_registry->set_flags(0);

#ifdef VERIFY_HEAP
  finalization_registry->JSFinalizationRegistryVerify(isolate);
#endif  // VERIFY_HEAP
  return finalization_registry;
}

Handle<JSWeakRef> ConstructJSWeakRef(DirectHandle<JSReceiver> target,
                                     Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<String> weak_ref_name = factory->WeakRef_string();
  Handle<JSGlobalObject> global =
      handle(isolate->native_context()->global_object(), isolate);
  Handle<JSFunction> weak_ref_fun = Cast<JSFunction>(
      Object::GetProperty(isolate, global, weak_ref_name).ToHandleChecked());
  auto weak_ref = Cast<JSWeakRef>(
      JSObject::New(weak_ref_fun, weak_ref_fun, Handle<AllocationSite>::null())
          .ToHandleChecked());
  weak_ref->set_target(*target);
#ifdef VERIFY_HEAP
  weak_ref->JSWeakRefVerify(isolate);
#endif  // VERIFY_HEAP
  return weak_ref;
}

Handle<JSObject> CreateKey(const char* key_prop_value, Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<String> key_string = factory->NewStringFromStaticChars("key_string");
  Handle<JSObject> key =
      isolate->factory()->NewJSObject(isolate->object_function());
  JSObject::AddProperty(isolate, key, key_string,
                        factory->NewStringFromAsciiChecked(key_prop_value),
                        NONE);
  return key;
}

Handle<WeakCell> FinalizationRegistryRegister(
    Handle<JSFinalizationRegistry> finalization_registry,
    Handle<JSObject> target, Handle<Object> held_value,
    Handle<Object> unregister_token, Isolate* isolate) {
  Factory* factory = isolate->factory();
  Handle<JSFunction> regfunc = Cast<JSFunction>(
      Object::GetProperty(isolate, finalization_registry,
                          factory->NewStringFromStaticChars("register"))
          .ToHandleChecked());
  Handle<Object> args[] = {target, held_value, unregister_token};
  Execution::Call(isolate, regfunc, finalization_registry, arraysize(args),
                  args)
      .ToHandleChecked();
  CHECK(IsWeakCell(finalization_registry->active_cells()));
  Handle<WeakCell> weak_cell =
      handle(Cast<WeakCell>(finalization_registry->active_cells()), isolate);
#ifdef VERIFY_HEAP
  weak_cell->WeakCellVerify(isolate);
#endif  // VERIFY_HEAP
  return weak_cell;
}

Handle<WeakCell> FinalizationRegistryRegister(
    Handle<JSFinalizationRegistry> finalization_registry,
    Handle<JSObject> target, Isolate* isolate) {
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);
  return FinalizationRegistryRegister(finalization_registry, target, undefined,
                                      undefined, isolate);
}

void NullifyWeakCell(DirectHandle<WeakCell> weak_cell, Isolate* isolate) {
  auto empty_func = [](Tagged<HeapObject> object, ObjectSlot slot,
                       Tagged<Object> target) {};
  weak_cell->Nullify(isolate, empty_func);
#ifdef VERIFY_HEAP
  weak_cell->WeakCellVerify(isolate);
#endif  // VERIFY_HEAP
}

Tagged<Object> PopClearedCellHoldings(
    DirectHandle<JSFinalizationRegistry> finalization_registry,
    Isolate* isolate) {
  // PopClearedCell is implemented in Torque. Reproduce that implementation here
  // for testing.
  DirectHandle<WeakCell> weak_cell(
      Cast<WeakCell>(finalization_registry->cleared_cells()), isolate);
  DCHECK(IsUndefined(weak_cell->prev(), isolate));
  finalization_registry->set_cleared_cells(weak_cell->next());
  weak_cell->set_next(ReadOnlyRoots(isolate).undefined_value());

  if (IsWeakCell(finalization_registry->cleared_cells())) {
    Tagged<WeakCell> cleared_cells_head =
        Cast<WeakCell>(finalization_registry->cleared_cells());
    DCHECK_EQ(cleared_cells_head->prev(), *weak_cell);
    cleared_cells_head->set_prev(ReadOnlyRoots(isolate).undefined_value());
  } else {
    DCHECK(IsUndefined(finalization_registry->cleared_cells(), isolate));
  }

  if (!IsUndefined(weak_cell->unregister_token(), isolate)) {
    JSFinalizationRegistry::RemoveCellFromUnregisterTokenMap(
        isolate, finalization_registry->ptr(), weak_cell->ptr());
  }

  return weak_cell->holdings();
}

// Usage: VerifyWeakCellChain(isolate, list_head, n, cell1, cell2, ..., celln);
// verifies that list_head == cell1 and cell1, cell2, ..., celln. form a list.
void VerifyWeakCellChain(Isolate* isolate, Tagged<Object> list_head, int n_args,
                         ...) {
  CHECK_GE(n_args, 0);

  va_list args;
  va_start(args, n_args);

  if (n_args == 0) {
    // Verify empty list
    CHECK(IsUndefined(list_head, isolate));
  } else {
    Tagged<WeakCell> current =
        Cast<WeakCell>(Tagged<Object>(va_arg(args, Address)));
    CHECK_EQ(current, list_head);
    CHECK(IsUndefined(current->prev(), isolate));

    for (int i = 1; i < n_args; i++) {
      Tagged<WeakCell> next =
          Cast<WeakCell>(Tagged<Object>(va_arg(args, Address)));
      CHECK_EQ(current->next(), next);
      CHECK_EQ(next->prev(), current);
      current = next;
    }
    CHECK(IsUndefined(current->next(), isolate));
  }
  va_end(args);
}

// Like VerifyWeakCellChain but verifies the chain created with key_list_prev
// and key_list_next instead of prev and next.
void VerifyWeakCellKeyChain(Isolate* isolate,
                            Tagged<SimpleNumberDictionary> key_map,
                            Tagged<Object> unregister_token, int n_args, ...) {
  CHECK_GE(n_args, 0);

  va_list args;
  va_start(args, n_args);

  Tagged<Object> hash = Object::GetHash(unregister_token);
  InternalIndex entry = InternalIndex::NotFound();
  if (!IsUndefined(hash, isolate)) {
    uint32_t key = Smi::ToInt(hash);
    entry = key_map->FindEntry(isolate, key);
  }
  if (n_args == 0) {
    // Verify empty list
    CHECK(entry.is_not_found());
  } else {
    CHECK(entry.is_found());
    Tagged<WeakCell> current =
        Cast<WeakCell>(Tagged<Object>(va_arg(args, Address)));
    Tagged<Object> list_head = key_map->ValueAt(entry);
    CHECK_EQ(current, list_head);
    CHECK(IsUndefined(current->key_list_prev(), isolate));

    for (int i = 1; i < n_args; i++) {
      Tagged<WeakCell> next =
          Cast<WeakCell>(Tagged<Object>(va_arg(args, Address)));
      CHECK_EQ(current->key_list_next(), next);
      CHECK_EQ(next->key_list_prev(), current);
      current = next;
    }
    CHECK(IsUndefined(current->key_list_next(), isolate));
  }
  va_end(args);
}

Handle<JSWeakRef> MakeWeakRefAndKeepDuringJob(Isolate* isolate) {
  HandleScope inner_scope(isolate);

  DirectHandle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());
  Handle<JSWeakRef> inner_weak_ref = ConstructJSWeakRef(js_object, isolate);
  isolate->heap()->KeepDuringJob(js_object);

  return inner_scope.CloseAndEscape(inner_weak_ref);
}

}  // namespace

TEST(TestRegister) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  // Register a weak reference and verify internal data structures.
  DirectHandle<WeakCell> weak_cell1 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 1,
                      *weak_cell1);
  CHECK(IsUndefined(weak_cell1->key_list_prev(), isolate));
  CHECK(IsUndefined(weak_cell1->key_list_next(), isolate));

  CHECK(IsUndefined(finalization_registry->cleared_cells(), isolate));

  // No key was used during registration, key-based map stays uninitialized.
  CHECK(IsUndefined(finalization_registry->key_map(), isolate));

  // Register another weak reference and verify internal data structures.
  DirectHandle<WeakCell> weak_cell2 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 2,
                      *weak_cell2, *weak_cell1);
  CHECK(IsUndefined(weak_cell2->key_list_prev(), isolate));
  CHECK(IsUndefined(weak_cell2->key_list_next(), isolate));

  CHECK(IsUndefined(finalization_registry->cleared_cells(), isolate));
  CHECK(IsUndefined(finalization_registry->key_map(), isolate));
}

TEST(TestRegisterWithKey) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<JSObject> token2 = CreateKey("token2", isolate);
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  // Register a weak reference with a key and verify internal data structures.
  DirectHandle<WeakCell> weak_cell1 = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 1, *weak_cell1);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 0);
  }

  // Register another weak reference with a different key and verify internal
  // data structures.
  DirectHandle<WeakCell> weak_cell2 = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);

  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 1, *weak_cell1);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 1, *weak_cell2);
  }

  // Register another weak reference with token1 and verify internal data
  // structures.
  DirectHandle<WeakCell> weak_cell3 = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell3,
                           *weak_cell1);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 1, *weak_cell2);
  }
}

TEST(TestWeakCellNullify1) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  DirectHandle<WeakCell> weak_cell1 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);
  DirectHandle<WeakCell> weak_cell2 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);

  // Nullify the first WeakCell and verify internal data structures.
  NullifyWeakCell(weak_cell1, isolate);
  CHECK_EQ(finalization_registry->active_cells(), *weak_cell2);
  CHECK(IsUndefined(weak_cell2->prev(), isolate));
  CHECK(IsUndefined(weak_cell2->next(), isolate));
  CHECK_EQ(finalization_registry->cleared_cells(), *weak_cell1);
  CHECK(IsUndefined(weak_cell1->prev(), isolate));
  CHECK(IsUndefined(weak_cell1->next(), isolate));

  // Nullify the second WeakCell and verify internal data structures.
  NullifyWeakCell(weak_cell2, isolate);
  CHECK(IsUndefined(finalization_registry->active_cells(), isolate));
  CHECK_EQ(finalization_registry->cleared_cells(), *weak_cell2);
  CHECK_EQ(weak_cell2->next(), *weak_cell1);
  CHECK(IsUndefined(weak_cell2->prev(), isolate));
  CHECK_EQ(weak_cell1->prev(), *weak_cell2);
  CHECK(IsUndefined(weak_cell1->next(), isolate));
}

TEST(TestWeakCellNullify2) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  DirectHandle<WeakCell> weak_cell1 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);
  DirectHandle<WeakCell> weak_cell2 =
      FinalizationRegistryRegister(finalization_registry, js_object, isolate);

  // Like TestWeakCellNullify1 but nullify the WeakCells in opposite order.
  NullifyWeakCell(weak_cell2, isolate);
  CHECK_EQ(finalization_registry->active_cells(), *weak_cell1);
  CHECK(IsUndefined(weak_cell1->prev(), isolate));
  CHECK(IsUndefined(weak_cell1->next(), isolate));
  CHECK_EQ(finalization_registry->cleared_cells(), *weak_cell2);
  CHECK(IsUndefined(weak_cell2->prev(), isolate));
  CHECK(IsUndefined(weak_cell2->next(), isolate));

  NullifyWeakCell(weak_cell1, isolate);
  CHECK(IsUndefined(finalization_registry->active_cells(), isolate));
  CHECK_EQ(finalization_registry->cleared_cells(), *weak_cell1);
  CHECK_EQ(weak_cell1->next(), *weak_cell2);
  CHECK(IsUndefined(weak_cell1->prev(), isolate));
  CHECK_EQ(weak_cell2->prev(), *weak_cell1);
  CHECK(IsUndefined(weak_cell2->next(), isolate));
}

TEST(TestJSFinalizationRegistryPopClearedCellHoldings1) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  Handle<Object> holdings1 = factory->NewStringFromAsciiChecked("holdings1");
  DirectHandle<WeakCell> weak_cell1 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings1, undefined, isolate);
  Handle<Object> holdings2 = factory->NewStringFromAsciiChecked("holdings2");
  DirectHandle<WeakCell> weak_cell2 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings2, undefined, isolate);
  Handle<Object> holdings3 = factory->NewStringFromAsciiChecked("holdings3");
  DirectHandle<WeakCell> weak_cell3 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings3, undefined, isolate);

  NullifyWeakCell(weak_cell2, isolate);
  NullifyWeakCell(weak_cell3, isolate);

  CHECK(finalization_registry->NeedsCleanup());
  Tagged<Object> cleared1 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared1, *holdings3);
  CHECK(IsUndefined(weak_cell3->prev(), isolate));
  CHECK(IsUndefined(weak_cell3->next(), isolate));

  CHECK(finalization_registry->NeedsCleanup());
  Tagged<Object> cleared2 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared2, *holdings2);
  CHECK(IsUndefined(weak_cell2->prev(), isolate));
  CHECK(IsUndefined(weak_cell2->next(), isolate));

  CHECK(!finalization_registry->NeedsCleanup());

  NullifyWeakCell(weak_cell1, isolate);

  CHECK(finalization_registry->NeedsCleanup());
  Tagged<Object> cleared3 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared3, *holdings1);
  CHECK(IsUndefined(weak_cell1->prev(), isolate));
  CHECK(IsUndefined(weak_cell1->next(), isolate));

  CHECK(!finalization_registry->NeedsCleanup());
  CHECK(IsUndefined(finalization_registry->active_cells(), isolate));
  CHECK(IsUndefined(finalization_registry->cleared_cells(), isolate));
}

TEST(TestJSFinalizationRegistryPopClearedCellHoldings2) {
  // Test that when all WeakCells for a key are popped, the key is removed from
  // the key map.
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());
  Handle<JSObject> token1 = CreateKey("token1", isolate);

  Handle<Object> holdings1 = factory->NewStringFromAsciiChecked("holdings1");
  DirectHandle<WeakCell> weak_cell1 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings1, token1, isolate);
  Handle<Object> holdings2 = factory->NewStringFromAsciiChecked("holdings2");
  DirectHandle<WeakCell> weak_cell2 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings2, token1, isolate);

  NullifyWeakCell(weak_cell1, isolate);
  NullifyWeakCell(weak_cell2, isolate);

  // Nullifying doesn't affect the key chains (just moves WeakCells from
  // active_cells to cleared_cells).
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell2,
                           *weak_cell1);
  }

  Tagged<Object> cleared1 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared1, *holdings2);

  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 1, *weak_cell1);
  }

  Tagged<Object> cleared2 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared2, *holdings1);

  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
  }
}

TEST(TestUnregisterActiveCells) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<JSObject> token2 = CreateKey("token2", isolate);
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  DirectHandle<WeakCell> weak_cell1a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);
  DirectHandle<WeakCell> weak_cell1b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  DirectHandle<WeakCell> weak_cell2a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);
  DirectHandle<WeakCell> weak_cell2b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 4,
                      *weak_cell2b, *weak_cell2a, *weak_cell1b, *weak_cell1a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell1b,
                           *weak_cell1a);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 2, *weak_cell2b,
                           *weak_cell2a);
  }

  JSFinalizationRegistry::Unregister(finalization_registry, token1, isolate);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 2, *weak_cell2b,
                           *weak_cell2a);
  }

  // Both weak_cell1a and weak_cell1b removed from active_cells.
  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 2,
                      *weak_cell2b, *weak_cell2a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
}

TEST(TestUnregisterActiveAndClearedCells) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<JSObject> token2 = CreateKey("token2", isolate);
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  DirectHandle<WeakCell> weak_cell1a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);
  DirectHandle<WeakCell> weak_cell1b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  DirectHandle<WeakCell> weak_cell2a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);
  DirectHandle<WeakCell> weak_cell2b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);

  NullifyWeakCell(weak_cell2a, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 3,
                      *weak_cell2b, *weak_cell1b, *weak_cell1a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 1,
                      *weak_cell2a);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell1b,
                           *weak_cell1a);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 2, *weak_cell2b,
                           *weak_cell2a);
  }

  JSFinalizationRegistry::Unregister(finalization_registry, token2, isolate);

  // Both weak_cell2a and weak_cell2b removed.
  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 2,
                      *weak_cell1b, *weak_cell1a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell1b,
                           *weak_cell1a);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 0);
  }
}

TEST(TestWeakCellUnregisterTwice) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<Object> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  DirectHandle<WeakCell> weak_cell1 = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 1,
                      *weak_cell1);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 1, *weak_cell1);
  }

  JSFinalizationRegistry::Unregister(finalization_registry, token1, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 0);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
  }

  JSFinalizationRegistry::Unregister(finalization_registry, token1, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 0);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
  }
}

TEST(TestWeakCellUnregisterPopped) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  Factory* factory = isolate->factory();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());
  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<Object> holdings1 = factory->NewStringFromAsciiChecked("holdings1");
  DirectHandle<WeakCell> weak_cell1 = FinalizationRegistryRegister(
      finalization_registry, js_object, holdings1, token1, isolate);

  NullifyWeakCell(weak_cell1, isolate);

  CHECK(finalization_registry->NeedsCleanup());
  Tagged<Object> cleared1 =
      PopClearedCellHoldings(finalization_registry, isolate);
  CHECK_EQ(cleared1, *holdings1);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 0);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
  }

  JSFinalizationRegistry::Unregister(finalization_registry, token1, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 0);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 0);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 0);
  }
}

TEST(TestWeakCellUnregisterNonexistentKey) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  DirectHandle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  DirectHandle<JSObject> token1 = CreateKey("token1", isolate);

  JSFinalizationRegistry::Unregister(finalization_registry, token1, isolate);
}

TEST(TestJSWeakRef) {
  CcTest::InitializeVM();
  LocalContext context;

  Isolate* isolate = CcTest::i_isolate();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());
  HandleScope outer_scope(isolate);
  IndirectHandle<JSWeakRef> weak_ref;
  {
    HandleScope inner_scope(isolate);

    IndirectHandle<JSObject> js_object =
        isolate->factory()->NewJSObject(isolate->object_function());
    // This doesn't add the target into the KeepDuringJob set.
    IndirectHandle<JSWeakRef> inner_weak_ref =
        ConstructJSWeakRef(js_object, isolate);

    heap::InvokeMajorGC(CcTest::heap());
    CHECK(!IsUndefined(inner_weak_ref->target(), isolate));

    weak_ref = inner_scope.CloseAndEscape(inner_weak_ref);
  }

  CHECK(!IsUndefined(weak_ref->target(), isolate));

  heap::InvokeMajorGC(CcTest::heap());

  CHECK(IsUndefined(weak_ref->target(), isolate));
}

TEST(TestJSWeakRefIncrementalMarking) {
  if (!v8_flags.incremental_marking) {
    return;
  }
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext context;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  HandleScope outer_scope(isolate);
  IndirectHandle<JSWeakRef> weak_ref;
  {
    HandleScope inner_scope(isolate);

    IndirectHandle<JSObject> js_object =
        isolate->factory()->NewJSObject(isolate->object_function());
    // This doesn't add the target into the KeepDuringJob set.
    IndirectHandle<JSWeakRef> inner_weak_ref =
        ConstructJSWeakRef(js_object, isolate);

    heap::SimulateIncrementalMarking(heap, true);
    heap::InvokeMajorGC(heap);
    CHECK(!IsUndefined(inner_weak_ref->target(), isolate));

    weak_ref = inner_scope.CloseAndEscape(inner_weak_ref);
  }

  CHECK(!IsUndefined(weak_ref->target(), isolate));

  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);

  CHECK(IsUndefined(weak_ref->target(), isolate));
}

TEST(TestJSWeakRefKeepDuringJob) {
  CcTest::InitializeVM();
  LocalContext context;

  Isolate* isolate = CcTest::i_isolate();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  HandleScope outer_scope(isolate);
  IndirectHandle<JSWeakRef> weak_ref = MakeWeakRefAndKeepDuringJob(isolate);
  CHECK(!IsUndefined(weak_ref->target(), isolate));
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(!IsUndefined(weak_ref->target(), isolate));

  // Clears the KeepDuringJob set.
  context->GetIsolate()->ClearKeptObjects();
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(IsUndefined(weak_ref->target(), isolate));

  weak_ref = MakeWeakRefAndKeepDuringJob(isolate);
  CHECK(!IsUndefined(weak_ref->target(), isolate));
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(!IsUndefined(weak_ref->target(), isolate));

  // ClearKeptObjects should be called by PerformMicrotasksCheckpoint.
  CcTest::isolate()->PerformMicrotaskCheckpoint();
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(IsUndefined(weak_ref->target(), isolate));

  weak_ref = MakeWeakRefAndKeepDuringJob(isolate);
  CHECK(!IsUndefined(weak_ref->target(), isolate));
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(!IsUndefined(weak_ref->target(), isolate));

  // ClearKeptObjects should be called by MicrotasksScope::PerformCheckpoint.
  v8::MicrotasksScope::PerformCheckpoint(CcTest::isolate());
  heap::InvokeMajorGC(CcTest::heap());
  CHECK(IsUndefined(weak_ref->target(), isolate));
}

TEST(TestJSWeakRefKeepDuringJobIncrementalMarking) {
  if (!v8_flags.incremental_marking) {
    return;
  }
  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext context;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  HandleScope outer_scope(isolate);
  IndirectHandle<JSWeakRef> weak_ref = MakeWeakRefAndKeepDuringJob(isolate);

  CHECK(!IsUndefined(weak_ref->target(), isolate));

  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);

  CHECK(!IsUndefined(weak_ref->target(), isolate));

  // Clears the KeepDuringJob set.
  context->GetIsolate()->ClearKeptObjects();
  heap::SimulateIncrementalMarking(heap, true);
  heap::InvokeMajorGC(heap);

  CHECK(IsUndefined(weak_ref->target(), isolate));
}

TEST(TestRemoveUnregisterToken) {
  CcTest::InitializeVM();
  LocalContext context;
  Isolate* isolate = CcTest::i_isolate();
  HandleScope outer_scope(isolate);
  Handle<JSFinalizationRegistry> finalization_registry =
      ConstructJSFinalizationRegistry(isolate);
  Handle<JSObject> js_object =
      isolate->factory()->NewJSObject(isolate->object_function());

  Handle<JSObject> token1 = CreateKey("token1", isolate);
  Handle<JSObject> token2 = CreateKey("token2", isolate);
  Handle<HeapObject> undefined =
      handle(ReadOnlyRoots(isolate).undefined_value(), isolate);

  DirectHandle<WeakCell> weak_cell1a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);
  DirectHandle<WeakCell> weak_cell1b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token1, isolate);

  DirectHandle<WeakCell> weak_cell2a = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);
  DirectHandle<WeakCell> weak_cell2b = FinalizationRegistryRegister(
      finalization_registry, js_object, undefined, token2, isolate);

  NullifyWeakCell(weak_cell2a, isolate);

  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 3,
                      *weak_cell2b, *weak_cell1b, *weak_cell1a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 1,
                      *weak_cell2a);
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell1b,
                           *weak_cell1a);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 2, *weak_cell2b,
                           *weak_cell2a);
  }

  finalization_registry->RemoveUnregisterToken(
      Cast<JSReceiver>(*token2), isolate,
      JSFinalizationRegistry::kKeepMatchedCellsInRegistry,
      [](Tagged<HeapObject>, ObjectSlot, Tagged<Object>) {});

  // Both weak_cell2a and weak_cell2b remain on the weak cell chains.
  VerifyWeakCellChain(isolate, finalization_registry->active_cells(), 3,
                      *weak_cell2b, *weak_cell1b, *weak_cell1a);
  VerifyWeakCellChain(isolate, finalization_registry->cleared_cells(), 1,
                      *weak_cell2a);

  // But both weak_cell2a and weak_cell2b are removed from the key chain.
  {
    Tagged<SimpleNumberDictionary> key_map =
        Cast<SimpleNumberDictionary>(finalization_registry->key_map());
    VerifyWeakCellKeyChain(isolate, key_map, *token1, 2, *weak_cell1b,
                           *weak_cell1a);
    VerifyWeakCellKeyChain(isolate, key_map, *token2, 0);
  }
}

TEST(JSWeakRefScavengedInWorklist) {
  if (!v8_flags.incremental_marking || v8_flags.single_generation) {
    return;
  }

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

  {
    HandleScope outer_scope(isolate);
    IndirectHandle<JSWeakRef> weak_ref;

    // Make a WeakRef that points to a target, both of which become unreachable.
    {
      HandleScope inner_scope(isolate);
      IndirectHandle<JSObject> js_object =
          isolate->factory()->NewJSObject(isolate->object_function());
      IndirectHandle<JSWeakRef> inner_weak_ref =
          ConstructJSWeakRef(js_object, isolate);
      CHECK(HeapLayout::InYoungGeneration(*js_object));
      CHECK(HeapLayout::InYoungGeneration(*inner_weak_ref));

      weak_ref = inner_scope.CloseAndEscape(inner_weak_ref);
    }

    // Store weak_ref in Global such that it is part of the root set when
    // starting incremental marking.
    v8::Global<Value> global_weak_ref(CcTest::isolate(),
                                      Utils::ToLocal(Cast<Object>(weak_ref)));

    // Do marking. This puts the WeakRef above into the js_weak_refs worklist
    // since its target isn't marked.
    CHECK(
        heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());
    heap::SimulateIncrementalMarking(heap, true);
    heap->mark_compact_collector()->local_weak_objects()->Publish();
    CHECK(!heap->mark_compact_collector()
               ->weak_objects()
               ->js_weak_refs.IsEmpty());
  }

  // Now collect both weak_ref and its target. The worklist should be empty.
  heap::InvokeMinorGC(heap);
  CHECK(heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());

  // The mark-compactor shouldn't see zapped WeakRefs in the worklist.
  heap::InvokeMajorGC(heap);
}

TEST(JSWeakRefTenuredInWorklist) {
  if (!v8_flags.incremental_marking || v8_flags.single_generation ||
      v8_flags.separate_gc_phases) {
    return;
  }

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

  HandleScope outer_scope(isolate);
  IndirectHandle<JSWeakRef> weak_ref;

  // Make a WeakRef that points to a target. The target becomes unreachable.
  {
    HandleScope inner_scope(isolate);
    IndirectHandle<JSObject> js_object =
        isolate->factory()->NewJSObject(isolate->object_function());
    IndirectHandle<JSWeakRef> inner_weak_ref =
        ConstructJSWeakRef(js_object, isolate);
    CHECK(HeapLayout::InYoungGeneration(*js_object));
    CHECK(HeapLayout::InYoungGeneration(*inner_weak_ref));

    weak_ref = inner_scope.CloseAndEscape(inner_weak_ref);
  }
  // Store weak_ref such that it is part of the root set when starting
  // incremental marking.
  v8::Global<Value> global_weak_ref(CcTest::isolate(),
                                    Utils::ToLocal(Cast<Object>(weak_ref)));
  Address old_weak_ref_location = weak_ref->address();

  // Do marking. This puts the WeakRef above into the js_weak_refs worklist
  // since its target isn't marked.
  CHECK(heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());
  heap::SimulateIncrementalMarking(heap, true);
  heap->mark_compact_collector()->local_weak_objects()->Publish();
  CHECK(
      !heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());

  // Now collect weak_ref's target. We still have a Handle to weak_ref, so it is
  // moved and remains on the worklist.
  heap::InvokeMinorGC(heap);
  Address new_weak_ref_location = weak_ref->address();
  CHECK_NE(old_weak_ref_location, new_weak_ref_location);
  CHECK(
      !heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());

  // The mark-compactor should see the moved WeakRef in the worklist.
  heap::InvokeMajorGC(heap);
  CHECK(heap->mark_compact_collector()->weak_objects()->js_weak_refs.IsEmpty());
  CHECK(IsUndefined(weak_ref->target(), isolate));
}

TEST(UnregisterTokenHeapVerifier) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
#ifdef VERIFY_HEAP
  v8_flags.verify_heap = true;
#endif

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  v8::HandleScope outer_scope(isolate);

  {
    // Make a new FinalizationRegistry and register two objects with the same
    // unregister token that's unreachable after the IIFE returns.
    v8::HandleScope scope(isolate);
    CompileRun(
        "var token = {}; "
        "var registry = new FinalizationRegistry(function ()  {}); "
        "(function () { "
        "  let o1 = {}; "
        "  let o2 = {}; "
        "  registry.register(o1, {}, token); "
        "  registry.register(o2, {}, token); "
        "})();");
  }

  // GC so the WeakCell corresponding to o is moved from the active_cells to
  // cleared_cells.
  heap::InvokeMajorGC(heap);
  heap::InvokeMajorGC(heap);

  {
    // Override the unregister token to make the original object collectible.
    v8::HandleScope scope(isolate);
    CompileRun("token = 0;");
  }

  heap::SimulateIncrementalMarking(heap, true);

  // Pump message loop to run the finalizer task, then the incremental marking
  // task. The finalizer task will pop the WeakCell from the cleared list. This
  // should make the unregister_token slot undefined. That slot is iterated as a
  // custom weak pointer, so if it is not made undefined, the verifier as part
  // of the incremental marking task will crash.
  EmptyMessageQueues(isolate);
}

TEST(UnregisteredAndUnclearedCellHeapVerifier) {
  if (!v8_flags.incremental_marking) return;
  ManualGCScope manual_gc_scope;
#ifdef VERIFY_HEAP
  v8_flags.verify_heap = true;
#endif

  CcTest::InitializeVM();
  v8::Isolate* isolate = CcTest::isolate();
  Heap* heap = CcTest::heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
  v8::HandleScope outer_scope(isolate);

  {
    // Make a new FinalizationRegistry and register an object with a token.
    v8::HandleScope scope(isolate);
    CompileRun(
        "var token = {}; "
        "var registry = new FinalizationRegistry(function () {}); "
        "registry.register({}, undefined, token);");
  }

  // Start incremental marking to activate the marking barrier.
  heap::SimulateIncrementalMarking(heap, false);

  {
    // Make a WeakCell list with length >1, then unregister with the token to
    // the WeakCell from the registry. The linked list manipulation keeps the
    // unregistered WeakCell alive (i.e. not put into cleared_cells) due to the
    // marking barrier from incremental marking. Then make the original token
    // collectible.
    v8::HandleScope scope(isolate);
    CompileRun(
        "registry.register({}); "
        "registry.unregister(token); "
        "token = 0;");
  }

  // Trigger GC.
  heap::InvokeMajorGC(heap);
  heap::InvokeMajorGC(heap);

  // Pump message loop to run the finalizer task, then the incremental marking
  // task. The verifier will verify that live WeakCells don't point to dead
  // unregister tokens.
  EmptyMessageQueues(isolate);
}

}  // namespace internal
}  // namespace v8

"""

```
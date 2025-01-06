Response:
The user wants a summary of the C++ code provided, specifically the file `v8/test/cctest/test-js-weak-refs.cc`.

Here's a breakdown of the request and how to address it:

1. **List the functionalities:** I need to go through the code and identify the core actions and concepts being tested. This involves looking at the test names (`TEST(...)`) and the helper functions defined.
2. **`.tq` check:**  I need to confirm if the filename ends in `.tq`. In this case, it ends in `.cc`, so this is not a Torque file.
3. **JavaScript relationship and examples:** Since the file deals with `JSWeakRef` and `JSFinalizationRegistry`, which are related to JavaScript's WeakRef and FinalizationRegistry, I need to provide JavaScript examples demonstrating their usage.
4. **Code logic and examples:**  The C++ code includes tests with assertions. I need to identify the logic being tested and create hypothetical inputs and expected outputs for those tests.
5. **Common programming errors:**  I need to think about how developers might misuse WeakRef and FinalizationRegistry in JavaScript and provide illustrative examples.
6. **Summarize the functionality (Part 1):** I need to synthesize the above points into a concise summary of what the code does.

**Mental Sandbox:**

* **Functionality Identification:** The code defines helper functions for constructing `JSFinalizationRegistry` and `JSWeakRef`, registering objects with finalization, nullifying weak cells, and unregistering objects. The tests focus on verifying the internal state and behavior of these mechanisms during registration, nullification, and unregistration, both with and without unregister tokens. There are also tests related to garbage collection behavior for `JSWeakRef`.
* **`.tq` Check:** Straightforward file extension check.
* **JavaScript Examples:**  I can use the standard `WeakRef` and `FinalizationRegistry` APIs in JavaScript to illustrate the concepts.
* **Code Logic Examples:** I can pick a simple test case, like `TestRegister`, and explain what the setup is (registering weak refs), the action (registration), and the verification (checking the linked list of weak cells).
* **Common Errors:**  For `WeakRef`, a common error is accessing the `.deref()` method without checking for `undefined`. For `FinalizationRegistry`, forgetting to handle the cleanup callback correctly or misunderstanding when it will be called are potential issues.
* **Summary (Part 1):**  Focus on the core purpose: testing the implementation of JavaScript's weak references and finalization registries within the V8 engine.

Strategizing complete. I will now generate the response following these steps.
这是对 V8 引擎中关于 JavaScript 弱引用 (`JSWeakRef`) 和终结器注册 (`JSFinalizationRegistry`) 功能进行单元测试的 C++ 代码。

**功能列举:**

1. **`ConstructJSFinalizationRegistry(Isolate* isolate)`:**  创建一个 `JSFinalizationRegistry` 对象的辅助函数。它模拟了在 JavaScript 中创建 `FinalizationRegistry` 实例的过程。
2. **`ConstructJSWeakRef(DirectHandle<JSReceiver> target, Isolate* isolate)`:** 创建一个 `JSWeakRef` 对象的辅助函数。它模拟了在 JavaScript 中创建 `WeakRef` 实例的过程。
3. **`CreateKey(const char* key_prop_value, Isolate* isolate)`:** 创建一个用于 `FinalizationRegistry` 注册的键对象的辅助函数。
4. **`FinalizationRegistryRegister(...)` (两个重载版本):**  模拟 `FinalizationRegistry.register()` 方法，将目标对象、保持的值（可选）和取消注册令牌（可选）注册到终结器注册表中。
5. **`NullifyWeakCell(DirectHandle<WeakCell> weak_cell, Isolate* isolate)`:**  模拟弱引用目标对象被垃圾回收，从而将 `WeakCell` 标记为需要清理。
6. **`PopClearedCellHoldings(...)`:** 模拟从 `FinalizationRegistry` 的已清理单元列表中弹出一个单元，并返回其保持的值。这对应于终结器回调被调用的过程。
7. **`VerifyWeakCellChain(...)`:**  一个辅助函数，用于验证 `FinalizationRegistry` 中活跃 `WeakCell` 构成的链表的结构是否正确。
8. **`VerifyWeakCellKeyChain(...)`:** 一个辅助函数，用于验证使用取消注册令牌注册的 `WeakCell` 在键映射表中构成的链表的结构是否正确。
9. **`MakeWeakRefAndKeepDuringJob(Isolate* isolate)`:**  创建一个 `JSWeakRef`，并在当前作业期间保持其目标对象不被垃圾回收。这用于测试 `WeakRef` 在微任务中的行为。
10. **`TEST(TestRegister)`:** 测试基本的 `FinalizationRegistry.register()` 功能，不带取消注册令牌。
11. **`TEST(TestRegisterWithKey)`:** 测试使用取消注册令牌的 `FinalizationRegistry.register()` 功能。
12. **`TEST(TestWeakCellNullify1)` 和 `TEST(TestWeakCellNullify2)`:** 测试 `WeakCell` 被标记为需要清理后的内部链表状态变化。
13. **`TEST(TestJSFinalizationRegistryPopClearedCellHoldings1)` 和 `TEST(TestJSFinalizationRegistryPopClearedCellHoldings2)`:** 测试从已清理单元列表中弹出保持的值的功能。
14. **`TEST(TestUnregisterActiveCells)` 和 `TEST(TestUnregisterActiveAndClearedCells)`:** 测试 `FinalizationRegistry.unregister()` 方法，移除活跃或已清理的注册项。
15. **`TEST(TestWeakCellUnregisterTwice)`:** 测试多次调用 `FinalizationRegistry.unregister()` 的行为。
16. **`TEST(TestWeakCellUnregisterPopped)`:** 测试取消注册已经清理过的注册项的行为。
17. **`TEST(TestWeakCellUnregisterNonexistentKey)`:** 测试使用不存在的键取消注册的行为。
18. **`TEST(TestJSWeakRef)`:** 测试基本的 `WeakRef` 功能，验证在垃圾回收后目标对象是否变为 `undefined`。
19. **`TEST(TestJSWeakRefIncrementalMarking)`:** 在增量标记垃圾回收期间测试 `WeakRef` 的行为。
20. **`TEST(TestJSWeakRefKeepDuringJob)` 和 `TEST(TestJSWeakRefKeepDuringJobIncrementalMarking)`:** 测试 `WeakRef` 目标对象在微任务期间被保留的情况。
21. **`TEST(TestRemoveUnregisterToken)`:**  (代码片段未完整，但从名称判断) 可能是测试移除取消注册令牌的相关功能。

**关于 `.tq` 结尾:**

`v8/test/cctest/test-js-weak-refs.cc` 的文件名以 `.cc` 结尾，这表明它是一个 **C++** 源代码文件，而不是 Torque (`.tq`) 文件。 Torque 是一种 V8 特定的领域特定语言，用于实现 JavaScript 的内置功能。

**与 JavaScript 的关系及举例:**

这段 C++ 代码测试的是 V8 引擎中 `WeakRef` 和 `FinalizationRegistry` 的底层实现。这两个特性在 JavaScript 中可以直接使用：

**JavaScript 弱引用 (`WeakRef`):**

```javascript
let target = { value: 'some data' };
let weakRef = new WeakRef(target);

// 在 target 没有被垃圾回收之前，可以通过 .deref() 获取目标对象
console.log(weakRef.deref()?.value); // 输出: some data

target = null; // 解除对 target 的强引用

// 在垃圾回收之后，.deref() 可能会返回 undefined
// 何时垃圾回收是不确定的
setTimeout(() => {
  console.log(weakRef.deref()?.value); // 可能输出: undefined
}, 1000);
```

**JavaScript 终结器注册 (`FinalizationRegistry`):**

```javascript
let target = { name: 'object to track' };
let registry = new FinalizationRegistry(heldValue => {
  console.log('Target was garbage collected, held value:', heldValue);
});

registry.register(target, 'some extra info');

// 解除对 target 的强引用
target = null;

// 当 target 被垃圾回收时，终结器回调函数会被调用，并传入 'some extra info'
```

**代码逻辑推理及假设输入与输出:**

以 `TEST(TestRegister)` 为例：

**假设输入:**

1. 创建一个 `Isolate` 实例。
2. 创建一个 `JSFinalizationRegistry` 实例。
3. 创建一个普通的 `JSObject` 实例作为目标对象。

**代码逻辑:**

1. 调用 `FinalizationRegistryRegister` 将目标对象注册到终结器注册表中（不带取消注册令牌）。
2. 使用 `VerifyWeakCellChain` 验证 `finalization_registry->active_cells()` 链表中只有一个 `WeakCell`，并且这个 `WeakCell` 就是刚刚注册的那个。
3. 验证该 `WeakCell` 的 `key_list_prev` 和 `key_list_next` 都是 `undefined`，因为没有使用取消注册令牌。
4. 验证 `finalization_registry->cleared_cells()` 是 `undefined`，因为还没有对象被垃圾回收。
5. 验证 `finalization_registry->key_map()` 是 `undefined`，因为没有使用取消注册令牌。
6. 再次注册另一个目标对象。
7. 再次使用 `VerifyWeakCellChain` 验证 `active_cells()` 链表中现在有两个 `WeakCell`，并且它们的链接顺序是正确的。
8. 再次验证 `cleared_cells()` 和 `key_map()` 仍然是 `undefined`。

**预期输出 (断言结果):**

所有的 `CHECK` 宏都会通过，表示内部数据结构的状态符合预期。

**涉及用户常见的编程错误及举例:**

**1. 滥用 `WeakRef.deref()` 而不检查 `undefined`:**

```javascript
let target = { data: 'important' };
let weakRef = new WeakRef(target);
target = null;

// 错误的做法：直接访问可能不存在的对象
// 可能会抛出 "Cannot read properties of undefined" 错误
console.log(weakRef.deref().data);

// 正确的做法：先检查是否为 undefined
const dereferenced = weakRef.deref();
if (dereferenced) {
  console.log(dereferenced.data);
} else {
  console.log('Target object has been garbage collected.');
}
```

**2. 对 `FinalizationRegistry` 的终结器回调函数的执行时机和次数的误解:**

* **错误理解:** 认为 `register` 后，只要解除强引用，回调函数就会立即执行。
* **正确理解:** 回调函数的执行依赖于垃圾回收器的运行，时机是不确定的。即使对象符合垃圾回收的条件，回调也可能不会立即执行。
* **错误理解:** 认为同一个目标对象多次 `register` 会导致回调函数执行多次。
* **正确理解:** 只要使用相同的目标对象注册，即使多次注册，也只会触发一次回调（在对象被回收后）。如果需要对同一类对象进行多次清理操作，可能需要使用不同的 heldValue 或不同的 FinalizationRegistry 实例。

**3. 在终结器回调中重新创建对已回收对象的强引用:**

```javascript
let target = { id: 1 };
let registry = new FinalizationRegistry(() => {
  // 这是一个潜在的内存泄漏！
  // 重新创建了对已回收对象的引用，阻止了其真正的释放
  globalThis.resurrectedTarget = { id: 1 };
  console.log('Target resurrected!');
});

registry.register(target, null);
target = null;
```

虽然在终结器回调中“复活”对象在技术上是可能的，但这通常是一个糟糕的主意，可能导致内存泄漏和其他难以调试的问题。

**功能归纳 (第 1 部分):**

`v8/test/cctest/test-js-weak-refs.cc` 的第 1 部分主要关注于 **`FinalizationRegistry` 的基本注册、取消注册以及内部数据结构的管理**。它测试了在不使用和使用取消注册令牌的情况下，注册对象时 `FinalizationRegistry` 内部 `active_cells` 链表和 `key_map` 的正确维护。此外，还测试了 `WeakCell` 对象在被标记为需要清理时，如何在 `active_cells` 和 `cleared_cells` 之间移动，以及如何通过 `PopClearedCellHoldings` 模拟清理过程。这些测试验证了 `FinalizationRegistry` 核心功能的正确性。

Prompt: 
```
这是目录为v8/test/cctest/test-js-weak-refs.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-js-weak-refs.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

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

  Hand
"""


```
Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/ic/ic.cc`. They have several specific questions about the code:

1. **General functionality:** What does this code do?
2. **Torque source:**  Is this a Torque file (would end in `.tq`)?
3. **JavaScript relationship:** If it relates to JavaScript, provide a JavaScript example.
4. **Code logic inference:** Provide an example with hypothetical input and output.
5. **Common programming errors:** Highlight any typical user errors this code relates to.
6. **Summary:**  Provide a concise summary of the code's function.

Let's break down the provided C++ code:

- It appears to be dealing with storing properties on JavaScript objects, specifically keyed stores (accessing properties using bracket notation like `obj[key]`).
- It involves Inline Caches (ICs), which are a V8 optimization technique to speed up property access.
- There's logic for handling different types of receivers (objects being stored onto), including arrays and objects with prototype chains.
- It considers different "store modes," like growing arrays or handling "copy-on-write" (COW) arrays.
- It interacts with `FeedbackVector` and `FeedbackSlot`, which are used for collecting runtime type information to optimize future executions.
- It calls into runtime functions like `Runtime::SetObjectProperty` and `Runtime::DefineObjectOwnProperty`.

**Plan:**

1. **Functionality:** Summarize the core purpose of the code.
2. **Torque:** Confirm that `.cc` is C++ and not Torque.
3. **JavaScript example:**  Craft a JavaScript example that demonstrates the keyed store operations this code handles.
4. **Input/Output:** Create a simple scenario with input JavaScript code and the expected effect after this C++ code executes (even if it's just an internal V8 change).
5. **Common errors:** Identify common JavaScript errors related to property assignment, especially with indexed access.
6. **Summary:**  Condense the functionality into a short paragraph.
这是目录为`v8/src/ic/ic.cc`的V8源代码的一部分，它主要负责 **处理 JavaScript 中对象属性的存储操作，特别是通过键（key）来存储属性（keyed store）的情况**。 这部分代码是 V8 的 **Inline Cache (IC)** 机制的一部分，用于优化属性存储的性能。

**1. 功能列举:**

* **处理 keyed store 操作的快慢路径:** 代码中可以看到对不同情况的处理，例如快速存储和慢速存储。
* **类型检查和优化:**  它会检查接收者（receiver）的类型和属性，并根据情况选择不同的优化路径。
* **处理数组的存储:**  专门处理了数组的存储，包括数组的增长和 copy-on-write (COW) 数组的处理。
* **处理原型链:** 考虑了原型链上的只读元素，避免不必要的错误。
* **使用反馈向量 (FeedbackVector) 和反馈槽 (FeedbackSlot):** 这部分代码与 V8 的反馈机制紧密相关，用于收集运行时类型信息以进行优化。
* **调用运行时函数:**  在必要时，会调用 V8 的运行时函数来执行更复杂的操作，例如属性定义。
* **处理元素类型的转换 (Elements Transition):** 当存储操作导致数组的元素类型发生变化时，会进行相应的处理。
* **处理废弃的 map (Deprecated Map):**  尝试迁移使用废弃 map 的对象。

**2. 是否为 Torque 源代码:**

`v8/src/ic/ic.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 源代码文件通常以 `.tq` 结尾。

**3. 与 JavaScript 功能的关系及 JavaScript 示例:**

这部分 C++ 代码直接对应于 JavaScript 中使用方括号 `[]` 来给对象或数组赋值的操作。

**JavaScript 示例:**

```javascript
const obj = {};
const key = 'propertyName';
const value = 10;

// 对应 KeyedStoreIC::Store 函数
obj[key] = value;

const arr = [1, 2, 3];
const index = 1;
const newValue = 4;

// 对应 KeyedStoreIC::Store 函数（对于数组） 或 StoreInArrayLiteralIC::Store 函数
arr[index] = newValue;
```

**4. 代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const obj = { a: 1 };
const key = 'b';
const value = 2;
obj[key] = value;
```

**假设输入 (C++ 代码层面):**

* `object`:  一个指向 JavaScript 对象 `{ a: 1 }` 的 `Handle<JSAny>`。
* `key`: 一个指向 JavaScript 字符串 `'b'` 的 `Handle<Object>`。
* `value`: 一个指向 JavaScript 数字 `2` 的 `Handle<Object>`。
* `receiver_maps_and_handlers` (在 `UpdateStoreElement` 函数中):  可能包含 `obj` 的 `Map` 和对应的属性处理句柄。

**可能的输出 (C++ 代码层面):**

* `UpdateStoreElement` 函数可能会更新 `receiver_maps_and_handlers`，为 `obj` 的 `Map` 添加一个过渡 (transition)，指向一个新的 `Map`，这个新的 `Map` 包含了属性 `'b'` 的信息。
* `StoreIC::Store` 函数最终可能会调用 `Runtime::SetObjectProperty`，这会在 `obj` 的内部表示中添加属性 `'b'`，并将其值设置为 `2`。

**5. 用户常见的编程错误:**

* **尝试修改只读属性:**

```javascript
'use strict';
const obj = {};
Object.defineProperty(obj, 'readOnlyProp', {
  value: 10,
  writable: false
});
obj.readOnlyProp = 20; // TypeError: Cannot assign to read only property 'readOnlyProp' of object '#<Object>'
```

* **尝试给不可扩展对象添加属性:**

```javascript
'use strict';
const obj = { a: 1 };
Object.preventExtensions(obj);
obj.b = 2; // TypeError: Cannot add property b, object is not extensible
```

* **对数组越界赋值 (在某些情况下可能不会报错，但行为可能不符合预期):**

```javascript
const arr = [1, 2, 3];
arr[5] = 4; // 数组长度变为 6，索引 3 和 4 的位置是空 (empty slots)
console.log(arr); // 输出: [ 1, 2, 3, <2 empty items>, 4 ]
```

* **在严格模式下对未声明的变量赋值 (间接地通过对象属性赋值):**

```javascript
'use strict';
const obj = {};
obj.undeclaredVar = 5; // 在非严格模式下会创建一个全局变量，但在严格模式下会报错: ReferenceError: undeclaredVar is not defined
```

**6. 功能归纳:**

这部分 `v8/src/ic/ic.cc` 代码是 V8 引擎中负责优化 JavaScript 对象属性的键值存储操作的关键组件。它通过内联缓存技术，根据对象类型和属性特征，采取不同的优化策略，以提高属性赋值的性能。 这段代码涵盖了对象和数组的存储，并考虑了原型链、元素类型转换以及错误处理等场景，是 V8 引擎实现高效 JavaScript 执行的重要组成部分。

### 提示词
```
这是目录为v8/src/ic/ic.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/ic.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
or (auto& [map, handler] : *receiver_maps_and_handlers) {
    receiver_maps.push_back(map);
    USE(handler);
  }
  for (size_t i = 0; i < receiver_maps_and_handlers->size(); i++) {
    Handle<Map> receiver_map = receiver_maps_and_handlers->at(i).first;
    DCHECK(!receiver_map->is_deprecated());
    MaybeObjectHandle old_handler = receiver_maps_and_handlers->at(i).second;
    Handle<Object> handler;
    Handle<Map> transition;

    if (receiver_map->instance_type() < FIRST_JS_RECEIVER_TYPE ||
        receiver_map->ShouldCheckForReadOnlyElementsInPrototypeChain(
            isolate())) {
      // TODO(mvstanton): Consider embedding store_mode in the state of the slow
      // keyed store ic for uniformity.
      TRACE_HANDLER_STATS(isolate(), KeyedStoreIC_SlowStub);
      handler = StoreHandler::StoreSlow(isolate());

    } else {
      {
        Tagged<Map> tmap = receiver_map->FindElementsKindTransitionedMap(
            isolate(),
            MapHandlesSpan(receiver_maps.begin(), receiver_maps.end()),
            ConcurrencyMode::kSynchronous);
        if (!tmap.is_null()) {
          if (receiver_map->is_stable()) {
            receiver_map->NotifyLeafMapLayoutChange(isolate());
          }
          transition = handle(tmap, isolate());
        }
      }

      MaybeHandle<UnionOf<Smi, Cell>> validity_cell;
      Tagged<HeapObject> old_handler_obj;
      if (!old_handler.is_null() &&
          (*old_handler).GetHeapObject(&old_handler_obj) &&
          IsDataHandler(old_handler_obj)) {
        validity_cell = handle(
            Cast<DataHandler>(old_handler_obj)->validity_cell(), isolate());
      }
      // TODO(mythria): Do not recompute the handler if we know there is no
      // change in the handler.
      // TODO(mvstanton): The code below is doing pessimistic elements
      // transitions. I would like to stop doing that and rely on Allocation
      // Site Tracking to do a better job of ensuring the data types are what
      // they need to be. Not all the elements are in place yet, pessimistic
      // elements transitions are still important for performance.
      if (!transition.is_null()) {
        TRACE_HANDLER_STATS(isolate(),
                            KeyedStoreIC_ElementsTransitionAndStoreStub);
        handler = StoreHandler::StoreElementTransition(
            isolate(), receiver_map, transition, store_mode, validity_cell);
      } else {
        handler = StoreElementHandler(receiver_map, store_mode, validity_cell);
      }
    }
    DCHECK(!handler.is_null());
    receiver_maps_and_handlers->at(i) =
        MapAndHandler(receiver_map, MaybeObjectHandle(handler));
  }
}

namespace {

bool MayHaveTypedArrayInPrototypeChain(Isolate* isolate,
                                       DirectHandle<JSObject> object) {
  for (PrototypeIterator iter(isolate, *object); !iter.IsAtEnd();
       iter.Advance()) {
    // Be conservative, don't walk into proxies.
    if (IsJSProxy(iter.GetCurrent())) return true;
    if (IsJSTypedArray(iter.GetCurrent())) return true;
  }
  return false;
}

KeyedAccessStoreMode GetStoreMode(DirectHandle<JSObject> receiver,
                                  size_t index) {
  bool oob_access = IsOutOfBoundsAccess(receiver, index);
  // Don't consider this a growing store if the store would send the receiver to
  // dictionary mode.
  bool allow_growth =
      IsJSArray(*receiver) && oob_access && index <= JSArray::kMaxArrayIndex &&
      !receiver->WouldConvertToSlowElements(static_cast<uint32_t>(index));
  if (allow_growth) {
    return KeyedAccessStoreMode::kGrowAndHandleCOW;
  }
  if (receiver->map()->has_typed_array_or_rab_gsab_typed_array_elements() &&
      oob_access) {
    return KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
  }
  return receiver->elements()->IsCowArray() ? KeyedAccessStoreMode::kHandleCOW
                                            : KeyedAccessStoreMode::kInBounds;
}

}  // namespace

MaybeHandle<Object> KeyedStoreIC::Store(Handle<JSAny> object,
                                        Handle<Object> key,
                                        Handle<Object> value) {
  // TODO(verwaest): Let SetProperty do the migration, since storing a property
  // might deprecate the current map again, if value does not fit.
  if (MigrateDeprecated(isolate(), object)) {
    Handle<Object> result;
    // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of StoreIC
    // so the logic doesn't get mixed here.
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), result,
        IsDefineKeyedOwnIC()
            ? Runtime::DefineObjectOwnProperty(isolate(), object, key, value,
                                               StoreOrigin::kNamed)
            : Runtime::SetObjectProperty(isolate(), object, key, value,
                                         StoreOrigin::kMaybeKeyed));
    return result;
  }

  Handle<Object> store_handle;

  intptr_t maybe_index;
  Handle<Name> maybe_name;
  KeyType key_type = TryConvertKey(key, isolate(), &maybe_index, &maybe_name);

  if (key_type == kName) {
    ASSIGN_RETURN_ON_EXCEPTION(
        isolate(), store_handle,
        StoreIC::Store(object, maybe_name, value, StoreOrigin::kMaybeKeyed));
    if (vector_needs_update()) {
      if (ConfigureVectorState(MEGAMORPHIC, key)) {
        set_slow_stub_reason("unhandled internalized string key");
        TraceIC("StoreIC", key);
      }
    }
    return store_handle;
  }

  JSObject::MakePrototypesFast(object, kStartAtPrototype, isolate());

  // TODO(jkummerow): Refactor the condition logic here and below.
  bool use_ic = (state() != NO_FEEDBACK) && v8_flags.use_ic &&
                !IsStringWrapper(*object) && !IsAccessCheckNeeded(*object) &&
                !IsJSGlobalProxy(*object);
  if (use_ic && !IsSmi(*object)) {
    // Don't use ICs for maps of the objects in Array's prototype chain. We
    // expect to be able to trap element sets to objects with those maps in
    // the runtime to enable optimization of element hole access.
    DirectHandle<HeapObject> heap_object = Cast<HeapObject>(object);
    if (heap_object->map()->IsMapInArrayPrototypeChain(isolate())) {
      set_slow_stub_reason("map in array prototype");
      use_ic = false;
    }
#if V8_ENABLE_WEBASSEMBLY
    if (IsWasmObjectMap(heap_object->map())) {
      set_slow_stub_reason("wasm object");
      use_ic = false;
    }
#endif
  }

  Handle<Map> old_receiver_map;
  bool is_arguments = false;
  bool key_is_valid_index = (key_type == kIntPtr);
  KeyedAccessStoreMode store_mode = KeyedAccessStoreMode::kInBounds;
  if (use_ic && IsJSReceiver(*object) && key_is_valid_index) {
    DirectHandle<JSReceiver> receiver = Cast<JSReceiver>(object);
    old_receiver_map = handle(receiver->map(), isolate());
    is_arguments = IsJSArgumentsObject(*receiver);
    bool is_jsobject = IsJSObject(*receiver);
    size_t index;
    key_is_valid_index = IntPtrKeyToSize(maybe_index, receiver, &index);
    if (is_jsobject && !is_arguments && key_is_valid_index) {
      DirectHandle<JSObject> receiver_object = Cast<JSObject>(object);
      store_mode = GetStoreMode(receiver_object, index);
    }
  }

  DCHECK(store_handle.is_null());
  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of StoreIC
  // so the logic doesn't get mixed here.
  MaybeHandle<Object> result =
      IsDefineKeyedOwnIC()
          ? Runtime::DefineObjectOwnProperty(isolate(), object, key, value,
                                             StoreOrigin::kNamed)
          : Runtime::SetObjectProperty(isolate(), object, key, value,
                                       StoreOrigin::kMaybeKeyed);
  if (result.is_null()) {
    DCHECK(isolate()->has_exception());
    set_slow_stub_reason("failed to set property");
    use_ic = false;
  }
  if (use_ic) {
    if (!old_receiver_map.is_null()) {
      if (is_arguments) {
        set_slow_stub_reason("arguments receiver");
      } else if (IsJSArray(*object) && StoreModeCanGrow(store_mode) &&
                 JSArray::HasReadOnlyLength(Cast<JSArray>(object))) {
        set_slow_stub_reason("array has read only length");
      } else if (IsJSObject(*object) &&
                 MayHaveTypedArrayInPrototypeChain(isolate(),
                                                   Cast<JSObject>(object))) {
        // Make sure we don't handle this in IC if there's any JSTypedArray in
        // the {receiver}'s prototype chain, since that prototype is going to
        // swallow all stores that are out-of-bounds for said prototype, and we
        // just let the runtime deal with the complexity of this.
        set_slow_stub_reason("typed array in the prototype chain");
      } else if (key_is_valid_index) {
        if (old_receiver_map->is_abandoned_prototype_map()) {
          set_slow_stub_reason("receiver with prototype map");
        } else if (old_receiver_map->has_dictionary_elements() ||
                   !old_receiver_map
                        ->ShouldCheckForReadOnlyElementsInPrototypeChain(
                            isolate())) {
          // We should go generic if receiver isn't a dictionary, but our
          // prototype chain does have dictionary elements. This ensures that
          // other non-dictionary receivers in the polymorphic case benefit
          // from fast path keyed stores.
          DirectHandle<HeapObject> receiver = Cast<HeapObject>(object);
          UpdateStoreElement(old_receiver_map, store_mode,
                             handle(receiver->map(), isolate()));
        } else {
          set_slow_stub_reason("prototype with potentially read-only elements");
        }
      } else {
        set_slow_stub_reason("non-smi-like key");
      }
    } else {
      set_slow_stub_reason("non-JSObject receiver");
    }
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, key);
  }
  TraceIC("StoreIC", key);

  return result;
}

namespace {
Maybe<bool> StoreOwnElement(Isolate* isolate, Handle<JSArray> array,
                            Handle<Object> index, Handle<Object> value) {
  DCHECK(IsNumber(*index));
  PropertyKey key(isolate, index);
  LookupIterator it(isolate, array, key, LookupIterator::OWN);

  MAYBE_RETURN(JSObject::DefineOwnPropertyIgnoreAttributes(
                   &it, value, NONE, Just(ShouldThrow::kThrowOnError)),
               Nothing<bool>());
  return Just(true);
}
}  // namespace

MaybeHandle<Object> StoreInArrayLiteralIC::Store(Handle<JSArray> array,
                                                 Handle<Object> index,
                                                 Handle<Object> value) {
  DCHECK(!array->map()->IsMapInArrayPrototypeChain(isolate()));
  DCHECK(IsNumber(*index));

  if (!v8_flags.use_ic || state() == NO_FEEDBACK ||
      MigrateDeprecated(isolate(), array)) {
    MAYBE_RETURN_NULL(StoreOwnElement(isolate(), array, index, value));
    TraceIC("StoreInArrayLiteralIC", index);
    return value;
  }

  // TODO(neis): Convert HeapNumber to Smi if possible?

  KeyedAccessStoreMode store_mode = KeyedAccessStoreMode::kInBounds;
  if (IsSmi(*index)) {
    DCHECK_GE(Smi::ToInt(*index), 0);
    uint32_t index32 = static_cast<uint32_t>(Smi::ToInt(*index));
    store_mode = GetStoreMode(array, index32);
  }

  Handle<Map> old_array_map(array->map(), isolate());
  MAYBE_RETURN_NULL(StoreOwnElement(isolate(), array, index, value));

  if (IsSmi(*index)) {
    DCHECK(!old_array_map->is_abandoned_prototype_map());
    UpdateStoreElement(old_array_map, store_mode,
                       handle(array->map(), isolate()));
  } else {
    set_slow_stub_reason("index out of Smi range");
  }

  if (vector_needs_update()) {
    ConfigureVectorState(MEGAMORPHIC, index);
  }
  TraceIC("StoreInArrayLiteralIC", index);
  return value;
}

// ----------------------------------------------------------------------------
// Static IC stub generators.
//
//
RUNTIME_FUNCTION(Runtime_LoadIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Name> key = args.at<Name>(1);
  int slot = args.tagged_index_value_at(2);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(3);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // A monomorphic or polymorphic KeyedLoadIC with a string key can call the
  // LoadIC miss handler if the handler misses. Since the vector Nexus is
  // set up outside the IC, handle that here.
  FeedbackSlotKind kind = vector->GetKind(vector_slot);
  if (IsLoadICKind(kind)) {
    LoadIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));

  } else if (IsLoadGlobalICKind(kind)) {
    DCHECK_EQ(isolate->native_context()->global_proxy(), *receiver);
    receiver = isolate->global_object();
    LoadGlobalIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(key));

  } else {
    DCHECK(IsKeyedLoadICKind(kind));
    KeyedLoadIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
  }
}

RUNTIME_FUNCTION(Runtime_LoadNoFeedbackIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Name> key = args.at<Name>(1);
  int slot_kind = args.smi_value_at(2);
  FeedbackSlotKind kind = static_cast<FeedbackSlotKind>(slot_kind);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  FeedbackSlot vector_slot = FeedbackSlot::Invalid();
  // This function is only called after looking up in the ScriptContextTable so
  // it is safe to call LoadIC::Load for global loads as well.
  LoadIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
}

RUNTIME_FUNCTION(Runtime_LoadWithReceiverNoFeedbackIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Name> key = args.at<Name>(2);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  FeedbackSlot vector_slot = FeedbackSlot::Invalid();
  LoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadProperty);
  ic.UpdateState(object, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(object, key, true, receiver));
}

RUNTIME_FUNCTION(Runtime_LoadGlobalIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  DirectHandle<JSGlobalObject> global = isolate->global_object();
  Handle<String> name = args.at<String>(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  int typeof_value = args.smi_value_at(3);
  TypeofMode typeof_mode = static_cast<TypeofMode>(typeof_value);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }

  FeedbackSlotKind kind = (typeof_mode == TypeofMode::kInside)
                              ? FeedbackSlotKind::kLoadGlobalInsideTypeof
                              : FeedbackSlotKind::kLoadGlobalNotInsideTypeof;
  LoadGlobalIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(global, name);

  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, ic.Load(name));
  return *result;
}

RUNTIME_FUNCTION(Runtime_LoadGlobalIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  Handle<String> name = args.at<String>(0);

  int slot = args.tagged_index_value_at(1);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(2);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);

  LoadGlobalIC ic(isolate, vector, vector_slot, kind);
  Handle<Object> result;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, result, ic.Load(name, false));
  return *result;
}

RUNTIME_FUNCTION(Runtime_LoadWithReceiverIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Name> key = args.at<Name>(2);
  int slot = args.tagged_index_value_at(3);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(4);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  DCHECK(IsLoadICKind(vector->GetKind(vector_slot)));
  LoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadProperty);
  ic.UpdateState(object, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(object, key, true, receiver));
}

RUNTIME_FUNCTION(Runtime_KeyedLoadIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> receiver = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  int slot = args.tagged_index_value_at(2);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(3);

  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  KeyedLoadIC ic(isolate, vector, vector_slot, FeedbackSlotKind::kLoadKeyed);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Load(receiver, key));
}

RUNTIME_FUNCTION(Runtime_StoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Name> key = args.at<Name>(4);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // When there is no feedback vector it is OK to use the SetNamedStrict as
  // the feedback slot kind. We only reuse this for DefineNamedOwnIC when
  // installing the handler for storing const properties. This will happen only
  // when feedback vector is available.
  FeedbackSlotKind kind = FeedbackSlotKind::kSetNamedStrict;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    DCHECK(!vector_slot.IsInvalid());
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
  }

  DCHECK(IsSetNamedICKind(kind) || IsDefineNamedOwnICKind(kind));
  StoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_DefineNamedOwnIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Name> key = args.at<Name>(4);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  // When there is no feedback vector it is OK to use the DefineNamedOwn
  // feedback kind. There _should_ be a vector, though.
  FeedbackSlotKind kind = FeedbackSlotKind::kDefineNamedOwn;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    DCHECK(!vector_slot.IsInvalid());
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
  }

  DCHECK(IsDefineNamedOwnICKind(kind));

  // TODO(v8:12548): refactor DefineNamedOwnIC as a subclass of StoreIC, which
  // can be called here.
  StoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_DefineNamedOwnIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());

  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);

  // Unlike DefineKeyedOwnIC, DefineNamedOwnIC doesn't handle private
  // fields and is used for defining data properties in object literals
  // and defining named public class fields.
  DCHECK(!IsSymbol(*key) || !Cast<Symbol>(*key)->is_private_name());

  PropertyKey lookup_key(isolate, key);
  MAYBE_RETURN(JSReceiver::CreateDataProperty(isolate, object, lookup_key,
                                              value, Nothing<ShouldThrow>()),
               ReadOnlyRoots(isolate).exception());
  return *value;
}

RUNTIME_FUNCTION(Runtime_StoreGlobalIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(4, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<FeedbackVector> vector = args.at<FeedbackVector>(2);
  Handle<Name> key = args.at<Name>(3);

  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);
  StoreGlobalIC ic(isolate, vector, vector_slot, kind);
  DirectHandle<JSGlobalObject> global = isolate->global_object();
  ic.UpdateState(global, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(key, value));
}

RUNTIME_FUNCTION(Runtime_StoreGlobalICNoFeedback_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(2, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<Name> key = args.at<Name>(1);

  // TODO(mythria): Replace StoreGlobalStrict/Sloppy with SetNamedProperty.
  StoreGlobalIC ic(isolate, Handle<FeedbackVector>(), FeedbackSlot(),
                   FeedbackSlotKind::kStoreGlobalStrict);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(key, value));
}

// TODO(mythria): Remove Feedback vector and slot. Since they are not used apart
// from the DCHECK.
RUNTIME_FUNCTION(Runtime_StoreGlobalIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<String> name = args.at<String>(4);

#ifdef DEBUG
  {
    int slot = args.tagged_index_value_at(1);
    DirectHandle<FeedbackVector> vector = args.at<FeedbackVector>(2);
    FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
    FeedbackSlotKind slot_kind = vector->GetKind(vector_slot);
    DCHECK(IsStoreGlobalICKind(slot_kind));
    DirectHandle<JSAny> receiver = args.at<JSAny>(3);
    DCHECK(IsJSGlobalProxy(*receiver));
  }
#endif

  Handle<JSGlobalObject> global = isolate->global_object();
  DirectHandle<Context> native_context = isolate->native_context();
  DirectHandle<ScriptContextTable> script_contexts(
      native_context->script_context_table(), isolate);

  VariableLookupResult lookup_result;
  if (script_contexts->Lookup(name, &lookup_result)) {
    DirectHandle<Context> script_context(
        script_contexts->get(lookup_result.context_index), isolate);
    if (IsImmutableLexicalVariableMode(lookup_result.mode)) {
      THROW_NEW_ERROR_RETURN_FAILURE(
          isolate, NewTypeError(MessageTemplate::kConstAssign, global, name));
    }

    {
      DisallowGarbageCollection no_gc;
      Tagged<Object> previous_value =
          script_context->get(lookup_result.slot_index);

      if (IsTheHole(previous_value, isolate)) {
        AllowGarbageCollection yes_gc;
        THROW_NEW_ERROR_RETURN_FAILURE(
            isolate,
            NewReferenceError(MessageTemplate::kAccessedUninitializedVariable,
                              name));
      }
    }
    if (v8_flags.const_tracking_let) {
      Context::StoreScriptContextAndUpdateSlotProperty(
          script_context, lookup_result.slot_index, value, isolate);
    } else {
      script_context->set(lookup_result.slot_index, *value);
    }
    return *value;
  }

  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, global, name, value,
                                          StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_KeyedStoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  FeedbackSlot vector_slot;

  // When the feedback vector is not valid the slot can only be of type
  // StoreKeyed. Storing in array literals falls back to
  // StoreInArrayLiterIC_Miss. This function is also used from store handlers
  // installed in feedback vectors. In such cases, we need to get the kind from
  // feedback vector slot since the handlers are used for both for StoreKeyed
  // and StoreInArrayLiteral kinds.
  FeedbackSlotKind kind = FeedbackSlotKind::kSetKeyedStrict;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
    int slot = args.tagged_index_value_at(1);
    vector_slot = FeedbackVector::ToSlot(slot);
    kind = vector->GetKind(vector_slot);
  }

  // The elements store stubs miss into this function, but they are shared by
  // different ICs.
  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of KeyedStoreIC,
  // which can be called here.
  if (IsKeyedStoreICKind(kind) || IsDefineKeyedOwnICKind(kind)) {
    KeyedStoreIC ic(isolate, vector, vector_slot, kind);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
  } else {
    DCHECK(IsStoreInArrayLiteralICKind(kind));
    DCHECK(IsJSArray(*receiver));
    DCHECK(IsNumber(*key));
    StoreInArrayLiteralIC ic(isolate, vector, vector_slot);
    ic.UpdateState(receiver, key);
    RETURN_RESULT_OR_FAILURE(isolate,
                             ic.Store(Cast<JSArray>(receiver), key, value));
  }
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);

  FeedbackSlotKind kind = FeedbackSlotKind::kDefineKeyedOwn;
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
    kind = vector->GetKind(vector_slot);
    DCHECK(IsDefineKeyedOwnICKind(kind));
  }

  // TODO(v8:12548): refactor DefineKeyedOwnIC as a subclass of KeyedStoreIC,
  // which can be called here.
  KeyedStoreIC ic(isolate, vector, vector_slot, kind);
  ic.UpdateState(receiver, key);
  RETURN_RESULT_OR_FAILURE(isolate, ic.Store(receiver, key, value));
}

RUNTIME_FUNCTION(Runtime_StoreInArrayLiteralIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(5, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  int slot = args.tagged_index_value_at(1);
  Handle<HeapObject> maybe_vector = args.at<HeapObject>(2);
  Handle<JSAny> receiver = args.at<JSAny>(3);
  Handle<Object> key = args.at(4);
  Handle<FeedbackVector> vector = Handle<FeedbackVector>();
  if (!IsUndefined(*maybe_vector, isolate)) {
    DCHECK(IsFeedbackVector(*maybe_vector));
    vector = Cast<FeedbackVector>(maybe_vector);
  }
  DCHECK(IsJSArray(*receiver));
  DCHECK(IsNumber(*key));
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  StoreInArrayLiteralIC ic(isolate, vector, vector_slot);
  RETURN_RESULT_OR_FAILURE(isolate,
                           ic.Store(Cast<JSArray>(receiver), key, value));
}

RUNTIME_FUNCTION(Runtime_KeyedStoreIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::SetObjectProperty(isolate, object, key, value,
                                          StoreOrigin::kMaybeKeyed));
}

RUNTIME_FUNCTION(Runtime_DefineKeyedOwnIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<JSAny> object = args.at<JSAny>(1);
  Handle<Object> key = args.at(2);
  RETURN_RESULT_OR_FAILURE(
      isolate, Runtime::DefineObjectOwnProperty(isolate, object, key, value,
                                                StoreOrigin::kNamed));
}

RUNTIME_FUNCTION(Runtime_StoreInArrayLiteralIC_Slow) {
  HandleScope scope(isolate);
  DCHECK_EQ(3, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<Object> value = args.at(0);
  Handle<Object> array = args.at(1);
  Handle<Object> index = args.at(2);
  StoreOwnElement(isolate, Cast<JSArray>(array), index, value);
  return *value;
}

RUNTIME_FUNCTION(Runtime_ElementsTransitionAndStoreIC_Miss) {
  HandleScope scope(isolate);
  DCHECK_EQ(6, args.length());
  // Runtime functions don't follow the IC's calling convention.
  Handle<JSAny> object = args.at<JSAny>(0);
  Handle<Object> key = args.at(1);
  Handle<Object> value = args.at(2);
  DirectHandle<Map> map = args.at<Map>(3);
  int slot = args.tagged_index_value_at(4);
  DirectHandle<FeedbackVector> vector = args.at<FeedbackVector>(5);
  FeedbackSlot vector_slot = FeedbackVector::ToSlot(slot);
  FeedbackSlotKind kind = vector->GetKind(vector_slot);

  if (IsJSObject(*object)) {
    JSObject::TransitionElementsKind(Cast<JSObject>(object),
                                     map->elements_kind());
  }

  if (IsStoreInArrayLiteralICKind(kind)) {
    StoreOwnElement(isolate, Cast<JSArray>(object), key, value);
    return *value;
  } else {
    DCHECK(IsKeyedStoreICKind(kind) || IsSetNamedICKind(kind) ||
           IsDefineKeyedOwnICKind(kind));
    RETURN_RESULT_OR_FAILURE(
        isolate, IsDefineKeyedOwnICKind(kind)
                     ? Runtime::DefineObjectOwnProperty(
                           isolate, object, key, value, StoreOrigin::kNamed)
                     : Runtime::SetObjectProperty(isolate, object, key, value,
                                                  StoreOrigin::kMaybeKeyed));
  }
}

namespace {

enum class FastCloneObjectMode {
  // The clone has the same map as the input.
  kIdenticalMap,
  // The clone is the empty object literal.
  kEmptyObject,
  // The clone has an empty object literal map.
  kDifferentMap,
  // The source map is to complicated to handle.
  kNotSupported,
  // Returned by PreCheck
  kMaybeSupported
};

FastCloneObjectMode GetCloneModeForMapPreCheck(DirectHandle<Map> map,
                                               bool null_proto_literal,
                                               Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  if (!IsJSObjectMap(*map)) {
    // Everything that produces the empty object literal can be supported since
    // we have a special case for that.
    if (null_proto_literal) return FastCloneObjectMode::kNotSupported;
    return IsNullOrUndefinedMap(*map) || IsBooleanMap(*map) ||
                   IsHeapNumberMap(*map)
               ? FastCloneObjectMode::kEmptyObject
               : FastCloneObjectMode::kNotSupported;
  }
  ElementsKind elements_kind = map->elements_kind();
  if (!IsSmiOrObjectElementsKind(elements_kind) &&
      !IsAnyNonextensibleElementsKind(elements_kind)) {
    return FastCloneObjectMode::kNotSupported;
  }
  if (!map->OnlyHasSimpleProperties()) {
    return FastCloneObjectMode::kNotSupported;
  }

  // TODO(olivf): Think about cases where cross-context copies are safe.
  if (!map->BelongsToSameNativeContextAs(isolate->context())) {
    return FastCloneObjectMode::kNotSupported;
  }

  return FastCloneObjectMode::kMaybeSupported;
}

FastCloneObjectMode GetCloneModeForMap(DirectHandle<M
```
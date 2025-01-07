Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the request.

**1. Initial Understanding of the Request:**

The core request is to understand the functionality of the provided C++ code, which is a snippet from `v8/src/objects/js-objects.cc`. The request also includes specific conditions and examples related to Torque, JavaScript, code logic, common errors, and finally, a summary of the functionality. The "Part 7 of 8" suggests this is a piece of a larger file, focusing on a specific set of functionalities.

**2. High-Level Code Overview:**

The first step is to skim the code to get a general sense of what it's doing. Keywords like `JSObject`, `Map`, `Prototype`, `Elements`, `Interceptor`, `JSGlobalObject`, and `JSDate` immediately stand out. This suggests the code deals with the internal representation and manipulation of JavaScript objects within the V8 engine. The presence of `#ifdef DEBUG` and `DCHECK` indicates this is internal V8 code with debugging and assertion mechanisms.

**3. Identifying Key Functionalities (Iterative Process):**

Now, let's go through the code section by section and extract the core functionalities.

* **`JSObject::MigrateToMap`:** This function clearly changes the map of a `JSObject`. The surrounding code talks about constructors and constant properties, implying this is part of object initialization or optimization.

* **`JSObject::ReoptimizeIfPrototype` and `JSObject::OptimizeAsPrototype`:** These functions relate to optimizing objects used as prototypes. The names suggest performance improvements for prototype chains.

* **`JSObject::LazyRegisterPrototypeUser` and `JSObject::UnregisterPrototypeUser`:** These functions deal with tracking which objects are using a specific object as their prototype. This is crucial for invalidating caches when prototypes change.

* **`InvalidateOnePrototypeValidityCellInternal` and `InvalidatePrototypeChainsInternal`:** These functions handle invalidating caches when the prototype chain changes. This is important for maintaining correctness in optimized code.

* **`JSObject::InvalidatePrototypeValidityCell`:**  Specifically targets the global object's prototype.

* **`JSObject::SetPrototype`:**  This is a fundamental operation: changing the prototype of an object. The code includes checks for extensibility, immutability, and cycles.

* **`JSObject::SetImmutableProto`:**  Marks a prototype as immutable.

* **`JSObject::EnsureCanContainElements` and `JSObject::ValidateElements`:** These functions deal with the storage of elements (array-like properties) in `JSObject`s.

* **`JSObject::WouldConvertToSlowElements`, `ShouldConvertToFastElements`, `BestFittingFastElementsKind`, and `JSObject::AddDataElement`:**  This set of functions manages the different ways elements can be stored (fast vs. slow, packed vs. holey) and handles transitions between these states.

* **`JSObject::TransitionElementsKind`:** Explicitly transitions the elements storage mechanism.

* **`JSObject::GetFastElementsUsage` and `HoleyElementsUsage`:** Functions to determine how efficiently elements are being stored.

* **`JSObject::GetPropertyWithInterceptor`:** Handles property access when an interceptor is involved.

* **`JSObject::HasRealNamedProperty`, `JSObject::HasRealElementProperty`, and `JSObject::HasRealNamedCallbackProperty`:** Checks for the existence of properties, skipping interceptors.

* **`JSObject::RawFastPropertyAtCompareAndSwap`:**  An atomic operation for updating fast properties.

* **`JSGlobalProxy::IsDetached`:** Checks if a global proxy is detached.

* **`JSGlobalObject::InvalidatePropertyCell`:** Invalidates a specific property cell of a global object.

* **`JSDate::New`, `JSDate::CurrentTimeValue`, `JSDate::GetField`, `JSDate::DoGetField`, `JSDate::GetUTCField`, `JSDate::SetValue`, `JSDate::SetNanValue`, and `JSDate::SetCachedFields`:**  Functions related to the `Date` object, including creation, getting time values, and handling cached fields.

**4. Addressing Specific Requirements:**

* **Torque:**  The code snippet is C++, not Torque. Mention this and explain the `.tq` extension.

* **JavaScript Relationship:**  For each identified functionality, think about the corresponding JavaScript operation. For example, `SetPrototype` maps directly to `Object.setPrototypeOf()` or the `__proto__` setter. `AddDataElement` relates to assigning values to array indices or object properties.

* **Code Logic Inference (Assumptions and Outputs):**  For functions like `MigrateToMap` or `SetPrototype`, think about simple scenarios. What happens if you change the prototype of an object? What are the inputs and expected outcomes?  Focus on demonstrating the function's core purpose.

* **Common Programming Errors:**  Relate the V8 internal operations to common JavaScript errors. Setting a non-object/null prototype leads to a `TypeError`. Trying to set the prototype of a non-extensible object also results in a `TypeError`.

* **Summary of Functionality:** Synthesize the individual functionalities into a cohesive high-level description of the code's purpose. Emphasize the core themes: object structure, prototypes, elements, and global objects.

**5. Structuring the Output:**

Organize the findings logically, addressing each point of the request systematically. Use clear headings and examples. Start with the general functionalities and then delve into specifics. The structure provided in the example output is a good model.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on low-level details of the C++ code.**  The request emphasizes understanding the *functionality* and its relation to JavaScript. So, shift the focus towards explaining the *what* and *why* in JavaScript terms, rather than just the *how* in C++.

* **For the "code logic" part, resist the urge to create overly complex scenarios.**  Simple, illustrative examples are more effective.

* **Ensure the JavaScript examples are accurate and directly related to the explained C++ functionality.**

* **Double-check the definitions of Torque and its file extensions.**

By following this systematic approach, analyzing the code snippet in parts, and constantly relating it back to the request's specific requirements, you can arrive at a comprehensive and accurate understanding of the code's functionality, as demonstrated in the example output.
好的，让我们来分析一下这段 v8 源代码 `v8/src/objects/js-objects.cc` 的功能。

**整体功能归纳（基于提供的代码片段）：**

这段代码主要负责 `JSObject`（JavaScript 对象）的内部管理和操作，特别是围绕以下几个核心方面：

1. **对象元数据管理 (Maps)：**  管理和更新对象的 `Map`，`Map` 包含了对象的结构信息，例如属性布局、原型等。`MigrateToMap` 函数是核心，用于改变对象的 `Map`。
2. **原型链优化和管理：** 涉及到原型链的优化 (`OptimizeAsPrototype`)，以及对原型链变更的追踪和失效机制 (`LazyRegisterPrototypeUser`, `UnregisterPrototypeUser`, `InvalidatePrototypeChains`, `InvalidatePrototypeValidityCell`)。
3. **原型设置和不变性：**  允许设置对象的原型 (`SetPrototype`)，并支持将原型标记为不可变 (`SetImmutableProto`)。
4. **元素管理 (Elements)：**  负责对象元素（数组索引属性）的存储和转换，包括从字典模式转换为快速模式，以及不同类型的元素数组之间的转换 (`EnsureCanContainElements`, `AddDataElement`, `TransitionElementsKind`)。
5. **属性访问和拦截器：**  处理带有拦截器的属性访问 (`GetPropertyWithInterceptor`)。
6. **全局对象和属性：**  涉及到全局对象的特殊处理，例如失效全局对象的属性单元 (`InvalidatePropertyCell`)。
7. **`Date` 对象相关操作：**  包含了 `JSDate` 对象的创建和获取时间相关字段的逻辑。

**逐个功能点详细解释：**

1. **对象元数据管理 (Maps)：**
   - `JSObject::MigrateToMap(isolate, object, new_map)`:  这个函数用于将 `object` 的 `Map` 更改为 `new_map`。这通常发生在对象结构发生变化时，例如添加新属性、改变原型等。
   - 代码中还涉及了设置构造函数到新的 `Map`，以及在特定条件下将字典属性标记为常量。

2. **原型链优化和管理：**
   - `JSObject::ReoptimizeIfPrototype(DirectHandle<JSObject> object)` 和 `JSObject::OptimizeAsPrototype(Handle<JSObject> object)`:  这些函数用于优化作为原型的对象。当一个对象被频繁用作原型时，V8 会尝试将其转换为更高效的表示形式。
   - `JSObject::LazyRegisterPrototypeUser(DirectHandle<Map> user, Isolate* isolate)`:  这个函数用于注册哪些 `Map`（代表了使用特定原型的对象）依赖于某个原型 `Map`。这用于在原型发生变化时，通知依赖它的对象。
   - `JSObject::UnregisterPrototypeUser(DirectHandle<Map> user, Isolate* isolate)`:  取消注册某个 `Map` 对原型的依赖。
   - `InvalidateOnePrototypeValidityCellInternal(Tagged<Map> map)` 和 `InvalidatePrototypeChainsInternal(Tagged<Map> map)`: 当原型对象的结构发生变化时，这些函数用于失效相关的缓存，确保依赖于该原型的对象能正确反映最新的状态。
   - `JSObject::InvalidatePrototypeValidityCell(Tagged<JSGlobalObject> global)`:  专门用于失效全局对象的原型有效性。

3. **原型设置和不变性：**
   - `JSObject::SetPrototype(Isolate* isolate, Handle<JSObject> object, Handle<Object> value_obj, bool from_javascript, ShouldThrow should_throw)`:  这个函数实现了 JavaScript 中设置对象原型的功能，对应于 `Object.setPrototypeOf()` 或者设置 `__proto__` 属性。它会进行一系列检查，例如是否允许设置原型（对象是否可扩展），以及是否会产生原型链循环。
   - `JSObject::SetImmutableProto(Isolate* isolate, DirectHandle<JSObject> object)`:  将对象的原型标记为不可变，之后尝试修改该对象的原型会抛出错误。

4. **元素管理 (Elements)：**
   - `JSObject::EnsureCanContainElements(...)`:  确保对象可以容纳一定数量的元素。
   - `JSObject::AddDataElement(Handle<JSObject> object, uint32_t index, DirectHandle<Object> value, PropertyAttributes attributes)`:  向对象添加数据元素（通常是数组索引属性）。它会根据元素类型和对象的状态，决定是否需要进行元素存储模式的转换（例如从稀疏数组转换为密集数组）。
   - `JSObject::TransitionElementsKind(Handle<JSObject> object, ElementsKind to_kind)`:  显式地将对象的元素存储模式从一种类型转换为另一种类型，例如从 `HOLEY_ELEMENTS` 转换为 `PACKED_ELEMENTS`。

5. **属性访问和拦截器：**
   - `JSObject::GetPropertyWithInterceptor(LookupIterator* it, bool* done)`:  当访问对象的属性时，如果对象定义了属性访问拦截器，则会调用此函数来处理属性的获取。

6. **全局对象和属性：**
   - `JSGlobalObject::InvalidatePropertyCell(DirectHandle<JSGlobalObject> global, Handle<Name> name)`:  用于失效全局对象的特定属性单元，这通常发生在全局变量被重新定义时。

7. **`Date` 对象相关操作：**
   - `JSDate::New(...)`:  创建新的 `Date` 对象。
   - `JSDate::CurrentTimeValue(Isolate* isolate)`:  获取当前时间戳。
   - `JSDate::GetField(Isolate* isolate, Address raw_object, Address smi_index)` 和相关 `DoGetField`、`GetUTCField` 函数:  用于获取 `Date` 对象的各个时间字段，例如年、月、日、小时等。

**关于 .tq 结尾的文件：**

你说的没错。如果 `v8/src/objects/js-objects.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**。Torque 是 V8 用来生成高效的运行时代码的领域特定语言。  当前的 `.cc` 结尾表明这是一个手写的 C++ 文件。

**与 JavaScript 功能的关系及示例：**

以下列举一些代码片段中的功能与 JavaScript 的对应关系和示例：

- **`JSObject::SetPrototype`**: 对应 JavaScript 的 `Object.setPrototypeOf()` 或者设置对象的 `__proto__` 属性。

  ```javascript
  const obj1 = {};
  const proto = { y: 2 };
  Object.setPrototypeOf(obj1, proto);
  console.log(obj1.y); // 输出 2

  const obj2 = {};
  obj2.__proto__ = proto;
  console.log(obj2.y); // 输出 2
  ```

- **`JSObject::AddDataElement`**: 对应 JavaScript 中给对象添加属性或给数组添加元素。

  ```javascript
  const arr = [];
  arr[0] = 10; // 内部会调用类似 AddDataElement 的操作

  const obj = {};
  obj.x = 5; // 内部也会调用类似 AddDataElement 的操作
  ```

- **`JSObject::SetImmutableProto`**: 虽然 JavaScript 没有直接的方法将原型设置为绝对不可变，但冻结对象 (`Object.freeze()`) 或阻止扩展 (`Object.preventExtensions()`) 可以间接地影响原型的修改。尝试设置冻结对象的原型会抛出 `TypeError`。

  ```javascript
  const obj = {};
  Object.freeze(obj);
  try {
    Object.setPrototypeOf(obj, { z: 3 }); // 抛出 TypeError
  } catch (e) {
    console.error(e);
  }
  ```

- **`JSDate` 相关操作**:  对应 JavaScript 的 `Date` 对象及其方法。

  ```javascript
  const now = new Date();
  console.log(now.getFullYear());
  console.log(now.getMonth()); // 注意月份从 0 开始
  ```

**代码逻辑推理（假设输入与输出）：**

**场景：`JSObject::SetPrototype`**

**假设输入：**

- `isolate`: 当前 V8 引擎的隔离区。
- `object`: 一个可扩展的 JavaScript 对象 `{ a: 1 }`。
- `value_obj`: 一个 JavaScript 对象 `{ b: 2 }`，将作为新的原型。
- `from_javascript`: `true` (表示从 JavaScript 代码调用)。
- `should_throw`:  一个指示是否应该抛出错误的枚举值（例如 `kThrowOnError`）。

**预期输出：**

如果一切顺利，`object` 的原型将被设置为 `value_obj`。之后访问 `object.b` 将返回 `2`。

**场景：`JSObject::AddDataElement`**

**假设输入：**

- `isolate`: 当前 V8 引擎的隔离区。
- `object`: 一个空数组 `[]`。
- `index`: `0`。
- `value`: 数字 `10`。
- `attributes`: `NONE` (没有特殊属性)。

**预期输出：**

数组 `object` 将变为 `[10]`。其内部的元素存储会进行相应的调整。

**用户常见的编程错误：**

1. **尝试设置 `null` 或非对象为原型：**

   ```javascript
   const obj = {};
   Object.setPrototypeOf(obj, null); // 正确
   Object.setPrototypeOf(obj, 123); // TypeError: 设置原型只能是 Object 或 null
   ```
   这段 C++ 代码中的检查会防止这种错误，并在 JavaScript 层抛出 `TypeError`。

2. **尝试设置不可扩展对象的原型：**

   ```javascript
   const obj = {};
   Object.preventExtensions(obj);
   try {
     Object.setPrototypeOf(obj, { c: 3 }); // TypeError: 无法设置不可扩展对象的原型
   } catch (e) {
     console.error(e);
   }
   ```
   `JSObject::SetPrototype` 中的可扩展性检查会阻止这种操作。

3. **创建原型链循环：**

   ```javascript
   const a = {};
   const b = {};
   Object.setPrototypeOf(a, b);
   try {
     Object.setPrototypeOf(b, a); // TypeError: 循环原型链
   } catch (e) {
     console.error(e);
   }
   ```
   `JSObject::SetPrototype` 中的原型链循环检测机制会阻止这种错误的发生。

**总结（针对第 7 部分）：**

这段代码作为 `v8/src/objects/js-objects.cc` 的一部分，主要关注 JavaScript 对象的核心生命周期管理，特别是**对象结构的变更（通过 `Map` 迁移）**和**原型链的管理与优化**。它包含了设置原型、追踪原型依赖、在原型变更时失效缓存等关键功能。此外，还涉及到对象元素的管理和 `Date` 对象的内部操作。 这些底层的 C++ 代码支撑着 JavaScript 中对象和原型链的各种行为。

Prompt: 
```
这是目录为v8/src/objects/js-objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能

"""
 } else {
          new_map->SetConstructor(object_function);
        }
      }
    }
    JSObject::MigrateToMap(isolate, object, new_map);

    if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && !object->HasFastProperties()) {
      ReadOnlyRoots roots(isolate);
      DisallowHeapAllocation no_gc;

      auto make_constant = [&](auto dict) {
        for (InternalIndex index : dict->IterateEntries()) {
          Tagged<Object> k;
          if (!dict->ToKey(roots, index, &k)) continue;

          PropertyDetails details = dict->DetailsAt(index);
          details = details.CopyWithConstness(PropertyConstness::kConst);
          dict->DetailsAtPut(index, details);
        }
      };
      if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
        make_constant(object->property_dictionary_swiss());
      } else {
        make_constant(object->property_dictionary());
      }
    }
  }
#ifdef DEBUG
  bool should_be_dictionary = V8_DICT_PROPERTY_CONST_TRACKING_BOOL &&
                              enable_setup_mode && !IsJSGlobalProxy(*object) &&
                              !isolate->bootstrapper()->IsActive();
  DCHECK_IMPLIES(should_be_dictionary,
                 object->map(isolate)->is_dictionary_map());
#endif
}

// static
void JSObject::ReoptimizeIfPrototype(DirectHandle<JSObject> object) {
  {
    Tagged<Map> map = object->map();
    if (!map->is_prototype_map()) return;
    if (!map->should_be_fast_prototype_map()) return;
  }
  OptimizeAsPrototype(object);
}

// static
void JSObject::LazyRegisterPrototypeUser(DirectHandle<Map> user,
                                         Isolate* isolate) {
  // Contract: In line with InvalidatePrototypeChains()'s requirements,
  // leaf maps don't need to register as users, only prototypes do.
  DCHECK(user->is_prototype_map());

  DirectHandle<Map> current_user = user;
  DirectHandle<PrototypeInfo> current_user_info =
      Map::GetOrCreatePrototypeInfo(user, isolate);
  for (PrototypeIterator iter(isolate, user); !iter.IsAtEnd(); iter.Advance()) {
    // Walk up the prototype chain as far as links haven't been registered yet.
    if (current_user_info->registry_slot() != MemoryChunk::UNREGISTERED) {
      break;
    }
    Handle<Object> maybe_proto = PrototypeIterator::GetCurrent(iter);
    // This checks for both proxies and shared objects.
    //
    // Proxies on the prototype chain are not supported. They make it
    // impossible to make any assumptions about the prototype chain anyway.
    //
    // Objects in the shared heap have fixed layouts and their maps never
    // change, so they don't need to be tracked as prototypes
    // anyway. Additionally, registering users of shared objects is not
    // threadsafe.
    if (!IsJSObjectThatCanBeTrackedAsPrototype(*maybe_proto)) continue;
    auto proto = Cast<JSObject>(maybe_proto);
    DirectHandle<PrototypeInfo> proto_info =
        Map::GetOrCreatePrototypeInfo(proto, isolate);
    Handle<Object> maybe_registry(proto_info->prototype_users(), isolate);
    Handle<WeakArrayList> registry =
        IsSmi(*maybe_registry)
            ? handle(ReadOnlyRoots(isolate->heap()).empty_weak_array_list(),
                     isolate)
            : Cast<WeakArrayList>(maybe_registry);
    int slot = 0;
    Handle<WeakArrayList> new_array =
        PrototypeUsers::Add(isolate, registry, current_user, &slot);
    current_user_info->set_registry_slot(slot);
    if (!maybe_registry.is_identical_to(new_array)) {
      proto_info->set_prototype_users(*new_array);
    }
    if (v8_flags.trace_prototype_users) {
      PrintF("Registering %p as a user of prototype %p (map=%p).\n",
             reinterpret_cast<void*>(current_user->ptr()),
             reinterpret_cast<void*>(proto->ptr()),
             reinterpret_cast<void*>(proto->map().ptr()));
    }

    current_user = handle(proto->map(), isolate);
    current_user_info = proto_info;
  }
}

// Can be called regardless of whether |user| was actually registered with
// |prototype|. Returns true when there was a registration.
// static
bool JSObject::UnregisterPrototypeUser(DirectHandle<Map> user,
                                       Isolate* isolate) {
  DCHECK(user->is_prototype_map());
  // If it doesn't have a PrototypeInfo, it was never registered.
  if (!user->has_prototype_info()) return false;
  DCHECK(IsPrototypeInfo(user->prototype_info()));
  // If it had no prototype before, see if it had users that might expect
  // registration.
  if (!IsJSObject(user->prototype())) {
    Tagged<Object> users =
        Cast<PrototypeInfo>(user->prototype_info())->prototype_users();
    return IsWeakArrayList(users);
  }
  DirectHandle<JSObject> prototype(Cast<JSObject>(user->prototype()), isolate);
  DirectHandle<PrototypeInfo> user_info =
      Map::GetOrCreatePrototypeInfo(user, isolate);
  int slot = user_info->registry_slot();
  if (slot == MemoryChunk::UNREGISTERED) return false;
  DCHECK(prototype->map()->is_prototype_map());
  Tagged<Object> maybe_proto_info = prototype->map()->prototype_info();
  // User knows its registry slot, prototype info and user registry must exist.
  DCHECK(IsPrototypeInfo(maybe_proto_info));
  DirectHandle<PrototypeInfo> proto_info(Cast<PrototypeInfo>(maybe_proto_info),
                                         isolate);
  DirectHandle<WeakArrayList> prototype_users(
      Cast<WeakArrayList>(proto_info->prototype_users()), isolate);
  DCHECK_EQ(prototype_users->Get(slot), MakeWeak(*user));
  PrototypeUsers::MarkSlotEmpty(*prototype_users, slot);
  if (v8_flags.trace_prototype_users) {
    PrintF("Unregistering %p as a user of prototype %p.\n",
           reinterpret_cast<void*>(user->ptr()),
           reinterpret_cast<void*>(prototype->ptr()));
  }
  return true;
}

namespace {

// This function must be kept in sync with
// AccessorAssembler::InvalidateValidityCellIfPrototype() which does pre-checks
// before jumping here.
void InvalidateOnePrototypeValidityCellInternal(Tagged<Map> map) {
  DCHECK(map->is_prototype_map());
  if (v8_flags.trace_prototype_users) {
    PrintF("Invalidating prototype map %p 's cell\n",
           reinterpret_cast<void*>(map.ptr()));
  }
  Tagged<Object> maybe_cell = map->prototype_validity_cell(kRelaxedLoad);
  if (IsCell(maybe_cell)) {
    // Just set the value; the cell will be replaced lazily.
    Tagged<Cell> cell = Cast<Cell>(maybe_cell);
    Tagged<Smi> invalid_value = Smi::FromInt(Map::kPrototypeChainInvalid);
    if (cell->value() != invalid_value) {
      cell->set_value(invalid_value);
    }
  }
  Tagged<PrototypeInfo> prototype_info;
  if (map->TryGetPrototypeInfo(&prototype_info)) {
    prototype_info->set_prototype_chain_enum_cache(Smi::zero());
  }

  // We may inline accesses to constants stored in dictionary mode prototypes in
  // optimized code. When doing so, we install dependencies of group
  // |kPrototypeCheckGroup| on each prototype between the receiver's immediate
  // prototype and the holder of the constant property. This dependency is used
  // both to detect changes to the constant value itself, and other changes to
  // the prototype chain that invalidate the access to the given property from
  // the given receiver (like adding the property to another prototype between
  // the receiver and the (previous) holder). This works by de-opting this group
  // whenever the validity cell would be invalidated. However, the actual value
  // of the validity cell is not used. Therefore, we always trigger the de-opt
  // here, even if the cell was already invalid.
  if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL && map->is_dictionary_map()) {
    // TODO(11527): pass Isolate as an argument.
    Isolate* isolate = GetIsolateFromWritableObject(map);
    DependentCode::DeoptimizeDependencyGroups(
        isolate, map, DependentCode::kPrototypeCheckGroup);
  }
}

void InvalidatePrototypeChainsInternal(Tagged<Map> map) {
  // We handle linear prototype chains by looping, and multiple children
  // by recursion, in order to reduce the likelihood of running into stack
  // overflows. So, conceptually, the outer loop iterates the depth of the
  // prototype tree, and the inner loop iterates the breadth of a node.
  Tagged<Map> next_map;
  for (; !map.is_null(); map = next_map, next_map = Map()) {
    InvalidateOnePrototypeValidityCellInternal(map);

    Tagged<PrototypeInfo> proto_info;
    if (!map->TryGetPrototypeInfo(&proto_info)) return;
    if (!IsWeakArrayList(proto_info->prototype_users())) {
      return;
    }
    Tagged<WeakArrayList> prototype_users =
        Cast<WeakArrayList>(proto_info->prototype_users());
    // For now, only maps register themselves as users.
    for (int i = PrototypeUsers::kFirstIndex; i < prototype_users->length();
         ++i) {
      Tagged<HeapObject> heap_object;
      if (prototype_users->Get(i).GetHeapObjectIfWeak(&heap_object) &&
          IsMap(heap_object)) {
        // Walk the prototype chain (backwards, towards leaf objects) if
        // necessary.
        if (next_map.is_null()) {
          next_map = Cast<Map>(heap_object);
        } else {
          InvalidatePrototypeChainsInternal(Cast<Map>(heap_object));
        }
      }
    }
  }
}

}  // namespace

// static
Tagged<Map> JSObject::InvalidatePrototypeChains(Tagged<Map> map) {
  DisallowGarbageCollection no_gc;
  InvalidatePrototypeChainsInternal(map);
  return map;
}

// We also invalidate global objects validity cell when a new lexical
// environment variable is added. This is necessary to ensure that
// Load/StoreGlobalIC handlers that load/store from global object's prototype
// get properly invalidated.
// Note, that the normal Load/StoreICs that load/store through the global object
// in the prototype chain are not affected by appearance of a new lexical
// variable and therefore we don't propagate invalidation down.
// static
void JSObject::InvalidatePrototypeValidityCell(Tagged<JSGlobalObject> global) {
  DisallowGarbageCollection no_gc;
  InvalidateOnePrototypeValidityCellInternal(global->map());
}

Maybe<bool> JSObject::SetPrototype(Isolate* isolate, Handle<JSObject> object,
                                   Handle<Object> value_obj,
                                   bool from_javascript,
                                   ShouldThrow should_throw) {
#ifdef DEBUG
  int size = object->Size();
#endif

  if (from_javascript) {
    if (IsAccessCheckNeeded(*object) &&
        !isolate->MayAccess(isolate->native_context(), object)) {
      RETURN_ON_EXCEPTION_VALUE(
          isolate, isolate->ReportFailedAccessCheck(object), Nothing<bool>());
      UNREACHABLE();
    }
  } else {
    DCHECK(!IsAccessCheckNeeded(*object));
  }

  // Silently ignore the change if value is not a JSReceiver or null.
  // SpiderMonkey behaves this way.
  Handle<JSPrototype> value;
  if (!TryCast(value_obj, &value)) return Just(true);

  bool all_extensible = object->map()->is_extensible();
  Handle<JSObject> real_receiver = object;
  if (from_javascript) {
    // Find the first object in the chain whose prototype object is not
    // hidden.
    PrototypeIterator iter(isolate, real_receiver, kStartAtPrototype,
                           PrototypeIterator::END_AT_NON_HIDDEN);
    while (!iter.IsAtEnd()) {
      // Casting to JSObject is fine because hidden prototypes are never
      // JSProxies.
      real_receiver = PrototypeIterator::GetCurrent<JSObject>(iter);
      iter.Advance();
      all_extensible = all_extensible && real_receiver->map()->is_extensible();
    }
  }
  Handle<Map> map(real_receiver->map(), isolate);

  // Nothing to do if prototype is already set.
  if (map->prototype() == *value) return Just(true);

  bool immutable_proto = map->is_immutable_proto();
  if (immutable_proto) {
    Handle<Object> msg;
    if (IsJSObjectPrototype(*object)) {  // is [[Object.prototype]]
      msg = isolate->factory()->Object_prototype_string();
    } else {
      msg = object;
    }
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kImmutablePrototypeSet, msg));
  }

  // From 6.1.7.3 Invariants of the Essential Internal Methods
  //
  // [[SetPrototypeOf]] ( V )
  // * ...
  // * If target is non-extensible, [[SetPrototypeOf]] must return false,
  //   unless V is the SameValue as the target's observed [[GetPrototypeOf]]
  //   value.
  if (!all_extensible) {
    RETURN_FAILURE(isolate, should_throw,
                   NewTypeError(MessageTemplate::kNonExtensibleProto, object));
  }

  // Before we can set the prototype we need to be sure prototype cycles are
  // prevented.  It is sufficient to validate that the receiver is not in the
  // new prototype chain.
  if (Tagged<JSReceiver> receiver; TryCast<JSReceiver>(*value, &receiver)) {
    for (PrototypeIterator iter(isolate, receiver, kStartAtReceiver);
         !iter.IsAtEnd(); iter.Advance()) {
      if (iter.GetCurrent<JSReceiver>() == *object) {
        // Cycle detected.
        RETURN_FAILURE(isolate, should_throw,
                       NewTypeError(MessageTemplate::kCyclicProto));
      }
    }
  }

  // Set the new prototype of the object.

  isolate->UpdateProtectorsOnSetPrototype(real_receiver, value);

  DirectHandle<Map> new_map =
      v8_flags.move_prototype_transitions_first
          ? MapUpdater(isolate, map).ApplyPrototypeTransition(value)
          : Map::TransitionToUpdatePrototype(isolate, map, value);

  DCHECK(new_map->prototype() == *value);
  JSObject::MigrateToMap(isolate, real_receiver, new_map);

  DCHECK_IMPLIES(!new_map->is_dictionary_map() && !map->is_deprecated() &&
                     !IsUndefined(new_map->GetBackPointer()),
                 size == object->Size());
  return Just(true);
}

// static
void JSObject::SetImmutableProto(Isolate* isolate,
                                 DirectHandle<JSObject> object) {
  Handle<Map> map(object->map(), isolate);

  // Nothing to do if prototype is already set.
  if (map->is_immutable_proto()) return;

  DirectHandle<Map> new_map = Map::TransitionToImmutableProto(isolate, map);
  object->set_map(isolate, *new_map, kReleaseStore);
}

void JSObject::EnsureCanContainElements(Handle<JSObject> object,
                                        JavaScriptArguments* args,
                                        uint32_t arg_count,
                                        EnsureElementsMode mode) {
  return EnsureCanContainElements(
      object, FullObjectSlot(args->address_of_arg_at(0)), arg_count, mode);
}

void JSObject::ValidateElements(Tagged<JSObject> object) {
#ifdef ENABLE_SLOW_DCHECKS
  if (v8_flags.enable_slow_asserts) {
    object->GetElementsAccessor()->Validate(object);
  }
#endif
}

bool JSObject::WouldConvertToSlowElements(uint32_t index) {
  if (!HasFastElements()) return false;
  uint32_t capacity = static_cast<uint32_t>(elements()->length());
  uint32_t new_capacity;
  return ShouldConvertToSlowElements(*this, capacity, index, &new_capacity);
}

static bool ShouldConvertToFastElements(Tagged<JSObject> object,
                                        Tagged<NumberDictionary> dictionary,
                                        uint32_t index,
                                        uint32_t* new_capacity) {
  // If properties with non-standard attributes or accessors were added, we
  // cannot go back to fast elements.
  if (dictionary->requires_slow_elements()) return false;

  // Adding a property with this index will require slow elements.
  if (index >= static_cast<uint32_t>(Smi::kMaxValue)) return false;

  if (IsJSArray(object)) {
    Tagged<Object> length = Cast<JSArray>(object)->length();
    if (!IsSmi(length)) return false;
    *new_capacity = static_cast<uint32_t>(Smi::ToInt(length));
  } else if (IsJSArgumentsObject(object)) {
    return false;
  } else {
    *new_capacity = dictionary->max_number_key() + 1;
  }
  *new_capacity = std::max(index + 1, *new_capacity);

  uint32_t dictionary_size = static_cast<uint32_t>(dictionary->Capacity()) *
                             NumberDictionary::kEntrySize;

  // Turn fast if the dictionary only saves 50% space.
  return 2 * dictionary_size >= *new_capacity;
}

static ElementsKind BestFittingFastElementsKind(Tagged<JSObject> object) {
  if (!object->map()->CanHaveFastTransitionableElementsKind()) {
    return HOLEY_ELEMENTS;
  }
  if (object->HasSloppyArgumentsElements()) {
    return FAST_SLOPPY_ARGUMENTS_ELEMENTS;
  }
  if (object->HasStringWrapperElements()) {
    return FAST_STRING_WRAPPER_ELEMENTS;
  }
  DCHECK(object->HasDictionaryElements());
  Tagged<NumberDictionary> dictionary = object->element_dictionary();
  ElementsKind kind = HOLEY_SMI_ELEMENTS;
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> key = dictionary->KeyAt(i);
    if (IsNumber(key)) {
      Tagged<Object> value = dictionary->ValueAt(i);
      if (!IsNumber(value)) return HOLEY_ELEMENTS;
      if (!IsSmi(value)) {
        if (!v8_flags.unbox_double_arrays) return HOLEY_ELEMENTS;
        kind = HOLEY_DOUBLE_ELEMENTS;
      }
    }
  }
  return kind;
}

// static
Maybe<bool> JSObject::AddDataElement(Handle<JSObject> object, uint32_t index,
                                     DirectHandle<Object> value,
                                     PropertyAttributes attributes) {
  Isolate* isolate = object->GetIsolate();

  DCHECK(object->map(isolate)->is_extensible());

  uint32_t old_length = 0;
  uint32_t new_capacity = 0;

  if (IsJSArray(*object, isolate)) {
    CHECK(Object::ToArrayLength(Cast<JSArray>(*object)->length(), &old_length));
  }

  ElementsKind kind = object->GetElementsKind(isolate);
  Tagged<FixedArrayBase> elements = object->elements(isolate);
  ElementsKind dictionary_kind = DICTIONARY_ELEMENTS;
  if (IsSloppyArgumentsElementsKind(kind)) {
    elements = Cast<SloppyArgumentsElements>(elements)->arguments();
    dictionary_kind = SLOW_SLOPPY_ARGUMENTS_ELEMENTS;
  } else if (IsStringWrapperElementsKind(kind)) {
    dictionary_kind = SLOW_STRING_WRAPPER_ELEMENTS;
  }

  if (attributes != NONE) {
    kind = dictionary_kind;
  } else if (IsNumberDictionary(elements, isolate)) {
    kind = ShouldConvertToFastElements(
               *object, Cast<NumberDictionary>(elements), index, &new_capacity)
               ? BestFittingFastElementsKind(*object)
               : dictionary_kind;
  } else if (ShouldConvertToSlowElements(
                 *object, static_cast<uint32_t>(elements->length()), index,
                 &new_capacity)) {
    kind = dictionary_kind;
  }

  ElementsKind to = Object::OptimalElementsKind(*value, isolate);
  if (IsHoleyElementsKind(kind) || !IsJSArray(*object, isolate) ||
      index > old_length) {
    to = GetHoleyElementsKind(to);
    kind = GetHoleyElementsKind(kind);
  }
  to = GetMoreGeneralElementsKind(kind, to);
  ElementsAccessor* accessor = ElementsAccessor::ForKind(to);
  MAYBE_RETURN(accessor->Add(object, index, value, attributes, new_capacity),
               Nothing<bool>());

  if (IsJSArray(*object, isolate) && index >= old_length) {
    DirectHandle<Number> new_length =
        isolate->factory()->NewNumberFromUint(index + 1);
    Cast<JSArray>(*object)->set_length(*new_length);
  }
  return Just(true);
}

template <AllocationSiteUpdateMode update_or_check>
bool JSObject::UpdateAllocationSite(DirectHandle<JSObject> object,
                                    ElementsKind to_kind) {
  if (!IsJSArray(*object)) return false;

  if (!HeapLayout::InYoungGeneration(*object)) return false;

  if (Heap::IsLargeObject(*object)) return false;

  Handle<AllocationSite> site;
  {
    DisallowGarbageCollection no_gc;

    Heap* heap = object->GetHeap();
    Tagged<AllocationMemento> memento =
        PretenuringHandler::FindAllocationMemento<
            PretenuringHandler::kForRuntime>(heap, object->map(), *object);
    if (memento.is_null()) return false;

    // Walk through to the Allocation Site
    site = handle(memento->GetAllocationSite(), heap->isolate());
  }
  return AllocationSite::DigestTransitionFeedback<update_or_check>(site,
                                                                   to_kind);
}

template bool
JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kCheckOnly>(
    DirectHandle<JSObject> object, ElementsKind to_kind);

template bool JSObject::UpdateAllocationSite<AllocationSiteUpdateMode::kUpdate>(
    DirectHandle<JSObject> object, ElementsKind to_kind);

void JSObject::TransitionElementsKind(Handle<JSObject> object,
                                      ElementsKind to_kind) {
  ElementsKind from_kind = object->GetElementsKind();

  if (IsHoleyElementsKind(from_kind)) {
    to_kind = GetHoleyElementsKind(to_kind);
  }

  if (from_kind == to_kind) return;

  // This method should never be called for any other case.
  DCHECK(IsFastElementsKind(from_kind) ||
         IsNonextensibleElementsKind(from_kind));
  DCHECK(IsFastElementsKind(to_kind) || IsNonextensibleElementsKind(to_kind));
  DCHECK_NE(TERMINAL_FAST_ELEMENTS_KIND, from_kind);

  UpdateAllocationSite(object, to_kind);
  Isolate* isolate = object->GetIsolate();
  if (object->elements() == ReadOnlyRoots(isolate).empty_fixed_array() ||
      IsDoubleElementsKind(from_kind) == IsDoubleElementsKind(to_kind)) {
    // No change is needed to the elements() buffer, the transition
    // only requires a map change.
    DirectHandle<Map> new_map = GetElementsTransitionMap(object, to_kind);
    JSObject::MigrateToMap(isolate, object, new_map);
    if (v8_flags.trace_elements_transitions) {
      DirectHandle<FixedArrayBase> elms(object->elements(), isolate);
      PrintElementsTransition(stdout, object, from_kind, elms, to_kind, elms);
    }
  } else {
    DCHECK((IsSmiElementsKind(from_kind) && IsDoubleElementsKind(to_kind)) ||
           (IsDoubleElementsKind(from_kind) && IsObjectElementsKind(to_kind)));
    uint32_t c = static_cast<uint32_t>(object->elements()->length());
    if (ElementsAccessor::ForKind(to_kind)
            ->GrowCapacityAndConvert(object, c)
            .IsNothing()) {
      // TODO(victorgomes): Temporarily forcing a fatal error here in case of
      // overflow, until all users of TransitionElementsKind can handle
      // exceptions.
      FATAL(
          "Fatal JavaScript invalid size error when transitioning elements "
          "kind");
      UNREACHABLE();
    }
  }
}

template <typename BackingStore>
static int HoleyElementsUsage(Tagged<JSObject> object,
                              Tagged<BackingStore> store) {
  Isolate* isolate = object->GetIsolate();
  int limit = IsJSArray(object) ? Smi::ToInt(Cast<JSArray>(object)->length())
                                : store->length();
  int used = 0;
  for (int i = 0; i < limit; ++i) {
    if (!store->is_the_hole(isolate, i)) ++used;
  }
  return used;
}

int JSObject::GetFastElementsUsage() {
  Tagged<FixedArrayBase> store = elements();
  switch (GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS:
      return IsJSArray(*this) ? Smi::ToInt(Cast<JSArray>(*this)->length())
                              : store->length();
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
      store = Cast<SloppyArgumentsElements>(store)->arguments();
      [[fallthrough]];
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
      return HoleyElementsUsage(*this, Cast<FixedArray>(store));
    case HOLEY_DOUBLE_ELEMENTS:
      if (elements()->length() == 0) return 0;
      return HoleyElementsUsage(*this, Cast<FixedDoubleArray>(store));

    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case DICTIONARY_ELEMENTS:
    case WASM_ARRAY_ELEMENTS:
    case NO_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:

      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      UNREACHABLE();
  }
  return 0;
}

MaybeHandle<JSAny> JSObject::GetPropertyWithInterceptor(LookupIterator* it,
                                                        bool* done) {
  DCHECK_EQ(LookupIterator::INTERCEPTOR, it->state());
  return GetPropertyWithInterceptorInternal(it, it->GetInterceptor(), done);
}

Maybe<bool> JSObject::HasRealNamedProperty(Isolate* isolate,
                                           Handle<JSObject> object,
                                           Handle<Name> name) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  return HasProperty(&it);
}

Maybe<bool> JSObject::HasRealElementProperty(Isolate* isolate,
                                             Handle<JSObject> object,
                                             uint32_t index) {
  LookupIterator it(isolate, object, index, object,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  return HasProperty(&it);
}

Maybe<bool> JSObject::HasRealNamedCallbackProperty(Isolate* isolate,
                                                   Handle<JSObject> object,
                                                   Handle<Name> name) {
  PropertyKey key(isolate, name);
  LookupIterator it(isolate, object, key, LookupIterator::OWN_SKIP_INTERCEPTOR);
  Maybe<PropertyAttributes> maybe_result = GetPropertyAttributes(&it);
  return maybe_result.IsJust() ? Just(it.state() == LookupIterator::ACCESSOR)
                               : Nothing<bool>();
}

Tagged<Object> JSObject::RawFastPropertyAtCompareAndSwap(
    FieldIndex index, Tagged<Object> expected, Tagged<Object> value,
    SeqCstAccessTag tag) {
  return HeapObject::SeqCst_CompareAndSwapField(
      expected, value,
      [=, this](Tagged<Object> expected_value, Tagged<Object> new_value) {
        return RawFastPropertyAtCompareAndSwapInternal(index, expected_value,
                                                       new_value, tag);
      });
}

bool JSGlobalProxy::IsDetached() { return !GetCreationContext().has_value(); }

void JSGlobalObject::InvalidatePropertyCell(DirectHandle<JSGlobalObject> global,
                                            Handle<Name> name) {
  Isolate* isolate = global->GetIsolate();
  // Regardless of whether the property is there or not invalidate
  // Load/StoreGlobalICs that load/store through global object's prototype.
  JSObject::InvalidatePrototypeValidityCell(*global);
  DCHECK(!global->HasFastProperties());
  auto dictionary = handle(global->global_dictionary(kAcquireLoad), isolate);
  InternalIndex entry = dictionary->FindEntry(isolate, name);
  if (entry.is_not_found()) return;

  DirectHandle<PropertyCell> cell(dictionary->CellAt(entry), isolate);
  DirectHandle<Object> value(cell->value(), isolate);
  PropertyDetails details = cell->property_details();
  details = details.set_cell_type(PropertyCellType::kMutable);
  PropertyCell::InvalidateAndReplaceEntry(isolate, dictionary, entry, details,
                                          value);
}

// static
MaybeHandle<JSDate> JSDate::New(Handle<JSFunction> constructor,
                                Handle<JSReceiver> new_target, double tv) {
  Handle<JSDate> result;
  ASSIGN_RETURN_ON_EXCEPTION(
      constructor->GetIsolate(), result,
      Cast<JSDate>(JSObject::New(constructor, new_target,
                                 Handle<AllocationSite>::null())));
  if (DateCache::TryTimeClip(&tv)) {
    result->SetValue(tv);
  } else {
    result->SetNanValue();
  }
  return result;
}

// static
int64_t JSDate::CurrentTimeValue(Isolate* isolate) {
  if (v8_flags.log_timer_events) LOG(isolate, CurrentTimeEvent());
  if (v8_flags.correctness_fuzzer_suppressions) return 4;

  // According to ECMA-262, section 15.9.1, page 117, the precision of
  // the number in a Date object representing a particular instant in
  // time is milliseconds. Therefore, we floor the result of getting
  // the OS time.
  return V8::GetCurrentPlatform()->CurrentClockTimeMilliseconds();
}

// static
Address JSDate::GetField(Isolate* isolate, Address raw_object,
                         Address smi_index) {
  // Called through CallCFunction.
  DisallowGarbageCollection no_gc;
  DisallowHandleAllocation no_handles;
  DisallowJavascriptExecution no_js(isolate);

  Tagged<Object> object(raw_object);
  Tagged<Smi> index(smi_index);
  return Cast<JSDate>(object)
      ->DoGetField(isolate, static_cast<FieldIndex>(index.value()))
      .ptr();
}

Tagged<Object> JSDate::DoGetField(Isolate* isolate, FieldIndex index) {
  DateCache* date_cache = isolate->date_cache();

  if (index < kFirstUncachedField) {
    Tagged<Object> stamp = cache_stamp();
    if (stamp != date_cache->stamp() && IsSmi(stamp)) {
      // Since the stamp is not NaN, the value is also not NaN.
      int64_t local_time_ms =
          date_cache->ToLocal(static_cast<int64_t>(value()));
      SetCachedFields(local_time_ms, date_cache);
    }
    switch (index) {
      case kYear:
        return year();
      case kMonth:
        return month();
      case kDay:
        return day();
      case kWeekday:
        return weekday();
      case kHour:
        return hour();
      case kMinute:
        return min();
      case kSecond:
        return sec();
      default:
        UNREACHABLE();
    }
  }

  if (index >= kFirstUTCField) {
    return GetUTCField(index, value(), date_cache);
  }

  double time = value();
  if (std::isnan(time)) return GetReadOnlyRoots().nan_value();

  int64_t local_time_ms = date_cache->ToLocal(static_cast<int64_t>(time));
  int days = DateCache::DaysFromTime(local_time_ms);

  if (index == kDays) return Smi::FromInt(days);

  int time_in_day_ms = DateCache::TimeInDay(local_time_ms, days);
  if (index == kMillisecond) return Smi::FromInt(time_in_day_ms % 1000);
  DCHECK_EQ(index, kTimeInDay);
  return Smi::FromInt(time_in_day_ms);
}

Tagged<Object> JSDate::GetUTCField(FieldIndex index, double value,
                                   DateCache* date_cache) {
  DCHECK_GE(index, kFirstUTCField);

  if (std::isnan(value)) return GetReadOnlyRoots().nan_value();

  int64_t time_ms = static_cast<int64_t>(value);

  if (index == kTimezoneOffset) {
    return Smi::FromInt(date_cache->TimezoneOffset(time_ms));
  }

  int days = DateCache::DaysFromTime(time_ms);

  if (index == kWeekdayUTC) return Smi::FromInt(date_cache->Weekday(days));

  if (index <= kDayUTC) {
    int year, month, day;
    date_cache->YearMonthDayFromDays(days, &year, &month, &day);
    if (index == kYearUTC) return Smi::FromInt(year);
    if (index == kMonthUTC) return Smi::FromInt(month);
    DCHECK_EQ(index, kDayUTC);
    return Smi::FromInt(day);
  }

  int time_in_day_ms = DateCache::TimeInDay(time_ms, days);
  switch (index) {
    case kHourUTC:
      return Smi::FromInt(time_in_day_ms / (60 * 60 * 1000));
    case kMinuteUTC:
      return Smi::FromInt((time_in_day_ms / (60 * 1000)) % 60);
    case kSecondUTC:
      return Smi::FromInt((time_in_day_ms / 1000) % 60);
    case kMillisecondUTC:
      return Smi::FromInt(time_in_day_ms % 1000);
    case kDaysUTC:
      return Smi::FromInt(days);
    case kTimeInDayUTC:
      return Smi::FromInt(time_in_day_ms);
    default:
      UNREACHABLE();
  }

  UNREACHABLE();
}

// static
void JSDate::SetValue(double value) {
#ifdef DEBUG
  DCHECK(!std::isnan(value));
  double clipped_value = value;
  DCHECK(DateCache::TryTimeClip(&clipped_value));
  DCHECK_EQ(value, clipped_value);
#endif
  set_value(value);
  set_cache_stamp(Smi::FromInt(DateCache::kInvalidStamp), SKIP_WRITE_BARRIER);
}
void JSDate::SetNanValue() {
  set_value(std::numeric_limits<double>::quiet_NaN());

  Tagged<HeapNumber> nan = GetReadOnlyRoots().nan_value();
  set_cache_stamp(nan, SKIP_WRITE_BARRIER);
  set_year(nan, SKIP_WRITE_BARRIER);
  set_month(nan, SKIP_WRITE_BARRIER);
  set_day(nan, SKIP_WRITE_BARRIER);
  set_hour(nan, SKIP_WRITE_BARRIER);
  set_min(nan, SKIP_WRITE_BARRIER);
  set_sec(nan, SKIP_WRITE_BARRIER);
  set_weekday(nan, SKIP_WRITE_BARRIER);
}

void JSDate::SetCachedFields(int64_t local_time_ms, DateCache* date_cache) {
  int days = DateCache::DaysFromTime(local_time_ms);
  int time_in_day_ms = DateCache::TimeInDay(local_time_ms, days);
  int year, month, day;
  date_cache->YearMonthDayFromDays(days, &year, &month, &day);
  int weekday = date_cache->Weekday(days);
  int hour = time_in_day_ms / (60 * 60 * 1000);
  int min = (time_in_day_ms / (60 * 1000)) % 60;
  int sec = (time_in_day_ms / 1000) % 60;
  set_cache_stamp(date_cache->stamp());
  set_year(Smi::FromInt(year), SKIP_WRITE_BARRIER);
  set_month(Smi::FromInt(month), SKIP_WRITE_BARRIER);
  set_day(Smi::FromInt(day), SKIP_WRITE_BARRIER);
  
"""


```
Response:
Let's break down the thought process for analyzing this C++ header file and generating the explanation.

1. **Understanding the Core Request:** The primary goal is to explain the functionality of `v8/src/objects/map-inl.h`. The prompt also highlights specific areas to focus on: Torque files, JavaScript relevance, logic, and common errors.

2. **Initial Scan for Keywords and Patterns:** I started by quickly reading through the code, looking for familiar terms and patterns. I noticed:
    * **`Map::`**:  This strongly suggests the file is defining inline methods for the `Map` class.
    * **`Get...`, `Set...`**:  These are typical getter and setter methods, indicating access and modification of `Map` properties.
    * **`BelongsToSameNativeContextAs`**: This points to the concept of different execution environments within V8.
    * **`constructor_or_back_pointer`**:  A key attribute related to object creation and inheritance.
    * **`prototype`**:  Central to JavaScript's prototypal inheritance.
    * **`NormalizedMapCache`**:  A potential optimization mechanism.
    * **`DEF_GETTER`**:  A macro likely simplifying the definition of getter methods.
    * **`DCHECK`, `CHECK`**:  Assertions used for debugging and enforcing invariants.
    * **`Smi`, `Tagged`, `HeapObject`, `JSFunction`, `Context`**:  V8's internal type system.

3. **Identifying Key Functionality Blocks:** I started grouping related methods and concepts:
    * **Prototype Chain Validation (`IsValidPrototypeChain`)**:  Clearly dealing with the correctness of the prototype chain.
    * **Native Contexts (`BelongsToSameNativeContextAs`)**:  Managing relationships between maps and execution environments.
    * **Constructor Retrieval (`GetConstructorRaw`, `GetConstructor`, `TryGetConstructor`)**:  Focusing on how to find the constructor associated with a map.
    * **Non-Instance Prototypes (`GetNonInstancePrototype`)**: A less common but important feature for certain object types.
    * **Function Template Information (`GetFunctionTemplateInfo`)**: Connecting maps to API functions.
    * **Constructor Setting (`SetConstructor`)**: Modifying the constructor.
    * **Map Copying (`CopyInitialMap`)**:  Creating copies of initial maps.
    * **In-object Slack Tracking (`IsInobjectSlackTrackingInProgress`, `InobjectSlackTrackingStep`)**:  An optimization related to object layout.
    * **Normalized Map Cache (`NormalizedMapCache`)**:  A caching mechanism for performance.

4. **Considering the ".inl.h" Extension and Torque:** The prompt specifically asks about `.tq`. Since this is `.inl.h`, it signifies *inline* implementations. Inline functions are meant for performance by potentially reducing function call overhead. The prompt's mention of `.tq` (Torque) is a bit of a red herring *in this specific case*. This file *isn't* a Torque file. It's important to address this distinction in the explanation.

5. **Relating to JavaScript (and Providing Examples):** This is crucial. For each functional block, I thought about how it manifests in JavaScript:
    * Prototype chain validation ->  How JavaScript resolves properties.
    * Native contexts ->  `<iframe>`s or different V8 isolates.
    * Constructors -> The `class` keyword, constructor functions, `Object.create()`.
    * Non-instance prototypes ->  Less directly exposed, but related to the internal workings of certain built-in objects.
    * Function templates ->  Used when creating native extensions or when V8's built-in objects are created.

6. **Thinking about Logic and Examples:**  For methods like `IsValidPrototypeChain`, I considered the steps involved and how to demonstrate them with simple inputs and outputs. The key is to create scenarios where the function would return `true` or `false`.

7. **Identifying Common Programming Errors:** I tried to connect the C++ concepts to common mistakes JavaScript developers might make:
    * Modifying the prototype chain incorrectly.
    * Confusing objects from different execution contexts.
    * Incorrectly setting up inheritance.

8. **Structuring the Explanation:** I organized the information logically:
    * Start with a general overview of the file's purpose.
    * Explain each functional block in detail.
    * Address the `.tq` question.
    * Provide JavaScript examples where relevant.
    * Discuss logic and examples.
    * Cover common errors.
    * Summarize the overall functionality in the conclusion.

9. **Refining and Adding Detail:** After the initial draft, I reviewed it to:
    * Ensure accuracy.
    * Add more technical details where appropriate (e.g., explaining "inline").
    * Clarify any ambiguous points.
    * Ensure the JavaScript examples were clear and relevant.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the technical C++ details. However, the prompt explicitly asks about JavaScript relevance. This would prompt me to go back and ensure I'm connecting the C++ code to concrete JavaScript concepts and providing illustrative examples. Similarly, the `.tq` question requires careful distinction – it's not enough to just say "it's not a Torque file";  explaining *why* (it's an inline header) is important. I might also initially miss some of the more subtle functionalities, like non-instance prototypes, and then add those in after a more careful reread of the code.
```cpp
bool Map::IsValidPrototypeChain(PtrComprCageBase cage_base) const {
  // The prototype validity cell is located in the same object as the map.
  Tagged<MaybeObject> maybe_validity_cell = prototype_validity_cell(cage_base);
  if (maybe_validity_cell == kNullAddress) return true;
  Tagged<Object> validity_cell;
  if (!maybe_validity_cell.To(&validity_cell)) return false;
  if (IsSmi(validity_cell)) {
    return validity_cell == Smi::FromInt(Map::kPrototypeChainValid);
  }
  Tagged<Cell> cell = Cast<Cell>(validity_cell);
  Object raw_value = cell->raw_value();
  if (raw_value.IsSmi()) {
    return Smi::ToInt(raw_value) == Map::kPrototypeChainValid;
  }
  return AccessorConstantTag(raw_value) == kMapObjectType;
}

bool Map::UpdateValidityCell(PtrComprCageBase cage_base) {
  // The prototype validity cell is located in the same object as the map.
  Tagged<MaybeObject> maybe_validity_cell = prototype_validity_cell(cage_base);
  if (maybe_validity_cell == kNullAddress) return true;
  Tagged<Object> validity_cell;
  if (!maybe_validity_cell.To(&validity_cell)) return false;
  if (IsSmi(validity_cell)) return true;
  Tagged<Smi> cell_value = Cast<Smi>(Cast<Cell>(validity_cell)->value());
  return cell_value == Smi::FromInt(Map::kPrototypeChainValid);
}

bool Map::BelongsToSameNativeContextAs(Tagged<Map> other_map) const {
  Tagged<Map> this_meta_map = map();
  // If the meta map is contextless (as in case of remote object's meta map)
  // we can't be sure the maps belong to the same context.
  if (this_meta_map == GetReadOnlyRoots().meta_map()) return false;
  DCHECK(IsNativeContext(this_meta_map->native_context_or_null()));
  return this_meta_map == other_map->map();
}

bool Map::BelongsToSameNativeContextAs(Tagged<Context> context) const {
  Tagged<Map> context_meta_map = context->map()->map();
  Tagged<Map> this_meta_map = map();
  DCHECK_NE(context_meta_map, GetReadOnlyRoots().meta_map());
  return this_meta_map == context_meta_map;
}

DEF_GETTER(Map, GetConstructorRaw, Tagged<Object>) {
  Tagged<Object> maybe_constructor = constructor_or_back_pointer(cage_base);
  // Follow any back pointers.
  // We don't expect maps from another native context in the transition tree,
  // so just compare object's map against current map's meta map.
  Tagged<Map> meta_map = map(cage_base);
  while (
      ConcurrentIsHeapObjectWithMap(cage_base, maybe_constructor, meta_map)) {
    DCHECK(IsMap(maybe_constructor));
    // Sanity check - only contextful maps can transition.
    DCHECK(IsNativeContext(meta_map->native_context_or_null()));
    maybe_constructor =
        Cast<Map>(maybe_constructor)->constructor_or_back_pointer(cage_base);
  }
  // If it was a map that'd mean that there are maps from different native
  // contexts in the transition tree.
  DCHECK(!IsMap(maybe_constructor));
  return maybe_constructor;
}

DEF_GETTER(Map, GetNonInstancePrototype, Tagged<Object>) {
  DCHECK(has_non_instance_prototype());
  Tagged<Object> raw_constructor = GetConstructorRaw(cage_base);
  CHECK(IsTuple2(raw_constructor));
  // Get prototype from the {constructor, non-instance_prototype} tuple.
  Tagged<Tuple2> non_instance_prototype_constructor_tuple =
      Cast<Tuple2>(raw_constructor);
  Tagged<Object> result = non_instance_prototype_constructor_tuple->value2();
  DCHECK(!IsJSReceiver(result));
  DCHECK(!IsFunctionTemplateInfo(result));
  return result;
}

DEF_GETTER(Map, GetConstructor, Tagged<Object>) {
  Tagged<Object> maybe_constructor = GetConstructorRaw(cage_base);
  if (IsTuple2(maybe_constructor)) {
    // Get constructor from the {constructor, non-instance_prototype} tuple.
    maybe_constructor = Cast<Tuple2>(maybe_constructor)->value1();
  }
  return maybe_constructor;
}

Tagged<Object> Map::TryGetConstructor(PtrComprCageBase cage_base,
                                      int max_steps) {
  Tagged<Object> maybe_constructor = constructor_or_back_pointer(cage_base);
  // Follow any back pointers.
  while (IsMap(maybe_constructor, cage_base)) {
    if (max_steps-- == 0) return Smi::FromInt(0);
    maybe_constructor =
        Cast<Map>(maybe_constructor)->constructor_or_back_pointer(cage_base);
  }
  if (IsTuple2(maybe_constructor)) {
    // Get constructor from the {constructor, non-instance_prototype} tuple.
    maybe_constructor = Cast<Tuple2>(maybe_constructor)->value1();
  }
  return maybe_constructor;
}

DEF_GETTER(Map, GetFunctionTemplateInfo, Tagged<FunctionTemplateInfo>) {
  Tagged<Object> constructor = GetConstructor(cage_base);
  if (IsJSFunction(constructor, cage_base)) {
    Tagged<SharedFunctionInfo> sfi =
        Cast<JSFunction>(constructor)->shared(cage_base);
    DCHECK(sfi->IsApiFunction());
    return sfi->api_func_data();
  }
  DCHECK(IsFunctionTemplateInfo(constructor, cage_base));
  return Cast<FunctionTemplateInfo>(constructor);
}

void Map::SetConstructor(Tagged<Object> constructor, WriteBarrierMode mode) {
  // Never overwrite a back pointer with a constructor.
  CHECK(!IsMap(constructor_or_back_pointer()));
  // Constructor field must contain {constructor, non-instance_prototype} tuple
  // for maps with non-instance prototype.
  DCHECK_EQ(has_non_instance_prototype(), IsTuple2(constructor));
  set_constructor_or_back_pointer(constructor, mode);
}

Handle<Map> Map::CopyInitialMap(Isolate* isolate, Handle<Map> map) {
  return CopyInitialMap(isolate, map, map->instance_size(),
                        map->GetInObjectProperties(),
                        map->UnusedPropertyFields());
}

bool Map::IsInobjectSlackTrackingInProgress() const {
  return construction_counter() != Map::kNoSlackTracking;
}

void Map::InobjectSlackTrackingStep(Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  // Slack tracking should only be performed on an initial map.
  DCHECK(IsUndefined(GetBackPointer()));
  if (!this->IsInobjectSlackTrackingInProgress()) return;
  int counter = construction_counter();
  set_construction_counter(counter - 1);
  if (counter == kSlackTrackingCounterEnd) {
    MapUpdater::CompleteInobjectSlackTracking(isolate, *this);
  }
}

int Map::SlackForArraySize(int old_size, int size_limit) {
  const int max_slack = size_limit - old_size;
  CHECK_LE(0, max_slack);
  if (old_size < 4) {
    DCHECK_LE(1, max_slack);
    return 1;
  }
  return std::min(max_slack, old_size / 4);
}

int Map::InstanceSizeFromSlack(int slack) const {
  return instance_size() - slack * kTaggedSize;
}

NEVER_READ_ONLY_SPACE_IMPL(NormalizedMapCache)

int NormalizedMapCache::GetIndex(Isolate* isolate, Tagged<Map> map,
                                 Tagged<HeapObject> prototype) {
  DisallowGarbageCollection no_gc;
  return map->Hash(isolate, prototype) % NormalizedMapCache::kEntries;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNormalizedMapCache) {
  if (!IsWeakFixedArray(obj, cage_base)) return false;
  if (Cast<WeakFixedArray>(obj)->length() != NormalizedMapCache::kEntries) {
    return false;
  }
  return true;
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_MAP_INL_H_
```

## 功能归纳 (第 2 部分)

This part of `v8/src/objects/map-inl.h` continues to define inline methods for the `Map` object in V8. Here's a summary of its key functionalities:

**1. Prototype Chain Management:**

* **`IsValidPrototypeChain(PtrComprCageBase cage_base) const`**: Checks if the prototype chain associated with this `Map` is valid. This involves inspecting a "validity cell" which can be a simple Smi or a more complex Cell object. It ensures the integrity of the inheritance structure.
* **`UpdateValidityCell(PtrComprCageBase cage_base)`**:  Potentially updates the validity cell. Although the current implementation simply returns `true` if it's not a Smi, the name suggests its purpose is to manage the state of prototype chain validity.

**2. Native Context Awareness:**

* **`BelongsToSameNativeContextAs(Tagged<Map> other_map) const`**: Determines if this `Map` and another `Map` belong to the same V8 NativeContext. Native contexts are like isolated JavaScript environments (e.g., different iframes). This is crucial for preventing cross-context access violations.
* **`BelongsToSameNativeContextAs(Tagged<Context> context) const`**: Checks if this `Map` belongs to the same NativeContext as the provided `Context` object.

**3. Constructor Retrieval:**

* **`GetConstructorRaw(PtrComprCageBase cage_base)`**: Retrieves the raw constructor associated with the `Map`. It follows "back pointers" in the `Map`'s structure to find the constructor. It handles cases where a `Map` might point to another `Map` as a way to link to its constructor.
* **`GetNonInstancePrototype(PtrComprCageBase cage_base)`**:  Retrieves the non-instance prototype. This is used for specific object types where the prototype is not a regular JavaScript object. The constructor in these cases is a tuple containing the actual constructor and the non-instance prototype.
* **`GetConstructor(PtrComprCageBase cage_base)`**: Retrieves the JavaScript constructor function associated with the `Map`. It handles the case where the constructor is stored as a tuple (when a non-instance prototype is involved) and extracts the actual constructor.
* **`TryGetConstructor(PtrComprCageBase cage_base, int max_steps)`**:  Similar to `GetConstructor`, but with a limit on the number of steps to follow back pointers. This can be used to prevent infinite loops in potentially corrupted object graphs.

**4. Function Template Information:**

* **`GetFunctionTemplateInfo(PtrComprCageBase cage_base)`**: If the constructor is a JavaScript function created from a Function Template (used for binding C++ functions to JavaScript), this method retrieves the `FunctionTemplateInfo` object.

**5. Constructor Setting:**

* **`SetConstructor(Tagged<Object> constructor, WriteBarrierMode mode)`**: Sets the constructor for the `Map`. It includes checks to ensure a back pointer isn't overwritten and that the constructor field is correctly formatted when a non-instance prototype is present.

**6. Map Copying:**

* **`CopyInitialMap(Isolate* isolate, Handle<Map> map)`**: Creates a copy of an "initial map". Initial maps are the blueprints for objects and are often shared.

**7. In-object Slack Tracking (Optimization):**

* **`IsInobjectSlackTrackingInProgress() const`**: Checks if the `Map` is currently undergoing "in-object slack tracking". This is an optimization technique where V8 initially allocates more in-object properties than needed and then later trims the excess.
* **`InobjectSlackTrackingStep(Isolate* isolate)`**: Performs one step of the in-object slack tracking process.
* **`SlackForArraySize(int old_size, int size_limit)`**: Calculates the amount of "slack" to add when resizing an array-like object.
* **`InstanceSizeFromSlack(int slack) const`**: Calculates the instance size based on the amount of slack.

**8. Normalized Map Cache:**

* **`NormalizedMapCache` and its related methods (`GetIndex`, `IsNormalizedMapCache`)**: Deals with a cache for "normalized maps". This is an optimization to quickly find canonical maps for objects with the same structure, especially after prototype chain manipulations.

**关于 .tq 后缀:**

您在问题中提到如果文件以 `.tq` 结尾，则它是 Torque 源代码。  `v8/src/objects/map-inl.h` 实际上是以 `.h` 结尾的 C++ 头文件，其中包含了 `Map` 类内联方法的定义。 **它不是 Torque 源代码。** Torque 文件通常用于定义 V8 内部函数的快速路径和类型安全操作。

**与 JavaScript 功能的关系及示例:**

This part of the code is deeply connected to JavaScript's object model and how V8 implements it:

* **原型链 (`IsValidPrototypeChain`)**: This directly relates to how JavaScript resolves properties. When you access a property on an object, JavaScript walks up the prototype chain until it finds the property. This function ensures that walk is valid.

   ```javascript
   const obj = {};
   const proto = { x: 10 };
   Object.setPrototypeOf(obj, proto);
   console.log(obj.x); // JavaScript implicitly traverses the prototype chain
   ```

* **原生上下文 (`BelongsToSameNativeContextAs`)**: This is relevant when dealing with `<iframe>` elements or different V8 isolates. Objects from different contexts cannot directly access each other's properties in most cases.

   ```javascript
   // In iframe 1:
   const iframe1Obj = { data: 1 };

   // In iframe 2 (attempting to access iframe1Obj):
   // This will likely result in an error or restricted access due to cross-context boundaries.
   // console.log(parent.iframe1Obj.data);
   ```

* **构造函数 (`GetConstructor`, `SetConstructor`)**:  The concept of a constructor is fundamental to JavaScript. Classes and constructor functions define how objects are created.

   ```javascript
   class MyClass {
       constructor(value) {
           this.value = value;
       }
   }
   const instance = new MyClass(5);
   console.log(instance.constructor); // Points to the MyClass constructor
   ```

* **非实例原型 (`GetNonInstancePrototype`)**: While less commonly directly manipulated in user-level JavaScript, this relates to the internal workings of certain built-in objects. For example, functions have a `prototype` property that's used when they are used as constructors.

* **Function Template 信息 (`GetFunctionTemplateInfo`)**:  Used when creating native extensions in V8. JavaScript functions can be backed by C++ code, and Function Templates provide the link.

* **In-object Slack Tracking**: This is an internal V8 optimization and not directly visible in JavaScript code. However, it affects the performance of object creation and property access.

**代码逻辑推理和示例:**

Let's consider `IsValidPrototypeChain`:

**假设输入:**  一个指向 `Map` 对象的指针，该 `Map` 对象代表一个 JavaScript 对象，其原型链可能有效或无效。

**场景 1 (有效原型链):**
* `Map` 对象的 `prototype_validity_cell` 指向一个 `Smi`，其值为 `Map::kPrototypeChainValid`。
* **输出:** `true`

**场景 2 (有效原型链，使用 Cell):**
* `Map` 对象的 `prototype_validity_cell` 指向一个 `Cell`，该 `Cell` 的 `value` 是一个 `Smi`，其值为 `Map::kPrototypeChainValid`。
* **输出:** `true`

**场景 3 (无效原型链):**
* `Map` 对象的 `prototype_validity_cell` 指向一个 `Smi`，其值**不是** `Map::kPrototypeChainValid`。
* **输出:** `false`

**场景 4 (原型链正在构建中):**
* `Map` 对象的 `prototype_validity_cell` 是 `kNullAddress`。 这可能发生在对象创建的早期阶段。
* **输出:** `true` (可能表示暂时有效或正在构建)

**用户常见的编程错误:**

* **跨原生上下文访问对象:**  试图在不同的 `<iframe>` 或 V8 上下文之间直接传递和操作对象，可能导致错误或安全问题。`BelongsToSameNativeContextAs` 相关的检查旨在防止这种情况。

   ```javascript
   // 错误示例 (可能在控制台中尝试访问 iframe 的变量):
   // console.log(document.getElementById('myIframe').contentWindow.someVariable);
   // 这样做可能会因为跨域策略或上下文隔离而失败。
   ```

* **不正确的原型链操作:**  手动修改对象的原型链可能会导致意外的行为或性能问题，如果操作不当，可能会导致 `IsValidPrototypeChain` 返回 `false`。

   ```javascript
   const obj = {};
   const brokenProto = 123; // 错误的原型值
   Object.setPrototypeOf(obj, brokenProto); // 这通常会导致错误或奇怪的行为
   // V8 内部的校验可能会发现这种无效的原型链。
   ```

**归纳总结 (第 2 部分功能):**

This second part of `v8/src/objects/map-inl.h` focuses on the following core responsibilities related to the `Map` object:

* **Ensuring the integrity of the prototype chain.**
* **Maintaining awareness of the V8 NativeContext to enforce isolation and prevent cross-context errors.**
* **Providing mechanisms to reliably retrieve the constructor associated with a `Map`, handling different ways constructors can be stored.**
* **Facilitating the retrieval of information about Function Templates.**
* **Supporting internal optimizations like in-object slack tracking and normalized map caching to improve performance.**

These functionalities are critical for V8's correct implementation of JavaScript's object model and its performance. They are largely internal mechanisms that ensure the smooth and secure execution of JavaScript code.

### 提示词
```
这是目录为v8/src/objects/map-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/map-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
ity_cell).value(), Map::kPrototypeChainValid);
    return true;
  }
  Tagged<Smi> cell_value = Cast<Smi>(Cast<Cell>(validity_cell)->value());
  return cell_value == Smi::FromInt(Map::kPrototypeChainValid);
}

bool Map::BelongsToSameNativeContextAs(Tagged<Map> other_map) const {
  Tagged<Map> this_meta_map = map();
  // If the meta map is contextless (as in case of remote object's meta map)
  // we can't be sure the maps belong to the same context.
  if (this_meta_map == GetReadOnlyRoots().meta_map()) return false;
  DCHECK(IsNativeContext(this_meta_map->native_context_or_null()));
  return this_meta_map == other_map->map();
}

bool Map::BelongsToSameNativeContextAs(Tagged<Context> context) const {
  Tagged<Map> context_meta_map = context->map()->map();
  Tagged<Map> this_meta_map = map();
  DCHECK_NE(context_meta_map, GetReadOnlyRoots().meta_map());
  return this_meta_map == context_meta_map;
}

DEF_GETTER(Map, GetConstructorRaw, Tagged<Object>) {
  Tagged<Object> maybe_constructor = constructor_or_back_pointer(cage_base);
  // Follow any back pointers.
  // We don't expect maps from another native context in the transition tree,
  // so just compare object's map against current map's meta map.
  Tagged<Map> meta_map = map(cage_base);
  while (
      ConcurrentIsHeapObjectWithMap(cage_base, maybe_constructor, meta_map)) {
    DCHECK(IsMap(maybe_constructor));
    // Sanity check - only contextful maps can transition.
    DCHECK(IsNativeContext(meta_map->native_context_or_null()));
    maybe_constructor =
        Cast<Map>(maybe_constructor)->constructor_or_back_pointer(cage_base);
  }
  // If it was a map that'd mean that there are maps from different native
  // contexts in the transition tree.
  DCHECK(!IsMap(maybe_constructor));
  return maybe_constructor;
}

DEF_GETTER(Map, GetNonInstancePrototype, Tagged<Object>) {
  DCHECK(has_non_instance_prototype());
  Tagged<Object> raw_constructor = GetConstructorRaw(cage_base);
  CHECK(IsTuple2(raw_constructor));
  // Get prototype from the {constructor, non-instance_prototype} tuple.
  Tagged<Tuple2> non_instance_prototype_constructor_tuple =
      Cast<Tuple2>(raw_constructor);
  Tagged<Object> result = non_instance_prototype_constructor_tuple->value2();
  DCHECK(!IsJSReceiver(result));
  DCHECK(!IsFunctionTemplateInfo(result));
  return result;
}

DEF_GETTER(Map, GetConstructor, Tagged<Object>) {
  Tagged<Object> maybe_constructor = GetConstructorRaw(cage_base);
  if (IsTuple2(maybe_constructor)) {
    // Get constructor from the {constructor, non-instance_prototype} tuple.
    maybe_constructor = Cast<Tuple2>(maybe_constructor)->value1();
  }
  return maybe_constructor;
}

Tagged<Object> Map::TryGetConstructor(PtrComprCageBase cage_base,
                                      int max_steps) {
  Tagged<Object> maybe_constructor = constructor_or_back_pointer(cage_base);
  // Follow any back pointers.
  while (IsMap(maybe_constructor, cage_base)) {
    if (max_steps-- == 0) return Smi::FromInt(0);
    maybe_constructor =
        Cast<Map>(maybe_constructor)->constructor_or_back_pointer(cage_base);
  }
  if (IsTuple2(maybe_constructor)) {
    // Get constructor from the {constructor, non-instance_prototype} tuple.
    maybe_constructor = Cast<Tuple2>(maybe_constructor)->value1();
  }
  return maybe_constructor;
}

DEF_GETTER(Map, GetFunctionTemplateInfo, Tagged<FunctionTemplateInfo>) {
  Tagged<Object> constructor = GetConstructor(cage_base);
  if (IsJSFunction(constructor, cage_base)) {
    Tagged<SharedFunctionInfo> sfi =
        Cast<JSFunction>(constructor)->shared(cage_base);
    DCHECK(sfi->IsApiFunction());
    return sfi->api_func_data();
  }
  DCHECK(IsFunctionTemplateInfo(constructor, cage_base));
  return Cast<FunctionTemplateInfo>(constructor);
}

void Map::SetConstructor(Tagged<Object> constructor, WriteBarrierMode mode) {
  // Never overwrite a back pointer with a constructor.
  CHECK(!IsMap(constructor_or_back_pointer()));
  // Constructor field must contain {constructor, non-instance_prototype} tuple
  // for maps with non-instance prototype.
  DCHECK_EQ(has_non_instance_prototype(), IsTuple2(constructor));
  set_constructor_or_back_pointer(constructor, mode);
}

Handle<Map> Map::CopyInitialMap(Isolate* isolate, Handle<Map> map) {
  return CopyInitialMap(isolate, map, map->instance_size(),
                        map->GetInObjectProperties(),
                        map->UnusedPropertyFields());
}

bool Map::IsInobjectSlackTrackingInProgress() const {
  return construction_counter() != Map::kNoSlackTracking;
}

void Map::InobjectSlackTrackingStep(Isolate* isolate) {
  DisallowGarbageCollection no_gc;
  // Slack tracking should only be performed on an initial map.
  DCHECK(IsUndefined(GetBackPointer()));
  if (!this->IsInobjectSlackTrackingInProgress()) return;
  int counter = construction_counter();
  set_construction_counter(counter - 1);
  if (counter == kSlackTrackingCounterEnd) {
    MapUpdater::CompleteInobjectSlackTracking(isolate, *this);
  }
}

int Map::SlackForArraySize(int old_size, int size_limit) {
  const int max_slack = size_limit - old_size;
  CHECK_LE(0, max_slack);
  if (old_size < 4) {
    DCHECK_LE(1, max_slack);
    return 1;
  }
  return std::min(max_slack, old_size / 4);
}

int Map::InstanceSizeFromSlack(int slack) const {
  return instance_size() - slack * kTaggedSize;
}

NEVER_READ_ONLY_SPACE_IMPL(NormalizedMapCache)

int NormalizedMapCache::GetIndex(Isolate* isolate, Tagged<Map> map,
                                 Tagged<HeapObject> prototype) {
  DisallowGarbageCollection no_gc;
  return map->Hash(isolate, prototype) % NormalizedMapCache::kEntries;
}

DEF_HEAP_OBJECT_PREDICATE(HeapObject, IsNormalizedMapCache) {
  if (!IsWeakFixedArray(obj, cage_base)) return false;
  if (Cast<WeakFixedArray>(obj)->length() != NormalizedMapCache::kEntries) {
    return false;
  }
  return true;
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_MAP_INL_H_
```
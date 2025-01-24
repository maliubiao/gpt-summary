Response: Let's break down the thought process for analyzing this C++ code and explaining its function and relation to JavaScript.

1. **Understand the Goal:** The core request is to understand the purpose of the `transitions.cc` file within the V8 engine. The key is the word "transitions," which immediately suggests state changes or transformations within objects. The request also asks about its connection to JavaScript.

2. **Initial Code Scan (Keywords and Structure):**  Quickly scan the file for recurring keywords and the overall structure. Notice:
    * `Map`:  This is fundamental in V8, representing the structure/shape of JavaScript objects.
    * `Transition`: The name of the file and a recurring term.
    * `TransitionArray`: A collection of transitions.
    * `TransitionsAccessor`: A class managing access to transitions.
    * `InsertHelper`, `SearchTransition`, `GetSimpleTransition`: Suggest operations on the transitions data.
    * `PropertyKind`, `PropertyAttributes`: Relate to JavaScript object properties.
    * `Prototype`:  Key concept in JavaScript inheritance.
    * `WeakFixedArray`: A V8 data structure that can hold weak references, likely used for optimization or lifecycle management.
    * `Isolate`: Represents an isolated V8 instance.
    * `MutexGuard`:  Indicates thread safety concerns and potential concurrency.

3. **Focus on the `TransitionsAccessor` Class:** This class seems to be the primary interface for interacting with transitions. Its methods provide clues about the functionality:
    * `GetSimpleTransition`:  Fetching a basic transition.
    * `InsertHelper`: Adding a new transition. The `flag` parameter hints at different kinds of transitions.
    * `SearchTransition`, `SearchSpecial`: Looking up transitions based on property names or special symbols.
    * `PutPrototypeTransition`, `GetPrototypeTransition`:  Specifically dealing with prototype-related transitions.
    * `SetMigrationTarget`, `GetMigrationTarget`:  Handling map migrations (optimizations).
    * `ReplaceTransitions`: Updating the transition data for a map.
    * `EnsureHasFullTransitionArray`: Ensuring a map has a comprehensive transition structure.
    * `TraverseTransitionTreeInternal`:  Navigating the chain of transitions.

4. **Infer the Core Functionality:** Based on the keywords and method names, the core purpose emerges:  `transitions.cc` manages how the *shape* or *structure* of JavaScript objects changes over time as properties are added, deleted, or modified.

5. **Connect to JavaScript Concepts:**  Now, link these C++ concepts to corresponding JavaScript behavior:
    * **Adding properties:**  When you add a property to a JavaScript object, its internal shape needs to change. The `InsertHelper` likely plays a role here, creating a transition to a new `Map` representing the object with the added property.
    * **Deleting properties:** Similar to adding, deletion triggers a shape change and a transition.
    * **Modifying properties (kind/attributes):**  Changing whether a property is writable, enumerable, or configurable also necessitates a transition.
    * **Prototypes and Inheritance:**  JavaScript's prototype chain means objects inherit properties from their prototypes. The `PutPrototypeTransition` and `GetPrototypeTransition` are clearly related to how V8 optimizes access to prototype properties. When the prototype of an object changes, the object's map might need to transition to a new map that reflects the new prototype.
    * **Object integrity (freezing, sealing, preventing extensions):** These operations fundamentally alter the possible transitions for an object. The `SearchSpecial` method and mentions of "nonextensible_symbol", "sealed_symbol", and "frozen_symbol" are directly connected.

6. **Formulate the Explanation:** Structure the explanation logically:
    * Start with a high-level summary of the file's purpose.
    * Explain the key concepts like `Map` and `Transition`.
    * Detail the different types of transitions (simple, full, prototype, migration).
    * Emphasize the optimization aspect – V8 avoids creating new `Map` objects unnecessarily by reusing or adapting existing ones through transitions.
    * Explain the role of `TransitionsAccessor`.

7. **Create JavaScript Examples:**  Craft simple JavaScript code snippets that clearly illustrate the concepts discussed:
    * **Adding a property:** Show how adding a property changes the object's "shape."
    * **Deleting a property:** Demonstrate the shape change upon deletion.
    * **Prototype interaction:**  Illustrate how prototype changes can trigger transitions.
    * **Freezing/Sealing:** Show how these operations limit future transitions.

8. **Refine and Review:**  Read through the explanation and examples to ensure clarity, accuracy, and completeness. Check for any jargon that needs further explanation. Ensure the connection between the C++ code and the JavaScript examples is clear. For instance, initially, I might just say "prototype transitions," but then realize I should explain *why* these are important for optimization in JavaScript inheritance.

Self-Correction Example During the Process:

* **Initial thought:** "Transitions are just about adding properties."
* **Correction:** After seeing `PutPrototypeTransition` and discussions of freezing/sealing, realize transitions are broader. They cover the full lifecycle of an object's structure, including inheritance and integrity levels. Adjust the explanation accordingly.

By following this detailed thought process, combining code analysis with understanding of JavaScript fundamentals, a comprehensive and accurate explanation can be constructed.
这个C++源代码文件 `transitions.cc` 的主要功能是**管理 V8 引擎中 JavaScript 对象的形状（Shape）转换，也就是对象的 `Map` 对象的变更过程**。

**核心概念：**

* **Map (也被称为 Structure 或 Hidden Class):** 在 V8 中，每个 JavaScript 对象都关联着一个 `Map` 对象。`Map` 描述了对象的结构，包括属性的名称、类型、存储位置等信息。拥有相同结构的对象可以共享同一个 `Map`，从而节省内存并提高性能。
* **Transition (转换):** 当一个对象的结构发生变化时（例如，添加、删除或修改属性），V8 会创建一个从旧 `Map` 到新 `Map` 的转换。这些转换被存储起来，以便 V8 可以快速找到新结构的 `Map`，而无需重新计算。
* **TransitionArray (转换数组):**  一个对象 `Map` 可能有多个可能的转换路径。`TransitionArray` 用于存储这些转换，它包含了属性名和指向目标 `Map` 的引用。

**`transitions.cc` 的主要职责：**

1. **存储和访问对象的转换信息:**
   - 它定义了 `TransitionsAccessor` 类，用于管理 `Map` 对象的转换信息。
   - 它提供了方法来获取一个 `Map` 的简单转换 (`GetSimpleTransition`) 或者完整的转换数组。
   - 它还定义了 `TransitionArray` 类，用于存储具体的转换条目。

2. **添加新的转换:**
   - `InsertHelper` 函数负责向一个 `Map` 对象添加新的转换。
   - 当向对象添加新的属性时，V8 会查找是否已存在相应的转换。如果不存在，则会创建一个新的转换，指向包含新属性的 `Map`。
   - 它会根据转换的类型（例如，简单属性转换、特殊转换）选择不同的存储方式和优化策略。

3. **查找和搜索转换:**
   - `SearchTransition` 和 `SearchSpecial` 函数用于根据属性名和属性特性查找目标 `Map`。
   - 这使得 V8 能够快速找到对象在特定结构变化后的 `Map`，而无需遍历所有可能的 `Map`。

4. **管理原型链的转换:**
   - `PutPrototypeTransition` 和 `GetPrototypeTransition` 函数专门用于处理由于原型变更而产生的转换。
   - 当一个对象的原型发生改变时，V8 会缓存相关的转换，以优化后续对原型属性的访问。

5. **处理对象完整性相关的转换:**
   -  代码中涉及到 `nonextensible_symbol`, `sealed_symbol`, `frozen_symbol` 等特殊符号，用于处理 `Object.preventExtensions()`, `Object.seal()`, `Object.freeze()` 等改变对象完整性的操作。

6. **迁移目标 (Migration Target):**
   - `SetMigrationTarget` 和 `GetMigrationTarget` 用于存储和获取对象的迁移目标 `Map`。这是一种优化技术，用于在某些情况下直接将对象迁移到更优化的 `Map` 结构。

**与 JavaScript 的关系及示例:**

`transitions.cc` 文件直接影响 JavaScript 对象的性能和内存使用。每当 JavaScript 代码操作对象的属性时，V8 内部都会涉及到 `transitions.cc` 中的逻辑。

**JavaScript 示例：**

```javascript
// 初始对象，拥有一个属性 'a'
const obj1 = { a: 1 };

// 此时 obj1 关联着一个 Map，描述了拥有属性 'a' 的结构

// 添加新的属性 'b'
obj1.b = 2;

// 当添加属性 'b' 时，V8 会创建一个从旧 Map（只有 'a'）到新 Map（拥有 'a' 和 'b'）的转换。
// 这个转换信息会被存储在旧 Map 的转换数组中。

// 创建另一个拥有相同属性的对象
const obj2 = { a: 3, b: 4 };

// obj2 可以直接使用与 obj1 结构相同的 Map，因为 V8 已经通过转换知道了这个结构。

// 删除属性 'a'
delete obj1.a;

// 删除属性 'a' 会触发另一个转换，从拥有 'a' 和 'b' 的 Map 转换到只有 'b' 的 Map。

// 修改属性的特性（例如，将 'b' 设置为不可枚举）
Object.defineProperty(obj1, 'b', { enumerable: false });

// 这也会导致 Map 的转换，因为属性的特性是 Map 的一部分。

// 改变对象的原型
const proto = { c: 5 };
Object.setPrototypeOf(obj1, proto);

// 原型的改变也会导致 Map 的转换，涉及到 `PutPrototypeTransition` 和 `GetPrototypeTransition`。

// 使用 Object.preventExtensions()
Object.preventExtensions(obj2);

// 这会触发一个特殊的转换，标记 obj2 的 Map 为不可扩展，
// 以后任何添加属性的操作都会失败。相关的逻辑在 `SearchSpecial` 中处理。
```

**总结:**

`transitions.cc` 是 V8 引擎中一个非常重要的组成部分，它负责管理 JavaScript 对象结构变化的元数据。通过高效地存储和查找这些转换信息，V8 可以优化对象的属性访问、内存分配和垃圾回收，从而提升 JavaScript 代码的执行效率。  它隐藏在 JavaScript 引擎的深处，但其运作机制直接影响着我们编写的每一行 JavaScript 代码的性能。

### 提示词
```
这是目录为v8/src/objects/transitions.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/transitions.h"

#include <optional>

#include "src/base/small-vector.h"
#include "src/objects/objects-inl.h"
#include "src/objects/transitions-inl.h"
#include "src/utils/utils.h"

namespace v8::internal {

// static
Tagged<Map> TransitionsAccessor::GetSimpleTransition(Isolate* isolate,
                                                     DirectHandle<Map> map) {
  Tagged<MaybeObject> raw_transitions =
      map->raw_transitions(isolate, kAcquireLoad);
  switch (GetEncoding(isolate, raw_transitions)) {
    case kWeakRef:
      return Cast<Map>(raw_transitions.GetHeapObjectAssumeWeak());
    default:
      return Tagged<Map>();
  }
}

bool TransitionsAccessor::HasSimpleTransitionTo(Tagged<Map> map) {
  switch (encoding()) {
    case kWeakRef:
      return raw_transitions_.GetHeapObjectAssumeWeak() == map;
    case kPrototypeInfo:
    case kUninitialized:
    case kMigrationTarget:
    case kFullTransitionArray:
      return false;
  }
  UNREACHABLE();
}

// static
void TransitionsAccessor::InsertHelper(Isolate* isolate, DirectHandle<Map> map,
                                       DirectHandle<Name> name,
                                       DirectHandle<Map> target,
                                       TransitionKindFlag flag) {
  DCHECK_NE(flag, PROTOTYPE_TRANSITION);
  Encoding encoding = GetEncoding(isolate, map);
  DCHECK_NE(kPrototypeInfo, encoding);
  ReadOnlyRoots roots(isolate);
  (*target)->SetBackPointer(*map);

  // If the map doesn't have any transitions at all yet, install the new one.
  if (encoding == kUninitialized || encoding == kMigrationTarget) {
    if (flag == SIMPLE_PROPERTY_TRANSITION) {
      ReplaceTransitions(isolate, map, MakeWeak(*target));
      return;
    }
    // If the flag requires a full TransitionArray, allocate one.
    DirectHandle<TransitionArray> result =
        isolate->factory()->NewTransitionArray(1, 0);
    result->Set(0, *name, MakeWeak(*target));
    ReplaceTransitions(isolate, map, result);
    DCHECK_EQ(kFullTransitionArray, GetEncoding(isolate, *result));
    return;
  }

  if (encoding == kWeakRef) {
    Tagged<Map> simple_transition = GetSimpleTransition(isolate, map);
    DCHECK(!simple_transition.is_null());

    if (flag == SIMPLE_PROPERTY_TRANSITION) {
      Tagged<Name> key = GetSimpleTransitionKey(simple_transition);
      PropertyDetails old_details =
          simple_transition->GetLastDescriptorDetails(isolate);
      PropertyDetails new_details = GetTargetDetails(*name, **target);
      if (key->Equals(*name) && old_details.kind() == new_details.kind() &&
          old_details.attributes() == new_details.attributes()) {
        ReplaceTransitions(isolate, map, MakeWeak(*target));
        return;
      }
    }

    // Otherwise allocate a full TransitionArray with slack for a new entry.
    DirectHandle<TransitionArray> result =
        isolate->factory()->NewTransitionArray(1, 1);

    // Reload `simple_transition`. Allocations might have caused it to be
    // cleared.
    simple_transition = GetSimpleTransition(isolate, map);
    if (simple_transition.is_null()) {
      result->Set(0, *name, MakeWeak(*target));
      ReplaceTransitions(isolate, map, result);
      DCHECK_EQ(kFullTransitionArray, GetEncoding(isolate, *result));
      return;
    }

    // Insert the original transition in index 0.
    result->Set(0, GetSimpleTransitionKey(simple_transition),
                MakeWeak(simple_transition));

    // Search for the correct index to insert the new transition.
    int insertion_index;
    int index;
    if (flag == SPECIAL_TRANSITION) {
      index =
          result->SearchSpecial(Cast<Symbol>(*name), false, &insertion_index);
    } else {
      PropertyDetails details = GetTargetDetails(*name, **target);
      index = result->Search(details.kind(), *name, details.attributes(),
                             &insertion_index);
    }
    DCHECK_EQ(index, kNotFound);
    USE(index);

    result->SetNumberOfTransitions(2);
    if (insertion_index == 0) {
      // If the new transition will be inserted in index 0, move the original
      // transition to index 1.
      result->Set(1, GetSimpleTransitionKey(simple_transition),
                  MakeWeak(simple_transition));
    }
    result->SetKey(insertion_index, *name);
    result->SetRawTarget(insertion_index, MakeWeak(*target));

    SLOW_DCHECK(result->IsSortedNoDuplicates());
    ReplaceTransitions(isolate, map, result);
    DCHECK_EQ(kFullTransitionArray, GetEncoding(isolate, *result));
    return;
  }

  // At this point, we know that the map has a full TransitionArray.
  DCHECK_EQ(kFullTransitionArray, encoding);

  int number_of_transitions = 0;
  int new_nof = 0;
  int insertion_index = kNotFound;
  const bool is_special_transition = flag == SPECIAL_TRANSITION;
  DCHECK_EQ(is_special_transition, IsSpecialTransition(roots, *name));
  PropertyDetails details = is_special_transition
                                ? PropertyDetails::Empty()
                                : GetTargetDetails(*name, **target);

  {
    DisallowGarbageCollection no_gc;
    Tagged<TransitionArray> array = GetTransitionArray(isolate, map);
    number_of_transitions = array->number_of_transitions();

    int index =
        is_special_transition
            ? array->SearchSpecial(Cast<Symbol>(*name), false, &insertion_index)
            : array->Search(details.kind(), *name, details.attributes(),
                            &insertion_index);
    // If an existing entry was found, overwrite it and return.
    if (index != kNotFound) {
      base::SharedMutexGuard<base::kExclusive> shared_mutex_guard(
          isolate->full_transition_array_access());
      array->SetRawTarget(index, MakeWeak(*target));
      return;
    }

    new_nof = number_of_transitions + 1;
    CHECK_LE(new_nof, kMaxNumberOfTransitions);
    DCHECK_GE(insertion_index, 0);
    DCHECK_LE(insertion_index, number_of_transitions);

    // If there is enough capacity, insert new entry into the existing array.
    if (new_nof <= array->Capacity()) {
      base::SharedMutexGuard<base::kExclusive> shared_mutex_guard(
          isolate->full_transition_array_access());
      array->SetNumberOfTransitions(new_nof);
      for (int i = number_of_transitions; i > insertion_index; --i) {
        array->SetKey(i, array->GetKey(i - 1));
        array->SetRawTarget(i, array->GetRawTarget(i - 1));
      }
      array->SetKey(insertion_index, *name);
      array->SetRawTarget(insertion_index, MakeWeak(*target));
      SLOW_DCHECK(array->IsSortedNoDuplicates());
      return;
    }
  }

  // We're gonna need a bigger TransitionArray.
  DirectHandle<TransitionArray> result = isolate->factory()->NewTransitionArray(
      new_nof,
      Map::SlackForArraySize(number_of_transitions, kMaxNumberOfTransitions));

  // The map's transition array may have shrunk during the allocation above as
  // it was weakly traversed, though it is guaranteed not to disappear. Trim the
  // result copy if needed, and recompute variables.
  DisallowGarbageCollection no_gc;
  Tagged<TransitionArray> array = GetTransitionArray(isolate, map);
  if (array->number_of_transitions() != number_of_transitions) {
    DCHECK_LT(array->number_of_transitions(), number_of_transitions);

    int index =
        is_special_transition
            ? array->SearchSpecial(Cast<Symbol>(*name), false, &insertion_index)
            : array->Search(details.kind(), *name, details.attributes(),
                            &insertion_index);
    CHECK_EQ(index, kNotFound);
    USE(index);
    DCHECK_GE(insertion_index, 0);
    DCHECK_LE(insertion_index, number_of_transitions);

    number_of_transitions = array->number_of_transitions();
    new_nof = number_of_transitions + 1;
    result->SetNumberOfTransitions(new_nof);
  }

  if (array->HasPrototypeTransitions()) {
    result->SetPrototypeTransitions(array->GetPrototypeTransitions());
  }
  if (array->HasSideStepTransitions()) {
    result->SetSideStepTransitions(array->GetSideStepTransitions());
  }

  DCHECK_NE(kNotFound, insertion_index);
  for (int i = 0; i < insertion_index; ++i) {
    result->Set(i, array->GetKey(i), array->GetRawTarget(i));
  }
  result->Set(insertion_index, *name, MakeWeak(*target));
  for (int i = insertion_index; i < number_of_transitions; ++i) {
    result->Set(i + 1, array->GetKey(i), array->GetRawTarget(i));
  }

  SLOW_DCHECK(result->IsSortedNoDuplicates());
  ReplaceTransitions(isolate, map, result);
}

Tagged<Map> TransitionsAccessor::SearchTransition(
    Tagged<Name> name, PropertyKind kind, PropertyAttributes attributes) {
  DCHECK(IsUniqueName(name));
  switch (encoding()) {
    case kPrototypeInfo:
    case kUninitialized:
    case kMigrationTarget:
      return Tagged<Map>();
    case kWeakRef: {
      Tagged<Map> map = Cast<Map>(raw_transitions_.GetHeapObjectAssumeWeak());
      if (!IsMatchingMap(map, name, kind, attributes)) return Tagged<Map>();
      return map;
    }
    case kFullTransitionArray: {
      base::SharedMutexGuardIf<base::kShared> scope(
          isolate_->full_transition_array_access(), concurrent_access_);
      return transitions()->SearchAndGetTarget(kind, name, attributes);
    }
  }
  UNREACHABLE();
}

Tagged<Map> TransitionsAccessor::SearchSpecial(Tagged<Symbol> name) {
  if (encoding() != kFullTransitionArray) return {};
  base::SharedMutexGuardIf<base::kShared> scope(
      isolate_->full_transition_array_access(), concurrent_access_);
  int transition = transitions()->SearchSpecial(name, concurrent_access_);
  if (transition == kNotFound) return {};
  return transitions()->GetTarget(transition);
}

// static
bool TransitionsAccessor::IsSpecialTransition(ReadOnlyRoots roots,
                                              Tagged<Name> name) {
  if (!IsSymbol(name)) return false;
  return name == roots.nonextensible_symbol() ||
         name == roots.sealed_symbol() || name == roots.frozen_symbol() ||
         name == roots.elements_transition_symbol() ||
         name == roots.strict_function_transition_symbol();
}

MaybeHandle<Map> TransitionsAccessor::FindTransitionToField(
    DirectHandle<String> name) {
  DCHECK(IsInternalizedString(*name));
  DisallowGarbageCollection no_gc;
  Tagged<Map> target = SearchTransition(*name, PropertyKind::kData, NONE);
  if (target.is_null()) return MaybeHandle<Map>();
#ifdef DEBUG
  PropertyDetails details = target->GetLastDescriptorDetails(isolate_);
  DCHECK_EQ(NONE, details.attributes());
  DCHECK_EQ(PropertyKind::kData, details.kind());
  DCHECK_EQ(PropertyLocation::kField, details.location());
#endif
  return Handle<Map>(target, isolate_);
}

void TransitionsAccessor::ForEachTransitionTo(
    Tagged<Name> name, const ForEachTransitionCallback& callback,
    DisallowGarbageCollection* no_gc) {
  DCHECK(IsUniqueName(name));
  switch (encoding()) {
    case kPrototypeInfo:
    case kUninitialized:
    case kMigrationTarget:
      return;
    case kWeakRef: {
      Tagged<Map> target =
          Cast<Map>(raw_transitions_.GetHeapObjectAssumeWeak());
      InternalIndex descriptor = target->LastAdded();
      Tagged<DescriptorArray> descriptors =
          target->instance_descriptors(kRelaxedLoad);
      Tagged<Name> key = descriptors->GetKey(descriptor);
      if (key == name) {
        callback(target);
      }
      return;
    }
    case kFullTransitionArray: {
      base::SharedMutexGuardIf<base::kShared> scope(
          isolate_->full_transition_array_access(), concurrent_access_);
      return transitions()->ForEachTransitionTo(name, callback);
    }
  }
  UNREACHABLE();
}

// static
bool TransitionsAccessor::CanHaveMoreTransitions(Isolate* isolate,
                                                 DirectHandle<Map> map) {
  if (map->is_dictionary_map()) return false;
  Tagged<MaybeObject> raw_transitions =
      map->raw_transitions(isolate, kAcquireLoad);
  if (GetEncoding(isolate, raw_transitions) == kFullTransitionArray) {
    return GetTransitionArray(isolate, raw_transitions)
               ->number_of_transitions() < kMaxNumberOfTransitions;
  }
  return true;
}

// static
bool TransitionsAccessor::IsMatchingMap(Tagged<Map> target, Tagged<Name> name,
                                        PropertyKind kind,
                                        PropertyAttributes attributes) {
  InternalIndex descriptor = target->LastAdded();
  Tagged<DescriptorArray> descriptors =
      target->instance_descriptors(kRelaxedLoad);
  Tagged<Name> key = descriptors->GetKey(descriptor);
  if (key != name) return false;
  return descriptors->GetDetails(descriptor)
      .HasKindAndAttributes(kind, attributes);
}

// static
bool TransitionArray::CompactPrototypeTransitionArray(
    Isolate* isolate, Tagged<WeakFixedArray> array) {
  const int header = kProtoTransitionHeaderSize;
  int number_of_transitions = NumberOfPrototypeTransitions(array);
  if (number_of_transitions == 0) {
    // Empty array cannot be compacted.
    return false;
  }
  int new_number_of_transitions = 0;
  for (int i = 0; i < number_of_transitions; i++) {
    Tagged<MaybeObject> target = array->get(header + i);
    DCHECK(target.IsCleared() ||
           (target.IsWeak() && IsMap(target.GetHeapObject())));
    if (!target.IsCleared()) {
      if (new_number_of_transitions != i) {
        array->set(header + new_number_of_transitions, target);
      }
      new_number_of_transitions++;
    }
  }
  // Fill slots that became free with undefined value.
  Tagged<MaybeObject> undefined = *isolate->factory()->undefined_value();
  for (int i = new_number_of_transitions; i < number_of_transitions; i++) {
    array->set(header + i, undefined);
  }
  if (number_of_transitions != new_number_of_transitions) {
    SetNumberOfPrototypeTransitions(array, new_number_of_transitions);
  }
  return new_number_of_transitions < number_of_transitions;
}

// static
Handle<WeakFixedArray> TransitionArray::GrowPrototypeTransitionArray(
    DirectHandle<WeakFixedArray> array, int new_capacity, Isolate* isolate) {
  // Grow array by factor 2 up to MaxCachedPrototypeTransitions.
  int capacity = array->length() - kProtoTransitionHeaderSize;
  new_capacity = std::min({kMaxCachedPrototypeTransitions, new_capacity});
  DCHECK_GT(new_capacity, capacity);
  int grow_by = new_capacity - capacity;
  Handle<WeakFixedArray> new_array =
      isolate->factory()->CopyWeakFixedArrayAndGrow(array, grow_by);
  if (capacity < 0) {
    // There was no prototype transitions array before, so the size
    // couldn't be copied. Initialize it explicitly.
    SetNumberOfPrototypeTransitions(*new_array, 0);
  }
  return new_array;
}

// static
bool TransitionsAccessor::PutPrototypeTransition(Isolate* isolate,
                                                 DirectHandle<Map> map,
                                                 DirectHandle<Object> prototype,
                                                 DirectHandle<Map> target_map) {
  DCHECK_IMPLIES(v8_flags.move_prototype_transitions_first,
                 IsUndefined(map->GetBackPointer()));
  DCHECK(IsMap(Cast<HeapObject>(*prototype)->map()));
  // Don't cache prototype transition if this map is either shared, or a map of
  // a prototype.
  if (map->is_prototype_map()) return false;
  if (map->is_dictionary_map() || !v8_flags.cache_prototype_transitions)
    return false;

  const int header = TransitionArray::kProtoTransitionHeaderSize;

  DirectHandle<WeakFixedArray> cache(GetPrototypeTransitions(isolate, *map),
                                     isolate);
  int capacity = cache->length() - header;
  int transitions = TransitionArray::NumberOfPrototypeTransitions(*cache) + 1;

  // We're not using a MutexGuard for {full_transition_array_access}, because
  // we'll need to release it before growing the transition array (if needed),
  // in order to avoid deadlock if a background thread is waiting for the shared
  // mutex outside of a safepoint. And after growing the array, we'll need to
  // re-lock it.
  base::SharedMutex* transition_array_mutex =
      isolate->full_transition_array_access();

  transition_array_mutex->LockExclusive();
  if (transitions > capacity) {
    // Grow the array if compacting it doesn't free space.
    if (!TransitionArray::CompactPrototypeTransitionArray(isolate, *cache)) {
      transition_array_mutex->UnlockExclusive();
      if (capacity == TransitionArray::kMaxCachedPrototypeTransitions)
        return false;

      // GrowPrototypeTransitionArray can allocate, so it shouldn't hold the
      // exclusive lock on {full_transition_array_access} mutex, since
      // background threads could be waiting for the shared lock (outside of a
      // safe point). This is not an issue, because GrowPrototypeTransitionArray
      // doesn't actually modify in place the array, but instead return a new
      // array.
      transition_array_mutex->LockShared();
      cache = TransitionArray::GrowPrototypeTransitionArray(
          cache, 2 * transitions, isolate);
      transition_array_mutex->UnlockShared();

      transition_array_mutex->LockExclusive();
      SetPrototypeTransitions(isolate, map, cache);
    }
  }

  if (v8_flags.move_prototype_transitions_first) {
    target_map->SetBackPointer(*map);
  }

  // Reload number of transitions as they might have been compacted.
  int last = TransitionArray::NumberOfPrototypeTransitions(*cache);
  int entry = header + last;

  cache->set(entry, MakeWeak(*target_map));
  TransitionArray::SetNumberOfPrototypeTransitions(*cache, last + 1);

  transition_array_mutex->UnlockExclusive();
  return true;
}

// static
std::optional<Tagged<Map>> TransitionsAccessor::GetPrototypeTransition(
    Isolate* isolate, Tagged<Map> map, Tagged<Object> prototype) {
  DisallowGarbageCollection no_gc;
  Tagged<WeakFixedArray> cache = GetPrototypeTransitions(isolate, map);
  int length = TransitionArray::NumberOfPrototypeTransitions(cache);
  for (int i = 0; i < length; i++) {
    Tagged<MaybeObject> target =
        cache->get(TransitionArray::kProtoTransitionHeaderSize + i);
    DCHECK(target.IsWeakOrCleared());
    Tagged<HeapObject> heap_object;
    if (target.GetHeapObjectIfWeak(&heap_object)) {
      Tagged<Map> target_map = Cast<Map>(heap_object);
      if (target_map->prototype() == prototype) {
        return target_map;
      }
    }
  }
  return {};
}

// static
Tagged<WeakFixedArray> TransitionsAccessor::GetPrototypeTransitions(
    Isolate* isolate, Tagged<Map> map) {
  Tagged<MaybeObject> raw_transitions =
      map->raw_transitions(isolate, kAcquireLoad);
  if (GetEncoding(isolate, raw_transitions) != kFullTransitionArray) {
    return ReadOnlyRoots(isolate).empty_weak_fixed_array();
  }
  Tagged<TransitionArray> transition_array =
      GetTransitionArray(isolate, raw_transitions);
  if (!transition_array->HasPrototypeTransitions()) {
    return ReadOnlyRoots(isolate).empty_weak_fixed_array();
  }
  return transition_array->GetPrototypeTransitions();
}

// static
void TransitionArray::SetNumberOfPrototypeTransitions(
    Tagged<WeakFixedArray> proto_transitions, int value) {
  DCHECK_NE(proto_transitions->length(), 0);
  proto_transitions->set(kProtoTransitionNumberOfEntriesOffset,
                         Smi::FromInt(value));
}

int TransitionsAccessor::NumberOfTransitions() {
  switch (encoding()) {
    case kPrototypeInfo:
    case kUninitialized:
    case kMigrationTarget:
      return 0;
    case kWeakRef:
      return 1;
    case kFullTransitionArray:
      return transitions()->number_of_transitions();
  }
  UNREACHABLE();
}

bool TransitionsAccessor::HasPrototypeTransitions() {
  switch (encoding()) {
    case kPrototypeInfo:
    case kUninitialized:
    case kMigrationTarget:
    case kWeakRef:
      return false;
    case kFullTransitionArray:
      return transitions()->HasPrototypeTransitions();
  }
  UNREACHABLE();
}

// static
void TransitionsAccessor::SetMigrationTarget(Isolate* isolate,
                                             DirectHandle<Map> map,
                                             Tagged<Map> migration_target) {
  // We only cache the migration target for maps with empty transitions for GC's
  // sake.
  if (GetEncoding(isolate, map) != kUninitialized) return;
  DCHECK(map->is_deprecated());
  map->set_raw_transitions(migration_target, kReleaseStore);
}

Tagged<Map> TransitionsAccessor::GetMigrationTarget() {
  if (encoding() == kMigrationTarget) {
    return Cast<Map>(map_->raw_transitions(kAcquireLoad));
  }
  return Tagged<Map>();
}

// static
void TransitionsAccessor::ReplaceTransitions(
    Isolate* isolate, DirectHandle<Map> map,
    Tagged<UnionOf<TransitionArray, MaybeWeak<Map>>> new_transitions) {
#if DEBUG
  if (GetEncoding(isolate, map) == kFullTransitionArray) {
    CheckNewTransitionsAreConsistent(
        isolate, map, new_transitions.GetHeapObjectAssumeStrong());
    DCHECK_NE(GetTransitionArray(isolate, map),
              new_transitions.GetHeapObjectAssumeStrong());
  }
#endif
  map->set_raw_transitions(new_transitions, kReleaseStore);
  USE(isolate);
}

// static
void TransitionsAccessor::ReplaceTransitions(
    Isolate* isolate, DirectHandle<Map> map,
    DirectHandle<TransitionArray> new_transitions) {
  ReplaceTransitions(isolate, map, *new_transitions);
}

// static
void TransitionsAccessor::SetPrototypeTransitions(
    Isolate* isolate, DirectHandle<Map> map,
    DirectHandle<WeakFixedArray> proto_transitions) {
  EnsureHasFullTransitionArray(isolate, map);
  GetTransitionArray(isolate, map->raw_transitions(isolate, kAcquireLoad))
      ->SetPrototypeTransitions(*proto_transitions);
}

// static
void TransitionsAccessor::EnsureHasFullTransitionArray(Isolate* isolate,
                                                       DirectHandle<Map> map) {
  Encoding encoding =
      GetEncoding(isolate, map->raw_transitions(isolate, kAcquireLoad));
  if (encoding == kFullTransitionArray) return;
  int nof =
      (encoding == kUninitialized || encoding == kMigrationTarget) ? 0 : 1;
  DirectHandle<TransitionArray> result =
      isolate->factory()->NewTransitionArray(nof);
  // Reload encoding after possible GC.
  encoding = GetEncoding(isolate, map->raw_transitions(isolate, kAcquireLoad));
  if (nof == 1) {
    if (encoding == kUninitialized) {
      // If allocation caused GC and cleared the target, trim the new array.
      result->SetNumberOfTransitions(0);
    } else {
      // Otherwise populate the new array.
      Tagged<Map> target = GetSimpleTransition(isolate, map);
      Tagged<Name> key = GetSimpleTransitionKey(target);
      result->Set(0, key, MakeWeak(target));
    }
  }
  ReplaceTransitions(isolate, map, result);
}

void TransitionsAccessor::TraverseTransitionTreeInternal(
    const TraverseCallback& callback, DisallowGarbageCollection* no_gc) {
  // Mostly arbitrary but more than enough to run the test suite in static
  // memory.
  static constexpr int kStaticStackSize = 16;
  base::SmallVector<Tagged<Map>, kStaticStackSize> stack;
  stack.emplace_back(map_);

  // Pre-order iterative depth-first-search.
  while (!stack.empty()) {
    Tagged<Map> current_map = stack.back();
    stack.pop_back();

    callback(current_map);

    Tagged<MaybeObject> raw_transitions =
        current_map->raw_transitions(isolate_, kAcquireLoad);
    Encoding encoding = GetEncoding(isolate_, raw_transitions);

    switch (encoding) {
      case kPrototypeInfo:
      case kUninitialized:
      case kMigrationTarget:
        break;
      case kWeakRef: {
        stack.emplace_back(
            Cast<Map>(raw_transitions.GetHeapObjectAssumeWeak()));
        break;
      }
      case kFullTransitionArray: {
        Tagged<TransitionArray> transitions =
            Cast<TransitionArray>(raw_transitions.GetHeapObjectAssumeStrong());
        if (transitions->HasPrototypeTransitions()) {
          Tagged<WeakFixedArray> proto_trans =
              transitions->GetPrototypeTransitions();
          int length =
              TransitionArray::NumberOfPrototypeTransitions(proto_trans);
          for (int i = 0; i < length; ++i) {
            int index = TransitionArray::kProtoTransitionHeaderSize + i;
            Tagged<MaybeObject> target = proto_trans->get(index);
            Tagged<HeapObject> heap_object;
            if (target.GetHeapObjectIfWeak(&heap_object)) {
              stack.emplace_back(Cast<Map>(heap_object));
            } else {
              DCHECK(target.IsCleared());
            }
          }
        }
        ReadOnlyRoots roots(isolate_);
        for (int i = 0; i < transitions->number_of_transitions(); ++i) {
          stack.emplace_back(transitions->GetTarget(i));
        }
        break;
      }
    }
  }
}

#ifdef DEBUG
// static
void TransitionsAccessor::CheckNewTransitionsAreConsistent(
    Isolate* isolate, DirectHandle<Map> map, Tagged<Object> transitions) {
  // This function only handles full transition arrays.
  Tagged<TransitionArray> old_transitions = GetTransitionArray(isolate, map);
  DCHECK_EQ(kFullTransitionArray, GetEncoding(isolate, old_transitions));
  Tagged<TransitionArray> new_transitions = Cast<TransitionArray>(transitions);
  ReadOnlyRoots roots(isolate);
  for (int i = 0; i < old_transitions->number_of_transitions(); i++) {
    Tagged<Map> target;
    if (old_transitions->GetTargetIfExists(i, isolate, &target)) {
      if (target->instance_descriptors(isolate) ==
          map->instance_descriptors(isolate)) {
        Tagged<Name> key = old_transitions->GetKey(i);
        int new_target_index;
        if (IsSpecialTransition(roots, key)) {
          new_target_index = new_transitions->SearchSpecial(Cast<Symbol>(key));
        } else {
          PropertyDetails details = GetTargetDetails(key, target);
          new_target_index = new_transitions->Search(details.kind(), key,
                                                     details.attributes());
        }
        DCHECK_NE(TransitionArray::kNotFound, new_target_index);
        DCHECK_EQ(target, new_transitions->GetTarget(new_target_index));
      }
    } else {
      DCHECK(IsSpecialTransition(roots, old_transitions->GetKey(i)));
    }
  }
}
#endif

// Private non-static helper functions (operating on full transition arrays).

int TransitionArray::SearchDetails(int transition, PropertyKind kind,
                                   PropertyAttributes attributes,
                                   int* out_insertion_index) {
  int nof_transitions = number_of_transitions();
  DCHECK(transition < nof_transitions);
  Tagged<Name> key = GetKey(transition);
  for (; transition < nof_transitions && GetKey(transition) == key;
       transition++) {
    Tagged<Map> target = GetTarget(transition);
    PropertyDetails target_details =
        TransitionsAccessor::GetTargetDetails(key, target);

    int cmp = CompareDetails(kind, attributes, target_details.kind(),
                             target_details.attributes());
    if (cmp == 0) {
      return transition;
    } else if (cmp < 0) {
      break;
    }
  }
  if (out_insertion_index != nullptr) *out_insertion_index = transition;
  return kNotFound;
}

Tagged<Map> TransitionArray::SearchDetailsAndGetTarget(
    int transition, PropertyKind kind, PropertyAttributes attributes) {
  int nof_transitions = number_of_transitions();
  DCHECK(transition < nof_transitions);
  Tagged<Name> key = GetKey(transition);
  for (; transition < nof_transitions && GetKey(transition) == key;
       transition++) {
    Tagged<Map> target = GetTarget(transition);
    PropertyDetails target_details =
        TransitionsAccessor::GetTargetDetails(key, target);

    int cmp = CompareDetails(kind, attributes, target_details.kind(),
                             target_details.attributes());
    if (cmp == 0) {
      return target;
    } else if (cmp < 0) {
      break;
    }
  }
  return Tagged<Map>();
}

int TransitionArray::Search(PropertyKind kind, Tagged<Name> name,
                            PropertyAttributes attributes,
                            int* out_insertion_index) {
  int transition = SearchName(name, false, out_insertion_index);
  if (transition == kNotFound) return kNotFound;
  return SearchDetails(transition, kind, attributes, out_insertion_index);
}

Tagged<Map> TransitionArray::SearchAndGetTarget(PropertyKind kind,
                                                Tagged<Name> name,
                                                PropertyAttributes attributes) {
  int transition = SearchName(name);
  if (transition == kNotFound) {
    return Tagged<Map>();
  }
  return SearchDetailsAndGetTarget(transition, kind, attributes);
}

void TransitionArray::ForEachTransitionTo(
    Tagged<Name> name, const ForEachTransitionCallback& callback) {
  int transition = SearchName(name);
  if (transition == kNotFound) return;

  int nof_transitions = number_of_transitions();
  DCHECK(transition < nof_transitions);
  Tagged<Name> key = GetKey(transition);
  for (; transition < nof_transitions && GetKey(transition) == key;
       transition++) {
    Tagged<Map> target = GetTarget(transition);
    callback(target);
  }
}

void TransitionArray::Sort() {
  DisallowGarbageCollection no_gc;
  // In-place insertion sort.
  int length = number_of_transitions();
  ReadOnlyRoots roots = GetReadOnlyRoots();
  for (int i = 1; i < length; i++) {
    Tagged<Name> key = GetKey(i);
    Tagged<MaybeObject> target = GetRawTarget(i);
    PropertyKind kind = PropertyKind::kData;
    PropertyAttributes attributes = NONE;
    if (!TransitionsAccessor::IsSpecialTransition(roots, key)) {
      Tagged<Map> target_map = TransitionsAccessor::GetTargetFromRaw(target);
      PropertyDetails details =
          TransitionsAccessor::GetTargetDetails(key, target_map);
      kind = details.kind();
      attributes = details.attributes();
    }
    int j;
    for (j = i - 1; j >= 0; j--) {
      Tagged<Name> temp_key = GetKey(j);
      Tagged<MaybeObject> temp_target = GetRawTarget(j);
      PropertyKind temp_kind = PropertyKind::kData;
      PropertyAttributes temp_attributes = NONE;
      if (!TransitionsAccessor::IsSpecialTransition(roots, temp_key)) {
        Tagged<Map> temp_target_map =
            TransitionsAccessor::GetTargetFromRaw(temp_target);
        PropertyDetails details =
            TransitionsAccessor::GetTargetDetails(temp_key, temp_target_map);
        temp_kind = details.kind();
        temp_attributes = details.attributes();
      }
      int cmp =
          CompareKeys(temp_key, temp_key->hash(), temp_kind, temp_attributes,
                      key, key->hash(), kind, attributes);
      if (cmp > 0) {
        SetKey(j + 1, temp_key);
        SetRawTarget(j + 1, temp_target);
      } else {
        break;
      }
    }
    SetKey(j + 1, key);
    SetRawTarget(j + 1, target);
  }
  DCHECK(IsSortedNoDuplicates());
}

bool TransitionsAccessor::HasIntegrityLevelTransitionTo(
    Tagged<Map> to, Tagged<Symbol>* out_symbol,
    PropertyAttributes* out_integrity_level) {
  ReadOnlyRoots roots(isolate_);
  if (SearchSpecial(roots.frozen_symbol()) == to) {
    if (out_integrity_level) *out_integrity_level = FROZEN;
    if (out_symbol) *out_symbol = roots.frozen_symbol();
  } else if (SearchSpecial(roots.sealed_symbol()) == to) {
    if (out_integrity_level) *out_integrity_level = SEALED;
    if (out_symbol) *out_symbol = roots.sealed_symbol();
  } else if (SearchSpecial(roots.nonextensible_symbol()) == to) {
    if (out_integrity_level) *out_integrity_level = NONE;
    if (out_symbol) *out_symbol = roots.nonextensible_symbol();
  } else {
    return false;
  }
  return true;
}

// static
void TransitionsAccessor::EnsureHasSideStepTransitions(Isolate* isolate,
                                                       DirectHandle<Map> map) {
  EnsureHasFullTransitionArray(isolate, map);
  Tagged<TransitionArray> transitions =
      GetTransitionArray(isolate, map->raw_transitions());
  if (transitions->HasSideStepTransitions()) return;
  TransitionArray::CreateSideStepTransitions(isolate,
                                             handle(transitions, isolate));
}

// static
void TransitionArray::CreateSideStepTransitions(
    Isolate* isolate, DirectHandle<TransitionArray> transitions) {
  DCHECK(!transitions->HasSideStepTransitions());  // Callers must check first.
  DirectHandle<WeakFixedArray> result = WeakFixedArray::New(
      isolate, SideStepTransition::kSize, AllocationType::kYoung,
      handle(SideStepTransition::Empty, isolate));
  transitions->SetSideStepTransitions(*result);
}

std::ostream& operator<<(std::ostream& os, SideStepTransition::Kind sidestep) {
  switch (sidestep) {
    case SideStepTransition::Kind::kObjectAssignValidityCell:
      os << "Object.assign-validity-cell";
      break;
    case SideStepTransition::Kind::kObjectAssign:
      os << "Object.assign-map";
      break;
    case SideStepTransition::Kind::kCloneObject:
      os << "Clone-object-IC-map";
      break;
  }
  return os;
}

}  // namespace v8::internal
```
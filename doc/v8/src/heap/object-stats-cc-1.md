Response:
The user wants to understand the functionality of the provided C++ code snippet from V8's `object-stats.cc`. They are asking for a summary of its purpose, considering potential Torque implementation, its relation to JavaScript (with examples), code logic (with input/output), common programming errors it might help diagnose, and a final overall summary as part 2 of a multi-part request.

Here's a breakdown of the thinking process:

1. **Identify the core purpose:** The code is named `object-stats.cc` and contains classes like `ObjectStatsCollectorImpl` and `ObjectStatsCollector`. This strongly suggests it's responsible for collecting statistics about objects within the V8 heap.

2. **Scan for key functionalities:**  Look for methods that indicate what kind of statistics are gathered. Methods like `RecordObjectStats`, `RecordVirtualObjectStats`, `CollectGlobalStatistics`, and specific `RecordVirtual...Details` methods point towards different categories of statistics.

3. **Differentiate between "real" and "virtual" objects:** Notice the distinction between `RecordObjectStats` and `RecordVirtualObjectStats`. The "virtual" prefix suggests these aren't necessarily concrete heap objects but rather logical groupings or aspects of objects for statistical purposes.

4. **Analyze `CollectGlobalStatistics`:** This method seems to handle special object categories like allocation sites, caches (number string, single character string, etc.), and the script list. This indicates the collector needs to account for internal V8 structures.

5. **Examine the `RecordVirtual...Details` methods:** These methods delve into the specifics of different object types (Maps, Scripts, ExternalStrings, SharedFunctionInfos, etc.). This is where the code breaks down the structure and related objects of each type for more granular statistics. For instance, `RecordVirtualMapDetails` looks at prototype maps, deprecated maps, and their associated descriptor arrays.

6. **Understand the role of `ObjectStatsCollectorImpl::Phase`:** The code iterates through "phases."  This likely represents different stages of the statistic collection process, perhaps focusing on different aspects of object analysis.

7. **Consider the interaction with the heap:** The code uses `heap_` and interacts with the `marking_state_`. This links the statistic collection to V8's garbage collection and object marking mechanisms. The `SameLiveness` function reinforces this connection.

8. **Address the Torque aspect:**  The prompt specifically asks about `.tq` files. Since there's no indication of Torque syntax in the provided code, conclude that it's not a Torque file.

9. **Connect to JavaScript functionality:** Think about how these internal V8 object statistics relate to JavaScript concepts. For example, Maps in V8 back the `Map` object in JavaScript. Scripts represent JavaScript code. This allows for demonstrating the connection with JavaScript examples.

10. **Infer code logic and example:** Consider a simple scenario. If a JavaScript object is created, the `RecordObjectStats` method would likely be called. If a `Map` is created, `RecordVirtualMapDetails` would be invoked. This helps create simple input/output scenarios.

11. **Identify potential programming errors:** Think about what kind of insights these statistics can provide. Excessive use of deprecated features, large numbers of megamorphic property accesses (leading to dictionary maps), or memory leaks could be highlighted by object statistics.

12. **Synthesize the overall functionality:** Combine all the observations into a concise summary of the code's purpose. Emphasize the goal of providing insights into heap object usage for performance analysis and debugging.

13. **Structure the answer according to the prompt:** Organize the findings into sections addressing the specific questions about functionality, Torque, JavaScript examples, code logic, programming errors, and the final summary (part 2).

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the "virtual" objects are just a way to count things without iterating through the entire heap.
* **Correction:** The `RecordVirtual...Details` methods show that "virtual" refers to logically related objects or attributes *within* a heap object, not entirely separate entities. They are still part of the heap but are tracked separately for finer-grained analysis.
* **Initial thought:** The phases might be related to different garbage collection cycles.
* **Refinement:** While related to the heap, the phases seem more about organizing the *collection* of statistics rather than directly tied to GC cycles, though the marking state is clearly involved.

By following these steps, one can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the user's request.
这是对 `v8/src/heap/object-stats.cc` 源代码功能的归纳总结，基于您提供的第二部分代码片段。

**归纳总结：`v8/src/heap/object-stats.cc` 的功能**

`v8/src/heap/object-stats.cc` 的主要功能是**收集 V8 堆中各种对象的统计信息**。它旨在提供对堆内存使用情况的详细了解，包括：

* **对象实例类型统计:**  记录不同对象类型（例如，`Map`、`String`、`Function` 等）的实例数量和大小。
* **虚拟对象统计:**  对某些逻辑上的对象或与主要对象关联的辅助数据结构进行统计，即使它们可能不是独立的堆对象。这有助于更深入地了解复杂对象的内部结构和关系。例如，记录 `Map` 对象相关的 `DescriptorArray`、`EnumCache` 等。
* **外部资源统计:**  专门记录不在 V8 堆内的外部资源（例如，外部字符串的底层缓冲区）的大小。
* **区分活动和死亡对象:** 在垃圾回收过程中，区分存活对象和待回收对象，分别统计它们的统计信息。
* **区分不同状态的对象:**  对于某些关键类型（如 `Map`），会根据其状态（例如，是否为原型 Map、是否已弃用、是否为字典 Map）进行更细粒度的统计。
* **处理特殊的对象:**  特殊处理诸如分配站点、各种缓存（字符串缓存、正则表达式缓存等）以及脚本列表等全局数据结构。
* **与代码对象关联的统计:**  统计与已编译代码对象相关的元数据，例如重定位信息、反优化数据、内嵌对象等。
* **上下文对象统计:**  区分本地上下文和函数上下文进行统计。

**它与第一部分的联系:**

第一部分的代码很可能包含了 `ObjectStats` 类的定义和 `ObjectStatsCollector` 类的基础结构。第二部分的代码是 `ObjectStatsCollectorImpl` 类的实现，它继承或使用了第一部分定义的接口，来具体执行统计信息的收集工作。

**关于 .tq 后缀:**

如果 `v8/src/heap/object-stats.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。Torque 是一种 V8 内部使用的类型安全的 DSL (Domain Specific Language)，用于生成高效的 C++ 代码。  然而，根据您提供的代码片段，该文件名为 `.cc`，表明它是 **C++ 源代码**。

**与 JavaScript 功能的关系 (举例说明):**

`object-stats.cc` 收集的统计信息直接反映了 JavaScript 代码在 V8 引擎中的运行时状态。以下是一些例子：

* **JavaScript 对象创建:** 当 JavaScript 代码创建一个对象（例如 `const obj = {}`），`ObjectStatsCollector` 会记录一个新的 `JSObject` 实例及其大小。
* **JavaScript Map 使用:** 当使用 JavaScript 的 `Map` 对象时，`RecordVirtualMapDetails` 会被调用，统计 `Map` 对象本身以及其内部的 `DescriptorArray` 和 `EnumCache` 等数据结构。

```javascript
// JavaScript 示例

// 创建一个普通对象
const myObject = { a: 1, b: 'hello' };

// 创建一个 Map 对象
const myMap = new Map();
myMap.set('key1', 'value1');
myMap.set('key2', 123);

// 定义一个函数
function myFunction() {
  console.log('Hello');
}

// 创建一个字符串
const myString = "This is a string";
```

在 V8 内部，`ObjectStatsCollector` 会记录：

* `myObject`:  作为一个 `JSObject` 实例。
* `myMap`: 作为一个 `JSMap` 实例，并且会通过 `RecordVirtualMapDetails` 记录其内部结构，例如用于存储键值对的 `HashTable` 或 `OrderedHashMap`。
* `myFunction`: 作为一个 `JSFunction` 实例，并可能通过 `RecordVirtualSharedFunctionInfoDetails` 记录相关的 `SharedFunctionInfo`。
* `myString`: 作为一个 `String` 实例。如果字符串内容来自外部（例如，从文件中加载），则可能还会记录外部字符串资源的统计信息。

**代码逻辑推理 (假设输入与输出):**

假设在堆中存在一个 JavaScript `Map` 对象 `myMap`：

**假设输入:**  `Tagged<HeapObject> obj` 指向 `myMap` 这个 `JSMap` 对象。

**`CollectStatistics` 函数处理 (部分逻辑):**

1. `CollectStatistics` 函数会根据 `obj` 的类型 (`JS_MAP_TYPE`) 进入 `case InstanceType::JS_MAP_TYPE:` 分支。
2. `field_stats_collector_.RecordStats(obj)` 可能会记录 `JSMap` 对象自身的统计信息（大小等）。
3. 如果 `phase_` 允许，`RecordVirtualMapDetails(Cast<Map>(obj))` 会被调用。
4. 在 `RecordVirtualMapDetails` 中，会记录 `myMap` 的各种状态（例如，是否为原型 Map），并会进一步记录与 `myMap` 关联的 `DescriptorArray` 和 `EnumCache` 的统计信息。

**可能的输出 (部分统计数据):**

* `ObjectStats::MAP_TYPE`: 增加 1 (如果 `myMap` 不是特殊状态的 Map)
* `ObjectStats::DESCRIPTOR_ARRAY_TYPE`: 增加 1 (如果 `myMap` 拥有自己的描述符数组)
* `ObjectStats::ENUM_KEYS_CACHE_TYPE`: 增加 1 (如果 `myMap` 的描述符数组有枚举缓存)
* `ObjectStats::ENUM_INDICES_CACHE_TYPE`: 增加 1 (如果 `myMap` 的描述符数组有枚举缓存)

**涉及用户常见的编程错误 (举例说明):**

`ObjectStatsCollector` 收集的信息可以帮助诊断一些常见的 JavaScript 编程错误和性能问题：

* **内存泄漏:** 如果某种类型的对象数量持续增长，即使在不再需要它们之后，这可能表明存在内存泄漏。`ObjectStatsCollector` 可以帮助识别泄漏的对象类型。 例如，如果 `ObjectStats::JS_CLOSURE_TYPE` 的数量持续增加，可能表明有闭包导致对象无法被回收。
* **原型链污染:**  过多的原型 Map 或被废弃的原型 Map (`ObjectStats::MAP_PROTOTYPE_DICTIONARY_TYPE`, `ObjectStats::MAP_ABANDONED_PROTOTYPE_TYPE`) 可能暗示存在原型链污染的问题。
* **性能问题:**
    * 大量的字典模式对象 (`ObjectStats::MAP_DICTIONARY_TYPE`) 可能表明代码中存在大量的动态属性访问，这会降低性能。
    * 大量的未编译的共享函数信息 (`ObjectStats::UNCOMPILED_SHARED_FUNCTION_INFO_TYPE`) 可能意味着有大量的函数没有被 JIT 编译，影响性能。
    * 过多的字符串碎片 (`ObjectStats::STRING_SPLIT_CACHE_TYPE`) 可能表明存在大量的字符串拼接操作，可以考虑使用模板字符串或数组 `join` 方法优化。

**总结:**

`v8/src/heap/object-stats.cc` (特别是 `ObjectStatsCollectorImpl`) 负责在 V8 引擎的堆中收集各种对象的详细统计信息。这些信息对于理解 JavaScript 代码的内存使用模式、诊断内存泄漏、识别性能瓶颈以及深入了解 V8 引擎的内部工作原理至关重要。它通过区分不同类型的对象、跟踪虚拟对象和外部资源，并根据对象的生命周期和状态进行分类，提供了对堆内存的全面视图。

### 提示词
```
这是目录为v8/src/heap/object-stats.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/object-stats.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ats::kYes) {
        field_stats_collector_.RecordStats(obj);
      }
      break;
  }
}

void ObjectStatsCollectorImpl::CollectGlobalStatistics() {
  // Iterate boilerplates first to disambiguate them from regular JS objects.
  Tagged<Object> list = heap_->allocation_sites_list();
  while (IsAllocationSite(list, cage_base())) {
    Tagged<AllocationSite> site = Cast<AllocationSite>(list);
    RecordVirtualAllocationSiteDetails(site);
    list = site->weak_next();
  }

  // FixedArray.
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->serialized_objects(),
                                 ObjectStats::SERIALIZED_OBJECTS_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->number_string_cache(),
                                 ObjectStats::NUMBER_STRING_CACHE_TYPE);
  RecordSimpleVirtualObjectStats(
      HeapObject(), heap_->single_character_string_table(),
      ObjectStats::SINGLE_CHARACTER_STRING_TABLE_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->string_split_cache(),
                                 ObjectStats::STRING_SPLIT_CACHE_TYPE);
  RecordSimpleVirtualObjectStats(HeapObject(), heap_->regexp_multiple_cache(),
                                 ObjectStats::REGEXP_MULTIPLE_CACHE_TYPE);

  // WeakArrayList.
  RecordSimpleVirtualObjectStats(HeapObject(),
                                 Cast<WeakArrayList>(heap_->script_list()),
                                 ObjectStats::SCRIPT_LIST_TYPE);
}

void ObjectStatsCollectorImpl::RecordObjectStats(Tagged<HeapObject> obj,
                                                 InstanceType type, size_t size,
                                                 size_t over_allocated) {
  if (virtual_objects_.find(obj) == virtual_objects_.end()) {
    stats_->RecordObjectStats(type, size, over_allocated);
  }
}

bool ObjectStatsCollectorImpl::CanRecordFixedArray(
    Tagged<FixedArrayBase> array) {
  ReadOnlyRoots roots(heap_);
  return array != roots.empty_fixed_array() &&
         array != roots.empty_slow_element_dictionary() &&
         array != roots.empty_property_dictionary();
}

bool ObjectStatsCollectorImpl::IsCowArray(Tagged<FixedArrayBase> array) {
  return array->map() == ReadOnlyRoots(heap_).fixed_cow_array_map();
}

bool ObjectStatsCollectorImpl::SameLiveness(Tagged<HeapObject> obj1,
                                            Tagged<HeapObject> obj2) {
  if (obj1.is_null() || obj2.is_null()) return true;
  const auto obj1_marked =
      HeapLayout::InReadOnlySpace(obj1) || marking_state_->IsMarked(obj1);
  const auto obj2_marked =
      HeapLayout::InReadOnlySpace(obj2) || marking_state_->IsMarked(obj2);
  return obj1_marked == obj2_marked;
}

void ObjectStatsCollectorImpl::RecordVirtualMapDetails(Tagged<Map> map) {
  // TODO(mlippautz): map->dependent_code(): DEPENDENT_CODE_TYPE.

  // For Map we want to distinguish between various different states
  // to get a better picture of what's going on in MapSpace. This
  // method computes the virtual instance type to use for a given map,
  // using MAP_TYPE for regular maps that aren't special in any way.
  if (map->is_prototype_map()) {
    if (map->is_dictionary_map()) {
      RecordSimpleVirtualObjectStats(
          HeapObject(), map, ObjectStats::MAP_PROTOTYPE_DICTIONARY_TYPE);
    } else if (map->is_abandoned_prototype_map()) {
      RecordSimpleVirtualObjectStats(HeapObject(), map,
                                     ObjectStats::MAP_ABANDONED_PROTOTYPE_TYPE);
    } else {
      RecordSimpleVirtualObjectStats(HeapObject(), map,
                                     ObjectStats::MAP_PROTOTYPE_TYPE);
    }
  } else if (map->is_deprecated()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_DEPRECATED_TYPE);
  } else if (map->is_dictionary_map()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_DICTIONARY_TYPE);
  } else if (map->is_stable()) {
    RecordSimpleVirtualObjectStats(HeapObject(), map,
                                   ObjectStats::MAP_STABLE_TYPE);
  } else {
    // This will be logged as MAP_TYPE in Phase2.
  }

  Tagged<DescriptorArray> array = map->instance_descriptors(cage_base());
  if (map->owns_descriptors() &&
      array != ReadOnlyRoots(heap_).empty_descriptor_array()) {
    // Generally DescriptorArrays have their own instance type already
    // (DESCRIPTOR_ARRAY_TYPE), but we'd like to be able to tell which
    // of those are for (abandoned) prototypes, and which of those are
    // owned by deprecated maps.
    if (map->is_prototype_map()) {
      RecordSimpleVirtualObjectStats(
          map, array, ObjectStats::PROTOTYPE_DESCRIPTOR_ARRAY_TYPE);
    } else if (map->is_deprecated()) {
      RecordSimpleVirtualObjectStats(
          map, array, ObjectStats::DEPRECATED_DESCRIPTOR_ARRAY_TYPE);
    }

    Tagged<EnumCache> enum_cache = array->enum_cache();
    RecordSimpleVirtualObjectStats(array, enum_cache->keys(),
                                   ObjectStats::ENUM_KEYS_CACHE_TYPE);
    RecordSimpleVirtualObjectStats(array, enum_cache->indices(),
                                   ObjectStats::ENUM_INDICES_CACHE_TYPE);
  }

  if (map->is_prototype_map()) {
    Tagged<PrototypeInfo> prototype_info;
    if (map->TryGetPrototypeInfo(&prototype_info)) {
      Tagged<Object> users = prototype_info->prototype_users();
      if (IsWeakFixedArray(users, cage_base())) {
        RecordSimpleVirtualObjectStats(map, Cast<WeakArrayList>(users),
                                       ObjectStats::PROTOTYPE_USERS_TYPE);
      }
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualScriptDetails(
    Tagged<Script> script) {
  RecordSimpleVirtualObjectStats(script, script->infos(),
                                 ObjectStats::SCRIPT_INFOS_TYPE);

  // Log the size of external source code.
  Tagged<Object> raw_source = script->source();
  if (IsExternalString(raw_source, cage_base())) {
    // The contents of external strings aren't on the heap, so we have to record
    // them manually. The on-heap String object is recorded independently in
    // the normal pass.
    Tagged<ExternalString> string = Cast<ExternalString>(raw_source);
    Address resource = string->resource_as_address();
    size_t off_heap_size = string->ExternalPayloadSize();
    RecordExternalResourceStats(
        resource,
        string->IsOneByteRepresentation()
            ? ObjectStats::SCRIPT_SOURCE_EXTERNAL_ONE_BYTE_TYPE
            : ObjectStats::SCRIPT_SOURCE_EXTERNAL_TWO_BYTE_TYPE,
        off_heap_size);
  } else if (IsString(raw_source, cage_base())) {
    Tagged<String> source = Cast<String>(raw_source);
    RecordSimpleVirtualObjectStats(
        script, source,
        source->IsOneByteRepresentation()
            ? ObjectStats::SCRIPT_SOURCE_NON_EXTERNAL_ONE_BYTE_TYPE
            : ObjectStats::SCRIPT_SOURCE_NON_EXTERNAL_TWO_BYTE_TYPE);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualExternalStringDetails(
    Tagged<ExternalString> string) {
  // Track the external string resource size in a separate category.

  Address resource = string->resource_as_address();
  size_t off_heap_size = string->ExternalPayloadSize();
  RecordExternalResourceStats(
      resource,
      string->IsOneByteRepresentation()
          ? ObjectStats::STRING_EXTERNAL_RESOURCE_ONE_BYTE_TYPE
          : ObjectStats::STRING_EXTERNAL_RESOURCE_TWO_BYTE_TYPE,
      off_heap_size);
}

void ObjectStatsCollectorImpl::RecordVirtualSharedFunctionInfoDetails(
    Tagged<SharedFunctionInfo> info) {
  // Uncompiled SharedFunctionInfo gets its own category.
  if (!info->is_compiled()) {
    RecordSimpleVirtualObjectStats(
        HeapObject(), info, ObjectStats::UNCOMPILED_SHARED_FUNCTION_INFO_TYPE);
  }
}

void ObjectStatsCollectorImpl::RecordVirtualArrayBoilerplateDescription(
    Tagged<ArrayBoilerplateDescription> description) {
  RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
      description, description->constant_elements(),
      ObjectStats::ARRAY_BOILERPLATE_DESCRIPTION_ELEMENTS_TYPE);
}

void ObjectStatsCollectorImpl::
    RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
        Tagged<HeapObject> parent, Tagged<HeapObject> object,
        ObjectStats::VirtualInstanceType type) {
  if (!RecordSimpleVirtualObjectStats(parent, object, type)) return;
  if (IsFixedArrayExact(object, cage_base())) {
    Tagged<FixedArray> array = Cast<FixedArray>(object);
    for (int i = 0; i < array->length(); i++) {
      Tagged<Object> entry = array->get(i);
      if (!IsHeapObject(entry)) continue;
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          array, Cast<HeapObject>(entry), type);
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualBytecodeArrayDetails(
    Tagged<BytecodeArray> bytecode) {
  RecordSimpleVirtualObjectStats(
      bytecode, bytecode->constant_pool(),
      ObjectStats::BYTECODE_ARRAY_CONSTANT_POOL_TYPE);
  // FixedArrays on constant pool are used for holding descriptor information.
  // They are shared with optimized code.
  Tagged<TrustedFixedArray> constant_pool =
      Cast<TrustedFixedArray>(bytecode->constant_pool());
  for (int i = 0; i < constant_pool->length(); i++) {
    Tagged<Object> entry = constant_pool->get(i);
    if (IsFixedArrayExact(entry)) {
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          constant_pool, Cast<HeapObject>(entry),
          ObjectStats::EMBEDDED_OBJECT_TYPE);
    }
  }
  RecordSimpleVirtualObjectStats(
      bytecode, bytecode->handler_table(),
      ObjectStats::BYTECODE_ARRAY_HANDLER_TABLE_TYPE);
  if (bytecode->HasSourcePositionTable()) {
    RecordSimpleVirtualObjectStats(bytecode, bytecode->SourcePositionTable(),
                                   ObjectStats::SOURCE_POSITION_TABLE_TYPE);
  }
}

namespace {

ObjectStats::VirtualInstanceType CodeKindToVirtualInstanceType(CodeKind kind) {
  switch (kind) {
#define CODE_KIND_CASE(type) \
  case CodeKind::type:       \
    return ObjectStats::type;
    CODE_KIND_LIST(CODE_KIND_CASE)
#undef CODE_KIND_CASE
  }
  UNREACHABLE();
}

}  // namespace

void ObjectStatsCollectorImpl::RecordVirtualCodeDetails(
    Tagged<InstructionStream> istream) {
  Tagged<Code> code;
  if (!istream->TryGetCode(&code, kAcquireLoad)) return;
  RecordSimpleVirtualObjectStats(HeapObject(), istream,
                                 CodeKindToVirtualInstanceType(code->kind()));
  RecordSimpleVirtualObjectStats(istream, istream->relocation_info(),
                                 ObjectStats::RELOC_INFO_TYPE);
  if (CodeKindIsOptimizedJSFunction(code->kind())) {
    Tagged<Object> source_position_table = code->source_position_table();
    if (IsHeapObject(source_position_table)) {
      RecordSimpleVirtualObjectStats(istream,
                                     Cast<HeapObject>(source_position_table),
                                     ObjectStats::SOURCE_POSITION_TABLE_TYPE);
    }
    RecordSimpleVirtualObjectStats(istream, code->deoptimization_data(),
                                   ObjectStats::DEOPTIMIZATION_DATA_TYPE);
    Tagged<DeoptimizationData> input_data =
        Cast<DeoptimizationData>(code->deoptimization_data());
    if (input_data->length() > 0) {
      RecordSimpleVirtualObjectStats(code->deoptimization_data(),
                                     input_data->LiteralArray(),
                                     ObjectStats::OPTIMIZED_CODE_LITERALS_TYPE);
    }
  }
  int const mode_mask = RelocInfo::EmbeddedObjectModeMask();
  for (RelocIterator it(code, mode_mask); !it.done(); it.next()) {
    DCHECK(RelocInfo::IsEmbeddedObjectMode(it.rinfo()->rmode()));
    Tagged<Object> target = it.rinfo()->target_object(cage_base());
    if (IsFixedArrayExact(target, cage_base())) {
      RecordVirtualObjectsForConstantPoolOrEmbeddedObjects(
          istream, Cast<HeapObject>(target), ObjectStats::EMBEDDED_OBJECT_TYPE);
    }
  }
}

void ObjectStatsCollectorImpl::RecordVirtualContext(Tagged<Context> context) {
  if (IsNativeContext(context)) {
    RecordObjectStats(context, NATIVE_CONTEXT_TYPE, context->Size());
    if (IsWeakArrayList(context->retained_maps(), cage_base())) {
      RecordSimpleVirtualObjectStats(
          context, Cast<WeakArrayList>(context->retained_maps()),
          ObjectStats::RETAINED_MAPS_TYPE);
    }

  } else if (context->IsFunctionContext()) {
    RecordObjectStats(context, FUNCTION_CONTEXT_TYPE, context->Size());
  } else {
    RecordSimpleVirtualObjectStats(HeapObject(), context,
                                   ObjectStats::OTHER_CONTEXT_TYPE);
  }
}

class ObjectStatsVisitor {
 public:
  ObjectStatsVisitor(Heap* heap, ObjectStatsCollectorImpl* live_collector,
                     ObjectStatsCollectorImpl* dead_collector,
                     ObjectStatsCollectorImpl::Phase phase)
      : live_collector_(live_collector),
        dead_collector_(dead_collector),
        marking_state_(heap->non_atomic_marking_state()),
        phase_(phase) {}

  void Visit(Tagged<HeapObject> obj) {
    if (HeapLayout::InReadOnlySpace(obj) || marking_state_->IsMarked(obj)) {
      live_collector_->CollectStatistics(
          obj, phase_, ObjectStatsCollectorImpl::CollectFieldStats::kYes);
    } else {
      dead_collector_->CollectStatistics(
          obj, phase_, ObjectStatsCollectorImpl::CollectFieldStats::kNo);
    }
  }

 private:
  ObjectStatsCollectorImpl* const live_collector_;
  ObjectStatsCollectorImpl* const dead_collector_;
  NonAtomicMarkingState* const marking_state_;
  ObjectStatsCollectorImpl::Phase phase_;
};

namespace {

void IterateHeap(Heap* heap, ObjectStatsVisitor* visitor) {
  // We don't perform a GC while collecting object stats but need this scope for
  // the nested SafepointScope inside CombinedHeapObjectIterator.
  AllowGarbageCollection allow_gc;
  CombinedHeapObjectIterator iterator(heap);
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    visitor->Visit(obj);
  }
}

}  // namespace

void ObjectStatsCollector::Collect() {
  ObjectStatsCollectorImpl live_collector(heap_, live_);
  ObjectStatsCollectorImpl dead_collector(heap_, dead_);
  live_collector.CollectGlobalStatistics();
  for (int i = 0; i < ObjectStatsCollectorImpl::kNumberOfPhases; i++) {
    ObjectStatsVisitor visitor(heap_, &live_collector, &dead_collector,
                               static_cast<ObjectStatsCollectorImpl::Phase>(i));
    IterateHeap(heap_, &visitor);
  }
}

}  // namespace internal
}  // namespace v8
```
Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/map.cc`. I need to analyze the code and identify its core responsibilities within the V8 JavaScript engine.

Here's a breakdown of the steps:

1. **Identify the purpose of `v8/src/objects/map.cc`:** This file likely deals with the `Map` object in V8, which is a fundamental concept for object structure and optimization.

2. **List the functionalities based on the provided code:** Go through the methods and functions in the snippet and describe what they do. Key areas seem to be:
    - Prototype chain handling.
    - Accessing constructor functions.
    - Determining visitor IDs for garbage collection.
    - Handling field types.
    - Copying and modifying Maps (adding fields, constants).
    - Checking if instances need rewriting during map transitions.
    - Managing descriptors.
    - Deprecating transition trees.
    - Updating maps (including handling deprecated maps).
    - Ensuring descriptor slack.
    - Creating maps for object creation.
    - Creating maps for derived classes.

3. **Check if it's a Torque file:** The prompt specifies checking for a `.tq` extension. This file has a `.cc` extension, so it's not a Torque file.

4. **Relate to JavaScript functionality (if applicable) with examples:** Explain how the operations in the C++ code relate to JavaScript concepts. For example, map transitions are linked to adding properties to objects.

5. **Provide code logic reasoning with examples:** For some functions, create hypothetical inputs and outputs to illustrate their behavior.

6. **Illustrate common programming errors:** Think about how developers might misuse the concepts related to maps and object structure in JavaScript, leading to errors.

7. **Summarize the functionality:**  Provide a concise overview of the responsibilities of the `v8/src/objects/map.cc` file based on the provided snippet.

**Overall Functionality Summary (Initial Thought):**

The code in `v8/src/objects/map.cc` is responsible for managing the internal representation of JavaScript object structures within the V8 engine. This includes handling prototype chains, managing object properties (fields and constants), optimizing object layouts through map transitions, and supporting garbage collection. It's a core component for efficient object management in V8.
这是 `v8/src/objects/map.cc` 文件的第 1 部分，主要负责定义和实现 `Map` 类的相关功能。`Map` 对象在 V8 引擎中扮演着至关重要的角色，它描述了 JavaScript 对象的结构和布局，是实现对象属性访问和优化的关键。

以下是根据提供的代码片段归纳出的 `v8/src/objects/map.cc` 的部分功能：

1. **获取原型链的根 Map (`GetPrototypeChainRootMap`)**:
   - 该函数用于查找给定 Map 对象原型链的根 Map。
   - 如果当前 Map 是一个 `JSReceiver` 的 Map，那么它本身就是根 Map。
   - 否则，它会尝试获取构造函数，并返回构造函数的初始 Map。
   - 如果没有构造函数，则返回 `null` 值的 Map。

2. **获取构造函数 (`GetConstructorFunction`)**:
   - 该函数尝试获取与给定 Map 关联的构造函数。
   - 它只对原始类型（primitive）的 Map 进行检查。
   - 如果 Map 有关联的构造函数索引，则从本地上下文中获取对应的 `JSFunction`。

3. **获取访问者 ID (`GetVisitorId`)**:
   - 该函数为不同类型的 V8 对象关联一个唯一的访问者 ID。
   - 这些 ID 用于垃圾回收器等组件，以便能够正确地遍历和处理不同类型的对象。
   - 函数内部通过 `instance_type()` 判断对象的类型，并返回相应的 `VisitorId` 枚举值。
   - 涵盖了各种 V8 内部对象类型，例如字符串、哈希表、上下文、函数、数组、Promise、WebAssembly 相关对象等等。

4. **包装和解包字段类型 (`WrapFieldType`, `UnwrapFieldType`)**:
   - `WrapFieldType` 用于将 `FieldType` 包装成 `MaybeObjectHandle`，如果类型是 Class，则包装成 WeakHandle。
   - `UnwrapFieldType` 执行相反的操作，从 `MaybeObject` 中提取 `FieldType`。

5. **复制并添加字段 (`CopyWithField`)**:
   - 该函数创建一个新的 Map，它是现有 Map 的副本，并添加一个新的字段。
   - 需要提供字段的名称、类型、属性、常量性、表示形式和过渡标志。
   - 它会检查描述符数组是否已满，并计算新字段的索引。
   - 对于上下文扩展对象，字段总是可变的，表示为 Tagged，类型为 Any。
   - 它还会调用 `GeneralizeIfCanHaveTransitionableFastElementsKind` 来可能地泛化元素类型。
   - 最终调用 `CopyAddDescriptor` 来完成 Map 的复制和描述符的添加。

6. **复制并添加常量 (`CopyWithConstant`)**:
   - 类似于 `CopyWithField`，但用于添加常量属性。
   - 它会自动推断常量的最佳表示形式和类型。

7. **判断实例是否需要重写 (`InstancesNeedRewriting`)**:
   - 该函数判断当对象的 Map 发生变化时，是否需要重写对象的实例。
   - 重写通常发生在字段数量改变、Smi 描述符被 Double 描述符替换或内联属性数量减少时。

8. **获取字段数量 (`NumberOfFields`)**:
   - 返回 Map 对象所描述的具有字段存储的属性数量。

9. **获取字段计数 (`GetFieldCounts`)**:
   - 返回 Map 对象中可变字段和常量字段的数量。

10. **废弃过渡树 (`DeprecateTransitionTree`)**:
    - 将当前的 Map 标记为已废弃，并递归地废弃其过渡树中的其他 Map。
    - 这通常发生在优化过程中，表示该 Map 不再适合作为新对象的模板。

11. **替换描述符 (`ReplaceDescriptors`)**:
    - 使用新的描述符数组替换当前 Map 及其共享相同描述符数组的其他 Map 的描述符。
    - 用于确保描述符数组的共享和一致性。

12. **查找根 Map (`FindRootMap`)**:
    - 沿着 `back_pointer_` 链向上查找，直到找到初始 Map，即原型链的根 Map。

13. **查找字段的所有者 (`FindFieldOwner`)**:
    -  确定特定字段（由描述符索引指定）是由哪个 Map 对象引入的。

14. **尝试更新 Map (`TryUpdate`)**:
    - 尝试将一个已废弃的 Map 更新到其迁移目标 Map。
    - 如果启用了快速 Map 更新，则会先尝试查找迁移目标。
    - 否则，会使用 `MapUpdater` 来进行更新。

15. **尝试重放属性过渡 (`TryReplayPropertyTransitions`)**:
    - 尝试将旧 Map 的属性过渡应用到当前 Map 上，以找到一个匹配的 Map。
    - 用于优化场景，避免不必要的 Map 创建。

16. **更新 Map (`Update`)**:
    - 强制更新一个 Map 对象，如果它是已废弃的，则更新到其最新的版本。

17. **确保描述符的空闲空间 (`EnsureDescriptorSlack`)**:
    - 增加 Map 的描述符数组的空闲空间，以便可以容纳更多的描述符。
    - 这涉及到复制描述符数组并更新所有共享该数组的 Map。

18. **获取 `Object.create()` 的 Map (`GetObjectCreateMap`)**:
    - 返回用于 `Object.create(prototype)` 创建对象的 Map。
    - 根据 `prototype` 的不同，返回不同的 Map，包括使用 `null` 原型的慢速对象 Map。

19. **获取派生类的 Map (`GetDerivedMap`)**:
    - 返回用于派生类实例的初始 Map。

**关于文件扩展名和 Torque：**

你提供的代码片段是以 `.cc` 结尾的，这意味着它是一个标准的 C++ 源代码文件，而不是 Torque 源代码（`.tq`）。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码。

**与 JavaScript 功能的关系及示例：**

`v8/src/objects/map.cc` 中的功能与 JavaScript 对象的创建、属性访问、继承和优化密切相关。以下是一些 JavaScript 示例，可以帮助理解这些功能：

```javascript
// 1. 获取原型链的根 Map (对应 GetPrototypeChainRootMap)
const obj = {};
const arr = [];
const func = () => {};

// 在 V8 内部，obj, arr, func 都有与之关联的 Map 对象，
// 它们的原型链最终会指向 Object.prototype，其 Map 就是根 Map 之一。

// 2. 获取构造函数 (对应 GetConstructorFunction)
const num = 1; // Number 类型的原始值
// 在 V8 内部，原始值也有对应的 Map，可以关联到 Number 构造函数。

// 5. 复制并添加字段 (对应 CopyWithField)
const person = { name: 'Alice' };
person.age = 30; // 当添加新的属性时，V8 可能会创建一个新的 Map

// 6. 复制并添加常量 (对应 CopyWithConstant)
Object.defineProperty(person, 'city', { value: 'New York', writable: false }); // 添加一个常量属性

// 7. 判断实例是否需要重写 (对应 InstancesNeedRewriting)
// 当修改对象的结构（例如添加或删除属性）时，如果 V8 认为有必要，
// 可能会创建一个新的 Map，并将对象的内部结构迁移到新的 Map。

// 18. 获取 Object.create() 的 Map (对应 GetObjectCreateMap)
const proto = { greeting: 'Hello' };
const customObj = Object.create(proto); // customObj 的 Map 会基于 proto 的 Map 创建

const nullProtoObj = Object.create(null); // nullProtoObj 会使用一个特殊的 Map
```

**代码逻辑推理和假设输入/输出：**

假设有一个简单的 JavaScript 对象：

```javascript
const point = { x: 10, y: 20 };
```

在 V8 内部，`point` 对象会关联到一个 `Map` 对象。

- **假设调用 `Map::CopyWithField` 添加一个 `z` 属性：**
    - **输入:** 指向 `point` 当前 `Map` 的指针，字段名 `"z"`，类型 `Number`，属性 `可写` 等。
    - **输出:** 一个新的 `Map` 对象，其结构与旧 `Map` 类似，但包含 `z` 属性的描述符，并且可能更新了字段数量和布局信息。`point` 对象的内部指针最终会指向这个新的 `Map`。

- **假设调用 `Map::InstancesNeedRewriting`，比较添加 `z` 属性前后的 Map：**
    - **输入:** 旧的 `Map`（只有 `x` 和 `y`），新的 `Map`（包含 `x`, `y`, `z`）。
    - **输出:** `true`，因为字段数量发生了变化，需要重写实例。

**用户常见的编程错误：**

- **过度动态地添加/删除属性:**  频繁地修改对象的结构会导致 V8 不断地创建新的 `Map` 对象，这可能会降低性能，因为 V8 需要进行更多的内部操作来跟踪这些变化。

  ```javascript
  const obj = {};
  for (let i = 0; i < 1000; i++) {
    obj[`prop${i}`] = i; // 每次循环都添加新的属性，可能导致 Map 不断变化
  }
  ```

- **假设所有对象都具有相同的结构:**  依赖于对象的特定内部结构可能会导致问题，因为 V8 会根据对象的属性和类型进行优化，具有不同属性的对象可能具有不同的 `Map`。

  ```javascript
  function processPoint(point) {
    console.log(point.x + point.y); // 假设 point 总是有 x 和 y 属性
  }

  processPoint({ x: 1, y: 2 });
  processPoint({ x: 3, z: 4 }); // 这里的对象没有 y 属性，可能导致错误
  ```

**总结一下 `v8/src/objects/map.cc` 第 1 部分的功能：**

总的来说，`v8/src/objects/map.cc` 的第一部分代码定义了 `Map` 类的核心功能，这些功能涉及到：

- 管理 JavaScript 对象的结构和布局信息。
- 处理原型链关系。
- 支持动态添加和修改对象属性。
- 优化对象访问性能，例如通过 Map 的迁移和更新。
- 为垃圾回收等内部机制提供必要的元数据。

这部分代码是 V8 引擎实现高效 JavaScript 对象模型的基础。

Prompt: 
```
这是目录为v8/src/objects/map.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/map.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/map.h"

#include <optional>

#include "src/common/assert-scope.h"
#include "src/common/globals.h"
#include "src/execution/frames.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/init/bootstrapper.h"
#include "src/logging/log.h"
#include "src/logging/runtime-call-stats-scope.h"
#include "src/objects/arguments-inl.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/elements-kind.h"
#include "src/objects/field-type.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-objects.h"
#include "src/objects/map-updater.h"
#include "src/objects/maybe-object.h"
#include "src/objects/oddball.h"
#include "src/objects/property.h"
#include "src/objects/transitions-inl.h"
#include "src/roots/roots.h"
#include "src/utils/ostreams.h"
#include "src/zone/zone-containers.h"

namespace v8::internal {

Tagged<Map> Map::GetPrototypeChainRootMap(Isolate* isolate) const {
  DisallowGarbageCollection no_alloc;
  if (IsJSReceiverMap(*this)) {
    return *this;
  }
  int constructor_function_index = GetConstructorFunctionIndex();
  if (constructor_function_index != Map::kNoConstructorFunctionIndex) {
    Tagged<Context> native_context = isolate->context()->native_context();
    Tagged<JSFunction> constructor_function =
        Cast<JSFunction>(native_context->get(constructor_function_index));
    return constructor_function->initial_map();
  }
  return ReadOnlyRoots(isolate).null_value()->map();
}

// static
std::optional<Tagged<JSFunction>> Map::GetConstructorFunction(
    Tagged<Map> map, Tagged<Context> native_context) {
  DisallowGarbageCollection no_gc;
  if (IsPrimitiveMap(map)) {
    int const constructor_function_index = map->GetConstructorFunctionIndex();
    if (constructor_function_index != kNoConstructorFunctionIndex) {
      return Cast<JSFunction>(native_context->get(constructor_function_index));
    }
  }
  return {};
}

VisitorId Map::GetVisitorId(Tagged<Map> map) {
  static_assert(kVisitorIdCount <= 256);

  const int instance_type = map->instance_type();

  if (instance_type < FIRST_NONSTRING_TYPE) {
    switch (instance_type & kStringRepresentationMask) {
      case kSeqStringTag:
        if ((instance_type & kStringEncodingMask) == kOneByteStringTag) {
          return kVisitSeqOneByteString;
        } else {
          return kVisitSeqTwoByteString;
        }

      case kConsStringTag:
        if (IsShortcutCandidate(instance_type)) {
          return kVisitShortcutCandidate;
        } else {
          return kVisitConsString;
        }

      case kSlicedStringTag:
        return kVisitSlicedString;

      case kExternalStringTag:
        return kVisitExternalString;

      case kThinStringTag:
        return kVisitThinString;
    }
    UNREACHABLE();
  }

  if (InstanceTypeChecker::IsJSApiObject(map->instance_type())) {
    return kVisitJSApiObject;
  }

  switch (instance_type) {
    case FILLER_TYPE:
      return kVisitFiller;
    case FREE_SPACE_TYPE:
      return kVisitFreeSpace;

    case EMBEDDER_DATA_ARRAY_TYPE:
      return kVisitEmbedderDataArray;

    case NAME_TO_INDEX_HASH_TABLE_TYPE:
    case REGISTERED_SYMBOL_TABLE_TYPE:
    case HASH_TABLE_TYPE:
    case ORDERED_HASH_MAP_TYPE:
    case ORDERED_HASH_SET_TYPE:
    case ORDERED_NAME_DICTIONARY_TYPE:
    case NAME_DICTIONARY_TYPE:
    case GLOBAL_DICTIONARY_TYPE:
    case NUMBER_DICTIONARY_TYPE:
    case SIMPLE_NUMBER_DICTIONARY_TYPE:
      return kVisitFixedArray;

    case SLOPPY_ARGUMENTS_ELEMENTS_TYPE:
      return kVisitSloppyArgumentsElements;

    case AWAIT_CONTEXT_TYPE:
    case BLOCK_CONTEXT_TYPE:
    case CATCH_CONTEXT_TYPE:
    case DEBUG_EVALUATE_CONTEXT_TYPE:
    case EVAL_CONTEXT_TYPE:
    case FUNCTION_CONTEXT_TYPE:
    case MODULE_CONTEXT_TYPE:
    case SCRIPT_CONTEXT_TYPE:
    case WITH_CONTEXT_TYPE:
      return kVisitContext;

    case NATIVE_CONTEXT_TYPE:
      return kVisitNativeContext;

    case EPHEMERON_HASH_TABLE_TYPE:
      return kVisitEphemeronHashTable;

    case PROPERTY_ARRAY_TYPE:
      return kVisitPropertyArray;

    case FEEDBACK_CELL_TYPE:
      return kVisitFeedbackCell;

    case FEEDBACK_METADATA_TYPE:
      return kVisitFeedbackMetadata;

    case ODDBALL_TYPE:
      return kVisitOddball;

    case HOLE_TYPE:
      return kVisitHole;

    case MAP_TYPE:
      return kVisitMap;

    case CELL_TYPE:
      return kVisitCell;

    case PROPERTY_CELL_TYPE:
      return kVisitPropertyCell;

    case CONTEXT_SIDE_PROPERTY_CELL_TYPE:
      return kVisitContextSidePropertyCell;

    case TRANSITION_ARRAY_TYPE:
      return kVisitTransitionArray;

    case JS_WEAK_MAP_TYPE:
    case JS_WEAK_SET_TYPE:
      return kVisitJSWeakCollection;

    case ACCESSOR_INFO_TYPE:
      return kVisitAccessorInfo;

    case FUNCTION_TEMPLATE_INFO_TYPE:
      return kVisitFunctionTemplateInfo;

    case OBJECT_TEMPLATE_INFO_TYPE:
      return kVisitStruct;

    case JS_PROXY_TYPE:
      return kVisitStruct;

    case SYMBOL_TYPE:
      return kVisitSymbol;

    case JS_ARRAY_BUFFER_TYPE:
      return kVisitJSArrayBuffer;

    case JS_DATA_VIEW_TYPE:
    case JS_RAB_GSAB_DATA_VIEW_TYPE:
      return kVisitJSDataViewOrRabGsabDataView;

    case JS_EXTERNAL_OBJECT_TYPE:
      return kVisitJSExternalObject;

    case JS_FUNCTION_TYPE:
    case JS_CLASS_CONSTRUCTOR_TYPE:
    case JS_PROMISE_CONSTRUCTOR_TYPE:
    case JS_REG_EXP_CONSTRUCTOR_TYPE:
    case JS_ARRAY_CONSTRUCTOR_TYPE:
#define TYPED_ARRAY_CONSTRUCTORS_SWITCH(Type, type, TYPE, Ctype) \
  case TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE:
      TYPED_ARRAYS(TYPED_ARRAY_CONSTRUCTORS_SWITCH)
#undef TYPED_ARRAY_CONSTRUCTORS_SWITCH
      return kVisitJSFunction;

    case JS_TYPED_ARRAY_TYPE:
      return kVisitJSTypedArray;

    case SMALL_ORDERED_HASH_MAP_TYPE:
      return kVisitSmallOrderedHashMap;

    case SMALL_ORDERED_HASH_SET_TYPE:
      return kVisitSmallOrderedHashSet;

    case SMALL_ORDERED_NAME_DICTIONARY_TYPE:
      return kVisitSmallOrderedNameDictionary;

    case SWISS_NAME_DICTIONARY_TYPE:
      return kVisitSwissNameDictionary;

    case SHARED_FUNCTION_INFO_TYPE:
      return kVisitSharedFunctionInfo;

    case PREPARSE_DATA_TYPE:
      return kVisitPreparseData;

    case COVERAGE_INFO_TYPE:
      return kVisitCoverageInfo;

    // Objects that may have embedder fields but otherwise are just a regular
    // JSObject.
    case JS_PROMISE_TYPE: {
      const bool has_raw_data_fields =
          COMPRESS_POINTERS_BOOL && JSObject::GetEmbedderFieldCount(map) > 0;
      return has_raw_data_fields ? kVisitJSObject : kVisitJSObjectFast;
    }

    // Objects that are guaranteed to not have any embedder fields and just
    // behave like regular JSObject.
    case JS_ARGUMENTS_OBJECT_TYPE:
    case JS_ARRAY_ITERATOR_PROTOTYPE_TYPE:
    case JS_ARRAY_ITERATOR_TYPE:
    case JS_ARRAY_TYPE:
    case JS_ASYNC_DISPOSABLE_STACK_TYPE:
    case JS_ASYNC_FROM_SYNC_ITERATOR_TYPE:
    case JS_ASYNC_FUNCTION_OBJECT_TYPE:
    case JS_ASYNC_GENERATOR_OBJECT_TYPE:
    case JS_CONTEXT_EXTENSION_OBJECT_TYPE:
    case JS_DISPOSABLE_STACK_BASE_TYPE:
    case JS_ERROR_TYPE:
    case JS_GENERATOR_OBJECT_TYPE:
    case JS_ITERATOR_FILTER_HELPER_TYPE:
    case JS_ITERATOR_MAP_HELPER_TYPE:
    case JS_ITERATOR_TAKE_HELPER_TYPE:
    case JS_ITERATOR_DROP_HELPER_TYPE:
    case JS_ITERATOR_FLAT_MAP_HELPER_TYPE:
    case JS_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_ITERATOR_PROTOTYPE_TYPE:
    case JS_MAP_KEY_ITERATOR_TYPE:
    case JS_MAP_KEY_VALUE_ITERATOR_TYPE:
    case JS_MAP_TYPE:
    case JS_MAP_VALUE_ITERATOR_TYPE:
    case JS_MESSAGE_OBJECT_TYPE:
    case JS_MODULE_NAMESPACE_TYPE:
    case JS_OBJECT_PROTOTYPE_TYPE:
    case JS_OBJECT_TYPE:
    case JS_PRIMITIVE_WRAPPER_TYPE:
    case JS_PROMISE_PROTOTYPE_TYPE:
    case JS_REG_EXP_PROTOTYPE_TYPE:
    case JS_REG_EXP_STRING_ITERATOR_TYPE:
    case JS_SET_ITERATOR_PROTOTYPE_TYPE:
    case JS_SET_KEY_VALUE_ITERATOR_TYPE:
    case JS_SET_PROTOTYPE_TYPE:
    case JS_SET_TYPE:
    case JS_SET_VALUE_ITERATOR_TYPE:
    case JS_SYNC_DISPOSABLE_STACK_TYPE:
    case JS_SHADOW_REALM_TYPE:
    case JS_SHARED_ARRAY_TYPE:
    case JS_SHARED_STRUCT_TYPE:
    case JS_STRING_ITERATOR_PROTOTYPE_TYPE:
    case JS_STRING_ITERATOR_TYPE:
    case JS_TEMPORAL_CALENDAR_TYPE:
    case JS_TEMPORAL_DURATION_TYPE:
    case JS_TEMPORAL_INSTANT_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TYPE:
    case JS_TEMPORAL_PLAIN_DATE_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_MONTH_DAY_TYPE:
    case JS_TEMPORAL_PLAIN_TIME_TYPE:
    case JS_TEMPORAL_PLAIN_YEAR_MONTH_TYPE:
    case JS_TEMPORAL_TIME_ZONE_TYPE:
    case JS_TEMPORAL_ZONED_DATE_TIME_TYPE:
    case JS_TYPED_ARRAY_PROTOTYPE_TYPE:
    case JS_VALID_ITERATOR_WRAPPER_TYPE:
    case JS_RAW_JSON_TYPE:
#ifdef V8_INTL_SUPPORT
    case JS_V8_BREAK_ITERATOR_TYPE:
    case JS_COLLATOR_TYPE:
    case JS_DATE_TIME_FORMAT_TYPE:
    case JS_DISPLAY_NAMES_TYPE:
    case JS_DURATION_FORMAT_TYPE:
    case JS_LIST_FORMAT_TYPE:
    case JS_LOCALE_TYPE:
    case JS_NUMBER_FORMAT_TYPE:
    case JS_PLURAL_RULES_TYPE:
    case JS_RELATIVE_TIME_FORMAT_TYPE:
    case JS_SEGMENT_ITERATOR_TYPE:
    case JS_SEGMENTER_TYPE:
    case JS_SEGMENTS_TYPE:
#endif  // V8_INTL_SUPPORT
#if V8_ENABLE_WEBASSEMBLY
    case WASM_EXCEPTION_PACKAGE_TYPE:
    case WASM_MODULE_OBJECT_TYPE:
    case WASM_VALUE_OBJECT_TYPE:
#endif  // V8_ENABLE_WEBASSEMBLY
    case JS_BOUND_FUNCTION_TYPE:
    case JS_WRAPPED_FUNCTION_TYPE: {
      CHECK_EQ(0, JSObject::GetEmbedderFieldCount(map));
      return kVisitJSObjectFast;
    }
    case JS_REG_EXP_TYPE:
      return kVisitJSRegExp;

    // Objects that are used as API wrapper objects and can have embedder
    // fields. Note that there's more of these kinds (e.g. JS_ARRAY_BUFFER_TYPE)
    // but they have their own visitor id for other reasons
    case JS_API_OBJECT_TYPE:
    case JS_GLOBAL_PROXY_TYPE:
    case JS_GLOBAL_OBJECT_TYPE:
    case JS_SPECIAL_API_OBJECT_TYPE:
      return kVisitJSApiObject;

    case JS_DATE_TYPE:
      return kVisitJSDate;

    case JS_WEAK_REF_TYPE:
      return kVisitJSWeakRef;

    case WEAK_CELL_TYPE:
      return kVisitWeakCell;

    case JS_FINALIZATION_REGISTRY_TYPE:
      return kVisitJSFinalizationRegistry;

    case JS_ATOMICS_MUTEX_TYPE:
    case JS_ATOMICS_CONDITION_TYPE:
      return kVisitJSSynchronizationPrimitive;

    case HEAP_NUMBER_TYPE:
      return kVisitHeapNumber;

    case FOREIGN_TYPE:
      return kVisitForeign;

    case BIGINT_TYPE:
      return kVisitBigInt;

    case ALLOCATION_SITE_TYPE:
      return kVisitAllocationSite;

    // Here we list all structs explicitly on purpose. This forces new structs
    // to choose a VisitorId explicitly.
    case PROMISE_FULFILL_REACTION_JOB_TASK_TYPE:
    case PROMISE_REJECT_REACTION_JOB_TASK_TYPE:
    case CALLABLE_TASK_TYPE:
    case CALLBACK_TASK_TYPE:
    case PROMISE_RESOLVE_THENABLE_JOB_TASK_TYPE:
    case ACCESS_CHECK_INFO_TYPE:
    case ACCESSOR_PAIR_TYPE:
    case ALIASED_ARGUMENTS_ENTRY_TYPE:
    case ALLOCATION_MEMENTO_TYPE:
    case ARRAY_BOILERPLATE_DESCRIPTION_TYPE:
    case ASYNC_GENERATOR_REQUEST_TYPE:
    case BREAK_POINT_TYPE:
    case BREAK_POINT_INFO_TYPE:
    case CLASS_BOILERPLATE_TYPE:
    case CLASS_POSITIONS_TYPE:
    case ENUM_CACHE_TYPE:
    case ERROR_STACK_DATA_TYPE:
    case FUNCTION_TEMPLATE_RARE_DATA_TYPE:
    case INTERCEPTOR_INFO_TYPE:
    case MODULE_REQUEST_TYPE:
    case PROMISE_CAPABILITY_TYPE:
    case PROMISE_REACTION_TYPE:
    case PROPERTY_DESCRIPTOR_OBJECT_TYPE:
    case SCRIPT_TYPE:
    case SCRIPT_OR_MODULE_TYPE:
    case SOURCE_TEXT_MODULE_INFO_ENTRY_TYPE:
    case STACK_FRAME_INFO_TYPE:
    case STACK_TRACE_INFO_TYPE:
    case TEMPLATE_OBJECT_DESCRIPTION_TYPE:
    case TUPLE2_TYPE:
#if V8_ENABLE_WEBASSEMBLY
    case ASM_WASM_DATA_TYPE:
    case WASM_EXCEPTION_TAG_TYPE:
#endif
      return kVisitStruct;

    case PROTOTYPE_INFO_TYPE:
      return kVisitPrototypeInfo;

    case DEBUG_INFO_TYPE:
      return kVisitDebugInfo;

    case CALL_SITE_INFO_TYPE:
      return kVisitCallSiteInfo;

    case BYTECODE_WRAPPER_TYPE:
      return kVisitBytecodeWrapper;

    case CODE_WRAPPER_TYPE:
      return kVisitCodeWrapper;

    case REG_EXP_BOILERPLATE_DESCRIPTION_TYPE:
      return kVisitRegExpBoilerplateDescription;

    case REG_EXP_DATA_WRAPPER_TYPE:
      return kVisitRegExpDataWrapper;

    case LOAD_HANDLER_TYPE:
    case STORE_HANDLER_TYPE:
      return kVisitDataHandler;

    case SOURCE_TEXT_MODULE_TYPE:
      return kVisitSourceTextModule;
    case SYNTHETIC_MODULE_TYPE:
      return kVisitSyntheticModule;

#if V8_ENABLE_WEBASSEMBLY
    case WASM_ARRAY_TYPE:
      return kVisitWasmArray;
    case WASM_CONTINUATION_OBJECT_TYPE:
      return kVisitWasmContinuationObject;
    case WASM_FUNC_REF_TYPE:
      return kVisitWasmFuncRef;
    case WASM_GLOBAL_OBJECT_TYPE:
      return kVisitWasmGlobalObject;
    case WASM_INSTANCE_OBJECT_TYPE:
      return kVisitWasmInstanceObject;
    case WASM_MEMORY_OBJECT_TYPE:
      return kVisitWasmMemoryObject;
    case WASM_NULL_TYPE:
      return kVisitWasmNull;
    case WASM_RESUME_DATA_TYPE:
      return kVisitWasmResumeData;
    case WASM_STRUCT_TYPE:
      return kVisitWasmStruct;
    case WASM_SUSPENDER_OBJECT_TYPE:
      return kVisitWasmSuspenderObject;
    case WASM_SUSPENDING_OBJECT_TYPE:
      return kVisitWasmSuspendingObject;
    case WASM_TABLE_OBJECT_TYPE:
      return kVisitWasmTableObject;
    case WASM_TAG_OBJECT_TYPE:
      return kVisitWasmTagObject;
    case WASM_TYPE_INFO_TYPE:
      return kVisitWasmTypeInfo;
#endif  // V8_ENABLE_WEBASSEMBLY

#define MAKE_TQ_CASE(TYPE, Name) \
  case TYPE:                     \
    return kVisit##Name;
      TORQUE_INSTANCE_TYPE_TO_BODY_DESCRIPTOR_LIST(MAKE_TQ_CASE)
#undef MAKE_TQ_CASE

#define CASE(TypeCamelCase, TYPE_UPPER_CASE) \
  case TYPE_UPPER_CASE##_TYPE:               \
    return kVisit##TypeCamelCase;
      SIMPLE_HEAP_OBJECT_LIST2(CASE)
      CONCRETE_TRUSTED_OBJECT_TYPE_LIST2(CASE)
#undef CASE
  }
  std::string name = ToString(map->instance_type());
  FATAL("Instance type %s (code %d) not mapped to VisitorId.", name.c_str(),
        instance_type);
}

// static
MaybeObjectHandle Map::WrapFieldType(Handle<FieldType> type) {
  if (IsClass(*type)) {
    return MaybeObjectHandle::Weak(FieldType::AsClass(type));
  }
  return MaybeObjectHandle(type);
}

// static
Tagged<FieldType> Map::UnwrapFieldType(Tagged<MaybeObject> wrapped_type) {
  DCHECK(!wrapped_type.IsCleared());
  Tagged<HeapObject> heap_object;
  if (wrapped_type.GetHeapObjectIfWeak(&heap_object)) {
    return Cast<FieldType>(heap_object);
  }
  return Cast<FieldType>(wrapped_type);
}

MaybeHandle<Map> Map::CopyWithField(Isolate* isolate, Handle<Map> map,
                                    Handle<Name> name, Handle<FieldType> type,
                                    PropertyAttributes attributes,
                                    PropertyConstness constness,
                                    Representation representation,
                                    TransitionFlag flag) {
  DCHECK(map->instance_descriptors(isolate)
             ->Search(*name, map->NumberOfOwnDescriptors())
             .is_not_found());

  // Ensure the descriptor array does not get too big.
  if (map->NumberOfOwnDescriptors() >= kMaxNumberOfDescriptors) {
    return MaybeHandle<Map>();
  }

  // Compute the new index for new field.
  int index = map->NextFreePropertyIndex();

  if (map->instance_type() == JS_CONTEXT_EXTENSION_OBJECT_TYPE) {
    constness = PropertyConstness::kMutable;
    representation = Representation::Tagged();
    type = FieldType::Any(isolate);
  } else {
    Map::GeneralizeIfCanHaveTransitionableFastElementsKind(
        isolate, map->instance_type(), &representation, &type);
  }

  MaybeObjectHandle wrapped_type = WrapFieldType(type);

  Descriptor d = Descriptor::DataField(name, index, attributes, constness,
                                       representation, wrapped_type);
  Handle<Map> new_map = Map::CopyAddDescriptor(isolate, map, &d, flag);
  new_map->AccountAddedPropertyField();
  return new_map;
}

MaybeHandle<Map> Map::CopyWithConstant(Isolate* isolate, Handle<Map> map,
                                       Handle<Name> name,
                                       DirectHandle<Object> constant,
                                       PropertyAttributes attributes,
                                       TransitionFlag flag) {
  // Ensure the descriptor array does not get too big.
  if (map->NumberOfOwnDescriptors() >= kMaxNumberOfDescriptors) {
    return MaybeHandle<Map>();
  }

  Representation representation =
      Object::OptimalRepresentation(*constant, isolate);
  Handle<FieldType> type =
      Object::OptimalType(*constant, isolate, representation);
  return CopyWithField(isolate, map, name, type, attributes,
                       PropertyConstness::kConst, representation, flag);
}

bool Map::InstancesNeedRewriting(Tagged<Map> target,
                                 ConcurrencyMode cmode) const {
  int target_number_of_fields = target->NumberOfFields(cmode);
  int target_inobject = target->GetInObjectProperties();
  int target_unused = target->UnusedPropertyFields();
  int old_number_of_fields;

  return InstancesNeedRewriting(target, target_number_of_fields,
                                target_inobject, target_unused,
                                &old_number_of_fields, cmode);
}

bool Map::InstancesNeedRewriting(Tagged<Map> target,
                                 int target_number_of_fields,
                                 int target_inobject, int target_unused,
                                 int* old_number_of_fields,
                                 ConcurrencyMode cmode) const {
  // If fields were added (or removed), rewrite the instance.
  *old_number_of_fields = NumberOfFields(cmode);
  DCHECK(target_number_of_fields >= *old_number_of_fields);
  if (target_number_of_fields != *old_number_of_fields) return true;

  // If smi descriptors were replaced by double descriptors, rewrite.
  Tagged<DescriptorArray> old_desc = IsConcurrent(cmode)
                                         ? instance_descriptors(kAcquireLoad)
                                         : instance_descriptors();
  Tagged<DescriptorArray> new_desc =
      IsConcurrent(cmode) ? target->instance_descriptors(kAcquireLoad)
                          : target->instance_descriptors();
  for (InternalIndex i : IterateOwnDescriptors()) {
    if (new_desc->GetDetails(i).representation().IsDouble() !=
        old_desc->GetDetails(i).representation().IsDouble()) {
      return true;
    }
  }

  // If no fields were added, and no inobject properties were removed, setting
  // the map is sufficient.
  if (target_inobject == GetInObjectProperties()) return false;
  // In-object slack tracking may have reduced the object size of the new map.
  // In that case, succeed if all existing fields were inobject, and they still
  // fit within the new inobject size.
  DCHECK(target_inobject < GetInObjectProperties());
  if (target_number_of_fields <= target_inobject) {
    DCHECK(target_number_of_fields + target_unused == target_inobject);
    return false;
  }
  // Otherwise, properties will need to be moved to the backing store.
  return true;
}

int Map::NumberOfFields(ConcurrencyMode cmode) const {
  Tagged<DescriptorArray> descriptors = IsConcurrent(cmode)
                                            ? instance_descriptors(kAcquireLoad)
                                            : instance_descriptors();
  int result = 0;
  for (InternalIndex i : IterateOwnDescriptors()) {
    if (descriptors->GetDetails(i).location() == PropertyLocation::kField)
      result++;
  }
  return result;
}

Map::FieldCounts Map::GetFieldCounts() const {
  Tagged<DescriptorArray> descriptors = instance_descriptors();
  int mutable_count = 0;
  int const_count = 0;
  for (InternalIndex i : IterateOwnDescriptors()) {
    PropertyDetails details = descriptors->GetDetails(i);
    if (details.location() == PropertyLocation::kField) {
      switch (details.constness()) {
        case PropertyConstness::kMutable:
          mutable_count++;
          break;
        case PropertyConstness::kConst:
          const_count++;
          break;
      }
    }
  }
  return FieldCounts(mutable_count, const_count);
}

void Map::DeprecateTransitionTree(Isolate* isolate) {
  if (is_deprecated()) return;
  DisallowGarbageCollection no_gc;
  ReadOnlyRoots roots(isolate);
  TransitionsAccessor transitions(isolate, *this);
  transitions.ForEachTransition(
      &no_gc, [&](Tagged<Map> map) { map->DeprecateTransitionTree(isolate); },
      [&](Tagged<Map> map) {
        if (v8_flags.move_prototype_transitions_first) {
          map->DeprecateTransitionTree(isolate);
        }
      },
      nullptr);
  DCHECK(!IsFunctionTemplateInfo(constructor_or_back_pointer()));
  DCHECK(CanBeDeprecated());
  set_is_deprecated(true);
  if (v8_flags.log_maps) {
    LOG(isolate, MapEvent("Deprecate", handle(*this, isolate), Handle<Map>()));
  }
  DependentCode::DeoptimizeDependencyGroups(isolate, *this,
                                            DependentCode::kTransitionGroup);
  NotifyLeafMapLayoutChange(isolate);
}

// Installs |new_descriptors| over the current instance_descriptors to ensure
// proper sharing of descriptor arrays.
void Map::ReplaceDescriptors(Isolate* isolate,
                             Tagged<DescriptorArray> new_descriptors) {
  PtrComprCageBase cage_base(isolate);
  // Don't overwrite the empty descriptor array or initial map's descriptors.
  if (NumberOfOwnDescriptors() == 0 ||
      IsUndefined(GetBackPointer(cage_base), isolate)) {
    return;
  }

  Tagged<DescriptorArray> to_replace = instance_descriptors(cage_base);
  // Replace descriptors by new_descriptors in all maps that share it. The old
  // descriptors will not be trimmed in the mark-compactor, we need to mark
  // all its elements.
  Tagged<Map> current = *this;
#ifndef V8_DISABLE_WRITE_BARRIERS
  WriteBarrier::ForDescriptorArray(to_replace,
                                   to_replace->number_of_descriptors());
#endif
  while (current->instance_descriptors(cage_base) == to_replace) {
    Tagged<Map> next;
    if (!current->TryGetBackPointer(cage_base, &next)) {
      break;  // Stop overwriting at initial map.
    }
    current->SetEnumLength(kInvalidEnumCacheSentinel);
    current->UpdateDescriptors(isolate, new_descriptors,
                               current->NumberOfOwnDescriptors());
    current = next;
  }
  set_owns_descriptors(false);
}

Tagged<Map> Map::FindRootMap(PtrComprCageBase cage_base) const {
  DisallowGarbageCollection no_gc;
  Tagged<Map> result = *this;
  while (true) {
    Tagged<Map> parent;
    if (!result->TryGetBackPointer(cage_base, &parent)) {
      // Initial map must not contain descriptors in the descriptors array
      // that do not belong to the map.
      DCHECK_LE(result->NumberOfOwnDescriptors(),
                result->instance_descriptors(cage_base, kRelaxedLoad)
                    ->number_of_descriptors());
      return result;
    }
    result = parent;
  }
}

Tagged<Map> Map::FindFieldOwner(PtrComprCageBase cage_base,
                                InternalIndex descriptor) const {
  DisallowGarbageCollection no_gc;
  DCHECK_EQ(PropertyLocation::kField,
            instance_descriptors(cage_base, kRelaxedLoad)
                ->GetDetails(descriptor)
                .location());
  Tagged<Map> result = *this;
  while (true) {
    Tagged<Map> parent;
    if (!result->TryGetBackPointer(cage_base, &parent)) break;
    if (parent->NumberOfOwnDescriptors() <= descriptor.as_int()) break;
    result = parent;
  }
  return result;
}

namespace {

Tagged<Map> SearchMigrationTarget(Isolate* isolate, Tagged<Map> old_map) {
  DisallowGarbageCollection no_gc;

  Tagged<Map> target = old_map;
  do {
    target = TransitionsAccessor(isolate, target).GetMigrationTarget();
  } while (!target.is_null() && target->is_deprecated());
  if (target.is_null()) return Map();

  SLOW_DCHECK(MapUpdater::TryUpdateNoLock(
                  isolate, old_map, ConcurrencyMode::kSynchronous) == target);
  return target;
}
}  // namespace

// static
MaybeHandle<Map> Map::TryUpdate(Isolate* isolate, Handle<Map> old_map) {
  DisallowGarbageCollection no_gc;
  DisallowDeoptimization no_deoptimization(isolate);

  if (!old_map->is_deprecated()) return old_map;

  if (v8_flags.fast_map_update) {
    Tagged<Map> target_map = SearchMigrationTarget(isolate, *old_map);
    if (!target_map.is_null()) {
      return handle(target_map, isolate);
    }
  }

  std::optional<Tagged<Map>> new_map = MapUpdater::TryUpdateNoLock(
      isolate, *old_map, ConcurrencyMode::kSynchronous);
  if (!new_map.has_value()) return MaybeHandle<Map>();
  if (v8_flags.fast_map_update) {
    TransitionsAccessor::SetMigrationTarget(isolate, old_map, new_map.value());
  }
  return handle(new_map.value(), isolate);
}

Tagged<Map> Map::TryReplayPropertyTransitions(Isolate* isolate,
                                              Tagged<Map> old_map,
                                              ConcurrencyMode cmode) {
  DisallowGarbageCollection no_gc;

  const int root_nof = NumberOfOwnDescriptors();
  const int old_nof = old_map->NumberOfOwnDescriptors();
  // TODO(jgruber,chromium:1239009): The main thread should use non-atomic
  // reads, but this currently leads to odd behavior (see the linked bug).
  // Investigate and fix this properly. Also below and in called functions.
  Tagged<DescriptorArray> old_descriptors =
      old_map->instance_descriptors(isolate, kAcquireLoad);

  Tagged<Map> new_map = *this;
  for (InternalIndex i : InternalIndex::Range(root_nof, old_nof)) {
    PropertyDetails old_details = old_descriptors->GetDetails(i);
    Tagged<Map> transition =
        TransitionsAccessor(isolate, new_map, IsConcurrent(cmode))
            .SearchTransition(old_descriptors->GetKey(i), old_details.kind(),
                              old_details.attributes());
    if (transition.is_null()) return Map();
    new_map = transition;
    Tagged<DescriptorArray> new_descriptors =
        new_map->instance_descriptors(isolate, kAcquireLoad);

    PropertyDetails new_details = new_descriptors->GetDetails(i);
    DCHECK_EQ(old_details.kind(), new_details.kind());
    DCHECK_EQ(old_details.attributes(), new_details.attributes());
    if (!IsGeneralizableTo(old_details.constness(), new_details.constness())) {
      return Map();
    }
    DCHECK(IsGeneralizableTo(old_details.location(), new_details.location()));
    if (!old_details.representation().fits_into(new_details.representation())) {
      return Map();
    }
    if (new_details.location() == PropertyLocation::kField) {
      if (new_details.kind() == PropertyKind::kData) {
        Tagged<FieldType> new_type = new_descriptors->GetFieldType(i);
        DCHECK_EQ(PropertyKind::kData, old_details.kind());
        DCHECK_EQ(PropertyLocation::kField, old_details.location());
        Tagged<FieldType> old_type = old_descriptors->GetFieldType(i);
        if (!FieldType::NowIs(old_type, new_type)) {
          return Map();
        }
      } else {
        DCHECK_EQ(PropertyKind::kAccessor, new_details.kind());
#ifdef DEBUG
        Tagged<FieldType> new_type = new_descriptors->GetFieldType(i);
        DCHECK(IsAny(new_type));
#endif
        UNREACHABLE();
      }
    } else {
      DCHECK_EQ(PropertyLocation::kDescriptor, new_details.location());
      if (old_details.location() == PropertyLocation::kField ||
          old_descriptors->GetStrongValue(i) !=
              new_descriptors->GetStrongValue(i)) {
        return Map();
      }
    }
  }
  if (new_map->NumberOfOwnDescriptors() != old_nof) return Map();
  return new_map;
}

// static
Handle<Map> Map::Update(Isolate* isolate, Handle<Map> map) {
  if (!map->is_deprecated()) return map;
  if (v8_flags.fast_map_update) {
    Tagged<Map> target_map = SearchMigrationTarget(isolate, *map);
    if (!target_map.is_null()) {
      return handle(target_map, isolate);
    }
  }
  MapUpdater mu(isolate, map);
  return mu.Update();
}

void Map::EnsureDescriptorSlack(Isolate* isolate, DirectHandle<Map> map,
                                int slack) {
  // Only supports adding slack to owned descriptors.
  CHECK(map->owns_descriptors());

  DirectHandle<DescriptorArray> descriptors(map->instance_descriptors(isolate),
                                            isolate);
  int old_size = map->NumberOfOwnDescriptors();
  if (slack <= descriptors->number_of_slack_descriptors()) return;

  DirectHandle<DescriptorArray> new_descriptors =
      DescriptorArray::CopyUpTo(isolate, descriptors, old_size, slack);

  DisallowGarbageCollection no_gc;
  if (old_size == 0) {
    map->UpdateDescriptors(isolate, *new_descriptors,
                           map->NumberOfOwnDescriptors());
    return;
  }

  // If the source descriptors had an enum cache we copy it. This ensures
  // that the maps to which we push the new descriptor array back can rely
  // on a cache always being available once it is set. If the map has more
  // enumerated descriptors than available in the original cache, the cache
  // will be lazily replaced by the extended cache when needed.
  new_descriptors->CopyEnumCacheFrom(*descriptors);

  // Replace descriptors by new_descriptors in all maps that share it. The old
  // descriptors will not be trimmed in the mark-compactor, we need to mark
  // all its elements.
#ifndef V8_DISABLE_WRITE_BARRIERS
  WriteBarrier::ForDescriptorArray(*descriptors,
                                   descriptors->number_of_descriptors());
#endif

  // Update the descriptors from {map} (inclusive) until the initial map
  // (exclusive). In the case that {map} is the initial map, update it.
  map->UpdateDescriptors(isolate, *new_descriptors,
                         map->NumberOfOwnDescriptors());
  Tagged<Object> next = map->GetBackPointer();
  if (IsUndefined(next, isolate)) return;

  Tagged<Map> current = Cast<Map>(next);
  while (current->instance_descriptors(isolate) == *descriptors) {
    next = current->GetBackPointer();
    if (IsUndefined(next, isolate)) break;
    current->UpdateDescriptors(isolate, *new_descriptors,
                               current->NumberOfOwnDescriptors());
    current = Cast<Map>(next);
  }
}

// static
Handle<Map> Map::GetObjectCreateMap(Isolate* isolate,
                                    Handle<JSPrototype> prototype) {
  Handle<Map> map(isolate->native_context()->object_function()->initial_map(),
                  isolate);
  if (map->prototype() == *prototype) return map;
  if (IsNull(*prototype, isolate)) {
    return isolate->slow_object_with_null_prototype_map();
  }
  if (IsJSObjectThatCanBeTrackedAsPrototype(*prototype)) {
    DirectHandle<JSObject> js_prototype = Cast<JSObject>(prototype);
    if (!js_prototype->map()->is_prototype_map()) {
      JSObject::OptimizeAsPrototype(js_prototype);
    }
    DirectHandle<PrototypeInfo> info =
        Map::GetOrCreatePrototypeInfo(js_prototype, isolate);
    // TODO(verwaest): Use inobject slack tracking for this map.
    Tagged<HeapObject> map_obj;
    if (info->ObjectCreateMap().GetHeapObjectIfWeak(&map_obj)) {
      map = handle(Cast<Map>(map_obj), isolate);
    } else {
      map = Map::CopyInitialMap(isolate, map);
      Map::SetPrototype(isolate, map, prototype);
      PrototypeInfo::SetObjectCreateMap(info, map, isolate);
    }
    return map;
  }

  return Map::TransitionRootMapToPrototypeForNewObject(isolate, map, prototype);
}

// static
Handle<Map> Map::GetDerivedMap(Isolate* isolate, Handle<Map> from,
                               Handle<JSReceiver> prototype) {
  DCHECK(IsUndefined(from->GetBackPointer()));

  if (IsJSObjectThatCanBeTrackedAsPrototype(*prototype)) {
    DirectHandle<JSObject> js_prototype = Cast<JSObject>(prototype);
    if (!js_prototype->map()->is_prototype_map()) {
      JSObject::OptimizeAsPrototype(js_prototype);
    }
    DirectHandle<PrototypeInfo> info =
        Map::GetOrCreatePrototypeInfo(js_prototype, isolate);
    Tagged<HeapObject> map_obj;
    Handle<Map> map;
    if (info->GetDerivedMap(from).GetHeapObjectIfWeak(&map_obj)) {
      map = handle(Cast<Map>(map_obj), isolate);
    } else {
      map = Map::CopyInitialMap(isolate, from);
      map->set_new_target_is_base(false);
      if (map->prototype() != *prototype) {
        Map::SetPrototype(isolate, map, prototype);
      }
      PrototypeInf
"""


```
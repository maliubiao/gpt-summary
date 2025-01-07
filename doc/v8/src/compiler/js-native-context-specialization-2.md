Response: The user wants a summary of the C++ source code file `v8/src/compiler/js-native-context-specialization.cc`, specifically the third part of it. The summary should focus on its functionality and illustrate its connection to JavaScript with examples.

Here's a breakdown of the code's functionality in this section:

1. **Property Access (Load, Store, Has):**  The code defines functions (`BuildPropertyLoad`, `BuildPropertyStore`, `BuildPropertyTest`, `BuildPropertyAccess`) to generate low-level operations for accessing object properties. This includes handling different access modes (load, store, existence checks), prototype chain lookups, and optimizations based on property characteristics (e.g., data fields, accessors, constant values).

2. **Element Access (Load, Store, Has):** Similarly, it provides functions (`BuildElementAccess`, `BuildElementAccessForTypedArrayOrRabGsabTypedArray`) for accessing array elements (including TypedArrays). It manages bounds checks, handling of holes in sparse arrays, and optimizations specific to TypedArrays.

3. **String Indexing:** The `BuildIndexedStringLoad` function handles accessing characters within a string using an index.

4. **Extending Property Backing Stores:** `BuildExtendPropertiesBackingStore` deals with allocating more space for object properties when needed.

5. **Name Equality Check:** `BuildCheckEqualsName` creates operations to compare a value with a specific name (string or symbol).

6. **Hole Treatment:** `CanTreatHoleAsUndefined` determines if the JavaScript engine can treat "holes" (uninitialized elements in sparse arrays) as `undefined`.

7. **Map Inference:** `InferMaps` attempts to determine the possible "maps" (object layouts) of a given object, which is crucial for optimization.

8. **Prototype Loading:** `BuildLoadPrototypeFromObject` generates code to load the prototype of an object.

9. **Utility Functions:** There are helper functions like `ReleaseEffectAndControlFromAssembler` and accessors for various compiler components (`graph`, `isolate`, etc.).

Now, let's consider how these relate to JavaScript and how to illustrate it with examples.

*   **Property Access:**  JavaScript code like `object.property` or `object['property']` uses these functions to be translated into efficient machine code.
*   **Element Access:**  JavaScript code like `array[index]` or `typedArray[index]` relies on the element access functions.
*   **String Indexing:** `string[index]` utilizes `BuildIndexedStringLoad`.
*   **Property Backing Stores:** When you dynamically add properties to an object, the engine might need to extend its internal storage, which involves `BuildExtendPropertiesBackingStore`.
*   **Name Equality:**  Comparisons like `typeof x === 'symbol'` or checking for specific property names can involve `BuildCheckEqualsName`.
*   **Holes:**  In sparse arrays, accessing an uninitialized element returns `undefined`. The `CanTreatHoleAsUndefined` logic determines if this optimization is safe.
*   **Map Inference:** The V8 engine uses map inference extensively to understand the structure of objects and optimize property accesses.
*   **Prototypes:**  The prototype chain is fundamental to JavaScript inheritance. Accessing properties on an object involves potentially traversing its prototype chain, which uses `BuildLoadPrototypeFromObject`.
这是 `v8/src/compiler/js-native-context-specialization.cc` 文件的第三部分，延续了前两部分的功能，主要负责针对 JavaScript 原生上下文（native context）中的特定操作进行优化。它通过分析和推断类型信息，以及利用内建对象和函数的特性，生成更高效的机器码。

**总的来说，这部分代码的功能可以归纳为：**

**对属性和元素访问进行更深层次的优化，特别是针对数组和类型化数组的访问。** 它利用了关于对象形状（maps）、元素类型（elements kind）以及原型链的知识，来避免一些冗余的检查和转换，从而提升性能。

**具体功能点包括：**

1. **构建属性访问操作 (`BuildPropertyAccess`, `BuildPropertyLoad`, `BuildPropertyStore`, `BuildPropertyTest`)：**  这部分延续了之前构建属性访问操作的逻辑，但更加关注细节优化，例如：
    *   针对常量属性的内联设置器调用 (`InlinePropertySetterCall`)。
    *   针对不同数据类型（如浮点数、SMI、指针）的存储操作，包括类型检查和写屏障处理。
    *   处理属性的转换存储（transitioning store），即修改对象的形状。
    *   针对 `HasProperty` 操作的优化，直接返回布尔值。

2. **优化特定场景下的属性定义 (`ReduceJSDefineKeyedOwnPropertyInLiteral`) 和存储 (`ReduceJSStoreInArrayLiteral`)：**  针对字面量对象和数组的特定操作进行优化，例如在数组字面量中存储值。

3. **优化 `JSToObject` 操作 (`ReduceJSToObject`)：**  当确定接收者已经是 JS 对象时，可以避免不必要的转换。

4. **构建元素访问操作 (`BuildElementAccess`, `BuildElementAccessForTypedArrayOrRabGsabTypedArray`)：** 这是本部分代码的重点，针对数组元素的读取和写入进行精细化优化：
    *   根据元素的种类（`ElementsKind`，例如 `PACKED_SMI_ELEMENTS`, `HOLEY_ELEMENTS`, `FLOAT64_ELEMENTS` 等）进行不同的处理。
    *   处理类型化数组（`TypedArray`）和可调整大小的 ArrayBuffer (Resizable ArrayBuffer - RAB) / SharedArrayBuffer (GSAB) 的元素访问，利用其底层数据布局进行优化。
    *   插入边界检查 (`CheckBounds`)，确保访问索引在有效范围内。
    *   处理超出边界的访问，根据 `LoadMode` 或 `StoreMode` 决定是返回 `undefined` 还是忽略操作。
    *   处理稀疏数组中的空洞（holes），根据是否可以安全地将其视为 `undefined` 来进行优化。
    *   对于类型化数组，会检查 ArrayBuffer 是否已分离 (detached)。
    *   在存储时，会进行类型检查和可能的截断操作，例如将数字转换为 `Uint8ClampedArray` 的值。
    *   处理需要扩展数组存储空间的情况 (`MaybeGrowFastElements`)。

5. **构建字符串索引访问 (`BuildIndexedStringLoad`)：** 优化通过索引访问字符串字符的操作。

6. **扩展属性的后备存储 (`BuildExtendPropertiesBackingStore`)：** 当需要为对象添加更多属性时，会扩展其内部存储空间。

7. **构建名称相等性检查 (`BuildCheckEqualsName`)：** 生成比较值是否等于特定名称（字符串或符号）的代码。

8. **判断是否可以将空洞视为 `undefined` (`CanTreatHoleAsUndefined`)：**  用于优化稀疏数组的访问。

9. **推断 Map (`InferMaps`) 和根 Map (`InferRootMap`)：**  尝试推断对象的形状信息，用于后续的优化。

10. **加载对象的原型 (`BuildLoadPrototypeFromObject`)：**  生成加载对象原型的代码。

11. **释放汇编器的效果和控制流 (`ReleaseEffectAndControlFromAssembler`)：**  用于管理代码生成过程中的效果和控制流信息。

**与 JavaScript 的关系及示例：**

这部分代码直接影响着 JavaScript 代码的执行效率。以下是一些 JavaScript 示例，展示了这部分 C++ 代码可能对其进行的优化：

**示例 1: 数组元素访问**

```javascript
const arr = [1, 2, 3];
const firstElement = arr[0]; // BuildElementAccess 将优化此操作
arr[1] = 4;                 // BuildElementAccess 将优化此操作
```

`BuildElementAccess` 会根据 `arr` 的元素种类（在这个例子中可能是 `PACKED_SMI_ELEMENTS`）生成高效的机器码，避免不必要的类型转换或原型链查找。

**示例 2: 类型化数组访问**

```javascript
const typedArray = new Uint32Array([10, 20, 30]);
const firstValue = typedArray[0]; // BuildElementAccessForTypedArrayOrRabGsabTypedArray 将优化
typedArray[1] = 40;             // BuildElementAccessForTypedArrayOrRabGsabTypedArray 将优化
```

`BuildElementAccessForTypedArrayOrRabGsabTypedArray` 会利用类型化数组的连续内存布局和已知的元素类型（`uint32`）来生成非常高效的加载和存储指令。它还会避免对原型链的查找。

**示例 3: 字符串索引**

```javascript
const str = "hello";
const firstChar = str[0]; // BuildIndexedStringLoad 将优化此操作
```

`BuildIndexedStringLoad` 可以直接从字符串的内部表示中提取字符，而无需将其视为普通的属性访问。

**示例 4: 对象属性访问**

```javascript
const obj = { x: 5 };
const value = obj.x;  // BuildPropertyLoad 将优化此操作
obj.y = 10;          // BuildPropertyStore 将优化此操作
```

`BuildPropertyLoad` 和 `BuildPropertyStore` 会利用 `obj` 的 Map 信息，直接访问存储 `x` 和 `y` 值的内存位置，而无需进行字符串查找。

**示例 5: 稀疏数组**

```javascript
const sparseArray = new Array(10);
sparseArray[0] = 1;
const element = sparseArray[5]; // CanTreatHoleAsUndefined 可能影响此处的优化
```

如果 V8 确定可以安全地将空洞视为 `undefined`，那么在访问 `sparseArray[5]` 时，它可以直接返回 `undefined`，而无需进行复杂的查找。

**总结：**

这部分代码是 V8 引擎中非常核心的部分，它专注于提升 JavaScript 代码在特定场景下的执行效率，尤其是针对常见的属性和元素访问模式。通过深入了解对象的结构和类型信息，它可以生成高度优化的机器码，从而显著提高 JavaScript 应用程序的性能。

Prompt: 
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 Node* control, PropertyAccessInfo const& access_info) {
  // TODO(v8:11457) Support property tests for dictionary mode protoypes.
  DCHECK(!access_info.HasDictionaryHolder());

  // Determine actual holder and perform prototype chain checks.
  OptionalJSObjectRef holder = access_info.holder();
  if (holder.has_value()) {
    dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        holder.value());
  }

  return ValueEffectControl(
      jsgraph()->BooleanConstant(!access_info.IsNotFound()), effect, control);
}

std::optional<JSNativeContextSpecialization::ValueEffectControl>
JSNativeContextSpecialization::BuildPropertyAccess(
    Node* lookup_start_object, Node* receiver, Node* value, Node* context,
    Node* frame_state, Node* effect, Node* control, NameRef name,
    ZoneVector<Node*>* if_exceptions, PropertyAccessInfo const& access_info,
    AccessMode access_mode) {
  switch (access_mode) {
    case AccessMode::kLoad:
      return BuildPropertyLoad(lookup_start_object, receiver, context,
                               frame_state, effect, control, name,
                               if_exceptions, access_info);
    case AccessMode::kStore:
    case AccessMode::kStoreInLiteral:
    case AccessMode::kDefine:
      DCHECK_EQ(receiver, lookup_start_object);
      return BuildPropertyStore(receiver, value, context, frame_state, effect,
                                control, name, if_exceptions, access_info,
                                access_mode);
    case AccessMode::kHas:
      DCHECK_EQ(receiver, lookup_start_object);
      return BuildPropertyTest(effect, control, access_info);
  }
  UNREACHABLE();
}

JSNativeContextSpecialization::ValueEffectControl
JSNativeContextSpecialization::BuildPropertyStore(
    Node* receiver, Node* value, Node* context, Node* frame_state, Node* effect,
    Node* control, NameRef name, ZoneVector<Node*>* if_exceptions,
    PropertyAccessInfo const& access_info, AccessMode access_mode) {
  // Determine actual holder and perform prototype chain checks.
  PropertyAccessBuilder access_builder(jsgraph(), broker());
  OptionalJSObjectRef holder = access_info.holder();
  if (holder.has_value()) {
    DCHECK_NE(AccessMode::kStoreInLiteral, access_mode);
    DCHECK_NE(AccessMode::kDefine, access_mode);
    dependencies()->DependOnStablePrototypeChains(
        access_info.lookup_start_object_maps(), kStartAtPrototype,
        holder.value());
  }

  DCHECK(!access_info.IsNotFound());

  // Generate the actual property access.
  if (access_info.IsFastAccessorConstant()) {
    InlinePropertySetterCall(receiver, value, context, frame_state, &effect,
                             &control, if_exceptions, access_info);
  } else {
    DCHECK(access_info.IsDataField() || access_info.IsFastDataConstant());
    DCHECK(access_mode == AccessMode::kStore ||
           access_mode == AccessMode::kStoreInLiteral ||
           access_mode == AccessMode::kDefine);
    FieldIndex const field_index = access_info.field_index();
    Type const field_type = access_info.field_type();
    MachineRepresentation const field_representation =
        PropertyAccessBuilder::ConvertRepresentation(
            access_info.field_representation());
    Node* storage = receiver;
    if (!field_index.is_inobject()) {
      storage = effect = graph()->NewNode(
          simplified()->LoadField(
              AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer()),
          storage, effect, control);
    }
    if (access_info.IsFastDataConstant() && access_mode == AccessMode::kStore &&
        !access_info.HasTransitionMap()) {
      Node* deoptimize = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kStoreToConstant),
          jsgraph()->FalseConstant(), effect, control);
      return ValueEffectControl(jsgraph()->UndefinedConstant(), deoptimize,
                                control);
    }
    FieldAccess field_access = {
        kTaggedBase,
        field_index.offset(),
        name.object(),
        OptionalMapRef(),
        field_type,
        MachineType::TypeForRepresentation(field_representation),
        kFullWriteBarrier,
        "BuildPropertyStore",
        access_info.GetConstFieldInfo(),
        access_mode == AccessMode::kStoreInLiteral};

    switch (field_representation) {
      case MachineRepresentation::kFloat64: {
        value = effect =
            graph()->NewNode(simplified()->CheckNumber(FeedbackSource()), value,
                             effect, control);
        if (access_info.HasTransitionMap()) {
          // Allocate a HeapNumber for the new property.
          AllocationBuilder a(jsgraph(), broker(), effect, control);
          a.Allocate(sizeof(HeapNumber), AllocationType::kYoung,
                     Type::OtherInternal());
          a.Store(AccessBuilder::ForMap(), broker()->heap_number_map());
          FieldAccess value_field_access = AccessBuilder::ForHeapNumberValue();
          value_field_access.const_field_info = field_access.const_field_info;
          a.Store(value_field_access, value);
          value = effect = a.Finish();

          field_access.type = Type::Any();
          field_access.machine_type = MachineType::TaggedPointer();
          field_access.write_barrier_kind = kPointerWriteBarrier;
        } else {
          // We just store directly to the HeapNumber.
          FieldAccess const storage_access = {
              kTaggedBase,
              field_index.offset(),
              name.object(),
              OptionalMapRef(),
              Type::OtherInternal(),
              MachineType::TaggedPointer(),
              kPointerWriteBarrier,
              "BuildPropertyStore",
              access_info.GetConstFieldInfo(),
              access_mode == AccessMode::kStoreInLiteral};
          storage = effect =
              graph()->NewNode(simplified()->LoadField(storage_access), storage,
                               effect, control);
          FieldAccess value_field_access = AccessBuilder::ForHeapNumberValue();
          value_field_access.const_field_info = field_access.const_field_info;
          value_field_access.is_store_in_literal =
              field_access.is_store_in_literal;
          field_access = value_field_access;
        }
        break;
      }
      case MachineRepresentation::kTaggedSigned:
      case MachineRepresentation::kTaggedPointer:
      case MachineRepresentation::kTagged:
        if (field_representation == MachineRepresentation::kTaggedSigned) {
          value = effect = graph()->NewNode(
              simplified()->CheckSmi(FeedbackSource()), value, effect, control);
          field_access.write_barrier_kind = kNoWriteBarrier;

        } else if (field_representation ==
                   MachineRepresentation::kTaggedPointer) {
          OptionalMapRef field_map = access_info.field_map();
          if (field_map.has_value()) {
            // Emit a map check for the value.
            effect = graph()->NewNode(
                simplified()->CheckMaps(CheckMapsFlag::kNone,
                                        ZoneRefSet<Map>(*field_map)),
                value, effect, control);
          } else {
            // Ensure that {value} is a HeapObject.
            value = effect = graph()->NewNode(simplified()->CheckHeapObject(),
                                              value, effect, control);
          }
          field_access.write_barrier_kind = kPointerWriteBarrier;

        } else {
          DCHECK(field_representation == MachineRepresentation::kTagged);
        }
        break;
      case MachineRepresentation::kNone:
      case MachineRepresentation::kBit:
      case MachineRepresentation::kCompressedPointer:
      case MachineRepresentation::kCompressed:
      case MachineRepresentation::kProtectedPointer:
      case MachineRepresentation::kIndirectPointer:
      case MachineRepresentation::kSandboxedPointer:
      case MachineRepresentation::kWord8:
      case MachineRepresentation::kWord16:
      case MachineRepresentation::kWord32:
      case MachineRepresentation::kWord64:
      case MachineRepresentation::kFloat16:
      case MachineRepresentation::kFloat32:
      case MachineRepresentation::kSimd128:
      case MachineRepresentation::kSimd256:
      case MachineRepresentation::kMapWord:
        UNREACHABLE();
    }
    // Check if we need to perform a transitioning store.
    OptionalMapRef transition_map = access_info.transition_map();
    if (transition_map.has_value()) {
      // Check if we need to grow the properties backing store
      // with this transitioning store.
      MapRef transition_map_ref = transition_map.value();
      MapRef original_map = transition_map_ref.GetBackPointer(broker()).AsMap();
      if (!field_index.is_inobject()) {
        // If slack tracking ends after this compilation started but before it's
        // finished, then we could {original_map} could be out-of-sync with
        // {transition_map_ref}. In particular, its UnusedPropertyFields could
        // be non-zero, which would lead us to not extend the property backing
        // store, while the underlying Map has actually zero
        // UnusedPropertyFields. Thus, we install a dependency on {orininal_map}
        // now, so that if such a situation happens, we'll throw away the code.
        dependencies()->DependOnNoSlackTrackingChange(original_map);
      }
      if (original_map.UnusedPropertyFields() == 0) {
        DCHECK(!field_index.is_inobject());

        // Reallocate the properties {storage}.
        storage = effect = BuildExtendPropertiesBackingStore(
            original_map, storage, effect, control);

        // Perform the actual store.
        effect = graph()->NewNode(simplified()->StoreField(field_access),
                                  storage, value, effect, control);

        // Atomically switch to the new properties below.
        field_access = AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer();
        value = storage;
        storage = receiver;
      }
      effect = graph()->NewNode(
          common()->BeginRegion(RegionObservability::kObservable), effect);
      effect = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForMap()), receiver,
          jsgraph()->ConstantNoHole(transition_map_ref, broker()), effect,
          control);
      effect = graph()->NewNode(simplified()->StoreField(field_access), storage,
                                value, effect, control);
      effect = graph()->NewNode(common()->FinishRegion(),
                                jsgraph()->UndefinedConstant(), effect);
    } else {
      // Regular non-transitioning field store.
      effect = graph()->NewNode(simplified()->StoreField(field_access), storage,
                                value, effect, control);
    }
  }

  return ValueEffectControl(value, effect, control);
}

Reduction
JSNativeContextSpecialization::ReduceJSDefineKeyedOwnPropertyInLiteral(
    Node* node) {
  JSDefineKeyedOwnPropertyInLiteralNode n(node);
  FeedbackParameter const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();

  NumberMatcher mflags(n.flags());
  CHECK(mflags.HasResolvedValue());
  DefineKeyedOwnPropertyInLiteralFlags cflags(mflags.ResolvedValue());
  if (cflags & DefineKeyedOwnPropertyInLiteralFlag::kSetFunctionName)
    return NoChange();

  return ReducePropertyAccess(node, n.name(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kStoreInLiteral);
}

Reduction JSNativeContextSpecialization::ReduceJSStoreInArrayLiteral(
    Node* node) {
  JSStoreInArrayLiteralNode n(node);
  FeedbackParameter const& p = n.Parameters();
  if (!p.feedback().IsValid()) return NoChange();
  return ReducePropertyAccess(node, n.index(), std::nullopt, n.value(),
                              FeedbackSource(p.feedback()),
                              AccessMode::kStoreInLiteral);
}

Reduction JSNativeContextSpecialization::ReduceJSToObject(Node* node) {
  DCHECK_EQ(IrOpcode::kJSToObject, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 0);
  Effect effect{NodeProperties::GetEffectInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  ReplaceWithValue(node, receiver, effect);
  return Replace(receiver);
}

JSNativeContextSpecialization::ValueEffectControl
JSNativeContextSpecialization::BuildElementAccess(
    Node* receiver, Node* index, Node* value, Node* effect, Node* control,
    Node* context, ElementAccessInfo const& access_info,
    KeyedAccessMode const& keyed_mode) {
  // TODO(bmeurer): We currently specialize based on elements kind. We should
  // also be able to properly support strings and other JSObjects here.
  ElementsKind elements_kind = access_info.elements_kind();
  ZoneVector<MapRef> const& receiver_maps =
      access_info.lookup_start_object_maps();

  if (IsTypedArrayElementsKind(elements_kind) ||
      IsRabGsabTypedArrayElementsKind(elements_kind)) {
    return BuildElementAccessForTypedArrayOrRabGsabTypedArray(
        receiver, index, value, effect, control, context, elements_kind,
        keyed_mode);
  }

  // Load the elements for the {receiver}.
  Node* elements = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSObjectElements()), receiver,
      effect, control);

  // Don't try to store to a copy-on-write backing store (unless supported by
  // the store mode).
  if (IsAnyStore(keyed_mode.access_mode()) &&
      IsSmiOrObjectElementsKind(elements_kind) &&
      !StoreModeHandlesCOW(keyed_mode.store_mode())) {
    effect = graph()->NewNode(
        simplified()->CheckMaps(CheckMapsFlag::kNone,
                                ZoneRefSet<Map>(broker()->fixed_array_map())),
        elements, effect, control);
  }

  // Check if the {receiver} is a JSArray.
  bool receiver_is_jsarray = HasOnlyJSArrayMaps(broker(), receiver_maps);

  // Load the length of the {receiver}.
  Node* length = effect =
      receiver_is_jsarray
          ? graph()->NewNode(
                simplified()->LoadField(
                    AccessBuilder::ForJSArrayLength(elements_kind)),
                receiver, effect, control)
          : graph()->NewNode(
                simplified()->LoadField(AccessBuilder::ForFixedArrayLength()),
                elements, effect, control);

  // Check if we might need to grow the {elements} backing store.
  if (keyed_mode.IsStore() && StoreModeCanGrow(keyed_mode.store_mode())) {
    // For growing stores we validate the {index} below.
  } else if (keyed_mode.IsLoad() &&
             LoadModeHandlesOOB(keyed_mode.load_mode()) &&
             CanTreatHoleAsUndefined(receiver_maps)) {
    // Check that the {index} is a valid array index, we do the actual
    // bounds check below and just skip the store below if it's out of
    // bounds for the {receiver}.
    index = effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource(),
                                  CheckBoundsFlag::kConvertStringAndMinusZero),
        index, jsgraph()->ConstantNoHole(Smi::kMaxValue), effect, control);
  } else {
    // Check that the {index} is in the valid range for the {receiver}.
    index = effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource(),
                                  CheckBoundsFlag::kConvertStringAndMinusZero),
        index, length, effect, control);
  }

  // Compute the element access.
  Type element_type = Type::NonInternal();
  MachineType element_machine_type = MachineType::AnyTagged();
  if (IsDoubleElementsKind(elements_kind)) {
    element_type = Type::Number();
    element_machine_type = MachineType::Float64();
  } else if (IsSmiElementsKind(elements_kind)) {
    element_type = Type::SignedSmall();
    element_machine_type = MachineType::TaggedSigned();
  }
  ElementAccess element_access = {kTaggedBase, OFFSET_OF_DATA_START(FixedArray),
                                  element_type, element_machine_type,
                                  kFullWriteBarrier};

  // Access the actual element.
  if (keyed_mode.access_mode() == AccessMode::kLoad) {
    // Compute the real element access type, which includes the hole in case
    // of holey backing stores.
    if (IsHoleyElementsKind(elements_kind)) {
      element_access.type =
          Type::Union(element_type, Type::Hole(), graph()->zone());
    }
    if (elements_kind == HOLEY_ELEMENTS ||
        elements_kind == HOLEY_SMI_ELEMENTS) {
      element_access.machine_type = MachineType::AnyTagged();
    }

    // Check if we can return undefined for out-of-bounds loads.
    if (LoadModeHandlesOOB(keyed_mode.load_mode()) &&
        CanTreatHoleAsUndefined(receiver_maps)) {
      Node* check =
          graph()->NewNode(simplified()->NumberLessThan(), index, length);
      Node* branch =
          graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

      Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
      Node* etrue = effect;
      Node* vtrue;
      {
        // Do a real bounds check against {length}. This is in order to
        // protect against a potential typer bug leading to the elimination of
        // the NumberLessThan above.
        if (v8_flags.turbo_typer_hardening) {
          index = etrue =
              graph()->NewNode(simplified()->CheckBounds(
                                   FeedbackSource(),
                                   CheckBoundsFlag::kConvertStringAndMinusZero |
                                       CheckBoundsFlag::kAbortOnOutOfBounds),
                               index, length, etrue, if_true);
        }

        // Perform the actual load
        vtrue = etrue =
            graph()->NewNode(simplified()->LoadElement(element_access),
                             elements, index, etrue, if_true);

        // Handle loading from holey backing stores correctly by mapping
        // the hole to undefined.
        if (elements_kind == HOLEY_ELEMENTS ||
            elements_kind == HOLEY_SMI_ELEMENTS) {
          // Turn the hole into undefined.
          vtrue = graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(),
                                   vtrue);
        } else if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
          // Return the signaling NaN hole directly if all uses are
          // truncating.
          if (LoadModeHandlesHoles(keyed_mode.load_mode())) {
            vtrue = graph()->NewNode(simplified()->ChangeFloat64HoleToTagged(),
                                     vtrue);
          } else {
            vtrue = etrue = graph()->NewNode(
                simplified()->CheckFloat64Hole(
                    CheckFloat64HoleMode::kAllowReturnHole, FeedbackSource()),
                vtrue, etrue, if_true);
          }
        }
      }

      Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
      Node* efalse = effect;
      Node* vfalse;
      {
        // Materialize undefined for out-of-bounds loads.
        vfalse = jsgraph()->UndefinedConstant();
      }

      control = graph()->NewNode(common()->Merge(2), if_true, if_false);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               vtrue, vfalse, control);
    } else {
      // Perform the actual load.
      value = effect =
          graph()->NewNode(simplified()->LoadElement(element_access), elements,
                           index, effect, control);

      // Handle loading from holey backing stores correctly, by either mapping
      // the hole to undefined if possible, or deoptimizing otherwise.
      if (elements_kind == HOLEY_ELEMENTS ||
          elements_kind == HOLEY_SMI_ELEMENTS) {
        // Check if we are allowed to turn the hole into undefined.
        if (CanTreatHoleAsUndefined(receiver_maps)) {
          // Turn the hole into undefined.
          value = graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(),
                                   value);
        } else {
          // Bailout if we see the hole.
          value = effect = graph()->NewNode(simplified()->CheckNotTaggedHole(),
                                            value, effect, control);
        }
      } else if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
        // Perform the hole check on the result.
        // Check if we are allowed to return the hole directly.
        if (CanTreatHoleAsUndefined(receiver_maps)) {
          if (LoadModeHandlesHoles(keyed_mode.load_mode())) {
            // Return the signaling NaN hole directly if all uses are
            // truncating.
            value = graph()->NewNode(simplified()->ChangeFloat64HoleToTagged(),
                                     value);
          } else {
            value = effect = graph()->NewNode(
                simplified()->CheckFloat64Hole(
                    CheckFloat64HoleMode::kAllowReturnHole, FeedbackSource()),
                value, effect, control);
          }
        } else {
          value = effect = graph()->NewNode(
              simplified()->CheckFloat64Hole(
                  CheckFloat64HoleMode::kNeverReturnHole, FeedbackSource()),
              value, effect, control);
        }
      }
    }
  } else if (keyed_mode.access_mode() == AccessMode::kHas) {
    // For packed arrays with NoElementsProctector valid, a bound check
    // is equivalent to HasProperty.
    value = effect = graph()->NewNode(simplified()->SpeculativeNumberLessThan(
                                          NumberOperationHint::kSignedSmall),
                                      index, length, effect, control);
    if (IsHoleyElementsKind(elements_kind)) {
      // If the index is in bounds, do a load and hole check.

      Node* branch = graph()->NewNode(common()->Branch(), value, control);

      Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
      Node* efalse = effect;
      Node* vfalse = jsgraph()->FalseConstant();

      element_access.type =
          Type::Union(element_type, Type::Hole(), graph()->zone());

      if (elements_kind == HOLEY_ELEMENTS ||
          elements_kind == HOLEY_SMI_ELEMENTS) {
        element_access.machine_type = MachineType::AnyTagged();
      }

      Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
      Node* etrue = effect;

      Node* checked = etrue = graph()->NewNode(
          simplified()->CheckBounds(
              FeedbackSource(), CheckBoundsFlag::kConvertStringAndMinusZero),
          index, length, etrue, if_true);

      Node* element = etrue =
          graph()->NewNode(simplified()->LoadElement(element_access), elements,
                           checked, etrue, if_true);

      Node* vtrue;
      if (CanTreatHoleAsUndefined(receiver_maps)) {
        if (elements_kind == HOLEY_ELEMENTS ||
            elements_kind == HOLEY_SMI_ELEMENTS) {
          // Check if we are allowed to turn the hole into undefined.
          // Turn the hole into undefined.
          vtrue = graph()->NewNode(simplified()->ReferenceEqual(), element,
                                   jsgraph()->TheHoleConstant());
        } else {
          vtrue =
              graph()->NewNode(simplified()->NumberIsFloat64Hole(), element);
        }

        // has == !IsHole
        vtrue = graph()->NewNode(simplified()->BooleanNot(), vtrue);
      } else {
        if (elements_kind == HOLEY_ELEMENTS ||
            elements_kind == HOLEY_SMI_ELEMENTS) {
          // Bailout if we see the hole.
          etrue = graph()->NewNode(simplified()->CheckNotTaggedHole(), element,
                                   etrue, if_true);
        } else {
          etrue = graph()->NewNode(
              simplified()->CheckFloat64Hole(
                  CheckFloat64HoleMode::kNeverReturnHole, FeedbackSource()),
              element, etrue, if_true);
        }

        vtrue = jsgraph()->TrueConstant();
      }

      control = graph()->NewNode(common()->Merge(2), if_true, if_false);
      effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                               vtrue, vfalse, control);
    }
  } else {
    DCHECK(keyed_mode.access_mode() == AccessMode::kStore ||
           keyed_mode.access_mode() == AccessMode::kStoreInLiteral ||
           keyed_mode.access_mode() == AccessMode::kDefine);

    if (IsSmiElementsKind(elements_kind)) {
      value = effect = graph()->NewNode(
          simplified()->CheckSmi(FeedbackSource()), value, effect, control);
    } else if (IsDoubleElementsKind(elements_kind)) {
      value = effect = graph()->NewNode(
          simplified()->CheckNumber(FeedbackSource()), value, effect, control);
      // Make sure we do not store signalling NaNs into double arrays.
      value = graph()->NewNode(simplified()->NumberSilenceNaN(), value);
    }

    // Ensure that copy-on-write backing store is writable.
    if (IsSmiOrObjectElementsKind(elements_kind) &&
        keyed_mode.store_mode() == KeyedAccessStoreMode::kHandleCOW) {
      elements = effect =
          graph()->NewNode(simplified()->EnsureWritableFastElements(), receiver,
                           elements, effect, control);
    } else if (StoreModeCanGrow(keyed_mode.store_mode())) {
      // Determine the length of the {elements} backing store.
      Node* elements_length = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForFixedArrayLength()),
          elements, effect, control);

      // Validate the {index} depending on holeyness:
      //
      // For HOLEY_*_ELEMENTS the {index} must not exceed the {elements}
      // backing store capacity plus the maximum allowed gap, as otherwise
      // the (potential) backing store growth would normalize and thus
      // the elements kind of the {receiver} would change to slow mode.
      //
      // For JSArray PACKED_*_ELEMENTS the {index} must be within the range
      // [0,length+1[ to be valid. In case {index} equals {length},
      // the {receiver} will be extended, but kept packed.
      //
      // Non-JSArray PACKED_*_ELEMENTS always grow by adding holes because they
      // lack the magical length property, which requires a map transition.
      // So we can assume that this did not happen if we did not see this map.
      Node* limit =
          IsHoleyElementsKind(elements_kind)
              ? graph()->NewNode(simplified()->NumberAdd(), elements_length,
                                 jsgraph()->ConstantNoHole(JSObject::kMaxGap))
          : receiver_is_jsarray
              ? graph()->NewNode(simplified()->NumberAdd(), length,
                                 jsgraph()->OneConstant())
              : elements_length;
      index = effect = graph()->NewNode(
          simplified()->CheckBounds(
              FeedbackSource(), CheckBoundsFlag::kConvertStringAndMinusZero),
          index, limit, effect, control);

      // Grow {elements} backing store if necessary.
      GrowFastElementsMode mode =
          IsDoubleElementsKind(elements_kind)
              ? GrowFastElementsMode::kDoubleElements
              : GrowFastElementsMode::kSmiOrObjectElements;
      elements = effect = graph()->NewNode(
          simplified()->MaybeGrowFastElements(mode, FeedbackSource()), receiver,
          elements, index, elements_length, effect, control);

      // If we didn't grow {elements}, it might still be COW, in which case we
      // copy it now.
      if (IsSmiOrObjectElementsKind(elements_kind) &&
          keyed_mode.store_mode() == KeyedAccessStoreMode::kGrowAndHandleCOW) {
        elements = effect =
            graph()->NewNode(simplified()->EnsureWritableFastElements(),
                             receiver, elements, effect, control);
      }

      // Also update the "length" property if {receiver} is a JSArray.
      if (receiver_is_jsarray) {
        Node* check =
            graph()->NewNode(simplified()->NumberLessThan(), index, length);
        Node* branch = graph()->NewNode(common()->Branch(), check, control);

        Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
        Node* etrue = effect;
        {
          // We don't need to do anything, the {index} is within
          // the valid bounds for the JSArray {receiver}.
        }

        Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
        Node* efalse = effect;
        {
          // Update the JSArray::length field. Since this is observable,
          // there must be no other check after this.
          Node* new_length = graph()->NewNode(simplified()->NumberAdd(), index,
                                              jsgraph()->OneConstant());
          efalse = graph()->NewNode(
              simplified()->StoreField(
                  AccessBuilder::ForJSArrayLength(elements_kind)),
              receiver, new_length, efalse, if_false);
        }

        control = graph()->NewNode(common()->Merge(2), if_true, if_false);
        effect =
            graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      }
    }

    // Perform the actual element access.
    effect = graph()->NewNode(simplified()->StoreElement(element_access),
                              elements, index, value, effect, control);
  }

  return ValueEffectControl(value, effect, control);
}

JSNativeContextSpecialization::ValueEffectControl
JSNativeContextSpecialization::
    BuildElementAccessForTypedArrayOrRabGsabTypedArray(
        Node* receiver, Node* index, Node* value, Node* effect, Node* control,
        Node* context, ElementsKind elements_kind,
        KeyedAccessMode const& keyed_mode) {
  DCHECK(IsTypedArrayElementsKind(elements_kind) ||
         IsRabGsabTypedArrayElementsKind(elements_kind));
  // AccessMode::kDefine is not handled here. Optimization should be skipped by
  // caller.
  DCHECK(keyed_mode.access_mode() != AccessMode::kDefine);

  Node* buffer_or_receiver = receiver;
  Node* length;
  Node* base_pointer;
  Node* external_pointer;

  // Check if we can constant-fold information about the {receiver} (e.g.
  // for asm.js-like code patterns).
  OptionalJSTypedArrayRef typed_array =
      GetTypedArrayConstant(broker(), receiver);
  if (typed_array.has_value() &&
      // TODO(v8:11111): Add support for rab/gsab here.
      !IsRabGsabTypedArrayElementsKind(elements_kind)) {
    if (typed_array->map(broker()).elements_kind() != elements_kind) {
      // This case should never be reachable at runtime.
      JSGraphAssembler assembler(broker(), jsgraph_, zone(),
                                 BranchSemantics::kJS,
                                 [this](Node* n) { this->Revisit(n); });
      assembler.InitializeEffectControl(effect, control);
      assembler.Unreachable();
      ReleaseEffectAndControlFromAssembler(&assembler);
      Node* dead = jsgraph_->Dead();
      return ValueEffectControl{dead, dead, dead};
    } else {
      length =
          jsgraph()->ConstantNoHole(static_cast<double>(typed_array->length()));

      DCHECK(!typed_array->is_on_heap());
      // Load the (known) data pointer for the {receiver} and set
      // {base_pointer} and {external_pointer} to the values that will allow
      // to generate typed element accesses using the known data pointer. The
      // data pointer might be invalid if the {buffer} was detached, so we
      // need to make sure that any access is properly guarded.
      base_pointer = jsgraph()->ZeroConstant();
      external_pointer = jsgraph()->PointerConstant(typed_array->data_ptr());
    }
  } else {
    // Load the {receiver}s length.
    JSGraphAssembler assembler(broker(), jsgraph_, zone(), BranchSemantics::kJS,
                               [this](Node* n) { this->Revisit(n); });
    assembler.InitializeEffectControl(effect, control);
    length = assembler.TypedArrayLength(
        TNode<JSTypedArray>::UncheckedCast(receiver), {elements_kind},
        TNode<Context>::UncheckedCast(context));
    std::tie(effect, control) =
        ReleaseEffectAndControlFromAssembler(&assembler);

    // Load the base pointer for the {receiver}. This will always be Smi
    // zero unless we allow on-heap TypedArrays, which is only the case
    // for Chrome. Node and Electron both set this limit to 0. Setting
    // the base to Smi zero here allows the EffectControlLinearizer to
    // optimize away the tricky part of the access later.
    if (JSTypedArray::kMaxSizeInHeap == 0) {
      base_pointer = jsgraph()->ZeroConstant();
    } else {
      base_pointer = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSTypedArrayBasePointer()),
          receiver, effect, control);
    }

    // Load the external pointer for the {receiver}.
    external_pointer = effect =
        graph()->NewNode(simplified()->LoadField(
                             AccessBuilder::ForJSTypedArrayExternalPointer()),
                         receiver, effect, control);
  }

  // See if we can skip the detaching check.
  if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
    // Load the buffer for the {receiver}.
    Node* buffer =
        typed_array.has_value()
            ? jsgraph()->ConstantNoHole(typed_array->buffer(broker()), broker())
            : (effect = graph()->NewNode(
                   simplified()->LoadField(
                       AccessBuilder::ForJSArrayBufferViewBuffer()),
                   receiver, effect, control));

    // Deopt if the {buffer} was detached.
    // Note: A detached buffer leads to megamorphic feedback.
    Node* buffer_bit_field = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayBufferBitField()),
        buffer, effect, control);
    Node* check = graph()->NewNode(
        simplified()->NumberEqual(),
        graph()->NewNode(
            simplified()->NumberBitwiseAnd(), buffer_bit_field,
            jsgraph()->ConstantNoHole(JSArrayBuffer::WasDetachedBit::kMask)),
        jsgraph()->ZeroConstant());
    effect = graph()->NewNode(
        simplified()->CheckIf(DeoptimizeReason::kArrayBufferWasDetached), check,
        effect, control);

    // Retain the {buffer} instead of {receiver} to reduce live ranges.
    buffer_or_receiver = buffer;
  }

  enum Situation { kBoundsCheckDone, kHandleOOB_SmiAndRangeCheckComputed };
  Situation situation;
  TNode<BoolT> check;
  if ((keyed_mode.IsLoad() && LoadModeHandlesOOB(keyed_mode.load_mode())) ||
      (keyed_mode.IsStore() &&
       StoreModeIgnoresTypeArrayOOB(keyed_mode.store_mode()))) {
    // Only check that the {index} is in SignedSmall range. We do the actual
    // bounds check below and just skip the property access if it's out of
    // bounds for the {receiver}.
    index = effect = graph()->NewNode(simplified()->CheckSmi(FeedbackSource()),
                                      index, effect, control);
    TNode<Boolean> compare_length = TNode<Boolean>::UncheckedCast(
        graph()->NewNode(simplified()->NumberLessThan(), index, length));

    JSGraphAssembler assembler(broker(), jsgraph_, zone(), BranchSemantics::kJS,
                               [this](Node* n) { this->Revisit(n); });
    assembler.InitializeEffectControl(effect, control);
    TNode<BoolT> check_less_than_length =
        assembler.EnterMachineGraph<BoolT>(compare_length, UseInfo::Bool());
    TNode<Int32T> index_int32 = assembler.EnterMachineGraph<Int32T>(
        TNode<Smi>::UncheckedCast(index), UseInfo::TruncatingWord32());
    TNode<BoolT> check_non_negative =
        assembler.Int32LessThanOrEqual(assembler.Int32Constant(0), index_int32);
    check = TNode<BoolT>::UncheckedCast(
        assembler.Word32And(check_less_than_length, check_non_negative));
    std::tie(effect, control) =
        ReleaseEffectAndControlFromAssembler(&assembler);

    situation = kHandleOOB_SmiAndRangeCheckComputed;
  } else {
    // Check that the {index} is in the valid range for the {receiver}.
    index = effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource(),
                                  CheckBoundsFlag::kConvertStringAndMinusZero),
        index, length, effect, control);
    situation = kBoundsCheckDone;
  }

  // Access the actual element.
  ExternalArrayType external_array_type =
      GetArrayTypeFromElementsKind(elements_kind);
  DCHECK_NE(external_array_type, ExternalArrayType::kExternalFloat16Array);
  switch (keyed_mode.access_mode()) {
    case AccessMode::kLoad: {
      // Check if we can return undefined for out-of-bounds loads.
      if (situation == kHandleOOB_SmiAndRangeCheckComputed) {
        DCHECK_NE(check, nullptr);
        Node* branch = graph()->NewNode(
            common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine),
            check, control);

        Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
        Node* etrue = effect;
        Node* vtrue;
        {
          // Do a real bounds check against {length}. This is in order to
          // protect against a potential typer bug leading to the elimination
          // of the NumberLessThan above.
          if (v8_flags.turbo_typer_hardening) {
            index = etrue = graph()->NewNode(
                simplified()->CheckBounds(
                    FeedbackSource(),
                    CheckBoundsFlag::kConvertStringAndMinusZero |
                        CheckBoundsFlag::kAbortOnOutOfBounds),
                index, length, etrue, if_true);
          }

          // Perform the actual load
          vtrue = etrue = graph()->NewNode(
              simplified()->LoadTypedElement(external_array_type),
              buffer_or_receiver, base_pointer, external_pointer, index, etrue,
              if_true);
        }

        Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
        Node* efalse = effect;
        Node* vfalse;
        {
          // Materialize undefined for out-of-bounds loads.
          vfalse = jsgraph()->UndefinedConstant();
        }

        control = graph()->NewNode(common()->Merge(2), if_true, if_false);
        effect =
            graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
        value =
            graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue, vfalse, control);
      } else {
        // Perform the actual load.
        DCHECK_EQ(kBoundsCheckDone, situation);
        value = effect = graph()->NewNode(
            simplified()->LoadTypedElement(external_array_type),
            buffer_or_receiver, base_pointer, external_pointer, index, effect,
            control);
      }
      break;
    }
    case AccessMode::kStoreInLiteral:
    case AccessMode::kDefine:
      UNREACHABLE();
    case AccessMode::kStore: {
      if (external_array_type == kExternalBigInt64Array ||
          external_array_type == kExternalBigUint64Array) {
        value = effect = graph()->NewNode(
            simplified()->SpeculativeToBigInt(BigIntOperationHint::kBigInt,
                                              FeedbackSource()),
            value, effect, control);
      } else {
        // Ensure that the {value} is actually a Number or an Oddball,
        // and truncate it to a Number appropriately.
        // TODO(panq): Eliminate the deopt loop introduced by the speculation.
        value = effect = graph()->NewNode(
            simplified()->SpeculativeToNumber(
                NumberOperationHint::kNumberOrOddball, FeedbackSource()),
            value, effect, control);
      }

      // Introduce the appropriate truncation for {value}. Currently we
      // only need to do this for ClamedUint8Array {receiver}s, as the
      // other truncations are implicit in the StoreTypedElement, but we
      // might want to change that at some point.
      if (external_array_type == kExternalUint8ClampedArray) {
        value = graph()->NewNode(simplified()->NumberToUint8Clamped(), value);
      }

      if (situation == kHandleOOB_SmiAndRangeCheckComputed) {
        // We have to detect OOB stores and handle them without deopt (by
        // simply not performing them).
        DCHECK_NE(check, nullptr);
        Node* branch = graph()->NewNode(
            common()->Branch(BranchHint::kTrue, BranchSemantics::kMachine),
            check, control);

        Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
        Node* etrue = effect;
        {
          // Do a real bounds check against {length}. This is in order to
          // protect against a potential typer bug leading to the elimination
          // of the NumberLessThan above.
          if (v8_flags.turbo_typer_hardening) {
            index = etrue = graph()->NewNode(
                simplified()->CheckBounds(
                    FeedbackSource(),
                    CheckBoundsFlag::kConvertStringAndMinusZero |
                        CheckBoundsFlag::kAbortOnOutOfBounds),
                index, length, etrue, if_true);
          }

          // Perform the actual store.
          etrue = graph()->NewNode(
              simplified()->StoreTypedElement(external_array_type),
              buffer_or_receiver, base_pointer, external_pointer, index, value,
              etrue, if_true);
        }

        Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
        Node* efalse = effect;
        {
          // Just ignore the out-of-bounds write.
        }

        control = graph()->NewNode(common()->Merge(2), if_true, if_false);
        effect =
            graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
      } else {
        // Perform the actual store
        DCHECK_EQ(kBoundsCheckDone, situation);
        effect = graph()->NewNode(
            simplified()->StoreTypedElement(external_array_type),
            buffer_or_receiver, base_pointer, external_pointer, index, value,
            effect, control);
      }
      break;
    }
    case AccessMode::kHas:
      if (situation == kHandleOOB_SmiAndRangeCheckComputed) {
        DCHECK_NE(check, nullptr);
        JSGraphAssembler assembler(broker(), jsgraph_, zone(),
                                   BranchSemantics::kJS,
                                   [this](Node* n) { this->Revisit(n); });
        assembler.InitializeEffectControl(effect, control);
        value = assembler.MachineSelectIf<Boolean>(check)
                    .Then([&]() { return assembler.TrueConstant(); })
                    .Else([&]() { return assembler.FalseConstant(); })
                    .ExpectTrue()
                    .Value();
        std::tie(effect, control) =
            ReleaseEffectAndControlFromAssembler(&assembler);
      } else {
        DCHECK_EQ(kBoundsCheckDone, situation);
        // For has-property on a typed array, all we need is a bounds check.
        value = jsgraph()->TrueConstant();
      }
      break;
  }

  return ValueEffectControl(value, effect, control);
}

Node* JSNativeContextSpecialization::BuildIndexedStringLoad(
    Node* receiver, Node* index, Node* length, Node** effect, Node** control,
    KeyedAccessLoadMode load_mode) {
  if (LoadModeHandlesOOB(load_mode) &&
      dependencies()->DependOnNoElementsProtector()) {
    // Ensure that the {index} is a valid String length.
    index = *effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource(),
                                  CheckBoundsFlag::kConvertStringAndMinusZero),
        index, jsgraph()->ConstantNoHole(String::kMaxLength), *effect,
        *control);

    // Load the single character string from {receiver} or yield
    // undefined if the {index} is not within the valid bounds.
    Node* check =
        graph()->NewNode(simplified()->NumberLessThan(), index, length);
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, *control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    // Do a real bounds check against {length}. This is in order to protect
    // against a potential typer bug leading to the elimination of the
    // NumberLessThan above.
    Node* etrue = *effect;
    if (v8_flags.turbo_typer_hardening) {
      etrue = index = graph()->NewNode(
          simplified()->CheckBounds(
              FeedbackSource(), CheckBoundsFlag::kConvertStringAndMinusZero |
                                    CheckBoundsFlag::kAbortOnOutOfBounds),
          index, length, etrue, if_true);
    }
    Node* vtrue = etrue = graph()->NewNode(simplified()->StringCharCodeAt(),
                                           receiver, index, etrue, if_true);
    vtrue = graph()->NewNode(simplified()->StringFromSingleCharCode(), vtrue);

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* vfalse = jsgraph()->UndefinedConstant();

    *control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    *effect =
        graph()->NewNode(common()->EffectPhi(2), etrue, *effect, *control);
    return graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                            vtrue, vfalse, *control);
  } else {
    // Ensure that {index} is less than {receiver} length.
    index = *effect = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource(),
                                  CheckBoundsFlag::kConvertStringAndMinusZero),
        index, length, *effect, *control);

    // Return the character from the {receiver} as single character string.
    Node* value = *effect = graph()->NewNode(
        simplified()->StringCharCodeAt(), receiver, index, *effect, *control);
    value = graph()->NewNode(simplified()->StringFromSingleCharCode(), value);
    return value;
  }
}

Node* JSNativeContextSpecialization::BuildExtendPropertiesBackingStore(
    MapRef map, Node* properties, Node* effect, Node* control) {
  // TODO(bmeurer/jkummerow): Property deletions can undo map transitions
  // while keeping the backing store around, meaning that even though the
  // map might believe that objects have no unused property fields, there
  // might actually be some. It would be nice to not create a new backing
  // store in that case (i.e. when properties->length() >= new_length).
  // However, introducing branches and Phi nodes here would make it more
  // difficult for escape analysis to get rid of the backing stores used
  // for intermediate states of chains of property additions. That makes
  // it unclear what the best approach is here.
  DCHECK_EQ(map.UnusedPropertyFields(), 0);
  int length = map.NextFreePropertyIndex() - map.GetInObjectProperties();
  // Under normal circumstances, NextFreePropertyIndex() will always be larger
  // than GetInObjectProperties(). However, an attacker able to corrupt heap
  // memory can break this invariant, in which case we'll get confused here,
  // potentially causing a sandbox violation. This CHECK defends against that.
  SBXCHECK_GE(length, 0);
  int new_length = length + JSObject::kFieldsAdded;
  // Collect the field values from the {properties}.
  ZoneVector<Node*> values(zone());
  values.reserve(new_length);
  for (int i = 0; i < length; ++i) {
    Node* value = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForFixedArraySlot(i)),
        properties, effect, control);
    values.push_back(value);
  }
  // Initialize the new fields to undefined.
  for (int i = 0; i < JSObject::kFieldsAdded; ++i) {
    values.push_back(jsgraph()->UndefinedConstant());
  }

  // Compute new length and hash.
  Node* hash;
  if (length == 0) {
    hash = graph()->NewNode(
        common()->Select(MachineRepresentation::kTaggedSigned),
        graph()->NewNode(simplified()->ObjectIsSmi(), properties), properties,
        jsgraph()->SmiConstant(PropertyArray::kNoHashSentinel));
    hash = effect = graph()->NewNode(common()->TypeGuard(Type::SignedSmall()),
                                     hash, effect, control);
    hash = graph()->NewNode(
        simplified()->NumberShiftLeft(), hash,
        jsgraph()->ConstantNoHole(PropertyArray::HashField::kShift));
  } else {
    hash = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForPropertyArrayLengthAndHash()),
        properties, effect, control);
    hash = graph()->NewNode(
        simplified()->NumberBitwiseAnd(), hash,
        jsgraph()->ConstantNoHole(PropertyArray::HashField::kMask));
  }
  Node* new_length_and_hash =
      graph()->NewNode(simplified()->NumberBitwiseOr(),
                       jsgraph()->ConstantNoHole(new_length), hash);
  // TDOO(jarin): Fix the typer to infer tighter bound for NumberBitwiseOr.
  new_length_and_hash = effect =
      graph()->NewNode(common()->TypeGuard(Type::SignedSmall()),
                       new_length_and_hash, effect, control);

  // Allocate and initialize the new properties.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.Allocate(PropertyArray::SizeFor(new_length), AllocationType::kYoung,
             Type::OtherInternal());
  a.Store(AccessBuilder::ForMap(), jsgraph()->PropertyArrayMapConstant());
  a.Store(AccessBuilder::ForPropertyArrayLengthAndHash(), new_length_and_hash);
  for (int i = 0; i < new_length; ++i) {
    a.Store(AccessBuilder::ForFixedArraySlot(i), values[i]);
  }
  return a.Finish();
}

Node* JSNativeContextSpecialization::BuildCheckEqualsName(NameRef name,
                                                          Node* value,
                                                          Node* effect,
                                                          Node* control) {
  DCHECK(name.IsUniqueName());
  Operator const* const op =
      name.IsSymbol() ? simplified()->CheckEqualsSymbol()
                      : simplified()->CheckEqualsInternalizedString();
  return graph()->NewNode(op, jsgraph()->ConstantNoHole(name, broker()), value,
                          effect, control);
}

bool JSNativeContextSpecialization::CanTreatHoleAsUndefined(
    ZoneVector<MapRef> const& receiver_maps) {
  // Check if all {receiver_maps} have one of the initial Array.prototype
  // or Object.prototype objects as their prototype (in any of the current
  // native contexts, as the global Array protector works isolate-wide).
  for (MapRef receiver_map : receiver_maps) {
    ObjectRef receiver_prototype = receiver_map.prototype(broker());
    if (!receiver_prototype.IsJSObject() ||
        !broker()->IsArrayOrObjectPrototype(receiver_prototype.AsJSObject())) {
      return false;
    }
  }

  // Check if the array prototype chain is intact.
  return dependencies()->DependOnNoElementsProtector();
}

bool JSNativeContextSpecialization::InferMaps(Node* object, Effect effect,
                                              ZoneVector<MapRef>* maps) const {
  ZoneRefSet<Map> map_set;
  NodeProperties::InferMapsResult result =
      NodeProperties::InferMapsUnsafe(broker(), object, effect, &map_set);
  if (result == NodeProperties::kReliableMaps) {
    for (MapRef map : map_set) {
      maps->push_back(map);
    }
    return true;
  } else if (result == NodeProperties::kUnreliableMaps) {
    // For untrusted maps, we can still use the information
    // if the maps are stable.
    for (MapRef map : map_set) {
      if (!map.is_stable()) return false;
    }
    for (MapRef map : map_set) {
      maps->push_back(map);
    }
    return true;
  }
  return false;
}

OptionalMapRef JSNativeContextSpecialization::InferRootMap(Node* object) const {
  HeapObjectMatcher m(object);
  if (m.HasResolvedValue()) {
    MapRef map = m.Ref(broker()).map(broker());
    return map.FindRootMap(broker());
  } else if (m.IsJSCreate()) {
    OptionalMapRef initial_map =
        NodeProperties::GetJSCreateMap(broker(), object);
    if (initial_map.has_value()) {
      DCHECK(initial_map->equals(initial_map->FindRootMap(broker())));
      return *initial_map;
    }
  }
  return std::nullopt;
}

Node* JSNativeContextSpecialization::BuildLoadPrototypeFromObject(
    Node* object, Node* effect, Node* control) {
  Node* map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()), object,
                       effect, control);
  return graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapPrototype()), map, effect,
      control);
}

std::pair<Node*, Node*>
JSNativeContextSpecialization::ReleaseEffectAndControlFromAssembler(
    JSGraphAssembler* gasm) {
  auto catch_scope = gasm->catch_scope();
  DCHECK(catch_scope->is_outermost());

  if (catch_scope->has_handler() &&
      catch_scope->has_exceptional_control_flow()) {
    TNode<Object> handler_exception;
    Effect handler_effect{nullptr};
    Control handler_control{nullptr};
    gasm->catch_scope()->MergeExceptionalPaths(
        &handler_exception, &handler_effect, &handler_control);

    ReplaceWithValue(gasm->outermost_handler(), handler_exception,
                     handler_effect, handler_control);
  }

  return {gasm->effect(), gasm->control()};
}

Graph* JSNativeContextSpecialization::graph() const {
  return jsgraph()->graph();
}

Isolate* JSNativeContextSpecialization::isolate() const {
  return jsgraph()->isolate();
}

Factory* JSNativeContextSpecialization::factory() const {
  return isolate()->factory();
}

CommonOperatorBuilder* JSNativeContextSpecialization::common() const {
  return jsgraph()->common();
}

JSOperatorBuilder* JSNativeContextSpecialization::javascript() const {
  return jsgraph()->javascript();
}

SimplifiedOperatorBuilder* JSNativeContextSpecialization::simplified() const {
  return jsgraph()->simplified();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
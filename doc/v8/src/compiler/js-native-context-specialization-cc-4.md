Response:
My thought process to analyze the provided C++ code snippet and fulfill the request goes through these stages:

1. **Initial Understanding of the Request:** I first identify the core task: analyze a V8 source code snippet (`js-native-context-specialization.cc`) and describe its functionality. The request also specifies several sub-tasks and constraints, including checking for Torque code, relating it to JavaScript, providing examples, and summarizing the functionality.

2. **Code Examination and Keyword Identification:** I start by scanning the code for key terms and patterns that hint at its purpose. I look for:
    * **Class Name:** `JSNativeContextSpecialization` is a strong indicator. "Native context" suggests dealing with built-in JavaScript features or optimizations related to the execution environment. "Specialization" implies tailoring code for specific scenarios.
    * **Function Names:** `BuildPropertyAccess`, `BuildPropertyLoad`, `BuildPropertyStore`, `BuildPropertyTest`, `BuildElementAccess`, `ReduceJSDefineKeyedOwnPropertyInLiteral`, `ReduceJSStoreInArrayLiteral`, `ReduceJSToObject`. These names clearly relate to accessing and manipulating object properties and array elements. The "Reduce" prefix suggests an optimization or simplification process within the V8 compiler.
    * **Data Structures:** `PropertyAccessInfo`, `ElementAccessInfo`, `AccessMode`, `KeyedAccessMode`. These indicate the code deals with different ways of accessing properties and elements, and associated metadata.
    * **V8 Specific Types:** `Node*`, `ZoneVector`, `OptionalJSObjectRef`, `NameRef`, `MapRef`, `FieldIndex`, `MachineRepresentation`, `Type`, `FeedbackSource`, `AllocationBuilder`, `CheckMapsFlag`, `DeoptimizeReason`, `SimplifiedLowering`, `CommonOperatorBuilder`. These signal that the code is part of the V8 compiler's internal workings, likely within the Turbofan or Crankshaft pipeline (though the presence of `SimplifiedLowering` points more strongly towards Turbofan).
    * **Keywords related to Optimization:** `Reduce`, `InlinePropertySetterCall`, `CheckMaps`, `CheckBounds`, `SpeculativeNumberLessThan`, `MaybeGrowFastElements`, `EnsureWritableFastElements`. This confirms the specialization aspect – optimizing common JavaScript operations.
    * **Keywords related to different data types:**  `HeapNumber`, `Smi`, `TaggedPointer`, `Float64`. This shows handling of different JavaScript value representations at a low level.
    * **Comments:**  The comments like `// TODO(v8:...)` often provide context or explain ongoing work.

3. **Inferring Functionality from Code Structure:** I observe the structure of the code:
    * **`BuildProperty...` and `BuildElementAccess` functions:** These functions take various inputs (receiver, index/name, value, effect, control, context) and `...AccessInfo` objects. They seem to generate lower-level V8 IR (Intermediate Representation) nodes for property and element access. The `effect` and `control` parameters are typical of SSA (Static Single Assignment) form used in compilers for tracking data flow and control flow.
    * **`ReduceJS...` functions:** These functions appear to be optimization passes. They identify specific JavaScript operations (like `DefineKeyedOwnPropertyInLiteral` and `StoreInArrayLiteral`) and then delegate to the `BuildPropertyAccess` or similar functions to generate optimized code based on feedback.
    * **Switch statements on `AccessMode`:** This highlights the different ways properties can be accessed (load, store, has, define).
    * **Checks and Assertions (`DCHECK`)**: These help understand the assumptions and invariants the code relies on.

4. **Connecting to JavaScript Concepts:**  I relate the observed code patterns to corresponding JavaScript features:
    * **Property Access:** The `BuildProperty...` functions clearly map to JavaScript property access (`object.property`, `object['property']`). The different `AccessMode` values correspond to getting, setting, checking for the existence of, and defining properties.
    * **Element Access:** `BuildElementAccess` relates to array element access (`array[index]`).
    * **Object and Array Literals:** `ReduceJSDefineKeyedOwnPropertyInLiteral` and `ReduceJSStoreInArrayLiteral` are specifically about optimizing operations within object and array literal creation.
    * **Type Conversion:** `ReduceJSToObject` deals with the `ToObject()` operation, which converts primitive values to their object wrappers.
    * **Typed Arrays:** The special handling of `TypedArrayElementsKind` shows optimization for Typed Array operations.

5. **Formulating a Functional Description:** Based on the code analysis, I start drafting a description of the file's functionality. I emphasize:
    * **Optimization:** The primary goal is to optimize JavaScript property and element access.
    * **Native Context:** It operates within the context of V8's internal implementation.
    * **Specialization:** It tailors code generation based on information gathered during runtime (feedback) and the specific characteristics of the objects and properties involved.

6. **Addressing Specific Requirements:** I go back to the request and ensure all points are covered:
    * **Torque:** I check for the `.tq` extension (not present).
    * **JavaScript Examples:** I create JavaScript code snippets that demonstrate the concepts being optimized (property access, array access, literals, type conversion).
    * **Code Logic Inference:** I construct simple "if-then" scenarios to illustrate how the code might handle different inputs and access modes, focusing on the `BuildPropertyTest` function as an example.
    * **Common Programming Errors:** I think about common mistakes related to property access and type assumptions that this code might help optimize or where optimizations could break down if those assumptions are incorrect. Accessing non-existent properties and incorrect type assumptions are good examples.
    * **Summary:** I synthesize the key findings into a concise summary of the file's purpose.

7. **Review and Refinement:**  I review my analysis for clarity, accuracy, and completeness. I ensure the language is accessible and the examples are relevant. I double-check that all parts of the request have been addressed. For instance, I made sure to explicitly state that the code isn't Torque and then provide a justification based on the file extension. I also ensured the JavaScript examples were clear and directly related to the C++ code's functionality.
这是提供的 C++ 代码片段 `v8/src/compiler/js-native-context-specialization.cc` 的一部分，主要功能是 **针对 JavaScript 原生上下文进行属性和元素访问的优化**。

以下是根据代码片段分析出的功能点：

**主要功能：优化属性和元素访问**

* **`BuildPropertyAccess`**:  这是一个核心函数，根据不同的 `AccessMode` (加载、存储、测试是否存在) 分派到更具体的属性操作构建函数。
* **`BuildPropertyLoad`**: 构建用于加载对象属性值的代码。
* **`BuildPropertyStore`**: 构建用于存储对象属性值的代码。 该函数还处理属性存储时的类型检查、写屏障以及属性过渡等复杂逻辑。
* **`BuildPropertyTest`**: 构建用于测试对象是否拥有某个属性的代码。
* **`BuildElementAccess`**: 构建用于访问数组或类似对象元素的代码，包括处理不同类型的元素（Smi, Double, Object）和处理越界访问。
* **`BuildElementAccessForTypedArrayOrRabGsabTypedArray`**:  专门为 TypedArray 或 SharedArrayBuffer 的 TypedArray 构建元素访问代码，利用其内存布局进行优化。

**优化的关键点：**

* **类型反馈 (Feedback):** 代码中多次出现 `FeedbackSource`，这表明该文件利用了 V8 的类型反馈机制。编译器会根据运行时收集到的类型信息，为特定的属性或元素访问生成更高效的代码。
* **内联缓存 (Inline Caching):**  虽然代码中没有显式提及，但其构建的结构是为了支持内联缓存。通过检查 `access_info` 中携带的信息（例如，持有者对象、字段索引、类型等），可以生成针对特定对象形状优化的访问代码。
* **原型链分析:**  代码会检查原型链的稳定性 (`DependOnStablePrototypeChains`)，以确保在原型链不发生变化的情况下进行优化。
* **隐藏类 (Hidden Classes/Maps):** 代码中涉及到 `access_info.holder()`, `access_info.lookup_start_object_maps()`, `access_info.field_index()`, `access_info.field_type()`, `access_info.transition_map()` 等信息，这些都与 V8 的隐藏类机制密切相关。通过分析对象的形状和布局，可以生成更直接的内存访问代码。
* **元素种类 (ElementsKind):**  `BuildElementAccess` 函数根据数组的元素种类（例如，`PACKED_SMI_ELEMENTS`, `HOLEY_DOUBLE_ELEMENTS`）采取不同的优化策略。
* **TypedArray 特殊处理:** 针对 TypedArray 进行了专门的优化，可以直接操作底层的 ArrayBuffer。

**涉及的优化场景：**

* **常量属性访问 (`access_info.IsFastAccessorConstant()`, `access_info.IsFastDataConstant()`):**  如果属性是常量或可以通过内联访问器快速访问，则会生成更直接的代码。
* **数据字段访问 (`access_info.IsDataField()`):**  直接访问对象内部的数据字段。
* **属性过渡 (`access_info.transition_map()`):**  处理由于添加新属性导致对象形状变化的场景。
* **数组字面量和对象字面量 (`ReduceJSDefineKeyedOwnPropertyInLiteral`, `ReduceJSStoreInArrayLiteral`):**  优化在字面量创建过程中的属性定义和存储操作。
* **`ToObject` 操作优化 (`ReduceJSToObject`):**  如果 `ToObject` 操作的输入已经是对象，则可以避免不必要的转换。
* **数组越界访问处理:**  `BuildElementAccess` 针对数组越界读取（返回 `undefined`）和写入（可能需要扩容）进行了处理。

**关于代码以 `.tq` 结尾：**

如果 `v8/src/compiler/js-native-context-specialization.cc` 以 `.tq` 结尾，那么它将是 **V8 Torque 源代码**。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它会生成 C++ 代码。  **然而，当前提供的文件扩展名是 `.cc`，所以它是一个标准的 C++ 源文件。**

**与 JavaScript 功能的关系和 JavaScript 示例：**

`js-native-context-specialization.cc` 中的代码直接影响 JavaScript 代码的执行效率。它优化了 JavaScript 中常见的属性和元素访问操作。

**JavaScript 示例：**

```javascript
// 属性访问优化
const obj = { a: 1, b: 2 };
console.log(obj.a); //  BuildPropertyLoad 可能会优化这个操作

obj.c = 3; // BuildPropertyStore 可能会优化这个操作

'a' in obj; // BuildPropertyTest 可能会优化这个操作

// 元素访问优化
const arr = [10, 20, 30];
console.log(arr[1]); // BuildElementAccess 可能会优化这个操作

arr[2] = 40; // BuildElementAccess 可能会优化这个操作

// 对象和数组字面量优化
const literalObj = { x: 5 }; // ReduceJSDefineKeyedOwnPropertyInLiteral 可能会优化
const literalArr = [1, 2];    // ReduceJSStoreInArrayLiteral 可能会优化

// ToObject 优化
const num = 5;
const objNum = Object(num); // 如果 V8 能推断出 num 已经是对象包装器，ReduceJSToObject 可能会优化

// TypedArray 优化
const typedArray = new Int32Array([1, 2, 3]);
console.log(typedArray[0]); // BuildElementAccessForTypedArrayOrRabGsabTypedArray 可能会优化
```

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const myObj = { value: 10 };
const result = myObj.value;
```

**在 `BuildPropertyLoad` 函数中，假设输入如下：**

* `lookup_start_object`: 指向 `myObj` 对象的 V8 内部表示的 Node。
* `receiver`:  指向 `myObj` 对象的 V8 内部表示的 Node。
* `context`: 当前执行上下文的 Node。
* `frame_state`: 当前帧状态的 Node。
* `effect`: 当前效果链的 Node。
* `control`: 当前控制流的 Node。
* `name`: 指向字符串 "value" 的 NameRef。
* `access_info`:  包含关于 `myObj` 对象和 `value` 属性的信息，例如 `value` 属性的字段索引、类型等。 假设 `access_info` 指示 `value` 是一个快速属性，存储在对象的实例内。

**可能的输出：**

`BuildPropertyLoad` 函数会生成一系列 V8 IR (Intermediate Representation) 节点，用于执行以下操作：

1. **加载字段:**  生成一个 `LoadField` 节点，指示从 `myObj` 对象内存中的特定偏移量（由 `access_info.field_index()` 提供）加载数据。
2. **连接效果和控制流:**  将新的 `LoadField` 节点连接到现有的 `effect` 和 `control` 链中。
3. **返回结果:**  返回一个 `ValueEffectControl` 对象，包含加载的值的 Node、更新后的 `effect` 和 `control`。

**涉及用户常见的编程错误：**

* **访问不存在的属性:**

   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); //  结果是 undefined，但 V8 依然会尝试查找，可能会触发不同的代码路径。
   ```
   `BuildPropertyLoad` 会根据 `access_info.IsNotFound()` 来处理这种情况，通常不会生成直接加载的代码，而是会生成查找原型链的代码或直接返回 `undefined`。

* **对 `undefined` 或 `null` 进行属性访问:**

   ```javascript
   let myVar; // myVar is undefined
   console.log(myVar.property); // TypeError: Cannot read properties of undefined (reading 'property')
   ```
   V8 在执行到这里之前通常会进行类型检查，但 `js-native-context-specialization.cc` 中的代码主要关注的是在已知接收者是对象的情况下如何优化属性访问。

* **类型假设错误导致优化失效:**

   ```javascript
   function process(obj) {
       return obj.value + 1;
   }

   process({ value: 10 }); // V8 可能会假设 obj.value 是一个数字

   process({ value: "hello" }); // 如果类型不一致，之前的优化可能需要回退 (deoptimization)。
   ```
   `js-native-context-specialization.cc` 中的代码依赖类型反馈，如果运行时的类型与之前的假设不符，V8 可能会取消之前的优化。

**归纳功能 (第 5 部分，共 6 部分):**

到目前为止，根据提供的代码片段，`v8/src/compiler/js-native-context-specialization.cc` 的主要功能是 **V8 编译器中负责根据 JavaScript 原生上下文的特性，对属性和元素访问操作进行优化的组件**。它利用类型反馈、隐藏类信息和元素种类等信息，为常见的属性和元素访问模式生成更高效的机器码。该组件通过构建特定的 IR 节点来实现这些优化，并且能够处理多种访问模式和不同的数据类型。  它致力于提高 JavaScript 代码在 V8 引擎中的执行性能。

Prompt: 
```
这是目录为v8/src/compiler/js-native-context-specialization.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-native-context-specialization.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能

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
      base_pointer = jsgraph()->ZeroConstant()
"""


```
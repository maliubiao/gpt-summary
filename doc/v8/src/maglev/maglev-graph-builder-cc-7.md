Response:
Let's break down the request and the provided C++ code snippet to formulate a comprehensive answer.

**1. Understanding the Goal:**

The core goal is to analyze the provided C++ code (`v8/src/maglev/maglev-graph-builder.cc`, part 8/18) and explain its functionality within the context of the V8 JavaScript engine. The prompt also includes specific constraints and questions to address.

**2. Initial Code Scan and High-Level Interpretation:**

The code snippet revolves around building and optimizing operations within V8's Maglev compiler. Key patterns emerge:

* **Comparison Functions:** `CheckConditionIn32`, `CompareInt32`, `CompareUint32` suggest handling numerical comparisons.
* **Typed Array Operations:**  Functions like `BuildLoadTypedArrayLength`, `BuildLoadTypedArrayElement`, `BuildStoreTypedArrayElement`, `TryBuildElementAccessOnTypedArray` indicate logic for accessing and manipulating typed arrays (like `Uint8Array`, `Float64Array`, etc.).
* **JS Array/Object Element Access:** Functions like `BuildLoadElements`, `TryBuildElementLoadOnJSArrayOrJSObject`, `TryBuildElementStoreOnJSArrayOrJSObject`, `TryBuildElementAccessOnJSArrayOrJSObject` are concerned with accessing elements of regular JavaScript arrays and objects.
* **Polymorphic Access:** The `TryBuildPolymorphicElementAccess` and `TryBuildPolymorphicPropertyAccess` templates suggest handling cases where the type of the object being accessed isn't known statically and can vary. This involves checking the object's map (structure) at runtime.
* **Graph Building:** The `MaglevGraphBuilder` class name and the functions like `AddNewNode` strongly imply this code is part of the process of constructing an intermediate representation (a graph) of the JavaScript code for optimization.
* **Deoptimization:** `EmitUnconditionalDeopt` and `DeoptimizeReason` point to mechanisms for falling back to a less optimized execution path if certain assumptions are violated during runtime.
* **Constants and Known Properties:**  `TryGetInt32Constant`, `TryFindLoadedProperty`, `RecordKnownProperty` indicate optimization based on knowing the values or properties of objects at compile time.
* **Type Checks:**  Functions like `BuildCheckInt32Condition`, `BuildCheckTypedArrayNotDetached`, `BuildCheckTypedArrayBounds`, `BuildCheckMaps`, `BuildTransitionElementsKindOrCheckMap` are used to insert runtime checks to ensure the validity of operations.

**3. Addressing Specific Constraints:**

* **Function Listing:**  This will involve creating a concise list summarizing the purpose of each function.
* **`.tq` Extension:**  The code provided is clearly C++, not Torque. This needs to be stated.
* **JavaScript Relationship:**  The functions dealing with arrays and objects directly relate to how JavaScript code interacts with these data structures. Examples will be needed.
* **Code Logic Inference (Input/Output):**  For functions like the comparison functions and basic element access, providing hypothetical inputs and outputs is possible. For more complex functions like polymorphic access, describing the overall flow based on different object types is more appropriate.
* **Common Programming Errors:**  Relating the code to common JavaScript errors like accessing array elements out of bounds or trying to perform operations on detached typed arrays is important.
* **Part 8 of 18:** This indicates we should focus on the functionality within this specific segment of the file and summarize its contribution to the overall Maglev graph building process.

**4. Structuring the Answer:**

A logical structure would be:

* **Introduction:** Briefly introduce the file and its role in Maglev.
* **Functionality Listing:** Provide a bulleted list of key functions and their purposes.
* **Torque Check:** Explicitly state that the file is C++.
* **JavaScript Relationship and Examples:** Demonstrate how the C++ code implements behaviors seen in JavaScript, with clear code examples.
* **Code Logic Inference (Examples):**  Illustrate the behavior of simpler functions with input/output examples.
* **Common Programming Errors:**  Show how the code helps prevent or handle common JavaScript errors.
* **Part 8 Summary:**  Summarize the functionality of this specific part of the file within the larger context of graph building.

**5. Refinement and Iteration (Internal Thought Process):**

* **Focus on the "Why":**  Not just *what* the code does, but *why* it's doing it. For example, why are there so many checks?  (Optimization and safety).
* **Clarity over Detail:** Avoid getting bogged down in low-level implementation details unless they are crucial to understanding the functionality. Focus on the higher-level concepts.
* **Use Concrete Examples:**  JavaScript examples make the C++ code much more relatable.
* **Relate to Compiler Optimization:** Emphasize how this code contributes to making JavaScript execution faster.

**Pre-computation/Pre-analysis (Mental or Scratchpad):**

* **Identify Core Concepts:**  Element access, type checks, polymorphism, graph building, deoptimization.
* **Group Related Functions:**  Functions dealing with typed arrays, functions dealing with regular arrays, etc.
* **Think of Simple JavaScript Equivalents:**  `array[index]`, `typedArray[index]`, property access, comparisons.

By following this structured approach and iteratively refining the understanding of the code and the request, a comprehensive and accurate answer can be generated. The key is to translate the technical details of the C++ code into concepts understandable to someone familiar with JavaScript and the general principles of compiler optimization.
这是对 V8 源代码文件 `v8/src/maglev/maglev-graph-builder.cc` 的第 8 部分的分析。根据您提供的信息，我们可以归纳出以下功能：

**整体功能归纳（基于第 8 部分）：**

这部分 `maglev-graph-builder.cc` 的代码主要负责在 Maglev 编译器中构建用于处理**数组和对象元素访问**相关的图节点。它涵盖了多种情况，包括：

* **基本类型比较和条件检查:**  构建用于比较整数值的节点，并根据比较结果进行分支或触发 deoptimization。
* **加载元素:** 从 JS 对象或数组中加载元素（elements）。它会尝试复用已加载的元素，并记录已知的属性。
* **加载 TypedArray 长度和元素:**  专门处理 TypedArray 的长度加载和元素加载。它会根据不同的元素类型（`Int8`, `Uint32`, `Float64` 等）构建不同的加载节点。
* **存储 TypedArray 元素:**  构建用于向 TypedArray 存储元素的节点，并根据元素类型进行适当的类型转换。
* **优化 TypedArray 元素访问:** 尝试优化 TypedArray 的元素访问，例如检查数组是否已分离，检查索引是否越界。
* **优化 JSArray 或 JSObject 的元素访问 (Load):**  尝试构建高效的节点来加载 JSArray 或 JSObject 的元素。这包括处理 holes（空洞）以及越界访问的情况。
* **优化 JSArray 或 JSObject 的元素存储 (Store):**  尝试构建高效的节点来存储 JSArray 或 JSObject 的元素。这包括处理数组的增长、写时复制 (COW) 以及类型转换。
* **处理多态元素访问:**  处理对象可能具有不同 Map 的情况下的元素访问，生成代码来检查 Map 并执行相应的访问操作。
* **处理多态属性访问:**  与多态元素访问类似，处理对象属性访问，并根据对象的 Map 生成相应的访问代码。

**具体功能列举：**

* **`CheckConditionIn32(int32_t lhs, int32_t rhs, AssertCondition condition)`:**  根据给定的条件比较两个 `int32_t` 值，用于断言检查。
* **`CompareInt32(int32_t lhs, int32_t rhs, Operation operation)`:** 根据给定的操作比较两个 `int32_t` 值。
* **`CompareUint32(uint32_t lhs, uint32_t rhs, Operation operation)`:** 根据给定的操作比较两个 `uint32_t` 值。
* **`TryBuildCheckInt32Condition(ValueNode* lhs, ValueNode* rhs, AssertCondition condition, DeoptimizeReason reason)`:** 尝试构建一个检查 `int32_t` 条件的节点。如果左右操作数都是常量，则直接进行检查，否则添加一个 `CheckInt32Condition` 节点。
* **`BuildLoadElements(ValueNode* object)`:** 构建一个加载对象 elements 的节点。它会尝试复用已知的 elements。
* **`BuildLoadTypedArrayLength(ValueNode* object, ElementsKind elements_kind)`:** 构建一个加载 TypedArray 长度的节点。
* **`BuildLoadTypedArrayElement(ValueNode* object, ValueNode* index, ElementsKind elements_kind)`:** 根据不同的元素类型，构建加载 TypedArray 元素的节点（例如 `LoadSignedIntTypedArrayElement`, `LoadDoubleTypedArrayElement`）。
* **`BuildStoreTypedArrayElement(ValueNode* object, ValueNode* index, ElementsKind elements_kind)`:** 根据不同的元素类型，构建存储 TypedArray 元素的节点（例如 `StoreIntTypedArrayElement`, `StoreDoubleTypedArrayElement`）。
* **`TryBuildElementAccessOnTypedArray(ValueNode* object, ValueNode* index_object, const compiler::ElementAccessInfo& access_info, compiler::KeyedAccessMode const& keyed_mode)`:** 尝试构建 TypedArray 的元素访问节点，包括加载和存储，并进行边界检查等优化。
* **`TryBuildElementLoadOnJSArrayOrJSObject(ValueNode* object, ValueNode* index_object, base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind, KeyedAccessLoadMode load_mode)`:** 尝试构建加载 JSArray 或 JSObject 元素的节点，处理不同类型的元素和 holes。
* **`ConvertForStoring(ValueNode* value, ElementsKind kind)`:**  在存储元素之前对值进行转换，例如处理 NaN 值或将值转换为 Smi。
* **`TryBuildElementStoreOnJSArrayOrJSObject(ValueNode* object, ValueNode* index_object, ValueNode* value, base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind, const compiler::KeyedAccessMode& keyed_mode)`:** 尝试构建存储 JSArray 或 JSObject 元素的节点，处理数组增长、COW 等情况。
* **`TryBuildElementAccessOnJSArrayOrJSObject(ValueNode* object, ValueNode* index_object, const compiler::ElementAccessInfo& access_info, compiler::KeyedAccessMode const& keyed_mode)`:**  根据访问模式（加载或存储）调用相应的构建函数来处理 JSArray 或 JSObject 的元素访问。
* **`TryBuildElementAccess(ValueNode* object, ValueNode* index_object, compiler::ElementAccessFeedback const& feedback, compiler::FeedbackSource const& feedback_source, GenericAccessFunc&& build_generic_access)`:**  尝试构建通用的元素访问节点，处理单态和多态的情况。如果反馈信息为空，则会构建调用内置函数的节点。
* **`TryBuildPolymorphicElementAccess(ValueNode* object, ValueNode* index_object, const compiler::KeyedAccessMode& keyed_mode, const ZoneVector<compiler::ElementAccessInfo>& access_infos, GenericAccessFunc&& build_generic_access)`:**  构建处理多态元素访问的节点，根据不同的 Map 生成不同的代码分支。
* **`TryBuildPolymorphicPropertyAccess(ValueNode* receiver, ValueNode* lookup_start_object, compiler::NamedAccessFeedback const& feedback, compiler::AccessMode access_mode, const ZoneVector<compiler::PropertyAccessInfo>& access_infos, GenericAccessFunc&& build_generic_access)`:** 构建处理多态属性访问的节点。

**关于文件类型：**

`v8/src/maglev/maglev-graph-builder.cc` 以 `.cc` 结尾，这表明它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件（Torque 文件通常以 `.tq` 结尾）。

**与 JavaScript 功能的关系及示例：**

这部分代码直接对应于 JavaScript 中对数组和对象元素进行访问的操作。

**JavaScript 示例：**

```javascript
const arr = [1, 2, 3];
const obj = { a: 4, b: 5 };
const typedArr = new Uint8Array([6, 7, 8]);

// 对应于 BuildLoadElements 和 TryBuildElementLoadOnJSArrayOrJSObject
const firstElementArr = arr[0]; // 加载数组元素

// 对应于 BuildLoadElements 和 TryBuildElementLoadOnJSArrayOrJSObject
const propertyA = obj.a;      // 加载对象属性（可以看作是字符串索引的元素访问）

// 对应于 BuildLoadTypedArrayElement
const firstElementTypedArr = typedArr[0]; // 加载 TypedArray 元素

// 对应于 TryBuildElementStoreOnJSArrayOrJSObject
arr[1] = 10;                 // 存储数组元素

// 对应于 BuildStoreTypedArrayElement
typedArr[2] = 20;              // 存储 TypedArray 元素
```

**代码逻辑推理 (假设输入与输出):**

**示例 1: `TryBuildCheckInt32Condition`**

* **假设输入:**
    * `lhs`: 一个表示常量 `5` 的 `ValueNode`
    * `rhs`: 一个表示常量 `10` 的 `ValueNode`
    * `condition`: `AssertCondition::kLessThan` (小于)
    * `reason`: `DeoptimizeReason::kConditionNotMet`

* **输出:** `ReduceResult::Done()`。由于 `5 < 10` 为真，条件成立，因此不需要生成 deoptimization 代码。

**示例 2: `BuildLoadTypedArrayElement`**

* **假设输入:**
    * `object`: 一个表示 `Uint8Array` 实例的 `ValueNode`
    * `index`: 一个表示常量 `1` 的 `ValueNode`
    * `elements_kind`: `UINT8_ELEMENTS`

* **输出:**  一个新的 `LoadUnsignedIntTypedArrayElement` 类型的 `ValueNode`，该节点表示加载 `Uint8Array` 中索引为 1 的元素。

**用户常见的编程错误及示例：**

这部分代码涉及的常见编程错误包括：

* **数组或 TypedArray 索引越界访问:**

   ```javascript
   const arr = [1, 2];
   console.log(arr[2]); // 访问不存在的索引，可能导致 undefined 或错误

   const typedArr = new Uint8Array([1, 2]);
   console.log(typedArr[2]); // 访问不存在的索引，可能返回 0 或错误
   ```
   `TryBuildElementAccessOnTypedArray` 和 `TryBuildElementLoadOnJSArrayOrJSObject` 中的边界检查逻辑旨在捕获或优化这类错误。

* **在 TypedArray 上存储不兼容类型的值:**

   ```javascript
   const typedArr = new Uint8Array(1);
   typedArr[0] = "hello"; // 尝试存储字符串到 Uint8Array，会被转换为数字 (NaN -> 0)
   typedArr[0] = 256;    // 尝试存储超出范围的值，会被截断为 0
   ```
   `BuildStoreTypedArrayElement` 中的类型转换逻辑处理了这些情况。

* **操作已分离的 ArrayBuffer (用于 TypedArray):**

   ```javascript
   const buffer = new ArrayBuffer(8);
   const typedArr = new Uint8Array(buffer);
   buffer.detach();
   console.log(typedArr[0]); // 尝试访问已分离的 ArrayBuffer，会抛出 TypeError
   ```
   `AddNewNode<CheckTypedArrayNotDetached>({object})` 旨在在 Maglev 图中添加检查，防止这种错误。

**第 8 部分的功能总结：**

总而言之，`v8/src/maglev/maglev-graph-builder.cc` 的第 8 部分专注于构建 Maglev 编译器中处理 JavaScript **数组和对象元素访问**的核心逻辑。它针对不同类型的数组（普通数组和 TypedArray）、不同的访问模式（加载和存储）以及可能遇到的多态情况进行了优化和代码生成。这部分代码的目标是生成高效的中间表示，以便后续的优化和代码生成阶段能够生成高性能的机器码来执行 JavaScript 数组和对象操作。

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共18部分，请归纳一下它的功能

"""
 rhs;
    case AssertCondition::kGreaterThan:
      return lhs > rhs;
    case AssertCondition::kGreaterThanEqual:
      return lhs >= rhs;
    case AssertCondition::kUnsignedLessThan:
      return static_cast<uint32_t>(lhs) < static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedLessThanEqual:
      return static_cast<uint32_t>(lhs) <= static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedGreaterThan:
      return static_cast<uint32_t>(lhs) > static_cast<uint32_t>(rhs);
    case AssertCondition::kUnsignedGreaterThanEqual:
      return static_cast<uint32_t>(lhs) >= static_cast<uint32_t>(rhs);
  }
}

bool CompareInt32(int32_t lhs, int32_t rhs, Operation operation) {
  switch (operation) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      return lhs == rhs;
    case Operation::kLessThan:
      return lhs < rhs;
    case Operation::kLessThanOrEqual:
      return lhs <= rhs;
    case Operation::kGreaterThan:
      return lhs > rhs;
    case Operation::kGreaterThanOrEqual:
      return lhs >= rhs;
    default:
      UNREACHABLE();
  }
}

bool CompareUint32(uint32_t lhs, uint32_t rhs, Operation operation) {
  switch (operation) {
    case Operation::kEqual:
    case Operation::kStrictEqual:
      return lhs == rhs;
    case Operation::kLessThan:
      return lhs < rhs;
    case Operation::kLessThanOrEqual:
      return lhs <= rhs;
    case Operation::kGreaterThan:
      return lhs > rhs;
    case Operation::kGreaterThanOrEqual:
      return lhs >= rhs;
    default:
      UNREACHABLE();
  }
}

}  // namespace

ReduceResult MaglevGraphBuilder::TryBuildCheckInt32Condition(
    ValueNode* lhs, ValueNode* rhs, AssertCondition condition,
    DeoptimizeReason reason) {
  auto lhs_const = TryGetInt32Constant(lhs);
  if (lhs_const) {
    auto rhs_const = TryGetInt32Constant(rhs);
    if (rhs_const) {
      if (CheckConditionIn32(lhs_const.value(), rhs_const.value(), condition)) {
        return ReduceResult::Done();
      }
      return EmitUnconditionalDeopt(reason);
    }
  }
  AddNewNode<CheckInt32Condition>({lhs, rhs}, condition, reason);
  return ReduceResult::Done();
}

ValueNode* MaglevGraphBuilder::BuildLoadElements(ValueNode* object) {
  ReduceResult known_elements =
      TryFindLoadedProperty(known_node_aspects().loaded_properties, object,
                            KnownNodeAspects::LoadedPropertyMapKey::Elements());
  if (known_elements.IsDone()) {
    DCHECK(known_elements.IsDoneWithValue());
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  * Reusing non-constant [Elements] "
                << PrintNodeLabel(graph_labeller(), known_elements.value())
                << ": " << PrintNode(graph_labeller(), known_elements.value())
                << std::endl;
    }
    return known_elements.value();
  }

  DCHECK_EQ(JSObject::kElementsOffset, JSArray::kElementsOffset);
  ValueNode* elements = BuildLoadTaggedField(object, JSObject::kElementsOffset);
  RecordKnownProperty(object,
                      KnownNodeAspects::LoadedPropertyMapKey::Elements(),
                      elements, false, compiler::AccessMode::kLoad);
  return elements;
}

ReduceResult MaglevGraphBuilder::BuildLoadTypedArrayLength(
    ValueNode* object, ElementsKind elements_kind) {
  DCHECK(IsTypedArrayOrRabGsabTypedArrayElementsKind(elements_kind));
  bool is_variable_length = IsRabGsabTypedArrayElementsKind(elements_kind);

  if (!is_variable_length) {
    // Note: We can't use broker()->length_string() here, because it could
    // conflict with redefinitions of the TypedArray length property.
    RETURN_IF_DONE(TryFindLoadedProperty(
        known_node_aspects().loaded_constant_properties, object,
        KnownNodeAspects::LoadedPropertyMapKey::TypedArrayLength()));
  }

  ValueNode* result = AddNewNode<LoadTypedArrayLength>({object}, elements_kind);
  if (!is_variable_length) {
    RecordKnownProperty(
        object, KnownNodeAspects::LoadedPropertyMapKey::TypedArrayLength(),
        result, true, compiler::AccessMode::kLoad);
  }
  return result;
}

ValueNode* MaglevGraphBuilder::BuildLoadTypedArrayElement(
    ValueNode* object, ValueNode* index, ElementsKind elements_kind) {
#define BUILD_AND_RETURN_LOAD_TYPED_ARRAY(Type)                     \
  return AddNewNode<Load##Type##TypedArrayElement>({object, index}, \
                                                   elements_kind);

  switch (elements_kind) {
    case INT8_ELEMENTS:
    case INT16_ELEMENTS:
    case INT32_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(SignedInt);
    case UINT8_CLAMPED_ELEMENTS:
    case UINT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case UINT32_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(UnsignedInt);
    case FLOAT32_ELEMENTS:
    case FLOAT64_ELEMENTS:
      BUILD_AND_RETURN_LOAD_TYPED_ARRAY(Double);
    default:
      UNREACHABLE();
  }
#undef BUILD_AND_RETURN_LOAD_TYPED_ARRAY
}

void MaglevGraphBuilder::BuildStoreTypedArrayElement(
    ValueNode* object, ValueNode* index, ElementsKind elements_kind) {
#define BUILD_STORE_TYPED_ARRAY(Type, value)                           \
  AddNewNode<Store##Type##TypedArrayElement>({object, index, (value)}, \
                                             elements_kind);

  // TODO(leszeks): These operations have a deopt loop when the ToNumber
  // conversion sees a type other than number or oddball. Turbofan has the same
  // deopt loop, but ideally we'd avoid it.
  switch (elements_kind) {
    case UINT8_CLAMPED_ELEMENTS: {
      BUILD_STORE_TYPED_ARRAY(Int, GetAccumulatorUint8ClampedForToNumber(
                                       ToNumberHint::kAssumeNumberOrOddball))
      break;
    }
    case INT8_ELEMENTS:
    case INT16_ELEMENTS:
    case INT32_ELEMENTS:
    case UINT8_ELEMENTS:
    case UINT16_ELEMENTS:
    case UINT32_ELEMENTS:
      BUILD_STORE_TYPED_ARRAY(Int, GetAccumulatorTruncatedInt32ForToNumber(
                                       ToNumberHint::kAssumeNumberOrOddball))
      break;
    case FLOAT32_ELEMENTS:
    case FLOAT64_ELEMENTS:
      BUILD_STORE_TYPED_ARRAY(Double, GetAccumulatorHoleyFloat64ForToNumber(
                                          ToNumberHint::kAssumeNumberOrOddball))
      break;
    default:
      UNREACHABLE();
  }
#undef BUILD_STORE_TYPED_ARRAY
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnTypedArray(
    ValueNode* object, ValueNode* index_object,
    const compiler::ElementAccessInfo& access_info,
    compiler::KeyedAccessMode const& keyed_mode) {
  DCHECK(HasOnlyJSTypedArrayMaps(
      base::VectorOf(access_info.lookup_start_object_maps())));
  ElementsKind elements_kind = access_info.elements_kind();
  if (elements_kind == FLOAT16_ELEMENTS ||
      elements_kind == BIGUINT64_ELEMENTS ||
      elements_kind == BIGINT64_ELEMENTS) {
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kLoad &&
      LoadModeHandlesOOB(keyed_mode.load_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore &&
      StoreModeIgnoresTypeArrayOOB(keyed_mode.store_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore &&
      elements_kind == UINT8_CLAMPED_ELEMENTS &&
      !IsSupported(CpuOperation::kFloat64Round)) {
    // TODO(victorgomes): Technically we still support if value (in the
    // accumulator) is of type int32. It would be nice to have a roll back
    // mechanism instead, so that we do not need to check this early.
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(leszeks): Eliminate this check.
    AddNewNode<CheckTypedArrayNotDetached>({object});
  }
  ValueNode* index;
  ValueNode* length;
  GET_VALUE_OR_ABORT(index, GetUint32ElementIndex(index_object));
  GET_VALUE_OR_ABORT(length, BuildLoadTypedArrayLength(object, elements_kind));
  AddNewNode<CheckTypedArrayBounds>({index, length});
  switch (keyed_mode.access_mode()) {
    case compiler::AccessMode::kLoad:
      DCHECK(!LoadModeHandlesOOB(keyed_mode.load_mode()));
      return BuildLoadTypedArrayElement(object, index, elements_kind);
    case compiler::AccessMode::kStore:
      DCHECK(StoreModeIsInBounds(keyed_mode.store_mode()));
      BuildStoreTypedArrayElement(object, index, elements_kind);
      return ReduceResult::Done();
    case compiler::AccessMode::kHas:
      // TODO(victorgomes): Implement has element access.
      return ReduceResult::Fail();
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kDefine:
      UNREACHABLE();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildElementLoadOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object,
    base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind,
    KeyedAccessLoadMode load_mode) {
  DCHECK(IsFastElementsKind(elements_kind));
  bool is_jsarray = HasOnlyJSArrayMaps(maps);
  DCHECK(is_jsarray || HasOnlyJSObjectMaps(maps));

  ValueNode* elements_array = BuildLoadElements(object);
  ValueNode* index = GetInt32ElementIndex(index_object);
  ValueNode* length = is_jsarray ? GetInt32(BuildLoadJSArrayLength(object))
                                 : BuildLoadFixedArrayLength(elements_array);

  auto emit_load = [&]() -> ReduceResult {
    ValueNode* result;
    if (elements_kind == HOLEY_DOUBLE_ELEMENTS) {
      result = BuildLoadHoleyFixedDoubleArrayElement(
          elements_array, index,
          CanTreatHoleAsUndefined(maps) && LoadModeHandlesHoles(load_mode));
    } else if (elements_kind == PACKED_DOUBLE_ELEMENTS) {
      result = BuildLoadFixedDoubleArrayElement(elements_array, index);
    } else {
      DCHECK(!IsDoubleElementsKind(elements_kind));
      result = BuildLoadFixedArrayElement(elements_array, index);
      if (IsHoleyElementsKind(elements_kind)) {
        if (CanTreatHoleAsUndefined(maps) && LoadModeHandlesHoles(load_mode)) {
          result = BuildConvertHoleToUndefined(result);
        } else {
          RETURN_IF_ABORT(BuildCheckNotHole(result));
          if (IsSmiElementsKind(elements_kind)) {
            EnsureType(result, NodeType::kSmi);
          }
        }
      } else if (IsSmiElementsKind(elements_kind)) {
        EnsureType(result, NodeType::kSmi);
      }
    }
    return result;
  };

  if (CanTreatHoleAsUndefined(maps) && LoadModeHandlesOOB(load_mode)) {
    ValueNode* positive_index;
    GET_VALUE_OR_ABORT(positive_index, GetUint32ElementIndex(index));
    ValueNode* uint32_length = AddNewNode<UnsafeInt32ToUint32>({length});
    return SelectReduction(
        [&](auto& builder) {
          return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                            positive_index, uint32_length);
        },
        emit_load, [&] { return GetRootConstant(RootIndex::kUndefinedValue); });
  } else {
    RETURN_IF_ABORT(TryBuildCheckInt32Condition(
        index, length, AssertCondition::kUnsignedLessThan,
        DeoptimizeReason::kOutOfBounds));
    return emit_load();
  }
}

ReduceResult MaglevGraphBuilder::ConvertForStoring(ValueNode* value,
                                                   ElementsKind kind) {
  if (IsDoubleElementsKind(kind)) {
    // Make sure we do not store signalling NaNs into double arrays.
    // TODO(leszeks): Consider making this a bit on StoreFixedDoubleArrayElement
    // rather than a separate node.
    return GetSilencedNaN(GetFloat64(value));
  }
  if (IsSmiElementsKind(kind)) return GetSmiValue(value);
  return value;
}

ReduceResult MaglevGraphBuilder::TryBuildElementStoreOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object, ValueNode* value,
    base::Vector<const compiler::MapRef> maps, ElementsKind elements_kind,
    const compiler::KeyedAccessMode& keyed_mode) {
  DCHECK(IsFastElementsKind(elements_kind));

  const bool is_jsarray = HasOnlyJSArrayMaps(maps);
  DCHECK(is_jsarray || HasOnlyJSObjectMaps(maps));

  // Get the elements array.
  ValueNode* elements_array = BuildLoadElements(object);
  GET_VALUE_OR_ABORT(value, ConvertForStoring(value, elements_kind));
  ValueNode* index;

  // TODO(verwaest): Loop peeling will turn the first iteration index of spread
  // literals into smi constants as well, breaking the assumption that we'll
  // have preallocated the space if we see known indices. Turn off this
  // optimization if loop peeling is on.
  if (keyed_mode.access_mode() == compiler::AccessMode::kStoreInLiteral &&
      index_object->Is<SmiConstant>() && is_jsarray && !any_peeled_loop_) {
    index = GetInt32ElementIndex(index_object);
  } else {
    // Check boundaries.
    ValueNode* elements_array_length = nullptr;
    ValueNode* length;
    if (is_jsarray) {
      length = GetInt32(BuildLoadJSArrayLength(object));
    } else {
      length = elements_array_length =
          BuildLoadFixedArrayLength(elements_array);
    }
    index = GetInt32ElementIndex(index_object);
    if (keyed_mode.store_mode() == KeyedAccessStoreMode::kGrowAndHandleCOW) {
      if (elements_array_length == nullptr) {
        elements_array_length = BuildLoadFixedArrayLength(elements_array);
      }

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
      ValueNode* limit =
          IsHoleyElementsKind(elements_kind)
              ? AddNewNode<Int32AddWithOverflow>(
                    {elements_array_length,
                     GetInt32Constant(JSObject::kMaxGap)})
          : is_jsarray
              ? AddNewNode<Int32AddWithOverflow>({length, GetInt32Constant(1)})
              : elements_array_length;
      RETURN_IF_ABORT(TryBuildCheckInt32Condition(
          index, limit, AssertCondition::kUnsignedLessThan,
          DeoptimizeReason::kOutOfBounds));

      // Grow backing store if necessary and handle COW.
      elements_array = AddNewNode<MaybeGrowFastElements>(
          {elements_array, object, index, elements_array_length},
          elements_kind);

      // If we didn't grow {elements}, it might still be COW, in which case we
      // copy it now.
      if (IsSmiOrObjectElementsKind(elements_kind)) {
        DCHECK_EQ(keyed_mode.store_mode(),
                  KeyedAccessStoreMode::kGrowAndHandleCOW);
        elements_array =
            AddNewNode<EnsureWritableFastElements>({elements_array, object});
      }

      // Update length if necessary.
      if (is_jsarray) {
        ValueNode* new_length =
            AddNewNode<UpdateJSArrayLength>({length, object, index});
        RecordKnownProperty(object, broker()->length_string(), new_length,
                            false, compiler::AccessMode::kStore);
      }
    } else {
      RETURN_IF_ABORT(TryBuildCheckInt32Condition(
          index, length, AssertCondition::kUnsignedLessThan,
          DeoptimizeReason::kOutOfBounds));

      // Handle COW if needed.
      if (IsSmiOrObjectElementsKind(elements_kind)) {
        if (keyed_mode.store_mode() == KeyedAccessStoreMode::kHandleCOW) {
          elements_array =
              AddNewNode<EnsureWritableFastElements>({elements_array, object});
        } else {
          // Ensure that this is not a COW FixedArray.
          RETURN_IF_ABORT(BuildCheckMaps(
              elements_array, base::VectorOf({broker()->fixed_array_map()})));
        }
      }
    }
  }

  // Do the store.
  if (IsDoubleElementsKind(elements_kind)) {
    BuildStoreFixedDoubleArrayElement(elements_array, index, value);
  } else {
    BuildStoreFixedArrayElement(elements_array, index, value);
  }

  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::TryBuildElementAccessOnJSArrayOrJSObject(
    ValueNode* object, ValueNode* index_object,
    const compiler::ElementAccessInfo& access_info,
    compiler::KeyedAccessMode const& keyed_mode) {
  if (!IsFastElementsKind(access_info.elements_kind())) {
    return ReduceResult::Fail();
  }
  switch (keyed_mode.access_mode()) {
    case compiler::AccessMode::kLoad:
      return TryBuildElementLoadOnJSArrayOrJSObject(
          object, index_object,
          base::VectorOf(access_info.lookup_start_object_maps()),
          access_info.elements_kind(), keyed_mode.load_mode());
    case compiler::AccessMode::kStoreInLiteral:
    case compiler::AccessMode::kStore: {
      base::Vector<const compiler::MapRef> maps =
          base::VectorOf(access_info.lookup_start_object_maps());
      ElementsKind elements_kind = access_info.elements_kind();
      return TryBuildElementStoreOnJSArrayOrJSObject(object, index_object,
                                                     GetAccumulator(), maps,
                                                     elements_kind, keyed_mode);
    }
    default:
      // TODO(victorgomes): Implement more access types.
      return ReduceResult::Fail();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildElementAccess(
    ValueNode* object, ValueNode* index_object,
    compiler::ElementAccessFeedback const& feedback,
    compiler::FeedbackSource const& feedback_source,
    GenericAccessFunc&& build_generic_access) {
  const compiler::KeyedAccessMode& keyed_mode = feedback.keyed_mode();
  // Check for the megamorphic case.
  if (feedback.transition_groups().empty()) {
    if (keyed_mode.access_mode() == compiler::AccessMode::kLoad) {
      return BuildCallBuiltin<Builtin::kKeyedLoadIC_Megamorphic>(
          {GetTaggedValue(object), GetTaggedValue(index_object)},
          feedback_source);
    } else if (keyed_mode.access_mode() == compiler::AccessMode::kStore) {
      return BuildCallBuiltin<Builtin::kKeyedStoreIC_Megamorphic>(
          {GetTaggedValue(object), GetTaggedValue(index_object),
           GetTaggedValue(GetAccumulator())},
          feedback_source);
    }
    return ReduceResult::Fail();
  }

  NodeInfo* object_info = known_node_aspects().TryGetInfoFor(object);
  compiler::ElementAccessFeedback refined_feedback =
      object_info && object_info->possible_maps_are_known()
          ? feedback.Refine(broker(), object_info->possible_maps())
          : feedback;

  if (refined_feedback.HasOnlyStringMaps(broker())) {
    return TryBuildElementAccessOnString(object, index_object, keyed_mode);
  }

  compiler::AccessInfoFactory access_info_factory(broker(), zone());
  ZoneVector<compiler::ElementAccessInfo> access_infos(zone());
  if (!access_info_factory.ComputeElementAccessInfos(refined_feedback,
                                                     &access_infos) ||
      access_infos.empty()) {
    return ReduceResult::Fail();
  }

  // TODO(leszeks): This is copied without changes from TurboFan's native
  // context specialization. We should figure out a way to share this code.
  //
  // For holey stores or growing stores, we need to check that the prototype
  // chain contains no setters for elements, and we need to guard those checks
  // via code dependencies on the relevant prototype maps.
  if (keyed_mode.access_mode() == compiler::AccessMode::kStore) {
    // TODO(v8:7700): We could have a fast path here, that checks for the
    // common case of Array or Object prototype only and therefore avoids
    // the zone allocation of this vector.
    ZoneVector<compiler::MapRef> prototype_maps(zone());
    for (compiler::ElementAccessInfo const& access_info : access_infos) {
      for (compiler::MapRef receiver_map :
           access_info.lookup_start_object_maps()) {
        // If the {receiver_map} has a prototype and its elements backing
        // store is either holey, or we have a potentially growing store,
        // then we need to check that all prototypes have stable maps with
        // with no element accessors and no throwing behavior for elements (and
        // we need to guard against changes to that below).
        if ((IsHoleyOrDictionaryElementsKind(receiver_map.elements_kind()) ||
             StoreModeCanGrow(refined_feedback.keyed_mode().store_mode())) &&
            !receiver_map.PrototypesElementsDoNotHaveAccessorsOrThrow(
                broker(), &prototype_maps)) {
          return ReduceResult::Fail();
        }

        // TODO(v8:12547): Support writing to objects in shared space, which
        // need a write barrier that calls Object::Share to ensure the RHS is
        // shared.
        if (InstanceTypeChecker::IsAlwaysSharedSpaceJSObject(
                receiver_map.instance_type())) {
          return ReduceResult::Fail();
        }
      }
    }
    for (compiler::MapRef prototype_map : prototype_maps) {
      broker()->dependencies()->DependOnStableMap(prototype_map);
    }
  }

  // Check for monomorphic case.
  if (access_infos.size() == 1) {
    compiler::ElementAccessInfo const& access_info = access_infos.front();
    // TODO(victorgomes): Support RAB/GSAB backed typed arrays.
    if (IsRabGsabTypedArrayElementsKind(access_info.elements_kind())) {
      return ReduceResult::Fail();
    }

    if (!access_info.transition_sources().empty()) {
      compiler::MapRef transition_target =
          access_info.lookup_start_object_maps().front();
      const ZoneVector<compiler::MapRef>& transition_sources =
          access_info.transition_sources();

      // There are no transitions in heap number maps. If `object` is a SMI, we
      // would anyway fail the transition and deopt later.
      DCHECK_NE(transition_target.instance_type(),
                InstanceType::HEAP_NUMBER_TYPE);
#ifdef DEBUG
      for (auto& transition_source : transition_sources) {
        DCHECK_NE(transition_source.instance_type(),
                  InstanceType::HEAP_NUMBER_TYPE);
      }
#endif  // DEBUG

      BuildCheckHeapObject(object);
      ValueNode* object_map =
          BuildLoadTaggedField(object, HeapObject::kMapOffset);

      RETURN_IF_ABORT(BuildTransitionElementsKindOrCheckMap(
          object, object_map, transition_sources, transition_target));
    } else {
      RETURN_IF_ABORT(BuildCheckMaps(
          object, base::VectorOf(access_info.lookup_start_object_maps())));
    }
    if (IsTypedArrayElementsKind(access_info.elements_kind())) {
      return TryBuildElementAccessOnTypedArray(object, index_object,
                                               access_info, keyed_mode);
    }
    return TryBuildElementAccessOnJSArrayOrJSObject(object, index_object,
                                                    access_info, keyed_mode);
  } else {
    return TryBuildPolymorphicElementAccess(object, index_object, keyed_mode,
                                            access_infos, build_generic_access);
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildPolymorphicElementAccess(
    ValueNode* object, ValueNode* index_object,
    const compiler::KeyedAccessMode& keyed_mode,
    const ZoneVector<compiler::ElementAccessInfo>& access_infos,
    GenericAccessFunc&& build_generic_access) {
  if (keyed_mode.access_mode() == compiler::AccessMode::kLoad &&
      LoadModeHandlesOOB(keyed_mode.load_mode())) {
    // TODO(victorgomes): Handle OOB mode.
    return ReduceResult::Fail();
  }

  const bool is_any_store = compiler::IsAnyStore(keyed_mode.access_mode());
  const int access_info_count = static_cast<int>(access_infos.size());
  // Stores don't return a value, so we don't need a variable for the result.
  MaglevSubGraphBuilder sub_graph(this, is_any_store ? 0 : 1);
  std::optional<MaglevSubGraphBuilder::Variable> ret_val;
  std::optional<MaglevSubGraphBuilder::Label> done;
  std::optional<MaglevSubGraphBuilder::Label> generic_access;

  BuildCheckHeapObject(object);
  ValueNode* object_map = BuildLoadTaggedField(object, HeapObject::kMapOffset);

  // TODO(pthier): We could do better here than just emitting code for each map,
  // as many different maps can produce the exact samce code (e.g. TypedArray
  // access for Uint16/Uint32/Int16/Int32/...).
  for (int i = 0; i < access_info_count; i++) {
    compiler::ElementAccessInfo const& access_info = access_infos[i];
    std::optional<MaglevSubGraphBuilder::Label> check_next_map;
    const bool handle_transitions = !access_info.transition_sources().empty();
    ReduceResult map_check_result;
    if (i == access_info_count - 1) {
      if (handle_transitions) {
        compiler::MapRef transition_target =
            access_info.lookup_start_object_maps().front();
        map_check_result = BuildTransitionElementsKindOrCheckMap(
            object, object_map, access_info.transition_sources(),
            transition_target);
      } else {
        map_check_result = BuildCheckMaps(
            object, base::VectorOf(access_info.lookup_start_object_maps()),
            object_map);
      }
    } else {
      if (handle_transitions) {
        compiler::MapRef transition_target =
            access_info.lookup_start_object_maps().front();
        map_check_result = BuildTransitionElementsKindAndCompareMaps(
            object, object_map, access_info.transition_sources(),
            transition_target, &sub_graph, check_next_map);
      } else {
        map_check_result = BuildCompareMaps(
            object, object_map,
            base::VectorOf(access_info.lookup_start_object_maps()), &sub_graph,
            check_next_map);
      }
    }
    if (map_check_result.IsDoneWithAbort()) {
      // We know from known possible maps that this branch is not reachable,
      // so don't emit any code for it.
      continue;
    }
    ReduceResult result;
    // TODO(victorgomes): Support RAB/GSAB backed typed arrays.
    if (IsRabGsabTypedArrayElementsKind(access_info.elements_kind())) {
      result = ReduceResult::Fail();
    } else if (IsTypedArrayElementsKind(access_info.elements_kind())) {
      result = TryBuildElementAccessOnTypedArray(object, index_object,
                                                 access_info, keyed_mode);
    } else {
      result = TryBuildElementAccessOnJSArrayOrJSObject(
          object, index_object, access_info, keyed_mode);
    }

    switch (result.kind()) {
      case ReduceResult::kDoneWithValue:
      case ReduceResult::kDoneWithoutValue:
        DCHECK_EQ(result.HasValue(), !is_any_store);
        if (!done.has_value()) {
          // We initialize the label {done} lazily on the first possible path.
          // If no possible path exists, it is guaranteed that BuildCheckMaps
          // emitted an unconditional deopt and we return DoneWithAbort at the
          // end. We need one extra predecessor to jump from the generic case.
          const int possible_predecessors = access_info_count - i + 1;
          if (is_any_store) {
            done.emplace(&sub_graph, possible_predecessors);
          } else {
            ret_val.emplace(0);
            done.emplace(
                &sub_graph, possible_predecessors,
                std::initializer_list<MaglevSubGraphBuilder::Variable*>{
                    &*ret_val});
          }
        }
        if (!is_any_store) {
          sub_graph.set(*ret_val, result.value());
        }
        sub_graph.Goto(&*done);
        break;
      case ReduceResult::kFail:
        if (!generic_access.has_value()) {
          // Conservatively assume that all remaining branches can go into the
          // generic path, as we have to initialize the predecessors upfront.
          // TODO(pthier): Find a better way to do that.
          generic_access.emplace(&sub_graph, access_info_count - i);
        }
        sub_graph.Goto(&*generic_access);
        break;
      case ReduceResult::kDoneWithAbort:
        break;
      case ReduceResult::kNone:
        UNREACHABLE();
    }
    if (check_next_map.has_value()) {
      sub_graph.Bind(&*check_next_map);
    }
  }
  if (generic_access.has_value() &&
      !sub_graph.TrimPredecessorsAndBind(&*generic_access).IsDoneWithAbort()) {
    ReduceResult generic_result = build_generic_access();
    DCHECK(generic_result.IsDone());
    DCHECK_EQ(generic_result.IsDoneWithValue(), !is_any_store);
    if (!done.has_value()) {
      return is_any_store ? ReduceResult::Done() : generic_result.value();
    }
    if (!is_any_store) {
      sub_graph.set(*ret_val, generic_result.value());
    }
    sub_graph.Goto(&*done);
  }
  if (done.has_value()) {
    RETURN_IF_ABORT(sub_graph.TrimPredecessorsAndBind(&*done));
    return is_any_store ? ReduceResult::Done() : sub_graph.get(*ret_val);
  } else {
    return ReduceResult::DoneWithAbort();
  }
}

template <typename GenericAccessFunc>
ReduceResult MaglevGraphBuilder::TryBuildPolymorphicPropertyAccess(
    ValueNode* receiver, ValueNode* lookup_start_object,
    compiler::NamedAccessFeedback const& feedback,
    compiler::AccessMode access_mode,
    const ZoneVector<compiler::PropertyAccessInfo>& access_infos,
    GenericAccessFunc&& build_generic_access) {
  const bool is_any_store = compiler::IsAnyStore(access_mode);
  const int access_info_count = static_cast<int>(access_infos.size());
  int number_map_index = -1;

  bool needs_migration = false;
  for (int i = 0; i < access_info_count; i++) {
    compiler::PropertyAccessInfo const& access_info = access_infos[i];
    DCHECK(!access_info.IsInvalid());
    for (compiler::MapRef map : access_info.lookup_start_object_maps()) {
      if (map.is_migration_target()) {
        needs_migration = true;
      }
      if (map.IsHeapNumberMap()) {
        GetOrCreateInfoFor(lookup_start_object);
        base::SmallVector<compiler::MapRef, 1> known_maps = {map};
        KnownMapsMerger merger(broker(), zone(), base::VectorOf(known_maps));
        merger.IntersectWithKnownNodeAspects(lookup_start_object,
                                             known_node_aspects());
        if (!merger.intersect_set().is_empty()) {
          DCHECK_EQ(number_map_index, -1);
          number_map_index = i;
        }
      }
    }
  }

  // Stores don't return a value, so we don't need a variable for the result.
  MaglevSubGraphBuilder sub_graph(this, is_any_store ? 0 : 1);
  std::optional<MaglevSubGraphBuilder::Variable> ret_val;
  std::optional<MaglevSubGraphBuilder::Label> done;
  std::optional<MaglevSubGraphBuilder::Label> is_number;
  std::optional<MaglevSubGraphBuilder::Label> generic_access;

  if (number_map_index >= 0) {
    is_number.emplace(&sub_graph, 2);
    sub_graph.GotoIfTrue<BranchIfSmi>(&*is_number, {lookup_start_object});
  } else {
    BuildCheckHeapObject(lookup_start_object);
  }
  ValueNode* lookup_start_object_map =
      BuildLoadTaggedField(lookup_start_object, HeapObject::kMapOffset);

  if (needs_migration &&
      !v8_flags.maglev_skip_migration_check_for_polymorphic_access) {
    // TODO(marja, v8:7700): Try migrating only if all comparisons failed.
    // TODO(marja, v8:7700): Investigate making polymoprhic map comparison (with
    // migration) a control node (like switch).
    lookup_start_object_map = AddNewNode<MigrateMapIfNeeded>(
        {lookup_start_object_map, lookup_start_object});
  }

  for (int i = 0; i < access_info_count; i++) {
    compiler::PropertyAccessInfo const& access_info = access_infos[i];
    std::optional<MaglevSubGraphBuilder::Label> check_next_map;
    ReduceResult map_check_result;
    const auto& maps = access_info.lookup_start_object_maps();
    if (i == access_info_count - 1) {
      map_check_result =
          BuildCheckMaps(lookup_start_object, base::VectorOf(maps));
    } else {
      map_check_result =
          BuildCompareMaps(lookup_start_object, lookup_start_object_map,
                           base::VectorOf(maps), &sub_graph, check_next_map);
    }
    if (map_check_result.IsDoneWithAbort()) {
      // We know from known possible maps that this branch is not reachable,
      // so don't emit any code for it.
      continue;
    }
    if (i == number_map_index) {
      DCHECK(is_number.has_value());
      sub_graph.Goto(&*is_number);
      sub_graph.Bind(&*is_number);
    }

    ReduceResult result;
    if (is_any_store) {
      result = TryBuildPropertyStore(receiver, lookup_start_object,
                                    
"""


```
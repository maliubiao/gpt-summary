Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding & Context:**

* **File Name:** `v8/src/compiler/js-create-lowering.cc`. The `.cc` extension strongly indicates C++ source code within the V8 JavaScript engine. The path suggests it's part of the compiler, specifically related to "lowering" and "JS create" operations. Lowering in compilers generally refers to transforming high-level operations into more primitive, machine-like ones. "JS create" likely refers to the creation of JavaScript objects.
* **Goal:** The request asks for the functionality of the code, its relation to JavaScript, examples, logic, error scenarios, and a final summary.
* **Instruction Check:** Pay attention to the specific instructions, especially the conditions about `.tq` files (not applicable here), the JavaScript relationship, examples, logic, errors, and the part number (3/3).

**2. High-Level Overview of the Code:**

* **Class `JSCreateLowering`:** This is the central class. It has methods like `ReduceJSCreateObject`, `ReduceJSCreateStringWrapper`, `TryAllocateArguments`, `AllocateElements`, and `TryAllocateFastLiteral`. The prefix "Reduce" suggests these methods are involved in the lowering process, likely handling specific JavaScript creation operations. "Allocate" clearly indicates memory allocation.
* **Key V8 Concepts:**  The code uses V8-specific types and classes: `Node`, `JSOpcode`, `MapRef`, `AllocationBuilder`, `FrameState`, `SharedFunctionInfoRef`, `ElementsKind`, `JSObjectRef`, `FixedArrayRef`, `HeapNumber`, etc. Recognizing these is crucial to understanding the code's purpose. If unfamiliar with some, a quick search for "V8 [TypeName]" can provide context.
* **Focus on `AllocationBuilder`:** This class appears frequently, suggesting that a core responsibility of this code is managing the allocation of memory for JavaScript objects.

**3. Analyzing Individual Methods:**

* **`ReduceJSCreateObject`:**  This function seems to handle the creation of generic JavaScript objects. It allocates memory, initializes the object's map, properties, and elements. The loop that initializes with `undefined` is a key detail.
* **`ReduceJSCreateStringWrapper`:** This is specific to creating `String` objects. It allocates a `JSPrimitiveWrapper` and stores the primitive string value within it.
* **`TryAllocateArguments` (and variations):** These methods deal with creating the `arguments` object within functions. They handle both simple and aliased (mapped) arguments, interacting with `FrameState` to get argument values. The logic for aliased arguments is more complex, involving context and parameter mapping.
* **`AllocateElements`:** This function is responsible for allocating the backing storage for JavaScript array elements (either regular or double arrays).
* **`TryAllocateFastLiteral` (and `TryAllocateFastLiteralElements`):** These are optimizations for creating object and array literals. They attempt to directly copy data from a "boilerplate" object, potentially saving allocation time. This is a key performance optimization.
* **`AllocateLiteralRegExp`:** This handles the creation of regular expression objects. The `static_assert` calls are for ensuring the layout of `JSRegExp` remains consistent.

**4. Connecting to JavaScript Functionality:**

* **Object Creation:** `ReduceJSCreateObject` directly relates to the `new Object()` or `{}` syntax in JavaScript.
* **String Creation:** `ReduceJSCreateStringWrapper` is used when creating `String` objects, like `new String("hello")`.
* **`arguments` Object:** `TryAllocateArguments` is fundamental to how the `arguments` object works inside functions.
* **Array Creation:** `AllocateElements` is used when creating arrays like `[]` or `new Array(5)`.
* **Object/Array Literals:** `TryAllocateFastLiteral` is an optimization for `{}`, `[]`, and nested literals.
* **Regular Expressions:** `AllocateLiteralRegExp` is used for creating `/pattern/` literals or `new RegExp("pattern")`.

**5. Identifying Logic and Assumptions:**

* **Memory Layout:** The code makes assumptions about the memory layout of JavaScript objects (e.g., offsets for map, properties, elements). These are V8 implementation details.
* **Allocation Strategy:** The code uses `AllocationBuilder`, indicating a specific allocation strategy within V8.
* **Optimization:** The "fast literal" allocation is an optimization based on the idea of copying from a template.

**6. Considering User Errors:**

* **`arguments` object and strict mode:**  Modifying `arguments` in strict mode can lead to errors. The aliasing logic in `TryAllocateAliasedArguments` is relevant here.
* **Large array allocations:**  While not directly shown as an error *handling* mechanism, the code has checks related to `kMaxRegularHeapObjectSize`, suggesting potential issues with very large allocations.

**7. Structuring the Output:**

* **Functionality:** Summarize the main purpose of the file (lowering JS create operations) and then detail the functionality of each key method.
* **Torque:**  Address the `.tq` check explicitly (it's not a Torque file).
* **JavaScript Relationship:** Provide concrete JavaScript examples for each major function.
* **Logic and I/O:**  Give simplified examples of inputs and outputs, focusing on the transformation from a high-level JS operation to lower-level allocation steps.
* **Common Errors:**  Illustrate common programming errors related to the concepts handled in the code.
* **Summary:**  Provide a concise overview of the file's role in V8.

**8. Refinement and Clarity:**

* **Use precise terminology:**  Refer to V8 concepts by their correct names.
* **Explain complex parts:**  For instance, clarify the concept of "lowering" and the purpose of `AllocationBuilder`.
* **Keep it concise:** Avoid overly technical jargon where possible, or explain it briefly.
* **Ensure the examples are clear and directly relevant.**

By following this structured approach, including examining the code, identifying key concepts, and connecting them to JavaScript behavior, a comprehensive and accurate analysis of the `js-create-lowering.cc` file can be achieved.
这是对V8源代码文件 `v8/src/compiler/js-create-lowering.cc` 功能的详细分析，作为第三部分进行总结。

**归纳 `v8/src/compiler/js-create-lowering.cc` 的功能:**

`v8/src/compiler/js-create-lowering.cc` 文件的主要职责是在 V8 编译器的**简化阶段 (Simplified phase)**，将高级的 JavaScript 对象创建操作 (例如 `new Object()`, 字面量 `{}`，`new String()`, `arguments` 对象，数组字面量 `[]`, 正则表达式字面量 `/.../`) **降低 (lower)** 为更底层的、更接近机器指令的操作。这个过程通常涉及到：

1. **内存分配:**  为即将创建的 JavaScript 对象在堆上分配内存。
2. **对象布局初始化:** 设置对象的元数据，如 `Map` (描述对象的结构和类型)，属性和元素的存储空间。
3. **属性和元素的初始化:**  根据创建操作的不同，初始化对象的属性和元素。

**核心功能模块和对应操作:**

* **`ReduceJSCreateObject(Node* node)`:**  处理通用的 JavaScript 对象创建，例如 `new Object()` 或 `{}`。它会分配内存，设置 `Map`，并将属性和元素初始化为空。
* **`ReduceJSCreateStringWrapper(Node* node)`:** 处理 `new String()` 创建的字符串包装对象。它会分配 `JSPrimitiveWrapper` 实例，并存储原始的字符串值。
* **`TryAllocateArguments(...)` 系列函数:**  处理函数内部 `arguments` 对象的创建。根据函数是否使用了参数别名（mapped arguments）以及参数的静态信息，采取不同的分配和初始化策略。
* **`AllocateElements(...)`:**  专门用于分配 JavaScript 数组的元素存储空间 (FixedArray 或 FixedDoubleArray)。可以根据预期的容量和元素类型（例如，是否是双精度浮点数）进行分配。
* **`TryAllocateFastLiteral(...)` 和 `TryAllocateFastLiteralElements(...)`:**  用于优化对象和数组字面量的创建。如果可能，它会尝试直接从一个“样板 (boilerplate)” 对象复制数据，避免逐个属性或元素的分配和初始化，从而提高性能。
* **`AllocateLiteralRegExp(...)`:** 处理正则表达式字面量 `/.../` 的创建。它会分配 `JSRegExp` 对象并初始化其内部结构，包括正则表达式的数据、源代码和标志。

**与 JavaScript 功能的关系 (总结):**

该文件中的代码直接对应于 JavaScript 中各种对象创建的语法和语义。编译器在编译 JavaScript 代码时，会识别这些创建操作，并使用 `js-create-lowering.cc` 中的函数将其转换为更底层的操作。

**代码逻辑推理 (总结):**

假设 JavaScript 代码中有一个对象字面量 `const obj = { a: 1, b: "hello" };`。

1. 编译器会识别出这是一个对象字面量创建操作。
2. `TryAllocateFastLiteral` 可能会被调用，尝试从一个预先存在的类似结构的对象（如果有）复制信息。
3. 如果无法进行快速字面量分配，则会调用 `ReduceJSCreateObject` 分配一个新的 `JSObject`。
4. 分配后，会设置该对象的 `Map`，指示其结构。
5. 接着，会为属性 "a" 和 "b" 分配存储空间。
6. 最后，会将值 `1` 和 `"hello"` 存储到相应的属性位置。

**用户常见的编程错误 (总结):**

虽然 `js-create-lowering.cc` 本身是编译器内部的代码，但它处理的 JavaScript 创建操作与用户常见的编程错误息息相关：

* **过度依赖 `arguments` 对象:** 在非严格模式下，修改 `arguments` 对象会影响到函数的形式参数，这可能会导致意想不到的行为和难以调试的错误。`TryAllocateAliasedArguments` 的逻辑就与这种行为有关。
* **创建过多的临时对象:**  频繁地创建和销毁大量临时对象会导致性能问题和垃圾回收压力。理解对象是如何被分配和初始化的有助于编写更高效的代码。
* **对性能敏感的代码中，使用动态的属性添加:**  虽然 JavaScript 的动态性很强，但在性能关键区域，预先定义好对象的结构（例如，在构造函数中初始化所有属性）可以帮助 V8 优化对象的创建和访问。`TryAllocateFastLiteral` 就是 V8 为了优化常见情况而做的努力。

**总结:**

`v8/src/compiler/js-create-lowering.cc` 是 V8 编译器中至关重要的一个组成部分，它负责将高级的 JavaScript 对象创建操作转换为更底层的内存分配和初始化操作。理解这个文件的功能有助于深入了解 V8 引擎是如何高效地创建和管理 JavaScript 对象的，并能帮助开发者编写更优化的 JavaScript 代码。它处理了多种对象创建场景，包括普通对象、字符串包装对象、`arguments` 对象、数组和正则表达式，并且包含了一些性能优化的策略，例如快速字面量分配。

Prompt: 
```
这是目录为v8/src/compiler/js-create-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-create-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  // Initialize Object fields.
  Node* undefined = jsgraph()->UndefinedConstant();
  for (int offset = JSObject::kHeaderSize; offset < instance_size;
       offset += kTaggedSize) {
    a.Store(AccessBuilder::ForJSObjectOffset(offset, kNoWriteBarrier),
            undefined);
  }
  Node* value = effect = a.Finish();

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCreateLowering::ReduceJSCreateStringWrapper(Node* node) {
  DCHECK_EQ(IrOpcode::kJSCreateStringWrapper, node->opcode());
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* primitive_value = NodeProperties::GetValueInput(node, 0);

  MapRef map = native_context().string_function(broker()).initial_map(broker());
  DCHECK_EQ(map.instance_size(), JSPrimitiveWrapper::kHeaderSize);
  CHECK(!map.IsInobjectSlackTrackingInProgress());

  // Emit code to allocate the JSPrimitiveWrapper instance for the given {map}.
  AllocationBuilder a(jsgraph(), broker(), effect, graph()->start());
  a.Allocate(JSPrimitiveWrapper::kHeaderSize, AllocationType::kYoung,
             Type::StringWrapper());
  a.Store(AccessBuilder::ForMap(), map);
  a.Store(AccessBuilder::ForJSObjectPropertiesOrHash(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSObjectElements(),
          jsgraph()->EmptyFixedArrayConstant());
  a.Store(AccessBuilder::ForJSPrimitiveWrapperValue(), primitive_value);
  a.FinishAndChange(node);
  return Changed(node);
}

// Helper that allocates a FixedArray holding argument values recorded in the
// given {frame_state}. Serves as backing store for JSCreateArguments nodes.
Node* JSCreateLowering::TryAllocateArguments(Node* effect, Node* control,
                                             FrameState frame_state) {
  FrameStateInfo state_info = frame_state.frame_state_info();
  int argument_count = state_info.parameter_count() - 1;  // Minus receiver.
  if (argument_count == 0) return jsgraph()->EmptyFixedArrayConstant();

  // Prepare an iterator over argument values recorded in the frame state.
  Node* const parameters = frame_state.parameters();
  StateValuesAccess parameters_access(parameters);
  auto parameters_it = parameters_access.begin_without_receiver();

  // Actually allocate the backing store.
  MapRef fixed_array_map = broker()->fixed_array_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  if (!ab.CanAllocateArray(argument_count, fixed_array_map)) {
    return nullptr;
  }
  ab.AllocateArray(argument_count, fixed_array_map);
  for (int i = 0; i < argument_count; ++i, ++parameters_it) {
    DCHECK_NOT_NULL(parameters_it.node());
    ab.Store(AccessBuilder::ForFixedArrayElement(),
             jsgraph()->ConstantNoHole(i), parameters_it.node());
  }
  return ab.Finish();
}

// Helper that allocates a FixedArray holding argument values recorded in the
// given {frame_state}. Serves as backing store for JSCreateArguments nodes.
Node* JSCreateLowering::TryAllocateRestArguments(Node* effect, Node* control,
                                                 FrameState frame_state,
                                                 int start_index) {
  FrameStateInfo state_info = frame_state.frame_state_info();
  int argument_count = state_info.parameter_count() - 1;  // Minus receiver.
  int num_elements = std::max(0, argument_count - start_index);
  if (num_elements == 0) return jsgraph()->EmptyFixedArrayConstant();

  // Prepare an iterator over argument values recorded in the frame state.
  Node* const parameters = frame_state.parameters();
  StateValuesAccess parameters_access(parameters);
  auto parameters_it =
      parameters_access.begin_without_receiver_and_skip(start_index);

  // Actually allocate the backing store.
  MapRef fixed_array_map = broker()->fixed_array_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  if (!ab.CanAllocateArray(num_elements, fixed_array_map)) {
    return nullptr;
  }
  ab.AllocateArray(num_elements, fixed_array_map);
  for (int i = 0; i < num_elements; ++i, ++parameters_it) {
    DCHECK_NOT_NULL(parameters_it.node());
    ab.Store(AccessBuilder::ForFixedArrayElement(),
             jsgraph()->ConstantNoHole(i), parameters_it.node());
  }
  return ab.Finish();
}

// Helper that allocates a FixedArray serving as a parameter map for values
// recorded in the given {frame_state}. Some elements map to slots within the
// given {context}. Serves as backing store for JSCreateArguments nodes.
Node* JSCreateLowering::TryAllocateAliasedArguments(
    Node* effect, Node* control, FrameState frame_state, Node* context,
    SharedFunctionInfoRef shared, bool* has_aliased_arguments) {
  FrameStateInfo state_info = frame_state.frame_state_info();
  int argument_count = state_info.parameter_count() - 1;  // Minus receiver.
  if (argument_count == 0) return jsgraph()->EmptyFixedArrayConstant();

  // If there is no aliasing, the arguments object elements are not special in
  // any way, we can just return an unmapped backing store instead.
  int parameter_count =
      shared.internal_formal_parameter_count_without_receiver();
  if (parameter_count == 0) {
    return TryAllocateArguments(effect, control, frame_state);
  }

  // Calculate number of argument values being aliased/mapped.
  int mapped_count = std::min(argument_count, parameter_count);
  *has_aliased_arguments = true;

  MapRef sloppy_arguments_elements_map =
      broker()->sloppy_arguments_elements_map();
  AllocationBuilder ab(jsgraph(), broker(), effect, control);

  if (!ab.CanAllocateSloppyArgumentElements(mapped_count,
                                            sloppy_arguments_elements_map)) {
    return nullptr;
  }

  MapRef fixed_array_map = broker()->fixed_array_map();
  if (!ab.CanAllocateArray(argument_count, fixed_array_map)) {
    return nullptr;
  }

  // Prepare an iterator over argument values recorded in the frame state.
  Node* const parameters = frame_state.parameters();
  StateValuesAccess parameters_access(parameters);
  auto parameters_it =
      parameters_access.begin_without_receiver_and_skip(mapped_count);

  // The unmapped argument values recorded in the frame state are stored yet
  // another indirection away and then linked into the parameter map below,
  // whereas mapped argument values are replaced with a hole instead.
  ab.AllocateArray(argument_count, fixed_array_map);
  for (int i = 0; i < mapped_count; ++i) {
    ab.Store(AccessBuilder::ForFixedArrayElement(),
             jsgraph()->ConstantNoHole(i), jsgraph()->TheHoleConstant());
  }
  for (int i = mapped_count; i < argument_count; ++i, ++parameters_it) {
    DCHECK_NOT_NULL(parameters_it.node());
    ab.Store(AccessBuilder::ForFixedArrayElement(),
             jsgraph()->ConstantNoHole(i), parameters_it.node());
  }
  Node* arguments = ab.Finish();

  // Actually allocate the backing store.
  AllocationBuilder a(jsgraph(), broker(), arguments, control);
  a.AllocateSloppyArgumentElements(mapped_count, sloppy_arguments_elements_map);
  a.Store(AccessBuilder::ForSloppyArgumentsElementsContext(), context);
  a.Store(AccessBuilder::ForSloppyArgumentsElementsArguments(), arguments);
  for (int i = 0; i < mapped_count; ++i) {
    int idx = shared.context_parameters_start() + parameter_count - 1 - i;
    a.Store(AccessBuilder::ForSloppyArgumentsElementsMappedEntry(),
            jsgraph()->ConstantNoHole(i), jsgraph()->ConstantNoHole(idx));
  }
  return a.Finish();
}

// Helper that allocates a FixedArray serving as a parameter map for values
// unknown at compile-time, the true {arguments_length} and {arguments_frame}
// values can only be determined dynamically at run-time and are provided.
// Serves as backing store for JSCreateArguments nodes.
Node* JSCreateLowering::TryAllocateAliasedArguments(
    Node* effect, Node* control, Node* context, Node* arguments_length,
    SharedFunctionInfoRef shared, bool* has_aliased_arguments) {
  // If there is no aliasing, the arguments object elements are not
  // special in any way, we can just return an unmapped backing store.
  int parameter_count =
      shared.internal_formal_parameter_count_without_receiver();
  if (parameter_count == 0) {
    return graph()->NewNode(
        simplified()->NewArgumentsElements(
            CreateArgumentsType::kUnmappedArguments, parameter_count),
        arguments_length, effect);
  }

  int mapped_count = parameter_count;
  MapRef sloppy_arguments_elements_map =
      broker()->sloppy_arguments_elements_map();

  {
    AllocationBuilder ab(jsgraph(), broker(), effect, control);
    if (!ab.CanAllocateSloppyArgumentElements(mapped_count,
                                              sloppy_arguments_elements_map)) {
      return nullptr;
    }
  }

  // From here on we are going to allocate a mapped (aka. aliased) elements
  // backing store. We do not statically know how many arguments exist, but
  // dynamically selecting the hole for some of the "mapped" elements allows
  // using a static shape for the parameter map.
  *has_aliased_arguments = true;

  // The unmapped argument values are stored yet another indirection away and
  // then linked into the parameter map below, whereas mapped argument values
  // (i.e. the first {mapped_count} elements) are replaced with a hole instead.
  Node* arguments = effect =
      graph()->NewNode(simplified()->NewArgumentsElements(
                           CreateArgumentsType::kMappedArguments, mapped_count),
                       arguments_length, effect);

  // Actually allocate the backing store.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.AllocateSloppyArgumentElements(mapped_count, sloppy_arguments_elements_map);
  a.Store(AccessBuilder::ForSloppyArgumentsElementsContext(), context);
  a.Store(AccessBuilder::ForSloppyArgumentsElementsArguments(), arguments);
  for (int i = 0; i < mapped_count; ++i) {
    int idx = shared.context_parameters_start() + parameter_count - 1 - i;
    Node* value = graph()->NewNode(
        common()->Select(MachineRepresentation::kTagged),
        graph()->NewNode(simplified()->NumberLessThan(),
                         jsgraph()->ConstantNoHole(i), arguments_length),
        jsgraph()->ConstantNoHole(idx), jsgraph()->TheHoleConstant());
    a.Store(AccessBuilder::ForSloppyArgumentsElementsMappedEntry(),
            jsgraph()->ConstantNoHole(i), value);
  }
  return a.Finish();
}

Node* JSCreateLowering::AllocateElements(Node* effect, Node* control,
                                         ElementsKind elements_kind,
                                         int capacity,
                                         AllocationType allocation) {
  DCHECK_LE(1, capacity);
  DCHECK_LE(capacity, JSArray::kInitialMaxFastElementArray);

  Handle<Map> elements_map = IsDoubleElementsKind(elements_kind)
                                 ? factory()->fixed_double_array_map()
                                 : factory()->fixed_array_map();
  ElementAccess access = IsDoubleElementsKind(elements_kind)
                             ? AccessBuilder::ForFixedDoubleArrayElement()
                             : AccessBuilder::ForFixedArrayElement();
  Node* value = jsgraph()->TheHoleConstant();

  // Actually allocate the backing store.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.AllocateArray(capacity, MakeRef(broker(), elements_map), allocation);
  for (int i = 0; i < capacity; ++i) {
    Node* index = jsgraph()->ConstantNoHole(i);
    a.Store(access, index, value);
  }
  return a.Finish();
}

Node* JSCreateLowering::AllocateElements(Node* effect, Node* control,
                                         ElementsKind elements_kind,
                                         std::vector<Node*> const& values,
                                         AllocationType allocation) {
  int const capacity = static_cast<int>(values.size());
  DCHECK_LE(1, capacity);
  DCHECK_LE(capacity, JSArray::kInitialMaxFastElementArray);

  Handle<Map> elements_map = IsDoubleElementsKind(elements_kind)
                                 ? factory()->fixed_double_array_map()
                                 : factory()->fixed_array_map();
  ElementAccess access = IsDoubleElementsKind(elements_kind)
                             ? AccessBuilder::ForFixedDoubleArrayElement()
                             : AccessBuilder::ForFixedArrayElement();

  // Actually allocate the backing store.
  AllocationBuilder a(jsgraph(), broker(), effect, control);
  a.AllocateArray(capacity, MakeRef(broker(), elements_map), allocation);
  for (int i = 0; i < capacity; ++i) {
    Node* index = jsgraph()->ConstantNoHole(i);
    a.Store(access, index, values[i]);
  }
  return a.Finish();
}

std::optional<Node*> JSCreateLowering::TryAllocateFastLiteral(
    Node* effect, Node* control, JSObjectRef boilerplate,
    AllocationType allocation, int max_depth, int* max_properties) {
  DCHECK_GE(max_depth, 0);
  DCHECK_GE(*max_properties, 0);

  if (max_depth == 0) return {};

  // Prevent concurrent migrations of boilerplate objects.
  JSHeapBroker::BoilerplateMigrationGuardIfNeeded boilerplate_access_guard(
      broker());

  // Now that we hold the migration lock, get the current map.
  MapRef boilerplate_map = boilerplate.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  dependencies()->DependOnObjectSlotValue(boilerplate, HeapObject::kMapOffset,
                                          boilerplate_map);
  {
    OptionalMapRef current_boilerplate_map =
        boilerplate.map_direct_read(broker());
    if (!current_boilerplate_map.has_value() ||
        !current_boilerplate_map->equals(boilerplate_map)) {
      return {};
    }
  }

  // Bail out if the boilerplate map has been deprecated.  The map could of
  // course be deprecated at some point after the line below, but it's not a
  // correctness issue -- it only means the literal won't be created with the
  // most up to date map(s).
  if (boilerplate_map.is_deprecated()) return {};

  // We currently only support in-object properties.
  if (boilerplate.map(broker()).elements_kind() == DICTIONARY_ELEMENTS ||
      boilerplate.map(broker()).is_dictionary_map() ||
      !boilerplate.raw_properties_or_hash(broker()).has_value()) {
    return {};
  }
  {
    ObjectRef properties = *boilerplate.raw_properties_or_hash(broker());
    bool const empty = properties.IsSmi() ||
                       properties.equals(broker()->empty_fixed_array()) ||
                       properties.equals(broker()->empty_property_array());
    if (!empty) return {};
  }

  // Compute the in-object properties to store first (might have effects).
  ZoneVector<std::pair<FieldAccess, Node*>> inobject_fields(zone());
  inobject_fields.reserve(boilerplate_map.GetInObjectProperties());
  int const boilerplate_nof = boilerplate_map.NumberOfOwnDescriptors();
  for (InternalIndex i : InternalIndex::Range(boilerplate_nof)) {
    PropertyDetails const property_details =
        boilerplate_map.GetPropertyDetails(broker(), i);
    if (property_details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, property_details.kind());
    if ((*max_properties)-- == 0) return {};

    NameRef property_name = boilerplate_map.GetPropertyKey(broker(), i);
    FieldIndex index =
        FieldIndex::ForDetails(*boilerplate_map.object(), property_details);
    ConstFieldInfo const_field_info(boilerplate_map);
    FieldAccess access = {kTaggedBase,
                          index.offset(),
                          property_name.object(),
                          OptionalMapRef(),
                          Type::Any(),
                          MachineType::AnyTagged(),
                          kFullWriteBarrier,
                          "TryAllocateFastLiteral",
                          const_field_info};

    // Note: the use of RawInobjectPropertyAt (vs. the higher-level
    // GetOwnFastConstantDataProperty) here is necessary, since the underlying
    // value may be `uninitialized`, which the latter explicitly does not
    // support.
    OptionalObjectRef maybe_boilerplate_value =
        boilerplate.RawInobjectPropertyAt(broker(), index);
    if (!maybe_boilerplate_value.has_value()) return {};

    // Note: We don't need to take a compilation dependency verifying the value
    // of `boilerplate_value`, since boilerplate properties are constant after
    // initialization modulo map migration. We protect against concurrent map
    // migrations (other than elements kind transition, which don't affect us)
    // via the boilerplate_migration_access lock.
    ObjectRef boilerplate_value = maybe_boilerplate_value.value();

    // Uninitialized fields are marked through the `uninitialized_value` marker
    // (even for Smi representation!), or in the case of Double representation
    // through a HeapNumber containing the hole-NaN. Since Double-to-Tagged
    // representation changes are done in-place, we may even encounter these
    // HeapNumbers in Tagged representation.
    // Note that although we create nodes to write `uninitialized_value` into
    // the object, the field should be overwritten immediately with a real
    // value, and `uninitialized_value` should never be exposed to JS.
    ObjectRef uninitialized_marker = broker()->uninitialized_value();
    if (boilerplate_value.equals(uninitialized_marker) ||
        (boilerplate_value.IsHeapNumber() &&
         boilerplate_value.AsHeapNumber().value_as_bits() == kHoleNanInt64)) {
      access.const_field_info = ConstFieldInfo::None();
    }

    Node* value;
    if (boilerplate_value.IsJSObject()) {
      JSObjectRef boilerplate_object = boilerplate_value.AsJSObject();
      std::optional<Node*> maybe_value =
          TryAllocateFastLiteral(effect, control, boilerplate_object,
                                 allocation, max_depth - 1, max_properties);
      if (!maybe_value.has_value()) return {};
      value = effect = maybe_value.value();
    } else if (property_details.representation().IsDouble()) {
      double number = boilerplate_value.AsHeapNumber().value();
      // Allocate a mutable HeapNumber box and store the value into it.
      AllocationBuilder builder(jsgraph(), broker(), effect, control);
      builder.Allocate(sizeof(HeapNumber), allocation);
      builder.Store(AccessBuilder::ForMap(), broker()->heap_number_map());
      builder.Store(AccessBuilder::ForHeapNumberValue(),
                    jsgraph()->ConstantMaybeHole(number));
      value = effect = builder.Finish();
    } else {
      // It's fine to store the 'uninitialized' marker into a Smi field since
      // it will get overwritten anyways and the store's MachineType (AnyTagged)
      // is compatible with it.
      DCHECK_IMPLIES(property_details.representation().IsSmi() &&
                         !boilerplate_value.IsSmi(),
                     boilerplate_value.equals(uninitialized_marker));
      value = jsgraph()->ConstantMaybeHole(boilerplate_value, broker());
    }
    inobject_fields.push_back(std::make_pair(access, value));
  }

  // Fill slack at the end of the boilerplate object with filler maps.
  int const boilerplate_length = boilerplate_map.GetInObjectProperties();
  for (int index = static_cast<int>(inobject_fields.size());
       index < boilerplate_length; ++index) {
    DCHECK(!V8_MAP_PACKING_BOOL);
    // TODO(wenyuzhao): Fix incorrect MachineType when V8_MAP_PACKING is
    // enabled.
    FieldAccess access =
        AccessBuilder::ForJSObjectInObjectProperty(boilerplate_map, index);
    Node* value =
        jsgraph()->HeapConstantNoHole(factory()->one_pointer_filler_map());
    inobject_fields.push_back(std::make_pair(access, value));
  }

  // Setup the elements backing store.
  std::optional<Node*> maybe_elements = TryAllocateFastLiteralElements(
      effect, control, boilerplate, allocation, max_depth, max_properties);
  if (!maybe_elements.has_value()) return {};
  Node* elements = maybe_elements.value();
  if (elements->op()->EffectOutputCount() > 0) effect = elements;

  // Actually allocate and initialize the object.
  AllocationBuilder builder(jsgraph(), broker(), effect, control);
  builder.Allocate(boilerplate_map.instance_size(), allocation,
                   Type::For(boilerplate_map, broker()));
  builder.Store(AccessBuilder::ForMap(), boilerplate_map);
  builder.Store(AccessBuilder::ForJSObjectPropertiesOrHashKnownPointer(),
                jsgraph()->EmptyFixedArrayConstant());
  builder.Store(AccessBuilder::ForJSObjectElements(), elements);
  if (boilerplate.IsJSArray()) {
    JSArrayRef boilerplate_array = boilerplate.AsJSArray();
    builder.Store(AccessBuilder::ForJSArrayLength(
                      boilerplate_array.map(broker()).elements_kind()),
                  boilerplate_array.GetBoilerplateLength(broker()));
  }
  for (auto const& inobject_field : inobject_fields) {
    builder.Store(inobject_field.first, inobject_field.second);
  }
  return builder.Finish();
}

std::optional<Node*> JSCreateLowering::TryAllocateFastLiteralElements(
    Node* effect, Node* control, JSObjectRef boilerplate,
    AllocationType allocation, int max_depth, int* max_properties) {
  DCHECK_GT(max_depth, 0);
  DCHECK_GE(*max_properties, 0);

  OptionalFixedArrayBaseRef maybe_boilerplate_elements =
      boilerplate.elements(broker(), kRelaxedLoad);
  if (!maybe_boilerplate_elements.has_value()) return {};
  FixedArrayBaseRef boilerplate_elements = maybe_boilerplate_elements.value();
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  dependencies()->DependOnObjectSlotValue(
      boilerplate, JSObject::kElementsOffset, boilerplate_elements);

  // Empty or copy-on-write elements just store a constant.
  const uint32_t elements_length = boilerplate_elements.length();
  MapRef elements_map = boilerplate_elements.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  dependencies()->DependOnObjectSlotValue(boilerplate_elements,
                                          HeapObject::kMapOffset, elements_map);
  if (boilerplate_elements.length() == 0 ||
      elements_map.IsFixedCowArrayMap(broker())) {
    if (allocation == AllocationType::kOld &&
        !boilerplate.IsElementsTenured(boilerplate_elements)) {
      return {};
    }
    return jsgraph()->ConstantNoHole(boilerplate_elements, broker());
  }

  // Compute the elements to store first (might have effects).
  ZoneVector<Node*> elements_values(elements_length, zone());
  if (boilerplate_elements.IsFixedDoubleArray()) {
    uint32_t const size =
        FixedDoubleArray::SizeFor(boilerplate_elements.length());
    if (size > kMaxRegularHeapObjectSize) return {};

    FixedDoubleArrayRef elements = boilerplate_elements.AsFixedDoubleArray();
    for (uint32_t i = 0; i < elements_length; ++i) {
      Float64 value = elements.GetFromImmutableFixedDoubleArray(i);
      elements_values[i] = value.is_hole_nan()
                               ? jsgraph()->TheHoleConstant()
                               : jsgraph()->ConstantNoHole(value.get_scalar());
    }
  } else {
    FixedArrayRef elements = boilerplate_elements.AsFixedArray();
    for (uint32_t i = 0; i < elements_length; ++i) {
      if ((*max_properties)-- == 0) return {};
      OptionalObjectRef element_value = elements.TryGet(broker(), i);
      if (!element_value.has_value()) return {};
      if (element_value->IsJSObject()) {
        std::optional<Node*> object =
            TryAllocateFastLiteral(effect, control, element_value->AsJSObject(),
                                   allocation, max_depth - 1, max_properties);
        if (!object.has_value()) return {};
        elements_values[i] = effect = *object;
      } else {
        elements_values[i] =
            jsgraph()->ConstantMaybeHole(*element_value, broker());
      }
    }
  }

  // Allocate the backing store array and store the elements.
  AllocationBuilder ab(jsgraph(), broker(), effect, control);
  CHECK(ab.CanAllocateArray(elements_length, elements_map, allocation));
  ab.AllocateArray(elements_length, elements_map, allocation);
  ElementAccess const access = boilerplate_elements.IsFixedDoubleArray()
                                   ? AccessBuilder::ForFixedDoubleArrayElement()
                                   : AccessBuilder::ForFixedArrayElement();
  for (uint32_t i = 0; i < elements_length; ++i) {
    ab.Store(access, jsgraph()->ConstantNoHole(i), elements_values[i]);
  }
  return ab.Finish();
}

Node* JSCreateLowering::AllocateLiteralRegExp(
    Node* effect, Node* control, RegExpBoilerplateDescriptionRef boilerplate) {
  MapRef initial_map =
      native_context().regexp_function(broker()).initial_map(broker());

  // Sanity check that JSRegExp object layout hasn't changed.
  static_assert(JSRegExp::kDataOffset == JSObject::kHeaderSize);
  static_assert(JSRegExp::kSourceOffset == JSRegExp::kDataOffset + kTaggedSize);
  static_assert(JSRegExp::kFlagsOffset ==
                JSRegExp::kSourceOffset + kTaggedSize);
  static_assert(JSRegExp::kHeaderSize == JSRegExp::kFlagsOffset + kTaggedSize);
  static_assert(JSRegExp::kLastIndexOffset == JSRegExp::kHeaderSize);
  DCHECK_EQ(JSRegExp::Size(), JSRegExp::kLastIndexOffset + kTaggedSize);

  AllocationBuilder builder(jsgraph(), broker(), effect, control);
  builder.Allocate(JSRegExp::Size(), AllocationType::kYoung,
                   Type::For(initial_map, broker()));
  builder.Store(AccessBuilder::ForMap(), initial_map);
  builder.Store(AccessBuilder::ForJSObjectPropertiesOrHash(),
                jsgraph()->EmptyFixedArrayConstant());
  builder.Store(AccessBuilder::ForJSObjectElements(),
                jsgraph()->EmptyFixedArrayConstant());

  builder.Store(AccessBuilder::ForJSRegExpData(), boilerplate.data(broker()));
  builder.Store(AccessBuilder::ForJSRegExpSource(),
                boilerplate.source(broker()));
  builder.Store(AccessBuilder::ForJSRegExpFlags(),
                jsgraph()->SmiConstant(boilerplate.flags()));
  builder.Store(AccessBuilder::ForJSRegExpLastIndex(),
                jsgraph()->SmiConstant(JSRegExp::kInitialLastIndexValue));

  return builder.Finish();
}

Factory* JSCreateLowering::factory() const {
  return jsgraph()->isolate()->factory();
}

Graph* JSCreateLowering::graph() const { return jsgraph()->graph(); }

CommonOperatorBuilder* JSCreateLowering::common() const {
  return jsgraph()->common();
}

CompilationDependencies* JSCreateLowering::dependencies() const {
  return broker()->dependencies();
}

SimplifiedOperatorBuilder* JSCreateLowering::simplified() const {
  return jsgraph()->simplified();
}

NativeContextRef JSCreateLowering::native_context() const {
  return broker()->target_native_context();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
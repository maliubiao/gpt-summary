Response: The user wants a summary of the provided C++ code. This is the second part of a two-part file, so it likely continues the functionality described in the first part. The code deals with lowering JavaScript "create" operations to more primitive operations within the V8 compiler. Specifically, it seems to be handling the allocation and initialization of various JavaScript objects like plain objects, string wrappers, and arguments objects.

Here's a breakdown of the code's functionality:

1. **Object Creation:** Functions like `ReduceJSCreateObject` handle the low-level steps to create a new JavaScript object, including allocating memory, setting the map (object type), and initializing properties and elements.

2. **String Wrapper Creation:**  `ReduceJSCreateStringWrapper` specifically handles the creation of String wrapper objects, which are used when a primitive string is treated as an object.

3. **Arguments Object Creation:**  Several `TryAllocateArguments` overloads handle the creation of the `arguments` object within a function. This includes different strategies depending on whether the arguments are *aliased* (connected to the function's parameters) or not, and whether the number of arguments is known at compile time.

4. **Literal Object/Array Allocation Optimization:**  `TryAllocateFastLiteral` and `TryAllocateFastLiteralElements` implement optimizations for creating object and array literals. They attempt to directly allocate and initialize these objects based on a "boilerplate" object, which represents the structure of the literal. This is a significant optimization because it avoids repeated property lookups and assignments.

5. **RegExp Literal Allocation:** `AllocateLiteralRegExp` handles the creation of regular expression objects.

6. **Element Allocation:**  The `AllocateElements` functions are helper methods for creating the backing storage (FixedArrays) for JavaScript arrays.

Based on this analysis, the file's core function is to translate high-level JavaScript object creation operations into a sequence of lower-level memory allocation and initialization steps within the V8 compiler's intermediate representation.

Now let's think about JavaScript examples.

- **`ReduceJSCreateObject`**:  This relates to the simple creation of objects in JavaScript.
- **`ReduceJSCreateStringWrapper`**: This is related to situations where JavaScript implicitly or explicitly wraps a string primitive in an object.
- **`TryAllocateArguments`**:  This is directly related to the `arguments` object available inside non-arrow JavaScript functions.
- **`TryAllocateFastLiteral` / `TryAllocateFastLiteralElements`**: These are related to the creation of object and array literals.
- **`AllocateLiteralRegExp`**: This is used when creating regular expression literals.
这是文件 `v8/src/compiler/js-create-lowering.cc` 的第二部分，它延续了第一部分的功能，主要负责将高级的 JavaScript 对象创建操作（如 `new Object()`, `{}`, `new String()`, 函数的 `arguments` 对象，以及字面量对象和数组）转换为 V8 编译器内部的更底层的操作。

**总而言之，这部分代码的核心功能是：**

**低级地实现各种 JavaScript 对象的创建过程。** 它将 JavaScript 的对象创建操作分解为：

1. **分配内存:** 根据对象类型和大小分配所需的内存空间。
2. **初始化对象头部:** 设置对象的 Map (描述对象类型和布局)，properties 数组和 elements 数组（用于存储属性和元素）。
3. **初始化对象属性和元素:**  根据需要填充对象的初始属性和元素值。
4. **处理特殊对象的创建:** 针对 `String` 包装对象和 `arguments` 对象有特殊的处理逻辑。
5. **优化字面量对象的创建:**  尝试直接分配和初始化对象和数组字面量，避免重复的属性设置操作，提高性能。
6. **处理正则表达式字面量的创建:**  专门处理正则表达式对象的创建和初始化。

**与 JavaScript 功能的关系及示例:**

这部分代码直接对应着 JavaScript 中创建各种对象的方式。

**1. 普通对象创建 (`ReduceJSCreateObject`):**

```javascript
const obj1 = new Object();
const obj2 = {};
```

`ReduceJSCreateObject` 负责将这些 JavaScript 代码转换为分配内存、设置 Map、初始化 properties 和 elements 数组等底层操作。

**2. 字符串包装对象创建 (`ReduceJSCreateStringWrapper`):**

```javascript
const str = "hello";
const wrapperObj = new String(str); // 显式创建
console.log(str.length);          // 隐式创建
```

当在字符串原始值上访问属性或方法时，JavaScript 引擎会临时创建一个字符串包装对象。 `ReduceJSCreateStringWrapper`  处理 `new String()` 的情况，并可能参与处理隐式创建的包装对象。

**3. `arguments` 对象创建 (`TryAllocateArguments`, `TryAllocateRestArguments`, `TryAllocateAliasedArguments`):**

```javascript
function myFunction(a, b) {
  console.log(arguments); // arguments 对象包含了传递给函数的所有参数
}

myFunction(1, 2, 3);

function restFunction(...args) {
  console.log(args); // rest 参数
}

restFunction(4, 5, 6);
```

`TryAllocateArguments` 系列函数负责创建函数内部的 `arguments` 对象，它是一个类数组对象，包含了函数调用时传入的所有参数。 代码中区分了有别名（aliased，与形参关联）和无别名的 `arguments` 对象，以及 rest 参数的情况。

**4. 字面量对象和数组创建 (`TryAllocateFastLiteral`, `TryAllocateFastLiteralElements`):**

```javascript
const literalObj = { x: 1, y: "hello" };
const literalArray = [1, "world", true];
```

`TryAllocateFastLiteral`  尝试优化字面量对象和数组的创建。它会检查“样板”对象（boilerplate），并尝试直接分配和初始化，而不是逐个设置属性，这可以显著提高性能。

**5. 正则表达式字面量创建 (`AllocateLiteralRegExp`):**

```javascript
const regex1 = /abc/g;
const regex2 = new RegExp("def", "i");
```

`AllocateLiteralRegExp` 负责处理正则表达式字面量的创建，并初始化其内部的数据结构，如正则表达式的模式和标志。

**总结:**

`js-create-lowering.cc` 的第二部分与 JavaScript 中各种对象创建的语法和行为紧密相关。它将这些高级的 JavaScript 操作转换为 V8 虚拟机可以理解和执行的底层步骤，是 V8 编译优化管道中的重要组成部分。 通过对字面量对象等创建过程的优化，它直接影响着 JavaScript 代码的执行效率。

### 提示词
```
这是目录为v8/src/compiler/js-create-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
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
```
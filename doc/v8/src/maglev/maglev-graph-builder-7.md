Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-graph-builder.cc`.
This file seems to be part of the Maglev compiler in V8, responsible for building the graph representation of JavaScript code.

Here's a breakdown of the request and how to address it:

1. **Identify the core functionality:** Analyze the provided code snippets, focusing on the class name `MaglevGraphBuilder`, the methods called within it (e.g., `VisitToString`, `VisitCreateArrayLiteral`, `BuildInlinedAllocation`), and the operations performed (e.g., creating nodes, managing registers, handling control flow).

2. **Relate to JavaScript functionality:**  Determine how the operations in the C++ code correspond to JavaScript language features. For example, `VisitToString` clearly relates to the JavaScript `toString()` method. `VisitCreateArrayLiteral` and `VisitCreateObjectLiteral` relate to array and object literal creation in JavaScript.

3. **Provide JavaScript examples:** For the identified relationships between C++ code and JavaScript features, create simple JavaScript code snippets that demonstrate these features.

4. **Address the "part 8 of 9" instruction:**  Acknowledge this information and consider if it provides any additional context for the functionality of this specific file. Since it's part of a larger process, it likely focuses on a specific set of bytecode instructions or a particular stage of graph construction.

**Mental Sandbox:**

*   **Initial thought:** This file is about translating JavaScript bytecode into a Maglev graph.
*   **Refinement:** It seems to handle the creation of various JavaScript objects and their representations in the graph (arrays, objects, functions, etc.).
*   **Considering the "part 8 of 9":** This might be one of the later stages, dealing with object creation and manipulation, possibly after basic control flow has been established.

**Key C++ Concepts Observed:**

*   **`MaglevGraphBuilder` class:**  The central entity responsible for building the graph.
*   **`Visit...` methods:**  These seem to correspond to different JavaScript bytecode instructions.
*   **`Build...` methods:** These methods likely create nodes in the Maglev graph.
*   **`VirtualObject`:**  A representation of JavaScript objects within the graph before they are fully allocated.
*   **`InlinedAllocation`:** Represents the actual allocation of objects in memory.
*   **Feedback:** The code uses feedback (type information) to optimize object creation.
*   **Deoptimization:** Mechanisms to fall back to the interpreter if assumptions are violated.

**JavaScript Examples to Consider:**

*   `String(value)` or `value.toString()` for `VisitToString`.
*   `Boolean(value)` or `!!value` for `VisitToBoolean`.
*   `/pattern/flags` for `VisitCreateRegExpLiteral`.
*   `[1, 2, 3]` for `VisitCreateArrayLiteral`.
*   `{a: 1, b: 2}` for `VisitCreateObjectLiteral`.
*   `function() {}` for `VisitCreateClosure`.

Now, construct the response based on these observations and examples.
这个C++源代码文件 `v8/src/maglev/maglev-graph-builder.cc` 是 **Maglev 编译器的核心组件之一，负责将 JavaScript 字节码转换成 Maglev 图 (Maglev Graph)**。这个图是 Maglev 编译器进行优化的中间表示形式。

根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：构建 Maglev 图**

*   **处理不同的 JavaScript 操作:**  文件中包含大量的 `Visit...` 方法，例如 `VisitToString`, `VisitToBoolean`, `VisitCreateRegExpLiteral`, `VisitCreateArrayLiteral`, `VisitCreateObjectLiteral`, `VisitCreateClosure` 等。  每个 `Visit...` 方法都对应着一个特定的 JavaScript 字节码指令，负责根据该指令在 Maglev 图中创建相应的节点。
*   **创建和管理图节点:** 文件中使用了 `AddNewNode` 模板方法来创建各种类型的 Maglev 图节点，例如 `ToObject`, `ToString`, `CreateRegExpLiteral`, `CreateArrayLiteral`, `CreateObjectLiteral`, `FastCreateClosure`, `CreateClosure` 等。这些节点代表了 JavaScript 代码中的各种操作和值。
*   **处理对象创建:** 文件中包含了大量的逻辑来处理各种 JavaScript 对象的创建，例如正则表达式、数组、普通对象、闭包、上下文等。它尝试根据类型反馈信息进行优化，例如通过 `TryBuildFastCreateObjectOrArrayLiteral` 尝试进行快速的对象创建。
*   **管理寄存器和累加器:** `SetAccumulator` 和 `LoadRegister` 等方法用于管理在 Maglev 图构建过程中的虚拟寄存器和累加器。
*   **处理控制流:**  `VisitJump`, `VisitJumpIfTrue`, `VisitJumpLoop` 等方法用于处理 JavaScript 代码中的控制流语句，并在 Maglev 图中创建相应的跳转和分支节点。
*   **内联分配 (Inlined Allocation):**  文件中实现了 `BuildInlinedAllocation` 等方法，用于在 Maglev 图中表示对象的内联分配，这是一种优化手段，可以减少堆分配的开销。
*   **处理函数调用和内置函数:**  `BuildCallBuiltin` 用于在图中表示对 JavaScript 内置函数的调用。
*   **处理作用域和上下文:**  文件中包含了创建不同类型上下文 (例如 `CreateBlockContext`, `CreateCatchContext`, `CreateFunctionContext`) 的逻辑，这对于正确处理 JavaScript 的作用域链至关重要。
*   **处理 Arguments 对象:** `VisitCreateMappedArguments`, `VisitCreateUnmappedArguments`, `VisitCreateRestParameter` 等方法用于创建不同类型的 `arguments` 对象。
*   **支持循环优化 (Loop Peeling):** `PeelLoop` 方法表明该文件支持循环展开 (loop peeling) 优化。

**与 JavaScript 功能的关系及示例**

这个文件直接负责将 JavaScript 代码（以字节码的形式）转化为 Maglev 编译器的内部表示。因此，它与几乎所有的 JavaScript 功能都有关系，因为它需要能够表示和处理各种 JavaScript 语法和语义。

以下是一些 JavaScript 功能及其在 `maglev-graph-builder.cc` 中对应的处理方式的示例：

1. **类型转换:**

    *   **JavaScript:**  `String(value)`, `value.toString()`, `Boolean(value)`, `!!value`
    *   **C++ (`maglev-graph-builder.cc`):**
        ```c++
        void MaglevGraphBuilder::VisitToString() {
          // ToString
          SetAccumulator(BuildToString(GetAccumulator(), ToString::kThrowOnSymbol));
        }

        void MaglevGraphBuilder::VisitToBoolean() {
          SetAccumulator(BuildToBoolean(GetAccumulator()));
        }
        ```
    *   **说明:** `VisitToString` 对应 JavaScript 中将值转换为字符串的操作，`BuildToString` 会创建一个将累加器中的值转换为字符串的图节点。 `VisitToBoolean` 类似，对应转换为布尔值的操作。

2. **正则表达式字面量:**

    *   **JavaScript:** `/pattern/flags`
    *   **C++ (`maglev-graph-builder.cc`):**
        ```c++
        void MaglevGraphBuilder::VisitCreateRegExpLiteral() {
          // CreateRegExpLiteral <pattern_idx> <literal_idx> <flags>
          compiler::StringRef pattern = GetRefOperand<String>(0);
          FeedbackSlot slot = GetSlotOperand(1);
          uint32_t flags = GetFlag16Operand(2);
          compiler::FeedbackSource feedback_source{feedback(), slot};
          // ... (创建 CreateRegExpLiteral 节点)
        }
        ```
    *   **说明:** `VisitCreateRegExpLiteral` 对应 JavaScript 中创建正则表达式字面量的操作，它会提取正则表达式的模式和标志，并创建一个 `CreateRegExpLiteral` 节点。

3. **数组字面量:**

    *   **JavaScript:** `[1, 2, 3]`
    *   **C++ (`maglev-graph-builder.cc`):**
        ```c++
        void MaglevGraphBuilder::VisitCreateArrayLiteral() {
          compiler::HeapObjectRef constant_elements = GetRefOperand<HeapObject>(0);
          FeedbackSlot slot_index = GetSlotOperand(1);
          int bytecode_flags = GetFlag8Operand(2);
          // ... (根据反馈信息尝试快速创建，否则创建 CreateArrayLiteral 节点)
        }
        ```
    *   **说明:** `VisitCreateArrayLiteral` 对应 JavaScript 中创建数组字面量的操作，它会尝试利用类型反馈信息进行优化，如果不能进行快速创建，则会创建一个 `CreateArrayLiteral` 节点。

4. **对象字面量:**

    *   **JavaScript:** `{a: 1, b: 2}`
    *   **C++ (`maglev-graph-builder.cc`):**
        ```c++
        void MaglevGraphBuilder::VisitCreateObjectLiteral() {
          compiler::ObjectBoilerplateDescriptionRef boilerplate_desc =
              GetRefOperand<ObjectBoilerplateDescription>(0);
          FeedbackSlot slot_index = GetSlotOperand(1);
          int bytecode_flags = GetFlag8Operand(2);
          // ... (根据反馈信息尝试快速创建，否则创建 CreateObjectLiteral 节点)
        }
        ```
    *   **说明:** `VisitCreateObjectLiteral` 对应 JavaScript 中创建对象字面量的操作，与数组类似，它也会尝试利用反馈信息进行优化。

5. **函数声明/表达式 (闭包):**

    *   **JavaScript:** `function() {}` 或 `() => {}`
    *   **C++ (`maglev-graph-builder.cc`):**
        ```c++
        void MaglevGraphBuilder::VisitCreateClosure() {
          compiler::SharedFunctionInfoRef shared_function_info =
              GetRefOperand<SharedFunctionInfo>(0);
          compiler::FeedbackCellRef feedback_cell =
              feedback().GetClosureFeedbackCell(broker(), iterator_.GetIndexOperand(1));
          uint32_t flags = GetFlag8Operand(2);

          if (interpreter::CreateClosureFlags::FastNewClosureBit::decode(flags)) {
            SetAccumulator(AddNewNode<FastCreateClosure>(
                {GetContext()}, shared_function_info, feedback_cell));
          } else {
            SetAccumulator(AddNewNode<CreateClosure>(
                {GetContext()}, shared_function_info, feedback_cell, pretenured));
          }
        }
        ```
    *   **说明:** `VisitCreateClosure` 对应 JavaScript 中创建闭包的操作。它会根据标志位选择创建 `FastCreateClosure` (优化) 或 `CreateClosure` 节点。

**第 8 部分，共 9 部分的意义**

作为 9 个部分中的第 8 部分，可以推测这个文件 **处于 Maglev 图构建过程的后期阶段**。  可能在早期的阶段已经处理了基本的操作符、变量访问和控制流。  第 8 部分可能专注于更复杂的对象创建、函数和作用域相关的操作。  考虑到下一部分可能是图构建的最终收尾工作或者与图优化、代码生成相关的部分。

总而言之，`v8/src/maglev/maglev-graph-builder.cc` 是 Maglev 编译器的核心，负责将 JavaScript 代码转化为可优化的图表示。它通过处理各种 JavaScript 字节码指令，创建相应的图节点，并利用类型反馈等信息进行优化。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第8部分，共9部分，请归纳一下它的功能
```

### 源代码
```
ister destination = iterator_.GetRegisterOperand(0);
  NodeType old_type;
  if (CheckType(value, NodeType::kJSReceiver, &old_type)) {
    MoveNodeBetweenRegisters(interpreter::Register::virtual_accumulator(),
                             destination);
  } else {
    StoreRegister(destination, AddNewNode<ToObject>({GetContext(), value},
                                                    GetCheckType(old_type)));
  }
}

void MaglevGraphBuilder::VisitToString() {
  // ToString
  SetAccumulator(BuildToString(GetAccumulator(), ToString::kThrowOnSymbol));
}

void MaglevGraphBuilder::VisitToBoolean() {
  SetAccumulator(BuildToBoolean(GetAccumulator()));
}

void MaglevGraphBuilder::VisitCreateRegExpLiteral() {
  // CreateRegExpLiteral <pattern_idx> <literal_idx> <flags>
  compiler::StringRef pattern = GetRefOperand<String>(0);
  FeedbackSlot slot = GetSlotOperand(1);
  uint32_t flags = GetFlag16Operand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForRegExpLiteral(feedback_source);
  if (!processed_feedback.IsInsufficient()) {
    compiler::RegExpBoilerplateDescriptionRef literal =
        processed_feedback.AsRegExpLiteral().value();
    compiler::NativeContextRef native_context =
        broker()->target_native_context();
    compiler::MapRef map =
        native_context.regexp_function(broker()).initial_map(broker());
    SetAccumulator(BuildInlinedAllocation(
        CreateRegExpLiteralObject(map, literal), AllocationType::kYoung));
    // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
    // effect clear it.
    ClearCurrentAllocationBlock();
    return;
  }
  // Fallback.
  SetAccumulator(
      AddNewNode<CreateRegExpLiteral>({}, pattern, feedback_source, flags));
}

void MaglevGraphBuilder::VisitCreateArrayLiteral() {
  compiler::HeapObjectRef constant_elements = GetRefOperand<HeapObject>(0);
  FeedbackSlot slot_index = GetSlotOperand(1);
  int bytecode_flags = GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateArrayLiteralFlags::FlagsBits::decode(bytecode_flags);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);

  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);

  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForArrayLiteral));
  }

  ReduceResult result =
      TryBuildFastCreateObjectOrArrayLiteral(processed_feedback.AsLiteral());
  PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

  if (interpreter::CreateArrayLiteralFlags::FastCloneSupportedBit::decode(
          bytecode_flags)) {
    // TODO(victorgomes): CreateShallowArrayLiteral should not need the
    // boilerplate descriptor. However the current builtin checks that the
    // feedback exists and fallsback to CreateArrayLiteral if it doesn't.
    SetAccumulator(AddNewNode<CreateShallowArrayLiteral>(
        {}, constant_elements, feedback_source, literal_flags));
  } else {
    SetAccumulator(AddNewNode<CreateArrayLiteral>(
        {}, constant_elements, feedback_source, literal_flags));
  }
}

void MaglevGraphBuilder::VisitCreateArrayFromIterable() {
  ValueNode* iterable = GetAccumulator();
  SetAccumulator(BuildCallBuiltin<Builtin::kIterableToListWithSymbolLookup>(
      {GetTaggedValue(iterable)}));
}

void MaglevGraphBuilder::VisitCreateEmptyArrayLiteral() {
  FeedbackSlot slot_index = GetSlotOperand(0);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);
  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForArrayLiteral));
  }
  compiler::AllocationSiteRef site = processed_feedback.AsLiteral().value();

  broker()->dependencies()->DependOnElementsKind(site);
  ElementsKind kind = site.GetElementsKind();

  compiler::NativeContextRef native_context = broker()->target_native_context();
  compiler::MapRef map = native_context.GetInitialJSArrayMap(broker(), kind);
  // Initial JSArray map shouldn't have any in-object properties.
  SBXCHECK_EQ(map.GetInObjectProperties(), 0);
  SetAccumulator(BuildInlinedAllocation(
      CreateJSArray(map, map.instance_size(), GetSmiConstant(0)),
      AllocationType::kYoung));
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

std::optional<VirtualObject*>
MaglevGraphBuilder::TryReadBoilerplateForFastLiteral(
    compiler::JSObjectRef boilerplate, AllocationType allocation, int max_depth,
    int* max_properties) {
  DCHECK_GE(max_depth, 0);
  DCHECK_GE(*max_properties, 0);

  if (max_depth == 0) return {};

  // Prevent concurrent migrations of boilerplate objects.
  compiler::JSHeapBroker::BoilerplateMigrationGuardIfNeeded
      boilerplate_access_guard(broker());

  // Now that we hold the migration lock, get the current map.
  compiler::MapRef boilerplate_map = boilerplate.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate, HeapObject::kMapOffset, boilerplate_map);
  {
    compiler::OptionalMapRef current_boilerplate_map =
        boilerplate.map_direct_read(broker());
    if (!current_boilerplate_map.has_value() ||
        !current_boilerplate_map->equals(boilerplate_map)) {
      // TODO(leszeks): Emit an eager deopt for this case, so that we can
      // re-learn the boilerplate. This will be easier once we get rid of the
      // two-pass approach, since we'll be able to create the eager deopt here
      // and return a ReduceResult::DoneWithAbort().
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
    compiler::ObjectRef properties =
        *boilerplate.raw_properties_or_hash(broker());
    bool const empty =
        properties.IsSmi() ||
        properties.equals(MakeRef(
            broker(), local_isolate()->factory()->empty_fixed_array())) ||
        properties.equals(MakeRef(
            broker(),
            Cast<Object>(local_isolate()->factory()->empty_property_array())));
    if (!empty) return {};
  }

  compiler::OptionalFixedArrayBaseRef maybe_elements =
      boilerplate.elements(broker(), kRelaxedLoad);
  if (!maybe_elements.has_value()) return {};
  compiler::FixedArrayBaseRef boilerplate_elements = maybe_elements.value();
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate, JSObject::kElementsOffset, boilerplate_elements);
  const uint32_t elements_length = boilerplate_elements.length();

  VirtualObject* fast_literal =
      boilerplate_map.IsJSArrayMap()
          ? CreateJSArray(
                boilerplate_map, boilerplate_map.instance_size(),
                GetConstant(
                    boilerplate.AsJSArray().GetBoilerplateLength(broker())))
          : CreateJSObject(boilerplate_map);

  int inobject_properties = boilerplate_map.GetInObjectProperties();

  // Compute the in-object properties to store first.
  int index = 0;
  for (InternalIndex i :
       InternalIndex::Range(boilerplate_map.NumberOfOwnDescriptors())) {
    PropertyDetails const property_details =
        boilerplate_map.GetPropertyDetails(broker(), i);
    if (property_details.location() != PropertyLocation::kField) continue;
    DCHECK_EQ(PropertyKind::kData, property_details.kind());
    if ((*max_properties)-- == 0) return {};

    int offset = boilerplate_map.GetInObjectPropertyOffset(index);
#ifdef DEBUG
    FieldIndex field_index =
        FieldIndex::ForDetails(*boilerplate_map.object(), property_details);
    DCHECK(field_index.is_inobject());
    DCHECK_EQ(index, field_index.property_index());
    DCHECK_EQ(field_index.offset(), offset);
#endif

    // The index is derived from the in-sandbox `NumberOfOwnDescriptors` value,
    // but the access is out-of-sandbox fast_literal fields.
    SBXCHECK_LT(index, inobject_properties);

    // Note: the use of RawInobjectPropertyAt (vs. the higher-level
    // GetOwnFastConstantDataProperty) here is necessary, since the underlying
    // value may be `uninitialized`, which the latter explicitly does not
    // support.
    compiler::OptionalObjectRef maybe_boilerplate_value =
        boilerplate.RawInobjectPropertyAt(
            broker(),
            FieldIndex::ForInObjectOffset(offset, FieldIndex::kTagged));
    if (!maybe_boilerplate_value.has_value()) return {};

    // Note: We don't need to take a compilation dependency verifying the value
    // of `boilerplate_value`, since boilerplate properties are constant after
    // initialization modulo map migration. We protect against concurrent map
    // migrations (other than elements kind transition, which don't affect us)
    // via the boilerplate_migration_access lock.
    compiler::ObjectRef boilerplate_value = maybe_boilerplate_value.value();

    if (boilerplate_value.IsJSObject()) {
      compiler::JSObjectRef boilerplate_object = boilerplate_value.AsJSObject();
      std::optional<VirtualObject*> maybe_object_value =
          TryReadBoilerplateForFastLiteral(boilerplate_object, allocation,
                                           max_depth - 1, max_properties);
      if (!maybe_object_value.has_value()) return {};
      fast_literal->set(offset, maybe_object_value.value());
    } else if (property_details.representation().IsDouble()) {
      fast_literal->set(offset,
                        CreateHeapNumber(Float64::FromBits(
                            boilerplate_value.AsHeapNumber().value_as_bits())));
    } else {
      // It's fine to store the 'uninitialized' Oddball into a Smi field since
      // it will get overwritten anyway.
      DCHECK_IMPLIES(property_details.representation().IsSmi() &&
                         !boilerplate_value.IsSmi(),
                     IsUninitialized(*boilerplate_value.object()));
      fast_literal->set(offset, GetConstant(boilerplate_value));
    }
    index++;
  }

  // Fill slack at the end of the boilerplate object with filler maps.
  for (; index < inobject_properties; ++index) {
    DCHECK(!V8_MAP_PACKING_BOOL);
    // TODO(wenyuzhao): Fix incorrect MachineType when V8_MAP_PACKING is
    // enabled.
    int offset = boilerplate_map.GetInObjectPropertyOffset(index);
    fast_literal->set(offset, GetRootConstant(RootIndex::kOnePointerFillerMap));
  }

  DCHECK_EQ(JSObject::kElementsOffset, JSArray::kElementsOffset);
  // Empty or copy-on-write elements just store a constant.
  compiler::MapRef elements_map = boilerplate_elements.map(broker());
  // Protect against concurrent changes to the boilerplate object by checking
  // for an identical value at the end of the compilation.
  broker()->dependencies()->DependOnObjectSlotValue(
      boilerplate_elements, HeapObject::kMapOffset, elements_map);
  if (boilerplate_elements.length() == 0 ||
      elements_map.IsFixedCowArrayMap(broker())) {
    if (allocation == AllocationType::kOld &&
        !boilerplate.IsElementsTenured(boilerplate_elements)) {
      return {};
    }
    fast_literal->set(JSObject::kElementsOffset,
                      GetConstant(boilerplate_elements));
  } else {
    // Compute the elements to store first (might have effects).
    if (boilerplate_elements.IsFixedDoubleArray()) {
      int const size = FixedDoubleArray::SizeFor(elements_length);
      if (size > kMaxRegularHeapObjectSize) return {};
      fast_literal->set(
          JSObject::kElementsOffset,
          CreateDoubleFixedArray(elements_length,
                                 boilerplate_elements.AsFixedDoubleArray()));
    } else {
      int const size = FixedArray::SizeFor(elements_length);
      if (size > kMaxRegularHeapObjectSize) return {};
      VirtualObject* elements =
          CreateFixedArray(broker()->fixed_array_map(), elements_length);
      compiler::FixedArrayRef boilerplate_elements_as_fixed_array =
          boilerplate_elements.AsFixedArray();
      for (uint32_t i = 0; i < elements_length; ++i) {
        if ((*max_properties)-- == 0) return {};
        compiler::OptionalObjectRef element_value =
            boilerplate_elements_as_fixed_array.TryGet(broker(), i);
        if (!element_value.has_value()) return {};
        if (element_value->IsJSObject()) {
          std::optional<VirtualObject*> object =
              TryReadBoilerplateForFastLiteral(element_value->AsJSObject(),
                                               allocation, max_depth - 1,
                                               max_properties);
          if (!object.has_value()) return {};
          elements->set(FixedArray::OffsetOfElementAt(i), *object);
        } else {
          elements->set(FixedArray::OffsetOfElementAt(i),
                        GetConstant(*element_value));
        }
      }

      fast_literal->set(JSObject::kElementsOffset, elements);
    }
  }

  return fast_literal;
}

VirtualObject* MaglevGraphBuilder::DeepCopyVirtualObject(VirtualObject* old) {
  CHECK_EQ(old->type(), VirtualObject::kDefault);
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(old->slot_count());
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, old->map(), NewObjectId(), old->slot_count(), slots);
  current_interpreter_frame_.add_object(vobject);
  for (int i = 0; i < static_cast<int>(old->slot_count()); i++) {
    vobject->set_by_index(i, old->get_by_index(i));
  }
  vobject->set_allocation(old->allocation());
  old->allocation()->UpdateObject(vobject);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateVirtualObjectForMerge(
    compiler::MapRef map, uint32_t slot_count) {
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(slot_count);
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, map, NewObjectId(), slot_count, slots);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateVirtualObject(
    compiler::MapRef map, uint32_t slot_count_including_map) {
  // VirtualObjects are not added to the Maglev graph.
  DCHECK_GT(slot_count_including_map, 0);
  uint32_t slot_count = slot_count_including_map - 1;
  ValueNode** slots = zone()->AllocateArray<ValueNode*>(slot_count);
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, map, NewObjectId(), slot_count, slots);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateHeapNumber(Float64 value) {
  // VirtualObjects are not added to the Maglev graph.
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, broker()->heap_number_map(), NewObjectId(), value);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateDoubleFixedArray(
    uint32_t elements_length, compiler::FixedDoubleArrayRef elements) {
  // VirtualObjects are not added to the Maglev graph.
  VirtualObject* vobject = NodeBase::New<VirtualObject>(
      zone(), 0, broker()->fixed_double_array_map(), NewObjectId(),
      elements_length, elements);
  return vobject;
}

VirtualObject* MaglevGraphBuilder::CreateJSObject(compiler::MapRef map) {
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_GE(slot_count, 3);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->ClearSlots(JSObject::kElementsOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSArray(compiler::MapRef map,
                                                 int instance_size,
                                                 ValueNode* length) {
  int slot_count = instance_size / kTaggedSize;
  SBXCHECK_GE(slot_count, 4);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSArray::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArray::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArray::kLengthOffset, length);
  object->ClearSlots(JSArray::kLengthOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSArrayIterator(
    compiler::MapRef map, ValueNode* iterated_object, IterationKind kind) {
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_EQ(slot_count, 6);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSArrayIterator::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArrayIterator::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSArrayIterator::kIteratedObjectOffset, iterated_object);
  object->set(JSArrayIterator::kNextIndexOffset, GetInt32Constant(0));
  object->set(JSArrayIterator::kKindOffset,
              GetInt32Constant(static_cast<int>(kind)));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSConstructor(
    compiler::JSFunctionRef constructor) {
  compiler::SlackTrackingPrediction prediction =
      broker()->dependencies()->DependOnInitialMapInstanceSizePrediction(
          constructor);
  int slot_count = prediction.instance_size() / kTaggedSize;
  VirtualObject* object =
      CreateVirtualObject(constructor.initial_map(broker()), slot_count);
  SBXCHECK_GE(slot_count, 3);
  object->set(JSObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->ClearSlots(JSObject::kElementsOffset,
                     GetRootConstant(RootIndex::kOnePointerFillerMap));
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateFixedArray(compiler::MapRef map,
                                                    int length) {
  int slot_count = FixedArray::SizeFor(length) / kTaggedSize;
  VirtualObject* array = CreateVirtualObject(map, slot_count);
  array->set(offsetof(FixedArray, length_), GetInt32Constant(length));
  array->ClearSlots(offsetof(FixedArray, length_),
                    GetRootConstant(RootIndex::kOnePointerFillerMap));
  return array;
}

VirtualObject* MaglevGraphBuilder::CreateContext(
    compiler::MapRef map, int length, compiler::ScopeInfoRef scope_info,
    ValueNode* previous_context, std::optional<ValueNode*> extension) {
  int slot_count = FixedArray::SizeFor(length) / kTaggedSize;
  VirtualObject* context = CreateVirtualObject(map, slot_count);
  context->set(Context::kLengthOffset, GetInt32Constant(length));
  context->set(Context::OffsetOfElementAt(Context::SCOPE_INFO_INDEX),
               GetConstant(scope_info));
  context->set(Context::OffsetOfElementAt(Context::PREVIOUS_INDEX),
               previous_context);
  int index = Context::PREVIOUS_INDEX + 1;
  if (extension.has_value()) {
    context->set(Context::OffsetOfElementAt(Context::EXTENSION_INDEX),
                 extension.value());
    index++;
  }
  for (; index < length; index++) {
    context->set(Context::OffsetOfElementAt(index),
                 GetRootConstant(RootIndex::kUndefinedValue));
  }
  return context;
}

VirtualObject* MaglevGraphBuilder::CreateArgumentsObject(
    compiler::MapRef map, ValueNode* length, ValueNode* elements,
    std::optional<ValueNode*> callee) {
  DCHECK_EQ(JSSloppyArgumentsObject::kLengthOffset, JSArray::kLengthOffset);
  DCHECK_EQ(JSStrictArgumentsObject::kLengthOffset, JSArray::kLengthOffset);
  int slot_count = map.instance_size() / kTaggedSize;
  SBXCHECK_EQ(slot_count, callee.has_value() ? 5 : 4);
  VirtualObject* arguments = CreateVirtualObject(map, slot_count);
  arguments->set(JSArray::kPropertiesOrHashOffset,
                 GetRootConstant(RootIndex::kEmptyFixedArray));
  arguments->set(JSArray::kElementsOffset, elements);
  arguments->set(JSArray::kLengthOffset, length);
  if (callee.has_value()) {
    arguments->set(JSSloppyArgumentsObject::kCalleeOffset, callee.value());
  }
  DCHECK(arguments->map().IsJSArgumentsObjectMap() ||
         arguments->map().IsJSArrayMap());
  return arguments;
}

VirtualObject* MaglevGraphBuilder::CreateMappedArgumentsElements(
    compiler::MapRef map, int mapped_count, ValueNode* context,
    ValueNode* unmapped_elements) {
  int slot_count = SloppyArgumentsElements::SizeFor(mapped_count) / kTaggedSize;
  VirtualObject* elements = CreateVirtualObject(map, slot_count);
  elements->set(offsetof(SloppyArgumentsElements, length_),
                GetInt32Constant(mapped_count));
  elements->set(offsetof(SloppyArgumentsElements, context_), context);
  elements->set(offsetof(SloppyArgumentsElements, arguments_),
                unmapped_elements);
  return elements;
}

VirtualObject* MaglevGraphBuilder::CreateRegExpLiteralObject(
    compiler::MapRef map, compiler::RegExpBoilerplateDescriptionRef literal) {
  DCHECK_EQ(JSRegExp::Size(), JSRegExp::kLastIndexOffset + kTaggedSize);
  int slot_count = JSRegExp::Size() / kTaggedSize;
  VirtualObject* regexp = CreateVirtualObject(map, slot_count);
  regexp->set(JSRegExp::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  regexp->set(JSRegExp::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  regexp->set(JSRegExp::kDataOffset,
              GetTrustedConstant(literal.data(broker()),
                                 kRegExpDataIndirectPointerTag));
  regexp->set(JSRegExp::kSourceOffset, GetConstant(literal.source(broker())));
  regexp->set(JSRegExp::kFlagsOffset, GetInt32Constant(literal.flags()));
  regexp->set(JSRegExp::kLastIndexOffset,
              GetInt32Constant(JSRegExp::kInitialLastIndexValue));
  return regexp;
}

VirtualObject* MaglevGraphBuilder::CreateJSGeneratorObject(
    compiler::MapRef map, int instance_size, ValueNode* context,
    ValueNode* closure, ValueNode* receiver, ValueNode* register_file) {
  int slot_count = instance_size / kTaggedSize;
  InstanceType instance_type = map.instance_type();
  DCHECK(instance_type == JS_GENERATOR_OBJECT_TYPE ||
         instance_type == JS_ASYNC_GENERATOR_OBJECT_TYPE);
  SBXCHECK_GE(slot_count, instance_type == JS_GENERATOR_OBJECT_TYPE ? 10 : 12);
  VirtualObject* object = CreateVirtualObject(map, slot_count);
  object->set(JSGeneratorObject::kPropertiesOrHashOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSGeneratorObject::kElementsOffset,
              GetRootConstant(RootIndex::kEmptyFixedArray));
  object->set(JSGeneratorObject::kContextOffset, context);
  object->set(JSGeneratorObject::kFunctionOffset, closure);
  object->set(JSGeneratorObject::kReceiverOffset, receiver);
  object->set(JSGeneratorObject::kInputOrDebugPosOffset,
              GetRootConstant(RootIndex::kUndefinedValue));
  object->set(JSGeneratorObject::kResumeModeOffset,
              GetInt32Constant(JSGeneratorObject::kNext));
  object->set(JSGeneratorObject::kContinuationOffset,
              GetInt32Constant(JSGeneratorObject::kGeneratorExecuting));
  object->set(JSGeneratorObject::kParametersAndRegistersOffset, register_file);
  if (instance_type == JS_ASYNC_GENERATOR_OBJECT_TYPE) {
    object->set(JSAsyncGeneratorObject::kQueueOffset,
                GetRootConstant(RootIndex::kUndefinedValue));
    object->set(JSAsyncGeneratorObject::kIsAwaitingOffset, GetInt32Constant(0));
  }
  return object;
}

VirtualObject* MaglevGraphBuilder::CreateJSIteratorResult(compiler::MapRef map,
                                                          ValueNode* value,
                                                          ValueNode* done) {
  static_assert(JSIteratorResult::kSize == 5 * kTaggedSize);
  int slot_count = JSIteratorResult::kSize / kTaggedSize;
  VirtualObject* iter_result = CreateVirtualObject(map, slot_count);
  iter_result->set(JSIteratorResult::kPropertiesOrHashOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  iter_result->set(JSIteratorResult::kElementsOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  iter_result->set(JSIteratorResult::kValueOffset, value);
  iter_result->set(JSIteratorResult::kDoneOffset, done);
  return iter_result;
}

VirtualObject* MaglevGraphBuilder::CreateJSStringIterator(compiler::MapRef map,
                                                          ValueNode* string) {
  static_assert(JSStringIterator::kHeaderSize == 5 * kTaggedSize);
  int slot_count = JSStringIterator::kHeaderSize / kTaggedSize;
  VirtualObject* string_iter = CreateVirtualObject(map, slot_count);
  string_iter->set(JSStringIterator::kPropertiesOrHashOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  string_iter->set(JSStringIterator::kElementsOffset,
                   GetRootConstant(RootIndex::kEmptyFixedArray));
  string_iter->set(JSStringIterator::kStringOffset, string);
  string_iter->set(JSStringIterator::kIndexOffset, GetInt32Constant(0));
  return string_iter;
}

InlinedAllocation* MaglevGraphBuilder::ExtendOrReallocateCurrentAllocationBlock(
    AllocationType allocation_type, VirtualObject* vobject) {
  DCHECK_LT(vobject->size(), kMaxRegularHeapObjectSize);
  if (!current_allocation_block_ ||
      current_allocation_block_->allocation_type() != allocation_type ||
      !v8_flags.inline_new ||
      compilation_unit()->info()->for_turboshaft_frontend()) {
    current_allocation_block_ =
        AddNewNode<AllocationBlock>({}, allocation_type);
  }

  int current_size = current_allocation_block_->size();
  if (current_size + vobject->size() > kMaxRegularHeapObjectSize) {
    current_allocation_block_ =
        AddNewNode<AllocationBlock>({}, allocation_type);
  }

  DCHECK_GE(current_size, 0);
  InlinedAllocation* allocation =
      AddNewNode<InlinedAllocation>({current_allocation_block_}, vobject);
  graph()->allocations_escape_map().emplace(allocation, zone());
  current_allocation_block_->Add(allocation);
  vobject->set_allocation(allocation);
  return allocation;
}

void MaglevGraphBuilder::ClearCurrentAllocationBlock() {
  current_allocation_block_ = nullptr;
}

void MaglevGraphBuilder::AddNonEscapingUses(InlinedAllocation* allocation,
                                            int use_count) {
  if (!v8_flags.maglev_escape_analysis) return;
  allocation->AddNonEscapingUses(use_count);
}

void MaglevGraphBuilder::AddDeoptUse(VirtualObject* vobject) {
  if (vobject->type() != VirtualObject::kDefault) return;
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    ValueNode* value = vobject->get_by_index(i);
    if (InlinedAllocation* nested_allocation =
            value->TryCast<InlinedAllocation>()) {
      VirtualObject* nested_object =
          current_interpreter_frame_.virtual_objects().FindAllocatedWith(
              nested_allocation);
      CHECK_NOT_NULL(nested_object);
      AddDeoptUse(nested_object);
    } else if (!IsConstantNode(value->opcode()) &&
               value->opcode() != Opcode::kArgumentsElements &&
               value->opcode() != Opcode::kArgumentsLength &&
               value->opcode() != Opcode::kRestLength) {
      AddDeoptUse(value);
    }
  }
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocationForHeapNumber(
    VirtualObject* vobject, AllocationType allocation_type) {
  DCHECK(vobject->map().IsHeapNumberMap());
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  AddNonEscapingUses(allocation, 2);
  BuildStoreMap(allocation, broker()->heap_number_map(),
                StoreMap::initializing_kind(allocation_type));
  AddNewNode<StoreFloat64>({allocation, GetFloat64Constant(vobject->number())},
                           static_cast<int>(offsetof(HeapNumber, value_)));
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocationForDoubleFixedArray(
    VirtualObject* vobject, AllocationType allocation_type) {
  DCHECK(vobject->map().IsFixedDoubleArrayMap());
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  int length = vobject->double_elements_length();
  AddNonEscapingUses(allocation, length + 2);
  BuildStoreMap(allocation, broker()->fixed_double_array_map(),
                StoreMap::initializing_kind(allocation_type));
  AddNewNode<StoreTaggedFieldNoWriteBarrier>(
      {allocation, GetSmiConstant(length)},
      static_cast<int>(offsetof(FixedDoubleArray, length_)),
      StoreTaggedMode::kDefault);
  for (int i = 0; i < length; ++i) {
    AddNewNode<StoreFloat64>(
        {allocation,
         GetFloat64Constant(
             vobject->double_elements().GetFromImmutableFixedDoubleArray(i))},
        FixedDoubleArray::OffsetOfElementAt(i));
  }
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedAllocation(
    VirtualObject* vobject, AllocationType allocation_type) {
  current_interpreter_frame_.add_object(vobject);
  if (vobject->type() == VirtualObject::kHeapNumber) {
    return BuildInlinedAllocationForHeapNumber(vobject, allocation_type);
  }
  if (vobject->type() == VirtualObject::kFixedDoubleArray) {
    return BuildInlinedAllocationForDoubleFixedArray(vobject, allocation_type);
  }
  SmallZoneVector<ValueNode*, 8> values(vobject->slot_count(), zone());
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    ValueNode* node = vobject->get_by_index(i);
    if (node->Is<VirtualObject>()) {
      VirtualObject* nested = node->Cast<VirtualObject>();
      node = BuildInlinedAllocation(nested, allocation_type);
      vobject->set_by_index(i, node);
    } else if (node->Is<Float64Constant>()) {
      node = BuildInlinedAllocationForHeapNumber(
          CreateHeapNumber(node->Cast<Float64Constant>()->value()),
          allocation_type);
    } else {
      node = GetTaggedValue(node);
    }
    values[i] = node;
  }
  InlinedAllocation* allocation =
      ExtendOrReallocateCurrentAllocationBlock(allocation_type, vobject);
  AddNonEscapingUses(allocation, vobject->slot_count() + 1);
  BuildStoreMap(allocation, vobject->map(),
                StoreMap::initializing_kind(allocation_type));
  for (uint32_t i = 0; i < vobject->slot_count(); i++) {
    BuildInitializeStore(allocation, values[i], (i + 1) * kTaggedSize);
  }
  if (is_loop_effect_tracking()) {
    loop_effects_->allocations.insert(allocation);
  }
  return allocation;
}

ValueNode* MaglevGraphBuilder::BuildInlinedArgumentsElements(int start_index,
                                                             int length) {
  DCHECK(is_inline());
  if (length == 0) {
    return GetRootConstant(RootIndex::kEmptyFixedArray);
  }
  VirtualObject* elements =
      CreateFixedArray(broker()->fixed_array_map(), length);
  for (int i = 0; i < length; i++) {
    elements->set(FixedArray::OffsetOfElementAt(i),
                  inlined_arguments_[i + start_index + 1]);
  }
  return elements;
}

ValueNode* MaglevGraphBuilder::BuildInlinedUnmappedArgumentsElements(
    int mapped_count) {
  int length = argument_count_without_receiver();
  if (length == 0) {
    return GetRootConstant(RootIndex::kEmptyFixedArray);
  }
  VirtualObject* unmapped_elements =
      CreateFixedArray(broker()->fixed_array_map(), length);
  int i = 0;
  for (; i < mapped_count; i++) {
    unmapped_elements->set(FixedArray::OffsetOfElementAt(i),
                           GetRootConstant(RootIndex::kTheHoleValue));
  }
  for (; i < length; i++) {
    unmapped_elements->set(FixedArray::OffsetOfElementAt(i),
                           inlined_arguments_[i + 1]);
  }
  return unmapped_elements;
}

template <CreateArgumentsType type>
VirtualObject* MaglevGraphBuilder::BuildVirtualArgumentsObject() {
  switch (type) {
    case CreateArgumentsType::kMappedArguments:
      if (parameter_count_without_receiver() == 0) {
        // If there is no aliasing, the arguments object elements are not
        // special in any way, we can just return an unmapped backing store.
        if (is_inline()) {
          int length = argument_count_without_receiver();
          ValueNode* elements = BuildInlinedArgumentsElements(0, length);
          return CreateArgumentsObject(
              broker()->target_native_context().sloppy_arguments_map(broker()),
              GetInt32Constant(length), elements, GetClosure());
        } else {
          ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
          EnsureType(length, NodeType::kSmi);
          ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
              {length}, CreateArgumentsType::kUnmappedArguments,
              parameter_count_without_receiver());
          return CreateArgumentsObject(
              broker()->target_native_context().sloppy_arguments_map(broker()),
              length, elements, GetClosure());
        }
      } else {
        // If the parameter count is zero, we should have used the unmapped
        // backing store.
        int param_count = parameter_count_without_receiver();
        DCHECK_GT(param_count, 0);
        DCHECK(CanAllocateSloppyArgumentElements());
        int param_idx_in_ctxt = compilation_unit_->shared_function_info()
                                    .context_parameters_start() +
                                param_count - 1;
        // The {unmapped_elements} correspond to the extra arguments
        // (overapplication) that do not need be "mapped" to the actual
        // arguments. Mapped arguments are accessed via the context, whereas
        // unmapped arguments are simply accessed via this fixed array. See
        // SloppyArgumentsElements in src/object/arguments.h.
        if (is_inline()) {
          int length = argument_count_without_receiver();
          int mapped_count = std::min(param_count, length);
          ValueNode* unmapped_elements =
              BuildInlinedUnmappedArgumentsElements(mapped_count);
          VirtualObject* elements = CreateMappedArgumentsElements(
              broker()->sloppy_arguments_elements_map(), mapped_count,
              GetContext(), unmapped_elements);
          for (int i = 0; i < mapped_count; i++, param_idx_in_ctxt--) {
            elements->set(SloppyArgumentsElements::OffsetOfElementAt(i),
                          GetInt32Constant(param_idx_in_ctxt));
          }
          return CreateArgumentsObject(
              broker()->target_native_context().fast_aliased_arguments_map(
                  broker()),
              GetInt32Constant(length), elements, GetClosure());
        } else {
          ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
          EnsureType(length, NodeType::kSmi);
          ArgumentsElements* unmapped_elements = AddNewNode<ArgumentsElements>(
              {length}, CreateArgumentsType::kMappedArguments, param_count);
          VirtualObject* elements = CreateMappedArgumentsElements(
              broker()->sloppy_arguments_elements_map(), param_count,
              GetContext(), unmapped_elements);
          ValueNode* the_hole_value = GetConstant(broker()->the_hole_value());
          for (int i = 0; i < param_count; i++, param_idx_in_ctxt--) {
            ValueNode* value = Select(
                [&](auto& builder) {
                  return BuildBranchIfInt32Compare(builder,
                                                   Operation::kLessThan,
                                                   GetInt32Constant(i), length);
                },
                [&] { return GetSmiConstant(param_idx_in_ctxt); },
                [&] { return the_hole_value; });
            elements->set(SloppyArgumentsElements::OffsetOfElementAt(i), value);
          }
          return CreateArgumentsObject(
              broker()->target_native_context().fast_aliased_arguments_map(
                  broker()),
              length, elements, GetClosure());
        }
      }
    case CreateArgumentsType::kUnmappedArguments:
      if (is_inline()) {
        int length = argument_count_without_receiver();
        ValueNode* elements = BuildInlinedArgumentsElements(0, length);
        return CreateArgumentsObject(
            broker()->target_native_context().strict_arguments_map(broker()),
            GetInt32Constant(length), elements);
      } else {
        ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
        EnsureType(length, NodeType::kSmi);
        ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
            {length}, CreateArgumentsType::kUnmappedArguments,
            parameter_count_without_receiver());
        return CreateArgumentsObject(
            broker()->target_native_context().strict_arguments_map(broker()),
            length, elements);
      }
    case CreateArgumentsType::kRestParameter:
      if (is_inline()) {
        int start_index = parameter_count_without_receiver();
        int length =
            std::max(0, argument_count_without_receiver() - start_index);
        ValueNode* elements =
            BuildInlinedArgumentsElements(start_index, length);
        return CreateArgumentsObject(
            broker()->target_native_context().js_array_packed_elements_map(
                broker()),
            GetInt32Constant(length), elements);
      } else {
        ArgumentsLength* length = AddNewNode<ArgumentsLength>({});
        EnsureType(length, NodeType::kSmi);
        ArgumentsElements* elements = AddNewNode<ArgumentsElements>(
            {length}, CreateArgumentsType::kRestParameter,
            parameter_count_without_receiver());
        RestLength* rest_length =
            AddNewNode<RestLength>({}, parameter_count_without_receiver());
        return CreateArgumentsObject(
            broker()->target_native_context().js_array_packed_elements_map(
                broker()),
            rest_length, elements);
      }
  }
}

template <CreateArgumentsType type>
ValueNode* MaglevGraphBuilder::BuildAndAllocateArgumentsObject() {
  auto arguments = BuildVirtualArgumentsObject<type>();
  ValueNode* allocation =
      BuildInlinedAllocation(arguments, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ReduceResult MaglevGraphBuilder::TryBuildFastCreateObjectOrArrayLiteral(
    const compiler::LiteralFeedback& feedback) {
  compiler::AllocationSiteRef site = feedback.value();
  if (!site.boilerplate(broker()).has_value()) return ReduceResult::Fail();
  AllocationType allocation_type =
      broker()->dependencies()->DependOnPretenureMode(site);

  // First try to extract out the shape and values of the boilerplate, bailing
  // out on complex boilerplates.
  int max_properties = compiler::kMaxFastLiteralProperties;
  std::optional<VirtualObject*> maybe_value = TryReadBoilerplateForFastLiteral(
      *site.boilerplate(broker()), allocation_type,
      compiler::kMaxFastLiteralDepth, &max_properties);
  if (!maybe_value.has_value()) return ReduceResult::Fail();

  // Then, use the collected information to actually create nodes in the graph.
  // TODO(leszeks): Add support for unwinding graph modifications, so that we
  // can get rid of this two pass approach.
  broker()->dependencies()->DependOnElementsKinds(site);
  ReduceResult result = BuildInlinedAllocation(*maybe_value, allocation_type);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return result;
}

void MaglevGraphBuilder::VisitCreateObjectLiteral() {
  compiler::ObjectBoilerplateDescriptionRef boilerplate_desc =
      GetRefOperand<ObjectBoilerplateDescription>(0);
  FeedbackSlot slot_index = GetSlotOperand(1);
  int bytecode_flags = GetFlag8Operand(2);
  int literal_flags =
      interpreter::CreateObjectLiteralFlags::FlagsBits::decode(bytecode_flags);
  compiler::FeedbackSource feedback_source(feedback(), slot_index);

  compiler::ProcessedFeedback const& processed_feedback =
      broker()->GetFeedbackForArrayOrObjectLiteral(feedback_source);
  if (processed_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForObjectLiteral));
  }

  ReduceResult result =
      TryBuildFastCreateObjectOrArrayLiteral(processed_feedback.AsLiteral());
  PROCESS_AND_RETURN_IF_DONE(result, SetAccumulator);

  if (interpreter::CreateObjectLiteralFlags::FastCloneSupportedBit::decode(
          bytecode_flags)) {
    // TODO(victorgomes): CreateShallowObjectLiteral should not need the
    // boilerplate descriptor. However the current builtin checks that the
    // feedback exists and fallsback to CreateObjectLiteral if it doesn't.
    SetAccumulator(AddNewNode<CreateShallowObjectLiteral>(
        {}, boilerplate_desc, feedback_source, literal_flags));
  } else {
    SetAccumulator(AddNewNode<CreateObjectLiteral>(
        {}, boilerplate_desc, feedback_source, literal_flags));
  }
}

void MaglevGraphBuilder::VisitCreateEmptyObjectLiteral() {
  compiler::NativeContextRef native_context = broker()->target_native_context();
  compiler::MapRef map =
      native_context.object_function(broker()).initial_map(broker());
  DCHECK(!map.is_dictionary_map());
  DCHECK(!map.IsInobjectSlackTrackingInProgress());
  SetAccumulator(
      BuildInlinedAllocation(CreateJSObject(map), AllocationType::kYoung));
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

void MaglevGraphBuilder::VisitCloneObject() {
  // CloneObject <source_idx> <flags> <feedback_slot>
  ValueNode* source = LoadRegister(0);
  ValueNode* flags =
      GetSmiConstant(interpreter::CreateObjectLiteralFlags::FlagsBits::decode(
          GetFlag8Operand(1)));
  FeedbackSlot slot = GetSlotOperand(2);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  SetAccumulator(BuildCallBuiltin<Builtin::kCloneObjectIC>(
      {GetTaggedValue(source), flags}, feedback_source));
}

void MaglevGraphBuilder::VisitGetTemplateObject() {
  // GetTemplateObject <descriptor_idx> <literal_idx>
  compiler::SharedFunctionInfoRef shared_function_info =
      compilation_unit_->shared_function_info();
  ValueNode* description = GetConstant(GetRefOperand<HeapObject>(0));
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& feedback =
      broker()->GetFeedbackForTemplateObject(feedback_source);
  if (feedback.IsInsufficient()) {
    return SetAccumulator(AddNewNode<GetTemplateObject>(
        {description}, shared_function_info, feedback_source));
  }
  compiler::JSArrayRef template_object = feedback.AsTemplateObject().value();
  SetAccumulator(GetConstant(template_object));
}

void MaglevGraphBuilder::VisitCreateClosure() {
  compiler::SharedFunctionInfoRef shared_function_info =
      GetRefOperand<SharedFunctionInfo>(0);
  compiler::FeedbackCellRef feedback_cell =
      feedback().GetClosureFeedbackCell(broker(), iterator_.GetIndexOperand(1));
  uint32_t flags = GetFlag8Operand(2);

  if (interpreter::CreateClosureFlags::FastNewClosureBit::decode(flags)) {
    SetAccumulator(AddNewNode<FastCreateClosure>(
        {GetContext()}, shared_function_info, feedback_cell));
  } else {
    bool pretenured =
        interpreter::CreateClosureFlags::PretenuredBit::decode(flags);
    SetAccumulator(AddNewNode<CreateClosure>(
        {GetContext()}, shared_function_info, feedback_cell, pretenured));
  }
}

ReduceResult MaglevGraphBuilder::TryBuildInlinedAllocatedContext(
    compiler::MapRef map, compiler::ScopeInfoRef scope, int context_length) {
  const int kContextAllocationLimit = 16;
  if (context_length > kContextAllocationLimit) {
    return ReduceResult::Fail();
  }
  DCHECK_GE(context_length, Context::MIN_CONTEXT_SLOTS);
  auto context = CreateContext(map, context_length, scope, GetContext());
  ValueNode* result = BuildInlinedAllocation(context, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
  return result;
}

void MaglevGraphBuilder::VisitCreateBlockContext() {
  // CreateBlockContext <scope_info_idx>
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(0);
  compiler::MapRef map =
      broker()->target_native_context().block_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, scope_info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(TryBuildInlinedAllocatedContext(
                                 map, scope_info, scope_info.ContextLength()),
                             done);
  // Fallback.
  done(BuildCallRuntime(Runtime::kPushBlockContext, {GetConstant(scope_info)})
           .value());
}

void MaglevGraphBuilder::VisitCreateCatchContext() {
  // CreateCatchContext <exception> <scope_info_idx>
  ValueNode* exception = LoadRegister(0);
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(1);
  auto context = CreateContext(
      broker()->target_native_context().catch_context_map(broker()),
      Context::MIN_CONTEXT_EXTENDED_SLOTS, scope_info, GetContext(), exception);
  SetAccumulator(BuildInlinedAllocation(context, AllocationType::kYoung));
  graph()->record_scope_info(GetAccumulator(), scope_info);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

void MaglevGraphBuilder::VisitCreateFunctionContext() {
  compiler::ScopeInfoRef info = GetRefOperand<ScopeInfo>(0);
  uint32_t slot_count = iterator_.GetUnsignedImmediateOperand(1);
  compiler::MapRef map =
      broker()->target_native_context().function_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(
      TryBuildInlinedAllocatedContext(map, info,
                                      slot_count + Context::MIN_CONTEXT_SLOTS),
      done);
  // Fallback.
  done(AddNewNode<CreateFunctionContext>({GetContext()}, info, slot_count,
                                         ScopeType::FUNCTION_SCOPE));
}

void MaglevGraphBuilder::VisitCreateEvalContext() {
  compiler::ScopeInfoRef info = GetRefOperand<ScopeInfo>(0);
  uint32_t slot_count = iterator_.GetUnsignedImmediateOperand(1);
  compiler::MapRef map =
      broker()->target_native_context().eval_context_map(broker());

  auto done = [&](ValueNode* res) {
    graph()->record_scope_info(res, info);
    SetAccumulator(res);
  };

  PROCESS_AND_RETURN_IF_DONE(
      TryBuildInlinedAllocatedContext(map, info,
                                      slot_count + Context::MIN_CONTEXT_SLOTS),
      done);
  if (slot_count <= static_cast<uint32_t>(
                        ConstructorBuiltins::MaximumFunctionContextSlots())) {
    done(AddNewNode<CreateFunctionContext>({GetContext()}, info, slot_count,
                                           ScopeType::EVAL_SCOPE));
  } else {
    done(BuildCallRuntime(Runtime::kNewFunctionContext, {GetConstant(info)})
             .value());
  }
}

void MaglevGraphBuilder::VisitCreateWithContext() {
  // CreateWithContext <register> <scope_info_idx>
  ValueNode* object = LoadRegister(0);
  compiler::ScopeInfoRef scope_info = GetRefOperand<ScopeInfo>(1);
  auto context = CreateContext(
      broker()->target_native_context().with_context_map(broker()),
      Context::MIN_CONTEXT_EXTENDED_SLOTS, scope_info, GetContext(), object);
  SetAccumulator(BuildInlinedAllocation(context, AllocationType::kYoung));
  graph()->record_scope_info(GetAccumulator(), scope_info);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the next side
  // effect clear it.
  ClearCurrentAllocationBlock();
}

bool MaglevGraphBuilder::CanAllocateSloppyArgumentElements() {
  return SloppyArgumentsElements::SizeFor(parameter_count()) <=
         kMaxRegularHeapObjectSize;
}

bool MaglevGraphBuilder::CanAllocateInlinedArgumentElements() {
  DCHECK(is_inline());
  return FixedArray::SizeFor(argument_count_without_receiver()) <=
         kMaxRegularHeapObjectSize;
}

void MaglevGraphBuilder::VisitCreateMappedArguments() {
  compiler::SharedFunctionInfoRef shared =
      compilation_unit_->shared_function_info();
  if (!shared.object()->has_duplicate_parameters()) {
    if (((is_inline() && CanAllocateInlinedArgumentElements()) ||
         (!is_inline() && CanAllocateSloppyArgumentElements()))) {
      SetAccumulator(BuildAndAllocateArgumentsObject<
                     CreateArgumentsType::kMappedArguments>());
      return;
    } else if (!is_inline()) {
      SetAccumulator(
          BuildCallBuiltin<Builtin::kFastNewSloppyArguments>({GetClosure()}));
      return;
    }
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewSloppyArguments, {GetClosure()}).value());
}

void MaglevGraphBuilder::VisitCreateUnmappedArguments() {
  if (!is_inline() || CanAllocateInlinedArgumentElements()) {
    SetAccumulator(BuildAndAllocateArgumentsObject<
                   CreateArgumentsType::kUnmappedArguments>());
    return;
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewStrictArguments, {GetClosure()}).value());
}

void MaglevGraphBuilder::VisitCreateRestParameter() {
  if (!is_inline() || CanAllocateInlinedArgumentElements()) {
    SetAccumulator(
        BuildAndAllocateArgumentsObject<CreateArgumentsType::kRestParameter>());
    return;
  }
  // Generic fallback.
  SetAccumulator(
      BuildCallRuntime(Runtime::kNewRestParameter, {GetClosure()}).value());
}

void MaglevGraphBuilder::PeelLoop() {
  int loop_header = iterator_.current_offset();
  DCHECK(loop_headers_to_peel_.Contains(loop_header));
  DCHECK(!in_peeled_iteration());
  peeled_iteration_count_ = v8_flags.maglev_optimistic_peeled_loops ? 2 : 1;
  any_peeled_loop_ = true;
  allow_loop_peeling_ = false;

  if (v8_flags.trace_maglev_graph_building) {
    std::cout << "  * Begin loop peeling...." << std::endl;
  }

  while (in_peeled_iteration()) {
    BuildLoopForPeeling();
  }
  // Emit the actual (not peeled) loop if needed.
  if (loop_header == iterator_.current_offset()) {
    BuildLoopForPeeling();
  }
  allow_loop_peeling_ = true;
}

void MaglevGraphBuilder::BuildLoopForPeeling() {
  int loop_header = iterator_.current_offset();
  DCHECK(loop_headers_to_peel_.Contains(loop_header));

  // Since peeled loops do not start with a loop merge state, we need to
  // explicitly enter e loop effect tracking scope for the peeled iteration.
  bool track_peeled_effects =
      v8_flags.maglev_optimistic_peeled_loops && peeled_iteration_count_ == 2;
  if (track_peeled_effects) {
    BeginLoopEffects(loop_header);
  }

#ifdef DEBUG
  bool was_in_peeled_iteration = in_peeled_iteration();
#endif  // DEBUG

  while (iterator_.current_bytecode() != interpreter::Bytecode::kJumpLoop) {
    local_isolate_->heap()->Safepoint();
    VisitSingleBytecode();
    iterator_.Advance();
  }

  VisitSingleBytecode();  // VisitJumpLoop

  DCHECK_EQ(was_in_peeled_iteration, in_peeled_iteration());
  if (!in_peeled_iteration()) {
    return;
  }

  // In case the peeled iteration was mergeable (see TryMergeLoop) or the
  // JumpLoop was dead, we are done.
  if (!current_block_) {
    decremented_predecessor_offsets_.clear();
    KillPeeledLoopTargets(peeled_iteration_count_);
    peeled_iteration_count_ = 0;
    if (track_peeled_effects) {
      EndLoopEffects(loop_header);
    }
    return;
  }

  peeled_iteration_count_--;

  // After processing the peeled iteration and reaching the `JumpLoop`, we
  // re-process the loop body. For this, we need to reset the graph building
  // state roughly as if we didn't process it yet.

  // Reset position in exception handler table to before the loop.
  HandlerTable table(*bytecode().object());
  while (next_handler_table_index_ > 0) {
    next_handler_table_index_--;
    int start = table.GetRangeStart(next_handler_table_index_);
    if (start < loop_header) break;
  }

  // Re-create catch handler merge states.
  for (int offset = loop_header; offset <= iterator_.current_offset();
       ++offset) {
    if (auto& merge_state = merge_states_[offset]) {
      if (merge_state->is_exception_handler()) {
        merge_state = MergePointInterpreterFrameState::NewForCatchBlock(
            *compilation_unit_, merge_state->frame_state().liveness(), offset,
            merge_state->exception_handler_was_used(),
            merge_state->catch_block_context_register(), graph_);
      } else {
        // We only peel innermost loops.
        DCHECK(!merge_state->is_loop());
        merge_state = nullptr;
      }
    }
    new (&jump_targets_[offset]) BasicBlockRef();
  }

  // Reset predecessors as if the loop body had not been visited.
  for (int offset : decremented_predecessor_offsets_) {
    DCHECK_GE(offset, loop_header);
    if (offset <= iterator_.current_offset()) {
      UpdatePredecessorCount(offset, 1);
    }
  }
  decremented_predecessor_offsets_.clear();

  DCHECK(current_block_);
  // After resetting, the actual loop header always has exactly 2
  // predecessors: the two copies of `JumpLoop`.
  InitializePredecessorCount(loop_header, 2);
  merge_states_[loop_header] = MergePointInterpreterFrameState::NewForLoop(
      current_interpreter_frame_, *compilation_unit_, loop_header, 2,
      GetInLivenessFor(loop_header),
      &bytecode_analysis_.GetLoopInfoFor(loop_header),
      /* has_been_peeled */ true);

  BasicBlock* block = FinishBlock<Jump>({}, &jump_targets_[loop_header]);
  // If we ever want more peelings, we should ensure that only the last one
  // creates a loop header.
  DCHECK_LE(peeled_iteration_count_, 1);
  DCHECK_IMPLIES(in_peeled_iteration(),
                 v8_flags.maglev_optimistic_peeled_loops);
  merge_states_[loop_header]->InitializeLoop(
      this, *compilation_unit_, current_interpreter_frame_, block,
      in_peeled_iteration(), loop_effects_);

  if (track_peeled_effects) {
    EndLoopEffects(loop_header);
  }
  DCHECK_NE(iterator_.current_offset(), loop_header);
  iterator_.SetOffset(loop_header);
}

void MaglevGraphBuilder::OsrAnalyzePrequel() {
  DCHECK_EQ(compilation_unit_->info()->toplevel_compilation_unit(),
            compilation_unit_);

  // TODO(olivf) We might want to start collecting known_node_aspects_ here.
  for (iterator_.SetOffset(0); iterator_.current_offset() != entrypoint_;
       iterator_.Advance()) {
    switch (iterator_.current_bytecode()) {
      case interpreter::Bytecode::kPushContext: {
        graph()->record_scope_info(GetContext(), {});
        // Nothing left to analyze...
        return;
      }
      default:
        continue;
    }
  }
}

void MaglevGraphBuilder::BeginLoopEffects(int loop_header) {
  loop_effects_stack_.push_back(zone()->New<LoopEffects>(loop_header, zone()));
  loop_effects_ = loop_effects_stack_.back();
}

void MaglevGraphBuilder::EndLoopEffects(int loop_header) {
  DCHECK_EQ(loop_effects_, loop_effects_stack_.back());
  DCHECK_EQ(loop_effects_->loop_header, loop_header);
  // TODO(olivf): Update merge states dominated by the loop header with
  // information we know to be unaffected by the loop.
  if (merge_states_[loop_header] && merge_states_[loop_header]->is_loop()) {
    merge_states_[loop_header]->set_loop_effects(loop_effects_);
  }
  if (loop_effects_stack_.size() > 1) {
    LoopEffects* inner_effects = loop_effects_;
    loop_effects_ = *(loop_effects_stack_.end() - 2);
    loop_effects_->Merge(inner_effects);
  } else {
    loop_effects_ = nullptr;
  }
  loop_effects_stack_.pop_back();
}

void MaglevGraphBuilder::VisitJumpLoop() {
  const uint32_t relative_jump_bytecode_offset =
      iterator_.GetUnsignedImmediateOperand(0);
  const int32_t loop_offset = iterator_.GetImmediateOperand(1);
  const FeedbackSlot feedback_slot = iterator_.GetSlotOperand(2);
  int target = iterator_.GetJumpTargetOffset();

  if (ShouldEmitInterruptBudgetChecks()) {
    int reduction = relative_jump_bytecode_offset *
                    v8_flags.osr_from_maglev_interrupt_scale_factor;
    AddNewNode<ReduceInterruptBudgetForLoop>({}, reduction > 0 ? reduction : 1);
  } else {
    AddNewNode<HandleNoHeapWritesInterrupt>({});
  }

  if (ShouldEmitOsrInterruptBudgetChecks()) {
    AddNewNode<TryOnStackReplacement>(
        {GetClosure()}, loop_offset, feedback_slot,
        BytecodeOffset(iterator_.current_offset()), compilation_unit_);
  }

  bool is_peeled_loop = loop_headers_to_peel_.Contains(target);
  auto FinishLoopBlock = [&]() {
    return FinishBlock<JumpLoop>({}, jump_targets_[target].block_ptr());
  };
  if (is_peeled_loop && in_peeled_iteration()) {
    ClobberAccumulator();
    if (in_optimistic_peeling_iteration()) {
      // Let's see if we can finish this loop without peeling it.
      if (!merge_states_[target]->TryMergeLoop(this, current_interpreter_frame_,
                                               FinishLoopBlock)) {
        merge_states_[target]->MergeDeadLoop(*compilation_unit());
      }
      if (is_loop_effect_tracking_enabled()) {
        EndLoopEffects(target);
      }
    }
  } else {
    BasicBlock* block = FinishLoopBlock();
    merge_states_[target]->MergeLoop(this, current_interpreter_frame_, block);
    block->set_predecessor_id(merge_states_[target]->predecessor_count() - 1);
    if (is_peeled_loop) {
      DCHECK(!in_peeled_iteration());
    }
    if (is_loop_effect_tracking_enabled()) {
      EndLoopEffects(target);
    }
  }
}
void MaglevGraphBuilder::VisitJump() {
  BasicBlock* block =
      FinishBlock<Jump>({}, &jump_targets_[iterator_.GetJumpTargetOffset()]);
  MergeIntoFrameState(block, iterator_.GetJumpTargetOffset());
  DCHECK_EQ(current_block_, nullptr);
  DCHECK_LT(next_offset(), bytecode().length());
}
void MaglevGraphBuilder::VisitJumpConstant() { VisitJump(); }
void MaglevGraphBuilder::VisitJumpIfNullConstant() { VisitJumpIfNull(); }
void MaglevGraphBuilder::VisitJumpIfNotNullConstant() { VisitJumpIfNotNull(); }
void MaglevGraphBuilder::VisitJumpIfUndefinedConstant() {
  VisitJumpIfUndefined();
}
void MaglevGraphBuilder::VisitJumpIfNotUndefinedConstant() {
  VisitJumpIfNotUndefined();
}
void MaglevGraphBuilder::VisitJumpIfUndefinedOrNullConstant() {
  VisitJumpIfUndefinedOrNull();
}
void MaglevGraphBuilder::VisitJumpIfTrueConstant() { VisitJumpIfTrue(); }
void MaglevGraphBuilder::VisitJumpIfFalseConstant() { VisitJumpIfFalse(); }
void MaglevGraphBuilder::VisitJumpIfJSReceiverConstant() {
  VisitJumpIfJSReceiver();
}
void MaglevGraphBuilder::VisitJumpIfForInDoneConstant() {
  VisitJumpIfForInDone();
}
void MaglevGraphBuilder::VisitJumpIfToBooleanTrueConstant() {
  VisitJumpIfToBooleanTrue();
}
void MaglevGraphBuilder::VisitJumpIfToBooleanFalseConstant() {
  VisitJumpIfToBooleanFalse();
}

void MaglevGraphBuilder::MergeIntoFrameState(BasicBlock* predecessor,
                                             int target) {
  if (merge_states_[target] == nullptr) {
    bool jumping_to_peeled_iteration = bytecode_analysis().IsLoopHeader(target);
    DCHECK_EQ(jumping_to_peeled_iteration,
              loop_headers_to_peel_.Contains(target));
    const compiler::BytecodeLivenessState* liveness = GetInLivenessFor(target);
    if (jumping_to_peeled_iteration) {
      // The peeled iteration is missing the backedge.
      DecrementDeadPredecessorAndAccountForPeeling(target);
    }
    // If there's no target frame state, allocate a new one.
    merge_states_[target] = MergePointInterpreterFrameState::New(
        *compilation_unit_, current_interpreter_frame_, target,
        predecessor_count(target), predecessor, liveness);
  } else {
    // If there already is a frame state, merge.
    merge_states_[target]->Merge(this, current_interpreter_frame_, predecessor);
  }
}

void MaglevGraphBuilder::MergeDeadIntoFrameState(int target) {
  // If there already is a frame state, merge.
  if (merge_states_[target]) {
    DCHECK_EQ(merge_states_[target]->predecessor_count(),
              predecessor_count(target));
    merge_states_[target]->MergeDead(*compilation_unit_);
    // If this merge is the last one which kills a loop merge, remove that
    // merge state.
    if (merge_states_[target]->is_unreachable_loop()) {
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "! Killing loop merge state at @" << target << std::endl;
      }
      merge_states_[target] = nullptr;
    }
  }
  // If there is no merge state yet, don't create one, but just reduce the
  // number of possible predecessors to zero.
  DecrementDeadPredecessorAndAccountForPeeling(target);
}

void MaglevGraphBuilder::MergeDeadLoopIntoFrameState(int target) {
  // Check if the Loop entry is dead already (e.g. an outer loop from OSR).
  if (V8_UNLIKELY(!merge_states_[target]) && predecessor_count(target) == 0) {
    static_assert(kLoopsMustBeEnteredThroughHeader);
    return;
  }
  // If there already is a frame state, merge.
  if (V8_LIKELY(merge_states_[target])) {
    DCHECK_EQ(merge_states_[target]->predecessor_count(),
              predecessor_count(target));
    if (is_loop_effect_tracking_enabled() &&
        !merge_states_[target]->is_unreachable_loop()) {
      EndLoopEffects(target);
    }
    merge_states_[target]->MergeDeadLoop(*compilation_unit_);
  }
  // If there is no merge state yet, don't create one, but just reduce the
  // number of possible predecessors to zero.
  DecrementDeadPredecessorAndAccountForPeeling(target);
}

void MaglevGraphBuilder::MergeIntoInlinedReturnFrameState(
    BasicBlock* predecessor) {
  int target = inline_exit_offset();
  if (merge_states_[target] == nullptr) {
    // All returns should have the same liveness, which is that only the
    // accumulator is live.
    const compiler::BytecodeLivenessState* liveness = GetInLiveness();
    DCHECK(liveness->AccumulatorIsLive());
    DCHECK_EQ(liveness->live_value_count(), 1);

    // If there's no target frame state, allocate a new one.
    merge_states_[target] = MergePointInterpreterFrameState::New(
        *compilation_unit_, current_interpreter_frame_, target,
        predecessor_count(target), predecessor, liveness);
  } else {
    // Again, all returns should have the same liveness, so double check this.
    DCHECK(GetInLiveness()->Equals(
        *merge_states_[target]->frame_state().liveness()));
    merge_states_[target]->Merge(this, current_interpreter_frame_, predecessor);
  }
}

MaglevGraphBuilder::BranchResult
MaglevGraphBuilder::BuildBranchIfReferenceEqual(BranchBuilder& builder,
                                                ValueNode* lhs,
                                                ValueNode* rhs) {
  if (RootConstant* root_constant = rhs->TryCast<RootConstant>()) {
    return builder.Build<BranchIfRootConstant>({lhs}, root_constant->index());
  }
  if (RootConstant* root_constant = lhs->TryCast<RootConstant>()) {
    return builder.Build<BranchIfRootConstant>({rhs}, root_constant->index());
  }
  if (InlinedAllocation* alloc_lhs = lhs->TryCast<InlinedAllocation>()) {
    if (InlinedAllocation* alloc_rhs = rhs->TryCast<InlinedAllocation>()) {
      return builder.FromBool(alloc_lhs == alloc_rhs);
    }
  }

  return builder.Build<BranchIfReferenceEqual>({lhs, rhs});
}

void MaglevGraphBuilder::MarkBranchDeadAndJumpIfNeeded(bool is_jump_taken) {
  int jump_offset = iterator_.GetJumpTargetOffset();
  if (is_jump_taken) {
    BasicBlock* block = FinishBlock<Jump>({}, &jump_targets_[jump_offset]);
    MergeDeadIntoFrameState(next_offset());
    MergeIntoFrameState(block, jump_offset);
  } else {
    MergeDeadIntoFrameState(jump_offset);
  }
}

#ifdef DEBUG
namespace {
bool IsNumberRootConstant(RootIndex root_index) {
  switch (root_index) {
#define CASE(type, name, label) case RootIndex::k##label:
    SMI_ROOT_LIST(CASE)
    STRONG_READ_ONLY_HEAP_NUMBER_ROOT_LIST(CASE)
    return true;
    default:
      return false;
  }
#undef CASE
}
}  // namespace
#endif

MaglevGraphBuilder::BranchResult MaglevGraphBuilder::BuildBranchIfRootConstant(
    BranchBuilder& builder, ValueNode* node, RootIndex root_index) {
  // We assume that Maglev never emits a comparison to a root number.
  DCHECK(!IsNumberRootConstant(root_index));

  // If the node we're checking is in the accumulator, swap it in the branch
  // with the checked value. Cache whether we want to swap, since after we've
  // swapped the accumulator isn't the original node anymore.
  BranchBuilder::PatchAccumulatorInBranchScope scope(builder, node, root_index
```
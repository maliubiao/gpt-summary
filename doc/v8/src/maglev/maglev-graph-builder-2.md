Response: The user wants a summary of the C++ source code file `v8/src/maglev/maglev-graph-builder.cc`.
Specifically, they are asking for the functionality of the code snippet provided, which is the third part of a larger file.
If the code relates to JavaScript, I should provide a JavaScript example.

The provided code snippet seems to focus on:
- **Comparison operations:** `BuildTaggedEqual`
- **Type checking:** `BuildTestUndetectable`, `BuildTestNull`, `BuildTestUndefined`, `VisitTestTypeOf`, `TryReduceTypeOf`
- **Global variable access (load and store):** `TryBuildScriptContextStore`, `TryBuildPropertyCellStore`, `TryBuildScriptContextConstantLoad`, `TryBuildScriptContextLoad`, `TryBuildPropertyCellLoad`, `TryBuildGlobalStore`, `TryBuildGlobalLoad`, `VisitLdaGlobal`, `VisitLdaGlobalInsideTypeof`, `VisitStaGlobal`
- **Variable lookup:** `VisitLdaLookupSlot`, `VisitLdaLookupContextSlot`, `VisitLdaLookupScriptContextSlot`, `VisitLdaLookupGlobalSlot`, `VisitLdaLookupSlotInsideTypeof`, `VisitLdaLookupContextSlotInsideTypeof`, `VisitLdaLookupScriptContextSlotInsideTypeof`, `VisitLdaLookupGlobalSlotInsideTypeof`, `VisitStaLookupSlot`
- **Static type analysis and type assertions:** `StaticTypeForNode`, `CheckStaticType`, `EnsureType`, `SetKnownValue`, `CheckTypes`, `CheckType`, `GetType`, `HaveDifferentTypes`, `HasDifferentType`, `MayBeNullOrUndefined`
- **Smi (Small Integer) handling:** `BuildSmiUntag`, `BuildCheckSmi`
- **Heap object and type checking:** `BuildCheckHeapObject`, `BuildCheckString`, `BuildCheckStringOrStringWrapper`, `BuildCheckNumber`, `BuildCheckSymbol`, `BuildCheckJSReceiver`, `BuildCheckMaps`, `BuildTransitionElementsKindOrCheckMap`, `BuildCompareMaps`, `BuildTransitionElementsKindAndCompareMaps`
- **Memory management and object tracking:** `CanElideWriteBarrier`, `BuildInitializeStore`, `CanTrackObjectChanges`, `GetObjectFromAllocation`, `GetModifiableObjectFromAllocation`, `TryBuildStoreTaggedFieldToAllocation`, `BuildStoreTaggedField`, `BuildStoreTaggedFieldNoWriteBarrier`, `BuildStoreTrustedPointerField`
- **Array element access:** `BuildLoadFixedArrayElement`, `BuildStoreFixedArrayElement`

This part of the `MaglevGraphBuilder` seems to be responsible for generating the intermediate representation (IR) nodes for various JavaScript operations related to type checking, global variable access, variable lookup, and object manipulation with a focus on optimization through static type analysis and object tracking.

Let's craft a summary and a Javascript example.
这是 `v8/src/maglev/maglev-graph-builder.cc` 文件的第三部分，主要负责构建 Maglev 图中的节点，以实现 JavaScript 中关于**类型判断、全局变量访问、作用域变量查找**等功能。

**主要功能归纳:**

1. **类型判断相关操作:**
   - 构建用于判断值是否为 `undefined`、`null` 或不可配置的节点 (`BuildTestUndetectable`, `BuildTestNull`, `BuildTestUndefined`)。
   - 处理 `typeof` 运算符 (`VisitTestTypeOf`, `TryReduceTypeOf`)，尝试基于静态类型信息进行优化。

2. **全局变量访问 (加载和存储):**
   - 尝试基于类型反馈优化全局变量的加载和存储操作 (`TryBuildScriptContextStore`, `TryBuildPropertyCellStore`, `TryBuildScriptContextConstantLoad`, `TryBuildScriptContextLoad`, `TryBuildPropertyCellLoad`, `TryBuildGlobalStore`, `TryBuildGlobalLoad`)，例如直接访问脚本上下文或属性单元。
   - 处理 `LdaGlobal` 和 `StaGlobal` 指令，用于加载和存储全局变量 (`VisitLdaGlobal`, `VisitLdaGlobalInsideTypeof`, `VisitStaGlobal`)。

3. **作用域变量查找:**
   - 处理各种作用域变量查找指令 (`VisitLdaLookupSlot`, `VisitLdaLookupContextSlot`, `VisitLdaLookupScriptContextSlot`, `VisitLdaLookupGlobalSlot`, `VisitLdaLookupSlotInsideTypeof`, `VisitLdaLookupContextSlotInsideTypeof`, `VisitLdaLookupScriptContextSlotInsideTypeof`, `VisitLdaLookupGlobalSlotInsideTypeof`)。
   - 针对 `LdaLookupGlobalSlot`，如果可以确定上下文链上没有扩展对象，则尝试直接进行全局变量加载，否则使用运行时或内建函数进行查找。
   - 处理 `StaLookupSlot` 指令，用于存储作用域变量 (`VisitStaLookupSlot`)。

4. **静态类型分析与断言:**
   - 提供函数用于推断和检查节点的静态类型 (`StaticTypeForNode`, `CheckStaticType`, `EnsureType`, `SetKnownValue`, `CheckTypes`, `CheckType`, `GetType`, `HaveDifferentTypes`, `HasDifferentType`, `MayBeNullOrUndefined`)，用于优化后续操作。

5. **小整数 (Smi) 处理:**
   - 提供用于将 Tagged 值转换为未标记的 Smi 的操作 (`BuildSmiUntag`)。
   - 提供用于检查值是否为 Smi 的操作 (`BuildCheckSmi`)。

6. **堆对象和类型检查:**
   - 提供用于检查值是否为特定类型的堆对象（如字符串、数字、符号、JS 对象等）的操作 (`BuildCheckHeapObject`, `BuildCheckString`, `BuildCheckStringOrStringWrapper`, `BuildCheckNumber`, `BuildCheckSymbol`, `BuildCheckJSReceiver`)。
   - 提供用于检查对象的 `Map` (隐藏类) 的操作 (`BuildCheckMaps`, `BuildTransitionElementsKindOrCheckMap`, `BuildCompareMaps`, `BuildTransitionElementsKindAndCompareMaps`)，用于类型特化和优化属性访问。

7. **内存管理和对象跟踪:**
   - 提供用于判断是否可以省略写屏障的操作 (`CanElideWriteBarrier`)，用于优化对象属性的写入。
   - 提供用于初始化对象存储的操作 (`BuildInitializeStore`)，特别是在对象内联分配时。
   - 提供用于跟踪对象变化的操作 (`CanTrackObjectChanges`, `GetObjectFromAllocation`, `GetModifiableObjectFromAllocation`, `TryBuildStoreTaggedFieldToAllocation`)，用于更激进的优化，例如直接在虚拟对象上操作。
   - 提供用于存储 Tagged 字段的操作 (`BuildStoreTaggedField`, `BuildStoreTaggedFieldNoWriteBarrier`, `BuildStoreTrustedPointerField`)。

8. **数组元素访问:**
   - 提供用于加载和存储固定数组元素的操作 (`BuildLoadFixedArrayElement`, `BuildStoreFixedArrayElement`)。

**与 JavaScript 的关系及示例:**

这段 C++ 代码是 V8 引擎 Maglev 编译器的核心部分，它负责将 JavaScript 代码转换成优化的机器码。上述功能都直接对应着 JavaScript 的语言特性。

**JavaScript 示例:**

```javascript
function example(obj, globalVar, x) {
  // 类型判断
  if (typeof obj === 'undefined') {
    console.log('obj is undefined');
  }
  if (obj === null) {
    console.log('obj is null');
  }

  // 全局变量访问
  globalVar = x + 1;
  console.log(globalVar);

  // 作用域变量查找 (假设 example 函数在一个闭包中)
  let localVar = 10;
  console.log(localVar + x);

  // 对象属性访问
  console.log(obj.property);
  obj.property = x * 2;

  // 数组访问
  const arr = [1, 2, 3];
  console.log(arr[0]);
  arr[1] = x;

  return obj;
}

let myGlobal = 5;
let myObject = { property: 20 };
example(myObject, myGlobal, 3);
```

**C++ 代码与 JavaScript 示例的对应关系:**

- **`typeof obj === 'undefined'`**:  对应 `BuildTestUndefined` 或 `VisitTestTypeOf` 以及相关的 `TryReduceTypeOf`。
- **`obj === null`**: 对应 `BuildTestNull` 或 `BuildTaggedEqual` 与 `RootIndex::kNullValue` 的比较。
- **`globalVar = x + 1`**: 对应 `VisitStaGlobal`，尝试使用 `TryBuildGlobalStore` 进行优化，可能直接操作脚本上下文或属性单元。
- **`console.log(globalVar)`**: 对应 `VisitLdaGlobal`，尝试使用 `TryBuildGlobalLoad` 进行优化。
- **`console.log(localVar + x)`**: `localVar` 的查找可能对应 `VisitLdaLookupSlot` 或 `VisitLdaLookupContextSlot`，取决于 `localVar` 的作用域。
- **`console.log(obj.property)`**:  涉及到属性加载，虽然这段代码没有直接体现，但 Maglev 会生成相应的节点来处理。
- **`obj.property = x * 2`**: 涉及到属性存储，Maglev 会生成相应的节点来处理，并可能使用 `CanElideWriteBarrier` 来优化写屏障。
- **`console.log(arr[0])`**: 对应 `BuildLoadFixedArrayElement`。
- **`arr[1] = x`**: 对应 `BuildStoreFixedArrayElement`。

总而言之，这部分 `MaglevGraphBuilder` 的代码是 Maglev 编译器将高层次的 JavaScript 语义转换为低层次、可执行的图结构的关键组成部分，为后续的优化和代码生成奠定了基础。
### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共9部分，请归纳一下它的功能
```

### 源代码
```
alueNode* lhs = LoadRegister(0);
  ValueNode* rhs = GetAccumulator();
  SetAccumulator(BuildTaggedEqual(lhs, rhs));
}

ValueNode* MaglevGraphBuilder::BuildTestUndetectable(ValueNode* value) {
  if (value->properties().value_representation() ==
      ValueRepresentation::kHoleyFloat64) {
    return AddNewNode<HoleyFloat64IsHole>({value});
  } else if (value->properties().value_representation() !=
             ValueRepresentation::kTagged) {
    return GetBooleanConstant(false);
  }

  if (auto maybe_constant = TryGetConstant(value)) {
    auto map = maybe_constant.value().map(broker());
    return GetBooleanConstant(map.is_undetectable());
  }

  NodeType node_type;
  if (CheckType(value, NodeType::kSmi, &node_type)) {
    return GetBooleanConstant(false);
  }

  auto it = known_node_aspects().FindInfo(value);
  if (known_node_aspects().IsValid(it)) {
    NodeInfo& info = it->second;
    if (info.possible_maps_are_known()) {
      // We check if all the possible maps have the same undetectable bit value.
      DCHECK_GT(info.possible_maps().size(), 0);
      bool first_is_undetectable = info.possible_maps()[0].is_undetectable();
      bool all_the_same_value =
          std::all_of(info.possible_maps().begin(), info.possible_maps().end(),
                      [first_is_undetectable](compiler::MapRef map) {
                        bool is_undetectable = map.is_undetectable();
                        return (first_is_undetectable && is_undetectable) ||
                               (!first_is_undetectable && !is_undetectable);
                      });
      if (all_the_same_value) {
        return GetBooleanConstant(first_is_undetectable);
      }
    }
  }

  enum CheckType type = GetCheckType(node_type);
  return AddNewNode<TestUndetectable>({value}, type);
}

MaglevGraphBuilder::BranchResult MaglevGraphBuilder::BuildBranchIfUndetectable(
    BranchBuilder& builder, ValueNode* value) {
  ValueNode* result = BuildTestUndetectable(value);
  switch (result->opcode()) {
    case Opcode::kRootConstant:
      switch (result->Cast<RootConstant>()->index()) {
        case RootIndex::kTrueValue:
        case RootIndex::kUndefinedValue:
        case RootIndex::kNullValue:
          return builder.AlwaysTrue();
        default:
          return builder.AlwaysFalse();
      }
    case Opcode::kHoleyFloat64IsHole:
      return BuildBranchIfFloat64IsHole(
          builder, result->Cast<HoleyFloat64IsHole>()->input().node());
    case Opcode::kTestUndetectable:
      return builder.Build<BranchIfUndetectable>(
          {result->Cast<TestUndetectable>()->value().node()},
          result->Cast<TestUndetectable>()->check_type());
    default:
      UNREACHABLE();
  }
}

void MaglevGraphBuilder::VisitTestUndetectable() {
  SetAccumulator(BuildTestUndetectable(GetAccumulator()));
}

void MaglevGraphBuilder::VisitTestNull() {
  ValueNode* value = GetAccumulator();
  SetAccumulator(BuildTaggedEqual(value, RootIndex::kNullValue));
}

void MaglevGraphBuilder::VisitTestUndefined() {
  ValueNode* value = GetAccumulator();
  SetAccumulator(BuildTaggedEqual(value, RootIndex::kUndefinedValue));
}

template <typename Function>
ReduceResult MaglevGraphBuilder::TryReduceTypeOf(ValueNode* value,
                                                 const Function& GetResult) {
  // Similar to TF, we assume that all undetectable receiver objects are also
  // callables. In practice, there is only one: document.all.
  switch (CheckTypes(
      value, {NodeType::kBoolean, NodeType::kNumber, NodeType::kString,
              NodeType::kSymbol, NodeType::kCallable, NodeType::kJSArray})) {
    case NodeType::kBoolean:
      return GetResult(TypeOfLiteralFlag::kBoolean, RootIndex::kboolean_string);
    case NodeType::kNumber:
      return GetResult(TypeOfLiteralFlag::kNumber, RootIndex::knumber_string);
    case NodeType::kString:
      return GetResult(TypeOfLiteralFlag::kString, RootIndex::kstring_string);
    case NodeType::kSymbol:
      return GetResult(TypeOfLiteralFlag::kSymbol, RootIndex::ksymbol_string);
    case NodeType::kCallable:
      return Select(
          [&](auto& builder) {
            return BuildBranchIfUndetectable(builder, value);
          },
          [&] {
            return GetResult(TypeOfLiteralFlag::kUndefined,
                             RootIndex::kundefined_string);
          },
          [&] {
            return GetResult(TypeOfLiteralFlag::kFunction,
                             RootIndex::kfunction_string);
          });
    case NodeType::kJSArray:
      // TODO(victorgomes): Track JSReceiver, non-callable types in Maglev.
      return GetResult(TypeOfLiteralFlag::kObject, RootIndex::kobject_string);
    default:
      break;
  }

  if (IsNullValue(value)) {
    return GetResult(TypeOfLiteralFlag::kObject, RootIndex::kobject_string);
  }
  if (IsUndefinedValue(value)) {
    return GetResult(TypeOfLiteralFlag::kUndefined,
                     RootIndex::kundefined_string);
  }

  return ReduceResult::Fail();
}

ReduceResult MaglevGraphBuilder::TryReduceTypeOf(ValueNode* value) {
  return TryReduceTypeOf(value,
                         [&](TypeOfLiteralFlag _, RootIndex idx) -> ValueNode* {
                           return GetRootConstant(idx);
                         });
}

void MaglevGraphBuilder::VisitTestTypeOf() {
  // TODO(v8:7700): Add a branch version of TestTypeOf that does not need to
  // materialise the boolean value.
  TypeOfLiteralFlag literal =
      interpreter::TestTypeOfFlags::Decode(GetFlag8Operand(0));
  if (literal == TypeOfLiteralFlag::kOther) {
    SetAccumulator(GetRootConstant(RootIndex::kFalseValue));
    return;
  }
  ValueNode* value = GetAccumulator();
  auto GetResult = [&](TypeOfLiteralFlag expected, RootIndex _) {
    return GetRootConstant(literal == expected ? RootIndex::kTrueValue
                                               : RootIndex::kFalseValue);
  };
  PROCESS_AND_RETURN_IF_DONE(TryReduceTypeOf(value, GetResult), SetAccumulator);

  SetAccumulator(AddNewNode<TestTypeOf>({value}, literal));
}

ReduceResult MaglevGraphBuilder::TryBuildScriptContextStore(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  DCHECK(global_access_feedback.IsScriptContextSlot());
  if (global_access_feedback.immutable()) {
    return ReduceResult::Fail();
  }
  auto script_context = GetConstant(global_access_feedback.script_context());
  return StoreAndCacheContextSlot(
      script_context, global_access_feedback.slot_index(), GetAccumulator(),
      ContextKind::kScriptContext);
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyCellStore(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  DCHECK(global_access_feedback.IsPropertyCell());

  compiler::PropertyCellRef property_cell =
      global_access_feedback.property_cell();
  if (!property_cell.Cache(broker())) return ReduceResult::Fail();

  compiler::ObjectRef property_cell_value = property_cell.value(broker());
  if (property_cell_value.IsPropertyCellHole()) {
    // The property cell is no longer valid.
    return EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess);
  }

  PropertyDetails property_details = property_cell.property_details();
  DCHECK_EQ(PropertyKind::kData, property_details.kind());

  if (property_details.IsReadOnly()) {
    // Don't even bother trying to lower stores to read-only data
    // properties.
    // TODO(neis): We could generate code that checks if the new value
    // equals the old one and then does nothing or deopts, respectively.
    return ReduceResult::Fail();
  }

  switch (property_details.cell_type()) {
    case PropertyCellType::kUndefined:
      return ReduceResult::Fail();
    case PropertyCellType::kConstant: {
      // TODO(victorgomes): Support non-internalized string.
      if (property_cell_value.IsString() &&
          !property_cell_value.IsInternalizedString()) {
        return ReduceResult::Fail();
      }
      // Record a code dependency on the cell, and just deoptimize if the new
      // value doesn't match the previous value stored inside the cell.
      broker()->dependencies()->DependOnGlobalProperty(property_cell);
      ValueNode* value = GetAccumulator();
      return BuildCheckValue(value, property_cell_value);
    }
    case PropertyCellType::kConstantType: {
      // We rely on stability further below.
      if (property_cell_value.IsHeapObject() &&
          !property_cell_value.AsHeapObject().map(broker()).is_stable()) {
        return ReduceResult::Fail();
      }
      // Record a code dependency on the cell, and just deoptimize if the new
      // value's type doesn't match the type of the previous value in the cell.
      broker()->dependencies()->DependOnGlobalProperty(property_cell);
      ValueNode* value = GetAccumulator();
      if (property_cell_value.IsHeapObject()) {
        compiler::MapRef property_cell_value_map =
            property_cell_value.AsHeapObject().map(broker());
        broker()->dependencies()->DependOnStableMap(property_cell_value_map);
        BuildCheckHeapObject(value);
        RETURN_IF_ABORT(
            BuildCheckMaps(value, base::VectorOf({property_cell_value_map})));
      } else {
        RETURN_IF_ABORT(GetSmiValue(value));
      }
      ValueNode* property_cell_node = GetConstant(property_cell.AsHeapObject());
      BuildStoreTaggedField(property_cell_node, value,
                            PropertyCell::kValueOffset,
                            StoreTaggedMode::kDefault);
      break;
    }
    case PropertyCellType::kMutable: {
      // Record a code dependency on the cell, and just deoptimize if the
      // property ever becomes read-only.
      broker()->dependencies()->DependOnGlobalProperty(property_cell);
      ValueNode* property_cell_node = GetConstant(property_cell.AsHeapObject());
      BuildStoreTaggedField(property_cell_node, GetAccumulator(),
                            PropertyCell::kValueOffset,
                            StoreTaggedMode::kDefault);
      break;
    }
    case PropertyCellType::kInTransition:
      UNREACHABLE();
  }
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::TryBuildScriptContextConstantLoad(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  DCHECK(global_access_feedback.IsScriptContextSlot());
  if (!global_access_feedback.immutable()) return ReduceResult::Fail();
  compiler::OptionalObjectRef maybe_slot_value =
      global_access_feedback.script_context().get(
          broker(), global_access_feedback.slot_index());
  if (!maybe_slot_value) return ReduceResult::Fail();
  return GetConstant(maybe_slot_value.value());
}

ReduceResult MaglevGraphBuilder::TryBuildScriptContextLoad(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  DCHECK(global_access_feedback.IsScriptContextSlot());
  RETURN_IF_DONE(TryBuildScriptContextConstantLoad(global_access_feedback));
  auto script_context = GetConstant(global_access_feedback.script_context());
  ContextSlotMutability mutability =
      global_access_feedback.immutable() ? kImmutable : kMutable;
  return LoadAndCacheContextSlot(script_context,
                                 global_access_feedback.slot_index(),
                                 mutability, ContextKind::kScriptContext);
}

ReduceResult MaglevGraphBuilder::TryBuildPropertyCellLoad(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  // TODO(leszeks): A bunch of this is copied from
  // js-native-context-specialization.cc -- I wonder if we can unify it
  // somehow.
  DCHECK(global_access_feedback.IsPropertyCell());

  compiler::PropertyCellRef property_cell =
      global_access_feedback.property_cell();
  if (!property_cell.Cache(broker())) return ReduceResult::Fail();

  compiler::ObjectRef property_cell_value = property_cell.value(broker());
  if (property_cell_value.IsPropertyCellHole()) {
    // The property cell is no longer valid.
    return EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForGenericNamedAccess);
  }

  PropertyDetails property_details = property_cell.property_details();
  PropertyCellType property_cell_type = property_details.cell_type();
  DCHECK_EQ(PropertyKind::kData, property_details.kind());

  if (!property_details.IsConfigurable() && property_details.IsReadOnly()) {
    return GetConstant(property_cell_value);
  }

  // Record a code dependency on the cell if we can benefit from the
  // additional feedback, or the global property is configurable (i.e.
  // can be deleted or reconfigured to an accessor property).
  if (property_cell_type != PropertyCellType::kMutable ||
      property_details.IsConfigurable()) {
    broker()->dependencies()->DependOnGlobalProperty(property_cell);
  }

  // Load from constant/undefined global property can be constant-folded.
  if (property_cell_type == PropertyCellType::kConstant ||
      property_cell_type == PropertyCellType::kUndefined) {
    return GetConstant(property_cell_value);
  }

  ValueNode* property_cell_node = GetConstant(property_cell.AsHeapObject());
  return BuildLoadTaggedField(property_cell_node, PropertyCell::kValueOffset);
}

ReduceResult MaglevGraphBuilder::TryBuildGlobalStore(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  if (global_access_feedback.IsScriptContextSlot()) {
    return TryBuildScriptContextStore(global_access_feedback);
  } else if (global_access_feedback.IsPropertyCell()) {
    return TryBuildPropertyCellStore(global_access_feedback);
  } else {
    DCHECK(global_access_feedback.IsMegamorphic());
    return ReduceResult::Fail();
  }
}

ReduceResult MaglevGraphBuilder::TryBuildGlobalLoad(
    const compiler::GlobalAccessFeedback& global_access_feedback) {
  if (global_access_feedback.IsScriptContextSlot()) {
    return TryBuildScriptContextLoad(global_access_feedback);
  } else if (global_access_feedback.IsPropertyCell()) {
    return TryBuildPropertyCellLoad(global_access_feedback);
  } else {
    DCHECK(global_access_feedback.IsMegamorphic());
    return ReduceResult::Fail();
  }
}

void MaglevGraphBuilder::VisitLdaGlobal() {
  // LdaGlobal <name_index> <slot>

  static const int kNameOperandIndex = 0;
  static const int kSlotOperandIndex = 1;

  compiler::NameRef name = GetRefOperand<Name>(kNameOperandIndex);
  FeedbackSlot slot = GetSlotOperand(kSlotOperandIndex);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  BuildLoadGlobal(name, feedback_source, TypeofMode::kNotInside);
}

void MaglevGraphBuilder::VisitLdaGlobalInsideTypeof() {
  // LdaGlobalInsideTypeof <name_index> <slot>

  static const int kNameOperandIndex = 0;
  static const int kSlotOperandIndex = 1;

  compiler::NameRef name = GetRefOperand<Name>(kNameOperandIndex);
  FeedbackSlot slot = GetSlotOperand(kSlotOperandIndex);
  compiler::FeedbackSource feedback_source{feedback(), slot};
  BuildLoadGlobal(name, feedback_source, TypeofMode::kInside);
}

void MaglevGraphBuilder::VisitStaGlobal() {
  // StaGlobal <name_index> <slot>
  FeedbackSlot slot = GetSlotOperand(1);
  compiler::FeedbackSource feedback_source{feedback(), slot};

  const compiler::ProcessedFeedback& access_feedback =
      broker()->GetFeedbackForGlobalAccess(feedback_source);

  if (access_feedback.IsInsufficient()) {
    RETURN_VOID_ON_ABORT(EmitUnconditionalDeopt(
        DeoptimizeReason::kInsufficientTypeFeedbackForGenericGlobalAccess));
  }

  const compiler::GlobalAccessFeedback& global_access_feedback =
      access_feedback.AsGlobalAccess();
  RETURN_VOID_IF_DONE(TryBuildGlobalStore(global_access_feedback));

  ValueNode* value = GetAccumulator();
  compiler::NameRef name = GetRefOperand<Name>(0);
  ValueNode* context = GetContext();
  AddNewNode<StoreGlobal>({context, value}, name, feedback_source);
}

void MaglevGraphBuilder::VisitLdaLookupSlot() {
  // LdaLookupSlot <name_index>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  SetAccumulator(BuildCallRuntime(Runtime::kLoadLookupSlot, {name}).value());
}

void MaglevGraphBuilder::VisitLdaLookupContextSlot() {
  // LdaLookupContextSlot <name_index> <feedback_slot> <depth>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
  ValueNode* depth =
      GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
  SetAccumulator(
      BuildCallBuiltin<Builtin::kLookupContextTrampoline>({name, depth, slot}));
}

void MaglevGraphBuilder::VisitLdaLookupScriptContextSlot() {
  // LdaLookupContextSlot <name_index> <feedback_slot> <depth>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
  ValueNode* depth =
      GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
  SetAccumulator(BuildCallBuiltin<Builtin::kLookupScriptContextTrampoline>(
      {name, depth, slot}));
}

bool MaglevGraphBuilder::CheckContextExtensions(size_t depth) {
  compiler::OptionalScopeInfoRef maybe_scope_info =
      graph()->TryGetScopeInfo(GetContext(), broker());
  if (!maybe_scope_info.has_value()) return false;
  compiler::ScopeInfoRef scope_info = maybe_scope_info.value();
  for (uint32_t d = 0; d < depth; d++) {
    CHECK_NE(scope_info.scope_type(), ScopeType::SCRIPT_SCOPE);
    CHECK_NE(scope_info.scope_type(), ScopeType::REPL_MODE_SCOPE);
    if (scope_info.HasContextExtensionSlot() &&
        !broker()->dependencies()->DependOnEmptyContextExtension(scope_info)) {
      // Using EmptyContextExtension dependency is not possible for this
      // scope_info, so generate dynamic checks.
      ValueNode* context = GetContextAtDepth(GetContext(), d);
      // Only support known contexts so that we can check that there's no
      // extension at compile time. Otherwise we could end up in a deopt loop
      // once we do get an extension.
      compiler::OptionalHeapObjectRef maybe_ref = TryGetConstant(context);
      if (!maybe_ref) return false;
      compiler::ContextRef context_ref = maybe_ref.value().AsContext();
      compiler::OptionalObjectRef extension_ref =
          context_ref.get(broker(), Context::EXTENSION_INDEX);
      // The extension may be concurrently installed while we're checking the
      // context, in which case it may still be uninitialized. This still
      // means an extension is about to appear, so we should block this
      // optimization.
      if (!extension_ref) return false;
      if (!extension_ref->IsUndefined()) return false;
      ValueNode* extension = LoadAndCacheContextSlot(
          context, Context::EXTENSION_INDEX, kMutable, ContextKind::kDefault);
      AddNewNode<CheckValue>({extension}, broker()->undefined_value());
    }
    CHECK_IMPLIES(!scope_info.HasOuterScopeInfo(), d + 1 == depth);
    if (scope_info.HasOuterScopeInfo()) {
      scope_info = scope_info.OuterScopeInfo(broker());
    }
  }
  return true;
}

void MaglevGraphBuilder::VisitLdaLookupGlobalSlot() {
  // LdaLookupGlobalSlot <name_index> <feedback_slot> <depth>
  compiler::NameRef name = GetRefOperand<Name>(0);
  if (CheckContextExtensions(iterator_.GetUnsignedImmediateOperand(2))) {
    FeedbackSlot slot = GetSlotOperand(1);
    compiler::FeedbackSource feedback_source{feedback(), slot};
    BuildLoadGlobal(name, feedback_source, TypeofMode::kNotInside);
  } else {
    ValueNode* name = GetConstant(GetRefOperand<Name>(0));
    ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
    ValueNode* depth =
        GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
    ValueNode* result;
    if (parent_) {
      ValueNode* vector = GetConstant(feedback());
      result = BuildCallBuiltin<Builtin::kLookupGlobalIC>(
          {name, depth, slot, vector});
    } else {
      result = BuildCallBuiltin<Builtin::kLookupGlobalICTrampoline>(
          {name, depth, slot});
    }
    SetAccumulator(result);
  }
}

void MaglevGraphBuilder::VisitLdaLookupSlotInsideTypeof() {
  // LdaLookupSlotInsideTypeof <name_index>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  SetAccumulator(
      BuildCallRuntime(Runtime::kLoadLookupSlotInsideTypeof, {name}).value());
}

void MaglevGraphBuilder::VisitLdaLookupContextSlotInsideTypeof() {
  // LdaLookupContextSlotInsideTypeof <name_index> <context_slot> <depth>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
  ValueNode* depth =
      GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
  SetAccumulator(
      BuildCallBuiltin<Builtin::kLookupContextInsideTypeofTrampoline>(
          {name, depth, slot}));
}

void MaglevGraphBuilder::VisitLdaLookupScriptContextSlotInsideTypeof() {
  // LdaLookupContextSlotInsideTypeof <name_index> <context_slot> <depth>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
  ValueNode* depth =
      GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
  SetAccumulator(
      BuildCallBuiltin<Builtin::kLookupScriptContextInsideTypeofTrampoline>(
          {name, depth, slot}));
}

void MaglevGraphBuilder::VisitLdaLookupGlobalSlotInsideTypeof() {
  // LdaLookupGlobalSlotInsideTypeof <name_index> <context_slot> <depth>
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  ValueNode* slot = GetTaggedIndexConstant(iterator_.GetIndexOperand(1));
  ValueNode* depth =
      GetTaggedIndexConstant(iterator_.GetUnsignedImmediateOperand(2));
  ValueNode* result;
  if (parent_) {
    ValueNode* vector = GetConstant(feedback());
    result = BuildCallBuiltin<Builtin::kLookupGlobalICInsideTypeof>(
        {name, depth, slot, vector});
  } else {
    result = BuildCallBuiltin<Builtin::kLookupGlobalICInsideTypeofTrampoline>(
        {name, depth, slot});
  }
  SetAccumulator(result);
}

namespace {
Runtime::FunctionId StaLookupSlotFunction(uint8_t sta_lookup_slot_flags) {
  using Flags = interpreter::StoreLookupSlotFlags;
  switch (Flags::GetLanguageMode(sta_lookup_slot_flags)) {
    case LanguageMode::kStrict:
      return Runtime::kStoreLookupSlot_Strict;
    case LanguageMode::kSloppy:
      if (Flags::IsLookupHoistingMode(sta_lookup_slot_flags)) {
        return Runtime::kStoreLookupSlot_SloppyHoisting;
      } else {
        return Runtime::kStoreLookupSlot_Sloppy;
      }
  }
}
}  // namespace

void MaglevGraphBuilder::VisitStaLookupSlot() {
  // StaLookupSlot <name_index> <flags>
  ValueNode* value = GetAccumulator();
  ValueNode* name = GetConstant(GetRefOperand<Name>(0));
  uint32_t flags = GetFlag8Operand(1);
  EscapeContext();
  SetAccumulator(
      BuildCallRuntime(StaLookupSlotFunction(flags), {name, value}).value());
}

NodeType StaticTypeForNode(compiler::JSHeapBroker* broker,
                           LocalIsolate* isolate, ValueNode* node) {
  switch (node->properties().value_representation()) {
    case ValueRepresentation::kInt32:
    case ValueRepresentation::kUint32:
    case ValueRepresentation::kFloat64:
      return NodeType::kNumber;
    case ValueRepresentation::kHoleyFloat64:
      return NodeType::kNumberOrOddball;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
    case ValueRepresentation::kTagged:
      break;
  }
  switch (node->opcode()) {
    case Opcode::kPhi:
      return node->Cast<Phi>()->type();
    case Opcode::kCheckedSmiTagInt32:
    case Opcode::kCheckedSmiTagUint32:
    case Opcode::kCheckedSmiTagFloat64:
    case Opcode::kUnsafeSmiTagInt32:
    case Opcode::kUnsafeSmiTagUint32:
    case Opcode::kSmiConstant:
      return NodeType::kSmi;
    case Opcode::kInt32ToNumber:
    case Opcode::kUint32ToNumber:
    case Opcode::kFloat64ToTagged:
      return NodeType::kNumber;
    case Opcode::kHoleyFloat64ToTagged:
      return NodeType::kNumberOrOddball;
    case Opcode::kAllocationBlock:
    case Opcode::kInlinedAllocation:
      return StaticTypeForMap(node->Cast<InlinedAllocation>()->object()->map(),
                              broker);
    case Opcode::kRootConstant: {
      RootConstant* constant = node->Cast<RootConstant>();
      switch (constant->index()) {
        case RootIndex::kTrueValue:
        case RootIndex::kFalseValue:
          return NodeType::kBoolean;
        case RootIndex::kUndefinedValue:
        case RootIndex::kNullValue:
          return NodeType::kOddball;
        default:
          break;
      }
      [[fallthrough]];
    }
    case Opcode::kConstant: {
      compiler::HeapObjectRef ref =
          MaglevGraphBuilder::TryGetConstant(broker, isolate, node).value();
      return StaticTypeForConstant(broker, ref);
    }
    case Opcode::kToNumberOrNumeric:
      if (node->Cast<ToNumberOrNumeric>()->mode() ==
          Object::Conversion::kToNumber) {
        return NodeType::kNumber;
      }
      // TODO(verwaest): Check what we need here.
      return NodeType::kUnknown;
    case Opcode::kToString:
    case Opcode::kNumberToString:
    case Opcode::kStringConcat:
    case Opcode::kStringWrapperConcat:
      return NodeType::kString;
    case Opcode::kCheckedInternalizedString:
      return NodeType::kInternalizedString;
    case Opcode::kToObject:
    case Opcode::kCreateObjectLiteral:
    case Opcode::kCreateShallowObjectLiteral:
      return NodeType::kJSReceiver;
    case Opcode::kCreateArrayLiteral:
    case Opcode::kCreateShallowArrayLiteral:
      return NodeType::kJSArray;
    case Opcode::kToName:
      return NodeType::kName;
    case Opcode::kFastCreateClosure:
    case Opcode::kCreateClosure:
      return NodeType::kCallable;
    case Opcode::kInt32Compare:
    case Opcode::kFloat64Compare:
    case Opcode::kGenericEqual:
    case Opcode::kGenericStrictEqual:
    case Opcode::kGenericLessThan:
    case Opcode::kGenericLessThanOrEqual:
    case Opcode::kGenericGreaterThan:
    case Opcode::kGenericGreaterThanOrEqual:
    case Opcode::kLogicalNot:
    case Opcode::kStringEqual:
    case Opcode::kTaggedEqual:
    case Opcode::kTaggedNotEqual:
    case Opcode::kTestInstanceOf:
    case Opcode::kTestTypeOf:
    case Opcode::kTestUndetectable:
    case Opcode::kToBoolean:
    case Opcode::kToBooleanLogicalNot:
      return NodeType::kBoolean;
      // Not value nodes:
#define GENERATE_CASE(Name) case Opcode::k##Name:
      CONTROL_NODE_LIST(GENERATE_CASE)
      NON_VALUE_NODE_LIST(GENERATE_CASE)
#undef GENERATE_CASE
      UNREACHABLE();
    case Opcode::kTransitionElementsKind:
    // Unsorted value nodes. TODO(maglev): See which of these should return
    // something else than kUnknown.
    case Opcode::kIdentity:
    case Opcode::kArgumentsElements:
    case Opcode::kArgumentsLength:
    case Opcode::kRestLength:
    case Opcode::kCall:
    case Opcode::kCallBuiltin:
    case Opcode::kCallCPPBuiltin:
    case Opcode::kCallForwardVarargs:
    case Opcode::kCallRuntime:
    case Opcode::kCallWithArrayLike:
    case Opcode::kCallWithSpread:
    case Opcode::kCallKnownApiFunction:
    case Opcode::kCallKnownJSFunction:
    case Opcode::kCallSelf:
    case Opcode::kConstruct:
    case Opcode::kCheckConstructResult:
    case Opcode::kCheckDerivedConstructResult:
    case Opcode::kConstructWithSpread:
    case Opcode::kConvertReceiver:
    case Opcode::kConvertHoleToUndefined:
    case Opcode::kCreateFunctionContext:
    case Opcode::kCreateRegExpLiteral:
    case Opcode::kDeleteProperty:
    case Opcode::kEnsureWritableFastElements:
    case Opcode::kExtendPropertiesBackingStore:
    case Opcode::kForInPrepare:
    case Opcode::kForInNext:
    case Opcode::kGeneratorRestoreRegister:
    case Opcode::kGetIterator:
    case Opcode::kGetSecondReturnedValue:
    case Opcode::kGetTemplateObject:
    case Opcode::kHasInPrototypeChain:
    case Opcode::kInitialValue:
    case Opcode::kLoadTaggedField:
    case Opcode::kLoadTaggedFieldForProperty:
    case Opcode::kLoadTaggedFieldForContextSlot:
    case Opcode::kLoadTaggedFieldForScriptContextSlot:
    case Opcode::kLoadDoubleField:
    case Opcode::kLoadTaggedFieldByFieldIndex:
    case Opcode::kLoadFixedArrayElement:
    case Opcode::kLoadFixedDoubleArrayElement:
    case Opcode::kLoadHoleyFixedDoubleArrayElement:
    case Opcode::kLoadHoleyFixedDoubleArrayElementCheckedNotHole:
    case Opcode::kLoadSignedIntDataViewElement:
    case Opcode::kLoadDoubleDataViewElement:
    case Opcode::kLoadTypedArrayLength:
    case Opcode::kLoadSignedIntTypedArrayElement:
    case Opcode::kLoadUnsignedIntTypedArrayElement:
    case Opcode::kLoadDoubleTypedArrayElement:
    case Opcode::kLoadEnumCacheLength:
    case Opcode::kLoadGlobal:
    case Opcode::kLoadNamedGeneric:
    case Opcode::kLoadNamedFromSuperGeneric:
    case Opcode::kMaybeGrowFastElements:
    case Opcode::kMigrateMapIfNeeded:
    case Opcode::kSetNamedGeneric:
    case Opcode::kDefineNamedOwnGeneric:
    case Opcode::kStoreInArrayLiteralGeneric:
    case Opcode::kStoreGlobal:
    case Opcode::kGetKeyedGeneric:
    case Opcode::kSetKeyedGeneric:
    case Opcode::kDefineKeyedOwnGeneric:
    case Opcode::kRegisterInput:
    case Opcode::kCheckedSmiSizedInt32:
    case Opcode::kCheckedSmiUntag:
    case Opcode::kUnsafeSmiUntag:
    case Opcode::kCheckedObjectToIndex:
    case Opcode::kCheckedTruncateNumberOrOddballToInt32:
    case Opcode::kCheckedInt32ToUint32:
    case Opcode::kUnsafeInt32ToUint32:
    case Opcode::kCheckedUint32ToInt32:
    case Opcode::kChangeInt32ToFloat64:
    case Opcode::kChangeUint32ToFloat64:
    case Opcode::kCheckedTruncateFloat64ToInt32:
    case Opcode::kCheckedTruncateFloat64ToUint32:
    case Opcode::kTruncateNumberOrOddballToInt32:
    case Opcode::kTruncateUint32ToInt32:
    case Opcode::kTruncateFloat64ToInt32:
    case Opcode::kUnsafeTruncateUint32ToInt32:
    case Opcode::kUnsafeTruncateFloat64ToInt32:
    case Opcode::kInt32ToUint8Clamped:
    case Opcode::kUint32ToUint8Clamped:
    case Opcode::kFloat64ToUint8Clamped:
    case Opcode::kCheckedNumberToUint8Clamped:
    case Opcode::kFloat64ToHeapNumberForField:
    case Opcode::kCheckedNumberOrOddballToFloat64:
    case Opcode::kUncheckedNumberOrOddballToFloat64:
    case Opcode::kCheckedNumberOrOddballToHoleyFloat64:
    case Opcode::kCheckedHoleyFloat64ToFloat64:
    case Opcode::kHoleyFloat64ToMaybeNanFloat64:
    case Opcode::kHoleyFloat64IsHole:
    case Opcode::kSetPendingMessage:
    case Opcode::kStringAt:
    case Opcode::kStringLength:
    case Opcode::kAllocateElementsArray:
    case Opcode::kUpdateJSArrayLength:
    case Opcode::kVirtualObject:
    case Opcode::kGetContinuationPreservedEmbedderData:
    case Opcode::kExternalConstant:
    case Opcode::kFloat64Constant:
    case Opcode::kInt32Constant:
    case Opcode::kUint32Constant:
    case Opcode::kTaggedIndexConstant:
    case Opcode::kTrustedConstant:
    case Opcode::kInt32AbsWithOverflow:
    case Opcode::kInt32AddWithOverflow:
    case Opcode::kInt32SubtractWithOverflow:
    case Opcode::kInt32MultiplyWithOverflow:
    case Opcode::kInt32DivideWithOverflow:
    case Opcode::kInt32ModulusWithOverflow:
    case Opcode::kInt32BitwiseAnd:
    case Opcode::kInt32BitwiseOr:
    case Opcode::kInt32BitwiseXor:
    case Opcode::kInt32ShiftLeft:
    case Opcode::kInt32ShiftRight:
    case Opcode::kInt32ShiftRightLogical:
    case Opcode::kInt32BitwiseNot:
    case Opcode::kInt32NegateWithOverflow:
    case Opcode::kInt32IncrementWithOverflow:
    case Opcode::kInt32DecrementWithOverflow:
    case Opcode::kInt32ToBoolean:
    case Opcode::kFloat64Abs:
    case Opcode::kFloat64Add:
    case Opcode::kFloat64Subtract:
    case Opcode::kFloat64Multiply:
    case Opcode::kFloat64Divide:
    case Opcode::kFloat64Exponentiate:
    case Opcode::kFloat64Modulus:
    case Opcode::kFloat64Negate:
    case Opcode::kFloat64Round:
    case Opcode::kFloat64ToBoolean:
    case Opcode::kFloat64Ieee754Unary:
    case Opcode::kCheckedSmiIncrement:
    case Opcode::kCheckedSmiDecrement:
    case Opcode::kGenericAdd:
    case Opcode::kGenericSubtract:
    case Opcode::kGenericMultiply:
    case Opcode::kGenericDivide:
    case Opcode::kGenericModulus:
    case Opcode::kGenericExponentiate:
    case Opcode::kGenericBitwiseAnd:
    case Opcode::kGenericBitwiseOr:
    case Opcode::kGenericBitwiseXor:
    case Opcode::kGenericShiftLeft:
    case Opcode::kGenericShiftRight:
    case Opcode::kGenericShiftRightLogical:
    case Opcode::kGenericBitwiseNot:
    case Opcode::kGenericNegate:
    case Opcode::kGenericIncrement:
    case Opcode::kGenericDecrement:
    case Opcode::kBuiltinStringFromCharCode:
    case Opcode::kBuiltinStringPrototypeCharCodeOrCodePointAt:
      return NodeType::kUnknown;
  }
}

bool MaglevGraphBuilder::CheckStaticType(ValueNode* node, NodeType type,
                                         NodeType* current_type) {
  NodeType static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (current_type) *current_type = static_type;
  return NodeTypeIs(static_type, type);
}

bool MaglevGraphBuilder::EnsureType(ValueNode* node, NodeType type,
                                    NodeType* old_type) {
  if (CheckStaticType(node, type, old_type)) return true;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (old_type) *old_type = known_info->type();
  if (NodeTypeIs(known_info->type(), type)) return true;
  known_info->CombineType(type);
  if (auto phi = node->TryCast<Phi>()) {
    known_info->CombineType(phi->type());
  }
  return false;
}

template <typename Function>
bool MaglevGraphBuilder::EnsureType(ValueNode* node, NodeType type,
                                    Function ensure_new_type) {
  if (CheckStaticType(node, type)) return true;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (NodeTypeIs(known_info->type(), type)) return true;
  ensure_new_type(known_info->type());
  known_info->CombineType(type);
  return false;
}

void MaglevGraphBuilder::SetKnownValue(ValueNode* node, compiler::ObjectRef ref,
                                       NodeType new_node_type) {
  DCHECK(!node->Is<Constant>());
  DCHECK(!node->Is<RootConstant>());
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  // ref type should be compatible with type.
  DCHECK(NodeTypeIs(StaticTypeForConstant(broker(), ref), new_node_type));
  known_info->CombineType(new_node_type);
  known_info->alternative().set_checked_value(GetConstant(ref));
}

NodeType MaglevGraphBuilder::CheckTypes(ValueNode* node,
                                        std::initializer_list<NodeType> types) {
  auto it = known_node_aspects().FindInfo(node);
  bool has_kna = known_node_aspects().IsValid(it);
  for (NodeType type : types) {
    if (CheckStaticType(node, type)) return type;
    if (has_kna) {
      if (NodeTypeIs(it->second.type(), type)) return type;
    }
  }
  return NodeType::kUnknown;
}

bool MaglevGraphBuilder::CheckType(ValueNode* node, NodeType type,
                                   NodeType* current_type) {
  if (CheckStaticType(node, type, current_type)) return true;
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) return false;
  if (current_type) *current_type = it->second.type();
  return NodeTypeIs(it->second.type(), type);
}

NodeType MaglevGraphBuilder::GetType(ValueNode* node) {
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) {
    return StaticTypeForNode(broker(), local_isolate(), node);
  }
  NodeType actual_type = it->second.type();
  if (auto phi = node->TryCast<Phi>()) {
    actual_type = CombineType(actual_type, phi->type());
  }
#ifdef DEBUG
  NodeType static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (!NodeTypeIs(actual_type, static_type)) {
    // In case we needed a numerical alternative of a smi value, the type
    // must generalize. In all other cases the node info type should reflect the
    // actual type.
    DCHECK(static_type == NodeType::kSmi && actual_type == NodeType::kNumber &&
           !known_node_aspects().TryGetInfoFor(node)->alternative().has_none());
  }
#endif  // DEBUG
  return actual_type;
}

bool MaglevGraphBuilder::HaveDifferentTypes(ValueNode* lhs, ValueNode* rhs) {
  return HasDifferentType(lhs, GetType(rhs));
}

// Note: this is conservative, ie, returns true if {lhs} cannot be {rhs}.
// It might return false even if {lhs} is not {rhs}.
bool MaglevGraphBuilder::HasDifferentType(ValueNode* lhs, NodeType rhs_type) {
  NodeType lhs_type = GetType(lhs);
  if (lhs_type == NodeType::kUnknown || rhs_type == NodeType::kUnknown) {
    return false;
  }
  return IntersectType(lhs_type, rhs_type) == NodeType::kUnknown;
}

bool MaglevGraphBuilder::MayBeNullOrUndefined(ValueNode* node) {
  NodeType static_type = StaticTypeForNode(broker(), local_isolate(), node);
  if (!NodeTypeMayBeNullOrUndefined(static_type)) return false;
  auto it = known_node_aspects().FindInfo(node);
  if (!known_node_aspects().IsValid(it)) return true;
  return NodeTypeMayBeNullOrUndefined(it->second.type());
}

ValueNode* MaglevGraphBuilder::BuildSmiUntag(ValueNode* node) {
  if (EnsureType(node, NodeType::kSmi)) {
    if (SmiValuesAre31Bits()) {
      if (auto phi = node->TryCast<Phi>()) {
        phi->SetUseRequires31BitValue();
      }
    }
    return AddNewNode<UnsafeSmiUntag>({node});
  } else {
    return AddNewNode<CheckedSmiUntag>({node});
  }
}

namespace {
NodeType TaggedToFloat64ConversionTypeToNodeType(
    TaggedToFloat64ConversionType conversion_type) {
  switch (conversion_type) {
    case TaggedToFloat64ConversionType::kOnlyNumber:
      return NodeType::kNumber;
    case TaggedToFloat64ConversionType::kNumberOrBoolean:
      return NodeType::kNumberOrBoolean;
    case TaggedToFloat64ConversionType::kNumberOrOddball:
      return NodeType::kNumberOrOddball;
  }
}
}  // namespace

ValueNode* MaglevGraphBuilder::BuildNumberOrOddballToFloat64(
    ValueNode* node, TaggedToFloat64ConversionType conversion_type) {
  NodeType old_type;
  if (EnsureType(node, TaggedToFloat64ConversionTypeToNodeType(conversion_type),
                 &old_type)) {
    if (old_type == NodeType::kSmi) {
      ValueNode* untagged_smi = BuildSmiUntag(node);
      return AddNewNode<ChangeInt32ToFloat64>({untagged_smi});
    }
    return AddNewNode<UncheckedNumberOrOddballToFloat64>({node},
                                                         conversion_type);
  } else {
    return AddNewNode<CheckedNumberOrOddballToFloat64>({node}, conversion_type);
  }
}

ReduceResult MaglevGraphBuilder::BuildCheckSmi(ValueNode* object,
                                               bool elidable) {
  if (CheckStaticType(object, NodeType::kSmi)) return object;
  if (CheckType(object, NodeType::kAnyHeapObject)) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kNotASmi);
  }
  if (EnsureType(object, NodeType::kSmi) && elidable) return object;
  switch (object->value_representation()) {
    case ValueRepresentation::kInt32:
      if (!SmiValuesAre32Bits()) {
        AddNewNode<CheckInt32IsSmi>({object});
      }
      break;
    case ValueRepresentation::kUint32:
      AddNewNode<CheckUint32IsSmi>({object});
      break;
    case ValueRepresentation::kFloat64:
    case ValueRepresentation::kHoleyFloat64:
      AddNewNode<CheckHoleyFloat64IsSmi>({object});
      break;
    case ValueRepresentation::kTagged:
      AddNewNode<CheckSmi>({object});
      break;
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  return object;
}

void MaglevGraphBuilder::BuildCheckHeapObject(ValueNode* object) {
  if (EnsureType(object, NodeType::kAnyHeapObject)) return;
  AddNewNode<CheckHeapObject>({object});
}

void MaglevGraphBuilder::BuildCheckString(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kString, &known_type)) return;
  AddNewNode<CheckString>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckStringOrStringWrapper(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kStringOrStringWrapper, &known_type)) return;
  AddNewNode<CheckStringOrStringWrapper>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckNumber(ValueNode* object) {
  if (EnsureType(object, NodeType::kNumber)) return;
  AddNewNode<CheckNumber>({object}, Object::Conversion::kToNumber);
}

void MaglevGraphBuilder::BuildCheckSymbol(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kSymbol, &known_type)) return;
  AddNewNode<CheckSymbol>({object}, GetCheckType(known_type));
}

void MaglevGraphBuilder::BuildCheckJSReceiver(ValueNode* object) {
  NodeType known_type;
  if (EnsureType(object, NodeType::kJSReceiver, &known_type)) return;
  AddNewNode<CheckInstanceType>({object}, GetCheckType(known_type),
                                FIRST_JS_RECEIVER_TYPE, LAST_JS_RECEIVER_TYPE);
}

namespace {

class KnownMapsMerger {
 public:
  explicit KnownMapsMerger(compiler::JSHeapBroker* broker, Zone* zone,
                           base::Vector<const compiler::MapRef> requested_maps)
      : broker_(broker), zone_(zone), requested_maps_(requested_maps) {}

  void IntersectWithKnownNodeAspects(
      ValueNode* object, const KnownNodeAspects& known_node_aspects) {
    auto node_info_it = known_node_aspects.FindInfo(object);
    bool has_node_info = known_node_aspects.IsValid(node_info_it);
    NodeType type =
        has_node_info ? node_info_it->second.type() : NodeType::kUnknown;
    if (has_node_info && node_info_it->second.possible_maps_are_known()) {
      // TODO(v8:7700): Make intersection non-quadratic.
      for (compiler::MapRef possible_map :
           node_info_it->second.possible_maps()) {
        if (std::find(requested_maps_.begin(), requested_maps_.end(),
                      possible_map) != requested_maps_.end()) {
          // No need to add dependencies, we already have them for all known
          // possible maps.
          // Filter maps which are impossible given this objects type. Since we
          // want to prove that an object with map `map` is not an instance of
          // `type`, we cannot use `StaticTypeForMap`, as it only provides an
          // approximation. This filtering is done to avoid creating
          // non-sensical types later (e.g. if we think only a non-string map
          // is possible, after a string check).
          if (IsInstanceOfNodeType(possible_map, type, broker_)) {
            InsertMap(possible_map);
          }
        } else {
          known_maps_are_subset_of_requested_maps_ = false;
        }
      }
      if (intersect_set_.is_empty()) {
        node_type_ = NodeType::kUnknown;
      }
    } else {
      // A missing entry here means the universal set, i.e., we don't know
      // anything about the possible maps of the object. Intersect with the
      // universal set, which means just insert all requested maps.
      known_maps_are_subset_of_requested_maps_ = false;
      existing_known_maps_found_ = false;
      for (compiler::MapRef map : requested_maps_) {
        InsertMap(map);
      }
    }
  }

  void UpdateKnownNodeAspects(ValueNode* object,
                              KnownNodeAspects& known_node_aspects) {
    // Update known maps.
    auto node_info = known_node_aspects.GetOrCreateInfoFor(
        object, broker_, broker_->local_isolate());
    node_info->SetPossibleMaps(intersect_set_, any_map_is_unstable_, node_type_,
                               broker_);
    // Make sure known_node_aspects.any_map_for_any_node_is_unstable is updated
    // in case any_map_is_unstable changed to true for this object -- this can
    // happen if this was an intersection with the universal set which added new
    // possible unstable maps.
    if (any_map_is_unstable_) {
      known_node_aspects.any_map_for_any_node_is_unstable = true;
    }
    // At this point, known_node_aspects.any_map_for_any_node_is_unstable may be
    // true despite there no longer being any unstable maps for any nodes (if
    // this was the only node with unstable maps and this intersection removed
    // those). This is ok, because that's at worst just an overestimate -- we
    // could track whether this node's any_map_is_unstable flipped from true to
    // false, but this is likely overkill.
    // Insert stable map dependencies which weren't inserted yet. This is only
    // needed if our set of known maps was empty and we created it anew based on
    // maps we checked.
    if (!existing_known_maps_found_) {
      for (compiler::MapRef map : intersect_set_) {
        if (map.is_stable()) {
          broker_->dependencies()->DependOnStableMap(map);
        }
      }
    } else {
      // TODO(victorgomes): Add a DCHECK_SLOW that checks if the maps already
      // exist in the CompilationDependencySet.
    }
  }

  bool known_maps_are_subset_of_requested_maps() const {
    return known_maps_are_subset_of_requested_maps_;
  }
  bool emit_check_with_migration() const { return emit_check_with_migration_; }

  const compiler::ZoneRefSet<Map>& intersect_set() const {
    return intersect_set_;
  }

  NodeType node_type() const { return node_type_; }

 private:
  compiler::JSHeapBroker* broker_;
  Zone* zone_;
  base::Vector<const compiler::MapRef> requested_maps_;
  compiler::ZoneRefSet<Map> intersect_set_;
  bool known_maps_are_subset_of_requested_maps_ = true;
  bool existing_known_maps_found_ = true;
  bool emit_check_with_migration_ = false;
  bool any_map_is_unstable_ = false;
  NodeType node_type_ = static_cast<NodeType>(-1);

  Zone* zone() const { return zone_; }

  void InsertMap(compiler::MapRef map) {
    if (map.is_migration_target()) {
      emit_check_with_migration_ = true;
    }
    NodeType new_type = StaticTypeForMap(map, broker_);
    if (new_type == NodeType::kHeapNumber) {
      new_type = IntersectType(new_type, NodeType::kSmi);
    }
    node_type_ = IntersectType(node_type_, new_type);
    if (!map.is_stable()) {
      any_map_is_unstable_ = true;
    }
    intersect_set_.insert(map, zone());
  }
};

}  // namespace

ReduceResult MaglevGraphBuilder::BuildCheckMaps(
    ValueNode* object, base::Vector<const compiler::MapRef> maps,
    std::optional<ValueNode*> map) {
  // TODO(verwaest): Support other objects with possible known stable maps as
  // well.
  if (compiler::OptionalHeapObjectRef constant = TryGetConstant(object)) {
    // For constants with stable maps that match one of the desired maps, we
    // don't need to emit a map check, and can use the dependency -- we
    // can't do this for unstable maps because the constant could migrate
    // during compilation.
    compiler::MapRef constant_map = constant.value().map(broker());
    if (std::find(maps.begin(), maps.end(), constant_map) != maps.end()) {
      if (constant_map.is_stable()) {
        broker()->dependencies()->DependOnStableMap(constant_map);
        return ReduceResult::Done();
      }
      // TODO(verwaest): Reduce maps to the constant map.
    } else {
      // TODO(leszeks): Insert an unconditional deopt if the constant map
      // doesn't match the required map.
    }
  }

  NodeInfo* known_info = GetOrCreateInfoFor(object);

  // Calculates if known maps are a subset of maps, their map intersection and
  // whether we should emit check with migration.
  KnownMapsMerger merger(broker(), zone(), maps);
  merger.IntersectWithKnownNodeAspects(object, known_node_aspects());

  // If the known maps are the subset of the maps to check, we are done.
  if (merger.known_maps_are_subset_of_requested_maps()) {
    // The node type of known_info can get out of sync with the possible maps.
    // For instance after merging with an effectively dead branch (i.e., check
    // contradicting all possible maps).
    // TODO(olivf) Try to combine node_info and possible maps and ensure that
    // narrowing the type also clears impossible possible_maps.
    if (!NodeTypeIs(known_info->type(), merger.node_type())) {
      known_info->IntersectType(merger.node_type());
    }
#ifdef DEBUG
    // Double check that, for every possible map, it's one of the maps we'd
    // want to check.
    for (compiler::MapRef map :
         known_node_aspects().TryGetInfoFor(object)->possible_maps()) {
      DCHECK_NE(std::find(maps.begin(), maps.end(), map), maps.end());
    }
#endif
    return ReduceResult::Done();
  }

  if (merger.intersect_set().is_empty()) {
    return EmitUnconditionalDeopt(DeoptimizeReason::kWrongMap);
  }

  // TODO(v8:7700): Check if the {maps} - {known_maps} size is smaller than
  // {maps} \intersect {known_maps}, we can emit CheckNotMaps instead.

  // Emit checks.
  if (merger.emit_check_with_migration()) {
    AddNewNode<CheckMapsWithMigration>({object}, merger.intersect_set(),
                                       GetCheckType(known_info->type()));
  } else if (map) {
    AddNewNode<CheckMapsWithAlreadyLoadedMap>({object, *map},
                                              merger.intersect_set());
  } else {
    AddNewNode<CheckMaps>({object}, merger.intersect_set(),
                          GetCheckType(known_info->type()));
  }

  merger.UpdateKnownNodeAspects(object, known_node_aspects());
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildTransitionElementsKindOrCheckMap(
    ValueNode* heap_object, ValueNode* object_map,
    const ZoneVector<compiler::MapRef>& transition_sources,
    compiler::MapRef transition_target) {
  // TODO(marja): Optimizations based on what we know about the intersection of
  // known maps and transition sources or transition target.

  // TransitionElementsKind doesn't happen in cases where we'd need to do
  // CheckMapsWithMigration instead of CheckMaps.
  CHECK(!transition_target.is_migration_target());
  for (const compiler::MapRef transition_source : transition_sources) {
    CHECK(!transition_source.is_migration_target());
  }

  NodeInfo* known_info = GetOrCreateInfoFor(heap_object);

  AddNewNode<TransitionElementsKindOrCheckMap>(
      {heap_object, object_map}, transition_sources, transition_target);
  // After this operation, heap_object's map is transition_target (or we
  // deopted).
  known_info->SetPossibleMaps(
      PossibleMaps{transition_target}, !transition_target.is_stable(),
      StaticTypeForMap(transition_target, broker()), broker());
  DCHECK(transition_target.IsJSReceiverMap());
  if (!transition_target.is_stable()) {
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    broker()->dependencies()->DependOnStableMap(transition_target);
  }
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildCompareMaps(
    ValueNode* heap_object, ValueNode* object_map,
    base::Vector<const compiler::MapRef> maps, MaglevSubGraphBuilder* sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& if_not_matched) {
  GetOrCreateInfoFor(heap_object);
  KnownMapsMerger merger(broker(), zone(), maps);
  merger.IntersectWithKnownNodeAspects(heap_object, known_node_aspects());

  if (merger.intersect_set().is_empty()) {
    return ReduceResult::DoneWithAbort();
  }

  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);

  // TODO(pthier): Handle map migrations.
  std::optional<MaglevSubGraphBuilder::Label> map_matched;
  const compiler::ZoneRefSet<Map>& relevant_maps = merger.intersect_set();
  if (relevant_maps.size() > 1) {
    map_matched.emplace(sub_graph, static_cast<int>(relevant_maps.size()));
    for (size_t map_index = 1; map_index < relevant_maps.size(); map_index++) {
      sub_graph->GotoIfTrue<BranchIfReferenceEqual>(
          &*map_matched,
          {object_map, GetConstant(relevant_maps.at(map_index))});
    }
  }
  if_not_matched.emplace(sub_graph, 1);
  sub_graph->GotoIfFalse<BranchIfReferenceEqual>(
      &*if_not_matched, {object_map, GetConstant(relevant_maps.at(0))});
  if (map_matched.has_value()) {
    sub_graph->Goto(&*map_matched);
    sub_graph->Bind(&*map_matched);
  }
  merger.UpdateKnownNodeAspects(heap_object, known_node_aspects());
  return ReduceResult::Done();
}

ReduceResult MaglevGraphBuilder::BuildTransitionElementsKindAndCompareMaps(
    ValueNode* heap_object, ValueNode* object_map,
    const ZoneVector<compiler::MapRef>& transition_sources,
    compiler::MapRef transition_target, MaglevSubGraphBuilder* sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& if_not_matched) {
  DCHECK(!transition_target.is_migration_target());

  NodeInfo* known_info = GetOrCreateInfoFor(heap_object);

  // TODO(pthier): Calculate and use the intersection of known maps with
  // (transition_sources union transition_target).

  ValueNode* new_map = AddNewNode<TransitionElementsKind>(
      {heap_object, object_map}, transition_sources, transition_target);

  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);
  if_not_matched.emplace(sub_graph, 1);
  sub_graph->GotoIfFalse<BranchIfReferenceEqual>(
      &*if_not_matched, {new_map, GetConstant(transition_target)});
  // After the branch, object's map is transition_target.
  DCHECK(transition_target.IsJSReceiverMap());
  known_info->SetPossibleMaps(
      PossibleMaps{transition_target}, !transition_target.is_stable(),
      StaticTypeForMap(transition_target, broker()), broker());
  if (!transition_target.is_stable()) {
    known_node_aspects().any_map_for_any_node_is_unstable = true;
  } else {
    broker()->dependencies()->DependOnStableMap(transition_target);
  }
  return ReduceResult::Done();
}

namespace {
AllocationBlock* GetAllocation(ValueNode* object) {
  if (object->Is<InlinedAllocation>()) {
    object = object->Cast<InlinedAllocation>()->input(0).node();
  }
  if (object->Is<AllocationBlock>()) {
    return object->Cast<AllocationBlock>();
  }
  return nullptr;
}
}  // namespace

bool MaglevGraphBuilder::CanElideWriteBarrier(ValueNode* object,
                                              ValueNode* value) {
  if (value->Is<RootConstant>()) return true;
  if (CheckType(value, NodeType::kSmi)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
    return true;
  }

  // No need for a write barrier if both object and value are part of the same
  // folded young allocation.
  AllocationBlock* allocation = GetAllocation(object);
  if (allocation != nullptr &&
      allocation->allocation_type() == AllocationType::kYoung &&
      allocation == GetAllocation(value)) {
    return true;
  }

  // If tagged and not Smi, we cannot elide write barrier.
  if (value->is_tagged()) return false;

  // If its alternative conversion node is Smi, {value} will be converted to
  // a Smi when tagged.
  NodeInfo* node_info = GetOrCreateInfoFor(value);
  if (ValueNode* tagged_alt = node_info->alternative().tagged()) {
    DCHECK(tagged_alt->properties().is_conversion());
    return CheckType(tagged_alt, NodeType::kSmi);
  }
  return false;
}

void MaglevGraphBuilder::BuildInitializeStore(InlinedAllocation* object,
                                              ValueNode* value, int offset) {
  const bool value_is_trusted = value->Is<TrustedConstant>();
  DCHECK(value->is_tagged());
  if (InlinedAllocation* inlined_value = value->TryCast<InlinedAllocation>()) {
    // Add to the escape set.
    auto escape_deps = graph()->allocations_escape_map().find(object);
    CHECK(escape_deps != graph()->allocations_escape_map().end());
    escape_deps->second.push_back(inlined_value);
    // Add to the elided set.
    auto& elided_map = graph()->allocations_elide_map();
    auto elided_deps = elided_map.try_emplace(inlined_value, zone()).first;
    elided_deps->second.push_back(object);
    inlined_value->AddNonEscapingUses();
  }
  if (value_is_trusted) {
    BuildStoreTrustedPointerField(object, value, offset,
                                  value->Cast<TrustedConstant>()->tag(),
                                  StoreTaggedMode::kInitializing);
  } else {
    BuildStoreTaggedField(object, value, offset,
                          StoreTaggedMode::kInitializing);
  }
}

namespace {
bool IsEscaping(Graph* graph, InlinedAllocation* alloc) {
  if (alloc->IsEscaping()) return true;
  auto it = graph->allocations_elide_map().find(alloc);
  if (it == graph->allocations_elide_map().end()) return false;
  for (InlinedAllocation* inner_alloc : it->second) {
    if (IsEscaping(graph, inner_alloc)) {
      return true;
    }
  }
  return false;
}

bool VerifyIsNotEscaping(VirtualObject::List vos, InlinedAllocation* alloc) {
  for (VirtualObject* vo : vos) {
    if (vo->type() != VirtualObject::kDefault) continue;
    if (vo->allocation() == alloc) continue;
    for (uint32_t i = 0; i < vo->slot_count(); i++) {
      ValueNode* nested_value = vo->get_by_index(i);
      if (!nested_value->Is<InlinedAllocation>()) continue;
      ValueNode* nested_alloc = nested_value->Cast<InlinedAllocation>();
      if (nested_alloc == alloc) {
        if (vo->allocation()->IsEscaping()) return false;
        if (!VerifyIsNotEscaping(vos, vo->allocation())) return false;
      }
    }
  }
  return true;
}
}  // namespace

bool MaglevGraphBuilder::CanTrackObjectChanges(ValueNode* receiver,
                                               TrackObjectMode mode) {
  DCHECK(!receiver->Is<VirtualObject>());
  if (!v8_flags.maglev_object_tracking) return false;
  if (!receiver->Is<InlinedAllocation>()) return false;
  InlinedAllocation* alloc = receiver->Cast<InlinedAllocation>();
  if (mode == TrackObjectMode::kStore) {
    // If we have two objects A and B, such that A points to B (it contains B in
    // one of its field), we cannot change B without also changing A, even if
    // both can be elided. For now, we escape both objects instead.
    if (graph_->allocations_elide_map().find(alloc) !=
        graph_->allocations_elide_map().end()) {
      return false;
    }
    if (alloc->IsEscaping()) return false;
    // Ensure object is escaped if we are within a try-catch block. This is
    // crucial because a deoptimization point inside the catch handler could
    // re-materialize objects differently, depending on whether the throw
    // occurred before or after this store. We could potentially relax this
    // requirement by verifying that no throwable nodes have been emitted since
    // the try-block started,  but for now, err on the side of caution and
    // always escape.
    if (IsInsideTryBlock()) return false;
  } else {
    DCHECK_EQ(mode, TrackObjectMode::kLoad);
    if (IsEscaping(graph_, alloc)) return false;
  }
  // We don't support loop phis inside VirtualObjects, so any access inside a
  // loop should escape the object, except for objects that were created since
  // the last loop header.
  if (IsInsideLoop()) {
    if (!is_loop_effect_tracking() ||
        !loop_effects_->allocations.contains(alloc)) {
      return false;
    }
  }
  // Iterate all live objects to be sure that the allocation is not escaping.
  SLOW_DCHECK(
      VerifyIsNotEscaping(current_interpreter_frame_.virtual_objects(), alloc));
  return true;
}

VirtualObject* MaglevGraphBuilder::GetObjectFromAllocation(
    InlinedAllocation* allocation) {
  VirtualObject* vobject = allocation->object();
  // If it hasn't be snapshotted yet, it is the latest created version of this
  // object, we don't need to search for it.
  if (vobject->IsSnapshot()) {
    vobject = current_interpreter_frame_.virtual_objects().FindAllocatedWith(
        allocation);
  }
  return vobject;
}

VirtualObject* MaglevGraphBuilder::GetModifiableObjectFromAllocation(
    InlinedAllocation* allocation) {
  VirtualObject* vobject = allocation->object();
  // If it hasn't be snapshotted yet, it is the latest created version of this
  // object and we can still modify it, we don't need to copy it.
  if (vobject->IsSnapshot()) {
    return DeepCopyVirtualObject(
        current_interpreter_frame_.virtual_objects().FindAllocatedWith(
            allocation));
  }
  return vobject;
}

void MaglevGraphBuilder::TryBuildStoreTaggedFieldToAllocation(ValueNode* object,
                                                              ValueNode* value,
                                                              int offset) {
  if (offset == HeapObject::kMapOffset) return;
  if (!CanTrackObjectChanges(object, TrackObjectMode::kStore)) return;
  // This avoids loop in the object graph.
  if (value->Is<InlinedAllocation>()) return;
  InlinedAllocation* allocation = object->Cast<InlinedAllocation>();
  VirtualObject* vobject = GetModifiableObjectFromAllocation(allocation);
  CHECK_EQ(vobject->type(), VirtualObject::kDefault);
  CHECK_NOT_NULL(vobject);
  vobject->set(offset, value);
  AddNonEscapingUses(allocation, 1);
  if (v8_flags.trace_maglev_object_tracking) {
    std::cout << "  * Setting value in virtual object "
              << PrintNodeLabel(graph_labeller(), vobject) << "[" << offset
              << "]: " << PrintNode(graph_labeller(), value) << std::endl;
  }
}

Node* MaglevGraphBuilder::BuildStoreTaggedField(ValueNode* object,
                                                ValueNode* value, int offset,
                                                StoreTaggedMode store_mode) {
  // The value may be used to initialize a VO, which can leak to IFS.
  // It should NOT be a conversion node, UNLESS it's an initializing value.
  // Initializing values are tagged before allocation, since conversion nodes
  // may allocate, and are not used to set a VO.
  DCHECK_IMPLIES(store_mode != StoreTaggedMode::kInitializing,
                 !value->properties().is_conversion());
  if (store_mode != StoreTaggedMode::kInitializing) {
    TryBuildStoreTaggedFieldToAllocation(object, value, offset);
  }
  if (CanElideWriteBarrier(object, value)) {
    return AddNewNode<StoreTaggedFieldNoWriteBarrier>({object, value}, offset,
                                                      store_mode);
  } else {
    return AddNewNode<StoreTaggedFieldWithWriteBarrier>({object, value}, offset,
                                                        store_mode);
  }
}

void MaglevGraphBuilder::BuildStoreTaggedFieldNoWriteBarrier(
    ValueNode* object, ValueNode* value, int offset,
    StoreTaggedMode store_mode) {
  // The value may be used to initialize a VO, which can leak to IFS.
  // It should NOT be a conversion node, UNLESS it's an initializing value.
  // Initializing values are tagged before allocation, since conversion nodes
  // may allocate, and are not used to set a VO.
  DCHECK_IMPLIES(store_mode != StoreTaggedMode::kInitializing,
                 !value->properties().is_conversion());
  DCHECK(CanElideWriteBarrier(object, value));
  if (store_mode != StoreTaggedMode::kInitializing) {
    TryBuildStoreTaggedFieldToAllocation(object, value, offset);
  }
  AddNewNode<StoreTaggedFieldNoWriteBarrier>({object, value}, offset,
                                             store_mode);
}

void MaglevGraphBuilder::BuildStoreTrustedPointerField(
    ValueNode* object, ValueNode* value, int offset, IndirectPointerTag tag,
    StoreTaggedMode store_mode) {
#ifdef V8_ENABLE_SANDBOX
  AddNewNode<StoreTrustedPointerFieldWithWriteBarrier>({object, value}, offset,
                                                       tag, store_mode);
#else
  BuildStoreTaggedField(object, value, offset, store_mode);
#endif  // V8_ENABLE_SANDBOX
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayElement(ValueNode* elements,
                                                          int index) {
  compiler::OptionalHeapObjectRef maybe_constant;
  if ((maybe_constant = TryGetConstant(elements)) &&
      maybe_constant.value().IsFixedArray()) {
    compiler::FixedArrayRef fixed_array_ref =
        maybe_constant.value().AsFixedArray();
    if (index >= 0 && static_cast<uint32_t>(index) < fixed_array_ref.length()) {
      compiler::OptionalObjectRef maybe_value =
          fixed_array_ref.TryGet(broker(), index);
      if (maybe_value) return GetConstant(*maybe_value);
    } else {
      return GetRootConstant(RootIndex::kTheHoleValue);
    }
  }
  if (CanTrackObjectChanges(elements, TrackObjectMode::kLoad)) {
    VirtualObject* vobject =
        GetObjectFromAllocation(elements->Cast<InlinedAllocation>());
    CHECK_EQ(vobject->type(), VirtualObject::kDefault);
    DCHECK(vobject->map().IsFixedArrayMap());
    ValueNode* length_node = vobject->get(offsetof(FixedArray, length_));
    if (auto length = TryGetInt32Constant(length_node)) {
      if (index >= 0 && index < length.value()) {
        return vobject->get(FixedArray::OffsetOfElementAt(index));
      } else {
        return GetRootConstant(RootIndex::kTheHoleValue);
      }
    }
  }
  if (index < 0 || index >= FixedArray::kMaxLength) {
    return GetRootConstant(RootIndex::kTheHoleValue);
  }
  return AddNewNode<LoadTaggedField>({elements},
                                     FixedArray::OffsetOfElementAt(index));
}

ValueNode* MaglevGraphBuilder::BuildLoadFixedArrayElement(ValueNode* elements,
                                                          ValueNode* index) {
  if (auto constant = TryGetInt32Constant(index)) {
    return BuildLoadFixedArrayElement(elements, constant.value());
  }
  return AddNewNode<LoadFixedArrayElement>({elements, index});
}

void MaglevGraphBuilder::BuildStoreFixedArrayElement(ValueNode* elements,
                                                     ValueNode* index,
                                                     ValueNode* value) {
  // TODO(victorgomes): Support storing element to a virtual object. If we
  // modify the elements array, we need to modify the original object to point
  // to the new elements array.
  if (CanElideWriteBarrier(elements, value)) {
    AddNewNo
```
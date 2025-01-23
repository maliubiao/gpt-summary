Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`.

Here's a breakdown of the thought process to achieve that:

1. **Identify the Core Purpose:** The file name `maglev-graph-builder.cc` suggests that this code is responsible for constructing the Maglev graph, which is an intermediate representation used in the V8 JavaScript engine's optimizing compiler.

2. **Analyze the Functions and their Names:**  The code contains several functions with descriptive names. I should categorize them based on their apparent function:
    * **Comparison/Equality:** `BuildTaggedEqual`, `BuildTestUndetectable`, `BuildBranchIfUndetectable`, `VisitTestNull`, `VisitTestUndefined`. These deal with comparing values and checking for specific properties like `null`, `undefined`, and undetectability.
    * **Type Checking:** `TryReduceTypeOf`, `VisitTestTypeOf`. These are related to determining the type of a JavaScript value.
    * **Global Variable Access (Load/Store):** `TryBuildScriptContextStore`, `TryBuildPropertyCellStore`, `TryBuildScriptContextConstantLoad`, `TryBuildScriptContextLoad`, `TryBuildPropertyCellLoad`, `TryBuildGlobalStore`, `TryBuildGlobalLoad`, `VisitLdaGlobal`, `VisitLdaGlobalInsideTypeof`, `VisitStaGlobal`. These functions manage accessing global variables, considering different storage mechanisms (script context, property cells).
    * **Lookup Operations:** `VisitLdaLookupSlot`, `VisitLdaLookupContextSlot`, `VisitLdaLookupScriptContextSlot`, `VisitLdaLookupGlobalSlot`, `VisitLdaLookupSlotInsideTypeof`, `VisitLdaLookupContextSlotInsideTypeof`, `VisitLdaLookupScriptContextSlotInsideTypeof`, `VisitLdaLookupGlobalSlotInsideTypeof`, `VisitStaLookupSlot`. These functions handle looking up variables in different scopes.
    * **Static Type Analysis:** `StaticTypeForNode`, `CheckStaticType`. These functions are used for static analysis of the types of values represented by the nodes in the graph.

3. **Infer High-Level Functionality from Categories:** Based on the categorized functions, I can infer the following high-level functionalities:
    * **Generating code for comparisons and type checks.**
    * **Generating code for accessing global variables, potentially with optimizations based on feedback.** This involves understanding different ways global variables are stored in V8.
    * **Generating code for variable lookups in different scopes (local, context, global).**
    * **Performing static type analysis to enable optimizations.**

4. **Address Specific Instructions:**
    * **".tq" suffix:** The prompt explicitly asks about the `.tq` suffix. The code is `.cc`, so it's not Torque.
    * **JavaScript relationship:**  Many of the operations directly correspond to JavaScript operations (e.g., `typeof`, equality checks, global variable access). I need to provide JavaScript examples for relevant functionalities.
    * **Code logic inference:** For sections with clear logic (e.g., `BuildTestUndetectable`), I should provide example inputs and outputs.
    * **Common programming errors:**  Consider potential pitfalls related to the covered functionality (e.g., using `typeof` incorrectly, relying on global variables).

5. **Structure the Output:**  Organize the information logically, starting with a high-level summary and then going into more detail about specific functionalities. Use clear headings and bullet points.

6. **Review and Refine:** Double-check the accuracy of the interpretations and ensure all parts of the prompt are addressed. Make sure the JavaScript examples are correct and illustrative. For the code logic inference, create simple but representative examples. For common errors, select prevalent mistakes.

**(Self-Correction during the process):**

* Initially, I might have focused too much on the individual functions. It's important to step back and identify the broader goals these functions contribute to.
* I need to remember the context: this is *graph building* for an *optimizing compiler*. This explains the emphasis on static analysis and the consideration of different code paths based on type information.
* When explaining global variable access, it's important to mention the feedback mechanism, as Maglev uses type feedback for optimization.

By following these steps, I can generate a comprehensive and accurate summary of the provided code snippet.
好的，让我们来分析一下 `v8/src/maglev/maglev-graph-builder.cc` 这个代码片段的功能。

**核心功能归纳：**

这段代码是 V8 引擎中 Maglev 编译器的一部分，**主要负责构建用于执行 JavaScript 代码的 Maglev 图（Maglev Graph）**。Maglev 图是一种中间表示形式，它将 JavaScript 代码的操作转换为图的节点和边，方便后续的优化和代码生成。

**具体功能拆解：**

1. **构建比较操作节点：**
   - `BuildTaggedEqual(lhs, rhs)`:  构建一个检查两个值是否严格相等的节点（类似 JavaScript 中的 `===`）。
   - `BuildTestUndetectable(value)`: 构建一个检查给定值是否是 `undetectable` 的节点。一个对象如果其 `typeof` 返回 'undefined' 但实际上存在，则被认为是 `undetectable` (例如 `document.all` 在某些浏览器中)。
   - `BuildBranchIfUndetectable(builder, value)`: 基于 `BuildTestUndetectable` 的结果，构建一个条件分支节点。
   - `VisitTestNull()`: 处理 JavaScript 中的 `value == null` 类型的检查。
   - `VisitTestUndefined()`: 处理 JavaScript 中的 `value == undefined` 类型的检查。

2. **构建类型检查操作节点：**
   - `TryReduceTypeOf(value, GetResult)` 和 `TryReduceTypeOf(value)`: 尝试优化 `typeof` 操作。如果能够静态确定值的类型，则直接返回常量字符串（例如 "number", "string"）。
   - `VisitTestTypeOf()`: 处理 JavaScript 中的 `typeof` 操作。如果无法静态确定类型，则构建一个 `TestTypeOf` 节点。

3. **构建全局变量访问操作节点：**
   - `TryBuildScriptContextStore/Load`:  尝试构建访问存储在 Script Context 中的全局变量的节点。Script Context 用于存储脚本级别的变量。
   - `TryBuildPropertyCellStore/Load`: 尝试构建访问存储在 Property Cell 中的全局变量的节点。Property Cell 是全局对象的属性的存储位置。
   - `TryBuildGlobalStore/Load`: 根据反馈信息，选择合适的全局变量存储或加载方式。
   - `VisitLdaGlobal/LdaGlobalInsideTypeof`: 处理加载全局变量的操作。`InsideTypeof` 版本用于 `typeof` 内部的全局变量加载。
   - `VisitStaGlobal()`: 处理存储全局变量的操作。
   - `VisitLdaLookupSlot/ContextSlot/ScriptContextSlot/GlobalSlot`: 处理需要通过作用域链查找变量的操作。
   - `VisitStaLookupSlot()`: 处理需要通过作用域链查找并存储变量的操作。

4. **静态类型分析：**
   - `StaticTypeForNode(broker, isolate, node)`: 尝试静态推断 Maglev 图节点表示的值的类型。
   - `CheckStaticType(node, type, current_type)`: 检查一个节点的静态类型是否符合预期。

**关于提问中的其他点：**

* **`.tq` 结尾：**  代码片段是 `.cc` 结尾，所以它不是 Torque 源代码。Torque 文件通常用于定义 V8 内部的内置函数。
* **与 JavaScript 的功能关系：**  这段代码直接对应 JavaScript 的各种操作，例如：
    ```javascript
    let x = 10;
    let y = "hello";
    if (x === y) { // BuildTaggedEqual
      console.log("相等");
    }
    if (typeof y === "string") { // VisitTestTypeOf
      console.log("是字符串");
    }
    console.log(typeof document.all); // VisitTestTypeOf 结合 BuildTestUndetectable
    globalVar = 5; // VisitStaGlobal
    console.log(globalVar); // VisitLdaGlobal
    ```

* **代码逻辑推理 (示例)：**

   **假设输入：**
   ```c++
   ValueNode* value = ...; // 假设 value 代表一个可能为 null 的变量
   ```

   **代码片段：**
   ```c++
   void MaglevGraphBuilder::VisitTestNull() {
     ValueNode* value = GetAccumulator();
     SetAccumulator(BuildTaggedEqual(value, RootIndex::kNullValue));
   }
   ```

   **推理：**  `VisitTestNull` 函数会获取当前累加器中的值（`GetAccumulator()`），并将其与 `null` 常量进行严格相等比较（`BuildTaggedEqual`）。比较的结果（true 或 false）会设置回累加器。

   **JavaScript 对应：**  如果当前的累加器代表 JavaScript 代码中的一个变量 `myVar`，那么 `VisitTestNull` 对应于执行 `myVar === null`。

* **用户常见的编程错误 (示例)：**

   一个与 `typeof` 相关的常见错误是忘记 `typeof` 运算符返回的是字符串：

   ```javascript
   let myVar = 10;
   if (typeof myVar == Number) { // 错误！ Number 是构造函数
       console.log("是数字");
   }
   if (typeof myVar === "number") { // 正确！
       console.log("是数字");
   }
   ```

   Maglev 图构建器需要正确处理这些情况，生成相应的类型检查节点。

**总结 `v8/src/maglev/maglev-graph-builder.cc` 第 5 部分的功能：**

这部分代码主要负责构建 Maglev 图中用于执行以下 JavaScript 操作的节点：

* **相等性比较（严格相等，与 `null` 或 `undefined` 比较）**
* **类型检查 (`typeof`)**
* **全局变量的加载和存储（包括不同类型的全局存储位置和查找方式）**
* **初步的静态类型分析，用于辅助优化。**

它通过检查操作数类型、利用类型反馈信息以及处理不同的全局变量存储策略，来高效地构建 Maglev 图，为后续的优化和代码生成奠定基础。这部分是 Maglev 编译器将 JavaScript 代码转换为可执行形式的关键步骤之一。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  NodeType
```
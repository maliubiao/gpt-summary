Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `v8/src/compiler/wasm-gc-operator-reducer.cc`. This immediately suggests we're dealing with WebAssembly (Wasm) and some form of compiler optimization or transformation within V8 (the JavaScript engine). The "reducer" part hints at simplifying or canonicalizing the Wasm intermediate representation (likely the Graph).

2. **Initial Code Scan (Keywords and Structure):**  Skim the code looking for key terms:
    * `WasmGCOperatorReducer`:  The core class.
    * `Reduce`:  A central method, likely the entry point for the reduction process. The `switch` statement inside suggests it handles various Wasm-related operations.
    * `IrOpcode::k...`:  These are clearly operation codes from V8's Intermediate Representation (IR). They represent different Wasm instructions or abstract operations.
    * `kWasmStructGet`, `kWasmStructSet`, `kWasmArrayLength`, etc.:  Specific Wasm GC (Garbage Collection) related operations.
    * `Type`, `wasm::ValueType`, `wasm::TypeInModule`:  Type system related information, crucial for GC.
    * `ControlPathTypes`:  Something related to tracking type information along control flow paths.
    * `UpdateStates`, `UpdateNodeAndAliasesTypes`: Methods for updating this control flow type information.
    * `ObjectTypeFromContext`:  A method to determine the type of an object based on the current control flow context.
    * `AssertNotNull`, `IsNull`, `IsNotNull`, `TypeGuard`, `WasmTypeCast`, `WasmTypeCheck`:  Operations related to type safety and manipulation.
    * `Merge`, `IfTrue`, `IfFalse`: Control flow nodes.
    * `SimplifiedOperator`, `MachineGraph`: References to other V8 compiler components.

3. **Identify Core Functionality - By Operation:** The `Reduce` method's `switch` statement is the key to understanding the reducer's actions. Go through each `case`:
    * **`kStart`:**  Likely initializes the type state at the beginning of a function.
    * **`kWasmStructGet`, `kWasmStructSet`:** Focuses on optimizing access to struct fields. The code checks for nullability and potentially removes null checks.
    * **`kWasmArrayLength`:** Similar to struct access, optimizes array length retrieval.
    * **`kAssertNotNull`:**  Optimizes or removes explicit null checks. If the type is known to be non-nullable, the check can be eliminated or turned into a `TypeGuard`.
    * **`kIsNull`, `kIsNotNull`:** Optimizes null checks. If the object is known to be null or non-null, the check can be replaced with a constant.
    * **`kWasmTypeCheck`, `kWasmTypeCheckAbstract`:**  Deals with Wasm type checking. The reducer tries to determine if the check is redundant or can be simplified based on the known types.
    * **`kWasmTypeCast`, `kWasmTypeCastAbstract`:** Handles Wasm type casting. The reducer tries to determine if the cast will always succeed or always fail, potentially optimizing or inserting traps.
    * **`kTypeGuard`:**  Refines type information based on `TypeGuard` nodes.
    * **`kWasmAnyConvertExtern`:**  Removes redundant conversions between Wasm's `anyref` and `externref`.
    * **`Merge`:**  Handles merging type information from different control flow paths, finding the common type information.
    * **`IfTrue`, `IfFalse`:**  Crucial for type refinement. If a type check or null check occurs in the condition of an `if`, this reducer updates the type information in the corresponding branches.
    * **`Dead`, `Loop`:** Basic control flow handling, propagating state.

4. **Infer High-Level Functionality:** Based on the individual operations, we can deduce the overall purpose: **The `WasmGCOperatorReducer` optimizes Wasm GC-related operations by leveraging type information.** It propagates and refines type information along control flow paths to eliminate redundant checks and potentially simplify operations.

5. **Consider the ".tq" Question:** The code itself is C++. The comment about ".tq" files points to V8's Torque language. Since the file *is* `.cc`, it's a C++ implementation. The comment serves as a potential point of confusion or an alternative scenario.

6. **Relate to JavaScript (If Applicable):** Since Wasm directly interacts with JavaScript, consider scenarios where these optimizations might be relevant. Wasm GC allows Wasm to interoperate more seamlessly with JavaScript's garbage-collected objects. The type checks and casts are essential for maintaining type safety when crossing the Wasm/JS boundary. Think about passing objects between JS and Wasm.

7. **Code Logic Inference (Hypothetical Examples):**  Choose a few key operations and create simplified scenarios:
    * **`kWasmStructGet`:**  Illustrate how knowing an object is non-nullable can remove a null check.
    * **`kWasmTypeCast`:** Show cases where the cast always succeeds or always fails.
    * **`IfTrue`/`kWasmTypeCheck`:**  Demonstrate how type information is refined within a conditional branch.

8. **Common Programming Errors:** Think about what mistakes developers might make that this reducer helps with:
    * Unnecessary null checks.
    * Redundant type casts.
    * Performing operations on potentially null objects without proper checks.

9. **Structure the Answer:** Organize the findings into logical sections:
    * **Functionality Summary:**  A concise overview.
    * **Detailed Functionality (by `Reduce` cases):**  Explain what each case does.
    * **Torque (.tq) Explanation:** Address the comment about Torque.
    * **Relationship to JavaScript (with examples):** Show the connection.
    * **Code Logic Inference (with examples):** Illustrate with input/output.
    * **Common Programming Errors:** Provide practical examples.

10. **Refine and Review:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Ensure the examples are clear and relevant. For instance, initially, I might just say "optimizes type checks," but then I would refine it to "optimizes or eliminates redundant type checks based on control flow information."

This iterative process of scanning, identifying key components, understanding individual actions, inferring the overall purpose, and then illustrating with examples is crucial for dissecting and explaining complex code like this.
这个 C++ 源代码文件 `v8/src/compiler/wasm-gc-operator-reducer.cc` 是 V8 引擎中 **WebAssembly (Wasm) 垃圾回收 (GC) 操作的优化器 (Reducer)**。它的主要功能是在编译 WebAssembly 代码的过程中，对涉及到垃圾回收的操作进行分析和简化，以提高生成的机器码的效率。

以下是其主要功能的详细列表：

**核心功能：优化 WebAssembly GC 操作**

1. **类型推断和传播 (Type Inference and Propagation):**
   - 跟踪和记录 WebAssembly GC 对象的类型信息，包括是否可空 (nullable)。
   - 通过控制流分析 (Control Flow Analysis)，在不同的代码路径上维护对象的类型信息。
   - 使用 `ControlPathTypes` 来存储和更新每个控制流点的类型知识。

2. **冗余检查消除 (Redundant Check Elimination):**
   - **空值检查消除 (Null Check Elimination):** 如果在某个代码点已知一个 GC 对象是非空的，那么可以移除后续的空值检查 (`AssertNotNull`, `IsNull`, `IsNotNull`)。
   - **类型检查消除 (Type Check Elimination):** 如果类型信息已经足够，可以消除冗余的类型检查 (`kWasmTypeCheck`, `kWasmTypeCheckAbstract`)。

3. **操作简化 (Operation Simplification):**
   - **`kWasmStructGet`/`kWasmStructSet` 优化:** 如果已知结构体对象是非空的，可以移除其内部的空值检查。
   - **`kWasmArrayLength` 优化:** 类似地，如果已知数组对象是非空的，可以移除其内部的空值检查。
   - **`kWasmTypeCast` 优化:**
     - 如果类型转换总是成功 (已知对象类型是目标类型的子类型)，可以将其转换为 `TypeGuard` 以保留类型信息，或者在目标类型不可空时插入一个非空断言。
     - 如果类型转换总是失败 (已知对象类型与目标类型不相关)，可以插入一个总是触发陷阱的条件分支，或者在目标类型可空时替换为 `null`。
   - **`kWasmAnyConvertExtern` 优化:** 移除冗余的 `any.convert_extern(extern.convert_any(...))` 模式。

4. **控制流分析辅助优化 (Control Flow Analysis for Optimization):**
   - 利用 `Merge` 节点来合并来自不同控制流路径的类型信息，找到它们共有的类型。
   - 分析 `IfTrue` 和 `IfFalse` 节点，根据条件表达式中的类型检查或空值检查结果，更新相应分支上的类型信息。

5. **类型保护 (Type Guarding):**
   - 使用 `TypeGuard` 节点来显式地记录类型信息，即使某些操作已经被简化或移除，也能保留更精确的类型。

**关于 .tq 结尾的文件:**

如果 `v8/src/compiler/wasm-gc-operator-reducer.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用来编写高效的内置函数和编译器优化的领域特定语言。由于这里的文件名是 `.cc`，所以它是一个 **C++ 源代码文件**。

**与 JavaScript 的关系及示例:**

WebAssembly 旨在与 JavaScript 紧密集成。`WasmGCOperatorReducer` 的优化直接影响到当 JavaScript 调用 WebAssembly 函数，或者 WebAssembly 调用 JavaScript 函数时涉及的 GC 对象的处理效率。

**JavaScript 示例:**

假设有一个 WebAssembly 模块定义了一个可以返回可空的结构体的函数：

```wasm
(module
  (type $struct_type (struct (field i32)))
  (func (export "get_struct") (result (ref null $struct_type))
    (struct.new_default $struct_type)
  )
)
```

在 JavaScript 中调用这个函数：

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const structRef = instance.exports.get_struct();

// 开发者可能会进行显式的空值检查
if (structRef != null) {
  // ... 访问结构体的字段
}
```

`WasmGCOperatorReducer` 的作用在于，如果 V8 的编译器能够通过分析 JavaScript 代码或其他 Wasm 代码的上下文，推断出 `structRef` 在某个特定的代码路径上永远不会是 `null`，那么它就可以在编译 `get_struct` 函数或调用它的代码时，消除一些潜在的空值检查，从而提高执行效率。

**代码逻辑推理示例 (假设输入与输出):**

**假设输入:**  一个 `kWasmStructGet` 节点，表示访问一个结构体的字段，其第一个输入是结构体对象节点，第二个输入是控制流节点。

**场景:**  编译器通过之前的分析，已经确定结构体对象节点的类型是非空的 (`!null`).

**`WasmGCOperatorReducer` 的 `ReduceWasmStructOperation` 函数的逻辑:**

1. 检查控制流输入是否已处理 (`IsReduced(control)`).
2. 获取结构体对象输入 (`object`).
3. 调用 `ObjectTypeFromContext` 获取对象类型。
4. **关键判断:** 检查对象类型是否为非空 (`object_type.type.is_non_nullable()`)。
5. 如果是非空，则创建一个新的 `WasmStructGet` 操作符，但不包含空值检查标志 (`kWithoutNullCheck`)。
6. 使用新的操作符替换原有的节点。

**假设输入:** 一个 `kAssertNotNull` 节点，其输入是一个可能为空的 GC 对象。

**场景 1:** 编译器已知该对象永远不为 `null`。

**输出:** `kAssertNotNull` 节点被替换为一个 `TypeGuard` 节点，保留了类型信息，但移除了实际的运行时空值检查。

**场景 2:** 编译器无法确定该对象是否为 `null`。

**输出:** `kAssertNotNull` 节点保持不变，将在运行时执行空值检查。

**用户常见的编程错误及示例:**

1. **过度进行空值检查:**

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const arr = instance.exports.get_array(); // 假设 get_array 保证返回非空数组

if (arr != null) { // 这里的检查可能是多余的
  const length = arr.length;
  // ...
}
```

`WasmGCOperatorReducer` 可以帮助优化这类情况，如果它能确定 `arr` 始终非空，就可以消除 `if (arr != null)` 的检查。

2. **不必要的类型转换:**

```wasm
(module
  (type $base (sub anyref))
  (type $derived (sub $base))
  (func (export "cast") (param $obj (ref null $base)) (result (ref null $derived))
    (local.get $obj)
    (ref.cast (ref null $derived))  ;; 即使已知 $obj 是 $derived 类型
  )
)
```

即使在某些情况下，开发者已经知道对象的具体类型，仍然可能进行类型转换。`WasmGCOperatorReducer` 可以识别并优化这些冗余的类型转换。

3. **在可能为空的对象上直接访问字段或长度:**

```javascript
const instance = await WebAssembly.instantiateStreaming(fetch('module.wasm'));
const maybeStruct = instance.exports.get_maybe_struct(); // 可能返回 null

// 如果没有检查 null，直接访问字段可能导致错误
// const fieldValue = maybeStruct.field; // 潜在的错误
if (maybeStruct != null) {
  const fieldValue = maybeStruct.field;
}
```

虽然 `WasmGCOperatorReducer` 的主要目标是优化，但它也会分析类型信息，这对于编译器进行一些静态分析和潜在的错误检测也是有帮助的。

总而言之，`v8/src/compiler/wasm-gc-operator-reducer.cc` 是 V8 引擎中一个关键的优化组件，专门针对 WebAssembly 垃圾回收相关的操作进行分析和改进，通过类型推断、冗余检查消除和操作简化等技术，提高 WebAssembly 代码的执行效率。它与 JavaScript 的互操作性密切相关，影响着跨语言调用的性能。

Prompt: 
```
这是目录为v8/src/compiler/wasm-gc-operator-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-gc-operator-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-gc-operator-reducer.h"

#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8 {
namespace internal {
namespace compiler {

WasmGCOperatorReducer::WasmGCOperatorReducer(
    Editor* editor, Zone* temp_zone_, MachineGraph* mcgraph,
    const wasm::WasmModule* module, SourcePositionTable* source_position_table)
    : AdvancedReducerWithControlPathState(editor, temp_zone_, mcgraph->graph()),
      mcgraph_(mcgraph),
      gasm_(mcgraph, mcgraph->zone()),
      module_(module),
      source_position_table_(source_position_table) {}

Reduction WasmGCOperatorReducer::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kStart:
      return ReduceStart(node);
    case IrOpcode::kWasmStructGet:
    case IrOpcode::kWasmStructSet:
      return ReduceWasmStructOperation(node);
    case IrOpcode::kWasmArrayLength:
      return ReduceWasmArrayLength(node);
    case IrOpcode::kAssertNotNull:
      return ReduceAssertNotNull(node);
    case IrOpcode::kIsNull:
    case IrOpcode::kIsNotNull:
      return ReduceCheckNull(node);
    case IrOpcode::kWasmTypeCheck:
      return ReduceWasmTypeCheck(node);
    case IrOpcode::kWasmTypeCheckAbstract:
      return ReduceWasmTypeCheckAbstract(node);
    case IrOpcode::kWasmTypeCast:
      return ReduceWasmTypeCast(node);
    case IrOpcode::kWasmTypeCastAbstract:
      return ReduceWasmTypeCastAbstract(node);
    case IrOpcode::kTypeGuard:
      return ReduceTypeGuard(node);
    case IrOpcode::kWasmAnyConvertExtern:
      return ReduceWasmAnyConvertExtern(node);
    case IrOpcode::kMerge:
      return ReduceMerge(node);
    case IrOpcode::kIfTrue:
      return ReduceIf(node, true);
    case IrOpcode::kIfFalse:
      return ReduceIf(node, false);
    case IrOpcode::kDead:
      return NoChange();
    case IrOpcode::kLoop:
      return TakeStatesFromFirstControl(node);
    default:
      if (node->op()->ControlOutputCount() > 0) {
        DCHECK_EQ(1, node->op()->ControlInputCount());
        return TakeStatesFromFirstControl(node);
      } else {
        return NoChange();
      }
  }
}

namespace {
bool InDeadBranch(Node* node) {
  return node->opcode() == IrOpcode::kDead ||
         node->opcode() == IrOpcode::kDeadValue ||
         NodeProperties::GetType(node).AsWasm().type.is_uninhabited();
}

Node* GetAlias(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kWasmTypeCast:
    case IrOpcode::kWasmTypeCastAbstract:
    case IrOpcode::kTypeGuard:
    case IrOpcode::kAssertNotNull:
      return NodeProperties::GetValueInput(node, 0);
    default:
      return nullptr;
  }
}

}  // namespace

Node* WasmGCOperatorReducer::SetType(Node* node, wasm::ValueType type) {
  NodeProperties::SetType(node, Type::Wasm(type, module_, graph()->zone()));
  return node;
}

Reduction WasmGCOperatorReducer::UpdateNodeAndAliasesTypes(
    Node* state_owner, ControlPathTypes parent_state, Node* node,
    wasm::TypeInModule type, bool in_new_block) {
  ControlPathTypes previous_knowledge = GetState(state_owner);
  if (!previous_knowledge.IsEmpty()) {
    NodeWithType current_info = previous_knowledge.LookupState(node);
    if (current_info.IsSet() && current_info.type == type) return NoChange();
  }
  Node* current = node;
  ControlPathTypes current_state = parent_state;
  while (current != nullptr) {
    UpdateStates(state_owner, current_state, current, {current, type},
                 in_new_block);
    current = GetAlias(current);
    current_state = GetState(state_owner);
    in_new_block = false;
  }
  return Changed(state_owner);
}

Reduction WasmGCOperatorReducer::ReduceStart(Node* node) {
  return UpdateStates(node, ControlPathTypes(zone()));
}

wasm::TypeInModule WasmGCOperatorReducer::ObjectTypeFromContext(
    Node* object, Node* control, bool allow_non_wasm) {
  if (object->opcode() == IrOpcode::kDead ||
      object->opcode() == IrOpcode::kDeadValue) {
    return {};
  }
  if (!IsReduced(control)) return {};
  if (allow_non_wasm && !NodeProperties::IsTyped(object)) return {};
  Type raw_type = NodeProperties::GetType(object);
  if (allow_non_wasm && !raw_type.IsWasm()) return {};
  wasm::TypeInModule type_from_node = raw_type.AsWasm();
  ControlPathTypes state = GetState(control);
  NodeWithType type_from_state = state.LookupState(object);
  // We manually resolve TypeGuard aliases in the state.
  while (object->opcode() == IrOpcode::kTypeGuard && !type_from_state.IsSet()) {
    object = NodeProperties::GetValueInput(object, 0);
    type_from_state = state.LookupState(object);
  }
  if (!type_from_state.IsSet()) return type_from_node;
  return wasm::Intersection(type_from_node, type_from_state.type);
}

Reduction WasmGCOperatorReducer::ReduceWasmStructOperation(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kWasmStructGet ||
         node->opcode() == IrOpcode::kWasmStructSet);
  Node* control = NodeProperties::GetControlInput(node);
  if (!IsReduced(control)) return NoChange();
  Node* object = NodeProperties::GetValueInput(node, 0);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();

  if (object_type.type.is_non_nullable()) {
    // If the object is known to be non-nullable in the context, remove the null
    // check.
    auto op_params = OpParameter<WasmFieldInfo>(node->op());
    const Operator* new_op =
        node->opcode() == IrOpcode::kWasmStructGet
            ? simplified()->WasmStructGet(op_params.type, op_params.field_index,
                                          op_params.is_signed,
                                          kWithoutNullCheck)
            : simplified()->WasmStructSet(op_params.type, op_params.field_index,
                                          kWithoutNullCheck);
    NodeProperties::ChangeOp(node, new_op);
  }

  object_type.type = object_type.type.AsNonNull();

  return UpdateNodeAndAliasesTypes(node, GetState(control), object, object_type,
                                   false);
}

Reduction WasmGCOperatorReducer::ReduceWasmArrayLength(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayLength);
  Node* control = NodeProperties::GetControlInput(node);
  if (!IsReduced(control)) return NoChange();
  Node* object = NodeProperties::GetValueInput(node, 0);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();

  if (object_type.type.is_non_nullable()) {
    // If the object is known to be non-nullable in the context, remove the null
    // check.
    const Operator* new_op = simplified()->WasmArrayLength(kWithoutNullCheck);
    NodeProperties::ChangeOp(node, new_op);
  }

  object_type.type = object_type.type.AsNonNull();

  return UpdateNodeAndAliasesTypes(node, GetState(control), object, object_type,
                                   false);
}

// If the condition of this node's branch is a type check or a null check,
// add the additional information about the type-checked node to the path
// state.
Reduction WasmGCOperatorReducer::ReduceIf(Node* node, bool condition) {
  DCHECK(node->opcode() == IrOpcode::kIfTrue ||
         node->opcode() == IrOpcode::kIfFalse);
  Node* branch = NodeProperties::GetControlInput(node);
  if (branch->opcode() == IrOpcode::kDead) return NoChange();
  DCHECK_EQ(branch->opcode(), IrOpcode::kBranch);
  if (!IsReduced(branch)) return NoChange();
  ControlPathTypes parent_state = GetState(branch);
  Node* condition_node = NodeProperties::GetValueInput(branch, 0);
  switch (condition_node->opcode()) {
    case IrOpcode::kWasmTypeCheck:
    case IrOpcode::kWasmTypeCheckAbstract: {
      if (!condition) break;
      Node* object = NodeProperties::GetValueInput(condition_node, 0);
      wasm::TypeInModule object_type = ObjectTypeFromContext(object, branch);
      if (object_type.type.is_uninhabited()) return NoChange();

      wasm::ValueType to_type =
          OpParameter<WasmTypeCheckConfig>(condition_node->op()).to;

      // TODO(12166): Think about {module_} below if we have cross-module
      // inlining.
      wasm::TypeInModule new_type =
          wasm::Intersection(object_type, {to_type, module_});
      return UpdateNodeAndAliasesTypes(node, parent_state, object, new_type,
                                       true);
    }
    case IrOpcode::kIsNull:
    case IrOpcode::kIsNotNull: {
      Node* object = NodeProperties::GetValueInput(condition_node, 0);
      Node* control = NodeProperties::GetControlInput(condition_node);
      wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
      if (object_type.type.is_uninhabited()) return NoChange();
      // If the checked value is null, narrow the type to the corresponding
      // null type, otherwise to a non-null reference.
      bool is_null =
          condition == (condition_node->opcode() == IrOpcode::kIsNull);
      object_type.type = is_null ? wasm::ToNullSentinel(object_type)
                                 : object_type.type.AsNonNull();
      return UpdateNodeAndAliasesTypes(node, parent_state, object, object_type,
                                       true);
    }
    default:
      break;
  }
  return TakeStatesFromFirstControl(node);
}

Reduction WasmGCOperatorReducer::ReduceMerge(Node* node) {
  // Shortcut for the case when we do not know anything about some
  // input.
  Node::Inputs inputs = node->inputs();
  for (Node* input : inputs) {
    if (!IsReduced(input)) return NoChange();
  }

  auto input_it = inputs.begin();

  DCHECK_GT(inputs.count(), 0);

  ControlPathTypes types = GetState(*input_it);
  ++input_it;

  auto input_end = inputs.end();
  for (; input_it != input_end; ++input_it) {
    // Change the current type block list to a longest common prefix of this
    // state list and the other list. (The common prefix should correspond to
    // the state of the common dominator.)
    // TODO(manoskouk): Consider computing unions for some types.
    types.ResetToCommonAncestor(GetState(*input_it));
  }
  return UpdateStates(node, types);
}

Reduction WasmGCOperatorReducer::ReduceAssertNotNull(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kAssertNotNull);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* control = NodeProperties::GetControlInput(node);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();

  // Optimize the check away if the argument is known to be non-null.
  if (object_type.type.is_non_nullable()) {
    // First, relax control.
    ReplaceWithValue(node, node, node, control);
    // Use a TypeGuard node to not lose any type information.
    NodeProperties::ChangeOp(
        node, common()->TypeGuard(NodeProperties::GetType(node)));
    return Changed(node);
  }

  object_type.type = object_type.type.AsNonNull();
  return UpdateNodeAndAliasesTypes(node, GetState(control), node, object_type,
                                   false);
}

Reduction WasmGCOperatorReducer::ReduceCheckNull(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kIsNull ||
         node->opcode() == IrOpcode::kIsNotNull);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* control = NodeProperties::GetControlInput(node);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();

  // Optimize the check away if the argument is known to be non-null.
  if (object_type.type.is_non_nullable()) {
    ReplaceWithValue(node,
                     SetType(gasm_.Int32Constant(
                                 node->opcode() == IrOpcode::kIsNull ? 0 : 1),
                             wasm::kWasmI32));
    node->Kill();
    return Replace(object);  // Irrelevant replacement.
  }

  // Optimize the check away if the argument is known to be null.
  if (object->opcode() == IrOpcode::kNull) {
    ReplaceWithValue(node,
                     SetType(gasm_.Int32Constant(
                                 node->opcode() == IrOpcode::kIsNull ? 1 : 0),
                             wasm::kWasmI32));
    node->Kill();
    return Replace(object);  // Irrelevant replacement.
  }

  return NoChange();
}

Reduction WasmGCOperatorReducer::ReduceWasmAnyConvertExtern(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmAnyConvertExtern);
  // Remove redundant any.convert_extern(extern.convert_any(...)) pattern.
  Node* input = NodeProperties::GetValueInput(node, 0);
  while (input->opcode() == IrOpcode::kTypeGuard) {
    input = NodeProperties::GetValueInput(input, 0);
  }
  if (input->opcode() == IrOpcode::kDead ||
      input->opcode() == IrOpcode::kDeadValue) {
    return NoChange();
  }
  if (input->opcode() == IrOpcode::kWasmExternConvertAny) {
    // "Skip" the extern.convert_any which doesn't have an effect on the value.
    input = NodeProperties::GetValueInput(input, 0);
    ReplaceWithValue(node, input);
    node->Kill();
    return Replace(input);
  }
  return TakeStatesFromFirstControl(node);
}

Reduction WasmGCOperatorReducer::ReduceTypeGuard(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kTypeGuard);
  Node* control = NodeProperties::GetControlInput(node);
  Node* object = NodeProperties::GetValueInput(node, 0);

  // Since TypeGuards can be generated for JavaScript, and this phase is run
  // for wasm-into-JS inlining, we cannot assume the object has a wasm type.
  wasm::TypeInModule object_type =
      ObjectTypeFromContext(object, control, /* allow_non_wasm = */ true);
  if (object_type.type.is_uninhabited()) return NoChange();
  Type guarded_type = TypeGuardTypeOf(node->op());
  if (!guarded_type.IsWasm()) return NoChange();

  wasm::TypeInModule new_type =
      wasm::Intersection(object_type, guarded_type.AsWasm());

  return UpdateNodeAndAliasesTypes(node, GetState(control), node, new_type,
                                   false);
}

Reduction WasmGCOperatorReducer::ReduceWasmTypeCast(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCast);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* rtt = NodeProperties::GetValueInput(node, 1);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();
  if (InDeadBranch(rtt)) return NoChange();
  wasm::TypeInModule rtt_type = NodeProperties::GetType(rtt).AsWasm();
  bool to_nullable =
      OpParameter<WasmTypeCheckConfig>(node->op()).to.is_nullable();

  if (wasm::IsHeapSubtypeOf(object_type.type.heap_type(),
                            wasm::HeapType(rtt_type.type.ref_index()),
                            object_type.module, rtt_type.module)) {
    if (to_nullable) {
      // Type cast will always succeed. Turn it into a TypeGuard to not lose any
      // type information.
      // First, relax control.
      ReplaceWithValue(node, node, node, control);
      // Remove rtt input.
      node->RemoveInput(1);
      NodeProperties::ChangeOp(
          node, common()->TypeGuard(NodeProperties::GetType(node)));
      return Changed(node);
    } else {
      gasm_.InitializeEffectControl(effect, control);
      Node* assert_not_null = gasm_.AssertNotNull(object, object_type.type,
                                                  TrapId::kTrapIllegalCast);
      UpdateSourcePosition(assert_not_null, node);
      return Replace(SetType(assert_not_null, object_type.type.AsNonNull()));
    }
  }

  if (wasm::HeapTypesUnrelated(object_type.type.heap_type(),
                               wasm::HeapType(rtt_type.type.ref_index()),
                               object_type.module, rtt_type.module)) {
    gasm_.InitializeEffectControl(effect, control);
    // A cast between unrelated types can only succeed if the argument is null.
    // Otherwise, it always fails.
    Node* non_trapping_condition = object_type.type.is_nullable() && to_nullable
                                       ? gasm_.IsNull(object, object_type.type)
                                       : gasm_.Int32Constant(0);
    gasm_.TrapUnless(SetType(non_trapping_condition, wasm::kWasmI32),
                     TrapId::kTrapIllegalCast);
    UpdateSourcePosition(gasm_.effect(), node);
    Node* null_node = SetType(gasm_.Null(object_type.type),
                              wasm::ToNullSentinel(object_type));
    ReplaceWithValue(node, null_node, gasm_.effect(), gasm_.control());
    node->Kill();
    return Replace(null_node);
  }

  // TODO(12166): Think about modules below if we have cross-module inlining.

  // Update the from-type in the type cast.
  WasmTypeCheckConfig current_config =
      OpParameter<WasmTypeCheckConfig>(node->op());
  NodeProperties::ChangeOp(node, gasm_.simplified()->WasmTypeCast(
                                     {object_type.type, current_config.to}));

  wasm::TypeInModule new_type = wasm::Intersection(
      object_type,
      {wasm::ValueType::RefNull(rtt_type.type.ref_index()), module_});

  return UpdateNodeAndAliasesTypes(node, GetState(control), node, new_type,
                                   false);
}

Reduction WasmGCOperatorReducer::ReduceWasmTypeCastAbstract(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCastAbstract);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* object = NodeProperties::GetValueInput(node, 0);
  WasmTypeCheckConfig config = OpParameter<WasmTypeCheckConfig>(node->op());

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();
  const bool to_nullable = config.to.is_nullable();

  if (wasm::IsHeapSubtypeOf(object_type.type.heap_type(), config.to.heap_type(),
                            object_type.module)) {
    if (to_nullable || object_type.type.is_non_nullable()) {
      // Type cast will always succeed. Turn it into a TypeGuard to not lose any
      // type information.
      // First, relax control.
      ReplaceWithValue(node, node, node, control);
      NodeProperties::ChangeOp(
          node, common()->TypeGuard(NodeProperties::GetType(node)));
      return Changed(node);
    } else {
      gasm_.InitializeEffectControl(effect, control);
      Node* assert_not_null = gasm_.AssertNotNull(object, object_type.type,
                                                  TrapId::kTrapIllegalCast);
      UpdateSourcePosition(assert_not_null, node);
      return Replace(SetType(assert_not_null, object_type.type.AsNonNull()));
    }
  }

  if (wasm::HeapTypesUnrelated(object_type.type.heap_type(),
                               config.to.heap_type(), object_type.module,
                               object_type.module)) {
    gasm_.InitializeEffectControl(effect, control);
    // A cast between unrelated types can only succeed if the argument is null.
    // Otherwise, it always fails.
    Node* non_trapping_condition = object_type.type.is_nullable() && to_nullable
                                       ? gasm_.IsNull(object, object_type.type)
                                       : gasm_.Int32Constant(0);
    gasm_.TrapUnless(SetType(non_trapping_condition, wasm::kWasmI32),
                     TrapId::kTrapIllegalCast);
    UpdateSourcePosition(gasm_.effect(), node);
    Node* null_node = SetType(gasm_.Null(object_type.type),
                              wasm::ToNullSentinel(object_type));
    ReplaceWithValue(node, null_node, gasm_.effect(), gasm_.control());
    node->Kill();
    return Replace(null_node);
  }

  // Update the from-type in the type cast.
  NodeProperties::ChangeOp(node, gasm_.simplified()->WasmTypeCastAbstract(
                                     {object_type.type, config.to}));

  wasm::TypeInModule new_type =
      wasm::Intersection(object_type, {config.to, module_});

  return UpdateNodeAndAliasesTypes(node, GetState(control), node, new_type,
                                   false);
}

Reduction WasmGCOperatorReducer::ReduceWasmTypeCheck(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCheck);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* rtt = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();
  if (InDeadBranch(rtt)) return NoChange();
  wasm::TypeInModule rtt_type = NodeProperties::GetType(rtt).AsWasm();

  if (wasm::IsHeapSubtypeOf(object_type.type.heap_type(),
                            wasm::HeapType(rtt_type.type.ref_index()),
                            object_type.module, rtt_type.module)) {
    bool null_succeeds =
        OpParameter<WasmTypeCheckConfig>(node->op()).to.is_nullable();
    // Type cast will fail only on null.
    gasm_.InitializeEffectControl(effect, control);
    Node* condition = SetType(object_type.type.is_nullable() && !null_succeeds
                                  ? gasm_.IsNotNull(object, object_type.type)
                                  : gasm_.Int32Constant(1),
                              wasm::kWasmI32);
    ReplaceWithValue(node, condition);
    node->Kill();
    return Replace(condition);
  }

  if (wasm::HeapTypesUnrelated(object_type.type.heap_type(),
                               wasm::HeapType(rtt_type.type.ref_index()),
                               object_type.module, rtt_type.module)) {
    bool null_succeeds =
        OpParameter<WasmTypeCheckConfig>(node->op()).to.is_nullable();
    Node* condition = nullptr;
    if (null_succeeds && object_type.type.is_nullable()) {
      // The cast only succeeds in case of null.
      gasm_.InitializeEffectControl(effect, control);
      condition =
          SetType(gasm_.IsNull(object, object_type.type), wasm::kWasmI32);
    } else {
      // The cast never succeeds.
      condition = SetType(gasm_.Int32Constant(0), wasm::kWasmI32);
    }
    ReplaceWithValue(node, condition);
    node->Kill();
    return Replace(condition);
  }

  // TODO(12166): Think about modules below if we have cross-module inlining.

  // Update the from-type in the type cast.
  WasmTypeCheckConfig current_config =
      OpParameter<WasmTypeCheckConfig>(node->op());
  NodeProperties::ChangeOp(node, gasm_.simplified()->WasmTypeCheck(
                                     {object_type.type, current_config.to}));

  return TakeStatesFromFirstControl(node);
}

Reduction WasmGCOperatorReducer::ReduceWasmTypeCheckAbstract(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCheckAbstract);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  WasmTypeCheckConfig config = OpParameter<WasmTypeCheckConfig>(node->op());

  wasm::TypeInModule object_type = ObjectTypeFromContext(object, control);
  if (object_type.type.is_uninhabited()) return NoChange();
  const bool null_succeeds = config.to.is_nullable();

  if (wasm::IsHeapSubtypeOf(object_type.type.heap_type(), config.to.heap_type(),
                            object_type.module)) {
    // Type cast will fail only on null.
    gasm_.InitializeEffectControl(effect, control);
    Node* condition = SetType(object_type.type.is_nullable() && !null_succeeds
                                  ? gasm_.IsNotNull(object, object_type.type)
                                  : gasm_.Int32Constant(1),
                              wasm::kWasmI32);
    ReplaceWithValue(node, condition);
    node->Kill();
    return Replace(condition);
  }

  // This can never result from user code, only from internal shortcuts,
  // e.g. when using externrefs as strings.
  const bool implicit_internalize =
      config.from.heap_representation() == wasm::HeapType::kExtern &&
      wasm::IsHeapSubtypeOf(config.to.heap_type(),
                            wasm::HeapType(wasm::HeapType::kAny),
                            object_type.module);
  if (!implicit_internalize &&
      wasm::HeapTypesUnrelated(object_type.type.heap_type(),
                               config.to.heap_type(), object_type.module,
                               object_type.module)) {
    Node* condition = nullptr;
    if (null_succeeds && object_type.type.is_nullable()) {
      // The cast only succeeds in case of null.
      gasm_.InitializeEffectControl(effect, control);
      condition =
          SetType(gasm_.IsNull(object, object_type.type), wasm::kWasmI32);
    } else {
      // The cast never succeeds.
      condition = SetType(gasm_.Int32Constant(0), wasm::kWasmI32);
    }
    ReplaceWithValue(node, condition);
    node->Kill();
    return Replace(condition);
  }

  // Update the from-type in the type cast.
  NodeProperties::ChangeOp(node, gasm_.simplified()->WasmTypeCheckAbstract(
                                     {object_type.type, config.to}));

  return TakeStatesFromFirstControl(node);
}

void WasmGCOperatorReducer::UpdateSourcePosition(Node* new_node,
                                                 Node* old_node) {
  if (source_position_table_) {
    SourcePosition position =
        source_position_table_->GetSourcePosition(old_node);
    DCHECK(position.ScriptOffset() != kNoSourcePosition);
    source_position_table_->SetSourcePosition(new_node, position);
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```
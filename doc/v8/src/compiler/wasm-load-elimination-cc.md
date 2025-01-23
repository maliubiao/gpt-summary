Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for a functional description of the C++ code, along with explanations related to its connection to JavaScript, potential programming errors, and example usage. The prompt also includes a hint about Torque if the file ended in `.tq`.

2. **Initial Scan and Key Terms:**  Quickly read through the code, identifying key terms and structures. Notice things like:
    * `#include` statements (especially the `wasm-load-elimination.h`) suggest this is a compiler optimization pass.
    * The namespace `v8::internal::compiler` reinforces this.
    * Function names like `ReduceWasmStructGet`, `ReduceWasmStructSet`, `ReduceWasmArrayLength` strongly indicate dealing with WebAssembly structures and arrays.
    * The use of `Node*`, `Graph*`, `JSGraph*`, `AbstractState` suggests interaction with Turbofan's intermediate representation.
    * The presence of `MayAlias`, `ResolveAliases`, `TypesUnrelated` points to alias analysis and type handling.
    * The `AbstractState` and `HalfState` classes likely manage the state of the optimization.

3. **Identify Core Functionality:** Based on the initial scan, the primary goal seems to be **load elimination** for WebAssembly code. This means identifying redundant loads from memory and replacing them with the previously computed value.

4. **Analyze `Reduce` Functions:**  Focus on the `Reduce` method and the specific `Reduce...` functions. Each of these handles a specific WebAssembly operation:
    * `ReduceWasmStructGet`:  Handles reading fields from WebAssembly structs. The logic here is central to load elimination – checking if the value is already known in the `AbstractState`.
    * `ReduceWasmStructSet`: Handles writing fields to WebAssembly structs. This is crucial for *updating* the `AbstractState`.
    * `ReduceWasmArrayLength`: Handles getting the length of a WebAssembly array.
    * Other `Reduce...` functions deal with related operations like array initialization, string operations, and type conversions.

5. **Examine the `AbstractState`:**  This class is key to understanding how the optimization works. It stores information about the values of fields and array elements. Notice:
    * `HalfState`:  Separate tracking of mutable and immutable fields. This is important for correctness.
    * `LookupField`: Checks if a value for a given field/object is already known.
    * `AddField`:  Registers a new value for a field/object.
    * `KillField`:  Invalidates information about a field, typically when a store occurs.
    * `IntersectWith`:  Used in `EffectPhi` to combine states from different control flow paths.

6. **Infer the Optimization Strategy:**  The code appears to use a **dataflow analysis** approach. It maintains an abstract state that tracks the values of memory locations (struct fields, array lengths). When a load operation is encountered, it checks the state. If the value is known, the load can be eliminated. Stores update the state, potentially invalidating previously known values.

7. **Connect to JavaScript (Conceptual):** While the code is for *WebAssembly* load elimination, understand how this relates to JavaScript. WebAssembly often runs within a JavaScript environment. Optimizing WebAssembly code can improve the overall performance of web applications. Think about how JavaScript objects and arrays have similar concepts of properties/elements. The optimization techniques are similar in spirit, though the specific operations differ.

8. **Identify Potential Programming Errors (Relating to Usage):**  Consider how a *user* interacting with a system that has this optimization might make mistakes that the optimization aims to handle or that the optimization's absence would make worse. Think about:
    * Redundant reads of the same struct field.
    * Repeatedly getting the length of an array.

9. **Develop Examples (Conceptual JavaScript):** Since the code is about WebAssembly, provide simplified *JavaScript* examples that illustrate the *concept* of redundant loads. The goal is to make the idea accessible, not to directly translate the C++ code into JavaScript.

10. **Consider Code Logic and Assumptions:**  Look for key assumptions made by the optimization:
    * Alias analysis: The `MayAlias` function is crucial. If the analysis is too conservative, it might miss opportunities for optimization. If it's too aggressive, it could lead to incorrect optimizations.
    * Type information:  The code relies heavily on type information (`NodeProperties::GetType`). Incorrect or missing type information can hinder the optimization.

11. **Address the `.tq` Question:** Note that the file extension is `.cc`, so it's C++, not Torque. Briefly explain what Torque is for completeness.

12. **Structure the Explanation:** Organize the findings into logical sections: functionality, relationship to JavaScript, example, assumptions, common errors, etc. Use clear and concise language.

13. **Refine and Review:** Read through the explanation, ensuring it's accurate, easy to understand, and addresses all parts of the request. Check for any inconsistencies or areas that could be clarified. For example, initially, I might have focused too much on the C++ details. Revising, I would emphasize the high-level purpose of load elimination and its benefit to performance. I would also make sure the JavaScript examples are conceptually aligned even if the syntax differs drastically.
This C++ source code file `v8/src/compiler/wasm-load-elimination.cc` implements a compiler optimization pass for WebAssembly (Wasm) code within the V8 JavaScript engine. Specifically, it performs **load elimination**.

Here's a breakdown of its functionality:

**Core Functionality: WebAssembly Load Elimination**

The primary goal of this code is to identify and eliminate redundant load operations in WebAssembly code. A load operation retrieves a value from memory (e.g., reading a field from a struct or an element from an array). If the compiler can prove that the value being loaded was already computed and is still valid, it can replace the load operation with the previously computed value, thus improving performance.

**Key Mechanisms:**

1. **Abstract State Tracking:** The code maintains an `AbstractState` for each point in the control flow graph. This state tracks the values of WebAssembly struct fields and array lengths that have been previously stored.

2. **Alias Analysis:**  The `MayAlias` function is used to determine if two memory locations might refer to the same data. This is crucial for correctness; a load can only be eliminated if no intervening store to the same location (or an aliasing location) has occurred.

3. **State Updates on Stores:** When a store operation (e.g., `WasmStructSet`) is encountered, the `AbstractState` is updated to reflect the new value. If a store might invalidate a previously known value (due to aliasing), that information is removed from the state.

4. **Load Replacement:** When a load operation (e.g., `WasmStructGet`, `WasmArrayLength`) is encountered, the `AbstractState` is checked. If the state contains the value being loaded and it's determined to be valid (no intervening potentially aliasing stores), the load operation is replaced with the stored value.

5. **Handling Control Flow:** The code correctly handles control flow constructs like loops (`EffectPhi` with `kLoop`) and merges (`EffectPhi` with `kMerge`) to propagate and merge the `AbstractState`.

**Specific Operations Handled:**

* **`ReduceWasmStructGet`:**  Eliminates redundant reads of struct fields.
* **`ReduceWasmStructSet`:** Updates the abstract state when writing to a struct field.
* **`ReduceWasmArrayLength`:** Eliminates redundant reads of array lengths.
* **`ReduceWasmArrayInitializeLength`:**  Handles the initial setting of array lengths.
* **`ReduceStringPrepareForGetCodeunit` and `ReduceStringAsWtf16`:**  Optimizes access to string data.
* **`ReduceAnyConvertExtern`:**  Handles conversions from `externref` to other Wasm types, treating certain `externref` values as immutable.

**File Type and Relationship to JavaScript:**

The file `v8/src/compiler/wasm-load-elimination.cc` ends with `.cc`, which signifies that it is a **C++ source code file**. It is **not** a V8 Torque source file (which would end in `.tq`).

This code is directly related to the performance of **WebAssembly** code executed within the V8 engine. While it doesn't directly manipulate JavaScript code, it significantly impacts the efficiency of Wasm modules running in a JavaScript environment.

**JavaScript Example (Conceptual)**

Although the optimization works on WebAssembly, we can illustrate the *concept* of load elimination with a simplified JavaScript analogy:

```javascript
function processPoint(point) {
  const x1 = point.x; // Load 'x'
  const y1 = point.y; // Load 'y'

  // ... some computations using x1 and y1 ...

  const x2 = point.x; // Potentially redundant load of 'x'
  const y2 = point.y; // Potentially redundant load of 'y'

  return x1 + y1 + x2 + y2;
}

const myPoint = { x: 10, y: 20 };
processPoint(myPoint);
```

In this JavaScript example, if the compiler can determine that the `point.x` and `point.y` values haven't changed between the first and second access, the second access could be optimized by reusing the values loaded initially. The `wasm-load-elimination.cc` code performs a similar optimization but for WebAssembly structures and arrays.

**Code Logic Reasoning (Hypothetical)**

**Assumption:** We have a WebAssembly function that accesses a struct field multiple times.

**Input (Wasm IR - Simplified):**

```
%struct = ... // Allocation of a struct
%field_value = i32.const 100
struct.set %struct, 0, %field_value  // Set field 0 to 100
%load1 = struct.get %struct, 0       // Load field 0
// ... some operations that don't modify %struct ...
%load2 = struct.get %struct, 0       // Load field 0 again
```

**Output (after Load Elimination):**

```
%struct = ...
%field_value = i32.const 100
struct.set %struct, 0, %field_value
%load1 = struct.get %struct, 0
// ... some operations ...
%load2 = %load1                  // Load replaced with the previous value
```

The `WasmLoadElimination` pass would identify that the value of field 0 of `%struct` is known to be `%load1` at the point of the second load (`%load2`) because there are no intervening store operations to that field (and no potential aliasing writes). Therefore, it replaces the second load with the result of the first load.

**Common Programming Errors (Conceptual)**

From a user's perspective (writing WebAssembly or tools that generate WebAssembly), the load elimination optimization aims to mitigate the performance impact of:

* **Redundant Data Access:**  Repeatedly reading the same data from memory when the value is already available in a register or cache.
* **Unnecessary Loads in Loops:**  Accessing the same struct field or array element within a loop iteration without a need to reload it.

**Example of a scenario where load elimination is beneficial:**

Imagine a WebAssembly function that calculates the distance between two 3D points represented as structs:

```wasm
(module
  (type $point_t (struct (field i32) (field i32) (field i32)))
  (func $distance (param $p1 (ref $point_t)) (param $p2 (ref $point_t)) (result f32)
    (local $dx f32)
    (local $dy f32)
    (local $dz f32)

    ;; Calculate dx = p1.x - p2.x
    local.get $p1
    struct.get $point_t 0  ;; Load p1.x
    i32.convert_f32_s
    local.get $p2
    struct.get $point_t 0  ;; Load p2.x
    i32.convert_f32_s
    f32.sub
    local.set $dx

    ;; Calculate dy = p1.y - p2.y
    local.get $p1
    struct.get $point_t 1  ;; Load p1.y
    i32.convert_f32_s
    local.get $p2
    struct.get $point_t 1  ;; Load p2.y
    i32.convert_f32_s
    f32.sub
    local.set $dy

    ;; Calculate dz = p1.z - p2.z
    local.get $p1
    struct.get $point_t 2  ;; Load p1.z
    i32.convert_f32_s
    local.get $p2
    struct.get $point_t 2  ;; Load p2.z
    i32.convert_f32_s
    f32.sub
    local.set $dz

    ;; Calculate sqrt(dx^2 + dy^2 + dz^2)
    local.get $dx
    local.get $dx
    f32.mul
    local.get $dy
    local.get $dy
    f32.mul
    f32.add
    local.get $dz
    local.get $dz
    f32.mul
    f32.add
    f32.sqrt
  )
  (export "distance" (func $distance))
)
```

Without load elimination, `p1.x`, `p1.y`, `p1.z`, `p2.x`, `p2.y`, and `p2.z` would be loaded multiple times. With load elimination, after the first load of each field, subsequent loads within the same function execution (without intervening modifications) can be replaced with the previously loaded value, making the function more efficient.

In summary, `v8/src/compiler/wasm-load-elimination.cc` is a crucial component of V8's WebAssembly compiler, responsible for optimizing performance by removing redundant memory load operations based on dataflow analysis and state tracking.

### 提示词
```
这是目录为v8/src/compiler/wasm-load-elimination.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-load-elimination.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-load-elimination.h"

#include "src/compiler/common-operator.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/simplified-operator.h"
#include "src/compiler/turbofan-graph.h"
#include "src/wasm/struct-types.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler {

/**** Helpers ****/

namespace {
bool TypesUnrelated(Node* lhs, Node* rhs) {
  wasm::TypeInModule type1 = NodeProperties::GetType(lhs).AsWasm();
  wasm::TypeInModule type2 = NodeProperties::GetType(rhs).AsWasm();
  return wasm::TypesUnrelated(type1.type, type2.type, type1.module,
                              type2.module);
}

bool IsFresh(Node* node) {
  return node->opcode() == IrOpcode::kAllocate ||
         node->opcode() == IrOpcode::kAllocateRaw;
}

bool IsConstant(Node* node) {
  return node->opcode() == IrOpcode::kParameter ||
         node->opcode() == IrOpcode::kHeapConstant;
}

bool MayAlias(Node* lhs, Node* rhs) {
  if (lhs == rhs) return true;
  if (TypesUnrelated(lhs, rhs) || (IsFresh(lhs) && IsFresh(rhs)) ||
      (IsFresh(lhs) && IsConstant(rhs)) || (IsConstant(lhs) && IsFresh(rhs))) {
    return false;
  }
  return true;
}

Node* ResolveAliases(Node* node) {
  while (node->opcode() == IrOpcode::kWasmTypeCast ||
         node->opcode() == IrOpcode::kWasmTypeCastAbstract ||
         node->opcode() == IrOpcode::kAssertNotNull ||
         node->opcode() == IrOpcode::kTypeGuard) {
    node = NodeProperties::GetValueInput(node, 0);
  }
  return node;
}

// We model array length and string canonicalization as fields at negative
// indices.
constexpr int kArrayLengthFieldIndex = -1;
constexpr int kStringPrepareForGetCodeunitIndex = -2;
constexpr int kStringAsWtf16Index = -3;
constexpr int kAnyConvertExternIndex = -4;
}  // namespace

Reduction WasmLoadElimination::UpdateState(Node* node,
                                           AbstractState const* state) {
  AbstractState const* original = node_states_.Get(node);
  // Only signal that the {node} has Changed, if the information about {state}
  // has changed wrt. the {original}.
  if (state != original) {
    if (original == nullptr || !state->Equals(original)) {
      node_states_.Set(node, state);
      return Changed(node);
    }
  }
  return NoChange();
}

std::tuple<Node*, Node*> WasmLoadElimination::TruncateAndExtendOrType(
    Node* value, Node* effect, Node* control, wasm::ValueType field_type,
    bool is_signed) {
  if (field_type == wasm::kWasmI8 || field_type == wasm::kWasmI16) {
    Node* ret = nullptr;
    if (is_signed) {
      int shift = 32 - 8 * field_type.value_kind_size();
      ret = graph()->NewNode(machine()->Word32Sar(),
                             graph()->NewNode(machine()->Word32Shl(), value,
                                              jsgraph()->Int32Constant(shift)),
                             jsgraph()->Int32Constant(shift));
    } else {
      int mask = (1 << 8 * field_type.value_kind_size()) - 1;
      ret = graph()->NewNode(machine()->Word32And(), value,
                             jsgraph()->Int32Constant(mask));
    }

    NodeProperties::SetType(ret, NodeProperties::GetType(value));
    return {ret, effect};
  }

  // The value might be untyped in case of wasm inlined into JS if the value
  // comes from a JS node.
  if (!NodeProperties::IsTyped(value)) {
    return {value, effect};
  }

  Type value_type = NodeProperties::GetType(value);
  if (!value_type.IsWasm()) {
    return {value, effect};
  }

  wasm::TypeInModule node_type = value_type.AsWasm();

  // TODO(12166): Adapt this if cross-module inlining is allowed.
  if (wasm::TypesUnrelated(node_type.type, field_type, node_type.module,
                           node_type.module)) {
    // Unrelated types can occur as a result of unreachable code.
    // Example: Storing a value x of type A in a struct, then casting the struct
    // to a different struct type to then load type B from the same offset
    // results in trying to replace the load with value x.
    return {dead(), dead()};
  }
  if (!wasm::IsSubtypeOf(node_type.type, field_type, node_type.module)) {
    Type type = Type::Wasm({field_type, node_type.module}, graph()->zone());
    Node* ret =
        graph()->NewNode(common()->TypeGuard(type), value, effect, control);
    NodeProperties::SetType(ret, type);
    return {ret, ret};
  }

  return {value, effect};
}

/***** Reductions *****/

Reduction WasmLoadElimination::Reduce(Node* node) {
  if (v8_flags.trace_turbo_load_elimination) {
    // TODO(manoskouk): Add some tracing.
  }
  switch (node->opcode()) {
    case IrOpcode::kWasmStructGet:
      return ReduceWasmStructGet(node);
    case IrOpcode::kWasmStructSet:
      return ReduceWasmStructSet(node);
    case IrOpcode::kWasmArrayLength:
      return ReduceWasmArrayLength(node);
    case IrOpcode::kWasmArrayInitializeLength:
      return ReduceWasmArrayInitializeLength(node);
    case IrOpcode::kStringPrepareForGetCodeunit:
      return ReduceStringPrepareForGetCodeunit(node);
    case IrOpcode::kStringAsWtf16:
      return ReduceStringAsWtf16(node);
    case IrOpcode::kWasmAnyConvertExtern:
      return ReduceAnyConvertExtern(node);
    case IrOpcode::kEffectPhi:
      return ReduceEffectPhi(node);
    case IrOpcode::kDead:
      return NoChange();
    case IrOpcode::kStart:
      return ReduceStart(node);
    default:
      return ReduceOtherNode(node);
  }
}

Reduction WasmLoadElimination::ReduceWasmStructGet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmStructGet);
  Node* input_struct = NodeProperties::GetValueInput(node, 0);
  Node* object = ResolveAliases(input_struct);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (object->opcode() == IrOpcode::kDead) return NoChange();
  AbstractState const* state = node_states_.Get(effect);
  if (state == nullptr) return NoChange();

  const WasmFieldInfo& field_info = OpParameter<WasmFieldInfo>(node->op());
  bool is_mutable = field_info.type->mutability(field_info.field_index);

  if (!NodeProperties::IsTyped(input_struct) ||
      !NodeProperties::GetType(input_struct).IsWasm()) {
    // The input should always be typed.  https://crbug.com/1507106 reported
    // that we can end up with Type None here instead of a wasm type.
    // In the worst case this only means that we miss a potential optimization,
    // still the assumption is that all inputs into StructGet should be typed.
    return NoChange();
  }
  // Skip reduction if the input type is nullref. in this case, the struct get
  // will always trap.
  wasm::ValueType struct_type =
      NodeProperties::GetType(input_struct).AsWasm().type;
  if (struct_type == wasm::kWasmNullRef) {
    return NoChange();
  }
  // The node is in unreachable code if its input is uninhabitable (bottom or
  // ref none type). It can also be treated as unreachable if the field index is
  // in the wrong half state. This can happen if an object gets cast to two
  // unrelated types subsequently (as the state only tracks the field index)
  // independent of the underlying type.
  if (struct_type.is_uninhabited() ||
      !(is_mutable ? state->immutable_state : state->mutable_state)
           .LookupField(field_info.field_index, object)
           .IsEmpty()) {
    ReplaceWithValue(node, dead(), dead(), dead());
    MergeControlToEnd(graph(), common(),
                      graph()->NewNode(common()->Throw(), effect, control));
    node->Kill();
    return Replace(dead());
  }
  // If the input type is not (ref null? none) or bottom and we don't have type
  // inconsistencies, then the result type must be valid.
  DCHECK(!NodeProperties::GetType(node).AsWasm().type.is_bottom());

  HalfState const* half_state =
      is_mutable ? &state->mutable_state : &state->immutable_state;

  FieldOrElementValue lookup_result =
      half_state->LookupField(field_info.field_index, object);

  if (!lookup_result.IsEmpty() && !lookup_result.value->IsDead()) {
    std::tuple<Node*, Node*> replacement = TruncateAndExtendOrType(
        lookup_result.value, effect, control,
        field_info.type->field(field_info.field_index), field_info.is_signed);
    if (std::get<0>(replacement) == dead()) {
      // If the value is dead (unreachable), this whole code path is unreachable
      // and we can mark this control flow path as dead.
      ReplaceWithValue(node, dead(), dead(), dead());
      MergeControlToEnd(graph(), common(),
                        graph()->NewNode(common()->Throw(), effect, control));
      node->Kill();
      return Replace(dead());
    }
    ReplaceWithValue(node, std::get<0>(replacement), std::get<1>(replacement),
                     control);
    node->Kill();
    return Replace(std::get<0>(replacement));
  }

  half_state = half_state->AddField(field_info.field_index, object, node);

  AbstractState const* new_state =
      is_mutable
          ? zone()->New<AbstractState>(*half_state, state->immutable_state)
          : zone()->New<AbstractState>(state->mutable_state, *half_state);

  return UpdateState(node, new_state);
}

Reduction WasmLoadElimination::ReduceWasmStructSet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmStructSet);
  Node* input_struct = NodeProperties::GetValueInput(node, 0);
  Node* object = ResolveAliases(input_struct);
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (object->opcode() == IrOpcode::kDead) return NoChange();
  AbstractState const* state = node_states_.Get(effect);
  if (state == nullptr) return NoChange();

  if (!NodeProperties::IsTyped(input_struct) ||
      !NodeProperties::GetType(input_struct).IsWasm()) {
    // Also see the same pattern in ReduceWasmStructGet. Note that this is
    // reached for cases where the StructSet has a value input that is
    // DeadValue(). Above we check for `object->opcode() == IrOpcode::kDead.
    // As an alternative that check could be extended to also check for
    // ... || object->opcode() == IrOpcode::kDeadValue.
    // It seems that the DeadValue may be caused by
    // DeadCodeElimination::ReducePureNode. If that finds any input that is a
    // Dead() node, it will replace that input with a DeadValue().
    return NoChange();
  }

  // Skip reduction if the input type is nullref. in this case, the struct get
  // will always trap.
  wasm::ValueType struct_type =
      NodeProperties::GetType(input_struct).AsWasm().type;
  if (struct_type == wasm::kWasmNullRef) {
    return NoChange();
  }

  const WasmFieldInfo& field_info = OpParameter<WasmFieldInfo>(node->op());
  bool is_mutable = field_info.type->mutability(field_info.field_index);

  // The struct.set is unreachable if its input struct is an uninhabitable type.
  // It can also be treated as unreachable if the field index is in the wrong
  // half state. This can happen if an object gets cast to two unrelated types
  // subsequently (as the state only tracks the field index) independent of the
  // underlying type.
  if (struct_type.is_uninhabited() ||
      !(is_mutable ? state->immutable_state : state->mutable_state)
           .LookupField(field_info.field_index, object)
           .IsEmpty()) {
    ReplaceWithValue(node, dead(), dead(), dead());
    MergeControlToEnd(graph(), common(),
                      graph()->NewNode(common()->Throw(), effect, control));
    node->Kill();
    return Replace(dead());
  }

  if (is_mutable) {
    HalfState const* mutable_state =
        state->mutable_state.KillField(field_info.field_index, object);
    mutable_state =
        mutable_state->AddField(field_info.field_index, object, value);
    AbstractState const* new_state =
        zone()->New<AbstractState>(*mutable_state, state->immutable_state);
    return UpdateState(node, new_state);
  } else {
    // We should not initialize the same immutable field twice.
    DCHECK(state->immutable_state.LookupField(field_info.field_index, object)
               .IsEmpty());
    HalfState const* immutable_state =
        state->immutable_state.AddField(field_info.field_index, object, value);
    AbstractState const* new_state =
        zone()->New<AbstractState>(state->mutable_state, *immutable_state);
    return UpdateState(node, new_state);
  }
}

Reduction WasmLoadElimination::ReduceLoadLikeFromImmutable(Node* node,
                                                           int index) {
  // The index must be negative as it is not a real load, to not confuse it with
  // actual loads.
  DCHECK_LT(index, 0);
  Node* object = ResolveAliases(NodeProperties::GetValueInput(node, 0));
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (object->opcode() == IrOpcode::kDead) return NoChange();
  AbstractState const* state = node_states_.Get(effect);
  if (state == nullptr) return NoChange();

  HalfState const* immutable_state = &state->immutable_state;

  FieldOrElementValue lookup_result =
      immutable_state->LookupField(index, object);

  if (!lookup_result.IsEmpty() && !lookup_result.value->IsDead()) {
    ReplaceWithValue(node, lookup_result.value, effect, control);
    node->Kill();
    return Replace(lookup_result.value);
  }

  immutable_state = immutable_state->AddField(index, object, node);

  AbstractState const* new_state =
      zone()->New<AbstractState>(state->mutable_state, *immutable_state);

  return UpdateState(node, new_state);
}

Reduction WasmLoadElimination::ReduceWasmArrayLength(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayLength);
  return ReduceLoadLikeFromImmutable(node, kArrayLengthFieldIndex);
}

Reduction WasmLoadElimination::ReduceWasmArrayInitializeLength(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayInitializeLength);
  Node* object = ResolveAliases(NodeProperties::GetValueInput(node, 0));
  Node* value = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);

  if (object->opcode() == IrOpcode::kDead) return NoChange();
  AbstractState const* state = node_states_.Get(effect);
  if (state == nullptr) return NoChange();

  // We should not initialize the length twice.
  DCHECK(state->immutable_state.LookupField(kArrayLengthFieldIndex, object)
             .IsEmpty());
  HalfState const* immutable_state =
      state->immutable_state.AddField(kArrayLengthFieldIndex, object, value);
  AbstractState const* new_state =
      zone()->New<AbstractState>(state->mutable_state, *immutable_state);
  return UpdateState(node, new_state);
}

Reduction WasmLoadElimination::ReduceStringPrepareForGetCodeunit(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kStringPrepareForGetCodeunit);
  Node* object = ResolveAliases(NodeProperties::GetValueInput(node, 0));
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  if (object->opcode() == IrOpcode::kDead) return NoChange();
  AbstractState const* state = node_states_.Get(effect);
  if (state == nullptr) return NoChange();

  HalfState const* mutable_state = &state->mutable_state;

  FieldOrElementValue lookup_result =
      mutable_state->LookupField(kStringPrepareForGetCodeunitIndex, object);

  if (!lookup_result.IsEmpty() && !lookup_result.value->IsDead()) {
    for (size_t i : {0, 1, 2}) {
      Node* proj_to_replace = NodeProperties::FindProjection(node, i);
      ReplaceWithValue(proj_to_replace,
                       NodeProperties::FindProjection(lookup_result.value, i));
      proj_to_replace->Kill();
    }
    ReplaceWithValue(node, lookup_result.value, effect, control);
    node->Kill();
    return Replace(lookup_result.value);
  }

  mutable_state =
      mutable_state->AddField(kStringPrepareForGetCodeunitIndex, object, node);

  AbstractState const* new_state =
      zone()->New<AbstractState>(*mutable_state, state->immutable_state);

  return UpdateState(node, new_state);
}

Reduction WasmLoadElimination::ReduceStringAsWtf16(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kStringAsWtf16);
  return ReduceLoadLikeFromImmutable(node, kStringAsWtf16Index);
}

Reduction WasmLoadElimination::ReduceAnyConvertExtern(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmAnyConvertExtern);
  // An externref is not immutable meaning it could change. However, the values
  // relevant for any.convert_extern (null, HeapNumber, Smi) are immutable, so
  // we can treat the externref as immutable.
  return ReduceLoadLikeFromImmutable(node, kAnyConvertExternIndex);
}

Reduction WasmLoadElimination::ReduceOtherNode(Node* node) {
  if (node->op()->EffectOutputCount() == 0) return NoChange();
  DCHECK_EQ(node->op()->EffectInputCount(), 1);
  Node* const effect = NodeProperties::GetEffectInput(node);
  AbstractState const* state = node_states_.Get(effect);
  // If we do not know anything about the predecessor, do not propagate just
  // yet because we will have to recompute anyway once we compute the
  // predecessor.
  if (state == nullptr) return NoChange();
  // If this {node} has some uncontrolled side effects (i.e. it is a call
  // without {kNoWrite}), set its state to the immutable half-state of its
  // input state, otherwise to its input state.
  // Any cached StringPrepareForGetCodeUnit nodes must be killed at any point
  // that can cause internalization of strings (i.e. that can turn sequential
  // strings into thin strings). Currently, that can only happen in JS, so
  // from Wasm's point of view only in calls.
  return UpdateState(node, node->opcode() == IrOpcode::kCall &&
                                   !node->op()->HasProperty(Operator::kNoWrite)
                               ? zone()->New<AbstractState>(
                                     HalfState(zone()), state->immutable_state)
                               : state);
}

Reduction WasmLoadElimination::ReduceStart(Node* node) {
  return UpdateState(node, empty_state());
}

Reduction WasmLoadElimination::ReduceEffectPhi(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kEffectPhi);
  Node* const effect0 = NodeProperties::GetEffectInput(node, 0);
  Node* const control = NodeProperties::GetControlInput(node);
  AbstractState const* state0 = node_states_.Get(effect0);
  if (state0 == nullptr) return NoChange();
  if (control->opcode() == IrOpcode::kLoop) {
    // Here we rely on having only reducible loops:
    // The loop entry edge always dominates the header, so we can just take
    // the state from the first input, and compute the loop state based on it.
    AbstractState const* state = ComputeLoopState(node, state0);
    return UpdateState(node, state);
  }
  DCHECK_EQ(IrOpcode::kMerge, control->opcode());

  // Shortcut for the case when we do not know anything about some input.
  int const input_count = node->op()->EffectInputCount();
  for (int i = 1; i < input_count; ++i) {
    Node* const effect = NodeProperties::GetEffectInput(node, i);
    if (node_states_.Get(effect) == nullptr) return NoChange();
  }

  // Make a copy of the first input's state and intersect it with the state
  // from other inputs.
  // TODO(manoskouk): Consider computing phis for at least a subset of the
  // state.
  AbstractState* state = zone()->New<AbstractState>(*state0);
  for (int i = 1; i < input_count; ++i) {
    Node* const input = NodeProperties::GetEffectInput(node, i);
    state->IntersectWith(node_states_.Get(input));
  }
  return UpdateState(node, state);
}

/***** AbstractState implementation *****/

WasmLoadElimination::FieldOrElementValue
WasmLoadElimination::HalfState::LookupField(int field_index,
                                            Node* object) const {
  return fields_.Get(field_index).Get(object);
}

WasmLoadElimination::HalfState const* WasmLoadElimination::HalfState::AddField(
    int field_index, Node* object, Node* value) const {
  HalfState* new_state = zone_->New<HalfState>(*this);
  Update(new_state->fields_, field_index, object, FieldOrElementValue(value));
  return new_state;
}

WasmLoadElimination::HalfState const* WasmLoadElimination::HalfState::KillField(
    int field_index, Node* object) const {
  const InnerMap& same_index_map = fields_.Get(field_index);
  InnerMap new_map(same_index_map);
  for (std::pair<Node*, FieldOrElementValue> pair : same_index_map) {
    if (MayAlias(pair.first, object)) {
      new_map.Set(pair.first, FieldOrElementValue());
    }
  }
  HalfState* result = zone_->New<HalfState>(*this);
  result->fields_.Set(field_index, new_map);
  return result;
}

WasmLoadElimination::AbstractState const* WasmLoadElimination::ComputeLoopState(
    Node* node, AbstractState const* state) const {
  DCHECK_EQ(node->opcode(), IrOpcode::kEffectPhi);
  if (state->mutable_state.IsEmpty()) return state;
  std::queue<Node*> queue;
  AccountingAllocator allocator;
  Zone temp_set_zone(&allocator, ZONE_NAME);
  ZoneUnorderedSet<Node*> visited(&temp_set_zone);
  visited.insert(node);
  for (int i = 1; i < node->InputCount() - 1; ++i) {
    queue.push(node->InputAt(i));
  }
  while (!queue.empty()) {
    Node* const current = queue.front();
    queue.pop();
    if (visited.insert(current).second) {
      if (current->opcode() == IrOpcode::kWasmStructSet) {
        Node* object = NodeProperties::GetValueInput(current, 0);
        if (object->opcode() == IrOpcode::kDead ||
            object->opcode() == IrOpcode::kDeadValue) {
          // We are in dead code. Bail out with no mutable state.
          return zone()->New<AbstractState>(HalfState(zone()),
                                            state->immutable_state);
        }
        WasmFieldInfo field_info = OpParameter<WasmFieldInfo>(current->op());
        bool is_mutable = field_info.type->mutability(field_info.field_index);
        if (is_mutable) {
          const HalfState* new_mutable_state =
              state->mutable_state.KillField(field_info.field_index, object);
          state = zone()->New<AbstractState>(*new_mutable_state,
                                             state->immutable_state);
        } else {
          // TODO(manoskouk): DCHECK
        }
      } else if (current->opcode() == IrOpcode::kCall &&
                 !current->op()->HasProperty(Operator::kNoWrite)) {
        return zone()->New<AbstractState>(HalfState(zone()),
                                          state->immutable_state);
      }
      for (int i = 0; i < current->op()->EffectInputCount(); ++i) {
        queue.push(NodeProperties::GetEffectInput(current, i));
      }
    }
  }
  return state;
}

void WasmLoadElimination::HalfState::IntersectWith(HalfState const* that) {
  FieldOrElementValue empty;
  for (const std::pair<int, InnerMap> to_map : fields_) {
    InnerMap to_map_copy(to_map.second);
    int key = to_map.first;
    const InnerMap& current_map = that->fields_.Get(key);
    for (std::pair<Node*, FieldOrElementValue> value : to_map.second) {
      if (current_map.Get(value.first) != value.second) {
        to_map_copy.Set(value.first, empty);
      }
    }
    fields_.Set(key, to_map_copy);
  }
}

/***** Constructor/ trivial accessors *****/
WasmLoadElimination::WasmLoadElimination(Editor* editor, JSGraph* jsgraph,
                                         Zone* zone)
    : AdvancedReducer(editor),
      empty_state_(zone),
      node_states_(jsgraph->graph()->NodeCount(), zone),
      jsgraph_(jsgraph),
      dead_(jsgraph->Dead()),
      zone_(zone) {}

CommonOperatorBuilder* WasmLoadElimination::common() const {
  return jsgraph()->common();
}

MachineOperatorBuilder* WasmLoadElimination::machine() const {
  return jsgraph()->machine();
}

Graph* WasmLoadElimination::graph() const { return jsgraph()->graph(); }

Isolate* WasmLoadElimination::isolate() const { return jsgraph()->isolate(); }

}  // namespace v8::internal::compiler
```
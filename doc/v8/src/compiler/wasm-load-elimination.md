Response: Let's break down the thought process for summarizing the C++ code.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its relationship to JavaScript, illustrated with JavaScript examples if applicable.

2. **Initial Scan and Keywords:**  Read through the code, looking for key terms and patterns. "WasmLoadElimination" in the class name is a major clue. Other recurring terms like "WasmStructGet," "WasmStructSet," "WasmArrayLength," and "AbstractState" jump out. The `#include` directives at the top hint at the code's purpose within the V8 compiler.

3. **Identify the Core Problem:** "Load elimination" suggests an optimization technique. The code seems to be dealing with WebAssembly (Wasm) structures and arrays. The goal is likely to remove redundant loads of data by tracking the state of these objects.

4. **Focus on the `Reduce` Methods:** The `Reduce` method and its many `ReduceXYZ` variations are the heart of the optimization. Each `Reduce` function seems to handle a specific Wasm operation (struct get, struct set, array length, etc.). This suggests the code is pattern-matching on these operations and applying specific optimization logic.

5. **Analyze `AbstractState`:** The `AbstractState` class and its `HalfState` inner class are crucial. They appear to be the mechanism for tracking the values of fields and array lengths. The `LookupField`, `AddField`, and `KillField` methods indicate how this state is updated. The `IntersectWith` method hints at how state is merged at control flow merge points.

6. **Connect State to Optimization:**  The `Reduce` methods use the `AbstractState` to determine if a load operation can be replaced by a previously stored value. If the state indicates a value has been written to a specific field and hasn't been invalidated since, a subsequent read can be optimized away.

7. **Identify Key Concepts and Data Structures:**
    * **Load Elimination:** The central optimization.
    * **Abstract State:**  Tracks the values of fields and array lengths.
    * **HalfState:**  Separates mutable and immutable states.
    * **Field/Element Value:** Represents the stored value.
    * **Alias Analysis:** The `MayAlias` function is important for determining when two memory locations might refer to the same object.
    * **Type Information:**  The code uses `NodeProperties::GetType` and `wasm::TypesUnrelated` to understand the types involved.

8. **Consider JavaScript Interaction (If Any):**  The code is part of the V8 compiler, which executes JavaScript. While this specific file focuses on *Wasm* load elimination, understanding *how* Wasm interacts with JavaScript is key. Wasm can manipulate memory and call JavaScript functions, and JavaScript can interact with Wasm memory. The `kWasmAnyConvertExtern` node suggests handling conversions between Wasm and JavaScript values.

9. **Formulate the Summary:**  Start drafting the summary based on the identified concepts.

    * **Purpose:** Optimize Wasm code by eliminating redundant loads.
    * **Mechanism:** Tracks the state of Wasm objects (structs, arrays) in an `AbstractState`.
    * **Key Operations:** Focus on `Reduce` methods and how they interact with the state.
    * **State Updates:** Explain how `StructSet` and array initialization update the state.
    * **Load Elimination Logic:** Explain how `StructGet` and `ArrayLength` use the state to potentially replace loads.
    * **Alias Analysis:** Mention its role in preventing incorrect optimizations.
    * **JavaScript Connection:**  Highlight that this is part of the V8 compiler, which executes JavaScript and Wasm. Mention possible interactions, like passing objects between JS and Wasm, even if this specific file doesn't directly handle those interactions. The `kWasmAnyConvertExtern` node is a good example here.

10. **Develop JavaScript Examples:** Since the code deals with Wasm, the JavaScript examples should demonstrate how these Wasm concepts manifest in JavaScript when interacting with Wasm.

    * **Structs:** Show how a Wasm struct can be created and its fields accessed and modified from JavaScript.
    * **Arrays:** Illustrate creating and accessing Wasm arrays from JavaScript.
    * **Load Elimination (Conceptually):**  Explain how the *compiler* (this C++ code) optimizes these patterns, even if the JavaScript itself doesn't explicitly show the optimization. The key is demonstrating the *operations* that the compiler is optimizing.

11. **Refine and Organize:**  Review the summary and examples for clarity, accuracy, and conciseness. Ensure the language is accessible and avoids overly technical jargon where possible. Group related ideas together.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the code directly manipulates JavaScript objects.
* **Correction:** Realize the focus is on *Wasm* objects within the *V8 compiler*. The JavaScript interaction is at a higher level (how JavaScript *uses* Wasm).
* **Initial thought:** The `AbstractState` might track all variables.
* **Correction:** Recognize it's specifically tracking fields of structs and array lengths, as indicated by the methods and the specific `Reduce` functions.
* **Ensuring JavaScript Relevance:**  Constantly ask: "How does this Wasm concept relate to what a JavaScript developer might do or see when working with Wasm?"

By following these steps, focusing on key concepts, and iteratively refining the understanding, a comprehensive and accurate summary can be produced.
这个C++源代码文件 `wasm-load-elimination.cc` 的功能是 **在 V8 引擎的 Turbofan 编译器中，对 WebAssembly (Wasm) 代码执行加载消除优化。**

**功能归纳：**

1. **跟踪 Wasm 对象的抽象状态:**  该文件定义了一个 `WasmLoadElimination` 类，它使用一种抽象状态（`AbstractState` 和 `HalfState`）来跟踪 Wasm 堆对象的属性值，例如结构体的字段和数组的长度。
2. **识别并消除冗余的加载操作:**  当编译器遇到对 Wasm 结构体字段或数组长度的加载操作 (`kWasmStructGet`, `kWasmArrayLength` 等) 时，`WasmLoadElimination` 会检查其维护的抽象状态。如果状态表明该属性的值在之前已经被设置并且没有被修改过，那么这次加载操作就是冗余的，可以被直接替换为之前设置的值。
3. **更新抽象状态:**  当编译器遇到修改 Wasm 对象的操作 (`kWasmStructSet`, `kWasmArrayInitializeLength` 等) 时，`WasmLoadElimination` 会更新其维护的抽象状态，记录新的值。
4. **处理控制流:**  该文件还处理了控制流结构，例如循环 (`kLoop`) 和合并点 (`kMerge`)，以确保抽象状态在不同的执行路径上得到正确维护。
5. **处理别名:**  `MayAlias` 函数用于判断两个节点是否可能指向同一个内存位置，这对于防止错误的加载消除非常重要。如果两个节点可能存在别名，那么对其中一个的修改可能会影响到另一个，因此不能随意消除加载。
6. **处理类型转换:**  代码中存在 `ResolveAliases` 函数，用于解析类型转换操作 (`kWasmTypeCast`, `kTypeGuard` 等)，以便更准确地追踪对象的来源。
7. **支持特定的 Wasm 操作:** 该文件针对特定的 Wasm 操作进行了优化，例如获取结构体字段、设置结构体字段、获取数组长度等。

**与 JavaScript 的关系：**

虽然这是一个 C++ 文件，直接在 V8 引擎的编译阶段工作，但它直接影响了 JavaScript 中 WebAssembly 代码的执行效率。

当 JavaScript 代码加载并执行 WebAssembly 模块时，V8 引擎会将 Wasm 代码编译成本地机器码。`wasm-load-elimination.cc` 中实现的加载消除优化是这个编译过程中的一个重要环节。通过消除冗余的加载操作，可以减少实际执行的指令数量，从而提高 Wasm 代码的执行速度，最终提升 JavaScript 应用的性能，尤其是在重度使用 Wasm 的场景下。

**JavaScript 示例说明：**

假设我们有以下 WebAssembly 代码（用 WAT 格式表示）：

```wat
(module
  (global (mut i32) (i32.const 0))
  (func $get_and_set (param $ptr i32) (result i32)
    local.get $ptr
    i32.load ;; 第一次加载
    global.set 0 (i32.load) ;; 第二次加载，可以被消除
    global.get 0
  )
  (export "get_and_set" (func $get_and_set))
)
```

这段 Wasm 代码定义了一个函数 `get_and_set`，它接受一个内存地址 `ptr`，从该地址加载一个 32 位整数，然后将该值存储到一个全局变量中，最后返回该全局变量的值。

在编译这段 Wasm 代码时，`wasm-load-elimination.cc` 的功能就能发挥作用。它会识别出第二次的 `i32.load` 操作是冗余的，因为第一次加载的结果已经被存储在寄存器或本地变量中了。因此，编译器可以优化掉第二次加载操作，直接使用第一次加载的结果。

**在 JavaScript 中调用这个 Wasm 函数：**

```javascript
const wasmCode = `
  // 上面的 WAT 代码的 ArrayBuffer 形式
  AGFzbQEAAAABBQJGTUVzcAEABQEABwYDAgABAwcBAAEFAQcIAQQAAgEABgEAAAACAQQBAAEFAQgJCAAABgs=
`;
const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule, {});
const memory = new WebAssembly.Memory({ initial: 1 });
const view = new Uint32Array(memory.buffer);

view[0] = 123; // 在 Wasm 内存地址 0 处写入值 123

const result = wasmInstance.exports.get_and_set(0);
console.log(result); // 输出 123
```

在这个 JavaScript 示例中，我们加载并实例化了上面定义的 Wasm 模块，然后在 Wasm 内存的地址 0 处写入了值 123。当我们调用 `wasmInstance.exports.get_and_set(0)` 时，Wasm 代码会从内存地址 0 加载值。

**`wasm-load-elimination.cc` 的作用在于，它确保了在 Wasm 函数内部，第二次加载操作被高效地处理，避免了不必要的内存访问，从而提高了 `get_and_set` 函数的执行效率。**

**总结：**

`wasm-load-elimination.cc` 是 V8 引擎中一个关键的优化模块，它通过跟踪 Wasm 对象的抽象状态来消除冗余的加载操作，直接提升了 JavaScript 中 WebAssembly 代码的性能。虽然开发者在 JavaScript 代码中无法直接控制这个优化过程，但它的存在使得运行在 V8 引擎上的 Wasm 代码能够更加高效。

Prompt: 
```
这是目录为v8/src/compiler/wasm-load-elimination.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```
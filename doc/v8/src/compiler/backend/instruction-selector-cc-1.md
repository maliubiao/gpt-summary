Response:
The user wants a summary of the functionality of the provided C++ code snippet from V8's `instruction-selector.cc`. Specifically, they're asking for:

1. **Overall Function:** What does this code do?
2. **Torque Check:** Does the `.cc` extension mean it's *not* Torque?
3. **JavaScript Relevance:** Does it relate to JavaScript, and if so, how? Provide an example.
4. **Logic Reasoning:** Are there code sections that perform logical inference? Give example inputs and outputs.
5. **Common Errors:** Does it relate to potential programming mistakes users might make?  Provide examples.
6. **Part Identification:** This is part 2 of 8; what is the specific function of this part?

**Plan:**

1. **Analyze the code:** Focus on the class and template functions defined in the snippet:
    - `TurboshaftStateObjectDeduplicator`: Seems to handle unique identification of objects, possibly for optimization or deoptimization.
    - `AddOperandToStateValueDescriptor`: Appears to process and add information about values at specific points in the code execution (state).
    - `CachedStateValues` and `CachedStateValuesBuilder`:  Suggest caching mechanisms for state values to improve performance.
    - `AddInputsToFrameStateDescriptor`:  Looks like it gathers information about the current execution state (frame state).
    - `EmitWithContinuation`:  Handles emitting instructions with associated continuation information (for control flow, deoptimization, etc.).
    - `AppendDeoptimizeArguments`:  Specifically for adding arguments needed during deoptimization.
    - `CallBufferT` and `InitializeCallBuffer`: Structures for managing the arguments and outputs of function calls.

2. **Address each point:**
    - **Functionality:**  This part is responsible for generating low-level instructions and managing the data needed for deoptimization, particularly focusing on the state of the program at specific points.
    - **Torque:**  `.cc` means it's C++, not Torque.
    - **JavaScript Relevance:** This code is crucial for the execution of JavaScript. The frame state represents the variables and execution context of a JavaScript function. Deoptimization happens when the compiler makes assumptions that later turn out to be false, and it needs to revert to a less optimized state, which directly impacts JavaScript execution. A simple example involves function calls and variable access.
    - **Logic Reasoning:** The `GetObjectId` and `InsertObject` methods in `TurboshaftStateObjectDeduplicator` perform a simple form of logical reasoning: checking if an object has already been encountered. The `AddOperandToStateValueDescriptor` function has conditional logic based on the opcode of the input node.
    - **Common Errors:**  The code handles deoptimization, which often stems from incorrect assumptions made by the compiler due to dynamic JavaScript behavior. A common error is relying on the type of a variable without proper checks, leading to unexpected behavior and potential deoptimization.
    - **Part Identification:** This part specifically deals with managing the state of the program, particularly for deoptimization and function calls. It builds the necessary data structures and emits instructions that reflect the program's state.

3. **Construct the answer:**  Organize the findings into clear points addressing each of the user's questions.这是 v8 源代码文件 `v8/src/compiler/backend/instruction-selector.cc` 的一部分，主要负责在 V8 的编译器后端，将**中间表示（Intermediate Representation, IR）**的节点转换成**目标机器指令**。更具体地说，这部分代码专注于处理与**程序状态（Frame State）**相关的操作，尤其是在需要进行**反优化（Deoptimization）**时如何收集和描述程序的状态。

**功能归纳:**

这部分代码的主要功能是：

1. **状态对象去重（State Object Deduplication）：**  `boshaftStateObjectDeduplicator` 和 `TurboshaftStateObjectDeduplicator` 类用于跟踪和识别在程序状态描述中重复出现的状态对象。这有助于减少状态描述的大小，提高效率。

2. **构建状态值描述（State Value Descriptor）：**  `AddOperandToStateValueDescriptor` 函数负责将 IR 节点的信息添加到 `StateValueList` 中，描述程序执行过程中的变量、参数、局部变量等值。它会根据不同的 IR 节点类型（例如 `kArgumentsElementsState`, `kArgumentsLengthState`, `kObjectState`, `kTypedObjectState` 等）采取不同的处理方式。

3. **缓存状态值（Caching State Values）：**  `CachedStateValues` 和 `CachedStateValuesBuilder` 结构体和类实现了状态值的缓存机制。由于相同的程序状态可能会在不同的 IR 节点中被引用，缓存可以避免重复计算，提高编译速度。

4. **构建帧状态描述（Frame State Descriptor）：** `AddInputsToFrameStateDescriptor` 函数负责收集当前函数调用栈帧的状态信息，包括参数、局部变量、栈上的值等。这些信息对于反优化至关重要，因为反优化需要恢复到之前的程序状态。

5. **生成带延续信息的指令（Emit With Continuation）：** `EmitWithContinuation` 函数用于生成带有控制流延续信息的机器指令。这在处理分支、循环、异常等控制流结构时非常重要，同时也用于处理反优化的情况。

6. **添加反优化参数（Append Deoptimize Arguments）：** `AppendDeoptimizeArguments` 函数专门负责在需要反优化时，将必要的参数（例如反优化原因、节点 ID、帧状态信息）添加到指令序列中。

7. **管理函数调用（Call Buffer）：** `CallBufferT` 结构体和 `InitializeCallBuffer` 函数用于辅助处理函数调用指令的生成。它们负责收集函数调用的参数、返回值信息，并根据调用约定进行处理。

**关于文件扩展名和 Torque:**

* `v8/src/compiler/backend/instruction-selector.cc` 以 `.cc` 结尾，这表明它是 **C++ 源代码文件**，而不是 V8 Torque 源代码。V8 Torque 文件的扩展名通常是 `.tq`。

**与 JavaScript 的关系:**

`instruction-selector.cc` 中处理的逻辑与 JavaScript 的执行密切相关。当 JavaScript 代码被 V8 编译时，`instruction-selector.cc` 的功能是将高级的 IR 转换成可以在目标机器上执行的指令。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let x = 5;
let y = "hello";
let result = add(x, y);
```

在编译这段代码时，如果 V8 的优化器假设 `a` 和 `b` 都是数字，并生成了高效的数字加法指令。但是，在实际执行时，`y` 是一个字符串。这时，V8 就需要进行反优化，回到一个更通用的、能处理不同类型加法的状态。

`instruction-selector.cc` 中的代码就参与了这个反优化的过程：

* **状态对象去重：** 可能会跟踪变量 `x` 和 `y` 的值。
* **构建状态值描述：** 会记录 `a` 的值（可能是 5）和 `b` 的值（"hello"）。
* **构建帧状态描述：** 会记录调用 `add` 函数时的上下文，包括局部变量 `a` 和 `b`。
* **添加反优化参数：** 会生成包含反优化原因（例如，类型不匹配）和当前状态信息的指令，以便 V8 能够安全地回退到未优化的代码执行。

**代码逻辑推理示例:**

`boshaftStateObjectDeduplicator::GetObjectId` 方法进行简单的逻辑推理：

**假设输入:** `object_ids_` 包含 `{10, 20, 30}`，调用 `GetObjectId(20)`。
**输出:** `1` (因为 20 是 `object_ids_` 中的第二个元素，索引为 1)。

**假设输入:** `object_ids_` 包含 `{10, 20, 30}`，调用 `GetObjectId(40)`。
**输出:** `kNotDuplicated` (因为 40 不在 `object_ids_` 中)。

`AddOperandToStateValueDescriptor` 中的 `switch` 语句根据 `input->opcode()` 的值进行不同的处理，这也是一种逻辑推理。例如，如果 `input->opcode()` 是 `IrOpcode::kArgumentsElementsState`，它会将 `ArgumentsStateTypeOf(input->op())` 推入 `values`。

**用户常见的编程错误示例:**

这部分代码与用户常见的编程错误（尤其是与类型相关的错误）有间接联系。例如，在动态类型的 JavaScript 中，类型不确定性可能导致优化器做出错误的假设，最终触发反优化。

**示例:**

```javascript
function maybeAdd(a, b) {
  if (Math.random() > 0.5) {
    return a + b; // 假设 a 和 b 是数字
  } else {
    return a + String(b); // 实际上 b 可能是其他类型
  }
}

let result1 = maybeAdd(1, 2); // 第一次调用可能都假设为数字
let result2 = maybeAdd(3, "hello"); // 第二次调用时，类型不匹配，可能触发反优化
```

在这个例子中，如果 V8 的优化器在第一次调用时假设 `a` 和 `b` 总是数字，并生成了优化的数字加法指令。当第二次调用时，`b` 是一个字符串，导致类型不匹配，就需要进行反优化。`instruction-selector.cc` 中的代码会参与记录此时的程序状态，以便安全地回退到未优化的版本。

**这是第 2 部分，共 8 部分的功能归纳:**

考虑到这是 `instruction-selector.cc` 的一部分，并且是第 2 部分，这部分代码的主要职责可能集中在：

* **处理程序状态相关的 IR 节点。**
* **构建用于反优化的关键数据结构（例如，状态值描述和帧状态描述）。**
* **生成与状态管理和反优化流程相关的机器指令。**
* **实现一些优化策略，例如状态对象的去重和状态值的缓存。**

总而言之，这部分代码在 V8 编译器的后端扮演着至关重要的角色，它负责将高级的程序表示转换为底层的机器指令，并且特别关注在需要进行反优化时如何安全地捕获和描述程序的执行状态。

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction-selector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction-selector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能

"""
boshaftStateObjectDeduplicator {
 public:
  explicit TurboshaftStateObjectDeduplicator(Zone* zone) : object_ids_(zone) {}
  static constexpr uint32_t kArgumentsElementsDummy =
      std::numeric_limits<uint32_t>::max();
  static constexpr size_t kNotDuplicated = std::numeric_limits<size_t>::max();

  size_t GetObjectId(uint32_t object) {
    for (size_t i = 0; i < object_ids_.size(); ++i) {
      if (object_ids_[i] == object) return i;
    }
    return kNotDuplicated;
  }

  size_t InsertObject(uint32_t object) {
    object_ids_.push_back(object);
    return object_ids_.size() - 1;
  }

  void InsertDummyForArgumentsElements() {
    object_ids_.push_back(kArgumentsElementsDummy);
  }

  size_t size() const { return object_ids_.size(); }

 private:
  ZoneVector<uint32_t> object_ids_;
};

// Returns the number of instruction operands added to inputs.
template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddOperandToStateValueDescriptor(
    StateValueList* values, InstructionOperandVector* inputs,
    OperandGeneratorT<TurbofanAdapter>* g,
    StateObjectDeduplicator* deduplicator, Node* input, MachineType type,
    FrameStateInputKind kind, Zone* zone) {
  DCHECK_NOT_NULL(input);
  switch (input->opcode()) {
    case IrOpcode::kArgumentsElementsState: {
      values->PushArgumentsElements(ArgumentsStateTypeOf(input->op()));
      // The elements backing store of an arguments object participates in the
      // duplicate object counting, but can itself never appear duplicated.
      DCHECK_EQ(StateObjectDeduplicator::kNotDuplicated,
                deduplicator->GetObjectId(input));
      deduplicator->InsertObject(input);
      return 0;
    }
    case IrOpcode::kArgumentsLengthState: {
      values->PushArgumentsLength();
      return 0;
    }
    case IrOpcode::kObjectState:
      UNREACHABLE();
    case IrOpcode::kTypedObjectState:
    case IrOpcode::kObjectId: {
      size_t id = deduplicator->GetObjectId(input);
      if (id == StateObjectDeduplicator::kNotDuplicated) {
        DCHECK_EQ(IrOpcode::kTypedObjectState, input->opcode());
        size_t entries = 0;
        id = deduplicator->InsertObject(input);
        StateValueList* nested = values->PushRecursiveField(zone, id);
        int const input_count = input->op()->ValueInputCount();
        ZoneVector<MachineType> const* types = MachineTypesOf(input->op());
        for (int i = 0; i < input_count; ++i) {
          entries += AddOperandToStateValueDescriptor(
              nested, inputs, g, deduplicator, input->InputAt(i), types->at(i),
              kind, zone);
        }
        return entries;
      } else {
        // Deoptimizer counts duplicate objects for the running id, so we have
        // to push the input again.
        deduplicator->InsertObject(input);
        values->PushDuplicate(id);
        return 0;
      }
    }
    default: {
      InstructionOperand op =
          OperandForDeopt(isolate(), g, input, kind, type.representation());
      if (op.kind() == InstructionOperand::INVALID) {
        // Invalid operand means the value is impossible or optimized-out.
        values->PushOptimizedOut();
        return 0;
      } else {
        inputs->push_back(op);
        values->PushPlain(type);
        return 1;
      }
    }
  }
}

template <typename Adapter>
struct InstructionSelectorT<Adapter>::CachedStateValues : public ZoneObject {
 public:
  CachedStateValues(Zone* zone, StateValueList* values, size_t values_start,
                    InstructionOperandVector* inputs, size_t inputs_start)
      : inputs_(inputs->begin() + inputs_start, inputs->end(), zone),
        values_(values->MakeSlice(values_start)) {}

  size_t Emit(InstructionOperandVector* inputs, StateValueList* values) {
    inputs->insert(inputs->end(), inputs_.begin(), inputs_.end());
    values->PushCachedSlice(values_);
    return inputs_.size();
  }

 private:
  InstructionOperandVector inputs_;
  StateValueList::Slice values_;
};

template <typename Adapter>
class InstructionSelectorT<Adapter>::CachedStateValuesBuilder {
 public:
  explicit CachedStateValuesBuilder(StateValueList* values,
                                    InstructionOperandVector* inputs,
                                    StateObjectDeduplicator* deduplicator)
      : values_(values),
        inputs_(inputs),
        deduplicator_(deduplicator),
        values_start_(values->size()),
        nested_start_(values->nested_count()),
        inputs_start_(inputs->size()),
        deduplicator_start_(deduplicator->size()) {}

  // We can only build a CachedStateValues for a StateValue if it didn't update
  // any of the ids in the deduplicator.
  bool CanCache() const { return deduplicator_->size() == deduplicator_start_; }

  InstructionSelectorT<Adapter>::CachedStateValues* Build(Zone* zone) {
    DCHECK(CanCache());
    DCHECK(values_->nested_count() == nested_start_);
    return zone->New<InstructionSelectorT<Adapter>::CachedStateValues>(
        zone, values_, values_start_, inputs_, inputs_start_);
  }

 private:
  StateValueList* values_;
  InstructionOperandVector* inputs_;
  StateObjectDeduplicator* deduplicator_;
  size_t values_start_;
  size_t nested_start_;
  size_t inputs_start_;
  size_t deduplicator_start_;
};

template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddInputsToFrameStateDescriptor(
    StateValueList* values, InstructionOperandVector* inputs,
    OperandGeneratorT<TurbofanAdapter>* g,
    StateObjectDeduplicator* deduplicator, node_t node,
    FrameStateInputKind kind, Zone* zone) {
  // StateValues are often shared across different nodes, and processing them
  // is expensive, so cache the result of processing a StateValue so that we
  // can quickly copy the result if we see it again.
  FrameStateInput key(node, kind);
  auto cache_entry = state_values_cache_.find(key);
  if (cache_entry != state_values_cache_.end()) {
    // Entry found in cache, emit cached version.
    return cache_entry->second->Emit(inputs, values);
  } else {
    // Not found in cache, generate and then store in cache if possible.
    size_t entries = 0;
    CachedStateValuesBuilder cache_builder(values, inputs, deduplicator);
    StateValuesAccess::iterator it = StateValuesAccess(node).begin();
    // Take advantage of sparse nature of StateValuesAccess to skip over
    // multiple empty nodes at once pushing repeated OptimizedOuts all in one
    // go.
    while (!it.done()) {
      values->PushOptimizedOut(it.AdvanceTillNotEmpty());
      if (it.done()) break;
      StateValuesAccess::TypedNode input_node = *it;
      entries += AddOperandToStateValueDescriptor(values, inputs, g,
                                                  deduplicator, input_node.node,
                                                  input_node.type, kind, zone);
      ++it;
    }
    if (cache_builder.CanCache()) {
      // Use this->zone() to build the cache entry in the instruction
      // selector's zone rather than the more long-lived instruction zone.
      state_values_cache_.emplace(key, cache_builder.Build(this->zone()));
    }
    return entries;
  }
}

size_t AddOperandToStateValueDescriptor(
    InstructionSelectorT<TurboshaftAdapter>* selector, StateValueList* values,
    InstructionOperandVector* inputs, OperandGeneratorT<TurboshaftAdapter>* g,
    TurboshaftStateObjectDeduplicator* deduplicator,
    turboshaft::FrameStateData::Iterator* it, FrameStateInputKind kind,
    Zone* zone) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  switch (it->current_instr()) {
    case FrameStateData::Instr::kUnusedRegister:
      it->ConsumeUnusedRegister();
      values->PushOptimizedOut();
      return 0;
    case FrameStateData::Instr::kInput: {
      MachineType type;
      OpIndex input;
      it->ConsumeInput(&type, &input);
      const Operation& op = selector->Get(input);
      if (op.outputs_rep()[0] == RegisterRepresentation::Word64() &&
          type.representation() == MachineRepresentation::kWord32) {
        // 64 to 32-bit conversion is implicit in turboshaft.
        // TODO(nicohartmann@): Fix this once we have explicit truncations.
        UNIMPLEMENTED();
      }
      InstructionOperand instr_op = OperandForDeopt(
          selector->isolate(), g, input, kind, type.representation());
      if (instr_op.kind() == InstructionOperand::INVALID) {
        // Invalid operand means the value is impossible or optimized-out.
        values->PushOptimizedOut();
        return 0;
      } else {
        inputs->push_back(instr_op);
        values->PushPlain(type);
        return 1;
      }
    }
    case FrameStateData::Instr::kDematerializedObject: {
      uint32_t obj_id;
      uint32_t field_count;
      it->ConsumeDematerializedObject(&obj_id, &field_count);
      size_t id = deduplicator->GetObjectId(obj_id);
      if (id == TurboshaftStateObjectDeduplicator::kNotDuplicated) {
        id = deduplicator->InsertObject(obj_id);
        size_t entries = 0;
        StateValueList* nested = values->PushRecursiveField(zone, id);
        for (uint32_t i = 0; i < field_count; ++i) {
          entries += AddOperandToStateValueDescriptor(
              selector, nested, inputs, g, deduplicator, it, kind, zone);
        }
        return entries;
      } else {
        // Deoptimizer counts duplicate objects for the running id, so we have
        // to push the input again.
        deduplicator->InsertObject(obj_id);
        values->PushDuplicate(id);
        return 0;
      }
    }
    case FrameStateData::Instr::kDematerializedObjectReference: {
      uint32_t obj_id;
      it->ConsumeDematerializedObjectReference(&obj_id);
      size_t id = deduplicator->GetObjectId(obj_id);
      DCHECK_NE(id, TurboshaftStateObjectDeduplicator::kNotDuplicated);
      // Deoptimizer counts duplicate objects for the running id, so we have
      // to push the input again.
      deduplicator->InsertObject(obj_id);
      values->PushDuplicate(id);
      return 0;
    }
    case FrameStateData::Instr::kDematerializedStringConcat: {
      DCHECK(v8_flags.turboshaft_string_concat_escape_analysis);
      it->ConsumeDematerializedStringConcat();
      StateValueList* nested = values->PushStringConcat(zone);
      static constexpr int kLeft = 1, kRight = 1;
      static constexpr int kInputCount = kLeft + kRight;
      size_t entries = 0;
      for (uint32_t i = 0; i < kInputCount; i++) {
        entries += AddOperandToStateValueDescriptor(
            selector, nested, inputs, g, deduplicator, it, kind, zone);
      }
      return entries;
    }
    case FrameStateData::Instr::kArgumentsElements: {
      CreateArgumentsType type;
      it->ConsumeArgumentsElements(&type);
      values->PushArgumentsElements(type);
      // The elements backing store of an arguments object participates in the
      // duplicate object counting, but can itself never appear duplicated.
      deduplicator->InsertDummyForArgumentsElements();
      return 0;
    }
    case FrameStateData::Instr::kArgumentsLength:
      it->ConsumeArgumentsLength();
      values->PushArgumentsLength();
      return 0;
    case FrameStateData::Instr::kRestLength:
      it->ConsumeRestLength();
      values->PushRestLength();
      return 0;
  }
  UNREACHABLE();
}

// Returns the number of instruction operands added to inputs.
template <>
size_t InstructionSelectorT<TurboshaftAdapter>::AddInputsToFrameStateDescriptor(
    FrameStateDescriptor* descriptor, node_t state_node, OperandGenerator* g,
    TurboshaftStateObjectDeduplicator* deduplicator,
    InstructionOperandVector* inputs, FrameStateInputKind kind, Zone* zone) {
  turboshaft::FrameStateOp& state =
      schedule()->Get(state_node).template Cast<turboshaft::FrameStateOp>();
  const FrameStateInfo& info = state.data->frame_state_info;
  USE(info);
  turboshaft::FrameStateData::Iterator it =
      state.data->iterator(state.state_values());

  size_t entries = 0;
  size_t initial_size = inputs->size();
  USE(initial_size);  // initial_size is only used for debug.
  if (descriptor->outer_state()) {
    entries += AddInputsToFrameStateDescriptor(
        descriptor->outer_state(), state.parent_frame_state(), g, deduplicator,
        inputs, kind, zone);
  }

  DCHECK_EQ(descriptor->parameters_count(), info.parameter_count());
  DCHECK_EQ(descriptor->locals_count(), info.local_count());
  DCHECK_EQ(descriptor->stack_count(), info.stack_count());

  StateValueList* values_descriptor = descriptor->GetStateValueDescriptors();

  DCHECK_EQ(values_descriptor->size(), 0u);
  values_descriptor->ReserveSize(descriptor->GetSize());

  // Function
  if (descriptor->HasClosure()) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it,
        FrameStateInputKind::kStackSlot, zone);
  } else {
    // Advance the iterator either way.
    MachineType unused_type;
    turboshaft::OpIndex unused_input;
    it.ConsumeInput(&unused_type, &unused_input);
  }

  // Parameters
  for (size_t i = 0; i < descriptor->parameters_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  // Context
  if (descriptor->HasContext()) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it,
        FrameStateInputKind::kStackSlot, zone);
  } else {
    // Advance the iterator either way.
    MachineType unused_type;
    turboshaft::OpIndex unused_input;
    it.ConsumeInput(&unused_type, &unused_input);
  }

  // Locals
  for (size_t i = 0; i < descriptor->locals_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  // Stack
  for (size_t i = 0; i < descriptor->stack_count(); ++i) {
    entries += v8::internal::compiler::AddOperandToStateValueDescriptor(
        this, values_descriptor, inputs, g, deduplicator, &it, kind, zone);
  }

  DCHECK_EQ(initial_size + entries, inputs->size());
  return entries;
}

template <>
size_t InstructionSelectorT<TurbofanAdapter>::AddInputsToFrameStateDescriptor(
    FrameStateDescriptor* descriptor, node_t state_node, OperandGenerator* g,
    StateObjectDeduplicator* deduplicator, InstructionOperandVector* inputs,
    FrameStateInputKind kind, Zone* zone) {
  FrameState state{state_node};
  size_t entries = 0;
  size_t initial_size = inputs->size();
  USE(initial_size);  // initial_size is only used for debug.

  if (descriptor->outer_state()) {
    entries += AddInputsToFrameStateDescriptor(
        descriptor->outer_state(), FrameState{state.outer_frame_state()}, g,
        deduplicator, inputs, kind, zone);
  }

  Node* parameters = state.parameters();
  Node* locals = state.locals();
  Node* stack = state.stack();
  Node* context = state.context();
  Node* function = state.function();

  DCHECK_EQ(descriptor->parameters_count(),
            StateValuesAccess(parameters).size());
  DCHECK_EQ(descriptor->locals_count(), StateValuesAccess(locals).size());
  DCHECK_EQ(descriptor->stack_count(), StateValuesAccess(stack).size());

  StateValueList* values_descriptor = descriptor->GetStateValueDescriptors();

  DCHECK_EQ(values_descriptor->size(), 0u);
  values_descriptor->ReserveSize(descriptor->GetSize());

  if (descriptor->HasClosure()) {
    DCHECK_NOT_NULL(function);
    entries += AddOperandToStateValueDescriptor(
        values_descriptor, inputs, g, deduplicator, function,
        MachineType::AnyTagged(), FrameStateInputKind::kStackSlot, zone);
  }

  entries += AddInputsToFrameStateDescriptor(
      values_descriptor, inputs, g, deduplicator, parameters, kind, zone);

  if (descriptor->HasContext()) {
    DCHECK_NOT_NULL(context);
    entries += AddOperandToStateValueDescriptor(
        values_descriptor, inputs, g, deduplicator, context,
        MachineType::AnyTagged(), FrameStateInputKind::kStackSlot, zone);
  }

  entries += AddInputsToFrameStateDescriptor(values_descriptor, inputs, g,
                                             deduplicator, locals, kind, zone);

  entries += AddInputsToFrameStateDescriptor(values_descriptor, inputs, g,
                                             deduplicator, stack, kind, zone);
  DCHECK_EQ(initial_size + entries, inputs->size());
  return entries;
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, FlagsContinuation* cont) {
  return EmitWithContinuation(opcode, 0, nullptr, 1, &a, cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, InstructionOperand b,
    FlagsContinuation* cont) {
  InstructionOperand inputs[] = {a, b};
  return EmitWithContinuation(opcode, 0, nullptr, arraysize(inputs), inputs,
                              cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, InstructionOperand a, InstructionOperand b,
    InstructionOperand c, FlagsContinuation* cont) {
  InstructionOperand inputs[] = {a, b, c};
  return EmitWithContinuation(opcode, 0, nullptr, arraysize(inputs), inputs,
                              cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, size_t output_count, InstructionOperand* outputs,
    size_t input_count, InstructionOperand* inputs, FlagsContinuation* cont) {
  return EmitWithContinuation(opcode, output_count, outputs, input_count,
                              inputs, 0, nullptr, cont);
}

template <typename Adapter>
Instruction* InstructionSelectorT<Adapter>::EmitWithContinuation(
    InstructionCode opcode, size_t output_count, InstructionOperand* outputs,
    size_t input_count, InstructionOperand* inputs, size_t temp_count,
    InstructionOperand* temps, FlagsContinuation* cont) {
  OperandGenerator g(this);

  opcode = cont->Encode(opcode);

  continuation_inputs_.resize(0);
  for (size_t i = 0; i < input_count; i++) {
    continuation_inputs_.push_back(inputs[i]);
  }

  continuation_outputs_.resize(0);
  for (size_t i = 0; i < output_count; i++) {
    continuation_outputs_.push_back(outputs[i]);
  }

  continuation_temps_.resize(0);
  for (size_t i = 0; i < temp_count; i++) {
    continuation_temps_.push_back(temps[i]);
  }

  if (cont->IsBranch() || cont->IsConditionalBranch()) {
    continuation_inputs_.push_back(g.Label(cont->true_block()));
    continuation_inputs_.push_back(g.Label(cont->false_block()));
  } else if (cont->IsDeoptimize()) {
    int immediate_args_count = 0;
    opcode |= DeoptImmedArgsCountField::encode(immediate_args_count) |
              DeoptFrameStateOffsetField::encode(static_cast<int>(input_count));
    AppendDeoptimizeArguments(&continuation_inputs_, cont->reason(),
                              cont->node_id(), cont->feedback(),
                              cont->frame_state());
  } else if (cont->IsSet() || cont->IsConditionalSet()) {
    continuation_outputs_.push_back(g.DefineAsRegister(cont->result()));
  } else if (cont->IsSelect()) {
    // The {Select} should put one of two values into the output register,
    // depending on the result of the condition. The two result values are in
    // the last two input slots, the {false_value} in {input_count - 2}, and the
    // true_value in {input_count - 1}. The other inputs are used for the
    // condition.
    AddOutputToSelectContinuation(&g, static_cast<int>(input_count) - 2,
                                  cont->result());
  } else if (cont->IsTrap()) {
    int trap_id = static_cast<int>(cont->trap_id());
    continuation_inputs_.push_back(g.UseImmediate(trap_id));
  } else {
    DCHECK(cont->IsNone());
  }

  size_t const emit_inputs_size = continuation_inputs_.size();
  auto* emit_inputs =
      emit_inputs_size ? &continuation_inputs_.front() : nullptr;
  size_t const emit_outputs_size = continuation_outputs_.size();
  auto* emit_outputs =
      emit_outputs_size ? &continuation_outputs_.front() : nullptr;
  size_t const emit_temps_size = continuation_temps_.size();
  auto* emit_temps = emit_temps_size ? &continuation_temps_.front() : nullptr;
  return Emit(opcode, emit_outputs_size, emit_outputs, emit_inputs_size,
              emit_inputs, emit_temps_size, emit_temps);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::AppendDeoptimizeArguments(
    InstructionOperandVector* args, DeoptimizeReason reason, id_t node_id,
    FeedbackSource const& feedback, node_t frame_state, DeoptimizeKind kind) {
  OperandGenerator g(this);
  FrameStateDescriptor* const descriptor = GetFrameStateDescriptor(frame_state);
  int const state_id = sequence()->AddDeoptimizationEntry(
      descriptor, kind, reason, node_id, feedback);
  args->push_back(g.TempImmediate(state_id));
  StateObjectDeduplicator deduplicator(instruction_zone());
  AddInputsToFrameStateDescriptor(descriptor, frame_state, &g, &deduplicator,
                                  args, FrameStateInputKind::kAny,
                                  instruction_zone());
}

// An internal helper class for generating the operands to calls.
// TODO(bmeurer): Get rid of the CallBuffer business and make
// InstructionSelector::VisitCall platform independent instead.
template <typename Adapter>
struct CallBufferT {
  using PushParameter = PushParameterT<Adapter>;
  CallBufferT(Zone* zone, const CallDescriptor* call_descriptor,
              FrameStateDescriptor* frame_state)
      : descriptor(call_descriptor),
        frame_state_descriptor(frame_state),
        output_nodes(zone),
        outputs(zone),
        instruction_args(zone),
        pushed_nodes(zone) {
    output_nodes.reserve(call_descriptor->ReturnCount());
    outputs.reserve(call_descriptor->ReturnCount());
    pushed_nodes.reserve(input_count());
    instruction_args.reserve(input_count() + frame_state_value_count());
  }

  const CallDescriptor* descriptor;
  FrameStateDescriptor* frame_state_descriptor;
  ZoneVector<PushParameter> output_nodes;
  InstructionOperandVector outputs;
  InstructionOperandVector instruction_args;
  ZoneVector<PushParameter> pushed_nodes;

  size_t input_count() const { return descriptor->InputCount(); }

  size_t frame_state_count() const { return descriptor->FrameStateCount(); }

  size_t frame_state_value_count() const {
    return (frame_state_descriptor == nullptr)
               ? 0
               : (frame_state_descriptor->GetTotalSize() +
                  1);  // Include deopt id.
  }
};

// TODO(bmeurer): Get rid of the CallBuffer business and make
// InstructionSelector::VisitCall platform independent instead.
template <typename Adapter>
void InstructionSelectorT<Adapter>::InitializeCallBuffer(
    node_t node, CallBuffer* buffer, CallBufferFlags flags,
    int stack_param_delta) {
  OperandGenerator g(this);
  size_t ret_count = buffer->descriptor->ReturnCount();
  bool is_tail_call = (flags & kCallTail) != 0;
  auto call = this->call_view(node);
  DCHECK_LE(call.return_count(), ret_count);

  if (ret_count > 0) {
    // Collect the projections that represent multiple outputs from this call.
    if (ret_count == 1) {
      PushParameter result = {call, buffer->descriptor->GetReturnLocation(0)};
      buffer->output_nodes.push_back(result);
    } else {
      buffer->output_nodes.resize(ret_count);
      for (size_t i = 0; i < ret_count; ++i) {
        LinkageLocation location = buffer->descriptor->GetReturnLocation(i);
        buffer->output_nodes[i] = PushParameter({}, location);
      }
      if constexpr (Adapter::IsTurboshaft) {
        for (turboshaft::OpIndex call_use : turboshaft_uses(call)) {
          const turboshaft::Operation& use_op = this->Get(call_use);
          if (use_op.Is<turboshaft::DidntThrowOp>()) {
            for (turboshaft::OpIndex use : turboshaft_uses(call_use)) {
              DCHECK(this->is_projection(use));
              size_t index = this->projection_index_of(use);
              DCHECK_LT(index, buffer->output_nodes.size());
              DCHECK(!Adapter::valid(buffer->output_nodes[index].node));
              buffer->output_nodes[index].node = use;
            }
          } else {
            DCHECK(use_op.Is<turboshaft::CheckExceptionOp>());
          }
        }
      } else {
        for (Edge const edge : ((node_t)call)->use_edges()) {
          if (!NodeProperties::IsValueEdge(edge)) continue;
          Node* node = edge.from();
          DCHECK_EQ(IrOpcode::kProjection, node->opcode());
          size_t const index = ProjectionIndexOf(node->op());

          DCHECK_LT(index, buffer->output_nodes.size());
          DCHECK(!buffer->output_nodes[index].node);
          buffer->output_nodes[index].node = node;
        }
      }
      frame_->EnsureReturnSlots(
          static_cast<int>(buffer->descriptor->ReturnSlotCount()));
    }

    // Filter out the outputs that aren't live because no projection uses them.
    size_t outputs_needed_by_framestate =
        buffer->frame_state_descriptor == nullptr
            ? 0
            : buffer->frame_state_descriptor->state_combine()
                  .ConsumedOutputCount();
    for (size_t i = 0; i < buffer->output_nodes.size(); i++) {
      bool output_is_live = this->valid(buffer->output_nodes[i].node) ||
                            i < outputs_needed_by_framestate;
      if (output_is_live) {
        LinkageLocation location = buffer->output_nodes[i].location;
        MachineRepresentation rep = location.GetType().representation();

        node_t output = buffer->output_nodes[i].node;
        InstructionOperand op = !this->valid(output)
                                    ? g.TempLocation(location)
                                    : g.DefineAsLocation(output, location);
        MarkAsRepresentation(rep, op);

        if (!UnallocatedOperand::cast(op).HasFixedSlotPolicy()) {
          buffer->outputs.push_back(op);
          buffer->output_nodes[i].node = {};
        }
      }
    }
  }

  // The first argument is always the callee code.
  node_t callee = call.callee();
  bool call_code_immediate = (flags & kCallCodeImmediate) != 0;
  bool call_address_immediate = (flags & kCallAddressImmediate) != 0;
  bool call_use_fixed_target_reg = (flags & kCallFixedTargetRegister) != 0;
  switch (buffer->descriptor->kind()) {
    case CallDescriptor::kCallCodeObject:
      buffer->instruction_args.push_back(
          (call_code_immediate && this->IsHeapConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
    case CallDescriptor::kCallAddress:
      buffer->instruction_args.push_back(
          (call_address_immediate && this->IsExternalConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
#if V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallWasmCapiFunction:
    case CallDescriptor::kCallWasmFunction:
    case CallDescriptor::kCallWasmImportWrapper:
      buffer->instruction_args.push_back(
          (call_address_immediate && this->IsRelocatableWasmConstant(callee))
              ? g.UseImmediate(callee)
          : call_use_fixed_target_reg
              ? g.UseFixed(callee, kJavaScriptCallCodeStartRegister)
              : g.UseRegister(callee));
      break;
#endif  // V8_ENABLE_WEBASSEMBLY
    case CallDescriptor::kCallBuiltinPointer: {
      // The common case for builtin pointers is to have the target in a
      // register. If we have a constant, we use a register anyway to simplify
      // related code.
      LinkageLocation location = buffer->descriptor->GetInputLocation(0);
      bool location_is_fixed_register =
          location.IsRegister() && !location.IsAnyRegister();
      InstructionOperand op;
      // If earlier phases specified a particular register, don't override
      // their choice.
      if (location_is_fixed_register) {
        op = g.UseLocation(callee, location);
      } else if (call_use_fixed_target_reg) {
        op = g.UseFixed(callee, kJavaScriptCallCodeStartRegister);
      } else {
        op = g.UseRegister(callee);
      }
      buffer->instruction_args.push_back(op);
      break;
    }
    case CallDescriptor::kCallJSFunction:
      buffer->instruction_args.push_back(
          g.UseLocation(callee, buffer->descriptor->GetInputLocation(0)));
      break;
  }
  DCHECK_EQ(1u, buffer->instruction_args.size());

  // If the call needs a frame state, we insert the state information as
  // follows (n is the number of value inputs to the frame state):
  // arg 1               : deoptimization id.
  // arg 2 - arg (n + 2) : value inputs to the frame state.
  size_t frame_state_entries = 0;
  USE(frame_state_entries);  // frame_state_entries is only used for debug.
  if (buffer->frame_state_descriptor != nullptr) {
    node_t frame_state = call.frame_state();

    // If it was a syntactic tail call we need to drop the current frame and
    // all the frames on top of it that are either inlined extra arguments
    // or a tail caller frame.
    if (is_tail_call) {
      frame_state = this->parent_frame_state(frame_state);
      buffer->frame_state_descriptor =
          buffer->frame_state_descriptor->outer_state();
      while (buffer->frame_state_descriptor != nullptr &&
             buffer->frame_state_descriptor->type() ==
                 FrameStateType::kInlinedExtraArguments) {
        frame_state = this->parent_frame_state(frame_state);
        buffer->frame_state_descriptor =
            buffer->frame_state_descriptor->outer_state();
      }
    }

    int const state_id = sequence()->AddDeoptimizationEntry(
        buffer->frame_state_descriptor, DeoptimizeKind::kLazy,
        DeoptimizeReason::kUnknown, this->id(call), FeedbackSource());
    buffer->instruction_args.push_back(g.TempImmediate(state_id));

    StateObjectDeduplicator deduplicator(instruction_zone());

    frame_state_entries =
        1 + AddInputsToFrameStateDescriptor(
                buffer->frame_state_descriptor, frame_state, &g, &deduplicator,
                &buffer->instruction_args, FrameStateInputKind::kStackSlot,
                instruction_zone());

    DCHECK_EQ(1 + frame_state_entries, buffer->instruction_args.size());
  }

  size_t input_count = buffer->input_count();

  // Split the arguments into pushed_nodes and instruction_args. Pushed
  // arguments require an explicit push instruction before the call and do
  // not appear as arguments to the call. Everything else ends up
  // as an InstructionOperand argument to the call.
  auto arguments = call.arguments();
  auto iter(arguments.begin());
  size_t pushed_count = 0;
  for (size_t index = 1; index < input_count; ++iter, ++index) {
    DCHECK_NE(iter, arguments.end());

    LinkageLocation location = buffer->descriptor->GetInputLocation(index);
    if (is_tail_call) {
      location = LinkageLocation::ConvertToTailCallerLocation(
          location, stack_param_delta);
    }
    InstructionOperand op = g.UseLocation(*iter, location);
    UnallocatedOperand unallocated = UnallocatedOperand::cast(op);
    if (unallocated.HasFixedSlotPolicy() && !is_tail_call) {
      int stack_index = buffer->descriptor->GetStackIndexFromSlot(
          unallocated.fixed_slot_index());
      // This can insert empty slots before stack_index and will insert enough
      // slots after stack_index to store the parameter.
      if (static_cast<size_t>(stack_index) >= buffer->pushed_nodes.size()) {
        int num_slots = location.GetSizeInPointers();
        buffer->pushed_nodes.resize(stack_index + num_slots);
      }
      PushParameter param = {*iter, location};
      buffer->pushed_nodes[stack_index] = param;
      pushed_count++;
    } else {
      if (location.IsNullRegister()) {
        EmitMoveFPRToParam(&op, location);
      }
      buffer->instruction_args.push_back(op);
    }
  }
  DCHECK_EQ(input_count, buffer->instruction_args.size() + pushed_count -
                             frame_state_entries);
  USE(pushed_count);
  if (V8_TARGET_ARCH_STORES_RETURN_ADDRESS_ON_STACK && is_tail_call &&
      stack_param_delta != 0) {
    // For tail calls that change the size of their parameter list and keep
    // their return address on the stack, move the return address to just above
    // the parameters.
    LinkageLocation saved_return_location =
        LinkageLocat
"""


```
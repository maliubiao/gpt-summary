Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's compiler. The code is located in `v8/src/compiler/backend/instruction.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core class:** The code heavily revolves around the `InstructionSequence` class. This is the central entity to understand.

2. **Analyze `InstructionSequence`'s members and methods:**
    * **`instruction_blocks_` and `ao_blocks_`:** These seem related to the organization of instructions into blocks. The `ComputeAssemblyOrder` method explicitly deals with the order of these blocks for assembly. This suggests a control flow graph representation.
    * **`instructions_`:** This is a vector of `Instruction` pointers. Clearly, this stores the actual instructions.
    * **`source_positions_`:**  A map relating instructions to `SourcePosition`. This connects machine code back to the original JavaScript source.
    * **`constants_`, `immediates_`, `rpo_immediates_`:** These likely store different types of constant values used by the instructions.
    * **`next_virtual_register_`:**  Indicates a system for allocating virtual registers.
    * **`representations_` and `representation_mask_`:** These track the data types (representations) of virtual registers.
    * **`deoptimization_entries_`:**  Stores information related to deoptimization, a process of falling back from optimized code to interpreted code.
    * **Methods like `StartBlock`, `EndBlock`, `AddInstruction`, `GetRepresentation`, `MarkAsRepresentation`, `AddDeoptimizationEntry`, `GetSourcePosition`, `SetSourcePosition`:** These methods provide the interface for building and manipulating the instruction sequence.

3. **Analyze `ComputeAssemblyOrder`:** This method is responsible for ordering the instruction blocks for final code generation. It handles deferred blocks (likely for uncommon cases) and loop rotation optimization. This provides insight into how the compiler optimizes code layout.

4. **Analyze `FrameStateDescriptor`:**  This class appears to describe the state of the execution stack at certain points, particularly for deoptimization. It includes information about parameters, locals, stack, and the calling context. The various `FrameStateType` enums suggest different call frame scenarios.

5. **Infer the overall purpose:** Based on the classes and methods, the `instruction.cc` file is responsible for:
    * Representing a sequence of machine-level instructions.
    * Organizing these instructions into basic blocks.
    * Optimizing the layout of these blocks for performance (e.g., loop rotation).
    * Tracking the data types of values in virtual registers.
    * Storing information needed for deoptimization.
    * Linking machine code back to the source code.

6. **Address the specific questions:**
    * **Functionality:** Summarize the core responsibilities identified above.
    * **Torque:** The code snippet is in C++, not Torque.
    * **JavaScript relationship:**  The file is a core part of the *compiler*, which translates JavaScript. Give an example where the compiler needs to represent operations and potentially deoptimize.
    * **Code logic reasoning:** The `ComputeAssemblyOrder` method offers a clear example. Provide a scenario with a loop and how loop rotation would reorder the blocks.
    * **User programming errors:** Deoptimization is often triggered by type mismatches or assumptions the compiler makes that are violated at runtime. Provide a simple example.
    * **Overall function (Part 2):**  Synthesize the individual functionalities into a concise summary, focusing on the stages of compilation involved.

7. **Structure the answer:**  Organize the findings into clear sections addressing each part of the user's request. Use formatting (like bullet points) for readability.

By following this process, we can systematically analyze the code and provide a comprehensive and accurate summary of its functionality. The key is to identify the main data structures and the methods that operate on them, and then infer the purpose of these operations within the context of a JavaScript compiler.
这是V8源代码文件 `v8/src/compiler/backend/instruction.cc` 的第二部分，延续了第一部分的功能，主要负责表示和操作编译器后端生成的机器指令序列。

**归纳一下它的功能:**

`v8/src/compiler/backend/instruction.cc` 文件的核心功能是定义和实现了 `InstructionSequence` 类，该类用于表示一个基本块图的机器指令序列，并提供了一系列方法来构建、修改和查询这个指令序列。  它在编译器的后端流程中扮演着至关重要的角色，负责将中间表示（如Sea of Nodes图）转换为最终的机器代码。

**更具体地，第二部分的功能包括:**

1. **计算和管理指令块的汇编顺序 (`ComputeAssemblyOrder`)**:
   - 该方法决定了指令块在最终生成的汇编代码中的排列顺序。
   - 它区分了非延迟块和延迟块，优先排列非延迟块。
   - 它实现了循环旋转优化，将循环的尾部块移动到循环头部之前，以提高指令缓存的效率。
   - 它考虑了对齐需求，例如循环头部和跳转目标。

2. **重新计算汇编顺序 ( `RecomputeAssemblyOrderForTesting`)**:
   - 提供了一个用于测试的接口，可以清除已计算的汇编顺序并重新计算。

3. **`InstructionSequence` 类的构造函数**:
   - 初始化 `InstructionSequence` 对象的各种成员，包括指令块、源位置映射、常量、立即数、指令列表、虚拟寄存器计数器、引用映射、数据表示等。
   - 在构造时调用 `ComputeAssemblyOrder` 计算初始的汇编顺序。

4. **管理虚拟寄存器 (`NextVirtualRegister`)**:
   - 提供分配新的虚拟寄存器的方法。

5. **获取块的起始指令 (`GetBlockStart`)**:
   - 根据块的 RPO 编号获取该块的第一条指令。

6. **标记块的开始和结束 (`StartBlock`, `EndBlock`)**:
   - 在构建指令序列时，标记每个指令块的起始和结束位置。

7. **添加指令 (`AddInstruction`)**:
   - 将新的 `Instruction` 对象添加到指令列表中，并将其关联到当前的指令块。
   - 如果指令需要引用映射（例如，可能触发垃圾回收的操作），则创建并关联 `ReferenceMap` 对象。

8. **管理数据表示 (`GetRepresentation`, `MarkAsRepresentation`)**:
   - 跟踪每个虚拟寄存器中存储的数据的机器表示形式（例如，整数、浮点数、指针）。
   - `FilterRepresentation` 函数用于规范化某些表示形式。

9. **管理去优化入口 (`AddDeoptimizationEntry`, `GetDeoptimizationEntry`)**:
   - 存储去优化所需的信息，包括帧状态描述符、去优化类型、原因、节点 ID 和反馈信息。
   - 提供方法添加和获取去优化入口。

10. **获取指令的输入块的 RPO 编号 (`InputRpo`)**:
    - 如果指令的输入是立即数或常量，并且该常量代表一个块的 RPO 编号，则获取该 RPO 编号。

11. **管理源代码位置信息 (`GetSourcePosition`, `SetSourcePosition`)**:
    - 维护指令和源代码位置之间的映射关系，用于调试和生成源映射。

12. **打印指令序列和指令块 (`Print`, `PrintBlock`)**:
    - 提供调试输出指令序列和单个指令块的功能。

13. **测试相关的注册配置 (`RegisterConfigurationForTesting`, `SetRegisterConfigurationForTesting`)**:
    - 提供用于测试目的的注册配置管理接口。

14. **计算保守的帧大小 (`GetConservativeFrameSizeInBytes`, `GetTotalConservativeFrameSizeInBytes`)**:
    - 用于计算去优化时保守估计的栈帧大小，这对于正确的去优化至关重要。

15. **`FrameStateDescriptor` 类**:
    - 定义了描述函数调用帧状态的类，用于去优化和调试。
    - 包含了帧的类型、参数、局部变量、栈大小、关联的共享函数信息、字节码数组以及外部帧状态等信息.
    - 提供了获取帧高度、大小、总大小和帧计数的方法.

16. **`JSToWasmFrameStateDescriptor` 类**:
    - 针对 JavaScript 调用 WebAssembly 的场景，扩展了 `FrameStateDescriptor`，包含了 WebAssembly 函数的返回类型信息。

17. **流输出操作符重载 (`operator<<`)**:
    - 提供了将 `RpoNumber` 和 `InstructionSequence` 对象输出到流的功能，方便调试和查看指令序列的内容。
    - 提供了将 `StateValueKind` 输出到流的功能，用于调试帧状态描述符。
    - 提供了 `StateValueDescriptor::Print` 方法，用于输出帧状态值的描述信息。

**关于代码特性和常见错误:**

* **.tq 结尾:**  `v8/src/compiler/backend/instruction.cc` **不是**以 `.tq` 结尾，因此它不是 Torque 源代码。Torque 文件通常用于定义 V8 内部的内置函数和类型。

* **与 JavaScript 的关系:**  `InstructionSequence` 中生成的指令直接对应于执行 JavaScript 代码的机器指令。例如，一个简单的 JavaScript 加法操作可能在 `InstructionSequence` 中表示为一个加法指令。

   ```javascript
   function add(a, b) {
     return a + b;
   }
   ```

   在编译 `add` 函数时，`InstructionSequence` 可能会包含类似于 "load register1, a", "load register2, b", "add register3, register1, register2", "return register3" 这样的指令序列（具体的指令取决于目标架构）。

* **代码逻辑推理:**
   假设我们有一个包含简单循环的 JavaScript 代码：

   ```javascript
   let sum = 0;
   for (let i = 0; i < 10; i++) {
     sum += i;
   }
   return sum;
   ```

   `ComputeAssemblyOrder` 中的循环旋转优化可能会将循环体之后的“goto 循环头部”的指令块移动到循环头部之前。

   **假设输入：**
   - `instruction_blocks_` 包含一个循环头块 (IsLoopHeader 为 true) 和一个循环尾块，尾块以无条件跳转回循环头结束。

   **输出 (经过循环旋转):**
   - 循环尾块的 `ao_number` 会被提前分配，并且 `ao_blocks_` 中循环尾块会出现在循环头块之前。
   - 循环尾块的 `loop_header_alignment` 会被设置为 true。

* **用户常见的编程错误:**
   `InstructionSequence` 本身是 V8 内部的实现细节，用户无法直接操作。但是，用户编写的 JavaScript 代码中的错误会影响编译器生成的指令序列和去优化过程。

   **示例：类型不一致**

   ```javascript
   function multiply(a, b) {
     return a * b;
   }

   multiply(5, 10); // 正常执行
   multiply(5, "hello"); // 可能触发去优化
   ```

   如果编译器在优化 `multiply` 时假设 `b` 总是数字，当 `b` 变为字符串时，就会发生类型不匹配，可能需要进行去优化。`InstructionSequence` 中会包含用于处理这种去优化的信息 (`deoptimization_entries_`)。

总而言之，`v8/src/compiler/backend/instruction.cc` 的第二部分继续构建了 V8 编译器后端的核心数据结构，并实现了关键的指令排序和管理功能，为最终生成高效的机器代码奠定了基础。它与 JavaScript 代码的性能和正确执行息息相关，但对于普通的 JavaScript 开发者来说是不可见的底层实现。

Prompt: 
```
这是目录为v8/src/compiler/backend/instruction.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/instruction.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
  }
}

void InstructionSequence::ComputeAssemblyOrder() {
  int ao = 0;
  RpoNumber invalid = RpoNumber::Invalid();

  ao_blocks_ = zone()->AllocateArray<InstructionBlocks>(1);
  new (ao_blocks_) InstructionBlocks(zone());
  ao_blocks_->reserve(instruction_blocks_->size());

  // Place non-deferred blocks.
  for (InstructionBlock* const block : *instruction_blocks_) {
    DCHECK_NOT_NULL(block);
    if (block->IsDeferred()) continue;            // skip deferred blocks.
    if (block->ao_number() != invalid) continue;  // loop rotated.
    if (block->IsLoopHeader()) {
      bool header_align = true;
      if (v8_flags.turbo_loop_rotation) {
        // Perform loop rotation for non-deferred loops.
        InstructionBlock* loop_end =
            instruction_blocks_->at(block->loop_end().ToSize() - 1);
        if (loop_end->SuccessorCount() == 1 && /* ends with goto */
            loop_end != block /* not a degenerate infinite loop */) {
          // If the last block has an unconditional jump back to the header,
          // then move it to be in front of the header in the assembly order.
          DCHECK_EQ(block->rpo_number(), loop_end->successors()[0]);
          loop_end->set_ao_number(RpoNumber::FromInt(ao++));
          ao_blocks_->push_back(loop_end);
          // This block will be the new machine-level loop header, so align
          // this block instead of the loop header block.
          loop_end->set_loop_header_alignment(true);
          header_align = false;
        }
      }
      block->set_loop_header_alignment(header_align);
    }
    if (block->loop_header().IsValid() && block->IsSwitchTarget()) {
      block->set_code_target_alignment(true);
    }
    block->set_ao_number(RpoNumber::FromInt(ao++));
    ao_blocks_->push_back(block);
  }
  // Add all leftover (deferred) blocks.
  for (InstructionBlock* const block : *instruction_blocks_) {
    if (block->ao_number() == invalid) {
      block->set_ao_number(RpoNumber::FromInt(ao++));
      ao_blocks_->push_back(block);
    }
  }
  DCHECK_EQ(instruction_blocks_->size(), ao);
}

void InstructionSequence::RecomputeAssemblyOrderForTesting() {
  RpoNumber invalid = RpoNumber::Invalid();
  for (InstructionBlock* block : *instruction_blocks_) {
    block->set_ao_number(invalid);
  }
  ComputeAssemblyOrder();
}

InstructionSequence::InstructionSequence(Isolate* isolate,
                                         Zone* instruction_zone,
                                         InstructionBlocks* instruction_blocks)
    : isolate_(isolate),
      zone_(instruction_zone),
      instruction_blocks_(instruction_blocks),
      ao_blocks_(nullptr),
      // Pre-allocate the hash map of source positions based on the block count.
      // (The actual number of instructions is only known after instruction
      // selection, but should at least correlate with the block count.)
      source_positions_(zone(), instruction_blocks->size() * 2),
      // Avoid collisions for functions with 256 or less constant vregs.
      constants_(zone(), 256),
      immediates_(zone()),
      rpo_immediates_(instruction_blocks->size(), zone()),
      instructions_(zone()),
      next_virtual_register_(0),
      reference_maps_(zone()),
      representations_(zone()),
      representation_mask_(0),
      deoptimization_entries_(zone()),
      current_block_(nullptr) {
  ComputeAssemblyOrder();
}

int InstructionSequence::NextVirtualRegister() {
  int virtual_register = next_virtual_register_++;
  CHECK_NE(virtual_register, InstructionOperand::kInvalidVirtualRegister);
  return virtual_register;
}

Instruction* InstructionSequence::GetBlockStart(RpoNumber rpo) const {
  const InstructionBlock* block = InstructionBlockAt(rpo);
  return InstructionAt(block->code_start());
}

void InstructionSequence::StartBlock(RpoNumber rpo) {
  DCHECK_NULL(current_block_);
  current_block_ = InstructionBlockAt(rpo);
  int code_start = static_cast<int>(instructions_.size());
  current_block_->set_code_start(code_start);
}

void InstructionSequence::EndBlock(RpoNumber rpo) {
  int end = static_cast<int>(instructions_.size());
  DCHECK_EQ(current_block_->rpo_number(), rpo);
  CHECK(current_block_->code_start() >= 0 &&
        current_block_->code_start() < end);
  current_block_->set_code_end(end);
  current_block_ = nullptr;
}

int InstructionSequence::AddInstruction(Instruction* instr) {
  DCHECK_NOT_NULL(current_block_);
  int index = static_cast<int>(instructions_.size());
  instr->set_block(current_block_);
  instructions_.push_back(instr);
  if (instr->NeedsReferenceMap()) {
    DCHECK_NULL(instr->reference_map());
    ReferenceMap* reference_map = zone()->New<ReferenceMap>(zone());
    reference_map->set_instruction_position(index);
    instr->set_reference_map(reference_map);
    reference_maps_.push_back(reference_map);
  }
  return index;
}

static MachineRepresentation FilterRepresentation(MachineRepresentation rep) {
  switch (rep) {
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
    case MachineRepresentation::kWord16:
      return InstructionSequence::DefaultRepresentation();
    case MachineRepresentation::kFloat16:
      return MachineRepresentation::kFloat32;
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord64:
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
    case MachineRepresentation::kFloat32:
    case MachineRepresentation::kFloat64:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
    case MachineRepresentation::kProtectedPointer:
    case MachineRepresentation::kSandboxedPointer:
      return rep;
    case MachineRepresentation::kNone:
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kIndirectPointer:
      UNREACHABLE();
  }
}

MachineRepresentation InstructionSequence::GetRepresentation(
    int virtual_register) const {
  DCHECK_LE(0, virtual_register);
  DCHECK_LT(virtual_register, VirtualRegisterCount());
  if (virtual_register >= static_cast<int>(representations_.size())) {
    return DefaultRepresentation();
  }
  return representations_[virtual_register];
}

void InstructionSequence::MarkAsRepresentation(MachineRepresentation rep,
                                               int virtual_register) {
  DCHECK_LE(0, virtual_register);
  DCHECK_LT(virtual_register, VirtualRegisterCount());
  if (virtual_register >= static_cast<int>(representations_.size())) {
    representations_.resize(VirtualRegisterCount(), DefaultRepresentation());
  }
  rep = FilterRepresentation(rep);
  DCHECK_IMPLIES(representations_[virtual_register] != rep,
                 representations_[virtual_register] == DefaultRepresentation());
  representations_[virtual_register] = rep;
  representation_mask_ |= RepresentationBit(rep);
}

int InstructionSequence::AddDeoptimizationEntry(
    FrameStateDescriptor* descriptor, DeoptimizeKind kind,
    DeoptimizeReason reason, NodeId node_id, FeedbackSource const& feedback) {
  int deoptimization_id = static_cast<int>(deoptimization_entries_.size());
  deoptimization_entries_.push_back(
      DeoptimizationEntry(descriptor, kind, reason, node_id, feedback));
  return deoptimization_id;
}

DeoptimizationEntry const& InstructionSequence::GetDeoptimizationEntry(
    int state_id) {
  return deoptimization_entries_[state_id];
}

RpoNumber InstructionSequence::InputRpo(Instruction* instr, size_t index) {
  InstructionOperand* operand = instr->InputAt(index);
  Constant constant =
      operand->IsImmediate()
          ? GetImmediate(ImmediateOperand::cast(operand))
          : GetConstant(ConstantOperand::cast(operand)->virtual_register());
  return constant.ToRpoNumber();
}

bool InstructionSequence::GetSourcePosition(const Instruction* instr,
                                            SourcePosition* result) const {
  auto it = source_positions_.find(instr);
  if (it == source_positions_.end()) return false;
  *result = it->second;
  return true;
}

void InstructionSequence::SetSourcePosition(const Instruction* instr,
                                            SourcePosition value) {
  source_positions_.insert(std::make_pair(instr, value));
}

void InstructionSequence::Print() const {
  StdoutStream{} << *this << std::endl;
}

void InstructionSequence::PrintBlock(int block_id) const {
  RpoNumber rpo = RpoNumber::FromInt(block_id);
  const InstructionBlock* block = InstructionBlockAt(rpo);
  CHECK(block->rpo_number() == rpo);
  StdoutStream{} << PrintableInstructionBlock{block, this} << std::endl;
}

const RegisterConfiguration*
    InstructionSequence::registerConfigurationForTesting_ = nullptr;

const RegisterConfiguration*
InstructionSequence::RegisterConfigurationForTesting() {
  DCHECK_NOT_NULL(registerConfigurationForTesting_);
  return registerConfigurationForTesting_;
}

void InstructionSequence::SetRegisterConfigurationForTesting(
    const RegisterConfiguration* regConfig) {
  registerConfigurationForTesting_ = regConfig;
  GetRegConfig = InstructionSequence::RegisterConfigurationForTesting;
}

namespace {

size_t GetConservativeFrameSizeInBytes(FrameStateType type,
                                       size_t parameters_count,
                                       size_t locals_count,
                                       BytecodeOffset bailout_id,
                                       uint32_t wasm_liftoff_frame_size) {
  switch (type) {
    case FrameStateType::kUnoptimizedFunction: {
      auto info = UnoptimizedFrameInfo::Conservative(
          static_cast<int>(parameters_count), static_cast<int>(locals_count));
      return info.frame_size_in_bytes();
    }
    case FrameStateType::kInlinedExtraArguments:
      // The inlined extra arguments frame state is only used in the deoptimizer
      // and does not occupy any extra space in the stack.
      // Check out the design doc:
      // https://docs.google.com/document/d/150wGaUREaZI6YWqOQFD5l2mWQXaPbbZjcAIJLOFrzMs/edit
      // We just need to account for the additional parameters we might push
      // here.
      return UnoptimizedFrameInfo::GetStackSizeForAdditionalArguments(
          static_cast<int>(parameters_count));
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kWasmInlinedIntoJS:
#endif
    case FrameStateType::kConstructCreateStub: {
      auto info = ConstructStubFrameInfo::Conservative(
          static_cast<int>(parameters_count));
      return info.frame_size_in_bytes();
    }
    case FrameStateType::kConstructInvokeStub:
      return FastConstructStubFrameInfo::Conservative().frame_size_in_bytes();
    case FrameStateType::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJSToWasmBuiltinContinuation:
#endif  // V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJavaScriptBuiltinContinuation:
    case FrameStateType::kJavaScriptBuiltinContinuationWithCatch: {
      const RegisterConfiguration* config = RegisterConfiguration::Default();
      auto info = BuiltinContinuationFrameInfo::Conservative(
          static_cast<int>(parameters_count),
          Builtins::CallInterfaceDescriptorFor(
              Builtins::GetBuiltinFromBytecodeOffset(bailout_id)),
          config);
      return info.frame_size_in_bytes();
    }
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kLiftoffFunction:
      return wasm_liftoff_frame_size;
#endif  // V8_ENABLE_WEBASSEMBLY
  }
  UNREACHABLE();
}

size_t GetTotalConservativeFrameSizeInBytes(FrameStateType type,
                                            size_t parameters_count,
                                            size_t locals_count,
                                            BytecodeOffset bailout_id,
                                            uint32_t wasm_liftoff_frame_size,
                                            FrameStateDescriptor* outer_state) {
  size_t outer_total_conservative_frame_size_in_bytes =
      (outer_state == nullptr)
          ? 0
          : outer_state->total_conservative_frame_size_in_bytes();
  return GetConservativeFrameSizeInBytes(type, parameters_count, locals_count,
                                         bailout_id, wasm_liftoff_frame_size) +
         outer_total_conservative_frame_size_in_bytes;
}

}  // namespace

FrameStateDescriptor::FrameStateDescriptor(
    Zone* zone, FrameStateType type, BytecodeOffset bailout_id,
    OutputFrameStateCombine state_combine, uint16_t parameters_count,
    uint16_t max_arguments, size_t locals_count, size_t stack_count,
    MaybeIndirectHandle<SharedFunctionInfo> shared_info,
    MaybeIndirectHandle<BytecodeArray> bytecode_aray,
    FrameStateDescriptor* outer_state, uint32_t wasm_liftoff_frame_size,
    uint32_t wasm_function_index)
    : type_(type),
      bailout_id_(bailout_id),
      frame_state_combine_(state_combine),
      parameters_count_(parameters_count),
      max_arguments_(max_arguments),
      locals_count_(locals_count),
      stack_count_(stack_count),
      total_conservative_frame_size_in_bytes_(
          GetTotalConservativeFrameSizeInBytes(
              type, parameters_count, locals_count, bailout_id,
              wasm_liftoff_frame_size, outer_state)),
      values_(zone),
      shared_info_(shared_info),
      bytecode_array_(bytecode_aray),
      outer_state_(outer_state),
      wasm_function_index_(wasm_function_index) {}

size_t FrameStateDescriptor::GetHeight() const {
  switch (type()) {
    case FrameStateType::kUnoptimizedFunction:
      return locals_count();  // The accumulator is *not* included.
    case FrameStateType::kBuiltinContinuation:
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kJSToWasmBuiltinContinuation:
    case FrameStateType::kWasmInlinedIntoJS:
#endif
      // Custom, non-JS calling convention (that does not have a notion of
      // a receiver or context).
      return parameters_count();
    case FrameStateType::kInlinedExtraArguments:
    case FrameStateType::kConstructCreateStub:
    case FrameStateType::kConstructInvokeStub:
    case FrameStateType::kJavaScriptBuiltinContinuation:
    case FrameStateType::kJavaScriptBuiltinContinuationWithCatch:
      // JS linkage. The parameters count
      // - includes the receiver (input 1 in CreateArtificialFrameState, and
      //   passed as part of stack parameters to
      //   CreateJavaScriptBuiltinContinuationFrameState), and
      // - does *not* include the context.
      return parameters_count();
#if V8_ENABLE_WEBASSEMBLY
    case FrameStateType::kLiftoffFunction:
      return locals_count() + parameters_count();
#endif
  }
  UNREACHABLE();
}

size_t FrameStateDescriptor::GetSize() const {
  return (HasClosure() ? 1 : 0) + parameters_count() + locals_count() +
         stack_count() + (HasContext() ? 1 : 0);
}

size_t FrameStateDescriptor::GetTotalSize() const {
  size_t total_size = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    total_size += iter->GetSize();
  }
  return total_size;
}

size_t FrameStateDescriptor::GetFrameCount() const {
  size_t count = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    ++count;
  }
  return count;
}

size_t FrameStateDescriptor::GetJSFrameCount() const {
  size_t count = 0;
  for (const FrameStateDescriptor* iter = this; iter != nullptr;
       iter = iter->outer_state_) {
    if (FrameStateFunctionInfo::IsJSFunctionType(iter->type_)) {
      ++count;
    }
  }
  return count;
}

#if V8_ENABLE_WEBASSEMBLY
JSToWasmFrameStateDescriptor::JSToWasmFrameStateDescriptor(
    Zone* zone, FrameStateType type, BytecodeOffset bailout_id,
    OutputFrameStateCombine state_combine, uint16_t parameters_count,
    size_t locals_count, size_t stack_count,
    MaybeIndirectHandle<SharedFunctionInfo> shared_info,
    FrameStateDescriptor* outer_state, const wasm::CanonicalSig* wasm_signature)
    : FrameStateDescriptor(zone, type, bailout_id, state_combine,
                           parameters_count, 0, locals_count, stack_count,
                           shared_info, {}, outer_state),
      return_kind_(wasm::WasmReturnTypeFromSignature(wasm_signature)) {}
#endif  // V8_ENABLE_WEBASSEMBLY

std::ostream& operator<<(std::ostream& os, const RpoNumber& rpo) {
  return os << rpo.ToSize();
}

std::ostream& operator<<(std::ostream& os, const InstructionSequence& code) {
  for (size_t i = 0; i < code.immediates_.size(); ++i) {
    Constant constant = code.immediates_[i];
    os << "IMM#" << i << ": " << constant << "\n";
  }
  int n = 0;
  for (ConstantMap::const_iterator it = code.constants_.begin();
       it != code.constants_.end(); ++n, ++it) {
    os << "CST#" << n << ": v" << it->first << " = " << it->second << "\n";
  }
  for (int i = 0; i < code.InstructionBlockCount(); i++) {
    auto* block = code.InstructionBlockAt(RpoNumber::FromInt(i));
    os << PrintableInstructionBlock{block, &code};
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, StateValueKind kind) {
  switch (kind) {
    case StateValueKind::kArgumentsElements:
      return os << "ArgumentsElements";
    case StateValueKind::kArgumentsLength:
      return os << "ArgumentsLength";
    case StateValueKind::kRestLength:
      return os << "RestLength";
    case StateValueKind::kPlain:
      return os << "Plain";
    case StateValueKind::kOptimizedOut:
      return os << "OptimizedOut";
    case StateValueKind::kNestedObject:
      return os << "NestedObject";
    case StateValueKind::kDuplicate:
      return os << "Duplicate";
    case StateValueKind::kStringConcat:
      return os << "StringConcat";
  }
}

void StateValueDescriptor::Print(std::ostream& os) const {
  os << "kind=" << kind_ << ", type=" << type_;
  if (kind_ == StateValueKind::kDuplicate ||
      kind_ == StateValueKind::kNestedObject) {
    os << ", id=" << id_;
  } else if (kind_ == StateValueKind::kArgumentsElements) {
    os << ", args_type=" << args_type_;
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
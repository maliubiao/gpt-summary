Response:
The user wants me to analyze a C++ source code file from the V8 project, specifically `v8/test/cctest/compiler/test-code-generator.cc`.

Here's a breakdown of the request and how I'll address it:

1. **Identify the file's function:** I need to understand the purpose of this C++ file within the V8 project. The name "test-code-generator.cc" strongly suggests it's a test file for the code generation phase of the V8 compiler.

2. **Check for Torque:** The request asks if the file ends with `.tq`, which would indicate a Torque source file. Since it ends with `.cc`, it's a standard C++ file.

3. **Relate to JavaScript:**  I need to determine if the code generator being tested has a direct impact on how JavaScript code is compiled and executed. Given that V8 is a JavaScript engine, the code generator is crucial for this.

4. **Provide JavaScript examples:** If there's a connection to JavaScript, I should provide illustrative JavaScript code snippets that would be affected by the code generator.

5. **Illustrate code logic:**  The request asks for examples of code logic, including hypothetical inputs and outputs. This requires me to infer the behavior of the code based on its structure and the surrounding context.

6. **Highlight common programming errors:** I need to identify potential pitfalls or common mistakes that developers might make when working with code generation concepts or using the V8 API related to this file.

7. **Summarize the functionality:** The user specifically asks for a summary of the file's purpose, indicating this is the second part of a three-part analysis.

**Mental Sandbox:**

*   I'll examine the provided code snippets, looking for patterns related to testing, such as setting up test environments, generating random inputs, simulating execution, and comparing results.
*   The presence of `ParallelMove`, `InstructionOperand`, `CodeGenerator`, and `MachineRepresentation` suggests this code tests the movement of data between different storage locations (registers, stack slots) during code generation.
*   The `SimulateSequentialMoves`, `SimulateParallelMoves`, and `SimulateSwaps` functions are likely used to create a ground truth against which the actual code generator's output is compared.
*   The code seems to focus on testing the correctness of the code generator's handling of data movement, including optimizations like coalescing adjacent moves in tail calls.

**Plan of Action:**

1. State that the file is a C++ test file for the V8 code generator.
2. Confirm that it's not a Torque file.
3. Explain that the code generator is responsible for translating intermediate representation (IR) of JavaScript code into machine code, thus directly impacting JavaScript execution.
4. Provide a simple JavaScript example and explain how the code generator would handle variable assignments and function calls.
5. Give an example of a simulated data movement scenario with hypothetical register/stack slot assignments and the expected outcome.
6. Discuss common programming errors related to register allocation or stack management that the code generator aims to handle correctly.
7. Summarize the functionality by highlighting its role in testing the correctness and efficiency of data movement during code generation, including sequential and parallel moves, and swaps.
这是 `v8/test/cctest/compiler/test-code-generator.cc` 的第二部分代码。根据提供的代码片段，可以归纳出以下功能：

**主要功能：模拟和测试代码生成器中的数据移动操作，特别是针对尾调用优化中的栈帧调整。**

**详细功能拆解：**

1. **尾调用间隙填充测试 (`AssembleTailCallGap` 测试用例)：**
    *   这段代码主要测试了代码生成器在生成尾调用指令前的间隙填充能力。尾调用优化需要在调用前调整栈帧，以确保被调用函数可以直接返回到调用者的调用者的栈帧。这个过程可能涉及到将寄存器或栈上的数据移动到正确的位置。
    *   测试用例通过创建一系列的 `ParallelMove` 对象，模拟在尾调用发生前需要进行的数据移动操作，例如将寄存器中的值推入栈中。
    *   `CheckAssembleTailCallGaps` 函数被用来驱动代码生成器处理这些移动操作，并验证其是否正确地生成了优化的代码，例如将多个相邻的 push 操作合并为一个。
    *   测试用例覆盖了寄存器 push 和栈 push 两种情况。

**与 JavaScript 的关系：**

尾调用优化是 JavaScript 引擎为了减少栈溢出风险和提高性能而进行的一种优化。当一个函数调用的返回值是另一个函数的调用结果时，就可以进行尾调用优化。

**JavaScript 示例：**

```javascript
function a(n) {
  if (n <= 0) {
    return 0;
  }
  return b(n - 1); // 这是一个尾调用
}

function b(n) {
  return a(n - 1); // 这也是一个尾调用
}

a(100000);
```

在这个例子中，函数 `a` 和 `b` 互相调用，并且它们的返回值都是对方的调用结果。V8 的代码生成器会对这样的尾调用进行优化，避免每次调用都创建一个新的栈帧，从而防止栈溢出。`AssembleTailCallGap` 测试用例就是用来确保 V8 在生成此类优化代码时，能够正确地处理数据移动，例如将参数或中间结果移动到正确的位置以便被调用的函数使用。

**代码逻辑推理（假设输入与输出）：**

考虑 `AssembleTailCallGap` 测试用例中的一个片段：

```c++
{
  // Generate a series of register pushes only.
  CodeGeneratorTester c(&env);
  Instruction* instr = c.CreateTailCall(first_slot + 4);
  instr
      ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                env.main_zone())
      ->AddMove(r3, slot_0);
  instr
      ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                env.main_zone())
      ->AddMove(r2, slot_1);
  instr
      ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                env.main_zone())
      ->AddMove(r1, slot_2);
  instr
      ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                env.main_zone())
      ->AddMove(r0, slot_3);

  c.CheckAssembleTailCallGaps(instr, first_slot + 4,
                              CodeGeneratorTester::kRegisterPush);
  DirectHandle<Code> code = c.Finalize();
  if (v8_flags.print_code) {
    Print(*code);
  }
}
```

**假设输入：**

*   寄存器 `r0`, `r1`, `r2`, `r3` 分别包含一些值（例如，指向堆对象的指针）。
*   `first_slot` 的值为某个特定的栈偏移量。

**预期输出：**

代码生成器应该生成一系列指令，将寄存器 `r3`, `r2`, `r1`, `r0` 的内容依次推入栈中的 `slot_0`, `slot_1`, `slot_2`, `slot_3` 位置。在支持指令合并的架构上，可能会生成一个或少数几个指令完成这个操作，例如使用一条 push 指令推送多个寄存器。

**涉及用户常见的编程错误：**

虽然这段代码是测试代码，但它间接涉及了用户在编写 JavaScript 时可能遇到的与尾调用相关的问题。例如：

*   **误认为所有递归调用都是尾调用：** 用户可能认为只要是递归调用，引擎就会进行尾调用优化，但实际上只有符合尾调用形式的递归才能被优化。例如：

    ```javascript
    function factorial(n) {
      if (n <= 1) {
        return 1;
      }
      return n * factorial(n - 1); // 这不是尾调用，因为乘法操作在递归调用之后
    }
    ```

*   **不理解尾调用优化的重要性：** 在处理大量递归时，不理解尾调用优化可能导致栈溢出错误。

**总结其功能：**

这段代码（作为 `v8/test/cctest/compiler/test-code-generator.cc` 的一部分）的主要功能是**测试 V8 代码生成器在处理尾调用优化时，能否正确地生成用于调整栈帧和移动数据的指令序列**。它通过模拟各种数据移动场景（例如将寄存器值推入栈中），并断言代码生成器能够生成预期的优化代码，例如合并相邻的 push 操作，从而确保尾调用优化的正确性和效率。

### 提示词
```
这是目录为v8/test/cctest/compiler/test-code-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/compiler/test-code-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
result->length());
    }
    return state_out;
  }

  std::vector<AllocatedOperand>& TeardownLayout() {
    return layout_mode_ == kPreserveLayout ? setup_layout_ : teardown_layout_;
  }

  CallDescriptor* TeardownCallDescriptor() {
    return layout_mode_ == kPreserveLayout ? test_descriptor_
                                           : teardown_descriptor_;
  }

  // For a given operand representing either a register or a stack slot, return
  // what position it should live in inside a FixedArray state.
  int OperandToStatePosition(std::vector<AllocatedOperand>& layout,
                             const AllocatedOperand& operand) const {
    // Search `layout_` for `operand`.
    auto it = std::find_if(layout.cbegin(), layout.cend(),
                           [operand](const AllocatedOperand& this_operand) {
                             return this_operand.Equals(operand);
                           });
    DCHECK_NE(it, layout.cend());
    return static_cast<int>(std::distance(layout.cbegin(), it));
  }

  Tagged<Object> GetMoveSource(DirectHandle<FixedArray> state,
                               MoveOperands* move) {
    InstructionOperand from = move->source();
    if (from.IsConstant()) {
      Constant constant = instructions_.GetConstant(
          ConstantOperand::cast(from).virtual_register());
      DirectHandle<Object> constant_value;
      switch (constant.type()) {
        case Constant::kInt32:
          constant_value =
              direct_handle(Tagged<Smi>(static_cast<Address>(
                                static_cast<intptr_t>(constant.ToInt32()))),
                            main_isolate());
          break;
        case Constant::kInt64:
          constant_value = direct_handle(
              Tagged<Smi>(static_cast<Address>(constant.ToInt64())),
              main_isolate());
          break;
        case Constant::kFloat32:
          constant_value = main_isolate()->factory()->NewHeapNumber(
              static_cast<double>(constant.ToFloat32()));
          break;
        case Constant::kFloat64:
          constant_value = main_isolate()->factory()->NewHeapNumber(
              constant.ToFloat64().value());
          break;
        default:
          UNREACHABLE();
      }
      return *constant_value;
    } else {
      int from_index =
          OperandToStatePosition(setup_layout_, AllocatedOperand::cast(from));
      return state->get(from_index);
    }
  }

  // Perform the given list of sequential moves on `state_in` and return a newly
  // allocated state with the results.
  Handle<FixedArray> SimulateSequentialMoves(
      ParallelMove* moves, DirectHandle<FixedArray> state_in) {
    Handle<FixedArray> state_out = main_isolate()->factory()->NewFixedArray(
        static_cast<int>(setup_layout_.size()));
    // We do not want to modify `state_in` in place so perform the moves on a
    // copy.
    FixedArray::CopyElements(main_isolate(), *state_out, 0, *state_in, 0,
                             state_in->length());
    DCHECK_EQ(kPreserveLayout, layout_mode_);
    for (auto move : *moves) {
      int to_index = OperandToStatePosition(
          TeardownLayout(), AllocatedOperand::cast(move->destination()));
      Tagged<Object> source = GetMoveSource(state_out, move);
      state_out->set(to_index, source);
    }
    return state_out;
  }

  // Perform the given list of parallel moves on `state_in` and return a newly
  // allocated state with the results.
  Handle<FixedArray> SimulateParallelMoves(ParallelMove* moves,
                                           DirectHandle<FixedArray> state_in) {
    Handle<FixedArray> state_out = main_isolate()->factory()->NewFixedArray(
        static_cast<int>(teardown_layout_.size()));
    for (auto move : *moves) {
      int to_index = OperandToStatePosition(
          TeardownLayout(), AllocatedOperand::cast(move->destination()));
      Tagged<Object> source = GetMoveSource(state_in, move);
      state_out->set(to_index, source);
    }
    // If we generated redundant moves, they were eliminated automatically and
    // don't appear in the parallel move. Simulate them now.
    for (auto& operand : teardown_layout_) {
      int to_index = OperandToStatePosition(TeardownLayout(), operand);
      if (IsUndefined(state_out->get(to_index))) {
        int from_index = OperandToStatePosition(setup_layout_, operand);
        state_out->set(to_index, state_in->get(from_index));
      }
    }
    return state_out;
  }

  // Perform the given list of swaps on `state_in` and return a newly allocated
  // state with the results.
  Handle<FixedArray> SimulateSwaps(ParallelMove* swaps,
                                   DirectHandle<FixedArray> state_in) {
    Handle<FixedArray> state_out = main_isolate()->factory()->NewFixedArray(
        static_cast<int>(setup_layout_.size()));
    // We do not want to modify `state_in` in place so perform the swaps on a
    // copy.
    FixedArray::CopyElements(main_isolate(), *state_out, 0, *state_in, 0,
                             state_in->length());
    for (auto swap : *swaps) {
      int lhs_index = OperandToStatePosition(
          setup_layout_, AllocatedOperand::cast(swap->destination()));
      int rhs_index = OperandToStatePosition(
          setup_layout_, AllocatedOperand::cast(swap->source()));
      DirectHandle<Object> lhs{state_out->get(lhs_index), main_isolate()};
      DirectHandle<Object> rhs{state_out->get(rhs_index), main_isolate()};
      state_out->set(lhs_index, *rhs);
      state_out->set(rhs_index, *lhs);
    }
    return state_out;
  }

  // Compare the given state with a reference.
  void CheckState(DirectHandle<FixedArray> actual,
                  DirectHandle<FixedArray> expected) {
    for (int i = 0; i < static_cast<int>(TeardownLayout().size()); i++) {
      DirectHandle<Object> actual_value{actual->get(i), main_isolate()};
      DirectHandle<Object> expected_value{expected->get(i), main_isolate()};
      if (!CompareValues(actual_value, expected_value,
                         TeardownLayout()[i].representation())) {
        std::ostringstream expected_str;
        PrintStateValue(expected_str, main_isolate(), expected_value,
                        TeardownLayout()[i]);
        std::ostringstream actual_str;
        PrintStateValue(actual_str, main_isolate(), actual_value,
                        TeardownLayout()[i]);
        FATAL("Expected: '%s' but got '%s'", expected_str.str().c_str(),
              actual_str.str().c_str());
      }
    }
  }

  bool CompareValues(DirectHandle<Object> actual, DirectHandle<Object> expected,
                     MachineRepresentation rep) {
    switch (rep) {
      case MachineRepresentation::kTagged:
      case MachineRepresentation::kFloat32:
      case MachineRepresentation::kFloat64:
        return Object::StrictEquals(*actual, *expected);
      case MachineRepresentation::kSimd128:
        for (int lane = 0; lane < 4; lane++) {
          int actual_lane =
              Cast<Smi>(Cast<FixedArray>(*actual)->get(lane)).value();
          int expected_lane =
              Cast<Smi>(Cast<FixedArray>(*expected)->get(lane)).value();
          if (actual_lane != expected_lane) {
            return false;
          }
        }
        return true;
      default:
        UNREACHABLE();
    }
  }

  enum OperandConstraint {
    kNone,
    // Restrict operands to non-constants. This is useful when generating a
    // destination.
    kCannotBeConstant
  };

  // Generate sequential moves at random. Note that they may not be compatible
  // between each other as this doesn't matter to the code generator.
  ParallelMove* GenerateRandomMoves(int size, MoveMode move_mode) {
    ParallelMove* parallel_move = main_zone()->New<ParallelMove>(main_zone());

    for (int i = 0; i < size;) {
      MachineRepresentation rep = CreateRandomMachineRepresentation();
      InstructionOperand source = CreateRandomOperand(kNone, rep, kInput);
      MoveOperands mo(source,
                      CreateRandomOperand(kCannotBeConstant, rep, kOutput));
      // It isn't valid to call `AssembleMove` and `AssembleSwap` with redundant
      // moves.
      if (mo.IsRedundant()) continue;
      parallel_move->AddMove(mo.source(), mo.destination());
      i++;
    }

    return parallel_move;
  }

  // Generate parallel moves at random. Generate exactly one move for each
  // available destination operand. Since the output layout is different from
  // the input layout, this ensures that each destination operand is initialized
  // with one of the values in the input fixed array.
  ParallelMove* GenerateRandomParallelMoves() {
    ParallelMove* parallel_move = main_zone()->New<ParallelMove>(main_zone());
    std::vector<AllocatedOperand> destinations = teardown_layout_;
    std::shuffle(destinations.begin(), destinations.end(), *rng_);

    for (size_t i = 0; i < destinations.size(); ++i) {
      MachineRepresentation rep = destinations[i].representation();
      InstructionOperand source = CreateRandomOperand(kNone, rep, kInput);
      MoveOperands mo(source, destinations[i]);
      parallel_move->AddMove(mo.source(), mo.destination());
    }

    return parallel_move;
  }

  ParallelMove* GenerateRandomSwaps(int size) {
    ParallelMove* parallel_move = main_zone()->New<ParallelMove>(main_zone());

    for (int i = 0; i < size;) {
      MachineRepresentation rep = CreateRandomMachineRepresentation();
      InstructionOperand lhs =
          CreateRandomOperand(kCannotBeConstant, rep, kOutput);
      InstructionOperand rhs =
          CreateRandomOperand(kCannotBeConstant, rep, kInput);
      MoveOperands mo(lhs, rhs);
      // It isn't valid to call `AssembleMove` and `AssembleSwap` with redundant
      // moves.
      if (mo.IsRedundant()) continue;
      // Canonicalize the swap: the register operand has to be the left hand
      // side.
      if (lhs.IsStackSlot() || lhs.IsFPStackSlot()) {
        std::swap(lhs, rhs);
      }
      parallel_move->AddMove(lhs, rhs);
      // Iterate only when a swap was created.
      i++;
    }

    return parallel_move;
  }

  MachineRepresentation CreateRandomMachineRepresentation() {
    int index = rng_->NextInt(static_cast<int>(supported_reps_.size()));
    return supported_reps_[index];
  }

  InstructionOperand CreateRandomOperand(OperandConstraint constraint,
                                         MachineRepresentation rep,
                                         OperandLifetime operand_lifetime) {
    // Only generate a Constant if the operand is a source and we have a
    // constant with a compatible representation in stock.
    bool generate_constant =
        (constraint != kCannotBeConstant) &&
        (allocated_constants_.find(rep) != allocated_constants_.end());
    switch (rng_->NextInt(generate_constant ? 3 : 2)) {
      case 0:
        return CreateRandomStackSlotOperand(rep, operand_lifetime);
      case 1:
        return CreateRandomRegisterOperand(rep);
      case 2:
        return CreateRandomConstant(rep);
    }
    UNREACHABLE();
  }

  AllocatedOperand CreateRandomRegisterOperand(MachineRepresentation rep) {
    int index =
        rng_->NextInt(static_cast<int>(allocated_registers_[rep].size()));
    return allocated_registers_[rep][index];
  }

  std::map<MachineRepresentation, std::vector<AllocatedOperand>>&
  AllocatedSlotsIn() {
    return allocated_slots_in_;
  }

  std::map<MachineRepresentation, std::vector<AllocatedOperand>>&
  AllocatedSlotsOut() {
    return layout_mode_ == kPreserveLayout ? allocated_slots_in_
                                           : allocated_slots_out_;
  }

  AllocatedOperand CreateRandomStackSlotOperand(
      MachineRepresentation rep,
      std::map<MachineRepresentation, std::vector<AllocatedOperand>>& slots) {
    int index = rng_->NextInt(static_cast<int>(AllocatedSlotsIn()[rep].size()));
    return slots[rep][index];
  }

  AllocatedOperand CreateRandomStackSlotOperand(
      MachineRepresentation rep, OperandLifetime operand_lifetime) {
    return CreateRandomStackSlotOperand(rep, operand_lifetime == kInput
                                                 ? AllocatedSlotsIn()
                                                 : AllocatedSlotsOut());
  }

  ConstantOperand CreateRandomConstant(MachineRepresentation rep) {
    int index =
        rng_->NextInt(static_cast<int>(allocated_constants_[rep].size()));
    return allocated_constants_[rep][index];
  }

  static InstructionBlock* NewBlock(Zone* zone, RpoNumber rpo) {
    return zone->New<InstructionBlock>(zone, rpo, RpoNumber::Invalid(),
                                       RpoNumber::Invalid(),
                                       RpoNumber::Invalid(), false, false);
  }

  v8::base::RandomNumberGenerator* rng() const { return rng_; }
  InstructionSequence* instructions() { return &instructions_; }
  CallDescriptor* test_descriptor() { return test_descriptor_; }
  int stack_slot_count() const { return stack_slot_count_; }
  LayoutMode layout_mode() const { return layout_mode_; }

 private:
  ZoneVector<InstructionBlock*> blocks_;
  InstructionSequence instructions_;
  v8::base::RandomNumberGenerator* rng_;
  // The layout describes the type of each element in the environment, in order.
  const LayoutMode layout_mode_;
  std::vector<AllocatedOperand> setup_layout_;
  std::vector<AllocatedOperand> teardown_layout_;
  CallDescriptor* test_descriptor_;
  CallDescriptor* teardown_descriptor_;
  // Allocated constants, registers and stack slots that we can generate moves
  // with. Each per compatible representation.
  std::vector<MachineRepresentation> supported_reps_;
  std::map<MachineRepresentation, std::vector<ConstantOperand>>
      allocated_constants_;
  std::map<MachineRepresentation, std::vector<AllocatedOperand>>
      allocated_registers_;
  std::map<MachineRepresentation, std::vector<AllocatedOperand>>
      allocated_slots_in_;
  std::map<MachineRepresentation, std::vector<AllocatedOperand>>
      allocated_slots_out_;
  int stack_slot_count_;
};

// static
constexpr int TestEnvironment::kGeneralRegisterCount;
constexpr int TestEnvironment::kDoubleRegisterCount;
constexpr int TestEnvironment::kTaggedSlotCount;
constexpr int TestEnvironment::kFloat32SlotCount;
constexpr int TestEnvironment::kFloat64SlotCount;
constexpr int TestEnvironment::kSimd128SlotCount;
constexpr int TestEnvironment::kSmiConstantCount;
constexpr int TestEnvironment::kFloatConstantCount;
constexpr int TestEnvironment::kDoubleConstantCount;

// Wrapper around the CodeGenerator. Code generated by this can
// only be called using the given `TestEnvironment`.
class CodeGeneratorTester {
 public:
  explicit CodeGeneratorTester(TestEnvironment* environment,
                               int extra_stack_space = 0)
      : zone_(environment->main_zone()),
        info_(base::ArrayVector("test"), environment->main_zone(),
              CodeKind::FOR_TESTING),
        linkage_(environment->test_descriptor()),
        frame_(environment->test_descriptor()->CalculateFixedFrameSize(
                   CodeKind::FOR_TESTING),
               environment->main_zone()) {
    // Pick half of the stack parameters at random and move them into spill
    // slots, separated by `extra_stack_space` bytes.
    // When testing a move with stack slots using CheckAssembleMove or
    // CheckAssembleSwap, we'll transparently make use of local spill slots
    // instead of stack parameters for those that were picked. This allows us to
    // test negative, positive, far and near ranges.
    if (environment->layout_mode() == kPreserveLayout) {
      for (int i = 0; i < (environment->stack_slot_count() / 2);) {
        MachineRepresentation rep =
            environment->CreateRandomMachineRepresentation();
        LocationOperand old_slot = LocationOperand::cast(
            environment->CreateRandomStackSlotOperand(rep, kInput));
        // Do not pick the same slot twice.
        if (GetSpillSlot(&old_slot) != spill_slots_.end()) {
          continue;
        }
        LocationOperand new_slot =
            AllocatedOperand(LocationOperand::STACK_SLOT, rep,
                             frame_.AllocateSpillSlot(GetSlotSizeInBytes(rep)));
        // Artificially create space on the stack by allocating a new slot.
        if (extra_stack_space > 0) {
          frame_.AllocateSpillSlot(extra_stack_space);
        }
        spill_slots_.emplace_back(old_slot, new_slot);
        i++;
      }
    }

    constexpr size_t kMaxUnoptimizedFrameHeight = 0;
    constexpr size_t kMaxPushedArgumentCount = 0;
    generator_ = new CodeGenerator(
        environment->main_zone(), &frame_, &linkage_,
        environment->instructions(), &info_, environment->main_isolate(),
        std::optional<OsrHelper>(), kNoSourcePosition, nullptr,
        AssemblerOptions::Default(environment->main_isolate()),
        Builtin::kNoBuiltinId, kMaxUnoptimizedFrameHeight,
        kMaxPushedArgumentCount);

    generator_->masm()->CodeEntry();

    // Force a frame to be created.
    generator_->frame_access_state()->MarkHasFrame(true);
    generator_->AssembleConstructFrame();
    // TODO(all): Generate a stack check here so that we fail gracefully if the
    // frame is too big.

    // Move chosen stack parameters into spill slots.
    for (auto move : spill_slots_) {
      generator_->AssembleMove(&move.first, &move.second);
    }
  }

  ~CodeGeneratorTester() { delete generator_; }

  std::vector<std::pair<LocationOperand, LocationOperand>>::iterator
  GetSpillSlot(InstructionOperand* op) {
    if (op->IsAnyStackSlot()) {
      LocationOperand slot = LocationOperand::cast(*op);
      return std::find_if(
          spill_slots_.begin(), spill_slots_.end(),
          [slot](
              const std::pair<LocationOperand, LocationOperand>& moved_pair) {
            return moved_pair.first.index() == slot.index();
          });
    } else {
      return spill_slots_.end();
    }
  }

  // If the operand corresponds to a spill slot, return it. Else just pass it
  // through.
  InstructionOperand* MaybeTranslateSlot(InstructionOperand* op) {
    auto it = GetSpillSlot(op);
    if (it != spill_slots_.end()) {
      // The second element is the spill slot associated with op.
      return &it->second;
    } else {
      return op;
    }
  }

  Instruction* CreateTailCall(int stack_slot_delta) {
    int optional_padding_slot = stack_slot_delta;
    InstructionOperand callee[] = {
        AllocatedOperand(LocationOperand::REGISTER,
                         MachineRepresentation::kTagged,
                         kReturnRegister0.code()),
        ImmediateOperand(ImmediateOperand::INLINE_INT32, optional_padding_slot),
        ImmediateOperand(ImmediateOperand::INLINE_INT32, stack_slot_delta)};
    Instruction* tail_call =
        Instruction::New(zone_, kArchTailCallCodeObject, 0, nullptr,
                         arraysize(callee), callee, 0, nullptr);
    return tail_call;
  }

  enum PushTypeFlag {
    kRegisterPush = CodeGenerator::kRegisterPush,
    kStackSlotPush = CodeGenerator::kStackSlotPush,
    kScalarPush = CodeGenerator::kScalarPush
  };

  void CheckAssembleTailCallGaps(Instruction* instr,
                                 int first_unused_stack_slot,
                                 CodeGeneratorTester::PushTypeFlag push_type) {
    generator_->AssembleTailCallBeforeGap(instr, first_unused_stack_slot);
#if defined(V8_TARGET_ARCH_ARM) || defined(V8_TARGET_ARCH_S390X) || \
    defined(V8_TARGET_ARCH_PPC64)
    // Only folding register pushes is supported on ARM.
    bool supported =
        ((int{push_type} & CodeGenerator::kRegisterPush) == push_type);
#elif defined(V8_TARGET_ARCH_X64) || defined(V8_TARGET_ARCH_IA32)
    bool supported =
        ((int{push_type} & CodeGenerator::kScalarPush) == push_type);
#else
    bool supported = false;
#endif
    if (supported) {
      // Architectures supporting folding adjacent pushes should now have
      // resolved all moves.
      for (const auto& move :
           *instr->parallel_moves()[Instruction::FIRST_GAP_POSITION]) {
        CHECK(move->IsEliminated());
      }
    }
    generator_->AssembleGaps(instr);
    generator_->AssembleTailCallAfterGap(instr, first_unused_stack_slot);
  }

  void CheckAssembleMove(InstructionOperand* source,
                         InstructionOperand* destination) {
    int start = generator_->masm()->pc_offset();
    generator_->AssembleMove(MaybeTranslateSlot(source),
                             MaybeTranslateSlot(destination));
    CHECK(generator_->masm()->pc_offset() > start);
  }

  void CheckAssembleMoves(ParallelMove* moves) {
    for (auto m : *moves) {
      m->set_source(*MaybeTranslateSlot(&m->source()));
      m->set_destination(*MaybeTranslateSlot(&m->destination()));
    }
    generator_->resolver()->Resolve(moves);
  }

  void CheckAssembleSwap(InstructionOperand* source,
                         InstructionOperand* destination) {
    int start = generator_->masm()->pc_offset();
    generator_->AssembleSwap(MaybeTranslateSlot(source),
                             MaybeTranslateSlot(destination));
    CHECK(generator_->masm()->pc_offset() > start);
  }

  Handle<Code> Finalize() {
    generator_->FinishCode();
    generator_->safepoints()->Emit(generator_->masm(),
                                   frame_.GetTotalFrameSlotCount());
    generator_->MaybeEmitOutOfLineConstantPool();

    return generator_->FinalizeCode().ToHandleChecked();
  }

  Handle<Code> FinalizeForExecuting() {
    // The test environment expects us to have performed moves on stack
    // parameters. However, some of them are mapped to local spill slots. They
    // should be moved back into stack parameters so their values are passed
    // along to the `teardown` function.
    for (auto move : spill_slots_) {
      generator_->AssembleMove(&move.second, &move.first);
    }

    InstructionSequence* sequence = generator_->instructions();

    sequence->StartBlock(RpoNumber::FromInt(0));
    // The environment expects this code to tail-call to its first parameter
    // placed in `kReturnRegister0`.
    sequence->AddInstruction(Instruction::New(zone_, kArchPrepareTailCall));

    // We use either zero or one slots.
    static constexpr int first_unused_stack_slot = kReturnAddressStackSlotCount;
    int optional_padding_slot = first_unused_stack_slot;
    InstructionOperand callee[] = {
        AllocatedOperand(LocationOperand::REGISTER,
                         MachineRepresentation::kTagged,
                         kReturnRegister0.code()),
        ImmediateOperand(
            ImmediateOperand::INLINE_INT32,
            (kDefaultCodeEntrypointTag >> kCodeEntrypointTagShift)),
        ImmediateOperand(ImmediateOperand::INLINE_INT32, optional_padding_slot),
        ImmediateOperand(ImmediateOperand::INLINE_INT32,
                         first_unused_stack_slot)};
    Instruction* tail_call =
        Instruction::New(zone_, kArchTailCallCodeObject, 0, nullptr,
                         arraysize(callee), callee, 0, nullptr);
    sequence->AddInstruction(tail_call);
    sequence->EndBlock(RpoNumber::FromInt(0));

    generator_->AssembleBlock(
        sequence->InstructionBlockAt(RpoNumber::FromInt(0)));

    return Finalize();
  }

 private:
  Zone* zone_;
  OptimizedCompilationInfo info_;
  Linkage linkage_;
  Frame frame_;
  CodeGenerator* generator_;
  // List of operands to be moved from stack parameters to spill slots.
  std::vector<std::pair<LocationOperand, LocationOperand>> spill_slots_;
};

// The following fuzz tests will assemble a lot of moves, wrap them in
// executable native code and run them. In order to check that moves were
// performed correctly, we need to setup an environment with an initial state
// and get it back after the list of moves were performed.
//
// We have two components to do this: TestEnvironment and CodeGeneratorTester.
//
// The TestEnvironment is in charge of bringing up an environment consisting of
// a set of registers, stack slots and constants, with initial values in
// them. The CodeGeneratorTester is a wrapper around the CodeGenerator and its
// only purpose is to generate code for a list of moves. The TestEnvironment is
// then able to run this code against the environment and return a resulting
// state.
//
// A "state" here is a packed FixedArray with tagged values which can either be
// Smis or HeapNumbers. When calling TestEnvironment::Run(...), registers and
// stack slots will be initialised according to this FixedArray. A new
// FixedArray is returned containing values that were moved by the generated
// code.
//
// And finally, we are able to compare the resulting FixedArray against a
// reference, computed with a simulation of AssembleMove and AssembleSwap. See
// SimulateSequentialMoves, SimulateParallelMoves and SimulateSwaps.

// Allocate space between slots to increase coverage of moves with larger
// ranges. Note that this affects how much stack is allocated when running the
// generated code. It means we have to be careful not to exceed the stack limit,
// which is lower on Windows.
#ifdef V8_OS_WIN
constexpr int kExtraSpace = 0;
#else
constexpr int kExtraSpace = 1 * KB;
#endif

TEST(FuzzAssembleMove) {
  TestEnvironment env;

  Handle<FixedArray> state_in = env.GenerateInitialState();
  ParallelMove* moves = env.GenerateRandomMoves(1000, kSequentialMoves);

  DirectHandle<FixedArray> expected =
      env.SimulateSequentialMoves(moves, state_in);

  // Test small and potentially large ranges separately.
  for (int extra_space : {0, kExtraSpace}) {
    CodeGeneratorTester c(&env, extra_space);

    for (auto m : *moves) {
      c.CheckAssembleMove(&m->source(), &m->destination());
    }

    Handle<Code> test = c.FinalizeForExecuting();
    if (v8_flags.print_code) {
      Print(*test);
    }

    DirectHandle<FixedArray> actual = env.Run(test, state_in);
    env.CheckState(actual, expected);
  }
}

// Test integration with the gap resolver by resolving parallel moves first.
TEST(FuzzAssembleParallelMove) {
  TestEnvironment env(kChangeLayout);

  Handle<FixedArray> state_in = env.GenerateInitialState();
  ParallelMove* moves = env.GenerateRandomParallelMoves();
  DirectHandle<FixedArray> state_out =
      env.SimulateParallelMoves(moves, state_in);

  CodeGeneratorTester c(&env);

  // The gap resolver modifies the parallel move in-place. Copy and restore
  // it after assembling.
  c.CheckAssembleMoves(moves);

  Handle<Code> test = c.FinalizeForExecuting();
  if (v8_flags.print_code) {
    Print(*test);
  }

  DirectHandle<FixedArray> actual = env.Run(test, state_in);
  env.CheckState(actual, state_out);
}

TEST(FuzzAssembleSwap) {
  TestEnvironment env;

  Handle<FixedArray> state_in = env.GenerateInitialState();
  ParallelMove* swaps = env.GenerateRandomSwaps(1000);

  DirectHandle<FixedArray> expected = env.SimulateSwaps(swaps, state_in);

  // Test small and potentially large ranges separately.
  for (int extra_space : {0, kExtraSpace}) {
    CodeGeneratorTester c(&env, extra_space);

    for (auto s : *swaps) {
      c.CheckAssembleSwap(&s->source(), &s->destination());
    }

    Handle<Code> test = c.FinalizeForExecuting();
    if (v8_flags.print_code) {
      Print(*test);
    }

    DirectHandle<FixedArray> actual = env.Run(test, state_in);
    env.CheckState(actual, expected);
  }
}

TEST(FuzzAssembleMoveAndSwap) {
  TestEnvironment env;

  Handle<FixedArray> state_in = env.GenerateInitialState();
  DirectHandle<FixedArray> expected =
      env.main_isolate()->factory()->NewFixedArray(state_in->length());

  // Test small and potentially large ranges separately.
  for (int extra_space : {0, kExtraSpace}) {
    CodeGeneratorTester c(&env, extra_space);

    FixedArray::CopyElements(env.main_isolate(), *expected, 0, *state_in, 0,
                             state_in->length());

    for (int i = 0; i < 1000; i++) {
      // Randomly alternate between swaps and moves.
      if (env.rng()->NextInt(2) == 0) {
        ParallelMove* move = env.GenerateRandomMoves(1, kSequentialMoves);
        expected = env.SimulateSequentialMoves(move, expected);
        c.CheckAssembleMove(&move->at(0)->source(),
                            &move->at(0)->destination());
      } else {
        ParallelMove* swap = env.GenerateRandomSwaps(1);
        expected = env.SimulateSwaps(swap, expected);
        c.CheckAssembleSwap(&swap->at(0)->source(),
                            &swap->at(0)->destination());
      }
    }

    Handle<Code> test = c.FinalizeForExecuting();
    if (v8_flags.print_code) {
      Print(*test);
    }

    DirectHandle<FixedArray> actual = env.Run(test, state_in);
    env.CheckState(actual, expected);
  }
}

TEST(AssembleTailCallGap) {
  const RegisterConfiguration* conf = GetRegConfig();
  TestEnvironment env;

  // This test assumes at least 4 registers are allocatable.
  CHECK_LE(4, conf->num_allocatable_general_registers());

  auto r0 = AllocatedOperand(LocationOperand::REGISTER,
                             MachineRepresentation::kTagged,
                             conf->GetAllocatableGeneralCode(0));
  auto r1 = AllocatedOperand(LocationOperand::REGISTER,
                             MachineRepresentation::kTagged,
                             conf->GetAllocatableGeneralCode(1));
  auto r2 = AllocatedOperand(LocationOperand::REGISTER,
                             MachineRepresentation::kTagged,
                             conf->GetAllocatableGeneralCode(2));
  auto r3 = AllocatedOperand(LocationOperand::REGISTER,
                             MachineRepresentation::kTagged,
                             conf->GetAllocatableGeneralCode(3));

  auto slot_minus_4 = AllocatedOperand(LocationOperand::STACK_SLOT,
                                       MachineRepresentation::kTagged, -4);
  auto slot_minus_3 = AllocatedOperand(LocationOperand::STACK_SLOT,
                                       MachineRepresentation::kTagged, -3);
  auto slot_minus_2 = AllocatedOperand(LocationOperand::STACK_SLOT,
                                       MachineRepresentation::kTagged, -2);
  auto slot_minus_1 = AllocatedOperand(LocationOperand::STACK_SLOT,
                                       MachineRepresentation::kTagged, -1);

  // Avoid slot 0 for architectures which use it store the return address.
  static constexpr int first_slot = kReturnAddressStackSlotCount;
  auto slot_0 = AllocatedOperand(LocationOperand::STACK_SLOT,
                                 MachineRepresentation::kTagged, first_slot);
  auto slot_1 =
      AllocatedOperand(LocationOperand::STACK_SLOT,
                       MachineRepresentation::kTagged, first_slot + 1);
  auto slot_2 =
      AllocatedOperand(LocationOperand::STACK_SLOT,
                       MachineRepresentation::kTagged, first_slot + 2);
  auto slot_3 =
      AllocatedOperand(LocationOperand::STACK_SLOT,
                       MachineRepresentation::kTagged, first_slot + 3);

  // These tests all generate series of moves that the code generator should
  // detect as adjacent pushes. Depending on the architecture, we make sure
  // these moves get eliminated.
  // Also, disassembling with `--print-code` is useful when debugging.

  {
    // Generate a series of register pushes only.
    CodeGeneratorTester c(&env);
    Instruction* instr = c.CreateTailCall(first_slot + 4);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(r3, slot_0);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(r2, slot_1);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(r1, slot_2);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(r0, slot_3);

    c.CheckAssembleTailCallGaps(instr, first_slot + 4,
                                CodeGeneratorTester::kRegisterPush);
    DirectHandle<Code> code = c.Finalize();
    if (v8_flags.print_code) {
      Print(*code);
    }
  }

  {
    // Generate a series of stack pushes only.
    CodeGeneratorTester c(&env);
    Instruction* instr = c.CreateTailCall(first_slot + 4);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(slot_minus_4, slot_0);
    instr
        ->GetOrCreateParallelMove(Instruction::FIRST_GAP_POSITION,
                                  env.main_zone())
        ->AddMove(slot_minus_3, slot_1);
    instr
        ->G
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`. The prompt also includes specific instructions about what to look for:
1. **General Functionality:** Describe what the code does.
2. **Torque Source:** Check if the filename ends with `.tq`.
3. **JavaScript Relation:** If it's related to JavaScript, provide a JavaScript example.
4. **Code Logic Inference:** If there's code logic, give example inputs and outputs.
5. **Common Programming Errors:** Identify potential user errors the code might address.
6. **Part of a Larger Set:**  Acknowledge that this is part 2 of 18 and summarize its function within that context.

Let's break down the code snippet:

- **Merging Frame States:** The first part of the code defines a `MergeIntoFrameState` function. This suggests that the code is involved in managing and combining the state of the interpreter's frame at different points in the program's execution. This is common in compiler optimization phases where different execution paths converge.
- **Constructor:** The `MaglevGraphBuilder` constructor initializes various members. Key initializations include:
    - `bytecode_analysis_`:  Indicates interaction with bytecode analysis.
    - `iterator_`: Suggests iterating through bytecode instructions.
    - `jump_targets_`, `merge_states_`:  These are likely used for building the control flow graph (CFG) of the compiled code, managing jump locations and the merged state at those locations.
    - `current_interpreter_frame_`:  Represents the current state of the interpreter's registers and stack.
    - OSR-related checks (`compilation_unit->is_osr()`).
- **Prologue and Arguments:** `StartPrologue`, `EndPrologue`, `SetArgument`, and `GetArgument` suggest the code is involved in setting up the initial state of a function and managing its arguments. `GetInlinedArgument` hints at handling inlined function calls.
- **Register Initialization:** `InitializeRegister` and `BuildRegisterFrameInitialization` show the process of setting initial values for registers. The handling of OSR (On-Stack Replacement) is also evident here.
- **Building Merge States (again):**  `BuildMergeStates` reiterates the importance of managing and creating merge points, especially for loops and exception handlers.
- **Result Location and Size:** `GetResultLocationAndSize` seems to determine where the result of an operation is stored (register) and how much space it occupies. The helper template `GetResultLocationAndSizeHelper` suggests a systematic way of handling different bytecode instructions.
- **Deoptimization Frames:** A significant portion of the code deals with `DeoptFrame`. This is crucial for optimizing compilers. When optimized code encounters a situation where it can no longer maintain its assumptions, it needs to "deoptimize" and return control to the interpreter. This part of the code builds the necessary information to facilitate this process.
- **Tagged Values and Representations:** Functions like `GetTaggedValue` and `GetSmiValue` are about managing different representations of values (e.g., tagged pointers, Smis, integers, floats) and converting between them. The use of `UseReprHintRecording` hints at optimization strategies based on value representation.
- **Internalized Strings:** `GetInternalizedString` deals with a specific type of string optimization.
- **ToNumber Conversion:** `GetTruncatedInt32ForToNumber` handles converting values to numbers, especially for cases where truncation to an integer is needed.

**High-Level Summary:**  This code is a crucial part of the Maglev compiler in V8. It takes the bytecode of a JavaScript function and builds an intermediate representation (the "graph") that can be further optimized and then translated into machine code. It meticulously manages the state of the interpreter's frame, handles control flow (jumps and merges), deals with different value representations, and sets up mechanisms for deoptimization.

Now, let's address the specific points in the prompt:

1. **Functionality:** The code is responsible for building the Maglev graph, an intermediate representation used in V8's Maglev compiler. This involves:
    - Analyzing bytecode.
    - Creating basic blocks and managing control flow.
    - Tracking the state of the interpreter's registers and stack (interpreter frame).
    - Handling function arguments and register initialization.
    - Managing merge points in the control flow graph, especially for loops and exception handlers.
    - Determining the location and size of instruction results.
    - Setting up deoptimization frames to allow the optimized code to fall back to the interpreter when necessary.
    - Managing different representations of JavaScript values (tagged, Smi, integer, float).
    - Performing type checks and conversions.

2. **Torque Source:** The filename ends with `.cc`, not `.tq`. Therefore, it's a standard C++ source file.

3. **JavaScript Relation:**  Yes, this code is directly related to the execution of JavaScript. It's part of the compilation pipeline that takes JavaScript bytecode and turns it into optimized machine code.

   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(5, 10); // When this function is executed, the Maglev compiler (if enabled) might process its bytecode using code like the snippet provided.
   ```

4. **Code Logic Inference:**

   **Assumption:**  A branch in the JavaScript code leads to two different states of the interpreter frame at a specific bytecode offset (a merge point).

   **Input:**
   - `label`: A `BasicBlock` representing the target of the merge.
   - `pseudo_frame_`: The current interpreter frame state.
   - `predecessor`: The block from which the execution flow is merging.

   **Scenario 1 (No existing merge state):**
   - `label->merge_state_` is initially `nullptr`.

   **Output:**
   - A new `MergePointInterpreterFrameState` is created for the `label`.
   - The new merge state is initialized with the current frame state (`pseudo_frame_`) and liveness information.

   **Scenario 2 (Existing merge state):**
   - `label->merge_state_` already points to a `MergePointInterpreterFrameState`.

   **Output:**
   - The existing `MergePointInterpreterFrameState` is updated by merging the state from `pseudo_frame_` and the `predecessor` block. This ensures that the merged state correctly reflects the combined knowledge from both incoming execution paths.

5. **Common Programming Errors:**  While this C++ code isn't directly about user programming errors in JavaScript, it helps handle situations arising from JavaScript's dynamic nature, which could be seen as "errors" from a static typing perspective. For example:

   - **Type Mismatches:**  JavaScript allows operations on values of different types (e.g., adding a number and a string). The `GetTaggedValue`, `GetSmiValue`, and `GetTruncatedInt32ForToNumber` functions are involved in ensuring that values are in the expected representation or converting them, potentially leading to deoptimization if assumptions are violated. A user "error" might be implicitly relying on a value being a specific type when it's not.

     ```javascript
     function maybeAdd(a, b) {
       if (typeof a === 'number' && typeof b === 'number') {
         return a + b;
       }
       return "Inputs were not numbers";
     }

     console.log(maybeAdd(5, 10));     // Maglev might optimize for the 'number' case.
     console.log(maybeAdd(5, "hello")); // This might trigger deoptimization if Maglev made assumptions about the types.
     ```

6. **Part 2 of 18:** Based on the functionality observed in this part, it seems like this section of the `maglev-graph-builder.cc` focuses on the initial stages of building the graph, including setting up the function's environment (prologue, arguments, registers) and handling basic control flow merges. Subsequent parts likely deal with more complex bytecode instructions, optimizations, and code generation. This specific part is foundational for establishing the basic structure of the Maglev graph and managing the interpreter's state.

这是 `v8/src/maglev/maglev-graph-builder.cc` 源代码的第 2 部分，主要负责构建 Maglev 图的早期阶段，包括：

**核心功能归纳:**

* **管理和合并解释器帧状态 (Interpreter Frame State):** `MergeIntoFrameState` 函数负责将不同执行路径上的解释器帧状态合并到一起，这是构建控制流图的关键步骤，尤其是在处理分支和循环时。
* **Maglev 图构建器的初始化:** `MaglevGraphBuilder` 的构造函数负责初始化构建过程所需的各种数据结构，例如：
    * **字节码分析器 (`bytecode_analysis_`)**: 用于分析 JavaScript 函数的字节码。
    * **字节码迭代器 (`iterator_`)**: 用于遍历字节码指令。
    * **跳转目标 (`jump_targets_`) 和合并状态 (`merge_states_`)**: 用于构建控制流图，记录跳转位置和合并点的状态。
    * **当前解释器帧 (`current_interpreter_frame_`)**: 维护当前执行点的解释器寄存器和局部变量的状态。
    * **处理内联 (`is_inline()`) 和 OSR (On-Stack Replacement)** 的相关逻辑。
* **处理函数序言 (Prologue):** `StartPrologue` 和 `EndPrologue` 负责处理函数执行的起始部分，例如创建起始基本块。
* **处理函数参数:** `SetArgument` 和 `GetArgument` 用于设置和获取函数的参数。`GetInlinedArgument` 用于处理内联函数的参数。
* **初始化寄存器:** `InitializeRegister` 和 `BuildRegisterFrameInitialization` 负责设置寄存器的初始值，包括处理上下文、闭包和 `new.target`。同时还处理了 OSR 的情况，为 OSR 的值创建占位符。
* **构建合并状态:** `BuildMergeStates` 详细地创建了循环入口和异常处理入口的合并状态，这些状态记录了在这些特殊控制流点上的解释器帧状态。
* **确定指令结果的位置和大小:** `GetResultLocationAndSize` 函数根据当前的字节码指令，确定指令执行结果存储在哪个寄存器以及占用多少空间。这对于后续的数据流分析和代码生成至关重要。
* **处理延迟反优化 (Lazy Deoptimization):**  `GetParentDeoptFrame`, `GetLatestCheckpointedFrame`, `GetDeoptFrameForLazyDeopt`, `GetDeoptFrameForLazyDeoptHelper`, 和 `GetDeoptFrameForEntryStackCheck` 等一系列函数用于构建和管理反优化帧 (Deopt Frame)。当优化的代码遇到无法处理的情况时，需要退回到解释器执行，反优化帧记录了恢复解释器状态所需的信息。
* **处理值的不同表示形式:** `GetTaggedValue` 和 `GetSmiValue` 用于处理 JavaScript 中值的不同表示形式，例如标记指针 (Tagged Value) 和小整数 (Smi)，并进行必要的转换和类型检查。
* **处理内部化字符串 (Internalized String):** `GetInternalizedString` 用于获取内部化字符串，这是一种优化技术，可以提高字符串比较的效率。
* **处理 `ToNumber` 转换:** `GetTruncatedInt32ForToNumber` 用于将值转换为数字，并根据提示信息进行优化，例如假设输入是 Smi。

**关于问题中的其他点:**

* **`.tq` 结尾:**  `v8/src/maglev/maglev-graph-builder.cc` 以 `.cc` 结尾，因此它是标准的 C++ 源代码，而不是 Torque 源代码。
* **与 JavaScript 的关系:**  这段代码与 JavaScript 的执行息息相关。Maglev 是 V8 引擎中的一个编译器，它将 JavaScript 字节码编译成优化的机器码。这段代码负责构建 Maglev 编译过程中的一个关键中间表示——Maglev 图。

   **JavaScript 示例:**

   ```javascript
   function example(a, b) {
     let sum = a + b;
     return sum;
   }

   example(10, 5);
   ```

   当 V8 引擎执行 `example(10, 5)` 时，Maglev 编译器会分析 `example` 函数的字节码，并使用类似 `MaglevGraphBuilder` 的代码来构建其内部表示，包括处理参数 `a` 和 `b`，执行加法操作，并将结果存储在某个位置。

* **代码逻辑推理:**

   **假设输入:**  在执行到一个条件分支语句之后，程序执行流可能到达同一个代码位置（一个合并点），并且在不同的分支上，某个变量 `x` 的类型可能不同。

   **输出:**  `MergeIntoFrameState` 函数会合并这两个分支的解释器帧状态。如果 `x` 在一个分支中被认为是数字，在另一个分支中被认为是字符串，合并后的状态可能会记录 `x` 的类型为 `number | string` (或者更底层的表示，指示需要进行类型检查)。

* **用户常见的编程错误:**  虽然这段 C++ 代码不是直接处理用户的 JavaScript 代码错误，但它在编译过程中会处理由于 JavaScript 的动态类型特性而可能出现的情况，这些情况在静态类型语言中会被认为是错误。例如：

   ```javascript
   function addOrConcat(a, b) {
     return a + b; // 用户可能期望是加法，但如果 a 或 b 是字符串，则会变成字符串拼接
   }

   addOrConcat(5, 10);     // 正常加法
   addOrConcat("hello", 10); // 字符串拼接

   function accessProperty(obj) {
     return obj.value; // 用户可能假设 obj 总是有一个 'value' 属性
   }

   accessProperty({ value: 1 }); // 正常访问
   accessProperty(null);        // 运行时错误 (TypeError)
   ```

   Maglev 图构建器需要处理这些动态类型带来的不确定性，并生成能够处理这些情况的代码，或者在类型不符合预期时触发反优化。

总而言之，`v8/src/maglev/maglev-graph-builder.cc` 的这一部分是 Maglev 编译器的核心组件，负责构建函数执行的中间表示，管理程序状态，并为后续的优化和代码生成奠定基础。它处理了函数的基本结构、参数、寄存器初始化、控制流的合并以及对 JavaScript 动态类型的处理。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共18部分，请归纳一下它的功能
```

### 源代码
```cpp
liveness_);
  } else {
    // If there already is a frame state, merge.
    label->merge_state_->Merge(builder_, *compilation_unit_, pseudo_frame_,
                               predecessor);
  }
}

MaglevGraphBuilder::MaglevGraphBuilder(
    LocalIsolate* local_isolate, MaglevCompilationUnit* compilation_unit,
    Graph* graph, float call_frequency, BytecodeOffset caller_bytecode_offset,
    bool caller_is_inside_loop, int inlining_id, MaglevGraphBuilder* parent)
    : local_isolate_(local_isolate),
      compilation_unit_(compilation_unit),
      parent_(parent),
      graph_(graph),
      bytecode_analysis_(bytecode().object(), zone(),
                         compilation_unit->osr_offset(), true),
      iterator_(bytecode().object()),
      source_position_iterator_(bytecode().SourcePositionTable(broker())),
      allow_loop_peeling_(v8_flags.maglev_loop_peeling),
      loop_effects_stack_(zone()),
      decremented_predecessor_offsets_(zone()),
      loop_headers_to_peel_(bytecode().length(), zone()),
      current_source_position_(SourcePosition(
          compilation_unit_->shared_function_info().StartPosition(),
          inlining_id)),
      call_frequency_(call_frequency),
      // Add an extra jump_target slot for the inline exit if needed.
      jump_targets_(zone()->AllocateArray<BasicBlockRef>(
          bytecode().length() + (is_inline() ? 1 : 0))),
      // Overallocate merge_states_ by one to allow always looking up the
      // next offset. This overallocated slot can also be used for the inline
      // exit when needed.
      merge_states_(zone()->AllocateArray<MergePointInterpreterFrameState*>(
          bytecode().length() + 1)),
      current_interpreter_frame_(
          *compilation_unit_,
          is_inline() ? parent->current_interpreter_frame_.known_node_aspects()
                      : compilation_unit_->zone()->New<KnownNodeAspects>(
                            compilation_unit_->zone()),
          is_inline() ? parent->current_interpreter_frame_.virtual_objects()
                      : VirtualObject::List()),
      caller_bytecode_offset_(caller_bytecode_offset),
      caller_is_inside_loop_(caller_is_inside_loop),
      entrypoint_(compilation_unit->is_osr()
                      ? bytecode_analysis_.osr_entry_point()
                      : 0),
      inlining_id_(inlining_id),
      catch_block_stack_(zone()),
      unobserved_context_slot_stores_(zone()) {
  memset(merge_states_, 0,
         (bytecode().length() + 1) * sizeof(InterpreterFrameState*));
  // Default construct basic block refs.
  // TODO(leszeks): This could be a memset of nullptr to ..._jump_targets_.
  for (int i = 0; i < bytecode().length(); ++i) {
    new (&jump_targets_[i]) BasicBlockRef();
  }

  if (is_inline()) {
    DCHECK_NOT_NULL(parent_);
    DCHECK_GT(compilation_unit->inlining_depth(), 0);
    // The allocation/initialisation logic here relies on inline_exit_offset
    // being the offset one past the end of the bytecode.
    DCHECK_EQ(inline_exit_offset(), bytecode().length());
    merge_states_[inline_exit_offset()] = nullptr;
    new (&jump_targets_[inline_exit_offset()]) BasicBlockRef();
    if (parent_->loop_effects_) {
      loop_effects_ = parent->loop_effects_;
      loop_effects_stack_.push_back(loop_effects_);
    }
    unobserved_context_slot_stores_ = parent_->unobserved_context_slot_stores_;
  }

  CHECK_IMPLIES(compilation_unit_->is_osr(), graph_->is_osr());
  CHECK_EQ(compilation_unit_->info()->toplevel_osr_offset() !=
               BytecodeOffset::None(),
           graph_->is_osr());
  if (compilation_unit_->is_osr()) {
    CHECK(!is_inline());
#ifdef DEBUG
    // OSR'ing into the middle of a loop is currently not supported. There
    // should not be any issue with OSR'ing outside of loops, just we currently
    // dont do it...
    iterator_.SetOffset(compilation_unit_->osr_offset().ToInt());
    DCHECK_EQ(iterator_.current_bytecode(), interpreter::Bytecode::kJumpLoop);
    DCHECK_EQ(entrypoint_, iterator_.GetJumpTargetOffset());
    iterator_.SetOffset(entrypoint_);
#endif

    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "- Non-standard entrypoint @" << entrypoint_
                << " by OSR from @" << compilation_unit_->osr_offset().ToInt()
                << std::endl;
    }
  }
  CHECK_IMPLIES(!compilation_unit_->is_osr(), entrypoint_ == 0);

  CalculatePredecessorCounts();
}

void MaglevGraphBuilder::StartPrologue() {
  current_block_ = zone()->New<BasicBlock>(nullptr, zone());
}

BasicBlock* MaglevGraphBuilder::EndPrologue() {
  BasicBlock* first_block;
  if (!is_inline() &&
      (v8_flags.maglev_hoist_osr_value_phi_untagging && graph_->is_osr())) {
    first_block =
        FinishBlock<CheckpointedJump>({}, &jump_targets_[entrypoint_]);
  } else {
    first_block = FinishBlock<Jump>({}, &jump_targets_[entrypoint_]);
  }
  MergeIntoFrameState(first_block, entrypoint_);
  return first_block;
}

void MaglevGraphBuilder::SetArgument(int i, ValueNode* value) {
  interpreter::Register reg = interpreter::Register::FromParameterIndex(i);
  current_interpreter_frame_.set(reg, value);
}

ValueNode* MaglevGraphBuilder::GetArgument(int i) {
  DCHECK_LT(i, parameter_count());
  interpreter::Register reg = interpreter::Register::FromParameterIndex(i);
  return current_interpreter_frame_.get(reg);
}

ValueNode* MaglevGraphBuilder::GetInlinedArgument(int i) {
  DCHECK(is_inline());
  DCHECK_LT(i, argument_count());
  return inlined_arguments_[i];
}

void MaglevGraphBuilder::InitializeRegister(interpreter::Register reg,
                                            ValueNode* value) {
  current_interpreter_frame_.set(
      reg, value ? value : AddNewNode<InitialValue>({}, reg));
}

void MaglevGraphBuilder::BuildRegisterFrameInitialization(
    ValueNode* context, ValueNode* closure, ValueNode* new_target) {
  if (closure == nullptr &&
      compilation_unit_->info()->specialize_to_function_context()) {
    compiler::JSFunctionRef function = compiler::MakeRefAssumeMemoryFence(
        broker(), broker()->CanonicalPersistentHandle(
                      compilation_unit_->info()->toplevel_function()));
    closure = GetConstant(function);
    context = GetConstant(function.context(broker()));
  }
  InitializeRegister(interpreter::Register::current_context(), context);
  InitializeRegister(interpreter::Register::function_closure(), closure);

  interpreter::Register new_target_or_generator_register =
      bytecode().incoming_new_target_or_generator_register();

  int register_index = 0;

  if (compilation_unit_->is_osr()) {
    for (; register_index < register_count(); register_index++) {
      auto val =
          AddNewNode<InitialValue>({}, interpreter::Register(register_index));
      InitializeRegister(interpreter::Register(register_index), val);
      graph_->osr_values().push_back(val);
    }
    return;
  }

  // TODO(leszeks): Don't emit if not needed.
  ValueNode* undefined_value = GetRootConstant(RootIndex::kUndefinedValue);
  if (new_target_or_generator_register.is_valid()) {
    int new_target_index = new_target_or_generator_register.index();
    for (; register_index < new_target_index; register_index++) {
      current_interpreter_frame_.set(interpreter::Register(register_index),
                                     undefined_value);
    }
    current_interpreter_frame_.set(
        new_target_or_generator_register,
        new_target ? new_target
                   : GetRegisterInput(kJavaScriptCallNewTargetRegister));
    register_index++;
  }
  for (; register_index < register_count(); register_index++) {
    InitializeRegister(interpreter::Register(register_index), undefined_value);
  }
}

void MaglevGraphBuilder::BuildMergeStates() {
  auto offset_and_info = bytecode_analysis().GetLoopInfos().begin();
  auto end = bytecode_analysis().GetLoopInfos().end();
  while (offset_and_info != end && offset_and_info->first < entrypoint_) {
    ++offset_and_info;
  }
  for (; offset_and_info != end; ++offset_and_info) {
    int offset = offset_and_info->first;
    const compiler::LoopInfo& loop_info = offset_and_info->second;
    if (loop_headers_to_peel_.Contains(offset)) {
      // Peeled loops are treated like normal merges at first. We will construct
      // the proper loop header merge state when reaching the `JumpLoop` of the
      // peeled iteration.
      continue;
    }
    const compiler::BytecodeLivenessState* liveness = GetInLivenessFor(offset);
    DCHECK_NULL(merge_states_[offset]);
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "- Creating loop merge state at @" << offset << std::endl;
    }
    merge_states_[offset] = MergePointInterpreterFrameState::NewForLoop(
        current_interpreter_frame_, *compilation_unit_, offset,
        predecessor_count(offset), liveness, &loop_info);
  }

  if (bytecode().handler_table_size() > 0) {
    HandlerTable table(*bytecode().object());
    for (int i = 0; i < table.NumberOfRangeEntries(); i++) {
      const int offset = table.GetRangeHandler(i);
      const bool was_used = table.HandlerWasUsed(i);
      const interpreter::Register context_reg(table.GetRangeData(i));
      const compiler::BytecodeLivenessState* liveness =
          GetInLivenessFor(offset);
      DCHECK_EQ(predecessor_count(offset), 0);
      DCHECK_NULL(merge_states_[offset]);
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "- Creating exception merge state at @" << offset
                  << (was_used ? "" : " (never used)") << ", context register r"
                  << context_reg.index() << std::endl;
      }
      merge_states_[offset] = MergePointInterpreterFrameState::NewForCatchBlock(
          *compilation_unit_, liveness, offset, was_used, context_reg, graph_);
    }
  }
}

namespace {

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper;

// Terminal cases
template <int index>
struct GetResultLocationAndSizeHelper<index> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // TODO(leszeks): This should probably actually be "UNREACHABLE" but we have
    // lazy deopt info for interrupt budget updates at returns, not for actual
    // lazy deopts, but just for stack iteration purposes.
    return {interpreter::Register::invalid_value(), 0};
  }
  static bool HasOutputRegisterOperand() { return false; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<index, interpreter::OperandType::kRegOut,
                                      operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    return {iterator.GetRegisterOperand(index), 1};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutPair, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    return {iterator.GetRegisterOperand(index), 2};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutTriple, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    // We shouldn't have any other output operands than this one.
    DCHECK(!(GetResultLocationAndSizeHelper<
             index + 1, operands...>::HasOutputRegisterOperand()));
    return {iterator.GetRegisterOperand(index), 3};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

// We don't support RegOutList for lazy deopts.
template <int index, interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<
    index, interpreter::OperandType::kRegOutList, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    interpreter::RegisterList list = iterator.GetRegisterListOperand(index);
    return {list.first_register(), list.register_count()};
  }
  static bool HasOutputRegisterOperand() { return true; }
};

// Induction case.
template <int index, interpreter::OperandType operand,
          interpreter::OperandType... operands>
struct GetResultLocationAndSizeHelper<index, operand, operands...> {
  static std::pair<interpreter::Register, int> GetResultLocationAndSize(
      const interpreter::BytecodeArrayIterator& iterator) {
    return GetResultLocationAndSizeHelper<
        index + 1, operands...>::GetResultLocationAndSize(iterator);
  }
  static bool HasOutputRegisterOperand() {
    return GetResultLocationAndSizeHelper<
        index + 1, operands...>::HasOutputRegisterOperand();
  }
};

template <interpreter::Bytecode bytecode,
          interpreter::ImplicitRegisterUse implicit_use,
          interpreter::OperandType... operands>
std::pair<interpreter::Register, int> GetResultLocationAndSizeForBytecode(
    const interpreter::BytecodeArrayIterator& iterator) {
  // We don't support output registers for implicit registers.
  DCHECK(!interpreter::BytecodeOperands::WritesImplicitRegister(implicit_use));
  if (interpreter::BytecodeOperands::WritesAccumulator(implicit_use)) {
    // If we write the accumulator, we shouldn't also write an output register.
    DCHECK(!(GetResultLocationAndSizeHelper<
             0, operands...>::HasOutputRegisterOperand()));
    return {interpreter::Register::virtual_accumulator(), 1};
  }

  // Use template magic to output a the appropriate GetRegisterOperand call and
  // size for this bytecode.
  return GetResultLocationAndSizeHelper<
      0, operands...>::GetResultLocationAndSize(iterator);
}

}  // namespace

std::pair<interpreter::Register, int>
MaglevGraphBuilder::GetResultLocationAndSize() const {
  using Bytecode = interpreter::Bytecode;
  using OperandType = interpreter::OperandType;
  using ImplicitRegisterUse = interpreter::ImplicitRegisterUse;
  Bytecode bytecode = iterator_.current_bytecode();
  // TODO(leszeks): Only emit these cases for bytecodes we know can lazy deopt.
  switch (bytecode) {
#define CASE(Name, ...)                                           \
  case Bytecode::k##Name:                                         \
    return GetResultLocationAndSizeForBytecode<Bytecode::k##Name, \
                                               __VA_ARGS__>(iterator_);
    BYTECODE_LIST(CASE, CASE)
#undef CASE
  }
  UNREACHABLE();
}

#ifdef DEBUG
bool MaglevGraphBuilder::HasOutputRegister(interpreter::Register reg) const {
  interpreter::Bytecode bytecode = iterator_.current_bytecode();
  if (reg == interpreter::Register::virtual_accumulator()) {
    return interpreter::Bytecodes::WritesAccumulator(bytecode);
  }
  for (int i = 0; i < interpreter::Bytecodes::NumberOfOperands(bytecode); ++i) {
    if (interpreter::Bytecodes::IsRegisterOutputOperandType(
            interpreter::Bytecodes::GetOperandType(bytecode, i))) {
      interpreter::Register operand_reg = iterator_.GetRegisterOperand(i);
      int operand_range = iterator_.GetRegisterOperandRange(i);
      if (base::IsInRange(reg.index(), operand_reg.index(),
                          operand_reg.index() + operand_range)) {
        return true;
      }
    }
  }
  return false;
}
#endif

DeoptFrame* MaglevGraphBuilder::GetParentDeoptFrame() {
  if (parent_ == nullptr) return nullptr;
  if (parent_deopt_frame_ == nullptr) {
    // The parent resumes after the call, which is roughly equivalent to a lazy
    // deopt. Use the helper function directly so that we can mark the
    // accumulator as dead (since it'll be overwritten by this function's
    // return value anyway).
    // TODO(leszeks): This is true for our current set of
    // inlinings/continuations, but there might be cases in the future where it
    // isn't. We may need to store the relevant overwritten register in
    // LazyDeoptFrameScope.
    DCHECK(interpreter::Bytecodes::WritesAccumulator(
        parent_->iterator_.current_bytecode()));

    parent_deopt_frame_ =
        zone()->New<DeoptFrame>(parent_->GetDeoptFrameForLazyDeoptHelper(
            interpreter::Register::invalid_value(), 0,
            parent_->current_deopt_scope_, true));
    // Only create InlinedArgumentsDeoptFrame if we have a mismatch between
    // formal parameter and arguments count.
    if (HasMismatchedArgumentAndParameterCount()) {
      parent_deopt_frame_ = zone()->New<InlinedArgumentsDeoptFrame>(
          *compilation_unit_, caller_bytecode_offset_, GetClosure(),
          inlined_arguments_, parent_deopt_frame_);
      AddDeoptUse(GetClosure());
      for (ValueNode* arg :
           parent_deopt_frame_->as_inlined_arguments().arguments()) {
        AddDeoptUse(arg);
      }
    }
  }
  return parent_deopt_frame_;
}

DeoptFrame MaglevGraphBuilder::GetLatestCheckpointedFrame() {
  if (in_prologue_) {
    return GetDeoptFrameForEntryStackCheck();
  }
  if (!latest_checkpointed_frame_) {
    current_interpreter_frame_.virtual_objects().Snapshot();
    latest_checkpointed_frame_.emplace(InterpretedDeoptFrame(
        *compilation_unit_,
        zone()->New<CompactInterpreterFrameState>(
            *compilation_unit_, GetInLiveness(), current_interpreter_frame_),
        GetClosure(), BytecodeOffset(iterator_.current_offset()),
        current_source_position_, GetParentDeoptFrame()));

    latest_checkpointed_frame_->as_interpreted().frame_state()->ForEachValue(
        *compilation_unit_,
        [&](ValueNode* node, interpreter::Register) { AddDeoptUse(node); });
    AddDeoptUse(latest_checkpointed_frame_->as_interpreted().closure());

    // Skip lazy deopt builtin continuations.
    const DeoptFrameScope* deopt_scope = current_deopt_scope_;
    while (deopt_scope != nullptr &&
           deopt_scope->IsLazyDeoptContinuationFrame()) {
      deopt_scope = deopt_scope->parent();
    }

    if (deopt_scope != nullptr) {
      // Support exactly one eager deopt builtin continuation. This can be
      // expanded in the future if necessary.
      DCHECK_NULL(deopt_scope->parent());
      DCHECK_EQ(deopt_scope->data().tag(),
                DeoptFrame::FrameType::kBuiltinContinuationFrame);
#ifdef DEBUG
      if (deopt_scope->data().tag() ==
          DeoptFrame::FrameType::kBuiltinContinuationFrame) {
        const DeoptFrame::BuiltinContinuationFrameData& frame =
            deopt_scope->data().get<DeoptFrame::BuiltinContinuationFrameData>();
        if (frame.maybe_js_target) {
          int stack_parameter_count =
              Builtins::GetStackParameterCount(frame.builtin_id);
          DCHECK_EQ(stack_parameter_count, frame.parameters.length());
        } else {
          CallInterfaceDescriptor descriptor =
              Builtins::CallInterfaceDescriptorFor(frame.builtin_id);
          DCHECK_EQ(descriptor.GetParameterCount(), frame.parameters.length());
        }
      }
#endif

      // Wrap the above frame in the scope frame.
      latest_checkpointed_frame_.emplace(
          deopt_scope->data(),
          zone()->New<DeoptFrame>(*latest_checkpointed_frame_));
    }
  }
  return *latest_checkpointed_frame_;
}

DeoptFrame MaglevGraphBuilder::GetDeoptFrameForLazyDeopt(
    interpreter::Register result_location, int result_size) {
  return GetDeoptFrameForLazyDeoptHelper(result_location, result_size,
                                         current_deopt_scope_, false);
}

DeoptFrame MaglevGraphBuilder::GetDeoptFrameForLazyDeoptHelper(
    interpreter::Register result_location, int result_size,
    DeoptFrameScope* scope, bool mark_accumulator_dead) {
  if (scope == nullptr) {
    compiler::BytecodeLivenessState* liveness =
        zone()->New<compiler::BytecodeLivenessState>(*GetOutLiveness(), zone());
    // Remove result locations from liveness.
    if (result_location == interpreter::Register::virtual_accumulator()) {
      DCHECK_EQ(result_size, 1);
      liveness->MarkAccumulatorDead();
      mark_accumulator_dead = false;
    } else {
      DCHECK(!result_location.is_parameter());
      for (int i = 0; i < result_size; i++) {
        liveness->MarkRegisterDead(result_location.index() + i);
      }
    }
    // Explicitly drop the accumulator if needed.
    if (mark_accumulator_dead && liveness->AccumulatorIsLive()) {
      liveness->MarkAccumulatorDead();
    }
    current_interpreter_frame_.virtual_objects().Snapshot();
    InterpretedDeoptFrame ret(
        *compilation_unit_,
        zone()->New<CompactInterpreterFrameState>(*compilation_unit_, liveness,
                                                  current_interpreter_frame_),
        GetClosure(), BytecodeOffset(iterator_.current_offset()),
        current_source_position_, GetParentDeoptFrame());
    ret.frame_state()->ForEachValue(
        *compilation_unit_, [this](ValueNode* node, interpreter::Register reg) {
          // Receiver and closure values have to be materialized, even if
          // they don't otherwise escape.
          if (reg == interpreter::Register::receiver() ||
              reg == interpreter::Register::function_closure()) {
            node->add_use();
          } else {
            AddDeoptUse(node);
          }
        });
    AddDeoptUse(ret.closure());
    return ret;
  }

  // Currently only support builtin continuations for bytecodes that write to
  // the accumulator
  DCHECK(interpreter::Bytecodes::WritesOrClobbersAccumulator(
      iterator_.current_bytecode()));

#ifdef DEBUG
  if (scope->data().tag() == DeoptFrame::FrameType::kBuiltinContinuationFrame) {
    const DeoptFrame::BuiltinContinuationFrameData& frame =
        current_deopt_scope_->data()
            .get<DeoptFrame::BuiltinContinuationFrameData>();
    if (frame.maybe_js_target) {
      int stack_parameter_count =
          Builtins::GetStackParameterCount(frame.builtin_id);
      // The deopt input value is passed by the deoptimizer, so shouldn't be a
      // parameter here.
      DCHECK_EQ(stack_parameter_count, frame.parameters.length() + 1);
    } else {
      CallInterfaceDescriptor descriptor =
          Builtins::CallInterfaceDescriptorFor(frame.builtin_id);
      // The deopt input value is passed by the deoptimizer, so shouldn't be a
      // parameter here.
      DCHECK_EQ(descriptor.GetParameterCount(), frame.parameters.length() + 1);
      // The deopt input value is passed on the stack.
      DCHECK_GT(descriptor.GetStackParameterCount(), 0);
    }
  }
#endif

  // Mark the accumulator dead in parent frames since we know that the
  // continuation will write it.
  return DeoptFrame(scope->data(),
                    zone()->New<DeoptFrame>(GetDeoptFrameForLazyDeoptHelper(
                        result_location, result_size, scope->parent(),
                        scope->data().tag() ==
                            DeoptFrame::FrameType::kBuiltinContinuationFrame)));
}

InterpretedDeoptFrame MaglevGraphBuilder::GetDeoptFrameForEntryStackCheck() {
  if (entry_stack_check_frame_) return *entry_stack_check_frame_;
  DCHECK_EQ(iterator_.current_offset(), entrypoint_);
  DCHECK_NULL(parent_);
  entry_stack_check_frame_.emplace(
      *compilation_unit_,
      zone()->New<CompactInterpreterFrameState>(
          *compilation_unit_,
          GetInLivenessFor(graph_->is_osr() ? bailout_for_entrypoint() : 0),
          current_interpreter_frame_),
      GetClosure(), BytecodeOffset(bailout_for_entrypoint()),
      current_source_position_, nullptr);

  (*entry_stack_check_frame_)
      .frame_state()
      ->ForEachValue(
          *compilation_unit_,
          [&](ValueNode* node, interpreter::Register) { AddDeoptUse(node); });
  AddDeoptUse((*entry_stack_check_frame_).closure());
  return *entry_stack_check_frame_;
}

ValueNode* MaglevGraphBuilder::GetTaggedValue(
    ValueNode* value, UseReprHintRecording record_use_repr_hint) {
  if (V8_LIKELY(record_use_repr_hint == UseReprHintRecording::kRecord)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
  }

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kTagged) return value;

  if (Int32Constant* as_int32_constant = value->TryCast<Int32Constant>();
      as_int32_constant && Smi::IsValid(as_int32_constant->value())) {
    return GetSmiConstant(as_int32_constant->value());
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.tagged()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kInt32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagInt32>({value}));
      }
      return alternative.set_tagged(AddNewNode<Int32ToNumber>({value}));
    }
    case ValueRepresentation::kUint32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagUint32>({value}));
      }
      return alternative.set_tagged(AddNewNode<Uint32ToNumber>({value}));
    }
    case ValueRepresentation::kFloat64: {
      return alternative.set_tagged(AddNewNode<Float64ToTagged>(
          {value}, Float64ToTagged::ConversionMode::kCanonicalizeSmi));
    }
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_tagged(AddNewNode<HoleyFloat64ToTagged>(
          {value}, HoleyFloat64ToTagged::ConversionMode::kForceHeapNumber));
    }

    case ValueRepresentation::kTagged:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

ReduceResult MaglevGraphBuilder::GetSmiValue(
    ValueNode* value, UseReprHintRecording record_use_repr_hint) {
  if (V8_LIKELY(record_use_repr_hint == UseReprHintRecording::kRecord)) {
    RecordUseReprHintIfPhi(value, UseRepresentation::kTagged);
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kTagged) {
    return BuildCheckSmi(value, !value->Is<Phi>());
  }

  auto& alternative = node_info->alternative();

  if (ValueNode* alt = alternative.tagged()) {
    // HoleyFloat64ToTagged does not canonicalize Smis by default, since it can
    // be expensive. If we are reading a Smi value, we should try to
    // canonicalize now.
    if (HoleyFloat64ToTagged* conversion_node =
            alt->TryCast<HoleyFloat64ToTagged>()) {
      conversion_node->SetMode(
          HoleyFloat64ToTagged::ConversionMode::kCanonicalizeSmi);
    }
    return BuildCheckSmi(alt, !value->Is<Phi>());
  }

  switch (representation) {
    case ValueRepresentation::kInt32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagInt32>({value}));
      }
      return alternative.set_tagged(AddNewNode<CheckedSmiTagInt32>({value}));
    }
    case ValueRepresentation::kUint32: {
      if (NodeTypeIsSmi(node_info->type())) {
        return alternative.set_tagged(AddNewNode<UnsafeSmiTagUint32>({value}));
      }
      return alternative.set_tagged(AddNewNode<CheckedSmiTagUint32>({value}));
    }
    case ValueRepresentation::kFloat64: {
      return alternative.set_tagged(AddNewNode<CheckedSmiTagFloat64>({value}));
    }
    case ValueRepresentation::kHoleyFloat64: {
      return alternative.set_tagged(AddNewNode<CheckedSmiTagFloat64>({value}));
    }

    case ValueRepresentation::kTagged:
    case ValueRepresentation::kIntPtr:
      UNREACHABLE();
  }
  UNREACHABLE();
}

namespace {
CheckType GetCheckType(NodeType type) {
  return NodeTypeIs(type, NodeType::kAnyHeapObject)
             ? CheckType::kOmitHeapObjectCheck
             : CheckType::kCheckHeapObject;
}
}  // namespace

ValueNode* MaglevGraphBuilder::GetInternalizedString(
    interpreter::Register reg) {
  ValueNode* node = current_interpreter_frame_.get(reg);
  NodeType old_type;
  if (CheckType(node, NodeType::kInternalizedString, &old_type)) return node;
  NodeInfo* known_info = GetOrCreateInfoFor(node);
  if (known_info->alternative().checked_value()) {
    node = known_info->alternative().checked_value();
    if (CheckType(node, NodeType::kInternalizedString, &old_type)) return node;
  }

  if (!NodeTypeIs(old_type, NodeType::kString)) {
    known_info->CombineType(NodeType::kString);
  }

  // This node may unwrap ThinStrings.
  ValueNode* maybe_unwrapping_node =
      AddNewNode<CheckedInternalizedString>({node}, GetCheckType(old_type));
  known_info->alternative().set_checked_value(maybe_unwrapping_node);

  current_interpreter_frame_.set(reg, maybe_unwrapping_node);
  return maybe_unwrapping_node;
}

namespace {
NodeType ToNumberHintToNodeType(ToNumberHint conversion_type) {
  switch (conversion_type) {
    case ToNumberHint::kAssumeSmi:
      return NodeType::kSmi;
    case ToNumberHint::kDisallowToNumber:
    case ToNumberHint::kAssumeNumber:
      return NodeType::kNumber;
    case ToNumberHint::kAssumeNumberOrBoolean:
      return NodeType::kNumberOrBoolean;
    case ToNumberHint::kAssumeNumberOrOddball:
      return NodeType::kNumberOrOddball;
  }
}
TaggedToFloat64ConversionType ToNumberHintToConversionType(
    ToNumberHint conversion_type) {
  switch (conversion_type) {
    case ToNumberHint::kAssumeSmi:
      UNREACHABLE();
    case ToNumberHint::kDisallowToNumber:
    case ToNumberHint::kAssumeNumber:
      return TaggedToFloat64ConversionType::kOnlyNumber;
    case ToNumberHint::kAssumeNumberOrOddball:
      return TaggedToFloat64ConversionType::kNumberOrOddball;
    case ToNumberHint::kAssumeNumberOrBoolean:
      return TaggedToFloat64ConversionType::kNumberOrBoolean;
  }
}
}  // namespace

ValueNode* MaglevGraphBuilder::GetTruncatedInt32ForToNumber(ValueNode* value,
                                                            ToNumberHint hint) {
  RecordUseReprHintIfPhi(value, UseRepresentation::kTruncatedInt32);

  ValueRepresentation representation =
      value->properties().value_representation();
  if (representation == ValueRepresentation::kInt32) return value;
  if (representation == ValueRepresentation::kUint32) {
    // This node is cheap (no code gen, just a bitcast), so don't cache it.
    return AddNewNode<TruncateUint32ToInt32>({value});
  }

  // Process constants first to avoid allocating NodeInfo for them.
  switch (value->opcode()) {
    case Opcode::kConstant: {
      compiler::ObjectRef object = value->Cast<Constant>()->object();
      if (!object.IsHeapNumber()) break;
      int32_t truncated_value = DoubleToInt32(object.AsHeapNumber().value());
      if (!Smi::IsValid(truncated_value)) break;
      return GetInt32Constant(truncated_value);
    }
    case Opcode::kSmiConstant:
      return GetInt32Constant(value->Cast<SmiConstant>()->value().value());
    case Opcode::kRootConstant: {
      Tagged<Object> root_object =
          local_isolate_->root(value->Cast<RootConstant>()->index());
      if (!IsOddball(root_object, local_isolate_)) break;
      int32_t truncated_value =
          DoubleToInt32(Cast<Oddball>(root_object)->to_number_raw());
      // All oddball ToNumber truncations are valid Smis.
      DCHECK(Smi::IsValid(truncated_value));
      return GetInt32Constant(truncated_value);
    }
    case Opcode::kFloat64Constant: {
      int32_t truncated_value =
          DoubleToInt32(value->Cast<Float64Constant>()->value().get_scalar());
      if (!Smi::IsValid(truncated_value)) break;
      return GetInt32Constant(truncated_value);
    }

    // We could emit unconditional eager deopts for other kinds of constant, but
    // it's not necessary, the appropriate checking conversion nodes will deopt.
    default:
      break;
  }

  NodeInfo* node_info = GetOrCreateInfoFor(value);
  auto& alternative = node_info->alternative();

  // If there is an int32_alternative, then that works as a truncated value
  // too.
  if (ValueNode* alt = alternative.int32()) {
    return alt;
  }
  if (ValueNode* alt = alternative.truncated_int32_to_number()) {
    return alt;
  }

  switch (representation) {
    case ValueRepresentation::kTagged: {
      NodeType old_type;
      NodeType desired_type = ToNumberHintToNodeType(hint);
      EnsureType(value, desired_type, &old_type);
      if (NodeTypeIsSmi(old_type)) {
        // Smi untagging can be cached as an int32 alternative, not just a
        // tr
```
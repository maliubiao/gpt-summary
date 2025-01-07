Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/bytecode-graph-builder.cc`.

Here's a breakdown of the thought process to achieve the desired output:

1. **Identify the core purpose:** The code is part of the V8 compiler and deals with transforming bytecode into a graph representation. The class name `BytecodeGraphBuilder` strongly suggests this.

2. **Analyze the key classes and their roles:**
    * `BytecodeGraphBuilder`:  The central class responsible for the overall transformation process. It manages the environment, iterates through bytecode, creates graph nodes, and handles control flow.
    * `Environment`:  Manages the current state of the compilation process, including the values of registers, the accumulator, the context, and control/effect dependencies. It also handles merging environments at control flow join points.
    * `BytecodeAnalysis`: (Although not directly in this snippet, it's mentioned and crucial)  Provides information about the bytecode, such as loop structure and liveness analysis.

3. **Deconstruct the functionalities of `BytecodeGraphBuilder`:**
    * **Initialization:**  The constructor sets up the necessary data structures and references.
    * **Graph Construction:**  `CreateGraph` is the main entry point for building the graph. It involves setting up the start and end nodes, iterating through bytecode, and creating nodes for each bytecode instruction.
    * **Bytecode Iteration:**  The `VisitBytecodes` and `VisitSingleBytecode` methods handle the step-by-step processing of bytecode instructions.
    * **Node Creation:**  Methods like `NewNode` and specific `Visit` methods (e.g., `VisitLdaZero`) are responsible for creating nodes in the graph based on bytecode instructions.
    * **Environment Management:**  The `environment()` member and related methods (`set_environment`) manage the current compilation state.
    * **Control Flow:**  Methods related to merging environments (`Merge`), handling loops (`PrepareForLoop`, `PrepareForLoopExit`), and exception handling (although not heavily present in this snippet) indicate control flow management.
    * **Optimization Hints/Feedback:**  The interaction with `FeedbackVector` and `FeedbackSource` shows the use of runtime feedback to guide optimization.
    * **On-Stack Replacement (OSR):** The code specifically handles OSR, a mechanism for optimizing functions while they are already running.
    * **Frame States:** The `PrepareFrameState` and `Checkpoint` methods are involved in creating frame states for deoptimization and debugging.

4. **Deconstruct the functionalities of `Environment`:**
    * **State Storage:**  It holds the current values of registers, the accumulator, and the context.
    * **Dependency Tracking:**  It maintains control and effect dependencies.
    * **Merging:** The `Merge` method is crucial for handling control flow merges, creating Phi nodes.
    * **Loop Handling:**  `PrepareForLoop` and `PrepareForLoopExit` set up the environment for loop constructs.
    * **OSR Value Initialization:** `FillWithOsrValues` is specific to OSR.
    * **Frame State Management:** It interacts with `BytecodeGraphBuilder` to create frame states.

5. **Address the specific questions in the prompt:**
    * **Listing functionalities:**  Summarize the main actions performed by the code based on the analysis above.
    * **Torque:**  The prompt provides the information that a `.tq` extension indicates a Torque file, and since the extension is `.cc`, it's not Torque.
    * **JavaScript relation:**  Connect the bytecode instructions (like `LdaZero`, `LdaConstant`, `Star`) to their corresponding JavaScript operations (loading constants, variables, etc.). Provide simple examples.
    * **Code logic/inference:**  Focus on the merging logic in the `Environment::Merge` method. Create a simple scenario with different register values converging at a point and show how Phi nodes are used.
    * **Common programming errors:** Relate the frame state and checkpointing mechanisms to potential issues like incorrect deoptimization or debugging information if frame states are not managed correctly.
    * **Summarization (Part 2):** Reiterate the core responsibility of the code snippet, focusing on environment management and control flow handling within the graph building process.

6. **Structure the output:** Organize the information clearly with headings and bullet points for readability. Use code examples in JavaScript and pseudocode for the merging logic.

7. **Refine and review:** Ensure the accuracy and completeness of the summary. Check for any missing functionalities or misinterpretations. For instance, initially, the focus might be too much on individual bytecode instructions. It's important to elevate the perspective and describe the overarching process. Also, double-check the specifics of OSR and frame states.
这是一个C++源代码文件，属于V8 JavaScript引擎的编译器部分。根据文件名 `bytecode-graph-builder.cc` 可以推断，它的主要功能是将字节码（bytecode）转换为图（graph）的表示形式，这是编译器进行进一步优化和代码生成的基础。

**功能归纳（基于提供的代码片段）：**

这部分代码主要关注 `BytecodeGraphBuilder::Environment` 类的实现，以及 `BytecodeGraphBuilder` 类中与环境管理和部分图构建相关的辅助功能。

**`BytecodeGraphBuilder::Environment` 的功能：**

* **维护编译过程中的状态：** `Environment` 类存储了在将字节码转换为图的过程中需要的各种信息，例如：
    * **控制依赖 (Control Dependency):**  表示代码执行顺序的依赖关系。
    * **效果依赖 (Effect Dependency):** 表示具有副作用的操作的依赖关系。
    * **上下文 (Context):**  当前执行的上下文。
    * **参数 (Parameters):**  函数的参数值。
    * **寄存器值 (Register Values):**  模拟解释器寄存器的值。
    * **累加器值 (Accumulator Value):** 模拟解释器累加器的值。
    * **生成器状态 (Generator State):**  如果当前编译的函数是生成器函数，则存储其状态。
* **记录操作后的状态：** `RecordAfterState` 方法用于在图中的某个节点执行后记录相应的状态，例如附加帧状态 (Frame State)。
* **复制环境：** `Copy` 方法用于创建一个新的、与当前环境相同的环境副本。这在处理分支和循环等控制流结构时非常有用。
* **合并环境：** `Merge` 方法用于将两个不同的环境合并为一个新的环境。这通常发生在控制流汇合点，例如 `if-else` 语句的结束或循环的入口。合并过程中，会对 live 的变量创建 Phi 节点，以表示这些变量可能来自不同的路径。
* **为循环做准备：** `PrepareForLoop` 方法用于在进入循环之前设置环境。它创建循环头节点、效果 Phi 节点以及为循环中可能被修改的变量创建 Phi 节点。
* **填充 OSR 值：** `FillWithOsrValues` 方法在进行 On-Stack Replacement (OSR) 优化时使用，用于为环境中的值创建 OSR 值节点。
* **检查状态值是否需要更新：** `StateValuesRequireUpdate` 方法用于比较当前状态值和新的值，判断是否需要更新状态值节点。
* **为循环退出做准备：** `PrepareForLoopExit` 方法在退出循环时更新环境，为循环中赋值的变量创建 `LoopExitValue` 节点。
* **更新状态值：** `UpdateStateValues` 方法创建一个 `StateValues` 节点，用于存储一组值。
* **从缓存获取状态值：** `GetStateValuesFromCache` 方法尝试从缓存中获取已存在的 `StateValues` 节点，避免重复创建。
* **创建检查点 (Checkpoint):** `Checkpoint` 方法创建一个 `FrameState` 节点，用于在执行到某个点时捕获程序的状态，这对于 deoptimization 和调试非常重要。

**`BytecodeGraphBuilder` 的辅助功能：**

* **获取函数闭包 (Closure):** `GetFunctionClosure` 方法用于获取当前正在编译的函数的闭包对象。
* **获取参数：** `GetParameter` 方法用于创建或获取表示函数参数的图节点。
* **创建反馈向量节点 (Feedback Vector Node):** `CreateFeedbackVectorNode` 用于创建表示反馈向量的常量节点。
* **构建加载反馈单元 (Load Feedback Cell):** `BuildLoadFeedbackCell` 用于创建加载反馈单元的节点。
* **创建原生上下文节点 (Native Context Node):** `CreateNativeContextNode` 用于创建表示原生上下文的常量节点。
* **构建加载原生上下文字段 (Load Native Context Field):** `BuildLoadNativeContextField` 用于创建加载原生上下文特定字段的节点.
* **创建反馈源 (Feedback Source):** `CreateFeedbackSource` 用于创建表示反馈信息的对象。
* **创建和管理图 (Graph):** `CreateGraph` 是构建图的主要入口点，它初始化图结构，并调用 `VisitBytecodes` 来遍历字节码并构建相应的图节点。
* **准备 Eager Checkpoint:** `PrepareEagerCheckpoint` 用于在某些操作之前创建一个显式的检查点节点。
* **准备帧状态 (Frame State):** `PrepareFrameState` 用于为指定的节点添加帧状态输入。
* **前进迭代器：** `AdvanceIteratorsTo` 用于将字节码和源码位置迭代器移动到指定的偏移量。
* **处理 OSR：**  `AdvanceToOsrEntryAndPeelLoops` 用于处理 On-Stack Replacement (OSR) 优化，它会部分地构建包含 OSR 入口点的外层循环的图。
* **访问单个字节码：** `VisitSingleBytecode` 根据当前字节码的类型调用相应的 `Visit` 方法来创建图节点。
* **访问所有字节码：** `VisitBytecodes` 迭代字节码数组并调用 `VisitSingleBytecode` 来构建完整的图。
* **添加/移除字节码位置装饰器：** `AddBytecodePositionDecorator` 和 `RemoveBytecodePositionDecorator` 用于在图节点上记录其对应的字节码位置信息。
* **访问各种加载指令 (Lda...):** `VisitLdaZero`, `VisitLdaSmi`, `VisitLdaConstant` 等方法用于处理加载不同类型值的字节码指令。
* **访问存储指令 (Star, Mov):** `VisitStar`, `VisitMov` 等方法用于处理将值存储到寄存器的字节码指令。
* **构建加载全局变量 (Load Global):** `BuildLoadGlobal` 用于创建加载全局变量的节点。

**关于文件扩展名和 Torque：**

你提供的信息是正确的。如果 `v8/src/compiler/bytecode-graph-builder.cc` 文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是 V8 用来定义一些底层操作和内置函数的领域特定语言。由于该文件以 `.cc` 结尾，它是一个标准的 C++ 源代码文件。

**与 JavaScript 功能的关系及示例：**

`bytecode-graph-builder.cc` 的核心功能是将 JavaScript 代码编译成机器码的过程中，将中间表示形式（字节码）转换为更适合优化的图结构。 每一种字节码指令通常对应着一个或多个 JavaScript 的操作。

**JavaScript 示例：**

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 编译这段 `add` 函数时，会生成相应的字节码。 `bytecode-graph-builder.cc` 的功能就是将这些字节码指令转换成图节点。例如，字节码中可能包含：

* `Ldar r0` (加载寄存器 r0 的值到累加器，对应 `a`)
* `Ldar r1` (加载寄存器 r1 的值到累加器，对应 `b`)
* `Add` (执行加法操作)
* `Return` (返回累加器中的值)

`BytecodeGraphBuilder` 会为这些字节码指令创建相应的图节点，例如：

* 一个表示加载 `a` 值的节点。
* 一个表示加载 `b` 值的节点。
* 一个表示加法运算的节点，其输入是前两个节点。
* 一个表示返回操作的节点，其输入是加法运算的结果。

**代码逻辑推理和假设输入/输出：**

以 `Environment::Merge` 方法为例，假设我们有两个 `Environment` 对象 `env1` 和 `env2`，它们代表了 `if-else` 语句的两个不同分支结束时的状态。

**假设输入：**

* `env1`:
    * 寄存器 `r0` 的值为节点 `NodeA` (代表值 10)
    * 寄存器 `r1` 的值为节点 `NodeB` (代表值 20)
    * 控制依赖为节点 `ControlFlowA`
* `env2`:
    * 寄存器 `r0` 的值为节点 `NodeC` (代表值 30)
    * 寄存器 `r1` 的值为节点 `NodeB` (代表值 20)
    * 控制依赖为节点 `ControlFlowB`
* `liveness`: 指示哪些寄存器在合并点是 live 的。假设 `r0` 和 `r1` 都是 live 的。

**输出：**

合并后的 `Environment` 对象：

* 控制依赖为 `Phi(ControlFlowA, ControlFlowB)`  (一个合并控制流的 Phi 节点)
* 寄存器 `r0` 的值为 `Phi(NodeA, NodeC)` (一个新的 Phi 节点，表示 `r0` 的值可能是 10 或 30)
* 寄存器 `r1` 的值为 `NodeB` (由于两个环境中的值相同，不需要创建 Phi 节点)

**用户常见的编程错误示例：**

与这部分代码相关的常见编程错误通常发生在编译器开发或 V8 引擎的内部修改中，普通 JavaScript 开发者不太会直接遇到。但是，理解其背后的原理可以帮助理解一些与性能相关的问题。

例如，如果 `BytecodeGraphBuilder` 在构建图的过程中错误地处理了帧状态 (Frame State)，那么在发生错误需要进行 deoptimization (反优化) 时，可能无法正确地恢复程序的原始状态，导致程序崩溃或行为异常。

另一个例子是，如果循环的 `PrepareForLoop` 和 `PrepareForLoopExit` 方法处理不当，可能会导致循环相关的优化出现问题，例如循环体内的变量没有正确地通过 Phi 节点传递，导致计算结果错误。

**总结 (针对第 2 部分):**

这部分代码主要定义了 `BytecodeGraphBuilder::Environment` 类，该类负责维护将字节码转换为图的过程中所需的各种状态信息，并提供了合并、复制、以及为循环和 OSR 做准备等操作。同时，展示了 `BytecodeGraphBuilder` 类中与环境管理和基本图节点创建相关的一些辅助方法。  其核心功能是为后续的图优化和代码生成奠定基础。

Prompt: 
```
这是目录为v8/src/compiler/bytecode-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/bytecode-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
ulator_base_ - values_index));
  }
  for (int i = 0; i < node->op()->ValueOutputCount(); i++) {
    values()->at(values_index + i) =
        builder()->NewNode(common()->Projection(i), node);
  }
}

void BytecodeGraphBuilder::Environment::RecordAfterState(
    Node* node, FrameStateAttachmentMode mode) {
  if (mode == FrameStateAttachmentMode::kAttachFrameState) {
    builder()->PrepareFrameState(node, OutputFrameStateCombine::Ignore());
  }
}

BytecodeGraphBuilder::Environment* BytecodeGraphBuilder::Environment::Copy() {
  return zone()->New<Environment>(this);
}

void BytecodeGraphBuilder::Environment::Merge(
    BytecodeGraphBuilder::Environment* other,
    const BytecodeLivenessState* liveness) {
  // Create a merge of the control dependencies of both environments and update
  // the current environment's control dependency accordingly.
  Node* control = builder()->MergeControl(GetControlDependency(),
                                          other->GetControlDependency());
  UpdateControlDependency(control);

  // Create a merge of the effect dependencies of both environments and update
  // the current environment's effect dependency accordingly.
  Node* effect = builder()->MergeEffect(GetEffectDependency(),
                                        other->GetEffectDependency(), control);
  UpdateEffectDependency(effect);

  // Introduce Phi nodes for values that are live and have differing inputs at
  // the merge point, potentially extending an existing Phi node if possible.
  context_ = builder()->MergeValue(context_, other->context_, control);
  for (int i = 0; i < parameter_count(); i++) {
    values_[i] = builder()->MergeValue(values_[i], other->values_[i], control);
  }
  for (int i = 0; i < register_count(); i++) {
    int index = register_base() + i;
    if (liveness == nullptr || liveness->RegisterIsLive(i)) {
#if DEBUG
      // We only do these DCHECKs when we are not in the resume path of a
      // generator -- this is, when either there is no generator state at all,
      // or the generator state is not the constant "executing" value.
      if (generator_state_ == nullptr ||
          NumberMatcher(generator_state_)
              .Is(JSGeneratorObject::kGeneratorExecuting)) {
        DCHECK_NE(values_[index], builder()->jsgraph()->OptimizedOutConstant());
        DCHECK_NE(other->values_[index],
                  builder()->jsgraph()->OptimizedOutConstant());
      }
#endif

      values_[index] =
          builder()->MergeValue(values_[index], other->values_[index], control);

    } else {
      values_[index] = builder()->jsgraph()->OptimizedOutConstant();
    }
  }

  if (liveness == nullptr || liveness->AccumulatorIsLive()) {
    DCHECK_NE(values_[accumulator_base()],
              builder()->jsgraph()->OptimizedOutConstant());
    DCHECK_NE(other->values_[accumulator_base()],
              builder()->jsgraph()->OptimizedOutConstant());

    values_[accumulator_base()] =
        builder()->MergeValue(values_[accumulator_base()],
                              other->values_[accumulator_base()], control);
  } else {
    values_[accumulator_base()] = builder()->jsgraph()->OptimizedOutConstant();
  }

  if (generator_state_ != nullptr) {
    DCHECK_NOT_NULL(other->generator_state_);
    generator_state_ = builder()->MergeValue(generator_state_,
                                             other->generator_state_, control);
  }
}

void BytecodeGraphBuilder::Environment::PrepareForLoop(
    const BytecodeLoopAssignments& assignments,
    const BytecodeLivenessState* liveness) {
  // Create a control node for the loop header.
  Node* control = builder()->NewLoop();

  // Create a Phi for external effects.
  Node* effect = builder()->NewEffectPhi(1, GetEffectDependency(), control);
  UpdateEffectDependency(effect);

  // Create Phis for any values that are live on entry to the loop and may be
  // updated by the end of the loop.
  context_ = builder()->NewPhi(1, context_, control);
  for (int i = 0; i < parameter_count(); i++) {
    if (assignments.ContainsParameter(i)) {
      values_[i] = builder()->NewPhi(1, values_[i], control);
    }
  }
  for (int i = 0; i < register_count(); i++) {
    if (assignments.ContainsLocal(i) &&
        (liveness == nullptr || liveness->RegisterIsLive(i))) {
      int index = register_base() + i;
      values_[index] = builder()->NewPhi(1, values_[index], control);
    }
  }
  // The accumulator should not be live on entry.
  DCHECK_IMPLIES(liveness != nullptr, !liveness->AccumulatorIsLive());

  if (generator_state_ != nullptr) {
    generator_state_ = builder()->NewPhi(1, generator_state_, control);
  }

  // Connect to the loop end.
  Node* terminate = builder()->graph()->NewNode(
      builder()->common()->Terminate(), effect, control);
  builder()->exit_controls_.push_back(terminate);
}

void BytecodeGraphBuilder::Environment::FillWithOsrValues() {
  Node* start = graph()->start();

  // Create OSR values for each environment value.
  SetContext(graph()->NewNode(
      common()->OsrValue(Linkage::kOsrContextSpillSlotIndex), start));
  int size = static_cast<int>(values()->size());
  for (int i = 0; i < size; i++) {
    int idx = i;  // Indexing scheme follows {StandardFrame}, adapt accordingly.
    if (i >= register_base()) idx += InterpreterFrameConstants::kExtraSlotCount;
    if (i >= accumulator_base()) idx = Linkage::kOsrAccumulatorRegisterIndex;
    values()->at(i) = graph()->NewNode(common()->OsrValue(idx), start);
  }
}

bool BytecodeGraphBuilder::Environment::StateValuesRequireUpdate(
    Node** state_values, Node** values, int count) {
  if (*state_values == nullptr) {
    return true;
  }
  Node::Inputs inputs = (*state_values)->inputs();
  if (inputs.count() != count) return true;
  for (int i = 0; i < count; i++) {
    if (inputs[i] != values[i]) {
      return true;
    }
  }
  return false;
}

void BytecodeGraphBuilder::Environment::PrepareForLoopExit(
    Node* loop, const BytecodeLoopAssignments& assignments,
    const BytecodeLivenessState* liveness) {
  DCHECK_EQ(loop->opcode(), IrOpcode::kLoop);

  Node* control = GetControlDependency();

  // Create the loop exit node.
  Node* loop_exit = graph()->NewNode(common()->LoopExit(), control, loop);
  UpdateControlDependency(loop_exit);

  // Rename the effect.
  Node* effect_rename = graph()->NewNode(common()->LoopExitEffect(),
                                         GetEffectDependency(), loop_exit);
  UpdateEffectDependency(effect_rename);

  // TODO(jarin) We should also rename context here. However, unconditional
  // renaming confuses global object and native context specialization.
  // We should only rename if the context is assigned in the loop.

  // Rename the environment values if they were assigned in the loop and are
  // live after exiting the loop.
  for (int i = 0; i < parameter_count(); i++) {
    if (assignments.ContainsParameter(i)) {
      Node* rename = graph()->NewNode(
          common()->LoopExitValue(MachineRepresentation::kTagged), values_[i],
          loop_exit);
      values_[i] = rename;
    }
  }
  for (int i = 0; i < register_count(); i++) {
    if (assignments.ContainsLocal(i) &&
        (liveness == nullptr || liveness->RegisterIsLive(i))) {
      Node* rename = graph()->NewNode(
          common()->LoopExitValue(MachineRepresentation::kTagged),
          values_[register_base() + i], loop_exit);
      values_[register_base() + i] = rename;
    }
  }
  if (liveness == nullptr || liveness->AccumulatorIsLive()) {
    Node* rename = graph()->NewNode(
        common()->LoopExitValue(MachineRepresentation::kTagged),
        values_[accumulator_base()], loop_exit);
    values_[accumulator_base()] = rename;
  }

  if (generator_state_ != nullptr) {
    generator_state_ = graph()->NewNode(
        common()->LoopExitValue(MachineRepresentation::kTagged),
        generator_state_, loop_exit);
  }
}

void BytecodeGraphBuilder::Environment::UpdateStateValues(Node** state_values,
                                                          Node** values,
                                                          int count) {
  if (StateValuesRequireUpdate(state_values, values, count)) {
    const Operator* op = common()->StateValues(count, SparseInputMask::Dense());
    (*state_values) = graph()->NewNode(op, count, values);
  }
}

Node* BytecodeGraphBuilder::Environment::GetStateValuesFromCache(
    Node** values, int count, const BytecodeLivenessState* liveness) {
  return builder_->state_values_cache_.GetNodeForValues(
      values, static_cast<size_t>(count), liveness);
}

Node* BytecodeGraphBuilder::Environment::Checkpoint(
    BytecodeOffset bailout_id, OutputFrameStateCombine combine,
    const BytecodeLivenessState* liveness) {
  if (parameter_count() == register_count()) {
    // Re-use the state-value cache if the number of local registers happens
    // to match the parameter count.
    parameters_state_values_ =
        GetStateValuesFromCache(&values()->at(0), parameter_count(), nullptr);
  } else {
    UpdateStateValues(&parameters_state_values_, &values()->at(0),
                      parameter_count());
  }

  Node* registers_state_values = GetStateValuesFromCache(
      &values()->at(register_base()), register_count(), liveness);

  bool accumulator_is_live = !liveness || liveness->AccumulatorIsLive();
  Node* accumulator_state_value =
      accumulator_is_live && combine != OutputFrameStateCombine::PokeAt(0)
          ? values()->at(accumulator_base())
          : builder()->jsgraph()->OptimizedOutConstant();

  const Operator* op = common()->FrameState(
      bailout_id, combine, builder()->frame_state_function_info());
  Node* result = graph()->NewNode(
      op, parameters_state_values_, registers_state_values,
      accumulator_state_value, Context(), builder()->GetFunctionClosure(),
      builder()->graph()->start());

  return result;
}

class BytecodeGraphBuilder::BytecodePositionDecorator final :
public GraphDecorator {
 public:
  explicit BytecodePositionDecorator(NodeOriginTable* node_origins)
      :  node_origins_(node_origins) {}

  void Decorate(Node* node) final {
    node_origins_->SetNodeOrigin(node->id(), NodeOrigin::kJSBytecode,
                                 node_origins_->GetCurrentBytecodePosition());
  }

 private:
  NodeOriginTable* node_origins_;
};

BytecodeGraphBuilder::BytecodeGraphBuilder(
    JSHeapBroker* broker, Zone* local_zone, NativeContextRef native_context,
    SharedFunctionInfoRef shared_info, BytecodeArrayRef bytecode,
    FeedbackCellRef feedback_cell, BytecodeOffset osr_offset, JSGraph* jsgraph,
    CallFrequency const& invocation_frequency,
    SourcePositionTable* source_positions, NodeOriginTable* node_origins,
    int inlining_id, CodeKind code_kind, BytecodeGraphBuilderFlags flags,
    TickCounter* tick_counter, ObserveNodeInfo const& observe_node_info)
    : broker_(broker),
      local_isolate_(broker_->local_isolate()
                         ? broker_->local_isolate()
                         : broker_->isolate()->AsLocalIsolate()),
      local_zone_(local_zone),
      jsgraph_(jsgraph),
      native_context_(native_context),
      shared_info_(shared_info),
      bytecode_array_(bytecode),
      feedback_cell_(feedback_cell),
      feedback_vector_(feedback_cell.feedback_vector(broker).value()),
      invocation_frequency_(invocation_frequency),
      type_hint_lowering_(
          broker, jsgraph, feedback_vector_,
          (flags & BytecodeGraphBuilderFlag::kBailoutOnUninitialized)
              ? JSTypeHintLowering::kBailoutOnUninitialized
              : JSTypeHintLowering::kNoFlags),
      frame_state_function_info_(common()->CreateFrameStateFunctionInfo(
          FrameStateType::kUnoptimizedFunction,
          bytecode_array().parameter_count(), bytecode_array().max_arguments(),
          bytecode_array().register_count(), shared_info.object(),
          bytecode_array().object())),
      source_position_iterator_(bytecode_array().SourcePositionTable(broker)),
      bytecode_iterator_(bytecode_array().object()),
      bytecode_analysis_(
          bytecode_array().object(), local_zone, osr_offset,
          flags & BytecodeGraphBuilderFlag::kAnalyzeEnvironmentLiveness),
      environment_(nullptr),
      decorator_(nullptr),
      osr_(!osr_offset.IsNone()),
      currently_peeled_loop_offset_(-1),
      skip_first_stack_and_tierup_check_(
          flags & BytecodeGraphBuilderFlag::kSkipFirstStackAndTierupCheck),
      merge_environments_(local_zone),
      generator_merge_environments_(local_zone),
      cached_parameters_(local_zone),
      exception_handlers_(local_zone),
      current_exception_handler_(0),
      input_buffer_size_(0),
      input_buffer_(nullptr),
      code_kind_(code_kind),
      feedback_vector_node_(nullptr),
      native_context_node_(nullptr),
      needs_eager_checkpoint_(true),
      exit_controls_(local_zone),
      state_values_cache_(jsgraph),
      node_origins_(node_origins),
      source_positions_(source_positions),
      start_position_(shared_info.StartPosition(), inlining_id),
      tick_counter_(tick_counter),
      observe_node_info_(observe_node_info) {}

Node* BytecodeGraphBuilder::GetFunctionClosure() {
  if (!function_closure_.is_set()) {
    int index = Linkage::kJSCallClosureParamIndex;
    Node* node = GetParameter(index, "%closure");
    function_closure_.set(node);
  }
  return function_closure_.get();
}

Node* BytecodeGraphBuilder::GetParameter(int parameter_index,
                                         const char* debug_name_hint) {
  // We use negative indices for some parameters.
  DCHECK_LE(ParameterInfo::kMinIndex, parameter_index);
  const size_t index =
      static_cast<size_t>(parameter_index - ParameterInfo::kMinIndex);

  if (cached_parameters_.size() <= index) {
    cached_parameters_.resize(index + 1, nullptr);
  }

  if (cached_parameters_[index] == nullptr) {
    cached_parameters_[index] =
        NewNode(common()->Parameter(parameter_index, debug_name_hint),
                graph()->start());
  }

  return cached_parameters_[index];
}

void BytecodeGraphBuilder::CreateFeedbackVectorNode() {
  DCHECK_NULL(feedback_vector_node_);
  feedback_vector_node_ =
      jsgraph()->ConstantNoHole(feedback_vector(), broker());
}

Node* BytecodeGraphBuilder::BuildLoadFeedbackCell(int index) {
  return jsgraph()->ConstantNoHole(
      feedback_vector().GetClosureFeedbackCell(broker(), index), broker());
}

void BytecodeGraphBuilder::CreateNativeContextNode() {
  DCHECK_NULL(native_context_node_);
  native_context_node_ = jsgraph()->ConstantNoHole(native_context(), broker());
}

Node* BytecodeGraphBuilder::BuildLoadNativeContextField(int index) {
  Node* result = NewNode(javascript()->LoadContext(0, index, true));
  NodeProperties::ReplaceContextInput(result, native_context_node());
  return result;
}

FeedbackSource BytecodeGraphBuilder::CreateFeedbackSource(int slot_id) {
  return CreateFeedbackSource(FeedbackVector::ToSlot(slot_id));
}

FeedbackSource BytecodeGraphBuilder::CreateFeedbackSource(FeedbackSlot slot) {
  return FeedbackSource(feedback_vector(), slot);
}

void BytecodeGraphBuilder::CreateGraph() {
  SourcePositionTable::Scope pos_scope(source_positions_, start_position_);
  if (node_origins_) {
    AddBytecodePositionDecorator();
  }
  // Set up the basic structure of the graph. Outputs for {Start} are the formal
  // parameters (including the receiver) plus new target, number of arguments,
  // context and closure.
  int start_output_arity = StartNode::OutputArityForFormalParameterCount(
      bytecode_array().parameter_count());
  graph()->SetStart(graph()->NewNode(common()->Start(start_output_arity)));

  Environment env(this, bytecode_array().register_count(),
                  bytecode_array().parameter_count(),
                  bytecode_array().incoming_new_target_or_generator_register(),
                  graph()->start());
  set_environment(&env);

  CreateFeedbackVectorNode();
  CreateNativeContextNode();

  VisitBytecodes();

  // Finish the basic structure of the graph.
  DCHECK_NE(0u, exit_controls_.size());
  int const input_count = static_cast<int>(exit_controls_.size());
  Node** const inputs = &exit_controls_.front();
  Node* end = graph()->NewNode(common()->End(input_count), input_count, inputs);
  graph()->SetEnd(end);
  if (node_origins_) {
    RemoveBytecodePositionDecorator();
  }
}

void BytecodeGraphBuilder::PrepareEagerCheckpoint() {
  if (needs_eager_checkpoint()) {
    // Create an explicit checkpoint node for before the operation. This only
    // needs to happen if we aren't effect-dominated by a {Checkpoint} already.
    mark_as_needing_eager_checkpoint(false);
    Node* node = NewNode(common()->Checkpoint());
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    DCHECK_EQ(IrOpcode::kDead,
              NodeProperties::GetFrameStateInput(node)->opcode());
    BytecodeOffset bailout_id(bytecode_iterator().current_offset());

    const BytecodeLivenessState* liveness_before =
        bytecode_analysis().GetInLivenessFor(
            bytecode_iterator().current_offset());

    Node* frame_state_before = environment()->Checkpoint(
        bailout_id, OutputFrameStateCombine::Ignore(), liveness_before);
    NodeProperties::ReplaceFrameStateInput(node, frame_state_before);
#ifdef DEBUG
  } else {
    // In case we skipped checkpoint creation above, we must be able to find an
    // existing checkpoint that effect-dominates the nodes about to be created.
    // Starting a search from the current effect-dependency has to succeed.
    Node* effect = environment()->GetEffectDependency();
    while (effect->opcode() != IrOpcode::kCheckpoint) {
      DCHECK(effect->op()->HasProperty(Operator::kNoWrite));
      DCHECK_EQ(1, effect->op()->EffectInputCount());
      effect = NodeProperties::GetEffectInput(effect);
    }
  }
#else
  }
#endif  // DEBUG
}

void BytecodeGraphBuilder::PrepareFrameState(
    Node* node, OutputFrameStateCombine combine, BytecodeOffset bailout_id,
    const BytecodeLivenessState* liveness) {
  if (OperatorProperties::HasFrameStateInput(node->op())) {
    // Add the frame state for after the operation. The node in question has
    // already been created and had a {Dead} frame state input up until now.
    DCHECK_EQ(1, OperatorProperties::GetFrameStateInputCount(node->op()));
    DCHECK_EQ(IrOpcode::kDead,
              NodeProperties::GetFrameStateInput(node)->opcode());

    Node* frame_state_after =
        environment()->Checkpoint(bailout_id, combine, liveness);
    NodeProperties::ReplaceFrameStateInput(node, frame_state_after);
  }
}

void BytecodeGraphBuilder::AdvanceIteratorsTo(int bytecode_offset) {
  for (; bytecode_iterator().current_offset() != bytecode_offset;
       bytecode_iterator().Advance()) {
    int current_offset = bytecode_iterator().current_offset();
    UpdateSourceAndBytecodePosition(current_offset);
  }
}

// Stores the state of the SourcePosition iterator, and the index to the
// current exception handlers stack. We need, during the OSR graph generation,
// to backup the states of these iterators at the LoopHeader offset of each
// outer loop which contains the OSR loop. The iterators are then restored when
// peeling the loops, so that both exception handling and synchronisation with
// the source position can be achieved.
class BytecodeGraphBuilder::OsrIteratorState {
 public:
  explicit OsrIteratorState(BytecodeGraphBuilder* graph_builder)
      : graph_builder_(graph_builder),
        saved_states_(graph_builder->local_zone()) {}

  void ProcessOsrPrelude() {
    ZoneVector<int> outer_loop_offsets(graph_builder_->local_zone());
    int osr_entry = graph_builder_->bytecode_analysis().osr_entry_point();

    // We find here the outermost loop which contains the OSR loop.
    int outermost_loop_offset = osr_entry;
    while ((outermost_loop_offset = graph_builder_->bytecode_analysis()
                                        .GetLoopInfoFor(outermost_loop_offset)
                                        .parent_offset()) != -1) {
      outer_loop_offsets.push_back(outermost_loop_offset);
    }
    outermost_loop_offset =
        outer_loop_offsets.empty() ? osr_entry : outer_loop_offsets.back();
    graph_builder_->AdvanceIteratorsTo(outermost_loop_offset);

    // We save some iterators states at the offsets of the loop headers of the
    // outer loops (the ones containing the OSR loop). They will be used for
    // jumping back in the bytecode.
    for (ZoneVector<int>::const_reverse_iterator it =
             outer_loop_offsets.crbegin();
         it != outer_loop_offsets.crend(); ++it) {
      graph_builder_->AdvanceIteratorsTo(*it);
      graph_builder_->ExitThenEnterExceptionHandlers(
          graph_builder_->bytecode_iterator().current_offset());
      saved_states_.push(IteratorsStates(
          graph_builder_->current_exception_handler(),
          graph_builder_->source_position_iterator().GetState()));
    }

    // Finishing by advancing to the OSR entry
    graph_builder_->AdvanceIteratorsTo(osr_entry);

    // Enters all remaining exception handler which end before the OSR loop
    // so that on next call of VisitSingleBytecode they will get popped from
    // the exception handlers stack.
    graph_builder_->ExitThenEnterExceptionHandlers(osr_entry);
    graph_builder_->set_currently_peeled_loop_offset(
        graph_builder_->bytecode_analysis()
            .GetLoopInfoFor(osr_entry)
            .parent_offset());
  }

  void RestoreState(int target_offset, int new_parent_offset) {
    graph_builder_->bytecode_iterator().SetOffset(target_offset);
    // In case of a return, we must not build loop exits for
    // not-yet-built outer loops.
    graph_builder_->set_currently_peeled_loop_offset(new_parent_offset);
    IteratorsStates saved_state = saved_states_.top();
    graph_builder_->source_position_iterator().RestoreState(
        saved_state.source_iterator_state_);
    graph_builder_->set_current_exception_handler(
        saved_state.exception_handler_index_);
    saved_states_.pop();
  }

 private:
  struct IteratorsStates {
    int exception_handler_index_;
    SourcePositionTableIterator::IndexAndPositionState source_iterator_state_;

    IteratorsStates(int exception_handler_index,
                    SourcePositionTableIterator::IndexAndPositionState
                        source_iterator_state)
        : exception_handler_index_(exception_handler_index),
          source_iterator_state_(source_iterator_state) {}
  };

  BytecodeGraphBuilder* graph_builder_;
  ZoneStack<IteratorsStates> saved_states_;
};

void BytecodeGraphBuilder::RemoveMergeEnvironmentsBeforeOffset(
    int limit_offset) {
  if (!merge_environments_.empty()) {
    ZoneMap<int, Environment*>::iterator it = merge_environments_.begin();
    ZoneMap<int, Environment*>::iterator stop_it = merge_environments_.end();
    while (it != stop_it && it->first <= limit_offset) {
      it = merge_environments_.erase(it);
    }
  }
}

void BytecodeGraphBuilder::BuildFunctionEntryStackCheck() {
  if (!skip_first_stack_check()) {
    DCHECK(exception_handlers_.empty());
    Node* node =
        NewNode(javascript()->StackCheck(StackCheckKind::kJSFunctionEntry));
    PrepareFrameStateForFunctionEntryStackCheck(node);
  }
}

void BytecodeGraphBuilder::BuildIterationBodyStackCheck() {
  Node* node =
      NewNode(javascript()->StackCheck(StackCheckKind::kJSIterationBody));
  environment()->RecordAfterState(node, Environment::kAttachFrameState);
}

void BytecodeGraphBuilder::BuildOSREntryStackCheck() {
  DCHECK(exception_handlers_.empty());
  Node* node =
      NewNode(javascript()->StackCheck(StackCheckKind::kJSFunctionEntry));
  PrepareFrameStateForOSREntryStackCheck(node);
}

// We will iterate through the OSR loop, then its parent, and so on
// until we have reached the outmost loop containing the OSR loop. We do
// not generate nodes for anything before the outermost loop.
void BytecodeGraphBuilder::AdvanceToOsrEntryAndPeelLoops() {
  environment()->FillWithOsrValues();

  // The entry stack check has to happen *before* initialising the OSR prelude;
  // it has to happen before setting up exception handlers, so that the
  // optimized code can't accidentally catch a failingstack with a OSR-ed loop
  // inside a try-catch, e.g.
  //
  //   try {
  //     loop { OSR(); }
  //   } catch {
  //     // Ignore failed stack check.
  //   }
  BuildOSREntryStackCheck();

  OsrIteratorState iterator_states(this);
  iterator_states.ProcessOsrPrelude();
  int osr_entry = bytecode_analysis().osr_entry_point();
  DCHECK_EQ(bytecode_iterator().current_offset(), osr_entry);

  // Suppose we have n nested loops, loop_0 being the outermost one, and
  // loop_n being the OSR loop. We start iterating the bytecode at the header
  // of loop_n (the OSR loop), and then we peel the part of the the body of
  // loop_{n-1} following the end of loop_n. We then rewind the iterator to
  // the header of loop_{n-1}, and so on until we have partly peeled loop 0.
  // The full loop_0 body will be generating with the rest of the function,
  // outside the OSR generation.

  // To do so, if we are visiting a loop, we continue to visit what's left
  // of its parent, and then when reaching the parent's JumpLoop, we do not
  // create any jump for that but rewind the bytecode iterator to visit the
  // parent loop entirely, and so on.

  int current_parent_offset =
      bytecode_analysis().GetLoopInfoFor(osr_entry).parent_offset();
  while (current_parent_offset != -1) {
    const LoopInfo& current_parent_loop =
        bytecode_analysis().GetLoopInfoFor(current_parent_offset);
    // We iterate until the back edge of the parent loop, which we detect by
    // the offset that the JumpLoop targets.
    for (; !bytecode_iterator().done(); bytecode_iterator().Advance()) {
      if (bytecode_iterator().current_bytecode() ==
              interpreter::Bytecode::kJumpLoop &&
          bytecode_iterator().GetJumpTargetOffset() == current_parent_offset) {
        // Reached the end of the current parent loop.
        break;
      }
      VisitSingleBytecode();
    }
    DCHECK(!bytecode_iterator()
                .done());  // Should have found the loop's jump target.

    // We also need to take care of the merge environments and exceptions
    // handlers here because the omitted JumpLoop bytecode can still be the
    // target of jumps or the first bytecode after a try block.
    ExitThenEnterExceptionHandlers(bytecode_iterator().current_offset());
    SwitchToMergeEnvironment(bytecode_iterator().current_offset());

    // This jump is the jump of our parent loop, which is not yet created.
    // So we do not build the jump nodes, but restore the bytecode and the
    // SourcePosition iterators to the values they had when we were visiting
    // the offset pointed at by the JumpLoop we've just reached.
    // We have already built nodes for inner loops, but now we will
    // iterate again over them and build new nodes corresponding to the same
    // bytecode offsets. Any jump or reference to this inner loops must now
    // point to the new nodes we will build, hence we clear the relevant part
    // of the environment.
    // Completely clearing the environment is not possible because merge
    // environments for forward jumps out of the loop need to be preserved
    // (e.g. a return or a labeled break in the middle of a loop).
    RemoveMergeEnvironmentsBeforeOffset(bytecode_iterator().current_offset());
    iterator_states.RestoreState(current_parent_offset,
                                 current_parent_loop.parent_offset());
    current_parent_offset = current_parent_loop.parent_offset();
  }
}

void BytecodeGraphBuilder::VisitSingleBytecode() {
  tick_counter_->TickAndMaybeEnterSafepoint();
  int current_offset = bytecode_iterator().current_offset();
  UpdateSourceAndBytecodePosition(current_offset);
  ExitThenEnterExceptionHandlers(current_offset);
  DCHECK_GE(exception_handlers_.empty() ? current_offset
                                        : exception_handlers_.top().end_offset_,
            current_offset);
  SwitchToMergeEnvironment(current_offset);

  if (environment() != nullptr) {
    BuildLoopHeaderEnvironment(current_offset);

    switch (bytecode_iterator().current_bytecode()) {
#define BYTECODE_CASE(name, ...)       \
  case interpreter::Bytecode::k##name: \
    Visit##name();                     \
    break;
      BYTECODE_LIST(BYTECODE_CASE, BYTECODE_CASE)
#undef BYTECODE_CASE
    }
  }
}

void BytecodeGraphBuilder::VisitBytecodes() {
  if (!bytecode_analysis().resume_jump_targets().empty()) {
    environment()->BindGeneratorState(
        jsgraph()->SmiConstant(JSGeneratorObject::kGeneratorExecuting));
  }

  if (osr_) {
    // We peel the OSR loop and any outer loop containing it except that we
    // leave the nodes corresponding to the whole outermost loop (including
    // the last copies of the loops it contains) to be generated by the normal
    // bytecode iteration below.
    AdvanceToOsrEntryAndPeelLoops();
  } else {
    BuildFunctionEntryStackCheck();
  }

  for (; !bytecode_iterator().done(); bytecode_iterator().Advance()) {
    VisitSingleBytecode();
  }

  DCHECK(exception_handlers_.empty());
}

void BytecodeGraphBuilder::AddBytecodePositionDecorator() {
  DCHECK_NULL(decorator_);
  decorator_ = graph_zone()->New<BytecodePositionDecorator>(node_origins_);
  graph()->AddDecorator(decorator_);
}

void BytecodeGraphBuilder::RemoveBytecodePositionDecorator() {
  DCHECK_NOT_NULL(decorator_);
  graph()->RemoveDecorator(decorator_);
  decorator_ = nullptr;
}

void BytecodeGraphBuilder::VisitLdaZero() {
  Node* node = jsgraph()->ZeroConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaSmi() {
  Node* node =
      jsgraph()->ConstantNoHole(bytecode_iterator().GetImmediateOperand(0));
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaConstant() {
  ObjectRef object = MakeRefForConstantForIndexOperand(0);
  Node* node = jsgraph()->ConstantNoHole(object, broker());
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaUndefined() {
  Node* node = jsgraph()->UndefinedConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaNull() {
  Node* node = jsgraph()->NullConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaTheHole() {
  Node* node = jsgraph()->TheHoleConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaTrue() {
  Node* node = jsgraph()->TrueConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdaFalse() {
  Node* node = jsgraph()->FalseConstant();
  environment()->BindAccumulator(node);
}

void BytecodeGraphBuilder::VisitLdar() {
  Node* value =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  environment()->BindAccumulator(value);
}

void BytecodeGraphBuilder::VisitStar() {
  Node* value = environment()->LookupAccumulator();
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(0), value);
}

#define SHORT_STAR_VISITOR(Name, ...)                                         \
  void BytecodeGraphBuilder::Visit##Name() {                                  \
    Node* value = environment()->LookupAccumulator();                         \
    environment()->BindRegister(                                              \
        interpreter::Register::FromShortStar(interpreter::Bytecode::k##Name), \
        value);                                                               \
  }
SHORT_STAR_BYTECODE_LIST(SHORT_STAR_VISITOR)
#undef SHORT_STAR_VISITOR

void BytecodeGraphBuilder::VisitMov() {
  Node* value =
      environment()->LookupRegister(bytecode_iterator().GetRegisterOperand(0));
  environment()->BindRegister(bytecode_iterator().GetRegisterOperand(1), value);
}

Node* BytecodeGraphBuilder::BuildLoadGlobal(NameRef name,
                                            uint32_t feedback_slot_index,
                                            TypeofMode typeof_mode) {
  FeedbackSource feedback = CreateFeedbackSource(feedback_slot_index);
  DCHECK(IsLoadGlobalICKind(broker()->GetFeedbackSlotKind(feedback)));
  const Operator* op = javascript()->LoadGlobal(name, feedback, typeof_mode);
  DCHECK(IrOpcode::IsFeedbackCollectingOpcode(op->opcode()));
  return NewNode(op, feedback_vector_node());
}

void BytecodeGraphBuilder::VisitLdaGlobal() {
  PrepareEagerCheckpoint();
  NameRef name = MakeRefForConstantForIndexOperand<Name>(0);
  uint32_t feedback_slot_index = bytecode_iterator().GetIndexOperand(1);
  Node* node =
      BuildLo
"""


```
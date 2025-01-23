Response:
The user wants to understand the functionality of the `v8/src/maglev/maglev-graph-builder.h` file in the V8 JavaScript engine. I need to analyze the provided C++ header file and extract its key responsibilities.

Here's a breakdown of the requested information:

1. **Functionality:** List the core purposes and operations performed by the `MaglevGraphBuilder` class.
2. **Torque Source:** Check if the filename ends with `.tq`. If so, it's a Torque source file.
3. **JavaScript Relation:** If the file relates to JavaScript functionality, provide JavaScript examples.
4. **Code Logic Inference:**  Look for methods that perform logical operations or transformations and provide example inputs and outputs.
5. **Common Programming Errors:** Identify any areas where typical JavaScript programming errors might interact with the code.
6. **Summary:** Provide a concise overview of the file's role.

**Analysis of the header file:**

- The file defines the `MaglevGraphBuilder` class.
- The class seems to be responsible for constructing a graph representation of JavaScript code, specifically for the Maglev compiler in V8.
- It includes methods for:
    - Building nodes representing various JavaScript operations (e.g., `BuildGenericUnaryOperationNode`, `BuildGenericBinaryOperationNode`).
    - Handling control flow (e.g., `CreateBranchBuilder`, `MergeIntoFrameState`).
    - Managing memory allocation (e.g., `GetObjectFromAllocation`, `CreateVirtualObject`).
    - Dealing with inlining (e.g., `is_inline`, `argument_count`).
    - Interacting with feedback data (e.g., `FeedbackNexusForOperand`).
    - Optimizations like loop peeling.
    - Handling deoptimization.

**Plan:**

1. State the primary function of `MaglevGraphBuilder`.
2. Confirm that the file is not a Torque source.
3. Provide JavaScript examples that would trigger the creation of nodes and execution paths within the graph builder.
4. Select a few methods with clear logic and provide example inputs and potential outputs.
5. Identify potential common JavaScript errors that might lead to specific graph structures or deoptimizations.
6. Summarize the overall purpose of the class.
这是对 `v8/src/maglev/maglev-graph-builder.h` 文件功能的归纳总结。

**功能列举:**

`MaglevGraphBuilder` 类是 V8 中 Maglev 编译器的核心组件，其主要功能是**将 JavaScript 字节码转换为 Maglev 图形表示（Maglev Graph）**。这个图形表示是后续 Maglev 优化和代码生成的基础。

以下是其更详细的功能点：

1. **构建节点 (Node Building):**
   - 创建代表各种 JavaScript 操作的节点，例如算术运算、比较、属性访问、函数调用等。
   - 针对不同的操作提供泛型和特定类型的构建方法 (例如 `BuildGenericUnaryOperationNode`, `BuildInt32BinaryOperationNode`)。
   - 支持内联分配对象的创建 (例如 `BuildInlinedAllocationForHeapNumber`)。
   - 创建表示虚拟对象的节点 (例如 `CreateVirtualObject`, `CreateJSObject`)，用于跟踪对象的属性和类型信息，辅助优化。
   - 创建与参数对象相关的节点 (例如 `BuildVirtualArgumentsObject`, `BuildAndAllocateArgumentsObject`)。

2. **控制流处理 (Control Flow Handling):**
   - 构建分支节点 (Branch Nodes) 来表示条件语句和循环。
   - 提供 `BranchBuilder` 类来简化分支节点的创建和管理。
   - 管理基本块 (Basic Blocks)，将代码分解为顺序执行的指令序列。
   - 处理循环结构，包括循环入口、循环体和循环出口。
   - 支持循环展开 (Loop Peeling) 优化。

3. **状态管理 (State Management):**
   - 维护当前解释器帧的状态 (`current_interpreter_frame_`)，包括局部变量、寄存器值等。
   - 管理合并点状态 (Merge Point State)，用于处理控制流汇合点。
   - 处理内联函数的调用和返回，管理内联函数的参数和上下文。

4. **优化支持 (Optimization Support):**
   - 利用类型反馈信息进行优化 (通过 `FeedbackNexus`)。
   - 支持常量折叠 (Constant Folding)，在编译时计算常量表达式的值。
   - 支持公共子表达式消除 (Common Subexpression Elimination, CSE)。
   - 进行简单的类型推断和检查 (例如 `TryBuildFastInstanceOf`)。
   - 支持对特定操作的快速路径构建 (例如 `TryBuildFastCreateObjectOrArrayLiteral`)。

5. **处理 Deoptimization (Deoptimization Handling):**
   - 记录可能导致去优化的节点和原因。
   - 管理去优化帧 (Deopt Frame) 信息。

6. **内存管理 (Memory Management):**
   - 管理内联分配块 (Inlined Allocation Block)，用于优化小对象的分配。

7. **其他功能:**
   - 处理 `instanceof` 操作 (例如 `TryBuildFastInstanceOf`, `BuildOrdinaryHasInstance`)。
   - 处理 `typeof` 操作 (例如 `TryReduceTypeOf`)。
   - 支持 `for...in` 循环的处理。
   - 处理 try...catch 块。

**是否为 Torque 源代码:**

否，`v8/src/maglev/maglev-graph-builder.h` 文件以 `.h` 结尾，表明它是一个 C++ 头文件，而不是 Torque 源代码。Torque 源代码文件通常以 `.tq` 结尾。

**与 JavaScript 功能的关系和 JavaScript 示例:**

`MaglevGraphBuilder` 的核心任务是将 JavaScript 代码转换为图形表示，因此它与几乎所有的 JavaScript 功能都有关系。以下是一些 JavaScript 示例以及它们在 `MaglevGraphBuilder` 中可能涉及的操作：

**示例 1: 算术运算**

```javascript
function add(a, b) {
  return a + b;
}
```

在 `MaglevGraphBuilder` 中，`a + b` 这个操作可能会被构建成一个二元运算节点，例如 `BuildGenericBinaryOperationNode<Operation::kAdd>` 或 `BuildInt32BinaryOperationNode<Operation::kAdd>`，具体取决于 `a` 和 `b` 的类型信息。

**示例 2: 条件语句**

```javascript
function isPositive(x) {
  if (x > 0) {
    return true;
  } else {
    return false;
  }
}
```

`if (x > 0)` 这个条件语句会导致 `MaglevGraphBuilder` 创建一个分支节点，例如使用 `BuildBranchIfInt32Compare` 或 `BuildBranchIfFloat64Compare` 来判断 `x` 是否大于 0，并根据结果跳转到不同的基本块。

**示例 3: 函数调用**

```javascript
function greet(name) {
  console.log("Hello, " + name + "!");
}

greet("World");
```

`greet("World")` 这个函数调用会触发 `MaglevGraphBuilder` 构建一个函数调用节点。它可能涉及查找函数、准备参数、执行调用以及处理返回值等操作。

**示例 4: 对象创建**

```javascript
const obj = { x: 10, y: 20 };
```

对象字面量 `{ x: 10, y: 20 }` 会导致 `MaglevGraphBuilder` 调用诸如 `TryBuildFastCreateObjectOrArrayLiteral` 或创建一系列的属性设置节点来初始化对象。`CreateVirtualObject` 也可能被用于表示这个新创建的对象。

**代码逻辑推理 (假设输入与输出):**

考虑 `BuildInt32BinaryOperationNode<Operation::kAdd>()` 这个方法（简化理解，实际实现会更复杂）。

**假设输入:**

- 当前 `iterator_` 指向字节码 `add Smi` 指令。
- 两个输入值节点 `left_node` 和 `right_node`，分别代表要相加的两个 `int32` 类型的值。

**可能的输出:**

- 创建一个新的 `ValueNode`，表示这两个 `int32` 值的相加结果。
- 该新节点的 `opcode` 将是 `kInt32Add`。
- 该新节点的输入将是 `left_node` 和 `right_node`。
- 该新节点会被添加到当前基本块 (`current_block_`)。

**涉及用户常见的编程错误:**

`MaglevGraphBuilder` 在构建图形时会考虑各种 JavaScript 编程模式，包括一些常见的错误。这些错误可能会导致生成特定的图结构或触发去优化。

**示例 1: 类型不匹配**

```javascript
function multiply(a, b) {
  return a * b;
}

multiply(5, "hello"); // 错误：字符串不能直接与数字相乘
```

当 `MaglevGraphBuilder` 遇到这种类型不匹配的操作时，可能会生成更复杂的节点来处理类型转换或检查。如果类型不匹配导致运行时错误，可能会触发去优化。

**示例 2: 访问未定义的属性**

```javascript
const obj = { x: 10 };
console.log(obj.y.value); // 错误：obj.y 是 undefined，访问 undefined 的属性会报错
```

访问 `obj.y` 时，`MaglevGraphBuilder` 可能会构建一个属性加载节点，但由于 `y` 未定义，后续的 `.value` 访问会导致错误。这可能会导致生成检查 `obj.y` 是否为 `undefined` 的代码，或者在运行时触发去优化。

**示例 3: `instanceof` 的误用**

```javascript
function MyClass() {}
const obj = {};
console.log(obj instanceof MyClass); // 结果为 false，但用户可能误以为是 true
```

`MaglevGraphBuilder` 中的 `TryBuildFastInstanceOf` 和 `BuildOrdinaryHasInstance` 方法会处理 `instanceof` 操作。如果类型反馈表明 `callable` 始终是某个特定的构造函数，则可能会进行快速路径优化。但如果类型反馈不准确，或者用户错误地使用了 `instanceof`，可能会导致意想不到的结果。

**总结功能:**

`v8/src/maglev/maglev-graph-builder.h` 定义了 `MaglevGraphBuilder` 类，它是 V8 中 Maglev 编译器的一个关键组件，负责将 JavaScript 字节码转换为 Maglev 图形表示。这个类提供了构建各种节点、处理控制流、管理状态以及支持多种优化的功能，为后续的 Maglev 编译阶段奠定了基础。它深入参与了 JavaScript 代码的执行流程，并将 JavaScript 的各种语法结构和语义转化为可供编译器优化的中间表示。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
ryHasInstance(ValueNode* object,
                                               compiler::JSObjectRef callable,
                                               ValueNode* callable_node);
  ReduceResult BuildOrdinaryHasInstance(ValueNode* object,
                                        compiler::JSObjectRef callable,
                                        ValueNode* callable_node);
  ReduceResult TryBuildFastInstanceOf(ValueNode* object,
                                      compiler::JSObjectRef callable_ref,
                                      ValueNode* callable_node);
  ReduceResult TryBuildFastInstanceOfWithFeedback(
      ValueNode* object, ValueNode* callable,
      compiler::FeedbackSource feedback_source);

  VirtualObject* GetObjectFromAllocation(InlinedAllocation* allocation);
  VirtualObject* GetModifiableObjectFromAllocation(
      InlinedAllocation* allocation);

  VirtualObject* DeepCopyVirtualObject(VirtualObject* vobj);
  VirtualObject* CreateVirtualObject(compiler::MapRef map,
                                     uint32_t slot_count_including_map);
  VirtualObject* CreateHeapNumber(Float64 value);
  VirtualObject* CreateDoubleFixedArray(uint32_t elements_length,
                                        compiler::FixedDoubleArrayRef elements);
  VirtualObject* CreateJSObject(compiler::MapRef map);
  VirtualObject* CreateJSArray(compiler::MapRef map, int instance_size,
                               ValueNode* length);
  VirtualObject* CreateJSArrayIterator(compiler::MapRef map,
                                       ValueNode* iterated_object,
                                       IterationKind kind);
  VirtualObject* CreateJSConstructor(compiler::JSFunctionRef constructor);
  VirtualObject* CreateFixedArray(compiler::MapRef map, int length);
  VirtualObject* CreateContext(compiler::MapRef map, int length,
                               compiler::ScopeInfoRef scope_info,
                               ValueNode* previous_context,
                               std::optional<ValueNode*> extension = {});
  VirtualObject* CreateArgumentsObject(compiler::MapRef map, ValueNode* length,
                                       ValueNode* elements,
                                       std::optional<ValueNode*> callee = {});
  VirtualObject* CreateMappedArgumentsElements(compiler::MapRef map,
                                               int mapped_count,
                                               ValueNode* context,
                                               ValueNode* unmapped_elements);
  VirtualObject* CreateRegExpLiteralObject(
      compiler::MapRef map, compiler::RegExpBoilerplateDescriptionRef literal);
  VirtualObject* CreateJSGeneratorObject(compiler::MapRef map,
                                         int instance_size, ValueNode* context,
                                         ValueNode* closure,
                                         ValueNode* receiver,
                                         ValueNode* register_file);
  VirtualObject* CreateJSIteratorResult(compiler::MapRef map, ValueNode* value,
                                        ValueNode* done);
  VirtualObject* CreateJSStringIterator(compiler::MapRef map,
                                        ValueNode* string);

  InlinedAllocation* ExtendOrReallocateCurrentAllocationBlock(
      AllocationType allocation_type, VirtualObject* value);

  void ClearCurrentAllocationBlock();

  inline void AddDeoptUse(ValueNode* node) {
    if (node == nullptr) return;
    DCHECK(!node->Is<VirtualObject>());
    if (InlinedAllocation* alloc = node->TryCast<InlinedAllocation>()) {
      VirtualObject* vobject =
          current_interpreter_frame_.virtual_objects().FindAllocatedWith(alloc);
      CHECK_NOT_NULL(vobject);
      AddDeoptUse(vobject);
      // Add an escaping use for the allocation.
      AddNonEscapingUses(alloc, 1);
      alloc->add_use();
    } else {
      node->add_use();
    }
  }
  void AddDeoptUse(VirtualObject* alloc);
  void AddNonEscapingUses(InlinedAllocation* allocation, int use_count);

  std::optional<VirtualObject*> TryGetNonEscapingArgumentsObject(
      ValueNode* value);

  ReduceResult TryBuildFastCreateObjectOrArrayLiteral(
      const compiler::LiteralFeedback& feedback);
  std::optional<VirtualObject*> TryReadBoilerplateForFastLiteral(
      compiler::JSObjectRef boilerplate, AllocationType allocation,
      int max_depth, int* max_properties);

  ValueNode* BuildInlinedAllocationForHeapNumber(VirtualObject* object,
                                                 AllocationType allocation);
  ValueNode* BuildInlinedAllocationForDoubleFixedArray(
      VirtualObject* object, AllocationType allocation);
  ValueNode* BuildInlinedAllocation(VirtualObject* object,
                                    AllocationType allocation);
  ValueNode* BuildInlinedArgumentsElements(int start_index, int length);
  ValueNode* BuildInlinedUnmappedArgumentsElements(int mapped_count);

  template <CreateArgumentsType type>
  VirtualObject* BuildVirtualArgumentsObject();
  template <CreateArgumentsType type>
  ValueNode* BuildAndAllocateArgumentsObject();

  bool CanAllocateSloppyArgumentElements();
  bool CanAllocateInlinedArgumentElements();

  ReduceResult TryBuildInlinedAllocatedContext(compiler::MapRef map,
                                               compiler::ScopeInfoRef scope,
                                               int context_length);

  template <Operation kOperation>
  void BuildGenericUnaryOperationNode();
  template <Operation kOperation>
  void BuildGenericBinaryOperationNode();
  template <Operation kOperation>
  void BuildGenericBinarySmiOperationNode();

  template <Operation kOperation>
  bool TryReduceCompareEqualAgainstConstant();

  template <Operation kOperation>
  ReduceResult TryFoldInt32UnaryOperation(ValueNode* value);
  template <Operation kOperation>
  ReduceResult TryFoldInt32BinaryOperation(ValueNode* left, ValueNode* right);
  template <Operation kOperation>
  ReduceResult TryFoldInt32BinaryOperation(ValueNode* left, int32_t cst_right);

  template <Operation kOperation>
  void BuildInt32UnaryOperationNode();
  void BuildTruncatingInt32BitwiseNotForToNumber(ToNumberHint hint);
  template <Operation kOperation>
  void BuildInt32BinaryOperationNode();
  template <Operation kOperation>
  void BuildInt32BinarySmiOperationNode();
  template <Operation kOperation>
  void BuildTruncatingInt32BinaryOperationNodeForToNumber(ToNumberHint hint);
  template <Operation kOperation>
  void BuildTruncatingInt32BinarySmiOperationNodeForToNumber(ToNumberHint hint);

  template <Operation kOperation>
  ReduceResult TryFoldFloat64UnaryOperationForToNumber(ToNumberHint hint,
                                                       ValueNode* value);
  template <Operation kOperation>
  ReduceResult TryFoldFloat64BinaryOperationForToNumber(ToNumberHint hint,
                                                        ValueNode* left,
                                                        ValueNode* right);
  template <Operation kOperation>
  ReduceResult TryFoldFloat64BinaryOperationForToNumber(ToNumberHint hint,
                                                        ValueNode* left,
                                                        double cst_right);

  template <Operation kOperation>
  void BuildFloat64UnaryOperationNodeForToNumber(ToNumberHint hint);
  template <Operation kOperation>
  void BuildFloat64BinaryOperationNodeForToNumber(ToNumberHint hint);
  template <Operation kOperation>
  void BuildFloat64BinarySmiOperationNodeForToNumber(ToNumberHint hint);

  template <Operation kOperation>
  void VisitUnaryOperation();
  template <Operation kOperation>
  void VisitBinaryOperation();
  template <Operation kOperation>
  void VisitBinarySmiOperation();

  template <Operation kOperation>
  void VisitCompareOperation();

  using TypeOfLiteralFlag = interpreter::TestTypeOfFlags::LiteralFlag;
  template <typename Function>
  ReduceResult TryReduceTypeOf(ValueNode* value, const Function& GetResult);
  ReduceResult TryReduceTypeOf(ValueNode* value);

  void BeginLoopEffects(int loop_header);
  void EndLoopEffects(int loop_header);
  void MergeIntoFrameState(BasicBlock* block, int target);
  void MergeDeadIntoFrameState(int target);
  void MergeDeadLoopIntoFrameState(int target);
  void MergeIntoInlinedReturnFrameState(BasicBlock* block);

  bool HasValidInitialMap(compiler::JSFunctionRef new_target,
                          compiler::JSFunctionRef constructor);

  ValueNode* BuildTaggedEqual(ValueNode* lhs, ValueNode* rhs);
  ValueNode* BuildTaggedEqual(ValueNode* lhs, RootIndex rhs_index);

  class BranchBuilder;

  enum class BranchType { kBranchIfTrue, kBranchIfFalse };
  enum class BranchSpecializationMode { kDefault, kAlwaysBoolean };
  enum class BranchResult {
    kDefault,
    kAlwaysTrue,
    kAlwaysFalse,
  };

  static inline BranchType NegateBranchType(BranchType jump_type) {
    switch (jump_type) {
      case BranchType::kBranchIfTrue:
        return BranchType::kBranchIfFalse;
      case BranchType::kBranchIfFalse:
        return BranchType::kBranchIfTrue;
    }
  }

  // This class encapsulates the logic of branch nodes (using the graph builder
  // or the sub graph builder).
  class BranchBuilder {
   public:
    enum Mode {
      kBytecodeJumpTarget,
      kLabelJumpTarget,
    };

    class PatchAccumulatorInBranchScope {
     public:
      PatchAccumulatorInBranchScope(BranchBuilder& builder, ValueNode* node,
                                    RootIndex root_index)
          : builder_(builder),
            node_(node),
            root_index_(root_index),
            jump_type_(builder.GetCurrentBranchType()) {
        if (builder.mode() == kBytecodeJumpTarget) {
          builder_.data_.bytecode_target.patch_accumulator_scope = this;
        }
      }

      ~PatchAccumulatorInBranchScope() {
        builder_.data_.bytecode_target.patch_accumulator_scope = nullptr;
      }

     private:
      BranchBuilder& builder_;
      ValueNode* node_;
      RootIndex root_index_;
      BranchType jump_type_;

      friend class BranchBuilder;
    };

    struct BytecodeJumpTarget {
      BytecodeJumpTarget(int jump_target_offset, int fallthrough_offset)
          : jump_target_offset(jump_target_offset),
            fallthrough_offset(fallthrough_offset),
            patch_accumulator_scope(nullptr) {}
      int jump_target_offset;
      int fallthrough_offset;
      PatchAccumulatorInBranchScope* patch_accumulator_scope;
    };

    struct LabelJumpTarget {
      explicit LabelJumpTarget(MaglevSubGraphBuilder::Label* jump_label)
          : jump_label(jump_label), fallthrough() {}
      MaglevSubGraphBuilder::Label* jump_label;
      BasicBlockRef fallthrough;
    };

    union Data {
      Data(int jump_target_offset, int fallthrough_offset)
          : bytecode_target(jump_target_offset, fallthrough_offset) {}
      explicit Data(MaglevSubGraphBuilder::Label* jump_label)
          : label_target(jump_label) {}
      BytecodeJumpTarget bytecode_target;
      LabelJumpTarget label_target;
    };

    // Creates a branch builder for bytecode offsets.
    BranchBuilder(MaglevGraphBuilder* builder, BranchType jump_type)
        : builder_(builder),
          sub_builder_(nullptr),
          jump_type_(jump_type),
          data_(builder->iterator_.GetJumpTargetOffset(),
                builder->iterator_.next_offset()) {}

    // Creates a branch builder for subgraph label.
    BranchBuilder(MaglevGraphBuilder* builder,
                  MaglevSubGraphBuilder* sub_builder, BranchType jump_type,
                  MaglevSubGraphBuilder::Label* jump_label)
        : builder_(builder),
          sub_builder_(sub_builder),
          jump_type_(jump_type),
          data_(jump_label) {}

    Mode mode() const {
      return sub_builder_ == nullptr ? kBytecodeJumpTarget : kLabelJumpTarget;
    }

    BranchType GetCurrentBranchType() const { return jump_type_; }

    void SetBranchSpecializationMode(BranchSpecializationMode mode) {
      branch_specialization_mode_ = mode;
    }
    void SwapTargets() { jump_type_ = NegateBranchType(jump_type_); }

    BasicBlockRef* jump_target();
    BasicBlockRef* fallthrough();
    BasicBlockRef* true_target();
    BasicBlockRef* false_target();

    BranchResult FromBool(bool value) const;
    BranchResult AlwaysTrue() const { return FromBool(true); }
    BranchResult AlwaysFalse() const { return FromBool(false); }

    template <typename NodeT, typename... Args>
    BranchResult Build(std::initializer_list<ValueNode*> inputs,
                       Args&&... args);

   private:
    MaglevGraphBuilder* builder_;
    MaglevGraphBuilder::MaglevSubGraphBuilder* sub_builder_;
    BranchType jump_type_;
    BranchSpecializationMode branch_specialization_mode_ =
        BranchSpecializationMode::kDefault;
    Data data_;

    void StartFallthroughBlock(BasicBlock* predecessor);
    void SetAccumulatorInBranch(BranchType jump_type) const;
  };

  BranchBuilder CreateBranchBuilder(
      BranchType jump_type = BranchType::kBranchIfTrue) {
    return BranchBuilder(this, jump_type);
  }
  BranchBuilder CreateBranchBuilder(
      MaglevSubGraphBuilder* subgraph, MaglevSubGraphBuilder::Label* jump_label,
      BranchType jump_type = BranchType::kBranchIfTrue) {
    return BranchBuilder(this, subgraph, jump_type, jump_label);
  }

  BranchResult BuildBranchIfRootConstant(BranchBuilder& builder,
                                         ValueNode* node, RootIndex root_index);
  BranchResult BuildBranchIfToBooleanTrue(BranchBuilder& builder,
                                          ValueNode* node);
  BranchResult BuildBranchIfInt32ToBooleanTrue(BranchBuilder& builder,
                                               ValueNode* node);
  BranchResult BuildBranchIfFloat64ToBooleanTrue(BranchBuilder& builder,
                                                 ValueNode* node);
  BranchResult BuildBranchIfFloat64IsHole(BranchBuilder& builder,
                                          ValueNode* node);
  BranchResult BuildBranchIfReferenceEqual(BranchBuilder& builder,
                                           ValueNode* lhs, ValueNode* rhs);
  BranchResult BuildBranchIfInt32Compare(BranchBuilder& builder, Operation op,
                                         ValueNode* lhs, ValueNode* rhs);
  BranchResult BuildBranchIfUint32Compare(BranchBuilder& builder, Operation op,
                                          ValueNode* lhs, ValueNode* rhs);
  BranchResult BuildBranchIfUndefinedOrNull(BranchBuilder& builder,
                                            ValueNode* node);
  BranchResult BuildBranchIfUndetectable(BranchBuilder& builder,
                                         ValueNode* value);
  BranchResult BuildBranchIfJSReceiver(BranchBuilder& builder,
                                       ValueNode* value);

  BranchResult BuildBranchIfTrue(BranchBuilder& builder, ValueNode* node);
  BranchResult BuildBranchIfNull(BranchBuilder& builder, ValueNode* node);
  BranchResult BuildBranchIfUndefined(BranchBuilder& builder, ValueNode* node);
  BasicBlock* BuildBranchIfReferenceEqual(ValueNode* lhs, ValueNode* rhs,
                                          BasicBlockRef* true_target,
                                          BasicBlockRef* false_target);

  template <typename FCond, typename FTrue, typename FFalse>
  ValueNode* Select(FCond cond, FTrue if_true, FFalse if_false);

  template <typename FCond, typename FTrue, typename FFalse>
  ReduceResult SelectReduction(FCond cond, FTrue if_true, FFalse if_false);

  void MarkBranchDeadAndJumpIfNeeded(bool is_jump_taken);

  void CalculatePredecessorCounts() {
    // Add 1 after the end of the bytecode so we can always write to the offset
    // after the last bytecode.
    uint32_t array_length = bytecode().length() + 1;
    predecessor_count_ = zone()->AllocateArray<uint32_t>(array_length);
    MemsetUint32(predecessor_count_, 0, entrypoint_);
    MemsetUint32(predecessor_count_ + entrypoint_, 1,
                 array_length - entrypoint_);

    const int max_peelings = v8_flags.maglev_optimistic_peeled_loops ? 2 : 1;
    // We count jumps from peeled loops to outside of the loop twice.
    bool is_loop_peeling_iteration = false;
    std::optional<int> peeled_loop_end;
    interpreter::BytecodeArrayIterator iterator(bytecode().object());
    for (iterator.SetOffset(entrypoint_); !iterator.done();
         iterator.Advance()) {
      interpreter::Bytecode bytecode = iterator.current_bytecode();
      if (allow_loop_peeling_ &&
          bytecode_analysis().IsLoopHeader(iterator.current_offset())) {
        const compiler::LoopInfo& loop_info =
            bytecode_analysis().GetLoopInfoFor(iterator.current_offset());
        // Generators use irreducible control flow, which makes loop peeling too
        // complicated.
        int size = loop_info.loop_end() - loop_info.loop_start();
        if (loop_info.innermost() && !loop_info.resumable() &&
            iterator.next_offset() < loop_info.loop_end() &&
            size < v8_flags.maglev_loop_peeling_max_size &&
            size + graph_->total_peeled_bytecode_size() <
                v8_flags.maglev_loop_peeling_max_size_cumulative) {
          DCHECK(!is_loop_peeling_iteration);
          graph_->add_peeled_bytecode_size(size);
          is_loop_peeling_iteration = true;
          loop_headers_to_peel_.Add(iterator.current_offset());
          peeled_loop_end = bytecode_analysis().GetLoopEndOffsetForInnermost(
              iterator.current_offset());
        }
      }
      if (interpreter::Bytecodes::IsJump(bytecode)) {
        if (is_loop_peeling_iteration &&
            bytecode == interpreter::Bytecode::kJumpLoop) {
          DCHECK_EQ(iterator.next_offset(), peeled_loop_end);
          is_loop_peeling_iteration = false;
          peeled_loop_end = {};
        }
        if (iterator.GetJumpTargetOffset() < entrypoint_) {
          static_assert(kLoopsMustBeEnteredThroughHeader);
          if (predecessor_count(iterator.GetJumpTargetOffset()) == 1) {
            // We encoutered a JumpLoop whose loop header is not reachable
            // otherwise. This loop is either dead or the JumpLoop will bail
            // with DeoptimizeReason::kOSREarlyExit.
            InitializePredecessorCount(iterator.GetJumpTargetOffset(), 0);
          }
        } else {
          UpdatePredecessorCount(iterator.GetJumpTargetOffset(), 1);
        }
        if (is_loop_peeling_iteration &&
            iterator.GetJumpTargetOffset() >= *peeled_loop_end) {
          // Jumps from within the peeled loop to outside need to be counted
          // twice, once for the peeled and once for the regular loop body.
          UpdatePredecessorCount(iterator.GetJumpTargetOffset(), max_peelings);
        }
        if (!interpreter::Bytecodes::IsConditionalJump(bytecode)) {
          UpdatePredecessorCount(iterator.next_offset(), -1);
        }
      } else if (interpreter::Bytecodes::IsSwitch(bytecode)) {
        for (auto offset : iterator.GetJumpTableTargetOffsets()) {
          UpdatePredecessorCount(offset.target_offset, 1);
        }
      } else if (interpreter::Bytecodes::Returns(bytecode) ||
                 interpreter::Bytecodes::UnconditionallyThrows(bytecode)) {
        UpdatePredecessorCount(iterator.next_offset(), -1);
        // Collect inline return jumps in the slot after the last bytecode.
        if (is_inline() && interpreter::Bytecodes::Returns(bytecode)) {
          UpdatePredecessorCount(array_length - 1, 1);
          if (is_loop_peeling_iteration) {
            UpdatePredecessorCount(array_length - 1, max_peelings);
          }
        }
      }
      // TODO(leszeks): Also consider handler entries (the bytecode analysis)
      // will do this automatically I guess if we merge this into that.
    }
    if (!is_inline()) {
      DCHECK_EQ(0, predecessor_count(bytecode().length()));
    }
  }

  compiler::FeedbackVectorRef feedback() const {
    return compilation_unit_->feedback();
  }
  const FeedbackNexus FeedbackNexusForOperand(int slot_operand_index) const {
    return FeedbackNexus(feedback().object(),
                         GetSlotOperand(slot_operand_index),
                         broker()->feedback_nexus_config());
  }
  const FeedbackNexus FeedbackNexusForSlot(FeedbackSlot slot) const {
    return FeedbackNexus(feedback().object(), slot,
                         broker()->feedback_nexus_config());
  }
  compiler::BytecodeArrayRef bytecode() const {
    return compilation_unit_->bytecode();
  }
  const compiler::BytecodeAnalysis& bytecode_analysis() const {
    return bytecode_analysis_;
  }
  int parameter_count() const { return compilation_unit_->parameter_count(); }
  int parameter_count_without_receiver() const { return parameter_count() - 1; }
  int register_count() const { return compilation_unit_->register_count(); }
  KnownNodeAspects& known_node_aspects() {
    return *current_interpreter_frame_.known_node_aspects();
  }

  // True when this graph builder is building the subgraph of an inlined
  // function.
  bool is_inline() const { return parent_ != nullptr; }
  int inlining_depth() const { return compilation_unit_->inlining_depth(); }

  int argument_count() const {
    DCHECK(is_inline());
    return static_cast<int>(inlined_arguments_.size());
  }
  int argument_count_without_receiver() const { return argument_count() - 1; }

  bool HasMismatchedArgumentAndParameterCount() {
    return is_inline() && (argument_count() != parameter_count());
  }

  bool IsInsideLoop() const {
    if (caller_is_inside_loop_) return true;
    int loop_header_offset =
        bytecode_analysis().GetLoopOffsetFor(iterator_.current_offset());
    if (loop_header_offset != -1) {
      const compiler::LoopInfo& loop_info =
          bytecode_analysis().GetLoopInfoFor(loop_header_offset);
      if (loop_info.parent_offset() == -1) {
        // This is the outmost loop, if we're actually inside the peel, we are
        // not really in a loop.
        return !in_peeled_iteration() || in_optimistic_peeling_iteration();
      }
      return true;
    }
    return false;
  }

  // The fake offset used as a target for all exits of an inlined function.
  int inline_exit_offset() const {
    DCHECK(is_inline());
    return bytecode().length();
  }

  uint32_t NewObjectId() { return graph_->NewObjectId(); }

  LocalIsolate* const local_isolate_;
  MaglevCompilationUnit* const compilation_unit_;
  MaglevGraphBuilder* const parent_;
  DeoptFrame* parent_deopt_frame_ = nullptr;
  CatchBlockDetails parent_catch_;
  int parent_catch_deopt_frame_distance_ = 0;
  // Cache the heap broker since we access it a bunch.
  compiler::JSHeapBroker* broker_ = compilation_unit_->broker();

  Graph* const graph_;
  compiler::BytecodeAnalysis bytecode_analysis_;
  interpreter::BytecodeArrayIterator iterator_;
  SourcePositionTableIterator source_position_iterator_;

  // Change the number of predecessors when encountering a dead predecessor.
  // In case we are in a peeled iteration the decrement is undone after
  // finishing the peel. This is needed since in the next iteration the
  // predecessor might not be dead.
  void DecrementDeadPredecessorAndAccountForPeeling(uint32_t offset) {
    DCHECK_LE(offset, bytecode().length());
    DCHECK_GT(predecessor_count_[offset], 0);
    DCHECK_IMPLIES(merge_states_[offset],
                   merge_states_[offset]->predecessor_count() ==
                       predecessor_count_[offset] - 1);
    predecessor_count_[offset]--;
    if (in_peeled_iteration()) {
      decremented_predecessor_offsets_.push_back(offset);
    } else {
      DCHECK(decremented_predecessor_offsets_.empty());
    }
  }
  // Set the number of predecessors initially.
  void InitializePredecessorCount(uint32_t offset, int amount) {
    DCHECK_LE(offset, bytecode().length());
    DCHECK_NULL(merge_states_[offset]);
    predecessor_count_[offset] = amount;
  }
  void UpdatePredecessorCount(uint32_t offset, int diff) {
    DCHECK_LE(offset, bytecode().length());
    DCHECK_LE(0, static_cast<int64_t>(predecessor_count_[offset]) + diff);
    DCHECK_IMPLIES(merge_states_[offset],
                   merge_states_[offset]->predecessor_count() ==
                       predecessor_count_[offset] + diff);
    predecessor_count_[offset] += diff;
  }
  uint32_t predecessor_count(uint32_t offset) {
    DCHECK_LE(offset, bytecode().length());
    DCHECK_IMPLIES(!decremented_predecessor_offsets_.empty(),
                   in_peeled_iteration());
    uint32_t actual = predecessor_count_[offset];
    DCHECK_IMPLIES(merge_states_[offset],
                   merge_states_[offset]->predecessor_count() == actual);
    return actual;
  }
  uint32_t* predecessor_count_;

  int peeled_iteration_count_ = 0;
  bool any_peeled_loop_ = false;
  bool allow_loop_peeling_;

  bool in_peeled_iteration() const {
    DCHECK_GE(peeled_iteration_count_, 0);
    return peeled_iteration_count_ > 0;
  }

  // When loop SPeeling is enabled then the second-last peeling iteration
  // is the optimistic iteration. At the end we try to compile the JumpLoop and
  // only proceed with the fallback iteration 0, if the loop state is
  // incompatible with the loop end state.
  bool in_optimistic_peeling_iteration() const {
    return v8_flags.maglev_optimistic_peeled_loops &&
           peeled_iteration_count_ == 1;
  }
  bool is_loop_effect_tracking_enabled() {
    return v8_flags.maglev_escape_analysis || v8_flags.maglev_licm;
  }
  bool is_loop_effect_tracking() { return loop_effects_; }
  LoopEffects* loop_effects_ = nullptr;
  ZoneDeque<LoopEffects*> loop_effects_stack_;

  // When processing the peeled iteration of a loop, we need to reset the
  // decremented predecessor counts inside of the loop before processing the
  // body again. For this, we record offsets where we decremented the
  // predecessor count.
  ZoneVector<int> decremented_predecessor_offsets_;
  // The set of loop headers for which we decided to do loop peeling.
  BitVector loop_headers_to_peel_;

  // Current block information.
  bool in_prologue_ = true;
  BasicBlock* current_block_ = nullptr;
  std::optional<InterpretedDeoptFrame> entry_stack_check_frame_;
  std::optional<DeoptFrame> latest_checkpointed_frame_;
  SourcePosition current_source_position_;
  struct ForInState {
    ValueNode* receiver = nullptr;
    ValueNode* cache_type = nullptr;
    ValueNode* enum_cache_indices = nullptr;
    ValueNode* key = nullptr;
    ValueNode* index = nullptr;
    bool receiver_needs_map_check = false;
  };
  // TODO(leszeks): Allow having a stack of these.
  ForInState current_for_in_state = ForInState();

  AllocationBlock* current_allocation_block_ = nullptr;

  float call_frequency_;

  BasicBlockRef* jump_targets_;
  MergePointInterpreterFrameState** merge_states_;

  InterpreterFrameState current_interpreter_frame_;
  compiler::FeedbackSource current_speculation_feedback_;

  base::Vector<ValueNode*> inlined_arguments_;
  BytecodeOffset caller_bytecode_offset_;
  bool caller_is_inside_loop_;
  ValueNode* inlined_new_target_ = nullptr;

  // Bytecode offset at which compilation should start.
  int entrypoint_;
  int bailout_for_entrypoint() {
    if (!graph_->is_osr()) return kFunctionEntryBytecodeOffset;
    return bytecode_analysis_.osr_bailout_id().ToInt();
  }

  int inlining_id_;

  DeoptFrameScope* current_deopt_scope_ = nullptr;

  struct HandlerTableEntry {
    int end;
    int handler;
  };
  ZoneStack<HandlerTableEntry> catch_block_stack_;
  int next_handler_table_index_ = 0;

#ifdef DEBUG
  bool IsNodeCreatedForThisBytecode(ValueNode* node) const {
    return new_nodes_.find(node) != new_nodes_.end();
  }
  std::unordered_set<Node*> new_nodes_;
#endif

  // Some helpers for CSE

  static size_t fast_hash_combine(size_t seed, size_t h) {
    // Implementation from boost. Good enough for GVN.
    return h + 0x9e3779b9 + (seed << 6) + (seed >> 2);
  }

  template <typename T>
  static size_t gvn_hash_value(const T& in) {
    return base::hash_value(in);
  }

  static size_t gvn_hash_value(const compiler::MapRef& map) {
    return map.hash_value();
  }

  static size_t gvn_hash_value(const interpreter::Register& reg) {
    return base::hash_value(reg.index());
  }

  static size_t gvn_hash_value(const Representation& rep) {
    return base::hash_value(rep.kind());
  }

  static size_t gvn_hash_value(const ExternalReference& ref) {
    return base::hash_value(ref.address());
  }

  static size_t gvn_hash_value(const PolymorphicAccessInfo& access_info) {
    return access_info.hash_value();
  }

  template <typename T>
  static size_t gvn_hash_value(const v8::internal::ZoneCompactSet<T>& vector) {
    size_t hash = base::hash_value(vector.size());
    for (auto e : vector) {
      hash = fast_hash_combine(hash, gvn_hash_value(e));
    }
    return hash;
  }

  template <typename T>
  static size_t gvn_hash_value(const v8::internal::ZoneVector<T>& vector) {
    size_t hash = base::hash_value(vector.size());
    for (auto e : vector) {
      hash = fast_hash_combine(hash, gvn_hash_value(e));
    }
    return hash;
  }

  bool CanSpeculateCall() const {
    return current_speculation_feedback_.IsValid();
  }

  inline void MarkNodeDead(Node* node) {
    for (int i = 0; i < node->input_count(); ++i) {
      node->input(i).clear();
    }
    node->OverwriteWith(Opcode::kDead);
  }

  ZoneUnorderedMap<KnownNodeAspects::LoadedContextSlotsKey, Node*>
      unobserved_context_slot_stores_;
};

}  // namespace maglev
}  // namespace internal
}  // namespace v8

#endif  // V8_MAGLEV_MAGLEV_GRAPH_BUILDER_H_
```
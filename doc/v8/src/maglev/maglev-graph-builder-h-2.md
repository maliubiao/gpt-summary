Response:
The user wants a summary of the functionality of the provided C++ header file, `v8/src/maglev/maglev-graph-builder.h`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file name `maglev-graph-builder.h` strongly suggests its main function is to build a graph, likely for the Maglev compiler in V8.

2. **Analyze the provided code snippets:**  Scan through the member functions and their names to infer their roles. Look for keywords related to:
    * **Graph construction:** `StartNewBlock`, `FinishBlock`, `Add`.
    * **Value representation:** `ConvertInputTo`, `GetValueOrUndefined`.
    * **Deoptimization:** `GetDeoptFrame`, `AttachEagerDeoptInfo`, `BuildCheck`.
    * **Side effects:** `MarkPossibleSideEffect`, `ResetBuilderCachedState`.
    * **Liveness analysis:** `GetInLiveness`, `GetOutLiveness`.
    * **Node creation:** `AddNewNode`.
    * **Calls and construction:**  Functions starting with `TryReduce` and `Build` often relate to handling function calls and object construction.
    * **Property access:**  Functions like `BuildLoadField`, `TryBuildStoreField`, `TryBuildPropertyLoad`.
    * **Element access:** Functions like `BuildLoadFixedArrayElement`, `BuildStoreTypedArrayElement`.
    * **Type checks:** Functions like `BuildCheckSmi`, `BuildCheckNumber`, `BuildCheckMaps`.
    * **Object tracking:** `CanTrackObjectChanges`.
    * **Inlining:** `ShouldInlineCall`, `TryBuildInlinedCall`.
    * **Built-in functions:** `MAGLEV_REDUCED_BUILTIN`.

3. **Categorize the functionalities:** Group the identified functionalities into logical categories. This helps in organizing the summary. Good categories emerge from the analysis above: Graph Building, Deoptimization, Data Handling & Conversions, Operations & Bytecode Integration, Function Calls & Object Creation, Property & Element Access, Type Checks & Assertions, Object Tracking & Optimization.

4. **Address specific questions from the prompt:**
    * **.tq extension:** Explicitly state that the file is C++ and not Torque.
    * **Relationship with JavaScript:** Explain that this C++ code is the implementation detail for optimizing JavaScript execution. Provide illustrative JavaScript examples that would trigger the functionalities described in the header file (e.g., arithmetic operations, function calls, property access).
    * **Code logic reasoning (input/output):**  Choose a simple function, like `ConvertInputTo`, and describe a plausible input and the expected output based on its purpose.
    * **Common programming errors:**  Think about common JavaScript errors that might lead to deoptimization or different execution paths handled by this code (e.g., type mismatches, accessing non-existent properties).

5. **Summarize the overall functionality:**  Condense the categorized functionalities into a concise summary statement.

6. **Review and refine:** Ensure the summary is clear, accurate, and addresses all aspects of the prompt. Check for any redundancy or areas that could be explained more effectively. For instance, explicitly mentioning the optimization goal of the graph builder is important.

**(Self-correction during the process):**

* **Initial thought:**  Focus too much on individual function names.
* **Correction:**  Group functions by their purpose to create a more thematic and understandable summary.
* **Initial thought:**  Not enough explicit connection to JavaScript.
* **Correction:** Add concrete JavaScript examples to illustrate how the C++ code relates to user-level programming.
* **Initial thought:**  The input/output example is too complex.
* **Correction:** Choose a simpler function for the input/output demonstration.
* **Initial thought:**  Not explicitly mentioning the optimization goal.
* **Correction:** Add a sentence in the summary highlighting the optimization aspect of the graph builder.
`v8/src/maglev/maglev-graph-builder.h` 是一个 V8 源代码文件，它在 V8 的 Maglev 编译器中扮演着核心角色。根据提供的代码片段，我们可以归纳出它的以下功能：

**主要功能：构建 Maglev 图 (Graph Building)**

这个头文件定义了 `MaglevGraphBuilder` 类，该类负责将 JavaScript 字节码转换成 Maglev 图。Maglev 图是 Maglev 编译器使用的中间表示形式，用于优化 JavaScript 代码的执行。

**详细功能点：**

1. **管理编译状态:**  `MaglevGraphBuilder` 维护了编译过程中的各种状态信息，例如当前正在处理的字节码指令、当前基本块、合并状态等。

2. **处理控制流:**
   - `StartNewBlock`:  开始一个新的基本块。
   - `FinishBlock`:  完成当前基本块，并添加控制流节点（如跳转、条件分支）。
   - `StartFallthroughBlock`: 处理顺序执行的下一个基本块。
   - 它处理了控制流语句，例如 `if`, `else`, 循环等，通过创建不同的基本块和连接它们来表示程序的执行路径。

3. **处理数据流和值:**
   - `ConvertInputTo`:  将输入值转换为期望的表示形式（例如，从 Tagged 指针转换为 Int32）。
   - `GetValueOrUndefined`:  如果给定值为空，则返回 `undefined` 常量。
   - 它负责创建和管理表示程序中值的节点，并确保这些值在不同操作之间以正确的格式传递。

4. **处理函数调用和对象创建:**
   - 提供了多种 `TryReduce...` 和 `Build...` 方法来处理不同类型的函数调用（内置函数、用户定义的 JavaScript 函数、API 函数等）和对象创建。
   - `TryBuildCallKnownJSFunction`, `TryBuildInlinedCall`, `BuildGenericCall`:  处理不同类型的函数调用，包括内联优化。
   - `TryReduceConstruct...`, `BuildConstruct`: 处理对象构造过程。

5. **处理属性和元素访问:**
   - `BuildLoadField`, `TryBuildStoreField`:  处理对象属性的加载和存储。
   - `BuildLoadFixedArrayElement`, `BuildStoreFixedArrayElement`: 处理数组元素的加载和存储。
   - `TryBuildPropertyLoad`, `TryBuildPropertyStore`:  更高级别的属性访问处理，考虑了类型反馈等信息。
   - `TryBuildElementAccess...`: 处理数组元素的访问，包括不同类型的数组（例如，TypedArray）。

6. **处理类型检查和断言:**
   - `BuildCheckSmi`, `BuildCheckNumber`, `BuildCheckHeapObject`, `BuildCheckMaps`:  插入类型检查节点，确保在执行过程中值的类型符合预期。
   - `TryBuildCheckInt32Condition`:  构建用于条件分支的 Int32 类型比较。
   - `BuildCheckValue`:  检查一个节点的值是否与给定的常量值匹配。

7. **处理全局变量和上下文:**
   - `TryBuildScriptContextLoad`, `TryBuildGlobalLoad`: 处理全局变量的加载。
   - `TryBuildScriptContextStore`, `TryBuildGlobalStore`: 处理全局变量的存储。

8. **处理 Deoptimization (反优化):**
   - `GetDeoptFrameForLazyDeopt`:  为延迟反优化创建反优化帧信息。
   - `AttachEagerDeoptInfo`, `AttachDeoptCheckpoint`:  将反优化信息附加到节点上。
   - 当运行时出现类型不匹配或假设不成立时，Maglev 可以进行反优化，退回到解释器执行。这个类包含了生成必要信息的支持。

9. **处理内联缓存 (Inline Caching) 和类型反馈 (Type Feedback):**
   - 许多 `TryReduce...` 方法会利用类型反馈信息来优化代码生成。
   - 例如，在处理属性访问时，会根据之前执行时的类型信息来生成更高效的代码。

10. **处理副作用 (Side Effects):**
    - `MarkPossibleSideEffect`: 标记一个节点可能产生的副作用，例如修改对象属性。
    - `ResetBuilderCachedState`: 清除由于副作用可能导致缓存失效的状态。

11. **处理循环 (Loop Handling):**
    - `is_loop_effect_tracking()`:  表明是否正在跟踪循环中的副作用。
    - 代码中涉及到 `loop_effects_`，表明该类也负责处理循环相关的优化。

12. **对象跟踪 (Object Tracking):**
    - `CanTrackObjectChanges`:  判断是否可以跟踪对象的修改。
    - 涉及到 `VirtualObject` 的操作，表明 Maglev 尝试在编译时跟踪对象的属性，以便进行更激进的优化。

**关于文件扩展名和 Torque:**

`v8/src/maglev/maglev-graph-builder.h` 以 `.h` 结尾，这表明它是一个 C++ 头文件。如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部函数的领域特定语言。

**与 JavaScript 功能的关系及示例:**

`MaglevGraphBuilder` 的工作是优化 JavaScript 代码的执行，因此它与几乎所有的 JavaScript 功能都有关系。以下是一些 JavaScript 示例以及 `MaglevGraphBuilder` 如何处理它们：

**示例 1: 算术运算**

```javascript
function add(a, b) {
  return a + b;
}
```

`MaglevGraphBuilder` 会将 `a + b` 这个操作转换成一个加法节点。它可能会调用内部函数来执行加法，并根据 `a` 和 `b` 的类型生成不同的代码（例如，Smi 加法、浮点数加法）。

**示例 2: 函数调用**

```javascript
function greet(name) {
  console.log("Hello, " + name);
}

greet("World");
```

当调用 `greet` 函数时，`MaglevGraphBuilder` 会生成一个调用节点。它会查找 `greet` 函数的定义，传递参数，并处理返回值。如果 `greet` 是一个已知函数，Maglev 可能会尝试内联它的代码。对于 `console.log` 这样的内置函数，`MaglevGraphBuilder` 可能会调用特定的优化路径。

**示例 3: 属性访问**

```javascript
const obj = { x: 10 };
console.log(obj.x);
```

访问 `obj.x` 时，`MaglevGraphBuilder` 会生成一个属性加载节点。它会尝试确定 `obj` 的类型和布局，并生成高效的机器码来访问 `x` 属性。如果类型信息可用，它可以避免进行昂贵的查找操作。

**示例 4: 数组访问**

```javascript
const arr = [1, 2, 3];
console.log(arr[1]);
```

访问 `arr[1]` 时，`MaglevGraphBuilder` 会生成一个数组元素加载节点。它会检查 `arr` 的元素类型，并生成相应的加载指令。

**代码逻辑推理 (假设输入与输出):**

**假设输入:** 正在编译以下 JavaScript 代码片段：

```javascript
function multiply(x) {
  return x * 2;
}
```

并且当前正在处理 `x * 2` 这个乘法操作，假设 `x` 当前存储在一个 ValueNode 指针 `input_x` 中，并且已知 `input_x` 的 ValueRepresentation 是 `kInt32`。

**输出:** `ConvertInputTo(input_x, ValueRepresentation::kTagged)` 将会返回一个新的 `ValueNode` 指针，它表示 `x` 被转换为 Tagged 指针。这个新的节点可能会表示一个装箱 (boxing) 操作，将 Int32 值包装成一个 HeapObject (Smi)。

**用户常见的编程错误:**

1. **类型不匹配:**
   ```javascript
   function add(a, b) {
     return a + b;
   }

   add(10, "hello"); // 错误：加法操作数类型不一致
   ```
   在 Maglev 编译期间，如果假设 `a` 和 `b` 都是数字，但运行时 `b` 是字符串，就会触发反优化。`MaglevGraphBuilder` 生成的类型检查节点会发现这个错误。

2. **访问未定义的属性:**
   ```javascript
   const obj = { x: 10 };
   console.log(obj.y); // 错误：访问未定义的属性
   ```
   `MaglevGraphBuilder` 在处理属性加载时，可能会根据对象的类型生成特定的加载指令。如果 `y` 属性不存在，生成的代码可能会导致运行时错误或触发原型链查找。

3. **数组索引越界:**
   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[5]); // 错误：数组索引越界
   ```
   `MaglevGraphBuilder` 在处理数组元素访问时，通常会假设索引在界内。如果索引越界，生成的代码可能会访问无效的内存，导致崩溃或返回 `undefined`。

**功能归纳 (第 3 部分):**

到目前为止，根据提供的代码片段，`v8/src/maglev/maglev-graph-builder.h` 的功能主要集中在 **数据流和值的处理，以及函数调用和对象创建的中间表示构建**。它提供了将 JavaScript 操作转换为 Maglev 图节点的工具，并开始处理更复杂的语义，如函数调用、构造函数和基本数据类型的操作。  它还在为后续的优化阶段准备基础，例如通过类型转换和值表示的管理。 前面的部分（我们未看到）可能涵盖了图构建的初始化和基本框架，而后续部分可能会涉及更高级的优化和代码生成。

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
HasOutputRegister(interpreter::Register reg) const;
#endif

  DeoptFrame* GetParentDeoptFrame();
  DeoptFrame GetDeoptFrameForLazyDeopt(interpreter::Register result_location,
                                       int result_size);
  DeoptFrame GetDeoptFrameForLazyDeoptHelper(
      interpreter::Register result_location, int result_size,
      DeoptFrameScope* scope, bool mark_accumulator_dead);
  InterpretedDeoptFrame GetDeoptFrameForEntryStackCheck();

  template <typename NodeT>
  void MarkPossibleSideEffect(NodeT* node) {
    if constexpr (NodeT::kProperties.can_read() ||
                  NodeT::kProperties.can_deopt() ||
                  NodeT::kProperties.can_throw()) {
      unobserved_context_slot_stores_.clear();
    }

    // Don't do anything for nodes without side effects.
    if constexpr (!NodeT::kProperties.can_write()) return;

    if (v8_flags.maglev_cse) {
      known_node_aspects().increment_effect_epoch();
    }

    // We only need to clear unstable node aspects on the current builder, not
    // the parent, since we'll anyway copy the known_node_aspects to the parent
    // once we finish the inlined function.

    if constexpr (IsElementsArrayWrite(Node::opcode_of<NodeT>)) {
      node->ClearElementsProperties(known_node_aspects());
      if (is_loop_effect_tracking()) {
        loop_effects_->keys_cleared.insert(
            KnownNodeAspects::LoadedPropertyMapKey::Elements());
      }
    } else if constexpr (!IsSimpleFieldStore(Node::opcode_of<NodeT>) &&
                         !IsTypedArrayStore(Node::opcode_of<NodeT>)) {
      // Don't change known node aspects for simple field stores. The only
      // relevant side effect on these is writes to objects which invalidate
      // loaded properties and context slots, and we invalidate these already as
      // part of emitting the store.
      node->ClearUnstableNodeAspects(known_node_aspects());
      if (is_loop_effect_tracking()) {
        loop_effects_->unstable_aspects_cleared = true;
      }
    }

    // Simple field stores can't possibly change or migrate the map.
    static constexpr bool is_possible_map_change =
        !IsSimpleFieldStore(Node::opcode_of<NodeT>);

    // All user-observable side effects need to clear state that is cached on
    // the builder. This reset has to be propagated up through the parents.
    // TODO(leszeks): What side effects aren't observable? Maybe migrations?
    for (MaglevGraphBuilder* builder = this; builder != nullptr;
         builder = builder->parent_) {
      builder->ResetBuilderCachedState<is_possible_map_change>();
    }
  }

  template <bool is_possible_map_change = true>
  void ResetBuilderCachedState() {
    latest_checkpointed_frame_.reset();

    // If a map might have changed, then we need to re-check it for for-in.
    // TODO(leszeks): Track this on merge states / known node aspects, rather
    // than on the graph, so that it can survive control flow.
    if constexpr (is_possible_map_change) {
      current_for_in_state.receiver_needs_map_check = true;
    }
  }

  int next_offset() const {
    return iterator_.current_offset() + iterator_.current_bytecode_size();
  }
  const compiler::BytecodeLivenessState* GetInLiveness() const {
    return GetInLivenessFor(iterator_.current_offset());
  }
  const compiler::BytecodeLivenessState* GetInLivenessFor(int offset) const {
    return bytecode_analysis().GetInLivenessFor(offset);
  }
  const compiler::BytecodeLivenessState* GetOutLiveness() const {
    return GetOutLivenessFor(iterator_.current_offset());
  }
  const compiler::BytecodeLivenessState* GetOutLivenessFor(int offset) const {
    return bytecode_analysis().GetOutLivenessFor(offset);
  }

  void StartNewBlock(int offset, BasicBlock* predecessor) {
    StartNewBlock(predecessor, merge_states_[offset], jump_targets_[offset]);
  }

  void StartNewBlock(BasicBlock* predecessor,
                     MergePointInterpreterFrameState* merge_state,
                     BasicBlockRef& refs_to_block) {
    DCHECK_NULL(current_block_);
    current_block_ = zone()->New<BasicBlock>(merge_state, zone());
    if (merge_state == nullptr) {
      DCHECK_NOT_NULL(predecessor);
      current_block_->set_predecessor(predecessor);
    } else {
      merge_state->InitializeWithBasicBlock(current_block_);
    }
    refs_to_block.Bind(current_block_);
  }

  template <UseReprHintRecording hint = UseReprHintRecording::kRecord>
  ValueNode* ConvertInputTo(ValueNode* input, ValueRepresentation expected) {
    ValueRepresentation repr = input->properties().value_representation();
    if (repr == expected) return input;
    switch (expected) {
      case ValueRepresentation::kTagged:
        return GetTaggedValue(input, hint);
      case ValueRepresentation::kInt32:
        return GetInt32(input);
      case ValueRepresentation::kFloat64:
      case ValueRepresentation::kHoleyFloat64:
        return GetFloat64(input);
      case ValueRepresentation::kUint32:
      case ValueRepresentation::kIntPtr:
        // These conversion should be explicitly done beforehand.
        UNREACHABLE();
    }
  }

  template <typename NodeT>
  static constexpr UseReprHintRecording ShouldRecordUseReprHint() {
    // We do not record a Tagged use on Return, since they are never on the hot
    // path, and will lead to a maximum of one additional Tagging operation in
    // the worst case. This allows loop accumulator to be untagged even if they
    // are later returned.
    if constexpr (std::is_same_v<NodeT, Return>) {
      return UseReprHintRecording::kDoNotRecord;
    } else {
      return UseReprHintRecording::kRecord;
    }
  }

  template <typename NodeT>
  void SetNodeInputs(NodeT* node, std::initializer_list<ValueNode*> inputs) {
    // Nodes with zero input count don't have kInputTypes defined.
    if constexpr (NodeT::kInputCount > 0) {
      constexpr UseReprHintRecording hint = ShouldRecordUseReprHint<NodeT>();
      int i = 0;
      for (ValueNode* input : inputs) {
        DCHECK_NOT_NULL(input);
        node->set_input(i, ConvertInputTo<hint>(input, NodeT::kInputTypes[i]));
        i++;
      }
    }
  }

  template <typename ControlNodeT, typename... Args>
  BasicBlock* FinishBlock(std::initializer_list<ValueNode*> control_inputs,
                          Args&&... args) {
    ControlNodeT* control_node = NodeBase::New<ControlNodeT>(
        zone(), control_inputs.size(), std::forward<Args>(args)...);
    SetNodeInputs(control_node, control_inputs);
    AttachEagerDeoptInfo(control_node);
    AttachDeoptCheckpoint(control_node);
    static_assert(!ControlNodeT::kProperties.can_lazy_deopt());
    static_assert(!ControlNodeT::kProperties.can_throw());
    static_assert(!ControlNodeT::kProperties.can_write());
    control_node->set_owner(current_block_);
    current_block_->set_control_node(control_node);
    // Clear unobserved context slot stores when there is any controlflow.
    // TODO(olivf): More precision could be achieved by tracking dominating
    // stores within known_node_aspects. For this we could use a stack of
    // stores, which we push on split and pop on merge.
    unobserved_context_slot_stores_.clear();

    BasicBlock* block = current_block_;
    current_block_ = nullptr;

    graph()->Add(block);
    if (has_graph_labeller()) {
      graph_labeller()->RegisterNode(control_node, compilation_unit_,
                                     BytecodeOffset(iterator_.current_offset()),
                                     current_source_position_);
      graph_labeller()->RegisterBasicBlock(block);
      if (v8_flags.trace_maglev_graph_building) {
        bool kSkipTargets = true;
        std::cout << "  " << control_node << "  "
                  << PrintNodeLabel(graph_labeller(), control_node) << ": "
                  << PrintNode(graph_labeller(), control_node, kSkipTargets)
                  << std::endl;
      }
    }
    return block;
  }

  void StartFallthroughBlock(int next_block_offset, BasicBlock* predecessor) {
    // Start a new block for the fallthrough path, unless it's a merge point, in
    // which case we merge our state into it. That merge-point could also be a
    // loop header, in which case the merge state might not exist yet (if the
    // only predecessors are this path and the JumpLoop).
    DCHECK_NULL(current_block_);

    if (predecessor_count(next_block_offset) == 1) {
      if (v8_flags.trace_maglev_graph_building) {
        std::cout << "== New block (single fallthrough) at "
                  << *compilation_unit_->shared_function_info().object()
                  << "==" << std::endl;
        PrintVirtualObjects();
      }
      StartNewBlock(next_block_offset, predecessor);
    } else {
      MergeIntoFrameState(predecessor, next_block_offset);
    }
  }

  ValueNode* GetValueOrUndefined(ValueNode* maybe_value) {
    if (maybe_value == nullptr) {
      return GetRootConstant(RootIndex::kUndefinedValue);
    }
    return maybe_value;
  }

  ValueNode* GetConvertReceiver(compiler::SharedFunctionInfoRef shared,
                                const CallArguments& args);

  compiler::OptionalHeapObjectRef TryGetConstant(
      ValueNode* node, ValueNode** constant_node = nullptr);

  template <typename LoadNode>
  ReduceResult TryBuildLoadDataView(const CallArguments& args,
                                    ExternalArrayType type);
  template <typename StoreNode, typename Function>
  ReduceResult TryBuildStoreDataView(const CallArguments& args,
                                     ExternalArrayType type,
                                     Function&& getValue);

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
#define CONTINUATION_PRESERVED_EMBEDDER_DATA_LIST(V) \
  V(GetContinuationPreservedEmbedderData)            \
  V(SetContinuationPreservedEmbedderData)
#else
#define CONTINUATION_PRESERVED_EMBEDDER_DATA_LIST(V)
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

#define MAGLEV_REDUCED_BUILTIN(V)              \
  V(ArrayConstructor)                          \
  V(ArrayForEach)                              \
  V(ArrayIsArray)                              \
  V(ArrayIteratorPrototypeNext)                \
  V(ArrayPrototypeEntries)                     \
  V(ArrayPrototypeKeys)                        \
  V(ArrayPrototypeValues)                      \
  V(DataViewPrototypeGetInt8)                  \
  V(DataViewPrototypeSetInt8)                  \
  V(DataViewPrototypeGetInt16)                 \
  V(DataViewPrototypeSetInt16)                 \
  V(DataViewPrototypeGetInt32)                 \
  V(DataViewPrototypeSetInt32)                 \
  V(DataViewPrototypeGetFloat64)               \
  V(DataViewPrototypeSetFloat64)               \
  V(FunctionPrototypeApply)                    \
  V(FunctionPrototypeCall)                     \
  V(FunctionPrototypeHasInstance)              \
  V(ObjectPrototypeGetProto)                   \
  V(ObjectGetPrototypeOf)                      \
  V(ReflectGetPrototypeOf)                     \
  V(ObjectPrototypeHasOwnProperty)             \
  V(NumberParseInt)                            \
  V(MathCeil)                                  \
  V(MathFloor)                                 \
  V(MathPow)                                   \
  V(ArrayPrototypePush)                        \
  V(ArrayPrototypePop)                         \
  V(MathAbs)                                   \
  V(MathRound)                                 \
  V(StringConstructor)                         \
  V(StringFromCharCode)                        \
  V(StringPrototypeCharCodeAt)                 \
  V(StringPrototypeCodePointAt)                \
  V(StringPrototypeIterator)                   \
  IF_INTL(V, StringPrototypeLocaleCompareIntl) \
  CONTINUATION_PRESERVED_EMBEDDER_DATA_LIST(V) \
  IEEE_754_UNARY_LIST(V)

#define DEFINE_BUILTIN_REDUCER(Name, ...)                      \
  ReduceResult TryReduce##Name(compiler::JSFunctionRef target, \
                               CallArguments& args);
  MAGLEV_REDUCED_BUILTIN(DEFINE_BUILTIN_REDUCER)
#undef DEFINE_BUILTIN_REDUCER

  ReduceResult TryReduceGetProto(ValueNode* node);

  template <typename MapKindsT, typename IndexToElementsKindFunc,
            typename BuildKindSpecificFunc>
  ReduceResult BuildJSArrayBuiltinMapSwitchOnElementsKind(
      ValueNode* receiver, const MapKindsT& map_kinds,
      MaglevSubGraphBuilder& sub_graph,
      std::optional<MaglevSubGraphBuilder::Label>& do_return,
      int unique_kind_count, IndexToElementsKindFunc&& index_to_elements_kind,
      BuildKindSpecificFunc&& build_kind_specific);

  ReduceResult DoTryReduceMathRound(CallArguments& args,
                                    Float64Round::Kind kind);

  template <typename CallNode, typename... Args>
  CallNode* AddNewCallNode(const CallArguments& args, Args&&... extra_args);

  ReduceResult TryReduceGetIterator(ValueNode* receiver, int load_slot,
                                    int call_slot);

  ValueNode* BuildCallSelf(ValueNode* context, ValueNode* function,
                           ValueNode* new_target,
                           compiler::SharedFunctionInfoRef shared,
                           CallArguments& args);
  ReduceResult TryReduceBuiltin(
      compiler::JSFunctionRef target, compiler::SharedFunctionInfoRef shared,
      CallArguments& args, const compiler::FeedbackSource& feedback_source);
  bool TargetIsCurrentCompilingUnit(compiler::JSFunctionRef target);
  ReduceResult TryBuildCallKnownJSFunction(
      compiler::JSFunctionRef function, ValueNode* new_target,
      CallArguments& args, const compiler::FeedbackSource& feedback_source);
  ReduceResult TryBuildCallKnownJSFunction(
      ValueNode* context, ValueNode* function, ValueNode* new_target,
      compiler::SharedFunctionInfoRef shared,
      compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
      const compiler::FeedbackSource& feedback_source);
  bool ShouldInlineCall(compiler::SharedFunctionInfoRef shared,
                        compiler::OptionalFeedbackVectorRef feedback_vector,
                        float call_frequency);
  ReduceResult TryBuildInlinedCall(
      ValueNode* context, ValueNode* function, ValueNode* new_target,
      compiler::SharedFunctionInfoRef shared,
      compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
      const compiler::FeedbackSource& feedback_source);
  ValueNode* BuildGenericCall(ValueNode* target, Call::TargetType target_type,
                              const CallArguments& args);
  ReduceResult ReduceCallForConstant(
      compiler::JSFunctionRef target, CallArguments& args,
      const compiler::FeedbackSource& feedback_source =
          compiler::FeedbackSource());
  ReduceResult ReduceCallForTarget(
      ValueNode* target_node, compiler::JSFunctionRef target,
      CallArguments& args, const compiler::FeedbackSource& feedback_source);
  ReduceResult ReduceCallForNewClosure(
      ValueNode* target_node, ValueNode* target_context,
      compiler::SharedFunctionInfoRef shared,
      compiler::OptionalFeedbackVectorRef feedback_vector, CallArguments& args,
      const compiler::FeedbackSource& feedback_source);
  ReduceResult TryBuildCallKnownApiFunction(
      compiler::JSFunctionRef function, compiler::SharedFunctionInfoRef shared,
      CallArguments& args);
  compiler::HolderLookupResult TryInferApiHolderValue(
      compiler::FunctionTemplateInfoRef function_template_info,
      ValueNode* receiver);
  ReduceResult ReduceCallForApiFunction(
      compiler::FunctionTemplateInfoRef api_callback,
      compiler::OptionalSharedFunctionInfoRef maybe_shared,
      compiler::OptionalJSObjectRef api_holder, CallArguments& args);
  ReduceResult ReduceFunctionPrototypeApplyCallWithReceiver(
      compiler::OptionalHeapObjectRef maybe_receiver, CallArguments& args,
      const compiler::FeedbackSource& feedback_source);
  ReduceResult ReduceCallWithArrayLikeForArgumentsObject(
      ValueNode* target_node, CallArguments& args,
      VirtualObject* arguments_object,
      const compiler::FeedbackSource& feedback_source);
  ReduceResult ReduceCallWithArrayLike(
      ValueNode* target_node, CallArguments& args,
      const compiler::FeedbackSource& feedback_source);
  ReduceResult ReduceCall(ValueNode* target_node, CallArguments& args,
                          const compiler::FeedbackSource& feedback_source =
                              compiler::FeedbackSource());
  void BuildCallWithFeedback(ValueNode* target_node, CallArguments& args,
                             const compiler::FeedbackSource& feedback_source);
  void BuildCallFromRegisterList(ConvertReceiverMode receiver_mode);
  void BuildCallFromRegisters(int argc_count,
                              ConvertReceiverMode receiver_mode);

  ValueNode* BuildElementsArray(int length);
  ValueNode* BuildAndAllocateKeyValueArray(ValueNode* key, ValueNode* value);
  ValueNode* BuildAndAllocateJSArray(
      compiler::MapRef map, ValueNode* length, ValueNode* elements,
      const compiler::SlackTrackingPrediction& slack_tracking_prediction,
      AllocationType allocation_type);
  ValueNode* BuildAndAllocateJSArrayIterator(ValueNode* array,
                                             IterationKind iteration_kind);

  ReduceResult TryBuildAndAllocateJSGeneratorObject(ValueNode* closure,
                                                    ValueNode* receiver);

  ValueNode* BuildGenericConstruct(
      ValueNode* target, ValueNode* new_target, ValueNode* context,
      const CallArguments& args,
      const compiler::FeedbackSource& feedback_source =
          compiler::FeedbackSource());

  ReduceResult TryReduceConstructArrayConstructor(
      compiler::JSFunctionRef array_function, CallArguments& args,
      compiler::OptionalAllocationSiteRef maybe_allocation_site = {});
  ReduceResult TryReduceConstructBuiltin(
      compiler::JSFunctionRef builtin,
      compiler::SharedFunctionInfoRef shared_function_info, ValueNode* target,
      CallArguments& args);
  ReduceResult TryReduceConstructGeneric(
      compiler::JSFunctionRef function,
      compiler::SharedFunctionInfoRef shared_function_info, ValueNode* target,
      ValueNode* new_target, CallArguments& args,
      compiler::FeedbackSource& feedback_source);
  ReduceResult TryReduceConstruct(compiler::HeapObjectRef feedback_target,
                                  ValueNode* target, ValueNode* new_target,
                                  CallArguments& args,
                                  compiler::FeedbackSource& feedback_source);
  void BuildConstruct(ValueNode* target, ValueNode* new_target,
                      CallArguments& args,
                      compiler::FeedbackSource& feedback_source);

  ReduceResult TryBuildScriptContextStore(
      const compiler::GlobalAccessFeedback& global_access_feedback);
  ReduceResult TryBuildPropertyCellStore(
      const compiler::GlobalAccessFeedback& global_access_feedback);
  ReduceResult TryBuildGlobalStore(
      const compiler::GlobalAccessFeedback& global_access_feedback);

  ReduceResult TryBuildScriptContextConstantLoad(
      const compiler::GlobalAccessFeedback& global_access_feedback);
  ReduceResult TryBuildScriptContextLoad(
      const compiler::GlobalAccessFeedback& global_access_feedback);
  ReduceResult TryBuildPropertyCellLoad(
      const compiler::GlobalAccessFeedback& global_access_feedback);
  ReduceResult TryBuildGlobalLoad(
      const compiler::GlobalAccessFeedback& global_access_feedback);

  bool TryBuildFindNonDefaultConstructorOrConstruct(
      ValueNode* this_function, ValueNode* new_target,
      std::pair<interpreter::Register, interpreter::Register> result);

  ValueNode* BuildSmiUntag(ValueNode* node);
  ValueNode* BuildNumberOrOddballToFloat64(
      ValueNode* node, TaggedToFloat64ConversionType conversion_type);

  ReduceResult BuildCheckSmi(ValueNode* object, bool elidable = true);
  void BuildCheckNumber(ValueNode* object);
  void BuildCheckHeapObject(ValueNode* object);
  void BuildCheckJSReceiver(ValueNode* object);
  void BuildCheckString(ValueNode* object);
  void BuildCheckStringOrStringWrapper(ValueNode* object);
  void BuildCheckSymbol(ValueNode* object);
  ReduceResult BuildCheckMaps(ValueNode* object,
                              base::Vector<const compiler::MapRef> maps,
                              std::optional<ValueNode*> map = {});
  ReduceResult BuildTransitionElementsKindOrCheckMap(
      ValueNode* heap_object, ValueNode* object_map,
      const ZoneVector<compiler::MapRef>& transition_sources,
      compiler::MapRef transition_target);
  ReduceResult BuildCompareMaps(
      ValueNode* heap_object, ValueNode* object_map,
      base::Vector<const compiler::MapRef> maps,
      MaglevSubGraphBuilder* sub_graph,
      std::optional<MaglevSubGraphBuilder::Label>& if_not_matched);
  ReduceResult BuildTransitionElementsKindAndCompareMaps(
      ValueNode* heap_object, ValueNode* object_map,
      const ZoneVector<compiler::MapRef>& transition_sources,
      compiler::MapRef transition_target, MaglevSubGraphBuilder* sub_graph,
      std::optional<MaglevSubGraphBuilder::Label>& if_not_matched);
  // Emits an unconditional deopt and returns false if the node is a constant
  // that doesn't match the ref.
  ReduceResult BuildCheckValue(ValueNode* node, compiler::ObjectRef ref);
  ReduceResult BuildCheckValue(ValueNode* node, compiler::HeapObjectRef ref);

  ValueNode* BuildConvertHoleToUndefined(ValueNode* node);
  ReduceResult BuildCheckNotHole(ValueNode* node);

  template <bool flip = false>
  ValueNode* BuildToBoolean(ValueNode* node);
  ValueNode* BuildLogicalNot(ValueNode* value);
  ValueNode* BuildTestUndetectable(ValueNode* value);
  void BuildToNumberOrToNumeric(Object::Conversion mode);

  enum class TrackObjectMode { kLoad, kStore };
  bool CanTrackObjectChanges(ValueNode* object, TrackObjectMode mode);
  bool CanElideWriteBarrier(ValueNode* object, ValueNode* value);

  void BuildInitializeStore(InlinedAllocation* alloc, ValueNode* value,
                            int offset);
  void TryBuildStoreTaggedFieldToAllocation(ValueNode* object, ValueNode* value,
                                            int offset);
  template <typename Instruction = LoadTaggedField, typename... Args>
  ValueNode* BuildLoadTaggedField(ValueNode* object, uint32_t offset,
                                  Args&&... args) {
    if (offset != HeapObject::kMapOffset &&
        CanTrackObjectChanges(object, TrackObjectMode::kLoad)) {
      VirtualObject* vobject =
          GetObjectFromAllocation(object->Cast<InlinedAllocation>());
      ValueNode* value;
      CHECK_NE(vobject->type(), VirtualObject::kHeapNumber);
      if (vobject->type() == VirtualObject::kDefault) {
        value = vobject->get(offset);
      } else {
        DCHECK_EQ(vobject->type(), VirtualObject::kFixedDoubleArray);
        // The only offset we're allowed to read from the a FixedDoubleArray as
        // tagged field is the length.
        CHECK_EQ(offset, offsetof(FixedDoubleArray, length_));
        value = GetInt32Constant(vobject->double_elements_length());
      }
      if (v8_flags.trace_maglev_object_tracking) {
        std::cout << "  * Reusing value in virtual object "
                  << PrintNodeLabel(graph_labeller(), vobject) << "[" << offset
                  << "]: " << PrintNode(graph_labeller(), value) << std::endl;
      }
      return value;
    }
    return AddNewNode<Instruction>({object}, offset,
                                   std::forward<Args>(args)...);
  }

  Node* BuildStoreTaggedField(ValueNode* object, ValueNode* value, int offset,
                              StoreTaggedMode store_mode);
  void BuildStoreTaggedFieldNoWriteBarrier(ValueNode* object, ValueNode* value,
                                           int offset,
                                           StoreTaggedMode store_mode);
  void BuildStoreTrustedPointerField(ValueNode* object, ValueNode* value,
                                     int offset, IndirectPointerTag tag,
                                     StoreTaggedMode store_mode);

  ValueNode* BuildLoadFixedArrayElement(ValueNode* elements, int index);
  ValueNode* BuildLoadFixedArrayElement(ValueNode* elements, ValueNode* index);
  void BuildStoreFixedArrayElement(ValueNode* elements, ValueNode* index,
                                   ValueNode* value);

  ValueNode* BuildLoadFixedDoubleArrayElement(ValueNode* elements, int index);
  ValueNode* BuildLoadFixedDoubleArrayElement(ValueNode* elements,
                                              ValueNode* index);
  void BuildStoreFixedDoubleArrayElement(ValueNode* elements, ValueNode* index,
                                         ValueNode* value);

  ValueNode* BuildLoadHoleyFixedDoubleArrayElement(ValueNode* elements,
                                                   ValueNode* index,
                                                   bool convert_hole);

  ValueNode* GetInt32ElementIndex(interpreter::Register reg) {
    ValueNode* index_object = current_interpreter_frame_.get(reg);
    return GetInt32ElementIndex(index_object);
  }
  ValueNode* GetInt32ElementIndex(ValueNode* index_object);

  ReduceResult GetUint32ElementIndex(interpreter::Register reg) {
    ValueNode* index_object = current_interpreter_frame_.get(reg);
    return GetUint32ElementIndex(index_object);
  }
  ReduceResult GetUint32ElementIndex(ValueNode* index_object);

  bool CanTreatHoleAsUndefined(
      base::Vector<const compiler::MapRef> const& receiver_maps);

  compiler::OptionalObjectRef TryFoldLoadDictPrototypeConstant(
      compiler::PropertyAccessInfo const& access_info);
  compiler::OptionalJSObjectRef TryGetConstantDataFieldHolder(
      compiler::PropertyAccessInfo const& access_info,
      ValueNode* lookup_start_object);
  compiler::OptionalObjectRef TryFoldLoadConstantDataField(
      compiler::JSObjectRef holder,
      compiler::PropertyAccessInfo const& access_info);
  std::optional<Float64> TryFoldLoadConstantDoubleField(
      compiler::JSObjectRef holder,
      compiler::PropertyAccessInfo const& access_info);

  // Returns the loaded value node but doesn't update the accumulator yet.
  ValueNode* BuildLoadField(compiler::PropertyAccessInfo const& access_info,
                            ValueNode* lookup_start_object,
                            compiler::NameRef name);
  ReduceResult TryBuildStoreField(
      compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
      compiler::AccessMode access_mode);
  ReduceResult TryBuildPropertyGetterCall(
      compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
      ValueNode* lookup_start_object);
  ReduceResult TryBuildPropertySetterCall(
      compiler::PropertyAccessInfo const& access_info, ValueNode* receiver,
      ValueNode* lookup_start_object, ValueNode* value);
  bool TryBuildGetKeyedPropertyWithEnumeratedKey(
      ValueNode* object, const compiler::FeedbackSource& feedback_source,
      const compiler::ProcessedFeedback& processed_feedback);
  void BuildGetKeyedProperty(
      ValueNode* object, const compiler::FeedbackSource& feedback_source,
      const compiler::ProcessedFeedback& processed_feedback);

  ValueNode* BuildLoadFixedArrayLength(ValueNode* fixed_array);
  ValueNode* BuildLoadJSArrayLength(ValueNode* js_array,
                                    NodeType length_type = NodeType::kSmi);
  ValueNode* BuildLoadElements(ValueNode* object);

  ReduceResult TryBuildCheckInt32Condition(ValueNode* lhs, ValueNode* rhs,
                                           AssertCondition condition,
                                           DeoptimizeReason reason);

  ReduceResult TryBuildPropertyLoad(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NameRef name, compiler::PropertyAccessInfo const& access_info);
  ReduceResult TryBuildPropertyStore(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NameRef name, compiler::PropertyAccessInfo const& access_info,
      compiler::AccessMode access_mode);
  ReduceResult TryBuildPropertyAccess(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NameRef name, compiler::PropertyAccessInfo const& access_info,
      compiler::AccessMode access_mode);
  template <typename GenericAccessFunc>
  ReduceResult TryBuildNamedAccess(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NamedAccessFeedback const& feedback,
      compiler::FeedbackSource const& feedback_source,
      compiler::AccessMode access_mode,
      GenericAccessFunc&& build_generic_access);

  template <typename GenericAccessFunc>
  ReduceResult TryBuildLoadNamedProperty(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NameRef name, compiler::FeedbackSource& feedback_source,
      GenericAccessFunc&& build_generic_access);
  ReduceResult TryBuildLoadNamedProperty(
      ValueNode* receiver, compiler::NameRef name,
      compiler::FeedbackSource& feedback_source);

  ReduceResult BuildLoadTypedArrayLength(ValueNode* object,
                                         ElementsKind elements_kind);
  ValueNode* BuildLoadTypedArrayElement(ValueNode* object, ValueNode* index,
                                        ElementsKind elements_kind);
  void BuildStoreTypedArrayElement(ValueNode* object, ValueNode* index,
                                   ElementsKind elements_kind);

  ReduceResult TryBuildElementAccessOnString(
      ValueNode* object, ValueNode* index,
      compiler::KeyedAccessMode const& keyed_mode);
  ReduceResult TryBuildElementAccessOnTypedArray(
      ValueNode* object, ValueNode* index,
      const compiler::ElementAccessInfo& access_info,
      compiler::KeyedAccessMode const& keyed_mode);
  ReduceResult TryBuildElementLoadOnJSArrayOrJSObject(
      ValueNode* object, ValueNode* index,
      base::Vector<const compiler::MapRef> maps, ElementsKind kind,
      KeyedAccessLoadMode load_mode);
  ReduceResult TryBuildElementStoreOnJSArrayOrJSObject(
      ValueNode* object, ValueNode* index_object, ValueNode* value,
      base::Vector<const compiler::MapRef> maps, ElementsKind kind,
      const compiler::KeyedAccessMode& keyed_mode);
  ReduceResult TryBuildElementAccessOnJSArrayOrJSObject(
      ValueNode* object, ValueNode* index,
      const compiler::ElementAccessInfo& access_info,
      compiler::KeyedAccessMode const& keyed_mode);
  template <typename GenericAccessFunc>
  ReduceResult TryBuildElementAccess(
      ValueNode* object, ValueNode* index,
      compiler::ElementAccessFeedback const& feedback,
      compiler::FeedbackSource const& feedback_source,
      GenericAccessFunc&& build_generic_access);
  template <typename GenericAccessFunc>
  ReduceResult TryBuildPolymorphicElementAccess(
      ValueNode* object, ValueNode* index,
      const compiler::KeyedAccessMode& keyed_mode,
      const ZoneVector<compiler::ElementAccessInfo>& access_infos,
      GenericAccessFunc&& build_generic_access);
  template <typename GenericAccessFunc>
  ReduceResult TryBuildPolymorphicPropertyAccess(
      ValueNode* receiver, ValueNode* lookup_start_object,
      compiler::NamedAccessFeedback const& feedback,
      compiler::AccessMode access_mode,
      const ZoneVector<compiler::PropertyAccessInfo>& access_infos,
      GenericAccessFunc&& build_generic_access);

  // Load elimination -- when loading or storing a simple property without
  // side effects, record its value, and allow that value to be re-used on
  // subsequent loads.
  void RecordKnownProperty(ValueNode* lookup_start_object,
                           KnownNodeAspects::LoadedPropertyMapKey key,
                           ValueNode* value, bool is_const,
                           compiler::AccessMode access_mode);
  ReduceResult TryReuseKnownPropertyLoad(ValueNode* lookup_start_object,
                                         compiler::NameRef name);
  ValueNode* BuildLoadStringLength(ValueNode* string);

  // Converts the input node to a representation that's valid to store into an
  // array with elements kind |kind|.
  ReduceResult ConvertForStoring(ValueNode* node, ElementsKind kind);

  enum InferHasInPrototypeChainResult {
    kMayBeInPrototypeChain,
    kIsInPrototypeChain,
    kIsNotInPrototypeChain
  };
  InferHasInPrototypeChainResult InferHasInPrototypeChain(
      ValueNode* receiver, compiler::HeapObjectRef prototype);
  ReduceResult TryBuildFastHasInPrototypeChain(
      ValueNode* object, compiler::HeapObjectRef prototype);
  ReduceResult BuildHasInPrototypeChain(ValueNode* object,
                                        compiler::HeapObjectRef prototype);
  ReduceResult TryBuildFastOrdina
```
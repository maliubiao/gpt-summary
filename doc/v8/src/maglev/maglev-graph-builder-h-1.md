Response:
The user wants a summary of the functionality of the provided C++ header file.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core class:** The name `MaglevGraphBuilder` strongly suggests this file is about building a graph data structure. The context "v8/src/maglev" points to a component within V8 responsible for optimization (Maglev is an intermediate tier optimizing compiler).

2. **Look for key methods and patterns:** Scan the code for recurring patterns and important-looking methods.
    * Methods starting with `Visit` clearly relate to processing different bytecode instructions.
    * Methods like `AddNewNode`, `CreateNewConstantNode`, and `AttachExtraInfoAndAddToGraph` are central to graph construction.
    * The presence of `Get...` and `Set...` methods related to registers (`GetAccumulator`, `SetAccumulator`, `StoreRegister`) indicates the graph builder manages register state.
    * The interaction with `interpreter::Bytecode` and `interpreter::Register` confirms the connection to V8's bytecode interpreter.
    * The `#ifdef DEBUG` sections suggest debugging and verification features.
    * The presence of `CatchBlockDetails` and related methods points to handling exceptions and try-catch blocks.
    * Template usage with `NodeT` suggests the builder works with different kinds of nodes in the graph.

3. **Infer functionality from method names and arguments:**
    * `Visit##name()`:  Processes specific bytecode instructions.
    * `AddNewNode<NodeT>`: Creates and adds a new node of type `NodeT` to the graph.
    * `CreateNewConstantNode<NodeT>`: Creates constant value nodes.
    * `GetTaggedValue`, `GetSmiValue`, `GetInt32`, `GetFloat64`:  Handles different data representations and performs type conversions/checks.
    * `BuildCallBuiltin`, `BuildCallRuntime`, `BuildCallCPPBuiltin`:  Creates nodes for calling built-in functions, runtime functions, and C++ built-ins.
    * `LoadRegister`, `StoreRegister`: Manages the flow of data between registers and graph nodes.
    * `BuildLoadContextSlot`, `BuildStoreContextSlot`: Deals with accessing variables from the JavaScript context.

4. **Connect functionality to the overall purpose:** The graph builder takes bytecode as input and transforms it into a graph representation. This graph likely represents the control flow and data flow of the JavaScript code, facilitating optimization.

5. **Address specific points from the prompt:**
    * **Filename ending with .tq:**  The prompt provides the information that if the filename ended with `.tq`, it would be a Torque source file. Since it ends in `.h`, it's a regular C++ header file.
    * **Relationship to JavaScript:** The builder processes bytecode generated from JavaScript, manages context, and deals with JavaScript value types. The example about adding numbers directly illustrates this connection.
    * **Code logic and examples:**  The core logic revolves around iterating through bytecode and creating corresponding graph nodes. The example of adding two registers demonstrates the input (two registers holding values) and output (a new Add node).
    * **Common programming errors:**  Type errors in JavaScript translate to type checks and potential deoptimizations within the graph builder. The example of adding a string and a number shows a case where the builder needs to handle different types.

6. **Structure the summary:** Organize the information logically, starting with the main purpose and then detailing specific functionalities. Use clear and concise language. Group related functionalities (e.g., node creation, register management, context handling).

7. **Refine and iterate:** Review the summary for clarity, accuracy, and completeness. Ensure it addresses all aspects of the prompt. For example, explicitly mention the handling of control flow (jumps, loops).

By following these steps, we can construct a comprehensive and accurate summary of the `MaglevGraphBuilder`'s functionality based on the provided code snippet.
Based on the provided code snippet from `v8/src/maglev/maglev-graph-builder.h`, here's a summary of its functionality:

**Core Functionality:**

The `MaglevGraphBuilder` class is responsible for constructing the Maglev graph, an intermediate representation of JavaScript code used for optimization within the V8 JavaScript engine. It does this by iterating through the bytecode of a JavaScript function and creating corresponding nodes in the graph.

**Key Features and Responsibilities:**

* **Bytecode Processing:** The core of its operation involves iterating through the bytecode instructions of a function (`VisitBytecodes` method) and calling specific `Visit` methods for each bytecode (e.g., `VisitLdar`, `VisitAdd`).
* **Graph Node Creation:** It provides methods for creating various types of nodes in the Maglev graph, such as:
    * **Value Nodes:** Represent values (e.g., constants, register values, results of operations). Examples include `AddNewNode`, `CreateNewConstantNode`.
    * **Operation Nodes:** Represent operations performed on values (e.g., addition, function calls).
    * **Control Flow Nodes:**  Implicitly managed through the block structure and jump targets.
* **Register Management:** It keeps track of the state of interpreter registers (`current_interpreter_frame_`) and provides methods to load values from and store values into these registers (`LoadRegister`, `StoreRegister`, `GetAccumulator`, `SetAccumulator`).
* **Common Subexpression Elimination (CSE):**  The code includes logic for CSE (`AddNewNodeOrGetEquivalent`), which aims to reuse the results of previously computed expressions to avoid redundant calculations. This is controlled by the `v8_flags.maglev_cse` flag.
* **Type Handling and Conversions:** It manages different representations of JavaScript values (e.g., tagged, Smi, Int32, Float64) and provides methods for converting between them (`GetTaggedValue`, `GetSmiValue`, `GetInt32`, `GetFloat64`). It also handles implicit type conversions like ToNumber.
* **Built-in and Runtime Function Calls:**  It provides methods to create nodes for calling built-in functions (`BuildCallBuiltin`), runtime functions (`BuildCallRuntime`), and C++ built-ins (`BuildCallCPPBuiltin`).
* **Context Management:** It handles the JavaScript context (`GetContext`, `SetContext`) and provides methods for loading and storing values from context slots (`BuildLoadContextSlot`, `BuildStoreContextSlot`).
* **Exception Handling:** It supports try-catch blocks and manages the stack of active catch blocks (`catch_block_stack_`).
* **Deoptimization:** It inserts deoptimization checkpoints into the graph and attaches information needed for lazy and eager deoptimization (`AttachDeoptCheckpoint`, `AttachEagerDeoptInfo`, `AttachLazyDeoptInfo`).
* **Debugging and Tracing:**  Includes conditional debug logging (`v8_flags.trace_maglev_graph_building`) and the ability to register nodes with a graph labeller.
* **Constant Handling:**  Provides methods to get constant values (e.g., `GetConstant`, `GetRootConstant`, `GetBooleanConstant`).

**Regarding the filename and Torque:**

The prompt correctly states that if `v8/src/maglev/maglev-graph-builder.h` ended with `.tq`, it would be a V8 Torque source file. Since it ends with `.h`, it is a standard C++ header file.

**Relationship to JavaScript and Examples:**

The `MaglevGraphBuilder` directly translates JavaScript bytecode into its graph representation. Here are some examples of how its functionality relates to JavaScript:

**JavaScript Example 1: Simple Addition**

```javascript
function add(a, b) {
  return a + b;
}
```

The `MaglevGraphBuilder` would process the bytecode for this function. Hypothetically, some of the `Visit` methods called might include:

* `VisitLdar`: Load the value of `a` into a register.
* `VisitLdar`: Load the value of `b` into another register.
* `VisitAdd`:  Create an "Add" node in the graph, taking the registers holding `a` and `b` as inputs.
* `VisitReturn`: Create a "Return" node, taking the output of the "Add" node as input.

**Code Logic and Hypothetical Input/Output (Addition Example):**

**Assumption:** Let's assume the `add` function's bytecode starts with instructions to load the arguments `a` and `b` into registers `r0` and `r1` respectively, and the `+` operation corresponds to the `interpreter::Bytecode::kAdd` bytecode.

**Hypothetical Input:**

* `iterator_.current_bytecode()` is `interpreter::Bytecode::kAdd`.
* `current_interpreter_frame_.get(interpreter::Register(0))` returns a node representing the value of `a`.
* `current_interpreter_frame_.get(interpreter::Register(1))` returns a node representing the value of `b`.

**Hypothetical Output:**

* The `VisitAdd()` method (not shown in the snippet but would be present in the corresponding `.cc` file) would likely call `AddNewNode<Add>({current_interpreter_frame_.get(interpreter::Register(0)), current_interpreter_frame_.get(interpreter::Register(1))})`, creating a new `Add` node in the graph with the nodes representing `a` and `b` as inputs.

**User Programming Errors:**

The `MaglevGraphBuilder` indirectly relates to common user programming errors. For example:

* **Type Errors:**  If a JavaScript program attempts an operation on incompatible types (e.g., adding a number and a string without explicit conversion), the generated bytecode will reflect this. The `MaglevGraphBuilder` will encounter nodes that might require implicit type conversions. If these conversions can fail or lead to unexpected behavior, the graph might include deoptimization points.

**Example:**

```javascript
function tryAdd(x) {
  return x + 5;
}
```

If `x` is sometimes a number and sometimes a string, the `VisitAdd` method might need to generate code that checks the type of `x` and performs appropriate actions (numeric addition or string concatenation). If the type is unexpected, a deoptimization might occur.

* **Uninitialized Variables:** Accessing an uninitialized variable in JavaScript will typically result in `undefined`. The bytecode and the `MaglevGraphBuilder` will handle loading this `undefined` value.

**归纳一下它的功能 (Summary of its Functionality):**

The `v8/src/maglev/maglev-graph-builder.h` file defines the `MaglevGraphBuilder` class, which is the central component responsible for translating JavaScript bytecode into the Maglev graph representation. This process involves iterating through bytecode instructions, creating corresponding graph nodes for values, operations, and control flow, managing register state, handling type conversions, supporting built-in and runtime function calls, managing the JavaScript context, and incorporating mechanisms for exception handling and deoptimization. It is a crucial part of V8's optimization pipeline.

### 提示词
```
这是目录为v8/src/maglev/maglev-graph-builder.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
_table_index_);
        if (offset >= end) {
          next_handler_table_index_++;
          continue;
        }
        int handler = table.GetRangeHandler(next_handler_table_index_);
        catch_block_stack_.push({end, handler});
        DCHECK_NOT_NULL(merge_states_[handler]);
        next_handler_table_index_++;
      }
    }

    DCHECK_NOT_NULL(current_block_);
#ifdef DEBUG
    // Clear new nodes for the next VisitFoo
    new_nodes_.clear();
#endif

    if (iterator_.current_bytecode() == interpreter::Bytecode::kJumpLoop &&
        iterator_.GetJumpTargetOffset() < entrypoint_) {
      static_assert(kLoopsMustBeEnteredThroughHeader);
      RETURN_VOID_ON_ABORT(
          EmitUnconditionalDeopt(DeoptimizeReason::kOSREarlyExit));
    }

    switch (iterator_.current_bytecode()) {
#define BYTECODE_CASE(name, ...)       \
  case interpreter::Bytecode::k##name: \
    Visit##name();                     \
    break;
      BYTECODE_LIST(BYTECODE_CASE, BYTECODE_CASE)
#undef BYTECODE_CASE
    }
  }

#define BYTECODE_VISITOR(name, ...) void Visit##name();
  BYTECODE_LIST(BYTECODE_VISITOR, BYTECODE_VISITOR)
#undef BYTECODE_VISITOR

#define DECLARE_VISITOR(name, ...) \
  void VisitIntrinsic##name(interpreter::RegisterList args);
  INTRINSICS_LIST(DECLARE_VISITOR)
#undef DECLARE_VISITOR

  void AddInitializedNodeToGraph(Node* node) {
    // VirtualObjects should never be add to the Maglev graph.
    DCHECK(!node->Is<VirtualObject>());
    current_block_->nodes().Add(node);
    node->set_owner(current_block_);
    if (has_graph_labeller())
      graph_labeller()->RegisterNode(node, compilation_unit_,
                                     BytecodeOffset(iterator_.current_offset()),
                                     current_source_position_);
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  " << node << "  "
                << PrintNodeLabel(graph_labeller(), node) << ": "
                << PrintNode(graph_labeller(), node) << std::endl;
    }
#ifdef DEBUG
    new_nodes_.insert(node);
#endif
  }

  // Add a new node with a dynamic set of inputs which are initialized by the
  // `post_create_input_initializer` function before the node is added to the
  // graph.
  template <typename NodeT, typename Function, typename... Args>
  NodeT* AddNewNode(size_t input_count,
                    Function&& post_create_input_initializer, Args&&... args) {
    NodeT* node =
        NodeBase::New<NodeT>(zone(), input_count, std::forward<Args>(args)...);
    post_create_input_initializer(node);
    return AttachExtraInfoAndAddToGraph(node);
  }

  template <typename NodeT, typename... Args>
  NodeT* AddNewNodeOrGetEquivalent(std::initializer_list<ValueNode*> raw_inputs,
                                   Args&&... args) {
    DCHECK(v8_flags.maglev_cse);
    static constexpr Opcode op = Node::opcode_of<NodeT>;
    static_assert(Node::participate_in_cse(op));
    using options_result =
        typename std::invoke_result<decltype(&NodeT::options),
                                    const NodeT>::type;
    static_assert(
        std::is_assignable<options_result, std::tuple<Args...>>::value,
        "Instruction participating in CSE needs options() returning "
        "a tuple matching the constructor arguments");
    static_assert(IsFixedInputNode<NodeT>());
    static_assert(NodeT::kInputCount <= 3);

    std::array<ValueNode*, NodeT::kInputCount> inputs;
    // Nodes with zero input count don't have kInputTypes defined.
    if constexpr (NodeT::kInputCount > 0) {
      int i = 0;
      constexpr UseReprHintRecording hint = ShouldRecordUseReprHint<NodeT>();
      for (ValueNode* raw_input : raw_inputs) {
        inputs[i] = ConvertInputTo<hint>(raw_input, NodeT::kInputTypes[i]);
        i++;
      }
      if constexpr (IsCommutativeNode(Node::opcode_of<NodeT>)) {
        static_assert(NodeT::kInputCount == 2);
        if (inputs[0] > inputs[1]) {
          std::swap(inputs[0], inputs[1]);
        }
      }
    }

    uint32_t value_number;
    {
      size_t tmp_value_number = base::hash_value(op);
      (
          [&] {
            tmp_value_number =
                fast_hash_combine(tmp_value_number, gvn_hash_value(args));
          }(),
          ...);
      for (const auto& inp : inputs) {
        tmp_value_number =
            fast_hash_combine(tmp_value_number, base::hash_value(inp));
      }
      value_number = static_cast<uint32_t>(tmp_value_number);
    }

    auto exists = known_node_aspects().available_expressions.find(value_number);
    if (exists != known_node_aspects().available_expressions.end()) {
      auto candidate = exists->second.node;
      const bool sanity_check =
          candidate->Is<NodeT>() &&
          static_cast<size_t>(candidate->input_count()) == inputs.size();
      DCHECK_IMPLIES(sanity_check,
                     (StaticPropertiesForOpcode(op) &
                      candidate->properties()) == candidate->properties());
      const bool epoch_check =
          !Node::needs_epoch_check(op) ||
          known_node_aspects().effect_epoch() <= exists->second.effect_epoch;
      if (sanity_check && epoch_check) {
        if (static_cast<NodeT*>(candidate)->options() ==
            std::tuple{std::forward<Args>(args)...}) {
          int i = 0;
          for (const auto& inp : inputs) {
            if (inp != candidate->input(i).node()) {
              break;
            }
            i++;
          }
          if (static_cast<size_t>(i) == inputs.size()) {
            return static_cast<NodeT*>(candidate);
          }
        }
      }
      if (!epoch_check) {
        known_node_aspects().available_expressions.erase(exists);
      }
    }
    NodeT* node = NodeBase::New<NodeT>(zone(), inputs.size(),
                                       std::forward<Args>(args)...);
    int i = 0;
    for (ValueNode* input : inputs) {
      DCHECK_NOT_NULL(input);
      node->set_input(i++, input);
    }
    DCHECK_EQ(node->options(), std::tuple{std::forward<Args>(args)...});
    uint32_t epoch = Node::needs_epoch_check(op)
                         ? known_node_aspects().effect_epoch()
                         : KnownNodeAspects::kEffectEpochForPureInstructions;
    if (epoch != KnownNodeAspects::kEffectEpochOverflow) {
      known_node_aspects().available_expressions[value_number] = {node, epoch};
    }
    return AttachExtraInfoAndAddToGraph(node);
  }

  // Add a new node with a static set of inputs.
  template <typename NodeT, typename... Args>
  NodeT* AddNewNode(std::initializer_list<ValueNode*> inputs, Args&&... args) {
    static_assert(IsFixedInputNode<NodeT>());
    if constexpr (Node::participate_in_cse(Node::opcode_of<NodeT>)) {
      if (v8_flags.maglev_cse) {
        return AddNewNodeOrGetEquivalent<NodeT>(inputs,
                                                std::forward<Args>(args)...);
      }
    }
    NodeT* node = NodeBase::New<NodeT>(zone(), inputs.size(),
                                       std::forward<Args>(args)...);
    SetNodeInputs(node, inputs);
    return AttachExtraInfoAndAddToGraph(node);
  }

  template <typename NodeT, typename... Args>
  NodeT* CreateNewConstantNode(Args&&... args) const {
    static_assert(IsConstantNode(Node::opcode_of<NodeT>));
    NodeT* node = NodeBase::New<NodeT>(zone(), std::forward<Args>(args)...);
    static_assert(!NodeT::kProperties.can_eager_deopt());
    static_assert(!NodeT::kProperties.can_lazy_deopt());
    static_assert(!NodeT::kProperties.can_throw());
    static_assert(!NodeT::kProperties.can_write());
    if (has_graph_labeller()) graph_labeller()->RegisterNode(node);
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  " << node << "  "
                << PrintNodeLabel(graph_labeller(), node) << ": "
                << PrintNode(graph_labeller(), node) << std::endl;
    }
    return node;
  }

  template <typename NodeT>
  NodeT* AttachExtraInfoAndAddToGraph(NodeT* node) {
    static_assert(NodeT::kProperties.is_deopt_checkpoint() +
                      NodeT::kProperties.can_eager_deopt() +
                      NodeT::kProperties.can_lazy_deopt() <=
                  1);
    if constexpr (NodeT::kProperties.can_eager_deopt() ||
                  NodeT::kProperties.can_lazy_deopt()) {
      ClearCurrentAllocationBlock();
    }
    AttachDeoptCheckpoint(node);
    AttachEagerDeoptInfo(node);
    AttachLazyDeoptInfo(node);
    AttachExceptionHandlerInfo(node);
    AddInitializedNodeToGraph(node);
    MarkPossibleSideEffect(node);
    return node;
  }

  template <typename NodeT>
  void AttachDeoptCheckpoint(NodeT* node) {
    if constexpr (NodeT::kProperties.is_deopt_checkpoint()) {
      node->SetEagerDeoptInfo(zone(), GetLatestCheckpointedFrame());
    }
  }

  template <typename NodeT>
  void AttachEagerDeoptInfo(NodeT* node) {
    if constexpr (NodeT::kProperties.can_eager_deopt()) {
      node->SetEagerDeoptInfo(zone(), GetLatestCheckpointedFrame(),
                              current_speculation_feedback_);
    }
  }

  template <typename NodeT>
  void AttachLazyDeoptInfo(NodeT* node) {
    if constexpr (NodeT::kProperties.can_lazy_deopt()) {
      auto [register_result, register_count] = GetResultLocationAndSize();
      new (node->lazy_deopt_info()) LazyDeoptInfo(
          zone(), GetDeoptFrameForLazyDeopt(register_result, register_count),
          register_result, register_count, current_speculation_feedback_);
    }
  }

  template <typename NodeT>
  void AttachExceptionHandlerInfo(NodeT* node) {
    if constexpr (NodeT::kProperties.can_throw()) {
      CatchBlockDetails catch_block = GetCurrentTryCatchBlock();
      if (catch_block.ref) {
        if (!catch_block.state->exception_handler_was_used()) {
          // Attach an empty live exception handler to mark that there's a
          // matching catch but we'll lazy deopt if we ever throw.
          new (node->exception_handler_info()) ExceptionHandlerInfo(
              catch_block.ref, ExceptionHandlerInfo::kLazyDeopt);
          DCHECK(node->exception_handler_info()->HasExceptionHandler());
          DCHECK(node->exception_handler_info()->ShouldLazyDeopt());
          return;
        }

        new (node->exception_handler_info()) ExceptionHandlerInfo(
            catch_block.ref, CatchBlockDeoptFrameDistance());
        DCHECK(node->exception_handler_info()->HasExceptionHandler());
        DCHECK(!node->exception_handler_info()->ShouldLazyDeopt());

        // Merge the current state into the handler state.
        DCHECK_NOT_NULL(catch_block.state);
        catch_block.state->MergeThrow(
            GetCurrentCatchBlockGraphBuilder(), catch_block.unit,
            *current_interpreter_frame_.known_node_aspects(),
            current_interpreter_frame_.virtual_objects());
      } else {
        // Patch no exception handler marker.
        // TODO(victorgomes): Avoid allocating exception handler data in this
        // case.
        new (node->exception_handler_info()) ExceptionHandlerInfo();
        DCHECK(!node->exception_handler_info()->HasExceptionHandler());
      }
    }
  }

  // Bytecode iterator of the current graph builder is inside a try-block
  // region.
  bool IsInsideTryBlock() const { return catch_block_stack_.size() > 0; }

  int CatchBlockDeoptFrameDistance() const {
    if (IsInsideTryBlock()) return 0;
    DCHECK_IMPLIES(parent_catch_deopt_frame_distance_ > 0, is_inline());
    return parent_catch_deopt_frame_distance_;
  }

  struct CatchBlockDetails {
    BasicBlockRef* ref = nullptr;
    MergePointInterpreterFrameState* state = nullptr;
    const MaglevCompilationUnit* unit = nullptr;
  };

  CatchBlockDetails GetCurrentTryCatchBlock() {
    if (IsInsideTryBlock()) {
      // Inside a try-block.
      int offset = catch_block_stack_.top().handler;
      return {&jump_targets_[offset], merge_states_[offset], compilation_unit_};
    }
    DCHECK_IMPLIES(parent_catch_.ref != nullptr, is_inline());
    return parent_catch_;
  }

  MaglevGraphBuilder* GetCurrentCatchBlockGraphBuilder() {
    if (IsInsideTryBlock()) return this;
    MaglevGraphBuilder* builder = this;
    for (int depth = 0; depth < parent_catch_deopt_frame_distance_; depth++) {
      builder = builder->parent();
    }
    return builder;
  }

  bool ContextMayAlias(ValueNode* context,
                       compiler::OptionalScopeInfoRef scope_info);
  enum ContextSlotMutability { kImmutable, kMutable };
  bool TrySpecializeLoadContextSlotToFunctionContext(
      ValueNode* context, int slot_index,
      ContextSlotMutability slot_mutability);
  ValueNode* TrySpecializeLoadScriptContextSlot(ValueNode* context, int index);
  ValueNode* LoadAndCacheContextSlot(ValueNode* context, int offset,
                                     ContextSlotMutability slot_mutability,
                                     ContextKind context_kind);
  ReduceResult TrySpecializeStoreScriptContextSlot(ValueNode* context,
                                                   int index, ValueNode* value,
                                                   Node** store);
  ReduceResult StoreAndCacheContextSlot(ValueNode* context, int index,
                                        ValueNode* value,
                                        ContextKind context_kind);
  ValueNode* TryGetParentContext(ValueNode* node);
  void MinimizeContextChainDepth(ValueNode** context, size_t* depth);
  void EscapeContext();
  void BuildLoadContextSlot(ValueNode* context, size_t depth, int slot_index,
                            ContextSlotMutability slot_mutability,
                            ContextKind context_kind);
  ReduceResult BuildStoreContextSlot(ValueNode* context, size_t depth,
                                     int slot_index, ValueNode* value,
                                     ContextKind context_kind);

  void BuildStoreMap(ValueNode* object, compiler::MapRef map,
                     StoreMap::Kind kind);

  ValueNode* BuildExtendPropertiesBackingStore(compiler::MapRef map,
                                               ValueNode* receiver,
                                               ValueNode* property_array);

  template <Builtin kBuiltin>
  CallBuiltin* BuildCallBuiltin(std::initializer_list<ValueNode*> inputs) {
    using Descriptor = typename CallInterfaceDescriptorFor<kBuiltin>::type;
    if constexpr (Descriptor::HasContextParameter()) {
      return AddNewNode<CallBuiltin>(
          inputs.size() + 1,
          [&](CallBuiltin* call_builtin) {
            int arg_index = 0;
            for (auto* input : inputs) {
              call_builtin->set_arg(arg_index++, input);
            }
          },
          kBuiltin, GetContext());
    } else {
      return AddNewNode<CallBuiltin>(
          inputs.size(),
          [&](CallBuiltin* call_builtin) {
            int arg_index = 0;
            for (auto* input : inputs) {
              call_builtin->set_arg(arg_index++, input);
            }
          },
          kBuiltin);
    }
  }

  template <Builtin kBuiltin>
  CallBuiltin* BuildCallBuiltin(
      std::initializer_list<ValueNode*> inputs,
      compiler::FeedbackSource const& feedback,
      CallBuiltin::FeedbackSlotType slot_type = CallBuiltin::kTaggedIndex) {
    CallBuiltin* call_builtin = BuildCallBuiltin<kBuiltin>(inputs);
    call_builtin->set_feedback(feedback, slot_type);
#ifdef DEBUG
    // Check that the last parameters are kSlot and kVector.
    using Descriptor = typename CallInterfaceDescriptorFor<kBuiltin>::type;
    int slot_index = call_builtin->InputCountWithoutContext();
    int vector_index = slot_index + 1;
    DCHECK_EQ(slot_index, Descriptor::kSlot);
    // TODO(victorgomes): Rename all kFeedbackVector parameters in the builtins
    // to kVector.
    DCHECK_EQ(vector_index, Descriptor::kVector);
#endif  // DEBUG
    return call_builtin;
  }

  CallCPPBuiltin* BuildCallCPPBuiltin(
      Builtin builtin, ValueNode* target, ValueNode* new_target,
      std::initializer_list<ValueNode*> inputs) {
    DCHECK(Builtins::IsCpp(builtin));
    const size_t input_count = inputs.size() + CallCPPBuiltin::kFixedInputCount;
    return AddNewNode<CallCPPBuiltin>(
        input_count,
        [&](CallCPPBuiltin* call_builtin) {
          int arg_index = 0;
          for (auto* input : inputs) {
            call_builtin->set_arg(arg_index++, input);
          }
        },
        builtin, GetTaggedValue(target), GetTaggedValue(new_target),
        GetTaggedValue(GetContext()));
  }

  void BuildLoadGlobal(compiler::NameRef name,
                       compiler::FeedbackSource& feedback_source,
                       TypeofMode typeof_mode);

  ValueNode* BuildToString(ValueNode* value, ToString::ConversionMode mode);

  constexpr bool RuntimeFunctionCanThrow(Runtime::FunctionId function_id) {
#define BAILOUT(name, ...)               \
  if (function_id == Runtime::k##name) { \
    return true;                         \
  }
    FOR_EACH_THROWING_INTRINSIC(BAILOUT)
#undef BAILOUT
    return false;
  }

  ReduceResult BuildCallRuntime(Runtime::FunctionId function_id,
                                std::initializer_list<ValueNode*> inputs) {
    CallRuntime* result = AddNewNode<CallRuntime>(
        inputs.size() + CallRuntime::kFixedInputCount,
        [&](CallRuntime* call_runtime) {
          int arg_index = 0;
          for (auto* input : inputs) {
            call_runtime->set_arg(arg_index++, GetTaggedValue(input));
          }
        },
        function_id, GetContext());

    if (RuntimeFunctionCanThrow(function_id)) {
      return BuildAbort(AbortReason::kUnexpectedReturnFromThrow);
    }
    return result;
  }

  ReduceResult BuildAbort(AbortReason reason) {
    // Create a block rather than calling finish, since we don't yet know the
    // next block's offset before the loop skipping the rest of the bytecodes.
    FinishBlock<Abort>({}, reason);
    return ReduceResult::DoneWithAbort();
  }

  void Print(const char* str) {
    Handle<String> string_handle =
        local_isolate()->factory()->NewStringFromAsciiChecked(
            str, AllocationType::kOld);
    ValueNode* string_node = GetConstant(MakeRefAssumeMemoryFence(
        broker(), broker()->CanonicalPersistentHandle(string_handle)));
    CHECK(BuildCallRuntime(Runtime::kGlobalPrint, {string_node}).IsDone());
  }

  void Print(ValueNode* value) {
    CHECK(BuildCallRuntime(Runtime::kDebugPrint, {value}).IsDone());
  }

  void Print(const char* str, ValueNode* value) {
    Print(str);
    Print(value);
  }

  ValueNode* GetClosure() const {
    return current_interpreter_frame_.get(
        interpreter::Register::function_closure());
  }

  ValueNode* GetContext() const {
    return current_interpreter_frame_.get(
        interpreter::Register::current_context());
  }

  void SetContext(ValueNode* context) {
    current_interpreter_frame_.set(interpreter::Register::current_context(),
                                   context);
  }

  FeedbackSlot GetSlotOperand(int operand_index) const {
    return iterator_.GetSlotOperand(operand_index);
  }

  uint32_t GetFlag8Operand(int operand_index) const {
    return iterator_.GetFlag8Operand(operand_index);
  }

  uint32_t GetFlag16Operand(int operand_index) const {
    return iterator_.GetFlag16Operand(operand_index);
  }

  template <class T, typename = std::enable_if_t<is_taggable_v<T>>>
  typename compiler::ref_traits<T>::ref_type GetRefOperand(int operand_index) {
    // The BytecodeArray itself was fetched by using a barrier so all reads
    // from the constant pool are safe.
    return MakeRefAssumeMemoryFence(
        broker(), broker()->CanonicalPersistentHandle(
                      Cast<T>(iterator_.GetConstantForIndexOperand(
                          operand_index, local_isolate()))));
  }

  ExternalConstant* GetExternalConstant(ExternalReference reference) {
    auto it = graph_->external_references().find(reference.address());
    if (it == graph_->external_references().end()) {
      ExternalConstant* node =
          CreateNewConstantNode<ExternalConstant>(0, reference);
      graph_->external_references().emplace(reference.address(), node);
      return node;
    }
    return it->second;
  }

  RootConstant* GetRootConstant(RootIndex index) {
    auto it = graph_->root().find(index);
    if (it == graph_->root().end()) {
      RootConstant* node = CreateNewConstantNode<RootConstant>(0, index);
      graph_->root().emplace(index, node);
      return node;
    }
    return it->second;
  }

  RootConstant* GetBooleanConstant(bool value) {
    return GetRootConstant(value ? RootIndex::kTrueValue
                                 : RootIndex::kFalseValue);
  }

  ValueNode* GetConstant(compiler::ObjectRef ref);

  ValueNode* GetTrustedConstant(compiler::HeapObjectRef ref,
                                IndirectPointerTag tag);

  ValueNode* GetRegisterInput(Register reg) {
    DCHECK(!graph_->register_inputs().has(reg));
    graph_->register_inputs().set(reg);
    return AddNewNode<RegisterInput>({}, reg);
  }

#define DEFINE_IS_ROOT_OBJECT(type, name, CamelName)               \
  bool Is##CamelName(ValueNode* value) const {                     \
    if (RootConstant* constant = value->TryCast<RootConstant>()) { \
      return constant->index() == RootIndex::k##CamelName;         \
    }                                                              \
    return false;                                                  \
  }
  ROOT_LIST(DEFINE_IS_ROOT_OBJECT)
#undef DEFINE_IS_ROOT_OBJECT

  // Move an existing ValueNode between two registers. You can pass
  // virtual_accumulator as the src or dst to move in or out of the accumulator.
  void MoveNodeBetweenRegisters(interpreter::Register src,
                                interpreter::Register dst) {
    // We shouldn't be moving newly created nodes between registers.
    DCHECK(!IsNodeCreatedForThisBytecode(current_interpreter_frame_.get(src)));
    DCHECK_NOT_NULL(current_interpreter_frame_.get(src));

    current_interpreter_frame_.set(dst, current_interpreter_frame_.get(src));
  }

  ValueNode* GetTaggedValue(ValueNode* value,
                            UseReprHintRecording record_use_repr_hint =
                                UseReprHintRecording::kRecord);
  ReduceResult GetSmiValue(ValueNode* value,
                           UseReprHintRecording record_use_repr_hint =
                               UseReprHintRecording::kRecord);

  ReduceResult GetSmiValue(interpreter::Register reg,
                           UseReprHintRecording record_use_repr_hint =
                               UseReprHintRecording::kRecord) {
    ValueNode* value = current_interpreter_frame_.get(reg);
    return GetSmiValue(value, record_use_repr_hint);
  }

  ValueNode* GetTaggedValue(interpreter::Register reg,
                            UseReprHintRecording record_use_repr_hint =
                                UseReprHintRecording::kRecord) {
    ValueNode* value = current_interpreter_frame_.get(reg);
    return GetTaggedValue(value, record_use_repr_hint);
  }

  ValueNode* GetInternalizedString(interpreter::Register reg);

  // Get an Int32 representation node whose value is equivalent to the ToInt32
  // truncation of the given node (including a ToNumber call). Only trivial
  // ToNumber is allowed -- values that are already numeric, and optionally
  // oddballs.
  //
  // Deopts if the ToNumber is non-trivial.
  ValueNode* GetTruncatedInt32ForToNumber(ValueNode* value, ToNumberHint hint);

  ValueNode* GetTruncatedInt32ForToNumber(interpreter::Register reg,
                                          ToNumberHint hint) {
    return GetTruncatedInt32ForToNumber(current_interpreter_frame_.get(reg),
                                        hint);
  }

  // Get an Int32 representation node whose value is equivalent to the ToUint8
  // truncation of the given node (including a ToNumber call). Only trivial
  // ToNumber is allowed -- values that are already numeric, and optionally
  // oddballs.
  //
  // Deopts if the ToNumber is non-trivial.
  ValueNode* GetUint8ClampedForToNumber(ValueNode* value, ToNumberHint hint);

  ValueNode* GetUint8ClampedForToNumber(interpreter::Register reg,
                                        ToNumberHint hint) {
    return GetUint8ClampedForToNumber(current_interpreter_frame_.get(reg),
                                      hint);
  }

  std::optional<int32_t> TryGetInt32Constant(ValueNode* value);
  std::optional<uint32_t> TryGetUint32Constant(ValueNode* value);

  // Get an Int32 representation node whose value is equivalent to the given
  // node.
  //
  // Deopts if the value is not exactly representable as an Int32.
  ValueNode* GetInt32(ValueNode* value);

  void EnsureInt32(ValueNode* value) {
    // Either the value is Int32 already, or we force a conversion to Int32 and
    // cache the value in its alternative representation node.
    GetInt32(value);
  }

  void EnsureInt32(interpreter::Register reg) {
    EnsureInt32(current_interpreter_frame_.get(reg));
  }

  std::optional<double> TryGetFloat64Constant(ValueNode* value,
                                              ToNumberHint hint);

  // Get a Float64 representation node whose value is equivalent to the given
  // node.
  //
  // Deopts if the value is not exactly representable as a Float64.
  ValueNode* GetFloat64(ValueNode* value);

  ValueNode* GetFloat64(interpreter::Register reg) {
    return GetFloat64(current_interpreter_frame_.get(reg));
  }

  // Get a Float64 representation node whose value is the result of ToNumber on
  // the given node. Only trivial ToNumber is allowed -- values that are already
  // numeric, and optionally oddballs.
  //
  // Deopts if the ToNumber value is not exactly representable as a Float64, or
  // the ToNumber is non-trivial.
  ValueNode* GetFloat64ForToNumber(ValueNode* value, ToNumberHint hint);

  ValueNode* GetFloat64ForToNumber(interpreter::Register reg,
                                   ToNumberHint hint) {
    return GetFloat64ForToNumber(current_interpreter_frame_.get(reg), hint);
  }

  ValueNode* GetHoleyFloat64ForToNumber(ValueNode* value, ToNumberHint hint);

  ValueNode* GetHoleyFloat64ForToNumber(interpreter::Register reg,
                                        ToNumberHint hint) {
    return GetHoleyFloat64ForToNumber(current_interpreter_frame_.get(reg),
                                      hint);
  }

  ValueNode* GetAccumulator() {
    return current_interpreter_frame_.get(
        interpreter::Register::virtual_accumulator());
  }

  ReduceResult GetAccumulatorSmi(UseReprHintRecording record_use_repr_hint =
                                     UseReprHintRecording::kRecord) {
    return GetSmiValue(interpreter::Register::virtual_accumulator(),
                       record_use_repr_hint);
  }

  ValueNode* GetAccumulatorTruncatedInt32ForToNumber(ToNumberHint hint) {
    return GetTruncatedInt32ForToNumber(
        interpreter::Register::virtual_accumulator(), hint);
  }

  ValueNode* GetAccumulatorUint8ClampedForToNumber(ToNumberHint hint) {
    return GetUint8ClampedForToNumber(
        interpreter::Register::virtual_accumulator(), hint);
  }

  ValueNode* GetAccumulatorHoleyFloat64ForToNumber(ToNumberHint hint) {
    return GetHoleyFloat64ForToNumber(
        interpreter::Register::virtual_accumulator(), hint);
  }

  ValueNode* GetSilencedNaN(ValueNode* value) {
    DCHECK_EQ(value->properties().value_representation(),
              ValueRepresentation::kFloat64);

    // We only need to check for silenced NaN in non-conversion nodes or
    // conversion from tagged, since they can't be signalling NaNs.
    if (value->properties().is_conversion()) {
      // A conversion node should have at least one input.
      DCHECK_GE(value->input_count(), 1);
      // If the conversion node is tagged, we could be reading a fabricated sNaN
      // value (built using a BufferArray for example).
      if (!value->input(0).node()->properties().is_tagged()) {
        return value;
      }
    }

    // Special case constants, since we know what they are.
    Float64Constant* constant = value->TryCast<Float64Constant>();
    if (constant) {
      constexpr double quiet_NaN = std::numeric_limits<double>::quiet_NaN();
      if (!constant->value().is_nan()) return constant;
      return GetFloat64Constant(quiet_NaN);
    }

    // Silence all other values.
    return AddNewNode<HoleyFloat64ToMaybeNanFloat64>({value});
  }

  bool IsRegisterEqualToAccumulator(int operand_index) {
    interpreter::Register source = iterator_.GetRegisterOperand(operand_index);
    return current_interpreter_frame_.get(source) ==
           current_interpreter_frame_.accumulator();
  }

  ValueNode* LoadRegister(int operand_index) {
    return current_interpreter_frame_.get(
        iterator_.GetRegisterOperand(operand_index));
  }

  ValueNode* LoadRegisterHoleyFloat64ForToNumber(int operand_index,
                                                 ToNumberHint hint) {
    return GetHoleyFloat64ForToNumber(
        iterator_.GetRegisterOperand(operand_index), hint);
  }

  template <typename NodeT>
  void SetAccumulator(NodeT* node) {
    // Accumulator stores are equivalent to stores to the virtual accumulator
    // register.
    StoreRegister(interpreter::Register::virtual_accumulator(), node);
  }

  void ClobberAccumulator() {
    DCHECK(interpreter::Bytecodes::ClobbersAccumulator(
        iterator_.current_bytecode()));
    current_interpreter_frame_.set_accumulator(
        GetRootConstant(RootIndex::kOptimizedOut));
  }

  ValueNode* GetSecondValue(ValueNode* result) {
    // GetSecondReturnedValue must be added just after a node that calls a
    // builtin that expects 2 returned values. It simply binds kReturnRegister1
    // to a value node. Since the previous node must have been a builtin
    // call, the register is available in the register allocator. No gap moves
    // would be emitted between these two nodes.
    if (result->opcode() == Opcode::kCallRuntime) {
      DCHECK_EQ(result->Cast<CallRuntime>()->ReturnCount(), 2);
    } else if (result->opcode() == Opcode::kCallBuiltin) {
      DCHECK_EQ(result->Cast<CallBuiltin>()->ReturnCount(), 2);
    } else {
      DCHECK_EQ(result->opcode(), Opcode::kForInPrepare);
    }
    // {result} must be the last node in the current block.
    DCHECK(current_block_->nodes().Contains(result));
    DCHECK_EQ(result->NextNode(), nullptr);
    return AddNewNode<GetSecondReturnedValue>({});
  }

  template <typename NodeT>
  void StoreRegister(interpreter::Register target, NodeT* value) {
    static_assert(std::is_base_of_v<ValueNode, NodeT>);
    DCHECK(HasOutputRegister(target));
    current_interpreter_frame_.set(target, value);

    // Make sure the lazy deopt info of this value, if any, is registered as
    // mutating this register.
    DCHECK_IMPLIES(value->properties().can_lazy_deopt() &&
                       IsNodeCreatedForThisBytecode(value),
                   value->lazy_deopt_info()->IsResultRegister(target));
  }

  void SetAccumulatorInBranch(ValueNode* value) {
    DCHECK_IMPLIES(value->properties().can_lazy_deopt(),
                   !IsNodeCreatedForThisBytecode(value));
    current_interpreter_frame_.set(interpreter::Register::virtual_accumulator(),
                                   value);
  }

  template <typename NodeT>
  void StoreRegisterPair(
      std::pair<interpreter::Register, interpreter::Register> target,
      NodeT* value) {
    const interpreter::Register target0 = target.first;
    const interpreter::Register target1 = target.second;

    DCHECK_EQ(interpreter::Register(target0.index() + 1), target1);
    DCHECK_EQ(value->ReturnCount(), 2);

    if (!v8_flags.maglev_cse) {
      // TODO(olivf): CSE might deduplicate this value and the one below.
      DCHECK_NE(0, new_nodes_.count(value));
    }
    DCHECK(HasOutputRegister(target0));
    current_interpreter_frame_.set(target0, value);

    ValueNode* second_value = GetSecondValue(value);
    if (!v8_flags.maglev_cse) {
      DCHECK_NE(0, new_nodes_.count(second_value));
    }
    DCHECK(HasOutputRegister(target1));
    current_interpreter_frame_.set(target1, second_value);

    // Make sure the lazy deopt info of this value, if any, is registered as
    // mutating these registers.
    DCHECK_IMPLIES(value->properties().can_lazy_deopt() &&
                       IsNodeCreatedForThisBytecode(value),
                   value->lazy_deopt_info()->IsResultRegister(target0));
    DCHECK_IMPLIES(value->properties().can_lazy_deopt() &&
                       IsNodeCreatedForThisBytecode(value),
                   value->lazy_deopt_info()->IsResultRegister(target1));
  }

  std::pair<interpreter::Register, int> GetResultLocationAndSize() const;
#ifdef DEBUG
  bool
```
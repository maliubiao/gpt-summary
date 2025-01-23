Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/compiler/js-inlining.cc`. They also have specific questions about its nature, relation to JavaScript, potential logic, and common programming errors.

Here's a plan to address each point:

1. **List the functionalities:** Analyze the code to identify its key actions and goals. Focus on the steps involved in inlining a function call.
2. **Check for `.tq` extension:** Examine the file path provided by the user to determine if it ends with `.tq`.
3. **Relate to JavaScript:**  If the code is related to JavaScript functionality, provide a simple JavaScript example demonstrating the concept of function inlining.
4. **Code logic and inference:**  Identify key decision points and data flow within the code. Define hypothetical inputs and trace their processing to determine the output.
5. **Common programming errors:** Look for code sections that deal with potential issues or checks related to how JavaScript functions are called or defined, which might correspond to common programming errors.
6. **Summarize functionality (Part 2):** Condense the identified functionalities from step 1 into a concise summary, as this is the second part of the user's request.
```c++
            : ""));
  // ----------------------------------------------------------------
  // After this point, we've made a decision to inline this function.
  // We shall not bailout from inlining if we got here.

  BytecodeArrayRef bytecode_array = shared_info->GetBytecodeArray(broker());

  // Remember that we inlined this function.
  int inlining_id =
      info_->AddInlinedFunction(shared_info->object(), bytecode_array.object(),
                                source_positions_->GetSourcePosition(node));
  if (v8_flags.profile_guided_optimization &&
      feedback_cell.feedback_vector(broker()).has_value() &&
      feedback_cell.feedback_vector(broker())
              .value()
              .object()
              ->invocation_count_before_stable(kRelaxedLoad) >
          v8_flags.invocation_count_for_early_optimization) {
    info_->set_could_not_inline_all_candidates();
  }

  // Create the subgraph for the inlinee.
  Node* start_node;
  Node* end;
  {
    // Run the BytecodeGraphBuilder to create the subgraph.
    Graph::SubgraphScope scope(graph());
    BytecodeGraphBuilderFlags flags(
        BytecodeGraphBuilderFlag::kSkipFirstStackAndTierupCheck);
    if (info_->analyze_environment_liveness()) {
      flags |= BytecodeGraphBuilderFlag::kAnalyzeEnvironmentLiveness;
    }
    if (info_->bailout_on_uninitialized()) {
      flags |= BytecodeGraphBuilderFlag::kBailoutOnUninitialized;
    }
    {
      CallFrequency frequency = call.frequency();
      BuildGraphFromBytecode(broker(), zone(), *shared_info, bytecode_array,
                             feedback_cell, BytecodeOffset::None(), jsgraph(),
                             frequency, source_positions_, node_origins_,
                             inlining_id, info_->code_kind(), flags,
                             &info_->tick_counter());
    }

    // Extract the inlinee start/end nodes.
    start_node = graph()->start();
    end = graph()->end();
  }
  StartNode start{start_node};

  // If we are inlining into a surrounding exception handler, we collect all
  // potentially throwing nodes within the inlinee that are not handled locally
  // by the inlinee itself. They are later wired into the surrounding handler.
  NodeVector uncaught_subcalls(local_zone_);
  if (exception_target != nullptr) {
    // Find all uncaught 'calls' in the inlinee.
    AllNodes inlined_nodes(local_zone_, end, graph());
    for (Node* subnode : inlined_nodes.reachable) {
      // Every possibly throwing node should get {IfSuccess} and {IfException}
      // projections, unless there already is local exception handling.
      if (subnode->op()->HasProperty(Operator::kNoThrow)) continue;
      if (!NodeProperties::IsExceptionalCall(subnode)) {
        DCHECK_EQ(2, subnode->op()->ControlOutputCount());
        uncaught_subcalls.push_back(subnode);
      }
    }
  }

  FrameState frame_state = call.frame_state();
  Node* new_target = jsgraph()->UndefinedConstant();

  // Inline {JSConstruct} requires some additional magic.
  if (node->opcode() == IrOpcode::kJSConstruct) {
    static_assert(JSCallOrConstructNode::kHaveIdenticalLayouts);
    JSConstructNode n(node);

    new_target = n.new_target();

    // Insert nodes around the call that model the behavior required for a
    // constructor dispatch (allocate implicit receiver and check return value).
    // This models the behavior usually accomplished by our {JSConstructStub}.
    // Note that the context has to be the callers context (input to call node).
    // Also note that by splitting off the {JSCreate} piece of the constructor
    // call, we create an observable deoptimization point after the receiver
    // instantiation but before the invocation (i.e. inside {JSConstructStub}
    // where execution continues at {construct_stub_create_deopt_pc_offset}).
    Node* receiver = jsgraph()->TheHoleConstant();  // Implicit receiver.
    Node* caller_context = NodeProperties::GetContextInput(node);
    if (NeedsImplicitReceiver(*shared_info)) {
      Effect effect = n.effect();
      Control control = n.control();
      Node* frame_state_inside;
      HeapObjectMatcher m(new_target);
      if (m.HasResolvedValue() && m.Ref(broker()).IsJSFunction()) {
        // If {new_target} is a JSFunction, then we cannot deopt in the
        // NewObject call. Therefore we do not need the artificial frame state.
        frame_state_inside = frame_state;
      } else {
        frame_state_inside = CreateArtificialFrameState(
            node, frame_state, n.ArgumentCount(),
            FrameStateType::kConstructCreateStub, *shared_info, caller_context);
      }
      Node* create =
          graph()->NewNode(javascript()->Create(), call.target(), new_target,
                           caller_context, frame_state_inside, effect, control);
      uncaught_subcalls.push_back(create);  // Adds {IfSuccess} & {IfException}.
      NodeProperties::ReplaceControlInput(node, create);
      NodeProperties::ReplaceEffectInput(node, create);
      // Placeholder to hold {node}'s value dependencies while {node} is
      // replaced.
      Node* dummy = graph()->NewNode(common()->Dead());
      NodeProperties::ReplaceUses(node, dummy, node, node, node);
      Node* result;
      // Insert a check of the return value to determine whether the return
      // value or the implicit receiver should be selected as a result of the
      // call.
      Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), node);
      result =
          graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                           check, node, create);
      receiver = create;  // The implicit receiver.
      ReplaceWithValue(dummy, result);
    } else if (IsDerivedConstructor(shared_info->kind())) {
      Node* node_success =
          NodeProperties::FindSuccessfulControlProjection(node);
      Node* is_receiver =
          graph()->NewNode(simplified()->ObjectIsReceiver(), node);
      Node* branch_is_receiver =
          graph()->NewNode(common()->Branch(), is_receiver, node_success);
      Node* branch_is_receiver_true =
          graph()->NewNode(common()->IfTrue(), branch_is_receiver);
      Node* branch_is_receiver_false =
          graph()->NewNode(common()->IfFalse(), branch_is_receiver);
      branch_is_receiver_false = graph()->NewNode(
          javascript()->CallRuntime(
              Runtime::kThrowConstructorReturnedNonObject),
          caller_context, NodeProperties::GetFrameStateInput(node), node,
          branch_is_receiver_false);
      uncaught_subcalls.push_back(branch_is_receiver_false);
      branch_is_receiver_false =
          graph()->NewNode(common()->Throw(), branch_is_receiver_false,
                           branch_is_receiver_false);
      MergeControlToEnd(graph(), common(), branch_is_receiver_false);

      ReplaceWithValue(node_success, node_success, node_success,
                       branch_is_receiver_true);
      // Fix input destroyed by the above {ReplaceWithValue} call.
      NodeProperties::ReplaceControlInput(branch_is_receiver, node_success, 0);
    }
    node->ReplaceInput(JSCallNode::ReceiverIndex(), receiver);
    // Insert a construct stub frame into the chain of frame states. This will
    // reconstruct the proper frame when deoptimizing within the constructor.
    frame_state = CreateArtificialFrameState(
        node, frame_state, 0, FrameStateType::kConstructInvokeStub,
        *shared_info, caller_context);
  }

  // Insert a JSConvertReceiver node for sloppy callees. Note that the context
  // passed into this node has to be the callees context (loaded above).
  if (node->opcode() == IrOpcode::kJSCall &&
      is_sloppy(shared_info->language_mode()) && !shared_info->native()) {
    Effect effect{NodeProperties::GetEffectInput(node)};
    if (NodeProperties::CanBePrimitive(broker(), call.receiver(), effect)) {
      CallParameters const& p = CallParametersOf(node->op());
      Node* global_proxy = jsgraph()->ConstantNoHole(
          broker()->target_native_context().global_proxy_object(broker()),
          broker());
      Node* receiver = effect = graph()->NewNode(
          simplified()->ConvertReceiver(p.convert_mode()), call.receiver(),
          jsgraph()->ConstantNoHole(broker()->target_native_context(),
                                    broker()),
          global_proxy, effect, start);
      NodeProperties::ReplaceValueInput(node, receiver,
                                        JSCallNode::ReceiverIndex());
      NodeProperties::ReplaceEffectInput(node, effect);
    }
  }

  // Insert inlined extra arguments if required. The callees formal parameter
  // count have to match the number of arguments passed to the call.
  int parameter_count = bytecode_array.parameter_count_without_receiver();
  DCHECK_EQ(parameter_count,
            shared_info->internal_formal_parameter_count_without_receiver());
  DCHECK_EQ(parameter_count, start.FormalParameterCountWithoutReceiver());
  if (call.argument_count() != parameter_count) {
    frame_state = CreateArtificialFrameState(
        node, frame_state, call.argument_count(),
        FrameStateType::kInlinedExtraArguments, *shared_info);
  }

  return InlineCall(node, new_target, context, frame_state, start, end,
                    exception_target, uncaught_subcalls, call.argument_count());
}

Graph* JSInliner::graph() const { return jsgraph()->graph(); }

JSOperatorBuilder* JSInliner::javascript() const {
  return jsgraph()->javascript();
}

CommonOperatorBuilder* JSInliner::common() const { return jsgraph()->common(); }

SimplifiedOperatorBuilder* JSInliner::simplified() const {
  return jsgraph()->simplified();
}

#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```

## 功能列举

这段 C++ 代码是 V8 引擎中 `JSInliner::InlineCall` 方法的一部分，它的主要功能是在编译优化期间，将一个函数调用（`call`）的函数体 **内联** 到调用它的地方。  具体来说，它执行以下步骤：

1. **标记内联决策:** 一旦决定内联，就记录下这个决定，不再回退。
2. **获取被内联函数的字节码:** 从 `shared_info` 中获取被调用函数的字节码数组 (`BytecodeArray`).
3. **记录内联信息:** 将被内联的函数信息添加到 `info_` 中，包括被内联函数的对象和字节码数组，并记录其在源代码中的位置。
4. **根据性能优化策略设置标志:**  如果启用了基于性能分析的优化，并且被调用函数在稳定之前的调用次数超过了预设阈值，则标记为可能无法内联所有候选函数。
5. **创建内联函数的子图:**
   - 使用 `BytecodeGraphBuilder` 将被内联函数的字节码转换为图结构，并将其添加到当前函数的图 (`graph()`) 中。
   - 在构建子图时，可以设置一些标志，例如跳过初始堆栈和分层检查，分析环境活跃性，以及在遇到未初始化变量时退出。
   - 提取内联子图的起始节点 (`start_node`) 和结束节点 (`end`).
6. **处理异常:** 如果当前函数在一个异常处理块中，则收集被内联函数中所有可能抛出异常且未在被内联函数内部处理的节点，以便将它们连接到外部的异常处理器。
7. **处理构造函数调用 (`JSConstruct`):**
   - 如果被内联的是一个构造函数调用，则需要插入额外的节点来模拟构造函数的行为，例如分配隐式接收者（`this`），并检查返回值是否为对象。
   - 对于派生类的构造函数，会插入检查以确保构造函数返回的是对象，否则会抛出异常。
   - 在内联构造函数调用时，会创建一个特殊的帧状态 (`FrameStateType::kConstructInvokeStub`)，以便在构造函数内部发生反优化时能够正确地恢复执行环境。
8. **处理 `sloppy` 模式下的函数调用:**
   - 如果被内联的函数是在 `sloppy` 模式下定义的，并且不是原生函数，并且接收者是原始类型，则会插入一个 `JSConvertReceiver` 节点，将接收者转换为对象。
9. **处理参数不匹配的情况:**
   - 如果调用方传递的参数数量与被内联函数声明的参数数量不一致，则会创建一个 `FrameStateType::kInlinedExtraArguments` 类型的帧状态。
10. **执行内联:** 调用 `InlineCall` 函数，传入必要的参数，完成内联操作。

## 关于 `.tq` 结尾

如果 `v8/src/compiler/js-inlining.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。 Torque 是一种 V8 内部使用的领域特定语言，用于更安全和高效地编写 V8 的内置函数和运行时代码。  但是，根据您提供的路径，该文件名为 `.cc`，所以它是 C++ 源代码文件。

## 与 JavaScript 的关系及示例

`v8/src/compiler/js-inlining.cc` 的功能与 JavaScript 的性能优化密切相关。函数内联是一种编译器优化技术，它可以减少函数调用的开销，从而提高 JavaScript 代码的执行速度。

**JavaScript 示例:**

```javascript
function add(a, b) {
  return a + b;
}

function calculate(x) {
  const y = 5;
  const sum = add(x, y); // 这里可能会发生内联
  return sum * 2;
}

console.log(calculate(10)); // 输出 30
```

在上述代码中，当 V8 编译 `calculate` 函数时，如果满足内联的条件，它可能会将 `add` 函数的函数体直接插入到 `calculate` 函数中，就像这样：

```javascript
function calculate_inlined(x) {
  const y = 5;
  const sum = x + 5; // add 函数被内联了
  return sum * 2;
}

console.log(calculate_inlined(10));
```

这样做的好处是避免了函数调用的开销（例如，创建新的栈帧，传递参数等）。

## 代码逻辑推理

**假设输入:**

- `node`: 代表一个函数调用 `add(1, 2)` 的节点。
- `shared_info`: 包含 `add` 函数的元信息（例如，字节码，参数个数）。
- `call.argument_count()`:  2 (参数 1 和 2)。
- `bytecode_array.parameter_count_without_receiver()`: 2 (函数 `add` 声明了两个参数)。
- `exception_target`: `nullptr` (假设当前不在异常处理块中)。

**输出:**

1. **`inlining_id`**: 将会生成一个唯一的 ID，用于标识这次内联操作。
2. **`start_node` 和 `end`**: 将会创建表示 `add` 函数体执行流程的图节点的起始和结束节点。
3. **`uncaught_subcalls`**: 由于 `exception_target` 为 `nullptr`，因此 `uncaught_subcalls` 将为空。
4. 如果满足内联条件，`add(1, 2)` 的调用节点将被替换为 `add` 函数内部操作的图节点。 例如，对于 `return a + b;`，可能会生成一个加法运算的节点。
5. `InlineCall` 函数会被调用，它将返回表示内联结果的节点。

**逻辑流程:**

1. 代码首先检查是否已经决定内联。
2. 获取 `add` 函数的字节码。
3. 创建 `add` 函数的子图，该子图包含一个加法运算的节点。
4. 因为是普通的函数调用，不会进入 `JSConstruct` 的处理分支。
5. 因为参数数量匹配，不会创建 `FrameStateType::kInlinedExtraArguments` 类型的帧状态。
6. 最后，调用 `InlineCall` 来执行内联。

## 涉及用户常见的编程错误

这段代码处理了一些与函数调用相关的潜在问题，这些问题可能源于用户的编程错误：

1. **构造函数调用错误 (缺少 `new` 关键字):** 代码中对 `JSConstruct` 的处理确保了即使在内联的情况下，构造函数的行为（例如，隐式接收者的创建和返回值检查）也能得到正确的模拟。  如果用户忘记使用 `new` 关键字调用构造函数，V8 在执行内联后的代码时仍然会按照构造函数的语义来处理，这有助于发现这类错误。

   **示例:**

   ```javascript
   function Person(name) {
     this.name = name;
   }

   const person = Person("Alice"); // 忘记使用 'new' 关键字
   console.log(person); // 输出 undefined (在非严格模式下) 或报错 (在严格模式下)
   ```

   V8 的内联逻辑需要处理这种情况，并可能在内联后的代码中插入检查来模拟正确的构造函数行为。

2. **派生类构造函数未正确返回对象:** 对于继承的类，其构造函数必须返回一个对象或 `undefined`。 如果派生类的构造函数返回了其他原始类型的值，将会导致错误。 代码中针对 `IsDerivedConstructor` 的处理会插入检查来捕获这种错误。

   **示例:**

   ```javascript
   class Parent {}
   class Child extends Parent {
     constructor() {
       super();
       return 1; // 错误：派生类的构造函数返回了原始类型
     }
   }

   new Child(); // 运行时抛出 TypeError
   ```

   内联逻辑会确保即使内联了派生类的构造函数，这个检查仍然会被执行。

3. **在 `sloppy` 模式下调用函数时 `this` 的指向问题:** 在 `sloppy` 模式下，如果函数被作为普通函数调用（而不是作为方法调用或构造函数调用），`this` 的值可能是全局对象。 如果被内联的函数期望 `this` 指向一个对象，可能会导致错误。  代码中对 `sloppy` 模式的处理，插入 `JSConvertReceiver` 节点，会在必要时将原始类型的 `this` 转换为对象，以符合 `sloppy` 模式下的语义，但这也能间接暴露出用户可能对 `this` 的理解偏差。

   **示例:**

   ```javascript
   function myFunction() {
     console.log(this);
   }

   myFunction(); // 在浏览器中，'this' 指向 window 对象 (sloppy 模式)
   ```

## 功能归纳 (第 2 部分)

总而言之，这段代码是 V8 引擎在执行 JavaScript 代码优化时，**内联函数调用** 的关键步骤。 它负责将被调用函数的代码逻辑融入到调用函数中，从而减少函数调用的开销。 这部分代码处理了多种情况，包括标准函数调用、构造函数调用、以及 `sloppy` 模式下的调用，并且考虑了异常处理和参数匹配等问题，以确保内联操作的正确性和性能收益。

### 提示词
```
这是目录为v8/src/compiler/js-inlining.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-inlining.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
: ""));
  // ----------------------------------------------------------------
  // After this point, we've made a decision to inline this function.
  // We shall not bailout from inlining if we got here.

  BytecodeArrayRef bytecode_array = shared_info->GetBytecodeArray(broker());

  // Remember that we inlined this function.
  int inlining_id =
      info_->AddInlinedFunction(shared_info->object(), bytecode_array.object(),
                                source_positions_->GetSourcePosition(node));
  if (v8_flags.profile_guided_optimization &&
      feedback_cell.feedback_vector(broker()).has_value() &&
      feedback_cell.feedback_vector(broker())
              .value()
              .object()
              ->invocation_count_before_stable(kRelaxedLoad) >
          v8_flags.invocation_count_for_early_optimization) {
    info_->set_could_not_inline_all_candidates();
  }

  // Create the subgraph for the inlinee.
  Node* start_node;
  Node* end;
  {
    // Run the BytecodeGraphBuilder to create the subgraph.
    Graph::SubgraphScope scope(graph());
    BytecodeGraphBuilderFlags flags(
        BytecodeGraphBuilderFlag::kSkipFirstStackAndTierupCheck);
    if (info_->analyze_environment_liveness()) {
      flags |= BytecodeGraphBuilderFlag::kAnalyzeEnvironmentLiveness;
    }
    if (info_->bailout_on_uninitialized()) {
      flags |= BytecodeGraphBuilderFlag::kBailoutOnUninitialized;
    }
    {
      CallFrequency frequency = call.frequency();
      BuildGraphFromBytecode(broker(), zone(), *shared_info, bytecode_array,
                             feedback_cell, BytecodeOffset::None(), jsgraph(),
                             frequency, source_positions_, node_origins_,
                             inlining_id, info_->code_kind(), flags,
                             &info_->tick_counter());
    }

    // Extract the inlinee start/end nodes.
    start_node = graph()->start();
    end = graph()->end();
  }
  StartNode start{start_node};

  // If we are inlining into a surrounding exception handler, we collect all
  // potentially throwing nodes within the inlinee that are not handled locally
  // by the inlinee itself. They are later wired into the surrounding handler.
  NodeVector uncaught_subcalls(local_zone_);
  if (exception_target != nullptr) {
    // Find all uncaught 'calls' in the inlinee.
    AllNodes inlined_nodes(local_zone_, end, graph());
    for (Node* subnode : inlined_nodes.reachable) {
      // Every possibly throwing node should get {IfSuccess} and {IfException}
      // projections, unless there already is local exception handling.
      if (subnode->op()->HasProperty(Operator::kNoThrow)) continue;
      if (!NodeProperties::IsExceptionalCall(subnode)) {
        DCHECK_EQ(2, subnode->op()->ControlOutputCount());
        uncaught_subcalls.push_back(subnode);
      }
    }
  }

  FrameState frame_state = call.frame_state();
  Node* new_target = jsgraph()->UndefinedConstant();

  // Inline {JSConstruct} requires some additional magic.
  if (node->opcode() == IrOpcode::kJSConstruct) {
    static_assert(JSCallOrConstructNode::kHaveIdenticalLayouts);
    JSConstructNode n(node);

    new_target = n.new_target();

    // Insert nodes around the call that model the behavior required for a
    // constructor dispatch (allocate implicit receiver and check return value).
    // This models the behavior usually accomplished by our {JSConstructStub}.
    // Note that the context has to be the callers context (input to call node).
    // Also note that by splitting off the {JSCreate} piece of the constructor
    // call, we create an observable deoptimization point after the receiver
    // instantiation but before the invocation (i.e. inside {JSConstructStub}
    // where execution continues at {construct_stub_create_deopt_pc_offset}).
    Node* receiver = jsgraph()->TheHoleConstant();  // Implicit receiver.
    Node* caller_context = NodeProperties::GetContextInput(node);
    if (NeedsImplicitReceiver(*shared_info)) {
      Effect effect = n.effect();
      Control control = n.control();
      Node* frame_state_inside;
      HeapObjectMatcher m(new_target);
      if (m.HasResolvedValue() && m.Ref(broker()).IsJSFunction()) {
        // If {new_target} is a JSFunction, then we cannot deopt in the
        // NewObject call. Therefore we do not need the artificial frame state.
        frame_state_inside = frame_state;
      } else {
        frame_state_inside = CreateArtificialFrameState(
            node, frame_state, n.ArgumentCount(),
            FrameStateType::kConstructCreateStub, *shared_info, caller_context);
      }
      Node* create =
          graph()->NewNode(javascript()->Create(), call.target(), new_target,
                           caller_context, frame_state_inside, effect, control);
      uncaught_subcalls.push_back(create);  // Adds {IfSuccess} & {IfException}.
      NodeProperties::ReplaceControlInput(node, create);
      NodeProperties::ReplaceEffectInput(node, create);
      // Placeholder to hold {node}'s value dependencies while {node} is
      // replaced.
      Node* dummy = graph()->NewNode(common()->Dead());
      NodeProperties::ReplaceUses(node, dummy, node, node, node);
      Node* result;
      // Insert a check of the return value to determine whether the return
      // value or the implicit receiver should be selected as a result of the
      // call.
      Node* check = graph()->NewNode(simplified()->ObjectIsReceiver(), node);
      result =
          graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                           check, node, create);
      receiver = create;  // The implicit receiver.
      ReplaceWithValue(dummy, result);
    } else if (IsDerivedConstructor(shared_info->kind())) {
      Node* node_success =
          NodeProperties::FindSuccessfulControlProjection(node);
      Node* is_receiver =
          graph()->NewNode(simplified()->ObjectIsReceiver(), node);
      Node* branch_is_receiver =
          graph()->NewNode(common()->Branch(), is_receiver, node_success);
      Node* branch_is_receiver_true =
          graph()->NewNode(common()->IfTrue(), branch_is_receiver);
      Node* branch_is_receiver_false =
          graph()->NewNode(common()->IfFalse(), branch_is_receiver);
      branch_is_receiver_false = graph()->NewNode(
          javascript()->CallRuntime(
              Runtime::kThrowConstructorReturnedNonObject),
          caller_context, NodeProperties::GetFrameStateInput(node), node,
          branch_is_receiver_false);
      uncaught_subcalls.push_back(branch_is_receiver_false);
      branch_is_receiver_false =
          graph()->NewNode(common()->Throw(), branch_is_receiver_false,
                           branch_is_receiver_false);
      MergeControlToEnd(graph(), common(), branch_is_receiver_false);

      ReplaceWithValue(node_success, node_success, node_success,
                       branch_is_receiver_true);
      // Fix input destroyed by the above {ReplaceWithValue} call.
      NodeProperties::ReplaceControlInput(branch_is_receiver, node_success, 0);
    }
    node->ReplaceInput(JSCallNode::ReceiverIndex(), receiver);
    // Insert a construct stub frame into the chain of frame states. This will
    // reconstruct the proper frame when deoptimizing within the constructor.
    frame_state = CreateArtificialFrameState(
        node, frame_state, 0, FrameStateType::kConstructInvokeStub,
        *shared_info, caller_context);
  }

  // Insert a JSConvertReceiver node for sloppy callees. Note that the context
  // passed into this node has to be the callees context (loaded above).
  if (node->opcode() == IrOpcode::kJSCall &&
      is_sloppy(shared_info->language_mode()) && !shared_info->native()) {
    Effect effect{NodeProperties::GetEffectInput(node)};
    if (NodeProperties::CanBePrimitive(broker(), call.receiver(), effect)) {
      CallParameters const& p = CallParametersOf(node->op());
      Node* global_proxy = jsgraph()->ConstantNoHole(
          broker()->target_native_context().global_proxy_object(broker()),
          broker());
      Node* receiver = effect = graph()->NewNode(
          simplified()->ConvertReceiver(p.convert_mode()), call.receiver(),
          jsgraph()->ConstantNoHole(broker()->target_native_context(),
                                    broker()),
          global_proxy, effect, start);
      NodeProperties::ReplaceValueInput(node, receiver,
                                        JSCallNode::ReceiverIndex());
      NodeProperties::ReplaceEffectInput(node, effect);
    }
  }

  // Insert inlined extra arguments if required. The callees formal parameter
  // count have to match the number of arguments passed to the call.
  int parameter_count = bytecode_array.parameter_count_without_receiver();
  DCHECK_EQ(parameter_count,
            shared_info->internal_formal_parameter_count_without_receiver());
  DCHECK_EQ(parameter_count, start.FormalParameterCountWithoutReceiver());
  if (call.argument_count() != parameter_count) {
    frame_state = CreateArtificialFrameState(
        node, frame_state, call.argument_count(),
        FrameStateType::kInlinedExtraArguments, *shared_info);
  }

  return InlineCall(node, new_target, context, frame_state, start, end,
                    exception_target, uncaught_subcalls, call.argument_count());
}

Graph* JSInliner::graph() const { return jsgraph()->graph(); }

JSOperatorBuilder* JSInliner::javascript() const {
  return jsgraph()->javascript();
}

CommonOperatorBuilder* JSInliner::common() const { return jsgraph()->common(); }

SimplifiedOperatorBuilder* JSInliner::simplified() const {
  return jsgraph()->simplified();
}

#undef TRACE

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```
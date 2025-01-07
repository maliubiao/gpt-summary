Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understanding the Goal:** The request asks for the *functionality* of the given C++ source code file, `graph-builder-interface.cc`, within the V8 JavaScript engine's WebAssembly (Wasm) implementation. Key aspects to consider are:
    * Its role in the overall Wasm compilation pipeline.
    * Its interaction with other V8 components (like TurboFan).
    * Potential connections to JavaScript functionality.
    * Common programming errors it helps prevent or handle.

2. **Initial Scan for Clues:** A quick read-through reveals several important terms and concepts:
    * `graph-builder-interface`:  This strongly suggests it's an interface for building a graph representation of the Wasm code. This graph is likely used by an optimizing compiler like TurboFan.
    * `TFNode`: This likely refers to TurboFan nodes, further solidifying the connection to the TurboFan compiler.
    * `SsaEnv`:  Suggests the use of Static Single Assignment (SSA) form, a common intermediate representation in compilers.
    * `FullDecoder`: Indicates a process of decoding the Wasm bytecode.
    * `Control`, `Loop`: Hints at handling control flow structures within Wasm.
    * `Call`, `ReturnCall`:  Deals with function calls.
    * `Exception`: Indicates support for Wasm's exception handling mechanism.
    * `InstanceCache`:  Likely related to accessing and managing Wasm module instance data (memory, globals, tables).
    * `v8_flags`:  Indicates runtime flags that can influence the behavior of this code. This is important for understanding conditional logic.
    * `BuildTFGraph`: The main entry point function, which orchestrates the graph building process.

3. **Dissecting Key Components:** Now, let's examine the core parts of the code more deeply:

    * **`WasmGraphBuildingInterface` Class:** This is the heart of the functionality. It seems to encapsulate the state and methods needed to build the graph. Let's look at some of its key methods:
        * `emit_loop_exits()`:  A flag based on V8 flags, suggesting optimization strategies like loop unrolling or peeling.
        * `GetNodes()`: Utility to extract `TFNode` pointers from `Value` objects.
        * `SetEnv()`: Manages the SSA environment. The debug printing with state information is interesting.
        * `CheckForException()`: Crucial for handling potential exceptions during Wasm execution. It creates `IfSuccess` and `IfException` nodes. The logic for inlined calls and try-catch blocks is important.
        * `MergeValuesInto()`, `Goto()`, `Split()`, `Steal()`:  Fundamental operations for working with SSA form, merging control flow paths and data.
        * `CallInfo` struct:  Encapsulates information about different types of Wasm calls (direct, indirect, ref).
        * `DoCall()`, `DoReturnCall()`:  Generate the appropriate TurboFan call nodes. Note the handling of `CheckForException` and reloading the instance cache.
        * `BuildLoopExits()`, `WrapLocalsAtLoopExit()`, `BuildNestedLoopExits()`:  Specific logic for handling loops and potential exit points, which is essential for optimization.
        * `FindFirstUsedMemoryIndex()`: An interesting optimization attempt to find the first memory access.
        * `ThrowRef()`:  Handles explicit `throw` operations in Wasm.

    * **`BuildTFGraph()` Function:** This is the top-level function that drives the graph building process. It instantiates the `WasmFullDecoder` with the `WasmGraphBuildingInterface`.

    * **`WasmFullDecoder`:**  This class (not fully shown in the snippet but implied) is responsible for iterating through the Wasm bytecode and using the `WasmGraphBuildingInterface` to create the corresponding graph nodes.

4. **Connecting to JavaScript:** The connection is through the compilation pipeline of V8. When JavaScript calls a WebAssembly function, or when Wasm code is being compiled initially, this code is involved in translating the Wasm bytecode into an optimized intermediate representation that TurboFan can further compile into machine code.

5. **Reasoning about Logic and Examples:**

    * **Control Flow Merging (using `Goto`):**  Imagine an `if-else` block in Wasm. The `Goto` function is used to merge the control flow from both branches into a single point after the `if-else`. This involves creating `Merge` nodes in the graph and potentially `Phi` nodes for values that might have different origins depending on the branch taken.

    * **Exception Handling:** The `CheckForException` function demonstrates how the graph builder handles potential exceptions. It creates separate paths for successful execution (`if_success`) and exceptional execution (`if_exception`).

    * **Loop Exits:** The `BuildLoopExits` and related functions are designed to handle scenarios where execution might break out of a loop. This is crucial for optimizations like loop unrolling, where the compiler needs to know the state of variables when exiting the loop.

6. **Identifying Common Errors:** The code helps mitigate common errors by:

    * **Type Checking:**  The `Value` struct and the `SetAndTypeNode` function suggest that the graph builder is aware of the types of values and ensures consistency.
    * **Handling Unreachable Code:** The `SsaEnv::kUnreachable` state allows the builder to track and potentially optimize away unreachable code.
    * **Managing Instance State:**  The `InstanceCache` and related functions ensure that memory and other instance-specific data are accessed correctly, preventing issues related to stale or incorrect data.

7. **Structuring the Answer:** Finally, organize the findings into a clear and logical structure, as demonstrated in the initial good answer. Use headings, bullet points, code snippets (where appropriate), and examples to make the explanation easy to understand. Pay attention to the specific requirements of the prompt (e.g., mentioning `.tq` files, JavaScript examples, input/output assumptions).

8. **Refinement (Self-Correction):** After drafting the answer, review it to ensure accuracy, completeness, and clarity. For instance, double-check the explanation of SSA concepts, the role of TurboFan, and the specific examples provided. Ensure that the summary accurately captures the core functionality. Initially, I might have focused too much on individual methods, but then I'd realize the importance of highlighting the overall *process* of graph building and its role in the compilation pipeline.
好的，让我们来分析一下 `v8/src/wasm/graph-builder-interface.cc` 这个文件的功能。

**功能归纳:**

`v8/src/wasm/graph-builder-interface.cc`  是 V8 引擎中 WebAssembly (Wasm) 模块的一个关键组件，它的主要功能是**作为桥梁，将解码后的 WebAssembly 指令转换为 TurboFan 图形表示 (TurboFan Graph)。** 这个图形表示是 TurboFan 优化编译器进行后续优化的基础。

**更详细的功能分解:**

1. **定义了 `WasmGraphBuildingInterface` 类:**  这个类是实际执行从 Wasm 指令到 TurboFan 图节点转换的核心接口。它包含了各种方法，用于创建和连接 TurboFan 图中的节点，以表示 Wasm 的各种操作，如算术运算、内存访问、控制流、函数调用等。

2. **管理 SSA 环境 (Static Single Assignment Environment):**  `SsaEnv` 结构体和相关的 `SetEnv`、`Split`、`Steal`、`Goto`、`MergeValuesInto` 等方法负责维护构建图时的静态单赋值信息。SSA 是一种编译器中间表示，其中每个变量只被赋值一次，这简化了后续的优化过程。

3. **处理控制流结构:** 代码中包含处理 Wasm 控制流指令（如 `if`、`else`、`loop`、`block`）的逻辑。例如，`Goto` 方法用于跳转到不同的控制流分支，`MergeValuesInto` 用于合并不同分支上的值。

4. **处理函数调用:** `CallInfo` 结构体和 `DoCall`、`DoReturnCall` 方法用于处理 Wasm 函数调用，包括直接调用、间接调用和通过 `funcref` 的调用。这涉及到创建 TurboFan 的 `Call` 或 `ReturnCall` 节点。

5. **处理异常:** `CheckForException` 方法负责处理可能抛出异常的 Wasm 操作。它会创建 `IfSuccess` 和 `IfException` 节点来表示正常执行和异常处理的控制流。

6. **处理循环:**  `BuildLoopExits`、`WrapLocalsAtLoopExit`、`BuildNestedLoopExits` 等方法用于处理 Wasm 循环结构。这对于优化循环（例如循环展开）非常重要。

7. **管理 WebAssembly 实例缓存:**  代码中涉及到 `instance_cache` 的操作，这与访问和更新 WebAssembly 模块实例的内存、全局变量和表有关。`ReloadInstanceCacheIntoSsa` 用于在某些操作后重新加载实例缓存的状态。

8. **处理 `return` 和 `tail call`:**  虽然代码片段没有直接展示创建 `Return` 或 `TailCall` 节点的代码，但注释提到了这些节点是 `emit_loop_exits` 方法可能被调用的场景之一，暗示了这个接口也负责构建这些节点。

9. **与类型反馈集成:**  `next_call_feedback` 方法表明该接口与类型反馈机制集成，以便在运行时收集类型信息，用于后续的优化。

10. **提供入口函数 `BuildTFGraph`:**  这个函数是构建 TurboFan 图的入口点。它创建 `WasmFullDecoder` 并驱动解码和图构建过程。

**关于文件扩展名和 Torque:**

如果 `v8/src/wasm/graph-builder-interface.cc` 的扩展名是 `.tq`，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 自研的一种领域特定语言，用于编写 V8 内部的运行时代码，特别是那些对性能要求很高的部分。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 的关系 (示例):**

WebAssembly 的主要目的是在 Web 浏览器中以接近原生速度执行代码。JavaScript 可以加载、编译和执行 WebAssembly 模块。`graph-builder-interface.cc` 在 WebAssembly 模块的编译过程中发挥作用，将 Wasm 代码转换为 V8 可以理解和优化的形式。

```javascript
// JavaScript 加载和实例化 WebAssembly 模块
fetch('my_wasm_module.wasm')
  .then(response => response.arrayBuffer())
  .then(bytes => WebAssembly.instantiate(bytes))
  .then(results => {
    const wasmModule = results.instance;
    // 调用 WebAssembly 导出的函数
    const result = wasmModule.exports.add(5, 3);
    console.log(result); // 输出 8
  });
```

在这个例子中，当 `WebAssembly.instantiate` 被调用时，V8 内部会解码 `my_wasm_module.wasm` 的内容，并使用类似 `graph-builder-interface.cc` 中的代码将 Wasm 指令转换为 TurboFan 图，最终编译成机器码执行。

**代码逻辑推理 (假设输入与输出):**

假设我们有一个简单的 WebAssembly 函数，它将两个 i32 类型的参数相加并返回结果：

```wasm
(module
  (func $add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
    return))
```

当解码器处理 `i32.add` 指令时，`WasmGraphBuildingInterface` 中的某个方法（可能在 `DoBinaryOp` 或类似的方法中）会被调用，它会：

* **输入:** 代表两个局部变量的 `Value` 对象 (`local.get 0`, `local.get 1`)，以及 `i32.add` 操作码。
* **输出:** 一个代表加法运算结果的 `Value` 对象，其内部包含指向新创建的 TurboFan `Int32Add` 节点的指针。这个节点的输入是之前两个 `Value` 对象中包含的节点。

**用户常见的编程错误 (举例):**

虽然 `graph-builder-interface.cc` 本身是 V8 内部代码，用户不会直接编写或修改它，但它在编译过程中帮助捕获一些 Wasm 代码中的错误，或者为后续的运行时错误处理提供基础。

一个例子是**类型不匹配**。如果 Wasm 代码尝试将一个 `f64` 类型的值传递给一个期望 `i32` 类型的函数参数，图构建过程可能会检测到这种类型不一致，并可能导致编译错误或运行时异常。虽然具体的类型检查可能在解码器或其他阶段进行，但图构建接口需要正确处理和表示这些类型信息。

**功能归纳 (针对第 4 部分):**

根据提供的代码片段，这部分代码主要关注以下几个方面：

* **处理循环的退出:** `emit_loop_exits` 方法和相关的 `BuildLoopExits` 等函数，用于在图构建阶段处理循环的退出点，这对于循环优化至关重要。
* **管理 SSA 环境:**  `GetNodes`、`SetEnv`、`Split`、`Steal`、`Goto`、`MergeValuesInto` 等方法展示了如何维护和操作 SSA 环境，这是构建正确和可优化的图的关键。
* **处理异常:** `CheckForException` 方法以及与 `TryInfo` 的交互，展示了如何将 Wasm 的异常处理机制映射到 TurboFan 图的结构中。
* **处理函数调用:** `CallInfo` 结构体和 `DoCall`、`DoReturnCall` 方法定义了如何构建函数调用相关的图节点。

总而言之，这部分代码是 `WasmGraphBuildingInterface` 的核心功能实现，负责将解码后的 Wasm 指令转换为 TurboFan 可以理解的图形表示，并处理控制流、数据流、异常和函数调用等关键方面。

Prompt: 
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/graph-builder-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
se are Return and TailCall nodes.
  // - After IfFailure nodes.
  // - When exiting a loop through Delegate.
  bool emit_loop_exits() {
    return v8_flags.wasm_loop_unrolling || v8_flags.wasm_loop_peeling;
  }

  void GetNodes(TFNode** nodes, const Value* values, size_t count) {
    for (size_t i = 0; i < count; ++i) {
      nodes[i] = values[i].node;
    }
  }

  void GetNodes(TFNode** nodes, base::Vector<const Value> values) {
    GetNodes(nodes, values.begin(), values.size());
  }

  void SetEnv(SsaEnv* env) {
    if (v8_flags.trace_wasm_decoder) {
      char state = 'X';
      if (env) {
        switch (env->state) {
          case SsaEnv::kReached:
            state = 'R';
            break;
          case SsaEnv::kUnreachable:
            state = 'U';
            break;
          case SsaEnv::kMerged:
            state = 'M';
            break;
        }
      }
      PrintF("{set_env = %p, state = %c", env, state);
      if (env && env->control) {
        PrintF(", control = ");
        compiler::WasmGraphBuilder::PrintDebugName(env->control);
      }
      PrintF("}\n");
    }
    if (ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    ssa_env_ = env;
    builder_->SetEffectControl(env->effect, env->control);
    builder_->set_instance_cache(&env->instance_cache);
  }

  TFNode* CheckForException(FullDecoder* decoder, TFNode* node,
                            bool may_modify_instance_cache) {
    DCHECK_NOT_NULL(node);

    // We need to emit IfSuccess/IfException nodes if this node throws and has
    // an exception handler. An exception handler can either be a try-scope
    // around this node, or if this function is being inlined, the IfException
    // output of the inlined Call node.
    const bool inside_try_scope = decoder->current_catch() != -1;
    if (inlined_status_ != kInlinedHandledCall && !inside_try_scope) {
      return node;
    }

    TFNode* if_success = nullptr;
    TFNode* if_exception = nullptr;
    if (!builder_->ThrowsException(node, &if_success, &if_exception)) {
      return node;
    }

    // TODO(choongwoo): Clear locals of `success_env` after use.
    SsaEnv* success_env = Steal(decoder->zone(), ssa_env_);
    success_env->control = if_success;

    SsaEnv* exception_env = Split(decoder->zone(), success_env);
    exception_env->control = if_exception;
    exception_env->effect = if_exception;

    ScopedSsaEnv scoped_env(this, exception_env, success_env);

    // The exceptional operation could have modified memory size; we need to
    // reload the memory context into the exceptional control path.
    if (may_modify_instance_cache) {
      ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);
    }

    if (emit_loop_exits()) {
      ValueVector values;
      BuildNestedLoopExits(decoder,
                           inside_try_scope
                               ? decoder->control_depth_of_current_catch()
                               : decoder->control_depth() - 1,
                           true, values, &if_exception);
    }
    if (inside_try_scope) {
      TryInfo* try_info = current_try_info(decoder);
      Goto(decoder, try_info->catch_env);
      if (try_info->exception == nullptr) {
        DCHECK_EQ(SsaEnv::kReached, try_info->catch_env->state);
        try_info->exception = if_exception;
      } else {
        DCHECK_EQ(SsaEnv::kMerged, try_info->catch_env->state);
        try_info->exception = builder_->CreateOrMergeIntoPhi(
            MachineRepresentation::kTaggedPointer, try_info->catch_env->control,
            try_info->exception, if_exception);
      }
    } else {
      DCHECK_EQ(inlined_status_, kInlinedHandledCall);
      // We leave the IfException/LoopExit node dangling, and record the
      // exception/effect/control here. We will connect them to the handler of
      // the inlined call during inlining.
      // Note: We have to generate the handler now since we have no way of
      // generating a LoopExit if needed in the inlining code.
      dangling_exceptions_.Add(if_exception, effect(), control());
    }
    return node;
  }

  void MergeValuesInto(FullDecoder* decoder, Control* c, Merge<Value>* merge,
                       Value* values) {
    DCHECK(merge == &c->start_merge || merge == &c->end_merge);

    SsaEnv* target = c->merge_env;
    // This has to be computed before calling Goto().
    const bool first = target->state == SsaEnv::kUnreachable;

    Goto(decoder, target);

    if (merge->arity == 0) return;

    for (uint32_t i = 0; i < merge->arity; ++i) {
      Value& val = values[i];
      Value& old = (*merge)[i];
      DCHECK_NOT_NULL(val.node);
      DCHECK(val.type == kWasmBottom || val.type.machine_representation() ==
                                            old.type.machine_representation());
      old.node = first ? val.node
                       : builder_->CreateOrMergeIntoPhi(
                             old.type.machine_representation(), target->control,
                             old.node, val.node);
    }
  }

  void MergeValuesInto(FullDecoder* decoder, Control* c, Merge<Value>* merge,
                       uint32_t drop_values = 0) {
#ifdef DEBUG
    uint32_t avail = decoder->stack_size() -
                     decoder->control_at(0)->stack_depth - drop_values;
    DCHECK_GE(avail, merge->arity);
#endif
    Value* stack_values = merge->arity > 0
                              ? decoder->stack_value(merge->arity + drop_values)
                              : nullptr;
    MergeValuesInto(decoder, c, merge, stack_values);
  }

  void Goto(FullDecoder* decoder, SsaEnv* to) {
    DCHECK_NOT_NULL(to);
    switch (to->state) {
      case SsaEnv::kUnreachable: {  // Overwrite destination.
        to->state = SsaEnv::kReached;
        DCHECK_EQ(ssa_env_->locals.size(), decoder->num_locals());
        to->locals = ssa_env_->locals;
        to->control = control();
        to->effect = effect();
        to->instance_cache = ssa_env_->instance_cache;
        break;
      }
      case SsaEnv::kReached: {  // Create a new merge.
        to->state = SsaEnv::kMerged;
        // Merge control.
        TFNode* controls[] = {to->control, control()};
        TFNode* merge = builder_->Merge(2, controls);
        to->control = merge;
        // Merge effects.
        TFNode* old_effect = effect();
        if (old_effect != to->effect) {
          TFNode* inputs[] = {to->effect, old_effect, merge};
          to->effect = builder_->EffectPhi(2, inputs);
        }
        // Merge locals.
        DCHECK_EQ(ssa_env_->locals.size(), decoder->num_locals());
        for (uint32_t i = 0; i < to->locals.size(); i++) {
          TFNode* a = to->locals[i];
          TFNode* b = ssa_env_->locals[i];
          if (a != b) {
            TFNode* inputs[] = {a, b, merge};
            to->locals[i] = builder_->Phi(decoder->local_type(i), 2, inputs);
          }
        }
        // Start a new merge from the instance cache.
        builder_->NewInstanceCacheMerge(&to->instance_cache,
                                        &ssa_env_->instance_cache, merge);
        break;
      }
      case SsaEnv::kMerged: {
        TFNode* merge = to->control;
        // Extend the existing merge control node.
        builder_->AppendToMerge(merge, control());
        // Merge effects.
        to->effect =
            builder_->CreateOrMergeIntoEffectPhi(merge, to->effect, effect());
        // Merge locals.
        for (uint32_t i = 0; i < to->locals.size(); i++) {
          to->locals[i] = builder_->CreateOrMergeIntoPhi(
              decoder->local_type(i).machine_representation(), merge,
              to->locals[i], ssa_env_->locals[i]);
        }
        // Merge the instance caches.
        builder_->MergeInstanceCacheInto(&to->instance_cache,
                                         &ssa_env_->instance_cache, merge);
        break;
      }
      default:
        UNREACHABLE();
    }
  }

  // Create a complete copy of {from}.
  SsaEnv* Split(Zone* zone, SsaEnv* from) {
    DCHECK_NOT_NULL(from);
    if (from == ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    SsaEnv* result = zone->New<SsaEnv>(*from);
    result->state = SsaEnv::kReached;
    return result;
  }

  // Create a copy of {from} that steals its state and leaves {from}
  // unreachable.
  SsaEnv* Steal(Zone* zone, SsaEnv* from) {
    DCHECK_NOT_NULL(from);
    if (from == ssa_env_) {
      ssa_env_->control = control();
      ssa_env_->effect = effect();
    }
    SsaEnv* result = zone->New<SsaEnv>(std::move(*from));
    result->state = SsaEnv::kReached;
    return result;
  }

  class CallInfo {
   public:
    enum CallMode { kCallDirect, kCallIndirect, kCallRef };

    static CallInfo CallDirect(uint32_t callee_index, int call_count) {
      return {kCallDirect, callee_index, nullptr,
              static_cast<uint32_t>(call_count),
              CheckForNull::kWithoutNullCheck};
    }

    static CallInfo CallIndirect(const Value& index_value, uint32_t table_index,
                                 ModuleTypeIndex sig_index) {
      return {kCallIndirect, sig_index.index, &index_value, table_index,
              CheckForNull::kWithoutNullCheck};
    }

    static CallInfo CallRef(const Value& funcref_value,
                            CheckForNull null_check) {
      return {kCallRef, 0, &funcref_value, 0, null_check};
    }

    CallMode call_mode() { return call_mode_; }

    ModuleTypeIndex sig_index() {
      DCHECK_EQ(call_mode_, kCallIndirect);
      return ModuleTypeIndex{callee_or_sig_index_};
    }

    uint32_t callee_index() {
      DCHECK_EQ(call_mode_, kCallDirect);
      return callee_or_sig_index_;
    }

    int call_count() {
      DCHECK_EQ(call_mode_, kCallDirect);
      return static_cast<int>(table_index_or_call_count_);
    }

    CheckForNull null_check() {
      DCHECK_EQ(call_mode_, kCallRef);
      return null_check_;
    }

    const Value* index_or_callee_value() {
      DCHECK_NE(call_mode_, kCallDirect);
      return index_or_callee_value_;
    }

    uint32_t table_index() {
      DCHECK_EQ(call_mode_, kCallIndirect);
      return table_index_or_call_count_;
    }

   private:
    CallInfo(CallMode call_mode, uint32_t callee_or_sig_index,
             const Value* index_or_callee_value,
             uint32_t table_index_or_call_count, CheckForNull null_check)
        : call_mode_(call_mode),
          callee_or_sig_index_(callee_or_sig_index),
          index_or_callee_value_(index_or_callee_value),
          table_index_or_call_count_(table_index_or_call_count),
          null_check_(null_check) {}
    CallMode call_mode_;
    uint32_t callee_or_sig_index_;
    const Value* index_or_callee_value_;
    uint32_t table_index_or_call_count_;
    CheckForNull null_check_;
  };

  void DoCall(FullDecoder* decoder, CallInfo call_info, const FunctionSig* sig,
              const Value args[], Value returns[]) {
    size_t param_count = sig->parameter_count();
    size_t return_count = sig->return_count();
    NodeVector arg_nodes(param_count + 1);
    base::SmallVector<TFNode*, 1> return_nodes(return_count);
    arg_nodes[0] = (call_info.call_mode() == CallInfo::kCallDirect)
                       ? nullptr
                       : call_info.index_or_callee_value()->node;

    for (size_t i = 0; i < param_count; ++i) {
      arg_nodes[i + 1] = args[i].node;
    }
    switch (call_info.call_mode()) {
      case CallInfo::kCallIndirect: {
        TFNode* call = builder_->CallIndirect(
            call_info.table_index(), call_info.sig_index(),
            base::VectorOf(arg_nodes), base::VectorOf(return_nodes),
            decoder->position());
        CheckForException(decoder, call, true);
        break;
      }
      case CallInfo::kCallDirect: {
        TFNode* call = builder_->CallDirect(
            call_info.callee_index(), base::VectorOf(arg_nodes),
            base::VectorOf(return_nodes), decoder->position());
        builder_->StoreCallCount(call, call_info.call_count());
        CheckForException(decoder, call, true);
        break;
      }
      case CallInfo::kCallRef: {
        TFNode* call = builder_->CallRef(
            sig, base::VectorOf(arg_nodes), base::VectorOf(return_nodes),
            call_info.null_check(), decoder->position());
        CheckForException(decoder, call, true);
        break;
      }
    }
    for (size_t i = 0; i < return_count; ++i) {
      SetAndTypeNode(&returns[i], return_nodes[i]);
    }
    // The invoked function could have used grow_memory, so we need to
    // reload memory information.
    ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);
  }

  void DoReturnCall(FullDecoder* decoder, CallInfo call_info,
                    const FunctionSig* sig, const Value args[]) {
    size_t arg_count = sig->parameter_count();

    ValueVector arg_values(arg_count + 1);
    if (call_info.call_mode() == CallInfo::kCallDirect) {
      arg_values[0].node = nullptr;
    } else {
      arg_values[0] = *call_info.index_or_callee_value();
      // This is not done by copy assignment.
      arg_values[0].node = call_info.index_or_callee_value()->node;
    }
    if (arg_count > 0) {
      std::memcpy(arg_values.data() + 1, args, arg_count * sizeof(Value));
    }

    if (emit_loop_exits()) {
      BuildNestedLoopExits(decoder, decoder->control_depth(), false,
                           arg_values);
    }

    NodeVector arg_nodes(arg_count + 1);
    GetNodes(arg_nodes.data(), base::VectorOf(arg_values));

    switch (call_info.call_mode()) {
      case CallInfo::kCallIndirect:
        builder_->ReturnCallIndirect(
            call_info.table_index(), call_info.sig_index(),
            base::VectorOf(arg_nodes), decoder->position());
        break;
      case CallInfo::kCallDirect: {
        TFNode* call = builder_->ReturnCall(call_info.callee_index(),
                                            base::VectorOf(arg_nodes),
                                            decoder->position());
        builder_->StoreCallCount(call, call_info.call_count());
        break;
      }
      case CallInfo::kCallRef:
        builder_->ReturnCallRef(sig, base::VectorOf(arg_nodes),
                                call_info.null_check(), decoder->position());
        break;
    }
  }

  const CallSiteFeedback& next_call_feedback() {
    DCHECK_LT(feedback_instruction_index_, type_feedback_.size());
    return type_feedback_[feedback_instruction_index_++];
  }

  void BuildLoopExits(FullDecoder* decoder, Control* loop) {
    builder_->LoopExit(loop->loop_node);
    ssa_env_->control = control();
    ssa_env_->effect = effect();
  }

  void WrapLocalsAtLoopExit(FullDecoder* decoder, Control* loop) {
    for (uint32_t index = 0; index < decoder->num_locals(); index++) {
      if (loop->loop_assignments->Contains(static_cast<int>(index))) {
        ssa_env_->locals[index] = builder_->LoopExitValue(
            ssa_env_->locals[index],
            decoder->local_type(index).machine_representation());
      }
    }
    if (loop->loop_assignments->Contains(decoder->num_locals())) {
      for (auto field : compiler::WasmInstanceCacheNodes::kFields) {
        if (ssa_env_->instance_cache.*field == nullptr) continue;
        ssa_env_->instance_cache.*field =
            builder_->LoopExitValue(ssa_env_->instance_cache.*field,
                                    MachineType::PointerRepresentation());
      }
    }
  }

  void BuildNestedLoopExits(FullDecoder* decoder, uint32_t depth_limit,
                            bool wrap_exit_values, ValueVector& stack_values,
                            TFNode** exception_value = nullptr) {
    DCHECK(emit_loop_exits());
    Control* control = nullptr;
    // We are only interested in exits from the innermost loop.
    for (uint32_t i = 0; i < depth_limit; i++) {
      Control* c = decoder->control_at(i);
      if (c->is_loop()) {
        control = c;
        break;
      }
    }
    if (control != nullptr && control->loop_innermost) {
      BuildLoopExits(decoder, control);
      for (Value& value : stack_values) {
        if (value.node != nullptr) {
          value.node = builder_->SetType(
              builder_->LoopExitValue(value.node,
                                      value.type.machine_representation()),
              value.type);
        }
      }
      if (exception_value != nullptr) {
        *exception_value = builder_->LoopExitValue(
            *exception_value, MachineRepresentation::kTaggedPointer);
      }
      if (wrap_exit_values) {
        WrapLocalsAtLoopExit(decoder, control);
      }
    }
  }

  CheckForNull NullCheckFor(ValueType type) {
    DCHECK(type.is_object_reference());
    return type.is_nullable() ? CheckForNull::kWithNullCheck
                              : CheckForNull::kWithoutNullCheck;
  }

  void SetAndTypeNode(Value* value, TFNode* node) {
    // This DCHECK will help us catch uninitialized values.
    DCHECK_LT(value->type.kind(), kBottom);
    value->node = builder_->SetType(node, value->type);
  }

  // In order to determine the memory index to cache in an SSA value, we try to
  // determine the first memory index that will be accessed in the function. If
  // we do not find a memory access this method returns -1.
  // This is a best-effort implementation: It ignores potential control flow and
  // only looks for basic memory load and store operations.
  int FindFirstUsedMemoryIndex(base::Vector<const uint8_t> body, Zone* zone) {
    BodyLocalDecls locals;
    for (BytecodeIterator it{body.begin(), body.end(), &locals, zone};
         it.has_next(); it.next()) {
      WasmOpcode opcode = it.current();
      constexpr bool kConservativelyAssumeMemory64 = true;
      switch (opcode) {
        default:
          break;
#define CASE(name, ...) case kExpr##name:
          FOREACH_LOAD_MEM_OPCODE(CASE)
          FOREACH_STORE_MEM_OPCODE(CASE)
#undef CASE
          MemoryAccessImmediate imm(&it, it.pc() + 1, UINT32_MAX,
                                    kConservativelyAssumeMemory64,
                                    Decoder::kNoValidation);
          return imm.mem_index;
      }
    }
    return -1;
  }

  void ThrowRef(FullDecoder* decoder, TFNode* exception) {
    DCHECK_NOT_NULL(exception);
    CheckForException(decoder, builder_->ThrowRef(exception), false);
    builder_->TerminateThrow(effect(), control());
  }
};

}  // namespace

void BuildTFGraph(AccountingAllocator* allocator, WasmEnabledFeatures enabled,
                  const WasmModule* module, compiler::WasmGraphBuilder* builder,
                  WasmDetectedFeatures* detected, const FunctionBody& body,
                  std::vector<compiler::WasmLoopInfo>* loop_infos,
                  DanglingExceptions* dangling_exceptions,
                  compiler::NodeOriginTable* node_origins, int func_index,
                  AssumptionsJournal* assumptions,
                  InlinedStatus inlined_status) {
  Zone zone(allocator, ZONE_NAME);
  WasmFullDecoder<Decoder::NoValidationTag, WasmGraphBuildingInterface> decoder(
      &zone, module, enabled, detected, body, builder, func_index, assumptions,
      inlined_status, &zone);
  if (node_origins) {
    builder->AddBytecodePositionDecorator(node_origins, &decoder);
  }
  decoder.Decode();
  if (node_origins) {
    builder->RemoveBytecodePositionDecorator();
  }
  *loop_infos = std::move(decoder.interface().loop_infos());
  if (dangling_exceptions != nullptr) {
    *dangling_exceptions = std::move(decoder.interface().dangling_exceptions());
  }
  // TurboFan does not run with validation, so graph building must always
  // succeed.
  CHECK(decoder.ok());
}

}  // namespace v8::internal::wasm

"""


```
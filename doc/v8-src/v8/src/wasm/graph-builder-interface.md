Response: The user wants a summary of the C++ source code file `v8/src/wasm/graph-builder-interface.cc`.
This file seems to be related to the process of building a graph representation of WebAssembly code, likely for compilation.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** Based on the file name, it seems to define an interface for building a graph. The inclusion of `<compiler/wasm-compiler.h>` suggests this graph is used by the V8 compiler.

2. **Analyze key classes and structs:** Look for the main building blocks like `WasmGraphBuildingInterface`, `SsaEnv`, `Control`, and `Value`. These structures likely represent the state and data during the graph construction process.

3. **Understand the flow:**  The names of methods like `StartFunction`, `NextInstruction`, `Block`, `Loop`, `If`, `CallDirect`, etc., suggest that the interface is used to process the WebAssembly bytecode sequentially.

4. **Look for relationships to JavaScript:**  The presence of "well-known imports" and handling of string operations (like `ExternRefToString`, `StringConcat`) points to interactions with JavaScript's string representation.

5. **Consider the "part 1 of 2" aspect:**  Focus on the functionality present in this first part of the file.

**High-Level Plan:**

* Briefly state the file's purpose: defining an interface for building a graph for WebAssembly compilation in V8.
* Highlight the key classes/structs and their roles (SSA environment, control flow, values).
* Explain how the interface processes WebAssembly instructions.
* Identify the JavaScript interaction through well-known imports and string operations, providing a simple example.
这个C++源代码文件 `v8/src/wasm/graph-builder-interface.cc` 的功能是定义了一个接口 `WasmGraphBuildingInterface`，用于将 WebAssembly 的字节码表示转换成 V8 编译器可以理解的图结构 (TF graph，即 TensorFlow graph 的变种)。

更具体地说，这个接口提供了一系列方法，当解析 WebAssembly 字节码时会被调用，用来构建代表程序逻辑和数据流的图节点。这些方法对应了各种 WebAssembly 的操作码，例如算术运算、内存访问、控制流指令（如 `block`、`loop`、`if`）、函数调用等等。

**与 JavaScript 的关系：**

这个接口与 JavaScript 的功能紧密相关，因为它处理的是如何在 V8 引擎中执行 WebAssembly 代码。WebAssembly 的主要目的是提供一个高性能的目标平台，使得其他语言（包括 JavaScript）可以编译到 WebAssembly 并在浏览器或其他环境中高效运行。

这个接口在以下几个方面与 JavaScript 有关：

1. **互操作性 (Interoperability):** WebAssembly 模块可以导入和导出 JavaScript 函数和值。`WasmGraphBuildingInterface` 需要处理这些导入和导出，确保 WebAssembly 代码可以正确地调用 JavaScript 代码，反之亦然。文件中的 `HandleWellKnownImport` 方法就处理了一些预定义的、与 JavaScript 相关的导入函数。

2. **类型系统 (Type System):** WebAssembly 有自己的类型系统，需要与 JavaScript 的类型系统进行交互。例如，当 WebAssembly 调用 JavaScript 函数时，需要进行类型转换和检查。

3. **内存管理 (Memory Management):** WebAssembly 可以拥有自己的线性内存，但也需要与 JavaScript 的内存模型进行交互，尤其是在共享内存的情况下。

4. **异常处理 (Exception Handling):**  WebAssembly 的异常处理机制需要与 JavaScript 的异常处理机制进行集成。

**JavaScript 示例：**

以下是一个简单的 JavaScript 例子，展示了 WebAssembly 如何与 JavaScript 交互，并说明了 `graph-builder-interface.cc` 在幕后所做的工作：

```javascript
// 创建一个 WebAssembly 模块
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM 标头
  0x01, 0x07, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07,
  0x08, 0x01, 0x04, 0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00,
  0x20, 0x00, 0x20, 0x00, 0x6a, 0x0b,
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const importObject = {
  env: {
    // 这里可以定义 WebAssembly 模块导入的 JavaScript 函数
  },
};
const wasmInstance = new WebAssembly.Instance(wasmModule, importObject);

// 调用 WebAssembly 导出的函数
// const result = wasmInstance.exports.add(5, 3);
// console.log(result); // 输出 8
```

在这个例子中，当 V8 引擎加载并编译 `wasmCode` 时，`WasmGraphBuildingInterface` 就会被用来构建 `add` 函数的图表示。如果 `wasmCode` 中包含了对 JavaScript 函数的调用（通过 `importObject` 导入），`HandleWellKnownImport` 或类似的方法就会负责处理这些调用，生成相应的图节点，以便在执行时能够桥接到 JavaScript 环境。

**总结（对于第 1 部分）：**

`v8/src/wasm/graph-builder-interface.cc` 的第 1 部分主要定义了 `WasmGraphBuildingInterface` 接口及其相关的辅助结构（如 `SsaEnv` 和 `Control`）。这个接口是 WebAssembly 代码编译到 V8 内部图表示的关键组件。它负责接收 WebAssembly 字节码的解码信息，并逐步构建出可以被 V8 编译器进一步优化和执行的图结构。 这一部分代码着重于定义构建过程的基础框架和状态管理，为后续处理各种 WebAssembly 指令打下基础。

Prompt: 
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/graph-builder-interface.h"

#include "src/base/vector.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/compiler/wasm-compiler.h"
#include "src/flags/flags.h"
#include "src/wasm/branch-hint-map.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/well-known-imports.h"

namespace v8::internal::wasm {

namespace {

// Expose {compiler::Node} opaquely as {wasm::TFNode}.
using TFNode = compiler::Node;
using LocalsAllocator = RecyclingZoneAllocator<TFNode*>;

class LocalsVector {
 public:
  LocalsVector(LocalsAllocator* allocator, size_t size)
      : allocator_(allocator), data_(allocator->allocate(size), size) {
    std::fill(data_.begin(), data_.end(), nullptr);
  }
  LocalsVector(const LocalsVector& other) V8_NOEXCEPT
      : allocator_(other.allocator_),
        data_(allocator_->allocate(other.size()), other.size()) {
    data_.OverwriteWith(other.data_);
  }
  LocalsVector(LocalsVector&& other) V8_NOEXCEPT
      : allocator_(other.allocator_),
        data_(other.data_.begin(), other.size()) {
    other.data_.Truncate(0);
  }
  ~LocalsVector() { Clear(); }

  LocalsVector& operator=(const LocalsVector& other) V8_NOEXCEPT {
    allocator_ = other.allocator_;
    if (data_.empty()) {
      data_ = base::Vector<TFNode*>(allocator_->allocate(other.size()),
                                    other.size());
    }
    data_.OverwriteWith(other.data_);
    return *this;
  }
  TFNode*& operator[](size_t index) { return data_[index]; }
  size_t size() const { return data_.size(); }

  void Clear() {
    if (size()) allocator_->deallocate(data_.begin(), size());
    data_.Truncate(0);
  }

 private:
  LocalsAllocator* allocator_ = nullptr;
  base::Vector<TFNode*> data_;
};

// An SsaEnv environment carries the current local variable renaming
// as well as the current effect and control dependency in the TF graph.
// It maintains a control state that tracks whether the environment
// is reachable, has reached a control end, or has been merged.
// It's encouraged to manage lifetime of SsaEnv by `ScopedSsaEnv` or
// `Control` (`block_env`, `false_env`, or `try_info->catch_env`).
struct SsaEnv : public ZoneObject {
  enum State { kUnreachable, kReached, kMerged };

  State state;
  TFNode* effect;
  TFNode* control;
  compiler::WasmInstanceCacheNodes instance_cache;
  LocalsVector locals;

  SsaEnv(LocalsAllocator* alloc, State state, TFNode* effect, TFNode* control,
         uint32_t locals_size)
      : state(state),
        effect(effect),
        control(control),
        locals(alloc, locals_size) {}

  SsaEnv(const SsaEnv& other) V8_NOEXCEPT = default;
  SsaEnv(SsaEnv&& other) V8_NOEXCEPT : state(other.state),
                                       effect(other.effect),
                                       control(other.control),
                                       instance_cache(other.instance_cache),
                                       locals(std::move(other.locals)) {
    other.Kill();
  }

  void Kill() {
    state = kUnreachable;
    control = nullptr;
    effect = nullptr;
    instance_cache = {};
    locals.Clear();
  }
  void SetNotMerged() {
    if (state == kMerged) state = kReached;
  }
};

class WasmGraphBuildingInterface {
 public:
  using ValidationTag = Decoder::NoValidationTag;
  using FullDecoder =
      WasmFullDecoder<ValidationTag, WasmGraphBuildingInterface>;
  using CheckForNull = compiler::CheckForNull;
  static constexpr bool kUsesPoppedArgs = true;

  struct Value : public ValueBase<ValidationTag> {
    TFNode* node = nullptr;

    template <typename... Args>
    explicit Value(Args&&... args) V8_NOEXCEPT
        : ValueBase(std::forward<Args>(args)...) {}
  };
  using ValueVector = base::SmallVector<Value, 8>;
  using NodeVector = base::SmallVector<TFNode*, 8>;

  struct TryInfo : public ZoneObject {
    SsaEnv* catch_env;
    TFNode* exception = nullptr;

    MOVE_ONLY_NO_DEFAULT_CONSTRUCTOR(TryInfo);

    explicit TryInfo(SsaEnv* c) : catch_env(c) {}
  };

  struct Control : public ControlBase<Value, ValidationTag> {
    SsaEnv* merge_env = nullptr;  // merge environment for the construct.
    SsaEnv* false_env = nullptr;  // false environment (only for if).
    SsaEnv* block_env = nullptr;  // environment that dies with this block.
    TryInfo* try_info = nullptr;  // information about try statements.
    int32_t previous_catch = -1;  // previous Control with a catch.
    bool loop_innermost = false;  // whether this loop can be innermost.
    BitVector* loop_assignments = nullptr;  // locals assigned in this loop.
    TFNode* loop_node = nullptr;            // loop header of this loop.

    template <typename... Args>
    explicit Control(Args&&... args) V8_NOEXCEPT
        : ControlBase(std::forward<Args>(args)...) {}
    Control(Control&& other) V8_NOEXCEPT
        : ControlBase(std::move(other)),
          merge_env(other.merge_env),
          false_env(other.false_env),
          block_env(other.block_env),
          try_info(other.try_info),
          previous_catch(other.previous_catch),
          loop_innermost(other.loop_innermost),
          loop_assignments(other.loop_assignments),
          loop_node(other.loop_node) {
      // The `control_` vector in WasmFullDecoder calls destructor of this when
      // growing capacity. Nullify these pointers to avoid destroying
      // environments before used.
      other.false_env = nullptr;
      other.block_env = nullptr;
      other.try_info = nullptr;
    }
    ~Control() {
      if (false_env) false_env->Kill();
      if (block_env) block_env->Kill();
      if (try_info) try_info->catch_env->Kill();
    }
    DISALLOW_IMPLICIT_CONSTRUCTORS(Control);
  };

  WasmGraphBuildingInterface(compiler::WasmGraphBuilder* builder,
                             int func_index, AssumptionsJournal* assumptions,
                             InlinedStatus inlined_status, Zone* zone)
      : locals_allocator_(zone),
        builder_(builder),
        func_index_(func_index),
        assumptions_(assumptions),
        inlined_status_(inlined_status) {}

  void StartFunction(FullDecoder* decoder) {
    // Get the branch hints map and type feedback for this function (if
    // available).
    if (decoder->module_) {
      auto branch_hints_it = decoder->module_->branch_hints.find(func_index_);
      if (branch_hints_it != decoder->module_->branch_hints.end()) {
        branch_hints_ = &branch_hints_it->second;
      }
      const TypeFeedbackStorage& feedbacks = decoder->module_->type_feedback;
      base::SharedMutexGuard<base::kShared> mutex_guard(&feedbacks.mutex);
      auto feedback = feedbacks.feedback_for_function.find(func_index_);
      if (feedback != feedbacks.feedback_for_function.end()) {
        // This creates a copy of the vector, which is cheaper than holding on
        // to the mutex throughout graph building.
        type_feedback_ = feedback->second.feedback_vector;
        // Preallocate space for storing call counts to save Zone memory.
        int total_calls = 0;
        for (size_t i = 0; i < type_feedback_.size(); i++) {
          total_calls += type_feedback_[i].num_cases();
        }
        builder_->ReserveCallCounts(static_cast<size_t>(total_calls));
        // We need to keep the feedback in the module to inline later. However,
        // this means we are stuck with it forever.
        // TODO(jkummerow): Reconsider our options here.
      }
    }
    // The first '+ 1' is needed by TF Start node, the second '+ 1' is for the
    // instance parameter.
    builder_->Start(static_cast<int>(decoder->sig_->parameter_count() + 1 + 1));
    uint32_t num_locals = decoder->num_locals();
    SsaEnv* ssa_env = decoder->zone()->New<SsaEnv>(
        &locals_allocator_, SsaEnv::kReached, effect(), control(), num_locals);
    SetEnv(ssa_env);

    // Initialize local variables. Parameters are shifted by 1 because of the
    // the instance parameter.
    uint32_t index = 0;
    for (; index < decoder->sig_->parameter_count(); ++index) {
      ssa_env->locals[index] = builder_->SetType(
          builder_->Param(index + 1), decoder->sig_->GetParam(index));
    }
    while (index < num_locals) {
      ValueType type = decoder->local_type(index);
      TFNode* node;
      if (!type.is_defaultable()) {
        DCHECK(type.is_reference());
        // TODO(jkummerow): Consider using "the hole" instead, to make any
        // illegal uses more obvious.
        node = builder_->SetType(builder_->RefNull(type), type);
      } else {
        node = builder_->SetType(builder_->DefaultValue(type), type);
      }
      while (index < num_locals && decoder->local_type(index) == type) {
        // Do a whole run of like-typed locals at a time.
        ssa_env->locals[index++] = node;
      }
    }

    size_t num_memories =
        decoder->module_ == nullptr ? 0 : decoder->module_->memories.size();
    if (num_memories == 1) {
      builder_->set_cached_memory_index(0);
    } else if (num_memories > 1) {
      int first_used_mem_index = FindFirstUsedMemoryIndex(
          base::VectorOf(decoder->start(), decoder->end() - decoder->start()),
          decoder->zone());
      if (first_used_mem_index >= 0) {
        builder_->set_cached_memory_index(first_used_mem_index);
      }
    }
    LoadInstanceCacheIntoSsa(ssa_env);

    if (v8_flags.trace_wasm && inlined_status_ == kRegularFunction) {
      builder_->TraceFunctionEntry(decoder->position());
    }
  }

  // Load the instance cache entries into the SSA Environment.
  void LoadInstanceCacheIntoSsa(SsaEnv* ssa_env) {
    builder_->InitInstanceCache(&ssa_env->instance_cache);
  }

  // Reload the instance cache entries into the SSA Environment, if memory can
  // actually grow.
  void ReloadInstanceCacheIntoSsa(SsaEnv* ssa_env, const WasmModule* module) {
    if (!builder_->has_cached_memory()) return;
    const WasmMemory* cached_memory =
        &module->memories[builder_->cached_memory_index()];
    if (cached_memory->initial_pages == cached_memory->maximum_pages) return;
    LoadInstanceCacheIntoSsa(ssa_env);
  }

  void StartFunctionBody(FullDecoder* decoder, Control* block) {}

  void FinishFunction(FullDecoder* decoder) {
    if (v8_flags.wasm_inlining) {
      DCHECK_EQ(feedback_instruction_index_, type_feedback_.size());
    }
    if (inlined_status_ == kRegularFunction) {
      builder_->PatchInStackCheckIfNeeded();
    }
  }

  void OnFirstError(FullDecoder*) {}

  void NextInstruction(FullDecoder*, WasmOpcode) {}

  void Block(FullDecoder* decoder, Control* block) {
    // The branch environment is the outer environment.
    block->merge_env = ssa_env_;
    SetEnv(Steal(decoder->zone(), ssa_env_));
    block->block_env = ssa_env_;
  }

  void Loop(FullDecoder* decoder, Control* block) {
    // This is the merge environment at the beginning of the loop.
    SsaEnv* merge_env = Steal(decoder->zone(), ssa_env_);
    block->merge_env = block->block_env = merge_env;
    SetEnv(merge_env);

    ssa_env_->state = SsaEnv::kMerged;

    TFNode* loop_node = builder_->Loop(control());

    builder_->SetControl(loop_node);
    decoder->control_at(0)->loop_node = loop_node;

    TFNode* effect_inputs[] = {effect(), control()};
    builder_->SetEffect(builder_->EffectPhi(1, effect_inputs));
    builder_->TerminateLoop(effect(), control());
    // Doing a preprocessing pass to analyze loop assignments seems to pay off
    // compared to reallocating Nodes when rearranging Phis in Goto.
    bool can_be_innermost = false;
    BitVector* assigned = WasmDecoder<ValidationTag>::AnalyzeLoopAssignment(
        decoder, decoder->pc(), decoder->num_locals(), decoder->zone(),
        &can_be_innermost);
    if (decoder->failed()) return;
    int instance_cache_index = decoder->num_locals();
    // If the cached memory is shared, the stack guard might reallocate the
    // backing store. We have to assume the instance cache will be updated.
    bool cached_mem_is_shared =
        builder_->has_cached_memory() &&
        decoder->module_->memories[builder_->cached_memory_index()].is_shared;
    if (cached_mem_is_shared) assigned->Add(instance_cache_index);
    DCHECK_NOT_NULL(assigned);
    decoder->control_at(0)->loop_assignments = assigned;

    if (emit_loop_exits()) {
      uint32_t nesting_depth = 0;
      for (uint32_t depth = 1; depth < decoder->control_depth(); depth++) {
        if (decoder->control_at(depth)->is_loop()) {
          nesting_depth++;
        }
      }
      loop_infos_.emplace_back(loop_node, nesting_depth, can_be_innermost);
      // Only innermost loops can be unrolled. We can avoid allocating
      // unnecessary nodes if this loop can not be innermost.
      decoder->control_at(0)->loop_innermost = can_be_innermost;
    }

    // Only introduce phis for variables assigned in this loop.
    for (int i = decoder->num_locals() - 1; i >= 0; i--) {
      if (!assigned->Contains(i)) continue;
      TFNode* inputs[] = {ssa_env_->locals[i], control()};
      ssa_env_->locals[i] =
          builder_->SetType(builder_->Phi(decoder->local_type(i), 1, inputs),
                            decoder->local_type(i));
    }
    // Introduce phis for instance cache pointers if necessary.
    if (assigned->Contains(instance_cache_index)) {
      builder_->PrepareInstanceCacheForLoop(&ssa_env_->instance_cache,
                                            control());
    }

    // Now we setup a new environment for the inside of the loop.
    // TODO(choongwoo): Clear locals of the following SsaEnv after use.
    SetEnv(Split(decoder->zone(), ssa_env_));
    builder_->StackCheck(
        cached_mem_is_shared ? &ssa_env_->instance_cache : nullptr,
        decoder->position());
    ssa_env_->SetNotMerged();

    // Wrap input merge into phis.
    for (uint32_t i = 0; i < block->start_merge.arity; ++i) {
      Value& val = block->start_merge[i];
      TFNode* inputs[] = {val.node, block->merge_env->control};
      SetAndTypeNode(&val, builder_->Phi(val.type, 1, inputs));
    }
  }

  void Try(FullDecoder* decoder, Control* block) {
    SsaEnv* outer_env = ssa_env_;
    SsaEnv* catch_env = Steal(decoder->zone(), outer_env);
    // Steal catch_env to make catch_env unreachable and clear locals.
    // The unreachable catch_env will create and copy locals in `Goto`.
    SsaEnv* try_env = Steal(decoder->zone(), catch_env);
    SetEnv(try_env);
    TryInfo* try_info = decoder->zone()->New<TryInfo>(catch_env);
    block->merge_env = outer_env;
    block->try_info = try_info;
    block->block_env = try_env;
  }

  void If(FullDecoder* decoder, const Value& cond, Control* if_block) {
    WasmBranchHint hint = WasmBranchHint::kNoHint;
    if (branch_hints_) {
      hint = branch_hints_->GetHintFor(decoder->pc_relative_offset());
    }
    auto [if_true, if_false] = hint == WasmBranchHint::kUnlikely
                                   ? builder_->BranchExpectFalse(cond.node)
                               : hint == WasmBranchHint::kLikely
                                   ? builder_->BranchExpectTrue(cond.node)
                                   : builder_->BranchNoHint(cond.node);
    SsaEnv* merge_env = ssa_env_;
    SsaEnv* false_env = Split(decoder->zone(), ssa_env_);
    false_env->control = if_false;
    SsaEnv* true_env = Steal(decoder->zone(), ssa_env_);
    true_env->control = if_true;
    if_block->merge_env = merge_env;
    if_block->false_env = false_env;
    if_block->block_env = true_env;
    SetEnv(true_env);
  }

  void FallThruTo(FullDecoder* decoder, Control* c) {
    DCHECK(!c->is_loop());
    MergeValuesInto(decoder, c, &c->end_merge);
  }

  void PopControl(FullDecoder* decoder, Control* block) {
    // A loop just continues with the end environment. There is no merge.
    // However, if loop unrolling is enabled, we must create a loop exit and
    // wrap the fallthru values on the stack.
    if (block->is_loop()) {
      if (emit_loop_exits() && block->reachable() && block->loop_innermost) {
        BuildLoopExits(decoder, block);
        WrapLocalsAtLoopExit(decoder, block);
        uint32_t arity = block->end_merge.arity;
        if (arity > 0) {
          Value* stack_base = decoder->stack_value(arity);
          for (uint32_t i = 0; i < arity; i++) {
            Value* val = stack_base + i;
            SetAndTypeNode(val,
                           builder_->LoopExitValue(
                               val->node, val->type.machine_representation()));
          }
        }
      }
      return;
    }
    // Any other block falls through to the parent block.
    if (block->reachable()) FallThruTo(decoder, block);
    if (block->is_onearmed_if()) {
      // Merge the else branch into the end merge.
      SetEnv(block->false_env);
      DCHECK_EQ(block->start_merge.arity, block->end_merge.arity);
      Value* values =
          block->start_merge.arity > 0 ? &block->start_merge[0] : nullptr;
      MergeValuesInto(decoder, block, &block->end_merge, values);
    }
    // Now continue with the merged environment.
    SetEnv(block->merge_env);
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
    SetAndTypeNode(result, builder_->Unop(opcode, value.node, value.type,
                                          decoder->position()));
  }

  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    TFNode* node =
        builder_->Binop(opcode, lhs.node, rhs.node, decoder->position());
    if (result) SetAndTypeNode(result, node);
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
    builder_->TraceInstruction(markid);
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    SetAndTypeNode(result, builder_->Int32Constant(value));
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    SetAndTypeNode(result, builder_->Int64Constant(value));
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    SetAndTypeNode(result, builder_->Float32Constant(value));
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    SetAndTypeNode(result, builder_->Float64Constant(value));
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    SetAndTypeNode(result, builder_->Simd128Constant(imm.value));
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value* result) {
    SetAndTypeNode(result, builder_->RefNull(type));
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    SetAndTypeNode(result, builder_->RefFunc(function_index));
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    TFNode* cast_node =
        builder_->AssertNotNull(arg.node, arg.type, decoder->position());
    SetAndTypeNode(result, cast_node);
  }

  void Drop(FullDecoder* decoder) {}

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    result->node = ssa_env_->locals[imm.index];
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    ssa_env_->locals[imm.index] = value.node;
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    result->node = value.node;
    ssa_env_->locals[imm.index] = value.node;
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    SetAndTypeNode(result, builder_->GlobalGet(imm.index));
  }

  void GlobalSet(FullDecoder* decoder, const Value& value,
                 const GlobalIndexImmediate& imm) {
    builder_->GlobalSet(imm.index, value.node);
  }

  void TableGet(FullDecoder* decoder, const Value& index, Value* result,
                const TableIndexImmediate& imm) {
    SetAndTypeNode(
        result, builder_->TableGet(imm.index, index.node, decoder->position()));
  }

  void TableSet(FullDecoder* decoder, const Value& index, const Value& value,
                const TableIndexImmediate& imm) {
    builder_->TableSet(imm.index, index.node, value.node, decoder->position());
  }

  void Trap(FullDecoder* decoder, TrapReason reason) {
    builder_->Trap(reason, decoder->position());
  }

  void AssertNullTypecheck(FullDecoder* decoder, const Value& obj,
                           Value* result) {
    builder_->TrapIfFalse(wasm::TrapReason::kTrapIllegalCast,
                          builder_->IsNull(obj.node, obj.type),
                          decoder->position());
    Forward(decoder, obj, result);
  }

  void AssertNotNullTypecheck(FullDecoder* decoder, const Value& obj,
                              Value* result) {
    SetAndTypeNode(
        result, builder_->AssertNotNull(obj.node, obj.type, decoder->position(),
                                        TrapReason::kTrapIllegalCast));
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {}

  void Select(FullDecoder* decoder, const Value& cond, const Value& fval,
              const Value& tval, Value* result) {
    SetAndTypeNode(result, builder_->Select(cond.node, tval.node, fval.node,
                                            result->type));
  }

  ValueVector CopyStackValues(FullDecoder* decoder, uint32_t count,
                              uint32_t drop_values) {
    Value* stack_base =
        count > 0 ? decoder->stack_value(count + drop_values) : nullptr;
    ValueVector stack_values(count);
    for (uint32_t i = 0; i < count; i++) {
      stack_values[i] = stack_base[i];
    }
    return stack_values;
  }

  void DoReturn(FullDecoder* decoder, uint32_t drop_values) {
    uint32_t ret_count = static_cast<uint32_t>(decoder->sig_->return_count());
    NodeVector values(ret_count);
    SsaEnv* internal_env = ssa_env_;
    SsaEnv* exit_env = nullptr;
    if (emit_loop_exits()) {
      exit_env = Split(decoder->zone(), ssa_env_);
      SetEnv(exit_env);
      auto stack_values = CopyStackValues(decoder, ret_count, drop_values);
      BuildNestedLoopExits(decoder, decoder->control_depth() - 1, false,
                           stack_values);
      GetNodes(values.begin(), base::VectorOf(stack_values));
    } else {
      Value* stack_base = ret_count == 0
                              ? nullptr
                              : decoder->stack_value(ret_count + drop_values);
      GetNodes(values.begin(), stack_base, ret_count);
    }
    if (v8_flags.trace_wasm && inlined_status_ == kRegularFunction) {
      builder_->TraceFunctionExit(base::VectorOf(values), decoder->position());
    }
    builder_->Return(base::VectorOf(values));
    if (exit_env) exit_env->Kill();
    SetEnv(internal_env);
  }

  void BrOrRet(FullDecoder* decoder, uint32_t depth, uint32_t drop_values = 0) {
    if (depth == decoder->control_depth() - 1) {
      DoReturn(decoder, drop_values);
    } else {
      Control* target = decoder->control_at(depth);
      if (emit_loop_exits()) {
        ScopedSsaEnv exit_env(this, Split(decoder->zone(), ssa_env_));
        uint32_t value_count = target->br_merge()->arity;
        auto stack_values = CopyStackValues(decoder, value_count, drop_values);
        BuildNestedLoopExits(decoder, depth, true, stack_values);
        MergeValuesInto(decoder, target, target->br_merge(),
                        stack_values.data());
      } else {
        MergeValuesInto(decoder, target, target->br_merge(), drop_values);
      }
    }
  }

  void BrIf(FullDecoder* decoder, const Value& cond, uint32_t depth) {
    SsaEnv* fenv = ssa_env_;
    SsaEnv* tenv = Split(decoder->zone(), fenv);
    fenv->SetNotMerged();
    WasmBranchHint hint = WasmBranchHint::kNoHint;
    if (branch_hints_) {
      hint = branch_hints_->GetHintFor(decoder->pc_relative_offset());
    }
    switch (hint) {
      case WasmBranchHint::kNoHint:
        std::tie(tenv->control, fenv->control) =
            builder_->BranchNoHint(cond.node);
        break;
      case WasmBranchHint::kUnlikely:
        std::tie(tenv->control, fenv->control) =
            builder_->BranchExpectFalse(cond.node);
        break;
      case WasmBranchHint::kLikely:
        std::tie(tenv->control, fenv->control) =
            builder_->BranchExpectTrue(cond.node);
        break;
    }
    builder_->SetControl(fenv->control);
    ScopedSsaEnv scoped_env(this, tenv);
    BrOrRet(decoder, depth);
  }

  void BrTable(FullDecoder* decoder, const BranchTableImmediate& imm,
               const Value& key) {
    if (imm.table_count == 0) {
      // Only a default target. Do the equivalent of br.
      uint32_t target = BranchTableIterator<ValidationTag>(decoder, imm).next();
      BrOrRet(decoder, target);
      return;
    }

    // Build branches to the various blocks based on the table.
    TFNode* sw = builder_->Switch(imm.table_count + 1, key.node);

    BranchTableIterator<ValidationTag> iterator(decoder, imm);
    while (iterator.has_next()) {
      uint32_t i = iterator.cur_index();
      uint32_t target = iterator.next();
      ScopedSsaEnv env(this, Split(decoder->zone(), ssa_env_));
      builder_->SetControl(i == imm.table_count ? builder_->IfDefault(sw)
                                                : builder_->IfValue(i, sw));
      BrOrRet(decoder, target);
    }
    DCHECK(decoder->ok());
  }

  void Else(FullDecoder* decoder, Control* if_block) {
    if (if_block->reachable()) {
      // Merge the if branch into the end merge.
      MergeValuesInto(decoder, if_block, &if_block->end_merge);
    }
    SetEnv(if_block->false_env);
  }

  void LoadMem(FullDecoder* decoder, LoadType type,
               const MemoryAccessImmediate& imm, const Value& index,
               Value* result) {
    SetAndTypeNode(result,
                   builder_->LoadMem(imm.memory, type.value_type(),
                                     type.mem_type(), index.node, imm.offset,
                                     imm.alignment, decoder->position()));
  }

  void LoadTransform(FullDecoder* decoder, LoadType type,
                     LoadTransformationKind transform,
                     const MemoryAccessImmediate& imm, const Value& index,
                     Value* result) {
    SetAndTypeNode(result, builder_->LoadTransform(
                               imm.memory, type.value_type(), type.mem_type(),
                               transform, index.node, imm.offset, imm.alignment,
                               decoder->position()));
  }

  void LoadLane(FullDecoder* decoder, LoadType type, const Value& value,
                const Value& index, const MemoryAccessImmediate& imm,
                const uint8_t laneidx, Value* result) {
    SetAndTypeNode(result, builder_->LoadLane(
                               imm.memory, type.value_type(), type.mem_type(),
                               value.node, index.node, imm.offset,
                               imm.alignment, laneidx, decoder->position()));
  }

  void StoreMem(FullDecoder* decoder, StoreType type,
                const MemoryAccessImmediate& imm, const Value& index,
                const Value& value) {
    builder_->StoreMem(imm.memory, type.mem_rep(), index.node, imm.offset,
                       imm.alignment, value.node, decoder->position(),
                       type.value_type());
  }

  void StoreLane(FullDecoder* decoder, StoreType type,
                 const MemoryAccessImmediate& imm, const Value& index,
                 const Value& value, const uint8_t laneidx) {
    builder_->StoreLane(imm.memory, type.mem_rep(), index.node, imm.offset,
                        imm.alignment, value.node, laneidx, decoder->position(),
                        type.value_type());
  }

  void CurrentMemoryPages(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                          Value* result) {
    SetAndTypeNode(result, builder_->CurrentMemoryPages(imm.memory));
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result) {
    SetAndTypeNode(result, builder_->MemoryGrow(imm.memory, value.node));
    // Always reload the instance cache after growing memory.
    ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);
  }

  TFNode* ExternRefToString(FullDecoder* decoder, const Value value,
                            bool null_succeeds = false) {
    wasm::ValueType target_type =
        null_succeeds ? kWasmRefNullExternString : kWasmRefExternString;
    WasmTypeCheckConfig config{value.type, target_type};
    TFNode* string =
        builder_->RefCastAbstract(value.node, config, decoder->position());
    TFNode* rename = builder_->TypeGuard(string, target_type);
    return builder_->SetType(rename, target_type);
  }

  bool HandleWellKnownImport(FullDecoder* decoder, uint32_t index,
                             const Value args[], Value returns[]) {
    if (!decoder->module_) return false;  // Only needed for tests.
    if (index >= decoder->module_->num_imported_functions) return false;
    const WellKnownImportsList& well_known_imports =
        decoder->module_->type_feedback.well_known_imports;
    using WKI = WellKnownImport;
    WKI import = well_known_imports.get(index);
    TFNode* result = nullptr;
    switch (import) {
      case WKI::kUninstantiated:
      case WKI::kGeneric:
      case WKI::kLinkError:
        return false;

      // JS String Builtins proposal.
      case WKI::kStringCast:
        result = ExternRefToString(decoder, args[0]);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringTest: {
        WasmTypeCheckConfig config{args[0].type, kWasmRefExternString};
        result = builder_->RefTestAbstract(args[0].node, config);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCharCodeAt: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        TFNode* view = builder_->StringAsWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(view, kWasmRefExternString);
        result = builder_->StringViewWtf16GetCodeUnit(
            view, compiler::kWithoutNullCheck, args[1].node,
            decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCodePointAt: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        TFNode* view = builder_->StringAsWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(view, kWasmRefExternString);
        result = builder_->StringCodePointAt(view, compiler::kWithoutNullCheck,
                                             args[1].node, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringCompare: {
        TFNode* a_string = ExternRefToString(decoder, args[0]);
        TFNode* b_string = ExternRefToString(decoder, args[1]);
        result = builder_->StringCompare(a_string, compiler::kWithoutNullCheck,
                                         b_string, compiler::kWithoutNullCheck,
                                         decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringConcat: {
        TFNode* head_string = ExternRefToString(decoder, args[0]);
        TFNode* tail_string = ExternRefToString(decoder, args[1]);
        result = builder_->StringConcat(
            head_string, compiler::kWithoutNullCheck, tail_string,
            compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringEquals: {
        // Using nullable type guards here because this instruction needs to
        // handle {null} without trapping.
        static constexpr bool kNullSucceeds = true;
        TFNode* a_string = ExternRefToString(decoder, args[0], kNullSucceeds);
        TFNode* b_string = ExternRefToString(decoder, args[1], kNullSucceeds);
        result = builder_->StringEqual(a_string, args[0].type, b_string,
                                       args[1].type, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringFromCharCode:
        result = builder_->StringFromCharCode(args[0].node);
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromCodePoint:
        result = builder_->StringFromCodePoint(args[0].node);
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromWtf16Array:
        result = builder_->StringNewWtf16Array(
            args[0].node, NullCheckFor(args[0].type), args[1].node,
            args[2].node, decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringFromUtf8Array:
        result = builder_->StringNewWtf8Array(
            unibrow::Utf8Variant::kLossyUtf8, args[0].node,
            NullCheckFor(args[0].type), args[1].node, args[2].node,
            decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      case WKI::kStringIntoUtf8Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringEncodeWtf8Array(
            unibrow::Utf8Variant::kLossyUtf8, string,
            compiler::kWithoutNullCheck, args[1].node,
            NullCheckFor(args[1].type), args[2].node, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToUtf8Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringToUtf8Array(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(result, returns[0].type);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringLength: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringMeasureWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringMeasureUtf8: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringMeasureWtf8(string, compiler::kWithNullCheck,
                                             decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringSubstring: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        TFNode* view = builder_->StringAsWtf16(
            string, compiler::kWithoutNullCheck, decoder->position());
        builder_->SetType(view, kWasmRefExternString);
        result = builder_->StringViewWtf16Slice(
            view, compiler::kWithoutNullCheck, args[1].node, args[2].node,
            decoder->position());
        builder_->SetType(result, kWasmRefExternString);
        decoder->detected_->add_imported_strings();
        break;
      }
      case WKI::kStringToWtf16Array: {
        TFNode* string = ExternRefToString(decoder, args[0]);
        result = builder_->StringEncodeWtf16Array(
            string, compiler::kWithoutNullCheck, args[1].node,
            NullCheckFor(args[1].type), args[2].node, decoder->position());
        decoder->detected_->add_imported_strings();
        break;
      }

      // Other string-related imports.
      case WKI::kDoubleToString:
        result = builder_->WellKnown_DoubleToString(args[0].node);
        break;
      case WKI::kIntToString:
        result = builder_->WellKnown_IntToString(args[0].node, args[1].node);
        break;
      case WKI::kParseFloat:
        result = builder_->WellKnown_ParseFloat(args[0].node,
                                                NullCheckFor(args[0].type));
        decoder->detected_->add_stringref();
        break;
      case WKI::kStringIndexOf:
        result = builder_->WellKnown_StringIndexOf(
            args[0].node, args[1].node, args[2].node,
            NullCheckFor(args[0].type), NullCheckFor(args[1].type));
        decoder->detected_->add_stringref();
        break;
      case WKI::kStringToLocaleLowerCaseStringref:
        // Temporarily ignored because of bugs (v8:13977, v8:13985).
        // TODO(jkummerow): Fix and re-enable.
        return false;
        // result = builder_->WellKnown_StringToLocaleLowerCaseStringref(
        //     args[0].node, args[1].node, NullCheckFor(args[0].type));
        // decoder->detected_->add_stringref();
        // break;
      case WKI::kStringToLowerCaseStringref:
        result = builder_->WellKnown_StringToLowerCaseStringref(
            args[0].node, NullCheckFor(args[0].type));
        decoder->detected_->add_stringref();
        break;
        // Not implementing for Turbofan.
      case WKI::kStringIndexOfImported:
      case WKI::kStringToLowerCaseImported:
      case WKI::kDataViewGetBigInt64:
      case WKI::kDataViewGetBigUint64:
      case WKI::kDataViewGetFloat32:
      case WKI::kDataViewGetFloat64:
      case WKI::kDataViewGetInt8:
      case WKI::kDataViewGetInt16:
      case WKI::kDataViewGetInt32:
      case WKI::kDataViewGetUint8:
      case WKI::kDataViewGetUint16:
      case WKI::kDataViewGetUint32:
      case WKI::kDataViewSetBigInt64:
      case WKI::kDataViewSetBigUint64:
      case WKI::kDataViewSetFloat32:
      case WKI::kDataViewSetFloat64:
      case WKI::kDataViewSetInt8:
      case WKI::kDataViewSetInt16:
      case WKI::kDataViewSetInt32:
      case WKI::kDataViewSetUint8:
      case WKI::kDataViewSetUint16:
      case WKI::kDataViewSetUint32:
      case WKI::kDataViewByteLength:
      case WKI::kFastAPICall:
        return false;
    }
    if (v8_flags.trace_wasm_inlining) {
      PrintF("[function %d: call to %d is well-known %s]\n", func_index_, index,
             WellKnownImportName(import));
    }
    assumptions_->RecordAssumption(index, import);
    SetAndTypeNode(&returns[0], result);
    // The decoder assumes that any call might throw, so if we are in a try
    // block, it marks the associated catch block as reachable, and will
    // later ask the graph builder to build the catch block's graph.
    // However, we just replaced the call with a sequence that doesn't throw,
    // which might make the catch block unreachable as far as the graph builder
    // is concerned, which would violate assumptions when trying to build a
    // graph for it. So we insert a fake branch to the catch block to make it
    // reachable. Later phases will optimize this out.
    if (decoder->current_catch() != -1) {
      TryInfo* try_info = current_try_info(decoder);
      if (try_info->catch_env->state == SsaEnv::kUnreachable) {
        auto [true_cont, false_cont] =
            builder_->BranchExpectTrue(builder_->Int32Constant(1));
        SsaEnv* success_env = Steal(decoder->zone(), ssa_env_);
        success_env->control = true_cont;

        SsaEnv* exception_env = Split(decoder->zone(), success_env);
        exception_env->control = false_cont;

        ScopedSsaEnv scoped_env(this, exception_env, success_env);

        if (emit_loop_exits()) {
          ValueVector stack_values;
          uint32_t depth = decoder->control_depth_of_current_catch();
          BuildNestedLoopExits(decoder, depth, true, stack_values);
        }
        Goto(decoder, try_info->catch_env);
        try_info->exception = builder_->Int32Constant(1);
      }
    }
    return true;
  }

  void CallDirect(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[], Value returns[]) {
    int maybe_call_count = -1;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      const CallSiteFeedback& feedback = next_call_feedback();
      DCHECK_EQ(feedback.num_cases(), 1);
      maybe_call_count = feedback.call_count(0);
    }
    // This must happen after the {next_call_feedback()} call.
    if (HandleWellKnownImport(decoder, imm.index, args, returns)) return;

    DoCall(decoder, CallInfo::CallDirect(imm.index, maybe_call_count), imm.sig,
           args, returns);
  }

  void ReturnCall(FullDecoder* decoder, const CallFunctionImmediate& imm,
                  const Value args[]) {
    int maybe_call_count = -1;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      const CallSiteFeedback& feedback = next_call_feedback();
      DCHECK_EQ(feedback.num_cases(), 1);
      maybe_call_count = feedback.call_count(0);
    }
    DoReturnCall(decoder, CallInfo::CallDirect(imm.index, maybe_call_count),
                 imm.sig, args);
  }

  void CallIndirect(FullDecoder* decoder, const Value& index,
                    const CallIndirectImmediate& imm, const Value args[],
                    Value returns[]) {
    DoCall(
        decoder,
        CallInfo::CallIndirect(index, imm.table_imm.index, imm.sig_imm.index),
        imm.sig, args, returns);
  }

  void ReturnCallIndirect(FullDecoder* decoder, const Value& index,
                          const CallIndirectImmediate& imm,
                          const Value args[]) {
    DoReturnCall(
        decoder,
        CallInfo::CallIndirect(index, imm.table_imm.index, imm.sig_imm.index),
        imm.sig, args);
  }

  void CallRef(FullDecoder* decoder, const Value& func_ref,
               const FunctionSig* sig, const Value args[], Value returns[]) {
    const CallSiteFeedback* feedback = nullptr;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      feedback = &next_call_feedback();
    }
    if (feedback == nullptr || feedback->num_cases() == 0) {
      DoCall(decoder, CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
             sig, args, returns);
      return;
    }

    // Check for equality against a function at a specific index, and if
    // successful, just emit a direct call.
    int num_cases = feedback->num_cases();
    std::vector<TFNode*> control_args;
    std::vector<TFNode*> effect_args;
    std::vector<Value*> returns_values;
    control_args.reserve(num_cases + 1);
    effect_args.reserve(num_cases + 2);
    returns_values.reserve(num_cases);
    for (int i = 0; i < num_cases; i++) {
      const uint32_t expected_function_index = feedback->function_index(i);

      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: graph support for inlining #%d]\n",
               func_index_, feedback_instruction_index_ - 1,
               expected_function_index);
      }

      TFNode* success_control;
      TFNode* failure_control;
      builder_->CompareToFuncRefAtIndex(func_ref.node, expected_function_index,
                                        &success_control, &failure_control,
                                        i == num_cases - 1);
      TFNode* initial_effect = effect();

      builder_->SetControl(success_control);
      ssa_env_->control = success_control;
      Value* returns_direct =
          decoder->zone()->AllocateArray<Value>(sig->return_count());
      for (size_t i = 0; i < sig->return_count(); i++) {
        returns_direct[i].type = returns[i].type;
      }
      DoCall(decoder,
             CallInfo::CallDirect(expected_function_index,
                                  feedback->call_count(i)),
             sig, args, returns_direct);
      control_args.push_back(control());
      effect_args.push_back(effect());
      returns_values.push_back(returns_direct);

      builder_->SetEffectControl(initial_effect, failure_control);
      ssa_env_->effect = initial_effect;
      ssa_env_->control = failure_control;
    }
    Value* returns_ref =
        decoder->zone()->AllocateArray<Value>(sig->return_count());
    for (size_t i = 0; i < sig->return_count(); i++) {
      returns_ref[i].type = returns[i].type;
    }
    DoCall(decoder, CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
           sig, args, returns_ref);

    control_args.push_back(control());
    TFNode* control = builder_->Merge(num_cases + 1, control_args.data());

    effect_args.push_back(effect());
    effect_args.push_back(control);
    TFNode* effect = builder_->EffectPhi(num_cases + 1, effect_args.data());

    ssa_env_->control = control;
    ssa_env_->effect = effect;
    builder_->SetEffectControl(effect, control);

    // Each of the {DoCall} helpers above has created a reload of the instance
    // cache nodes. Rather than merging all of them into a Phi, just
    // let them get DCE'ed and perform a single reload after the merge.
    ReloadInstanceCacheIntoSsa(ssa_env_, decoder->module_);

    for (uint32_t i = 0; i < sig->return_count(); i++) {
      std::vector<TFNode*> phi_args;
      phi_args.reserve(num_cases + 2);
      for (int j = 0; j < num_cases; j++) {
        phi_args.push_back(returns_values[j][i].node);
      }
      phi_args.push_back(returns_ref[i].node);
      phi_args.push_back(control);
      SetAndTypeNode(
          &returns[i],
          builder_->Phi(sig->GetReturn(i), num_cases + 1, phi_args.data()));
    }
  }

  void ReturnCallRef(FullDecoder* decoder, const Value& func_ref,
                     const FunctionSig* sig, const Value args[]) {
    const CallSiteFeedback* feedback = nullptr;
    if (v8_flags.wasm_inlining && !type_feedback_.empty()) {
      feedback = &next_call_feedback();
    }
    if (feedback == nullptr || feedback->num_cases() == 0) {
      DoReturnCall(decoder,
                   CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)),
                   sig, args);
      return;
    }

    // Check for equality against a function at a specific index, and if
    // successful, just emit a direct call.
    int num_cases = feedback->num_cases();
    for (int i = 0; i < num_cases; i++) {
      const uint32_t expected_function_index = feedback->function_index(i);

      if (v8_flags.trace_wasm_inlining) {
        PrintF("[function %d: call #%d: graph support for inlining #%d]\n",
               func_index_, feedback_instruction_index_ - 1,
               expected_function_index);
      }

      TFNode* success_control;
      TFNode* failure_control;
      builder_->CompareToFuncRefAtIndex(func_ref.node, expected_function_index,
                                        &success_control, &failure_control,
                                        i == num_cases - 1);
      TFNode* initial_effect = effect();

      builder_->SetControl(success_control);
      ssa_env_->control = success_control;
      DoReturnCall(decoder,
                   CallInfo::CallDirect(expected_function_index,
                                        feedback->call_count(i)),
                   sig, args);

      builder_->SetEffectControl(initial_effect, failure_control);
      ssa_env_->effect = initial_effect;
      ssa_env_->control = failure_control;
    }

    DoReturnCall(decoder,
                 CallInfo::CallRef(func_ref, NullCheckFor(func_ref.type)), sig,
                 args);
  }

  void BrOnNull(FullDecoder* decoder, const Value& ref_object, uint32_t depth,
                bool pass_null_along_branch, Value* result_on_fallthrough) {
    SsaEnv* false_env = ssa_env_;
    SsaEnv* true_env = Split(decoder->zone(), false_env);
    false_env->SetNotMerged();
    std::tie(true_env->control, false_env->control) =
        builder_->BrOnNull(ref_object.node, ref_object.type);
    builder_->SetControl(false_env->control);
    {
      ScopedSsaEnv scoped_env(this, true_env);
      int drop_values = pass_null_along_branch ? 0 : 1;
      BrOrRet(decoder, depth, drop_values);
    }
    SetAndTypeNode(
        result_on_fallthrough,
        builder_->TypeGuard(ref_object.node, result_on_fallthrough->type));
  }

  void BrOnNonNull(FullDecoder* decoder, const Value& ref_object, Value* result,
                   uint32_t depth, bool /* drop_null_on_fallthrough */) {
    SsaEnv* false_env = ssa_env_;
    SsaEnv* true_env = Split(decoder->zone(), false_env);
    false_env->SetNotMerged();
    std::tie(false_env->control, true_env->control) =
        builder_->BrOnNull(ref_object.node, ref_object.type);
    builder_->SetControl(false_env->control);
    ScopedSsaEnv scoped_env(this, true_env);
    // Make sure the TypeGuard has the right Control dependency.
    SetAndTypeNode(result, builder_->TypeGuard(ref_object.node, result->type));
    BrOrRet(decoder, depth);
  }

  void SimdOp(FullDecoder* decoder, WasmOpcode opcode, const Value* args,
              Value* result) {
    size_t num_inputs = WasmOpcodes::Signature(opcode)->parameter_count();
    NodeVector inputs(num_inputs);
    GetNodes(inputs.begin(), args, num_inputs);
    TFNode* node = builder_->SimdOp(opcode, inputs.begin());
    if (result) SetAndTypeNode(result, node);
  }

  void SimdLaneOp(FullDecoder* decoder, WasmOpcode opcode,
                  const SimdLaneImmediate& imm,
                  base::Vector<const Value> inputs, Value* result) {
    NodeVector nodes(inputs.size());
    GetNodes(nodes.begin(), inputs);
    SetAndTypeNode(result,
                   builder_->SimdLaneOp(opcode, imm.lane, nodes.begin()));
  }

  void Simd8x16ShuffleOp(FullDecoder* decoder, const Simd128Immediate& imm,
                         const Value& input0, const Value& input1,
                         Value* result) {
    TFNode* input_nodes[] = {input0.node, input1.node};
    SetAndTypeNode(result, builder_->Simd8x16ShuffleOp(imm.value, input_nodes));
  }

  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value arg_values[]) {
    int count = static_cast<int>(imm.tag->sig->parameter_count());
    NodeVector args(count);
    GetNodes(args.data(), base::VectorOf(arg_values, count));
    CheckForException(decoder,
                      builder_->Throw(imm.index, imm.tag, base::VectorOf(args),
                                      decoder->position()),
                      false);
    builder_->TerminateThrow(effect(), control());
  }

  void Rethrow(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    TFNode* exception = block->try_info->exception;
    DCHECK_NOT_NULL(exception);
    CheckForException(decoder, builder_->Rethrow(exception), false);
    builder_->TerminateThrow(effect(), control());
  }

  void CatchAndUnpackWasmException(FullDecoder* decoder, Control* block,
                                   TFNode* exception, const WasmTag* tag,
                                   TFNode* caught_tag, TFNode* exception_tag,
                                   base::Vector<Value> values) {
    TFNode* compare = builder_->ExceptionTagEqual(caught_tag, exception_tag);
    auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
    // If the tags don't match we continue with the next tag by setting the
    // false environment as the new {TryInfo::catch_env} here.
    block->try_info->catch_env = Split(decoder->zone(), ssa_env_);
    block->try_info->catch_env->control = if_no_catch;
    block->block_env = Steal(decoder->zone(), ssa_env_);
    block->block_env->control = if_catch;
    SetEnv(block->block_env);
    NodeVector caught_values(values.size());
    base::Vector<TFNode*> caught_vector = base::VectorOf(caught_values);
    builder_->GetExceptionValues(exception, tag, caught_vector);
    for (size_t i = 0, e = values.size(); i < e; ++i) {
      SetAndTypeNode(&values[i], caught_values[i]);
    }
  }

  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    DCHECK(block->is_try_catch());
    TFNode* exception = block->try_info->exception;
    SetEnv(block->try_info->catch_env);

    TFNode* caught_tag = builder_->GetExceptionTag(exception);
    TFNode* expected_tag = builder_->LoadTagFromTable(imm.index);

    if (imm.tag->sig->parameter_count() == 1 &&
        imm.tag->sig->GetParam(0).is_reference_to(HeapType::kExtern)) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref or (ref extern), otherwise
      // we know statically that it cannot be the JSTag.

      TFNode* is_js_exn = builder_->IsExceptionTagUndefined(caught_tag);
      auto [exn_is_js, exn_is_wasm] = builder_->BranchExpectFalse(is_js_exn);
      SsaEnv* exn_is_js_env = Split(decoder->zone(), ssa_env_);
      exn_is_js_env->control = exn_is_js;
      SsaEnv* exn_is_wasm_env = Steal(decoder->zone(), ssa_env_);
      exn_is_wasm_env->control = exn_is_wasm;

      // Case 1: A wasm exception.
      SetEnv(exn_is_wasm_env);
      CatchAndUnpackWasmException(decoder, block, exception, imm.tag,
                                  caught_tag, expected_tag, values);

      // Case 2: A JS exception.
      SetEnv(exn_is_js_env);
      TFNode* js_tag = builder_->LoadJSTag();
      TFNode* compare = builder_->ExceptionTagEqual(expected_tag, js_tag);
      auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
      // Merge the wasm no-catch and JS no-catch paths.
      SsaEnv* if_no_catch_env = Split(decoder->zone(), ssa_env_);
      if_no_catch_env->control = if_no_catch;
      SetEnv(if_no_catch_env);
      Goto(decoder, block->try_info->catch_env);
      // Merge the wasm catch and JS catch paths.
      SsaEnv* if_catch_env = Steal(decoder->zone(), ssa_env_);
      if_catch_env->control = if_catch;
      SetEnv(if_catch_env);
      Goto(decoder, block->block_env);

      // The final env is a merge of case 1 and 2. The unpacked value is a Phi
      // of the unpacked value (case 1) and the exception itself (case 2).
      SetEnv(block->block_env);
      TFNode* phi_inputs[] = {values[0].node, exception,
                              block->block_env->control};
      TFNode* ref = builder_->Phi(wasm::kWasmExternRef, 2, phi_inputs);
      SetAndTypeNode(&values[0], ref);
    } else {
      CatchAndUnpackWasmException(decoder, block, exception, imm.tag,
                                  caught_tag, expected_tag, values);
    }
  }

  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    DCHECK_EQ(decoder->control_at(0), block);
    DCHECK(block->is_incomplete_try());

    if (block->try_info->exception) {
      // Merge the current env into the target handler's env.
      SetEnv(block->try_info->catch_env);
      if (depth == decoder->control_depth() - 1) {
        if (inlined_status_ == kInlinedHandledCall) {
          if (emit_loop_exits()) {
            ValueVector stack_values;
            BuildNestedLoopExits(decoder, depth, false, stack_values,
                                 &block->try_info->exception);
          }
          // We are inlining this function and the inlined Call has a handler.
          // Add the delegated exception to {dangling_exceptions_}.
          dangling_exceptions_.Add(block->try_info->exception, effect(),
                                   control());
          return;
        }
        // We just throw to the caller here, so no need to generate IfSuccess
        // and IfFailure nodes.
        builder_->Rethrow(block->try_info->exception);
        builder_->TerminateThrow(effect(), control());
        return;
      }
      DCHECK(decoder->control_at(depth)->is_try());
      TryInfo* target_try = decoder->control_at(depth)->try_info;
      if (emit_loop_exits()) {
        ValueVector stack_values;
        BuildNestedLoopExits(decoder, depth, true, stack_values,
                             &block->try_info->exception);
      }
      Goto(decoder, target_try->catch_env);

      // Create or merge the exception.
      if (target_try->catch_env->state == SsaEnv::kReached) {
        target_try->exception = block->try_info->exception;
      } else {
        DCHECK_EQ(target_try->catch_env->state, SsaEnv::kMerged);
        target_try->exception = builder_->CreateOrMergeIntoPhi(
            MachineRepresentation::kTagged, target_try->catch_env->control,
            target_try->exception, block->try_info->exception);
      }
    }
  }

  void CatchAll(FullDecoder* decoder, Control* block) {
    DCHECK(block->is_try_catchall() || block->is_try_catch());
    DCHECK_EQ(decoder->control_at(0), block);
    SetEnv(block->try_info->catch_env);
  }

  void TryTable(FullDecoder* decoder, Control* block) { Try(decoder, block); }

  void CatchCase(FullDecoder* decoder, Control* block,
                 const CatchCase& catch_case, base::Vector<Value> values) {
    DCHECK(block->is_try_table());
    TFNode* exception = block->try_info->exception;
    SetEnv(block->try_info->catch_env);

    if (catch_case.kind == kCatchAll || catch_case.kind == kCatchAllRef) {
      if (catch_case.kind == kCatchAllRef) {
        DCHECK_EQ(values[0].type, ValueType::Ref(HeapType::kExn));
        values[0].node = block->try_info->exception;
      }
      BrOrRet(decoder, catch_case.br_imm.depth);
      return;
    }

    TFNode* caught_tag = builder_->GetExceptionTag(exception);
    TFNode* expected_tag =
        builder_->LoadTagFromTable(catch_case.maybe_tag.tag_imm.index);

    base::Vector<Value> values_without_exnref =
        catch_case.kind == kCatch ? values
                                  : values.SubVector(0, values.size() - 1);

    if (catch_case.maybe_tag.tag_imm.tag->sig->parameter_count() == 1 &&
        catch_case.maybe_tag.tag_imm.tag->sig->GetParam(0) == kWasmExternRef) {
      // Check for the special case where the tag is WebAssembly.JSTag and the
      // exception is not a WebAssembly.Exception. In this case the exception is
      // caught and pushed on the operand stack.
      // Only perform this check if the tag signature is the same as
      // the JSTag signature, i.e. a single externref, otherwise
      // we know statically that it cannot be the JSTag.

      TFNode* is_js_exn = builder_->IsExceptionTagUndefined(caught_tag);
      auto [exn_is_js, exn_is_wasm] = builder_->BranchExpectFalse(is_js_exn);
      SsaEnv* exn_is_js_env = Split(decoder->zone(), ssa_env_);
      exn_is_js_env->control = exn_is_js;
      SsaEnv* exn_is_wasm_env = Steal(decoder->zone(), ssa_env_);
      exn_is_wasm_env->control = exn_is_wasm;

      // Case 1: A wasm exception.
      SetEnv(exn_is_wasm_env);
      CatchAndUnpackWasmException(decoder, block, exception,
                                  catch_case.maybe_tag.tag_imm.tag, caught_tag,
                                  expected_tag, values_without_exnref);

      // Case 2: A JS exception.
      SetEnv(exn_is_js_env);
      TFNode* js_tag = builder_->LoadJSTag();
      TFNode* compare = builder_->ExceptionTagEqual(expected_tag, js_tag);
      auto [if_catch, if_no_catch] = builder_->BranchNoHint(compare);
      // Merge the wasm no-catch and JS no-catch paths.
      SsaEnv* if_no_catch_env = Split(decoder->zone(), ssa_env_);
      if_no_catch_env->control = if_no_catch;
      SetEnv(if_no_catch_env);
      Goto(decoder, block->try_info->catch_env);
      // Merge the wasm catch and JS catch paths.
      SsaEnv* if_catch_env = Steal(decoder->zone(), ssa_env_);
      if_catch_env->control = if_catch;
      SetEnv(if_catch_env);
      Goto(decoder, block->block_env);

      // The final env is a merge of case 1 and 2. The unpacked value is a Phi
      // of the unpacked value (case 1) and the exception itself (case 2).
      SetEnv(block->block_env);
      TFNode* phi_inputs[] = {values[0].node, exception,
                              block->block_env->control};
      TFNode* ref = builder_->Phi(wasm::kWasmExternRef, 2, phi_inputs);
      SetAndTypeNode(&values[0], ref);
    } else {
      CatchAndUnpackWasmException(decoder, block, exception,
                                  catch_case.maybe_tag.tag_imm.tag, caught_tag,
                                  expected_tag, values_without_exnref);
    }

    if (catch_case.kind == kCatchRef) {
      DCHECK_EQ(values.last().type, ValueType::Ref(HeapType::kExn));
      values.last().node = block->try_info->exception;
    }
    BrOrRet(decoder, catch_case.br_imm.depth);
    bool is_last = &catch_case == &block->catch_cases.last();
    if (is_last && !decoder->HasCatchAll(block)) {
      SetEnv(block->try_info->catch_env);
      ThrowRef(decoder, block->try_info->exception);
    }
  }

  void ThrowRef(FullDecoder* decoder, Value* value) {
    ThrowRef(decoder, value->node);
  }

  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    NodeVector inputs(argc);
    GetNodes(inputs.begin(), args, argc);
    TFNode* node =
        builder_->AtomicOp(imm.memory, opcode, inputs.begin(), imm.alignment,
                           imm.offset, decoder->position());
    if (result) SetAndTypeNode(result, node);
  }

  void AtomicFence(FullDecoder* decoder) { builder_->AtomicFence(); }

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    builder_->MemoryInit(imm.memory.memory, imm.data_segment.index, dst.node,
                         src.node, size.node, decoder->position());
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    builder_->DataDrop(imm.index, decoder->position());
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    builder_->MemoryCopy(imm.memory_dst.memory, imm.memory_src.memory, dst.node,
                         src.node, size.node, decoder->position());
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& dst, const Value& value, const Value& size) {
    builder_->MemoryFill(imm.memory, dst.node, value.node, size.node,
                         decoder->position());
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value& dst, const Value& src, const Value& size) {
    builder_->TableInit(imm.table.index, imm.element_segment.index, dst.node,
                        src.node, size.node, decoder->position());
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    builder_->ElemDrop(imm.index, decoder->position());
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value& dst, const Value& src, const Value& size) {
    builder_->TableCopy(imm.table_dst.index, imm.table_src.index, dst.node,
                        src.node, size.node, decoder->position());
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& value, const Value& delta, Value* result) {
    SetAndTypeNode(result,
                   builder_->TableGrow(imm.index, value.node, delta.node,
                                       decoder->position()));
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm,
                 Value* result) {
    SetAndTypeNode(result, builder_->TableSize(imm.index));
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& start, const Value& value, const Value& count) {
    builder_->TableFill(imm.index, start.node, value.node, count.node,
                        decoder->position());
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    uint32_t field_count = imm.struct_type->field_count();
    NodeVector arg_nodes(field_count);
    for (uint32_t i = 0; i < field_count; i++) {
      arg_nodes[i] = args[i].node;
    }
    SetAndTypeNode(result, builder_->StructNew(imm.index, imm.struct_type, rtt,
                                               base::VectorOf(arg_nodes)));
  }
  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    TFNode* rtt = builder_->RttCanon(imm.index);
    uint32_t field_count = imm.struct_type->field_count();
    NodeVector arg_nodes(field_count);
    for (uint32_t i = 0; i < field_count; i++) {
      ValueType field_type = imm.struct_type->field(i);
      arg_nodes[i] = builder_->SetType(builder_->DefaultValue(field_type),
                                       field_type.Unpacked());
    }
    SetAndTypeNode(result, builder_->StructNew(imm.index, imm.struct_type, rtt,
                                               base::VectorOf(arg_nodes)));
  }

  void StructGet(FullDecoder* decoder, const Value& struct_object,
                 const FieldI
"""


```
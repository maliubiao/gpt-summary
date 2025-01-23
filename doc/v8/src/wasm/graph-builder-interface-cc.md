Response:
My thinking process to answer the request about `v8/src/wasm/graph-builder-interface.cc` goes like this:

1. **Understand the Core Request:** The request asks for the functionality of the provided C++ code snippet. It also has specific sub-questions regarding Torque, JavaScript relation, code logic, common errors, and a summary for this first part.

2. **Initial Code Analysis (Keywords and Structure):** I scanned the code for key terms and structural elements:
    * `#include`:  Indicates dependencies on other V8 components. I noted includes like `compiler/wasm-compiler-definitions.h`, `wasm/decoder.h`, `wasm/value-type.h`, etc. These hint at the file's role in translating WASM code into an intermediate representation used by the compiler.
    * `namespace v8::internal::wasm`:  Confirms it's a part of the V8 WASM implementation.
    * `class WasmGraphBuildingInterface`: This is the central class, suggesting it's responsible for building something (likely the graph).
    * `using TFNode = compiler::Node;`: This alias strongly suggests the file is about building a graph of `compiler::Node`s, which are part of V8's TurboFan compiler infrastructure.
    * `struct SsaEnv`: "SSA" usually stands for Static Single Assignment, a common intermediate representation in compilers. This struct likely manages the state during graph construction.
    * `struct Control`:  This likely manages control flow structures like blocks, loops, and if-statements in the WASM code.
    * Methods like `StartFunction`, `Block`, `Loop`, `If`, `LoadMem`, `StoreMem`, `CallFunction`, `Return`, etc.: These clearly map to WASM instructions and indicate the interface's role in processing the WASM bytecode.

3. **Inferring Functionality:** Based on the keywords and structure, I concluded that `graph-builder-interface.cc` is the bridge between the WASM decoder (which parses the WASM bytecode) and the V8 TurboFan compiler's graph builder. It takes the decoded WASM instructions and translates them into a graph representation that TurboFan can optimize and generate machine code from.

4. **Addressing Specific Questions:**

    * **Torque:** The prompt explicitly asks about `.tq`. Since the file ends in `.cc`, it's C++, not Torque.
    * **JavaScript Relation:**  WASM is designed to be executed within a JavaScript engine. The connection is that this code is part of the process that allows JavaScript to run WASM code efficiently. I thought of a simple example: a WASM function called from JavaScript.
    * **Code Logic (Hypothetical Input/Output):** I looked for simple operations. `I32Const` is a good example. If the input is the `i32.const 10` WASM instruction, the output would be the creation of a `compiler::Node` representing the constant value 10, with the correct type information. Similarly, `LocalGet` retrieves a local variable's node.
    * **Common Programming Errors:** I considered common mistakes when working with WASM or low-level languages. Memory access errors (out-of-bounds) and type mismatches are typical. I formulated examples related to these.

5. **Summarizing Functionality (Part 1):** I focused on the core responsibilities evident in the provided snippet: connecting the decoder to the graph builder, managing the SSA environment, handling control flow, and basic WASM instructions like constants, locals, and simple operations. I made sure to highlight its role in preparing the WASM code for compilation by TurboFan.

6. **Structuring the Answer:** I organized my answer to address each part of the prompt clearly. I used headings and bullet points for better readability. I tried to use precise terminology related to compilers and WASM.

7. **Review and Refine:** I reread my answer and the original code to ensure accuracy and completeness. I checked that my JavaScript example was relevant and easy to understand. I also ensured my hypothetical input/output examples were simple and directly related to the code.

Essentially, I followed a top-down approach, starting with the overall purpose and then diving into the details to answer the specific questions. My knowledge of compiler architecture and WASM internals was crucial for interpreting the code and providing relevant explanations.
这是V8源代码文件 `v8/src/wasm/graph-builder-interface.cc` 的第一部分。根据你提供的信息，我可以归纳出它的主要功能：

**主要功能归纳:**

`v8/src/wasm/graph-builder-interface.cc` 的主要功能是定义了一个接口 (`WasmGraphBuildingInterface`)，用于将解码后的 WebAssembly (Wasm) 指令转换成 V8 的 TurboFan 编译器能够理解的图结构 (Graph)。  它充当了 Wasm 解码器和 TurboFan 图构建器之间的桥梁。

**更详细的功能点:**

* **作为解码器和图构建器的接口:**  `WasmGraphBuildingInterface` 类定义了一系列方法，这些方法会被 Wasm 解码器调用，用来通知图构建器关于解码出的 Wasm 操作。
* **管理 SSA 环境 (SsaEnv):**  它维护了一个 `SsaEnv` 结构，用于跟踪当前代码点的静态单赋值 (SSA) 环境。这包括局部变量的重命名、当前的 effect 和 control 依赖关系。`SsaEnv` 还负责管理局部变量的存储。
* **处理控制流结构 (Control):**  它使用 `Control` 结构来表示 Wasm 中的控制流结构，如 blocks, loops, ifs, 和 try/catch 块。  `Control` 结构存储了与这些结构相关的环境信息，例如合并环境 (`merge_env`) 和分支环境 (`false_env`, `block_env`)。
* **与 TurboFan 图构建器交互:**  `WasmGraphBuildingInterface` 内部持有一个 `compiler::WasmGraphBuilder` 的指针，并调用其方法来创建和连接图节点。例如，当解码到 `i32.const` 指令时，会调用 `builder_->Int32Constant()`。
* **处理局部变量:** 它负责初始化和管理 Wasm 函数的局部变量，包括参数和声明的局部变量。
* **处理内存访问:**  它包含了处理内存加载 (`LoadMem`) 和存储 (`StoreMem`) 指令的方法。
* **处理常量:**  它包含了处理各种类型的常量指令的方法 (例如 `I32Const`, `F64Const`)。
* **处理基本操作:**  它包含了处理基本运算符的方法 (例如 `UnOp`, `BinOp`)。
* **处理分支指令:**  它包含了处理条件分支 (`BrIf`) 和无条件分支 (`Br`, `BrTable`) 指令的方法。
* **支持循环:**  它包含了处理循环结构 (`Loop`) 的逻辑，包括设置循环头节点和处理循环中的变量赋值。
* **支持异常处理:** 它包含了处理 `try` 块的逻辑，包括创建 catch 环境。
* **集成类型反馈和分支提示:**  代码中可以看到它尝试从模块中获取分支提示 (`branch_hints_`) 和类型反馈信息 (`type_feedback_`)，以便在图构建过程中进行优化。
* **处理 well-known imports:**  它包含处理一些预定义的导入函数 (`HandleWellKnownImport`) 的逻辑。

**关于你的问题：**

* **`.tq` 结尾:**  你提供的信息表明，如果文件以 `.tq` 结尾，它将是 V8 Torque 源代码。由于 `v8/src/wasm/graph-builder-interface.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 Torque 源代码。
* **与 JavaScript 的关系:**  `v8/src/wasm/graph-builder-interface.cc` 与 JavaScript 的功能 **密切相关**。 WebAssembly 的目标之一就是在 JavaScript 引擎中高效地执行代码。这个文件负责将 Wasm 代码转换成 V8 可以执行的中间表示形式，这是 JavaScript 引擎运行 Wasm 代码的关键步骤。

**JavaScript 示例 (说明关系):**

```javascript
// 在 JavaScript 中加载并运行 Wasm 模块
async function runWasm() {
  const response = await fetch('my_wasm_module.wasm'); // 假设有 wasm 文件
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer); // 编译 Wasm 模块
  const instance = await WebAssembly.instantiate(module); // 实例化 Wasm 模块

  // 调用 Wasm 模块导出的函数
  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

在这个 JavaScript 示例中，`WebAssembly.compile(buffer)` 阶段，V8 会解析 Wasm 字节码，并使用类似 `graph-builder-interface.cc` 中的代码将 Wasm 指令转换成内部的图结构。  `WebAssembly.instantiate(module)` 阶段会创建 Wasm 模块的实例，使得 JavaScript 可以调用 Wasm 模块导出的函数。

* **代码逻辑推理 (假设输入与输出):**

假设输入是解码后的 Wasm 指令 `i32.const 10`。

* **假设输入:** 解码器解析到 `i32.const` 操作码，并提取出常量值 `10`。
* **可能调用的方法:** `WasmGraphBuildingInterface::I32Const` 方法会被调用。
* **假设输出:**  `I32Const` 方法会调用 `builder_->Int32Constant(10)`，创建一个表示整数常量 10 的 `compiler::Node`，并将其赋值给 `result->node`。  这个 `compiler::Node` 将作为图结构的一部分，用于后续的编译优化。

假设输入是解码后的 Wasm 指令 `local.get 0` (获取索引为 0 的局部变量)。

* **假设输入:** 解码器解析到 `local.get` 操作码，并提取出局部变量索引 `0`。
* **可能调用的方法:** `WasmGraphBuildingInterface::LocalGet` 方法会被调用。
* **假设输出:** `LocalGet` 方法会从当前的 `ssa_env_->locals` 数组中取出索引为 0 的 `TFNode*`，并将其赋值给 `result->node`。这个 `TFNode*` 代表了该局部变量的值。

* **用户常见的编程错误 (与此文件功能相关):**

虽然用户通常不会直接与 `graph-builder-interface.cc` 交互，但与它相关的用户编程错误通常体现在编写的 Wasm 代码上，这些错误会在图构建阶段被检测或处理：

1. **类型不匹配:**  例如，尝试将一个浮点数存储到只能存储整数的局部变量中。在图构建阶段，类型信息会被检查，可能会导致类型错误。
2. **访问未初始化的局部变量:**  虽然 V8 在这里会进行初始化，但在其他上下文中，访问未初始化的变量是常见的错误。在图构建阶段，可能会通过数据流分析来检测这种潜在问题。
3. **内存访问越界:** 当 Wasm 代码尝试访问超出已分配内存范围的地址时，图构建器可能会生成包含边界检查的节点，或者在编译时就能检测到某些静态的越界访问。
4. **函数调用参数类型不匹配:**  如果 Wasm 函数的调用参数类型与函数签名不符，图构建器会根据函数签名进行类型检查。

**总结 (针对第 1 部分):**

`v8/src/wasm/graph-builder-interface.cc` 的第一部分主要定义了 `WasmGraphBuildingInterface` 类及其相关的辅助结构 (`SsaEnv`, `Control`)。  它确立了将解码后的 Wasm 指令转换为 V8 TurboFan 编译器图结构的基础框架，并实现了对一些基本 Wasm 指令 (如常量、局部变量操作、控制流初步) 的处理。 这部分代码负责维护编译过程中的状态信息，并与底层的图构建器进行交互。

### 提示词
```
这是目录为v8/src/wasm/graph-builder-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/graph-builder-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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
      case
```
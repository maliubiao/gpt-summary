Response:
The user wants a summary of the functionality of the provided C++ code snippet. I need to identify the key responsibilities of the `wasm-compiler.cc` file within the V8 JavaScript engine, focusing on its role in compiling WebAssembly code.

Here's a breakdown of the process:

1. **Identify the core purpose:** The filename and the included headers strongly suggest this file is responsible for compiling WebAssembly code within V8.

2. **Analyze included headers:**  The included headers provide clues about the functionalities:
    - `src/compiler/*`: Indicates interaction with the Turbofan compiler pipeline.
    - `src/codegen/*`:  Suggests code generation aspects.
    - `src/wasm/*`:  Confirms WebAssembly specific logic.

3. **Examine the `WasmGraphBuilder` class:** This class seems central to the compilation process. Its methods likely correspond to different WebAssembly operations.

4. **Identify key functionalities based on methods and macros:**  Look for methods related to:
    - Basic control flow (Start, Param, Loop, Merge, Phi, If, etc.)
    - Memory operations (Load, Store)
    - Arithmetic and logical operations (Binop, Unop)
    - Function calls (TryWasmInlining, CallBuiltinThroughJumptable)
    - Conversions between types
    - Handling specific WebAssembly features (SIMD, int64)
    - Integration with the Turbofan pipeline (MachineGraph, Operators)
    - Stack checks
    - Handling of instances and imports

5. **Address specific user requests:**
    - **`.tq` extension:**  The code is C++, so it's not a Torque file.
    - **Relationship with JavaScript:**  The file handles the compilation of WebAssembly, which can interact with JavaScript.
    - **JavaScript example:**  Demonstrate how WebAssembly interacts with JavaScript.
    - **Code logic reasoning:**  Pick a simple function and illustrate the input/output.
    - **Common programming errors:**  Consider errors related to memory access or type mismatches.

6. **Structure the summary:** Organize the findings into clear categories for better readability.

7. **Acknowledge the partial nature of the code:**  Clearly state that this is only part 1 of the file.
这是 V8 引擎中负责 WebAssembly 代码编译的关键部分。根据提供的代码，可以归纳出以下功能：

**核心功能：将 WebAssembly 代码编译成机器码**

`v8/src/compiler/wasm-compiler.cc` 的主要职责是将 WebAssembly (Wasm) 代码转换成可执行的机器码，使其能在 V8 引擎中高效运行。它利用了 V8 的 Turbofan 优化编译器框架。

**具体功能点：**

1. **构建中间表示 (IR) 图:**
   - 使用 `WasmGraphBuilder` 类，将 WebAssembly 的操作码转换成 Turbofan 编译器能够理解的图结构（`MachineGraph`）。
   - `WasmGraphBuilder` 提供了各种方法来创建图节点，对应 WebAssembly 的不同操作，例如：
     - `Start`, `Param`, `Loop`, `Merge`, `Phi`:  处理控制流。
     - `Binop`, `Unop`: 处理算术和逻辑运算。
     - `Load`, `Store`: 处理内存访问。
     - `CallBuiltinThroughJumptable`: 调用内置函数。
     - `RefNull`, `RefFunc`: 处理引用类型。
   - 使用 `WasmGraphAssembler` 辅助构建图。

2. **支持 WebAssembly 的各种特性:**
   - 通过条件编译 (`#ifdef`) 或运行时检查来支持不同的 WebAssembly 特性，例如 SIMD (`ContainsSimd`) 和 Int64 (`ContainsInt64`)。
   - 针对不同的 WebAssembly 操作码 (`wasm::WasmOpcode`) 生成相应的 Turbofan 操作。

3. **与 Turbofan 编译器集成:**
   - 使用 Turbofan 的 `MachineOperatorBuilder` 来创建特定架构的机器操作。
   - 利用 Turbofan 的优化 passes，例如指令选择 (`InstructionSelector`) 和代码生成 (`CodeGenerator`)。

4. **处理函数调用和内联:**
   - `TryWasmInlining` 方法尝试将小的 WebAssembly 函数内联到调用点，以提高性能。
   - 处理 WebAssembly 函数到 JavaScript 函数的调用，以及反向的调用。

5. **管理 WebAssembly 实例数据:**
   - 通过 `GetInstanceData` 获取 WebAssembly 实例数据。
   - 使用宏如 `LOAD_INSTANCE_FIELD` 和 `LOAD_MUTABLE_INSTANCE_FIELD` 来加载实例中的字段。

6. **进行栈检查:**
   - `StackCheck` 方法用于插入栈溢出检查，确保代码执行的安全性。

7. **处理异常和错误:**
   - `TerminateThrow` 方法用于处理 WebAssembly 代码抛出的异常。

8. **支持不同的调用约定:**
   - 根据 `parameter_mode_` 处理不同的参数传递方式，例如用于直接 WebAssembly 调用 (`kInstanceParameterMode`)，导入函数 (`kWasmImportDataMode`) 和 JavaScript 调用 WebAssembly (`kJSFunctionAbiMode`)。

**关于代码的特定问题：**

* **`.tq` 结尾:**  代码是以 `.cc` 结尾，所以它是 C++ 源代码，而不是 V8 Torque 源代码。Torque 文件通常用于定义 V8 内部的内置函数和类型。

* **与 JavaScript 的关系:**  `wasm-compiler.cc` 负责编译 WebAssembly 代码，而 WebAssembly 旨在与 JavaScript 并行运行并相互调用。

   **JavaScript 示例:**

   ```javascript
   // 假设有一个名为 'add' 的 WebAssembly 函数，它接受两个整数并返回它们的和。

   async function loadWasm() {
     const response = await fetch('my_module.wasm');
     const buffer = await response.arrayBuffer();
     const module = await WebAssembly.compile(buffer);
     const instance = await WebAssembly.instantiate(module);

     const result = instance.exports.add(5, 3); // 调用 WebAssembly 函数
     console.log(result); // 输出 8
   }

   loadWasm();
   ```

   在这个例子中，JavaScript 代码加载并实例化了一个 WebAssembly 模块，然后调用了该模块导出的 `add` 函数。`wasm-compiler.cc` 的工作就是将 `my_module.wasm` 中的 `add` 函数编译成高效的机器码，以便 JavaScript 可以调用它。

* **代码逻辑推理 (假设输入与输出):**

   **假设输入:** WebAssembly 代码中的一个简单的加法操作 `i32.add local.get 0 local.get 1`。

   **处理过程 (简化):**
   1. `WasmGraphBuilder` 接收到 `kExprI32Add` 操作码。
   2. 它会调用 `Binop(wasm::kExprI32Add, left, right)`，其中 `left` 和 `right` 是对应于 `local.get 0` 和 `local.get 1` 的节点，表示局部变量 0 和 1 的值。
   3. `Binop` 方法会创建 Turbofan 的 `Int32Add` 操作节点，并将 `left` 和 `right` 作为其输入。

   **假设输入:**  局部变量 0 的值为 10，局部变量 1 的值为 5。

   **输出 (中间表示):**  一个 Turbofan 图节点，表示将两个输入值相加的操作。

   **最终输出 (机器码):**  生成的机器码指令可能类似于 `add eax, ebx` (x86 架构)，假设局部变量的值被加载到了 `eax` 和 `ebx` 寄存器中。

* **涉及用户常见的编程错误:**

   一个常见的编程错误是在 WebAssembly 中进行内存访问时越界。例如，尝试读取或写入超出分配内存范围的地址。

   **示例:**

   假设 WebAssembly 模块分配了 100 字节的内存，但代码尝试写入地址 150。

   ```wasm
   (module
     (memory (export "memory") 1) ; 分配 65536 字节 (1 页)
     (func (export "write_oob") (param $offset i32) (param $value i32)
       local.get $offset
       local.get $value
       i32.store ;; 如果 $offset 大于等于内存大小，就会出错
     )
   )
   ```

   在 V8 中，`wasm-compiler.cc` 生成的代码会包含边界检查，当检测到越界访问时，会触发一个错误或陷阱，防止程序崩溃或造成安全问题。用户可能会在 JavaScript 控制台中看到类似 "wasm trap: out of bounds memory access" 的错误信息。

**总结第 1 部分的功能:**

这部分代码主要负责 `WasmGraphBuilder` 类的初始化和基本结构，以及处理一些核心的 WebAssembly 操作，例如启动编译、处理参数、创建循环、处理简单的算术和逻辑运算、以及进行栈检查。它奠定了将 WebAssembly 代码转换为 Turbofan 中间表示的基础。由于这是第 1 部分，后续的部分会继续展开，处理更复杂的 WebAssembly 特性和优化。

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-compiler.h"

#include <memory>
#include <optional>

#include "src/base/small-vector.h"
#include "src/base/vector.h"
#include "src/codegen/assembler.h"
#include "src/codegen/compiler.h"
#include "src/codegen/interface-descriptors-inl.h"
#include "src/codegen/machine-type.h"
#include "src/codegen/optimized-compilation-info.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/backend/code-generator.h"
#include "src/compiler/backend/instruction-selector.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/diamond.h"
#include "src/compiler/fast-api-calls.h"
#include "src/compiler/graph-assembler.h"
#include "src/compiler/int64-lowering.h"
#include "src/compiler/linkage.h"
#include "src/compiler/machine-operator.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-origin-table.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/pipeline.h"
#include "src/compiler/turbofan-graph-visualizer.h"
#include "src/compiler/turbofan-graph.h"
#include "src/compiler/turboshaft/wasm-turboshaft-compiler.h"
#include "src/compiler/wasm-call-descriptors.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/compiler/wasm-graph-assembler.h"
#include "src/compiler/wasm-inlining-into-js.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/execution/simulator-base.h"
#include "src/heap/factory.h"
#include "src/logging/counters.h"
#include "src/objects/code-kind.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type.h"
#include "src/objects/name.h"
#include "src/objects/string.h"
#include "src/roots/roots.h"
#include "src/tracing/trace-event.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/graph-builder-interface.h"
#include "src/wasm/jump-table-assembler.h"
#include "src/wasm/memory-tracing.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-code-manager.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler {

namespace {

constexpr MachineType kMaybeSandboxedPointer =
    V8_ENABLE_SANDBOX_BOOL ? MachineType::SandboxedPointer()
                           : MachineType::Pointer();

#define FATAL_UNSUPPORTED_OPCODE(opcode)        \
  FATAL("Unsupported opcode 0x%x:%s", (opcode), \
        wasm::WasmOpcodes::OpcodeName(opcode));

MachineType assert_size(int expected_size, MachineType type) {
  DCHECK_EQ(expected_size, ElementSizeInBytes(type.representation()));
  return type;
}

#define WASM_INSTANCE_OBJECT_SIZE(name)          \
  (WasmTrustedInstanceData::k##name##OffsetEnd - \
   WasmTrustedInstanceData::k##name##Offset + 1)  // NOLINT(whitespace/indent)

#define LOAD_MUTABLE_INSTANCE_FIELD(name, type)                              \
  gasm_->LoadFromObject(                                                     \
      assert_size(WASM_INSTANCE_OBJECT_SIZE(name), type), GetInstanceData(), \
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::k##name##Offset))

#define LOAD_INSTANCE_FIELD(name, type)                                      \
  gasm_->LoadImmutable(                                                      \
      assert_size(WASM_INSTANCE_OBJECT_SIZE(name), type), GetInstanceData(), \
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::k##name##Offset))

#define LOAD_PROTECTED_INSTANCE_FIELD(name) \
  gasm_->LoadProtectedPointerFromObject(    \
      GetInstanceData(),                    \
      wasm::ObjectAccess::ToTagged(         \
          WasmTrustedInstanceData::kProtected##name##Offset));

#define LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(name) \
  gasm_->LoadImmutableProtectedPointerFromObject(     \
      GetInstanceData(),                              \
      wasm::ObjectAccess::ToTagged(                   \
          WasmTrustedInstanceData::kProtected##name##Offset));

#define LOAD_INSTANCE_FIELD_NO_ELIMINATION(name, type)                       \
  gasm_->Load(                                                               \
      assert_size(WASM_INSTANCE_OBJECT_SIZE(name), type), GetInstanceData(), \
      wasm::ObjectAccess::ToTagged(WasmTrustedInstanceData::k##name##Offset))

// Use MachineType::Pointer() over Tagged() to load root pointers because they
// do not get compressed.
#define LOAD_ROOT(RootName, factory_name)                         \
  (isolate_ ? graph()->NewNode(mcgraph()->common()->HeapConstant( \
                  isolate_->factory()->factory_name()))           \
            : gasm_->LoadImmutable(                               \
                  MachineType::Pointer(), BuildLoadIsolateRoot(), \
                  IsolateData::root_slot_offset(RootIndex::k##RootName)))

#define LOAD_MUTABLE_ROOT(RootName, factory_name)                 \
  (isolate_ ? graph()->NewNode(mcgraph()->common()->HeapConstant( \
                  isolate_->factory()->factory_name()))           \
            : gasm_->BitcastWordToTagged(gasm_->Load(             \
                  MachineType::Pointer(), BuildLoadIsolateRoot(), \
                  IsolateData::root_slot_offset(RootIndex::k##RootName))))

template <typename T>
bool ContainsSimd(const Signature<T>* sig) {
  for (auto type : sig->all()) {
    if (type == T::Primitive(wasm::kS128)) return true;
  }
  return false;
}

bool ContainsInt64(const wasm::CanonicalSig* sig) {
  for (auto type : sig->all()) {
    if (type == wasm::kCanonicalI64) return true;
  }
  return false;
}

}  // namespace

WasmGraphBuilder::WasmGraphBuilder(
    wasm::CompilationEnv* env, Zone* zone, MachineGraph* mcgraph,
    const wasm::FunctionSig* sig,
    compiler::SourcePositionTable* source_position_table,
    ParameterMode parameter_mode, Isolate* isolate,
    wasm::WasmEnabledFeatures enabled_features,
    const wasm::CanonicalSig* wrapper_sig)
    : gasm_(std::make_unique<WasmGraphAssembler>(mcgraph, zone)),
      zone_(zone),
      mcgraph_(mcgraph),
      env_(env),
      enabled_features_(enabled_features),
      has_simd_(sig ? ContainsSimd(sig) : ContainsSimd(wrapper_sig)),
      function_sig_(sig),
      wrapper_sig_(wrapper_sig),
      source_position_table_(source_position_table),
      parameter_mode_(parameter_mode),
      isolate_(isolate),
      null_check_strategy_(trap_handler::IsTrapHandlerEnabled() &&
                                   V8_STATIC_ROOTS_BOOL
                               ? NullCheckStrategy::kTrapHandler
                               : NullCheckStrategy::kExplicit) {
  // This code is only used
  // - if `--no-turboshaft-wasm` is passed,
  // - for compiling certain wrappers (wasm-to-fast API, C-wasm-entry), and
  // - for inlining js-to-wasm wrappers into Turbofan-compile JS functions.
  CHECK(!v8_flags.turboshaft_wasm ||
        parameter_mode != ParameterMode::kInstanceParameterMode);

  // There are two kinds of isolate-specific code: JS-to-JS wrappers (passing
  // kNoSpecialParameterMode) and JS-to-Wasm wrappers (passing
  // kJSFunctionAbiMode).
  DCHECK_IMPLIES(isolate != nullptr,
                 parameter_mode_ == kJSFunctionAbiMode ||
                     parameter_mode_ == kNoSpecialParameterMode);
  DCHECK_IMPLIES(env && env->module &&
                     std::any_of(env->module->memories.begin(),
                                 env->module->memories.end(),
                                 [](auto& memory) {
                                   return memory.bounds_checks ==
                                          wasm::kTrapHandler;
                                 }),
                 trap_handler::IsTrapHandlerEnabled());
  DCHECK_NOT_NULL(mcgraph_);
}

// Destructor define here where the definition of {WasmGraphAssembler} is
// available.
WasmGraphBuilder::~WasmGraphBuilder() = default;

bool WasmGraphBuilder::TryWasmInlining(int fct_index,
                                       wasm::NativeModule* native_module,
                                       int inlining_id) {
#define TRACE(x)                         \
  do {                                   \
    if (v8_flags.trace_turbo_inlining) { \
      StdoutStream() << x << "\n";       \
    }                                    \
  } while (false)

  DCHECK(native_module->HasWireBytes());
  const wasm::WasmModule* module = native_module->module();
  const wasm::WasmFunction& inlinee = module->functions[fct_index];
  // TODO(mliedtke): What would be a proper maximum size?
  const uint32_t kMaxWasmInlineeSize = 30;
  if (inlinee.code.length() > kMaxWasmInlineeSize) {
    TRACE("- not inlining: function body is larger than max inlinee size ("
          << inlinee.code.length() << " > " << kMaxWasmInlineeSize << ")");
    return false;
  }
  if (inlinee.imported) {
    TRACE("- not inlining: function is imported");
    return false;
  }
  base::Vector<const uint8_t> bytes(native_module->wire_bytes().SubVector(
      inlinee.code.offset(), inlinee.code.end_offset()));
  bool is_shared = module->type(inlinee.sig_index).is_shared;
  const wasm::FunctionBody inlinee_body(inlinee.sig, inlinee.code.offset(),
                                        bytes.begin(), bytes.end(), is_shared);
  // If the inlinee was not validated before, do that now.
  if (V8_UNLIKELY(!module->function_was_validated(fct_index))) {
    wasm::WasmDetectedFeatures unused_detected_features;
    if (ValidateFunctionBody(graph()->zone(), enabled_features_, module,
                             &unused_detected_features, inlinee_body)
            .failed()) {
      // At this point we cannot easily raise a compilation error any more.
      // Since this situation is highly unlikely though, we just ignore this
      // inlinee and move on. The same validation error will be triggered
      // again when actually compiling the invalid function.
      TRACE("- not inlining: function body is invalid");
      return false;
    }
    module->set_function_validated(fct_index);
  }
  bool result = WasmIntoJSInliner::TryInlining(
      graph()->zone(), module, mcgraph_, inlinee_body, bytes,
      source_position_table_, inlining_id);
  TRACE((
      result
          ? "- inlining"
          : "- not inlining: function body contains unsupported instructions"));
  return result;
#undef TRACE
}

void WasmGraphBuilder::Start(unsigned params) {
  Node* start = graph()->NewNode(mcgraph()->common()->Start(params));
  graph()->SetStart(start);
  SetEffectControl(start);
  // Initialize parameter nodes.
  parameters_ = zone_->AllocateArray<Node*>(params);
  for (unsigned i = 0; i < params; i++) {
    parameters_[i] = nullptr;
  }
  // Initialize instance node.
  switch (parameter_mode_) {
    case kInstanceParameterMode: {
      Node* param = Param(wasm::kWasmInstanceDataParameterIndex);
      if (v8_flags.debug_code) {
        Assert(gasm_->HasInstanceType(param, WASM_TRUSTED_INSTANCE_DATA_TYPE),
               AbortReason::kUnexpectedInstanceType);
      }
      instance_data_node_ = param;
      break;
    }
    case kWasmImportDataMode: {
      Node* param = Param(0);
      if (v8_flags.debug_code) {
        Assert(gasm_->HasInstanceType(param, WASM_IMPORT_DATA_TYPE),
               AbortReason::kUnexpectedInstanceType);
      }
      instance_data_node_ = gasm_->LoadProtectedPointerFromObject(
          param, wasm::ObjectAccess::ToTagged(
                     WasmImportData::kProtectedInstanceDataOffset));
      break;
    }
    case kJSFunctionAbiMode: {
      Node* param = Param(Linkage::kJSCallClosureParamIndex, "%closure");
      if (v8_flags.debug_code) {
        Assert(gasm_->HasInstanceType(param, JS_FUNCTION_TYPE),
               AbortReason::kUnexpectedInstanceType);
      }
      instance_data_node_ = gasm_->LoadExportedFunctionInstanceData(
          gasm_->LoadFunctionDataFromJSFunction(param));
      break;
    }
    case kNoSpecialParameterMode:
      break;
  }
  graph()->SetEnd(graph()->NewNode(mcgraph()->common()->End(0)));
}

Node* WasmGraphBuilder::Param(int index, const char* debug_name) {
  DCHECK_NOT_NULL(graph()->start());
  // Turbofan allows negative parameter indices.
  DCHECK_GE(index, kMinParameterIndex);
  int array_index = index - kMinParameterIndex;
  if (parameters_[array_index] == nullptr) {
    parameters_[array_index] = graph()->NewNode(
        mcgraph()->common()->Parameter(index, debug_name), graph()->start());
  }
  return parameters_[array_index];
}

Node* WasmGraphBuilder::Loop(Node* entry) {
  return graph()->NewNode(mcgraph()->common()->Loop(1), entry);
}

void WasmGraphBuilder::TerminateLoop(Node* effect, Node* control) {
  Node* terminate =
      graph()->NewNode(mcgraph()->common()->Terminate(), effect, control);
  gasm_->MergeControlToEnd(terminate);
}

Node* WasmGraphBuilder::LoopExit(Node* loop_node) {
  DCHECK(loop_node->opcode() == IrOpcode::kLoop);
  Node* loop_exit =
      graph()->NewNode(mcgraph()->common()->LoopExit(), control(), loop_node);
  Node* loop_exit_effect = graph()->NewNode(
      mcgraph()->common()->LoopExitEffect(), effect(), loop_exit);
  SetEffectControl(loop_exit_effect, loop_exit);
  return loop_exit;
}

Node* WasmGraphBuilder::LoopExitValue(Node* value,
                                      MachineRepresentation representation) {
  DCHECK_EQ(control()->opcode(), IrOpcode::kLoopExit);
  return graph()->NewNode(mcgraph()->common()->LoopExitValue(representation),
                          value, control());
}

void WasmGraphBuilder::TerminateThrow(Node* effect, Node* control) {
  Node* terminate =
      graph()->NewNode(mcgraph()->common()->Throw(), effect, control);
  gasm_->MergeControlToEnd(terminate);
  gasm_->InitializeEffectControl(nullptr, nullptr);
}

bool WasmGraphBuilder::IsPhiWithMerge(Node* phi, Node* merge) {
  return phi && IrOpcode::IsPhiOpcode(phi->opcode()) &&
         NodeProperties::GetControlInput(phi) == merge;
}

bool WasmGraphBuilder::ThrowsException(Node* node, Node** if_success,
                                       Node** if_exception) {
  if (node->op()->HasProperty(compiler::Operator::kNoThrow)) {
    return false;
  }

  *if_success = graph()->NewNode(mcgraph()->common()->IfSuccess(), node);
  *if_exception =
      graph()->NewNode(mcgraph()->common()->IfException(), node, node);

  return true;
}

void WasmGraphBuilder::AppendToMerge(Node* merge, Node* from) {
  DCHECK(IrOpcode::IsMergeOpcode(merge->opcode()));
  merge->AppendInput(mcgraph()->zone(), from);
  int new_size = merge->InputCount();
  NodeProperties::ChangeOp(
      merge, mcgraph()->common()->ResizeMergeOrPhi(merge->op(), new_size));
}

void WasmGraphBuilder::AppendToPhi(Node* phi, Node* from) {
  DCHECK(IrOpcode::IsPhiOpcode(phi->opcode()));
  int new_size = phi->InputCount();
  phi->InsertInput(mcgraph()->zone(), phi->InputCount() - 1, from);
  NodeProperties::ChangeOp(
      phi, mcgraph()->common()->ResizeMergeOrPhi(phi->op(), new_size));
}

template <typename... Nodes>
Node* WasmGraphBuilder::Merge(Node* fst, Nodes*... args) {
  return graph()->NewNode(this->mcgraph()->common()->Merge(1 + sizeof...(args)),
                          fst, args...);
}

Node* WasmGraphBuilder::Merge(unsigned count, Node** controls) {
  return graph()->NewNode(mcgraph()->common()->Merge(count), count, controls);
}

Node* WasmGraphBuilder::Phi(wasm::ValueType type, unsigned count,
                            Node** vals_and_control) {
  DCHECK(IrOpcode::IsMergeOpcode(vals_and_control[count]->opcode()));
  DCHECK_EQ(vals_and_control[count]->op()->ControlInputCount(), count);
  return graph()->NewNode(
      mcgraph()->common()->Phi(type.machine_representation(), count), count + 1,
      vals_and_control);
}

Node* WasmGraphBuilder::EffectPhi(unsigned count, Node** effects_and_control) {
  DCHECK(IrOpcode::IsMergeOpcode(effects_and_control[count]->opcode()));
  return graph()->NewNode(mcgraph()->common()->EffectPhi(count), count + 1,
                          effects_and_control);
}

Node* WasmGraphBuilder::RefNull(wasm::ValueType type) {
  // This version is for functions, not wrappers.
  DCHECK_EQ(parameter_mode_, kInstanceParameterMode);
  return gasm_->Null(type);
}

Node* WasmGraphBuilder::RefFunc(uint32_t function_index) {
  Node* func_refs = LOAD_INSTANCE_FIELD(FuncRefs, MachineType::TaggedPointer());
  Node* maybe_function =
      gasm_->LoadFixedArrayElementPtr(func_refs, function_index);
  auto done = gasm_->MakeLabel(MachineRepresentation::kTaggedPointer);
  auto create_funcref = gasm_->MakeDeferredLabel();
  // We only care to distinguish between zero and funcref, "IsI31" is close
  // enough.
  gasm_->GotoIf(gasm_->IsSmi(maybe_function), &create_funcref);
  gasm_->Goto(&done, maybe_function);

  gasm_->Bind(&create_funcref);
  Node* function_from_builtin = gasm_->CallBuiltinThroughJumptable(
      Builtin::kWasmRefFunc, Operator::kNoThrow,
      gasm_->Uint32Constant(function_index), gasm_->Int32Constant(0));
  gasm_->Goto(&done, function_from_builtin);

  gasm_->Bind(&done);
  return done.PhiAt(0);
}

Node* WasmGraphBuilder::NoContextConstant() {
  return mcgraph()->IntPtrConstant(0);
}

Node* WasmGraphBuilder::GetInstanceData() { return instance_data_node_.get(); }

Node* WasmGraphBuilder::BuildLoadIsolateRoot() {
  return isolate_ ? mcgraph()->IntPtrConstant(isolate_->isolate_root())
                  : gasm_->LoadRootRegister();
}

Node* WasmGraphBuilder::TraceInstruction(uint32_t mark_id) {
  const Operator* op = mcgraph()->machine()->TraceInstruction(mark_id);
  Node* node = SetEffect(graph()->NewNode(op, effect(), control()));
  return node;
}

Node* WasmGraphBuilder::Int32Constant(int32_t value) {
  return mcgraph()->Int32Constant(value);
}

Node* WasmGraphBuilder::Int64Constant(int64_t value) {
  return mcgraph()->Int64Constant(value);
}

Node* WasmGraphBuilder::UndefinedValue() {
  return LOAD_ROOT(UndefinedValue, undefined_value);
}

void WasmGraphBuilder::StackCheck(
    WasmInstanceCacheNodes* shared_memory_instance_cache,
    wasm::WasmCodePosition position) {
  DCHECK_NOT_NULL(env_);  // Wrappers don't get stack checks.
  if (!v8_flags.wasm_stack_checks) return;

  Node* limit =
      gasm_->Load(MachineType::Pointer(), gasm_->LoadRootRegister(),
                  mcgraph()->IntPtrConstant(IsolateData::jslimit_offset()));

  Node* check = SetEffect(graph()->NewNode(
      mcgraph()->machine()->StackPointerGreaterThan(StackCheckKind::kWasm),
      limit, effect()));

  auto [if_true, if_false] = BranchExpectTrue(check);

  if (stack_check_call_operator_ == nullptr) {
    // Build and cache the stack check call operator and the constant
    // representing the stack check code.

    // A direct call to a wasm runtime stub defined in this module.
    // Just encode the stub index. This will be patched at relocation.
    stack_check_code_node_.set(
        mcgraph()->RelocatableWasmBuiltinCallTarget(Builtin::kWasmStackGuard));

    constexpr Operator::Properties properties =
        Operator::kNoThrow | Operator::kNoWrite;
    // If we ever want to mark this call as kNoDeopt, we'll have to make it
    // non-eliminatable some other way.
    static_assert((properties & Operator::kEliminatable) !=
                  Operator::kEliminatable);
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        mcgraph()->zone(),                    // zone
        NoContextDescriptor{},                // descriptor
        0,                                    // stack parameter count
        CallDescriptor::kNoFlags,             // flags
        properties,                           // properties
        StubCallMode::kCallWasmRuntimeStub);  // stub call mode
    stack_check_call_operator_ = mcgraph()->common()->Call(call_descriptor);
  }

  Node* call =
      graph()->NewNode(stack_check_call_operator_.get(),
                       stack_check_code_node_.get(), effect(), if_false);
  SetSourcePosition(call, position);

  DCHECK_GT(call->op()->EffectOutputCount(), 0);
  DCHECK_EQ(call->op()->ControlOutputCount(), 0);

  SetEffectControl(call, if_false);

  // We only need to refresh the size of a shared memory, as its start can never
  // change.
  // We handle caching of the instance cache nodes manually, and we may reload
  // them in contexts where load elimination would eliminate the reload.
  // Therefore, we use plain Load nodes which are not subject to load
  // elimination.
  DCHECK_IMPLIES(shared_memory_instance_cache, has_cached_memory());
  Node* new_memory_size = shared_memory_instance_cache == nullptr
                              ? nullptr
                              : LoadMemSize(cached_memory_index_);

  Node* merge = Merge(if_true, control());
  Node* ephi_inputs[] = {check, effect(), merge};
  Node* ephi = EffectPhi(2, ephi_inputs);

  if (shared_memory_instance_cache != nullptr) {
    shared_memory_instance_cache->mem_size = CreateOrMergeIntoPhi(
        MachineType::PointerRepresentation(), merge,
        shared_memory_instance_cache->mem_size, new_memory_size);
  }

  SetEffectControl(ephi, merge);
}

void WasmGraphBuilder::PatchInStackCheckIfNeeded() {
  if (!needs_stack_check_) return;

  Node* start = graph()->start();
  // Place a stack check which uses a dummy node as control and effect.
  Node* dummy = graph()->NewNode(mcgraph()->common()->Dead());
  SetEffectControl(dummy);
  // The function-prologue stack check is associated with position 0, which
  // is never a position of any instruction in the function.
  // We pass the null instance cache, as we are at the beginning of the function
  // and do not need to update it.
  StackCheck(nullptr, 0);

  // In testing, no stack checks were emitted. Nothing to rewire then.
  if (effect() == dummy) return;

  // Now patch all control uses of {start} to use {control} and all effect uses
  // to use {effect} instead. We exclude Projection nodes: Projections pointing
  // to start are floating control, and we want it to point directly to start
  // because of restrictions later in the pipeline (specifically, loop
  // unrolling).
  // Then rewire the dummy node to use start instead.
  NodeProperties::ReplaceUses(start, start, effect(), control());
  {
    // We need an intermediate vector because we are not allowed to modify a use
    // while traversing uses().
    std::vector<Node*> projections;
    for (Node* use : control()->uses()) {
      if (use->opcode() == IrOpcode::kProjection) projections.emplace_back(use);
    }
    for (Node* use : projections) {
      use->ReplaceInput(NodeProperties::FirstControlIndex(use), start);
    }
  }
  NodeProperties::ReplaceUses(dummy, nullptr, start, start);
}

Node* WasmGraphBuilder::Binop(wasm::WasmOpcode opcode, Node* left, Node* right,
                              wasm::WasmCodePosition position) {
  const Operator* op;
  MachineOperatorBuilder* m = mcgraph()->machine();
  switch (opcode) {
    case wasm::kExprI32Add:
      op = m->Int32Add();
      break;
    case wasm::kExprI32Sub:
      op = m->Int32Sub();
      break;
    case wasm::kExprI32Mul:
      op = m->Int32Mul();
      break;
    case wasm::kExprI32DivS:
      return BuildI32DivS(left, right, position);
    case wasm::kExprI32DivU:
      return BuildI32DivU(left, right, position);
    case wasm::kExprI32RemS:
      return BuildI32RemS(left, right, position);
    case wasm::kExprI32RemU:
      return BuildI32RemU(left, right, position);
    case wasm::kExprI32And:
      op = m->Word32And();
      break;
    case wasm::kExprI32Ior:
      op = m->Word32Or();
      break;
    case wasm::kExprI32Xor:
      op = m->Word32Xor();
      break;
    case wasm::kExprI32Shl:
      op = m->Word32Shl();
      right = MaskShiftCount32(right);
      break;
    case wasm::kExprI32ShrU:
      op = m->Word32Shr();
      right = MaskShiftCount32(right);
      break;
    case wasm::kExprI32ShrS:
      op = m->Word32Sar();
      right = MaskShiftCount32(right);
      break;
    case wasm::kExprI32Ror:
      op = m->Word32Ror();
      right = MaskShiftCount32(right);
      break;
    case wasm::kExprI32Rol:
      if (m->Word32Rol().IsSupported()) {
        op = m->Word32Rol().op();
        right = MaskShiftCount32(right);
        break;
      }
      return BuildI32Rol(left, right);
    case wasm::kExprI32Eq:
      op = m->Word32Equal();
      break;
    case wasm::kExprI32Ne:
      return Invert(Binop(wasm::kExprI32Eq, left, right));
    case wasm::kExprI32LtS:
      op = m->Int32LessThan();
      break;
    case wasm::kExprI32LeS:
      op = m->Int32LessThanOrEqual();
      break;
    case wasm::kExprI32LtU:
      op = m->Uint32LessThan();
      break;
    case wasm::kExprI32LeU:
      op = m->Uint32LessThanOrEqual();
      break;
    case wasm::kExprI32GtS:
      op = m->Int32LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprI32GeS:
      op = m->Int32LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprI32GtU:
      op = m->Uint32LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprI32GeU:
      op = m->Uint32LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprI64And:
      op = m->Word64And();
      break;
    case wasm::kExprI64Add:
      op = m->Int64Add();
      break;
    case wasm::kExprI64Sub:
      op = m->Int64Sub();
      break;
    case wasm::kExprI64Mul:
      op = m->Int64Mul();
      break;
    case wasm::kExprI64DivS:
      return BuildI64DivS(left, right, position);
    case wasm::kExprI64DivU:
      return BuildI64DivU(left, right, position);
    case wasm::kExprI64RemS:
      return BuildI64RemS(left, right, position);
    case wasm::kExprI64RemU:
      return BuildI64RemU(left, right, position);
    case wasm::kExprI64Ior:
      op = m->Word64Or();
      break;
    case wasm::kExprI64Xor:
      op = m->Word64Xor();
      break;
    case wasm::kExprI64Shl:
      op = m->Word64Shl();
      right = MaskShiftCount64(right);
      break;
    case wasm::kExprI64ShrU:
      op = m->Word64Shr();
      right = MaskShiftCount64(right);
      break;
    case wasm::kExprI64ShrS:
      op = m->Word64Sar();
      right = MaskShiftCount64(right);
      break;
    case wasm::kExprI64Eq:
      op = m->Word64Equal();
      break;
    case wasm::kExprI64Ne:
      return Invert(Binop(wasm::kExprI64Eq, left, right));
    case wasm::kExprI64LtS:
      op = m->Int64LessThan();
      break;
    case wasm::kExprI64LeS:
      op = m->Int64LessThanOrEqual();
      break;
    case wasm::kExprI64LtU:
      op = m->Uint64LessThan();
      break;
    case wasm::kExprI64LeU:
      op = m->Uint64LessThanOrEqual();
      break;
    case wasm::kExprI64GtS:
      op = m->Int64LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprI64GeS:
      op = m->Int64LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprI64GtU:
      op = m->Uint64LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprI64GeU:
      op = m->Uint64LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprI64Ror:
      right = MaskShiftCount64(right);
      return m->Is64() ? graph()->NewNode(m->Word64Ror(), left, right)
                       : graph()->NewNode(m->Word64RorLowerable(), left, right,
                                          control());
    case wasm::kExprI64Rol:
      if (m->Word64Rol().IsSupported()) {
        return m->Is64() ? graph()->NewNode(m->Word64Rol().op(), left,
                                            MaskShiftCount64(right))
                         : graph()->NewNode(m->Word64RolLowerable().op(), left,
                                            MaskShiftCount64(right), control());
      } else if (m->Word32Rol().IsSupported()) {
        return graph()->NewNode(m->Word64RolLowerable().placeholder(), left,
                                right, control());
      }
      return BuildI64Rol(left, right);
    case wasm::kExprF32CopySign:
      return BuildF32CopySign(left, right);
    case wasm::kExprF64CopySign:
      return BuildF64CopySign(left, right);
    case wasm::kExprF32Add:
      op = m->Float32Add();
      break;
    case wasm::kExprF32Sub:
      op = m->Float32Sub();
      break;
    case wasm::kExprF32Mul:
      op = m->Float32Mul();
      break;
    case wasm::kExprF32Div:
      op = m->Float32Div();
      break;
    case wasm::kExprF32Eq:
      op = m->Float32Equal();
      break;
    case wasm::kExprF32Ne:
      return Invert(Binop(wasm::kExprF32Eq, left, right));
    case wasm::kExprF32Lt:
      op = m->Float32LessThan();
      break;
    case wasm::kExprF32Ge:
      op = m->Float32LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprF32Gt:
      op = m->Float32LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprF32Le:
      op = m->Float32LessThanOrEqual();
      break;
    case wasm::kExprF64Add:
      op = m->Float64Add();
      break;
    case wasm::kExprF64Sub:
      op = m->Float64Sub();
      break;
    case wasm::kExprF64Mul:
      op = m->Float64Mul();
      break;
    case wasm::kExprF64Div:
      op = m->Float64Div();
      break;
    case wasm::kExprF64Eq:
      op = m->Float64Equal();
      break;
    case wasm::kExprF64Ne:
      return Invert(Binop(wasm::kExprF64Eq, left, right));
    case wasm::kExprF64Lt:
      op = m->Float64LessThan();
      break;
    case wasm::kExprF64Le:
      op = m->Float64LessThanOrEqual();
      break;
    case wasm::kExprF64Gt:
      op = m->Float64LessThan();
      std::swap(left, right);
      break;
    case wasm::kExprF64Ge:
      op = m->Float64LessThanOrEqual();
      std::swap(left, right);
      break;
    case wasm::kExprF32Min:
      op = m->Float32Min();
      break;
    case wasm::kExprF64Min:
      op = m->Float64Min();
      break;
    case wasm::kExprF32Max:
      op = m->Float32Max();
      break;
    case wasm::kExprF64Max:
      op = m->Float64Max();
      break;
    case wasm::kExprF64Pow:
      return BuildF64Pow(left, right);
    case wasm::kExprF64Atan2:
      op = m->Float64Atan2();
      break;
    case wasm::kExprF64Mod:
      return BuildF64Mod(left, right);
    case wasm::kExprRefEq:
      return gasm_->TaggedEqual(left, right);
    case wasm::kExprI32AsmjsDivS:
      return BuildI32AsmjsDivS(left, right);
    case wasm::kExprI32AsmjsDivU:
      return BuildI32AsmjsDivU(left, right);
    case wasm::kExprI32AsmjsRemS:
      return BuildI32AsmjsRemS(left, right);
    case wasm::kExprI32AsmjsRemU:
      return BuildI32AsmjsRemU(left, right);
    case wasm::kExprI32AsmjsStoreMem8:
      return BuildAsmjsStoreMem(MachineType::Int8(), left, right);
    case wasm::kExprI32AsmjsStoreMem16:
      return BuildAsmjsStoreMem(MachineType::Int16(), left, right);
    case wasm::kExprI32AsmjsStoreMem:
      return BuildAsmjsStoreMem(MachineType::Int32(), left, right);
    case wasm::kExprF32AsmjsStoreMem:
      return BuildAsmjsStoreMem(MachineType::Float32(), left, right);
    case wasm::kExprF64AsmjsStoreMem:
      return BuildAsmjsStoreMem(MachineType::Float64(), left, right);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
  return graph()->NewNode(op, left, right);
}

Node* WasmGraphBuilder::Unop(wasm::WasmOpcode opcode, Node* input,
                             wasm::ValueType type,
                             wasm::WasmCodePosition position) {
  const Operator* op;
  MachineOperatorBuilder* m = mcgraph()->machine();
  switch (opcode) {
    case wasm::kExprI32Eqz:
      return gasm_->Word32Equal(input, Int32Constant(0));
    case wasm::kExprF32Abs:
      op = m->Float32Abs();
      break;
    case wasm::kExprF32Neg: {
      op = m->Float32Neg();
      break;
    }
    case wasm::kExprF32Sqrt:
      op = m->Float32Sqrt();
      break;
    case wasm::kExprF64Abs:
      op = m->Float64Abs();
      break;
    case wasm::kExprF64Neg: {
      op = m->Float64Neg();
      break;
    }
    case wasm::kExprF64Sqrt:
      op = m->Float64Sqrt();
      break;
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32SConvertSatF64:
    case wasm::kExprI32UConvertSatF64:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI32UConvertSatF32:
      return BuildIntConvertFloat(input, position, opcode);
    case wasm::kExprI32AsmjsSConvertF64
```
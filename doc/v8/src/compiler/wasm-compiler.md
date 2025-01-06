Response: The user wants a summary of the C++ source code file `v8/src/compiler/wasm-compiler.cc`.
This is the first part of a series of files.
The goal is to understand the purpose of this specific part of the file.
The file seems to be related to the compilation of WebAssembly code within the V8 JavaScript engine.
It includes a class called `WasmGraphBuilder`, which strongly suggests that it's involved in building a graph representation of the WebAssembly code, likely for optimization and code generation.

Here's a breakdown of the code snippets:
- Includes: Standard C++ headers and V8-specific headers related to compiler, codegen, and WebAssembly.
- Namespaces: Defines code within the `v8::internal::compiler` namespace and an anonymous namespace for internal helpers.
- Macros: `FATAL_UNSUPPORTED_OPCODE`, `WASM_INSTANCE_OBJECT_SIZE`, `LOAD_*_INSTANCE_FIELD`, `LOAD_ROOT`, `LOAD_MUTABLE_ROOT`: These seem to be helper macros for error handling, accessing WebAssembly instance data, and loading global roots.
- `ContainsSimd` and `ContainsInt64` functions: Check if a function signature includes SIMD or Int64 types.
- `WasmGraphBuilder` class: This is the core of the file. It has a constructor, destructor, and methods like `Start`, `Param`, `Loop`, `Branch`, `Binop`, `Unop`, `Load`, `Store`, `Call`, `Return`, etc. These methods directly correspond to WebAssembly operations and suggest the class is responsible for translating WebAssembly bytecode into a compiler graph.
- Inlining logic: The `TryWasmInlining` method handles the inlining of WebAssembly functions into other WebAssembly or JavaScript code.
- Graph manipulation methods: Methods like `Merge`, `Phi`, `EffectPhi` are used for building control flow and data flow within the compiler graph.
- Type conversions and arithmetic operations: The `Binop` and `Unop` methods handle various arithmetic, logical, and type conversion operations in WebAssembly.
- Memory access: The code includes logic for loading and storing values from memory, including handling endianness.
- Exception handling: Methods like `TrapIfTrue`, `TrapIfFalse`, and `Trap` handle WebAssembly traps.

Based on this analysis, the primary function of `wasm-compiler.cc` (part 1) is to provide the foundational building blocks and logic for translating WebAssembly bytecode into an intermediate representation (likely a graph) that can be further optimized and then compiled into machine code by the V8 JavaScript engine. It provides the `WasmGraphBuilder` class which acts as the central interface for constructing this graph.

Regarding the relationship with JavaScript, this file is crucial for enabling JavaScript to execute WebAssembly code. When JavaScript code calls a WebAssembly function, or when WebAssembly code needs to interact with the JavaScript environment, this compiler plays a key role in bridging the gap.

Here's a JavaScript example illustrating the interaction:

```javascript
// Assume we have a WebAssembly module loaded and instantiated
const wasmModule = ...;
const wasmInstance = ...;

// Call a WebAssembly function from JavaScript
const result = wasmInstance.exports.add(5, 10);
console.log(result); // Output: 15

// This call goes through the V8 engine. The 'wasm-compiler.cc'
// (or related parts of the compiler) is responsible for compiling
// the 'add' function in the WebAssembly module to machine code
// that can be executed efficiently.
```

In this scenario, when `wasmInstance.exports.add(5, 10)` is called, the V8 engine will utilize the WebAssembly compiler (including files like `wasm-compiler.cc`) to ensure that the WebAssembly `add` function is compiled and executed correctly within the JavaScript environment. This file is responsible for the initial stages of that compilation process.

这个C++源代码文件 `v8/src/compiler/wasm-compiler.cc` 的主要功能是**为 WebAssembly 代码构建中间表示图 (Intermediate Representation Graph)**，这是 V8 JavaScript 引擎编译 WebAssembly 代码过程中的关键步骤。更具体地说，这个文件的第一部分主要负责：

1. **定义 `WasmGraphBuilder` 类**:  这是一个核心类，提供了将 WebAssembly 指令转换为 Turbofan 图节点的接口。Turbofan 是 V8 的优化编译器。

2. **提供构建各种 WebAssembly 操作对应图节点的方法**:  `WasmGraphBuilder` 类包含了诸如 `Binop` (二元运算), `Unop` (一元运算), `Load` (加载), `Store` (存储), `Call` (调用), `Return` (返回), `Branch` (分支) 等方法，每个方法负责创建表示相应 WebAssembly 操作的图节点。

3. **处理控制流**:  提供了构建控制流结构（如循环、分支）的节点和方法，例如 `Loop`, `Merge`, `Phi`, `Branch`, `Switch` 等。

4. **处理内存访问**:  包含了加载和存储内存的方法，并考虑了字节序转换等细节。

5. **处理类型转换**:  提供了各种 WebAssembly 类型之间转换操作的实现。

6. **处理函数调用**:  包括调用 WebAssembly 函数和内置函数的方法。

7. **支持 WebAssembly 内联**:  `TryWasmInlining` 方法尝试将小的 WebAssembly 函数内联到调用者中，以提高性能。

8. **与 V8 内部组件交互**:  该文件引用了 V8 内部的编译器、代码生成器、对象模型等组件，表明它是 V8 编译流水线的一部分。

9. **处理 WebAssembly 特有的概念**:  例如实例数据（Instance Data）、引用类型（Reference Types）等。

**与 JavaScript 的关系 (及 JavaScript 示例)**

这个文件与 JavaScript 的功能紧密相关，因为它负责将 WebAssembly 代码编译成 V8 可以执行的机器码。WebAssembly 旨在作为 JavaScript 的补充，提供高性能的执行能力。

当 JavaScript 代码调用一个 WebAssembly 函数时，或者当 WebAssembly 代码需要与 JavaScript 环境交互时，这个编译器就发挥着关键作用。它确保 WebAssembly 代码能够高效地与 JavaScript 代码协同工作。

以下是一个简单的 JavaScript 示例，说明了这种关系：

```javascript
// 假设我们已经加载并实例化了一个 WebAssembly 模块
const wasmCode = await fetch('my_module.wasm');
const wasmArrayBuffer = await wasmCode.arrayBuffer();
const wasmModule = await WebAssembly.compile(wasmArrayBuffer);
const wasmInstance = await WebAssembly.instantiate(wasmModule);

// 调用 WebAssembly 模块导出的函数
const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出: 15
```

在这个例子中，当 `wasmInstance.exports.add(5, 10)` 被调用时，V8 引擎需要执行 WebAssembly 模块中名为 `add` 的函数。`v8/src/compiler/wasm-compiler.cc` (以及相关的编译文件) 的工作就是将 `add` 函数的 WebAssembly 字节码转换成 V8 可以执行的优化后的机器码。`WasmGraphBuilder` 类在这个过程中构建函数的中间表示图，为后续的优化和代码生成奠定基础。

简而言之，`v8/src/compiler/wasm-compiler.cc` 的第一部分是 WebAssembly 代码进入 V8 执行流水线的入口之一，负责将 WebAssembly 的指令翻译成 V8 优化编译器能够理解和处理的图结构，从而实现 WebAssembly 代码在 JavaScript 环境中的高效执行。

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能

"""
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
    case wasm::kExprI32AsmjsSConvertF64:
      return BuildI32AsmjsSConvertF64(input);
    case wasm::kExprI32AsmjsUConvertF64:
      return BuildI32AsmjsUConvertF64(input);
    case wasm::kExprF32ConvertF64:
      op = m->TruncateFloat64ToFloat32();
      break;
    case wasm::kExprF64SConvertI32:
      op = m->ChangeInt32ToFloat64();
      break;
    case wasm::kExprF64UConvertI32:
      op = m->ChangeUint32ToFloat64();
      break;
    case wasm::kExprF32SConvertI32:
      op = m->RoundInt32ToFloat32();
      break;
    case wasm::kExprF32UConvertI32:
      op = m->RoundUint32ToFloat32();
      break;
    case wasm::kExprI32AsmjsSConvertF32:
      return BuildI32AsmjsSConvertF32(input);
    case wasm::kExprI32AsmjsUConvertF32:
      return BuildI32AsmjsUConvertF32(input);
    case wasm::kExprF64ConvertF32:
      op = m->ChangeFloat32ToFloat64();
      break;
    case wasm::kExprF32ReinterpretI32:
      op = m->BitcastInt32ToFloat32();
      break;
    case wasm::kExprI32ReinterpretF32:
      op = m->BitcastFloat32ToInt32();
      break;
    case wasm::kExprI32Clz:
      op = m->Word32Clz();
      break;
    case wasm::kExprI32Ctz: {
      if (m->Word32Ctz().IsSupported()) {
        op = m->Word32Ctz().op();
        break;
      } else if (m->Word32ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word32ReverseBits().op(), input);
        Node* result = graph()->NewNode(m->Word32Clz(), reversed);
        return result;
      } else {
        return BuildI32Ctz(input);
      }
    }
    case wasm::kExprI32Popcnt: {
      if (m->Word32Popcnt().IsSupported()) {
        op = m->Word32Popcnt().op();
        break;
      } else {
        return BuildI32Popcnt(input);
      }
    }
    case wasm::kExprF32Floor: {
      if (!m->Float32RoundDown().IsSupported()) return BuildF32Floor(input);
      op = m->Float32RoundDown().op();
      break;
    }
    case wasm::kExprF32Ceil: {
      if (!m->Float32RoundUp().IsSupported()) return BuildF32Ceil(input);
      op = m->Float32RoundUp().op();
      break;
    }
    case wasm::kExprF32Trunc: {
      if (!m->Float32RoundTruncate().IsSupported()) return BuildF32Trunc(input);
      op = m->Float32RoundTruncate().op();
      break;
    }
    case wasm::kExprF32NearestInt: {
      if (!m->Float32RoundTiesEven().IsSupported())
        return BuildF32NearestInt(input);
      op = m->Float32RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Floor: {
      if (!m->Float64RoundDown().IsSupported()) return BuildF64Floor(input);
      op = m->Float64RoundDown().op();
      break;
    }
    case wasm::kExprF64Ceil: {
      if (!m->Float64RoundUp().IsSupported()) return BuildF64Ceil(input);
      op = m->Float64RoundUp().op();
      break;
    }
    case wasm::kExprF64Trunc: {
      if (!m->Float64RoundTruncate().IsSupported()) return BuildF64Trunc(input);
      op = m->Float64RoundTruncate().op();
      break;
    }
    case wasm::kExprF64NearestInt: {
      if (!m->Float64RoundTiesEven().IsSupported())
        return BuildF64NearestInt(input);
      op = m->Float64RoundTiesEven().op();
      break;
    }
    case wasm::kExprF64Acos: {
      return BuildF64Acos(input);
    }
    case wasm::kExprF64Asin: {
      return BuildF64Asin(input);
    }
    case wasm::kExprF64Atan:
      op = m->Float64Atan();
      break;
    case wasm::kExprF64Cos: {
      op = m->Float64Cos();
      break;
    }
    case wasm::kExprF64Sin: {
      op = m->Float64Sin();
      break;
    }
    case wasm::kExprF64Tan: {
      op = m->Float64Tan();
      break;
    }
    case wasm::kExprF64Exp: {
      op = m->Float64Exp();
      break;
    }
    case wasm::kExprF64Log:
      op = m->Float64Log();
      break;
    case wasm::kExprI32ConvertI64:
      op = m->TruncateInt64ToInt32();
      break;
    case wasm::kExprI64SConvertI32:
      op = m->ChangeInt32ToInt64();
      break;
    case wasm::kExprI64UConvertI32:
      op = m->ChangeUint32ToUint64();
      break;
    case wasm::kExprF64ReinterpretI64:
      op = m->BitcastInt64ToFloat64();
      break;
    case wasm::kExprI64ReinterpretF64:
      op = m->BitcastFloat64ToInt64();
      break;
    case wasm::kExprI64Clz:
      return m->Is64()
                 ? graph()->NewNode(m->Word64Clz(), input)
                 : graph()->NewNode(m->Word64ClzLowerable(), input, control());
    case wasm::kExprI64Ctz: {
      if (m->Word64Ctz().IsSupported()) {
        return m->Is64() ? graph()->NewNode(m->Word64Ctz().op(), input)
                         : graph()->NewNode(m->Word64CtzLowerable().op(), input,
                                            control());
      } else if (m->Is32() && m->Word32Ctz().IsSupported()) {
        return graph()->NewNode(m->Word64CtzLowerable().placeholder(), input,
                                control());
      } else if (m->Word64ReverseBits().IsSupported()) {
        Node* reversed = graph()->NewNode(m->Word64ReverseBits().op(), input);
        Node* result = m->Is64() ? graph()->NewNode(m->Word64Clz(), reversed)
                                 : graph()->NewNode(m->Word64ClzLowerable(),
                                                    reversed, control());
        return result;
      } else {
        return BuildI64Ctz(input);
      }
    }
    case wasm::kExprI64Popcnt: {
      OptionalOperator popcnt64 = m->Word64Popcnt();
      if (popcnt64.IsSupported()) {
        op = popcnt64.op();
      } else if (m->Is32() && m->Word32Popcnt().IsSupported()) {
        op = popcnt64.placeholder();
      } else {
        return BuildI64Popcnt(input);
      }
      break;
    }
    case wasm::kExprI64Eqz:
      return gasm_->Word64Equal(input, Int64Constant(0));
    case wasm::kExprF32SConvertI64:
      if (m->Is32()) {
        return BuildF32SConvertI64(input);
      }
      op = m->RoundInt64ToFloat32();
      break;
    case wasm::kExprF32UConvertI64:
      if (m->Is32()) {
        return BuildF32UConvertI64(input);
      }
      op = m->RoundUint64ToFloat32();
      break;
    case wasm::kExprF64SConvertI64:
      if (m->Is32()) {
        return BuildF64SConvertI64(input);
      }
      op = m->RoundInt64ToFloat64();
      break;
    case wasm::kExprF64UConvertI64:
      if (m->Is32()) {
        return BuildF64UConvertI64(input);
      }
      op = m->RoundUint64ToFloat64();
      break;
    case wasm::kExprI32SExtendI8:
      op = m->SignExtendWord8ToInt32();
      break;
    case wasm::kExprI32SExtendI16:
      op = m->SignExtendWord16ToInt32();
      break;
    case wasm::kExprI64SExtendI8:
      op = m->SignExtendWord8ToInt64();
      break;
    case wasm::kExprI64SExtendI16:
      op = m->SignExtendWord16ToInt64();
      break;
    case wasm::kExprI64SExtendI32:
      op = m->SignExtendWord32ToInt64();
      break;
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return mcgraph()->machine()->Is32()
                 ? BuildCcallConvertFloat(input, position, opcode)
                 : BuildIntConvertFloat(input, position, opcode);
    case wasm::kExprRefIsNull:
      return IsNull(input, type);
    // We abuse ref.as_non_null, which isn't otherwise used in this switch, as
    // a sentinel for the negation of ref.is_null.
    case wasm::kExprRefAsNonNull:
      return gasm_->Word32Equal(gasm_->Int32Constant(0), IsNull(input, type));
    case wasm::kExprI32AsmjsLoadMem8S:
      return BuildAsmjsLoadMem(MachineType::Int8(), input);
    case wasm::kExprI32AsmjsLoadMem8U:
      return BuildAsmjsLoadMem(MachineType::Uint8(), input);
    case wasm::kExprI32AsmjsLoadMem16S:
      return BuildAsmjsLoadMem(MachineType::Int16(), input);
    case wasm::kExprI32AsmjsLoadMem16U:
      return BuildAsmjsLoadMem(MachineType::Uint16(), input);
    case wasm::kExprI32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Int32(), input);
    case wasm::kExprF32AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float32(), input);
    case wasm::kExprF64AsmjsLoadMem:
      return BuildAsmjsLoadMem(MachineType::Float64(), input);
    case wasm::kExprAnyConvertExtern: {
      return gasm_->WasmAnyConvertExtern(input);
    }
    case wasm::kExprExternConvertAny:
      return gasm_->WasmExternConvertAny(input);
    default:
      FATAL_UNSUPPORTED_OPCODE(opcode);
  }
  return graph()->NewNode(op, input);
}

Node* WasmGraphBuilder::Float32Constant(float value) {
  return mcgraph()->Float32Constant(value);
}

Node* WasmGraphBuilder::Float64Constant(double value) {
  return mcgraph()->Float64Constant(value);
}

Node* WasmGraphBuilder::Simd128Constant(const uint8_t value[16]) {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->S128Const(value));
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchNoHint(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kNone);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectFalse(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kFalse);
  return {true_node, false_node};
}

std::tuple<Node*, Node*> WasmGraphBuilder::BranchExpectTrue(Node* cond) {
  Node* true_node;
  Node* false_node;
  gasm_->Branch(cond, &true_node, &false_node, BranchHint::kTrue);
  return {true_node, false_node};
}

Node* WasmGraphBuilder::Select(Node *cond, Node* true_node,
                               Node* false_node, wasm::ValueType type) {
  MachineOperatorBuilder* m = mcgraph()->machine();
  wasm::ValueKind kind = type.kind();
  // Lower to select if supported.
  if (kind == wasm::kF32 && m->Float32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float32Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kF64 && m->Float64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Float64Select().op(), cond,
                                       true_node, false_node);
  }
  if (kind == wasm::kI32 && m->Word32Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word32Select().op(), cond, true_node,
                                       false_node);
  }
  if (kind == wasm::kI64 && m->Word64Select().IsSupported()) {
    return mcgraph()->graph()->NewNode(m->Word64Select().op(), cond, true_node,
                                       false_node);
  }
  // Default to control-flow.

  auto [if_true, if_false] = BranchNoHint(cond);
  Node* merge = Merge(if_true, if_false);
  SetControl(merge);
  Node* inputs[] = {true_node, false_node, merge};
  return Phi(type, 2, inputs);
}

// TODO(ahaas): Merge TrapId with TrapReason.
TrapId WasmGraphBuilder::GetTrapIdForTrap(wasm::TrapReason reason) {
  switch (reason) {
#define TRAPREASON_TO_TRAPID(name)                                 \
  case wasm::k##name:                                              \
    static_assert(static_cast<int>(TrapId::k##name) ==             \
                      static_cast<int>(Builtin::kThrowWasm##name), \
                  "trap id mismatch");                             \
    return TrapId::k##name;
    FOREACH_WASM_TRAPREASON(TRAPREASON_TO_TRAPID)
#undef TRAPREASON_TO_TRAPID
    default:
      UNREACHABLE();
  }
}

void WasmGraphBuilder::TrapIfTrue(wasm::TrapReason reason, Node* cond,
                                  wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapIf(cond, trap_id);
  SetSourcePosition(effect(), position);
}

void WasmGraphBuilder::TrapIfFalse(wasm::TrapReason reason, Node* cond,
                                   wasm::WasmCodePosition position) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  gasm_->TrapUnless(cond, trap_id);
  SetSourcePosition(effect(), position);
}

Node* WasmGraphBuilder::AssertNotNull(Node* object, wasm::ValueType type,
                                      wasm::WasmCodePosition position,
                                      wasm::TrapReason reason) {
  TrapId trap_id = GetTrapIdForTrap(reason);
  Node* result = gasm_->AssertNotNull(object, type, trap_id);
  SetSourcePosition(result, position);
  return result;
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq32(wasm::TrapReason reason, Node* node,
                                  int32_t val,
                                  wasm::WasmCodePosition position) {
  if (val == 0) {
    TrapIfFalse(reason, node, position);
  } else {
    TrapIfTrue(reason, gasm_->Word32Equal(node, Int32Constant(val)), position);
  }
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck32(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq32(reason, node, 0, position);
}

// Add a check that traps if {node} is equal to {val}.
void WasmGraphBuilder::TrapIfEq64(wasm::TrapReason reason, Node* node,
                                  int64_t val,
                                  wasm::WasmCodePosition position) {
  TrapIfTrue(reason, gasm_->Word64Equal(node, Int64Constant(val)), position);
}

// Add a check that traps if {node} is zero.
void WasmGraphBuilder::ZeroCheck64(wasm::TrapReason reason, Node* node,
                                   wasm::WasmCodePosition position) {
  TrapIfEq64(reason, node, 0, position);
}

Node* WasmGraphBuilder::Switch(unsigned count, Node* key) {
  // The instruction selector will use {kArchTableSwitch} for large switches,
  // which has limited input count, see {InstructionSelector::EmitTableSwitch}.
  DCHECK_LE(count, Instruction::kMaxInputCount - 2);          // value_range + 2
  DCHECK_LE(count, wasm::kV8MaxWasmFunctionBrTableSize + 1);  // plus IfDefault
  return graph()->NewNode(mcgraph()->common()->Switch(count), key, control());
}

Node* WasmGraphBuilder::IfValue(int32_t value, Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfValue(value), sw);
}

Node* WasmGraphBuilder::IfDefault(Node* sw) {
  DCHECK_EQ(IrOpcode::kSwitch, sw->opcode());
  return graph()->NewNode(mcgraph()->common()->IfDefault(), sw);
}

Node* WasmGraphBuilder::Return(base::Vector<Node*> vals) {
  unsigned count = static_cast<unsigned>(vals.size());
  base::SmallVector<Node*, 8> buf(count + 3);

  // TODOC: What is the meaning of the 0-constant?
  buf[0] = Int32Constant(0);
  if (count > 0) {
    memcpy(buf.data() + 1, vals.begin(), sizeof(void*) * count);
  }
  buf[count + 1] = effect();
  buf[count + 2] = control();
  Node* ret = graph()->NewNode(mcgraph()->common()->Return(count), count + 3,
                               buf.data());

  gasm_->MergeControlToEnd(ret);
  return ret;
}

void WasmGraphBuilder::Trap(wasm::TrapReason reason,
                            wasm::WasmCodePosition position) {
  TrapIfFalse(reason, Int32Constant(0), position);
  // Connect control to end via a Throw() node.
  TerminateThrow(effect(), control());
}

Node* WasmGraphBuilder::MaskShiftCount32(Node* node) {
  static const int32_t kMask32 = 0x1F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int32Matcher match(node);
    if (match.HasResolvedValue()) {
      int32_t masked = (match.ResolvedValue() & kMask32);
      if (match.ResolvedValue() != masked) node = Int32Constant(masked);
    } else {
      node = gasm_->Word32And(node, Int32Constant(kMask32));
    }
  }
  return node;
}

Node* WasmGraphBuilder::MaskShiftCount64(Node* node) {
  static const int64_t kMask64 = 0x3F;
  if (!mcgraph()->machine()->Word32ShiftIsSafe()) {
    // Shifts by constants are so common we pattern-match them here.
    Int64Matcher match(node);
    if (match.HasResolvedValue()) {
      int64_t masked = (match.ResolvedValue() & kMask64);
      if (match.ResolvedValue() != masked) node = Int64Constant(masked);
    } else {
      node = gasm_->Word64And(node, Int64Constant(kMask64));
    }
  }
  return node;
}

namespace {

bool ReverseBytesSupported(MachineOperatorBuilder* m, size_t size_in_bytes) {
  switch (size_in_bytes) {
    case 4:
    case 16:
      return true;
    case 8:
      return m->Is64();
    default:
      break;
  }
  return false;
}

}  // namespace

Node* WasmGraphBuilder::BuildChangeEndiannessStore(
    Node* node, MachineRepresentation mem_rep, wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = wasmtype.value_kind_size();
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (wasmtype.kind()) {
    case wasm::kF64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI64:
      result = Int64Constant(0);
      break;
    case wasm::kF32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case wasm::kI32:
      result = Int32Constant(0);
      break;
    case wasm::kS128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  if (mem_rep == MachineRepresentation::kWord8) {
    // No need to change endianness for byte size, return original node
    return node;
  }
  if (wasmtype == wasm::kWasmI64 && mem_rep < MachineRepresentation::kWord64) {
    // In case we store lower part of WasmI64 expression, we can truncate
    // upper 32bits
    value = gasm_->TruncateInt64ToInt32(value);
    valueSizeInBytes = wasm::kWasmI32.value_kind_size();
    valueSizeInBits = 8 * valueSizeInBytes;
    if (mem_rep == MachineRepresentation::kWord16) {
      value = gasm_->Word32Shl(value, Int32Constant(16));
    }
  } else if (wasmtype == wasm::kWasmI32 &&
             mem_rep == MachineRepresentation::kWord16) {
    value = gasm_->Word32Shl(value, Int32Constant(16));
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64Constant(static_cast<uint64_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word64And(
            shiftHigher, Int64Constant(static_cast<uint64_t>(0xFF) << i));
        result = gasm_->Word64Or(result, lowerByte);
        result = gasm_->Word64Or(result, higherByte);
      } else {
        shiftLower = gasm_->Word32Shl(value, Int32Constant(shiftCount));
        shiftHigher = gasm_->Word32Shr(value, Int32Constant(shiftCount));
        lowerByte = gasm_->Word32And(
            shiftLower, Int32Constant(static_cast<uint32_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word32And(
            shiftHigher, Int32Constant(static_cast<uint32_t>(0xFF) << i));
        result = gasm_->Word32Or(result, lowerByte);
        result = gasm_->Word32Or(result, higherByte);
      }
    }
  }

  if (isFloat) {
    switch (wasmtype.kind()) {
      case wasm::kF64:
        result = gasm_->BitcastInt64ToFloat64(result);
        break;
      case wasm::kF32:
        result = gasm_->BitcastInt32ToFloat32(result);
        break;
      default:
        UNREACHABLE();
    }
  }

  return result;
}

Node* WasmGraphBuilder::BuildChangeEndiannessLoad(Node* node,
                                                  MachineType memtype,
                                                  wasm::ValueType wasmtype) {
  Node* result;
  Node* value = node;
  MachineOperatorBuilder* m = mcgraph()->machine();
  int valueSizeInBytes = ElementSizeInBytes(memtype.representation());
  int valueSizeInBits = 8 * valueSizeInBytes;
  bool isFloat = false;

  switch (memtype.representation()) {
    case MachineRepresentation::kFloat64:
      value = gasm_->BitcastFloat64ToInt64(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord64:
      result = Int64Constant(0);
      break;
    case MachineRepresentation::kFloat32:
      value = gasm_->BitcastFloat32ToInt32(node);
      isFloat = true;
      [[fallthrough]];
    case MachineRepresentation::kWord32:
    case MachineRepresentation::kWord16:
      result = Int32Constant(0);
      break;
    case MachineRepresentation::kWord8:
      // No need to change endianness for byte size, return original node
      return node;
    case MachineRepresentation::kSimd128:
      DCHECK(ReverseBytesSupported(m, valueSizeInBytes));
      break;
    default:
      UNREACHABLE();
  }

  int i;
  uint32_t shiftCount;

  if (ReverseBytesSupported(m, valueSizeInBytes < 4 ? 4 : valueSizeInBytes)) {
    switch (valueSizeInBytes) {
      case 2:
        result = gasm_->Word32ReverseBytes(
            gasm_->Word32Shl(value, Int32Constant(16)));
        break;
      case 4:
        result = gasm_->Word32ReverseBytes(value);
        break;
      case 8:
        result = gasm_->Word64ReverseBytes(value);
        break;
      case 16:
        result = graph()->NewNode(m->Simd128ReverseBytes(), value);
        break;
      default:
        UNREACHABLE();
    }
  } else {
    for (i = 0, shiftCount = valueSizeInBits - 8; i < valueSizeInBits / 2;
         i += 8, shiftCount -= 16) {
      Node* shiftLower;
      Node* shiftHigher;
      Node* lowerByte;
      Node* higherByte;

      DCHECK_LT(0, shiftCount);
      DCHECK_EQ(0, (shiftCount + 8) % 16);

      if (valueSizeInBits > 32) {
        shiftLower = gasm_->Word64Shl(value, Int64Constant(shiftCount));
        shiftHigher = gasm_->Word64Shr(value, Int64Constant(shiftCount));
        lowerByte = gasm_->Word64And(
            shiftLower, Int64Constant(static_cast<uint64_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word64And(
            shiftHigher, Int64Constant(static_cast<uint64_t>(0xFF) << i));
        result = gasm_->Word64Or(result, lowerByte);
        result = gasm_->Word64Or(result, higherByte);
      } else {
        shiftLower = gasm_->Word32Shl(value, Int32Constant(shiftCount));
        shiftHigher = gasm_->Word32Shr(value, Int32Constant(shiftCount));
        lowerByte = gasm_->Word32And(
            shiftLower, Int32Constant(static_cast<uint32_t>(0xFF)
                                      << (valueSizeInBits - 8 - i)));
        higherByte = gasm_->Word32And(
            shiftHigher, Int32Constant(static_cast<uint32_t>(0xFF) << i));
        result = gasm_->Word32Or(result, lowerByte);
        result = gasm_->Word32Or(result, higherByte);
      }
    }
  }

  if (isFloat) {
    switch (memtype.representation()) {
      case MachineRepresentation::kFloat64:
        result = gasm_->BitcastInt64ToFloat64(result);
        break;
      case MachineRepresentation::kFloat32:
        result = gasm_->BitcastInt32ToFloat32(result);
        break;
      default:
        UNREACHABLE();
    }
  }

  // We need to sign or zero extend the value
  if (memtype.IsSigned()) {
    DCHECK(!isFloat);
    if (valueSizeInBits < 32) {
      Node* shiftBitCount;
      // Perform sign extension using following trick
      // result = (x << machine_width - type_width) >> (machine_width -
      // type_width)
      if (wasmtype == wasm::kWasmI64) {
        shiftBitCount = Int32Constant(64 - valueSizeInBits);
        result = gasm_->Word64Sar(
            gasm_->Word64Shl(gasm_->ChangeInt32ToInt64(result), shiftBitCount),
            shiftBitCount);
      } else if (wasmtype == wasm::kWasmI32) {
        shiftBitCount = Int32Constant(32 - valueSizeInBits);
        result = gasm_->Word32Sar(gasm_->Word32Shl(result, shiftBitCount),
                                  shiftBitCount);
      }
    }
  } else if (wasmtype == wasm::kWasmI64 && valueSizeInBits < 64) {
    result = gasm_->ChangeUint32ToUint64(result);
  }

  return result;
}

Node* WasmGraphBuilder::BuildF32CopySign(Node* left, Node* right) {
  Node* result = Unop(
      wasm::kExprF32ReinterpretI32,
      Binop(wasm::kExprI32Ior,
            Binop(wasm::kExprI32And, Unop(wasm::kExprI32ReinterpretF32, left),
                  Int32Constant(0x7FFFFFFF)),
            Binop(wasm::kExprI32And, Unop(wasm::kExprI32ReinterpretF32, right),
                  Int32Constant(0x80000000))));

  return result;
}

Node* WasmGraphBuilder::BuildF64CopySign(Node* left, Node* right) {
  if (mcgraph()->machine()->Is64()) {
    return gasm_->BitcastInt64ToFloat64(
        gasm_->Word64Or(gasm_->Word64And(gasm_->BitcastFloat64ToInt64(left),
                                         Int64Constant(0x7FFFFFFFFFFFFFFF)),
                        gasm_->Word64And(gasm_->BitcastFloat64ToInt64(right),
                                         Int64Constant(0x8000000000000000))));
  }

  DCHECK(mcgraph()->machine()->Is32());

  Node* high_word_left = gasm_->Float64ExtractHighWord32(left);
  Node* high_word_right = gasm_->Float64ExtractHighWord32(right);

  Node* new_high_word = gasm_->Word32Or(
      gasm_->Word32And(high_word_left, Int32Constant(0x7FFFFFFF)),
      gasm_->Word32And(high_word_right, Int32Constant(0x80000000)));

  return gasm_->Float64InsertHighWord32(left, new_high_word);
}

namespace {

MachineType IntConvertType(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI32SConvertSatF64:
      return MachineType::Int32();
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI32UConvertSatF64:
      return MachineType::Uint32();
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
      return MachineType::Int64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64UConvertSatF64:
      return MachineType::Uint64();
    default:
      UNREACHABLE();
  }
}

MachineType FloatConvertType(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
      return MachineType::Float32();
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI32SConvertSatF64:
    case wasm::kExprI32UConvertSatF64:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return MachineType::Float64();
    default:
      UNREACHABLE();
  }
}

const Operator* ConvertOp(WasmGraphBuilder* builder, wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToInt32(
          TruncateKind::kSetOverflowToMin);
    case wasm::kExprI32SConvertSatF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToInt32(
          TruncateKind::kArchitectureDefault);
    case wasm::kExprI32UConvertF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToUint32(
          TruncateKind::kSetOverflowToMin);
    case wasm::kExprI32UConvertSatF32:
      return builder->mcgraph()->machine()->TruncateFloat32ToUint32(
          TruncateKind::kArchitectureDefault);
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF64:
      return builder->mcgraph()->machine()->ChangeFloat64ToInt32();
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF64:
      return builder->mcgraph()->machine()->TruncateFloat64ToUint32();
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64SConvertSatF32:
      return builder->mcgraph()->machine()->TryTruncateFloat32ToInt64();
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64UConvertSatF32:
      return builder->mcgraph()->machine()->TryTruncateFloat32ToUint64();
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64SConvertSatF64:
      return builder->mcgraph()->machine()->TryTruncateFloat64ToInt64();
    case wasm::kExprI64UConvertF64:
    case wasm::kExprI64UConvertSatF64:
      return builder->mcgraph()->machine()->TryTruncateFloat64ToUint64();
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode ConvertBackOp(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32SConvertSatF32:
      return wasm::kExprF32SConvertI32;
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32UConvertSatF32:
      return wasm::kExprF32UConvertI32;
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32SConvertSatF64:
      return wasm::kExprF64SConvertI32;
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI32UConvertSatF64:
      return wasm::kExprF64UConvertI32;
    default:
      UNREACHABLE();
  }
}

bool IsTrappingConvertOp(wasm::WasmOpcode opcode) {
  switch (opcode) {
    case wasm::kExprI32SConvertF32:
    case wasm::kExprI32UConvertF32:
    case wasm::kExprI32SConvertF64:
    case wasm::kExprI32UConvertF64:
    case wasm::kExprI64SConvertF32:
    case wasm::kExprI64UConvertF32:
    case wasm::kExprI64SConvertF64:
    case wasm::kExprI64UConvertF64:
      return true;
    case wasm::kExprI32SConvertSatF64:
    case wasm::kExprI32UConvertSatF64:
    case wasm::kExprI32SConvertSatF32:
    case wasm::kExprI32UConvertSatF32:
    case wasm::kExprI64SConvertSatF32:
    case wasm::kExprI64UConvertSatF32:
    case wasm::kExprI64SConvertSatF64:
    case wasm::kExprI64UConvertSatF64:
      return false;
    default:
      UNREACHABLE();
  }
}

Node* Zero(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kWord32:
      return builder->Int32Constant(0);
    case MachineRepresentation::kWord64:
      return builder->Int64Constant(0);
    case MachineRepresentation::kFloat32:
      return builder->Float32Constant(0.0);
    case MachineRepresentation::kFloat64:
      return builder->Float64Constant(0.0);
    default:
      UNREACHABLE();
  }
}

Node* Min(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.semantic()) {
    case MachineSemantic::kInt32:
      return builder->Int32Constant(std::numeric_limits<int32_t>::min());
    case MachineSemantic::kUint32:
      return builder->Int32Constant(std::numeric_limits<uint32_t>::min());
    case MachineSemantic::kInt64:
      return builder->Int64Constant(std::numeric_limits<int64_t>::min());
    case MachineSemantic::kUint64:
      return builder->Int64Constant(std::numeric_limits<uint64_t>::min());
    default:
      UNREACHABLE();
  }
}

Node* Max(WasmGraphBuilder* builder, const MachineType& ty) {
  switch (ty.semantic()) {
    case MachineSemantic::kInt32:
      return builder->Int32Constant(std::numeric_limits<int32_t>::max());
    case MachineSemantic::kUint32:
      return builder->Int32Constant(std::numeric_limits<uint32_t>::max());
    case MachineSemantic::kInt64:
      return builder->Int64Constant(std::numeric_limits<int64_t>::max());
    case MachineSemantic::kUint64:
      return builder->Int64Constant(std::numeric_limits<uint64_t>::max());
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode TruncOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Trunc;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF64Trunc;
    default:
      UNREACHABLE();
  }
}

wasm::WasmOpcode NeOp(const MachineType& ty) {
  switch (ty.representation()) {
    case MachineRepresentation::kFloat32:
      return wasm::kExprF32Ne;
    case MachineRepresentation::kFloat64:
      return wasm::kExprF6
"""


```
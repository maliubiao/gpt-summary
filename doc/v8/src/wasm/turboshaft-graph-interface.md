Response: The user wants me to summarize the functionality of the provided C++ code snippet.
This is the first part of a larger file, so I should focus on the functionality present in this section.
The code seems to be related to the Turboshaft compiler in V8, specifically for handling WebAssembly.
It defines a class `TurboshaftGraphBuildingInterface` that inherits from `WasmGraphBuilderBase`.
This class appears to be responsible for translating WebAssembly bytecode into Turboshaft's intermediate representation (IR).

Key aspects I can identify:
- Includes necessary headers for Turboshaft and WebAssembly.
- Defines type aliases for better readability.
- Implements methods for handling various WebAssembly operations, such as:
    - Function calls (runtime and built-in).
    - Memory access (loads and stores).
    - Control flow (blocks, loops, if statements, branches).
    - Local and global variable access.
    - Constants.
    - Conversions.
    - SIMD operations.
    - Memory management (current memory size, memory growth).
- Uses Turboshaft's graph building API (e.g., `__ NewBlock()`, `__ Goto()`, `__ Call()`, `__ Load()`, `__ Store()`).
- Handles both regular and inlined function compilation.
- Includes logic for bounds checking and endianness conversion for memory operations.
- Contains debug code and tracing functionalities.

Regarding the relationship with JavaScript:
- This C++ code is part of the V8 JavaScript engine, which executes JavaScript code.
- When JavaScript code calls WebAssembly functions, V8 uses this kind of code to compile the WebAssembly into efficient machine code.
- Some built-in JavaScript functionalities might have corresponding built-in WebAssembly functions or runtime calls handled by this code.

For the JavaScript example, I can think of demonstrating how a simple JavaScript function interacting with WebAssembly relates to the underlying C++ logic.
这个C++代码文件是V8 JavaScript引擎中用于将WebAssembly代码编译成Turboshaft图表示的接口实现的第一部分。 `TurboshaftGraphBuildingInterface` 类负责遍历WebAssembly字节码，并将其转换为Turboshaft编译器能够理解的操作和控制流图。

主要功能可以归纳为：

1. **定义了将WebAssembly操作映射到Turboshaft图节点的机制。**  类中包含了处理各种WebAssembly指令的方法，例如 `I32Const`, `LocalGet`, `StoreMem`, `CallRuntime`, `Br`, `If` 等。每个方法都会生成相应的Turboshaft操作节点。

2. **管理编译过程中的状态。** 它维护了局部变量的状态 (`ssa_env_`)，控制流块的信息 (`Control` 结构体)，以及用于内联优化的相关数据。

3. **处理函数调用。**  它能够处理调用JavaScript运行时函数 (`CallRuntime`) 和内置函数 (`GetTargetForBuiltinCall`, `CallBuiltinThroughJumptable`)，也包括调用导入的函数。

4. **处理内存访问。** 包含了加载 (`LoadMem`, `LoadTransform`, `LoadLane`) 和存储 (`StoreMem`, `StoreLane`) WebAssembly线性内存的操作，并实现了 bounds checking 和 endianness 转换。

5. **处理控制流。** 实现了块 (`Block`)、循环 (`Loop`)、条件分支 (`If`, `Else`, `BrIf`) 和跳转表 (`BrTable`) 的逻辑。

6. **支持内联。** 该接口既可以用于编译顶层WebAssembly函数，也可以用于编译内联的函数。

7. **进行类型转换。** 例如 `BuildChangeInt64ToBigInt` 将64位整数转换为BigInt。

8. **包含调试和跟踪功能。** 例如 `BuildModifyThreadInWasmFlag` 和对 `v8_flags.trace_wasm` 的检查。

**与 JavaScript 的关系和 JavaScript 示例：**

这段C++代码是V8引擎处理WebAssembly的核心部分。当JavaScript代码加载并执行WebAssembly模块时，V8会使用这个接口将WebAssembly代码编译成高效的机器码。

例如，考虑以下简单的 JavaScript 代码：

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type section (i32, i32) => i32
  0x03, 0x02, 0x01, 0x00,                            // function section (function 0 is of type 0)
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // code section (local.get 0, local.get 1, i32.add, end)
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);

const result = wasmInstance.exports.add(5, 10);
console.log(result); // 输出 15
```

在这个 JavaScript 示例中，我们定义了一个简单的 WebAssembly 模块，它包含一个名为 `add` 的函数，该函数接受两个 i32 类型的参数并返回它们的和。

当 V8 执行 `new WebAssembly.Instance(wasmModule)` 时，引擎会解析 WebAssembly 字节码。对于 `add` 函数的字节码 `0x20 0x00 0x20 0x01 0x6a 0x0b` (分别对应 `local.get 0`, `local.get 1`, `i32.add`, `end`)，`TurboshaftGraphBuildingInterface` 中的方法将会被调用，例如：

- 当遇到 `0x20 0x00` (`local.get 0`) 时，`LocalGet` 方法会被调用，它会创建一个 Turboshaft 节点来获取第一个局部变量的值。
- 当遇到 `0x20 0x01` (`local.get 1`) 时，`LocalGet` 方法再次被调用，创建节点获取第二个局部变量的值。
- 当遇到 `0x6a` (`i32.add`) 时，`BinOp` 方法会被调用，它会创建一个 Turboshaft 节点来执行 i32 类型的加法操作，并将之前获取的局部变量值作为输入。
- 当遇到 `0x0b` (`end`) 时，可能涉及到控制流的结束处理。

最终，`TurboshaftGraphBuildingInterface` 会构建一个表示 `add` 函数逻辑的 Turboshaft 图，这个图随后会被 Turboshaft 编译器进一步优化并生成机器码，从而使得 `wasmInstance.exports.add(5, 10)` 能够高效地执行。

总结来说，这个C++文件定义了 V8 中 WebAssembly 代码编译到 Turboshaft 图表示的关键接口，是 JavaScript 能够执行 WebAssembly 代码的基础。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/turboshaft-graph-interface.h"

#include <optional>

#include "absl/container/btree_map.h"
#include "include/v8-fast-api-calls.h"
#include "src/base/logging.h"
#include "src/builtins/builtins.h"
#include "src/builtins/data-view-ops.h"
#include "src/common/globals.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/builtin-call-descriptors.h"
#include "src/compiler/turboshaft/graph.h"
#include "src/compiler/turboshaft/wasm-assembler-helpers.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/objects/object-list-macros.h"
#include "src/objects/torque-defined-classes.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/function-compiler.h"
#include "src/wasm/inlining-tree.h"
#include "src/wasm/jump-table-assembler.h"
#include "src/wasm/memory-tracing.h"
#include "src/wasm/signature-hashing.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects-inl.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes-inl.h"

namespace v8::internal::wasm {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

using compiler::AccessBuilder;
using compiler::CallDescriptor;
using compiler::MemoryAccessKind;
using compiler::Operator;
using compiler::TrapId;
using TSBlock = compiler::turboshaft::Block;
using compiler::turboshaft::BuiltinCallDescriptor;
using compiler::turboshaft::CallOp;
using compiler::turboshaft::ConditionWithHint;
using compiler::turboshaft::ConstantOp;
using compiler::turboshaft::ConstOrV;
using compiler::turboshaft::DidntThrowOp;
using compiler::turboshaft::Float32;
using compiler::turboshaft::Float64;
using compiler::turboshaft::FrameState;
using compiler::turboshaft::Graph;
using compiler::turboshaft::Label;
using compiler::turboshaft::LoadOp;
using compiler::turboshaft::LoopLabel;
using compiler::turboshaft::MemoryRepresentation;
using compiler::turboshaft::OpEffects;
using compiler::turboshaft::Operation;
using compiler::turboshaft::OperationMatcher;
using compiler::turboshaft::OpIndex;
using compiler::turboshaft::OptionalOpIndex;
using compiler::turboshaft::OptionalV;
using compiler::turboshaft::PendingLoopPhiOp;
using compiler::turboshaft::RegisterRepresentation;
using compiler::turboshaft::Simd128ConstantOp;
using compiler::turboshaft::StoreOp;
using compiler::turboshaft::StringOrNull;
using compiler::turboshaft::SupportedOperations;
using compiler::turboshaft::Tuple;
using compiler::turboshaft::V;
using compiler::turboshaft::Variable;
using compiler::turboshaft::WasmArrayNullable;
using compiler::turboshaft::WasmCodePtr;
using compiler::turboshaft::WasmStackCheckOp;
using compiler::turboshaft::WasmStringRefNullable;
using compiler::turboshaft::WasmStructNullable;
using compiler::turboshaft::WasmTypeAnnotationOp;
using compiler::turboshaft::WasmTypeCastOp;
using compiler::turboshaft::Word32;
using compiler::turboshaft::WordPtr;
using compiler::turboshaft::WordRepresentation;

namespace {

ExternalArrayType GetExternalArrayType(DataViewOp op_type) {
  switch (op_type) {
#define V(Name)                \
  case DataViewOp::kGet##Name: \
  case DataViewOp::kSet##Name: \
    return kExternal##Name##Array;
    DATAVIEW_OP_LIST(V)
#undef V
    case DataViewOp::kByteLength:
      UNREACHABLE();
  }
}

size_t GetTypeSize(DataViewOp op_type) {
  ExternalArrayType array_type = GetExternalArrayType(op_type);
  switch (array_type) {
#define ELEMENTS_KIND_TO_ELEMENT_SIZE(Type, type, TYPE, ctype) \
  case kExternal##Type##Array:                                 \
    return sizeof(ctype);

    TYPED_ARRAYS(ELEMENTS_KIND_TO_ELEMENT_SIZE)
#undef ELEMENTS_KIND_TO_ELEMENT_SIZE
  }
}

bool ReverseBytesSupported(size_t size_in_bytes) {
  switch (size_in_bytes) {
    case 4:
    case 16:
      return true;
    case 8:
      return Is64();
    default:
      return false;
  }
}

}  // namespace

// TODO(14108): Annotate runtime functions as not having side effects
// where appropriate.
OpIndex WasmGraphBuilderBase::CallRuntime(
    Zone* zone, Runtime::FunctionId f,
    std::initializer_list<const OpIndex> args, V<Context> context) {
  const Runtime::Function* fun = Runtime::FunctionForId(f);
  OpIndex isolate_root = __ LoadRootRegister();
  DCHECK_EQ(1, fun->result_size);
  int builtin_slot_offset = IsolateData::BuiltinSlotOffset(
      Builtin::kCEntry_Return1_ArgvOnStack_NoBuiltinExit);
  OpIndex centry_stub =
      __ Load(isolate_root, LoadOp::Kind::RawAligned(),
              MemoryRepresentation::UintPtr(), builtin_slot_offset);
  // CallRuntime is always called with 0 or 1 argument, so a vector of size 4
  // always suffices.
  SmallZoneVector<OpIndex, 4> centry_args(zone);
  for (OpIndex arg : args) centry_args.emplace_back(arg);
  centry_args.emplace_back(__ ExternalConstant(ExternalReference::Create(f)));
  centry_args.emplace_back(__ Word32Constant(fun->nargs));
  centry_args.emplace_back(context);
  const CallDescriptor* call_descriptor =
      compiler::Linkage::GetRuntimeCallDescriptor(
          __ graph_zone(), f, fun->nargs, Operator::kNoProperties,
          CallDescriptor::kNoFlags);
  const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
      call_descriptor, compiler::CanThrow::kYes,
      compiler::LazyDeoptOnThrow::kNo, __ graph_zone());
  return __ Call(centry_stub, OpIndex::Invalid(), base::VectorOf(centry_args),
                 ts_call_descriptor);
}

OpIndex WasmGraphBuilderBase::GetBuiltinPointerTarget(Builtin builtin) {
  static_assert(std::is_same<Smi, BuiltinPtr>(), "BuiltinPtr must be Smi");
  return __ SmiConstant(Smi::FromInt(static_cast<int>(builtin)));
}

V<WordPtr> WasmGraphBuilderBase::GetTargetForBuiltinCall(
    Builtin builtin, StubCallMode stub_mode) {
  return stub_mode == StubCallMode::kCallWasmRuntimeStub
             ? __ RelocatableWasmBuiltinCallTarget(builtin)
             : GetBuiltinPointerTarget(builtin);
}

V<BigInt> WasmGraphBuilderBase::BuildChangeInt64ToBigInt(
    V<Word64> input, StubCallMode stub_mode) {
  Builtin builtin = Is64() ? Builtin::kI64ToBigInt : Builtin::kI32PairToBigInt;
  V<WordPtr> target = GetTargetForBuiltinCall(builtin, stub_mode);
  CallInterfaceDescriptor interface_descriptor =
      Builtins::CallInterfaceDescriptorFor(builtin);
  const CallDescriptor* call_descriptor =
      compiler::Linkage::GetStubCallDescriptor(
          __ graph_zone(),  // zone
          interface_descriptor,
          0,                         // stack parameter count
          CallDescriptor::kNoFlags,  // flags
          Operator::kNoProperties,   // properties
          stub_mode);
  const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
      call_descriptor, compiler::CanThrow::kNo, compiler::LazyDeoptOnThrow::kNo,
      __ graph_zone());
  if constexpr (Is64()) {
    return V<BigInt>::Cast(__ Call(target, {input}, ts_call_descriptor));
  }
  V<Word32> low_word = __ TruncateWord64ToWord32(input);
  V<Word32> high_word = __ TruncateWord64ToWord32(__ ShiftRightLogical(
      input, __ Word32Constant(32), WordRepresentation::Word64()));
  return V<BigInt>::Cast(
      __ Call(target, {low_word, high_word}, ts_call_descriptor));
}

std::pair<V<WasmCodePtr>, V<HeapObject>>
WasmGraphBuilderBase::BuildImportedFunctionTargetAndImplicitArg(
    ConstOrV<Word32> func_index,
    V<WasmTrustedInstanceData> trusted_instance_data) {
  V<WasmDispatchTable> dispatch_table = LOAD_IMMUTABLE_PROTECTED_INSTANCE_FIELD(
      trusted_instance_data, DispatchTableForImports, WasmDispatchTable);
  // Handle constant indexes specially to reduce graph size, even though later
  // optimization would optimize this to the same result.
  if (func_index.is_constant()) {
    int offset = WasmDispatchTable::OffsetOf(func_index.constant_value());
    V<WasmCodePtr> target = __ Load(dispatch_table, LoadOp::Kind::TaggedBase(),
                                    MemoryRepresentation::WasmCodePointer(),
                                    offset + WasmDispatchTable::kTargetBias);
    V<ExposedTrustedObject> implicit_arg =
        V<ExposedTrustedObject>::Cast(__ LoadProtectedPointerField(
            dispatch_table, LoadOp::Kind::TaggedBase(),
            offset + WasmDispatchTable::kImplicitArgBias));
    return {target, implicit_arg};
  }

  V<WordPtr> dispatch_table_entry_offset =
      __ WordPtrMul(__ ChangeUint32ToUintPtr(func_index.value()),
                    WasmDispatchTable::kEntrySize);
  V<WasmCodePtr> target = __ Load(
      dispatch_table, dispatch_table_entry_offset, LoadOp::Kind::TaggedBase(),
      MemoryRepresentation::WasmCodePointer(),
      WasmDispatchTable::kEntriesOffset + WasmDispatchTable::kTargetBias);
  V<ExposedTrustedObject> implicit_arg = V<ExposedTrustedObject>::Cast(
      __ LoadProtectedPointerField(dispatch_table, dispatch_table_entry_offset,
                                   LoadOp::Kind::TaggedBase(),
                                   WasmDispatchTable::kEntriesOffset +
                                       WasmDispatchTable::kImplicitArgBias,
                                   0));
  return {target, implicit_arg};
}

std::pair<V<WasmCodePtr>, V<ExposedTrustedObject>>
WasmGraphBuilderBase::BuildFunctionTargetAndImplicitArg(
    V<WasmInternalFunction> internal_function, uint64_t expected_sig_hash) {
  V<ExposedTrustedObject> implicit_arg =
      V<ExposedTrustedObject>::Cast(__ LoadProtectedPointerField(
          internal_function, LoadOp::Kind::TaggedBase().Immutable(),
          WasmInternalFunction::kProtectedImplicitArgOffset));

#if V8_ENABLE_SANDBOX
  V<Word64> actual_sig_hash =
      __ Load(internal_function, LoadOp::Kind::TaggedBase(),
              MemoryRepresentation::Uint64(),
              WasmInternalFunction::kSignatureHashOffset);
  IF_NOT (LIKELY(__ Word64Equal(actual_sig_hash, expected_sig_hash))) {
    auto sig = FixedSizeSignature<MachineType>::Params(MachineType::AnyTagged(),
                                                       MachineType::Uint64());
    CallC(&sig, ExternalReference::wasm_signature_check_fail(),
          {internal_function, __ Word64Constant(expected_sig_hash)});
    __ Unreachable();
  }
#endif

  V<WasmCodePtr> target = __ Load(internal_function, LoadOp::Kind::TaggedBase(),
                                  MemoryRepresentation::WasmCodePointer(),
                                  WasmInternalFunction::kCallTargetOffset);

  return {target, implicit_arg};
}

RegisterRepresentation WasmGraphBuilderBase::RepresentationFor(
    ValueTypeBase type) {
  switch (type.kind()) {
    case kI8:
    case kI16:
    case kI32:
      return RegisterRepresentation::Word32();
    case kI64:
      return RegisterRepresentation::Word64();
    case kF16:
    case kF32:
      return RegisterRepresentation::Float32();
    case kF64:
      return RegisterRepresentation::Float64();
    case kRefNull:
    case kRef:
      return RegisterRepresentation::Tagged();
    case kS128:
      return RegisterRepresentation::Simd128();
    case kVoid:
    case kRtt:
    case kTop:
    case kBottom:
      UNREACHABLE();
  }
}

// Load the trusted data from a WasmInstanceObject.
V<WasmTrustedInstanceData>
WasmGraphBuilderBase::LoadTrustedDataFromInstanceObject(
    V<HeapObject> instance_object) {
  return V<WasmTrustedInstanceData>::Cast(__ LoadTrustedPointerField(
      instance_object, LoadOp::Kind::TaggedBase().Immutable(),
      kWasmTrustedInstanceDataIndirectPointerTag,
      WasmInstanceObject::kTrustedDataOffset));
}

void WasmGraphBuilderBase::BuildModifyThreadInWasmFlagHelper(
    Zone* zone, OpIndex thread_in_wasm_flag_address, bool new_value) {
  if (v8_flags.debug_code) {
    V<Word32> flag_value =
        __ Load(thread_in_wasm_flag_address, LoadOp::Kind::RawAligned(),
                MemoryRepresentation::Int32(), 0);

    IF (UNLIKELY(__ Word32Equal(flag_value, new_value))) {
      OpIndex message_id = __ TaggedIndexConstant(static_cast<int32_t>(
          new_value ? AbortReason::kUnexpectedThreadInWasmSet
                    : AbortReason::kUnexpectedThreadInWasmUnset));
      CallRuntime(zone, Runtime::kAbort, {message_id}, __ NoContextConstant());
      __ Unreachable();
    }
  }

  __ Store(thread_in_wasm_flag_address, __ Word32Constant(new_value),
           LoadOp::Kind::RawAligned(), MemoryRepresentation::Int32(),
           compiler::kNoWriteBarrier);
}

void WasmGraphBuilderBase::BuildModifyThreadInWasmFlag(Zone* zone,
                                                       bool new_value) {
  if (!trap_handler::IsTrapHandlerEnabled()) return;

  OpIndex isolate_root = __ LoadRootRegister();
  OpIndex thread_in_wasm_flag_address =
      __ Load(isolate_root, LoadOp::Kind::RawAligned().Immutable(),
              MemoryRepresentation::UintPtr(),
              Isolate::thread_in_wasm_flag_address_offset());
  BuildModifyThreadInWasmFlagHelper(zone, thread_in_wasm_flag_address,
                                    new_value);
}

// TODO(14108): Annotate C functions as not having side effects where
// appropriate.
OpIndex WasmGraphBuilderBase::CallC(const MachineSignature* sig,
                                    ExternalReference ref,
                                    std::initializer_list<OpIndex> args) {
  return WasmGraphBuilderBase::CallC(sig, __ ExternalConstant(ref), args);
}

OpIndex WasmGraphBuilderBase::CallC(const MachineSignature* sig,
                                    OpIndex function,
                                    std::initializer_list<OpIndex> args) {
  DCHECK_LE(sig->return_count(), 1);
  DCHECK_EQ(sig->parameter_count(), args.size());
  const CallDescriptor* call_descriptor =
      compiler::Linkage::GetSimplifiedCDescriptor(__ graph_zone(), sig);
  const TSCallDescriptor* ts_call_descriptor = TSCallDescriptor::Create(
      call_descriptor, compiler::CanThrow::kNo, compiler::LazyDeoptOnThrow::kNo,
      __ graph_zone());
  return __ Call(function, OpIndex::Invalid(), base::VectorOf(args),
                 ts_call_descriptor);
}

class TurboshaftGraphBuildingInterface : public WasmGraphBuilderBase {
 private:
  class BlockPhis;
  class InstanceCache;

 public:
  enum Mode {
    kRegular,
    kInlinedUnhandled,
    kInlinedWithCatch,
    kInlinedTailCall
  };
  using ValidationTag = Decoder::NoValidationTag;
  using FullDecoder =
      WasmFullDecoder<ValidationTag, TurboshaftGraphBuildingInterface>;
  static constexpr bool kUsesPoppedArgs = true;

  struct Value : public ValueBase<ValidationTag> {
    OpIndex op = OpIndex::Invalid();
    template <typename... Args>
    explicit Value(Args&&... args) V8_NOEXCEPT
        : ValueBase(std::forward<Args>(args)...) {}
  };

  struct Control : public ControlBase<Value, ValidationTag> {
    TSBlock* merge_block = nullptr;
    // for 'if', loops, and 'try'/'try-table' respectively.
    TSBlock* false_or_loop_or_catch_block = nullptr;
    BitVector* assigned = nullptr;             // Only for loops.
    V<Object> exception = OpIndex::Invalid();  // Only for 'try-catch'.

    template <typename... Args>
    explicit Control(Args&&... args) V8_NOEXCEPT
        : ControlBase(std::forward<Args>(args)...) {}
  };

 public:
  // For non-inlined functions.
  TurboshaftGraphBuildingInterface(
      Zone* zone, CompilationEnv* env, Assembler& assembler,
      AssumptionsJournal* assumptions,
      ZoneVector<WasmInliningPosition>* inlining_positions, int func_index,
      bool shared, const WireBytesStorage* wire_bytes)
      : WasmGraphBuilderBase(zone, assembler),
        mode_(kRegular),
        block_phis_(zone),
        env_(env),
        owned_instance_cache_(std::make_unique<InstanceCache>(assembler)),
        instance_cache_(*owned_instance_cache_.get()),
        assumptions_(assumptions),
        inlining_positions_(inlining_positions),
        ssa_env_(zone),
        func_index_(func_index),
        shared_(shared),
        wire_bytes_(wire_bytes),
        return_phis_(nullptr),
        is_inlined_tail_call_(false) {
    DCHECK_NOT_NULL(env_);
    DCHECK_NOT_NULL(env_->module);
  }

  // For inlined functions.
  TurboshaftGraphBuildingInterface(
      Zone* zone, CompilationEnv* env, Assembler& assembler, Mode mode,
      InstanceCache& instance_cache, AssumptionsJournal* assumptions,
      ZoneVector<WasmInliningPosition>* inlining_positions, int func_index,
      bool shared, const WireBytesStorage* wire_bytes,
      base::Vector<OpIndex> real_parameters, TSBlock* return_block,
      BlockPhis* return_phis, TSBlock* catch_block, bool is_inlined_tail_call,
      OptionalV<FrameState> parent_frame_state)
      : WasmGraphBuilderBase(zone, assembler),
        mode_(mode),
        block_phis_(zone),
        env_(env),
        instance_cache_(instance_cache),
        assumptions_(assumptions),
        inlining_positions_(inlining_positions),
        ssa_env_(zone),
        func_index_(func_index),
        shared_(shared),
        wire_bytes_(wire_bytes),
        real_parameters_(real_parameters),
        return_block_(return_block),
        return_phis_(return_phis),
        return_catch_block_(catch_block),
        is_inlined_tail_call_(is_inlined_tail_call),
        parent_frame_state_(parent_frame_state) {
    DCHECK_NE(mode_, kRegular);
    DCHECK_EQ(return_block == nullptr, mode == kInlinedTailCall);
    DCHECK_EQ(catch_block != nullptr, mode == kInlinedWithCatch);
  }

  void StartFunction(FullDecoder* decoder) {
    if (mode_ == kRegular) __ Bind(__ NewBlock());
    // Set 0 as the current source position (before locals declarations).
    __ SetCurrentOrigin(WasmPositionToOpIndex(0, inlining_id_));
    ssa_env_.resize(decoder->num_locals());
    uint32_t index = 0;
    V<WasmTrustedInstanceData> trusted_instance_data;
    if (mode_ == kRegular) {
      static_assert(kWasmInstanceDataParameterIndex == 0);
      trusted_instance_data = __ WasmInstanceDataParameter();
      for (; index < decoder->sig_->parameter_count(); index++) {
        // Parameter indices are shifted by 1 because parameter 0 is the
        // instance.
        ssa_env_[index] = __ Parameter(
            index + 1, RepresentationFor(decoder->sig_->GetParam(index)));
      }
      instance_cache_.Initialize(trusted_instance_data, decoder->module_);
    } else {
      trusted_instance_data = real_parameters_[0];
      for (; index < decoder->sig_->parameter_count(); index++) {
        // Parameter indices are shifted by 1 because parameter 0 is the
        // instance.
        ssa_env_[index] = real_parameters_[index + 1];
      }
      if (!is_inlined_tail_call_) {
        return_phis_->InitReturnPhis(decoder->sig_->returns());
      }
    }
    while (index < decoder->num_locals()) {
      ValueType type = decoder->local_type(index);
      OpIndex op;
      if (!type.is_defaultable()) {
        DCHECK(type.is_reference());
        // TODO(jkummerow): Consider using "the hole" instead, to make any
        // illegal uses more obvious.
        op = __ Null(type.AsNullable());
      } else {
        op = DefaultValue(type);
      }
      while (index < decoder->num_locals() &&
             decoder->local_type(index) == type) {
        ssa_env_[index++] = op;
      }
    }

    if (v8_flags.wasm_inlining) {
      if (mode_ == kRegular) {
        if (v8_flags.liftoff) {
          inlining_decisions_ = InliningTree::CreateRoot(
              decoder->zone_, decoder->module_, func_index_);
        } else {
          set_no_liftoff_inlining_budget(
              InliningTree::NoLiftoffBudget(decoder->module_, func_index_));
        }
      } else {
#if DEBUG
        // We don't have support for inlining asm.js functions, those should
        // never be selected in `InliningTree`.
        DCHECK(!wasm::is_asmjs_module(decoder->module_));

        if (v8_flags.liftoff && inlining_decisions_) {
          // DCHECK that `inlining_decisions_` is consistent.
          DCHECK(inlining_decisions_->is_inlined());
          DCHECK_EQ(inlining_decisions_->function_index(), func_index_);
          base::SharedMutexGuard<base::kShared> mutex_guard(
              &decoder->module_->type_feedback.mutex);
          if (inlining_decisions_->feedback_found()) {
            DCHECK_NE(
                decoder->module_->type_feedback.feedback_for_function.find(
                    func_index_),
                decoder->module_->type_feedback.feedback_for_function.end());
            DCHECK_EQ(inlining_decisions_->function_calls().size(),
                      decoder->module_->type_feedback.feedback_for_function
                          .find(func_index_)
                          ->second.feedback_vector.size());
            DCHECK_EQ(inlining_decisions_->function_calls().size(),
                      decoder->module_->type_feedback.feedback_for_function
                          .find(func_index_)
                          ->second.call_targets.size());
          }
        }
#endif
      }
    }

    if (v8_flags.debug_code) {
      IF_NOT (LIKELY(__ HasInstanceType(trusted_instance_data,
                                        WASM_TRUSTED_INSTANCE_DATA_TYPE))) {
        OpIndex message_id = __ TaggedIndexConstant(
            static_cast<int32_t>(AbortReason::kUnexpectedInstanceType));
        CallRuntime(decoder->zone(), Runtime::kAbort, {message_id},
                    __ NoContextConstant());
        __ Unreachable();
      }
    }

    if (mode_ == kRegular) {
      StackCheck(WasmStackCheckOp::Kind::kFunctionEntry, decoder);
    }

    if (v8_flags.trace_wasm) {
      __ SetCurrentOrigin(
          WasmPositionToOpIndex(decoder->position(), inlining_id_));
      CallRuntime(decoder->zone(), Runtime::kWasmTraceEnter, {},
                  __ NoContextConstant());
    }

    auto branch_hints_it = decoder->module_->branch_hints.find(func_index_);
    if (branch_hints_it != decoder->module_->branch_hints.end()) {
      branch_hints_ = &branch_hints_it->second;
    }
  }

  void StartFunctionBody(FullDecoder* decoder, Control* block) {}

  void FinishFunction(FullDecoder* decoder) {
    if (v8_flags.liftoff && inlining_decisions_ &&
        inlining_decisions_->feedback_found()) {
      DCHECK_EQ(
          feedback_slot_,
          static_cast<int>(inlining_decisions_->function_calls().size()) - 1);
    }
    if (mode_ == kRegular) {
      // Just accessing `source_positions` at the maximum `OpIndex` already
      // pre-allocates the underlying storage such that we avoid repeatedly
      // resizing/copying in the following loop.
      __ output_graph().source_positions()[__ output_graph().EndIndex()];

      for (OpIndex index : __ output_graph().AllOperationIndices()) {
        SourcePosition position = OpIndexToSourcePosition(
            __ output_graph().operation_origins()[index]);
        __ output_graph().source_positions()[index] = position;
      }
      if (v8_flags.trace_wasm_inlining) {
        uint32_t node_count =
            __ output_graph().NumberOfOperationsForDebugging();
        PrintF("[function %d: emitted %d nodes]\n", func_index_, node_count);
      }
    }
  }

  void OnFirstError(FullDecoder*) {}

  void NextInstruction(FullDecoder* decoder, WasmOpcode) {
    __ SetCurrentOrigin(
        WasmPositionToOpIndex(decoder->position(), inlining_id_));
  }

  // ******** Control Flow ********
  // The basic structure of control flow is {block_phis_}. It contains a mapping
  // from blocks to phi inputs corresponding to the SSA values plus the stack
  // merge values at the beginning of the block.
  // - When we create a new block (to be bound in the future), we register it to
  //   {block_phis_} with {NewBlockWithPhis}.
  // - When we encounter an jump to a block, we invoke {SetupControlFlowEdge}.
  // - Finally, when we bind a block, we setup its phis, the SSA environment,
  //   and its merge values, with {BindBlockAndGeneratePhis}.
  // - When we create a loop, we generate PendingLoopPhis for the SSA state and
  //   the incoming stack values. We also create a block which will act as a
  //   merge block for all loop backedges (since a loop in Turboshaft can only
  //   have one backedge). When we PopControl a loop, we enter the merge block
  //   to create its Phis for all backedges as necessary, and use those values
  //   to patch the backedge of the PendingLoopPhis of the loop.

  void Block(FullDecoder* decoder, Control* block) {
    block->merge_block = NewBlockWithPhis(decoder, block->br_merge());
  }

  void Loop(FullDecoder* decoder, Control* block) {
    TSBlock* loop = __ NewLoopHeader();
    __ Goto(loop);
    __ Bind(loop);

    bool can_be_innermost = false;  // unused
    BitVector* assigned = WasmDecoder<ValidationTag>::AnalyzeLoopAssignment(
        decoder, decoder->pc(), decoder->num_locals(), decoder->zone(),
        &can_be_innermost);
    block->assigned = assigned;

    for (uint32_t i = 0; i < decoder->num_locals(); i++) {
      if (!assigned->Contains(i)) continue;
      OpIndex phi = __ PendingLoopPhi(
          ssa_env_[i], RepresentationFor(decoder->local_type(i)));
      ssa_env_[i] = phi;
    }
    uint32_t arity = block->start_merge.arity;
    Value* stack_base = arity > 0 ? decoder->stack_value(arity) : nullptr;
    for (uint32_t i = 0; i < arity; i++) {
      OpIndex phi = __ PendingLoopPhi(stack_base[i].op,
                                      RepresentationFor(stack_base[i].type));
      block->start_merge[i].op = phi;
    }

    StackCheck(WasmStackCheckOp::Kind::kLoop, decoder);

    TSBlock* loop_merge = NewBlockWithPhis(decoder, &block->start_merge);
    block->merge_block = loop_merge;
    block->false_or_loop_or_catch_block = loop;
  }

  void If(FullDecoder* decoder, const Value& cond, Control* if_block) {
    TSBlock* true_block = __ NewBlock();
    TSBlock* false_block = NewBlockWithPhis(decoder, nullptr);
    TSBlock* merge_block = NewBlockWithPhis(decoder, &if_block->end_merge);
    if_block->false_or_loop_or_catch_block = false_block;
    if_block->merge_block = merge_block;
    SetupControlFlowEdge(decoder, false_block);
    __ Branch({cond.op, GetBranchHint(decoder)}, true_block, false_block);
    __ Bind(true_block);
  }

  void Else(FullDecoder* decoder, Control* if_block) {
    if (if_block->reachable()) {
      SetupControlFlowEdge(decoder, if_block->merge_block);
      __ Goto(if_block->merge_block);
    }
    BindBlockAndGeneratePhis(decoder, if_block->false_or_loop_or_catch_block,
                             nullptr);
  }

  void BrOrRet(FullDecoder* decoder, uint32_t depth, uint32_t drop_values = 0) {
    if (depth == decoder->control_depth() - 1) {
      DoReturn(decoder, drop_values);
    } else {
      Control* target = decoder->control_at(depth);
      SetupControlFlowEdge(decoder, target->merge_block, drop_values);
      __ Goto(target->merge_block);
    }
  }

  void BrIf(FullDecoder* decoder, const Value& cond, uint32_t depth) {
    BranchHint hint = GetBranchHint(decoder);
    if (depth == decoder->control_depth() - 1) {
      IF ({cond.op, hint}) {
        DoReturn(decoder, 0);
      }
    } else {
      Control* target = decoder->control_at(depth);
      SetupControlFlowEdge(decoder, target->merge_block);
      TSBlock* non_branching = __ NewBlock();
      __ Branch({cond.op, hint}, target->merge_block, non_branching);
      __ Bind(non_branching);
    }
  }

  // An analysis to determine whether a br_table should be lowered to a switch
  // or a series of compare and branch. This can be for small tables or larger
  // 'sparse' ones, which include many cases but few targets. A sparse table may
  // look like this: br_table [ 1, 0, 0, 0, 0, 0, 2, 0 ] which can be lowered to
  // two conditional branches followed by an unconditional one. The advantages
  // of this are reducing the space required for the table and reducing the
  // latency.
  template <typename ValidationTag>
  class BrTableAnalysis {
   public:
    static constexpr int32_t kMaxComparesPerTarget = 2;
    static constexpr uint32_t kMaxTargets = 3;
    static constexpr int32_t kMaxTableCount = 20;
    using CaseVector = base::SmallVector<uint8_t, 8>;
    using TargetMap = absl::btree_map<uint32_t, CaseVector>;

    bool LowerToBranches(Decoder* decoder, const BranchTableImmediate& imm) {
      BranchTableIterator<ValidationTag> iterator(decoder, imm);
      while (iterator.has_next()) {
        uint32_t i = iterator.cur_index();
        uint32_t target = iterator.next();

        if (i == imm.table_count) {
          AddDefault(target);
        } else if (!TryAddTarget(target, i)) {
          return false;
        }
      }
      primary_indices_ = other_targets_[primary_target()];
      other_targets_.erase(primary_target());
      size_t total_targets = other_targets_.size() + 1;
      if (default_target() != primary_target() &&
          !other_targets_.count(default_target())) {
        total_targets++;
      }
      return total_targets <= kMaxTargets;
    }
    // The most often occurring target, or the default if there is no other
    // target with multiple cases.
    uint32_t primary_target() const { return primary_target_.value(); }
    // The default target, for when the br_table index is out-of-range.
    uint32_t default_target() const { return default_target_.value(); }
    // other_targets doesn't include the primary target, nor the default if it
    // isn't an in-range target.
    const TargetMap& other_targets() const { return other_targets_; }
    // All the indices which target the primary target.
    const CaseVector& primary_indices() const { return primary_indices_; }

   private:
    bool TryAddTarget(uint32_t target, uint32_t index) {
      DCHECK_LT(index, kMaxTableCount);
      CaseVector& cases = other_targets_[target];
      if (other_targets_.size() > kMaxTargets) {
        return false;
      }
      if (cases.size() == kMaxComparesPerTarget) {
        if (primary_target_.has_value() && target != primary_target()) {
          return false;
        }
        primary_target_ = target;
      }
      cases.push_back(index);
      return true;
    }
    void AddDefault(uint32_t target) {
      default_target_ = target;
      if (!primary_target_.has_value()) {
        primary_target_ = default_target();
      }
    }

    std::optional<uint32_t> default_target_;
    std::optional<uint32_t> primary_target_;
    CaseVector primary_indices_;
    TargetMap other_targets_;
  };

  void BrTable(FullDecoder* decoder, const BranchTableImmediate& imm,
               const Value& key) {
    if (imm.table_count < BrTableAnalysis<ValidationTag>::kMaxTableCount) {
      BrTableAnalysis<ValidationTag> table_analysis;
      if (table_analysis.LowerToBranches(decoder, imm)) {
        auto generate_cond =
            [this](const Value& key,
                   const BrTableAnalysis<ValidationTag>::CaseVector& cases)
            -> OpIndex {
          switch (cases.size()) {
            default:
              static_assert(
                  BrTableAnalysis<ValidationTag>::kMaxComparesPerTarget <= 2);
              UNREACHABLE();
            case 1:
              return __ Word32Equal(key.op, __ Word32Constant(cases[0]));
            case 2: {
              return __ Word32BitwiseOr(__ Word32Equal(key.op, cases[0]),
                                        __ Word32Equal(key.op, cases[1]));
            }
          }
        };
        auto insert_cond_branch = [this, &decoder](OpIndex cond,
                                                   uint32_t depth) {
          BranchHint hint = GetBranchHint(decoder);
          if (depth == decoder->control_depth() - 1) {
            IF ({cond, hint}) {
              DoReturn(decoder, 0);
            }
          } else {
            Control* target = decoder->control_at(depth);
            SetupControlFlowEdge(decoder, target->merge_block);
            TSBlock* non_branching = __ NewBlock();
            __ Branch({cond, hint}, target->merge_block, non_branching);
            __ Bind(non_branching);
          }
        };
        // Insert conditional branches to the other targets.
        for (auto const& [target, cases] : table_analysis.other_targets()) {
          DCHECK_LE(cases.size(),
                    BrTableAnalysis<ValidationTag>::kMaxComparesPerTarget);
          insert_cond_branch(generate_cond(key, cases), target);
        }
        // If needed, insert the range check for the primary target.
        if (table_analysis.primary_target() !=
            table_analysis.default_target()) {
          OpIndex lower = __ Word32Equal(__ Int32LessThan(key.op, 0), 0);
          OpIndex upper =
              __ Int32LessThan(key.op, __ Word32Constant(imm.table_count));
          OpIndex cond = __ Word32BitwiseAnd(lower, upper);
          insert_cond_branch(cond, table_analysis.primary_target());
        }
        // Always fallthrough and branch to the default case.
        BrOrRet(decoder, table_analysis.default_target());
        return;
      }
    }
    compiler::turboshaft::SwitchOp::Case* cases =
        __ output_graph().graph_zone()
            -> AllocateArray<compiler::turboshaft::SwitchOp::Case>(
                             imm.table_count);
    BranchTableIterator<ValidationTag> new_block_iterator(decoder, imm);
    SmallZoneVector<TSBlock*, 16> intermediate_blocks(decoder->zone_);
    TSBlock* default_case = nullptr;
    while (new_block_iterator.has_next()) {
      TSBlock* intermediate = __ NewBlock();
      intermediate_blocks.emplace_back(intermediate);
      uint32_t i = new_block_iterator.cur_index();
      if (i == imm.table_count) {
        default_case = intermediate;
      } else {
        cases[i] = {static_cast<int>(i), intermediate, BranchHint::kNone};
      }
      new_block_iterator.next();
    }
    DCHECK_NOT_NULL(default_case);
    __ Switch(key.op, base::VectorOf(cases, imm.table_count), default_case);

    int i = 0;
    BranchTableIterator<ValidationTag> branch_iterator(decoder, imm);
    while (branch_iterator.has_next()) {
      TSBlock* intermediate = intermediate_blocks[i];
      i++;
      __ Bind(intermediate);
      BrOrRet(decoder, branch_iterator.next());
    }
  }

  void FallThruTo(FullDecoder* decoder, Control* block) {
    // TODO(14108): Why is {block->reachable()} not reliable here? Maybe it is
    // not in other spots as well.
    if (__ current_block() != nullptr) {
      SetupControlFlowEdge(decoder, block->merge_block);
      __ Goto(block->merge_block);
    }
  }

  void PopControl(FullDecoder* decoder, Control* block) {
    switch (block->kind) {
      case kControlIf:
        if (block->reachable()) {
          SetupControlFlowEdge(decoder, block->merge_block);
          __ Goto(block->merge_block);
        }
        BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                                 nullptr);
        // Exceptionally for one-armed if, we cannot take the values from the
        // stack; we have to pass the stack values at the beginning of the
        // if-block.
        SetupControlFlowEdge(decoder, block->merge_block, 0, OpIndex::Invalid(),
                             &block->start_merge);
        __ Goto(block->merge_block);
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlIfElse:
      case kControlBlock:
      case kControlTry:
      case kControlTryCatch:
      case kControlTryCatchAll:
        // {block->reachable()} is not reliable here for exceptions, because
        // the decoder sets the reachability to the upper block's reachability
        // before calling this interface function.
        if (__ current_block() != nullptr) {
          SetupControlFlowEdge(decoder, block->merge_block);
          __ Goto(block->merge_block);
        }
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlTryTable:
        DCHECK_EQ(__ current_block(), nullptr);
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlLoop: {
        TSBlock* post_loop = NewBlockWithPhis(decoder, nullptr);
        if (block->reachable()) {
          SetupControlFlowEdge(decoder, post_loop);
          __ Goto(post_loop);
        }
        if (!block->false_or_loop_or_catch_block->IsBound()) {
          // The loop is unreachable. In this case, no operations have been
          // emitted for it. Do nothing.
        } else if (block->merge_block->PredecessorCount() == 0) {
          // Turns out, the loop has no backedges, i.e. it is not quite a loop
          // at all. Replace it with a merge, and its PendingPhis with one-input
          // phis.
          block->false_or_loop_or_catch_block->SetKind(
              compiler::turboshaft::Block::Kind::kMerge);
          for (auto& op : __ output_graph().operations(
                   *block->false_or_loop_or_catch_block)) {
            PendingLoopPhiOp* pending_phi = op.TryCast<PendingLoopPhiOp>();
            if (!pending_phi) break;
            OpIndex replaced = __ output_graph().Index(op);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced, base::VectorOf({pending_phi -> first()}),
                pending_phi->rep);
          }
        } else {
          // We abuse the start merge of the loop, which is not used otherwise
          // anymore, to store backedge inputs for the pending phi stack values
          // of the loop.
          BindBlockAndGeneratePhis(decoder, block->merge_block,
                                   block->br_merge());
          __ Goto(block->false_or_loop_or_catch_block);
          auto operations = __ output_graph().operations(
              *block -> false_or_loop_or_catch_block);
          auto to = operations.begin();
          // The VariableReducer can introduce loop phis as well which are at
          // the beginning of the block. We need to skip them.
          while (to != operations.end() &&
                 to->Is<compiler::turboshaft::PhiOp>()) {
            ++to;
          }
          for (auto it = block->assigned->begin(); it != block->assigned->end();
               ++it, ++to) {
            // The last bit represents the instance cache.
            if (*it == static_cast<int>(ssa_env_.size())) break;
            PendingLoopPhiOp& pending_phi = to->Cast<PendingLoopPhiOp>();
            OpIndex replaced = __ output_graph().Index(*to);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced, base::VectorOf({pending_phi.first(), ssa_env_[*it]}),
                pending_phi.rep);
          }
          for (uint32_t i = 0; i < block->br_merge()->arity; ++i, ++to) {
            PendingLoopPhiOp& pending_phi = to->Cast<PendingLoopPhiOp>();
            OpIndex replaced = __ output_graph().Index(*to);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced,
                base::VectorOf(
                    {pending_phi.first(), (*block->br_merge())[i].op}),
                pending_phi.rep);
          }
        }
        BindBlockAndGeneratePhis(decoder, post_loop, nullptr);
        break;
      }
    }
  }

  void DoReturn(FullDecoder* decoder, uint32_t drop_values) {
    size_t return_count = decoder->sig_->return_count();
    SmallZoneVector<OpIndex, 16> return_values(return_count, decoder->zone_);
    Value* stack_base = return_count == 0
                            ? nullptr
                            : decoder->stack_value(static_cast<uint32_t>(
                                  return_count + drop_values));
    for (size_t i = 0; i < return_count; i++) {
      return_values[i] = stack_base[i].op;
    }
    if (v8_flags.trace_wasm) {
      V<WordPtr> info = __ IntPtrConstant(0);
      if (return_count == 1) {
        wasm::ValueType return_type = decoder->sig_->GetReturn(0);
        int size = return_type.value_kind_size();
        // TODO(14108): This won't fit everything.
        info = __ StackSlot(size, size);
        // TODO(14108): Write barrier might be needed.
        __ Store(
            info, return_values[0], StoreOp::Kind::RawAligned(),
            MemoryRepresentation::FromMachineType(return_type.machine_type()),
            compiler::kNoWriteBarrier);
      }
      CallRuntime(decoder->zone(), Runtime::kWasmTraceExit, {info},
                  __ NoContextConstant());
    }
    if (mode_ == kRegular || mode_ == kInlinedTailCall) {
      __ Return(__ Word32Constant(0), base::VectorOf(return_values),
                v8_flags.experimental_wasm_growable_stacks);
    } else {
      // Do not add return values if we are in unreachable code.
      if (__ generating_unreachable_operations()) return;
      for (size_t i = 0; i < return_count; i++) {
        return_phis_->AddInputForPhi(i, return_values[i]);
      }
      __ Goto(return_block_);
    }
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
    result->op = UnOpImpl(opcode, value.op, value.type);
  }

  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    result->op = BinOpImpl(opcode, lhs.op, rhs.op);
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
    // TODO(14108): Implement.
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    result->op = __ Word32Constant(value);
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    result->op = __ Word64Constant(value);
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    result->op = __ Float32Constant(value);
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    result->op = __ Float64Constant(value);
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    result->op = __ Simd128Constant(imm.value);
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value* result) {
    result->op = __ Null(type);
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    ModuleTypeIndex sig_index =
        decoder->module_->functions[function_index].sig_index;
    bool shared = decoder->module_->type(sig_index).is_shared;
    result->op = __ WasmRefFunc(trusted_instance_data(shared), function_index);
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    result->op =
        __ AssertNotNull(arg.op, arg.type, TrapId::kTrapNullDereference);
  }

  void Drop(FullDecoder* decoder) {}

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    result->op = ssa_env_[imm.index];
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    ssa_env_[imm.index] = value.op;
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    ssa_env_[imm.index] = result->op = value.op;
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    result->op = __ GlobalGet(trusted_instance_data(shared), imm.global);
  }

  void GlobalSet(FullDecoder* decoder, const Value& value,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    __ GlobalSet(trusted_instance_data(shared), value.op, imm.global);
  }

  void Trap(FullDecoder* decoder, TrapReason reason) {
    __ TrapIfNot(__ Word32Constant(0), GetTrapIdForTrap(reason));
    __ Unreachable();
  }

  void AssertNullTypecheck(FullDecoder* decoder, const Value& obj,
                           Value* result) {
    __ TrapIfNot(__ IsNull(obj.op, obj.type), TrapId::kTrapIllegalCast);
    Forward(decoder, obj, result);
  }

  void AssertNotNullTypecheck(FullDecoder* decoder, const Value& obj,
                              Value* result) {
    __ AssertNotNull(obj.op, obj.type, TrapId::kTrapIllegalCast);
    Forward(decoder, obj, result);
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {
    // This is just for testing bailouts in Liftoff, here it's just a nop.
  }

  void Select(FullDecoder* decoder, const Value& cond, const Value& fval,
              const Value& tval, Value* result) {
    using Implementation = compiler::turboshaft::SelectOp::Implementation;
    bool use_select = false;
    switch (tval.type.kind()) {
      case kI32:
        if (SupportedOperations::word32_select()) use_select = true;
        break;
      case kI64:
        if (SupportedOperations::word64_select()) use_select = true;
        break;
      case kF32:
        if (SupportedOperations::float32_select()) use_select = true;
        break;
      case kF64:
        if (SupportedOperations::float64_select()) use_select = true;
        break;
      case kRef:
      case kRefNull:
      case kS128:
        break;
      case kI8:
      case kI16:
      case kF16:
      case kRtt:
      case kVoid:
      case kTop:
      case kBottom:
        UNREACHABLE();
    }
    result->op = __ Select(
        cond.op, tval.op, fval.op, RepresentationFor(tval.type),
        BranchHint::kNone,
        use_select ? Implementation::kCMove : Implementation::kBranch);
  }

  OpIndex BuildChangeEndiannessStore(OpIndex node,
                                     MachineRepresentation mem_rep,
                                     wasm::ValueType wasmtype) {
    OpIndex result;
    OpIndex value = node;
    int value_size_in_bytes = wasmtype.value_kind_size();
    int value_size_in_bits = 8 * value_size_in_bytes;
    bool is_float = false;

    switch (wasmtype.kind()) {
      case wasm::kF64:
        value = __ BitcastFloat64ToWord64(node);
        is_float = true;
        [[fallthrough]];
      case wasm::kI64:
        result = __ Word64Constant(static_cast<uint64_t>(0));
        break;
      case wasm::kF32:
        value = __ BitcastFloat32ToWord32(node);
        is_float = true;
        [[fallthrough]];
      case wasm::kI32:
        result = __ Word32Constant(0);
        break;
      case wasm::kS128:
        DCHECK(ReverseBytesSupported(value_size_in_bytes));
        break;
      default:
        UNREACHABLE();
    }

    if (mem_rep == MachineRepresentation::kWord8) {
      // No need to change endianness for byte size, return original node
      return node;
    }
    if (wasmtype == wasm::kWasmI64 &&
        mem_rep < MachineRepresentation::kWord64) {
      // In case we store lower part of WasmI64 expression, we can truncate
      // upper 32bits.
      value_size_in_bytes = wasm::kWasmI32.value_kind_size();
      value_size_in_bits = 8 * value_size_in_bytes;
      if (mem_rep == MachineRepresentation::kWord16) {
        value = __ Word32ShiftLeft(value, 16);
      }
    } else if (wasmtype == wasm::kWasmI32 &&
               mem_rep == MachineRepresentation::kWord16) {
      value = __ Word32ShiftLeft(value, 16);
    }

    int i;
    uint32_t shift_count;

    if (ReverseBytesSupported(value_size_in_bytes)) {
      switch (value_size_in_bytes) {
        case 4:
          result = __ Word32ReverseBytes(V<Word32>::Cast(value));
          break;
        case 8:
          result = __ Word64ReverseBytes(V<Word64>::Cast(value));
          break;
        case 16:
          result = __ Simd128ReverseBytes(
              V<compiler::turboshaft::Simd128>::Cast(value));
          break;
        default:
          UNREACHABLE();
      }
    } else {
      for (i = 0, shift_count = value_size_in_bits - 8;
           i < value_size_in_bits / 2; i += 8, shift_count -= 16) {
        OpIndex shift_lower;
        OpIndex shift_higher;
        OpIndex lower_byte;
        OpIndex higher_byte;

        DCHECK_LT(0, shift_count);
        DCHECK_EQ(0, (shift_count + 8) % 16);

        if (value_size_in_bits > 32) {
          shift_lower = __ Word64ShiftLeft(value, shift_count);
          shift_higher = __ Word64ShiftRightLogical(value, shift_count);
          lower_byte = __ Word64BitwiseAnd(shift_lower,
                                           static_cast<uint64_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word64BitwiseAnd(shift_higher,
                                            static_cast<uint64_t>(0xFF) << i);
          result = __ Word64BitwiseOr(result, lower_byte);
          result = __ Word64BitwiseOr(result, higher_byte);
        } else {
          shift_lower = __ Word32ShiftLeft(value, shift_count);
          shift_higher = __ Word32ShiftRightLogical(value, shift_count);
          lower_byte = __ Word32BitwiseAnd(shift_lower,
                                           static_cast<uint32_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word32BitwiseAnd(shift_higher,
                                            static_cast<uint32_t>(0xFF) << i);
          result = __ Word32BitwiseOr(result, lower_byte);
          result = __ Word32BitwiseOr(result, higher_byte);
        }
      }
    }

    if (is_float) {
      switch (wasmtype.kind()) {
        case wasm::kF64:
          result = __ BitcastWord64ToFloat64(result);
          break;
        case wasm::kF32:
          result = __ BitcastWord32ToFloat32(result);
          break;
        default:
          UNREACHABLE();
      }
    }

    return result;
  }

  OpIndex BuildChangeEndiannessLoad(OpIndex node, MachineType memtype,
                                    wasm::ValueType wasmtype) {
    OpIndex result;
    OpIndex value = node;
    int value_size_in_bytes = ElementSizeInBytes(memtype.representation());
    int value_size_in_bits = 8 * value_size_in_bytes;
    bool is_float = false;

    switch (memtype.representation()) {
      case MachineRepresentation::kFloat64:
        value = __ BitcastFloat64ToWord64(node);
        is_float = true;
        [[fallthrough]];
      case MachineRepresentation::kWord64:
        result = __ Word64Constant(static_cast<uint64_t>(0));
        break;
      case MachineRepresentation::kFloat32:
        value = __ BitcastFloat32ToWord32(node);
        is_float = true;
        [[fallthrough]];
      case MachineRepresentation::kWord32:
      case MachineRepresentation::kWord16:
        result = __ Word32Constant(0);
        break;
      case MachineRepresentation::kWord8:
        // No need to change endianness for byte size, return original node.
        return node;
      case MachineRepresentation::kSimd128:
        DCHECK(ReverseBytesSupported(value_size_in_bytes));
        break;
      default:
        UNREACHABLE();
    }

    int i;
    uint32_t shift_count;

    if (ReverseBytesSupported(value_size_in_bytes < 4 ? 4
                                                      : value_size_in_bytes)) {
      switch (value_size_in_bytes) {
        case 2:
          result = __ Word32ReverseBytes(__ Word32ShiftLeft(value, 16));
          break;
        case 4:
          result = __ Word32ReverseBytes(value);
          break;
        case 8:
          result = __ Word64ReverseBytes(value);
          break;
        case 16:
          result = __ Simd128ReverseBytes(value);
          break;
        default:
          UNREACHABLE();
      }
    } else {
      for (i = 0, shift_count = value_size_in_bits - 8;
           i < value_size_in_bits / 2; i += 8, shift_count -= 16) {
        OpIndex shift_lower;
        OpIndex shift_higher;
        OpIndex lower_byte;
        OpIndex higher_byte;

        DCHECK_LT(0, shift_count);
        DCHECK_EQ(0, (shift_count + 8) % 16);

        if (value_size_in_bits > 32) {
          shift_lower = __ Word64ShiftLeft(value, shift_count);
          shift_higher = __ Word64ShiftRightLogical(value, shift_count);
          lower_byte = __ Word64BitwiseAnd(shift_lower,
                                           static_cast<uint64_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word64BitwiseAnd(shift_higher,
                                            static_cast<uint64_t>(0xFF) << i);
          result = __ Word64BitwiseOr(result, lower_byte);
          result = __ Word64BitwiseOr(result, higher_byte);
        } else {
          shift_lower = __ Word32ShiftLeft(value, shift_count);
          shift_higher = __ Word32ShiftRightLogical(value, shift_count);
          lower_byte = __ Word32BitwiseAnd(shift_lower,
                                           static_cast<uint32_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word32BitwiseAnd(shift_higher,
                                            static_cast<uint32_t>(0xFF) << i);
          result = __ Word32BitwiseOr(result, lower_byte);
          result = __ Word32BitwiseOr(result, higher_byte);
        }
      }
    }

    if (is_float) {
      switch (memtype.representation()) {
        case MachineRepresentation::kFloat64:
          result = __ BitcastWord64ToFloat64(result);
          break;
        case MachineRepresentation::kFloat32:
          result = __ BitcastWord32ToFloat32(result);
          break;
        default:
          UNREACHABLE();
      }
    }

    // We need to sign or zero extend the value.
    // Values with size >= 32-bits may need to be sign/zero extended after
    // calling this function.
    if (value_size_in_bits < 32) {
      DCHECK(!is_float);
      int shift_bit_count = 32 - value_size_in_bits;
      result = __ Word32ShiftLeft(result, shift_bit_count);
      if (memtype.IsSigned()) {
        result =
            __ Word32ShiftRightArithmeticShiftOutZeros(result, shift_bit_count);
      } else {
        result = __ Word32ShiftRightLogical(result, shift_bit_count);
      }
    }

    return result;
  }

  void LoadMem(FullDecoder* decoder, LoadType type,
               const MemoryAccessImmediate& imm, const Value& index,
               Value* result) {
    bool needs_f16_to_f32_conv = false;
    if (type.value() == LoadType::kF32LoadF16 &&
        !SupportedOperations::float16()) {
      needs_f16_to_f32_conv = true;
      type = LoadType::kI32Load16U;
    }
    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    V<WordPtr> mem_start = MemStart(imm.memory->index);

    LoadOp::Kind load_kind = GetMemoryAccessKind(repr, strategy);

    const bool offset_in_int_range =
        imm.offset <= std::numeric_limits<int32_t>::max();
    OpIndex base =
        offset_in_int_range ? mem_start : __ WordPtrAdd(mem_start, imm.offset);
    int32_t offset = offset_in_int_range ? static_cast<int32_t>(imm.offset) : 0;
    OpIndex load = __ Load(base, final_index, load_kind, repr, offset);

#if V8_TARGET_BIG_ENDIAN
    load = BuildChangeEndiannessLoad(load, type.mem_type(), type.value_type());
#endif

    if (type.value_type() == kWasmI64 && repr.SizeInBytes() < 8) {
      load = repr.IsSigned() ? __ ChangeInt32ToInt64(load)
                             : __ ChangeUint32ToUint64(load);
    }

    if (needs_f16_to_f32_conv) {
      load = CallCStackSlotToStackSlot(
          load, ExternalReference::wasm_float16_to_float32(),
          MemoryRepresentation::Uint16(), MemoryRepresentation::Float32());
    }

    if (v8_flags.trace_wasm_memory) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void LoadTransform(FullDecoder* decoder, LoadType type,
                     LoadTransformationKind transform,
                     const MemoryAccessImmediate& imm, const Value& index,
                     Value* result) {
    MemoryRepresentation repr =
        transform == LoadTransformationKind::kExtend
            ? MemoryRepresentation::Int64()
            : MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    compiler::turboshaft::Simd128LoadTransformOp::LoadKind load_kind =
        GetMemoryAccessKind(repr, strategy);

    using TransformKind =
        compiler::turboshaft::Simd128LoadTransformOp::TransformKind;

    TransformKind transform_kind;

    if (transform == LoadTransformationKind::kExtend) {
      if (type.mem_type() == MachineType::Int8()) {
        transform_kind = TransformKind::k8x8S;
      } else if (type.mem_type() == MachineType::Uint8()) {
        transform_kind = TransformKind::k8x8U;
      } else if (type.mem_type() == MachineType::Int16()) {
        transform_kind = TransformKind::k16x4S;
      } else if (type.mem_type() == MachineType::Uint16()) {
        transform_kind = TransformKind::k16x4U;
      } else if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32x2S;
      } else if (type.mem_type() == MachineType::Uint32()) {
        transform_kind = TransformKind::k32x2U;
      } else {
        UNREACHABLE();
      }
    } else if (transform == LoadTransformationKind::kSplat) {
      if (type.mem_type() == MachineType::Int8()) {
        transform_kind = TransformKind::k8Splat;
      } else if (type.mem_type() == MachineType::Int16()) {
        transform_kind = TransformKind::k16Splat;
      } else if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32Splat;
      } else if (type.mem_type() == MachineType::Int64()) {
        transform_kind = TransformKind::k64Splat;
      } else {
        UNREACHABLE();
      }
    } else {
      if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32Zero;
      } else if (type.mem_type() == MachineType::Int64()) {
        transform_kind = TransformKind::k64Zero;
      } else {
        UNREACHABLE();
      }
    }

    V<compiler::turboshaft::Simd128> load = __ Simd128LoadTransform(
        __ WordPtrAdd(MemStart(imm.mem_index), imm.offset), final_index,
        load_kind, transform_kind, 0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void LoadLane(FullDecoder* decoder, LoadType type, const Value& value,
                const Value& index, const MemoryAccessImmediate& imm,
                const uint8_t laneidx, Value* result) {
    using compiler::turboshaft::Simd128LaneMemoryOp;

    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);
    Simd128LaneMemoryOp::Kind kind = GetMemoryAccessKind(repr, strategy);

    Simd128LaneMemoryOp::LaneKind lane_kind;

    switch (repr) {
      case MemoryRepresentation::Int8():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k8;
        break;
      case MemoryRepresentation::Int16():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k16;
        break;
      case MemoryRepresentation::Int32():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k32;
        break;
      case MemoryRepresentation::Int64():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k64;
        break;
      default:
        UNREACHABLE();
    }

    // TODO(14108): If `offset` is in int range, use it as static offset, or
    // consider using a larger type as offset.
    OpIndex load = __ Simd128LaneMemory(
        __ WordPtrAdd(MemStart(imm.mem_index), imm.offset), final_index,
        value.op, Simd128LaneMemoryOp::Mode::kLoad, kind, lane_kind, laneidx,
        0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void StoreMem(FullDecoder* decoder, StoreType type,
                const MemoryAccessImmediate& imm, const Value& index,
                const Value& value) {
    bool needs_f32_to_f16_conv = false;
    if (type.value() == StoreType::kF32StoreF16 &&
        !SupportedOperations::float16()) {
      needs_f32_to_f16_conv = true;
      type = StoreType::kI32Store16;
    }
    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineRepresentation(type.mem_rep());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       wasm::kPartialOOBWritesAreNoops
                           ? compiler::EnforceBoundsCheck::kCanOmitBoundsCheck
                           : compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    V<WordPtr> mem_start = MemStart(imm.memory->index);

    StoreOp::Kind store_kind = GetMemoryAccessKind(repr, strategy);

    OpIndex store_value = value.op;
    if (value.type == kWasmI64 && repr.SizeInBytes() <= 4) {
      store_value = __ TruncateWord64ToWord32(store_value);
    }
    if (needs_f32_to_f16_conv) {
      store_value = CallCStackSlotToStackSlot(
          store_value, ExternalReference::wasm_float32_to_float16(),
          MemoryRepresentation::Float32(), MemoryRepresentation::Int16());
    }

#if defined(V8_TARGET_BIG_ENDIAN)
    store_value = BuildChangeEndiannessStore(store_value, type.mem_rep(),
                                             type.value_type());
#endif
    const bool offset_in_int_range =
        imm.offset <= std::numeric_limits<int32_t>::max();
    OpIndex base =
        offset_in_int_range ? mem_start : __ WordPtrAdd(mem_start, imm.offset);
    int32_t offset = offset_in_int_range ? static_cast<int32_t>(imm.offset) : 0;
    __ Store(base, final_index, store_value, store_kind, repr,
             compiler::kNoWriteBarrier, offset);

    if (v8_flags.trace_wasm_memory) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(decoder, true, repr, final_index, imm.offset);
    }
  }

  void StoreLane(FullDecoder* decoder, StoreType type,
                 const MemoryAccessImmediate& imm, const Value& index,
                 const Value& value, const uint8_t laneidx) {
    using compiler::turboshaft::Simd128LaneMemoryOp;

    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineRepresentation(type.mem_rep());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       kPartialOOBWritesAreNoops
                           ? compiler::EnforceBoundsCheck::kCanOmitBoundsCheck
                           : compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
                       compiler::AlignmentCheck::kNo);
    Simd128LaneMemoryOp::Kind kind = GetMemoryAccessKind(repr, strategy);

    Simd128LaneMemoryOp::LaneKind lane_kind;

    switch (repr) {
      // TODO(manoskouk): Why use unsigned representations here as opposed to
      // LoadLane?
      case MemoryRepresentation::Uint8():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k8;
        break;
      case MemoryRepresentation::Uint16():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k16;
        break;
      case MemoryRepresentation::Uint32():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k32;
        break;
      case MemoryRepresentation::Uint64():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k64;
        break;
      default:
        UNREACHABLE();
    }

    // TODO(14108): If `offset` is in int range, use it as static offset, or
    // consider using a larger type as offset.
    __ Simd128LaneMemory(__ WordPtrAdd(MemStart(imm.mem_index), imm.offset),
                         final_index, value.op,
                         Simd128LaneMemoryOp::Mode::kStore, kind, lane_kind,
                         laneidx, 0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, true, repr, final_index, imm.offset);
    }
  }

  void CurrentMemoryPages(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                          Value* result) {
    V<WordPtr> result_wordptr =
        __ WordPtrShiftRightArithmetic(MemSize(imm.index), kWasmPageSizeLog2);
    // In the 32-bit case, truncation happens implicitly.
    if (imm.memory->is_memory64()) {
      result->op = __ ChangeIntPtrToInt64(result_wordptr);
    } else {
      result->op = __ TruncateWordPtrToWord32(result_wordptr);
    }
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result) {
    if (!imm.memory->is_memory64()) {
      result->op =
          CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmMemoryGrow>(
              decoder, {__ Word32Constant(imm.index), value.op});
    }
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/turboshaft-graph-interface.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name itself, "turboshaft-graph-interface.cc", strongly suggests that this code is responsible for bridging the WebAssembly code representation with the Turboshaft compiler's graph representation. Turboshaft is V8's next-generation optimizing compiler.

2. **Analyze Includes:**  The `#include` directives offer valuable clues about the file's dependencies and functionalities.
    * Includes related to `turboshaft`:  `compiler/turboshaft/assembler.h`, `compiler/turboshaft/builtin-call-descriptors.h`, `compiler/turboshaft/graph.h`, `compiler/turboshaft/wasm-assembler-helpers.h` solidify the graph interface idea.
    * Includes related to `wasm`: `src/wasm/compilation-environment.h`, `src/wasm/function-body-decoder-impl.h`, etc., indicate the code interacts with the Wasm compilation pipeline.
    * Includes related to general V8 concepts: `src/builtins/builtins.h`, `src/objects/object-list-macros.h`,  `src/trap-handler/trap-handler.h` point to integration with other V8 components.

3. **Examine Namespaces and `using` Declarations:** The code is within the `v8::internal::wasm` namespace. The `using compiler::turboshaft::...` statements show which Turboshaft components are actively used. These include core graph elements like `Block`, `CallOp`, `ConstantOp`, `LoadOp`, `StoreOp`, `Graph`, `Variable`, etc.

4. **Analyze Key Functions and Classes:**  Focus on the most prominent classes and functions defined in the snippet.
    * `WasmGraphBuilderBase`: This seems like a base class providing common functionalities for building the graph. Its methods like `CallRuntime`, `GetBuiltinPointerTarget`, `BuildChangeInt64ToBigInt`, `BuildImportedFunctionTargetAndImplicitArg`, `BuildFunctionTargetAndImplicitArg`, `LoadTrustedDataFromInstanceObject`, `BuildModifyThreadInWasmFlag`, and `CallC` suggest core operations performed during graph construction.
    * `TurboshaftGraphBuildingInterface`: This class inherits from `WasmGraphBuilderBase` and appears to be the main class responsible for the translation process. Its methods like `StartFunction`, `FinishFunction`, `Block`, `Loop`, `If`, `BrOrRet`, `BrIf`, `BrTable`, and the presence of internal classes like `BlockPhis` and `InstanceCache` confirm its role in building the graph based on the Wasm bytecode structure.

5. **Infer Functionality from Methods:**  Based on the names of the methods in `TurboshaftGraphBuildingInterface`, deduce how the Wasm bytecode is being translated:
    * `StartFunction`, `FinishFunction`:  Likely handle the entry and exit points of a Wasm function during graph construction.
    * `Block`, `Loop`, `If`:  Deal with the control flow structures in Wasm.
    * `BrOrRet`, `BrIf`, `BrTable`:  Handle branching and control transfer within the Wasm code.
    * The presence of `Value` and `Control` structs suggests they hold intermediate information during the translation.

6. **Address Specific Instructions:**
    * **`.tq` Extension:** The code is `.cc`, so it's C++, not Torque.
    * **JavaScript Relationship:** The code is part of the Wasm compilation pipeline, so it directly impacts how Wasm code is executed within a JavaScript environment. Provide a simple example of calling a Wasm function from JavaScript.
    * **Code Logic Inference:** Focus on a specific method like `BuildImportedFunctionTargetAndImplicitArg`. Describe the likely inputs (function index, trusted instance data) and outputs (target address, implicit argument).
    * **Common Programming Errors:** Think about what could go wrong when interfacing with Wasm and generating a graph. Incorrect types, out-of-bounds access, and assumptions about the Wasm environment are potential errors.

7. **Structure the Answer:** Organize the findings into a clear and concise summary of the file's functionality. Address each part of the user's request systematically.

8. **Refine and Review:** Read through the generated summary to ensure accuracy, clarity, and completeness. Make any necessary corrections or additions. For example, initially, I might have overlooked the significance of `InstanceCache`, but realizing its purpose in optimizing access to instance data is important. Similarly,  explicitly stating that it's part of the *optimizing* compiler clarifies its role.
```cpp
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
    BitVector*
Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共12部分，请归纳一下它的功能

"""
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
          OpIndex 
"""


```
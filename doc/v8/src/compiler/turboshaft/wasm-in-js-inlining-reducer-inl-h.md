Response:
The user is asking for a summary of the functionality of the provided C++ header file.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name `wasm-in-js-inlining-reducer-inl.h` strongly suggests that this code is involved in the process of inlining WebAssembly function calls within JavaScript code during compilation. The "reducer" part hints that it's part of a compiler optimization pass. The `.inl.h` extension usually indicates inline implementations.

2. **Analyze the includes:** The included header files give clues about the technologies involved:
    * `src/compiler/js-inlining.h`: Deals with JavaScript inlining.
    * `src/compiler/turboshaft/...`: Points to the Turboshaft compiler pipeline.
    * `src/wasm/...`: Indicates WebAssembly specific functionality.
    * The presence of `assembler.h`, `operations.h`, etc., confirms it's a compiler component.

3. **Examine the `WasmInJSInliningReducer` class:** This is the main class in the file.
    * The `REDUCE(Call)` method is crucial. It's triggered when a function call is encountered during the reduction process. The logic inside checks if it's a JS-to-Wasm call (`descriptor->js_wasm_call_parameters`).
    * The `TryInlineWasmCall` method suggests the core functionality of attempting to inline the Wasm call.
    * The code within the `else` block of `REDUCE(Call)` deals with setting and unsetting a "thread-in-Wasm" flag, indicating handling of non-inlined cases.

4. **Examine the `WasmInJsInliningInterface` class:** This class looks like an interface used to decode and process the WebAssembly bytecode of the function being inlined.
    * The presence of methods like `UnOp`, `BinOp`, `I32Const`, `LocalGet`, `LocalSet`, etc., mirrors the structure of WebAssembly instructions.
    * The numerous `Bailout(decoder)` calls indicate that the current implementation only supports a subset of Wasm opcodes for inlining.

5. **Connect the two classes:** The `TryInlineWasmCall` method likely uses the `WasmInJsInliningInterface` to decode the Wasm function body and generate the corresponding Turboshaft operations for inlining.

6. **Address the specific questions:**
    * **Functionality:** Summarize the core inlining process.
    * **Torque:** The `.inl.h` extension means it's *not* Torque.
    * **JavaScript relation:**  Explain that it optimizes JS code by inlining Wasm. Provide a simple JS example calling a Wasm function.
    * **Code Logic:** Focus on the `REDUCE(Call)` method. Create a hypothetical scenario where inlining succeeds and another where it fails.
    * **Common Programming Errors:**  Think about the context of inlining. Incorrect assumptions about Wasm function behavior or type mismatches are possible errors.
    * **Summary:**  Condense the main functionality into a few bullet points.

7. **Refine the language:**  Ensure the explanation is clear, concise, and uses appropriate technical terminology. Emphasize the experimental nature of the feature (based on the `v8_flags.turboshaft_wasm_in_js_inlining` check).
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_TURBOSHAFT_WASM_IN_JS_INLINING_REDUCER_INL_H_
#define V8_COMPILER_TURBOSHAFT_WASM_IN_JS_INLINING_REDUCER_INL_H_

#include "src/compiler/js-inlining.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/define-assembler-macros.inc"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/wasm-assembler-helpers.h"
#include "src/heap/factory-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler::turboshaft {

#define TRACE(x)                         \
  do {                                   \
    if (v8_flags.trace_turbo_inlining) { \
      StdoutStream() << x << std::endl;   \
    }                                    \
  } while (false)

template <class Next>
class WasmInJSInliningReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(WasmInJSInlining)

  V<Any> REDUCE(Call)(V<CallTarget> callee,
                      OptionalV<turboshaft::FrameState> frame_state,
                      base::Vector<const OpIndex> arguments,
                      const TSCallDescriptor* descriptor, OpEffects effects) {
    if (!descriptor->js_wasm_call_parameters) {
      // Regular call, nothing to do with Wasm or inlining. Proceed untouched...
      return Next::ReduceCall(callee, frame_state, arguments, descriptor,
                              effects);
    }

    // We shouldn't have attached `JSWasmCallParameters` at this call, unless
    // we have TS Wasm-in-JS inlining enabled.
    CHECK(v8_flags.turboshaft_wasm_in_js_inlining);

    const wasm::WasmModule* module =
        descriptor->js_wasm_call_parameters->module();
    wasm::NativeModule* native_module =
        descriptor->js_wasm_call_parameters->native_module();
    uint32_t func_idx = descriptor->js_wasm_call_parameters->function_index();

    V<Any> result =
        TryInlineWasmCall(module, native_module, func_idx, arguments);
    if (result.valid()) {
      return result;
    } else {
      // The JS-to-Wasm wrapper was already inlined by the earlier TurboFan
      // phase, specifically `JSInliner::ReduceJSWasmCall`. However, it did
      // not toggle the thread-in-Wasm flag, since we don't want to set it
      // in the inline case above.
      // For the non-inline case, we need to toggle the flag now.
      // TODO(dlehmann,353475584): Reuse the code from
      // `WasmGraphBuilderBase::BuildModifyThreadInWasmFlag`, but that
      // requires a different assembler stack...
      OpIndex isolate_root = __ LoadRootRegister();
      V<WordPtr> thread_in_wasm_flag_address =
          __ Load(isolate_root, LoadOp::Kind::RawAligned().Immutable(),
                  MemoryRepresentation::UintPtr(),
                  Isolate::thread_in_wasm_flag_address_offset());
      __ Store(thread_in_wasm_flag_address, __ Word32Constant(1),
               LoadOp::Kind::RawAligned(), MemoryRepresentation::Int32(),
               compiler::kNoWriteBarrier);

      V<Any> result =
          Next::ReduceCall(callee, frame_state, arguments, descriptor, effects);

      __ Store(thread_in_wasm_flag_address, __ Word32Constant(0),
               LoadOp::Kind::RawAligned(), MemoryRepresentation::Int32(),
               compiler::kNoWriteBarrier);

      return result;
    }
  }

 private:
  V<Any> TryInlineWasmCall(const wasm::WasmModule* module,
                           wasm::NativeModule* native_module, uint32_t func_idx,
                           base::Vector<const OpIndex> arguments);
};

using wasm::ArrayIndexImmediate;
using wasm::BranchTableImmediate;
using wasm::CallFunctionImmediate;
using wasm::CallIndirectImmediate;
using wasm::FieldImmediate;
using wasm::GlobalIndexImmediate;
using wasm::IndexImmediate;
using wasm::MemoryAccessImmediate;
using wasm::MemoryCopyImmediate;
using wasm::MemoryIndexImmediate;
using wasm::MemoryInitImmediate;
using wasm::Simd128Immediate;
using wasm::SimdLaneImmediate;
using wasm::StringConstImmediate;
using wasm::StructIndexImmediate;
using wasm::TableCopyImmediate;
using wasm::TableIndexImmediate;
using wasm::TableInitImmediate;
using wasm::TagIndexImmediate;
using wasm::ValueType;
using wasm::WasmOpcode;

template <class Assembler>
class WasmInJsInliningInterface {
 public:
  using ValidationTag = wasm::Decoder::NoValidationTag;
  using FullDecoder =
      wasm::WasmFullDecoder<ValidationTag, WasmInJsInliningInterface>;
  struct Value : public wasm::ValueBase<ValidationTag> {
    OpIndex op = OpIndex::Invalid();
    template <typename... Args>
    explicit Value(Args&&... args) V8_NOEXCEPT
        : ValueBase(std::forward<Args>(args)...) {}
  };
  // TODO(dlehmann,353475584): Introduce a proper `Control` struct/class, once
  // we want to support control-flow in the inlinee.
  using Control = wasm::ControlBase<Value, ValidationTag>;
  static constexpr bool kUsesPoppedArgs = false;

  WasmInJsInliningInterface(Assembler& assembler,
                            base::Vector<const OpIndex> arguments,
                            V<WasmTrustedInstanceData> trusted_instance_data)
      : asm_(assembler),
        locals_(assembler.phase_zone()),
        arguments_(arguments),
        trusted_instance_data_(trusted_instance_data) {}

  V<Any> Result() { return result_; }

  void OnFirstError(FullDecoder*) {}

  void Bailout(FullDecoder* decoder) {
    decoder->errorf("unsupported operation: %s",
                    decoder->SafeOpcodeNameAt(decoder->pc()));
  }

  void StartFunction(FullDecoder* decoder) {
    locals_.resize(decoder->num_locals());

    // Initialize the function parameters, which are part of the local space.
    CHECK_LE(arguments_.size(), locals_.size());
    std::copy(arguments_.begin(), arguments_.end(), locals_.begin());

    // Initialize the non-parameter locals.
    uint32_t index = static_cast<uint32_t>(decoder->sig_->parameter_count());
    CHECK_EQ(index, arguments_.size());
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
        locals_[index++] = op;
      }
    }
  }
  void StartFunctionBody(FullDecoder* decoder, Control* block) {}
  void FinishFunction(FullDecoder* decoder) {}

  void NextInstruction(FullDecoder* decoder, WasmOpcode) {
    // TODO(dlehmann,353475584): Copied from Turboshaft graph builder, still
    // need to understand what the inlining ID is / where to get it.
    // __ SetCurrentOrigin(
    //     WasmPositionToOpIndex(decoder->position(), inlining_id_));
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {
    // This is just for testing bailouts in Liftoff, here it's just a nop.
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
    Bailout(decoder);
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
    result->op = UnOpImpl(decoder, opcode, value.op, value.type);
  }
  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    result->op = BinOpImpl(decoder, opcode, lhs.op, rhs.op);
  }

  OpIndex UnOpImpl(FullDecoder* decoder, WasmOpcode opcode, OpIndex arg,
                   ValueType input_type /* for ref.is_null only*/) {
    switch (opcode) {
      case wasm::kExprI32Eqz:
        return __ Word32Equal(arg, 0);
      case wasm::kExprF32Abs:
        return __ Float32Abs(arg);
      case wasm::kExprF32Neg:
        return __ Float32Negate(arg);
      case wasm::kExprF32Sqrt:
        return __ Float32Sqrt(arg);
      case wasm::kExprF64Abs:
        return __ Float64Abs(arg);
      case wasm::kExprF64Neg:
        return __ Float64Negate(arg);
      case wasm::kExprF64Sqrt:
        return __ Float64Sqrt(arg);
      case wasm::kExprF64SConvertI32:
        return __ ChangeInt32ToFloat64(arg);
      case wasm::kExprF64UConvertI32:
        return __ ChangeUint32ToFloat64(arg);
      case wasm::kExprF32SConvertI32:
        return __ ChangeInt32ToFloat32(arg);
      case wasm::kExprF32UConvertI32:
        return __ ChangeUint32ToFloat32(arg);
      case wasm::kExprF32ConvertF64:
        return __ TruncateFloat64ToFloat32(arg);
      case wasm::kExprF64ConvertF32:
        return __ ChangeFloat32ToFloat64(arg);
      case wasm::kExprF32ReinterpretI32:
        return __ BitcastWord32ToFloat32(arg);
      case wasm::kExprI32ReinterpretF32:
        return __ BitcastFloat32ToWord32(arg);
      case wasm::kExprI32Clz:
        return __ Word32CountLeadingZeros(arg);
      case wasm::kExprI32SExtendI8:
        return __ Word32SignExtend8(arg);
      case wasm::kExprI32SExtendI16:
        return __ Word32SignExtend16(arg);
      case wasm::kExprRefIsNull:
        return __ IsNull(arg, input_type);
      case wasm::kExprRefAsNonNull:
        // We abuse ref.as_non_null opcode (which is ordinarily a binary op and
        // not otherwise used in this switch) as a sentinel for the negation of
        // ref.is_null. See `function-body-decoder-impl.h`
        return __ Word32Equal(__ IsNull(arg, input_type), 0);

      // We currently don't support operations that:
      // - could trap,
      // - call a builtin,
      // - need the instance,
      // - require later Int64Lowering (which is currently only compatible with
      //   the Wasm pipeline),
      // - are actually asm.js opcodes and not spec'ed in Wasm.
      case wasm::kExprI32ConvertI64:
      case wasm::kExprI64SConvertI32:
      case wasm::kExprI64UConvertI32:
      case wasm::kExprF64ReinterpretI64:
      case wasm::kExprI64ReinterpretF64:
      case wasm::kExprI64Clz:
      case wasm::kExprI64Eqz:
      case wasm::kExprI64SExtendI8:
      case wasm::kExprI64SExtendI16:
      case wasm::kExprI64SExtendI32:
      case wasm::kExprI32SConvertF32:
      case wasm::kExprI32UConvertF32:
      case wasm::kExprI32SConvertF64:
      case wasm::kExprI32UConvertF64:
      case wasm::kExprI64SConvertF32:
      case wasm::kExprI64UConvertF32:
      case wasm::kExprI64SConvertF64:
      case wasm::kExprI64UConvertF64:
      case wasm::kExprI32SConvertSatF32:
      case wasm::kExprI32UConvertSatF32:
      case wasm::kExprI32SConvertSatF64:
      case wasm::kExprI32UConvertSatF64:
      case wasm::kExprI64SConvertSatF32:
      case wasm::kExprI64UConvertSatF32:
      case wasm::kExprI64SConvertSatF64:
      case wasm::kExprI64UConvertSatF64:
      case wasm::kExprI32Ctz:
      case wasm::kExprI32Popcnt:
      case wasm::kExprF32Floor:
      case wasm::kExprF32Ceil:
      case wasm::kExprF32Trunc:
      case wasm::kExprF32NearestInt:
      case wasm::kExprF64Floor:
      case wasm::kExprF64Ceil:
      case wasm::kExprF64Trunc:
      case wasm::kExprF64NearestInt:
      case wasm::kExprI64Ctz:
      case wasm::kExprI64Popcnt:
      case wasm::kExprF32SConvertI64:
      case wasm::kExprF32UConvertI64:
      case wasm::kExprF64SConvertI64:
      case wasm::kExprF64UConvertI64:

      // TODO(dlehmann): Fix arm64 no-ptr-compression builds, see relevant
      // earlier CL https://crrev.com/c/4311941/1..4.
      case wasm::kExprAnyConvertExtern:
      case wasm::kExprExternConvertAny:

      // asm.js:
      case wasm::kExprF64Acos:
      case wasm::kExprF64Asin:
      case wasm::kExprF64Atan:
      case wasm::kExprF64Cos:
      case wasm::kExprF64Sin:
      case wasm::kExprF64Tan:
      case wasm::kExprF64Exp:
      case wasm::kExprF64Log:
      case wasm::kExprI32AsmjsLoadMem8S:
      case wasm::kExprI32AsmjsLoadMem8U:
      case wasm::kExprI32AsmjsLoadMem16S:
      case wasm::kExprI32AsmjsLoadMem16U:
      case wasm::kExprI32AsmjsLoadMem:
      case wasm::kExprF32AsmjsLoadMem:
      case wasm::kExprF64AsmjsLoadMem:
      case wasm::kExprI32AsmjsSConvertF32:
      case wasm::kExprI32AsmjsUConvertF32:
      case wasm::kExprI32AsmjsSConvertF64:
      case wasm::kExprI32AsmjsUConvertF64:
        // Not supported, but we are aware of it. Bailout below.
        break;

      default:
        // Fuzzers should alert us when we forget ops, but it's not security
        // critical, so we just bailout below as well.
        DCHECK_WITH_MSG(false, "unhandled unary op");
    }

    Bailout(decoder);
    return OpIndex::Invalid();
  }

  OpIndex BinOpImpl(FullDecoder* decoder, WasmOpcode opcode, OpIndex lhs,
                    OpIndex rhs) {
    switch (opcode) {
      case wasm::kExprI32Add:
        return __ Word32Add(lhs, rhs);
      case wasm::kExprI32Sub:
        return __ Word32Sub(lhs, rhs);
      case wasm::kExprI32Mul:
        return __ Word32Mul(lhs, rhs);
      case wasm::kExprI32And:
        return __ Word32BitwiseAnd(lhs, rhs);
      case wasm::kExprI32Ior:
        return __ Word32BitwiseOr(lhs, rhs);
      case wasm::kExprI32Xor:
        return __ Word32BitwiseXor(lhs, rhs);
      case wasm::kExprI32Shl:
        // If possible, the bitwise-and gets optimized away later.
        return __ Word32ShiftLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32ShrS:
        return __ Word32ShiftRightArithmetic(lhs,
                                             __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32ShrU:
        return __ Word32ShiftRightLogical(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32Ror:
        return __ Word32RotateRight(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32Rol:
        if (SupportedOperations::word32_rol()) {
          return __ Word32RotateLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
        } else {
          return __ Word32RotateRight(
              lhs, __ Word32Sub(32, __ Word32BitwiseAnd(rhs, 0x1f)));
        }
      case wasm::kExprI32Eq:
        return __ Word32Equal(lhs, rhs);
      case wasm::kExprI32Ne:
        return __ Word32Equal(__ Word32Equal(lhs, rhs), 0);
      case wasm::kExprI32LtS:
        return __ Int32LessThan(lhs, rhs);
      case wasm::kExprI32LeS:
        return __ Int32LessThanOrEqual(lhs, rhs);
      case wasm::kExprI32LtU:
        return __ Uint32LessThan(lhs, rhs);
      case wasm::kExprI32LeU:
        return __ Uint32LessThanOrEqual(lhs, rhs);
      case wasm::kExprI32GtS:
        return __ Int32LessThan(rhs, lhs);
      case wasm::kExprI32GeS:
        return __ Int32LessThanOrEqual(rhs, lhs);
      case wasm::kExprI32GtU:
        return __ Uint32LessThan(rhs, lhs);
      case wasm::kExprI32GeU:
        return __ Uint32LessThanOrEqual(rhs, lhs);

      case wasm::kExprF32CopySign: {
        V<Word32> lhs_without_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(lhs), 0x7fffffff);
        V<Word32> rhs_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(rhs), 0x80000000);
        return __ BitcastWord32ToFloat32(
            __ Word32BitwiseOr(lhs_without_sign, rhs_sign));
      }
      case wasm::kExprF32Add:
        return __ Float32Add(lhs, rhs);
      case wasm::kExprF32Sub:
        return __ Float32Sub(lhs, rhs);
      case wasm::kExprF32Mul:
        return __ Float32Mul(lhs, rhs);
      case wasm::kExprF32Div:
        return __ Float32Div(lhs, rhs);
      case wasm::kExprF32Eq:
        return __ Float32Equal(lhs, rhs);
      case wasm::kExprF32Ne:
        return __ Word32Equal(__ Float32Equal(lhs, rhs), 0);
      case wasm::kExprF32Lt:
        return __ Float32LessThan(lhs, rhs);
      case wasm::kExprF32Le:
        return __ Float32LessThanOrEqual(lhs, rhs);
      case wasm::kExprF32Gt:
        return __ Float32LessThan(rhs, lhs);
      case wasm::kExprF32Ge:
        return __ Float32LessThanOrEqual(rhs, lhs);
      case wasm::kExprF32Min:
        return __ Float32Min(rhs, lhs);
      case wasm::kExprF32Max:
        return __ Float32Max(rhs, lhs);
      case wasm::kExprF64Add:
        return __ Float64Add(lhs, rhs);
      case wasm::kExprF64Sub:
        return __ Float64Sub(lhs, rhs);
      case wasm::kExprF64Mul:
        return __ Float64Mul(lhs, rhs);
      case wasm::kExprF64Div:
        return __ Float64Div(lhs, rhs);
      case wasm::kExprF64Eq:
        return __ Float64Equal(lhs, rhs);
      case wasm::kExprF64Ne:
        return __ Word32Equal(__ Float64Equal(lhs, rhs), 0);
      case wasm::kExprF64Lt:
        return __ Float64LessThan(lhs, rhs);
      case wasm::kExprF64Le:
        return __ Float64LessThanOrEqual(lhs, rhs);
      case wasm::kExprF64Gt:
        return __ Float64LessThan(rhs, lhs);
      case wasm::kExprF64Ge:
        return __ Float64LessThanOrEqual(rhs, lhs);
      case wasm::kExprF64Min:
        return __ Float64Min(lhs, rhs);
      case wasm::kExprF64Max:
        return __ Float64Max(lhs, rhs);
      case wasm::kExprRefEq:
        return __ TaggedEqual(lhs, rhs);

      // We currently don't support operations that:
      // - could trap,
      // - call a builtin,
      // - need the instance,
      // - require later Int64Lowering (which is currently only compatible with
      //   the Wasm pipeline),
      // - are actually asm.js opcodes and not spec'ed in Wasm.
      case wasm::kExprI64Add:
      case wasm::kExprI64Sub:
      case wasm::kExprI64Mul:
      case wasm::kExprI64And:
      case wasm::kExprI64Ior:
      case wasm::kExprI64Xor:
      case wasm::kExprI64Shl:
      case wasm::kExprI64ShrS:
      case wasm::kExprI64ShrU:
      case wasm::kExprI64Ror:
      case wasm::kExprI64Rol:
      case wasm::kExprI64Eq:
      case wasm::kExprI64Ne:
      case wasm::kExprI64LtS:
      case wasm::kExprI64LeS:
      case wasm::kExprI64LtU:
      case wasm::kExprI64LeU:
      case wasm::kExprI64GtS:
      case wasm::kExprI64GeS:
      case wasm::kExprI64GtU:
      case wasm::kExprI64GeU:

      case wasm::kExprF64CopySign:

      case wasm::kExprI32DivS:
      case wasm::kExprI32DivU:
      case wasm::kExprI32RemS:
      case wasm::kExprI32RemU:
      case wasm::kExprI64DivS:
      case wasm::kExprI64DivU:
      case wasm::kExprI64RemS:
      case wasm::kExprI64RemU:

      // asm.js:
      case wasm::kExprF64Atan2:
      case wasm::kExprF64Pow:
      case wasm::kExprF64Mod:
      case wasm::kExprI32AsmjsDivS:
      case wasm::kExprI32AsmjsDivU:
      case wasm::kExprI32AsmjsRemS:
      case wasm::kExprI32AsmjsRemU:
      case wasm::kExprI32AsmjsStoreMem8:
      case wasm::kExprI32AsmjsStoreMem16:
      case wasm::kExprI32AsmjsStoreMem:
      case wasm::kExprF32AsmjsStoreMem:
      case wasm::kExprF64AsmjsStoreMem:
        // Not supported, but we are aware of it. Bailout below.
        break;

      default:
        // Fuzzers should alert us when we forget ops, but it's not security
        // critical, so we just bailout below as well.
        DCHECK_WITH_MSG(false, "unhandled binary op");
    }

    Bailout(decoder);
    return OpIndex::Invalid();
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    result->op = __ Word32Constant(value);
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    // TODO(dlehmann,353475584): Support i64 ops.
    Bailout(decoder);
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    result->op = __ Float32Constant(value);
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    result->op = __ Float64Constant(value);
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    Bailout(decoder);
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value* result) {
    Bailout(decoder);
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    Bailout(decoder);
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    Bailout(decoder);
  }

  void Drop(FullDecoder* decoder) {}

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    result->op = locals_[imm.index];
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    locals_[imm.index] = value.op;
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    locals_[imm.index] = result->op = value.op;
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    if (shared) {
      return Bailout(decoder);
    }
    result->op = __ GlobalGet(trusted_instance_data_, imm.global);
  }

  void GlobalSet(FullDecoder* decoder, const Value& value,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    if (shared) {
      return Bailout(decoder);
    }
    __ GlobalSet(trusted_instance_data_, value.op, imm.global);
  }

  // TODO(dlehmann,353475584): Support control-flow in the inlinee.

  void Block(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void Loop(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void If(FullDecoder* decoder, const Value& cond, Control* if_block) {
    Bailout(decoder);
  }

### 提示词
```
这是目录为v8/src/compiler/turboshaft/wasm-in-js-inlining-reducer-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/wasm-in-js-inlining-reducer-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_TURBOSHAFT_WASM_IN_JS_INLINING_REDUCER_INL_H_
#define V8_COMPILER_TURBOSHAFT_WASM_IN_JS_INLINING_REDUCER_INL_H_

#include "src/compiler/js-inlining.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/define-assembler-macros.inc"
#include "src/compiler/turboshaft/index.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/wasm-assembler-helpers.h"
#include "src/heap/factory-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder-impl.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler::turboshaft {

#define TRACE(x)                         \
  do {                                   \
    if (v8_flags.trace_turbo_inlining) { \
      StdoutStream() << x << std::endl;  \
    }                                    \
  } while (false)

template <class Next>
class WasmInJSInliningReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(WasmInJSInlining)

  V<Any> REDUCE(Call)(V<CallTarget> callee,
                      OptionalV<turboshaft::FrameState> frame_state,
                      base::Vector<const OpIndex> arguments,
                      const TSCallDescriptor* descriptor, OpEffects effects) {
    if (!descriptor->js_wasm_call_parameters) {
      // Regular call, nothing to do with Wasm or inlining. Proceed untouched...
      return Next::ReduceCall(callee, frame_state, arguments, descriptor,
                              effects);
    }

    // We shouldn't have attached `JSWasmCallParameters` at this call, unless
    // we have TS Wasm-in-JS inlining enabled.
    CHECK(v8_flags.turboshaft_wasm_in_js_inlining);

    const wasm::WasmModule* module =
        descriptor->js_wasm_call_parameters->module();
    wasm::NativeModule* native_module =
        descriptor->js_wasm_call_parameters->native_module();
    uint32_t func_idx = descriptor->js_wasm_call_parameters->function_index();

    V<Any> result =
        TryInlineWasmCall(module, native_module, func_idx, arguments);
    if (result.valid()) {
      return result;
    } else {
      // The JS-to-Wasm wrapper was already inlined by the earlier TurboFan
      // phase, specifically `JSInliner::ReduceJSWasmCall`. However, it did
      // not toggle the thread-in-Wasm flag, since we don't want to set it
      // in the inline case above.
      // For the non-inline case, we need to toggle the flag now.
      // TODO(dlehmann,353475584): Reuse the code from
      // `WasmGraphBuilderBase::BuildModifyThreadInWasmFlag`, but that
      // requires a different assembler stack...
      OpIndex isolate_root = __ LoadRootRegister();
      V<WordPtr> thread_in_wasm_flag_address =
          __ Load(isolate_root, LoadOp::Kind::RawAligned().Immutable(),
                  MemoryRepresentation::UintPtr(),
                  Isolate::thread_in_wasm_flag_address_offset());
      __ Store(thread_in_wasm_flag_address, __ Word32Constant(1),
               LoadOp::Kind::RawAligned(), MemoryRepresentation::Int32(),
               compiler::kNoWriteBarrier);

      V<Any> result =
          Next::ReduceCall(callee, frame_state, arguments, descriptor, effects);

      __ Store(thread_in_wasm_flag_address, __ Word32Constant(0),
               LoadOp::Kind::RawAligned(), MemoryRepresentation::Int32(),
               compiler::kNoWriteBarrier);

      return result;
    }
  }

 private:
  V<Any> TryInlineWasmCall(const wasm::WasmModule* module,
                           wasm::NativeModule* native_module, uint32_t func_idx,
                           base::Vector<const OpIndex> arguments);
};

using wasm::ArrayIndexImmediate;
using wasm::BranchTableImmediate;
using wasm::CallFunctionImmediate;
using wasm::CallIndirectImmediate;
using wasm::FieldImmediate;
using wasm::GlobalIndexImmediate;
using wasm::IndexImmediate;
using wasm::MemoryAccessImmediate;
using wasm::MemoryCopyImmediate;
using wasm::MemoryIndexImmediate;
using wasm::MemoryInitImmediate;
using wasm::Simd128Immediate;
using wasm::SimdLaneImmediate;
using wasm::StringConstImmediate;
using wasm::StructIndexImmediate;
using wasm::TableCopyImmediate;
using wasm::TableIndexImmediate;
using wasm::TableInitImmediate;
using wasm::TagIndexImmediate;
using wasm::ValueType;
using wasm::WasmOpcode;

template <class Assembler>
class WasmInJsInliningInterface {
 public:
  using ValidationTag = wasm::Decoder::NoValidationTag;
  using FullDecoder =
      wasm::WasmFullDecoder<ValidationTag, WasmInJsInliningInterface>;
  struct Value : public wasm::ValueBase<ValidationTag> {
    OpIndex op = OpIndex::Invalid();
    template <typename... Args>
    explicit Value(Args&&... args) V8_NOEXCEPT
        : ValueBase(std::forward<Args>(args)...) {}
  };
  // TODO(dlehmann,353475584): Introduce a proper `Control` struct/class, once
  // we want to support control-flow in the inlinee.
  using Control = wasm::ControlBase<Value, ValidationTag>;
  static constexpr bool kUsesPoppedArgs = false;

  WasmInJsInliningInterface(Assembler& assembler,
                            base::Vector<const OpIndex> arguments,
                            V<WasmTrustedInstanceData> trusted_instance_data)
      : asm_(assembler),
        locals_(assembler.phase_zone()),
        arguments_(arguments),
        trusted_instance_data_(trusted_instance_data) {}

  V<Any> Result() { return result_; }

  void OnFirstError(FullDecoder*) {}

  void Bailout(FullDecoder* decoder) {
    decoder->errorf("unsupported operation: %s",
                    decoder->SafeOpcodeNameAt(decoder->pc()));
  }

  void StartFunction(FullDecoder* decoder) {
    locals_.resize(decoder->num_locals());

    // Initialize the function parameters, which are part of the local space.
    CHECK_LE(arguments_.size(), locals_.size());
    std::copy(arguments_.begin(), arguments_.end(), locals_.begin());

    // Initialize the non-parameter locals.
    uint32_t index = static_cast<uint32_t>(decoder->sig_->parameter_count());
    CHECK_EQ(index, arguments_.size());
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
        locals_[index++] = op;
      }
    }
  }
  void StartFunctionBody(FullDecoder* decoder, Control* block) {}
  void FinishFunction(FullDecoder* decoder) {}

  void NextInstruction(FullDecoder* decoder, WasmOpcode) {
    // TODO(dlehmann,353475584): Copied from Turboshaft graph builder, still
    // need to understand what the inlining ID is / where to get it.
    // __ SetCurrentOrigin(
    //     WasmPositionToOpIndex(decoder->position(), inlining_id_));
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {
    // This is just for testing bailouts in Liftoff, here it's just a nop.
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
    Bailout(decoder);
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
    result->op = UnOpImpl(decoder, opcode, value.op, value.type);
  }
  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    result->op = BinOpImpl(decoder, opcode, lhs.op, rhs.op);
  }

  OpIndex UnOpImpl(FullDecoder* decoder, WasmOpcode opcode, OpIndex arg,
                   ValueType input_type /* for ref.is_null only*/) {
    switch (opcode) {
      case wasm::kExprI32Eqz:
        return __ Word32Equal(arg, 0);
      case wasm::kExprF32Abs:
        return __ Float32Abs(arg);
      case wasm::kExprF32Neg:
        return __ Float32Negate(arg);
      case wasm::kExprF32Sqrt:
        return __ Float32Sqrt(arg);
      case wasm::kExprF64Abs:
        return __ Float64Abs(arg);
      case wasm::kExprF64Neg:
        return __ Float64Negate(arg);
      case wasm::kExprF64Sqrt:
        return __ Float64Sqrt(arg);
      case wasm::kExprF64SConvertI32:
        return __ ChangeInt32ToFloat64(arg);
      case wasm::kExprF64UConvertI32:
        return __ ChangeUint32ToFloat64(arg);
      case wasm::kExprF32SConvertI32:
        return __ ChangeInt32ToFloat32(arg);
      case wasm::kExprF32UConvertI32:
        return __ ChangeUint32ToFloat32(arg);
      case wasm::kExprF32ConvertF64:
        return __ TruncateFloat64ToFloat32(arg);
      case wasm::kExprF64ConvertF32:
        return __ ChangeFloat32ToFloat64(arg);
      case wasm::kExprF32ReinterpretI32:
        return __ BitcastWord32ToFloat32(arg);
      case wasm::kExprI32ReinterpretF32:
        return __ BitcastFloat32ToWord32(arg);
      case wasm::kExprI32Clz:
        return __ Word32CountLeadingZeros(arg);
      case wasm::kExprI32SExtendI8:
        return __ Word32SignExtend8(arg);
      case wasm::kExprI32SExtendI16:
        return __ Word32SignExtend16(arg);
      case wasm::kExprRefIsNull:
        return __ IsNull(arg, input_type);
      case wasm::kExprRefAsNonNull:
        // We abuse ref.as_non_null opcode (which is ordinarily a binary op and
        // not otherwise used in this switch) as a sentinel for the negation of
        // ref.is_null. See `function-body-decoder-impl.h`
        return __ Word32Equal(__ IsNull(arg, input_type), 0);

      // We currently don't support operations that:
      // - could trap,
      // - call a builtin,
      // - need the instance,
      // - require later Int64Lowering (which is currently only compatible with
      //   the Wasm pipeline),
      // - are actually asm.js opcodes and not spec'ed in Wasm.
      case wasm::kExprI32ConvertI64:
      case wasm::kExprI64SConvertI32:
      case wasm::kExprI64UConvertI32:
      case wasm::kExprF64ReinterpretI64:
      case wasm::kExprI64ReinterpretF64:
      case wasm::kExprI64Clz:
      case wasm::kExprI64Eqz:
      case wasm::kExprI64SExtendI8:
      case wasm::kExprI64SExtendI16:
      case wasm::kExprI64SExtendI32:
      case wasm::kExprI32SConvertF32:
      case wasm::kExprI32UConvertF32:
      case wasm::kExprI32SConvertF64:
      case wasm::kExprI32UConvertF64:
      case wasm::kExprI64SConvertF32:
      case wasm::kExprI64UConvertF32:
      case wasm::kExprI64SConvertF64:
      case wasm::kExprI64UConvertF64:
      case wasm::kExprI32SConvertSatF32:
      case wasm::kExprI32UConvertSatF32:
      case wasm::kExprI32SConvertSatF64:
      case wasm::kExprI32UConvertSatF64:
      case wasm::kExprI64SConvertSatF32:
      case wasm::kExprI64UConvertSatF32:
      case wasm::kExprI64SConvertSatF64:
      case wasm::kExprI64UConvertSatF64:
      case wasm::kExprI32Ctz:
      case wasm::kExprI32Popcnt:
      case wasm::kExprF32Floor:
      case wasm::kExprF32Ceil:
      case wasm::kExprF32Trunc:
      case wasm::kExprF32NearestInt:
      case wasm::kExprF64Floor:
      case wasm::kExprF64Ceil:
      case wasm::kExprF64Trunc:
      case wasm::kExprF64NearestInt:
      case wasm::kExprI64Ctz:
      case wasm::kExprI64Popcnt:
      case wasm::kExprF32SConvertI64:
      case wasm::kExprF32UConvertI64:
      case wasm::kExprF64SConvertI64:
      case wasm::kExprF64UConvertI64:

      // TODO(dlehmann): Fix arm64 no-ptr-compression builds, see relevant
      // earlier CL https://crrev.com/c/4311941/1..4.
      case wasm::kExprAnyConvertExtern:
      case wasm::kExprExternConvertAny:

      // asm.js:
      case wasm::kExprF64Acos:
      case wasm::kExprF64Asin:
      case wasm::kExprF64Atan:
      case wasm::kExprF64Cos:
      case wasm::kExprF64Sin:
      case wasm::kExprF64Tan:
      case wasm::kExprF64Exp:
      case wasm::kExprF64Log:
      case wasm::kExprI32AsmjsLoadMem8S:
      case wasm::kExprI32AsmjsLoadMem8U:
      case wasm::kExprI32AsmjsLoadMem16S:
      case wasm::kExprI32AsmjsLoadMem16U:
      case wasm::kExprI32AsmjsLoadMem:
      case wasm::kExprF32AsmjsLoadMem:
      case wasm::kExprF64AsmjsLoadMem:
      case wasm::kExprI32AsmjsSConvertF32:
      case wasm::kExprI32AsmjsUConvertF32:
      case wasm::kExprI32AsmjsSConvertF64:
      case wasm::kExprI32AsmjsUConvertF64:
        // Not supported, but we are aware of it. Bailout below.
        break;

      default:
        // Fuzzers should alert us when we forget ops, but it's not security
        // critical, so we just bailout below as well.
        DCHECK_WITH_MSG(false, "unhandled unary op");
    }

    Bailout(decoder);
    return OpIndex::Invalid();
  }

  OpIndex BinOpImpl(FullDecoder* decoder, WasmOpcode opcode, OpIndex lhs,
                    OpIndex rhs) {
    switch (opcode) {
      case wasm::kExprI32Add:
        return __ Word32Add(lhs, rhs);
      case wasm::kExprI32Sub:
        return __ Word32Sub(lhs, rhs);
      case wasm::kExprI32Mul:
        return __ Word32Mul(lhs, rhs);
      case wasm::kExprI32And:
        return __ Word32BitwiseAnd(lhs, rhs);
      case wasm::kExprI32Ior:
        return __ Word32BitwiseOr(lhs, rhs);
      case wasm::kExprI32Xor:
        return __ Word32BitwiseXor(lhs, rhs);
      case wasm::kExprI32Shl:
        // If possible, the bitwise-and gets optimized away later.
        return __ Word32ShiftLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32ShrS:
        return __ Word32ShiftRightArithmetic(lhs,
                                             __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32ShrU:
        return __ Word32ShiftRightLogical(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32Ror:
        return __ Word32RotateRight(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
      case wasm::kExprI32Rol:
        if (SupportedOperations::word32_rol()) {
          return __ Word32RotateLeft(lhs, __ Word32BitwiseAnd(rhs, 0x1f));
        } else {
          return __ Word32RotateRight(
              lhs, __ Word32Sub(32, __ Word32BitwiseAnd(rhs, 0x1f)));
        }
      case wasm::kExprI32Eq:
        return __ Word32Equal(lhs, rhs);
      case wasm::kExprI32Ne:
        return __ Word32Equal(__ Word32Equal(lhs, rhs), 0);
      case wasm::kExprI32LtS:
        return __ Int32LessThan(lhs, rhs);
      case wasm::kExprI32LeS:
        return __ Int32LessThanOrEqual(lhs, rhs);
      case wasm::kExprI32LtU:
        return __ Uint32LessThan(lhs, rhs);
      case wasm::kExprI32LeU:
        return __ Uint32LessThanOrEqual(lhs, rhs);
      case wasm::kExprI32GtS:
        return __ Int32LessThan(rhs, lhs);
      case wasm::kExprI32GeS:
        return __ Int32LessThanOrEqual(rhs, lhs);
      case wasm::kExprI32GtU:
        return __ Uint32LessThan(rhs, lhs);
      case wasm::kExprI32GeU:
        return __ Uint32LessThanOrEqual(rhs, lhs);

      case wasm::kExprF32CopySign: {
        V<Word32> lhs_without_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(lhs), 0x7fffffff);
        V<Word32> rhs_sign =
            __ Word32BitwiseAnd(__ BitcastFloat32ToWord32(rhs), 0x80000000);
        return __ BitcastWord32ToFloat32(
            __ Word32BitwiseOr(lhs_without_sign, rhs_sign));
      }
      case wasm::kExprF32Add:
        return __ Float32Add(lhs, rhs);
      case wasm::kExprF32Sub:
        return __ Float32Sub(lhs, rhs);
      case wasm::kExprF32Mul:
        return __ Float32Mul(lhs, rhs);
      case wasm::kExprF32Div:
        return __ Float32Div(lhs, rhs);
      case wasm::kExprF32Eq:
        return __ Float32Equal(lhs, rhs);
      case wasm::kExprF32Ne:
        return __ Word32Equal(__ Float32Equal(lhs, rhs), 0);
      case wasm::kExprF32Lt:
        return __ Float32LessThan(lhs, rhs);
      case wasm::kExprF32Le:
        return __ Float32LessThanOrEqual(lhs, rhs);
      case wasm::kExprF32Gt:
        return __ Float32LessThan(rhs, lhs);
      case wasm::kExprF32Ge:
        return __ Float32LessThanOrEqual(rhs, lhs);
      case wasm::kExprF32Min:
        return __ Float32Min(rhs, lhs);
      case wasm::kExprF32Max:
        return __ Float32Max(rhs, lhs);
      case wasm::kExprF64Add:
        return __ Float64Add(lhs, rhs);
      case wasm::kExprF64Sub:
        return __ Float64Sub(lhs, rhs);
      case wasm::kExprF64Mul:
        return __ Float64Mul(lhs, rhs);
      case wasm::kExprF64Div:
        return __ Float64Div(lhs, rhs);
      case wasm::kExprF64Eq:
        return __ Float64Equal(lhs, rhs);
      case wasm::kExprF64Ne:
        return __ Word32Equal(__ Float64Equal(lhs, rhs), 0);
      case wasm::kExprF64Lt:
        return __ Float64LessThan(lhs, rhs);
      case wasm::kExprF64Le:
        return __ Float64LessThanOrEqual(lhs, rhs);
      case wasm::kExprF64Gt:
        return __ Float64LessThan(rhs, lhs);
      case wasm::kExprF64Ge:
        return __ Float64LessThanOrEqual(rhs, lhs);
      case wasm::kExprF64Min:
        return __ Float64Min(lhs, rhs);
      case wasm::kExprF64Max:
        return __ Float64Max(lhs, rhs);
      case wasm::kExprRefEq:
        return __ TaggedEqual(lhs, rhs);

      // We currently don't support operations that:
      // - could trap,
      // - call a builtin,
      // - need the instance,
      // - require later Int64Lowering (which is currently only compatible with
      //   the Wasm pipeline),
      // - are actually asm.js opcodes and not spec'ed in Wasm.
      case wasm::kExprI64Add:
      case wasm::kExprI64Sub:
      case wasm::kExprI64Mul:
      case wasm::kExprI64And:
      case wasm::kExprI64Ior:
      case wasm::kExprI64Xor:
      case wasm::kExprI64Shl:
      case wasm::kExprI64ShrS:
      case wasm::kExprI64ShrU:
      case wasm::kExprI64Ror:
      case wasm::kExprI64Rol:
      case wasm::kExprI64Eq:
      case wasm::kExprI64Ne:
      case wasm::kExprI64LtS:
      case wasm::kExprI64LeS:
      case wasm::kExprI64LtU:
      case wasm::kExprI64LeU:
      case wasm::kExprI64GtS:
      case wasm::kExprI64GeS:
      case wasm::kExprI64GtU:
      case wasm::kExprI64GeU:

      case wasm::kExprF64CopySign:

      case wasm::kExprI32DivS:
      case wasm::kExprI32DivU:
      case wasm::kExprI32RemS:
      case wasm::kExprI32RemU:
      case wasm::kExprI64DivS:
      case wasm::kExprI64DivU:
      case wasm::kExprI64RemS:
      case wasm::kExprI64RemU:

      // asm.js:
      case wasm::kExprF64Atan2:
      case wasm::kExprF64Pow:
      case wasm::kExprF64Mod:
      case wasm::kExprI32AsmjsDivS:
      case wasm::kExprI32AsmjsDivU:
      case wasm::kExprI32AsmjsRemS:
      case wasm::kExprI32AsmjsRemU:
      case wasm::kExprI32AsmjsStoreMem8:
      case wasm::kExprI32AsmjsStoreMem16:
      case wasm::kExprI32AsmjsStoreMem:
      case wasm::kExprF32AsmjsStoreMem:
      case wasm::kExprF64AsmjsStoreMem:
        // Not supported, but we are aware of it. Bailout below.
        break;

      default:
        // Fuzzers should alert us when we forget ops, but it's not security
        // critical, so we just bailout below as well.
        DCHECK_WITH_MSG(false, "unhandled binary op");
    }

    Bailout(decoder);
    return OpIndex::Invalid();
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    result->op = __ Word32Constant(value);
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    // TODO(dlehmann,353475584): Support i64 ops.
    Bailout(decoder);
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    result->op = __ Float32Constant(value);
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    result->op = __ Float64Constant(value);
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    Bailout(decoder);
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value* result) {
    Bailout(decoder);
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    Bailout(decoder);
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    Bailout(decoder);
  }

  void Drop(FullDecoder* decoder) {}

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    result->op = locals_[imm.index];
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    locals_[imm.index] = value.op;
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    locals_[imm.index] = result->op = value.op;
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    if (shared) {
      return Bailout(decoder);
    }
    result->op = __ GlobalGet(trusted_instance_data_, imm.global);
  }

  void GlobalSet(FullDecoder* decoder, const Value& value,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    if (shared) {
      return Bailout(decoder);
    }
    __ GlobalSet(trusted_instance_data_, value.op, imm.global);
  }

  // TODO(dlehmann,353475584): Support control-flow in the inlinee.

  void Block(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void Loop(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void If(FullDecoder* decoder, const Value& cond, Control* if_block) {
    Bailout(decoder);
  }
  void Else(FullDecoder* decoder, Control* if_block) { Bailout(decoder); }
  void BrOrRet(FullDecoder* decoder, uint32_t depth, uint32_t drop_values = 0) {
    Bailout(decoder);
  }
  void BrIf(FullDecoder* decoder, const Value& cond, uint32_t depth) {
    Bailout(decoder);
  }
  void BrTable(FullDecoder* decoder, const BranchTableImmediate& imm,
               const Value& key) {
    Bailout(decoder);
  }

  void FallThruTo(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void PopControl(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void DoReturn(FullDecoder* decoder, uint32_t drop_values) {
    size_t return_count = decoder->sig_->return_count();

    if (return_count == 1) {
      result_ =
          decoder
              ->stack_value(static_cast<uint32_t>(return_count + drop_values))
              ->op;
    } else if (return_count == 0) {
      Isolate* isolate = __ data() -> isolate();
      DCHECK_NOT_NULL(isolate);
      result_ = __ HeapConstant(isolate->factory()->undefined_value());
    } else {
      // We currently don't support wrapper inlining with multi-value returns,
      // so this should never be hit.
      UNREACHABLE();
    }
  }
  void Select(FullDecoder* decoder, const Value& cond, const Value& fval,
              const Value& tval, Value* result) {
    Bailout(decoder);
  }

  // TODO(dlehmann,353475584): Support exceptions in the inlinee.

  void Try(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void Throw(FullDecoder* decoder, const TagIndexImmediate& imm,
             const Value arg_values[]) {
    Bailout(decoder);
  }
  void Rethrow(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void CatchException(FullDecoder* decoder, const TagIndexImmediate& imm,
                      Control* block, base::Vector<Value> values) {
    Bailout(decoder);
  }
  void Delegate(FullDecoder* decoder, uint32_t depth, Control* block) {
    Bailout(decoder);
  }

  void CatchAll(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void TryTable(FullDecoder* decoder, Control* block) { Bailout(decoder); }
  void CatchCase(FullDecoder* decoder, Control* block,
                 const wasm::CatchCase& catch_case,
                 base::Vector<Value> values) {
    Bailout(decoder);
  }
  void ThrowRef(FullDecoder* decoder, Value* value) { Bailout(decoder); }

  // TODO(dlehmann,353475584): Support traps in the inlinee.

  void Trap(FullDecoder* decoder, wasm::TrapReason reason) { Bailout(decoder); }
  void AssertNullTypecheck(FullDecoder* decoder, const Value& obj,
                           Value* result) {
    Bailout(decoder);
  }

  void AssertNotNullTypecheck(FullDecoder* decoder, const Value& obj,
                              Value* result) {
    Bailout(decoder);
  }
  void AtomicNotify(FullDecoder* decoder, const MemoryAccessImmediate& imm,
                    OpIndex index, OpIndex num_waiters_to_wake, Value* result) {
    Bailout(decoder);
  }
  void AtomicWait(FullDecoder* decoder, WasmOpcode opcode,
                  const MemoryAccessImmediate& imm, OpIndex index,
                  OpIndex expected, V<Word64> timeout, Value* result) {
    Bailout(decoder);
  }
  void AtomicOp(FullDecoder* decoder, WasmOpcode opcode, const Value args[],
                const size_t argc, const MemoryAccessImmediate& imm,
                Value* result) {
    Bailout(decoder);
  }
  void AtomicFence(FullDecoder* decoder) { Bailout(decoder); }

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    Bailout(decoder);
  }
  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value& dst, const Value& src, const Value& size) {
    Bailout(decoder);
  }
  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& dst, const Value& value, const Value& size) {
    Bailout(decoder);
  }
  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    Bailout(decoder);
  }

  void TableGet(FullDecoder* decoder, const Value& index, Value* result,
                const TableIndexImmediate& imm) {
    Bailout(decoder);
  }
  void TableSet(FullDecoder* decoder, const Value& index, const Value& value,
                const TableIndexImmediate& imm) {
    Bailout(decoder);
  }
  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    Bailout(decoder);
  }
  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value& dst_val, const Value& src_val,
                 const Value& size_val) {
    Bailout(decoder);
  }
  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& value, const Value& delta, Value* result) {
    Bailout(decoder);
  }
  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value& start, const Value& value, const Value& count) {
    Bailout(decoder);
  }
  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm,
                 Value* result) {
    Bailout(decoder);
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    Bailout(decoder);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    Bailout(decoder);
  }
  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    Bailout(decoder);
  }
  void StructGet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, bool is_signed, Value* result) {
    Bailout(decoder);
  }
  void StructSet(FullDecoder* decoder, const Value& struct_object,
                 const FieldImmediate& field, const Value& field_value) {
    Bailout(decoder);
  }
  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length, const Value& initial_value,
                Value* result) {
    Bailout(decoder);
  }
  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    // TODO(dlehmann): This will pull in/cause a lot of code duplication wrt.
    // the Wasm pipeline / `TurboshaftGraphBuildingInterface`.
    // How to reduce duplication best? Common superclass? But both will have
    // different Assemblers (reducer stacks), so I will have to templatize that.
    Bailout(decoder);
  }
  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                bool is_signed, Value* result) {
    Bailout(decoder);
  }
  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index,
                const Value& value) {
    Bailout(decoder);
  }
  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    Bailout(decoder);
  }
  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    Bailout(decoder);
  }
  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& index, const Value& value,
                 const Value& length) {
    Bailout(decoder);
  }
  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm, const Value elements[],
                     Value* result) {
    Bailout(decoder);
  }
  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm, const Value& offset,
                       const Value& length, Value* result) {
    Bailout(decoder);
  }
  void ArrayInitSegment(FullDecoder* decoder,
                        const ArrayIndexImmediate& array_imm,
                        const IndexImmediate& segment_imm, const Value& array,
                        const Value& array_index, const Value& segment_offset,
                        const Value& length) {
    Bailout(decoder);
  }

  void RefI31(FullDecoder* decoder, const Value& input, Value* result) {
    Bailout(decoder);
  }
  void I31GetS(FullDecoder* decoder, const Value& input, Value* result) {
    Bailout(decoder);
  }

  void I31GetU(FullDecoder* decoder, const Value& input, Value* result) {
    Bailout(decoder);
  }

  void RefTest(FullDecoder* decoder, wasm::ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    Bailout(decoder);
  }
  void RefTestAbstract(FullDecoder* decoder, const Value& object,
                       wasm::HeapType type, Value* result, bool null_succeeds) {
    Bailout(decoder);
  }
  void RefCast(FullDecoder* decoder, wasm::ModuleTypeIndex ref_index,
               const Value& object, Value* result, bool null_succeeds) {
    Bailout(decoder);
  }
  void RefCastAbstract(FullDecoder* decoder, const Value& object,
                       wasm::HeapType type, Value* result, bool null_succeeds) {
    Bailout(decoder);
  }
  void LoadMem(FullDecoder* decoder, wasm::LoadType type,
               const MemoryAccessImmediate& imm, const Value& index,
               Value* result) {
    Bailout(decoder);
  }
  void LoadTransform(FullDecoder* decoder, wasm::LoadType type,
                     wasm::LoadTransformationKind transform,
                     const MemoryAccessImmediate& imm, const Value& index,
                     Value* result) {
    Bailout(decoder);
  }
  void LoadLane(FullDecoder* decoder, wasm::LoadType type, const Value& value,
                const Value& index, const MemoryAccessImmediate& imm,
                const uint8_t laneidx, Value* result) {
    Bailout(decoder);
  }

  void StoreMem(FullDecoder* decoder, wasm::StoreType type,
                const MemoryAccessImmediate& imm, const Value& index,
                const Value& value) {
    Bailout(decoder);
  }

  void StoreLane(FullDecoder* decoder, wasm::StoreType type,
                 const MemoryAccessImmediate& imm, const Value& index,
                 const Value& value, const uint8_t laneidx) {
    Bailout(decoder);
  }

  void CurrentMemoryPages(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                          Value* result) {
    Bailout(decoder);
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result) {
    Bailout(decoder);
  }

  // TODO(dlehmann
```
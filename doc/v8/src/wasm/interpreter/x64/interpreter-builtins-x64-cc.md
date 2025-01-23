Response:

### 提示词
```
这是目录为v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/x64/interpreter-builtins-x64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/code-factory.h"
#include "src/codegen/macro-assembler.h"
#include "src/codegen/signature.h"
#include "src/execution/frame-constants.h"
#include "src/execution/isolate.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/interpreter/wasm-interpreter-runtime.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-objects.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

#define __ ACCESS_MASM(masm)

#if V8_ENABLE_WEBASSEMBLY

namespace {
// Helper functions for the GenericJSToWasmInterpreterWrapper.

void PrepareForJsToWasmConversionBuiltinCall(
    MacroAssembler* masm, Register array_start, Register param_count,
    Register current_param_slot, Register valuetypes_array_ptr,
    Register wasm_instance, Register function_data) {
  __ movq(
      MemOperand(
          rbp, BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset),
      Immediate(2));

  // Pushes and puts the values in order onto the stack before builtin calls for
  // the GenericJSToWasmInterpreterWrapper.
  __ pushq(array_start);
  __ pushq(param_count);
  __ pushq(current_param_slot);
  __ pushq(valuetypes_array_ptr);
  // The following two slots contain tagged objects that need to be visited
  // during GC.
  __ pushq(wasm_instance);
  __ pushq(function_data);
  // We had to prepare the parameters for the Call: we have to put the context
  // into rsi.
  Register wasm_trusted_instance = wasm_instance;
  __ LoadTrustedPointerField(
      wasm_trusted_instance,
      FieldMemOperand(wasm_instance, WasmInstanceObject::kTrustedDataOffset),
      kWasmTrustedInstanceDataIndirectPointerTag, kScratchRegister);
  __ LoadTaggedField(
      rsi, MemOperand(wasm_trusted_instance,
                      wasm::ObjectAccess::ToTagged(
                          WasmTrustedInstanceData::kNativeContextOffset)));
}

void RestoreAfterJsToWasmConversionBuiltinCall(
    MacroAssembler* masm, Register function_data, Register wasm_instance,
    Register valuetypes_array_ptr, Register current_param_slot,
    Register param_count, Register array_start) {
  // Pop and load values from the stack in order into the registers after
  // builtin calls for the GenericJSToWasmInterpreterWrapper.
  __ popq(function_data);
  __ popq(wasm_instance);
  __ popq(valuetypes_array_ptr);
  __ popq(current_param_slot);
  __ popq(param_count);
  __ popq(array_start);

  __ movq(
      MemOperand(
          rbp, BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset),
      Immediate(0));
}

void PrepareForBuiltinCall(MacroAssembler* masm, Register array_start,
                           Register return_count, Register wasm_instance) {
  // Pushes and puts the values in order onto the stack before builtin calls for
  // the GenericJSToWasmInterpreterWrapper.
  __ movq(
      MemOperand(
          rbp, BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset),
      Immediate(1));

  __ pushq(array_start);
  __ pushq(return_count);
  // The following slot contains a tagged object that need to be visited during
  // GC.
  __ pushq(wasm_instance);
  // We had to prepare the parameters for the Call: we have to put the context
  // into rsi.
  Register wasm_trusted_instance = wasm_instance;
  __ LoadTrustedPointerField(
      wasm_trusted_instance,
      FieldMemOperand(wasm_instance, WasmInstanceObject::kTrustedDataOffset),
      kWasmTrustedInstanceDataIndirectPointerTag, kScratchRegister);
  __ LoadTaggedField(
      rsi, MemOperand(wasm_trusted_instance,
                      wasm::ObjectAccess::ToTagged(
                          WasmTrustedInstanceData::kNativeContextOffset)));
}

void RestoreAfterBuiltinCall(MacroAssembler* masm, Register wasm_instance,
                             Register return_count, Register array_start) {
  // Pop and load values from the stack in order into the registers after
  // builtin calls for the GenericJSToWasmInterpreterWrapper.
  __ popq(wasm_instance);
  __ popq(return_count);
  __ popq(array_start);
}

void PrepareForWasmToJsConversionBuiltinCall(
    MacroAssembler* masm, Register return_count, Register result_index,
    Register current_return_slot, Register valuetypes_array_ptr,
    Register wasm_instance, Register fixed_array, Register jsarray) {
  __ movq(
      MemOperand(
          rbp, BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset),
      Immediate(3));

  // Pushes and puts the values in order onto the stack before builtin calls
  // for the GenericJSToWasmInterpreterWrapper.
  __ pushq(return_count);
  __ pushq(result_index);
  __ pushq(current_return_slot);
  __ pushq(valuetypes_array_ptr);
  // The following three slots contain tagged objects that need to be visited
  // during GC.
  __ pushq(wasm_instance);
  __ pushq(fixed_array);
  __ pushq(jsarray);
  // Put the context into rsi.
  Register wasm_trusted_instance = wasm_instance;
  __ LoadTrustedPointerField(
      wasm_trusted_instance,
      FieldMemOperand(wasm_instance, WasmInstanceObject::kTrustedDataOffset),
      kWasmTrustedInstanceDataIndirectPointerTag, kScratchRegister);
  __ LoadTaggedField(
      rsi, MemOperand(wasm_trusted_instance,
                      wasm::ObjectAccess::ToTagged(
                          WasmTrustedInstanceData::kNativeContextOffset)));
}

void RestoreAfterWasmToJsConversionBuiltinCall(
    MacroAssembler* masm, Register jsarray, Register fixed_array,
    Register wasm_instance, Register valuetypes_array_ptr,
    Register current_return_slot, Register result_index,
    Register return_count) {
  // Pop and load values from the stack in order into the registers after
  // builtin calls for the GenericJSToWasmInterpreterWrapper.
  __ popq(jsarray);
  __ popq(fixed_array);
  __ popq(wasm_instance);
  __ popq(valuetypes_array_ptr);
  __ popq(current_return_slot);
  __ popq(result_index);
  __ popq(return_count);
}

}  // namespace

void Builtins::Generate_WasmInterpreterEntry(MacroAssembler* masm) {
  Register wasm_instance = rsi;
  Register function_index = r12;
  Register array_start = r15;

  // Set up the stackframe.
  __ EnterFrame(StackFrame::WASM_INTERPRETER_ENTRY);

  __ pushq(wasm_instance);
  __ pushq(function_index);
  __ pushq(array_start);
  __ Move(wasm_instance, 0);
  __ CallRuntime(Runtime::kWasmRunInterpreter, 3);

  // Deconstruct the stack frame.
  __ LeaveFrame(StackFrame::WASM_INTERPRETER_ENTRY);
  __ ret(0);
}

void LoadFunctionDataAndWasmInstance(MacroAssembler* masm,
                                     Register function_data,
                                     Register wasm_instance) {
  Register closure = function_data;
  Register shared_function_info = closure;
  __ LoadTaggedField(
      shared_function_info,
      MemOperand(
          closure,
          wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction()));
  closure = no_reg;
  __ LoadTrustedPointerField(
      function_data,
      FieldOperand(shared_function_info,
                   SharedFunctionInfo::kTrustedFunctionDataOffset),
      kUnknownIndirectPointerTag, kScratchRegister);
  shared_function_info = no_reg;

  Register trusted_instance_data = wasm_instance;
#if V8_ENABLE_SANDBOX
  __ DecompressProtected(
      trusted_instance_data,
      MemOperand(function_data,
                 WasmExportedFunctionData::kProtectedInstanceDataOffset -
                     kHeapObjectTag));
#else
  __ LoadTaggedField(
      trusted_instance_data,
      MemOperand(function_data,
                 WasmExportedFunctionData::kProtectedInstanceDataOffset -
                     kHeapObjectTag));
#endif
  __ LoadTaggedField(wasm_instance,
                     MemOperand(trusted_instance_data,
                                WasmTrustedInstanceData::kInstanceObjectOffset -
                                    kHeapObjectTag));
}

void LoadFromSignature(MacroAssembler* masm, Register valuetypes_array_ptr,
                       Register return_count, Register param_count) {
  Register signature = valuetypes_array_ptr;
  __ movq(return_count,
          MemOperand(signature, wasm::FunctionSig::kReturnCountOffset));
  __ movq(param_count,
          MemOperand(signature, wasm::FunctionSig::kParameterCountOffset));
  valuetypes_array_ptr = signature;
  __ movq(valuetypes_array_ptr,
          MemOperand(signature, wasm::FunctionSig::kRepsOffset));
}

void LoadValueTypesArray(MacroAssembler* masm, Register function_data,
                         Register valuetypes_array_ptr, Register return_count,
                         Register param_count, Register signature_data) {
  __ LoadTaggedField(
      signature_data,
      FieldOperand(function_data,
                   WasmExportedFunctionData::kPackedArgsSizeOffset));
  __ SmiToInt32(signature_data);

  Register signature = valuetypes_array_ptr;
  __ movq(signature,
          MemOperand(function_data,
                     WasmExportedFunctionData::kSigOffset - kHeapObjectTag));
  LoadFromSignature(masm, valuetypes_array_ptr, return_count, param_count);
}

// TODO(paolosev@microsoft.com): this should be converted into a Torque builtin,
// like it was done for GenericJSToWasmWrapper.
void Builtins::Generate_GenericJSToWasmInterpreterWrapper(
    MacroAssembler* masm) {
  // Set up the stackframe.
  __ EnterFrame(StackFrame::JS_TO_WASM);

  // -------------------------------------------
  // Compute offsets and prepare for GC.
  // -------------------------------------------
  // GenericJSToWasmInterpreterWrapperFrame:
  // rbp-N     Args/retvals array for Wasm call
  // ...       ...
  // rbp-0x50  SignatureData (== rbp-N)
  // rbp-0x48  CurrentIndex
  // rbp-0x40  ArgRetsIsArgs
  // rbp-0x38  ArgRetsAddress
  // rbp-0x30  ValueTypesArray
  // rbp-0x28  ReturnCount
  // rbp-0x20  ParamCount
  // rbp-0x18  InParamCount
  // rbp-0x10  GCScanSlotCount
  // rbp-0x08  Marker(StackFrame::JS_TO_WASM)
  // rbp       Old RBP
  // rbp+0x08  return address
  // rbp+0x10  receiver
  // rpb+0x18  arg

  constexpr int kMarkerOffset =
      BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset +
      kSystemPointerSize;
  // The number of parameters passed to this function.
  constexpr int kInParamCountOffset =
      BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset -
      kSystemPointerSize;
  // The number of parameters according to the signature.
  constexpr int kParamCountOffset =
      BuiltinWasmInterpreterWrapperConstants::kParamCountOffset;
  constexpr int kReturnCountOffset =
      BuiltinWasmInterpreterWrapperConstants::kReturnCountOffset;
  constexpr int kValueTypesArrayStartOffset =
      BuiltinWasmInterpreterWrapperConstants::kValueTypesArrayStartOffset;
  // Array for arguments and return values. They will be scanned by GC.
  constexpr int kArgRetsAddressOffset =
      BuiltinWasmInterpreterWrapperConstants::kArgRetsAddressOffset;
  // Arg/Return arrays use the same stack address. So, we should keep a flag
  // whether we are using the array for args or returns. (1 = Args, 0 = Rets)
  constexpr int kArgRetsIsArgsOffset =
      BuiltinWasmInterpreterWrapperConstants::kArgRetsIsArgsOffset;
  // The index of the argument being converted.
  constexpr int kCurrentIndexOffset =
      BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset;
  // Precomputed signature data, a uint32_t with the format:
  // bit 0-14: PackedArgsSize
  // bit 15:   HasRefArgs
  // bit 16:   HasRefRets
  constexpr int kSignatureDataOffset =
      BuiltinWasmInterpreterWrapperConstants::kSignatureDataOffset;
  // We set and use this slot only when moving parameters into the parameter
  // registers (so no GC scan is needed).
  constexpr int kNumSpillSlots =
      (kMarkerOffset - kSignatureDataOffset) / kSystemPointerSize;
  __ subq(rsp, Immediate(kNumSpillSlots * kSystemPointerSize));
  // Put the in_parameter count on the stack, we only need it at the very end
  // when we pop the parameters off the stack.
  Register in_param_count = rax;
  __ decq(in_param_count);
  __ movq(MemOperand(rbp, kInParamCountOffset), in_param_count);
  in_param_count = no_reg;

  // -------------------------------------------
  // Load the Wasm exported function data and the Wasm instance.
  // -------------------------------------------
  Register function_data = rdi;
  Register wasm_instance = kWasmImplicitArgRegister;  // rsi
  LoadFunctionDataAndWasmInstance(masm, function_data, wasm_instance);

  // -------------------------------------------
  // Load values from the signature.
  // -------------------------------------------
  Register valuetypes_array_ptr = r11;
  Register return_count = r8;
  Register param_count = rcx;
  Register signature_data = r15;
  LoadValueTypesArray(masm, function_data, valuetypes_array_ptr, return_count,
                      param_count, signature_data);
  __ movq(MemOperand(rbp, kSignatureDataOffset), signature_data);
  Register array_size = signature_data;
  signature_data = no_reg;
  __ andq(array_size,
          Immediate(wasm::WasmInterpreterRuntime::PackedArgsSizeField::kMask));

  // -------------------------------------------
  // Store signature-related values to the stack.
  // -------------------------------------------
  // We store values on the stack to restore them after function calls.
  // We cannot push values onto the stack right before the wasm call. The wasm
  // function expects the parameters, that didn't fit into the registers, on the
  // top of the stack.
  __ movq(MemOperand(rbp, kParamCountOffset), param_count);
  __ movq(MemOperand(rbp, kReturnCountOffset), return_count);
  __ movq(MemOperand(rbp, kValueTypesArrayStartOffset), valuetypes_array_ptr);

  // -------------------------------------------
  // Allocate array for args and return value.
  // -------------------------------------------
  Register array_start = array_size;
  array_size = no_reg;
  __ negq(array_start);
  __ addq(array_start, rsp);
  __ movq(rsp, array_start);
  __ movq(MemOperand(rbp, kArgRetsAddressOffset), array_start);

  __ movq(MemOperand(rbp, kArgRetsIsArgsOffset), Immediate(1));
  __ Move(MemOperand(rbp, kCurrentIndexOffset), 0);

  Label prepare_for_wasm_call;
  __ Cmp(param_count, 0);

  // If we have 0 params: jump through parameter handling.
  __ j(equal, &prepare_for_wasm_call);

  // Create a section on the stack to pass the evaluated parameters to the
  // interpreter and to receive the results. This section represents the array
  // expected as argument by the Runtime_WasmRunInterpreter.
  // Arguments are stored one after the other without holes, starting at the
  // beginning of the array, and the interpreter puts the returned values in the
  // same array, also starting at the beginning.

  // Set the current_param_slot to point to the start of the section.
  Register current_param_slot = r10;
  __ movq(current_param_slot, array_start);

  // Loop through the params starting with the first.
  // [rbp + 8 * current_index + kArgsOffset] gives us the JS argument we are
  // processing. We iterate through half-open interval [1st param, rbp + 8 *
  // param_count + kArgsOffset).

  constexpr int kReceiverOnStackSize = kSystemPointerSize;
  constexpr int kArgsOffset =
      kFPOnStackSize + kPCOnStackSize + kReceiverOnStackSize;

  Register param = rax;
  // We have to check the types of the params. The ValueType array contains
  // first the return then the param types.
  constexpr int kValueTypeSize = sizeof(wasm::ValueType);
  static_assert(kValueTypeSize == 4);
  const int32_t kValueTypeSizeLog2 = log2(kValueTypeSize);
  // Set the ValueType array pointer to point to the first parameter.
  Register returns_size = return_count;
  return_count = no_reg;
  __ shlq(returns_size, Immediate(kValueTypeSizeLog2));
  __ addq(valuetypes_array_ptr, returns_size);
  returns_size = no_reg;

  Register current_index = rbx;
  __ Move(current_index, 0);

  // -------------------------------------------
  // Param evaluation loop.
  // -------------------------------------------
  Label loop_through_params;
  __ bind(&loop_through_params);

  __ movq(MemOperand(
              rbp, BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset),
          current_index);
  __ movq(param, MemOperand(rbp, current_index, times_system_pointer_size,
                            kArgsOffset));

  Register valuetype = r12;
  __ movl(valuetype,
          Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  // -------------------------------------------
  // Param conversion.
  // -------------------------------------------
  // If param is a Smi we can easily convert it. Otherwise we'll call a builtin
  // for conversion.
  Label param_conversion_done;
  Label check_ref_param;
  Label convert_param;
  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(not_equal, &check_ref_param);
  __ JumpIfNotSmi(param, &convert_param);

  // Change the param from Smi to int32.
  __ SmiUntag(param);
  // Zero extend.
  __ movl(param, param);
  // Place the param into the proper slot in Integer section.
  __ movq(MemOperand(current_param_slot, 0), param);
  __ addq(current_param_slot, Immediate(sizeof(int32_t)));
  __ jmp(&param_conversion_done);

  Label handle_ref_param;
  __ bind(&check_ref_param);
  __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ j(equal, &handle_ref_param);
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
  __ j(not_equal, &convert_param);

  // Place the reference param into the proper slot.
  __ bind(&handle_ref_param);
  // Make sure slot for ref args are 64-bit aligned.
  __ movq(r9, current_param_slot);
  __ andq(r9, Immediate(0x04));
  __ addq(current_param_slot, r9);
  __ movq(MemOperand(current_param_slot, 0), param);
  __ addq(current_param_slot, Immediate(kSystemPointerSize));

  // -------------------------------------------
  // Param conversion done.
  // -------------------------------------------
  __ bind(&param_conversion_done);

  __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));

  __ movq(
      current_index,
      MemOperand(rbp,
                 BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset));
  __ incq(current_index);
  __ cmpq(current_index, param_count);
  __ j(less, &loop_through_params);
  __ movq(MemOperand(
              rbp, BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset),
          current_index);

  // ----------- S t a t e -------------
  //  -- r10 : current_param_slot
  //  -- r11 : valuetypes_array_ptr
  //  -- r15 : array_start
  //  -- rdi : function_data
  //  -- rsi : wasm_trusted_instance
  //  -- GpParamRegisters = rax, rdx, rcx, rbx, r9
  // -----------------------------------

  __ bind(&prepare_for_wasm_call);
  // -------------------------------------------
  // Prepare for the Wasm call.
  // -------------------------------------------
  // Set thread_in_wasm_flag.
  Register thread_in_wasm_flag_addr = r12;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(1));
  thread_in_wasm_flag_addr = no_reg;

  Register function_index = r12;
  __ movl(
      function_index,
      MemOperand(function_data, WasmExportedFunctionData::kFunctionIndexOffset -
                                    kHeapObjectTag));
  // We pass function_index as Smi.

  // One tagged object (the wasm_instance) to be visited if there is a GC
  // during the call.
  constexpr int kWasmCallGCScanSlotCount = 1;
  __ Move(
      MemOperand(
          rbp, BuiltinWasmInterpreterWrapperConstants::kGCScanSlotCountOffset),
      kWasmCallGCScanSlotCount);

  // -------------------------------------------
  // Call the Wasm function.
  // -------------------------------------------
  __ pushq(wasm_instance);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmInterpreterEntry),
          RelocInfo::CODE_TARGET);
  __ popq(wasm_instance);
  __ movq(array_start, MemOperand(rbp, kArgRetsAddressOffset));
  __ Move(MemOperand(rbp, kArgRetsIsArgsOffset), 0);

  function_index = no_reg;

  // Unset thread_in_wasm_flag.
  thread_in_wasm_flag_addr = r8;
  __ movq(
      thread_in_wasm_flag_addr,
      MemOperand(kRootRegister, Isolate::thread_in_wasm_flag_address_offset()));
  __ movl(MemOperand(thread_in_wasm_flag_addr, 0), Immediate(0));
  thread_in_wasm_flag_addr = no_reg;

  // -------------------------------------------
  // Return handling.
  //
  // ----------- S t a t e -------------
  //  -- r15 : array_start
  //  -- rsi : wasm_instance
  // -------------------------------------------
  return_count = r8;
  __ movq(return_count, MemOperand(rbp, kReturnCountOffset));

  // All return values are already in the packed array.
  __ movq(MemOperand(
              rbp, BuiltinWasmInterpreterWrapperConstants::kCurrentIndexOffset),
          return_count);

  Register return_value = rax;
  Register fixed_array = rdi;
  __ Move(fixed_array, 0);
  Register jsarray = rdx;
  __ Move(jsarray, 0);

  Label return_undefined;
  __ cmpl(return_count, Immediate(1));
  // If no return value, load undefined.
  __ j(less, &return_undefined);

  Label start_return_conversion;
  // If we have more than one return value, we need to return a JSArray.
  __ j(equal, &start_return_conversion);

  PrepareForBuiltinCall(masm, array_start, return_count, wasm_instance);
  __ movq(rax, return_count);
  __ SmiTag(rax);
  // Create JSArray to hold results.
  __ Call(BUILTIN_CODE(masm->isolate(), WasmAllocateJSArray),
          RelocInfo::CODE_TARGET);
  __ movq(jsarray, rax);
  RestoreAfterBuiltinCall(masm, wasm_instance, return_count, array_start);
  __ LoadTaggedField(fixed_array, MemOperand(jsarray, JSArray::kElementsOffset -
                                                          kHeapObjectTag));

  __ bind(&start_return_conversion);
  Register current_return_slot = array_start;

  Register result_index = r9;
  __ xorq(result_index, result_index);

  Label convert_return_value;
  __ jmp(&convert_return_value);

  __ bind(&return_undefined);
  __ LoadRoot(return_value, RootIndex::kUndefinedValue);
  Label all_results_conversion_done;
  __ jmp(&all_results_conversion_done);

  Label next_return_value;
  __ bind(&next_return_value);
  __ incq(result_index);
  __ cmpq(result_index, return_count);
  __ j(less, &convert_return_value);

  __ bind(&all_results_conversion_done);
  __ movq(param_count, MemOperand(rbp, kParamCountOffset));

  Label do_return;
  __ cmpq(fixed_array, Immediate(0));
  __ j(equal, &do_return);
  // The result is jsarray.
  __ movq(rax, jsarray);

  // Calculate the number of parameters we have to pop off the stack. This
  // number is max(in_param_count, param_count).
  __ bind(&do_return);
  in_param_count = rdx;
  __ movq(in_param_count, MemOperand(rbp, kInParamCountOffset));
  __ cmpq(param_count, in_param_count);
  __ cmovq(less, param_count, in_param_count);

  // -------------------------------------------
  // Deconstruct the stack frame.
  // -------------------------------------------
  __ LeaveFrame(StackFrame::JS_TO_WASM);

  // We have to remove the caller frame slots:
  //  - JS arguments
  //  - the receiver
  // and transfer the control to the return address (the return address is
  // expected to be on the top of the stack).
  // We cannot use just the ret instruction for this, because we cannot pass the
  // number of slots to remove in a Register as an argument.
  __ DropArguments(param_count, rbx);
  __ ret(0);

  // --------------------------------------------------------------------------
  //                          Deferred code.
  // --------------------------------------------------------------------------

  // -------------------------------------------
  // Param conversion builtins.
  // -------------------------------------------
  __ bind(&convert_param);
  // The order of pushes is important. We want the heap objects, that should be
  // scanned by GC, to be on the top of the stack.
  // We have to set the indicating value for the GC to the number of values on
  // the top of the stack that have to be scanned before calling the builtin
  // function.
  // We don't need the JS context for these builtin calls.
  // The builtin expects the parameter to be in register param = rax.

  PrepareForJsToWasmConversionBuiltinCall(
      masm, array_start, param_count, current_param_slot, valuetypes_array_ptr,
      wasm_instance, function_data);

  Label param_kWasmI32_not_smi;
  Label param_kWasmI64;
  Label param_kWasmF32;
  Label param_kWasmF64;
  Label throw_type_error;

  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(equal, &param_kWasmI32_not_smi);
  __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ j(equal, &param_kWasmI64);
  __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ j(equal, &param_kWasmF32);
  __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ j(equal, &param_kWasmF64);

  __ cmpq(valuetype, Immediate(wasm::kWasmS128.raw_bit_field()));
  // Simd arguments cannot be passed from JavaScript.
  __ j(equal, &throw_type_error);

  __ int3();

  __ bind(&param_kWasmI32_not_smi);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedNonSmiToInt32),
          RelocInfo::CODE_TARGET);
  // Param is the result of the builtin.
  __ AssertZeroExtended(param);
  RestoreAfterJsToWasmConversionBuiltinCall(
      masm, function_data, wasm_instance, valuetypes_array_ptr,
      current_param_slot, param_count, array_start);
  __ movl(MemOperand(current_param_slot, 0), param);
  __ addq(current_param_slot, Immediate(sizeof(int32_t)));
  __ jmp(&param_conversion_done);

  __ bind(&param_kWasmI64);
  __ Call(BUILTIN_CODE(masm->isolate(), BigIntToI64), RelocInfo::CODE_TARGET);
  RestoreAfterJsToWasmConversionBuiltinCall(
      masm, function_data, wasm_instance, valuetypes_array_ptr,
      current_param_slot, param_count, array_start);
  __ movq(MemOperand(current_param_slot, 0), param);
  __ addq(current_param_slot, Immediate(sizeof(int64_t)));
  __ jmp(&param_conversion_done);

  __ bind(&param_kWasmF32);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedToFloat32),
          RelocInfo::CODE_TARGET);
  RestoreAfterJsToWasmConversionBuiltinCall(
      masm, function_data, wasm_instance, valuetypes_array_ptr,
      current_param_slot, param_count, array_start);
  __ Movsd(MemOperand(current_param_slot, 0), xmm0);
  __ addq(current_param_slot, Immediate(sizeof(float)));
  __ jmp(&param_conversion_done);

  __ bind(&param_kWasmF64);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmTaggedToFloat64),
          RelocInfo::CODE_TARGET);
  RestoreAfterJsToWasmConversionBuiltinCall(
      masm, function_data, wasm_instance, valuetypes_array_ptr,
      current_param_slot, param_count, array_start);
  __ Movsd(MemOperand(current_param_slot, 0), xmm0);
  __ addq(current_param_slot, Immediate(sizeof(double)));
  __ jmp(&param_conversion_done);

  __ bind(&throw_type_error);
  // CallRuntime expects kRootRegister (r13) to contain the root.
  __ CallRuntime(Runtime::kWasmThrowJSTypeError);
  __ int3();  // Should not return.

  // -------------------------------------------
  // Return conversions.
  // -------------------------------------------
  __ bind(&convert_return_value);
  // We have to make sure that the kGCScanSlotCount is set correctly when we
  // call the builtins for conversion. For these builtins it's the same as for
  // the Wasm call, that is, kGCScanSlotCount = 0, so we don't have to reset it.
  // We don't need the JS context for these builtin calls.

  __ movq(valuetypes_array_ptr, MemOperand(rbp, kValueTypesArrayStartOffset));
  // The first valuetype of the array is the return's valuetype.
  __ movl(valuetype,
          Operand(valuetypes_array_ptr, wasm::ValueType::bit_field_offset()));

  Label return_kWasmI32;
  Label return_kWasmI64;
  Label return_kWasmF32;
  Label return_kWasmF64;
  Label return_kWasmRef;

  __ cmpq(valuetype, Immediate(wasm::kWasmI32.raw_bit_field()));
  __ j(equal, &return_kWasmI32);

  __ cmpq(valuetype, Immediate(wasm::kWasmI64.raw_bit_field()));
  __ j(equal, &return_kWasmI64);

  __ cmpq(valuetype, Immediate(wasm::kWasmF32.raw_bit_field()));
  __ j(equal, &return_kWasmF32);

  __ cmpq(valuetype, Immediate(wasm::kWasmF64.raw_bit_field()));
  __ j(equal, &return_kWasmF64);

  __ andl(valuetype, Immediate(wasm::kWasmValueKindBitsMask));
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRefNull));
  __ j(equal, &return_kWasmRef);
  __ cmpq(valuetype, Immediate(wasm::ValueKind::kRef));
  __ j(equal, &return_kWasmRef);

  // Invalid type. Wasm cannot return Simd results to JavaScript.
  __ int3();

  Label return_value_done;

  __ bind(&return_kWasmI32);
  __ movl(return_value, MemOperand(current_return_slot, 0));
  __ addq(current_return_slot, Immediate(sizeof(int32_t)));
  Label to_heapnumber;
  // If pointer compression is disabled, we can convert the return to a smi.
  if (SmiValuesAre32Bits()) {
    __ SmiTag(return_value);
  } else {
    Register temp = rbx;
    __ movq(temp, return_value);
    // Double the return value to test if it can be a Smi.
    __ addl(temp, return_value);
    temp = no_reg;
    // If there was overflow, convert to a HeapNumber.
    __ j(overflow, &to_heapnumber);
    // If there was no overflow, we can convert to Smi.
    __ SmiTag(return_value);
  }
  __ jmp(&return_value_done);

  // Handle the conversion of the I32 return value to HeapNumber when it cannot
  // be a smi.
  __ bind(&to_heapnumber);

  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmInt32ToHeapNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmI64);
  __ movq(return_value, MemOperand(current_return_slot, 0));
  __ addq(current_return_slot, Immediate(sizeof(int64_t)));
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), I64ToBigInt), RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmF32);
  __ movq(xmm1, MemOperand(current_return_slot, 0));
  __ addq(current_return_slot, Immediate(sizeof(float)));
  // The builtin expects the value to be in xmm0.
  __ Movss(xmm0, xmm1);
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat32ToNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmF64);
  // The builtin expects the value to be in xmm0.
  __ movq(xmm0, MemOperand(current_return_slot, 0));
  __ addq(current_return_slot, Immediate(sizeof(double)));
  PrepareForWasmToJsConversionBuiltinCall(
      masm, return_count, result_index, current_return_slot,
      valuetypes_array_ptr, wasm_instance, fixed_array, jsarray);
  __ Call(BUILTIN_CODE(masm->isolate(), WasmFloat64ToNumber),
          RelocInfo::CODE_TARGET);
  RestoreAfterWasmToJsConversionBuiltinCall(
      masm, jsarray, fixed_array, wasm_instance, valuetypes_array_ptr,
      current_return_slot, result_index, return_count);
  __ jmp(&return_value_done);

  __ bind(&return_kWasmRef);
  // Make sure slot for ref args are 64-bit aligned.
  __ movq(rbx, current_return_slot);
  __ andq(rbx, Immediate(0x04));
  __ addq(current_return_slot, rbx);
  __ movq(return_value, MemOperand(current_return_slot, 0));
  __ addq(current_return_slot, Immediate(kSystemPointerSize));
  // Do not modify the result in return_value.

  __ bind(&return_value_done);
  __ addq(valuetypes_array_ptr, Immediate(kValueTypeSize));
  __ movq(MemOperand(rbp, kValueTypesArrayStartOffset), valuetypes_array_ptr);
  __ cmpq(fixed_array, Immediate(0));
  __ j(equal, &next_return_value);

  // Store resu
```
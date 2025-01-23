Response:
The user wants to understand the functionality of the `v8/src/codegen/external-reference.cc` file in the V8 JavaScript engine. I need to analyze the provided C++ code and explain its purpose.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file defines the `ExternalReference` class and provides static methods to create instances of it. Looking at the included headers and the names of the static methods, it's clear that `ExternalReference` is used to represent references to entities outside the generated code (e.g., C++ functions, global variables, isolate data). This is crucial for the V8 compiler to interact with the runtime environment.

2. **Check for Torque:** The prompt specifically asks if the file is a Torque file based on the `.tq` extension. The given file ends in `.cc`, so it's a regular C++ file, not a Torque file.

3. **Analyze JavaScript relevance:**  The file heavily interacts with V8 internals like `Isolate`, `Heap`, `Runtime`, and even includes headers related to JavaScript features like `Date` and `RegExp`. This strongly suggests a relationship with JavaScript functionality. I need to find concrete examples of how these external references are used in the context of JavaScript operations. The presence of references to `Runtime::FunctionId` and specific runtime functions is a key indicator.

4. **Look for code logic and examples:** The code defines constants and functions related to various aspects of V8. While there isn't explicit complex logic *within this file*, the *creation* of `ExternalReference` instances based on different inputs (`ApiFunction`, `Runtime::FunctionId`, raw addresses) implies different use cases and potential branching logic in the compiler that utilizes these references. The examples provided in the code itself (like `f64_acos_wrapper`) can be used to illustrate functionality.

5. **Consider common programming errors:** The concept of external references, especially function pointers, can be a source of errors if types don't match. Calling a C++ function with the wrong signature from JavaScript or generated code is a classic example.

6. **Structure the response:**  I should organize the information into the categories requested by the user:
    * Overall functionality
    * Torque check
    * JavaScript relationship and examples
    * Code logic/inference (even if basic)
    * Common errors
    * Summary for Part 1

7. **Draft the response (internal monologue during generation):**

    * "Okay, the main thing is `ExternalReference`. It's like a bridge between the compiled code and the C++ runtime."
    * "It's definitely not a `.tq` file."
    * "How does this relate to JavaScript?  Well, when JavaScript code needs to call built-in functions or access internal data, that's where these references come in. Think of `Math.random()` or accessing properties of objects."
    * "The code itself doesn't have complex `if/else`, but the *creation* of these references is based on different types of external entities. Let's show a simple case where we get a reference to a runtime function."
    * "What can go wrong?  Mismatched function signatures are a big one. Imagine trying to pass a string to a function that expects a number."
    * "For the summary, just reiterate the main purpose: managing external references for the compiler."

8. **Refine and polish:** Ensure the language is clear, concise, and accurate. Provide concrete examples where possible. Make sure to address all parts of the user's request. For instance, explicitly mention the use of `Redirect` and the role of the simulator.

By following these steps, I can generate a comprehensive and informative response that addresses all aspects of the user's query about the `external-reference.cc` file.
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/external-reference.h"

#include <optional>

#include "include/v8-fast-api-calls.h"
#include "src/api/api-inl.h"
#include "src/base/bits.h"
#include "src/base/ieee754.h"
#include "src/codegen/cpu-features.h"
#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/encoded-c-signature.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/isolate.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/simulator.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap.h"
#include "src/ic/stub-cache.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/numbers/ieee754.h"
#include "src/numbers/math-random.h"
#include "src/objects/elements-kind.h"
#include "src/objects/elements.h"
#include "src/objects/object-type.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/simd.h"
#include "src/regexp/experimental/experimental.h"
#include "src/regexp/regexp-interpreter.h"
#include "src/regexp/regexp-macro-assembler-arch.h"
#include "src/regexp/regexp-result-vector.h"
#include "src/regexp/regexp-stack.h"
#include "src/strings/string-search.h"
#include "src/strings/unicode-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-external-refs.h"
#include "src/wasm/wasm-js.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_INTL_SUPPORT
#include "src/base/strings.h"
#include "src/objects/intl-objects.h"
#endif  // V8_INTL_SUPPORT

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// Common double constants.

constexpr double double_min_int_constant = kMinInt;
constexpr double double_one_half_constant = 0.5;
constexpr uint64_t double_the_hole_nan_constant = kHoleNanInt64;
constexpr double double_uint32_bias_constant =
    static_cast<double>(kMaxUInt32) + 1;

constexpr struct alignas(16) {
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t d;
  uint16_t e;
  uint16_t f;
  uint16_t g;
  uint16_t h;
} fp16_absolute_constant = {0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
                            0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF};

constexpr struct alignas(16) {
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t d;
  uint16_t e;
  uint16_t f;
  uint16_t g;
  uint16_t h;
} fp16_negate_constant = {0x8000, 0x8000, 0x8000, 0x8000,
                          0x8000, 0x8000, 0x8000, 0x8000};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} float_absolute_constant = {0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} float_negate_constant = {0x80000000, 0x80000000, 0x80000000, 0x80000000};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} double_absolute_constant = {uint64_t{0x7FFFFFFFFFFFFFFF},
                              uint64_t{0x7FFFFFFFFFFFFFFF}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} double_negate_constant = {uint64_t{0x8000000000000000},
                            uint64_t{0x8000000000000000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_swizzle_mask = {uint64_t{0x70707070'70707070},
                             uint64_t{0x70707070'70707070}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_popcnt_mask = {uint64_t{0x03020201'02010100},
                            uint64_t{0x04030302'03020201}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x01 = {uint64_t{0x01010101'01010101},
                           uint64_t{0x01010101'01010101}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x0f = {uint64_t{0x0F0F0F0F'0F0F0F0F},
                           uint64_t{0x0F0F0F0F'0F0F0F0F}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x33 = {uint64_t{0x33333333'33333333},
                           uint64_t{0x33333333'33333333}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x55 = {uint64_t{0x55555555'55555555},
                           uint64_t{0x55555555'55555555}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i16x8_splat_0x0001 = {uint64_t{0x00010001'00010001},
                             uint64_t{0x00010001'00010001}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_f64x2_convert_low_i32x4_u_int_mask = {uint64_t{0x4330000043300000},
                                             uint64_t{0x4330000043300000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_double_2_power_52 = {uint64_t{0x4330000000000000},
                            uint64_t{0x4330000000000000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_int32_max_as_double = {uint64_t{0x41dfffffffc00000},
                              uint64_t{0x41dfffffffc00000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_uint32_max_as_double = {uint64_t{0x41efffffffe00000},
                               uint64_t{0x41efffffffe00000}};

// This is 2147483648.0, which is 1 more than INT32_MAX.
constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} wasm_int32_overflow_as_float = {
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
} wasm_i32x8_int32_overflow_as_float = {
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
};

// Implementation of ExternalReference

bool ExternalReference::IsIsolateFieldId() const {
  return (raw_ > 0 && raw_ <= static_cast<Address>(kNumIsolateFieldIds));
}

Address ExternalReference::address() const {
  // If this CHECK triggers, then an ExternalReference gets created with an
  // IsolateFieldId where the root register is not available, and therefore
  // IsolateFieldIds cannot be used, or ExternalReferences with IsolateFieldIds
  // don't get supported yet and support should be added.
  CHECK(!IsIsolateFieldId());
  return raw_;
}

int32_t ExternalReference::offset_from_root_register() const {
  CHECK(IsIsolateFieldId());
  return static_cast<int32_t>(
      IsolateData::GetOffset(static_cast<IsolateFieldId>(raw_)));
}

static ExternalReference::Type BuiltinCallTypeForResultSize(int result_size) {
  switch (result_size) {
    case 1:
      return ExternalReference::BUILTIN_CALL;
    case 2:
      return ExternalReference::BUILTIN_CALL_PAIR;
  }
  UNREACHABLE();
}

// static
ExternalReference ExternalReference::Create(ApiFunction* fun, Type type) {
  return ExternalReference(Redirect(fun->address(), type));
}

// static
ExternalReference ExternalReference::Create(
    Isolate* isolate, ApiFunction* fun, Type type, Address* c_functions,
    const CFunctionInfo* const* c_signatures, unsigned num_functions) {
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  isolate->simulator_data()->RegisterFunctionsAndSignatures(
      c_functions, c_signatures, num_functions);
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  return ExternalReference(Redirect(fun->address(), type));
}

// static
ExternalReference ExternalReference::Create(Runtime::FunctionId id) {
  return Create(Runtime::FunctionForId(id));
}

// static
ExternalReference ExternalReference::Create(IsolateFieldId id) {
  return ExternalReference(id);
}

// static
ExternalReference ExternalReference::Create(const Runtime::Function* f) {
  return ExternalReference(
      Redirect(f->entry, BuiltinCallTypeForResultSize(f->result_size)));
}

// static
ExternalReference ExternalReference::Create(Address address, Type type) {
  return ExternalReference(Redirect(address, type));
}

ExternalReference ExternalReference::isolate_address(Isolate* isolate) {
  return ExternalReference(isolate);
}

ExternalReference ExternalReference::isolate_address() {
  return ExternalReference(IsolateFieldId::kIsolateAddress);
}

ExternalReference ExternalReference::handle_scope_implementer_address(
    Isolate* isolate) {
  return ExternalReference(isolate->handle_scope_implementer_address());
}

#ifdef V8_ENABLE_SANDBOX
ExternalReference ExternalReference::sandbox_base_address() {
  return ExternalReference(GetProcessWideSandbox()->base_address());
}

ExternalReference ExternalReference::sandbox_end_address() {
  return ExternalReference(GetProcessWideSandbox()->end_address());
}

ExternalReference ExternalReference::empty_backing_store_buffer() {
  return ExternalReference(GetProcessWideSandbox()
                               ->constants()
                               .empty_backing_store_buffer_address());
}

ExternalReference ExternalReference::external_pointer_table_address(
    Isolate* isolate) {
  return ExternalReference(isolate->external_pointer_table_address());
}

ExternalReference
ExternalReference::shared_external_pointer_table_address_address(
    Isolate* isolate) {
  return ExternalReference(
      isolate->shared_external_pointer_table_address_address());
}

ExternalReference ExternalReference::trusted_pointer_table_base_address(
    Isolate* isolate) {
  // TODO(saelo): maybe the external pointer table external references should
  // also directly return the table base address?
  return ExternalReference(isolate->trusted_pointer_table_base_address());
}

ExternalReference ExternalReference::shared_trusted_pointer_table_base_address(
    Isolate* isolate) {
  // TODO(saelo): maybe the external pointer table external references should
  // also directly return the table base address?
  return ExternalReference(
      isolate->shared_trusted_pointer_table_base_address());
}

ExternalReference ExternalReference::code_pointer_table_address() {
  // TODO(saelo): maybe rename to code_pointer_table_base_address?
  return ExternalReference(
      IsolateGroup::current()->code_pointer_table()->base_address());
}

ExternalReference ExternalReference::memory_chunk_metadata_table_address() {
  return ExternalReference(MemoryChunk::MetadataTableAddress());
}

ExternalReference ExternalReference::js_dispatch_table_address() {
  // TODO(saelo): maybe rename to js_dispatch_table_base_address?
  return ExternalReference(GetProcessWideJSDispatchTable()->base_address());
}

#endif  // V8_ENABLE_SANDBOX

ExternalReference ExternalReference::interpreter_dispatch_table_address(
    Isolate* isolate) {
  return ExternalReference(isolate->interpreter()->dispatch_table_address());
}

ExternalReference ExternalReference::interpreter_dispatch_counters(
    Isolate* isolate) {
  return ExternalReference(
      isolate->interpreter()->bytecode_dispatch_counters_table());
}

ExternalReference
ExternalReference::address_of_interpreter_entry_trampoline_instruction_start(
    Isolate* isolate) {
  return ExternalReference(
      isolate->interpreter()
          ->address_of_interpreter_entry_trampoline_instruction_start());
}

ExternalReference ExternalReference::bytecode_size_table_address() {
  return ExternalReference(
      interpreter::Bytecodes::bytecode_size_table_address());
}

// static
ExternalReference ExternalReference::Create(StatsCounter* counter) {
  return ExternalReference(
      reinterpret_cast<Address>(counter->GetInternalPointer()));
}

// static
ExternalReference ExternalReference::Create(IsolateAddressId id,
                                            Isolate* isolate) {
  return ExternalReference(isolate->get_address_from_id(id));
}

// static
ExternalReference ExternalReference::Create(const SCTableReference& table_ref) {
  return ExternalReference(table_ref.address());
}

namespace {

// Helper function to verify that all types in a list of types are scalar.
// This includes primitive types (int, Address) and pointer types. We also
// allow void.
template <typename T>
constexpr bool AllScalar() {
  return std::is_scalar<T>::value || std::is_void<T>::value;
}

template <typename T1, typename T2, typename... Rest>
constexpr bool AllScalar() {
  return AllScalar<T1>() && AllScalar<T2, Rest...>();
}

// Checks a function pointer's type for compatibility with the
// ExternalReference calling mechanism. Specifically, all arguments
// as well as the result type must pass the AllScalar check above,
// because we expect each item to fit into one register or stack slot.
template <typename T>
struct IsValidExternalReferenceType;

template <typename Result, typename... Args>
struct IsValidExternalReferenceType<Result (*)(Args...)> {
  static const bool value = AllScalar<Result, Args...>();
};

template <typename Result, typename Class, typename... Args>
struct IsValidExternalReferenceType<Result (Class::*)(Args...)> {
  static const bool value = AllScalar<Result, Args...>();
};

}  // namespace

// .. for functions that will not be called through CallCFunction. For these,
// all signatures are valid.
#define RAW_FUNCTION_REFERENCE(Name, Target)         \
  ExternalReference ExternalReference::Name() {      \
    return ExternalReference(FUNCTION_ADDR(Target)); \
  }

// .. for functions that will be called through CallCFunction.
#define FUNCTION_REFERENCE(Name, Target)                                   \
  ExternalReference ExternalReference::Name() {                            \
    static_assert(IsValidExternalReferenceType<decltype(&Target)>::value); \
    return ExternalReference(Redirect(FUNCTION_ADDR(Target)));             \
  }

#define FUNCTION_REFERENCE_WITH_TYPE(Name, Target, Type)                   \
  ExternalReference ExternalReference::Name() {                            \
    static_assert(IsValidExternalReferenceType<decltype(&Target)>::value); \
    return ExternalReference(Redirect(FUNCTION_ADDR(Target), Type));       \
  }

FUNCTION_REFERENCE(write_barrier_marking_from_code_function,
                   WriteBarrier::MarkingFromCode)

FUNCTION_REFERENCE(write_barrier_indirect_pointer_marking_from_code_function,
                   WriteBarrier::IndirectPointerMarkingFromCode)

FUNCTION_REFERENCE(write_barrier_shared_marking_from_code_function,
                   WriteBarrier::SharedMarkingFromCode)

FUNCTION_REFERENCE(shared_barrier_from_code_function,
                   WriteBarrier::SharedFromCode)

FUNCTION_REFERENCE(insert_remembered_set_function,
                   Heap::InsertIntoRememberedSetFromCode)

namespace {

intptr_t DebugBreakAtEntry(Isolate* isolate, Address raw_sfi) {
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> sfi =
      Cast<SharedFunctionInfo>(Tagged<Object>(raw_sfi));
  return isolate->debug()->BreakAtEntry(sfi) ? 1 : 0;
}

Address DebugGetCoverageInfo(Isolate* isolate, Address raw_sfi) {
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> sfi =
      Cast<SharedFunctionInfo>(Tagged<Object>(raw_sfi));
  std::optional<Tagged<DebugInfo>> debug_info =
      isolate->debug()->TryGetDebugInfo(sfi);
  if (debug_info.has_value() && debug_info.value()->HasCoverageInfo()) {
    return debug_info.value()->coverage_info().ptr();
  }
  return Smi::zero().ptr();
}

}  // namespace

FUNCTION_REFERENCE(debug_break_at_entry_function, DebugBreakAtEntry)
FUNCTION_REFERENCE(debug_get_coverage_info_function, DebugGetCoverageInfo)

FUNCTION_REFERENCE(delete_handle_scope_extensions,
                   HandleScope::DeleteExtensions)

FUNCTION_REFERENCE(ephemeron_key_write_barrier_function,
                   WriteBarrier::EphemeronKeyWriteBarrierFromCode)

ExternalPointerHandle AllocateAndInitializeYoungExternalPointerTableEntry(
    Isolate* isolate, Address pointer) {
#ifdef V8_ENABLE_SANDBOX
  return isolate->external_pointer_table().AllocateAndInitializeEntry(
      isolate->heap()->young_external_pointer_space(), pointer,
      kExternalObjectValueTag);
#else
  return 0;
#endif  // V8_ENABLE_SANDBOX
}

FUNCTION_REFERENCE(allocate_and_initialize_young_external_pointer_table_entry,
                   AllocateAndInitializeYoungExternalPointerTableEntry)

FUNCTION_REFERENCE(get_date_field_function, JSDate::GetField)

ExternalReference ExternalReference::date_cache_stamp(Isolate* isolate) {
  return ExternalReference(isolate->date_cache()->stamp_address());
}

// static
ExternalReference
ExternalReference::runtime_function_table_address_for_unittests(
    Isolate* isolate) {
  return runtime_function_table_address(isolate);
}

// static
Address ExternalReference::Redirect(Address external_function, Type type) {
#ifdef USE_SIMULATOR
  return SimulatorBase::RedirectExternalReference(external_function, type);
#else
  return external_function;
#endif
}

// static
Address ExternalReference::UnwrapRedirection(Address redirection_trampoline) {
#ifdef USE_SIMULATOR
  return SimulatorBase::UnwrapRedirection(redirection_trampoline);
#else
  return redirection_trampoline;
#endif
}

ExternalReference ExternalReference::stress_deopt_count(Isolate* isolate) {
  return ExternalReference(isolate->stress_deopt_count_address());
}

ExternalReference ExternalReference::force_slow_path(Isolate* isolate) {
  return ExternalReference(isolate->force_slow_path_address());
}

FUNCTION_REFERENCE(new_deoptimizer_function, Deoptimizer::New)

FUNCTION_REFERENCE(compute_output_frames_function,
                   Deoptimizer::ComputeOutputFrames)

#ifdef V8_ENABLE_CET_SHADOW_STACK
FUNCTION_REFERENCE(ensure_valid_return_address,
                   Deoptimizer::EnsureValidReturnAddress)
#endif  // V8_ENABLE_CET_SHADOW_STACK

#ifdef V8_ENABLE_WEBASSEMBLY
FUNCTION_REFERENCE(wasm_sync_stack_limit, wasm::sync_stack_limit)
FUNCTION_REFERENCE(wasm_return_switch, wasm::return_switch)
FUNCTION_REFERENCE(wasm_switch_to_the_central_stack,
                   wasm::switch_to_the_central_stack)
FUNCTION_REFERENCE(wasm_switch_from_the_central_stack,
                   wasm::switch_from_the_central_stack)
FUNCTION_REFERENCE(wasm_switch_to_the_central_stack_for_js,
                   wasm::switch_to_the_central_stack_for_js)
FUNCTION_REFERENCE(wasm_switch_from_the_central_stack_for_js,
                   wasm::switch_from_the_central_stack_for_js)
FUNCTION_REFERENCE(wasm_grow_stack, wasm::grow_stack)
FUNCTION_REFERENCE(wasm_shrink_stack, wasm::shrink_stack)
FUNCTION_REFERENCE(wasm_load_old_fp, wasm::load_old_fp)
FUNCTION_REFERENCE(wasm_f32_trunc, wasm::f32_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f32_floor, wasm::f32_floor_wrapper)
FUNCTION_REFERENCE(wasm_f32_ceil, wasm::f32_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f32_nearest_int, wasm::f32_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f64_trunc, wasm::f64_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f64_floor, wasm::f64_floor_wrapper)
FUNCTION_REFERENCE(wasm_f64_ceil, wasm::f64_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f64_nearest_int, wasm::f64_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_int64_to_float32, wasm::int64_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_uint64_to_float32, wasm::uint64_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_int64_to_float64, wasm::int64_to_float64_wrapper)
FUNCTION_REFERENCE(wasm_uint64_to_float64, wasm::uint64_to_float64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_int64, wasm::float32_to_int64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_uint64, wasm::float32_to_uint64_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_int64, wasm::float64_to_int64_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_uint64, wasm::float64_to_uint64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_int64_sat,
                   wasm::float32_to_int64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_uint64_sat,
                   wasm::float32_to_uint64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_int64_sat,
                   wasm::float64_to_int64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_uint64_sat,
                   wasm::float64_to_uint64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float16_to_float32, wasm::float16_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_float16, wasm::float32_to_float16_wrapper)
FUNCTION_REFERENCE(wasm_int64_div, wasm::int64_div_wrapper)
FUNCTION_REFERENCE(wasm_int64_mod, wasm::int64_mod_wrapper)
FUNCTION_REFERENCE(wasm_uint64_div, wasm::uint64_div_wrapper)
FUNCTION_REFERENCE(wasm_uint64_mod, wasm::uint64_mod_wrapper)
FUNCTION_REFERENCE(wasm_word32_ctz, base::bits::CountTrailingZeros<uint32_t>)
FUNCTION_REFERENCE(wasm_word64_ctz, base::bits::CountTrailingZeros<uint64_t>)
FUNCTION_REFERENCE(wasm_word32_popcnt, base::bits::CountPopulation<uint32_t>)
FUNCTION_REFERENCE(wasm_word64_popcnt, base::bits::CountPopulation<uint64_t>)
FUNCTION_REFERENCE(wasm_word32_rol, wasm::word32_rol_wrapper)
FUNCTION_REFERENCE(wasm_word32_ror, wasm::word32_ror_wrapper)
FUNCTION_REFERENCE(wasm_word64_rol, wasm::word64_rol_wrapper)
FUNCTION_REFERENCE(wasm_word64_ror, wasm::word64_ror_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_ceil, wasm::f64x2_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_floor, wasm::f64x2_floor_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_trunc, wasm::f64x2_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_nearest_int, wasm::f64x2_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_ceil, wasm::f32x4_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_floor, wasm::f32x4_floor_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_trunc, wasm::f32x
### 提示词
```
这是目录为v8/src/codegen/external-reference.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/external-reference.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/external-reference.h"

#include <optional>

#include "include/v8-fast-api-calls.h"
#include "src/api/api-inl.h"
#include "src/base/bits.h"
#include "src/base/ieee754.h"
#include "src/codegen/cpu-features.h"
#include "src/common/globals.h"
#include "src/date/date.h"
#include "src/debug/debug.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/execution/encoded-c-signature.h"
#include "src/execution/isolate-utils.h"
#include "src/execution/isolate.h"
#include "src/execution/microtask-queue.h"
#include "src/execution/simulator.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap.h"
#include "src/ic/stub-cache.h"
#include "src/interpreter/interpreter.h"
#include "src/logging/counters.h"
#include "src/logging/log.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/numbers/ieee754.h"
#include "src/numbers/math-random.h"
#include "src/objects/elements-kind.h"
#include "src/objects/elements.h"
#include "src/objects/object-type.h"
#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/simd.h"
#include "src/regexp/experimental/experimental.h"
#include "src/regexp/regexp-interpreter.h"
#include "src/regexp/regexp-macro-assembler-arch.h"
#include "src/regexp/regexp-result-vector.h"
#include "src/regexp/regexp-stack.h"
#include "src/strings/string-search.h"
#include "src/strings/unicode-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-external-refs.h"
#include "src/wasm/wasm-js.h"
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_INTL_SUPPORT
#include "src/base/strings.h"
#include "src/objects/intl-objects.h"
#endif  // V8_INTL_SUPPORT

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// Common double constants.

constexpr double double_min_int_constant = kMinInt;
constexpr double double_one_half_constant = 0.5;
constexpr uint64_t double_the_hole_nan_constant = kHoleNanInt64;
constexpr double double_uint32_bias_constant =
    static_cast<double>(kMaxUInt32) + 1;

constexpr struct alignas(16) {
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t d;
  uint16_t e;
  uint16_t f;
  uint16_t g;
  uint16_t h;
} fp16_absolute_constant = {0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF,
                            0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF};

constexpr struct alignas(16) {
  uint16_t a;
  uint16_t b;
  uint16_t c;
  uint16_t d;
  uint16_t e;
  uint16_t f;
  uint16_t g;
  uint16_t h;
} fp16_negate_constant = {0x8000, 0x8000, 0x8000, 0x8000,
                          0x8000, 0x8000, 0x8000, 0x8000};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} float_absolute_constant = {0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} float_negate_constant = {0x80000000, 0x80000000, 0x80000000, 0x80000000};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} double_absolute_constant = {uint64_t{0x7FFFFFFFFFFFFFFF},
                              uint64_t{0x7FFFFFFFFFFFFFFF}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} double_negate_constant = {uint64_t{0x8000000000000000},
                            uint64_t{0x8000000000000000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_swizzle_mask = {uint64_t{0x70707070'70707070},
                             uint64_t{0x70707070'70707070}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_popcnt_mask = {uint64_t{0x03020201'02010100},
                            uint64_t{0x04030302'03020201}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x01 = {uint64_t{0x01010101'01010101},
                           uint64_t{0x01010101'01010101}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x0f = {uint64_t{0x0F0F0F0F'0F0F0F0F},
                           uint64_t{0x0F0F0F0F'0F0F0F0F}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x33 = {uint64_t{0x33333333'33333333},
                           uint64_t{0x33333333'33333333}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i8x16_splat_0x55 = {uint64_t{0x55555555'55555555},
                           uint64_t{0x55555555'55555555}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_i16x8_splat_0x0001 = {uint64_t{0x00010001'00010001},
                             uint64_t{0x00010001'00010001}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_f64x2_convert_low_i32x4_u_int_mask = {uint64_t{0x4330000043300000},
                                             uint64_t{0x4330000043300000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_double_2_power_52 = {uint64_t{0x4330000000000000},
                            uint64_t{0x4330000000000000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_int32_max_as_double = {uint64_t{0x41dfffffffc00000},
                              uint64_t{0x41dfffffffc00000}};

constexpr struct alignas(16) {
  uint64_t a;
  uint64_t b;
} wasm_uint32_max_as_double = {uint64_t{0x41efffffffe00000},
                               uint64_t{0x41efffffffe00000}};

// This is 2147483648.0, which is 1 more than INT32_MAX.
constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} wasm_int32_overflow_as_float = {
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000},
};

constexpr struct alignas(16) {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
} wasm_i32x8_int32_overflow_as_float = {
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
    uint32_t{0x4f00'0000}, uint32_t{0x4f00'0000},
};

// Implementation of ExternalReference

bool ExternalReference::IsIsolateFieldId() const {
  return (raw_ > 0 && raw_ <= static_cast<Address>(kNumIsolateFieldIds));
}

Address ExternalReference::address() const {
  // If this CHECK triggers, then an ExternalReference gets created with an
  // IsolateFieldId where the root register is not available, and therefore
  // IsolateFieldIds cannot be used, or ExternalReferences with IsolateFieldIds
  // don't get supported yet and support should be added.
  CHECK(!IsIsolateFieldId());
  return raw_;
}

int32_t ExternalReference::offset_from_root_register() const {
  CHECK(IsIsolateFieldId());
  return static_cast<int32_t>(
      IsolateData::GetOffset(static_cast<IsolateFieldId>(raw_)));
}

static ExternalReference::Type BuiltinCallTypeForResultSize(int result_size) {
  switch (result_size) {
    case 1:
      return ExternalReference::BUILTIN_CALL;
    case 2:
      return ExternalReference::BUILTIN_CALL_PAIR;
  }
  UNREACHABLE();
}

// static
ExternalReference ExternalReference::Create(ApiFunction* fun, Type type) {
  return ExternalReference(Redirect(fun->address(), type));
}

// static
ExternalReference ExternalReference::Create(
    Isolate* isolate, ApiFunction* fun, Type type, Address* c_functions,
    const CFunctionInfo* const* c_signatures, unsigned num_functions) {
#ifdef V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  isolate->simulator_data()->RegisterFunctionsAndSignatures(
      c_functions, c_signatures, num_functions);
#endif  //  V8_USE_SIMULATOR_WITH_GENERIC_C_CALLS
  return ExternalReference(Redirect(fun->address(), type));
}

// static
ExternalReference ExternalReference::Create(Runtime::FunctionId id) {
  return Create(Runtime::FunctionForId(id));
}

// static
ExternalReference ExternalReference::Create(IsolateFieldId id) {
  return ExternalReference(id);
}

// static
ExternalReference ExternalReference::Create(const Runtime::Function* f) {
  return ExternalReference(
      Redirect(f->entry, BuiltinCallTypeForResultSize(f->result_size)));
}

// static
ExternalReference ExternalReference::Create(Address address, Type type) {
  return ExternalReference(Redirect(address, type));
}

ExternalReference ExternalReference::isolate_address(Isolate* isolate) {
  return ExternalReference(isolate);
}

ExternalReference ExternalReference::isolate_address() {
  return ExternalReference(IsolateFieldId::kIsolateAddress);
}

ExternalReference ExternalReference::handle_scope_implementer_address(
    Isolate* isolate) {
  return ExternalReference(isolate->handle_scope_implementer_address());
}

#ifdef V8_ENABLE_SANDBOX
ExternalReference ExternalReference::sandbox_base_address() {
  return ExternalReference(GetProcessWideSandbox()->base_address());
}

ExternalReference ExternalReference::sandbox_end_address() {
  return ExternalReference(GetProcessWideSandbox()->end_address());
}

ExternalReference ExternalReference::empty_backing_store_buffer() {
  return ExternalReference(GetProcessWideSandbox()
                               ->constants()
                               .empty_backing_store_buffer_address());
}

ExternalReference ExternalReference::external_pointer_table_address(
    Isolate* isolate) {
  return ExternalReference(isolate->external_pointer_table_address());
}

ExternalReference
ExternalReference::shared_external_pointer_table_address_address(
    Isolate* isolate) {
  return ExternalReference(
      isolate->shared_external_pointer_table_address_address());
}

ExternalReference ExternalReference::trusted_pointer_table_base_address(
    Isolate* isolate) {
  // TODO(saelo): maybe the external pointer table external references should
  // also directly return the table base address?
  return ExternalReference(isolate->trusted_pointer_table_base_address());
}

ExternalReference ExternalReference::shared_trusted_pointer_table_base_address(
    Isolate* isolate) {
  // TODO(saelo): maybe the external pointer table external references should
  // also directly return the table base address?
  return ExternalReference(
      isolate->shared_trusted_pointer_table_base_address());
}

ExternalReference ExternalReference::code_pointer_table_address() {
  // TODO(saelo): maybe rename to code_pointer_table_base_address?
  return ExternalReference(
      IsolateGroup::current()->code_pointer_table()->base_address());
}

ExternalReference ExternalReference::memory_chunk_metadata_table_address() {
  return ExternalReference(MemoryChunk::MetadataTableAddress());
}

ExternalReference ExternalReference::js_dispatch_table_address() {
  // TODO(saelo): maybe rename to js_dispatch_table_base_address?
  return ExternalReference(GetProcessWideJSDispatchTable()->base_address());
}

#endif  // V8_ENABLE_SANDBOX

ExternalReference ExternalReference::interpreter_dispatch_table_address(
    Isolate* isolate) {
  return ExternalReference(isolate->interpreter()->dispatch_table_address());
}

ExternalReference ExternalReference::interpreter_dispatch_counters(
    Isolate* isolate) {
  return ExternalReference(
      isolate->interpreter()->bytecode_dispatch_counters_table());
}

ExternalReference
ExternalReference::address_of_interpreter_entry_trampoline_instruction_start(
    Isolate* isolate) {
  return ExternalReference(
      isolate->interpreter()
          ->address_of_interpreter_entry_trampoline_instruction_start());
}

ExternalReference ExternalReference::bytecode_size_table_address() {
  return ExternalReference(
      interpreter::Bytecodes::bytecode_size_table_address());
}

// static
ExternalReference ExternalReference::Create(StatsCounter* counter) {
  return ExternalReference(
      reinterpret_cast<Address>(counter->GetInternalPointer()));
}

// static
ExternalReference ExternalReference::Create(IsolateAddressId id,
                                            Isolate* isolate) {
  return ExternalReference(isolate->get_address_from_id(id));
}

// static
ExternalReference ExternalReference::Create(const SCTableReference& table_ref) {
  return ExternalReference(table_ref.address());
}

namespace {

// Helper function to verify that all types in a list of types are scalar.
// This includes primitive types (int, Address) and pointer types. We also
// allow void.
template <typename T>
constexpr bool AllScalar() {
  return std::is_scalar<T>::value || std::is_void<T>::value;
}

template <typename T1, typename T2, typename... Rest>
constexpr bool AllScalar() {
  return AllScalar<T1>() && AllScalar<T2, Rest...>();
}

// Checks a function pointer's type for compatibility with the
// ExternalReference calling mechanism. Specifically, all arguments
// as well as the result type must pass the AllScalar check above,
// because we expect each item to fit into one register or stack slot.
template <typename T>
struct IsValidExternalReferenceType;

template <typename Result, typename... Args>
struct IsValidExternalReferenceType<Result (*)(Args...)> {
  static const bool value = AllScalar<Result, Args...>();
};

template <typename Result, typename Class, typename... Args>
struct IsValidExternalReferenceType<Result (Class::*)(Args...)> {
  static const bool value = AllScalar<Result, Args...>();
};

}  // namespace

// .. for functions that will not be called through CallCFunction. For these,
// all signatures are valid.
#define RAW_FUNCTION_REFERENCE(Name, Target)         \
  ExternalReference ExternalReference::Name() {      \
    return ExternalReference(FUNCTION_ADDR(Target)); \
  }

// .. for functions that will be called through CallCFunction.
#define FUNCTION_REFERENCE(Name, Target)                                   \
  ExternalReference ExternalReference::Name() {                            \
    static_assert(IsValidExternalReferenceType<decltype(&Target)>::value); \
    return ExternalReference(Redirect(FUNCTION_ADDR(Target)));             \
  }

#define FUNCTION_REFERENCE_WITH_TYPE(Name, Target, Type)                   \
  ExternalReference ExternalReference::Name() {                            \
    static_assert(IsValidExternalReferenceType<decltype(&Target)>::value); \
    return ExternalReference(Redirect(FUNCTION_ADDR(Target), Type));       \
  }

FUNCTION_REFERENCE(write_barrier_marking_from_code_function,
                   WriteBarrier::MarkingFromCode)

FUNCTION_REFERENCE(write_barrier_indirect_pointer_marking_from_code_function,
                   WriteBarrier::IndirectPointerMarkingFromCode)

FUNCTION_REFERENCE(write_barrier_shared_marking_from_code_function,
                   WriteBarrier::SharedMarkingFromCode)

FUNCTION_REFERENCE(shared_barrier_from_code_function,
                   WriteBarrier::SharedFromCode)

FUNCTION_REFERENCE(insert_remembered_set_function,
                   Heap::InsertIntoRememberedSetFromCode)

namespace {

intptr_t DebugBreakAtEntry(Isolate* isolate, Address raw_sfi) {
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> sfi =
      Cast<SharedFunctionInfo>(Tagged<Object>(raw_sfi));
  return isolate->debug()->BreakAtEntry(sfi) ? 1 : 0;
}

Address DebugGetCoverageInfo(Isolate* isolate, Address raw_sfi) {
  DisallowGarbageCollection no_gc;
  Tagged<SharedFunctionInfo> sfi =
      Cast<SharedFunctionInfo>(Tagged<Object>(raw_sfi));
  std::optional<Tagged<DebugInfo>> debug_info =
      isolate->debug()->TryGetDebugInfo(sfi);
  if (debug_info.has_value() && debug_info.value()->HasCoverageInfo()) {
    return debug_info.value()->coverage_info().ptr();
  }
  return Smi::zero().ptr();
}

}  // namespace

FUNCTION_REFERENCE(debug_break_at_entry_function, DebugBreakAtEntry)
FUNCTION_REFERENCE(debug_get_coverage_info_function, DebugGetCoverageInfo)

FUNCTION_REFERENCE(delete_handle_scope_extensions,
                   HandleScope::DeleteExtensions)

FUNCTION_REFERENCE(ephemeron_key_write_barrier_function,
                   WriteBarrier::EphemeronKeyWriteBarrierFromCode)

ExternalPointerHandle AllocateAndInitializeYoungExternalPointerTableEntry(
    Isolate* isolate, Address pointer) {
#ifdef V8_ENABLE_SANDBOX
  return isolate->external_pointer_table().AllocateAndInitializeEntry(
      isolate->heap()->young_external_pointer_space(), pointer,
      kExternalObjectValueTag);
#else
  return 0;
#endif  // V8_ENABLE_SANDBOX
}

FUNCTION_REFERENCE(allocate_and_initialize_young_external_pointer_table_entry,
                   AllocateAndInitializeYoungExternalPointerTableEntry)

FUNCTION_REFERENCE(get_date_field_function, JSDate::GetField)

ExternalReference ExternalReference::date_cache_stamp(Isolate* isolate) {
  return ExternalReference(isolate->date_cache()->stamp_address());
}

// static
ExternalReference
ExternalReference::runtime_function_table_address_for_unittests(
    Isolate* isolate) {
  return runtime_function_table_address(isolate);
}

// static
Address ExternalReference::Redirect(Address external_function, Type type) {
#ifdef USE_SIMULATOR
  return SimulatorBase::RedirectExternalReference(external_function, type);
#else
  return external_function;
#endif
}

// static
Address ExternalReference::UnwrapRedirection(Address redirection_trampoline) {
#ifdef USE_SIMULATOR
  return SimulatorBase::UnwrapRedirection(redirection_trampoline);
#else
  return redirection_trampoline;
#endif
}

ExternalReference ExternalReference::stress_deopt_count(Isolate* isolate) {
  return ExternalReference(isolate->stress_deopt_count_address());
}

ExternalReference ExternalReference::force_slow_path(Isolate* isolate) {
  return ExternalReference(isolate->force_slow_path_address());
}

FUNCTION_REFERENCE(new_deoptimizer_function, Deoptimizer::New)

FUNCTION_REFERENCE(compute_output_frames_function,
                   Deoptimizer::ComputeOutputFrames)

#ifdef V8_ENABLE_CET_SHADOW_STACK
FUNCTION_REFERENCE(ensure_valid_return_address,
                   Deoptimizer::EnsureValidReturnAddress)
#endif  // V8_ENABLE_CET_SHADOW_STACK

#ifdef V8_ENABLE_WEBASSEMBLY
FUNCTION_REFERENCE(wasm_sync_stack_limit, wasm::sync_stack_limit)
FUNCTION_REFERENCE(wasm_return_switch, wasm::return_switch)
FUNCTION_REFERENCE(wasm_switch_to_the_central_stack,
                   wasm::switch_to_the_central_stack)
FUNCTION_REFERENCE(wasm_switch_from_the_central_stack,
                   wasm::switch_from_the_central_stack)
FUNCTION_REFERENCE(wasm_switch_to_the_central_stack_for_js,
                   wasm::switch_to_the_central_stack_for_js)
FUNCTION_REFERENCE(wasm_switch_from_the_central_stack_for_js,
                   wasm::switch_from_the_central_stack_for_js)
FUNCTION_REFERENCE(wasm_grow_stack, wasm::grow_stack)
FUNCTION_REFERENCE(wasm_shrink_stack, wasm::shrink_stack)
FUNCTION_REFERENCE(wasm_load_old_fp, wasm::load_old_fp)
FUNCTION_REFERENCE(wasm_f32_trunc, wasm::f32_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f32_floor, wasm::f32_floor_wrapper)
FUNCTION_REFERENCE(wasm_f32_ceil, wasm::f32_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f32_nearest_int, wasm::f32_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f64_trunc, wasm::f64_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f64_floor, wasm::f64_floor_wrapper)
FUNCTION_REFERENCE(wasm_f64_ceil, wasm::f64_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f64_nearest_int, wasm::f64_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_int64_to_float32, wasm::int64_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_uint64_to_float32, wasm::uint64_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_int64_to_float64, wasm::int64_to_float64_wrapper)
FUNCTION_REFERENCE(wasm_uint64_to_float64, wasm::uint64_to_float64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_int64, wasm::float32_to_int64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_uint64, wasm::float32_to_uint64_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_int64, wasm::float64_to_int64_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_uint64, wasm::float64_to_uint64_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_int64_sat,
                   wasm::float32_to_int64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_uint64_sat,
                   wasm::float32_to_uint64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_int64_sat,
                   wasm::float64_to_int64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float64_to_uint64_sat,
                   wasm::float64_to_uint64_sat_wrapper)
FUNCTION_REFERENCE(wasm_float16_to_float32, wasm::float16_to_float32_wrapper)
FUNCTION_REFERENCE(wasm_float32_to_float16, wasm::float32_to_float16_wrapper)
FUNCTION_REFERENCE(wasm_int64_div, wasm::int64_div_wrapper)
FUNCTION_REFERENCE(wasm_int64_mod, wasm::int64_mod_wrapper)
FUNCTION_REFERENCE(wasm_uint64_div, wasm::uint64_div_wrapper)
FUNCTION_REFERENCE(wasm_uint64_mod, wasm::uint64_mod_wrapper)
FUNCTION_REFERENCE(wasm_word32_ctz, base::bits::CountTrailingZeros<uint32_t>)
FUNCTION_REFERENCE(wasm_word64_ctz, base::bits::CountTrailingZeros<uint64_t>)
FUNCTION_REFERENCE(wasm_word32_popcnt, base::bits::CountPopulation<uint32_t>)
FUNCTION_REFERENCE(wasm_word64_popcnt, base::bits::CountPopulation<uint64_t>)
FUNCTION_REFERENCE(wasm_word32_rol, wasm::word32_rol_wrapper)
FUNCTION_REFERENCE(wasm_word32_ror, wasm::word32_ror_wrapper)
FUNCTION_REFERENCE(wasm_word64_rol, wasm::word64_rol_wrapper)
FUNCTION_REFERENCE(wasm_word64_ror, wasm::word64_ror_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_ceil, wasm::f64x2_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_floor, wasm::f64x2_floor_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_trunc, wasm::f64x2_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f64x2_nearest_int, wasm::f64x2_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_ceil, wasm::f32x4_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_floor, wasm::f32x4_floor_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_trunc, wasm::f32x4_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_nearest_int, wasm::f32x4_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_abs, wasm::f16x8_abs_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_neg, wasm::f16x8_neg_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_sqrt, wasm::f16x8_sqrt_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_ceil, wasm::f16x8_ceil_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_floor, wasm::f16x8_floor_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_trunc, wasm::f16x8_trunc_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_nearest_int, wasm::f16x8_nearest_int_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_eq, wasm::f16x8_eq_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_ne, wasm::f16x8_ne_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_lt, wasm::f16x8_lt_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_le, wasm::f16x8_le_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_add, wasm::f16x8_add_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_sub, wasm::f16x8_sub_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_mul, wasm::f16x8_mul_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_div, wasm::f16x8_div_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_min, wasm::f16x8_min_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_max, wasm::f16x8_max_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_pmin, wasm::f16x8_pmin_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_pmax, wasm::f16x8_pmax_wrapper)
FUNCTION_REFERENCE(wasm_i16x8_sconvert_f16x8,
                   wasm::i16x8_sconvert_f16x8_wrapper)
FUNCTION_REFERENCE(wasm_i16x8_uconvert_f16x8,
                   wasm::i16x8_uconvert_f16x8_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_sconvert_i16x8,
                   wasm::f16x8_sconvert_i16x8_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_uconvert_i16x8,
                   wasm::f16x8_uconvert_i16x8_wrapper)
FUNCTION_REFERENCE(wasm_f32x4_promote_low_f16x8,
                   wasm::f32x4_promote_low_f16x8_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_demote_f32x4_zero,
                   wasm::f16x8_demote_f32x4_zero_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_demote_f64x2_zero,
                   wasm::f16x8_demote_f64x2_zero_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_qfma, wasm::f16x8_qfma_wrapper)
FUNCTION_REFERENCE(wasm_f16x8_qfms, wasm::f16x8_qfms_wrapper)
FUNCTION_REFERENCE(wasm_memory_init, wasm::memory_init_wrapper)
FUNCTION_REFERENCE(wasm_memory_copy, wasm::memory_copy_wrapper)
FUNCTION_REFERENCE(wasm_memory_fill, wasm::memory_fill_wrapper)
FUNCTION_REFERENCE(wasm_float64_pow, wasm::float64_pow_wrapper)
FUNCTION_REFERENCE(wasm_array_copy, wasm::array_copy_wrapper)
FUNCTION_REFERENCE(wasm_array_fill, wasm::array_fill_wrapper)
FUNCTION_REFERENCE_WITH_TYPE(wasm_string_to_f64, wasm::flat_string_to_f64,
                             BUILTIN_FP_POINTER_CALL)

int32_t (&futex_emulation_wake)(void*, uint32_t) = FutexEmulation::Wake;
FUNCTION_REFERENCE(wasm_atomic_notify, futex_emulation_wake)

void WasmSignatureCheckFail(Address raw_internal_function,
                            uintptr_t expected_hash) {
  // WasmInternalFunction::signature_hash doesn't exist in non-sandbox builds.
  // TODO(saelo): Consider using Abort instead, as we do for JavaScript
  // signature mismatches (See AbortReason::kJSSignatureMismatch).
#if V8_ENABLE_SANDBOX
  Tagged<WasmInternalFunction> internal_function =
      Cast<WasmInternalFunction>(Tagged<Object>(raw_internal_function));
  PrintF("Wasm sandbox violation! Expected signature hash %lx, got %lx\n",
         expected_hash, internal_function->signature_hash());
  SBXCHECK_EQ(expected_hash, internal_function->signature_hash());
#endif
}
FUNCTION_REFERENCE(wasm_signature_check_fail, WasmSignatureCheckFail)

#define V(Name) RAW_FUNCTION_REFERENCE(wasm_##Name, wasm::Name)
WASM_JS_EXTERNAL_REFERENCE_LIST(V)
#undef V

ExternalReference ExternalReference::wasm_code_pointer_table() {
  return ExternalReference(wasm::GetProcessWideWasmCodePointerTable()->base());
}

#endif  // V8_ENABLE_WEBASSEMBLY

static void f64_acos_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  WriteUnalignedValue(data, base::ieee754::acos(input));
}

FUNCTION_REFERENCE(f64_acos_wrapper_function, f64_acos_wrapper)

static void f64_asin_wrapper(Address data) {
  double input = ReadUnalignedValue<double>(data);
  WriteUnalignedValue<double>(data, base::ieee754::asin(input));
}

FUNCTION_REFERENCE(f64_asin_wrapper_function, f64_asin_wrapper)


static void f64_mod_wrapper(Address data) {
  double dividend = ReadUnalignedValue<double>(data);
  double divisor = ReadUnalignedValue<double>(data + sizeof(dividend));
  WriteUnalignedValue<double>(data, Modulo(dividend, divisor));
}

FUNCTION_REFERENCE(f64_mod_wrapper_function, f64_mod_wrapper)

ExternalReference ExternalReference::isolate_root(Isolate* isolate) {
  return ExternalReference(isolate->isolate_root());
}

ExternalReference ExternalReference::allocation_sites_list_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->allocation_sites_list_address());
}

ExternalReference ExternalReference::address_of_jslimit(Isolate* isolate) {
  Address address = isolate->stack_guard()->address_of_jslimit();
  // For efficient generated code, this should be root-register-addressable.
  DCHECK(isolate->root_register_addressable_region().contains(address));
  return ExternalReference(address);
}

ExternalReference ExternalReference::address_of_no_heap_write_interrupt_request(
    Isolate* isolate) {
  Address address = isolate->stack_guard()->address_of_interrupt_request(
      StackGuard::InterruptLevel::kNoHeapWrites);
  // For efficient generated code, this should be root-register-addressable.
  DCHECK(isolate->root_register_addressable_region().contains(address));
  return ExternalReference(address);
}

ExternalReference ExternalReference::address_of_real_jslimit(Isolate* isolate) {
  Address address = isolate->stack_guard()->address_of_real_jslimit();
  // For efficient generated code, this should be root-register-addressable.
  DCHECK(isolate->root_register_addressable_region().contains(address));
  return ExternalReference(address);
}

ExternalReference ExternalReference::heap_is_marking_flag_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->IsMarkingFlagAddress());
}

ExternalReference ExternalReference::heap_is_minor_marking_flag_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->IsMinorMarkingFlagAddress());
}

ExternalReference ExternalReference::is_shared_space_isolate_flag_address(
    Isolate* isolate) {
  return ExternalReference(
      isolate->isolate_data()->is_shared_space_isolate_flag_address());
}

ExternalReference ExternalReference::new_space_allocation_top_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->NewSpaceAllocationTopAddress());
}

ExternalReference ExternalReference::new_space_allocation_limit_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->NewSpaceAllocationLimitAddress());
}

ExternalReference ExternalReference::old_space_allocation_top_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->OldSpaceAllocationTopAddress());
}

ExternalReference ExternalReference::old_space_allocation_limit_address(
    Isolate* isolate) {
  return ExternalReference(isolate->heap()->OldSpaceAllocationLimitAddress());
}

ExternalReference ExternalReference::handle_scope_level_address(
    Isolate* isolate) {
  return ExternalReference(HandleScope::current_level_address(isolate));
}

ExternalReference ExternalReference::handle_scope_next_address(
    Isolate* isolate) {
  return ExternalReference(HandleScope::current_next_address(isolate));
}

ExternalReference ExternalReference::handle_scope_limit_address(
    Isolate* isolate) {
  return ExternalReference(HandleScope::current_limit_address(isolate));
}

ExternalReference ExternalReference::exception_address(Isolate* isolate) {
  return ExternalReference(isolate->exception_address());
}

ExternalReference ExternalReference::address_of_pending_message(
    Isolate* isolate) {
  return ExternalReference(isolate->pending_message_address());
}

ExternalReference ExternalReference::address_of_pending_message(
    LocalIsolate* local_isolate) {
  return ExternalReference(local_isolate->pending_message_address());
}

FUNCTION_REFERENCE(abort_with_reason, i::abort_with_reason)

ExternalReference ExternalReference::address_of_min_int() {
  return ExternalReference(reinterpret_cast<Address>(&double_min_int_constant));
}

ExternalReference
ExternalReference::address_of_mock_arraybuffer_allocator_flag() {
  return ExternalReference(&v8_flags.mock_arraybuffer_allocator);
}

// TODO(jgruber): Update the other extrefs pointing at v8_flags. addresses to be
// called address_of_FLAG_foo (easier grep-ability).
ExternalReference ExternalReference::address_of_log_or_trace_osr() {
  return ExternalReference(&v8_flags.log_or_trace_osr);
}

ExternalReference ExternalReference::address_of_builtin_subclassing_flag() {
  return ExternalReference(&v8_flags.builtin_subclassing);
}

ExternalReference ExternalReference::address_of_runtime_stats_flag() {
  return ExternalReference(&TracingFlags::runtime_stats);
}

ExternalReference ExternalReference::address_of_shared_string_table_flag() {
  return ExternalReference(&v8_flags.shared_string_table);
}

#ifdef V8_ENABLE_CET_SHADOW_STACK
ExternalReference ExternalReference::address_of_cet_compatible_flag() {
  return ExternalReference(&v8_flags.cet_compatible);
}
#endif  // V8_ENABLE_CET_SHADOW_STACK

ExternalReference ExternalReference::script_context_mutable_heap_number_flag() {
  return ExternalReference(&v8_flags.script_context_mutable_heap_number);
}

ExternalReference ExternalReference::address_of_load_from_stack_count(
    const char* function_name) {
  return ExternalReference(
      Isolate::load_from_stack_count_address(function_name));
}

ExternalReference ExternalReference::address_of_store_to_stack_count(
    const char* function_name) {
  return ExternalReference(
      Isolate::store_to_stack_count_address(function_name));
}

ExternalReference ExternalReference::address_of_one_half() {
  return ExternalReference(
      reinterpret_cast<Address>(&double_one_half_constant));
}

ExternalReference ExternalReference::address_of_the_hole_nan() {
  return ExternalReference(
      reinterpret_cast<Address>(&double_the_hole_nan_constant));
}

ExternalReference ExternalReference::address_of_uint32_bias() {
  return ExternalReference(
      reinterpret_cast<Address>(&double_uint32_bias_constant));
}

ExternalReference ExternalReference::address_of_fp16_abs_constant() {
  return ExternalReference(reinterpret_cast<Address>(&fp16_absolute_constant));
}

ExternalReference ExternalReference::address_of_fp16_neg_constant() {
  return ExternalReference(reinterpret_cast<Address>(&fp16_negate_constant));
}

ExternalReference ExternalReference::address_of_float_abs_constant() {
  return ExternalReference(reinterpret_cast<Address>(&float_absolute_constant));
}

ExternalReference ExternalReference::address_of_float_neg_constant() {
  return ExternalReference(reinterpret_cast<Address>(&float_negate_constant));
}

ExternalReference ExternalReference::address_of_double_abs_constant() {
  return ExternalReference(
      reinterpret_cast<Address>(&double_absolute_cons
```
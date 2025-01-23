Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/codegen/external-reference.cc`.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The file name `external-reference.cc` strongly suggests that the code is about managing references to things outside the immediate scope of the generated code. These "external" things are primarily global variables, C++ functions (both standard library and V8-specific), and potentially hardware features.

2. **Scan for key structures and patterns:**  The dominant pattern is the `ExternalReference` class and its static methods. These methods generally follow a pattern:
    - They return an `ExternalReference` object.
    - They often take no arguments or an `Isolate*` argument.
    - Inside the methods, `reinterpret_cast<Address>(&some_variable)` or `FUNCTION_ADDR(&some_function)` are used to get the raw memory address of the external entity.
    - Some methods use `FUNCTION_REFERENCE` or `FUNCTION_REFERENCE_WITH_TYPE` which seem to be macros for encapsulating function pointers with metadata.

3. **Categorize the external references:** By examining the names of the variables and functions being referenced, we can group them into logical categories:
    - **Constants:**  Variables like `double_constant`, `wasm_i8x16_swizzle_mask`, etc., which are used for specific numerical or bitmask values. The `wasm_` prefix indicates WebAssembly related constants.
    - **CPU Features:**  References to `CpuFeatures::supports_wasm_simd_128_`, `CpuFeatures::supports_cetss_`, indicating querying hardware capabilities.
    - **RegExp (Regular Expression) Related:** Many references start with `re_`, such as `re_check_stack_guard_state`, `re_grow_stack`, etc., suggesting functions and data structures used by the regular expression engine.
    - **Math Functions:** References like `ieee754_acos_function`, `ieee754_sin_function`, and others, clearly point to mathematical functions, often using the `base::ieee754` namespace, indicating adherence to the IEEE 754 standard.
    - **Standard Library Functions:** References to `libc_memchr_function`, `libc_memcpy_function`, etc., signify calls to standard C library functions for memory manipulation.
    - **String Manipulation:** Functions like `search_string_raw`, `string_write_to_flat_one_byte`, and `external_one_byte_string_get_chars` are clearly related to string processing.
    - **Hashing and Dictionary Lookups:** References to `orderedhashmap_gethash_raw`, `get_or_create_hash_raw`, and functions involving `NameDictionary`, `GlobalDictionary`, etc., are related to hash table operations and dictionary lookups within V8's internal data structures.
    - **Typed Arrays:** References to functions like `copy_fast_number_jsarray_elements_to_typed_array` and `typed_array_and_rab_gsab_typed_array_elements_kind_shifts` deal with operations on Typed Arrays.
    - **BigInt:** Functions starting with `mutable_big_int_` are for operations on BigInt values.
    - **Internationalization (Intl):** References like `intl_convert_one_byte_to_lower` suggest support for internationalization features.
    - **Isolate-Specific Data:** References taking an `Isolate*` argument often point to data that is specific to a V8 isolate (an isolated instance of the V8 engine). Examples include `thread_in_wasm_flag_address_address`, `address_of_regexp_static_result_offsets_vector`, etc.
    - **Callbacks:**  Functions like `invoke_function_callback_generic` and `invoke_accessor_getter_callback` are related to calling back into JavaScript or C++ code.
    - **Debugging:** References like `debug_is_active_address`, `debug_hook_on_function_call_address`, and `debug_suspended_generator_address` are used for debugging purposes.
    - **Microtasks:** The `call_enqueue_microtask_function` is related to V8's microtask queue.
    - **Atomic Operations:**  Functions with `atomic_pair_` in their name deal with atomic operations on 64-bit values.
    - **Prototype Chains:** The `invalidate_prototype_chains_function` is related to V8's prototype inheritance mechanism.

4. **Address the specific questions:**
    - **Functionality:**  Summarize the identified categories of external references.
    - **`.tq` extension:** Explain that `.tq` indicates Torque code, and this file is `.cc`, so it's not Torque.
    - **JavaScript relationship:**  Provide examples of how some of these external references relate to JavaScript features (e.g., `Math.sin`, regular expressions, `Array.prototype.indexOf`).
    - **Code logic and input/output:** For simple cases like constants, the input is implicit (accessing the reference), and the output is the value of the constant. For function references, the input and output depend on the referenced function's signature.
    - **Common programming errors:**  Explain that incorrect usage of these low-level references can lead to crashes or undefined behavior.
    - **Part 2 summary:**  Reiterate the main purpose of providing external references and the types of entities being referenced.

5. **Structure the summary:** Organize the findings into clear sections for better readability.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive summary of its functionality, addressing all the user's specific questions.
好的，根据您提供的代码片段，以下是 `v8/src/codegen/external-reference.cc` 的功能归纳：

**功能归纳 (基于提供的代码片段):**

这个代码片段的主要功能是**定义和提供对 V8 引擎外部资源的引用 (ExternalReference)**。这些外部资源包括：

* **全局常量:**  例如 `double_constant`, `double_negate_constant`, 以及各种 `wasm_` 前缀的常量，这些常量在 V8 的代码生成和执行过程中被使用。
* **CPU 特性标志:** 例如 `CpuFeatures::supports_wasm_simd_128_` 和 `CpuFeatures::supports_cetss_`，用于在运行时检查 CPU 的硬件特性。
* **C++ 函数地址:**  这包括 V8 内部的辅助函数 (例如处理 API 回调、正则表达式操作、数学运算、字符串操作、哈希计算、Typed Array 操作、BigInt 操作、以及 Intl 相关的功能) 和标准 C 库函数 (例如 `memchr`, `memcpy`, `memset`)。
* **V8 引擎内部数据结构的地址:** 例如正则表达式的栈限制地址、结果偏移向量地址等。
* **V8 标志 (Flags):** 例如 `v8_flags.enable_experimental_regexp_engine`。

**更具体地说，这段代码提供了获取这些外部资源地址的便捷方法，以便 V8 的代码生成器 (Codegen) 可以生成可以直接访问这些资源的机器码。**

**针对您提出的问题：**

* **`.tq` 结尾:**  `v8/src/codegen/external-reference.cc` 的确是以 `.cc` 结尾，这意味着它是一个 **C++ 源代码文件**，而不是 V8 Torque 源代码。如果以 `.tq` 结尾，则表示它是用 V8 的领域特定语言 Torque 编写的。

* **与 JavaScript 的功能关系 (举例说明):**

   许多在此文件中定义的外部引用都直接支持着 JavaScript 的核心功能。例如：

   ```javascript
   // Math 对象的方法会用到这里的 ieee754_* 函数
   console.log(Math.sin(0.5));
   console.log(Math.pow(2, 3));

   // 正则表达式操作会用到 re_* 系列的引用
   const regex = /abc/;
   regex.test("abcdefg");

   // 字符串操作可能会用到 search_string_raw_* 或 string_write_to_flat_*
   const str = "hello";
   console.log(str.indexOf("e"));

   // Typed Array 的操作会用到 copy_typed_array_elements_* 等
   const buffer = new ArrayBuffer(16);
   const view = new Uint32Array(buffer);
   view[0] = 10;

   // BigInt 的操作会用到 mutable_big_int_* 系列的引用
   const bigIntValue = 9007199254740991n + 1n;

   //  Array 的 includes 和 indexOf 方法会用到 array_indexof_includes_*
   const arr = [1, 2, 3];
   arr.includes(2);
   arr.indexOf(3);
   ```

   当 JavaScript 引擎执行这些 JavaScript 代码时，V8 的代码生成器会生成机器码，这些机器码会通过 `ExternalReference` 来调用 C++ 实现的底层功能或者访问必要的常量数据。

* **代码逻辑推理 (假设输入与输出):**

   大部分 `ExternalReference` 的静态方法的功能是直接返回一个包含特定外部资源地址的 `ExternalReference` 对象。

   **假设输入:** 调用 `ExternalReference::address_of_double_constant()`

   **输出:** 一个 `ExternalReference` 对象，该对象内部存储着 `double_constant` 变量的内存地址。

   **假设输入:** 调用 `ExternalReference::ieee754_sin_function()`

   **输出:** 一个 `ExternalReference` 对象，该对象内部存储着 `base::ieee754::sin` 函数的地址 (可能通过 `Redirect` 包装)。

* **涉及用户常见的编程错误 (举例说明):**

   普通 JavaScript 开发者通常不会直接与 `v8/src/codegen/external-reference.cc` 中定义的引用交互。这些是 V8 引擎内部使用的。 然而，理解这些引用有助于理解 V8 引擎的底层工作原理。

   虽然用户不会直接操作这些 `ExternalReference`，但理解其背后的原理可以帮助理解一些性能问题或边界情况。例如，如果正则表达式写得过于复杂，可能会导致 `re_grow_stack` 被频繁调用，从而影响性能。错误地使用 Typed Array 也可能涉及到一些底层内存操作，如果超出边界可能会导致崩溃，而这些操作的实现可能就依赖于这里定义的外部引用。

**总结 (针对第 2 部分):**

这部分代码主要负责定义和提供对 V8 引擎在代码生成和执行过程中需要访问的外部资源的引用。这些资源涵盖了常量、CPU 特性、C++ 函数 (包括 V8 内部和标准库函数) 以及引擎内部数据结构的地址。通过 `ExternalReference` 机制，V8 的代码生成器能够有效地访问这些外部资源，从而实现 JavaScript 的各种核心功能。

### 提示词
```
这是目录为v8/src/codegen/external-reference.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/external-reference.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
tant));
}

ExternalReference ExternalReference::address_of_double_neg_constant() {
  return ExternalReference(reinterpret_cast<Address>(&double_negate_constant));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_swizzle_mask() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_swizzle_mask));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_popcnt_mask() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_popcnt_mask));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_splat_0x01() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_splat_0x01));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_splat_0x0f() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_splat_0x0f));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_splat_0x33() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_splat_0x33));
}

ExternalReference ExternalReference::address_of_wasm_i8x16_splat_0x55() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i8x16_splat_0x55));
}

ExternalReference ExternalReference::address_of_wasm_i16x8_splat_0x0001() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_i16x8_splat_0x0001));
}

ExternalReference
ExternalReference::address_of_wasm_f64x2_convert_low_i32x4_u_int_mask() {
  return ExternalReference(
      reinterpret_cast<Address>(&wasm_f64x2_convert_low_i32x4_u_int_mask));
}

ExternalReference ExternalReference::supports_wasm_simd_128_address() {
  return ExternalReference(
      reinterpret_cast<Address>(&CpuFeatures::supports_wasm_simd_128_));
}

ExternalReference ExternalReference::address_of_wasm_double_2_power_52() {
  return ExternalReference(reinterpret_cast<Address>(&wasm_double_2_power_52));
}

ExternalReference ExternalReference::address_of_wasm_int32_max_as_double() {
  return ExternalReference(
      reinterpret_cast<Address>(&wasm_int32_max_as_double));
}

ExternalReference ExternalReference::address_of_wasm_uint32_max_as_double() {
  return ExternalReference(
      reinterpret_cast<Address>(&wasm_uint32_max_as_double));
}

ExternalReference ExternalReference::address_of_wasm_int32_overflow_as_float() {
  return ExternalReference(
      reinterpret_cast<Address>(&wasm_int32_overflow_as_float));
}

ExternalReference
ExternalReference::address_of_wasm_i32x8_int32_overflow_as_float() {
  return ExternalReference(
      reinterpret_cast<Address>(&wasm_i32x8_int32_overflow_as_float));
}

ExternalReference ExternalReference::supports_cetss_address() {
  return ExternalReference(
      reinterpret_cast<Address>(&CpuFeatures::supports_cetss_));
}

ExternalReference
ExternalReference::address_of_enable_experimental_regexp_engine() {
  return ExternalReference(&v8_flags.enable_experimental_regexp_engine);
}

namespace {

static uintptr_t BaselinePCForBytecodeOffset(Address raw_code_obj,
                                             int bytecode_offset,
                                             Address raw_bytecode_array) {
  Tagged<Code> code_obj = Cast<Code>(Tagged<Object>(raw_code_obj));
  Tagged<BytecodeArray> bytecode_array =
      Cast<BytecodeArray>(Tagged<Object>(raw_bytecode_array));
  return code_obj->GetBaselineStartPCForBytecodeOffset(bytecode_offset,
                                                       bytecode_array);
}

static uintptr_t BaselinePCForNextExecutedBytecode(Address raw_code_obj,
                                                   int bytecode_offset,
                                                   Address raw_bytecode_array) {
  Tagged<Code> code_obj = Cast<Code>(Tagged<Object>(raw_code_obj));
  Tagged<BytecodeArray> bytecode_array =
      Cast<BytecodeArray>(Tagged<Object>(raw_bytecode_array));
  return code_obj->GetBaselinePCForNextExecutedBytecode(bytecode_offset,
                                                        bytecode_array);
}

}  // namespace

FUNCTION_REFERENCE(baseline_pc_for_bytecode_offset, BaselinePCForBytecodeOffset)
FUNCTION_REFERENCE(baseline_pc_for_next_executed_bytecode,
                   BaselinePCForNextExecutedBytecode)

ExternalReference ExternalReference::thread_in_wasm_flag_address_address(
    Isolate* isolate) {
  return ExternalReference(isolate->thread_in_wasm_flag_address_address());
}

ExternalReference ExternalReference::invoke_function_callback_generic() {
  Address thunk_address = FUNCTION_ADDR(&InvokeFunctionCallbackGeneric);
  ExternalReference::Type thunk_type = ExternalReference::DIRECT_API_CALL;
  ApiFunction thunk_fun(thunk_address);
  return ExternalReference::Create(&thunk_fun, thunk_type);
}

ExternalReference ExternalReference::invoke_function_callback_optimized() {
  Address thunk_address = FUNCTION_ADDR(&InvokeFunctionCallbackOptimized);
  ExternalReference::Type thunk_type = ExternalReference::DIRECT_API_CALL;
  ApiFunction thunk_fun(thunk_address);
  return ExternalReference::Create(&thunk_fun, thunk_type);
}

// static
ExternalReference ExternalReference::invoke_function_callback(
    CallApiCallbackMode mode) {
  switch (mode) {
    case CallApiCallbackMode::kGeneric:
      return invoke_function_callback_generic();
    case CallApiCallbackMode::kOptimized:
      return invoke_function_callback_optimized();
    case CallApiCallbackMode::kOptimizedNoProfiling:
      return ExternalReference();
  }
}

ExternalReference ExternalReference::invoke_accessor_getter_callback() {
  Address thunk_address = FUNCTION_ADDR(&InvokeAccessorGetterCallback);
  ExternalReference::Type thunk_type = ExternalReference::DIRECT_GETTER_CALL;
  ApiFunction thunk_fun(thunk_address);
  return ExternalReference::Create(&thunk_fun, thunk_type);
}

#if V8_TARGET_ARCH_X64
#define re_stack_check_func RegExpMacroAssemblerX64::CheckStackGuardState
#elif V8_TARGET_ARCH_IA32
#define re_stack_check_func RegExpMacroAssemblerIA32::CheckStackGuardState
#elif V8_TARGET_ARCH_ARM64
#define re_stack_check_func RegExpMacroAssemblerARM64::CheckStackGuardState
#elif V8_TARGET_ARCH_ARM
#define re_stack_check_func RegExpMacroAssemblerARM::CheckStackGuardState
#elif V8_TARGET_ARCH_PPC64
#define re_stack_check_func RegExpMacroAssemblerPPC::CheckStackGuardState
#elif V8_TARGET_ARCH_MIPS64
#define re_stack_check_func RegExpMacroAssemblerMIPS::CheckStackGuardState
#elif V8_TARGET_ARCH_LOONG64
#define re_stack_check_func RegExpMacroAssemblerLOONG64::CheckStackGuardState
#elif V8_TARGET_ARCH_S390X
#define re_stack_check_func RegExpMacroAssemblerS390::CheckStackGuardState
#elif V8_TARGET_ARCH_RISCV32 || V8_TARGET_ARCH_RISCV64
#define re_stack_check_func RegExpMacroAssemblerRISCV::CheckStackGuardState
#else
UNREACHABLE();
#endif

FUNCTION_REFERENCE(re_check_stack_guard_state, re_stack_check_func)
#undef re_stack_check_func

FUNCTION_REFERENCE(re_grow_stack, NativeRegExpMacroAssembler::GrowStack)

FUNCTION_REFERENCE(re_match_for_call_from_js,
                   IrregexpInterpreter::MatchForCallFromJs)

FUNCTION_REFERENCE(re_experimental_match_for_call_from_js,
                   ExperimentalRegExp::MatchForCallFromJs)

FUNCTION_REFERENCE(re_atom_exec_raw, RegExp::AtomExecRaw)

FUNCTION_REFERENCE(allocate_regexp_result_vector, RegExpResultVector::Allocate)
FUNCTION_REFERENCE(free_regexp_result_vector, RegExpResultVector::Free)

FUNCTION_REFERENCE(re_case_insensitive_compare_unicode,
                   NativeRegExpMacroAssembler::CaseInsensitiveCompareUnicode)

FUNCTION_REFERENCE(re_case_insensitive_compare_non_unicode,
                   NativeRegExpMacroAssembler::CaseInsensitiveCompareNonUnicode)

FUNCTION_REFERENCE(re_is_character_in_range_array,
                   RegExpMacroAssembler::IsCharacterInRangeArray)

ExternalReference ExternalReference::re_word_character_map() {
  return ExternalReference(
      NativeRegExpMacroAssembler::word_character_map_address());
}

ExternalReference
ExternalReference::address_of_regexp_static_result_offsets_vector(
    Isolate* isolate) {
  return ExternalReference(
      isolate->address_of_regexp_static_result_offsets_vector());
}

ExternalReference ExternalReference::address_of_regexp_stack_limit_address(
    Isolate* isolate) {
  return ExternalReference(isolate->regexp_stack()->limit_address_address());
}

ExternalReference ExternalReference::address_of_regexp_stack_memory_top_address(
    Isolate* isolate) {
  return ExternalReference(
      isolate->regexp_stack()->memory_top_address_address());
}

ExternalReference ExternalReference::address_of_regexp_stack_stack_pointer(
    Isolate* isolate) {
  return ExternalReference(isolate->regexp_stack()->stack_pointer_address());
}

FUNCTION_REFERENCE_WITH_TYPE(ieee754_acos_function, base::ieee754::acos,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_acosh_function, base::ieee754::acosh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_asin_function, base::ieee754::asin,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_asinh_function, base::ieee754::asinh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_atan_function, base::ieee754::atan,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_atanh_function, base::ieee754::atanh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_atan2_function, base::ieee754::atan2,
                             BUILTIN_FP_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_cbrt_function, base::ieee754::cbrt,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_cosh_function, base::ieee754::cosh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_exp_function, base::ieee754::exp,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_expm1_function, base::ieee754::expm1,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_log_function, base::ieee754::log,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_log1p_function, base::ieee754::log1p,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_log10_function, base::ieee754::log10,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_log2_function, base::ieee754::log2,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_sinh_function, base::ieee754::sinh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_tan_function, base::ieee754::tan,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_tanh_function, base::ieee754::tanh,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_pow_function, math::pow,
                             BUILTIN_FP_FP_CALL)

#if defined(V8_USE_LIBM_TRIG_FUNCTIONS)
ExternalReference ExternalReference::ieee754_sin_function() {
  static_assert(
      IsValidExternalReferenceType<decltype(&base::ieee754::libm_sin)>::value);
  static_assert(IsValidExternalReferenceType<
                decltype(&base::ieee754::fdlibm_sin)>::value);
  auto* f = v8_flags.use_libm_trig_functions ? base::ieee754::libm_sin
                                             : base::ieee754::fdlibm_sin;
  return ExternalReference(Redirect(FUNCTION_ADDR(f), BUILTIN_FP_CALL));
}
ExternalReference ExternalReference::ieee754_cos_function() {
  static_assert(
      IsValidExternalReferenceType<decltype(&base::ieee754::libm_cos)>::value);
  static_assert(IsValidExternalReferenceType<
                decltype(&base::ieee754::fdlibm_cos)>::value);
  auto* f = v8_flags.use_libm_trig_functions ? base::ieee754::libm_cos
                                             : base::ieee754::fdlibm_cos;
  return ExternalReference(Redirect(FUNCTION_ADDR(f), BUILTIN_FP_CALL));
}
#else
FUNCTION_REFERENCE_WITH_TYPE(ieee754_sin_function, base::ieee754::sin,
                             BUILTIN_FP_CALL)
FUNCTION_REFERENCE_WITH_TYPE(ieee754_cos_function, base::ieee754::cos,
                             BUILTIN_FP_CALL)
#endif

void* libc_memchr(void* string, int character, size_t search_length) {
  return memchr(string, character, search_length);
}

FUNCTION_REFERENCE(libc_memchr_function, libc_memchr)

void* libc_memcpy(void* dest, const void* src, size_t n) {
  return memcpy(dest, src, n);
}

FUNCTION_REFERENCE(libc_memcpy_function, libc_memcpy)

void* libc_memmove(void* dest, const void* src, size_t n) {
  return memmove(dest, src, n);
}

FUNCTION_REFERENCE(libc_memmove_function, libc_memmove)

void* libc_memset(void* dest, int value, size_t n) {
  DCHECK_EQ(static_cast<uint8_t>(value), value);
  return memset(dest, value, n);
}

FUNCTION_REFERENCE(libc_memset_function, libc_memset)

void relaxed_memcpy(volatile base::Atomic8* dest,
                    volatile const base::Atomic8* src, size_t n) {
  base::Relaxed_Memcpy(dest, src, n);
}

FUNCTION_REFERENCE(relaxed_memcpy_function, relaxed_memcpy)

void relaxed_memmove(volatile base::Atomic8* dest,
                     volatile const base::Atomic8* src, size_t n) {
  base::Relaxed_Memmove(dest, src, n);
}

FUNCTION_REFERENCE(relaxed_memmove_function, relaxed_memmove)

ExternalReference ExternalReference::printf_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(std::printf)));
}

FUNCTION_REFERENCE(refill_math_random, MathRandom::RefillCache)

template <typename SubjectChar, typename PatternChar>
ExternalReference ExternalReference::search_string_raw() {
  auto f = SearchStringRaw<SubjectChar, PatternChar>;
  return ExternalReference(Redirect(FUNCTION_ADDR(f)));
}

FUNCTION_REFERENCE(jsarray_array_join_concat_to_sequential_string,
                   JSArray::ArrayJoinConcatToSequentialString)

FUNCTION_REFERENCE(gsab_byte_length, JSArrayBuffer::GsabByteLength)

ExternalReference ExternalReference::search_string_raw_one_one() {
  return search_string_raw<const uint8_t, const uint8_t>();
}

ExternalReference ExternalReference::search_string_raw_one_two() {
  return search_string_raw<const uint8_t, const base::uc16>();
}

ExternalReference ExternalReference::search_string_raw_two_one() {
  return search_string_raw<const base::uc16, const uint8_t>();
}

ExternalReference ExternalReference::search_string_raw_two_two() {
  return search_string_raw<const base::uc16, const base::uc16>();
}

ExternalReference
ExternalReference::typed_array_and_rab_gsab_typed_array_elements_kind_shifts() {
  uint8_t* ptr =
      const_cast<uint8_t*>(TypedArrayAndRabGsabTypedArrayElementsKindShifts());
  return ExternalReference(reinterpret_cast<Address>(ptr));
}

ExternalReference
ExternalReference::typed_array_and_rab_gsab_typed_array_elements_kind_sizes() {
  uint8_t* ptr =
      const_cast<uint8_t*>(TypedArrayAndRabGsabTypedArrayElementsKindSizes());
  return ExternalReference(reinterpret_cast<Address>(ptr));
}

namespace {

void StringWriteToFlatOneByte(Address source, uint8_t* sink, int32_t start,
                              int32_t length) {
  return String::WriteToFlat<uint8_t>(Cast<String>(Tagged<Object>(source)),
                                      sink, start, length);
}

void StringWriteToFlatTwoByte(Address source, uint16_t* sink, int32_t start,
                              int32_t length) {
  return String::WriteToFlat<uint16_t>(Cast<String>(Tagged<Object>(source)),
                                       sink, start, length);
}

const uint8_t* ExternalOneByteStringGetChars(Address string) {
  // The following CHECK is a workaround to prevent a CFI bug where
  // ExternalOneByteStringGetChars() and ExternalTwoByteStringGetChars() are
  // merged by the linker, resulting in one of the input type's vtable address
  // failing the address range check.
  // TODO(chromium:1160961): Consider removing the CHECK when CFI is fixed.
  CHECK(IsExternalOneByteString(Tagged<Object>(string)));
  return Cast<ExternalOneByteString>(Tagged<Object>(string))->GetChars();
}
const uint16_t* ExternalTwoByteStringGetChars(Address string) {
  // The following CHECK is a workaround to prevent a CFI bug where
  // ExternalOneByteStringGetChars() and ExternalTwoByteStringGetChars() are
  // merged by the linker, resulting in one of the input type's vtable address
  // failing the address range check.
  // TODO(chromium:1160961): Consider removing the CHECK when CFI is fixed.
  CHECK(IsExternalTwoByteString(Tagged<Object>(string)));
  return Cast<ExternalTwoByteString>(Tagged<Object>(string))->GetChars();
}

}  // namespace

FUNCTION_REFERENCE(string_write_to_flat_one_byte, StringWriteToFlatOneByte)
FUNCTION_REFERENCE(string_write_to_flat_two_byte, StringWriteToFlatTwoByte)

FUNCTION_REFERENCE(external_one_byte_string_get_chars,
                   ExternalOneByteStringGetChars)
FUNCTION_REFERENCE(external_two_byte_string_get_chars,
                   ExternalTwoByteStringGetChars)

// See:
// https://lemire.me/blog/2021/06/03/computing-the-number-of-digits-of-an-integer-even-faster/
static constexpr uint64_t kLog10OffsetTable[] = {
    0x100000000, 0x1fffffff6, 0x1fffffff6, 0x1fffffff6, 0x2ffffff9c,
    0x2ffffff9c, 0x2ffffff9c, 0x3fffffc18, 0x3fffffc18, 0x3fffffc18,
    0x4ffffd8f0, 0x4ffffd8f0, 0x4ffffd8f0, 0x4ffffd8f0, 0x5fffe7960,
    0x5fffe7960, 0x5fffe7960, 0x6fff0bdc0, 0x6fff0bdc0, 0x6fff0bdc0,
    0x7ff676980, 0x7ff676980, 0x7ff676980, 0x7ff676980, 0x8fa0a1f00,
    0x8fa0a1f00, 0x8fa0a1f00, 0x9c4653600, 0x9c4653600, 0x9c4653600,
    0xa00000000, 0xa00000000,
};

ExternalReference ExternalReference::address_of_log10_offset_table() {
  return ExternalReference(reinterpret_cast<Address>(&kLog10OffsetTable[0]));
}

FUNCTION_REFERENCE(orderedhashmap_gethash_raw, OrderedHashMap::GetHash)

Address GetOrCreateHash(Isolate* isolate, Address raw_key) {
  DisallowGarbageCollection no_gc;
  return Object::GetOrCreateHash(Tagged<Object>(raw_key), isolate).ptr();
}

FUNCTION_REFERENCE(get_or_create_hash_raw, GetOrCreateHash)

static Address JSReceiverCreateIdentityHash(Isolate* isolate, Address raw_key) {
  Tagged<JSReceiver> key = Cast<JSReceiver>(Tagged<Object>(raw_key));
  return JSReceiver::CreateIdentityHash(isolate, key).ptr();
}

FUNCTION_REFERENCE(jsreceiver_create_identity_hash,
                   JSReceiverCreateIdentityHash)

static uint32_t ComputeSeededIntegerHash(Isolate* isolate, int32_t key) {
  DisallowGarbageCollection no_gc;
  return ComputeSeededHash(static_cast<uint32_t>(key), HashSeed(isolate));
}

FUNCTION_REFERENCE(compute_integer_hash, ComputeSeededIntegerHash)

enum LookupMode { kFindExisting, kFindInsertionEntry };
template <typename Dictionary, LookupMode mode>
static size_t NameDictionaryLookupForwardedString(Isolate* isolate,
                                                  Address raw_dict,
                                                  Address raw_key) {
  // This function cannot allocate, but there is a HandleScope because it needs
  // to pass Handle<Name> to the dictionary methods.
  DisallowGarbageCollection no_gc;
  HandleScope handle_scope(isolate);

  Handle<String> key(Cast<String>(Tagged<Object>(raw_key)), isolate);
  // This function should only be used as the slow path for forwarded strings.
  DCHECK(Name::IsForwardingIndex(key->raw_hash_field()));

  Tagged<Dictionary> dict = Cast<Dictionary>(Tagged<Object>(raw_dict));
  ReadOnlyRoots roots(isolate);
  uint32_t hash = key->hash();
  InternalIndex entry = mode == kFindExisting
                            ? dict->FindEntry(isolate, roots, key, hash)
                            : dict->FindInsertionEntry(isolate, roots, hash);
  return entry.raw_value();
}

FUNCTION_REFERENCE(
    name_dictionary_lookup_forwarded_string,
    (NameDictionaryLookupForwardedString<NameDictionary, kFindExisting>))
FUNCTION_REFERENCE(
    name_dictionary_find_insertion_entry_forwarded_string,
    (NameDictionaryLookupForwardedString<NameDictionary, kFindInsertionEntry>))
FUNCTION_REFERENCE(
    global_dictionary_lookup_forwarded_string,
    (NameDictionaryLookupForwardedString<GlobalDictionary, kFindExisting>))
FUNCTION_REFERENCE(global_dictionary_find_insertion_entry_forwarded_string,
                   (NameDictionaryLookupForwardedString<GlobalDictionary,
                                                        kFindInsertionEntry>))
FUNCTION_REFERENCE(
    name_to_index_hashtable_lookup_forwarded_string,
    (NameDictionaryLookupForwardedString<NameToIndexHashTable, kFindExisting>))
FUNCTION_REFERENCE(
    name_to_index_hashtable_find_insertion_entry_forwarded_string,
    (NameDictionaryLookupForwardedString<NameToIndexHashTable,
                                         kFindInsertionEntry>))

FUNCTION_REFERENCE(copy_fast_number_jsarray_elements_to_typed_array,
                   CopyFastNumberJSArrayElementsToTypedArray)
FUNCTION_REFERENCE(copy_typed_array_elements_to_typed_array,
                   CopyTypedArrayElementsToTypedArray)
FUNCTION_REFERENCE(copy_typed_array_elements_slice, CopyTypedArrayElementsSlice)
FUNCTION_REFERENCE(try_string_to_index_or_lookup_existing,
                   StringTable::TryStringToIndexOrLookupExisting)
FUNCTION_REFERENCE(string_from_forward_table,
                   StringForwardingTable::GetForwardStringAddress)
FUNCTION_REFERENCE(raw_hash_from_forward_table,
                   StringForwardingTable::GetRawHashStatic)
FUNCTION_REFERENCE(string_to_array_index_function, String::ToArrayIndex)
FUNCTION_REFERENCE(array_indexof_includes_smi_or_object,
                   ArrayIndexOfIncludesSmiOrObject)
FUNCTION_REFERENCE(array_indexof_includes_double, ArrayIndexOfIncludesDouble)

static Address LexicographicCompareWrapper(Isolate* isolate, Address smi_x,
                                           Address smi_y) {
  Tagged<Smi> x(smi_x);
  Tagged<Smi> y(smi_y);
  return Smi::LexicographicCompare(isolate, x, y);
}

FUNCTION_REFERENCE(smi_lexicographic_compare_function,
                   LexicographicCompareWrapper)

uint32_t HasUnpairedSurrogate(const uint16_t* code_units, size_t length) {
  // Use uint32_t to avoid complexity around bool return types.
  static constexpr uint32_t kTrue = 1;
  static constexpr uint32_t kFalse = 0;
  return unibrow::Utf16::HasUnpairedSurrogate(code_units, length) ? kTrue
                                                                  : kFalse;
}

FUNCTION_REFERENCE(has_unpaired_surrogate, HasUnpairedSurrogate)

void ReplaceUnpairedSurrogates(const uint16_t* source_code_units,
                               uint16_t* dest_code_units, size_t length) {
  return unibrow::Utf16::ReplaceUnpairedSurrogates(source_code_units,
                                                   dest_code_units, length);
}

FUNCTION_REFERENCE(replace_unpaired_surrogates, ReplaceUnpairedSurrogates)

FUNCTION_REFERENCE(mutable_big_int_absolute_add_and_canonicalize_function,
                   MutableBigInt_AbsoluteAddAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_absolute_compare_function,
                   MutableBigInt_AbsoluteCompare)

FUNCTION_REFERENCE(mutable_big_int_absolute_sub_and_canonicalize_function,
                   MutableBigInt_AbsoluteSubAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_absolute_mul_and_canonicalize_function,
                   MutableBigInt_AbsoluteMulAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_absolute_div_and_canonicalize_function,
                   MutableBigInt_AbsoluteDivAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_absolute_mod_and_canonicalize_function,
                   MutableBigInt_AbsoluteModAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_and_pp_and_canonicalize_function,
                   MutableBigInt_BitwiseAndPosPosAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_and_nn_and_canonicalize_function,
                   MutableBigInt_BitwiseAndNegNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_and_pn_and_canonicalize_function,
                   MutableBigInt_BitwiseAndPosNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_or_pp_and_canonicalize_function,
                   MutableBigInt_BitwiseOrPosPosAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_or_nn_and_canonicalize_function,
                   MutableBigInt_BitwiseOrNegNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_or_pn_and_canonicalize_function,
                   MutableBigInt_BitwiseOrPosNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_xor_pp_and_canonicalize_function,
                   MutableBigInt_BitwiseXorPosPosAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_xor_nn_and_canonicalize_function,
                   MutableBigInt_BitwiseXorNegNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_bitwise_xor_pn_and_canonicalize_function,
                   MutableBigInt_BitwiseXorPosNegAndCanonicalize)

FUNCTION_REFERENCE(mutable_big_int_left_shift_and_canonicalize_function,
                   MutableBigInt_LeftShiftAndCanonicalize)

FUNCTION_REFERENCE(big_int_right_shift_result_length_function,
                   RightShiftResultLength)

FUNCTION_REFERENCE(mutable_big_int_right_shift_and_canonicalize_function,
                   MutableBigInt_RightShiftAndCanonicalize)

FUNCTION_REFERENCE(check_object_type, CheckObjectType)

#ifdef V8_INTL_SUPPORT

static Address ConvertOneByteToLower(Address raw_src, Address raw_dst) {
  Tagged<String> src = Cast<String>(Tagged<Object>(raw_src));
  Tagged<String> dst = Cast<String>(Tagged<Object>(raw_dst));
  return Intl::ConvertOneByteToLower(src, dst).ptr();
}
FUNCTION_REFERENCE(intl_convert_one_byte_to_lower, ConvertOneByteToLower)

ExternalReference ExternalReference::intl_to_latin1_lower_table() {
  uint8_t* ptr = const_cast<uint8_t*>(Intl::ToLatin1LowerTable());
  return ExternalReference(reinterpret_cast<Address>(ptr));
}

ExternalReference ExternalReference::intl_ascii_collation_weights_l1() {
  uint8_t* ptr = const_cast<uint8_t*>(Intl::AsciiCollationWeightsL1());
  return ExternalReference(reinterpret_cast<Address>(ptr));
}

ExternalReference ExternalReference::intl_ascii_collation_weights_l3() {
  uint8_t* ptr = const_cast<uint8_t*>(Intl::AsciiCollationWeightsL3());
  return ExternalReference(reinterpret_cast<Address>(ptr));
}

#endif  // V8_INTL_SUPPORT

// Explicit instantiations for all combinations of 1- and 2-byte strings.
template ExternalReference
ExternalReference::search_string_raw<const uint8_t, const uint8_t>();
template ExternalReference
ExternalReference::search_string_raw<const uint8_t, const base::uc16>();
template ExternalReference
ExternalReference::search_string_raw<const base::uc16, const uint8_t>();
template ExternalReference
ExternalReference::search_string_raw<const base::uc16, const base::uc16>();

ExternalReference ExternalReference::FromRawAddress(Address address) {
  if (address <= static_cast<Address>(kNumIsolateFieldIds)) {
    return ExternalReference(static_cast<IsolateFieldId>(address));
  }
  return ExternalReference(address);
}

ExternalReference ExternalReference::cpu_features() {
  DCHECK(CpuFeatures::initialized_);
  return ExternalReference(&CpuFeatures::supported_);
}

ExternalReference ExternalReference::promise_hook_flags_address(
    Isolate* isolate) {
  return ExternalReference(isolate->promise_hook_flags_address());
}

ExternalReference ExternalReference::promise_hook_address(Isolate* isolate) {
  return ExternalReference(isolate->promise_hook_address());
}

ExternalReference ExternalReference::async_event_delegate_address(
    Isolate* isolate) {
  return ExternalReference(isolate->async_event_delegate_address());
}

ExternalReference ExternalReference::debug_is_active_address(Isolate* isolate) {
  return ExternalReference(isolate->debug()->is_active_address());
}

ExternalReference ExternalReference::debug_hook_on_function_call_address(
    Isolate* isolate) {
  return ExternalReference(isolate->debug()->hook_on_function_call_address());
}

ExternalReference ExternalReference::runtime_function_table_address(
    Isolate* isolate) {
  return ExternalReference(
      const_cast<Runtime::Function*>(Runtime::RuntimeFunctionTable(isolate)));
}

static Address InvalidatePrototypeChainsWrapper(Address raw_map) {
  Tagged<Map> map = Cast<Map>(Tagged<Object>(raw_map));
  return JSObject::InvalidatePrototypeChains(map).ptr();
}

FUNCTION_REFERENCE(invalidate_prototype_chains_function,
                   InvalidatePrototypeChainsWrapper)

double modulo_double_double(double x, double y) { return Modulo(x, y); }

FUNCTION_REFERENCE_WITH_TYPE(mod_two_doubles_operation, modulo_double_double,
                             BUILTIN_FP_FP_CALL)

ExternalReference ExternalReference::debug_suspended_generator_address(
    Isolate* isolate) {
  return ExternalReference(isolate->debug()->suspended_generator_address());
}

ExternalReference ExternalReference::context_address(Isolate* isolate) {
  return ExternalReference(isolate->context_address());
}

FUNCTION_REFERENCE(call_enqueue_microtask_function,
                   MicrotaskQueue::CallEnqueueMicrotask)

ExternalReference ExternalReference::int64_mul_high_function() {
  return ExternalReference(
      Redirect(FUNCTION_ADDR(base::bits::SignedMulHigh64)));
}

static int64_t atomic_pair_load(intptr_t address) {
  return std::atomic_load(reinterpret_cast<std::atomic<int64_t>*>(address));
}

ExternalReference ExternalReference::atomic_pair_load_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_load)));
}

static void atomic_pair_store(intptr_t address, int value_low, int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  std::atomic_store(reinterpret_cast<std::atomic<int64_t>*>(address), value);
}

ExternalReference ExternalReference::atomic_pair_store_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_store)));
}

static int64_t atomic_pair_add(intptr_t address, int value_low,
                               int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_fetch_add(reinterpret_cast<std::atomic<int64_t>*>(address),
                               value);
}

ExternalReference ExternalReference::atomic_pair_add_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_add)));
}

static int64_t atomic_pair_sub(intptr_t address, int value_low,
                               int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_fetch_sub(reinterpret_cast<std::atomic<int64_t>*>(address),
                               value);
}

ExternalReference ExternalReference::atomic_pair_sub_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_sub)));
}

static int64_t atomic_pair_and(intptr_t address, int value_low,
                               int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_fetch_and(reinterpret_cast<std::atomic<int64_t>*>(address),
                               value);
}

ExternalReference ExternalReference::atomic_pair_and_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_and)));
}

static int64_t atomic_pair_or(intptr_t address, int value_low, int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_fetch_or(reinterpret_cast<std::atomic<int64_t>*>(address),
                              value);
}

ExternalReference ExternalReference::atomic_pair_or_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_or)));
}

static int64_t atomic_pair_xor(intptr_t address, int value_low,
                               int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_fetch_xor(reinterpret_cast<std::atomic<int64_t>*>(address),
                               value);
}

ExternalReference ExternalReference::atomic_pair_xor_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_xor)));
}

static int64_t atomic_pair_exchange(intptr_t address, int value_low,
                                    int value_high) {
  int64_t value =
      static_cast<int64_t>(value_high) << 32 | (value_low & 0xFFFFFFFF);
  return std::atomic_exchange(reinterpret_cast<std::atomic<int64_t>*>(address),
                              value);
}

ExternalReference ExternalReference::atomic_pair_exchange_function() {
  return ExternalReference(Redirect(FUNCTION_ADDR(atomic_pair_exchange)));
}

static uint64_t atomic_pair_compare_exchange(intptr_t address,
                                             int old_value_low,
```
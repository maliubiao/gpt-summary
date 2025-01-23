Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Understanding & Keyword Spotting:**

* **Copyright & License:** Standard boilerplate, indicating open-source nature.
* **`#if !V8_ENABLE_WEBASSEMBLY`:**  Immediately flags this file's strong association with WebAssembly within V8. The `#error` reinforces this.
* **`#ifndef V8_WASM_FUNCTION_BODY_DECODER_IMPL_H_`:** Standard header guard. Not functionally relevant to *what* it does, but important for preventing multiple inclusions.
* **`// Do only include this header for implementing new Interface of the WasmFullDecoder.`:** This is a crucial hint. The file is intended for internal use when extending the `WasmFullDecoder`.
* **Includes:**  A bunch of `src/...` and standard library headers. These point to core V8 data structures (`wasm/decoder.h`, `wasm/function-body-decoder.h`, `wasm/value-type.h`, etc.) and fundamental utilities (`base/small-vector.h`, `<optional>`, `<inttypes.h>`). This suggests the file deals with the low-level representation of WASM code.
* **`namespace v8::internal::wasm {`:**  Confirms the file is part of V8's internal WebAssembly implementation.
* **`TRACE(...)` and `TRACE_INST_FORMAT`:**  Debugging/logging utilities specific to WASM decoding. Not core functionality, but aids in development.
* **`VALIDATE(condition)`:**  A macro for conditional validation, likely used for error checking during development or in debug builds.

**2. Core Functionality - The "Decoder" in the Name:**

* The filename itself, `function-body-decoder-impl.h`, is a huge clue. It implies the file is about *decoding* the *body* of a *WebAssembly function*.
* The includes reinforce this (`src/wasm/decoder.h`, `src/wasm/function-body-decoder.h`).
* The numerous `Imm...Immediate` structs are strong indicators of how WASM instructions are parsed. "Immediate" refers to the data directly following an opcode. The names (`ImmI32Immediate`, `ImmF64Immediate`, `IndexImmediate`, etc.) suggest different data types and categories of immediates.

**3. Data Structures and Types:**

* **`WasmGlobal`, `WasmTag`:**  These are likely representations of global variables and tags (for exception handling) in the WASM module.
* **`LoadType`, `StoreType`:** Enums representing different kinds of memory access operations (e.g., loading an integer, storing a float).
* **`ATOMIC_OP_LIST`, `ATOMIC_STORE_OP_LIST`:**  Macros defining lists of atomic operations. This highlights the support for multi-threading/shared memory.
* **`HeapType`, `ValueType`:**  Fundamental types in WebAssembly. The `value_type_reader` namespace confirms that this file is involved in reading and validating these types.
* **`DecodingMode`:** An enum suggesting different contexts in which the decoder can be used (function bodies vs. constant expressions).

**4. Decoding Logic (Inferred):**

* The `Imm...Immediate` structs with their `template <typename ValidationTag> ...` constructors strongly suggest a pattern of reading data from a byte stream (`Decoder* decoder`, `const uint8_t* pc`).
* The `length` member in these structs indicates how many bytes were consumed while reading the immediate value.
* The `VALIDATE` macro being used extensively in these constructors points to error handling during the decoding process. The `DecodeError` functions further confirm this.

**5. Connection to JavaScript (Hypothesized):**

* WebAssembly is designed to be a compilation target for languages like C++ and Rust, but it runs *within* a JavaScript environment in the browser (or Node.js).
* The decoder's role is to translate the binary WASM format into V8's internal representation that can be executed by the JavaScript engine.
* Therefore, while this file is low-level C++, it's directly involved in enabling JavaScript to run WASM code.

**6. Torque Consideration:**

* The prompt explicitly asks about `.tq` files. The file ends in `.h`, so it's *not* a Torque file.

**7. Common Programming Errors (Inferred):**

* **Incorrectly sized immediates:** Reading too many or too few bytes for an immediate. The `length` fields and validation checks aim to prevent this.
* **Invalid opcodes:** Encountering a byte that doesn't correspond to a valid WASM instruction.
* **Type mismatches:** Trying to perform operations on values of incompatible types. The type validation logic in `value_type_reader` is crucial here.
* **Out-of-bounds memory access:**  Attempting to read or write memory outside the allocated WASM memory. The `MemoryAccessImmediate` and related checks are likely involved in validating this.
* **Incorrect branch targets:**  Branching to an invalid location within the code. The `BranchDepthImmediate` and branch table structures are relevant.

**8. Structuring the Answer:**

Based on these observations, the logical flow for summarizing the file's functionality is:

* **High-level purpose:** Decoding WASM function bodies.
* **Key components:** Immediates, value type reading, error handling.
* **Relationship to JavaScript:** Enabling WASM execution in JS environments.
* **Non-Torque nature:**  Confirming it's not a `.tq` file.
* **Common errors:**  Relating the file's functionality to potential pitfalls in WASM programming.

This methodical approach, starting with obvious clues and progressively inferring deeper functionalities based on naming conventions, includes, and code structure, leads to a comprehensive understanding of the C++ header file's role within the V8 WebAssembly implementation.
```cpp
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_FUNCTION_BODY_DECODER_IMPL_H_
#define V8_WASM_FUNCTION_BODY_DECODER_IMPL_H_

// Do only include this header for implementing new Interface of the
// WasmFullDecoder.

#include <inttypes.h>

#include <optional>

#include "src/base/bounds.h"
#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/strings/unicode.h"
#include "src/utils/bit-vector.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::wasm {

struct WasmGlobal;
struct WasmTag;

#define TRACE(...)                                        \
  do {                                                    \
    if (v8_flags.trace_wasm_decoder) PrintF(__VA_ARGS__); \
  } while (false)

#define TRACE_INST_FORMAT "  @%-8d #%-30s|"

// Return the evaluation of {condition} if {ValidationTag::validate} is true,
// DCHECK that it is true and always return true otherwise.
// Note that this needs to be a macro, because the "likely" annotation does not
// survive inlining.
#ifdef DEBUG
#define VALIDATE(condition)                       \
  (ValidationTag::validate ? V8_LIKELY(condition) \
                           : ValidateAssumeTrue(condition, #condition))

V8_INLINE bool ValidateAssumeTrue(bool condition, const char* message) {
  DCHECK_WITH_MSG(condition, message);
  return true;
}
#else
#define VALIDATE(condition) (!ValidationTag::validate || V8_LIKELY(condition))
#endif

#define CHECK_PROTOTYPE_OPCODE(feat)                                         \
  DCHECK(this->module_->origin == kWasmOrigin);                              \
  if (!VALIDATE(this->enabled_.has_##feat())) {                              \
    this->DecodeError(                                                       \
        "Invalid opcode 0x%02x (enable with --experimental-wasm-" #feat ")", \
        opcode);                                                             \
    return 0;                                                                \
  }                                                                          \
  this->detected_->add_##feat()

static constexpr LoadType GetLoadType(WasmOpcode opcode) {
  // Hard-code the list of load types. The opcodes are highly unlikely to
  // ever change, and we have some checks here to guard against that.
  static_assert(sizeof(LoadType) == sizeof(uint8_t), "LoadType is compact");
  constexpr uint8_t kMinOpcode = kExprI32LoadMem;
  constexpr uint8_t kMaxOpcode = kExprI64LoadMem32U;
  constexpr LoadType kLoadTypes[] = {
      LoadType::kI32Load,    LoadType::kI64Load,    LoadType::kF32Load,
      LoadType::kF64Load,    LoadType::kI32Load8S,  LoadType::kI32Load8U,
      LoadType::kI32Load16S, LoadType::kI32Load16U, LoadType::kI64Load8S,
      LoadType::kI64Load8U,  LoadType::kI64Load16S, LoadType::kI64Load16U,
      LoadType::kI64Load32S, LoadType::kI64Load32U};
  static_assert(arraysize(kLoadTypes) == kMaxOpcode - kMinOpcode + 1);
  DCHECK_LE(kMinOpcode, opcode);
  DCHECK_GE(kMaxOpcode, opcode);
  return kLoadTypes[opcode - kMinOpcode];
}

static constexpr StoreType GetStoreType(WasmOpcode opcode) {
  // Hard-code the list of store types. The opcodes are highly unlikely to
  // ever change, and we have some checks here to guard against that.
  static_assert(sizeof(StoreType) == sizeof(uint8_t), "StoreType is compact");
  constexpr uint8_t kMinOpcode = kExprI32StoreMem;
  constexpr uint8_t kMaxOpcode = kExprI64StoreMem32;
  constexpr StoreType kStoreTypes[] = {
      StoreType::kI32Store,  StoreType::kI64Store,   StoreType::kF32Store,
      StoreType::kF64Store,  StoreType::kI32Store8,  StoreType::kI32Store16,
      StoreType::kI64Store8, StoreType::kI64Store16, StoreType::kI64Store32};
  static_assert(arraysize(kStoreTypes) == kMaxOpcode - kMinOpcode + 1);
  DCHECK_LE(kMinOpcode, opcode);
  DCHECK_GE(kMaxOpcode, opcode);
  return kStoreTypes[opcode - kMinOpcode];
}

#define ATOMIC_OP_LIST(V)                \
  V(AtomicNotify, Uint32)                \
  V(I32AtomicWait, Uint32)               \
  V(I64AtomicWait, Uint64)               \
  V(I32AtomicLoad, Uint32)               \
  V(I64AtomicLoad, Uint64)               \
  V(I32AtomicLoad8U, Uint8)              \
  V(I32AtomicLoad16U, Uint16)            \
  V(I64AtomicLoad8U, Uint8)              \
  V(I64AtomicLoad16U, Uint16)            \
  V(I64AtomicLoad32U, Uint32)            \
  V(I32AtomicAdd, Uint32)                \
  V(I32AtomicAdd8U, Uint8)               \
  V(I32AtomicAdd16U, Uint16)             \
  V(I64AtomicAdd, Uint64)                \
  V(I64AtomicAdd8U, Uint8)               \
  V(I64AtomicAdd16U, Uint16)             \
  V(I64AtomicAdd32U, Uint32)             \
  V(I32AtomicSub, Uint32)                \
  V(I64AtomicSub, Uint64)                \
  V(I32AtomicSub8U, Uint8)               \
  V(I32AtomicSub16U, Uint16)             \
  V(I64AtomicSub8U, Uint8)               \
  V(I64AtomicSub16U, Uint16)             \
  V(I64AtomicSub32U, Uint32)             \
  V(I32AtomicAnd, Uint32)                \
  V(I64AtomicAnd, Uint64)                \
  V(I32AtomicAnd8U, Uint8)               \
  V(I32AtomicAnd16U, Uint16)             \
  V(I64AtomicAnd8U, Uint8)               \
  V(I64AtomicAnd16U, Uint16)             \
  V(I64AtomicAnd32U, Uint32)             \
  V(I32AtomicOr, Uint32)                 \
  V(I64AtomicOr, Uint64)                 \
  V(I32AtomicOr8U, Uint8)                \
  V(I32AtomicOr16U, Uint16)              \
  V(I64AtomicOr8U, Uint8)                \
  V(I64AtomicOr16U, Uint16)              \
  V(I64AtomicOr32U, Uint32)              \
  V(I32AtomicXor, Uint32)                \
  V(I64AtomicXor, Uint64)                \
  V(I32AtomicXor8U, Uint8)               \
  V(I32AtomicXor16U, Uint16)             \
  V(I64AtomicXor8U, Uint8)               \
  V(I64AtomicXor16U, Uint16)             \
  V(I64AtomicXor32U, Uint32)             \
  V(I32AtomicExchange, Uint32)           \
  V(I64AtomicExchange, Uint64)           \
  V(I32AtomicExchange8U, Uint8)          \
  V(I32AtomicExchange16U, Uint16)        \
  V(I64AtomicExchange8U, Uint8)          \
  V(I64AtomicExchange16U, Uint16)        \
  V(I64AtomicExchange32U, Uint32)        \
  V(I32AtomicCompareExchange, Uint32)    \
  V(I64AtomicCompareExchange, Uint64)    \
  V(I32AtomicCompareExchange8U, Uint8)   \
  V(I32AtomicCompareExchange16U, Uint16) \
  V(I64AtomicCompareExchange8U, Uint8)   \
  V(I64AtomicCompareExchange16U, Uint16) \
  V(I64AtomicCompareExchange32U, Uint32)

#define ATOMIC_STORE_OP_LIST(V) \
  V(I32AtomicStore, Uint32)     \
  V(I64AtomicStore, Uint64)     \
  V(I32AtomicStore8U, Uint8)    \
  V(I32AtomicStore16U, Uint16)  \
  V(I64AtomicStore8U, Uint8)    \
  V(I64AtomicStore16U, Uint16)  \
  V(I64AtomicStore32U, Uint32)

// Decoder error with explicit PC and optional format arguments.
// Depending on the validation tag and the number of arguments, this forwards to
// a V8_NOINLINE and V8_PRESERVE_MOST method of the decoder.
template <typename ValidationTag, typename... Args>
V8_INLINE void DecodeError(Decoder* decoder, const uint8_t* pc, const char* str,
                           Args&&... args) {
  // Decode errors can only happen if we are validating; the compiler should
  // know this e.g. from the VALIDATE macro, but this assumption tells it again
  // that this path is impossible.
  V8_ASSUME(ValidationTag::validate);
  if constexpr (sizeof...(Args) == 0) {
    decoder->error(pc, str);
  } else {
    decoder->errorf(pc, str, std::forward<Args>(args)...);
  }
}

// Decoder error without explicit PC and with optional format arguments.
// Depending on the validation tag and the number of arguments, this forwards to
// a V8_NOINLINE and V8_PRESERVE_MOST method of the decoder.
template <typename ValidationTag, typename... Args>
V8_INLINE void DecodeError(Decoder* decoder, const char* str, Args&&... args) {
  // Decode errors can only happen if we are validating; the compiler should
  // know this e.g. from the VALIDATE macro, but this assumption tells it again
  // that this path is impossible.
  V8_ASSUME(ValidationTag::validate);
  if constexpr (sizeof...(Args) == 0) {
    decoder->error(str);
  } else {
    decoder->errorf(str, std::forward<Args>(args)...);
  }
}

namespace value_type_reader {

template <typename ValidationTag>
std::pair<HeapType, uint32_t> read_heap_type(Decoder* decoder,
                                             const uint8_t* pc,
                                             WasmEnabledFeatures enabled) {
  auto [heap_index, length] =
      decoder->read_i33v<ValidationTag>(pc, "heap type");
  if (heap_index < 0) {
    int64_t min_1_byte_leb128 = -64;
    if (!VALIDATE(heap_index >= min_1_byte_leb128)) {
      DecodeError<ValidationTag>(decoder, pc, "Unknown heap type %" PRId64,
                                 heap_index);
      return {HeapType(HeapType::kBottom), length};
    }
    uint8_t uint_7_mask = 0x7F;
    uint8_t code = static_cast<ValueTypeCode>(heap_index) & uint_7_mask;
    bool is_shared = false;
    if (code == kSharedFlagCode) {
      if (!VALIDATE(enabled.has_shared())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid heap type 0x%x, enable with --experimental-wasm-shared",
            kSharedFlagCode);
        return {HeapType(HeapType::kBottom), length};
      }
      code = decoder->read_u8<ValidationTag>(pc + length, "heap type");
      length++;
      is_shared = true;
    }
    switch (code) {
      case kEqRefCode:
      case kI31RefCode:
      case kStructRefCode:
      case kArrayRefCode:
      case kAnyRefCode:
      case kNoneCode:
      case kNoExternCode:
      case kNoFuncCode:
      case kExternRefCode:
      case kFuncRefCode:
        return {HeapType::from_code(code, is_shared), length};
      case kNoExnCode:
      case kExnRefCode:
        if (!VALIDATE(enabled.has_exnref())) {
          DecodeError<ValidationTag>(
              decoder, pc,
              "invalid heap type '%s', enable with --experimental-wasm-exnref",
              HeapType::from_code(code, is_shared).name().c_str());
        }
        return {HeapType::from_code(code, is_shared), length};
      case kStringRefCode:
      case kStringViewWtf8Code:
      case kStringViewWtf16Code:
      case kStringViewIterCode:
        if (!VALIDATE(enabled.has_stringref())) {
          DecodeError<ValidationTag>(
              decoder, pc,
              "invalid heap type '%s', enable with "
              "--experimental-wasm-stringref",
              HeapType::from_code(code, is_shared).name().c_str());
        }
        return {HeapType::from_code(code, is_shared), length};
      default:
        DecodeError<ValidationTag>(decoder, pc, "Unknown heap type %" PRId64,
                                   heap_index);
        return {HeapType(HeapType::kBottom), length};
    }
  } else {
    uint32_t type_index = static_cast<uint32_t>(heap_index);
    if (!VALIDATE(type_index < kV8MaxWasmTypes)) {
      DecodeError<ValidationTag>(
          decoder, pc,
          "Type index %u is greater than the maximum number %zu "
          "of type definitions supported by V8",
          type_index, kV8MaxWasmTypes);
      return {HeapType(HeapType::kBottom), length};
    }
    return {HeapType(ModuleTypeIndex{type_index}), length};
  }
}

// Read a value type starting at address {pc} using {decoder}.
// No bytes are consumed.
// Returns the read value type and the number of bytes read (a.k.a. length).
template <typename ValidationTag>
std::pair<ValueType, uint32_t> read_value_type(Decoder* decoder,
                                               const uint8_t* pc,
                                               WasmEnabledFeatures enabled) {
  uint8_t val = decoder->read_u8<ValidationTag>(pc, "value type opcode");
  if (!VALIDATE(decoder->ok())) {
    return {kWasmBottom, 0};
  }
  ValueTypeCode code = static_cast<ValueTypeCode>(val);
  switch (code) {
    case kEqRefCode:
    case kI31RefCode:
    case kStructRefCode:
    case kArrayRefCode:
    case kAnyRefCode:
    case kNoneCode:
    case kNoExternCode:
    case kNoFuncCode:
    case kExternRefCode:
    case kFuncRefCode:
      return {ValueType::RefNull(HeapType::from_code(code, false)), 1};
    case kNoExnCode:
    case kExnRefCode:
      if (!VALIDATE(enabled.has_exnref())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid value type '%s', enable with --experimental-wasm-exnref",
            HeapType::from_code(code, false).name().c_str());
        return {kWasmBottom, 0};
      }
      return {code == kExnRefCode ? kWasmExnRef : kWasmNullExnRef, 1};
    case kStringRefCode:
    case kStringViewWtf8Code:
    case kStringViewWtf16Code:
    case kStringViewIterCode: {
      if (!VALIDATE(enabled.has_stringref())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid value type '%sref', enable with "
            "--experimental-wasm-stringref",
            HeapType::from_code(code, false).name().c_str());
        return {kWasmBottom, 0};
      }
      // String views are not nullable, so interpret the shorthand accordingly.
      ValueType type = code == kStringRefCode
                           ? kWasmStringRef
                           : ValueType::Ref(HeapType::from_code(code, false));
      return {type, 1};
    }
    case kI32Code:
      return {kWasmI32, 1};
    case kI64Code:
      return {kWasmI64, 1};
    case kF32Code:
      return {kWasmF32, 1};
    case kF64Code:
      return {kWasmF64, 1};
    case kRefCode:
    case kRefNullCode: {
      Nullability nullability = code == kRefNullCode ? kNullable : kNonNullable;
      auto [heap_type, length] =
          value_type_reader::read_heap_type<ValidationTag>(decoder, pc + 1, enabled);
      if (!VALIDATE(!heap_type.is_string_view() ||
                    nullability == kNonNullable)) {
        DecodeError<ValidationTag>(decoder, pc,
                                   "nullable string views don't exist");
        return {kWasmBottom, 0};
      }
      ValueType type = heap_type.is_bottom()
                           ? kWasmBottom
                           : ValueType::RefMaybeNull(heap_type, nullability);
      return {type, length + 1};
    }
    case kS128Code: {
      if (!VALIDATE(CheckHardwareSupportsSimd())) {
        if (v8_flags.correctness_fuzzer_suppressions) {
          FATAL("Aborting on missing Wasm SIMD support");
        }
        DecodeError<ValidationTag>(decoder, pc, "Wasm SIMD unsupported");
        return {kWasmBottom, 0};
      }
      return {kWasmS128, 1};
    }
    // Although these codes are included in ValueTypeCode, they technically
    // do not correspond to value types and are only used in specific
    // contexts. The caller of this function is responsible for handling them.
    case kVoidCode:
    case kI8Code:
    case kI16Code:
    case kF16Code:
      // Fall through to the error reporting below.
      break;
  }
  // Anything that doesn't match an enumeration value is an invalid type code.
  if constexpr (!ValidationTag::validate) UNREACHABLE();
  DecodeError<ValidationTag>(decoder, pc, "invalid value type 0x%x", code);
  return {kWasmBottom, 0};
}

template <typename ValidationTag>
bool ValidateHeapType(Decoder* decoder, const uint8_t* pc,
                      const WasmModule* module, HeapType type) {
  if (!VALIDATE(!type.is_bottom())) return false;
  if (!type.is_index()) return true;
  // A {nullptr} module is accepted if we are not validating anyway (e.g. for
  // opcode length computation).
  if (!ValidationTag::validate && module == nullptr) return true;
  if (!VALIDATE(type.ref_index().index < module->types.size())) {
    DecodeError<ValidationTag>(decoder, pc, "Type index %u is out of bounds",
                               type.ref_index());
    return false;
  }
  return true;
}

template <typename ValidationTag>
bool ValidateValueType(Decoder* decoder, const uint8_t* pc,
                       const WasmModule* module, ValueType type) {
  if (!VALIDATE(!type.is_bottom())) return false;
  if (V8_LIKELY(!type.is_object_reference())) return true;
  return ValidateHeapType<ValidationTag>(decoder, pc, module, type.heap_type());
}

}  // namespace value_type_reader

enum DecodingMode { kFunctionBody, kConstantExpression };

// Helpers for decoding different kinds of immediates which follow bytecodes.
struct ImmI32Immediate {
  int32_t value;
  uint32_t length;

  template <typename ValidationTag>
  ImmI32Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    std::tie(value, length) = decoder->read_i32v<ValidationTag>(pc, "immi32");
  }
};

struct ImmI64Immediate {
  int64_t value;
  uint32_t length;

  template <typename ValidationTag>
  ImmI64Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    std::tie(value, length) = decoder->read_i64v<ValidationTag>(pc, "immi64");
  }
};

struct ImmF32Immediate {
  float value;
  uint32_t length = 4;

  template <typename ValidationTag>
  ImmF32Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    // We can't use base::bit_cast here because calling any helper function
    // that returns a float would potentially flip NaN bits per C++ semantics,
    // so we have to inline the memcpy call directly.
    uint32_t tmp = decoder->read_u32<ValidationTag>(pc, "immf32");
    memcpy(&value, &tmp, sizeof(value));
  }
};

struct ImmF64Immediate {
  double value;
  uint32_t length = 8;

  template <typename ValidationTag>
  ImmF64Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    // Avoid base::bit_cast because it might not preserve the signalling bit
    // of a NaN.
    uint64_t tmp = decoder->read_u64<ValidationTag>(pc, "immf64");
    memcpy(&value, &tmp, sizeof(value));
  }
};

struct BrOnCastFlags {
  enum Values {
    SRC_IS_NULL = 1,
    RES_IS_NULL = 1 << 1,
  };

  bool src_is_null = false;
  bool res_is_null = false;

  BrOnCastFlags() = default;
  explicit BrOnCastFlags(uint8_t value)
      : src_is_null((value & BrOnCastFlags::SRC_IS_NULL) != 0),
        res_is_null((value & BrOnCastFlags::RES_IS_NULL) != 0) {
    DCHECK_LE(value, BrOnCastFlags::SRC_IS_NULL | BrOnCastFlags::RES_IS_NULL);
  }
};

struct BrOnCastImmediate {
  BrOnCastFlags flags;
  uint8_t raw_value = 0;
  uint32_t length = 1;

  template <typename ValidationTag>
  BrOnCastImmediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    raw_value = decoder->read_u8<ValidationTag>(pc, "br_on_cast flags");
    if (raw_value > (BrOnCastFlags::SRC_IS_NULL | BrOnCastFlags::RES_IS_NULL)) {
      decoder->errorf(pc, "invalid br_on_cast flags %u", raw_value);
      return;
    }
    flags = BrOnCastFlags(raw_value);
  }
};

// Parent class for all Immediates which read a u32v index value in their
// constructor.
struct IndexImmediate {
  uint32_t index;
  uint32_t length;

  template <typename ValidationTag>
  IndexImmediate(Decoder* decoder, const uint8_t* pc, const char* name,
                 ValidationTag = {}) {
    std::tie(index, length) = decoder->read_u32v<ValidationTag>(pc, name);
  }
};

struct MemoryIndexImmediate : public IndexImmediate {
  const WasmMemory* memory = nullptr;

  template <typename ValidationTag>
  MemoryIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "memory index", validate) {}
};

struct TableIndexImmediate : public IndexImmediate {
  const WasmTable* table = nullptr;

  template <typename ValidationTag>
  TableIndexImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "table index", validate) {}
};

struct TagIndexImmediate : public IndexImmediate {
  const WasmTag* tag = nullptr;

  template <typename ValidationTag>
  TagIndexImmediate(Decoder* decoder, const uint8_t* pc,
                    ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "tag index", validate) {}
};

struct GlobalIndexImmediate : public IndexImmediate {
  const WasmGlobal* global = nullptr;

  template <typename ValidationTag>
  GlobalIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "global index", validate) {}
};

struct TypeIndexImmediate {
  ModuleTypeIndex index;
  uint32_t length;

  template <typename ValidationTag>
  TypeIndexImmediate(Decoder* decoder, const uint8_t* pc, const char* name,
                     ValidationTag = {}) {
    uint32_t raw_index;
    std::tie(raw_index, length) = decoder->read_u32v<ValidationTag>(pc, name);
    index = ModuleTypeIndex{raw_index};
  }
};

struct SigIndexImmediate : public TypeIndexImmediate {
  const FunctionSig* sig = nullptr;

  template <typename ValidationTag>
  SigIndexImmediate(Decoder* decoder, const uint8_t* pc,
                    ValidationTag validate = {})
      : TypeIndexImmediate(decoder, pc, "signature index", validate) {}
};

struct StructIndexImmediate : public TypeIndexImmediate {
  const StructType* struct_type = nullptr;

  template <typename ValidationTag>
  StructIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      :
### 提示词
```
这是目录为v8/src/wasm/function-body-decoder-impl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/function-body-decoder-impl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_FUNCTION_BODY_DECODER_IMPL_H_
#define V8_WASM_FUNCTION_BODY_DECODER_IMPL_H_

// Do only include this header for implementing new Interface of the
// WasmFullDecoder.

#include <inttypes.h>

#include <optional>

#include "src/base/bounds.h"
#include "src/base/small-vector.h"
#include "src/base/strings.h"
#include "src/base/vector.h"
#include "src/strings/unicode.h"
#include "src/utils/bit-vector.h"
#include "src/wasm/decoder.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-features.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::wasm {

struct WasmGlobal;
struct WasmTag;

#define TRACE(...)                                        \
  do {                                                    \
    if (v8_flags.trace_wasm_decoder) PrintF(__VA_ARGS__); \
  } while (false)

#define TRACE_INST_FORMAT "  @%-8d #%-30s|"

// Return the evaluation of {condition} if {ValidationTag::validate} is true,
// DCHECK that it is true and always return true otherwise.
// Note that this needs to be a macro, because the "likely" annotation does not
// survive inlining.
#ifdef DEBUG
#define VALIDATE(condition)                       \
  (ValidationTag::validate ? V8_LIKELY(condition) \
                           : ValidateAssumeTrue(condition, #condition))

V8_INLINE bool ValidateAssumeTrue(bool condition, const char* message) {
  DCHECK_WITH_MSG(condition, message);
  return true;
}
#else
#define VALIDATE(condition) (!ValidationTag::validate || V8_LIKELY(condition))
#endif

#define CHECK_PROTOTYPE_OPCODE(feat)                                         \
  DCHECK(this->module_->origin == kWasmOrigin);                              \
  if (!VALIDATE(this->enabled_.has_##feat())) {                              \
    this->DecodeError(                                                       \
        "Invalid opcode 0x%02x (enable with --experimental-wasm-" #feat ")", \
        opcode);                                                             \
    return 0;                                                                \
  }                                                                          \
  this->detected_->add_##feat()

static constexpr LoadType GetLoadType(WasmOpcode opcode) {
  // Hard-code the list of load types. The opcodes are highly unlikely to
  // ever change, and we have some checks here to guard against that.
  static_assert(sizeof(LoadType) == sizeof(uint8_t), "LoadType is compact");
  constexpr uint8_t kMinOpcode = kExprI32LoadMem;
  constexpr uint8_t kMaxOpcode = kExprI64LoadMem32U;
  constexpr LoadType kLoadTypes[] = {
      LoadType::kI32Load,    LoadType::kI64Load,    LoadType::kF32Load,
      LoadType::kF64Load,    LoadType::kI32Load8S,  LoadType::kI32Load8U,
      LoadType::kI32Load16S, LoadType::kI32Load16U, LoadType::kI64Load8S,
      LoadType::kI64Load8U,  LoadType::kI64Load16S, LoadType::kI64Load16U,
      LoadType::kI64Load32S, LoadType::kI64Load32U};
  static_assert(arraysize(kLoadTypes) == kMaxOpcode - kMinOpcode + 1);
  DCHECK_LE(kMinOpcode, opcode);
  DCHECK_GE(kMaxOpcode, opcode);
  return kLoadTypes[opcode - kMinOpcode];
}

static constexpr StoreType GetStoreType(WasmOpcode opcode) {
  // Hard-code the list of store types. The opcodes are highly unlikely to
  // ever change, and we have some checks here to guard against that.
  static_assert(sizeof(StoreType) == sizeof(uint8_t), "StoreType is compact");
  constexpr uint8_t kMinOpcode = kExprI32StoreMem;
  constexpr uint8_t kMaxOpcode = kExprI64StoreMem32;
  constexpr StoreType kStoreTypes[] = {
      StoreType::kI32Store,  StoreType::kI64Store,   StoreType::kF32Store,
      StoreType::kF64Store,  StoreType::kI32Store8,  StoreType::kI32Store16,
      StoreType::kI64Store8, StoreType::kI64Store16, StoreType::kI64Store32};
  static_assert(arraysize(kStoreTypes) == kMaxOpcode - kMinOpcode + 1);
  DCHECK_LE(kMinOpcode, opcode);
  DCHECK_GE(kMaxOpcode, opcode);
  return kStoreTypes[opcode - kMinOpcode];
}

#define ATOMIC_OP_LIST(V)                \
  V(AtomicNotify, Uint32)                \
  V(I32AtomicWait, Uint32)               \
  V(I64AtomicWait, Uint64)               \
  V(I32AtomicLoad, Uint32)               \
  V(I64AtomicLoad, Uint64)               \
  V(I32AtomicLoad8U, Uint8)              \
  V(I32AtomicLoad16U, Uint16)            \
  V(I64AtomicLoad8U, Uint8)              \
  V(I64AtomicLoad16U, Uint16)            \
  V(I64AtomicLoad32U, Uint32)            \
  V(I32AtomicAdd, Uint32)                \
  V(I32AtomicAdd8U, Uint8)               \
  V(I32AtomicAdd16U, Uint16)             \
  V(I64AtomicAdd, Uint64)                \
  V(I64AtomicAdd8U, Uint8)               \
  V(I64AtomicAdd16U, Uint16)             \
  V(I64AtomicAdd32U, Uint32)             \
  V(I32AtomicSub, Uint32)                \
  V(I64AtomicSub, Uint64)                \
  V(I32AtomicSub8U, Uint8)               \
  V(I32AtomicSub16U, Uint16)             \
  V(I64AtomicSub8U, Uint8)               \
  V(I64AtomicSub16U, Uint16)             \
  V(I64AtomicSub32U, Uint32)             \
  V(I32AtomicAnd, Uint32)                \
  V(I64AtomicAnd, Uint64)                \
  V(I32AtomicAnd8U, Uint8)               \
  V(I32AtomicAnd16U, Uint16)             \
  V(I64AtomicAnd8U, Uint8)               \
  V(I64AtomicAnd16U, Uint16)             \
  V(I64AtomicAnd32U, Uint32)             \
  V(I32AtomicOr, Uint32)                 \
  V(I64AtomicOr, Uint64)                 \
  V(I32AtomicOr8U, Uint8)                \
  V(I32AtomicOr16U, Uint16)              \
  V(I64AtomicOr8U, Uint8)                \
  V(I64AtomicOr16U, Uint16)              \
  V(I64AtomicOr32U, Uint32)              \
  V(I32AtomicXor, Uint32)                \
  V(I64AtomicXor, Uint64)                \
  V(I32AtomicXor8U, Uint8)               \
  V(I32AtomicXor16U, Uint16)             \
  V(I64AtomicXor8U, Uint8)               \
  V(I64AtomicXor16U, Uint16)             \
  V(I64AtomicXor32U, Uint32)             \
  V(I32AtomicExchange, Uint32)           \
  V(I64AtomicExchange, Uint64)           \
  V(I32AtomicExchange8U, Uint8)          \
  V(I32AtomicExchange16U, Uint16)        \
  V(I64AtomicExchange8U, Uint8)          \
  V(I64AtomicExchange16U, Uint16)        \
  V(I64AtomicExchange32U, Uint32)        \
  V(I32AtomicCompareExchange, Uint32)    \
  V(I64AtomicCompareExchange, Uint64)    \
  V(I32AtomicCompareExchange8U, Uint8)   \
  V(I32AtomicCompareExchange16U, Uint16) \
  V(I64AtomicCompareExchange8U, Uint8)   \
  V(I64AtomicCompareExchange16U, Uint16) \
  V(I64AtomicCompareExchange32U, Uint32)

#define ATOMIC_STORE_OP_LIST(V) \
  V(I32AtomicStore, Uint32)     \
  V(I64AtomicStore, Uint64)     \
  V(I32AtomicStore8U, Uint8)    \
  V(I32AtomicStore16U, Uint16)  \
  V(I64AtomicStore8U, Uint8)    \
  V(I64AtomicStore16U, Uint16)  \
  V(I64AtomicStore32U, Uint32)

// Decoder error with explicit PC and optional format arguments.
// Depending on the validation tag and the number of arguments, this forwards to
// a V8_NOINLINE and V8_PRESERVE_MOST method of the decoder.
template <typename ValidationTag, typename... Args>
V8_INLINE void DecodeError(Decoder* decoder, const uint8_t* pc, const char* str,
                           Args&&... args) {
  // Decode errors can only happen if we are validating; the compiler should
  // know this e.g. from the VALIDATE macro, but this assumption tells it again
  // that this path is impossible.
  V8_ASSUME(ValidationTag::validate);
  if constexpr (sizeof...(Args) == 0) {
    decoder->error(pc, str);
  } else {
    decoder->errorf(pc, str, std::forward<Args>(args)...);
  }
}

// Decoder error without explicit PC and with optional format arguments.
// Depending on the validation tag and the number of arguments, this forwards to
// a V8_NOINLINE and V8_PRESERVE_MOST method of the decoder.
template <typename ValidationTag, typename... Args>
V8_INLINE void DecodeError(Decoder* decoder, const char* str, Args&&... args) {
  // Decode errors can only happen if we are validating; the compiler should
  // know this e.g. from the VALIDATE macro, but this assumption tells it again
  // that this path is impossible.
  V8_ASSUME(ValidationTag::validate);
  if constexpr (sizeof...(Args) == 0) {
    decoder->error(str);
  } else {
    decoder->errorf(str, std::forward<Args>(args)...);
  }
}

namespace value_type_reader {

template <typename ValidationTag>
std::pair<HeapType, uint32_t> read_heap_type(Decoder* decoder,
                                             const uint8_t* pc,
                                             WasmEnabledFeatures enabled) {
  auto [heap_index, length] =
      decoder->read_i33v<ValidationTag>(pc, "heap type");
  if (heap_index < 0) {
    int64_t min_1_byte_leb128 = -64;
    if (!VALIDATE(heap_index >= min_1_byte_leb128)) {
      DecodeError<ValidationTag>(decoder, pc, "Unknown heap type %" PRId64,
                                 heap_index);
      return {HeapType(HeapType::kBottom), length};
    }
    uint8_t uint_7_mask = 0x7F;
    uint8_t code = static_cast<ValueTypeCode>(heap_index) & uint_7_mask;
    bool is_shared = false;
    if (code == kSharedFlagCode) {
      if (!VALIDATE(enabled.has_shared())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid heap type 0x%x, enable with --experimental-wasm-shared",
            kSharedFlagCode);
        return {HeapType(HeapType::kBottom), length};
      }
      code = decoder->read_u8<ValidationTag>(pc + length, "heap type");
      length++;
      is_shared = true;
    }
    switch (code) {
      case kEqRefCode:
      case kI31RefCode:
      case kStructRefCode:
      case kArrayRefCode:
      case kAnyRefCode:
      case kNoneCode:
      case kNoExternCode:
      case kNoFuncCode:
      case kExternRefCode:
      case kFuncRefCode:
        return {HeapType::from_code(code, is_shared), length};
      case kNoExnCode:
      case kExnRefCode:
        if (!VALIDATE(enabled.has_exnref())) {
          DecodeError<ValidationTag>(
              decoder, pc,
              "invalid heap type '%s', enable with --experimental-wasm-exnref",
              HeapType::from_code(code, is_shared).name().c_str());
        }
        return {HeapType::from_code(code, is_shared), length};
      case kStringRefCode:
      case kStringViewWtf8Code:
      case kStringViewWtf16Code:
      case kStringViewIterCode:
        if (!VALIDATE(enabled.has_stringref())) {
          DecodeError<ValidationTag>(
              decoder, pc,
              "invalid heap type '%s', enable with "
              "--experimental-wasm-stringref",
              HeapType::from_code(code, is_shared).name().c_str());
        }
        return {HeapType::from_code(code, is_shared), length};
      default:
        DecodeError<ValidationTag>(decoder, pc, "Unknown heap type %" PRId64,
                                   heap_index);
        return {HeapType(HeapType::kBottom), length};
    }
  } else {
    uint32_t type_index = static_cast<uint32_t>(heap_index);
    if (!VALIDATE(type_index < kV8MaxWasmTypes)) {
      DecodeError<ValidationTag>(
          decoder, pc,
          "Type index %u is greater than the maximum number %zu "
          "of type definitions supported by V8",
          type_index, kV8MaxWasmTypes);
      return {HeapType(HeapType::kBottom), length};
    }
    return {HeapType(ModuleTypeIndex{type_index}), length};
  }
}

// Read a value type starting at address {pc} using {decoder}.
// No bytes are consumed.
// Returns the read value type and the number of bytes read (a.k.a. length).
template <typename ValidationTag>
std::pair<ValueType, uint32_t> read_value_type(Decoder* decoder,
                                               const uint8_t* pc,
                                               WasmEnabledFeatures enabled) {
  uint8_t val = decoder->read_u8<ValidationTag>(pc, "value type opcode");
  if (!VALIDATE(decoder->ok())) {
    return {kWasmBottom, 0};
  }
  ValueTypeCode code = static_cast<ValueTypeCode>(val);
  switch (code) {
    case kEqRefCode:
    case kI31RefCode:
    case kStructRefCode:
    case kArrayRefCode:
    case kAnyRefCode:
    case kNoneCode:
    case kNoExternCode:
    case kNoFuncCode:
    case kExternRefCode:
    case kFuncRefCode:
      return {ValueType::RefNull(HeapType::from_code(code, false)), 1};
    case kNoExnCode:
    case kExnRefCode:
      if (!VALIDATE(enabled.has_exnref())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid value type '%s', enable with --experimental-wasm-exnref",
            HeapType::from_code(code, false).name().c_str());
        return {kWasmBottom, 0};
      }
      return {code == kExnRefCode ? kWasmExnRef : kWasmNullExnRef, 1};
    case kStringRefCode:
    case kStringViewWtf8Code:
    case kStringViewWtf16Code:
    case kStringViewIterCode: {
      if (!VALIDATE(enabled.has_stringref())) {
        DecodeError<ValidationTag>(
            decoder, pc,
            "invalid value type '%sref', enable with "
            "--experimental-wasm-stringref",
            HeapType::from_code(code, false).name().c_str());
        return {kWasmBottom, 0};
      }
      // String views are not nullable, so interpret the shorthand accordingly.
      ValueType type = code == kStringRefCode
                           ? kWasmStringRef
                           : ValueType::Ref(HeapType::from_code(code, false));
      return {type, 1};
    }
    case kI32Code:
      return {kWasmI32, 1};
    case kI64Code:
      return {kWasmI64, 1};
    case kF32Code:
      return {kWasmF32, 1};
    case kF64Code:
      return {kWasmF64, 1};
    case kRefCode:
    case kRefNullCode: {
      Nullability nullability = code == kRefNullCode ? kNullable : kNonNullable;
      auto [heap_type, length] =
          read_heap_type<ValidationTag>(decoder, pc + 1, enabled);
      if (!VALIDATE(!heap_type.is_string_view() ||
                    nullability == kNonNullable)) {
        DecodeError<ValidationTag>(decoder, pc,
                                   "nullable string views don't exist");
        return {kWasmBottom, 0};
      }
      ValueType type = heap_type.is_bottom()
                           ? kWasmBottom
                           : ValueType::RefMaybeNull(heap_type, nullability);
      return {type, length + 1};
    }
    case kS128Code: {
      if (!VALIDATE(CheckHardwareSupportsSimd())) {
        if (v8_flags.correctness_fuzzer_suppressions) {
          FATAL("Aborting on missing Wasm SIMD support");
        }
        DecodeError<ValidationTag>(decoder, pc, "Wasm SIMD unsupported");
        return {kWasmBottom, 0};
      }
      return {kWasmS128, 1};
    }
    // Although these codes are included in ValueTypeCode, they technically
    // do not correspond to value types and are only used in specific
    // contexts. The caller of this function is responsible for handling them.
    case kVoidCode:
    case kI8Code:
    case kI16Code:
    case kF16Code:
      // Fall through to the error reporting below.
      break;
  }
  // Anything that doesn't match an enumeration value is an invalid type code.
  if constexpr (!ValidationTag::validate) UNREACHABLE();
  DecodeError<ValidationTag>(decoder, pc, "invalid value type 0x%x", code);
  return {kWasmBottom, 0};
}

template <typename ValidationTag>
bool ValidateHeapType(Decoder* decoder, const uint8_t* pc,
                      const WasmModule* module, HeapType type) {
  if (!VALIDATE(!type.is_bottom())) return false;
  if (!type.is_index()) return true;
  // A {nullptr} module is accepted if we are not validating anyway (e.g. for
  // opcode length computation).
  if (!ValidationTag::validate && module == nullptr) return true;
  if (!VALIDATE(type.ref_index().index < module->types.size())) {
    DecodeError<ValidationTag>(decoder, pc, "Type index %u is out of bounds",
                               type.ref_index());
    return false;
  }
  return true;
}

template <typename ValidationTag>
bool ValidateValueType(Decoder* decoder, const uint8_t* pc,
                       const WasmModule* module, ValueType type) {
  if (!VALIDATE(!type.is_bottom())) return false;
  if (V8_LIKELY(!type.is_object_reference())) return true;
  return ValidateHeapType<ValidationTag>(decoder, pc, module, type.heap_type());
}

}  // namespace value_type_reader

enum DecodingMode { kFunctionBody, kConstantExpression };

// Helpers for decoding different kinds of immediates which follow bytecodes.
struct ImmI32Immediate {
  int32_t value;
  uint32_t length;

  template <typename ValidationTag>
  ImmI32Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    std::tie(value, length) = decoder->read_i32v<ValidationTag>(pc, "immi32");
  }
};

struct ImmI64Immediate {
  int64_t value;
  uint32_t length;

  template <typename ValidationTag>
  ImmI64Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    std::tie(value, length) = decoder->read_i64v<ValidationTag>(pc, "immi64");
  }
};

struct ImmF32Immediate {
  float value;
  uint32_t length = 4;

  template <typename ValidationTag>
  ImmF32Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    // We can't use base::bit_cast here because calling any helper function
    // that returns a float would potentially flip NaN bits per C++ semantics,
    // so we have to inline the memcpy call directly.
    uint32_t tmp = decoder->read_u32<ValidationTag>(pc, "immf32");
    memcpy(&value, &tmp, sizeof(value));
  }
};

struct ImmF64Immediate {
  double value;
  uint32_t length = 8;

  template <typename ValidationTag>
  ImmF64Immediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    // Avoid base::bit_cast because it might not preserve the signalling bit
    // of a NaN.
    uint64_t tmp = decoder->read_u64<ValidationTag>(pc, "immf64");
    memcpy(&value, &tmp, sizeof(value));
  }
};

struct BrOnCastFlags {
  enum Values {
    SRC_IS_NULL = 1,
    RES_IS_NULL = 1 << 1,
  };

  bool src_is_null = false;
  bool res_is_null = false;

  BrOnCastFlags() = default;
  explicit BrOnCastFlags(uint8_t value)
      : src_is_null((value & BrOnCastFlags::SRC_IS_NULL) != 0),
        res_is_null((value & BrOnCastFlags::RES_IS_NULL) != 0) {
    DCHECK_LE(value, BrOnCastFlags::SRC_IS_NULL | BrOnCastFlags::RES_IS_NULL);
  }
};

struct BrOnCastImmediate {
  BrOnCastFlags flags;
  uint8_t raw_value = 0;
  uint32_t length = 1;

  template <typename ValidationTag>
  BrOnCastImmediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    raw_value = decoder->read_u8<ValidationTag>(pc, "br_on_cast flags");
    if (raw_value > (BrOnCastFlags::SRC_IS_NULL | BrOnCastFlags::RES_IS_NULL)) {
      decoder->errorf(pc, "invalid br_on_cast flags %u", raw_value);
      return;
    }
    flags = BrOnCastFlags(raw_value);
  }
};

// Parent class for all Immediates which read a u32v index value in their
// constructor.
struct IndexImmediate {
  uint32_t index;
  uint32_t length;

  template <typename ValidationTag>
  IndexImmediate(Decoder* decoder, const uint8_t* pc, const char* name,
                 ValidationTag = {}) {
    std::tie(index, length) = decoder->read_u32v<ValidationTag>(pc, name);
  }
};

struct MemoryIndexImmediate : public IndexImmediate {
  const WasmMemory* memory = nullptr;

  template <typename ValidationTag>
  MemoryIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "memory index", validate) {}
};

struct TableIndexImmediate : public IndexImmediate {
  const WasmTable* table = nullptr;

  template <typename ValidationTag>
  TableIndexImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "table index", validate) {}
};

struct TagIndexImmediate : public IndexImmediate {
  const WasmTag* tag = nullptr;

  template <typename ValidationTag>
  TagIndexImmediate(Decoder* decoder, const uint8_t* pc,
                    ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "tag index", validate) {}
};

struct GlobalIndexImmediate : public IndexImmediate {
  const WasmGlobal* global = nullptr;

  template <typename ValidationTag>
  GlobalIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "global index", validate) {}
};

struct TypeIndexImmediate {
  ModuleTypeIndex index;
  uint32_t length;

  template <typename ValidationTag>
  TypeIndexImmediate(Decoder* decoder, const uint8_t* pc, const char* name,
                     ValidationTag = {}) {
    uint32_t raw_index;
    std::tie(raw_index, length) = decoder->read_u32v<ValidationTag>(pc, name);
    index = ModuleTypeIndex{raw_index};
  }
};

struct SigIndexImmediate : public TypeIndexImmediate {
  const FunctionSig* sig = nullptr;

  template <typename ValidationTag>
  SigIndexImmediate(Decoder* decoder, const uint8_t* pc,
                    ValidationTag validate = {})
      : TypeIndexImmediate(decoder, pc, "signature index", validate) {}
};

struct StructIndexImmediate : public TypeIndexImmediate {
  const StructType* struct_type = nullptr;

  template <typename ValidationTag>
  StructIndexImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag validate = {})
      : TypeIndexImmediate(decoder, pc, "struct index", validate) {}
};

struct ArrayIndexImmediate : public TypeIndexImmediate {
  const ArrayType* array_type = nullptr;

  template <typename ValidationTag>
  ArrayIndexImmediate(Decoder* decoder, const uint8_t* pc,
                      ValidationTag validate = {})
      : TypeIndexImmediate(decoder, pc, "array index", validate) {}
};

struct CallFunctionImmediate : public IndexImmediate {
  const FunctionSig* sig = nullptr;

  template <typename ValidationTag>
  CallFunctionImmediate(Decoder* decoder, const uint8_t* pc,
                        ValidationTag validate = {})
      : IndexImmediate(decoder, pc, "function index", validate) {}
};

struct SelectTypeImmediate {
  uint32_t length;
  ValueType type;

  template <typename ValidationTag>
  SelectTypeImmediate(WasmEnabledFeatures enabled, Decoder* decoder,
                      const uint8_t* pc, ValidationTag = {}) {
    uint8_t num_types;
    std::tie(num_types, length) =
        decoder->read_u32v<ValidationTag>(pc, "number of select types");
    if (!VALIDATE(num_types == 1)) {
      DecodeError<ValidationTag>(
          decoder, pc,
          "Invalid number of types. Select accepts exactly one type");
      return;
    }
    uint32_t type_length;
    std::tie(type, type_length) =
        value_type_reader::read_value_type<ValidationTag>(decoder, pc + length,
                                                          enabled);
    length += type_length;
  }
};

struct BlockTypeImmediate {
  uint32_t length = 1;
  // After decoding, either {sig_index} is set XOR {sig} points to
  // {single_return_sig_storage}.
  ModuleTypeIndex sig_index = ModuleTypeIndex::Invalid();
  FunctionSig sig{0, 0, single_return_sig_storage};
  // Internal field, potentially pointed to by {sig}. Do not access directly.
  ValueType single_return_sig_storage[1];

  // Do not copy or move, as {sig} might point to {single_return_sig_storage} so
  // this cannot trivially be copied. If needed, define those operators later.
  BlockTypeImmediate(const BlockTypeImmediate&) = delete;
  BlockTypeImmediate(BlockTypeImmediate&&) = delete;
  BlockTypeImmediate& operator=(const BlockTypeImmediate&) = delete;
  BlockTypeImmediate& operator=(BlockTypeImmediate&&) = delete;

  template <typename ValidationTag>
  BlockTypeImmediate(WasmEnabledFeatures enabled, Decoder* decoder,
                     const uint8_t* pc, ValidationTag = {}) {
    int64_t block_type;
    std::tie(block_type, length) =
        decoder->read_i33v<ValidationTag>(pc, "block type");
    if (block_type < 0) {
      // All valid negative types are 1 byte in length, so we check against the
      // minimum 1-byte LEB128 value.
      constexpr int64_t min_1_byte_leb128 = -64;
      if (!VALIDATE(block_type >= min_1_byte_leb128)) {
        DecodeError<ValidationTag>(decoder, pc, "invalid block type %" PRId64,
                                   block_type);
        return;
      }
      if (static_cast<ValueTypeCode>(block_type & 0x7F) != kVoidCode) {
        sig = FunctionSig{1, 0, single_return_sig_storage};
        std::tie(single_return_sig_storage[0], length) =
            value_type_reader::read_value_type<ValidationTag>(decoder, pc,
                                                              enabled);
      }
    } else {
      sig = FunctionSig{0, 0, nullptr};
      sig_index = ModuleTypeIndex{static_cast<uint32_t>(block_type)};
    }
  }

  uint32_t in_arity() const {
    return static_cast<uint32_t>(sig.parameter_count());
  }
  uint32_t out_arity() const {
    return static_cast<uint32_t>(sig.return_count());
  }
  ValueType in_type(uint32_t index) const { return sig.GetParam(index); }
  ValueType out_type(uint32_t index) const { return sig.GetReturn(index); }
};

struct BranchDepthImmediate {
  uint32_t depth;
  uint32_t length;

  template <typename ValidationTag>
  BranchDepthImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag = {}) {
    std::tie(depth, length) =
        decoder->read_u32v<ValidationTag>(pc, "branch depth");
  }
};

struct FieldImmediate {
  StructIndexImmediate struct_imm;
  IndexImmediate field_imm;
  uint32_t length;

  template <typename ValidationTag>
  FieldImmediate(Decoder* decoder, const uint8_t* pc,
                 ValidationTag validate = {})
      : struct_imm(decoder, pc, validate),
        field_imm(decoder, pc + struct_imm.length, "field index", validate),
        length(struct_imm.length + field_imm.length) {}
};

struct CallIndirectImmediate {
  SigIndexImmediate sig_imm;
  TableIndexImmediate table_imm;
  uint32_t length;
  const FunctionSig* sig = nullptr;

  template <typename ValidationTag>
  CallIndirectImmediate(Decoder* decoder, const uint8_t* pc,
                        ValidationTag validate = {})
      : sig_imm(decoder, pc, validate),
        table_imm(decoder, pc + sig_imm.length, validate),
        length(sig_imm.length + table_imm.length) {}
};

struct BranchTableImmediate {
  uint32_t table_count;
  const uint8_t* start;
  const uint8_t* table;

  template <typename ValidationTag>
  BranchTableImmediate(Decoder* decoder, const uint8_t* pc,
                       ValidationTag = {}) {
    start = pc;
    uint32_t len;
    std::tie(table_count, len) =
        decoder->read_u32v<ValidationTag>(pc, "table count");
    table = pc + len;
  }
};

using TryTableImmediate = BranchTableImmediate;

// A helper to iterate over a branch table.
template <typename ValidationTag>
class BranchTableIterator {
 public:
  uint32_t cur_index() const { return index_; }
  bool has_next() const {
    return VALIDATE(decoder_->ok()) && index_ <= table_count_;
  }
  uint32_t next() {
    DCHECK(has_next());
    index_++;
    auto [result, length] =
        decoder_->read_u32v<ValidationTag>(pc_, "branch table entry");
    pc_ += length;
    return result;
  }
  // length, including the length of the {BranchTableImmediate}, but not the
  // opcode. This consumes the table entries, so it is invalid to call next()
  // before or after this method.
  uint32_t length() {
    while (has_next()) next();
    return static_cast<uint32_t>(pc_ - start_);
  }
  const uint8_t* pc() const { return pc_; }

  BranchTableIterator(Decoder* decoder, const BranchTableImmediate& imm)
      : decoder_(decoder),
        start_(imm.start),
        pc_(imm.table),
        table_count_(imm.table_count) {}

 private:
  Decoder* const decoder_;
  const uint8_t* const start_;
  const uint8_t* pc_;
  uint32_t index_ = 0;          // the current index.
  const uint32_t table_count_;  // the count of entries, not including default.
};

struct CatchCase {
  CatchKind kind;
  // The union contains a TagIndexImmediate iff kind == kCatch or kind ==
  // kCatchRef.
  union MaybeTagIndex {
    uint8_t empty;
    TagIndexImmediate tag_imm;
  } maybe_tag;
  BranchDepthImmediate br_imm;
};

// A helper to iterate over a try table.
template <typename ValidationTag>
class TryTableIterator {
 public:
  uint32_t cur_index() const { return index_; }
  bool has_next() const {
    return VALIDATE(decoder_->ok()) && index_ < table_count_;
  }

  CatchCase next() {
    uint8_t kind =
        static_cast<CatchKind>(decoder_->read_u8<ValidationTag>(pc_));
    pc_ += 1;
    CatchCase::MaybeTagIndex maybe_tag{0};
    if (kind == kCatch || kind == kCatchRef) {
      maybe_tag.tag_imm = TagIndexImmediate(decoder_, pc_, ValidationTag{});
      pc_ += maybe_tag.tag_imm.length;
    }
    BranchDepthImmediate br_imm(decoder_, pc_, ValidationTag{});
    pc_ += br_imm.length;
    index_++;
    return CatchCase{static_cast<CatchKind>(kind), maybe_tag, br_imm};
  }

  // length, including the length of the {TryTableImmediate}, but not the
  // opcode. This consumes the table entries, so it is invalid to call next()
  // before or after this method.
  uint32_t length() {
    while (has_next()) next();
    return static_cast<uint32_t>(pc_ - start_);
  }
  const uint8_t* pc() const { return pc_; }

  TryTableIterator(Decoder* decoder, const TryTableImmediate& imm)
      : decoder_(decoder),
        start_(imm.start),
        pc_(imm.table),
        table_count_(imm.table_count) {}

 private:
  Decoder* const decoder_;
  const uint8_t* const start_;
  const uint8_t* pc_;
  uint32_t index_ = 0;          // the current index.
  const uint32_t table_count_;  // the count of entries, not including default.
};

struct MemoryAccessImmediate {
  uint32_t alignment;
  uint32_t mem_index;
  uint64_t offset;
  const WasmMemory* memory = nullptr;

  uint32_t length;

  template <typename ValidationTag>
  V8_INLINE MemoryAccessImmediate(Decoder* decoder, const uint8_t* pc,
                                  uint32_t max_alignment, bool memory64_enabled,
                                  ValidationTag = {}) {
    // Check for the fast path (two single-byte LEBs, mem index 0).
    const bool two_bytes = !ValidationTag::validate || decoder->end() - pc >= 2;
    const bool use_fast_path = two_bytes && !(pc[0] & 0xc0) && !(pc[1] & 0x80);
    if (V8_LIKELY(use_fast_path)) {
      alignment = pc[0];
      mem_index = 0;
      offset = pc[1];
      length = 2;
    } else {
      ConstructSlow<ValidationTag>(decoder, pc, max_alignment,
                                   memory64_enabled);
    }
    if (!VALIDATE(alignment <= max_alignment)) {
      DecodeError<ValidationTag>(
          decoder, pc,
          "invalid alignment; expected maximum alignment is %u, "
          "actual alignment is %u",
          max_alignment, alignment);
    }
  }

 private:
  template <typename ValidationTag>
  V8_NOINLINE V8_PRESERVE_MOST void ConstructSlow(Decoder* decoder,
                                                  const uint8_t* pc,
                                                  uint32_t max_alignment,
                                                  bool memory64_enabled) {
    uint32_t alignment_length;
    std::tie(alignment, alignment_length) =
        decoder->read_u32v<ValidationTag>(pc, "alignment");
    length = alignment_length;
    if (alignment & 0x40) {
      alignment &= ~0x40;
      uint32_t mem_index_length;
      std::tie(mem_index, mem_index_length) =
          decoder->read_u32v<ValidationTag>(pc + length, "memory index");
      length += mem_index_length;
    } else {
      mem_index = 0;
    }
    uint32_t offset_length;
    if (memory64_enabled) {
      std::tie(offset, offset_length) =
          decoder->read_u64v<ValidationTag>(pc + length, "offset");
    } else {
      std::tie(offset, offset_length) =
          decoder->read_u32v<ValidationTag>(pc + length, "offset");
    }
    length += offset_length;
  }
};

// Immediate for SIMD lane operations.
struct SimdLaneImmediate {
  uint8_t lane;
  uint32_t length = 1;

  template <typename ValidationTag>
  SimdLaneImmediate(Decoder* decoder, const uint8_t* pc, ValidationTag = {}) {
    lane = decoder->read_u8<ValidationTag>(pc, "lane");
  }
};

// Immediate for SIMD S8x16 shuffle operations.
struct Simd128Immediat
```
Response: The user wants a summary of the C++ code in `v8/src/wasm/fuzzing/random-module-generation.cc`.
The code seems to be involved in generating random WebAssembly modules for fuzzing purposes.
It defines various constraints and structures to guide the generation process.
It also includes a `BodyGen` class, which likely handles the generation of function bodies with random instructions and data.

**Plan:**

1. Identify the main purpose of the file.
2. List the key data structures and their roles.
3. Summarize the functionality of the `BodyGen` class.
4. Check for any obvious relationships with JavaScript.
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的C++源代码文件的前半部分。它的主要功能是**生成随机的WebAssembly模块**，用于进行模糊测试。

该文件定义了各种常量和结构体，用于控制生成的WebAssembly模块的特征，例如：

* **最大数量限制**:  `kMaxArrays`, `kMaxStructs`, `kMaxFunctions`, `kMaxGlobals` 等，限制了生成的模块中各种元素的数量。
* **类型和大小限制**: `kMaxStructFields`, `kMaxLocals`, `kMaxParameters`, `kMaxReturns`, `kMaxArraySize` 等，限制了类型定义和大小。
* **其他限制**: `kMaxRecursionDepth`, `kMaxCatchCases` 等，限制了代码的复杂程度。
* **`StringImports` 结构体**: 存储了一些用于字符串操作的导入函数的索引，以及一些相关的类型索引。这暗示了生成的模块可能会涉及到字符串操作，并且依赖于某些预定义的导入函数。
* **`DataRange` 类**:  用于管理和分配随机数据，包括从输入数据中获取以及生成伪随机数。它负责为模块的各个部分提供随机内容。
* **`GetValueTypeHelper` 和 `GetValueType` 函数模板**:  用于随机选择 WebAssembly 的值类型，包括基本数值类型、引用类型（包括可空和非可空）、以及用户定义的类型。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身是用 C++ 编写的，但它生成的 WebAssembly 模块最终会在 JavaScript 虚拟机（例如 V8）中执行。 该文件通过随机生成各种 WebAssembly 结构和指令，来测试 JavaScript 虚拟机在处理各种合法的和可能包含边界情况的 WebAssembly 代码时的健壮性。

**JavaScript 示例说明:**

假设这个 C++ 代码生成了一个包含字符串操作的 WebAssembly 模块，这个模块可能导入了一些用于字符串操作的函数。 在 JavaScript 中，我们可以加载并实例化这个生成的 WebAssembly 模块，并调用其中定义的函数。

例如，如果生成的 WebAssembly 模块导入了一个名为 `fromCharCode` 的函数，我们可以这样使用：

```javascript
async function runWasm() {
  // 假设 fetchWasmModule 是一个获取生成的 wasm 模块二进制数据的函数
  const wasmModuleBytes = await fetchWasmModule();
  const wasmModule = await WebAssembly.compile(wasmModuleBytes);

  // 假设生成的 wasm 模块需要一些导入，包括来自 "env" 模块的函数
  const importObject = {
    env: {
      // 这里假设 'stringImports.fromCharCode' 对应 wasm 模块中 "env" 模块下的 fromCharCode 函数
      fromCharCode: function(charCode) {
        return String.fromCharCode(charCode);
      },
      // ... 其他导入函数 ...
    }
  };

  const wasmInstance = await WebAssembly.instantiate(wasmModule, importObject);

  // 假设生成的 wasm 模块中有一个名为 'myStringFunction' 的导出函数，它使用了导入的 fromCharCode
  if (wasmInstance.exports.myStringFunction) {
    const result = wasmInstance.exports.myStringFunction();
    console.log("Wasm 函数返回的字符串:", result);
  }
}

runWasm();
```

在这个例子中，`fetchWasmModule` 函数会获取由 C++ 代码生成的随机 WebAssembly 模块的二进制数据。`importObject` 定义了 WebAssembly 模块导入的函数，其中就包含了模拟 `String.fromCharCode` 的 JavaScript 函数。  当 WebAssembly 模块中的代码调用导入的 `fromCharCode` 函数时，实际上会执行 JavaScript 中提供的实现。 这展示了生成的 WebAssembly 模块如何与 JavaScript 环境进行交互。

总而言之，这个 C++ 文件的功能是为 V8 引擎的模糊测试框架 **生成具有随机结构的 WebAssembly 模块**，这些模块旨在测试 V8 在处理各种 WebAssembly 代码时的正确性和健壮性。它通过定义各种约束和使用随机数据来生成这些模块，并且生成的模块最终会在 JavaScript 环境中运行。

Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/wasm/fuzzing/random-module-generation.h"

#include <algorithm>
#include <array>
#include <optional>

#include "src/base/small-vector.h"
#include "src/base/utils/random-number-generator.h"
#include "src/wasm/function-body-decoder.h"
#include "src/wasm/wasm-module-builder.h"
#include "src/wasm/wasm-module.h"
#include "src/wasm/wasm-opcodes-inl.h"

// This whole compilation unit should only be included in non-official builds to
// reduce binary size (it's a testing-only implementation which lives in src/ so
// that the GenerateRandomWasmModule runtime function can use it).  We normally
// disable V8_WASM_RANDOM_FUZZERS in official builds.
#ifndef V8_WASM_RANDOM_FUZZERS
#error Exclude this compilation unit in official builds.
#endif

namespace v8::internal::wasm::fuzzing {

namespace {

constexpr int kMaxArrays = 3;
constexpr int kMaxStructs = 4;
constexpr int kMaxStructFields = 4;
constexpr int kMaxFunctions = 4;
constexpr int kMaxGlobals = 64;
constexpr uint32_t kMaxLocals = 32;
constexpr int kMaxParameters = 15;
constexpr int kMaxReturns = 15;
constexpr int kMaxExceptions = 4;
constexpr int kMaxTableSize = 32;
constexpr int kMaxTables = 4;
constexpr int kMaxMemories = 4;
constexpr int kMaxArraySize = 20;
constexpr int kMaxPassiveDataSegments = 2;
constexpr uint32_t kMaxRecursionDepth = 64;
constexpr int kMaxCatchCases = 6;

struct StringImports {
  uint32_t cast;
  uint32_t test;
  uint32_t fromCharCode;
  uint32_t fromCodePoint;
  uint32_t charCodeAt;
  uint32_t codePointAt;
  uint32_t length;
  uint32_t concat;
  uint32_t substring;
  uint32_t equals;
  uint32_t compare;
  uint32_t fromCharCodeArray;
  uint32_t intoCharCodeArray;
  uint32_t measureStringAsUTF8;
  uint32_t encodeStringIntoUTF8Array;
  uint32_t encodeStringToUTF8Array;
  uint32_t decodeStringFromUTF8Array;

  // These aren't imports, but closely related, so store them here as well:
  ModuleTypeIndex array_i16;
  ModuleTypeIndex array_i8;
};

// Creates an array out of the arguments without hardcoding the exact number of
// arguments.
template <typename... T>
constexpr auto CreateArray(T... elements) {
  std::array result = {elements...};
  return result;
}

// Concatenate arrays into one array in compile-time.
template <typename T, size_t... N>
constexpr auto ConcatArrays(std::array<T, N>... array) {
  constexpr size_t kNumArrays = sizeof...(array);
  std::array<T*, kNumArrays> kArrays = {&array[0]...};
  constexpr size_t kLengths[kNumArrays] = {array.size()...};
  constexpr size_t kSumOfLengths = (... + array.size());

  std::array<T, kSumOfLengths> result = {0};
  size_t result_index = 0;
  for (size_t arr = 0; arr < kNumArrays; arr++) {
    for (size_t pos = 0; pos < kLengths[arr]; pos++) {
      result[result_index++] = kArrays[arr][pos];
    }
  }
  return result;
}

template <bool predicate, typename T, size_t kSize1, size_t kSize2>
constexpr auto AppendArrayIf(std::array<T, kSize1> array1,
                             std::array<T, kSize2> array2) {
  if constexpr (!predicate) {
    return array1;
  } else {
    return ConcatArrays(array1, array2);
  }
}

class DataRange {
  // data_ is used for general random values for fuzzing.
  base::Vector<const uint8_t> data_;
  // The RNG is used for generating random values (i32.consts etc.) for which
  // the quality of the input is less important.
  base::RandomNumberGenerator rng_;

 public:
  explicit DataRange(base::Vector<const uint8_t> data, int64_t seed = -1)
      : data_(data), rng_(seed == -1 ? get<int64_t>() : seed) {}
  DataRange(const DataRange&) = delete;
  DataRange& operator=(const DataRange&) = delete;

  // Don't accidentally pass DataRange by value. This will reuse bytes and might
  // lead to OOM because the end might not be reached.
  // Define move constructor and move assignment, disallow copy constructor and
  // copy assignment (below).
  DataRange(DataRange&& other) V8_NOEXCEPT : data_(other.data_),
                                             rng_(other.rng_) {
    other.data_ = {};
  }
  DataRange& operator=(DataRange&& other) V8_NOEXCEPT {
    data_ = other.data_;
    rng_ = other.rng_;
    other.data_ = {};
    return *this;
  }

  size_t size() const { return data_.size(); }

  DataRange split() {
    // As we might split many times, only use 2 bytes if the data size is large.
    uint16_t random_choice = data_.size() > std::numeric_limits<uint8_t>::max()
                                 ? get<uint16_t>()
                                 : get<uint8_t>();
    uint16_t num_bytes = random_choice % std::max(size_t{1}, data_.size());
    int64_t new_seed = rng_.initial_seed() ^ rng_.NextInt64();
    DataRange split(data_.SubVector(0, num_bytes), new_seed);
    data_ += num_bytes;
    return split;
  }

  template <typename T, size_t max_bytes = sizeof(T)>
  T getPseudoRandom() {
    static_assert(!std::is_same<T, bool>::value, "bool needs special handling");
    static_assert(max_bytes <= sizeof(T));
    // Special handling for signed integers: Calling getPseudoRandom<int32_t, 1>
    // () should be equal to getPseudoRandom<int8_t>(). (The NextBytes() below
    // does not achieve that due to depending on endianness and either never
    // generating negative values or filling in the highest significant bits
    // which would be unexpected).
    if constexpr (std::is_integral_v<T> && std::is_signed_v<T>) {
      switch (max_bytes) {
        case 1:
          return static_cast<int8_t>(getPseudoRandom<uint8_t>());
        case 2:
          return static_cast<int16_t>(getPseudoRandom<uint16_t>());
        case 4:
          return static_cast<int32_t>(getPseudoRandom<uint32_t>());
        default:
          return static_cast<T>(
              getPseudoRandom<std::make_unsigned_t<T>, max_bytes>());
      }
    }

    T result{};
    rng_.NextBytes(&result, max_bytes);
    return result;
  }

  template <typename T>
  T get() {
    // Bool needs special handling (see template specialization below).
    static_assert(!std::is_same<T, bool>::value, "bool needs special handling");

    // We want to support the case where we have less than sizeof(T) bytes
    // remaining in the slice. We'll just use what we have, so we get a bit of
    // randomness when there are still some bytes left. If size == 0, get<T>()
    // returns the type's value-initialized value.
    const size_t num_bytes = std::min(sizeof(T), data_.size());
    T result{};
    memcpy(&result, data_.begin(), num_bytes);
    data_ += num_bytes;
    return result;
  }
};

// Explicit specialization must be defined outside of class body.
template <>
bool DataRange::get() {
  // The general implementation above is not instantiable for bool, as that
  // would cause undefinied behaviour when memcpy'ing random bytes to the
  // bool. This can result in different observable side effects when invoking
  // get<bool> between debug and release version, which eventually makes the
  // code output different as well as raising various unrecoverable errors on
  // runtime.
  // Hence we specialize get<bool> to consume a full byte and use the least
  // significant bit only (0 == false, 1 == true).
  return get<uint8_t>() % 2;
}

enum IncludeNumericTypes {
  kIncludeNumericTypes = true,
  kExcludeNumericTypes = false
};
enum IncludePackedTypes {
  kIncludePackedTypes = true,
  kExcludePackedTypes = false
};
enum IncludeAllGenerics {
  kIncludeAllGenerics = true,
  kExcludeSomeGenerics = false
};
enum IncludeS128 { kIncludeS128 = true, kExcludeS128 = false };

// Chooses one `ValueType` randomly based on `options` and the enums specified
// above.
template <WasmModuleGenerationOptions options>
ValueType GetValueTypeHelper(DataRange* data, uint32_t num_nullable_types,
                             uint32_t num_non_nullable_types,
                             IncludeNumericTypes include_numeric_types,
                             IncludePackedTypes include_packed_types,
                             IncludeAllGenerics include_all_generics,
                             IncludeS128 include_s128 = kIncludeS128) {
  // Create and fill a vector of potential types to choose from.
  base::SmallVector<ValueType, 32> types;

  // Numeric non-wasmGC types.
  if (include_numeric_types) {
    // Many "general-purpose" instructions return i32, so give that a higher
    // probability (such as 3x).
    types.insert(types.end(),
                 {kWasmI32, kWasmI32, kWasmI32, kWasmI64, kWasmF32, kWasmF64});

    // SIMD type.
    if (ShouldGenerateSIMD(options) && include_s128) {
      types.push_back(kWasmS128);
    }
  }

  // The MVP types: apart from numeric types, contains only the non-nullable
  // funcRef. We don't add externRef, because for externRef globals we generate
  // initialiser expressions where we need wasmGC types. Also, externRef is not
  // really useful for the MVP fuzzer, as there is nothing that we could
  // generate.
  types.push_back(kWasmFuncRef);

  // WasmGC types (including user-defined types).
  // Decide if the return type will be nullable or not.
  const bool nullable =
      ShouldGenerateWasmGC(options) ? data->get<bool>() : false;

  if (ShouldGenerateWasmGC(options)) {
    types.push_back(kWasmI31Ref);

    if (include_numeric_types && include_packed_types) {
      types.insert(types.end(), {kWasmI8, kWasmI16});
    }

    if (nullable) {
      types.insert(types.end(),
                   {kWasmNullRef, kWasmNullExternRef, kWasmNullFuncRef});
    }
    if (nullable || include_all_generics) {
      types.insert(types.end(), {kWasmStructRef, kWasmArrayRef, kWasmAnyRef,
                                 kWasmEqRef, kWasmExternRef});
    }
  }

  // The last index of user-defined types allowed is different based on the
  // nullability of the output. User-defined types are function signatures or
  // structs and arrays (in case of wasmGC).
  const uint32_t num_user_defined_types =
      nullable ? num_nullable_types : num_non_nullable_types;

  // Conceptually, user-defined types are added to the end of the list. Pick a
  // random one among them.
  uint32_t chosen_id =
      data->get<uint8_t>() % (types.size() + num_user_defined_types);

  Nullability nullability = nullable ? kNullable : kNonNullable;

  if (chosen_id >= types.size()) {
    // Return user-defined type.
    return ValueType::RefMaybeNull(
        ModuleTypeIndex{chosen_id - static_cast<uint32_t>(types.size())},
        nullability);
  }
  // If returning a reference type, fix its nullability according to {nullable}.
  if (types[chosen_id].is_reference()) {
    return ValueType::RefMaybeNull(types[chosen_id].heap_type(), nullability);
  }
  // Otherwise, just return the picked type.
  return types[chosen_id];
}

template <WasmModuleGenerationOptions options>
ValueType GetValueType(DataRange* data, uint32_t num_types) {
  return GetValueTypeHelper<options>(data, num_types, num_types,
                                     kIncludeNumericTypes, kExcludePackedTypes,
                                     kIncludeAllGenerics);
}

void GeneratePassiveDataSegment(DataRange* range, WasmModuleBuilder* builder) {
  int length = range->get<uint8_t>() % 65;
  ZoneVector<uint8_t> data(length, builder->zone());
  for (int i = 0; i < length; ++i) {
    data[i] = range->getPseudoRandom<uint8_t>();
  }
  builder->AddPassiveDataSegment(data.data(),
                                 static_cast<uint32_t>(data.size()));
}

uint32_t GenerateRefTypeElementSegment(DataRange* range,
                                       WasmModuleBuilder* builder,
                                       ValueType element_type) {
  DCHECK(element_type.is_object_reference());
  DCHECK(element_type.has_index());
  WasmModuleBuilder::WasmElemSegment segment(
      builder->zone(), element_type, false,
      WasmInitExpr::RefNullConst(element_type.heap_representation()));
  size_t element_count = range->get<uint8_t>() % 11;
  for (size_t i = 0; i < element_count; ++i) {
    segment.entries.emplace_back(
        WasmModuleBuilder::WasmElemSegment::Entry::kRefNullEntry,
        element_type.ref_index().index);
  }
  return builder->AddElementSegment(std::move(segment));
}

template <WasmModuleGenerationOptions options>
std::vector<ValueType> GenerateTypes(DataRange* data, uint32_t num_ref_types) {
  std::vector<ValueType> types;
  int num_params = int{data->get<uint8_t>()} % (kMaxParameters + 1);
  types.reserve(num_params);
  for (int i = 0; i < num_params; ++i) {
    types.push_back(GetValueType<options>(data, num_ref_types));
  }
  return types;
}

FunctionSig* CreateSignature(Zone* zone,
                             base::Vector<const ValueType> param_types,
                             base::Vector<const ValueType> return_types) {
  FunctionSig::Builder builder(zone, return_types.size(), param_types.size());
  for (auto& type : param_types) {
    builder.AddParam(type);
  }
  for (auto& type : return_types) {
    builder.AddReturn(type);
  }
  return builder.Get();
}

template <WasmModuleGenerationOptions options>
class BodyGen {
  template <WasmOpcode Op, ValueKind... Args>
  void op(DataRange* data) {
    Generate<Args...>(data);
    builder_->Emit(Op);
  }

  class V8_NODISCARD BlockScope {
   public:
    BlockScope(BodyGen* gen, WasmOpcode block_type,
               base::Vector<const ValueType> param_types,
               base::Vector<const ValueType> result_types,
               base::Vector<const ValueType> br_types, bool emit_end = true)
        : gen_(gen), emit_end_(emit_end) {
      gen->blocks_.emplace_back(br_types.begin(), br_types.end());
      gen->builder_->EmitByte(block_type);

      if (param_types.size() == 0 && result_types.size() == 0) {
        gen->builder_->EmitValueType(kWasmVoid);
        return;
      }
      if (param_types.size() == 0 && result_types.size() == 1) {
        gen->builder_->EmitValueType(result_types[0]);
        return;
      }
      // Multi-value block.
      Zone* zone = gen->builder_->builder()->zone();
      FunctionSig::Builder builder(zone, result_types.size(),
                                   param_types.size());
      for (auto& type : param_types) {
        DCHECK_NE(type, kWasmVoid);
        builder.AddParam(type);
      }
      for (auto& type : result_types) {
        DCHECK_NE(type, kWasmVoid);
        builder.AddReturn(type);
      }
      FunctionSig* sig = builder.Get();
      const bool is_final = true;
      ModuleTypeIndex sig_id =
          gen->builder_->builder()->AddSignature(sig, is_final);
      gen->builder_->EmitI32V(sig_id);
    }

    ~BlockScope() {
      if (emit_end_) gen_->builder_->Emit(kExprEnd);
      gen_->blocks_.pop_back();
    }

   private:
    BodyGen* const gen_;
    bool emit_end_;
  };

  void block(base::Vector<const ValueType> param_types,
             base::Vector<const ValueType> return_types, DataRange* data) {
    BlockScope block_scope(this, kExprBlock, param_types, return_types,
                           return_types);
    ConsumeAndGenerate(param_types, return_types, data);
  }

  template <ValueKind T>
  void block(DataRange* data) {
    if constexpr (T == kVoid) {
      block({}, {}, data);
    } else {
      block({}, base::VectorOf({ValueType::Primitive(T)}), data);
    }
  }

  void loop(base::Vector<const ValueType> param_types,
            base::Vector<const ValueType> return_types, DataRange* data) {
    BlockScope block_scope(this, kExprLoop, param_types, return_types,
                           param_types);
    ConsumeAndGenerate(param_types, return_types, data);
  }

  template <ValueKind T>
  void loop(DataRange* data) {
    if constexpr (T == kVoid) {
      loop({}, {}, data);
    } else {
      loop({}, base::VectorOf({ValueType::Primitive(T)}), data);
    }
  }

  void finite_loop(base::Vector<const ValueType> param_types,
                   base::Vector<const ValueType> return_types,
                   DataRange* data) {
    // int counter = `kLoopConstant`;
    int kLoopConstant = data->get<uint8_t>() % 8 + 1;
    uint32_t counter = builder_->AddLocal(kWasmI32);
    builder_->EmitI32Const(kLoopConstant);
    builder_->EmitSetLocal(counter);

    // begin loop {
    BlockScope loop_scope(this, kExprLoop, param_types, return_types,
                          param_types);
    //   Consume the parameters:
    //   Resetting locals in each iteration can create interesting loop-phis.
    // TODO(evih): Iterate through existing locals and try to reuse them instead
    // of creating new locals.
    for (auto it = param_types.rbegin(); it != param_types.rend(); it++) {
      uint32_t local = builder_->AddLocal(*it);
      builder_->EmitSetLocal(local);
    }

    //   Loop body.
    Generate(kWasmVoid, data);

    //   Decrement the counter.
    builder_->EmitGetLocal(counter);
    builder_->EmitI32Const(1);
    builder_->Emit(kExprI32Sub);
    builder_->EmitTeeLocal(counter);

    //   If there is another iteration, generate new parameters for the loop and
    //   go to the beginning of the loop.
    {
      BlockScope if_scope(this, kExprIf, {}, {}, {});
      Generate(param_types, data);
      builder_->EmitWithI32V(kExprBr, 1);
    }

    //   Otherwise, generate the return types.
    Generate(return_types, data);
    // } end loop
  }

  template <ValueKind T>
  void finite_loop(DataRange* data) {
    if constexpr (T == kVoid) {
      finite_loop({}, {}, data);
    } else {
      finite_loop({}, base::VectorOf({ValueType::Primitive(T)}), data);
    }
  }

  enum IfType { kIf, kIfElse };

  void if_(base::Vector<const ValueType> param_types,
           base::Vector<const ValueType> return_types, IfType type,
           DataRange* data) {
    // One-armed "if" are only valid if the input and output types are the same.
    DCHECK_IMPLIES(type == kIf, param_types == return_types);
    Generate(kWasmI32, data);
    BlockScope block_scope(this, kExprIf, param_types, return_types,
                           return_types);
    ConsumeAndGenerate(param_types, return_types, data);
    if (type == kIfElse) {
      builder_->Emit(kExprElse);
      ConsumeAndGenerate(param_types, return_types, data);
    }
  }

  template <ValueKind T, IfType type>
  void if_(DataRange* data) {
    static_assert(T == kVoid || type == kIfElse,
                  "if without else cannot produce a value");
    if_({},
        T == kVoid ? base::Vector<ValueType>{}
                   : base::VectorOf({ValueType::Primitive(T)}),
        type, data);
  }

  void try_block_helper(ValueType return_type, DataRange* data) {
    bool has_catch_all = data->get<bool>();
    uint8_t num_catch =
        data->get<uint8_t>() % (builder_->builder()->NumTags() + 1);
    bool is_delegate = num_catch == 0 && !has_catch_all && data->get<bool>();
    // Allow one more target than there are enclosing try blocks, for delegating
    // to the caller.

    base::Vector<const ValueType> return_type_vec =
        return_type.kind() == kVoid ? base::Vector<ValueType>{}
                                    : base::VectorOf(&return_type, 1);
    BlockScope block_scope(this, kExprTry, {}, return_type_vec, return_type_vec,
                           !is_delegate);
    int control_depth = static_cast<int>(blocks_.size()) - 1;
    Generate(return_type, data);
    catch_blocks_.push_back(control_depth);
    for (int i = 0; i < num_catch; ++i) {
      const FunctionSig* exception_type = builder_->builder()->GetTagType(i);
      builder_->EmitWithU32V(kExprCatch, i);
      ConsumeAndGenerate(exception_type->parameters(), return_type_vec, data);
    }
    if (has_catch_all) {
      builder_->Emit(kExprCatchAll);
      Generate(return_type, data);
    }
    if (is_delegate) {
      // The delegate target depth does not include the current try block,
      // because 'delegate' closes this scope. However it is still in the
      // {blocks_} list, so remove one to get the correct size.
      int delegate_depth = data->get<uint8_t>() % (blocks_.size() - 1);
      builder_->EmitWithU32V(kExprDelegate, delegate_depth);
    }
    catch_blocks_.pop_back();
  }

  template <ValueKind T>
  void try_block(DataRange* data) {
    try_block_helper(ValueType::Primitive(T), data);
  }

  struct CatchCase {
    int tag_index;
    CatchKind kind;
  };

  // Generates the i-th nested block for the try-table, and recursively generate
  // the blocks inside it.
  void try_table_rec(base::Vector<const ValueType> param_types,
                     base::Vector<const ValueType> return_types,
                     base::Vector<CatchCase> catch_cases, size_t i,
                     DataRange* data) {
    if (i == catch_cases.size()) {
      // Base case: emit the try-table itself.
      builder_->Emit(kExprTryTable);
      blocks_.emplace_back(return_types.begin(), return_types.end());
      const bool is_final = true;
      ModuleTypeIndex try_sig_index = builder_->builder()->AddSignature(
          CreateSignature(builder_->builder()->zone(), param_types,
                          return_types),
          is_final);
      builder_->EmitI32V(try_sig_index);
      builder_->EmitU32V(static_cast<uint32_t>(catch_cases.size()));
      for (size_t j = 0; j < catch_cases.size(); ++j) {
        builder_->EmitByte(catch_cases[j].kind);
        if (catch_cases[j].kind == kCatch || catch_cases[j].kind == kCatchRef) {
          builder_->EmitByte(catch_cases[j].tag_index);
        }
        builder_->EmitByte(catch_cases.size() - j - 1);
      }
      ConsumeAndGenerate(param_types, return_types, data);
      builder_->Emit(kExprEnd);
      blocks_.pop_back();
      builder_->EmitWithI32V(kExprBr, static_cast<int32_t>(catch_cases.size()));
      return;
    }

    // Enter the i-th nested block. The signature of the block is built as
    // follows:
    // - The input types are the same for each block, the operands are forwarded
    // as-is to the inner try-table.
    // - The output types can be empty, or contain the tag types and/or an
    // exnref depending on the catch kind
    const FunctionSig* type =
        builder_->builder()->GetTagType(catch_cases[i].tag_index);
    int has_tag =
        catch_cases[i].kind == kCatchRef || catch_cases[i].kind == kCatch;
    int has_ref =
        catch_cases[i].kind == kCatchAllRef || catch_cases[i].kind == kCatchRef;
    size_t return_count =
        (has_tag ? type->parameter_count() : 0) + (has_ref ? 1 : 0);
    auto block_returns =
        builder_->builder()->zone()->AllocateVector<ValueType>(return_count);
    if (has_tag) {
      std::copy_n(type->parameters().begin(), type->parameter_count(),
                  block_returns.begin());
    }
    if (has_ref) block_returns.last() = kWasmExnRef;
    {
      BlockScope block(this, kExprBlock, param_types, block_returns,
                       block_returns);
      try_table_rec(param_types, return_types, catch_cases, i + 1, data);
    }
    // Catch label. Consume the unpacked values and exnref (if any), produce
    // values that match the outer scope, and branch to it.
    ConsumeAndGenerate(block_returns, return_types, data);
    builder_->EmitWithU32V(kExprBr, static_cast<uint32_t>(i));
  }

  void try_table_block_helper(base::Vector<const ValueType> param_types,
                              base::Vector<const ValueType> return_types,
                              DataRange* data) {
    uint8_t num_catch = data->get<uint8_t>() % kMaxCatchCases;
    auto catch_cases =
        builder_->builder()->zone()->AllocateVector<CatchCase>(num_catch);
    for (int i = 0; i < num_catch; ++i) {
      catch_cases[i].tag_index =
          data->get<uint8_t>() % builder_->builder()->NumTags();
      catch_cases[i].kind =
          static_cast<CatchKind>(data->get<uint8_t>() % (kLastCatchKind + 1));
    }

    BlockScope block_scope(this, kExprBlock, param_types, return_types,
                           return_types);
    try_table_rec(param_types, return_types, catch_cases, 0, data);
  }

  template <ValueKind T>
  void try_table_block(DataRange* data) {
    try_table_block_helper({}, base::VectorOf({ValueType::Primitive(T)}), data);
  }

  void any_block(base::Vector<const ValueType> param_types,
                 base::Vector<const ValueType> return_types, DataRange* data) {
    uint8_t block_type = data->get<uint8_t>() % 6;
    switch (block_type) {
      case 0:
        block(param_types, return_types, data);
        return;
      case 1:
        loop(param_types, return_types, data);
        return;
      case 2:
        finite_loop(param_types, return_types, data);
        return;
      case 3:
        if (param_types == return_types) {
          if_({}, {}, kIf, data);
          return;
        }
        [[fallthrough]];
      case 4:
        if_(param_types, return_types, kIfElse, data);
        return;
      case 5:
        try_table_block_helper(param_types, return_types, data);
        return;
    }
  }

  void br(DataRange* data) {
    // There is always at least the block representing the function body.
    DCHECK(!blocks_.empty());
    const uint32_t target_block = data->get<uint8_t>() % blocks_.size();
    const auto break_types = base::VectorOf(blocks_[target_block]);

    Generate(break_types, data);
    builder_->EmitWithI32V(
        kExprBr, static_cast<uint32_t>(blocks_.size()) - 1 - target_block);
  }

  template <ValueKind wanted_kind>
  void br_if(DataRange* data) {
    // There is always at least the block representing the function body.
    DCHECK(!blocks_.empty());
    const uint32_t target_block = data->get<uint8_t>() % blocks_.size();
    const auto break_types = base::VectorOf(blocks_[target_block]);

    Generate(break_types, data);
    Generate(kWasmI32, data);
    builder_->EmitWithI32V(
        kExprBrIf, static_cast<uint32_t>(blocks_.size()) - 1 - target_block);
    ConsumeAndGenerate(
        break_types,
        wanted_kind == kVoid
            ? base::Vector<ValueType>{}
            : base::VectorOf({ValueType::Primitive(wanted_kind)}),
        data);
  }

  template <ValueKind wanted_kind>
  void br_on_null(DataRange* data) {
    DCHECK(!blocks_.empty());
    const uint32_t target_block = data->get<uint8_t>() % blocks_.size();
    const auto break_types = base::VectorOf(blocks_[target_block]);
    Generate(break_types, data);
    GenerateRef(data);
    builder_->EmitWithI32V(
        kExprBrOnNull,
        static_cast<uint32_t>(blocks_.size()) - 1 - target_block);
    builder_->Emit(kExprDrop);
    ConsumeAndGenerate(
        break_types,
        wanted_kind == kVoid
            ? base::Vector<ValueType>{}
            : base::VectorOf({ValueType::Primitive(wanted_kind)}),
        data);
  }

  template <ValueKind wanted_kind>
  void br_on_non_null(DataRange* data) {
    DCHECK(!blocks_.empty());
    const uint32_t target_block = data->get<uint8_t>() % blocks_.size();
    const auto break_types = base::VectorOf(blocks_[target_block]);
    if (break_types.empty() ||
        !break_types[break_types.size() - 1].is_reference()) {
      // Invalid break_types for br_on_non_null.
      Generate<wanted_kind>(data);
      return;
    }
    Generate(break_types, data);
    builder_->EmitWithI32V(
        kExprBrOnNonNull,
        static_cast<uint32_t>(blocks_.size()) - 1 - target_block);
    ConsumeAndGenerate(
        break_types.SubVector(0, break_types.size() - 1),
        wanted_kind == kVoid
            ? base::Vector<ValueType>{}
            : base::VectorOf({ValueType::Primitive(wanted_kind)}),
        data);
  }

  void br_table(ValueType result_type, DataRange* data) {
    const uint8_t block_count = 1 + data->get<uint8_t>() % 8;
    // Generate the block entries.
    uint16_t entry_bits =
        block_count > 4 ? data->get<uint16_t>() : data->get<uint8_t>();
    for (size_t i = 0; i < block_count; ++i) {
      builder_->Emit(kExprBlock);
      builder_->EmitValueType(result_type);
      blocks_.emplace_back();
      if (result_type != kWasmVoid) {
        blocks_.back().push_back(result_type);
      }
      // There can be additional instructions in each block.
      // Only generate it with a 25% chance as it's otherwise quite unlikely to
      // have enough random bytes left for the br_table instruction.
      if ((entry_bits & 3) == 3) {
        Generate(kWasmVoid, data);
      }
      entry_bits >>= 2;
    }
    // Generate the br_table.
    Generate(result_type, data);
    Generate(kWasmI32, data);
    builder_->Emit(kExprBrTable);
    uint32_t entry_count = 1 + data->get<uint8_t>() % 8;
    builder_->EmitU32V(entry_count);
    for (size_t i = 0; i < entry_count + 1; ++i) {
      builder_->EmitU32V(data->get<uint8_t>() % block_count);
    }
    // Generate the block ends.
    uint8_t exit_bits = result_type == kWasmVoid ? 0 : data->get<uint8_t>();
    for (size_t i = 0; i < block_count; ++i) {
      if (exit_bits & 1) {
        // Drop and generate new value.
        builder_->Emit(kExprDrop);
        Generate(result_type, data);
      }
      exit_bits >>= 1;
      builder_->Emit(kExprEnd);
      blocks_.pop_back();
    }
  }

  template <ValueKind wanted_kind>
  void br_table(DataRange* data) {
    br_table(
        wanted_kind == kVoid ? kWasmVoid : ValueType::Primitive(wanted_kind),
        data);
  }

  void return_op(DataRange* data) {
    auto returns = builder_->signature()->returns();
    Generate(returns, data);
    builder_->Emit(kExprReturn);
  }

  constexpr static uint8_t max_alignment(WasmOpcode memop) {
    switch (memop) {
      case kExprS128LoadMem:
      case kExprS128StoreMem:
        return 4;
      case kExprI64LoadMem:
      case kExprF64LoadMem:
      case kExprI64StoreMem:
      case kExprF64StoreMem:
      case kExprI64AtomicStore:
      case kExprI64AtomicLoad:
      case kExprI64AtomicAdd:
      case kExprI64AtomicSub:
      case kExprI64AtomicAnd:
      case kExprI64AtomicOr:
      case kExprI64AtomicXor:
      case kExprI64AtomicExchange:
      case kExprI64AtomicCompareExchange:
      case kExprS128Load8x8S:
      case kExprS128Load8x8U:
      case kExprS128Load16x4S:
      case kExprS128Load16x4U:
      case kExprS128Load32x2S:
      case kExprS128Load32x2U:
      case kExprS128Load64Splat:
      case kExprS128Load64Zero:
        return 3;
      case kExprI32LoadMem:
      case kExprI64LoadMem32S:
      case kExprI64LoadMem32U:
      case kExprF32LoadMem:
      case kExprI32StoreMem:
      case kExprI64StoreMem32:
      case kExprF32StoreMem:
      case kExprI32AtomicStore:
      case kExprI64AtomicStore32U:
      case kExprI32AtomicLoad:
      case kExprI64AtomicLoad32U:
      case kExprI32AtomicAdd:
      case kExprI32AtomicSub:
      case kExprI32AtomicAnd:
      case kExprI32AtomicOr:
      case kExprI32AtomicXor:
      case kExprI32AtomicExchange:
      case kExprI32AtomicCompareExchange:
      case kExprI64AtomicAdd32U:
      case kExprI64AtomicSub32U:
      case kExprI64AtomicAnd32U:
      case kExprI64AtomicOr32U:
      case kExprI64AtomicXor32U:
      case kExprI64AtomicExchange32U:
      case kExprI64AtomicCompareExchange32U:
      case kExprS128Load32Splat:
      case kExprS128Load32Zero:
        return 2;
      case kExprI32LoadMem16S:
      case kExprI32LoadMem16U:
      case kExprI64LoadMem16S:
      case kExprI64LoadMem16U:
      case kExprI32StoreMem16:
      case kExprI64StoreMem16:
      case kExprI32AtomicStore16U:
      case kExprI64AtomicStore16U:
      case kExprI32AtomicLoad16U:
      case kExprI64AtomicLoad16U:
      case kExprI32AtomicAdd16U:
      case kExprI32AtomicSub16U:
      case kExprI32AtomicAnd16U:
      case kExprI32AtomicOr16U:
      case kExprI32AtomicXor16U:
      case kExprI32AtomicExchange16U:
      case kExprI32AtomicCompareExchange16U:
      case kExprI64AtomicAdd16U:
      case kExprI64AtomicSub16U:
      case kExprI64AtomicAnd16U:
      case kExprI64AtomicOr16U:
      case kExprI64AtomicXor16U:
      case kExprI64AtomicExchange16U:
      case kExprI64AtomicCompareExchange16U:
      case kExprS128Load16Splat:
        return 1;
      case kExprI32LoadMem8S:
      case kExprI32LoadMem8U:
      case kExprI64LoadMem8S:
      case kExprI64LoadMem8U:
      case kExprI32StoreMem8:
      case kExprI64StoreMem8:
      case kExprI32AtomicStore8U:
      case kExprI64AtomicStore8U:
      case kExprI32AtomicLoad8U:
      case kExprI64AtomicLoad8U:
      case kExprI32AtomicAdd8U:
      case kExprI32AtomicSub8U:
      case kExprI32AtomicAnd8U:
      case kExprI32AtomicOr8U:
      case kExprI32AtomicXor8U:
      case kExprI32AtomicExchange8U:
      case kExprI32AtomicCompareExchange8U:
      case kExprI64AtomicAdd8U:
      case kExprI64AtomicSub8U:
      case kExprI64AtomicAnd8U:
      case kExprI64AtomicOr8U:
      case kExprI64AtomicXor8U:
      case kExprI64AtomicExchange8U:
      case kExprI64AtomicCompareExchange8U:
      case kExprS128Load8Splat:
        return 0;
      default:
        return 0;
    }
  }

  template <WasmOpcode memory_op, ValueKind... arg_kinds>
  void memop(DataRange* data) {
    // Atomic operations need to be aligned exactly to their max alignment.
    const bool is_atomic = memory_op >> 8 == kAtomicPrefix;
    const uint8_t align = is_atomic ? max_alignment(memory_op)
                                    : data->getPseudoRandom<uint8_t>() %
                                          (max_alignment(memory_op) + 1);

    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    uint64_t offset = data->get<uint16_t>();
    // With a 1/256 chance generate potentially very large offsets.
    if ((offset & 0xff) == 0xff) {
      offset = builder_->builder()->IsMemory64(memory_index)
                   ? data->getPseudoRandom<uint64_t>() & 0x1ffffffff
                   : data->getPseudoRandom<uint32_t>();
    }

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index)
        ? Generate<kI64, arg_kinds...>(data)
        : Generate<kI32, arg_kinds...>(data);

    // Format of the instruction (supports multi-memory):
    // memory_op (align | 0x40) memory_index offset
    if (WasmOpcodes::IsPrefixOpcode(static_cast<WasmOpcode>(memory_op >> 8))) {
      DCHECK(memory_op >> 8 == kAtomicPrefix || memory_op >> 8 == kSimdPrefix);
      builder_->EmitWithPrefix(memory_op);
    } else {
      builder_->Emit(memory_op);
    }
    builder_->EmitU32V(align | 0x40);
    builder_->EmitU32V(memory_index);
    builder_->EmitU64V(offset);
  }

  template <WasmOpcode Op, ValueKind... Args>
  void op_with_prefix(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
  }

  void simd_const(DataRange* data) {
    builder_->EmitWithPrefix(kExprS128Const);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(data->getPseudoRandom<uint8_t>());
    }
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_op(DataRange* data) {
    Generate<Args...>(data);
    builder_->EmitWithPrefix(Op);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  template <WasmOpcode Op, int lanes, ValueKind... Args>
  void simd_lane_memop(DataRange* data) {
    // Simd load/store instructions that have a lane immediate.
    memop<Op, Args...>(data);
    builder_->EmitByte(data->get<uint8_t>() % lanes);
  }

  void simd_shuffle(DataRange* data) {
    Generate<kS128, kS128>(data);
    builder_->EmitWithPrefix(kExprI8x16Shuffle);
    for (int i = 0; i < kSimd128Size; i++) {
      builder_->EmitByte(static_cast<uint8_t>(data->get<uint8_t>() % 32));
    }
  }

  void drop(DataRange* data) {
    Generate(GetValueType<options>(
                 data, static_cast<uint32_t>(functions_.size() +
                                             structs_.size() + arrays_.size())),
             data);
    builder_->Emit(kExprDrop);
  }

  enum CallKind { kCallDirect, kCallIndirect, kCallRef };

  template <ValueKind wanted_kind>
  void call(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallDirect);
  }

  template <ValueKind wanted_kind>
  void call_indirect(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallIndirect);
  }

  template <ValueKind wanted_kind>
  void call_ref(DataRange* data) {
    call(data, ValueType::Primitive(wanted_kind), kCallRef);
  }

  void Convert(ValueType src, ValueType dst) {
    auto idx = [](ValueType t) -> int {
      switch (t.kind()) {
        case kI32:
          return 0;
        case kI64:
          return 1;
        case kF32:
          return 2;
        case kF64:
          return 3;
        default:
          UNREACHABLE();
      }
    };
    static constexpr WasmOpcode kConvertOpcodes[] = {
        // {i32, i64, f32, f64} -> i32
        kExprNop, kExprI32ConvertI64, kExprI32SConvertF32, kExprI32SConvertF64,
        // {i32, i64, f32, f64} -> i64
        kExprI64SConvertI32, kExprNop, kExprI64SConvertF32, kExprI64SConvertF64,
        // {i32, i64, f32, f64} -> f32
        kExprF32SConvertI32, kExprF32SConvertI64, kExprNop, kExprF32ConvertF64,
        // {i32, i64, f32, f64} -> f64
        kExprF64SConvertI32, kExprF64SConvertI64, kExprF64ConvertF32, kExprNop};
    int arr_idx = idx(dst) << 2 | idx(src);
    builder_->Emit(kConvertOpcodes[arr_idx]);
  }

  int choose_function_table_index(DataRange* data) {
    int table_count = builder_->builder()->NumTables();
    int start = data->get<uint8_t>() % table_count;
    for (int i = 0; i < table_count; ++i) {
      int index = (start + i) % table_count;
      if (builder_->builder()->GetTableType(index).is_reference_to(
              HeapType::kFunc)) {
        return index;
      }
    }
    FATAL("No funcref table found; table index 0 is expected to be funcref");
  }

  void call(DataRange* data, ValueType wanted_kind, CallKind call_kind) {
    uint8_t random_byte = data->get<uint8_t>();
    int func_index = random_byte % functions_.size();
    ModuleTypeIndex sig_index = functions_[func_index];
    const FunctionSig* sig = builder_->builder()->GetSignature(sig_index);
    // Generate arguments.
    for (size_t i = 0; i < sig->parameter_count(); ++i) {
      Generate(sig->GetParam(i), data);
    }
    // Emit call.
    // If the return types of the callee happen to match the return types of the
    // caller, generate a tail call.
    bool use_return_call = random_byte > 127;
    if (use_return_call &&
        std::equal(sig->returns().begin(), sig->returns().end(),
                   builder_->signature()->returns().begin(),
                   builder_->signature()->returns().end())) {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprReturnCall,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprReturnCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprReturnCallRef, sig_index);
      }
      return;
    } else {
      if (call_kind == kCallDirect) {
        builder_->EmitWithU32V(kExprCallFunction,
                               NumImportedFunctions() + func_index);
      } else if (call_kind == kCallIndirect) {
        // This will not trap because table[func_index] always contains function
        // func_index.
        uint32_t table_index = choose_function_table_index(data);
        builder_->builder()->IsTable64(table_index)
            ? builder_->EmitI64Const(func_index)
            : builder_->EmitI32Const(func_index);
        builder_->EmitWithU32V(kExprCallIndirect, sig_index);
        builder_->EmitByte(table_index);
      } else {
        GenerateRef(HeapType(sig_index), data);
        builder_->EmitWithU32V(kExprCallRef, sig_index);
      }
    }
    if (sig->return_count() == 0 && wanted_kind != kWasmVoid) {
      // The call did not generate a value. Thus just generate it here.
      Generate(wanted_kind, data);
      return;
    }
    if (wanted_kind == kWasmVoid) {
      // The call did generate values, but we did not want one.
      for (size_t i = 0; i < sig->return_count(); ++i) {
        builder_->Emit(kExprDrop);
      }
      return;
    }
    auto wanted_types =
        base::VectorOf(&wanted_kind, wanted_kind == kWasmVoid ? 0 : 1);
    ConsumeAndGenerate(sig->returns(), wanted_types, data);
  }

  struct Var {
    uint32_t index;
    ValueType type = kWasmVoid;
    Var() = default;
    Var(uint32_t index, ValueType type) : index(index), type(type) {}
    bool is_valid() const { return type != kWasmVoid; }
  };

  Var GetRandomLocal(DataRange* data) {
    uint32_t num_params =
        static_cast<uint32_t>(builder_->signature()->parameter_count());
    uint32_t num_locals = static_cast<uint32_t>(locals_.size());
    if (num_params + num_locals == 0) return {};
    uint32_t index = data->get<uint8_t>() % (num_params + num_locals);
    ValueType type = index < num_params ? builder_->signature()->GetParam(index)
                                        : locals_[index - num_params];
    return {index, type};
  }

  constexpr static bool is_convertible_kind(ValueKind kind) {
    return kind == kI32 || kind == kI64 || kind == kF32 || kind == kF64;
  }

  template <ValueKind wanted_kind>
  void local_op(DataRange* data, WasmOpcode opcode) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    Var local = GetRandomLocal(data);
    // If there are no locals and no parameters, just generate any value (if a
    // value is needed), or do nothing.
    if (!local.is_valid() || !is_convertible_kind(local.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (opcode != kExprLocalGet) Generate(local.type, data);
    builder_->EmitWithU32V(opcode, local.index);
    if (wanted_kind != kVoid && local.type.kind() != wanted_kind) {
      Convert(local.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_local(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    local_op<wanted_kind>(data, kExprLocalGet);
  }

  void set_local(DataRange* data) { local_op<kVoid>(data, kExprLocalSet); }

  template <ValueKind wanted_kind>
  void tee_local(DataRange* data) {
    local_op<wanted_kind>(data, kExprLocalTee);
  }

  template <size_t num_bytes>
  void i32_const(DataRange* data) {
    builder_->EmitI32Const(data->getPseudoRandom<int32_t, num_bytes>());
  }

  template <size_t num_bytes>
  void i64_const(DataRange* data) {
    builder_->EmitI64Const(data->getPseudoRandom<int64_t, num_bytes>());
  }

  Var GetRandomGlobal(DataRange* data, bool ensure_mutable) {
    uint32_t index;
    if (ensure_mutable) {
      if (mutable_globals_.empty()) return {};
      index = mutable_globals_[data->get<uint8_t>() % mutable_globals_.size()];
    } else {
      if (globals_.empty()) return {};
      index = data->get<uint8_t>() % globals_.size();
    }
    ValueType type = globals_[index];
    return {index, type};
  }

  template <ValueKind wanted_kind>
  void global_op(DataRange* data) {
    static_assert(wanted_kind == kVoid || is_convertible_kind(wanted_kind));
    constexpr bool is_set = wanted_kind == kVoid;
    Var global = GetRandomGlobal(data, is_set);
    // If there are no globals, just generate any value (if a value is needed),
    // or do nothing.
    if (!global.is_valid() || !is_convertible_kind(global.type.kind())) {
      if (wanted_kind == kVoid) return;
      return Generate<wanted_kind>(data);
    }

    if (is_set) Generate(global.type, data);
    builder_->EmitWithU32V(is_set ? kExprGlobalSet : kExprGlobalGet,
                           global.index);
    if (!is_set && global.type.kind() != wanted_kind) {
      Convert(global.type, ValueType::Primitive(wanted_kind));
    }
  }

  template <ValueKind wanted_kind>
  void get_global(DataRange* data) {
    static_assert(wanted_kind != kVoid, "illegal type");
    global_op<wanted_kind>(data);
  }

  template <ValueKind select_kind>
  void select_with_type(DataRange* data) {
    static_assert(select_kind != kVoid, "illegal kind for select");
    Generate<select_kind, select_kind, kI32>(data);
    // num_types is always 1.
    uint8_t num_types = 1;
    builder_->EmitWithU8U8(kExprSelectWithType, num_types,
                           ValueType::Primitive(select_kind).value_type_code());
  }

  void set_global(DataRange* data) { global_op<kVoid>(data); }

  void throw_or_rethrow(DataRange* data) {
    bool rethrow = data->get<bool>();
    if (rethrow && !catch_blocks_.empty()) {
      int control_depth = static_cast<int>(blocks_.size() - 1);
      int catch_index =
          data->get<uint8_t>() % static_cast<int>(catch_blocks_.size());
      builder_->EmitWithU32V(kExprRethrow,
                             control_depth - catch_blocks_[catch_index]);
    } else {
      int tag = data->get<uint8_t>() % builder_->builder()->NumTags();
      const FunctionSig* exception_sig = builder_->builder()->GetTagType(tag);
      Generate(exception_sig->parameters(), data);
      builder_->EmitWithU32V(kExprThrow, tag);
    }
  }

  template <ValueKind... Types>
  void sequence(DataRange* data) {
    Generate<Types...>(data);
  }

  void memory_size(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    builder_->EmitWithU8(kExprMemorySize, memory_index);
    // The `memory_size` returns an I32. However, `kExprMemorySize` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void grow_memory(DataRange* data) {
    uint8_t memory_index =
        data->get<uint8_t>() % builder_->builder()->NumMemories();

    // Generate the index and the arguments, if any.
    builder_->builder()->IsMemory64(memory_index) ? Generate<kI64>(data)
                                                  : Generate<kI32>(data);
    builder_->EmitWithU8(kExprMemoryGrow, memory_index);
    // The `grow_memory` returns an I32. However, `kExprMemoryGrow` for memory64
    // returns an I64, so we should convert it.
    if (builder_->builder()->IsMemory64(memory_index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  void ref_null(HeapType type, DataRange* data) {
    builder_->EmitWithI32V(kExprRefNull, type.code());
  }

  bool get_local_ref(HeapType type, DataRange* data, Nullability nullable) {
    Var local = GetRandomLocal(data);
    // TODO(14034): Ideally we would check for subtyping here over type
    // equality, but we don't have a module.
    if (local.is_valid() && local.type.is_object_reference() &&
        local.type.heap_type() == type &&
        (local.type.is_nullable()
             ? nullable == kNullable  // We check for nullability-subtyping
             : locals_initialized_    // If the local is not nullable, we cannot
                                      // use it during locals initialization
         )) {
      builder_->EmitWithU32V(kExprLocalGet, local.index);
      return true;
    }

    return false;
  }

  bool new_object(HeapType type, DataRange* data, Nullability nullable) {
    DCHECK(type.is_index());

    ModuleTypeIndex index = type.ref_index();
    bool new_default = data->get<bool>();

    if (builder_->builder()->IsStructType(index)) {
      const StructType* struct_gen = builder_->builder()->GetStructType(index);
      int field_count = struct_gen->field_count();
      bool can_be_defaultable = std::all_of(
          struct_gen->fields().begin(), struct_gen->fields().end(),
          [](ValueType type) -> bool { return type.is_defaultable(); });

      if (new_default && can_be_defaultable) {
        builder_->EmitWithPrefix(kExprStructNewDefault);
        builder_->EmitU32V(index);
      } else {
        for (int i = 0; i < field_count; i++) {
          Generate(struct_gen->field(i).Unpacked(), data);
        }
        builder_->EmitWithPrefix(kExprStructNew);
        builder_->EmitU32V(index);
      }
    } else if (builder_->builder()->IsArrayType(index)) {
      ValueType element_type =
          builder_->builder()->GetArrayType(index)->element_type();
      bool can_be_defaultable = element_type.is_defaultable();
      WasmOpcode array_new_op[] = {
          kExprArrayNew,        kExprArrayNewFixed,
          kExprArrayNewData,    kExprArrayNewElem,
          kExprArrayNewDefault,  // default op has to be at the end of the list.
      };
      size_t op_size = arraysize(array_new_op);
      if (!can_be_defaultable) --op_size;
      switch (array_new_op[data->get<uint8_t>() % op_size]) {
        case kExprArrayNewElem:
        case kExprArrayNewData: {
          // This is more restrictive than it has to be.
          // TODO(14034): Also support nonnullable and non-index reference
          // types.
          if (element_type.is_reference() && element_type.is_nullable() &&
              element_type.has_index()) {
            // Add a new element segment with the corresponding type.
            uint32_t element_segment = GenerateRefTypeElementSegment(
                data, builder_->builder(), element_type);
            // Generate offset, length.
            // TODO(14034): Change the distribution here to make it more likely
            // that the numbers are in range.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            // Generate array.new_elem instruction.
            builder_->EmitWithPrefix(kExprArrayNewElem);
            builder_->EmitU32V(index);
            builder_->EmitU32V(element_segment);
            break;
          } else if (!element_type.is_reference()) {
            // Lazily create a data segment if the module doesn't have one yet.
            if (builder_->builder()->NumDataSegments() == 0) {
              GeneratePassiveDataSegment(data, builder_->builder());
            }
            int data_index =
                data->get<uint8_t>() % builder_->builder()->NumDataSegments();
            // Generate offset, length.
            Generate(base::VectorOf({kWasmI32, kWasmI32}), data);
            builder_->EmitWithPrefix(kExprArrayNewData);
            builder_->EmitU32V(index);
            builder_->EmitU32V(data_index);
            break;
          }
          [[fallthrough]];  // To array.new.
        }
        case kExprArrayNew:
          Generate(element_type.Unpacked(), data);
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNew);
          builder_->EmitU32V(index);
          break;
        case kExprArrayNewFixed: {
          size_t element_count =
              std::min(static_cast<size_t>(data->get<uint8_t>()), data->size());
          for (size_t i = 0; i < element_count; ++i) {
            Generate(element_type.Unpacked(), data);
          }
          builder_->EmitWithPrefix(kExprArrayNewFixed);
          builder_->EmitU32V(index);
          builder_->EmitU32V(static_cast<uint32_t>(element_count));
          break;
        }
        case kExprArrayNewDefault:
          Generate(kWasmI32, data);
          builder_->EmitI32Const(kMaxArraySize);
          builder_->Emit(kExprI32RemS);
          builder_->EmitWithPrefix(kExprArrayNewDefault);
          builder_->EmitU32V(index);
          break;
        default:
          FATAL("Unimplemented opcode");
      }
    } else {
      CHECK(builder_->builder()->IsSignature(index));
      // Map the type index to a function index.
      // TODO(11954. 7748): Once we have type canonicalization, choose a random
      // function from among those matching the signature (consider function
      // subtyping?).
      uint32_t declared_func_index =
          index.index - static_cast<uint32_t>(arrays_.size() + structs_.size());
      size_t num_functions = builder_->builder()->NumDeclaredFunctions();
      const FunctionSig* sig = builder_->builder()->GetSignature(index);
      for (size_t i = 0; i < num_functions; ++i) {
        if (sig == builder_->builder()
                       ->GetFunction(declared_func_index)
                       ->signature()) {
          uint32_t absolute_func_index =
              NumImportedFunctions() + declared_func_index;
          builder_->EmitWithU32V(kExprRefFunc, absolute_func_index);
          return true;
        }
        declared_func_index = (declared_func_index + 1) % num_functions;
      }
      // We did not find a function matching the requested signature.
      builder_->EmitWithI32V(kExprRefNull, index.index);
      if (!nullable) {
        builder_->Emit(kExprRefAsNonNull);
      }
    }

    return true;
  }

  void table_op(uint32_t index, std::vector<ValueType> types, DataRange* data,
                WasmOpcode opcode) {
    DCHECK(opcode == kExprTableSet || opcode == kExprTableSize ||
           opcode == kExprTableGrow || opcode == kExprTableFill);
    for (size_t i = 0; i < types.size(); i++) {
      // When passing the reftype by default kWasmFuncRef is used.
      // Then the type is changed according to its table type.
      if (types[i] == kWasmFuncRef) {
        types[i] = builder_->builder()->GetTableType(index);
      }
    }
    Generate(base::VectorOf(types), data);
    if (opcode == kExprTableSet) {
      builder_->Emit(opcode);
    } else {
      builder_->EmitWithPrefix(opcode);
    }
    builder_->EmitU32V(index);

    // The `table_size` and `table_grow` should return an I32. However, the Wasm
    // instruction for table64 returns an I64, so it should be converted.
    if ((opcode == kExprTableSize || opcode == kExprTableGrow) &&
        builder_->builder()->IsTable64(index)) {
      builder_->Emit(kExprI32ConvertI64);
    }
  }

  ValueType table_address_type(int table_index) {
    return builder_->builder()->IsTable64(table_index) ? kWasmI64 : kWasmI32;
  }

  std::pair<int, ValueType> select_random_table(DataRange* data) {
    int num_tables = builder_->builder()->NumTables();
    DCHECK_GT(num_tables, 0);
    int index = data->get<uint8_t>() % num_tables;
    ValueType address_type = table_address_type(index);

    return {index, address_type};
  }

  bool table_get(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    int table_count = builder_->builder()->NumTables();
    DCHECK_GT(table_count, 0);
    ZoneVector<uint32_t> table(builder_->builder()->zone());
    for (int i = 0; i < table_count; i++) {
      if (builder_->builder()->GetTableType(i) == needed_type) {
        table.push_back(i);
      }
    }
    if (table.empty()) {
      return false;
    }
    int table_index =
        table[data->get<uint8_t>() % static_cast<int>(table.size())];
    ValueType address_type = table_address_type(table_index);
    Generate(address_type, data);
    builder_->Emit(kExprTableGet);
    builder_->EmitU32V(table_index);
    return true;
  }

  void table_set(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {address_type, kWasmFuncRef}, data, kExprTableSet);
  }

  void table_size(DataRange* data) {
    auto [table_index, _] = select_random_table(data);
    table_op(table_index, {}, data, kExprTableSize);
  }

  void table_grow(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {kWasmFuncRef, address_type}, data, kExprTableGrow);
  }

  void table_fill(DataRange* data) {
    auto [table_index, address_type] = select_random_table(data);
    table_op(table_index, {address_type, kWasmFuncRef, address_type}, data,
             kExprTableFill);
  }

  void table_copy(DataRange* data) {
    ValueType needed_type = data->get<bool>() ? kWasmFuncRef : kWasmExternRef;
    int table_count = builder_->builder()->NumTables();
    ZoneVector<uint32_t> table(builder_->builder()->zone());
    for (int i = 0; i < table_count; i++) {
      if (builder_->builder()->GetTableType(i) == needed_type) {
        table.push_back(i);
      }
    }
    if (table.empty()) {
      return;
    }
    int first_index = data->get<uint8_t>() % static_cast<int>(table.size());
    int second_index = data->get<uint8_t>() % static_cast<int>(table.size());
    ValueType first_addrtype = table_address_type(table[first_index]);
    ValueType second_addrtype = table_address_type(table[second_index]);
    ValueType result_addrtype =
        first_addrtype == kWasmI32 ? kWasmI32 : second_addrtype;
    Generate(first_addrtype, data);
    Generate(second_addrtype, data);
    Generate(result_addrtype, data);
    builder_->EmitWithPrefix(kExprTableCopy);
    builder_->EmitU32V(table[first_index]);
    builder_->EmitU32V(table[second_index]);
  }

  bool array_get_helper(ValueType value_type, DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<ModuleTypeIndex> array_indices(builder->zone());

    for (ModuleTypeIndex i : arrays_) {
      DCHECK(builder->IsArrayType(i));
      if (builder->GetArrayType(i)->element_type().Unpacked() == value_type) {
        array_indices.push_back(i);
      }
    }

    if (!array_indices.empty()) {
      int index = data->get<uint8_t>() % static_cast<int>(array_indices.size());
      GenerateRef(HeapType(array_indices[index]), data, kNullable);
      Generate(kWasmI32, data);
      if (builder->GetArrayType(array_indices[index])
              ->element_type()
              .is_packed()) {
        builder_->EmitWithPrefix(data->get<bool>() ? kExprArrayGetS
                                                   : kExprArrayGetU);

      } else {
        builder_->EmitWithPrefix(kExprArrayGet);
      }
      builder_->EmitU32V(array_indices[index]);
      return true;
    }

    return false;
  }

  template <ValueKind wanted_kind>
  void array_get(DataRange* data) {
    bool got_array_value =
        array_get_helper(ValueType::Primitive(wanted_kind), data);
    if (!got_array_value) {
      Generate<wanted_kind>(data);
    }
  }
  bool array_get_ref(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    return array_get_helper(needed_type, data);
  }

  void i31_get(DataRange* data) {
    GenerateRef(HeapType(HeapType::kI31), data);
    if (data->get<bool>()) {
      builder_->EmitWithPrefix(kExprI31GetS);
    } else {
      builder_->EmitWithPrefix(kExprI31GetU);
    }
  }

  void array_len(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    GenerateRef(HeapType(HeapType::kArray), data);
    builder_->EmitWithPrefix(kExprArrayLen);
  }

  void array_copy(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    // TODO(14034): The source element type only has to be a subtype of the
    // destination element type. Currently this only generates copy from same
    // typed arrays.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    GenerateRef(HeapType(array_index), data);  // destination
    Generate(kWasmI32, data);                  // destination index
    GenerateRef(HeapType(array_index), data);  // source
    Generate(kWasmI32, data);                  // source index
    Generate(kWasmI32, data);                  // length
    builder_->EmitWithPrefix(kExprArrayCopy);
    builder_->EmitU32V(array_index);  // destination array type index
    builder_->EmitU32V(array_index);  // source array type index
  }

  void array_fill(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    ValueType element_type = builder_->builder()
                                 ->GetArrayType(array_index)
                                 ->element_type()
                                 .Unpacked();
    GenerateRef(HeapType(array_index), data);  // array
    Generate(kWasmI32, data);                  // offset
    Generate(element_type, data);              // value
    Generate(kWasmI32, data);                  // length
    builder_->EmitWithPrefix(kExprArrayFill);
    builder_->EmitU32V(array_index);
  }

  void array_init_data(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    const ArrayType* array_type =
        builder_->builder()->GetArrayType(array_index);
    DCHECK(array_type->mutability());
    ValueType element_type = array_type->element_type().Unpacked();
    if (element_type.is_reference()) {
      return;
    }
    if (builder_->builder()->NumDataSegments() == 0) {
      GeneratePassiveDataSegment(data, builder_->builder());
    }

    int data_index =
        data->get<uint8_t>() % builder_->builder()->NumDataSegments();
    // Generate array, index, data_offset, length.
    Generate(base::VectorOf({ValueType::RefNull(array_index), kWasmI32,
                             kWasmI32, kWasmI32}),
             data);
    builder_->EmitWithPrefix(kExprArrayInitData);
    builder_->EmitU32V(array_index);
    builder_->EmitU32V(data_index);
  }

  void array_init_elem(DataRange* data) {
    DCHECK_NE(0, arrays_.size());  // We always emit at least one array type.
    ModuleTypeIndex array_index =
        arrays_[data->get<uint8_t>() % arrays_.size()];
    DCHECK(builder_->builder()->IsArrayType(array_index));
    const ArrayType* array_type =
        builder_->builder()->GetArrayType(array_index);
    DCHECK(array_type->mutability());
    ValueType element_type = array_type->element_type().Unpacked();
    // This is more restrictive than it has to be.
    // TODO(14034): Also support nonnullable and non-index reference
    // types.
    if (!element_type.is_reference() || element_type.is_non_nullable() ||
        !element_type.has_index()) {
      return;
    }
    // Add a new element segment with the corresponding type.
    uint32_t element_segment =
        GenerateRefTypeElementSegment(data, builder_->builder(), element_type);
    // Generate array, index, elem_offset, length.
    // TODO(14034): Change the distribution here to make it more likely
    // that the numbers are in range.
    Generate(base::VectorOf({ValueType::RefNull(array_index), kWasmI32,
                             kWasmI32, kWasmI32}),
             data);
    // Generate array.new_elem instruction.
    builder_->EmitWithPrefix(kExprArrayInitElem);
    builder_->EmitU32V(array_index);
    builder_->EmitU32V(element_segment);
  }

  void array_set(DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<ModuleTypeIndex> array_indices(builder->zone());
    for (ModuleTypeIndex i : arrays_) {
      DCHECK(builder->IsArrayType(i));
      if (builder->GetArrayType(i)->mutability()) {
        array_indices.push_back(i);
      }
    }

    if (array_indices.empty()) {
      return;
    }

    int index = data->get<uint8_t>() % static_cast<int>(array_indices.size());
    GenerateRef(HeapType(array_indices[index]), data);
    Generate(kWasmI32, data);
    Generate(
        builder->GetArrayType(array_indices[index])->element_type().Unpacked(),
        data);
    builder_->EmitWithPrefix(kExprArraySet);
    builder_->EmitU32V(array_indices[index]);
  }

  bool struct_get_helper(ValueType value_type, DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    ZoneVector<uint32_t> field_index(builder->zone());
    ZoneVector<ModuleTypeIndex> struct_index(builder->zone());
    for (ModuleTypeIndex i : structs_) {
      DCHECK(builder->IsStructType(i));
      int field_count = builder->GetStructType(i)->field_count();
      for (int index = 0; index < field_count; index++) {
        // TODO(14034): This should be a subtype check!
        if (builder->GetStructType(i)->field(index) == value_type) {
          field_index.push_back(index);
          struct_index.push_back(i);
        }
      }
    }
    if (!field_index.empty()) {
      int index = data->get<uint8_t>() % static_cast<int>(field_index.size());
      GenerateRef(HeapType(struct_index[index]), data, kNullable);
      if (builder->GetStructType(struct_index[index])
              ->field(field_index[index])
              .is_packed()) {
        builder_->EmitWithPrefix(data->get<bool>() ? kExprStructGetS
                                                   : kExprStructGetU);
      } else {
        builder_->EmitWithPrefix(kExprStructGet);
      }
      builder_->EmitU32V(struct_index[index]);
      builder_->EmitU32V(field_index[index]);
      return true;
    }
    return false;
  }

  template <ValueKind wanted_kind>
  void struct_get(DataRange* data) {
    bool got_struct_value =
        struct_get_helper(ValueType::Primitive(wanted_kind), data);
    if (!got_struct_value) {
      Gene
"""


```
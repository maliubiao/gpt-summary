Response:
Let's break down the thought process for analyzing this V8 code snippet.

**1. Initial Scan and Goal Identification:**

* **Keyword Recognition:**  The filename `random-module-generation.cc` immediately suggests its core function: generating random WebAssembly modules. Keywords like "fuzzing" further reinforce this idea.
* **Copyright and License:** These are standard boilerplate and don't contribute to functional understanding.
* **Includes:**  The included headers provide clues about the dependencies:
    * `<algorithm>`, `<array>`, `<optional>`: Standard C++ utilities.
    * `"src/base/...`": Base V8 utilities (random number generation, small vectors).
    * `"src/wasm/...`": Core WebAssembly components (module builder, module representation, opcodes).
* **`#ifndef V8_WASM_RANDOM_FUZZERS`:**  This is a critical conditional compilation directive. It confirms the code is intended for non-official builds, specifically for testing/fuzzing. The `#error` emphasizes this.
* **Namespace:** `v8::internal::wasm::fuzzing` clearly defines the code's location and purpose within V8.

**2. Analyzing Key Data Structures and Constants:**

* **`constexpr` Values:**  The long list of `constexpr` integers (e.g., `kMaxArrays`, `kMaxFunctions`) defines the limits and constraints for the randomly generated modules. This is crucial for understanding the scope of the generation process. These constants tell us *what* aspects of a WASM module are being randomized.
* **`StringImports` struct:** This suggests the generated WASM modules might interact with JavaScript string functions through imports. The field names are direct hints (e.g., `fromCharCode`, `concat`).
* **Template Utilities (`CreateArray`, `ConcatArrays`, `AppendArrayIf`):**  These are compile-time helpers for managing arrays, likely used to define sets of possible values or configurations.

**3. Deeper Dive into `DataRange`:**

* **Purpose:** The comments clearly state the role of `data_` (raw fuzzing data) and `rng_` (for less critical random values).
* **Splitting:** The `split()` method indicates a strategy for consuming the input data in chunks, allowing for more complex and varied generation processes.
* **`getPseudoRandom()`:** This function generates random values of specific types. The handling of signed integers is a noteworthy detail, showing awareness of potential biases in simple byte-based random generation.
* **`get()`:** This is the primary mechanism for consuming data from the input buffer. The specialization for `bool` highlights the need to handle boolean randomness carefully.

**4. Examining Type Generation (`GetValueTypeHelper`, `GetValueType`):**

* **Random Type Selection:** These functions are responsible for choosing random WebAssembly value types. The logic involves:
    * A vector of potential types.
    * Prioritizing `i32`.
    * Handling SIMD and WasmGC types based on `options`.
    * Incorporating nullable and non-nullable types.
    * Selecting user-defined types (function signatures, structs, arrays).
* **`Include...` Enums:** These enums control which categories of types are considered during generation, allowing for different fuzzing scenarios.

**5. High-Level Understanding of Other Functions:**

* **`GeneratePassiveDataSegment`:** Generates random data for passive data segments in the WASM module.
* **`GenerateRefTypeElementSegment`:**  Generates element segments specifically for reference types.
* **`GenerateTypes`:** Creates a vector of random function parameter types.
* **`CreateSignature`:** Builds a `FunctionSig` object, representing a function signature.
* **`BodyGen` Class (Incomplete):**  This class is clearly the heart of the function body generation. The provided snippet shows methods for:
    * Generating different control flow structures (`block`, `loop`, `if`, `try`).
    * Emitting opcodes (`op`).
    * Handling branching (`br`, `br_if`, `br_table`).
    * Returning from functions (`return_op`).
    * Memory access (`max_alignment`).

**6. Answering the Prompts:**

With the above analysis in mind, addressing the specific questions becomes straightforward:

* **Functionality:** Generate random WASM modules for fuzzing.
* **`.tq` Extension:** It's not a Torque file.
* **Relationship to JavaScript:** The `StringImports` struct strongly suggests interaction with JS string functions.
* **Code Logic Inference:**  The `DataRange`'s `split()` and `get()` methods manage data consumption. The `GetValueType` functions select random types based on various criteria.
* **Common Programming Errors:**  Not explicitly shown in this snippet, but potential errors could arise in complex WASM interactions or type mismatches during generation.
* **Summary:** The code generates random WASM modules, likely for testing and finding bugs in the V8 WebAssembly implementation. It uses a data-driven approach with various constraints and options to control the generated modules.

**7. Iteration and Refinement (Self-Correction):**

Initially, one might focus solely on the `BodyGen` class, as it deals with the core logic. However, recognizing the importance of the `DataRange` and type generation functions is crucial for understanding *how* the randomness is introduced. The conditional compilation directive is another key piece of information that defines the code's intended context. Also, noting the limitations imposed by the `constexpr` constants is essential for understanding the boundaries of the generated modules.

By systematically examining the code's structure, data structures, and functions, we can build a comprehensive understanding of its purpose and functionality. The comments are also invaluable for guiding this process.
这是 V8 源代码的一部分，位于 `v8/src/wasm/fuzzing/random-module-generation.cc`，其主要功能是**随机生成 WebAssembly 模块**。  这个模块是为 WebAssembly 模糊测试而设计的，用于生成各种各样可能的 WebAssembly 模块结构和指令序列，以测试 V8 的 WebAssembly 引擎的健壮性和正确性。

下面是更详细的功能分解：

**核心功能:**

1. **随机模块结构生成:**
   - 它定义了生成 WebAssembly 模块的各种组成部分的规则和限制，例如：
     - 最大数组、结构体、函数、全局变量、局部变量的数量。
     - 函数参数和返回值的最大数量。
     - 表、内存、数据段的最大数量和大小。
     - 最大递归深度和异常处理情况的数量。
   - 使用 `DataRange` 类来从输入数据中提取随机值，以决定模块的各种属性。

2. **类型生成:**
   - 能够随机生成不同的 WebAssembly 值类型 (`ValueType`)，包括：
     - 基本数值类型 (i32, i64, f32, f64)。
     - SIMD 类型 (s128)。
     - 引用类型 (funcref, externref, 以及 WasmGC 的 structref, arrayref 等)。
     - 可以控制是否包含数值类型、打包类型和泛型类型。

3. **函数体生成:**
   - `BodyGen` 类负责生成函数体的指令序列。它可以生成各种 WebAssembly 指令，包括：
     - 控制流指令 (block, loop, if, br, br_if, br_table, return)。
     - 内存访问指令 (load, store)。
     - 原子操作指令。
     - 常量指令 (i32.const)。
     - 局部和全局变量访问指令 (local.get, local.set, global.get, global.set)。
     - 函数调用指令 (call, call_indirect)。
     - 异常处理指令 (try, catch, throw)。
     - WasmGC 相关指令 (struct.new, array.new, ref.cast, instanceof 等)。

4. **导入和导出生成:**
   - 可以生成导入函数和全局变量的声明。
   - 可以生成导出函数、全局变量、内存和表的声明。
   - 特别地，它定义了一个 `StringImports` 结构体，暗示它可以生成与 JavaScript 字符串操作相关的导入函数。

5. **数据段和元素段生成:**
   - 可以生成被动数据段，用于存储模块的静态数据。
   - 可以生成引用类型的元素段，用于初始化表。

**关于代码中提到的几点:**

* **`.tq` 结尾:**  `random-module-generation.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 源代码文件。Torque 文件通常以 `.tq` 结尾。
* **与 JavaScript 功能的关系:**  `StringImports` 结构体明确列出了一些 JavaScript 字符串相关的函数名 (如 `fromCharCode`, `concat`, `substring` 等)。这意味着这个生成器可以创建导入这些 JavaScript 函数的 WebAssembly 模块。这允许生成的 WebAssembly 代码与 JavaScript 环境进行交互，特别是进行字符串操作。

**JavaScript 示例 (假设生成的 WASM 模块导入了 `fromCharCode`):**

```javascript
async function runWasm() {
  const importObject = {
    string: {
      fromCharCode: String.fromCharCode
    }
  };

  const response = await fetch('your_random_module.wasm'); // 假设生成的 WASM 文件名为 your_random_module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer, importObject);

  // 假设生成的 WASM 模块导出了一个名为 'getString' 的函数，
  // 它使用导入的 fromCharCode 生成一个字符串。
  const result = module.instance.exports.getString(65, 66, 67); // 传入字符编码
  console.log(result); // 输出 "ABC"
}

runWasm();
```

**代码逻辑推理 (假设输入与输出):**

假设 `DataRange` 提供了以下随机数据 (简化示例):

```
data: [0x02, 0x00, 0x01, 0x00, 0x0A, 0x41, 0x42, 0x43, 0x00]
```

* **假设 `GetValueType` 被调用:** 它可能会读取前几个字节来决定生成哪种类型。 例如，`0x02` 可能对应 `i32`，`0x00` 可能表示非 nullable。
* **假设生成一个简单的函数:**
    * 第一个字节 `0x02` 可能决定函数有 2 个局部变量。
    * 接下来两个字节 `0x00`, `0x01` 可能决定局部变量的类型分别是 `i32` 和 `f32`。
    * 之后的字节可能决定函数体内的指令序列。例如，`0x0A` 可能对应 `i32.const` 指令，`0x41, 0x42, 0x43` 可能表示常量值 65, 66, 67。
    * 最后一个 `0x00` 可能表示 `return` 指令。

**输出 (生成的 WASM 模块可能包含如下逻辑的函数):**

```wasm
(module
  (func $generated_function (local i32) (local f32)
    i32.const 65
    return
  )
  (export "generated_function" (func $generated_function))
)
```

**涉及用户常见的编程错误 (模糊测试的目的就是找到这些错误):**

由于这是模糊测试代码，它旨在生成各种可能的、甚至是无效的 WebAssembly 模块来发现 V8 引擎中的错误。一些可能被生成的有问题的模式包括：

* **类型不匹配:**  例如，将 `f32` 类型的值赋给 `i32` 类型的局部变量，或者在需要特定类型的操作数时提供错误的类型。
* **内存越界访问:** 生成超出已分配内存范围的 load 或 store 指令。
* **栈溢出:**  生成深度递归的函数调用。
* **无效的操作码或操作数:** 尽管代码会尽量生成有效的操作码，但在某些情况下，由于随机性，可能会生成带有无效操作数的指令。
* **违反 WebAssembly 规范的结构:**  例如，在不允许的位置使用特定的指令，或者形成不合法的控制流结构。
* **未对齐的内存访问 (取决于是否开启了相关特性):**  尝试在非对齐的地址上执行需要对齐的内存操作。
* **WasmGC 特性相关的错误:** 例如，错误地使用 `ref.cast`，访问空引用，或进行无效的类型转换。

**第 1 部分功能归纳:**

`v8/src/wasm/fuzzing/random-module-generation.cc` 的第 1 部分（我们看到的代码片段）主要负责构建 WebAssembly 模块的基本框架和一些核心组件。它定义了生成器可以使用的最大值和类型范围，并提供了生成随机值、类型、被动数据段和引用类型元素段的基础工具。`BodyGen` 类的初步定义暗示了函数体指令生成的复杂性。  关键在于它为后续部分奠定了基础，定义了随机模块生成的基本能力和限制。

后续部分很可能会扩展 `BodyGen` 类，实现更复杂的指令生成逻辑，并处理导入、导出、表、内存等模块组件的生成。

Prompt: 
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共7部分，请归纳一下它的功能

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
      case kExprI64A
"""


```
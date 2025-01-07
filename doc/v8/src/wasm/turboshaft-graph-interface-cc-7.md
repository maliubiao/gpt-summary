Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a functional summary of the provided C++ code snippet, along with specific details about its nature, relationship to JavaScript, logic, potential errors, and a concise overall summary. The prompt also highlights that this is part 8 of 12, implying a larger context.

2. **Initial Code Inspection:** I first scan the code for keywords and patterns. I see:
    * `V<>`: This strongly suggests a value representation within the Turboshaft compiler.
    * `FullDecoder* decoder`:  Indicates this code is part of the decoding process for WebAssembly.
    * `BuiltinCallDescriptor::...`:  This points to calling built-in functions, crucial for implementing WebAssembly features.
    * `CallBuiltinThroughJumptable`:  Confirms the use of jump tables for efficient built-in calls.
    * `String`, `WasmStringViewIter`:  Suggests this code deals with WebAssembly string manipulation.
    * `InstanceCache`: An optimization for accessing instance data.
    * `BlockPhis`: Related to managing values within basic blocks of the compiled code.
    * `FrameState`:  Crucial for deoptimization and debugging.
    * `MaybePhi`, `Phi`:  Indicates the code constructs SSA (Static Single Assignment) form.
    * Operations like `StringAsIter`, `StringViewIterNext`, `StringCompare`, `StringFromCodePoint`, `StringHash`: These are explicit WebAssembly string operations.

3. **Identify Key Functionalities:** Based on the initial inspection, I can deduce the major responsibilities of this code:
    * **Interfacing with Built-in Functions:**  The primary function is to provide a C++ interface to call optimized built-in functions for various WebAssembly string operations.
    * **String Manipulation:** The code offers functionalities for creating iterators over string views, moving the iterator, slicing string views, comparing strings, creating strings from code points, and calculating string hashes.
    * **Instance Data Caching:** The `InstanceCache` class is designed to optimize access to frequently used fields of the WebAssembly instance.
    * **Block Management and Phi Nodes:** The `BlockPhis` class is involved in managing values within basic blocks during compilation, particularly for handling control flow merges using phi nodes.
    * **Frame State Management:** The code deals with creating and managing `FrameState` objects, which are essential for deoptimization.
    * **Type Conversions and Arithmetic:**  Functions related to converting between integer and floating-point types (including handling overflows and saturation) are present.

4. **Address Specific Questions:**  Now, I systematically address each part of the user's query:

    * **Functionality Listing:** I create a bulleted list summarizing the identified functionalities in clear terms.
    * **Torque Source:** I check the file extension. Since it's `.cc`, it's not a Torque file.
    * **JavaScript Relationship:** I identify the string operations as directly related to JavaScript's string handling (since WebAssembly aims for interoperability). I then create JavaScript examples demonstrating the equivalent functionalities using `String` methods and iterators.
    * **Code Logic and Assumptions:** I pick a representative function, `StringCompare`, and create a simple input/output scenario to illustrate its behavior. I also state the assumption that the inputs are valid string values.
    * **Common Programming Errors:**  I focus on errors related to string handling in general, such as null checks and out-of-bounds access, as hinted at by the `NullCheck` function and iterator manipulation functions. I provide simple JavaScript examples of these errors.
    * **Overall Function Summary:** I synthesize a concise summary highlighting the core role of this code in bridging the gap between the Turboshaft compiler and WebAssembly string built-ins.

5. **Consider the "Part 8 of 12" Context:**  While the provided snippet is self-contained, recognizing it's part of a larger sequence suggests that this code likely focuses on a specific subset of WebAssembly features (in this case, string manipulation) within the overall compilation pipeline.

6. **Refine and Organize:**  Finally, I review the generated answer for clarity, accuracy, and organization. I ensure the language is precise and the examples are easy to understand. I use formatting (like bullet points and code blocks) to enhance readability.

By following this process, I can break down the C++ code snippet, understand its purpose, and address all aspects of the user's request in a comprehensive and informative way. The initial code scan and identification of key patterns are crucial for quickly grasping the overall functionality before diving into the details.
这是一个V8源代码文件，位于`v8/src/wasm/`目录下，名为`turboshaft-graph-interface.cc`。从文件名和代码内容来看，它在V8的WebAssembly (Wasm) 引擎 Turboshaft 编译器的图形表示层起着关键作用。

**功能归纳:**

这个文件的主要功能是定义了一系列方法，用于在 Turboshaft 编译器的图形表示中构建和操作与 WebAssembly 指令相对应的节点。它提供了一个高级接口，将 WebAssembly 的操作语义映射到 Turboshaft 图形表示的节点上。

**详细功能列表:**

* **提供 WebAssembly 操作到 Turboshaft 图节点的映射:**  文件中定义了许多函数，每个函数对应一个或一组 WebAssembly 操作。这些函数负责创建 Turboshaft 图中的相应节点，并将其连接起来，形成程序的图形表示。例如，`Load`, `Store`, `Add`, `Sub`, `Call`, `Return` 等。
* **处理不同数据类型:** 代码中可以看到对多种 WebAssembly 数据类型的处理，例如 `i32`, `i64`, `f32`, `f64`, 以及引用类型 (`Ref`), Simd类型 (`S128`) 和字符串类型 (`String`, `WasmStringViewIter`)。
* **支持控制流:**  包含了创建和连接控制流块 (`TSBlock`) 的方法，例如 `NewBlock`, `Bind`, `Goto`, `Branch`, `Switch` 等，以及处理 Phi 节点 (`Phi`) 来合并不同控制流路径上的值。
* **与内置函数交互:** 通过 `CallBuiltinThroughJumptable` 调用 V8 的内置函数，用于实现一些复杂的 WebAssembly 操作，例如字符串操作 (`StringAsIter`, `StringViewIterNext`, `StringCompare`, `StringFromCodePoint`, `StringHash`)。
* **处理内存访问:** 提供了 `Load` 和 `Store` 操作，用于访问 WebAssembly 线性内存。
* **支持函数调用:**  包含了 `Call` 和 `CallIndirect` 操作，用于表示直接和间接的函数调用。
* **实现类型转换:**  提供了各种类型转换操作，例如整数到浮点数，浮点数到整数等。
* **处理异常:**  代码中涉及到异常处理的机制，例如 `Throw`, `Try`, `Catch`。
* **优化和缓存:** 引入了 `InstanceCache` 类，用于缓存 WebAssembly 实例数据，提高访问效率。
* **处理帧状态:**  `CreateFrameState` 和相关的函数用于创建和管理帧状态，这对于 deoptimization (反优化) 非常重要。
* **支持 Simd 操作:**  包含对 Simd (单指令多数据流) 操作的支持。
* **支持引用类型:**  处理 `ref.null`, `ref.is_null` 等引用类型相关的操作。
* **支持尾调用优化:**  `ReturnVoidImpl` 中可能包含尾调用优化的逻辑。
* **字符串操作:** 专门提供了处理 WebAssembly 字符串的操作，包括创建迭代器、移动迭代器、比较字符串、获取哈希值等。

**关于文件类型和 JavaScript 关系:**

* **文件类型:**  由于文件扩展名是 `.cc`，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件 (`.tq`)。
* **JavaScript 关系:**  这个文件与 JavaScript 的功能有密切关系，因为它负责将 WebAssembly 代码编译成可以在 V8 引擎中执行的机器码。WebAssembly 的目标之一就是在浏览器中提供接近原生性能的执行，并且可以与 JavaScript 互操作。

**JavaScript 示例 (与字符串功能相关):**

```javascript
// 假设在 WebAssembly 模块中定义了一个函数，它使用了这里实现的字符串操作

// 模拟 WebAssembly 模块的导入
const wasmModule = {
  instance: {
    exports: {
      // 假设这个函数接收一个字符串并返回其哈希值
      getStringHash: (wasmStringPtr, wasmStringLength) => {
        // 在实际的 Wasm 实现中，这里会调用 Wasm 的字符串哈希函数
        // 这里只是一个模拟
        const wasmString = getStringFromWasmMemory(wasmStringPtr, wasmStringLength);
        let hash = 0;
        for (let i = 0; i < wasmString.length; i++) {
          const char = wasmString.charCodeAt(i);
          hash = ((hash << 5) - hash) + char;
          hash = hash & hash; // Convert to 32bit integer
        }
        return hash;
      },

      // 假设这个函数比较两个字符串
      compareStrings: (wasmStringPtr1, wasmStringLength1, wasmStringPtr2, wasmStringLength2) => {
        const str1 = getStringFromWasmMemory(wasmStringPtr1, wasmStringLength1);
        const str2 = getStringFromWasmMemory(wasmStringPtr2, wasmStringLength2);
        if (str1 < str2) return -1;
        if (str1 > str2) return 1;
        return 0;
      }
    }
  }
};

// 辅助函数，从 Wasm 内存中读取字符串 (简化)
function getStringFromWasmMemory(ptr, length) {
  // 这在真实的 Wasm 集成中会涉及访问 WebAssembly 的线性内存
  // 这里只是一个占位符
  console.log(`模拟从 Wasm 内存读取字符串，指针: ${ptr}, 长度: ${length}`);
  return "example";
}

const jsString = "hello";
const jsString2 = "world";

// 模拟将 JavaScript 字符串传递给 WebAssembly
const wasmStringPtr = 100; // 假设的 Wasm 内存地址
const wasmStringLength = jsString.length;

const wasmStringPtr2 = 200;
const wasmStringLength2 = jsString2.length;

// 调用 WebAssembly 函数
const hash = wasmModule.instance.exports.getStringHash(wasmStringPtr, wasmStringLength);
console.log(`Wasm 字符串哈希值: ${hash}`);

const comparisonResult = wasmModule.instance.exports.compareStrings(wasmStringPtr, wasmStringLength, wasmStringPtr2, wasmStringLength2);
console.log(`字符串比较结果: ${comparisonResult}`);
```

**代码逻辑推理 (以 `StringCompare` 为例):**

**假设输入:**

* `decoder`: 一个 `FullDecoder` 对象，用于解码 WebAssembly 指令。
* `lhs`: 一个 `Value` 对象，代表要比较的左侧字符串。假设其内部 `op` 字段是一个指向 V8 `String` 对象的指针。
* `rhs`: 一个 `Value` 对象，代表要比较的右侧字符串。假设其内部 `op` 字段也是一个指向 V8 `String` 对象的指针。
* `result`: 一个指向 `Value` 的指针，用于存储比较结果。

**输出:**

* `result` 指向的 `Value` 对象的 `op` 字段将被设置为一个表示比较结果的 Turboshaft 图节点。这个节点的值类型可能是 `int32`，表示比较的结果 (-1, 0, 或 1)。

**代码逻辑:**

1. `V<String> lhs_val = V<String>::Cast(NullCheck(lhs));`:  将输入的 `lhs` 值转换为 Turboshaft 的 `V<String>` 类型，并进行空值检查。
2. `V<String> rhs_val = V<String>::Cast(NullCheck(rhs));`: 将输入的 `rhs` 值转换为 Turboshaft 的 `V<String>` 类型，并进行空值检查。
3. `result->op = __ UntagSmi(...)`:  调用内置的字符串比较函数。
    * `CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringCompare>(decoder, {lhs_val, rhs_val})`:  通过跳转表调用名为 `StringCompare` 的内置函数，并将左右两个字符串作为参数传递。这个内置函数会执行实际的字符串比较，并返回一个 Smi (Small Integer) 表示的比较结果。
    * `__ UntagSmi(...)`:  将返回的 Smi 值解包成原始的整数值。
4. 最终，比较结果的 Turboshaft 图节点被赋值给 `result->op`。

**用户常见的编程错误 (可能与此处功能相关):**

* **空指针解引用:** 在 WebAssembly 中处理字符串时，如果字符串指针或字符串视图为空，尝试访问其内容会导致错误。代码中的 `NullCheck` 函数就是为了预防这种错误。
* **类型不匹配:** 将非字符串类型的数据错误地当作字符串处理。
* **越界访问:**  在使用字符串视图的迭代器时，如果迭代器超出字符串的范围，可能会导致错误。
* **字符串编码问题:**  WebAssembly 字符串可能使用不同的编码 (UTF-8, UTF-16)，如果编码处理不当，会导致乱码或比较错误。
* **内存管理错误:**  在与 WebAssembly 模块共享内存时，如果 JavaScript 代码不正确地分配或释放内存，可能会导致错误。

**示例 (空指针解引用，虽然此处代码有 `NullCheck` 防御):**

```javascript
// 假设一个错误的 WebAssembly 模块尝试传递一个空指针作为字符串
const wasmModuleWithError = {
  instance: {
    exports: {
      getStringLength: (wasmStringPtr, wasmStringLength) => {
        // 错误：假设 wasmStringPtr 是 0 (空指针)
        // 尝试访问空指针指向的内存
        // ... (这会导致错误，但在 C++ 代码中会被 `NullCheck` 捕获)
        return wasmStringLength;
      }
    }
  }
};

try {
  wasmModuleWithError.instance.exports.getStringLength(0, 10);
} catch (error) {
  console.error("发生错误:", error); // 可能会捕获到类似于内存访问错误的异常
}
```

**作为第 8 部分的功能总结:**

作为 Turboshaft 编译流程的第 8 部分，这个文件主要负责将 WebAssembly 中涉及到基本操作（如加载、存储、算术运算、比较、控制流）以及特定领域操作（如字符串处理）的指令，转换成 Turboshaft 编译器内部的图形表示。这个图形表示是后续优化和代码生成的基础。  这个阶段至关重要，因为它确保了 WebAssembly 的语义被正确地翻译到编译器的中间表示中。 尤其是在字符串处理方面，这个文件提供了连接 Wasm 语义和 V8 内部高性能字符串操作的桥梁。

Prompt: 
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第8部分，共12部分，请归纳一下它的功能

"""
= V<String>::Cast(NullCheck(str));
    V<WasmStringViewIter> result_value =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringAsIter>(
            decoder, {string});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringViewIterNext(FullDecoder* decoder, const Value& view,
                          Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterNext>(decoder, {iter});
  }

  void StringViewIterAdvance(FullDecoder* decoder, const Value& view,
                             const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterAdvance>(
        decoder, {iter, codepoints.op});
  }

  void StringViewIterRewind(FullDecoder* decoder, const Value& view,
                            const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    result->op = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterRewind>(decoder,
                                                         {iter, codepoints.op});
  }

  void StringViewIterSlice(FullDecoder* decoder, const Value& view,
                           const Value& codepoints, Value* result) {
    V<WasmStringViewIter> iter = V<WasmStringViewIter>::Cast(NullCheck(view));
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringViewIterSlice>(decoder,
                                                        {iter, codepoints.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringCompare(FullDecoder* decoder, const Value& lhs, const Value& rhs,
                     Value* result) {
    V<String> lhs_val = V<String>::Cast(NullCheck(lhs));
    V<String> rhs_val = V<String>::Cast(NullCheck(rhs));
    result->op = __ UntagSmi(
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::StringCompare>(
            decoder, {lhs_val, rhs_val}));
  }

  void StringFromCodePoint(FullDecoder* decoder, const Value& code_point,
                           Value* result) {
    V<String> result_value = CallBuiltinThroughJumptable<
        BuiltinCallDescriptor::WasmStringFromCodePoint>(decoder,
                                                        {code_point.op});
    result->op = __ AnnotateWasmType(result_value, result->type);
  }

  void StringHash(FullDecoder* decoder, const Value& string, Value* result) {
    V<String> string_val = V<String>::Cast(NullCheck(string));

    Label<> runtime_label(&Asm());
    Label<Word32> end_label(&Asm());

    V<Word32> raw_hash = __ template LoadField<Word32>(
        string_val, compiler::AccessBuilder::ForNameRawHashField());
    V<Word32> hash_not_computed_mask =
        __ Word32Constant(static_cast<int32_t>(Name::kHashNotComputedMask));
    static_assert(Name::HashFieldTypeBits::kShift == 0);
    V<Word32> hash_not_computed =
        __ Word32BitwiseAnd(raw_hash, hash_not_computed_mask);
    GOTO_IF(hash_not_computed, runtime_label);

    // Fast path if hash is already computed: Decode raw hash value.
    static_assert(Name::HashBits::kLastUsedBit == kBitsPerInt - 1);
    V<Word32> hash = __ Word32ShiftRightLogical(
        raw_hash, static_cast<int32_t>(Name::HashBits::kShift));
    GOTO(end_label, hash);

    BIND(runtime_label);
    V<Word32> hash_runtime =
        CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmStringHash>(
            decoder, {string_val});
    GOTO(end_label, hash_runtime);

    BIND(end_label, hash_val);
    result->op = hash_val;
  }

  void Forward(FullDecoder* decoder, const Value& from, Value* to) {
    to->op = from.op;
  }

 private:
  // The InstanceCache caches commonly used fields of the
  // WasmTrustedInstanceData.
  // We can extend the set of cached fields as needed.
  // This caching serves two purposes:
  // (1) It makes sure that the respective fields are loaded early on, as
  //     opposed to within conditional branches, so the values are easily
  //     reusable.
  // (2) It makes sure that the loaded values are actually reused.
  // It achieves these effects more reliably and more cheaply than general-
  // purpose optimizations could (loop peeling isn't always used; load
  // elimination struggles with arbitrary side effects of indexed stores;
  // we don't currently have a generic mechanism for hoisting loads out of
  // conditional branches).
  class InstanceCache {
   public:
    explicit InstanceCache(Assembler& assembler)
        : mem_start_(assembler), mem_size_(assembler), asm_(assembler) {}

    void Initialize(V<WasmTrustedInstanceData> trusted_instance_data,
                    const WasmModule* mod) {
      DCHECK(!trusted_data_.valid());  // Only call {Initialize()} once.
      trusted_data_ = trusted_instance_data;
      managed_object_maps_ =
          __ Load(trusted_instance_data, LoadOp::Kind::TaggedBase().Immutable(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmTrustedInstanceData::kManagedObjectMapsOffset);
      native_context_ =
          __ Load(trusted_instance_data, LoadOp::Kind::TaggedBase().Immutable(),
                  MemoryRepresentation::TaggedPointer(),
                  WasmTrustedInstanceData::kNativeContextOffset);

      if (!mod->memories.empty()) {
#if DEBUG
        has_memory_ = true;
#endif
        const WasmMemory& mem = mod->memories[0];
        memory_can_grow_ = mem.initial_pages != mem.maximum_pages;
        // For now, we don't cache the size of shared growable memories.
        // If we wanted to support this case, we would have to reload the
        // memory size when loop stack checks detect an interrupt request.
        // Since memory size caching is particularly important for asm.js,
        // which never uses growable or shared memories, this limitation is
        // considered acceptable for now.
        memory_size_cached_ = !mem.is_shared || !memory_can_grow_;
        // Trap handler enabled memories never move.
        // Memories that can't grow have no reason to move.
        // Shared memories can only be grown in-place.
        memory_can_move_ = mem.bounds_checks != kTrapHandler &&
                           memory_can_grow_ && !mem.is_shared;
        memory_is_shared_ = mem.is_shared;
        if (memory_size_cached_) {
          mem_size_ = LoadMemSize();
        }
        mem_start_ = LoadMemStart();
      }
    }

    // TODO(14108): Port the dynamic "cached_memory_index" infrastructure
    // from Turbofan.
    void ReloadCachedMemory() {
      if (memory_can_move()) mem_start_ = LoadMemStart();
      if (memory_can_grow_ && memory_size_cached_) mem_size_ = LoadMemSize();
    }

    V<WasmTrustedInstanceData> trusted_instance_data() { return trusted_data_; }
    V<FixedArray> managed_object_maps() { return managed_object_maps_; }
    V<NativeContext> native_context() { return native_context_; }
    V<WordPtr> memory0_start() {
      DCHECK(has_memory_);
      return mem_start_;
    }
    V<WordPtr> memory0_size() {
      DCHECK(has_memory_);
      if (!memory_size_cached_) return LoadMemSize();
      return mem_size_;
    }

   private:
    static constexpr uint8_t kUnused = ~uint8_t{0};

    V<WordPtr> LoadMemStart() {
      DCHECK(has_memory_);
      // In contrast to memory size loads, we can mark memory start loads as
      // eliminable: shared memories never move, and non-shared memories can't
      // have their start modified by other threads.
      LoadOp::Kind kind = LoadOp::Kind::TaggedBase();
      if (!memory_can_move()) kind = kind.Immutable();
      return __ Load(trusted_data_, kind, MemoryRepresentation::UintPtr(),
                     WasmTrustedInstanceData::kMemory0StartOffset);
    }

    V<WordPtr> LoadMemSize() {
      DCHECK(has_memory_);
      LoadOp::Kind kind = LoadOp::Kind::TaggedBase();
      if (memory_is_shared_ && memory_can_grow_) {
        // Memory size loads should not be load-eliminated as the memory size
        // can be modified by another thread.
        kind = kind.NotLoadEliminable();
      }
      if (!memory_can_grow_) kind = kind.Immutable();
      return __ Load(trusted_data_, kind, MemoryRepresentation::UintPtr(),
                     WasmTrustedInstanceData::kMemory0SizeOffset);
    }

    bool memory_can_move() { return memory_can_move_; }

    // For compatibility with `__` macro.
    Assembler& Asm() { return asm_; }

    // Cached immutable fields (need no Phi nodes):
    V<WasmTrustedInstanceData> trusted_data_;
    V<FixedArray> managed_object_maps_;
    V<NativeContext> native_context_;

    // Cached mutable fields:
    ScopedVar<WordPtr> mem_start_;
    ScopedVar<WordPtr> mem_size_;

    // Other fields for internal usage.
    Assembler& asm_;
    bool memory_is_shared_{false};
    bool memory_can_grow_{false};
    bool memory_can_move_{false};
    bool memory_size_cached_{false};
#if DEBUG
    bool has_memory_{false};
#endif
  };

  enum class CheckForException { kNo, kCatchInThisFrame, kCatchInParentFrame };

 private:
  // Holds phi inputs for a specific block. These include SSA values, stack
  // merge values, and cached fields from the instance..
  // Conceptually, this is a two-dimensional, rectangular array of size
  // `phi_count * inputs_per_phi`, since each phi has the same number of inputs,
  // namely the number of incoming edges for this block.
  class BlockPhis {
   public:
    // Ctor for regular blocks.
    V8_INLINE BlockPhis(FullDecoder* decoder, Merge<Value>* merge)
        : incoming_exceptions_(decoder -> zone()) {
      // Allocate space and initialize the types of all phis.
      uint32_t num_locals = decoder->num_locals();
      uint32_t merge_arity = merge != nullptr ? merge->arity : 0;

      phi_count_ = num_locals + merge_arity;
      phi_types_ = decoder->zone()->AllocateArray<ValueType>(phi_count_);

      base::Vector<ValueType> locals = decoder->local_types();
      std::uninitialized_copy(locals.begin(), locals.end(), phi_types_);
      for (uint32_t i = 0; i < merge_arity; i++) {
        new (&phi_types_[num_locals + i]) ValueType((*merge)[i].type);
      }
      AllocatePhiInputs(decoder->zone());
    }

    // Consider this "private"; it's next to the constructors (where it's
    // called) for context.
    void AllocatePhiInputs(Zone* zone) {
      // Only reserve some space for the inputs to be added later.
      phi_inputs_capacity_total_ = phi_count_ * input_capacity_per_phi_;
      phi_inputs_ = zone->AllocateArray<OpIndex>(phi_inputs_capacity_total_);

#ifdef DEBUG
      constexpr uint32_t kNoInputs = 0;
      input_count_per_phi_ = std::vector(phi_count_, kNoInputs);
#endif
    }

    // Default ctor and later initialization for function returns.
    explicit BlockPhis(Zone* zone) : incoming_exceptions_(zone) {}
    void InitReturnPhis(base::Vector<const ValueType> return_types) {
      // For `return_phis_`, nobody should have inserted into `this` before
      // calling `InitReturnPhis`.
      DCHECK_EQ(phi_count_, 0);
      DCHECK_EQ(inputs_per_phi_, 0);

      uint32_t return_count = static_cast<uint32_t>(return_types.size());
      phi_count_ = return_count;
      phi_types_ = zone()->AllocateArray<ValueType>(phi_count_);

      std::uninitialized_copy(return_types.begin(), return_types.end(),
                              phi_types_);
      AllocatePhiInputs(zone());
    }

    void AddInputForPhi(size_t phi_i, OpIndex input) {
      if (V8_UNLIKELY(phi_inputs_total_ >= phi_inputs_capacity_total_)) {
        GrowInputsVector();
      }

#ifdef DEBUG
      // We rely on adding inputs in the order of phis, i.e.,
      // `AddInputForPhi(0, ...); AddInputForPhi(1, ...); ...`.
      size_t phi_inputs_start = phi_i * input_capacity_per_phi_;
      size_t phi_input_offset_from_start = inputs_per_phi_;
      CHECK_EQ(input_count_per_phi_[phi_i]++, phi_input_offset_from_start);
      size_t phi_input_offset = phi_inputs_start + phi_input_offset_from_start;
      CHECK_EQ(next_phi_input_add_offset_, phi_input_offset);
#endif
      new (&phi_inputs_[next_phi_input_add_offset_]) OpIndex(input);

      phi_inputs_total_++;
      next_phi_input_add_offset_ += input_capacity_per_phi_;
      if (next_phi_input_add_offset_ >= phi_inputs_capacity_total_) {
        // We have finished adding the last input for all phis.
        inputs_per_phi_++;
        next_phi_input_add_offset_ = inputs_per_phi_;
#ifdef DEBUG
        EnsureAllPhisHaveSameInputCount();
#endif
      }
    }

    uint32_t phi_count() const { return phi_count_; }

    ValueType phi_type(size_t phi_i) const { return phi_types_[phi_i]; }

    base::Vector<const OpIndex> phi_inputs(size_t phi_i) const {
      size_t phi_inputs_start = phi_i * input_capacity_per_phi_;
      return base::VectorOf(&phi_inputs_[phi_inputs_start], inputs_per_phi_);
    }

    void AddIncomingException(OpIndex exception) {
      incoming_exceptions_.push_back(exception);
    }

    base::Vector<const OpIndex> incoming_exceptions() const {
      return base::VectorOf(incoming_exceptions_);
    }

#if DEBUG
    void DcheckConsistency() { EnsureAllPhisHaveSameInputCount(); }
#endif

   private:
    // Invariants:
    // The number of phis for a given block (e.g., locals, merged stack values,
    // and cached instance fields) is known when constructing the `BlockPhis`
    // and doesn't grow afterwards.
    // The number of _inputs_ for each phi is however _not_ yet known when
    // constructing this, but grows over time as new incoming edges for a given
    // block are created.
    // After such an edge is created, each phi has the same number of inputs.
    // When eventually creating a phi, we also need all inputs layed out
    // contiguously.
    // Due to those requirements, we write our own little container, see below.

    // First the backing storage:
    // Of size `phi_count_`, one type per phi.
    ValueType* phi_types_ = nullptr;
    // Of size `phi_inputs_capacity_total_ == phi_count_ *
    // input_capacity_per_phi_`, of which `phi_inputs_total_ == phi_count_ *
    // inputs_per_phi_` are set/initialized. All inputs for a given phi are
    // stored contiguously, but between them are uninitialized elements for
    // adding new inputs without reallocating.
    OpIndex* phi_inputs_ = nullptr;

    // Stored explicitly to save multiplications in the hot `AddInputForPhi()`.
    // Also pulled up to be in the same cache-line as `phi_inputs_`.
    uint32_t phi_inputs_capacity_total_ = 0;  // Updated with `phi_inputs_`.
    uint32_t phi_inputs_total_ = 0;
    uint32_t next_phi_input_add_offset_ = 0;

    // The dimensions.
    uint32_t phi_count_ = 0;
    uint32_t inputs_per_phi_ = 0;
    static constexpr uint32_t kInitialInputCapacityPerPhi = 2;
    uint32_t input_capacity_per_phi_ = kInitialInputCapacityPerPhi;

#ifdef DEBUG
    std::vector<uint32_t> input_count_per_phi_;
    void EnsureAllPhisHaveSameInputCount() const {
      CHECK_EQ(phi_inputs_total_, phi_count() * inputs_per_phi_);
      CHECK_EQ(phi_count(), input_count_per_phi_.size());
      CHECK(std::all_of(input_count_per_phi_.begin(),
                        input_count_per_phi_.end(),
                        [=, this](uint32_t input_count) {
                          return input_count == inputs_per_phi_;
                        }));
    }
#endif

    // The number of `incoming_exceptions` is also not known when constructing
    // the block, but at least it is only one-dimensional, so we can use a
    // simple `ZoneVector`.
    ZoneVector<OpIndex> incoming_exceptions_;

    Zone* zone() { return incoming_exceptions_.zone(); }

    V8_NOINLINE V8_PRESERVE_MOST void GrowInputsVector() {
      // We should have always initialized some storage, see
      // `kInitialInputCapacityPerPhi`.
      DCHECK_NOT_NULL(phi_inputs_);
      DCHECK_NE(phi_inputs_capacity_total_, 0);

      OpIndex* old_phi_inputs = phi_inputs_;
      uint32_t old_input_capacity_per_phi = input_capacity_per_phi_;
      uint32_t old_phi_inputs_capacity_total = phi_inputs_capacity_total_;

      input_capacity_per_phi_ *= 2;
      phi_inputs_capacity_total_ *= 2;
      phi_inputs_ = zone()->AllocateArray<OpIndex>(phi_inputs_capacity_total_);

      // This is essentially a strided copy, where we expand the storage by
      // "inserting" unitialized elements in between contiguous stretches of
      // inputs belonging to the same phi.
#ifdef DEBUG
      EnsureAllPhisHaveSameInputCount();
#endif
      for (size_t phi_i = 0; phi_i < phi_count(); ++phi_i) {
        const OpIndex* old_begin =
            &old_phi_inputs[phi_i * old_input_capacity_per_phi];
        const OpIndex* old_end = old_begin + inputs_per_phi_;
        OpIndex* begin = &phi_inputs_[phi_i * input_capacity_per_phi_];
        std::uninitialized_copy(old_begin, old_end, begin);
      }

      zone()->DeleteArray(old_phi_inputs, old_phi_inputs_capacity_total);
    }
  };

  // Perform a null check if the input type is nullable.
  V<Object> NullCheck(const Value& value,
                      TrapId trap_id = TrapId::kTrapNullDereference) {
    V<Object> not_null_value = V<Object>::Cast(value.op);
    if (value.type.is_nullable()) {
      not_null_value = __ AssertNotNull(value.op, value.type, trap_id);
    }
    return not_null_value;
  }

  // Creates a new block, initializes a {BlockPhis} for it, and registers it
  // with block_phis_. We pass a {merge} only if we later need to recover values
  // for that merge.
  TSBlock* NewBlockWithPhis(FullDecoder* decoder, Merge<Value>* merge) {
    TSBlock* block = __ NewBlock();
    block_phis_.emplace(block, BlockPhis(decoder, merge));
    return block;
  }

  // Sets up a control flow edge from the current SSA environment and a stack to
  // {block}. The stack is {stack_values} if present, otherwise the current
  // decoder stack.
  void SetupControlFlowEdge(FullDecoder* decoder, TSBlock* block,
                            uint32_t drop_values = 0,
                            V<Object> exception = OpIndex::Invalid(),
                            Merge<Value>* stack_values = nullptr) {
    if (__ current_block() == nullptr) return;
    // It is guaranteed that this element exists.
    DCHECK_NE(block_phis_.find(block), block_phis_.end());
    BlockPhis& phis_for_block = block_phis_.find(block)->second;
    uint32_t merge_arity = static_cast<uint32_t>(phis_for_block.phi_count()) -
                           decoder->num_locals();

    for (size_t i = 0; i < ssa_env_.size(); i++) {
      phis_for_block.AddInputForPhi(i, ssa_env_[i]);
    }
    // We never drop values from an explicit merge.
    DCHECK_IMPLIES(stack_values != nullptr, drop_values == 0);
    Value* stack_base = merge_arity == 0 ? nullptr
                        : stack_values != nullptr
                            ? &(*stack_values)[0]
                            : decoder->stack_value(merge_arity + drop_values);
    for (size_t i = 0; i < merge_arity; i++) {
      DCHECK(stack_base[i].op.valid());
      phis_for_block.AddInputForPhi(decoder->num_locals() + i,
                                    stack_base[i].op);
    }
    if (exception.valid()) {
      phis_for_block.AddIncomingException(exception);
    }
  }

  OpIndex MaybePhi(base::Vector<const OpIndex> elements, ValueType type) {
    if (elements.empty()) return OpIndex::Invalid();
    for (size_t i = 1; i < elements.size(); i++) {
      if (elements[i] != elements[0]) {
        return __ Phi(elements, RepresentationFor(type));
      }
    }
    return elements[0];
  }

  // Binds a block, initializes phis for its SSA environment from its entry in
  // {block_phis_}, and sets values to its {merge} (if available) from the
  // its entry in {block_phis_}.
  void BindBlockAndGeneratePhis(FullDecoder* decoder, TSBlock* tsblock,
                                Merge<Value>* merge,
                                OpIndex* exception = nullptr) {
    __ Bind(tsblock);
    auto block_phis_it = block_phis_.find(tsblock);
    DCHECK_NE(block_phis_it, block_phis_.end());
    BlockPhis& block_phis = block_phis_it->second;

    uint32_t merge_arity = merge != nullptr ? merge->arity : 0;
    DCHECK_EQ(decoder->num_locals() + merge_arity, block_phis.phi_count());

#ifdef DEBUG
    // Check consistency of Phi storage. We do this here rather than inside
    // {block_phis.phi_inputs()} to avoid overall O(n²) complexity.
    block_phis.DcheckConsistency();
#endif

    for (uint32_t i = 0; i < decoder->num_locals(); i++) {
      ssa_env_[i] = MaybePhi(block_phis.phi_inputs(i), block_phis.phi_type(i));
    }
    for (uint32_t i = 0; i < merge_arity; i++) {
      uint32_t phi_index = decoder->num_locals() + i;
      (*merge)[i].op = MaybePhi(block_phis.phi_inputs(phi_index),
                                block_phis.phi_type(phi_index));
    }
    DCHECK_IMPLIES(exception == nullptr,
                   block_phis.incoming_exceptions().empty());
    if (exception != nullptr && !exception->valid()) {
      *exception = MaybePhi(block_phis.incoming_exceptions(), kWasmExternRef);
    }
    block_phis_.erase(block_phis_it);
  }

  V<Any> DefaultValue(ValueType type) {
    switch (type.kind()) {
      case kI8:
      case kI16:
      case kI32:
        return __ Word32Constant(int32_t{0});
      case kI64:
        return __ Word64Constant(int64_t{0});
      case kF16:
      case kF32:
        return __ Float32Constant(0.0f);
      case kF64:
        return __ Float64Constant(0.0);
      case kRefNull:
        return __ Null(type);
      case kS128: {
        uint8_t value[kSimd128Size] = {};
        return __ Simd128Constant(value);
      }
      case kVoid:
      case kRtt:
      case kRef:
      case kTop:
      case kBottom:
        UNREACHABLE();
    }
  }

 private:
  V<FrameState> CreateFrameState(FullDecoder* decoder,
                                 const FunctionSig* callee_sig,
                                 const Value* func_ref_or_index,
                                 const Value args[]) {
    compiler::turboshaft::FrameStateData::Builder builder;
    if (parent_frame_state_.valid()) {
      builder.AddParentFrameState(parent_frame_state_.value());
    }
    // The first input is the closure for JS. (The instruction selector will
    // just skip this input as the liftoff frame doesn't have a closure.)
    V<Object> dummy_tagged = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), dummy_tagged);
    // Add the parameters.
    size_t param_count = decoder->sig_->parameter_count();
    for (size_t i = 0; i < param_count; ++i) {
      builder.AddInput(decoder->sig_->GetParam(i).machine_type(), ssa_env_[i]);
    }
    // Add the context. Wasm doesn't have a JS context, so this is another
    // value skipped by the instruction selector.
    builder.AddInput(MachineType::AnyTagged(), dummy_tagged);

    // Add the wasm locals.
    for (size_t i = param_count; i < ssa_env_.size(); ++i) {
      builder.AddInput(
          decoder->local_type(static_cast<uint32_t>(i)).machine_type(),
          ssa_env_[i]);
    }
    // Add the wasm stack values.
    // Note that the decoder stack is already in the state after the call, i.e.
    // the callee and the arguments were already popped from the stack and the
    // returns are pushed. Therefore skip the results and manually add the
    // call_ref stack values.
    for (int32_t i = decoder->stack_size();
         i > static_cast<int32_t>(callee_sig->return_count()); --i) {
      Value* val = decoder->stack_value(i);
      builder.AddInput(val->type.machine_type(), val->op);
    }
    // Add the call_ref or call_indirect stack values.
    if (args != nullptr) {
      for (const Value& arg :
           base::VectorOf(args, callee_sig->parameter_count())) {
        builder.AddInput(arg.type.machine_type(), arg.op);
      }
    }
    if (func_ref_or_index) {
      builder.AddInput(func_ref_or_index->type.machine_type(),
                       func_ref_or_index->op);
    }
    // The call_ref (callee) or the table index.
    const size_t kExtraLocals = func_ref_or_index != nullptr ? 1 : 0;
    size_t wasm_local_count = ssa_env_.size() - param_count;
    size_t local_count = kExtraLocals + decoder->stack_size() +
                         wasm_local_count - callee_sig->return_count();
    local_count += args != nullptr ? callee_sig->parameter_count() : 0;
    Handle<SharedFunctionInfo> shared_info;
    Zone* zone = Asm().data()->compilation_zone();
    auto* function_info = zone->New<compiler::FrameStateFunctionInfo>(
        compiler::FrameStateType::kLiftoffFunction,
        static_cast<uint16_t>(param_count), 0, static_cast<int>(local_count),
        shared_info, kNullMaybeHandle, GetLiftoffFrameSize(decoder),
        func_index_);
    auto* frame_state_info = zone->New<compiler::FrameStateInfo>(
        BytecodeOffset(decoder->pc_offset()),
        compiler::OutputFrameStateCombine::Ignore(), function_info);

    // TODO(mliedtke): For compile-time and memory reasons (huge deopt data), it
    // might be beneficial to limit this to an arbitrary lower value.
    size_t max_input_count =
        std::numeric_limits<decltype(Operation::input_count)>::max();
    // Int64 lowering might double the input count.
    if (!Is64()) max_input_count /= 2;
    if (builder.Inputs().size() >= max_input_count) {
      // If there are too many inputs, we cannot create a valid FrameState.
      // For simplicity reasons disable deopts completely for the rest of the
      // function. (Note that this is an exceptional case that should not be
      // relevant for any real-world application.)
      deopts_enabled_ = false;
      return OpIndex::Invalid();
    }

    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, zone));
  }

  void DeoptIfNot(FullDecoder* decoder, OpIndex deopt_condition,
                  V<FrameState> frame_state) {
    CHECK(deopts_enabled_);
    DCHECK(frame_state.valid());
    __ DeoptimizeIfNot(deopt_condition, frame_state,
                       DeoptimizeReason::kWrongCallTarget,
                       compiler::FeedbackSource());
  }

  void Deopt(FullDecoder* decoder, V<FrameState> frame_state) {
    CHECK(deopts_enabled_);
    DCHECK(frame_state.valid());
    __ Deoptimize(frame_state, DeoptimizeReason::kWrongCallTarget,
                  compiler::FeedbackSource());
  }

  uint32_t GetLiftoffFrameSize(const FullDecoder* decoder) {
    if (liftoff_frame_size_ !=
        FunctionTypeFeedback::kUninitializedLiftoffFrameSize) {
      return liftoff_frame_size_;
    }
    const TypeFeedbackStorage& feedback = decoder->module_->type_feedback;
    base::SharedMutexGuard<base::kShared> mutex_guard(&feedback.mutex);
    auto function_feedback = feedback.feedback_for_function.find(func_index_);
    CHECK_NE(function_feedback, feedback.feedback_for_function.end());
    liftoff_frame_size_ = function_feedback->second.liftoff_frame_size;
    // The liftoff frame size is strictly required. If it is not properly set,
    // calling the function embedding the deopt node will always fail on the
    // stack check.
    CHECK_NE(liftoff_frame_size_,
             FunctionTypeFeedback::kUninitializedLiftoffFrameSize);
    return liftoff_frame_size_;
  }

  V<Word64> ExtractTruncationProjections(V<Tuple<Word64, Word32>> truncated) {
    V<Word64> result = __ template Projection<0>(truncated);
    V<Word32> check = __ template Projection<1>(truncated);
    __ TrapIf(__ Word32Equal(check, 0), TrapId::kTrapFloatUnrepresentable);
    return result;
  }

  std::pair<OpIndex, V<Word32>> BuildCCallForFloatConversion(
      OpIndex arg, MemoryRepresentation float_type,
      ExternalReference ccall_ref) {
    uint8_t slot_size = MemoryRepresentation::Int64().SizeInBytes();
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, arg, StoreOp::Kind::RawAligned(), float_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, reps);
    V<Word32> overflow = CallC(&sig, ccall_ref, stack_slot);
    return {stack_slot, overflow};
  }

  OpIndex BuildCcallConvertFloat(OpIndex arg, MemoryRepresentation float_type,
                                 ExternalReference ccall_ref) {
    auto [stack_slot, overflow] =
        BuildCCallForFloatConversion(arg, float_type, ccall_ref);
    __ TrapIf(__ Word32Equal(overflow, 0),
              compiler::TrapId::kTrapFloatUnrepresentable);
    MemoryRepresentation int64 = MemoryRepresentation::Int64();
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64);
  }

  OpIndex BuildCcallConvertFloatSat(OpIndex arg,
                                    MemoryRepresentation float_type,
                                    ExternalReference ccall_ref,
                                    bool is_signed) {
    MemoryRepresentation int64 = MemoryRepresentation::Int64();
    uint8_t slot_size = int64.SizeInBytes();
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, arg, StoreOp::Kind::RawAligned(), float_type,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ccall_ref, stack_slot);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64);
  }

  OpIndex BuildIntToFloatConversionInstruction(
      OpIndex input, ExternalReference ccall_ref,
      MemoryRepresentation input_representation,
      MemoryRepresentation result_representation) {
    uint8_t slot_size = std::max(input_representation.SizeInBytes(),
                                 result_representation.SizeInBytes());
    V<WordPtr> stack_slot = __ StackSlot(slot_size, slot_size);
    __ Store(stack_slot, input, StoreOp::Kind::RawAligned(),
             input_representation, compiler::WriteBarrierKind::kNoWriteBarrier);
    MachineType reps[]{MachineType::Pointer()};
    MachineSignature sig(0, 1, reps);
    CallC(&sig, ccall_ref, stack_slot);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(),
                   result_representation);
  }

  OpIndex BuildDiv64Call(OpIndex lhs, OpIndex rhs, ExternalReference ccall_ref,
                         wasm::TrapId trap_zero) {
    MemoryRepresentation int64_rep = MemoryRepresentation::Int64();
    V<WordPtr> stack_slot =
        __ StackSlot(2 * int64_rep.SizeInBytes(), int64_rep.SizeInBytes());
    __ Store(stack_slot, lhs, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier);
    __ Store(stack_slot, rhs, StoreOp::Kind::RawAligned(), int64_rep,
             compiler::WriteBarrierKind::kNoWriteBarrier,
             int64_rep.SizeInBytes());

    MachineType sig_types[] = {MachineType::Int32(), MachineType::Pointer()};
    MachineSignature sig(1, 1, sig_types);
    OpIndex rc = CallC(&sig, ccall_ref, stack_slot);
    __ TrapIf(__ Word32Equal(rc, 0), trap_zero);
    __ TrapIf(__ Word32Equal(rc, -1), TrapId::kTrapDivUnrepresentable);
    return __ Load(stack_slot, LoadOp::Kind::RawAligned(), int64_rep);
  }

  OpIndex UnOpImpl(WasmOpcode opcode, OpIndex arg,
                   ValueType input_type /* for ref.is_null only*/) {
    switch (opcode) {
      case kExprI32Eqz:
        return __ Word32Equal(arg, 0);
      case kExprF32Abs:
        return __ Float32Abs(arg);
      case kExprF32Neg:
        return __ Float32Negate(arg);
      case kExprF32Sqrt:
        return __ Float32Sqrt(arg);
      case kExprF64Abs:
        return __ Float64Abs(arg);
      case kExprF64Neg:
        return __ Float64Negate(arg);
      case kExprF64Sqrt:
        return __ Float64Sqrt(arg);
      case kExprI32SConvertF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> result = __ TruncateFloat32ToInt32OverflowToMin(truncated);
        V<Float32> converted_back = __ ChangeInt32ToFloat32(result);
        __ TrapIf(__ Word32Equal(__ Float32Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatUnrepresentable);
        return result;
      }
      case kExprI32UConvertF32: {
        V<Float32> truncated = UnOpImpl(kExprF32Trunc, arg, kWasmF32);
        V<Word32> result = __ TruncateFloat32ToUint32OverflowToMin(truncated);
        V<Float32> converted_back = __ ChangeUint32ToFloat32(result);
        __ TrapIf(__ Word32Equal(__ Float32Equal(converted_back, truncated), 0),
                  TrapId::kTrapFloatU
"""


```
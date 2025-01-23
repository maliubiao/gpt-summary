Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided C++ code snippet from `v8/src/wasm/fuzzing/random-module-generation.cc`. The prompt specifically asks for a function summary, checks for Torque, relates it to JavaScript (if applicable), asks for logic inference with examples, identifies common programming errors, and summarizes the functionality of *this specific part* (part 3 of 7).

2. **Initial Scan for Keywords and Structure:** I'll quickly scan the code for important keywords and structural elements:
    * Class name: `BodyGen`
    * Member variables: `builder_`, `functions_`, `globals_`, `mutable_globals_`, `structs_`, `arrays_`, `string_imports_`, `blocks_`, `locals_`, `recursion_depth`
    * Member functions:  Many functions starting with `Generate`, `op`, `memop`, `struct_`, `ref_`, `call_string_import`, `string_`, and helper functions like `rate`, `top_type`, `choose_sub_type`.
    * Templates:  `GenerateOneOf`, `ref_test`, `op`, `memop`, indicating generic operations.
    * `DCHECK`: Indicates assertions for debugging.
    * `kExpr...`:  Constants likely representing WebAssembly opcodes.

3. **Identify Core Functionality - Random WASM Generation:**  The presence of "fuzzing" in the path and the "random-module-generation" in the filename strongly suggest that this code is responsible for randomly generating WebAssembly code. The numerous `Generate...` functions confirm this.

4. **Analyze Individual Functions/Groups of Functions:**  Now, I'll examine specific functions and try to understand their roles:

    * **`rate<wanted_kind>(data)`:** This seems to be a helper for probabilistic generation. It checks if a random condition is met based on the `wanted_kind`.

    * **`struct_get_ref`, `ref_cast`, `top_type`, `choose_sub_type`:** These functions deal with WebAssembly's reference types (structs, arrays, functions). They help in generating valid casts and retrieving subtypes, indicating type system awareness.

    * **`br_on_cast`:** This function generates WebAssembly's `br_on_cast` and `br_on_cast_fail` instructions, which are related to type checking during branching.

    * **`any_convert_extern`, `ref_as_non_null`:** These handle conversions involving `anyref` and `externref`, and enforcing non-nullability.

    * **`struct_set`:** This generates code to set a field within a struct.

    * **`ref_is_null`, `ref_test`, `ref_eq`:** These generate instructions for checking null references, testing reference types, and comparing references.

    * **`call_string_import`, `string_*` functions:** This block deals with generating calls to imported functions that manipulate strings. This is a strong indication of interaction with JavaScript, as WebAssembly itself has limited native string support.

    * **`GenerateOneOf`:** This is a key function for randomly choosing among different generation strategies. The template overloads allow choosing based on regular functions or functions taking heap types.

    * **`GeneratorRecursionScope`:**  This is a guard to prevent infinite recursion during code generation, which is a crucial part of a fuzzer.

    * **`BodyGen` Constructor:**  This initializes the generator with necessary context like function builder, existing types, globals, and the random data source.

    * **`GenerateVoid`, `GenerateI32`, `GenerateI64`:** These are the main entry points for generating code of specific WebAssembly types. They contain arrays of function pointers representing different ways to generate expressions of that type. The `AppendArrayIf` calls suggest conditional inclusion of features based on compiler flags (like SIMD and WasmGC).

5. **Address Specific Prompt Requirements:**

    * **Functionality:** Summarize the purpose of each function/group.
    * **Torque:**  Check if the filename ends with `.tq`. It doesn't, so it's not Torque.
    * **JavaScript Relation:** The `string_*` functions and `call_string_import` strongly link to JavaScript. Provide examples of how these WebAssembly string operations might be used in JavaScript.
    * **Code Logic Inference:** Choose a function like `br_on_cast` and demonstrate how different inputs (types, nullability) could lead to different output bytecode.
    * **Common Programming Errors:**  Think about the WebAssembly features being generated (e.g., casting, memory access) and how they could lead to errors if not handled correctly in a real-world scenario.
    * **Part 3 Summary:** Combine the individual function summaries into an overall description of what this part of the code is responsible for. Emphasize the focus on generating expressions, particularly those related to references, structs, arrays, and interactions with string imports.

6. **Refine and Structure the Answer:** Organize the findings logically. Start with a high-level overview, then detail individual functionalities, address the specific prompt points, and conclude with the part-specific summary. Use clear and concise language. Provide code examples where requested.

7. **Self-Correction/Review:** Before submitting the answer, review it for accuracy and completeness. Have I addressed all parts of the prompt? Are my explanations clear and easy to understand? Are my code examples correct? For example, I initially might have overlooked the conditional inclusion of SIMD and WasmGC features, but upon closer inspection of the `AppendArrayIf` calls, I'd correct that. I'd also double-check the generated WebAssembly opcodes.
好的，让我们来分析一下 `v8/src/wasm/fuzzing/random-module-generation.cc` 源代码的第 3 部分。

**功能列举:**

这部分代码主要定义了 `BodyGen` 类的一些成员函数，这些函数负责生成 WebAssembly 指令序列，用于构造随机的 WebAssembly 模块。 核心功能集中在生成各种类型的表达式，尤其是涉及到引用类型（`ref`）、结构体（`struct`）、数组（`array`）以及与字符串相关的操作。

以下是各个函数功能的详细说明：

* **`rate<wanted_kind>(data)`:**  这是一个辅助函数，用于根据给定的 `DataRange` 决定是否生成特定类型的指令。它实现了一种概率性的生成机制。

* **`struct_get_ref(HeapType type, DataRange* data, Nullability nullable)`:** 生成从结构体中获取引用类型值的指令。它调用 `struct_get_helper` 并根据可空性设置所需类型。

* **`ref_cast(HeapType type, DataRange* data, Nullability nullable)`:** 生成 WebAssembly 的 `ref.cast` 或 `ref.cast_null` 指令，用于将引用类型转换为指定的类型。

* **`top_type(HeapType type)`:** 返回给定 `HeapType` 的顶层类型。例如，`arrayref` 的顶层类型是 `anyref`， `funcref` 的顶层类型是 `funcref`。

* **`choose_sub_type(HeapType type, DataRange* data)`:**  根据给定的 `HeapType`，随机选择一个它的子类型。这用于生成类型转换相关的指令。

* **`br_on_cast(HeapType type, DataRange* data, Nullability nullable)`:** 生成 `br_on_cast` 或 `br_on_cast_fail` 指令，这些指令用于在类型转换成功或失败时进行条件分支。

* **`any_convert_extern(HeapType type, DataRange* data, Nullability nullable)`:** 生成将 `externref` 转换为 `anyref` 的指令，如果 `nullable` 为 `kNonNullable`，还会附加 `ref.as_non_null`。

* **`ref_as_non_null(HeapType type, DataRange* data, Nullability nullable)`:** 生成 `ref.as_non_null` 指令，将可空的引用类型转换为非空引用类型。

* **`struct_set(DataRange* data)`:** 生成设置结构体字段值的指令 (`struct.set`)。它会随机选择一个可变的字段进行设置。

* **`ref_is_null(DataRange* data)`:** 生成 `ref.is_null` 指令，用于检查引用是否为空。

* **`ref_test<WasmOpcode opcode>(DataRange* data)`:** 生成 `ref.test` 或 `ref.test_null` 指令，用于检查引用是否属于特定类型。

* **`ref_eq(DataRange* data)`:** 生成 `ref.eq` 指令，用于比较两个引用是否相等。

* **`call_string_import(uint32_t index)`:** 生成调用预先导入的字符串操作函数的指令。

* **`string_cast(DataRange* data)`:** 生成调用字符串类型转换导入函数的指令。

* **`string_test(DataRange* data)`:** 生成调用字符串类型测试导入函数的指令。

* **`string_fromcharcode(DataRange* data)`:** 生成调用 `String.fromCharCode` 类似功能的导入函数的指令。

* **`string_fromcodepoint(DataRange* data)`:** 生成调用 `String.fromCodePoint` 类似功能的导入函数的指令。

* **`string_charcodeat(DataRange* data)`:** 生成调用 `String.charCodeAt` 类似功能的导入函数的指令。

* **`string_codepointat(DataRange* data)`:** 生成调用 `String.codePointAt` 类似功能的导入函数的指令。

* **`string_length(DataRange* data)`:** 生成调用获取字符串长度的导入函数的指令。

* **`string_concat(DataRange* data)`:** 生成调用字符串连接的导入函数的指令。

* **`string_substring(DataRange* data)`:** 生成调用获取子字符串的导入函数的指令。

* **`string_equals(DataRange* data)`:** 生成调用字符串判等的导入函数的指令。

* **`string_compare(DataRange* data)`:** 生成调用字符串比较的导入函数的指令。

* **`string_fromcharcodearray(DataRange* data)`:** 生成调用从字符码数组创建字符串的导入函数的指令。

* **`string_intocharcodearray(DataRange* data)`:** 生成调用将字符串复制到字符码数组的导入函数的指令。

* **`string_measureutf8(DataRange* data)`:** 生成调用测量字符串 UTF-8 编码长度的导入函数的指令。

* **`string_intoutf8array(DataRange* data)`:** 生成调用将字符串编码到 UTF-8 数组的导入函数的指令。

* **`string_toutf8array(DataRange* data)`:** 生成调用将字符串编码到新的 UTF-8 数组的导入函数的指令。

* **`string_fromutf8array(DataRange* data)`:** 生成调用从 UTF-8 数组解码字符串的导入函数的指令。

* **`GenerateFn` 和 `GenerateFnWithHeap` 类型别名:** 定义了生成函数的类型。

* **`GenerateOneOf` (两个重载):**  这是一个模板函数，用于从一组生成函数中随机选择一个并执行。一个版本用于普通的生成函数，另一个版本用于需要 `HeapType` 和可空性的生成函数。

* **`GeneratorRecursionScope`:**  这是一个 RAII 风格的辅助类，用于管理代码生成时的递归深度，防止无限递归。

* **`BodyGen` 构造函数:** 初始化 `BodyGen` 对象，包括函数构建器、已有的函数、全局变量、结构体和数组类型信息，以及字符串导入信息。它还会根据随机数据初始化局部变量。

* **`NumImportedFunctions()`:** 返回导入的函数数量。

* **`GenerateVoid(DataRange* data)`:** 生成返回值为 void 的指令序列。它包含了各种控制流指令、内存操作、函数调用、局部/全局变量操作、异常处理、表操作等。

* **`GenerateI32(DataRange* data)`:** 生成返回值为 i32 的指令序列。它包含了常量、各种 i32 和 i64 的运算、浮点数比较和转换、控制流、内存操作、原子操作、内存大小调整、局部/全局变量访问、select 指令、函数调用、以及 WASM GC 和字符串相关的操作。

* **`GenerateI64(DataRange* data)`:** 生成返回值为 i64 的指令序列。

**是否为 Torque 源代码:**

根据您的描述，`v8/src/wasm/fuzzing/random-module-generation.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 Torque 源代码。 Torque 源代码文件以 `.tq` 结尾。

**与 JavaScript 的关系 (使用 JavaScript 举例):**

这部分代码与 JavaScript 的关系主要体现在 **字符串操作** 上。WebAssembly 本身对字符串的支持有限，V8 通过导入 JavaScript 的字符串操作函数来实现 WebAssembly 中对字符串的处理。

例如，`string_length` 函数对应于 JavaScript 中的 `String.prototype.length` 属性：

```javascript
// 在 WebAssembly 模块中调用导入的 "string_length" 函数
const length = wasmModuleInstance.exports.string_length_wrapper(someString);

// JavaScript 中对应的操作
const jsLength = someString.length;
```

`string_concat` 函数对应于 JavaScript 中的 `String.prototype.concat()` 方法或 `+` 运算符：

```javascript
// 在 WebAssembly 模块中调用导入的 "string_concat" 函数
const combinedString = wasmModuleInstance.exports.string_concat_wrapper(string1, string2);

// JavaScript 中对应的操作
const jsCombinedString = string1 + string2;
```

`string_substring` 函数对应于 JavaScript 中的 `String.prototype.substring()` 方法：

```javascript
// 在 WebAssembly 模块中调用导入的 "string_substring" 函数
const sub = wasmModuleInstance.exports.string_substring_wrapper(myString, startIndex, endIndex);

// JavaScript 中对应的操作
const jsSub = myString.substring(startIndex, endIndex);
```

其他 `string_*` 函数也类似地对应于 JavaScript 的字符串操作方法。

**代码逻辑推理 (假设输入与输出):**

以 `br_on_cast` 函数为例，假设我们有以下输入：

* **`type`**: 一个结构体类型 `structref`
* **`data`**: 一个 `DataRange` 对象，提供随机数据，假设其返回 `true` 表示选择 `br_on_cast` 分支，并且后续的随机数据指示其他选择。
* **`nullable`**: `kNonNullable`
* **`blocks_`**:  假设 `blocks_` 中包含一个块，其返回类型为 `anyref?` (可空的 `anyref`)。

**假设执行流程:**

1. `br_on_cast` 函数被调用。
2. 从 `blocks_` 中随机选择一个目标块 (假设选择了索引为 0 的块)。
3. 获取目标块的返回类型 `anyref?`。
4. 调用 `Generate` 生成除了最后一个返回值的其他值 (如果存在)。
5. 根据 `data->get<bool>()` 的返回值 (假设为 `true`)，进入 `br_on_cast` 分支。
6. 调用 `top_type(break_type.heap_type())`，其中 `break_type.heap_type()` 是 `anyref`，所以 `source_type` 是 `anyref`。
7. 根据 `data->get<bool>()` 生成一个 `anyref` (假设为可空的)。
8. 根据 `data->get<bool>()` 决定目标类型是否可空。
9. 发射 `kExprBrOnCast` 指令。
10. 发射可空性标志。
11. 发射块索引。
12. 发射源类型 `anyref` 的代码。
13. 发射目标类型 (目标块的返回类型) `anyref` 的代码。
14. 调用 `ConsumeAndGenerate` 处理 `br_on_cast` 指令后的类型变化。
15. 调用 `GenerateRef` 生成实际期望的引用类型 (`type`)。

**假设输出 (部分 WebAssembly 指令):**

```wasm
br_on_cast 1 ;; 可空性标志 (假设源和目标都可空)
  0        ;; 块索引
  -1       ;; anyref 的类型代码
  -1       ;; anyref 的类型代码
... (其他指令)
```

**涉及用户常见的编程错误:**

* **类型转换错误:**  在 WebAssembly 中，不正确的类型转换会导致运行时错误。例如，尝试将一个不兼容的引用类型进行强制转换，或者在期望非空引用的地方使用了空引用。 `ref_cast` 和 `br_on_cast` 相关的操作如果使用不当，就可能触发这类错误。

  ```javascript
  // 假设 WebAssembly 模块导出了一个函数，该函数尝试将一个 externref 强制转换为 structref
  try {
    wasmModuleInstance.exports.force_cast(someExternRef);
  } catch (e) {
    console.error("类型转换错误:", e); // 可能抛出 Trap
  }
  ```

* **空指针解引用:**  类似于 C/C++ 中的空指针解引用，在 WebAssembly 中，尝试访问空引用的成员或调用其方法会导致运行时错误。 `ref_is_null` 和 `br_on_null`/`br_on_non_null` 指令可以帮助避免这类错误，但如果逻辑不严谨，仍然可能发生。

  ```javascript
  // 假设 WebAssembly 模块导出了一个函数，该函数访问一个可能为空的结构体引用的字段
  const structRef = wasmModuleInstance.exports.get_maybe_null_struct();
  if (structRef !== null) {
    const field = wasmModuleInstance.exports.access_struct_field(structRef);
    console.log("字段值:", field);
  } else {
    console.log("结构体引用为空");
  }
  ```

* **数组越界访问:**  虽然这部分代码主要关注引用类型，但在 `array_get` 和 `array_set` 等相关操作中，如果生成的索引超出数组的边界，会导致运行时错误。

  ```javascript
  // 假设 WebAssembly 模块导出了一个函数，该函数尝试访问数组的特定索引
  const array = wasmModuleInstance.exports.get_an_array();
  const index = wasmModuleInstance.exports.get_an_invalid_index(); // 假设返回越界索引
  try {
    const element = wasmModuleInstance.exports.access_array_element(array, index);
    console.log("元素值:", element);
  } catch (e) {
    console.error("数组越界错误:", e); // 可能抛出 Trap
  }
  ```

**第 3 部分功能归纳:**

`v8/src/wasm/fuzzing/random-module-generation.cc` 的第 3 部分主要负责定义 `BodyGen` 类中用于 **生成各种 WebAssembly 表达式** 的成员函数，特别是那些涉及 **引用类型操作、结构体、数组以及与 JavaScript 互操作的字符串操作** 的表达式。 这部分代码提供了生成 `ref.cast`、`br_on_cast`、`struct.get`、`struct.set` 等 WebAssembly 指令的能力，并且能够生成调用导入的 JavaScript 字符串操作函数的指令。 它的核心目标是为 WebAssembly 模糊测试提供生成随机但合法的指令序列的基础。

### 提示词
```
这是目录为v8/src/wasm/fuzzing/random-module-generation.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/fuzzing/random-module-generation.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
rate<wanted_kind>(data);
    }
  }

  bool struct_get_ref(HeapType type, DataRange* data, Nullability nullable) {
    ValueType needed_type = ValueType::RefMaybeNull(type, nullable);
    return struct_get_helper(needed_type, data);
  }

  bool ref_cast(HeapType type, DataRange* data, Nullability nullable) {
    HeapType input_type = top_type(type);
    GenerateRef(input_type, data);
    builder_->EmitWithPrefix(nullable ? kExprRefCastNull : kExprRefCast);
    builder_->EmitI32V(type.code());
    return true;  // It always produces the desired result type.
  }

  HeapType top_type(HeapType type) {
    switch (type.representation()) {
      case HeapType::kAny:
      case HeapType::kEq:
      case HeapType::kArray:
      case HeapType::kStruct:
      case HeapType::kI31:
      case HeapType::kNone:
        return HeapType(HeapType::kAny);
      case HeapType::kExtern:
      case HeapType::kNoExtern:
        return HeapType(HeapType::kExtern);
      case HeapType::kExn:
      case HeapType::kNoExn:
        return HeapType(HeapType::kExn);
      case HeapType::kFunc:
      case HeapType::kNoFunc:
        return HeapType(HeapType::kFunc);
      default:
        DCHECK(type.is_index());
        if (builder_->builder()->IsSignature(type.ref_index())) {
          return HeapType(HeapType::kFunc);
        }
        DCHECK(builder_->builder()->IsStructType(type.ref_index()) ||
               builder_->builder()->IsArrayType(type.ref_index()));
        return HeapType(HeapType::kAny);
    }
  }

  HeapType choose_sub_type(HeapType type, DataRange* data) {
    switch (type.representation()) {
      case HeapType::kAny: {
        constexpr HeapType::Representation generic_types[] = {
            HeapType::kAny,    HeapType::kEq,  HeapType::kArray,
            HeapType::kStruct, HeapType::kI31, HeapType::kNone,
        };
        size_t choice =
            data->get<uint8_t>() %
            (arrays_.size() + structs_.size() + arraysize(generic_types));

        if (choice < arrays_.size()) return HeapType(arrays_[choice]);
        choice -= arrays_.size();
        if (choice < structs_.size()) return HeapType(structs_[choice]);
        choice -= structs_.size();
        return HeapType(generic_types[choice]);
      }
      case HeapType::kEq: {
        constexpr HeapType::Representation generic_types[] = {
            HeapType::kEq,  HeapType::kArray, HeapType::kStruct,
            HeapType::kI31, HeapType::kNone,
        };
        size_t choice =
            data->get<uint8_t>() %
            (arrays_.size() + structs_.size() + arraysize(generic_types));

        if (choice < arrays_.size()) return HeapType(arrays_[choice]);
        choice -= arrays_.size();
        if (choice < structs_.size()) return HeapType(structs_[choice]);
        choice -= structs_.size();
        return HeapType(generic_types[choice]);
      }
      case HeapType::kStruct: {
        constexpr HeapType::Representation generic_types[] = {
            HeapType::kStruct,
            HeapType::kNone,
        };
        const size_t type_count = structs_.size();
        const size_t choice =
            data->get<uint8_t>() % (type_count + arraysize(generic_types));
        return choice >= type_count
                   ? HeapType(generic_types[choice - type_count])
                   : HeapType(structs_[choice]);
      }
      case HeapType::kArray: {
        constexpr HeapType::Representation generic_types[] = {
            HeapType::kArray,
            HeapType::kNone,
        };
        const size_t type_count = arrays_.size();
        const size_t choice =
            data->get<uint8_t>() % (type_count + arraysize(generic_types));
        return choice >= type_count
                   ? HeapType(generic_types[choice - type_count])
                   : HeapType(arrays_[choice]);
      }
      case HeapType::kFunc: {
        constexpr HeapType::Representation generic_types[] = {
            HeapType::kFunc, HeapType::kNoFunc};
        const size_t type_count = functions_.size();
        const size_t choice =
            data->get<uint8_t>() % (type_count + arraysize(generic_types));
        return choice >= type_count
                   ? HeapType(generic_types[choice - type_count])
                   : HeapType(functions_[choice]);
      }
      case HeapType::kExtern:
        // About 10% of chosen subtypes will be kNoExtern.
        return HeapType(data->get<uint8_t>() > 25 ? HeapType::kExtern
                                                  : HeapType::kNoExtern);
      default:
        if (!type.is_index()) {
          // No logic implemented to find a sub-type.
          return type;
        }
        // Collect all (direct) sub types.
        // TODO(14034): Also collect indirect sub types.
        std::vector<ModuleTypeIndex> subtypes;
        uint32_t type_count = builder_->builder()->NumTypes();
        for (uint32_t i = 0; i < type_count; ++i) {
          if (builder_->builder()->GetSuperType(i) == type.ref_index()) {
            subtypes.push_back(ModuleTypeIndex{i});
          }
        }
        return subtypes.empty()
                   ? type  // no downcast possible
                   : HeapType(subtypes[data->get<uint8_t>() % subtypes.size()]);
    }
  }

  bool br_on_cast(HeapType type, DataRange* data, Nullability nullable) {
    DCHECK(!blocks_.empty());
    const uint32_t target_block = data->get<uint8_t>() % blocks_.size();
    const uint32_t block_index =
        static_cast<uint32_t>(blocks_.size()) - 1 - target_block;
    const auto break_types = base::VectorOf(blocks_[target_block]);
    if (break_types.empty()) {
      return false;
    }
    ValueType break_type = break_types.last();
    if (!break_type.is_reference()) {
      return false;
    }

    Generate(break_types.SubVector(0, break_types.size() - 1), data);
    if (data->get<bool>()) {
      // br_on_cast
      HeapType source_type = top_type(break_type.heap_type());
      const bool source_is_nullable = data->get<bool>();
      GenerateRef(source_type, data,
                  source_is_nullable ? kNullable : kNonNullable);
      const bool target_is_nullable =
          source_is_nullable && break_type.is_nullable() && data->get<bool>();
      builder_->EmitWithPrefix(kExprBrOnCast);
      builder_->EmitU32V(source_is_nullable + (target_is_nullable << 1));
      builder_->EmitU32V(block_index);
      builder_->EmitI32V(source_type.code());             // source type
      builder_->EmitI32V(break_type.heap_type().code());  // target type
      // Fallthrough: The type has been up-cast to the source type of the
      // br_on_cast instruction! (If the type on the stack was more specific,
      // this loses type information.)
      base::SmallVector<ValueType, 32> fallthrough_types(break_types);
      fallthrough_types.back() = ValueType::RefMaybeNull(
          source_type, source_is_nullable ? kNullable : kNonNullable);
      ConsumeAndGenerate(base::VectorOf(fallthrough_types), {}, data);
      // Generate the actually desired ref type.
      GenerateRef(type, data, nullable);
    } else {
      // br_on_cast_fail
      HeapType source_type = break_type.heap_type();
      const bool source_is_nullable = data->get<bool>();
      GenerateRef(source_type, data,
                  source_is_nullable ? kNullable : kNonNullable);
      const bool target_is_nullable =
          source_is_nullable &&
          (!break_type.is_nullable() || data->get<bool>());
      HeapType target_type = choose_sub_type(source_type, data);

      builder_->EmitWithPrefix(kExprBrOnCastFail);
      builder_->EmitU32V(source_is_nullable + (target_is_nullable << 1));
      builder_->EmitU32V(block_index);
      builder_->EmitI32V(source_type.code());
      builder_->EmitI32V(target_type.code());
      // Fallthrough: The type has been cast to the target type.
      base::SmallVector<ValueType, 32> fallthrough_types(break_types);
      fallthrough_types.back() = ValueType::RefMaybeNull(
          target_type, target_is_nullable ? kNullable : kNonNullable);
      ConsumeAndGenerate(base::VectorOf(fallthrough_types), {}, data);
      // Generate the actually desired ref type.
      GenerateRef(type, data, nullable);
    }
    return true;
  }

  bool any_convert_extern(HeapType type, DataRange* data,
                          Nullability nullable) {
    if (type.representation() != HeapType::kAny) {
      return false;
    }
    GenerateRef(HeapType(HeapType::kExtern), data);
    builder_->EmitWithPrefix(kExprAnyConvertExtern);
    if (nullable == kNonNullable) {
      builder_->Emit(kExprRefAsNonNull);
    }
    return true;
  }

  bool ref_as_non_null(HeapType type, DataRange* data, Nullability nullable) {
    GenerateRef(type, data, kNullable);
    builder_->Emit(kExprRefAsNonNull);
    return true;
  }

  void struct_set(DataRange* data) {
    WasmModuleBuilder* builder = builder_->builder();
    DCHECK_NE(0, structs_.size());  // We always emit at least one struct type.
    ModuleTypeIndex struct_index =
        structs_[data->get<uint8_t>() % structs_.size()];
    DCHECK(builder->IsStructType(struct_index));
    const StructType* struct_type = builder->GetStructType(struct_index);
    ZoneVector<uint32_t> field_indices(builder->zone());
    for (uint32_t i = 0; i < struct_type->field_count(); i++) {
      if (struct_type->mutability(i)) {
        field_indices.push_back(i);
      }
    }
    if (field_indices.empty()) {
      return;
    }
    int field_index =
        field_indices[data->get<uint8_t>() % field_indices.size()];
    GenerateRef(HeapType(struct_index), data);
    Generate(struct_type->field(field_index).Unpacked(), data);
    builder_->EmitWithPrefix(kExprStructSet);
    builder_->EmitU32V(struct_index);
    builder_->EmitU32V(field_index);
  }

  void ref_is_null(DataRange* data) {
    GenerateRef(HeapType(HeapType::kAny), data);
    builder_->Emit(kExprRefIsNull);
  }

  template <WasmOpcode opcode>
  void ref_test(DataRange* data) {
    GenerateRef(HeapType(HeapType::kAny), data);
    constexpr int generic_types[] = {kAnyRefCode,    kEqRefCode, kArrayRefCode,
                                     kStructRefCode, kNoneCode,  kI31RefCode};
    size_t num_types = structs_.size() + arrays_.size();
    size_t num_all_types = num_types + arraysize(generic_types);
    size_t type_choice = data->get<uint8_t>() % num_all_types;
    builder_->EmitWithPrefix(opcode);
    if (type_choice < structs_.size()) {
      builder_->EmitU32V(structs_[type_choice]);
      return;
    }
    type_choice -= structs_.size();
    if (type_choice < arrays_.size()) {
      builder_->EmitU32V(arrays_[type_choice]);
      return;
    }
    type_choice -= arrays_.size();
    builder_->EmitU32V(generic_types[type_choice]);
  }

  void ref_eq(DataRange* data) {
    GenerateRef(HeapType(HeapType::kEq), data);
    GenerateRef(HeapType(HeapType::kEq), data);
    builder_->Emit(kExprRefEq);
  }

  void call_string_import(uint32_t index) {
    builder_->EmitWithU32V(kExprCallFunction, index);
  }

  void string_cast(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.cast);
  }

  void string_test(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.test);
  }

  void string_fromcharcode(DataRange* data) {
    Generate(kWasmI32, data);
    call_string_import(string_imports_.fromCharCode);
  }

  void string_fromcodepoint(DataRange* data) {
    Generate(kWasmI32, data);
    call_string_import(string_imports_.fromCodePoint);
  }

  void string_charcodeat(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.charCodeAt);
  }

  void string_codepointat(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.codePointAt);
  }

  void string_length(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.length);
  }

  void string_concat(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.concat);
  }

  void string_substring(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    Generate(kWasmI32, data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.substring);
  }

  void string_equals(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.equals);
  }

  void string_compare(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.compare);
  }

  void string_fromcharcodearray(DataRange* data) {
    GenerateRef(HeapType(string_imports_.array_i16), data);
    Generate(kWasmI32, data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.fromCharCodeArray);
  }

  void string_intocharcodearray(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    GenerateRef(HeapType(string_imports_.array_i16), data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.intoCharCodeArray);
  }

  void string_measureutf8(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.measureStringAsUTF8);
  }

  void string_intoutf8array(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    GenerateRef(HeapType(string_imports_.array_i8), data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.encodeStringIntoUTF8Array);
  }

  void string_toutf8array(DataRange* data) {
    GenerateRef(HeapType(HeapType::kExtern), data);
    call_string_import(string_imports_.encodeStringToUTF8Array);
  }

  void string_fromutf8array(DataRange* data) {
    GenerateRef(HeapType(string_imports_.array_i8), data);
    Generate(kWasmI32, data);
    Generate(kWasmI32, data);
    call_string_import(string_imports_.decodeStringFromUTF8Array);
  }

  using GenerateFn = void (BodyGen::*)(DataRange*);
  using GenerateFnWithHeap = bool (BodyGen::*)(HeapType, DataRange*,
                                               Nullability);

  template <size_t N>
  void GenerateOneOf(const std::array<GenerateFn, N>& alternatives,
                     DataRange* data) {
    static_assert(N < std::numeric_limits<uint8_t>::max(),
                  "Too many alternatives. Use a bigger type if needed.");
    const auto which = data->get<uint8_t>();

    GenerateFn alternate = alternatives[which % N];
    (this->*alternate)(data);
  }

  // Returns true if it had succesfully generated a randomly chosen expression
  // from the `alternatives`.
  template <size_t N>
  bool GenerateOneOf(const std::array<GenerateFnWithHeap, N>& alternatives,
                     HeapType type, DataRange* data, Nullability nullability) {
    static_assert(N < std::numeric_limits<uint8_t>::max(),
                  "Too many alternatives. Use a bigger type if needed.");

    int index = data->get<uint8_t>() % (N + 1);

    if (nullability && index == N) {
      ref_null(type, data);
      return true;
    }

    for (int i = index; i < static_cast<int>(N); i++) {
      if ((this->*alternatives[i])(type, data, nullability)) {
        return true;
      }
    }

    for (int i = 0; i < index; i++) {
      if ((this->*alternatives[i])(type, data, nullability)) {
        return true;
      }
    }

    if (nullability == kNullable) {
      ref_null(type, data);
      return true;
    }

    return false;
  }

  struct GeneratorRecursionScope {
    explicit GeneratorRecursionScope(BodyGen* gen) : gen(gen) {
      ++gen->recursion_depth;
      DCHECK_LE(gen->recursion_depth, kMaxRecursionDepth);
    }
    ~GeneratorRecursionScope() {
      DCHECK_GT(gen->recursion_depth, 0);
      --gen->recursion_depth;
    }
    BodyGen* gen;
  };

 public:
  BodyGen(WasmFunctionBuilder* fn,
          const std::vector<ModuleTypeIndex>& functions,
          const std::vector<ValueType>& globals,
          const std::vector<uint8_t>& mutable_globals,
          const std::vector<ModuleTypeIndex>& structs,
          const std::vector<ModuleTypeIndex>& arrays,
          const StringImports& strings, DataRange* data)
      : builder_(fn),
        functions_(functions),
        globals_(globals),
        mutable_globals_(mutable_globals),
        structs_(structs),
        arrays_(arrays),
        string_imports_(strings) {
    const FunctionSig* sig = fn->signature();
    blocks_.emplace_back();
    for (size_t i = 0; i < sig->return_count(); ++i) {
      blocks_.back().push_back(sig->GetReturn(i));
    }
    locals_.resize(data->get<uint8_t>() % kMaxLocals);
    uint32_t num_types = static_cast<uint32_t>(
        functions_.size() + structs_.size() + arrays_.size());
    for (ValueType& local : locals_) {
      local = GetValueType<options>(data, num_types);
      fn->AddLocal(local);
    }
  }

  int NumImportedFunctions() {
    return builder_->builder()->NumImportedFunctions();
  }

  // Generator functions.
  // Implementation detail: We define non-template Generate*TYPE*() functions
  // instead of templatized Generate<TYPE>(). This is because we cannot define
  // the templatized Generate<TYPE>() functions:
  //  - outside of the class body without specializing the template of the
  //  `BodyGen` (results in partial template specialization error);
  //  - inside of the class body (gcc complains about explicit specialization in
  //  non-namespace scope).

  void GenerateVoid(DataRange* data) {
    GeneratorRecursionScope rec_scope(this);
    if (recursion_limit_reached() || data->size() == 0) return;

    constexpr auto mvp_alternatives =
        CreateArray(&BodyGen::sequence<kVoid, kVoid>,
                    &BodyGen::sequence<kVoid, kVoid, kVoid, kVoid>,
                    &BodyGen::sequence<kVoid, kVoid, kVoid, kVoid, kVoid, kVoid,
                                       kVoid, kVoid>,
                    &BodyGen::block<kVoid>,           //
                    &BodyGen::loop<kVoid>,            //
                    &BodyGen::finite_loop<kVoid>,     //
                    &BodyGen::if_<kVoid, kIf>,        //
                    &BodyGen::if_<kVoid, kIfElse>,    //
                    &BodyGen::br,                     //
                    &BodyGen::br_if<kVoid>,           //
                    &BodyGen::br_on_null<kVoid>,      //
                    &BodyGen::br_on_non_null<kVoid>,  //
                    &BodyGen::br_table<kVoid>,        //
                    &BodyGen::return_op,              //

                    &BodyGen::memop<kExprI32StoreMem, kI32>,
                    &BodyGen::memop<kExprI32StoreMem8, kI32>,
                    &BodyGen::memop<kExprI32StoreMem16, kI32>,
                    &BodyGen::memop<kExprI64StoreMem, kI64>,
                    &BodyGen::memop<kExprI64StoreMem8, kI64>,
                    &BodyGen::memop<kExprI64StoreMem16, kI64>,
                    &BodyGen::memop<kExprI64StoreMem32, kI64>,
                    &BodyGen::memop<kExprF32StoreMem, kF32>,
                    &BodyGen::memop<kExprF64StoreMem, kF64>,
                    &BodyGen::memop<kExprI32AtomicStore, kI32>,
                    &BodyGen::memop<kExprI32AtomicStore8U, kI32>,
                    &BodyGen::memop<kExprI32AtomicStore16U, kI32>,
                    &BodyGen::memop<kExprI64AtomicStore, kI64>,
                    &BodyGen::memop<kExprI64AtomicStore8U, kI64>,
                    &BodyGen::memop<kExprI64AtomicStore16U, kI64>,
                    &BodyGen::memop<kExprI64AtomicStore32U, kI64>,

                    &BodyGen::drop,

                    &BodyGen::call<kVoid>,           //
                    &BodyGen::call_indirect<kVoid>,  //
                    &BodyGen::call_ref<kVoid>,       //

                    &BodyGen::set_local,         //
                    &BodyGen::set_global,        //
                    &BodyGen::throw_or_rethrow,  //
                    &BodyGen::try_block<kVoid>,  //

                    &BodyGen::table_set,    //
                    &BodyGen::table_fill,   //
                    &BodyGen::table_copy);  //

    auto constexpr simd_alternatives =
        CreateArray(&BodyGen::memop<kExprS128StoreMem, kS128>,
                    &BodyGen::simd_lane_memop<kExprS128Store8Lane, 16, kS128>,
                    &BodyGen::simd_lane_memop<kExprS128Store16Lane, 8, kS128>,
                    &BodyGen::simd_lane_memop<kExprS128Store32Lane, 4, kS128>,
                    &BodyGen::simd_lane_memop<kExprS128Store64Lane, 2, kS128>);

    auto constexpr wasmGC_alternatives =
        CreateArray(&BodyGen::struct_set,        //
                    &BodyGen::array_set,         //
                    &BodyGen::array_copy,        //
                    &BodyGen::array_fill,        //
                    &BodyGen::array_init_data,   //
                    &BodyGen::array_init_elem);  //

    constexpr auto alternatives = AppendArrayIf<ShouldGenerateWasmGC(options)>(
        AppendArrayIf<ShouldGenerateSIMD(options)>(mvp_alternatives,
                                                   simd_alternatives),
        wasmGC_alternatives);
    GenerateOneOf(alternatives, data);
  }

  void GenerateI32(DataRange* data) {
    GeneratorRecursionScope rec_scope(this);
    if (recursion_limit_reached() || data->size() <= 1) {
      // Rather than evenly distributing values across the full 32-bit range,
      // distribute them evenly over the possible bit lengths. In particular,
      // for values used as indices into something else, smaller values are
      // more likely to be useful.
      uint8_t size = 1 + (data->getPseudoRandom<uint8_t>() & 31);
      uint32_t mask = kMaxUInt32 >> (32 - size);
      builder_->EmitI32Const(data->getPseudoRandom<uint32_t>() & mask);
      return;
    }

    constexpr auto mvp_alternatives = CreateArray(
        &BodyGen::i32_const<1>,  //
        &BodyGen::i32_const<2>,  //
        &BodyGen::i32_const<3>,  //
        &BodyGen::i32_const<4>,  //

        &BodyGen::sequence<kI32, kVoid>,         //
        &BodyGen::sequence<kVoid, kI32>,         //
        &BodyGen::sequence<kVoid, kI32, kVoid>,  //

        &BodyGen::op<kExprI32Eqz, kI32>,        //
        &BodyGen::op<kExprI32Eq, kI32, kI32>,   //
        &BodyGen::op<kExprI32Ne, kI32, kI32>,   //
        &BodyGen::op<kExprI32LtS, kI32, kI32>,  //
        &BodyGen::op<kExprI32LtU, kI32, kI32>,  //
        &BodyGen::op<kExprI32GeS, kI32, kI32>,  //
        &BodyGen::op<kExprI32GeU, kI32, kI32>,  //

        &BodyGen::op<kExprI64Eqz, kI64>,        //
        &BodyGen::op<kExprI64Eq, kI64, kI64>,   //
        &BodyGen::op<kExprI64Ne, kI64, kI64>,   //
        &BodyGen::op<kExprI64LtS, kI64, kI64>,  //
        &BodyGen::op<kExprI64LtU, kI64, kI64>,  //
        &BodyGen::op<kExprI64GeS, kI64, kI64>,  //
        &BodyGen::op<kExprI64GeU, kI64, kI64>,  //

        &BodyGen::op<kExprF32Eq, kF32, kF32>,
        &BodyGen::op<kExprF32Ne, kF32, kF32>,
        &BodyGen::op<kExprF32Lt, kF32, kF32>,
        &BodyGen::op<kExprF32Ge, kF32, kF32>,

        &BodyGen::op<kExprF64Eq, kF64, kF64>,
        &BodyGen::op<kExprF64Ne, kF64, kF64>,
        &BodyGen::op<kExprF64Lt, kF64, kF64>,
        &BodyGen::op<kExprF64Ge, kF64, kF64>,

        &BodyGen::op<kExprI32Add, kI32, kI32>,
        &BodyGen::op<kExprI32Sub, kI32, kI32>,
        &BodyGen::op<kExprI32Mul, kI32, kI32>,

        &BodyGen::op<kExprI32DivS, kI32, kI32>,
        &BodyGen::op<kExprI32DivU, kI32, kI32>,
        &BodyGen::op<kExprI32RemS, kI32, kI32>,
        &BodyGen::op<kExprI32RemU, kI32, kI32>,

        &BodyGen::op<kExprI32And, kI32, kI32>,
        &BodyGen::op<kExprI32Ior, kI32, kI32>,
        &BodyGen::op<kExprI32Xor, kI32, kI32>,
        &BodyGen::op<kExprI32Shl, kI32, kI32>,
        &BodyGen::op<kExprI32ShrU, kI32, kI32>,
        &BodyGen::op<kExprI32ShrS, kI32, kI32>,
        &BodyGen::op<kExprI32Ror, kI32, kI32>,
        &BodyGen::op<kExprI32Rol, kI32, kI32>,

        &BodyGen::op<kExprI32Clz, kI32>,     //
        &BodyGen::op<kExprI32Ctz, kI32>,     //
        &BodyGen::op<kExprI32Popcnt, kI32>,  //

        &BodyGen::op<kExprI32ConvertI64, kI64>,
        &BodyGen::op<kExprI32SConvertF32, kF32>,
        &BodyGen::op<kExprI32UConvertF32, kF32>,
        &BodyGen::op<kExprI32SConvertF64, kF64>,
        &BodyGen::op<kExprI32UConvertF64, kF64>,
        &BodyGen::op<kExprI32ReinterpretF32, kF32>,

        &BodyGen::op_with_prefix<kExprI32SConvertSatF32, kF32>,
        &BodyGen::op_with_prefix<kExprI32UConvertSatF32, kF32>,
        &BodyGen::op_with_prefix<kExprI32SConvertSatF64, kF64>,
        &BodyGen::op_with_prefix<kExprI32UConvertSatF64, kF64>,

        &BodyGen::block<kI32>,           //
        &BodyGen::loop<kI32>,            //
        &BodyGen::finite_loop<kI32>,     //
        &BodyGen::if_<kI32, kIfElse>,    //
        &BodyGen::br_if<kI32>,           //
        &BodyGen::br_on_null<kI32>,      //
        &BodyGen::br_on_non_null<kI32>,  //
        &BodyGen::br_table<kI32>,        //

        &BodyGen::memop<kExprI32LoadMem>,                               //
        &BodyGen::memop<kExprI32LoadMem8S>,                             //
        &BodyGen::memop<kExprI32LoadMem8U>,                             //
        &BodyGen::memop<kExprI32LoadMem16S>,                            //
        &BodyGen::memop<kExprI32LoadMem16U>,                            //
                                                                        //
        &BodyGen::memop<kExprI32AtomicLoad>,                            //
        &BodyGen::memop<kExprI32AtomicLoad8U>,                          //
        &BodyGen::memop<kExprI32AtomicLoad16U>,                         //
        &BodyGen::memop<kExprI32AtomicAdd, kI32>,                       //
        &BodyGen::memop<kExprI32AtomicSub, kI32>,                       //
        &BodyGen::memop<kExprI32AtomicAnd, kI32>,                       //
        &BodyGen::memop<kExprI32AtomicOr, kI32>,                        //
        &BodyGen::memop<kExprI32AtomicXor, kI32>,                       //
        &BodyGen::memop<kExprI32AtomicExchange, kI32>,                  //
        &BodyGen::memop<kExprI32AtomicCompareExchange, kI32, kI32>,     //
        &BodyGen::memop<kExprI32AtomicAdd8U, kI32>,                     //
        &BodyGen::memop<kExprI32AtomicSub8U, kI32>,                     //
        &BodyGen::memop<kExprI32AtomicAnd8U, kI32>,                     //
        &BodyGen::memop<kExprI32AtomicOr8U, kI32>,                      //
        &BodyGen::memop<kExprI32AtomicXor8U, kI32>,                     //
        &BodyGen::memop<kExprI32AtomicExchange8U, kI32>,                //
        &BodyGen::memop<kExprI32AtomicCompareExchange8U, kI32, kI32>,   //
        &BodyGen::memop<kExprI32AtomicAdd16U, kI32>,                    //
        &BodyGen::memop<kExprI32AtomicSub16U, kI32>,                    //
        &BodyGen::memop<kExprI32AtomicAnd16U, kI32>,                    //
        &BodyGen::memop<kExprI32AtomicOr16U, kI32>,                     //
        &BodyGen::memop<kExprI32AtomicXor16U, kI32>,                    //
        &BodyGen::memop<kExprI32AtomicExchange16U, kI32>,               //
        &BodyGen::memop<kExprI32AtomicCompareExchange16U, kI32, kI32>,  //

        &BodyGen::memory_size,  //
        &BodyGen::grow_memory,  //

        &BodyGen::get_local<kI32>,                    //
        &BodyGen::tee_local<kI32>,                    //
        &BodyGen::get_global<kI32>,                   //
        &BodyGen::op<kExprSelect, kI32, kI32, kI32>,  //
        &BodyGen::select_with_type<kI32>,             //

        &BodyGen::call<kI32>,           //
        &BodyGen::call_indirect<kI32>,  //
        &BodyGen::call_ref<kI32>,       //
        &BodyGen::try_block<kI32>,      //

        &BodyGen::table_size,   //
        &BodyGen::table_grow);  //

    auto constexpr simd_alternatives =
        CreateArray(&BodyGen::op_with_prefix<kExprV128AnyTrue, kS128>,
                    &BodyGen::op_with_prefix<kExprI8x16AllTrue, kS128>,
                    &BodyGen::op_with_prefix<kExprI8x16BitMask, kS128>,
                    &BodyGen::op_with_prefix<kExprI16x8AllTrue, kS128>,
                    &BodyGen::op_with_prefix<kExprI16x8BitMask, kS128>,
                    &BodyGen::op_with_prefix<kExprI32x4AllTrue, kS128>,
                    &BodyGen::op_with_prefix<kExprI32x4BitMask, kS128>,
                    &BodyGen::op_with_prefix<kExprI64x2AllTrue, kS128>,
                    &BodyGen::op_with_prefix<kExprI64x2BitMask, kS128>,
                    &BodyGen::simd_lane_op<kExprI8x16ExtractLaneS, 16, kS128>,
                    &BodyGen::simd_lane_op<kExprI8x16ExtractLaneU, 16, kS128>,
                    &BodyGen::simd_lane_op<kExprI16x8ExtractLaneS, 8, kS128>,
                    &BodyGen::simd_lane_op<kExprI16x8ExtractLaneU, 8, kS128>,
                    &BodyGen::simd_lane_op<kExprI32x4ExtractLane, 4, kS128>);

    auto constexpr wasmGC_alternatives =
        CreateArray(&BodyGen::i31_get,                     //
                                                           //
                    &BodyGen::struct_get<kI32>,            //
                    &BodyGen::array_get<kI32>,             //
                    &BodyGen::array_len,                   //
                                                           //
                    &BodyGen::ref_is_null,                 //
                    &BodyGen::ref_eq,                      //
                    &BodyGen::ref_test<kExprRefTest>,      //
                    &BodyGen::ref_test<kExprRefTestNull>,  //
                                                           //
                    &BodyGen::string_test,                 //
                    &BodyGen::string_charcodeat,           //
                    &BodyGen::string_codepointat,          //
                    &BodyGen::string_length,               //
                    &BodyGen::string_equals,               //
                    &BodyGen::string_compare,              //
                    &BodyGen::string_intocharcodearray,    //
                    &BodyGen::string_intoutf8array,        //
                    &BodyGen::string_measureutf8);         //

    constexpr auto alternatives = AppendArrayIf<ShouldGenerateWasmGC(options)>(
        AppendArrayIf<ShouldGenerateSIMD(options)>(mvp_alternatives,
                                                   simd_alternatives),
        wasmGC_alternatives);
    GenerateOneOf(alternatives, data);
  }

  void GenerateI64(DataRange* data) {
    GeneratorRecursionScope rec_scope(this);
    if (recursion_limit_reached() || data->size() <= 1) {
      builder_->EmitI64Const(data->getPseudoRandom<int64_t>());
      return;
    }

    constexpr auto mvp_alternatives = CreateArray(
        &BodyGen::i64_const<1>,  //
        &BodyGen::i64_const<2>,  //
        &BodyGen::i64_const<3>,  //
        &BodyGen::i64_const<4>,  //
        &BodyGen::i64_const<5>,  //
        &BodyGen::i64_const<6>,  //
        &BodyGen::i64_const<7>,  //
        &BodyGen::i64_const<8>,  //

        &BodyGen::sequence<kI64, kVoid>,         //
        &BodyGen::sequence<kVoid, kI64>,         //
        &BodyGen::sequence<kVoid, kI64, kVoid>,  //

        &BodyGen::op<kExprI64Add, kI64, kI64>,
        &BodyGen::op<kExprI64Sub, kI64, kI64>,
        &BodyGen::op<kExprI64Mul, kI64, kI64>,

        &BodyGen::op<kExprI64DivS, kI64, kI64>,
        &BodyGen::op<kExprI64DivU, kI64, kI64>,
        &BodyGen::op<kExprI64RemS, kI64, kI64>,
        &BodyGen::op<kExprI64RemU, kI64, kI64>,

        &BodyGen::op<kExprI64And, kI64, kI64>,
        &BodyGen::op<kExprI64Ior, kI64, kI64>,
        &BodyGen::op<kExprI64Xor, kI64, kI64>,
        &BodyGen::op<kExprI64Shl, kI64, kI64>,
        &BodyGen::op<kExprI64ShrU, kI64, kI64>,
        &BodyGen::op<kExprI64ShrS, kI64, kI64>,
        &BodyGen::op<kExprI64Ror, kI64, kI64>,
        &BodyGen::op<kExprI64Rol, kI64, kI64>,

        &BodyGen::op<kExprI64Clz, kI64>,     //
        &BodyGen::op<kExprI64Ctz, kI64>,     //
        &BodyGen::op<kExprI64Popcnt, kI64>,  //

        &BodyGen::op_with_prefix<kExprI64SConvertSatF32, kF32>,
        &BodyGen::op_with_prefix<kExprI64UConvertSatF32, kF32>,
        &BodyGen::op_with_prefix<kExprI64SConvertSatF64, kF64>,
        &BodyGen::op_with_prefix<kExprI64UConvertSatF64, kF64>,

        &BodyGen::block<kI64>,           //
        &BodyGen::loop<kI64>,            //
        &BodyGen::finite_loop<kI64>,     //
        &BodyGen::if_<kI64, kIfEl
```
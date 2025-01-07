Response:
My thinking process to analyze the provided C++ header file snippet goes like this:

1. **Identify the Core Purpose:** The filename `assembler.h` and the code itself strongly suggest this is related to code generation within the V8 JavaScript engine. Specifically, it seems to be a high-level interface for creating low-level instructions. The "turboshaft" part of the path hints at V8's newer Turboshaft compiler.

2. **Recognize the Abstraction:**  The code uses templates and generic types like `V<T>` and `OpIndex`. This indicates an abstraction layer. It's not directly emitting assembly code but rather generating an intermediate representation that will later be translated. The `ReduceIfReachable...` functions are key here – they suggest a process of transforming higher-level operations into simpler, more concrete ones.

3. **Categorize Functionality by Grouping:**  I started scanning the function names and noticed patterns:
    * **String Operations:** `StringConcat`, `StringComparison`, `StringEqual`, etc. Clearly dealing with JavaScript string manipulation.
    * **Arguments Handling:** `ArgumentsLength`, `RestLength`, `NewArgumentsElements`. Related to function arguments in JavaScript.
    * **Memory Access:** `LoadTypedElement`, `LoadDataViewElement`, `StoreTypedElement`, `StoreDataViewElement`. Handling typed arrays and data views.
    * **Object and Map Operations:** `CompareMaps`, `CheckMaps`, `AssumeMap`. Working with JavaScript object structures and their internal maps for optimization.
    * **Control Flow:**  While not explicitly defining control flow *structures* here, the presence of checks and conditional logic within the `ReduceIfReachable` functions hints at how control flow will be managed at a lower level.
    * **Constants:** `LoadRoot`, `...Constant()`. Accessing pre-defined values within the V8 runtime.
    * **WebAssembly Integration:**  The extensive section starting with `#ifdef V8_ENABLE_WEBASSEMBLY` clearly points to functionalities for supporting WebAssembly. This includes memory access (`GlobalGet`, `GlobalSet`), type checking (`WasmTypeCheck`, `IsNull`), and SIMD operations (`Simd128...`, `Simd256...`).

4. **Connect to JavaScript Concepts:**  For each category, I tried to connect it back to familiar JavaScript features. This is where the "if it relates to JavaScript" part of the prompt comes in. Examples:
    * String operations are fundamental to JavaScript.
    * Argument handling relates directly to how functions are called.
    * Typed arrays and DataView are JavaScript APIs for manipulating binary data.
    * Object maps are an internal optimization technique in V8, but the operations here relate to ensuring type stability.
    * WebAssembly features directly map to the WebAssembly specification and its integration with JavaScript.

5. **Identify Potential Torque Connection:** The prompt specifically mentions `.tq` files (Torque). While the given snippet is a `.h` file, the *kind* of operations being performed (high-level operations that get "reduced") aligns with the purpose of Torque, which is V8's domain-specific language for writing compiler intrinsics. This isn't a Torque file itself, but it's part of the infrastructure that Torque might use.

6. **Address Specific Prompt Questions:**
    * **Function Listing:**  This involves simply listing the categorized functionalities.
    * **`.tq` Check:**  Directly answer based on the filename.
    * **JavaScript Examples:**  Provide concrete JavaScript code that would trigger the corresponding internal operations.
    * **Code Logic/Input-Output:** For specific functions like `StringComparison`,  hypothesize the input types and the expected boolean output.
    * **Common Programming Errors:**  Think about what kind of errors developers make that relate to these low-level operations (e.g., type mismatches when dealing with typed arrays).

7. **Infer Overall Function (For the "Summarize" Part):**  Synthesize the individual functionalities into a concise description of the header file's role. It's an interface for generating operations within the Turboshaft compiler, abstracting away low-level details and providing building blocks for implementing higher-level JavaScript and WebAssembly semantics.

8. **Pay Attention to Part Numbering:** The prompt mentions "Part 7 of 8." This suggests a larger context. The specific functions in this part likely build upon concepts introduced in earlier parts and will be used by later parts of the compilation pipeline. This information helps in the summarization.

9. **Refine and Organize:**  Structure the analysis logically, using headings and bullet points for clarity. Ensure that all parts of the prompt are addressed.

Essentially, I treated the code snippet as a puzzle. I looked for patterns, made connections to my existing knowledge of JavaScript and compiler concepts, and systematically addressed each aspect of the prompt. The "ReduceIfReachable" pattern was a significant clue to the overall architecture and the purpose of this header file.
This是目录为 `v8/src/compiler/turboshaft/assembler.h` 的 V8 源代码片段，它定义了一个 `Assembler` 类，用于在 Turboshaft 编译器中构建中间表示 (IR) 图。这个类提供了一系列方法，用于生成各种操作，这些操作最终会被 Lowering 阶段转换为机器码。

以下是 `v8/src/compiler/turboshaft/assembler.h` 中代码片段的功能列表：

1. **字符串操作:**
   - `StringConcat`: 连接两个字符串。
   - `StringComparison`: 比较两个字符串，返回一个布尔值，可以指定比较的类型（相等、小于、小于等于）。
   - `StringEqual`: 判断两个字符串是否相等。
   - `StringLessThan`: 判断一个字符串是否小于另一个字符串。
   - `StringLessThanOrEqual`: 判断一个字符串是否小于等于另一个字符串。

2. **函数参数处理:**
   - `ArgumentsLength`: 获取 `arguments` 对象的长度。
   - `RestLength`: 获取剩余参数（rest parameters）的长度。
   - `NewArgumentsElements`: 创建一个新的 `arguments` 对象的元素。

3. **类型化数组和 DataView 操作:**
   - `LoadTypedElement`: 从类型化数组中加载元素。
   - `LoadDataViewElement`: 从 DataView 中加载元素。
   - `StoreTypedElement`: 将元素存储到类型化数组中。
   - `StoreDataViewElement`: 将元素存储到 DataView 中。

4. **栈操作:**
   - `LoadStackArgument`: 加载栈上的参数。

5. **数组元素存储和转换:**
   - `TransitionAndStoreArrayElement`: 存储数组元素，并可能进行元素类型的转换。
   - `StoreSignedSmallElement`: 存储有符号的小整数到数组中。

6. **类型检查和断言:**
   - `CompareMaps`: 比较对象的 Map（隐藏类）。
   - `CheckMaps`: 检查对象的 Map 是否在给定的集合中。
   - `AssumeMap`: 假设对象的 Map 是给定的。
   - `CheckedClosure`: 检查闭包的反馈单元。
   - `CheckEqualsInternalizedString`: 检查一个值是否是指定的内部化字符串。

7. **消息操作:**
   - `LoadMessage`: 加载消息。
   - `StoreMessage`: 存储消息。

8. **值比较:**
   - `SameValue`: 判断两个值是否在 JavaScript 的 SameValue 语义下相等。
   - `Float64SameValue`: 判断两个 64 位浮点数是否按位相等。

9. **快速 API 调用:**
   - `FastApiCall`: 生成快速 C++ API 调用的代码。

10. **运行时中止:**
    - `RuntimeAbort`:  生成一个导致运行时中止的操作。

11. **快速元素操作:**
    - `EnsureWritableFastElements`: 确保对象的快速元素是可写的。
    - `MaybeGrowFastElements`:  如果需要，可能增长对象的快速元素数组。
    - `TransitionElementsKind`: 转换对象的元素类型。

12. **有序哈希表操作:**
    - `FindOrderedHashEntry`: 在有序哈希表中查找条目。
    - `FindOrderedHashMapEntry`: 在有序哈希映射表中查找条目（键为 Smi）。
    - `FindOrderedHashSetEntry`: 在有序哈希集合中查找条目（键为 Smi）。
    - `FindOrderedHashMapEntryForInt32Key`: 在有序哈希映射表中查找条目（键为 32 位整数）。

13. **投机性数字二元操作:**
    - `SpeculativeNumberBinop`: 生成投机性的数字二元运算。

14. **加载根对象:**
    - `LoadRoot`: 加载根对象，例如全局对象、`undefined` 等。

15. **加载和测试常量:**
    - 提供了一系列宏 (`HEAP_CONSTANT_ACCESSOR`, `HEAP_CONSTANT_TEST`) 用于方便地加载和测试 V8 堆中的常量对象。例如 `UndefinedConstant()`, `NullConstant()`, `IsUndefined()`, `IsNull()` 等。

16. **WebAssembly 支持 (如果 `V8_ENABLE_WEBASSEMBLY` 定义):**
    - 提供了许多用于 WebAssembly 操作的方法，例如：
        - `GlobalGet`, `GlobalSet`: 访问和修改 WebAssembly 全局变量。
        - `Null`, `IsNull`, `AssertNotNull`: 处理 WebAssembly 的 null 值。
        - `RttCanon`, `WasmTypeCheck`, `WasmTypeCast`: 与 WebAssembly 的运行时类型信息 (RTT) 相关的操作。
        - `StructGet`, `StructSet`, `ArrayGet`, `ArraySet`, `ArrayLength`: 访问和修改 WebAssembly 结构体和数组。
        - `WasmAllocateArray`, `WasmAllocateStruct`: 分配 WebAssembly 数组和结构体。
        - `WasmRefFunc`: 创建对 WebAssembly 函数的引用。
        - 字符串操作 (`StringAsWtf16`, `StringPrepareForGetCodeUnit`).
        - SIMD (单指令多数据) 操作 (`Simd128...`, `Simd256...`).
        - 加载 WebAssembly 实例数据 (`WasmInstanceDataParameter`).
        - 栈指针操作 (`LoadStackPointer`, `SetStackPointer`).

17. **延续保留的嵌入器数据支持 (如果 `V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA` 定义):**
    - `GetContinuationPreservedEmbedderData`: 获取延续保留的嵌入器数据。
    - `SetContinuationPreservedEmbedderData`: 设置延续保留的嵌入器数据。

18. **辅助方法:**
    - `resolve`: 用于解析 `ConstOrV` 类型，获取其常量值或 `V` 值。
    - `ReduceIfReachable...`:  这是一组宏生成的函数，用于实际生成操作。它们首先检查当前是否在生成不可达代码，如果不是，则调用 `Asm().Reduce##Op` 来生成相应的操作。
    - `LoadElement`, `StoreElement`: 用于加载和存储元素的模板方法，根据是否为 ArrayBuffer 进行区分。
    - `BranchAndBind`:  用于生成分支指令并绑定后续块。

**如果 `v8/src/compiler/turboshaft/assembler.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但根据描述，它以 `.h` 结尾，所以它是一个 C++ 头文件。 Torque 文件（`.tq`）会被编译成 C++ 代码，其中可能包含对这里定义的 `Assembler` 类的使用。

**与 javascript 的功能关系及 javascript 示例:**

这个头文件中的许多功能都直接对应于 JavaScript 的语言特性。以下是一些示例：

- **字符串连接:**  `ngConcat` 对应 JavaScript 中的字符串连接操作符 `+`。
  ```javascript
  const str1 = "hello";
  const str2 = "world";
  const result = str1 + str2; // 在 Turboshaft 内部，可能会使用 ngConcat 生成 IR
  ```

- **字符串比较:** `StringEqual`, `StringLessThan` 等对应 JavaScript 中的比较运算符 `==`, `<`, 等。
  ```javascript
  const a = "apple";
  const b = "banana";
  if (a < b) { // 在 Turboshaft 内部，可能会使用 StringLessThan 生成 IR
    console.log("apple comes before banana");
  }
  ```

- **`arguments` 对象:** `ArgumentsLength`, `RestLength`, `NewArgumentsElements` 对应 JavaScript 函数中的 `arguments` 对象和剩余参数。
  ```javascript
  function foo(a, b, ...rest) {
    console.log(arguments.length); // 对应 ArgumentsLength
    console.log(rest.length);      // 对应 RestLength
  }
  foo(1, 2, 3, 4);
  ```

- **类型化数组:** `LoadTypedElement`, `StoreTypedElement` 对应 JavaScript 中对 `TypedArray` 的访问。
  ```javascript
  const buffer = new ArrayBuffer(8);
  const view = new Int32Array(buffer);
  view[0] = 42; // 对应 StoreTypedElement
  console.log(view[0]); // 对应 LoadTypedElement
  ```

- **`DataView`:** `LoadDataViewElement`, `StoreDataViewElement` 对应 JavaScript 中对 `DataView` 的访问。
  ```javascript
  const buffer = new ArrayBuffer(8);
  const dataView = new DataView(buffer);
  dataView.setInt32(0, 12345, true); // 对应 StoreDataViewElement (true 表示 little-endian)
  console.log(dataView.getInt32(0, true)); // 对应 LoadDataViewElement
  ```

- **SameValue 比较:** `SameValue` 对应 JavaScript 中的 `Object.is()` 或严格相等 `===` 在特定情况下的行为。
  ```javascript
  console.log(Object.is(NaN, NaN));   // true, 内部可能使用 SameValue
  console.log(NaN === NaN);         // false
  console.log(0 === -0);            // true
  console.log(Object.is(0, -0));    // false, 内部可能使用 SameValue
  ```

**代码逻辑推理 (假设输入与输出):**

假设我们调用 `StringLessThan` 函数，输入两个 `V<String>` 类型的操作索引，分别代表字符串 "abc" 和 "def"。

```c++
V<String> left_string = /* ... 代表 "abc" 的操作索引 ... */;
V<String> right_string = /* ... 代表 "def" 的操作索引 ... */;
V<Boolean> result = StringLessThan(left_string, right_string);
```

**假设输入:**
- `left_string` 代表字符串 "abc"。
- `right_string` 代表字符串 "def"。

**预期输出:**
- `result` 将代表一个布尔值 `true` 的操作索引，因为 "abc" 在字典序上小于 "def"。

**用户常见的编程错误示例:**

- **类型错误:** 在需要字符串的地方传递了其他类型的对象，例如尝试连接一个数字和一个字符串而没有显式转换。
  ```javascript
  const num = 10;
  const str = "hello";
  const result = num + str; // JavaScript 会将数字转换为字符串，但在编译过程中可能需要进行类型检查和转换操作。
  ```
  在 Turboshaft 内部，如果类型不匹配，可能会导致类型检查失败或需要插入类型转换操作。

- **错误的数组索引:** 访问类型化数组或 `DataView` 时使用超出范围的索引。
  ```javascript
  const buffer = new ArrayBuffer(4);
  const view = new Int32Array(buffer);
  view[1] = 42; // 合法，索引 1 在范围内
  view[10] = 100; // 错误，索引 10 超出范围，会导致运行时错误。
  ```
  在编译过程中，如果编译器能够推断出索引超出范围，可能会生成优化的代码或抛出错误。

- **在 WebAssembly 中错误地使用类型:**  例如，尝试将一个非 null 的值赋给一个需要 null 的变量，或者对类型不匹配的值进行操作。
  ```typescript
  // WebAssembly (使用 TypeScript 语法表示类型)
  function processNullable(value: number | null): void {
    if (value !== null) {
      // ... 对 value 进行操作
    }
  }

  processNullable(10);
  processNullable(null);

  // 如果在 WebAssembly 模块中错误地假设 value 总是非 null，可能会导致错误。
  ```
  `WasmTypeCheck` 等方法用于在编译时或运行时检查 WebAssembly 的类型安全。

**归纳一下它的功能 (作为第 7 部分):**

作为 Turboshaft 编译器流水线的第 7 部分，这个 `assembler.h` 文件定义了 **构建 Turboshaft 中间表示 (IR) 的核心接口**。它提供了一组丰富的方法，用于表达各种 JavaScript 和 WebAssembly 操作，从基本的算术和逻辑运算到更高级的特性如字符串操作、对象属性访问、函数调用以及 WebAssembly 特有的操作。

这个 `Assembler` 类充当了一个 **抽象工厂**，允许编译器的后续阶段（例如 Lowering）将这些高层次的操作转换为目标架构的机器码。它隐藏了底层架构的细节，并提供了一种类型安全的方式来构建 IR 图。

由于这是第 7 部分，可以推断出之前的阶段可能负责语法分析、语义分析以及初步的类型推断，而后续的阶段将会利用这里构建的 IR 进行优化和代码生成。这个阶段的关键作用是将高级语言结构转换为编译器可以进一步处理的中间表示形式。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能

"""
ngConcat(V<Smi> length, V<String> left, V<String> right) {
    return ReduceIfReachableStringConcat(length, left, right);
  }

  V<Boolean> StringComparison(V<String> left, V<String> right,
                              StringComparisonOp::Kind kind) {
    return ReduceIfReachableStringComparison(left, right, kind);
  }
  V<Boolean> StringEqual(V<String> left, V<String> right) {
    return StringComparison(left, right, StringComparisonOp::Kind::kEqual);
  }
  V<Boolean> StringLessThan(V<String> left, V<String> right) {
    return StringComparison(left, right, StringComparisonOp::Kind::kLessThan);
  }
  V<Boolean> StringLessThanOrEqual(V<String> left, V<String> right) {
    return StringComparison(left, right,
                            StringComparisonOp::Kind::kLessThanOrEqual);
  }

  V<Smi> ArgumentsLength() {
    return ReduceIfReachableArgumentsLength(ArgumentsLengthOp::Kind::kArguments,
                                            0);
  }
  V<Smi> RestLength(int formal_parameter_count) {
    DCHECK_LE(0, formal_parameter_count);
    return ReduceIfReachableArgumentsLength(ArgumentsLengthOp::Kind::kRest,
                                            formal_parameter_count);
  }

  V<FixedArray> NewArgumentsElements(V<Smi> arguments_count,
                                     CreateArgumentsType type,
                                     int formal_parameter_count) {
    DCHECK_LE(0, formal_parameter_count);
    return ReduceIfReachableNewArgumentsElements(arguments_count, type,
                                                 formal_parameter_count);
  }

  OpIndex LoadTypedElement(OpIndex buffer, V<Object> base, V<WordPtr> external,
                           V<WordPtr> index, ExternalArrayType array_type) {
    return ReduceIfReachableLoadTypedElement(buffer, base, external, index,
                                             array_type);
  }

  OpIndex LoadDataViewElement(V<Object> object, V<WordPtr> storage,
                              V<WordPtr> index, V<Word32> is_little_endian,
                              ExternalArrayType element_type) {
    return ReduceIfReachableLoadDataViewElement(object, storage, index,
                                                is_little_endian, element_type);
  }

  V<Object> LoadStackArgument(V<Object> base, V<WordPtr> index) {
    return ReduceIfReachableLoadStackArgument(base, index);
  }

  void StoreTypedElement(OpIndex buffer, V<Object> base, V<WordPtr> external,
                         V<WordPtr> index, OpIndex value,
                         ExternalArrayType array_type) {
    ReduceIfReachableStoreTypedElement(buffer, base, external, index, value,
                                       array_type);
  }

  void StoreDataViewElement(V<Object> object, V<WordPtr> storage,
                            V<WordPtr> index, OpIndex value,
                            ConstOrV<Word32> is_little_endian,
                            ExternalArrayType element_type) {
    ReduceIfReachableStoreDataViewElement(
        object, storage, index, value, resolve(is_little_endian), element_type);
  }

  void TransitionAndStoreArrayElement(
      V<Object> array, V<WordPtr> index, OpIndex value,
      TransitionAndStoreArrayElementOp::Kind kind, MaybeHandle<Map> fast_map,
      MaybeHandle<Map> double_map) {
    ReduceIfReachableTransitionAndStoreArrayElement(array, index, value, kind,
                                                    fast_map, double_map);
  }

  void StoreSignedSmallElement(V<Object> array, V<WordPtr> index,
                               V<Word32> value) {
    TransitionAndStoreArrayElement(
        array, index, value,
        TransitionAndStoreArrayElementOp::Kind::kSignedSmallElement, {}, {});
  }

  V<Word32> CompareMaps(V<HeapObject> heap_object, OptionalV<Map> map,
                        const ZoneRefSet<Map>& maps) {
    return ReduceIfReachableCompareMaps(heap_object, map, maps);
  }

  void CheckMaps(V<HeapObject> heap_object,
                 V<turboshaft::FrameState> frame_state, OptionalV<Map> map,
                 const ZoneRefSet<Map>& maps, CheckMapsFlags flags,
                 const FeedbackSource& feedback) {
    ReduceIfReachableCheckMaps(heap_object, frame_state, map, maps, flags,
                               feedback);
  }

  void AssumeMap(V<HeapObject> heap_object, const ZoneRefSet<Map>& maps) {
    ReduceIfReachableAssumeMap(heap_object, maps);
  }

  V<Object> CheckedClosure(V<Object> input,
                           V<turboshaft::FrameState> frame_state,
                           Handle<FeedbackCell> feedback_cell) {
    return ReduceIfReachableCheckedClosure(input, frame_state, feedback_cell);
  }

  void CheckEqualsInternalizedString(V<Object> expected, V<Object> value,
                                     V<turboshaft::FrameState> frame_state) {
    ReduceIfReachableCheckEqualsInternalizedString(expected, value,
                                                   frame_state);
  }

  V<Object> LoadMessage(V<WordPtr> offset) {
    return ReduceIfReachableLoadMessage(offset);
  }

  void StoreMessage(V<WordPtr> offset, V<Object> object) {
    ReduceIfReachableStoreMessage(offset, object);
  }

  V<Boolean> SameValue(V<Object> left, V<Object> right,
                       SameValueOp::Mode mode) {
    return ReduceIfReachableSameValue(left, right, mode);
  }

  V<Word32> Float64SameValue(V<Float64> left, V<Float64> right) {
    return ReduceIfReachableFloat64SameValue(left, right);
  }

  OpIndex FastApiCall(V<turboshaft::FrameState> frame_state,
                      V<Object> data_argument, V<Context> context,
                      base::Vector<const OpIndex> arguments,
                      const FastApiCallParameters* parameters,
                      base::Vector<const RegisterRepresentation> out_reps) {
    return ReduceIfReachableFastApiCall(frame_state, data_argument, context,
                                        arguments, parameters, out_reps);
  }

  void RuntimeAbort(AbortReason reason) {
    ReduceIfReachableRuntimeAbort(reason);
  }

  V<Object> EnsureWritableFastElements(V<Object> object, V<Object> elements) {
    return ReduceIfReachableEnsureWritableFastElements(object, elements);
  }

  V<Object> MaybeGrowFastElements(V<Object> object, V<Object> elements,
                                  V<Word32> index, V<Word32> elements_length,
                                  V<turboshaft::FrameState> frame_state,
                                  GrowFastElementsMode mode,
                                  const FeedbackSource& feedback) {
    return ReduceIfReachableMaybeGrowFastElements(
        object, elements, index, elements_length, frame_state, mode, feedback);
  }

  void TransitionElementsKind(V<HeapObject> object,
                              const ElementsTransition& transition) {
    ReduceIfReachableTransitionElementsKind(object, transition);
  }

  OpIndex FindOrderedHashEntry(V<Object> data_structure, OpIndex key,
                               FindOrderedHashEntryOp::Kind kind) {
    return ReduceIfReachableFindOrderedHashEntry(data_structure, key, kind);
  }
  V<Smi> FindOrderedHashMapEntry(V<Object> table, V<Smi> key) {
    return FindOrderedHashEntry(
        table, key, FindOrderedHashEntryOp::Kind::kFindOrderedHashMapEntry);
  }
  V<Smi> FindOrderedHashSetEntry(V<Object> table, V<Smi> key) {
    return FindOrderedHashEntry(
        table, key, FindOrderedHashEntryOp::Kind::kFindOrderedHashSetEntry);
  }
  V<WordPtr> FindOrderedHashMapEntryForInt32Key(V<Object> table,
                                                V<Word32> key) {
    return FindOrderedHashEntry(
        table, key,
        FindOrderedHashEntryOp::Kind::kFindOrderedHashMapEntryForInt32Key);
  }
  V<Object> SpeculativeNumberBinop(V<Object> left, V<Object> right,
                                   V<turboshaft::FrameState> frame_state,
                                   SpeculativeNumberBinopOp::Kind kind) {
    return ReduceIfReachableSpeculativeNumberBinop(left, right, frame_state,
                                                   kind);
  }

  V<Object> LoadRoot(RootIndex root_index) {
    Isolate* isolate = __ data() -> isolate();
    DCHECK_NOT_NULL(isolate);
    if (RootsTable::IsImmortalImmovable(root_index)) {
      Handle<Object> root = isolate->root_handle(root_index);
      if (i::IsSmi(*root)) {
        return __ SmiConstant(Cast<Smi>(*root));
      } else {
        return HeapConstantMaybeHole(i::Cast<HeapObject>(root));
      }
    }

    // TODO(jgruber): In theory we could generate better code for this by
    // letting the macro assembler decide how to load from the roots list. In
    // most cases, it would boil down to loading from a fixed kRootRegister
    // offset.
    OpIndex isolate_root =
        __ ExternalConstant(ExternalReference::isolate_root(isolate));
    int offset = IsolateData::root_slot_offset(root_index);
    return __ LoadOffHeap(isolate_root, offset,
                          MemoryRepresentation::AnyTagged());
  }

#define HEAP_CONSTANT_ACCESSOR(rootIndexName, rootAccessorName, name)          \
  V<RemoveTagged<                                                              \
      decltype(std::declval<ReadOnlyRoots>().rootAccessorName())>::type>       \
      name##Constant() {                                                       \
    const TurboshaftPipelineKind kind = __ data() -> pipeline_kind();          \
    if (V8_UNLIKELY(kind == TurboshaftPipelineKind::kCSA ||                    \
                    kind == TurboshaftPipelineKind::kTSABuiltin)) {            \
      DCHECK(RootsTable::IsImmortalImmovable(RootIndex::k##rootIndexName));    \
      return V<RemoveTagged<                                                   \
          decltype(std::declval<ReadOnlyRoots>().rootAccessorName())>::type>:: \
          Cast(__ LoadRoot(RootIndex::k##rootIndexName));                      \
    } else {                                                                   \
      Isolate* isolate = __ data() -> isolate();                               \
      DCHECK_NOT_NULL(isolate);                                                \
      Factory* factory = isolate->factory();                                   \
      DCHECK_NOT_NULL(factory);                                                \
      return __ HeapConstant(factory->rootAccessorName());                     \
    }                                                                          \
  }
  HEAP_IMMUTABLE_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_ACCESSOR)
#undef HEAP_CONSTANT_ACCESSOR

#define HEAP_CONSTANT_ACCESSOR(rootIndexName, rootAccessorName, name)       \
  V<RemoveTagged<decltype(std::declval<Heap>().rootAccessorName())>::type>  \
      name##Constant() {                                                    \
    const TurboshaftPipelineKind kind = __ data() -> pipeline_kind();       \
    if (V8_UNLIKELY(kind == TurboshaftPipelineKind::kCSA ||                 \
                    kind == TurboshaftPipelineKind::kTSABuiltin)) {         \
      DCHECK(RootsTable::IsImmortalImmovable(RootIndex::k##rootIndexName)); \
      return V<                                                             \
          RemoveTagged<decltype(std::declval<Heap>().rootAccessorName())>:: \
              type>::Cast(__ LoadRoot(RootIndex::k##rootIndexName));        \
    } else {                                                                \
      Isolate* isolate = __ data() -> isolate();                            \
      DCHECK_NOT_NULL(isolate);                                             \
      Factory* factory = isolate->factory();                                \
      DCHECK_NOT_NULL(factory);                                             \
      return __ HeapConstant(factory->rootAccessorName());                  \
    }                                                                       \
  }
  HEAP_MUTABLE_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_ACCESSOR)
#undef HEAP_CONSTANT_ACCESSOR

#define HEAP_CONSTANT_TEST(rootIndexName, rootAccessorName, name) \
  V<Word32> Is##name(V<Object> value) {                           \
    return TaggedEqual(value, name##Constant());                  \
  }                                                               \
  V<Word32> IsNot##name(V<Object> value) {                        \
    return TaggedNotEqual(value, name##Constant());               \
  }
  HEAP_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_TEST)
#undef HEAP_CONSTANT_TEST

#ifdef V8_ENABLE_WEBASSEMBLY
  V<Any> GlobalGet(V<WasmTrustedInstanceData> trusted_instance_data,
                   const wasm::WasmGlobal* global) {
    return ReduceIfReachableGlobalGet(trusted_instance_data, global);
  }

  OpIndex GlobalSet(V<WasmTrustedInstanceData> trusted_instance_data,
                    V<Any> value, const wasm::WasmGlobal* global) {
    return ReduceIfReachableGlobalSet(trusted_instance_data, value, global);
  }

  V<HeapObject> Null(wasm::ValueType type) {
    return ReduceIfReachableNull(type);
  }

  V<Word32> IsNull(V<Object> input, wasm::ValueType type) {
    return ReduceIfReachableIsNull(input, type);
  }

  V<Object> AssertNotNull(V<Object> object, wasm::ValueType type,
                          TrapId trap_id) {
    return ReduceIfReachableAssertNotNull(object, type, trap_id);
  }

  V<Map> RttCanon(V<FixedArray> rtts, wasm::ModuleTypeIndex type_index) {
    return ReduceIfReachableRttCanon(rtts, type_index);
  }

  V<Word32> WasmTypeCheck(V<Object> object, OptionalV<Map> rtt,
                          WasmTypeCheckConfig config) {
    return ReduceIfReachableWasmTypeCheck(object, rtt, config);
  }

  V<Object> WasmTypeCast(V<Object> object, OptionalV<Map> rtt,
                         WasmTypeCheckConfig config) {
    return ReduceIfReachableWasmTypeCast(object, rtt, config);
  }

  V<Object> AnyConvertExtern(V<Object> input) {
    return ReduceIfReachableAnyConvertExtern(input);
  }

  V<Object> ExternConvertAny(V<Object> input) {
    return ReduceIfReachableExternConvertAny(input);
  }

  template <typename T>
  V<T> AnnotateWasmType(V<T> value, const wasm::ValueType type) {
    return ReduceIfReachableWasmTypeAnnotation(value, type);
  }

  V<Any> StructGet(V<WasmStructNullable> object, const wasm::StructType* type,
                   wasm::ModuleTypeIndex type_index, int field_index,
                   bool is_signed, CheckForNull null_check) {
    return ReduceIfReachableStructGet(object, type, type_index, field_index,
                                      is_signed, null_check);
  }

  void StructSet(V<WasmStructNullable> object, V<Any> value,
                 const wasm::StructType* type, wasm::ModuleTypeIndex type_index,
                 int field_index, CheckForNull null_check) {
    ReduceIfReachableStructSet(object, value, type, type_index, field_index,
                               null_check);
  }

  V<Any> ArrayGet(V<WasmArrayNullable> array, V<Word32> index,
                  const wasm::ArrayType* array_type, bool is_signed) {
    return ReduceIfReachableArrayGet(array, index, array_type, is_signed);
  }

  void ArraySet(V<WasmArrayNullable> array, V<Word32> index, V<Any> value,
                wasm::ValueType element_type) {
    ReduceIfReachableArraySet(array, index, value, element_type);
  }

  V<Word32> ArrayLength(V<WasmArrayNullable> array, CheckForNull null_check) {
    return ReduceIfReachableArrayLength(array, null_check);
  }

  V<WasmArray> WasmAllocateArray(V<Map> rtt, ConstOrV<Word32> length,
                                 const wasm::ArrayType* array_type) {
    return ReduceIfReachableWasmAllocateArray(rtt, resolve(length), array_type);
  }

  V<WasmStruct> WasmAllocateStruct(V<Map> rtt,
                                   const wasm::StructType* struct_type) {
    return ReduceIfReachableWasmAllocateStruct(rtt, struct_type);
  }

  V<WasmFuncRef> WasmRefFunc(V<Object> wasm_instance, uint32_t function_index) {
    return ReduceIfReachableWasmRefFunc(wasm_instance, function_index);
  }

  V<String> StringAsWtf16(V<String> string) {
    return ReduceIfReachableStringAsWtf16(string);
  }

  V<turboshaft::Tuple<Object, WordPtr, Word32>> StringPrepareForGetCodeUnit(
      V<Object> string) {
    return ReduceIfReachableStringPrepareForGetCodeUnit(string);
  }

  V<Simd128> Simd128Constant(const uint8_t value[kSimd128Size]) {
    return ReduceIfReachableSimd128Constant(value);
  }

  V<Simd128> Simd128Binop(V<Simd128> left, V<Simd128> right,
                          Simd128BinopOp::Kind kind) {
    return ReduceIfReachableSimd128Binop(left, right, kind);
  }

  V<Simd128> Simd128Unary(V<Simd128> input, Simd128UnaryOp::Kind kind) {
    return ReduceIfReachableSimd128Unary(input, kind);
  }

  V<Simd128> Simd128ReverseBytes(V<Simd128> input) {
    return Simd128Unary(input, Simd128UnaryOp::Kind::kSimd128ReverseBytes);
  }

  V<Simd128> Simd128Shift(V<Simd128> input, V<Word32> shift,
                          Simd128ShiftOp::Kind kind) {
    return ReduceIfReachableSimd128Shift(input, shift, kind);
  }

  V<Word32> Simd128Test(V<Simd128> input, Simd128TestOp::Kind kind) {
    return ReduceIfReachableSimd128Test(input, kind);
  }

  V<Simd128> Simd128Splat(V<Any> input, Simd128SplatOp::Kind kind) {
    return ReduceIfReachableSimd128Splat(input, kind);
  }

  V<Simd128> Simd128Ternary(V<Simd128> first, V<Simd128> second,
                            V<Simd128> third, Simd128TernaryOp::Kind kind) {
    return ReduceIfReachableSimd128Ternary(first, second, third, kind);
  }

  V<Any> Simd128ExtractLane(V<Simd128> input, Simd128ExtractLaneOp::Kind kind,
                            uint8_t lane) {
    return ReduceIfReachableSimd128ExtractLane(input, kind, lane);
  }

  V<Simd128> Simd128Reduce(V<Simd128> input, Simd128ReduceOp::Kind kind) {
    return ReduceIfReachableSimd128Reduce(input, kind);
  }

  V<Simd128> Simd128ReplaceLane(V<Simd128> into, V<Any> new_lane,
                                Simd128ReplaceLaneOp::Kind kind, uint8_t lane) {
    return ReduceIfReachableSimd128ReplaceLane(into, new_lane, kind, lane);
  }

  OpIndex Simd128LaneMemory(V<WordPtr> base, V<WordPtr> index, V<WordPtr> value,
                            Simd128LaneMemoryOp::Mode mode,
                            Simd128LaneMemoryOp::Kind kind,
                            Simd128LaneMemoryOp::LaneKind lane_kind,
                            uint8_t lane, int offset) {
    return ReduceIfReachableSimd128LaneMemory(base, index, value, mode, kind,
                                              lane_kind, lane, offset);
  }

  V<Simd128> Simd128LoadTransform(
      V<WordPtr> base, V<WordPtr> index,
      Simd128LoadTransformOp::LoadKind load_kind,
      Simd128LoadTransformOp::TransformKind transform_kind, int offset) {
    return ReduceIfReachableSimd128LoadTransform(base, index, load_kind,
                                                 transform_kind, offset);
  }

  V<Simd128> Simd128Shuffle(V<Simd128> left, V<Simd128> right,
                            const uint8_t shuffle[kSimd128Size]) {
    return ReduceIfReachableSimd128Shuffle(left, right, shuffle);
  }

  // SIMD256
#if V8_ENABLE_WASM_SIMD256_REVEC
  V<Simd256> Simd256Constant(const uint8_t value[kSimd256Size]) {
    return ReduceIfReachableSimd256Constant(value);
  }

  OpIndex Simd256Extract128Lane(V<Simd256> source, uint8_t lane) {
    return ReduceIfReachableSimd256Extract128Lane(source, lane);
  }

  V<Simd256> Simd256LoadTransform(
      V<WordPtr> base, V<WordPtr> index,
      Simd256LoadTransformOp::LoadKind load_kind,
      Simd256LoadTransformOp::TransformKind transform_kind, int offset) {
    return ReduceIfReachableSimd256LoadTransform(base, index, load_kind,
                                                 transform_kind, offset);
  }

  V<Simd256> Simd256Unary(V<Simd256> input, Simd256UnaryOp::Kind kind) {
    return ReduceIfReachableSimd256Unary(input, kind);
  }

  V<Simd256> Simd256Unary(V<Simd128> input, Simd256UnaryOp::Kind kind) {
    DCHECK_GE(kind, Simd256UnaryOp::Kind::kFirstSignExtensionOp);
    DCHECK_LE(kind, Simd256UnaryOp::Kind::kLastSignExtensionOp);
    return ReduceIfReachableSimd256Unary(input, kind);
  }

  V<Simd256> Simd256Binop(V<Simd256> left, V<Simd256> right,
                          Simd256BinopOp::Kind kind) {
    return ReduceIfReachableSimd256Binop(left, right, kind);
  }

  V<Simd256> Simd256Binop(V<Simd128> left, V<Simd128> right,
                          Simd256BinopOp::Kind kind) {
    DCHECK_GE(kind, Simd256BinopOp::Kind::kFirstSignExtensionOp);
    DCHECK_LE(kind, Simd256BinopOp::Kind::kLastSignExtensionOp);
    return ReduceIfReachableSimd256Binop(left, right, kind);
  }

  V<Simd256> Simd256Shift(V<Simd256> input, V<Word32> shift,
                          Simd256ShiftOp::Kind kind) {
    return ReduceIfReachableSimd256Shift(input, shift, kind);
  }

  V<Simd256> Simd256Ternary(V<Simd256> first, V<Simd256> second,
                            V<Simd256> third, Simd256TernaryOp::Kind kind) {
    return ReduceIfReachableSimd256Ternary(first, second, third, kind);
  }

  V<Simd256> Simd256Splat(OpIndex input, Simd256SplatOp::Kind kind) {
    return ReduceIfReachableSimd256Splat(input, kind);
  }

  V<Simd256> SimdPack128To256(V<Simd128> left, V<Simd128> right) {
    return ReduceIfReachableSimdPack128To256(left, right);
  }

#ifdef V8_TARGET_ARCH_X64
  V<Simd256> Simd256Shufd(V<Simd256> input, const uint8_t control) {
    return ReduceIfReachableSimd256Shufd(input, control);
  }

  V<Simd256> Simd256Shufps(V<Simd256> left, V<Simd256> right,
                           const uint8_t control) {
    return ReduceIfReachableSimd256Shufps(left, right, control);
  }

  V<Simd256> Simd256Unpack(V<Simd256> left, V<Simd256> right,
                           Simd256UnpackOp::Kind kind) {
    return ReduceIfReachableSimd256Unpack(left, right, kind);
  }
#endif  // V8_TARGET_ARCH_X64
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

  V<WasmTrustedInstanceData> WasmInstanceDataParameter() {
    return Parameter(wasm::kWasmInstanceDataParameterIndex,
                     RegisterRepresentation::Tagged());
  }

  OpIndex LoadStackPointer() { return ReduceIfReachableLoadStackPointer(); }

  void SetStackPointer(V<WordPtr> value) {
    ReduceIfReachableSetStackPointer(value);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  V<Object> GetContinuationPreservedEmbedderData() {
    return ReduceIfReachableGetContinuationPreservedEmbedderData();
  }

  void SetContinuationPreservedEmbedderData(V<Object> data) {
    ReduceIfReachableSetContinuationPreservedEmbedderData(data);
  }
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  template <typename Rep>
  V<Rep> resolve(const V<Rep>& v) {
    return v;
  }
  V<Word32> resolve(const ConstOrV<Word32>& v) {
    return v.is_constant() ? Word32Constant(v.constant_value()) : v.value();
  }
  V<Word64> resolve(const ConstOrV<Word64>& v) {
    return v.is_constant() ? Word64Constant(v.constant_value()) : v.value();
  }
  V<Float32> resolve(const ConstOrV<Float32>& v) {
    return v.is_constant() ? Float32Constant(v.constant_value()) : v.value();
  }
  V<Float64> resolve(const ConstOrV<Float64>& v) {
    return v.is_constant() ? Float64Constant(v.constant_value()) : v.value();
  }

 private:
#ifdef DEBUG
#define REDUCE_OP(Op)                                                    \
  template <class... Args>                                               \
  V8_INLINE OpIndex ReduceIfReachable##Op(Args... args) {                \
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) {        \
      DCHECK(Asm().conceptually_in_a_block());                           \
      return OpIndex::Invalid();                                         \
    }                                                                    \
    OpIndex result = Asm().Reduce##Op(args...);                          \
    if constexpr (!IsBlockTerminator(Opcode::k##Op)) {                   \
      if (Asm().current_block() == nullptr) {                            \
        /* The input operation was not a block terminator, but a reducer \
         * lowered it into a block terminator. */                        \
        Asm().set_conceptually_in_a_block(true);                         \
      }                                                                  \
    }                                                                    \
    return result;                                                       \
  }
#else
#define REDUCE_OP(Op)                                             \
  template <class... Args>                                        \
  V8_INLINE OpIndex ReduceIfReachable##Op(Args... args) {         \
    if (V8_UNLIKELY(Asm().generating_unreachable_operations())) { \
      return OpIndex::Invalid();                                  \
    }                                                             \
    return Asm().Reduce##Op(args...);                             \
  }
#endif
  TURBOSHAFT_OPERATION_LIST(REDUCE_OP)
#undef REDUCE_OP

  // LoadArrayBufferElement and LoadNonArrayBufferElement should be called
  // instead of LoadElement.
  template <typename T = Any, typename Base>
  V<T> LoadElement(V<Base> object, const ElementAccess& access,
                   V<WordPtr> index, bool is_array_buffer) {
    if constexpr (is_taggable_v<Base>) {
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kTaggedBase);
    } else {
      static_assert(std::is_same_v<Base, WordPtr>);
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kUntaggedBase);
    }
    LoadOp::Kind kind = LoadOp::Kind::Aligned(access.base_is_tagged);
    if (is_array_buffer) kind = kind.NotLoadEliminable();
    MemoryRepresentation rep =
        MemoryRepresentation::FromMachineType(access.machine_type);
    return Load(object, index, kind, rep, access.header_size,
                rep.SizeInBytesLog2());
  }

  // StoreArrayBufferElement and StoreNonArrayBufferElement should be called
  // instead of StoreElement.
  template <typename Base>
  void StoreElement(V<Base> object, const ElementAccess& access,
                    ConstOrV<WordPtr> index, V<Any> value,
                    bool is_array_buffer) {
    if constexpr (is_taggable_v<Base>) {
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kTaggedBase);
    } else {
      static_assert(std::is_same_v<Base, WordPtr>);
      DCHECK_EQ(access.base_is_tagged, BaseTaggedness::kUntaggedBase);
    }
    LoadOp::Kind kind = LoadOp::Kind::Aligned(access.base_is_tagged);
    if (is_array_buffer) kind = kind.NotLoadEliminable();
    MemoryRepresentation rep =
        MemoryRepresentation::FromMachineType(access.machine_type);
    Store(object, resolve(index), value, kind, rep, access.write_barrier_kind,
          access.header_size, rep.SizeInBytesLog2());
  }

  // BranchAndBind should be called from GotoIf/GotoIfNot. It will insert a
  // Branch, bind {to_bind} (which should correspond to the implicit new block
  // following the GotoIf/GotoIfNot) and return a ConditionalGotoStatus
  // representing whether the destinations of the Branch are reachable or not.
  ConditionalGotoStatus BranchAndBind(V<Word32> condition, Block* if_true,
                                      Block* if_false, BranchHint hint,
                                      Block* to_bind) {
    DCHECK_EQ(to_bind, any_of(if_true, if_false));
    Block* other = to_bind == if_true ? if_false : if_true;
    Block* to_bind_last_pred = to_bind->LastPredecessor();
    Block* other_last_pred = other->LastPredecessor();
    Asm().Branch(condition, if_true, if_false, hint);
    bool to_bind_reachable = to_bind_last_pred != to_bind->LastPredecessor();
    bool other_reachable = other_last_pred != other->LastPredecessor();
    ConditionalGotoStatus status = static_cast<ConditionalGotoStatus>(
        static_cast<int>(other_reachable) | ((to_bind_reachable) << 1));
    bool bind_status = Asm().Bind(to_bind);
    DCHECK_EQ(bind_status, to_bind_reachable);
    USE(bind_status);
    return status;
  }

  base::SmallVector<OpIndex, 16> cached_parameters_;
  // [0] contains the stub with exit frame.
  MaybeHandle<Code> cached_centry_stub_constants_[4];
  bool in_object_initialization_ = false;

  OperationMatcher matcher_;
};

// Some members of Assembler that are used in the constructors of the stack are
// extracted to the AssemblerData class, so that they can be initialized before
// the rest of the stack, and thus don't need to be passed as argument to all of
// the constructors of the stack.
struct AssemblerData {
  // TODO(dmercadier): consider removing input_graph from this, and only having
  // it in GraphVisitor for Stacks that have it.
  AssemblerData(PipelineData* data, Graph& input_graph, Graph& output_graph,
                Zone* phase_zone)
      : data(data),
        phase_zone(phase_zone),
        input_graph(input_graph),
        output_graph(output_graph) {}
  PipelineData* data;
  Zone* phase_zone;
  Graph& input_graph;
  Graph& output_graph;
};

template <class Reducers>
class Assembler : public AssemblerData,
                  public ReducerStack<Reducers>::type,
                  public TurboshaftAssemblerOpInterface<Assembler<Reducers>> {
  using Stack = typename ReducerStack<Reducers>::type;
  using node_t = typename Stack::node_t;

 public:
  explicit Assembler(PipelineData* data, Graph& input_graph,
                     Graph& output_graph, Zone* phase_zone)
      : AssemblerData(data, input_graph, output_graph, phase_zone), Stack() {
    SupportedOperations::Initialize();
  }

  using Stack::Asm;

  PipelineData* data() const { return AssemblerData::data; }
  Zone* phase_zone() { return AssemblerData::phase_zone; }
  const Graph& input_graph() const { return AssemblerData::input_graph; }
  Graph& output_graph() const { return AssemblerData::output_graph; }
  Zone* graph_zone() const { return output_graph().graph_zone(); }

  // When analyzers detect that an operation is dead, they replace its opcode by
  // kDead in-place, and thus need to have a non-const input graph.
  Graph& modifiable_input_graph() const { return AssemblerData::input_graph; }

  Block* NewLoopHeader() { return this->output_graph().NewLoopHeader(); }
  Block* NewBlock() { return this->output_graph().NewBlock(); }

// This condition is true for any compiler except GCC.
#if defined(__clang__) || !defined(V8_CC_GNU)
  V8_INLINE
#endif
  bool Bind(Block* block) {
#ifdef DEBUG
    set_conceptually_in_a_block(true);
#endif

    if (block->IsLoop() && block->single_loop_predecessor()) {
      // {block} is a loop header that had multiple incoming forward edges, and
      // for which we've created a "single_predecessor" block. We bind it now,
      // and insert a single Goto to the original loop header.
      BindReachable(block->single_loop_predecessor());
      // We need to go through a raw Emit because calling this->Goto would go
      // through AddPredecessor and SplitEdge, which would wrongly try to
      // prevent adding more predecessors to the loop header.
      this->template Emit<GotoOp>(block, /*is_backedge*/ false);
    }

    if (!this->output_graph().Add(block)) {
      return false;
    }
    DCHECK_NULL(current_block_);
    current_block_ = block;
    Stack::Bind(block);
    return true;
  }

  // TODO(nicohartmann@): Remove this.
  V8_INLINE void BindReachable(Block* block) {
    bool bound = Bind(block);
    DCHECK(bound);
    USE(bound);
  }

  // Every loop should be finalized once, after it is certain that no backedge
  // can be added anymore.
  void FinalizeLoop(Block* loop_header) {
    if (loop_header->IsLoop() && loop_header->PredecessorCount() == 1) {
      this->output_graph().TurnLoopIntoMerge(loop_header);
    }
  }

  void SetCurrentOrigin(OpIndex operation_origin) {
    current_operation_origin_ = operation_origin;
  }

#ifdef DEBUG
  void set_conceptually_in_a_block(bool value) {
    conceptually_in_a_block_ = value;
  }
  bool conceptually_in_a_block() { return conceptually_in_a_block_; }
#endif

  Block* current_block() const { return current_block_; }
  bool generating_unreachable_operations() const {
    return current_block() == nullptr;
  }
  V<AnyOrNone> current_operation_origin() const {
    return current_operation_origin_;
  }

  const Operation& Get(OpIndex op_idx) const {
    return this->output_graph().Get(op_idx);
  }

  Block* current_catch_block() const { return current_catch_block_; }
  // CatchScope should be used in most cases to set the current catch block, but
  // this is sometimes impractical.
  void set_current_catch_block(Block* block) { current_catch_block_ = block; }

#ifdef DEBUG
  int& intermediate_tracing_depth() { return intermediate_tracing_depth_; }
#endif

  // ReduceProjection elimin
"""


```
Response:
My goal is to analyze the provided C++ code snippet from V8's `code-stub-assembler.h` and extract its functionalities. Here's a breakdown of the thinking process to achieve the desired output:

1. **Understanding the Core Purpose:** The filename `code-stub-assembler.h` strongly suggests this header defines a class or set of utilities for generating low-level code stubs within V8. The "assembler" part indicates it deals with machine-level instructions or an abstraction layer close to it.

2. **Initial Scan for Key Functionalities:** I'll read through the code, looking for groups of related functions or obvious patterns. Keywords like `GetProperty`, `SetProperty`, `LoadProperty`, `TryLookupProperty`, `StoreElement`, `BuildFastLoop`, and `RelationalComparison` immediately stand out as potential areas of functionality.

3. **Categorizing Function Groups:**  Based on the initial scan, I can start grouping functions. For example:
    * **Property Access:**  Functions like `GetProperty`, `SetPropertyStrict`, `CreateDataProperty`, `GetMethod`, `GetInterestingProperty`, `TryLookupProperty`, `TryLookupPropertyInSimpleObject`.
    * **Property Loading:** Functions like `LoadPropertyFromFastObject`, `LoadPropertyFromDictionary`, `LoadPropertyFromGlobalDictionary`.
    * **Prototype Chain Traversal:** Functions like `TryPrototypeChainLookup`.
    * **Element Access (Arrays):** Functions like `StoreElement`, `EmitElementStore`, `CheckForCapacityGrow`, `CopyElementsOnWrite`, `TransitionElementsKind`.
    * **Looping Constructs:** Functions like `BuildFastLoop`, `BuildFastArrayForEach`.
    * **Type Checking/Conversion:** Functions like `IsInterestingProperty`, `Int32ToUint8Clamped`, `Float64ToUint8Clamped`, `PrepareValueForWriteToTypedArray`.
    * **Feedback Vector Management:** Functions like `LoadFeedbackVectorForStub`, `UpdateFeedback`, `CombineFeedback`.
    * **Object/Map Operations:** Functions like `AllocatePropertyDescriptorObject`, `InitializePropertyDescriptorObject`, `LoadReceiverMap`.
    * **Comparison Operations:** Functions like `RelationalComparison`, `BranchIfNumberEqual`, `Equal`, `StrictEqual`, `BranchIfSameValue`.
    * **Array Buffer/Typed Array Handling:**  A significant block of functions deals with `JSArrayBuffer` and `JSTypedArray`.
    * **Builtin Function Loading:** Functions like `LoadBuiltin`.
    * **Debugging:** `IsDebugActive`.

4. **Describing Each Functionality:**  For each category, I'll summarize the purpose of the functions within it. I'll try to use clear and concise language, focusing on the "what" rather than the "how" at this stage.

5. **Checking for Torque Connection:** The prompt mentions `.tq` files and Torque. I'll explicitly check if the header file name ends in `.tq`. In this case, it doesn't, so I'll note that.

6. **Identifying JavaScript Relevance and Examples:** This is crucial. For each functional category, I'll consider how it relates to JavaScript's behavior. I'll provide simple JavaScript examples to illustrate the corresponding C++ functions' roles. For instance:
    * Property access in JS maps to the `GetProperty` family of functions.
    * Array element access in JS relates to `StoreElement`, `EmitElementStore`, etc.
    * Loops in JS are related to `BuildFastLoop`.
    * Comparisons in JS tie into the `RelationalComparison` and `Equal` functions.
    * Typed arrays in JS directly correspond to the `JSArrayBuffer` and `JSTypedArray` related functions.

7. **Illustrating Code Logic with Input/Output:** Where the function names suggest a clear logical transformation, I'll provide hypothetical inputs and expected outputs. For example, `Int32ToUint8Clamped` with an input of 300 would likely output 255 due to clamping. `ElementOffsetFromIndex` would take an index and element kind and return a memory offset.

8. **Highlighting Common Programming Errors:**  I'll think about common JavaScript mistakes that the code in this header might help prevent or handle. Examples include:
    * Accessing non-existent properties leading to `undefined`.
    * Setting properties on non-objects causing errors.
    * Indexing arrays out of bounds.
    * Type mismatches when working with typed arrays.

9. **Summarizing the Overall Functionality:**  Finally, I'll synthesize all the identified functionalities into a concise summary, reiterating the role of `code-stub-assembler.h` in generating efficient code for core JavaScript operations.

10. **Addressing the "Part 6 of 8" Instruction:** This indicates I should focus on summarizing the *specific* functionalities present in *this* snippet, rather than the entire `code-stub-assembler.h` file if it were longer. The previous parts likely covered other aspects.

**Self-Correction/Refinement During the Process:**

* **Initial Overlap:** I might initially categorize some functions incorrectly. For instance, `GetMethod` could fall under property access or method invocation. I'll refine these categories as I understand the nuances better.
* **Specificity of Examples:** My initial JavaScript examples might be too generic. I'll strive for examples that clearly demonstrate the connection to the specific C++ functions.
* **Technical Jargon:**  I need to balance technical accuracy with understandable language. I'll avoid overly V8-specific terms unless necessary and provide context when using them.
* **Completeness:** I'll reread the code snippet to ensure I haven't missed any significant functional areas.

By following this structured approach, I can systematically analyze the C++ code and generate a comprehensive and informative response that addresses all aspects of the prompt.
好的，让我们来分析一下 `v8/src/codegen/code-stub-assembler.h` 这个代码片段的功能。

**功能概览**

这个代码片段是 V8 引擎中 `CodeStubAssembler` 的头文件，它定义了一系列用于生成优化的、特定用途的机器码片段（称为 code stubs）的工具函数。  这些 code stubs 用于实现 JavaScript 语言的关键操作，例如属性访问、函数调用、类型转换等。  `CodeStubAssembler` 提供了一个 DSL (Domain Specific Language)，允许开发者以一种更高级的方式来描述底层的机器码逻辑，而无需直接编写汇编代码。

**具体功能列表**

1. **属性访问和操作:**
   - `GetOwnProperty`: 获取对象的自有属性，可以处理不同模式（例如，是否期望接收者）。
   - `AllocatePropertyDescriptorObject`, `InitializePropertyDescriptorObject`:  用于创建和初始化属性描述符对象，这在定义或修改对象属性的特性时使用。
   - `GetProperty`: 获取属性值，内部调用了内置函数 `kGetProperty`。
   - `IsInterestingProperty`:  判断属性名是否是“有趣的”属性（可能需要特殊处理）。
   - `GetInterestingProperty`: 获取“有趣的”属性。
   - `SetPropertyStrict`: 严格模式下设置属性值，内部调用了内置函数 `kSetProperty`。
   - `CreateDataProperty`: 创建数据属性，内部调用了内置函数 `kCreateDataProperty`。
   - `GetMethod`: 获取对象的方法。
   - `TryLookupProperty`:  尝试查找属性，根据对象类型（快速对象、字典对象、全局对象）跳转到不同的标签。
   - `TryLookupPropertyInSimpleObject`:  在简单对象中查找属性。
   - `TryLookupElement`: 尝试查找元素（用于数组等）。
   - `BranchIfMaybeSpecialIndex`: 判断字符串是否可能是特殊的索引。
   - `TryPrototypeChainLookup`:  在原型链上查找属性或元素。

2. **迭代器支持:**
   - `GetIteratorMethod`: 获取对象的迭代器方法。
   - `CreateAsyncFromSyncIterator`: 创建将同步迭代器转换为异步迭代器的对象。

3. **底层数据加载:**
   - `LoadPropertyFromFastObject`: 从快速对象加载属性。
   - `LoadPropertyFromDictionary`: 从字典对象加载属性。
   - `LoadPropertyFromGlobalDictionary`: 从全局字典加载属性。

4. **类型反馈 (Type Feedback) 机制:**
   - `LoadBytecodeArrayFromBaseline`: 从基线编译的代码中加载字节码数组。
   - `LoadFeedbackVectorForStub`, `LoadFeedbackVectorFromBaseline`, `LoadFeedbackVectorForStubWithTrampoline`: 加载类型反馈向量。
   - `LoadContextFromBaseline`: 从基线编译的代码中加载上下文。
   - `LoadFeedbackCellValue`: 加载闭包的反馈单元格的值。
   - `LoadFeedbackVector`: 加载闭包的反馈向量。
   - `LoadClosureFeedbackArray`: 加载闭包的反馈单元格数组。
   - `UpdateFeedback`, `MaybeUpdateFeedback`: 更新类型反馈信息。
   - `ReportFeedbackUpdate`: 报告反馈更新。
   - `CombineFeedback`, `OverwriteFeedback`: 合并或覆盖反馈信息。
   - `CheckForAssociatedProtector`: 检查属性名是否关联了保护器（用于优化）。

5. **对象和 Map 操作:**
   - `LoadReceiverMap`: 加载接收者的 Map 对象。

6. **上下文 (Context) 操作:**
   - `LoadScriptContext`: 从脚本上下文表中加载脚本上下文。
   - `GotoIfHasContextExtensionUpToDepth`: 如果上下文链中有扩展，则跳转。

7. **类型转换:**
   - `Int32ToUint8Clamped`, `Float64ToUint8Clamped`:  将数值转换为 `uint8_t` 并进行钳制。
   - `PrepareValueForWriteToTypedArray`:  准备要写入 TypedArray 的值。

8. **数组元素操作:**
   - `StoreElement`: 存储元素到数组中。
   - `BigIntToRawBytes`: 将 BigInt 转换为原始字节。
   - `EmitElementStore`: 发射元素存储操作的代码。
   - `CheckForCapacityGrow`: 检查数组容量是否需要增长。
   - `CopyElementsOnWrite`:  写入时复制数组元素。
   - `TransitionElementsKind`: 转换数组的元素类型。

9. **内存管理助手:**
   - `TrapAllocationMemento`:  检查对象是否分配了 memento。
   - `MemoryChunkFromAddress`, `PageMetadataFromMemoryChunk`, `PageMetadataFromAddress`:  用于获取内存页元数据。

10. **弱引用:**
    - `StoreWeakReferenceInFeedbackVector`: 在反馈向量中存储弱引用。

11. **Allocation Site (分配站点) 相关:**
    - `CreateAllocationSiteInFeedbackVector`: 在反馈向量中创建新的分配站点。
    - `HasBoilerplate`, `LoadTransitionInfo`, `LoadBoilerplate`, `LoadElementsKind`, `LoadNestedAllocationSite`:  处理分配站点信息，用于对象字面量等的优化。

12. **循环构建:**
    - `BuildFastLoop`: 构建快速循环结构。
    - `BuildFastArrayForEach`: 构建用于遍历数组的快速循环。
    - `GetArrayAllocationSize`, `GetFixedArrayAllocationSize`, `GetPropertyArrayAllocationSize`: 计算数组的分配大小。
    - `GotoIfFixedArraySizeDoesntFitInNewSpace`:  如果固定数组的大小不适合在新生代分配，则跳转。

13. **字段初始化:**
    - `InitializeFieldsWithRoot`:  使用 Root 对象初始化字段。

14. **比较操作:**
    - `RelationalComparison`:  执行关系比较。
    - `BranchIfNumberRelationalComparison`:  如果数字关系比较结果为真/假，则跳转。
    - `BranchIfNumberEqual`, `BranchIfNumberNotEqual`, `BranchIfNumberLessThan`, `BranchIfNumberLessThanOrEqual`, `BranchIfNumberGreaterThan`, `BranchIfNumberGreaterThanOrEqual`:  针对数字的特定比较跳转。
    - `BranchIfAccessorPair`: 判断是否是访问器对。
    - `GotoIfNumberGreaterThanOrEqual`:  如果数字大于等于，则跳转。
    - `Equal`: 执行相等性比较。
    - `StrictEqual`: 执行严格相等性比较。
    - `GotoIfStringEqual`, `BranchIfStringEqual`:  字符串相等性判断。
    - `BranchIfSameValue`, `BranchIfSameNumberValue`:  判断是否 SameValue。

15. **属性存在性检查:**
    - `HasProperty`, `HasProperty_Inline`: 检查对象是否拥有某个属性。
    - `ForInPrepare`: 为 `for...in` 循环做准备。

16. **类型判断:**
    - `Typeof`:  实现 `typeof` 操作符。

17. **原型链操作:**
    - `GetSuperConstructor`: 获取父构造函数。
    - `SpeciesConstructor`: 获取用于创建派生对象的构造函数。
    - `InstanceOf`:  实现 `instanceof` 操作符。
    - `OrdinaryHasInstance`:  实现 `OrdinaryHasInstance` 抽象操作。
    - `HasInPrototypeChain`: 判断对象原型链上是否存在某个原型。

18. **调试助手:**
    - `IsDebugActive`:  判断调试器是否激活。

19. **ArrayBuffer 和 TypedArray 助手:**
    - `LoadJSArrayBufferByteLength`, `LoadJSArrayBufferMaxByteLength`, `LoadJSArrayBufferBackingStorePtr`:  加载 `JSArrayBuffer` 的属性。
    - `ThrowIfArrayBufferIsDetached`:  如果 `ArrayBuffer` 已分离，则抛出异常。
    - `LoadJSArrayBufferViewBuffer`, `LoadJSArrayBufferViewByteLength`, `StoreJSArrayBufferViewByteLength`, `LoadJSArrayBufferViewByteOffset`, `StoreJSArrayBufferViewByteOffset`:  加载和存储 `JSArrayBufferView` 的属性。
    - `ThrowIfArrayBufferViewBufferIsDetached`: 如果 `ArrayBufferView` 的缓冲区已分离，则抛出异常。
    - `LoadJSTypedArrayLength`, `StoreJSTypedArrayLength`, `LoadJSTypedArrayLengthAndCheckDetached`, `LoadVariableLengthJSTypedArrayLength`, `LoadVariableLengthJSTypedArrayByteLength`, `LoadVariableLengthJSArrayBufferViewByteLength`: 加载和存储 `JSTypedArray` 的长度。
    - `IsJSArrayBufferViewDetachedOrOutOfBounds`, `IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean`: 检查 `ArrayBufferView` 是否已分离或越界。
    - `CheckJSTypedArrayIndex`: 检查 `JSTypedArray` 的索引是否有效。
    - `RabGsabElementsKindToElementByteSize`: 获取共享数组缓冲区组（RAB GSAB）元素类型的字节大小。
    - `LoadJSTypedArrayDataPtr`: 加载 `JSTypedArray` 的数据指针。
    - `GetTypedArrayBuffer`: 获取 `JSTypedArray` 的缓冲区。
    - `ElementOffsetFromIndex`, `OffsetOfElementAt`: 计算元素在数组中的偏移量。
    - `IsOffsetInBounds`: 检查偏移量是否在边界内。

20. **内置函数 (Builtin) 加载:**
    - `LoadBuiltin`: 从 isolate 的 builtin 数组中加载内置函数的代码。
    - `LoadBuiltinDispatchHandle`, `LoadCodeObjectFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`:  在启用了 Leap Tiering 的情况下，加载内置函数的调度句柄和相关信息。

21. **动态参数计数支持:**
    - (注释部分)  表明代码可能需要支持动态的参数计数。

**关于 .tq 结尾**

如果 `v8/src/codegen/code-stub-assembler.h` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。 Torque 是 V8 团队开发的一种领域特定语言，用于更安全、更易于维护的方式生成高效的 C++ 代码，这些代码通常用于实现 V8 的内置函数和运行时部分。  但是，根据你提供的文件名，它以 `.h` 结尾，所以它是一个 C++ 头文件，定义了 `CodeStubAssembler` 类的接口。  Torque 文件通常会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例**

`CodeStubAssembler` 中的功能与 JavaScript 的核心操作息息相关。以下是一些 JavaScript 示例以及它们可能在底层如何使用 `CodeStubAssembler` 中的函数：

* **属性访问:**
   ```javascript
   const obj = { x: 10 };
   console.log(obj.x); //  底层可能使用 GetProperty
   ```
   `GetProperty` 函数会被调用来查找 `obj` 的 `x` 属性并返回其值。

* **属性设置:**
   ```javascript
   const obj = {};
   obj.y = 20; // 底层可能使用 SetPropertyStrict 或 CreateDataProperty
   ```
   `SetPropertyStrict` (在严格模式下) 或 `CreateDataProperty` 会被用来在 `obj` 上创建或修改 `y` 属性。

* **函数调用:**
   ```javascript
   function add(a, b) { return a + b; }
   add(5, 3); // 底层涉及到参数传递、上下文设置等，CodeStubAssembler 用于生成调用桩
   ```
   `CodeStubAssembler` 用于生成高效的代码来处理函数调用，包括参数的传递和执行上下文的设置。

* **数组操作:**
   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[1]); // 底层可能使用 TryLookupElement 或 LoadElement
   arr[0] = 10; // 底层可能使用 StoreElement
   ```
   `TryLookupElement` 或更底层的加载/存储函数会被用来访问和修改数组元素。

* **类型转换:**
   ```javascript
   const numStr = "123";
   const num = parseInt(numStr); // 底层的类型转换逻辑可能使用 Int32ToUint8Clamped 等函数
   ```
   `CodeStubAssembler` 中提供的类型转换函数用于实现 JavaScript 中的类型转换操作。

* **比较操作:**
   ```javascript
   const a = 5;
   const b = 10;
   console.log(a < b); // 底层使用 RelationalComparison 或 BranchIfNumberLessThan
   ```
   `RelationalComparison` 或针对特定类型的比较函数（如 `BranchIfNumberLessThan`) 会被用来执行比较操作。

**代码逻辑推理的假设输入与输出示例**

假设我们调用 `Int32ToUint8Clamped` 函数：

* **假设输入:** `int32_value = 300`
* **预期输出:**  由于 `uint8_t` 的最大值是 255，该函数会将 300 钳制到 255。所以预期输出是 `255`。

假设我们调用 `ElementOffsetFromIndex` 函数：

* **假设输入:** `index = 2`, `kind = PACKED_SMI_ELEMENTS`
* **预期输出:**  假设 `PACKED_SMI_ELEMENTS` 每个元素占用 4 字节（Smi），偏移量应该是 `base_size + index * element_size`。 如果 `base_size` 为 0，则输出为 `2 * 4 = 8` 字节。

**用户常见的编程错误示例**

`CodeStubAssembler` 的功能旨在提高 V8 引擎执行 JavaScript 代码的效率和正确性。 它间接帮助避免或处理用户常见的编程错误，例如：

* **访问未定义的属性:**  如果 JavaScript 代码尝试访问一个对象上不存在的属性，`GetProperty` 相关的逻辑会处理这种情况，通常返回 `undefined` 而不是崩溃。
* **类型错误的操作:** 例如，尝试对非数字类型进行算术运算。 V8 的类型检查和转换机制（部分由 `CodeStubAssembler` 生成的代码实现）会处理这些情况，可能抛出 `TypeError` 或尝试进行隐式转换。
* **数组越界访问:**  当 JavaScript 代码尝试访问数组的越界索引时，相关的数组访问函数会进行边界检查，避免内存错误，并可能返回 `undefined`。
* **对已分离的 ArrayBuffer 进行操作:** `ThrowIfArrayBufferIsDetached` 等函数会在底层检查 `ArrayBuffer` 的状态，并在用户代码尝试操作已分离的缓冲区时抛出错误，防止数据损坏。

**归纳功能 (第 6 部分)**

根据提供的代码片段，第 6 部分主要关注以下功能：

* **高级属性访问和操作:**  包含了获取、设置、查找对象属性的多种方式，包括对快速对象、字典对象和全局对象的处理。
* **类型反馈机制的关键部分:**  涉及加载和更新类型反馈信息，这是 V8 优化 JavaScript 代码执行的关键技术。
* **底层数据加载:**  提供了从不同类型的对象存储结构中加载属性值的工具。
* **对象和 Map 的基本操作:** 例如加载接收者的 Map。
* **上下文管理:**  用于处理 JavaScript 的执行上下文。

总而言之，这个代码片段定义了 `CodeStubAssembler` 中用于实现 JavaScript 对象属性访问和操作、类型反馈管理以及底层数据加载的关键工具函数。 这些功能是 V8 引擎高效执行 JavaScript 代码的基础。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能

"""
<Object> receiver, TNode<JSReceiver> object,
      TNode<Map> map, TNode<Int32T> instance_type, TNode<Name> unique_name,
      Label* if_found_value, TVariable<Object>* var_value,
      TVariable<Uint32T>* var_details, TVariable<Object>* var_raw_value,
      Label* if_not_found, Label* if_bailout, GetOwnPropertyMode mode,
      ExpectedReceiverMode expected_receiver_mode = kExpectingAnyReceiver);

  TNode<PropertyDescriptorObject> AllocatePropertyDescriptorObject(
      TNode<Context> context);
  void InitializePropertyDescriptorObject(
      TNode<PropertyDescriptorObject> descriptor, TNode<Object> value,
      TNode<Uint32T> details, Label* if_bailout);

  TNode<Object> GetProperty(TNode<Context> context, TNode<Object> receiver,
                            Handle<Name> name) {
    return GetProperty(context, receiver, HeapConstantNoHole(name));
  }

  TNode<Object> GetProperty(TNode<Context> context, TNode<Object> receiver,
                            TNode<Object> name) {
    return CallBuiltin(Builtin::kGetProperty, context, receiver, name);
  }

  TNode<BoolT> IsInterestingProperty(TNode<Name> name);
  TNode<Object> GetInterestingProperty(TNode<Context> context,
                                       TNode<JSReceiver> receiver,
                                       TNode<Name> name, Label* if_not_found);
  TNode<Object> GetInterestingProperty(TNode<Context> context,
                                       TNode<Object> receiver,
                                       TVariable<HeapObject>* var_holder,
                                       TVariable<Map>* var_holder_map,
                                       TNode<Name> name, Label* if_not_found);

  TNode<Object> SetPropertyStrict(TNode<Context> context,
                                  TNode<Object> receiver, TNode<Object> key,
                                  TNode<Object> value) {
    return CallBuiltin(Builtin::kSetProperty, context, receiver, key, value);
  }

  TNode<Object> CreateDataProperty(TNode<Context> context,
                                   TNode<JSObject> receiver, TNode<Object> key,
                                   TNode<Object> value) {
    return CallBuiltin(Builtin::kCreateDataProperty, context, receiver, key,
                       value);
  }

  TNode<Object> GetMethod(TNode<Context> context, TNode<Object> object,
                          Handle<Name> name, Label* if_null_or_undefined);

  TNode<Object> GetIteratorMethod(TNode<Context> context,
                                  TNode<HeapObject> heap_obj,
                                  Label* if_iteratorundefined);

  TNode<Object> CreateAsyncFromSyncIterator(TNode<Context> context,
                                            TNode<Object> sync_iterator);
  TNode<JSObject> CreateAsyncFromSyncIterator(TNode<Context> context,
                                              TNode<JSReceiver> sync_iterator,
                                              TNode<Object> next);

  void LoadPropertyFromFastObject(TNode<HeapObject> object, TNode<Map> map,
                                  TNode<DescriptorArray> descriptors,
                                  TNode<IntPtrT> name_index,
                                  TVariable<Uint32T>* var_details,
                                  TVariable<Object>* var_value);

  void LoadPropertyFromFastObject(TNode<HeapObject> object, TNode<Map> map,
                                  TNode<DescriptorArray> descriptors,
                                  TNode<IntPtrT> name_index, TNode<Uint32T>,
                                  TVariable<Object>* var_value);

  template <typename Dictionary>
  void LoadPropertyFromDictionary(TNode<Dictionary> dictionary,
                                  TNode<IntPtrT> name_index,
                                  TVariable<Uint32T>* var_details,
                                  TVariable<Object>* var_value);
  void LoadPropertyFromGlobalDictionary(TNode<GlobalDictionary> dictionary,
                                        TNode<IntPtrT> name_index,
                                        TVariable<Uint32T>* var_details,
                                        TVariable<Object>* var_value,
                                        Label* if_deleted);

  // Generic property lookup generator. If the {object} is fast and
  // {unique_name} property is found then the control goes to {if_found_fast}
  // label and {var_meta_storage} and {var_name_index} will contain
  // DescriptorArray and an index of the descriptor's name respectively.
  // If the {object} is slow or global then the control goes to {if_found_dict}
  // or {if_found_global} and the {var_meta_storage} and {var_name_index} will
  // contain a dictionary and an index of the key field of the found entry.
  // If property is not found or given lookup is not supported then
  // the control goes to {if_not_found} or {if_bailout} respectively.
  //
  // Note: this code does not check if the global dictionary points to deleted
  // entry! This has to be done by the caller.
  void TryLookupProperty(TNode<HeapObject> object, TNode<Map> map,
                         TNode<Int32T> instance_type, TNode<Name> unique_name,
                         Label* if_found_fast, Label* if_found_dict,
                         Label* if_found_global,
                         TVariable<HeapObject>* var_meta_storage,
                         TVariable<IntPtrT>* var_name_index,
                         Label* if_not_found, Label* if_bailout);

  // This is a building block for TryLookupProperty() above. Supports only
  // non-special fast and dictionary objects.
  // TODO(v8:11167, v8:11177) |bailout| only needed for SetDataProperties
  // workaround.
  void TryLookupPropertyInSimpleObject(TNode<JSObject> object, TNode<Map> map,
                                       TNode<Name> unique_name,
                                       Label* if_found_fast,
                                       Label* if_found_dict,
                                       TVariable<HeapObject>* var_meta_storage,
                                       TVariable<IntPtrT>* var_name_index,
                                       Label* if_not_found, Label* bailout);

  // This method jumps to if_found if the element is known to exist. To
  // if_absent if it's known to not exist. To if_not_found if the prototype
  // chain needs to be checked. And if_bailout if the lookup is unsupported.
  void TryLookupElement(TNode<HeapObject> object, TNode<Map> map,
                        TNode<Int32T> instance_type,
                        TNode<IntPtrT> intptr_index, Label* if_found,
                        Label* if_absent, Label* if_not_found,
                        Label* if_bailout);

  // For integer indexed exotic cases, check if the given string cannot be a
  // special index. If we are not sure that the given string is not a special
  // index with a simple check, return False. Note that "False" return value
  // does not mean that the name_string is a special index in the current
  // implementation.
  void BranchIfMaybeSpecialIndex(TNode<String> name_string,
                                 Label* if_maybe_special_index,
                                 Label* if_not_special_index);

  // This is a type of a lookup property in holder generator function. The {key}
  // is guaranteed to be an unique name.
  using LookupPropertyInHolder = std::function<void(
      TNode<HeapObject> receiver, TNode<HeapObject> holder, TNode<Map> map,
      TNode<Int32T> instance_type, TNode<Name> key, Label* next_holder,
      Label* if_bailout)>;

  // This is a type of a lookup element in holder generator function. The {key}
  // is an Int32 index.
  using LookupElementInHolder = std::function<void(
      TNode<HeapObject> receiver, TNode<HeapObject> holder, TNode<Map> map,
      TNode<Int32T> instance_type, TNode<IntPtrT> key, Label* next_holder,
      Label* if_bailout)>;

  // Generic property prototype chain lookup generator.
  // For properties it generates lookup using given {lookup_property_in_holder}
  // and for elements it uses {lookup_element_in_holder}.
  // Upon reaching the end of prototype chain the control goes to {if_end}.
  // If it can't handle the case {receiver}/{key} case then the control goes
  // to {if_bailout}.
  // If {if_proxy} is nullptr, proxies go to if_bailout.
  void TryPrototypeChainLookup(
      TNode<Object> receiver, TNode<Object> object, TNode<Object> key,
      const LookupPropertyInHolder& lookup_property_in_holder,
      const LookupElementInHolder& lookup_element_in_holder, Label* if_end,
      Label* if_bailout, Label* if_proxy, bool handle_private_names = false);

  // Instanceof helpers.
  // Returns true if {object} has {prototype} somewhere in it's prototype
  // chain, otherwise false is returned. Might cause arbitrary side effects
  // due to [[GetPrototypeOf]] invocations.
  TNode<Boolean> HasInPrototypeChain(TNode<Context> context,
                                     TNode<HeapObject> object,
                                     TNode<Object> prototype);
  // ES6 section 7.3.19 OrdinaryHasInstance (C, O)
  TNode<Boolean> OrdinaryHasInstance(TNode<Context> context,
                                     TNode<Object> callable,
                                     TNode<Object> object);

  TNode<BytecodeArray> LoadBytecodeArrayFromBaseline();

  // Load type feedback vector from the stub caller's frame.
  TNode<FeedbackVector> LoadFeedbackVectorForStub();
  TNode<FeedbackVector> LoadFeedbackVectorFromBaseline();
  TNode<Context> LoadContextFromBaseline();
  // Load type feedback vector from the stub caller's frame, skipping an
  // intermediate trampoline frame.
  TNode<FeedbackVector> LoadFeedbackVectorForStubWithTrampoline();

  // Load the value from closure's feedback cell.
  TNode<HeapObject> LoadFeedbackCellValue(TNode<JSFunction> closure);

  // Load the object from feedback vector cell for the given closure.
  // The returned object could be undefined if the closure does not have
  // a feedback vector associated with it.
  TNode<HeapObject> LoadFeedbackVector(TNode<JSFunction> closure);
  TNode<FeedbackVector> LoadFeedbackVector(TNode<JSFunction> closure,
                                           Label* if_no_feedback_vector);

  // Load the ClosureFeedbackCellArray that contains the feedback cells
  // used when creating closures from this function. This array could be
  // directly hanging off the FeedbackCell when there is no feedback vector
  // or available from the feedback vector's header.
  TNode<ClosureFeedbackCellArray> LoadClosureFeedbackArray(
      TNode<JSFunction> closure);

  // Update the type feedback vector.
  bool UpdateFeedbackModeEqual(UpdateFeedbackMode a, UpdateFeedbackMode b) {
    return a == b;
  }
  void UpdateFeedback(TNode<Smi> feedback,
                      TNode<HeapObject> maybe_feedback_vector,
                      TNode<UintPtrT> slot_id, UpdateFeedbackMode mode);
  void UpdateFeedback(TNode<Smi> feedback,
                      TNode<FeedbackVector> feedback_vector,
                      TNode<UintPtrT> slot_id);
  void MaybeUpdateFeedback(TNode<Smi> feedback,
                           TNode<HeapObject> maybe_feedback_vector,
                           TNode<UintPtrT> slot_id);

  // Report that there was a feedback update, performing any tasks that should
  // be done after a feedback update.
  void ReportFeedbackUpdate(TNode<FeedbackVector> feedback_vector,
                            TNode<UintPtrT> slot_id, const char* reason);

  // Combine the new feedback with the existing_feedback. Do nothing if
  // existing_feedback is nullptr.
  void CombineFeedback(TVariable<Smi>* existing_feedback, int feedback);
  void CombineFeedback(TVariable<Smi>* existing_feedback, TNode<Smi> feedback);

  // Overwrite the existing feedback with new_feedback. Do nothing if
  // existing_feedback is nullptr.
  void OverwriteFeedback(TVariable<Smi>* existing_feedback, int new_feedback);

  // Check if a property name might require protector invalidation when it is
  // used for a property store or deletion.
  void CheckForAssociatedProtector(TNode<Name> name, Label* if_protector);

  TNode<Map> LoadReceiverMap(TNode<Object> receiver);

  // Loads script context from the script context table.
  TNode<Context> LoadScriptContext(TNode<Context> context,
                                   TNode<IntPtrT> context_index);

  TNode<Uint8T> Int32ToUint8Clamped(TNode<Int32T> int32_value);
  TNode<Uint8T> Float64ToUint8Clamped(TNode<Float64T> float64_value);

  template <typename T>
  TNode<T> PrepareValueForWriteToTypedArray(TNode<Object> input,
                                            ElementsKind elements_kind,
                                            TNode<Context> context);

  // Store value to an elements array with given elements kind.
  // TODO(turbofan): For BIGINT64_ELEMENTS and BIGUINT64_ELEMENTS
  // we pass {value} as BigInt object instead of int64_t. We should
  // teach TurboFan to handle int64_t on 32-bit platforms eventually.
  template <typename TIndex, typename TValue>
  void StoreElement(TNode<RawPtrT> elements, ElementsKind kind,
                    TNode<TIndex> index, TNode<TValue> value);

  // Implements the BigInt part of
  // https://tc39.github.io/proposal-bigint/#sec-numbertorawbytes,
  // including truncation to 64 bits (i.e. modulo 2^64).
  // {var_high} is only used on 32-bit platforms.
  void BigIntToRawBytes(TNode<BigInt> bigint, TVariable<UintPtrT>* var_low,
                        TVariable<UintPtrT>* var_high);

#if V8_ENABLE_WEBASSEMBLY
  TorqueStructInt64AsInt32Pair BigIntToRawBytes(TNode<BigInt> value);
#endif  // V8_ENABLE_WEBASSEMBLY

  void EmitElementStore(TNode<JSObject> object, TNode<Object> key,
                        TNode<Object> value, ElementsKind elements_kind,
                        KeyedAccessStoreMode store_mode, Label* bailout,
                        TNode<Context> context,
                        TVariable<Object>* maybe_converted_value = nullptr);

  TNode<FixedArrayBase> CheckForCapacityGrow(
      TNode<JSObject> object, TNode<FixedArrayBase> elements, ElementsKind kind,
      TNode<UintPtrT> length, TNode<IntPtrT> key, Label* bailout);

  TNode<FixedArrayBase> CopyElementsOnWrite(TNode<HeapObject> object,
                                            TNode<FixedArrayBase> elements,
                                            ElementsKind kind,
                                            TNode<IntPtrT> length,
                                            Label* bailout);

  void TransitionElementsKind(TNode<JSObject> object, TNode<Map> map,
                              ElementsKind from_kind, ElementsKind to_kind,
                              Label* bailout);

  void TrapAllocationMemento(TNode<JSObject> object, Label* memento_found);

  // Helpers to look up Page metadata for a given address.
  // Equivalent to MemoryChunk::FromAddress().
  TNode<IntPtrT> MemoryChunkFromAddress(TNode<IntPtrT> address);
  // Equivalent to MemoryChunk::MutablePageMetadata().
  TNode<IntPtrT> PageMetadataFromMemoryChunk(TNode<IntPtrT> address);
  // Equivalent to MemoryChunkMetadata::FromAddress().
  TNode<IntPtrT> PageMetadataFromAddress(TNode<IntPtrT> address);

  // Store a weak in-place reference into the FeedbackVector.
  TNode<MaybeObject> StoreWeakReferenceInFeedbackVector(
      TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
      TNode<HeapObject> value, int additional_offset = 0);

  // Create a new AllocationSite and install it into a feedback vector.
  TNode<AllocationSite> CreateAllocationSiteInFeedbackVector(
      TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot);

  TNode<BoolT> HasBoilerplate(TNode<Object> maybe_literal_site);
  TNode<Smi> LoadTransitionInfo(TNode<AllocationSite> allocation_site);
  TNode<JSObject> LoadBoilerplate(TNode<AllocationSite> allocation_site);
  TNode<Int32T> LoadElementsKind(TNode<AllocationSite> allocation_site);
  TNode<Object> LoadNestedAllocationSite(TNode<AllocationSite> allocation_site);

  enum class IndexAdvanceMode { kPre, kPost };
  enum class IndexAdvanceDirection { kUp, kDown };
  enum class LoopUnrollingMode { kNo, kYes };

  template <typename TIndex>
  using FastLoopBody = std::function<void(TNode<TIndex> index)>;

  template <typename TIndex>
  void BuildFastLoop(const VariableList& vars, TVariable<TIndex>& var_index,
                     TNode<TIndex> start_index, TNode<TIndex> end_index,
                     const FastLoopBody<TIndex>& body, TNode<TIndex> increment,
                     LoopUnrollingMode unrolling_mode,
                     IndexAdvanceMode advance_mode,
                     IndexAdvanceDirection advance_direction);

  template <typename TIndex>
  void BuildFastLoop(const VariableList& vars, TVariable<TIndex>& var_index,
                     TNode<TIndex> start_index, TNode<TIndex> end_index,
                     const FastLoopBody<TIndex>& body, int increment,
                     LoopUnrollingMode unrolling_mode,
                     IndexAdvanceMode advance_mode = IndexAdvanceMode::kPre);

  template <typename TIndex>
  void BuildFastLoop(TVariable<TIndex>& var_index, TNode<TIndex> start_index,
                     TNode<TIndex> end_index, const FastLoopBody<TIndex>& body,
                     int increment, LoopUnrollingMode unrolling_mode,
                     IndexAdvanceMode advance_mode = IndexAdvanceMode::kPre) {
    BuildFastLoop(VariableList(0, zone()), var_index, start_index, end_index,
                  body, increment, unrolling_mode, advance_mode);
  }

  template <typename TIndex>
  void BuildFastLoop(const VariableList& vars, TNode<TIndex> start_index,
                     TNode<TIndex> end_index, const FastLoopBody<TIndex>& body,
                     int increment, LoopUnrollingMode unrolling_mode,
                     IndexAdvanceMode advance_mode) {
    TVARIABLE(TIndex, var_index);
    BuildFastLoop(vars, var_index, start_index, end_index, body, increment,
                  unrolling_mode, advance_mode);
  }

  template <typename TIndex>
  void BuildFastLoop(TNode<TIndex> start_index, TNode<TIndex> end_index,
                     const FastLoopBody<TIndex>& body, int increment,
                     LoopUnrollingMode unrolling_mode,
                     IndexAdvanceMode advance_mode = IndexAdvanceMode::kPre) {
    BuildFastLoop(VariableList(0, zone()), start_index, end_index, body,
                  increment, unrolling_mode, advance_mode);
  }

  enum class ForEachDirection { kForward, kReverse };

  using FastArrayForEachBody =
      std::function<void(TNode<HeapObject> array, TNode<IntPtrT> offset)>;

  template <typename TIndex>
  void BuildFastArrayForEach(
      TNode<UnionOf<FixedArray, PropertyArray, HeapObject>> array,
      ElementsKind kind, TNode<TIndex> first_element_inclusive,
      TNode<TIndex> last_element_exclusive, const FastArrayForEachBody& body,
      LoopUnrollingMode loop_unrolling_mode,
      ForEachDirection direction = ForEachDirection::kReverse);

  template <typename TIndex>
  TNode<IntPtrT> GetArrayAllocationSize(TNode<TIndex> element_count,
                                        ElementsKind kind, int header_size) {
    return ElementOffsetFromIndex(element_count, kind, header_size);
  }

  template <typename TIndex>
  TNode<IntPtrT> GetFixedArrayAllocationSize(TNode<TIndex> element_count,
                                             ElementsKind kind) {
    return GetArrayAllocationSize(element_count, kind,
                                  OFFSET_OF_DATA_START(FixedArray));
  }

  TNode<IntPtrT> GetPropertyArrayAllocationSize(TNode<IntPtrT> element_count) {
    return GetArrayAllocationSize(element_count, PACKED_ELEMENTS,
                                  PropertyArray::kHeaderSize);
  }

  template <typename TIndex>
  void GotoIfFixedArraySizeDoesntFitInNewSpace(TNode<TIndex> element_count,
                                               Label* doesnt_fit,
                                               int base_size);

  void InitializeFieldsWithRoot(TNode<HeapObject> object,
                                TNode<IntPtrT> start_offset,
                                TNode<IntPtrT> end_offset, RootIndex root);

  // Goto the given |target| if the context chain starting at |context| has any
  // extensions up to the given |depth|. Returns the Context with the
  // extensions if there was one, otherwise returns the Context at the given
  // |depth|.
  TNode<Context> GotoIfHasContextExtensionUpToDepth(TNode<Context> context,
                                                    TNode<Uint32T> depth,
                                                    Label* target);

  TNode<Boolean> RelationalComparison(
      Operation op, TNode<Object> left, TNode<Object> right,
      TNode<Context> context, TVariable<Smi>* var_type_feedback = nullptr) {
    return RelationalComparison(
        op, left, right, [=]() { return context; }, var_type_feedback);
  }

  TNode<Boolean> RelationalComparison(
      Operation op, TNode<Object> left, TNode<Object> right,
      const LazyNode<Context>& context,
      TVariable<Smi>* var_type_feedback = nullptr);

  void BranchIfNumberRelationalComparison(Operation op, TNode<Number> left,
                                          TNode<Number> right, Label* if_true,
                                          Label* if_false);

  void BranchIfNumberEqual(TNode<Number> left, TNode<Number> right,
                           Label* if_true, Label* if_false) {
    BranchIfNumberRelationalComparison(Operation::kEqual, left, right, if_true,
                                       if_false);
  }

  void BranchIfNumberNotEqual(TNode<Number> left, TNode<Number> right,
                              Label* if_true, Label* if_false) {
    BranchIfNumberEqual(left, right, if_false, if_true);
  }

  void BranchIfNumberLessThan(TNode<Number> left, TNode<Number> right,
                              Label* if_true, Label* if_false) {
    BranchIfNumberRelationalComparison(Operation::kLessThan, left, right,
                                       if_true, if_false);
  }

  void BranchIfNumberLessThanOrEqual(TNode<Number> left, TNode<Number> right,
                                     Label* if_true, Label* if_false) {
    BranchIfNumberRelationalComparison(Operation::kLessThanOrEqual, left, right,
                                       if_true, if_false);
  }

  void BranchIfNumberGreaterThan(TNode<Number> left, TNode<Number> right,
                                 Label* if_true, Label* if_false) {
    BranchIfNumberRelationalComparison(Operation::kGreaterThan, left, right,
                                       if_true, if_false);
  }

  void BranchIfNumberGreaterThanOrEqual(TNode<Number> left, TNode<Number> right,
                                        Label* if_true, Label* if_false) {
    BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual, left,
                                       right, if_true, if_false);
  }

  void BranchIfAccessorPair(TNode<Object> value, Label* if_accessor_pair,
                            Label* if_not_accessor_pair) {
    GotoIf(TaggedIsSmi(value), if_not_accessor_pair);
    Branch(IsAccessorPair(CAST(value)), if_accessor_pair, if_not_accessor_pair);
  }

  void GotoIfNumberGreaterThanOrEqual(TNode<Number> left, TNode<Number> right,
                                      Label* if_false);

  TNode<Boolean> Equal(TNode<Object> lhs, TNode<Object> rhs,
                       TNode<Context> context,
                       TVariable<Smi>* var_type_feedback = nullptr) {
    return Equal(
        lhs, rhs, [=]() { return context; }, var_type_feedback);
  }
  TNode<Boolean> Equal(TNode<Object> lhs, TNode<Object> rhs,
                       const LazyNode<Context>& context,
                       TVariable<Smi>* var_type_feedback = nullptr);

  TNode<Boolean> StrictEqual(TNode<Object> lhs, TNode<Object> rhs,
                             TVariable<Smi>* var_type_feedback = nullptr);

  void GotoIfStringEqual(TNode<String> lhs, TNode<IntPtrT> lhs_length,
                         TNode<String> rhs, Label* if_true) {
    Label if_false(this);
    // Callers must handle the case where {lhs} and {rhs} refer to the same
    // String object.
    CSA_DCHECK(this, TaggedNotEqual(lhs, rhs));
    TNode<IntPtrT> rhs_length = LoadStringLengthAsWord(rhs);
    BranchIfStringEqual(lhs, lhs_length, rhs, rhs_length, if_true, &if_false,
                        nullptr);

    BIND(&if_false);
  }

  void BranchIfStringEqual(TNode<String> lhs, TNode<String> rhs, Label* if_true,
                           Label* if_false,
                           TVariable<Boolean>* result = nullptr) {
    return BranchIfStringEqual(lhs, LoadStringLengthAsWord(lhs), rhs,
                               LoadStringLengthAsWord(rhs), if_true, if_false,
                               result);
  }

  void BranchIfStringEqual(TNode<String> lhs, TNode<IntPtrT> lhs_length,
                           TNode<String> rhs, TNode<IntPtrT> rhs_length,
                           Label* if_true, Label* if_false,
                           TVariable<Boolean>* result = nullptr);

  // ECMA#sec-samevalue
  // Similar to StrictEqual except that NaNs are treated as equal and minus zero
  // differs from positive zero.
  enum class SameValueMode { kNumbersOnly, kFull };
  void BranchIfSameValue(TNode<Object> lhs, TNode<Object> rhs, Label* if_true,
                         Label* if_false,
                         SameValueMode mode = SameValueMode::kFull);
  // A part of BranchIfSameValue() that handles two double values.
  // Treats NaN == NaN and +0 != -0.
  void BranchIfSameNumberValue(TNode<Float64T> lhs_value,
                               TNode<Float64T> rhs_value, Label* if_true,
                               Label* if_false);

  enum HasPropertyLookupMode { kHasProperty, kForInHasProperty };

  TNode<Boolean> HasProperty(TNode<Context> context, TNode<Object> object,
                             TNode<Object> key, HasPropertyLookupMode mode);

  // Due to naming conflict with the builtin function namespace.
  TNode<Boolean> HasProperty_Inline(TNode<Context> context,
                                    TNode<JSReceiver> object,
                                    TNode<Object> key) {
    return HasProperty(context, object, key,
                       HasPropertyLookupMode::kHasProperty);
  }

  void ForInPrepare(TNode<HeapObject> enumerator, TNode<UintPtrT> slot,
                    TNode<HeapObject> maybe_feedback_vector,
                    TNode<FixedArray>* cache_array_out,
                    TNode<Smi>* cache_length_out,
                    UpdateFeedbackMode update_feedback_mode);

  TNode<String> Typeof(
      TNode<Object> value, std::optional<TNode<UintPtrT>> slot_id = {},
      std::optional<TNode<HeapObject>> maybe_feedback_vector = {});

  TNode<HeapObject> GetSuperConstructor(TNode<JSFunction> active_function);

  TNode<JSReceiver> SpeciesConstructor(TNode<Context> context,
                                       TNode<Object> object,
                                       TNode<JSReceiver> default_constructor);

  TNode<Boolean> InstanceOf(TNode<Object> object, TNode<Object> callable,
                            TNode<Context> context);

  // Debug helpers
  TNode<BoolT> IsDebugActive();

  // JSArrayBuffer helpers
  TNode<UintPtrT> LoadJSArrayBufferByteLength(
      TNode<JSArrayBuffer> array_buffer);
  TNode<UintPtrT> LoadJSArrayBufferMaxByteLength(
      TNode<JSArrayBuffer> array_buffer);
  TNode<RawPtrT> LoadJSArrayBufferBackingStorePtr(
      TNode<JSArrayBuffer> array_buffer);
  void ThrowIfArrayBufferIsDetached(TNode<Context> context,
                                    TNode<JSArrayBuffer> array_buffer,
                                    const char* method_name);

  // JSArrayBufferView helpers
  TNode<JSArrayBuffer> LoadJSArrayBufferViewBuffer(
      TNode<JSArrayBufferView> array_buffer_view);
  TNode<UintPtrT> LoadJSArrayBufferViewByteLength(
      TNode<JSArrayBufferView> array_buffer_view);
  void StoreJSArrayBufferViewByteLength(
      TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value);
  TNode<UintPtrT> LoadJSArrayBufferViewByteOffset(
      TNode<JSArrayBufferView> array_buffer_view);
  void StoreJSArrayBufferViewByteOffset(
      TNode<JSArrayBufferView> array_buffer_view, TNode<UintPtrT> value);
  void ThrowIfArrayBufferViewBufferIsDetached(
      TNode<Context> context, TNode<JSArrayBufferView> array_buffer_view,
      const char* method_name);

  // JSTypedArray helpers
  TNode<UintPtrT> LoadJSTypedArrayLength(TNode<JSTypedArray> typed_array);
  void StoreJSTypedArrayLength(TNode<JSTypedArray> typed_array,
                               TNode<UintPtrT> value);
  TNode<UintPtrT> LoadJSTypedArrayLengthAndCheckDetached(
      TNode<JSTypedArray> typed_array, Label* detached);
  // Helper for length tracking JSTypedArrays and JSTypedArrays backed by
  // ResizableArrayBuffer.
  TNode<UintPtrT> LoadVariableLengthJSTypedArrayLength(
      TNode<JSTypedArray> array, TNode<JSArrayBuffer> buffer,
      Label* detached_or_out_of_bounds);
  // Helper for length tracking JSTypedArrays and JSTypedArrays backed by
  // ResizableArrayBuffer.
  TNode<UintPtrT> LoadVariableLengthJSTypedArrayByteLength(
      TNode<Context> context, TNode<JSTypedArray> array,
      TNode<JSArrayBuffer> buffer);
  TNode<UintPtrT> LoadVariableLengthJSArrayBufferViewByteLength(
      TNode<JSArrayBufferView> array, TNode<JSArrayBuffer> buffer,
      Label* detached_or_out_of_bounds);

  void IsJSArrayBufferViewDetachedOrOutOfBounds(
      TNode<JSArrayBufferView> array_buffer_view, Label* detached_or_oob,
      Label* not_detached_nor_oob);

  TNode<BoolT> IsJSArrayBufferViewDetachedOrOutOfBoundsBoolean(
      TNode<JSArrayBufferView> array_buffer_view);

  void CheckJSTypedArrayIndex(TNode<JSTypedArray> typed_array,
                              TNode<UintPtrT> index,
                              Label* detached_or_out_of_bounds);

  TNode<IntPtrT> RabGsabElementsKindToElementByteSize(
      TNode<Int32T> elementsKind);
  TNode<RawPtrT> LoadJSTypedArrayDataPtr(TNode<JSTypedArray> typed_array);
  TNode<JSArrayBuffer> GetTypedArrayBuffer(TNode<Context> context,
                                           TNode<JSTypedArray> array);

  template <typename TIndex>
  TNode<IntPtrT> ElementOffsetFromIndex(TNode<TIndex> index, ElementsKind kind,
                                        int base_size = 0);
  template <typename Array, typename TIndex>
  TNode<IntPtrT> OffsetOfElementAt(TNode<TIndex> index) {
    static_assert(Array::kElementSize == kTaggedSize);
    return ElementOffsetFromIndex(index, PACKED_ELEMENTS,
                                  OFFSET_OF_DATA_START(Array) - kHeapObjectTag);
  }

  // Check that a field offset is within the bounds of the an object.
  TNode<BoolT> IsOffsetInBounds(TNode<IntPtrT> offset, TNode<IntPtrT> length,
                                int header_size,
                                ElementsKind kind = HOLEY_ELEMENTS);

  // Load a builtin's code from the builtin array in the isolate.
  TNode<Code> LoadBuiltin(TNode<Smi> builtin_id);

#ifdef V8_ENABLE_LEAPTIERING
  // Load a builtin's handle into the JSDispatchTable.
  TNode<JSDispatchHandleT> LoadBuiltinDispatchHandle(
      JSBuiltinDispatchHandleRoot::Idx dispatch_root_idx);
  inline TNode<JSDispatchHandleT> LoadBuiltinDispatchHandle(RootIndex idx) {
    return LoadBuiltinDispatchHandle(JSBuiltinDispatchHandleRoot::to_idx(idx));
  }

  // Load the Code object of a JSDispatchTable entry.
  TNode<Code> LoadCodeObjectFromJSDispatchTable(
      TNode<JSDispatchHandleT> dispatch_handle);
  // Load the parameter count of a JSDispatchTable entry.
  TNode<Uint16T> LoadParameterCountFromJSDispatchTable(
      TNode<JSDispatchHandleT> dispatch_handle);
#endif

  // Indicate that this code must support a dynamic parameter count.
  //
  // This is used for builtins that must work on functions with different
  // parameter counts. In that case, the true JS parameter count is only known
  // at runtime and must be obtained in order to compute the total number of
  // arguments (which may include padding arguments). The parameter count is
  // subsequently available through the corresponding CodeAssembler accessors.
  // The target function object and the dispatch handle need to be passed in
  // and are used to obtain the actual parameter count of the called function.
  //
  // This should generally be invoked directly at the start of the function.
  //
  // TODO(saelo): it would be a bit nicer if this would happen automatically in
  // the function prologue for functions marked as requiring this (e.g. via th
"""


```
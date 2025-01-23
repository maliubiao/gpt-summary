Response:
The user wants a summary of the functionality provided by the C++ header file `v8/src/codegen/code-stub-assembler.h`, based on the provided code snippet.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name "code-stub-assembler.h" strongly suggests that this header defines a mechanism for generating machine code stubs. The presence of `TNode` and functions like `Select`, `Truncate`, `Branch`, `Load`, and `Store` reinforces this idea. It's a low-level code generation interface within V8.

2. **Categorize Functionality:** To make the summary clear, group the functions based on their purpose. Looking at the code, several categories emerge:
    * **Conditional Selection:** Functions starting with "Select" clearly handle conditional value selection.
    * **Constant Creation:**  Functions like `Int32Constant`, `SmiConstant`, `SingleCharacterStringConstant`, and `HeapConstant` deal with creating constant values within the generated code.
    * **Type Conversions/Truncation:**  Functions starting with "Truncate" are for converting between different data types.
    * **Type Checking:** Functions like `TaggedIsSmi`, `WordIsAligned`, `IsInRange` perform runtime type checks.
    * **Control Flow:**  Functions like `Bind`, `BranchIfSmiEqual`, `BranchIfToBooleanIsTrue`, and `GotoIfForceSlowPath` manage the flow of execution within the generated code.
    * **Memory Access (Load/Store):**  A large number of functions starting with "Load" and "Store" handle reading and writing data to memory, often with variations for different data types, object layouts, and security mechanisms (sandboxing, protected pointers). This is a crucial part of interacting with V8's object model.
    * **Object Property Access:** Several `Load` functions are specifically designed to access properties of JavaScript objects (e.g., `LoadSlowProperties`, `LoadFastProperties`, `LoadElements`).
    * **Array Length Access:**  A subset of `Load` functions focuses on retrieving the lengths of different array types.
    * **Map (Object Structure) Access:**  Functions like `LoadMap`, `LoadInstanceType`, `LoadMapBitField`, `LoadMapPrototype` are for inspecting the structure (Map) of JavaScript objects.
    * **String Handling:**  Functions like `LoadStringLengthAsSmi` are for working with string objects.
    * **Weak Reference Handling:** Functions like `DispatchMaybeObject`, `IsStrong`, `IsWeakOrCleared`, `MakeWeak` deal with weak references, a garbage collection mechanism.
    * **Bounds Checking:** Functions like `FixedArrayBoundsCheck` ensure array accesses are within valid limits.
    * **Simd128 Operations:** The presence of `LoadSimd128` indicates support for SIMD operations.
    * **Frame Access:** `LoadFromParentFrame` suggests the ability to access data in the call stack.
    * **Buffer Access:** `LoadBufferObject`, `LoadBufferData`, etc., allow access to raw memory buffers.

3. **Address Specific Instructions:** Pay attention to functions with specific names or patterns:
    * **`Select...Constant`**:  These functions conditionally select between constant values. Note the overloads for different types.
    * **`Truncate...`**:  These functions truncate values between different integer and floating-point types.
    * **`TaggedIsSmi`**: Checks if a value is a Small Integer (Smi).
    * **`WordIsAligned`**: Checks memory alignment.
    * **`IsInRange`**:  Checks if a value falls within a given range.
    * **`Bind`**: Associates a label with a specific point in the code.
    * **`BranchIf...`**: Conditional jumps based on various conditions.
    * **`LoadSandboxedPointerFromObject`**:  Indicates a security feature for accessing memory.
    * **`LoadExternalPointerFromObject`**:  Accessing pointers to external (non-V8 heap) data.
    * **`LoadTrustedPointerFromObject`**: Accessing pointers that are considered "trusted."
    * **`LoadCodePointerFromObject`**: A specific type of trusted pointer for code objects.
    * **`LoadObjectField`**: A fundamental function for accessing object properties.
    * **`LoadMap...`**: Functions for accessing properties of the `Map` object, which describes the structure of JavaScript objects.
    * **`LoadStringLengthAs...`**: Accessing the length of a string.
    * **`DispatchMaybeObject`**:  Handling `MaybeObject` which can be a Smi, a strong reference, or a weak reference.
    * **`FixedArrayBoundsCheck`**: Important for memory safety.

4. **Handle Conditional Compilation (`#ifdef`)**:  Note the sections within `#ifdef DEBUG` and `#ifdef V8_ENABLE_SANDBOX` as these indicate features that might not be present in all builds.

5. **Infer Relationships to JavaScript:** While the code is C++, connect the functionality back to JavaScript concepts where possible. For example:
    * Object property access directly relates to how JavaScript accesses object members.
    * Array length relates to the `.length` property of JavaScript arrays.
    * Maps relate to the internal structure and hidden classes of JavaScript objects.
    * Weak references are used in JavaScript for features like `WeakMap` and `WeakSet`.

6. **Address the `.tq` Question:** Explicitly state that the provided file is a `.h` file and therefore not Torque. Explain the relationship between `.tq` and Torque.

7. **Provide JavaScript Examples (Where Applicable):**  Illustrate the concepts with simple JavaScript code. Focus on actions that would internally trigger the kind of operations seen in the C++ code (e.g., accessing object properties, array elements, checking object types).

8. **Address Code Logic and Assumptions:** For more complex functions, try to infer the likely inputs and outputs. For example, a `Select` function takes a boolean condition and two values, and returns one of them.

9. **Identify Potential User Errors:**  Think about common JavaScript errors that might relate to the low-level operations. For example, accessing properties of `null` or `undefined`, or going out of bounds on an array, could be related to the checks and memory access functions seen in the header.

10. **Structure the Summary:** Organize the findings into a clear and logical structure with headings and bullet points. Start with a high-level overview and then delve into more specific functionalities.

11. **Review and Refine:** Read through the summary to ensure accuracy, clarity, and completeness, based on the provided code snippet. Make sure to address all parts of the user's request.
这是 `v8/src/codegen/code-stub-assembler.h` 文件的第 2 部分，延续了第 1 部分定义的功能，主要围绕在代码桩（code stubs）的汇编过程中，提供了一系列用于生成和操作底层代码的工具函数。

**功能归纳:**

这部分 `code-stub-assembler.h` 的功能可以归纳为以下几个方面：

1. **条件选择 (Conditional Selection):**
   - 提供了一系列 `Select...Constant` 函数，用于根据布尔条件选择不同的常量值。这些常量可以是整数、Smi（Small Integer）、布尔值等。

2. **字符串常量创建:**
   - `SingleCharacterStringConstant`: 用于创建只包含单个字符的字符串常量。

3. **类型转换与截断 (Type Conversion and Truncation):**
   - 提供了一系列 `Truncate...` 函数，用于在不同的数值类型之间进行转换和截断，例如浮点数到半精度浮点数，Word 到 Int32 等。

4. **类型检查 (Type Checking):**
   - 提供了一系列 `TaggedIs...` 和 `WordIs...` 函数，用于检查值的类型和属性，例如是否为 Smi、是否为正 Smi、地址是否对齐、是否为 2 的幂等。
   - `IsInRange`:  用于检查一个数值是否在一个给定的范围内。

5. **控制流 (Control Flow):**
   - `Bind`: 用于将标签（Label）绑定到代码中的特定位置。
   - `BranchIfSmiEqual`, `BranchIfSmiLessThan`, `BranchIfSmiLessThanOrEqual`:  根据 Smi 类型的比较结果进行分支跳转。
   - `BranchIfFloat64IsNaN`:  检查浮点数是否为 NaN 并进行分支。
   - `BranchIfToBooleanIsTrue`, `BranchIfToBooleanIsFalse`: 根据对值应用 ToBoolean 抽象操作的结果进行分支。
   - `BranchIfJSReceiver`:  检查对象是否为 JS 接收器（可以拥有属性的对象）并进行分支。
   - `GotoIfForceSlowPath`:  在特定编译配置下，强制跳转到慢速执行路径，用于测试。

6. **沙箱指针相关功能 (Sandboxed Pointer Functionality):**
   - `LoadSandboxedPointerFromObject`, `StoreSandboxedPointerToObject`: 用于从对象中加载和存储沙箱指针。沙箱指针是一种安全机制，用于限制指针的访问范围。
   - `EmptyBackingStoreBufferConstant`: 获取一个空的 backing store buffer 常量。

7. **有界尺寸相关功能 (Bounded Size Functionality):**
   - `LoadBoundedSizeFromObject`, `StoreBoundedSizeToObject`: 用于加载和存储对象的有界尺寸值。

8. **外部指针相关功能 (External Pointer Functionality):**
   - `ExternalPointerTableAddress`: 获取外部指针表的地址。
   - `LoadExternalPointerFromObject`, `StoreExternalPointerToObject`: 用于加载和存储指向外部内存的指针。

9. **受信任指针相关功能 (Trusted Pointer Functionality):**
   - `LoadTrustedPointerFromObject`: 用于加载受信任的指针，通常用于指向 V8 内部对象。
   - `LoadCodePointerFromObject`:  用于加载指向 Code 对象的指针。

10. **间接指针相关功能 (Indirect Pointer Functionality, 仅在启用沙箱时):**
    - `LoadIndirectPointerFromObject`, `IsTrustedPointerHandle`, `ResolveIndirectPointerHandle`, `ResolveCodePointerHandle`, `ResolveTrustedPointerHandle`, `ComputeCodePointerTableEntryOffset`, `LoadCodeEntrypointViaCodePointerField`, `LoadCodeEntryFromIndirectPointerHandle`, `ComputeJSDispatchTableEntryOffset`:  这部分功能与间接指针表相关，用于在启用沙箱模式下安全地访问对象，特别是 Code 对象。

11. **受保护指针字段 (Protected Pointer Fields):**
    - `LoadProtectedPointerField`: 用于加载受保护的指针字段，可能涉及额外的安全检查。

12. **特定对象类型的指针加载 (Specific Object Type Pointer Loading):**
    - 提供了一些针对特定 V8 对象类型（如 `Foreign`, `FunctionTemplateInfo`, `ExternalString`, `WasmImportData`, `WasmInternalFunction`, `WasmTypeInfo`, `WasmFuncRef`, `WasmFunctionData`, `WasmExportedFunctionData`, `JSTypedArray`）加载指针的便捷函数。

13. **WebAssembly 相关功能 (WebAssembly Functionality, 仅在启用 WebAssembly 时):**
    - `LoadInstanceDataFromWasmImportData`, `LoadImplicitArgFromWasmInternalFunction`, `LoadWasmTypeInfoNativeTypePtr`, `LoadWasmInternalFunctionFromFuncRef`, `LoadWasmInternalFunctionFromFunctionData`, `LoadWasmTrustedInstanceDataFromWasmExportedFunctionData`:  提供了一系列用于加载 WebAssembly 相关数据的函数。

14. **JSAPI 对象初始化 (JSAPI Object Initialization):**
    - `InitializeJSAPIObjectWithEmbedderSlotsCppHeapWrapperPtr`: 用于初始化带有嵌入器插槽的 JSAPI 对象。

15. **帧数据加载 (Frame Data Loading):**
    - `LoadFromParentFrame`: 用于从父帧加载数据。

16. **缓冲区操作 (Buffer Operations):**
    - `LoadBufferObject`, `LoadBufferData`, `LoadBufferPointer`, `LoadBufferSmi`, `LoadBufferIntptr`, `LoadUint8Ptr`, `LoadUint64Ptr`:  用于从原始内存缓冲区中加载不同类型的数据。

17. **对象字段加载 (Object Field Loading):**
    - `LoadObjectField`:  这是加载对象字段的核心函数，提供了多种重载，可以加载不同类型的字段（包括 tagged 和 untagged）。
    - `LoadAndUntagPositiveSmiObjectField`, `LoadAndUntagToWord32ObjectField`: 用于加载并解包 Smi 类型的字段。
    - `LoadMaybeWeakObjectField`: 用于加载可能为弱引用的对象字段。
    - `LoadConstructorOrBackPointer`: 加载 Map 的构造函数或反向指针。

18. **SIMD 操作 (SIMD Operations):**
    - `LoadSimd128`: 用于加载 SIMD128 类型的数据。

19. **引用 (Reference) 结构体与加载/存储:**
    - 定义了一个 `Reference` 结构体，用于表示指向对象内部的指针。
    - 提供了一系列 `LoadReference` 和 `StoreReference` 函数，用于通过 `Reference` 结构体加载和存储不同类型的数据。

20. **GC 不安全引用 (GC Unsafe Reference):**
    - `GCUnsafeReferenceToRawPtr`:  将对象和偏移量转换为原始指针，但这种操作可能不安全，因为 GC 可能在访问期间移动对象。

21. **HeapNumber 和 Map 相关操作:**
    - `LoadHeapNumberValue`: 加载 HeapNumber 的浮点数值。
    - `LoadMap`: 加载对象的 Map。
    - `LoadInstanceType`, `HasInstanceType`, `DoesntHaveInstanceType`, `TaggedDoesntHaveInstanceType`: 用于检查对象的实例类型。
    - `IsStringWrapperElementsKind`, `GotoIfMapHasSlowProperties`:  检查 Map 的属性。
    - `LoadSlowProperties`, `LoadFastProperties`: 加载对象的慢速和快速属性存储。

22. **数组相关操作 (Array Operations):**
    - `LoadElements`: 加载 JSObject 的元素存储。
    - `LoadJSArgumentsObjectLength`, `LoadFastJSArrayLength`, `LoadFixedArrayBaseLength`, `LoadSmiArrayLength`, `LoadAndUntagFixedArrayBaseLength`, `LoadAndUntagFixedArrayBaseLengthAsUint32`, `LoadWeakFixedArrayLength`, `LoadAndUntagWeakFixedArrayLength`, `LoadAndUntagWeakFixedArrayLengthAsUint32`, `LoadAndUntagBytecodeArrayLength`: 用于加载不同类型数组的长度。

23. **DescriptorArray 相关操作:**
    - `LoadNumberOfDescriptors`: 加载 DescriptorArray 中的描述符数量。
    - `LoadNumberOfOwnDescriptors`: 加载 Map 拥有的描述符数量。

24. **Map 结构体字段加载 (Map Structure Field Loading):**
    - `LoadMapBitField`, `LoadMapBitField2`, `LoadMapBitField3`, `LoadMapInstanceType`, `LoadMapElementsKind`, `LoadMapDescriptors`, `LoadMapPrototype`, `LoadMapInstanceSizeInWords`, `LoadMapInobjectPropertiesStartInWords`, `LoadMapConstructorFunctionIndex`, `LoadMapConstructor`, `LoadMapEnumLength`, `LoadMapBackPointer`:  用于加载 Map 对象的各种内部字段。
    - `MapUsedInstanceSizeInWords`, `MapUsedInObjectProperties`:  计算 Map 使用的实例大小和内联属性数量。
    - `EnsureOnlyHasSimpleProperties`: 检查 Map 是否只包含简单属性。

25. **JSReceiver Identity Hash:**
    - `LoadJSReceiverIdentityHash`: 加载 JSReceiver 对象的身份哈希值。

26. **PropertyArray 初始化:**
    - `InitializePropertyArrayLength`: 初始化 PropertyArray 的长度。

27. **Dictionary Map 检查:**
    - `IsDictionaryMap`: 检查 Map 是否为字典模式（慢速属性）。

28. **Name 对象操作:**
    - `LoadNameHash`, `LoadNameHashAssumeComputed`, `LoadNameRawHash`: 加载 Name 对象的哈希值。

29. **String 对象操作:**
    - `LoadStringLengthAsSmi`, `LoadStringLengthAsWord`, `LoadStringLengthAsWord32`: 加载 String 对象的长度。

30. **JSPrimitiveWrapper 对象操作:**
    - `LoadJSPrimitiveWrapperValue`: 加载 JSPrimitiveWrapper 对象的值。

31. **MaybeObject 处理 (MaybeObject Handling):**
    - `DispatchMaybeObject`:  用于处理 `MaybeObject` 类型，它可以是 Smi、强引用或弱引用。
    - `IsStrong`, `GetHeapObjectIfStrong`, `IsWeakOrCleared`, `IsCleared`, `IsNotCleared`, `GetHeapObjectAssumeWeak`:  用于检查和提取 `MaybeObject` 的值。
    - `IsWeakReferenceTo`, `IsWeakReferenceToObject`: 检查是否为指向特定对象的弱引用。
    - `MakeWeak`: 创建一个指向 HeapObject 的弱引用。
    - `ClearedValue`: 获取一个表示已清除弱引用的特殊值。

32. **数组边界检查 (Array Bounds Checking):**
    - `FixedArrayBoundsCheck`:  用于在访问数组元素之前进行边界检查，防止越界访问。

**关于 `.tq` 结尾:**

你提供的信息是正确的。如果 `v8/src/codegen/code-stub-assembler.h` 文件以 `.tq` 结尾，那么它就是一个 **V8 Torque 源代码**文件。Torque 是一种 V8 自有的领域特定语言（DSL），用于生成高效的 C++ 代码，特别是用于实现 V8 的内置函数和运行时代码。

**与 Javascript 的关系及 Javascript 例子:**

`code-stub-assembler.h` 中定义的功能是 V8 引擎实现 JavaScript 功能的基础。当 JavaScript 代码执行时，V8 会生成对应的机器码来执行。`CodeStubAssembler` 提供了一种在较低层次上生成这些机器码的工具。

以下是一些与 JavaScript 功能相关的例子：

* **条件选择 (`Select...Constant`)**:  在 JavaScript 的 `if` 语句或三元运算符中，V8 内部可能会使用条件选择来决定执行哪个分支的代码。

   ```javascript
   const x = 10;
   const y = 20;
   const max = x > y ? x : y; // 内部可能使用条件选择来确定 max 的值
   ```

* **类型检查 (`TaggedIsSmi`, `IsInRange`)**: JavaScript 是一门动态类型语言，V8 需要在运行时检查变量的类型。例如，在执行算术运算之前，V8 需要确保操作数是数字。

   ```javascript
   function add(a, b) {
     if (typeof a === 'number' && typeof b === 'number') {
       return a + b;
     } else {
       throw new Error('Arguments must be numbers');
     }
   }
   ```

* **控制流 (`BranchIf...`)**:  JavaScript 的控制流语句（如 `if`, `else`, `for`, `while`）在 V8 内部会转化为条件分支指令。

   ```javascript
   for (let i = 0; i < 10; i++) {
     console.log(i);
   }
   ```

* **对象属性访问 (`LoadObjectField`)**: 当你访问 JavaScript 对象的属性时，V8 内部会使用类似 `LoadObjectField` 的操作来获取属性的值。

   ```javascript
   const obj = { name: 'Alice', age: 30 };
   console.log(obj.name); // 内部会加载 obj 对象的 'name' 属性
   ```

* **数组访问 (`FixedArrayBoundsCheck`, 加载数组长度等)**: 访问 JavaScript 数组元素时，V8 需要进行边界检查，并加载数组的长度。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[1]); // 内部需要检查索引 1 是否越界
   ```

* **字符串操作 (`LoadStringLengthAsSmi`)**: 获取字符串的长度是常见的操作。

   ```javascript
   const str = "hello";
   console.log(str.length); // 内部会加载字符串的长度
   ```

* **弱引用 (`MakeWeak`, `IsWeakReferenceTo`)**:  JavaScript 中的 `WeakMap` 和 `WeakSet` 使用弱引用来避免内存泄漏。

   ```javascript
   const wm = new WeakMap();
   let key = {};
   wm.set(key, 'value');
   // 当 key 不再被其他地方引用时，WeakMap 中的条目可能会被垃圾回收
   ```

**代码逻辑推理示例 (假设输入与输出):**

假设我们调用 `SelectIntPtrConstant(condition, 100, 200)`:

* **假设输入:**
    * `condition`: 一个 `TNode<BoolT>`，表示一个布尔条件。假设这个条件在运行时求值为 `true`。
    * `true_value`: 整数 `100`。
    * `false_value`: 整数 `200`。

* **输出:**
    * `TNode<IntPtrT>`:  一个表示整数值 `100` 的 `TNode<IntPtrT>`.

如果 `condition` 在运行时求值为 `false`，那么输出将是表示整数值 `200` 的 `TNode<IntPtrT>`.

**用户常见的编程错误示例:**

* **类型错误:** 在 JavaScript 中进行操作时，如果类型不匹配，可能会导致错误。例如，尝试将一个非数字类型的值与数字相加，V8 内部的类型检查机制会捕捉到这类错误。

   ```javascript
   const num = 10;
   const str = "hello";
   const result = num + str; // JavaScript 会将数字转换为字符串进行拼接，但某些底层操作可能需要更严格的类型检查
   ```

* **数组越界访问:** 尝试访问数组中不存在的索引会导致运行时错误。`FixedArrayBoundsCheck` 这样的函数就是为了防止这类错误。

   ```javascript
   const arr = [1, 2, 3];
   console.log(arr[5]); // 错误：索引 5 超出了数组的范围
   ```

* **访问 `null` 或 `undefined` 的属性:**  这是非常常见的错误，因为 `null` 和 `undefined` 没有属性。

   ```javascript
   let obj = null;
   console.log(obj.name); // 错误：无法读取 null 的属性 'name'
   ```

这些底层的 `CodeStubAssembler` 功能正是 V8 用来实现和优化 JavaScript 语言特性的构建块。了解这些可以更深入地理解 JavaScript 引擎的工作原理。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```c
int false_value);
  TNode<IntPtrT> SelectIntPtrConstant(TNode<BoolT> condition, int true_value,
                                      int false_value);
  TNode<Boolean> SelectBooleanConstant(TNode<BoolT> condition);
  TNode<Smi> SelectSmiConstant(TNode<BoolT> condition, Tagged<Smi> true_value,
                               Tagged<Smi> false_value);
  TNode<Smi> SelectSmiConstant(TNode<BoolT> condition, int true_value,
                               Tagged<Smi> false_value) {
    return SelectSmiConstant(condition, Smi::FromInt(true_value), false_value);
  }
  TNode<Smi> SelectSmiConstant(TNode<BoolT> condition, Tagged<Smi> true_value,
                               int false_value) {
    return SelectSmiConstant(condition, true_value, Smi::FromInt(false_value));
  }
  TNode<Smi> SelectSmiConstant(TNode<BoolT> condition, int true_value,
                               int false_value) {
    return SelectSmiConstant(condition, Smi::FromInt(true_value),
                             Smi::FromInt(false_value));
  }

  TNode<String> SingleCharacterStringConstant(char const* single_char) {
    DCHECK_EQ(strlen(single_char), 1);
    return HeapConstantNoHole(
        isolate()->factory()->LookupSingleCharacterStringFromCode(
            single_char[0]));
  }

  TNode<Float16RawBitsT> TruncateFloat32ToFloat16(TNode<Float32T> value);
  TNode<Float16RawBitsT> TruncateFloat64ToFloat16(TNode<Float64T> value);

  TNode<Int32T> TruncateWordToInt32(TNode<WordT> value);
  TNode<Int32T> TruncateIntPtrToInt32(TNode<IntPtrT> value);
  TNode<Word32T> TruncateWord64ToWord32(TNode<Word64T> value);

  // Check a value for smi-ness
  TNode<BoolT> TaggedIsSmi(TNode<MaybeObject> a);
  TNode<BoolT> TaggedIsNotSmi(TNode<MaybeObject> a);

  // Check that the value is a non-negative smi.
  TNode<BoolT> TaggedIsPositiveSmi(TNode<Object> a);
  // Check that a word has a word-aligned address.
  TNode<BoolT> WordIsAligned(TNode<WordT> word, size_t alignment);
  TNode<BoolT> WordIsPowerOfTwo(TNode<IntPtrT> value);

  // Check if lower_limit <= value <= higher_limit.
  template <typename U>
  TNode<BoolT> IsInRange(TNode<Word32T> value, U lower_limit, U higher_limit) {
    DCHECK_LE(lower_limit, higher_limit);
    static_assert(sizeof(U) <= kInt32Size);
    if (lower_limit == 0) {
      return Uint32LessThanOrEqual(value, Int32Constant(higher_limit));
    }
    return Uint32LessThanOrEqual(Int32Sub(value, Int32Constant(lower_limit)),
                                 Int32Constant(higher_limit - lower_limit));
  }

  TNode<BoolT> IsInRange(TNode<UintPtrT> value, TNode<UintPtrT> lower_limit,
                         TNode<UintPtrT> higher_limit) {
    CSA_DCHECK(this, UintPtrLessThanOrEqual(lower_limit, higher_limit));
    return UintPtrLessThanOrEqual(UintPtrSub(value, lower_limit),
                                  UintPtrSub(higher_limit, lower_limit));
  }

  TNode<BoolT> IsInRange(TNode<WordT> value, intptr_t lower_limit,
                         intptr_t higher_limit) {
    DCHECK_LE(lower_limit, higher_limit);
    if (lower_limit == 0) {
      return UintPtrLessThanOrEqual(value, IntPtrConstant(higher_limit));
    }
    return UintPtrLessThanOrEqual(IntPtrSub(value, IntPtrConstant(lower_limit)),
                                  IntPtrConstant(higher_limit - lower_limit));
  }

#if DEBUG
  void Bind(Label* label, AssemblerDebugInfo debug_info);
#endif  // DEBUG
  void Bind(Label* label);

  template <class... T>
  void Bind(compiler::CodeAssemblerParameterizedLabel<T...>* label,
            TNode<T>*... phis) {
    CodeAssembler::Bind(label, phis...);
  }

  void BranchIfSmiEqual(TNode<Smi> a, TNode<Smi> b, Label* if_true,
                        Label* if_false) {
    Branch(SmiEqual(a, b), if_true, if_false);
  }

  void BranchIfSmiLessThan(TNode<Smi> a, TNode<Smi> b, Label* if_true,
                           Label* if_false) {
    Branch(SmiLessThan(a, b), if_true, if_false);
  }

  void BranchIfSmiLessThanOrEqual(TNode<Smi> a, TNode<Smi> b, Label* if_true,
                                  Label* if_false) {
    Branch(SmiLessThanOrEqual(a, b), if_true, if_false);
  }

  void BranchIfFloat64IsNaN(TNode<Float64T> value, Label* if_true,
                            Label* if_false) {
    Branch(Float64Equal(value, value), if_false, if_true);
  }

  // Branches to {if_true} if ToBoolean applied to {value} yields true,
  // otherwise goes to {if_false}.
  void BranchIfToBooleanIsTrue(TNode<Object> value, Label* if_true,
                               Label* if_false);

  // Branches to {if_false} if ToBoolean applied to {value} yields false,
  // otherwise goes to {if_true}.
  void BranchIfToBooleanIsFalse(TNode<Object> value, Label* if_false,
                                Label* if_true) {
    BranchIfToBooleanIsTrue(value, if_true, if_false);
  }

  void BranchIfJSReceiver(TNode<Object> object, Label* if_true,
                          Label* if_false);

  // Branches to {if_true} when --force-slow-path flag has been passed.
  // It's used for testing to ensure that slow path implementation behave
  // equivalent to corresponding fast paths (where applicable).
  //
  // Works only with V8_ENABLE_FORCE_SLOW_PATH compile time flag. Nop otherwise.
  void GotoIfForceSlowPath(Label* if_true);

  //
  // Sandboxed pointer related functionality.
  //

  // Load a sandboxed pointer value from an object.
  TNode<RawPtrT> LoadSandboxedPointerFromObject(TNode<HeapObject> object,
                                                int offset) {
    return LoadSandboxedPointerFromObject(object, IntPtrConstant(offset));
  }

  TNode<RawPtrT> LoadSandboxedPointerFromObject(TNode<HeapObject> object,
                                                TNode<IntPtrT> offset);

  // Stored a sandboxed pointer value to an object.
  void StoreSandboxedPointerToObject(TNode<HeapObject> object, int offset,
                                     TNode<RawPtrT> pointer) {
    StoreSandboxedPointerToObject(object, IntPtrConstant(offset), pointer);
  }

  void StoreSandboxedPointerToObject(TNode<HeapObject> object,
                                     TNode<IntPtrT> offset,
                                     TNode<RawPtrT> pointer);

  TNode<RawPtrT> EmptyBackingStoreBufferConstant();

  //
  // Bounded size related functionality.
  //

  // Load a bounded size value from an object.
  TNode<UintPtrT> LoadBoundedSizeFromObject(TNode<HeapObject> object,
                                            int offset) {
    return LoadBoundedSizeFromObject(object, IntPtrConstant(offset));
  }

  TNode<UintPtrT> LoadBoundedSizeFromObject(TNode<HeapObject> object,
                                            TNode<IntPtrT> offset);

  // Stored a bounded size value to an object.
  void StoreBoundedSizeToObject(TNode<HeapObject> object, int offset,
                                TNode<UintPtrT> value) {
    StoreBoundedSizeToObject(object, IntPtrConstant(offset), value);
  }

  void StoreBoundedSizeToObject(TNode<HeapObject> object, TNode<IntPtrT> offset,
                                TNode<UintPtrT> value);
  //
  // ExternalPointerT-related functionality.
  //

  TNode<RawPtrT> ExternalPointerTableAddress(ExternalPointerTag tag);

  // Load an external pointer value from an object.
  TNode<RawPtrT> LoadExternalPointerFromObject(TNode<HeapObject> object,
                                               int offset,
                                               ExternalPointerTag tag) {
    return LoadExternalPointerFromObject(object, IntPtrConstant(offset), tag);
  }

  TNode<RawPtrT> LoadExternalPointerFromObject(TNode<HeapObject> object,
                                               TNode<IntPtrT> offset,
                                               ExternalPointerTag tag);

  // Store external object pointer to object.
  void StoreExternalPointerToObject(TNode<HeapObject> object, int offset,
                                    TNode<RawPtrT> pointer,
                                    ExternalPointerTag tag) {
    StoreExternalPointerToObject(object, IntPtrConstant(offset), pointer, tag);
  }

  void StoreExternalPointerToObject(TNode<HeapObject> object,
                                    TNode<IntPtrT> offset,
                                    TNode<RawPtrT> pointer,
                                    ExternalPointerTag tag);

  // Load a trusted pointer field.
  // When the sandbox is enabled, these are indirect pointers using the trusted
  // pointer table. Otherwise they are regular tagged fields.
  TNode<TrustedObject> LoadTrustedPointerFromObject(TNode<HeapObject> object,
                                                    int offset,
                                                    IndirectPointerTag tag);

  // Load a code pointer field.
  // These are special versions of trusted pointers that, when the sandbox is
  // enabled, reference code objects through the code pointer table.
  TNode<Code> LoadCodePointerFromObject(TNode<HeapObject> object, int offset);

#ifdef V8_ENABLE_SANDBOX
  // Load an indirect pointer field.
  TNode<TrustedObject> LoadIndirectPointerFromObject(TNode<HeapObject> object,
                                                     int offset,
                                                     IndirectPointerTag tag);

  // Determines whether the given indirect pointer handle is a trusted pointer
  // handle or a code pointer handle.
  TNode<BoolT> IsTrustedPointerHandle(TNode<IndirectPointerHandleT> handle);

  // Retrieve the heap object referenced by the given indirect pointer handle,
  // which can either be a trusted pointer handle or a code pointer handle.
  TNode<TrustedObject> ResolveIndirectPointerHandle(
      TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag);

  // Retrieve the Code object referenced by the given trusted pointer handle.
  TNode<Code> ResolveCodePointerHandle(TNode<IndirectPointerHandleT> handle);

  // Retrieve the heap object referenced by the given trusted pointer handle.
  TNode<TrustedObject> ResolveTrustedPointerHandle(
      TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag);

  // Helper function to compute the offset into the code pointer table from a
  // code pointer handle.
  TNode<UintPtrT> ComputeCodePointerTableEntryOffset(
      TNode<IndirectPointerHandleT> handle);

  // Load the pointer to a Code's entrypoint via code pointer.
  // Only available when the sandbox is enabled as it requires the code pointer
  // table.
  TNode<RawPtrT> LoadCodeEntrypointViaCodePointerField(TNode<HeapObject> object,
                                                       int offset,
                                                       CodeEntrypointTag tag) {
    return LoadCodeEntrypointViaCodePointerField(object, IntPtrConstant(offset),
                                                 tag);
  }
  TNode<RawPtrT> LoadCodeEntrypointViaCodePointerField(TNode<HeapObject> object,
                                                       TNode<IntPtrT> offset,
                                                       CodeEntrypointTag tag);
  TNode<RawPtrT> LoadCodeEntryFromIndirectPointerHandle(
      TNode<IndirectPointerHandleT> handle, CodeEntrypointTag tag);

  TNode<UintPtrT> ComputeJSDispatchTableEntryOffset(
      TNode<JSDispatchHandleT> handle);
#endif

  TNode<JSDispatchHandleT> InvalidDispatchHandleConstant();

  TNode<Object> LoadProtectedPointerField(TNode<TrustedObject> object,
                                          TNode<IntPtrT> offset) {
    return CAST(LoadProtectedPointerFromObject(
        object, IntPtrSub(offset, IntPtrConstant(kHeapObjectTag))));
  }
  TNode<Object> LoadProtectedPointerField(TNode<TrustedObject> object,
                                          int offset) {
    return CAST(LoadProtectedPointerFromObject(
        object, IntPtrConstant(offset - kHeapObjectTag)));
  }

  TNode<RawPtrT> LoadForeignForeignAddressPtr(TNode<Foreign> object,
                                              ExternalPointerTag tag) {
    return LoadExternalPointerFromObject(object, Foreign::kForeignAddressOffset,
                                         tag);
  }

  TNode<RawPtrT> LoadFunctionTemplateInfoJsCallbackPtr(
      TNode<FunctionTemplateInfo> object) {
    return LoadExternalPointerFromObject(
        object, FunctionTemplateInfo::kMaybeRedirectedCallbackOffset,
        kFunctionTemplateInfoCallbackTag);
  }

  TNode<RawPtrT> LoadExternalStringResourcePtr(TNode<ExternalString> object) {
    return LoadExternalPointerFromObject(object,
                                         offsetof(ExternalString, resource_),
                                         kExternalStringResourceTag);
  }

  TNode<RawPtrT> LoadExternalStringResourceDataPtr(
      TNode<ExternalString> object) {
    // This is only valid for ExternalStrings where the resource data
    // pointer is cached (i.e. no uncached external strings).
    CSA_DCHECK(this, Word32NotEqual(
                         Word32And(LoadInstanceType(object),
                                   Int32Constant(kUncachedExternalStringMask)),
                         Int32Constant(kUncachedExternalStringTag)));
    return LoadExternalPointerFromObject(
        object, offsetof(ExternalString, resource_data_),
        kExternalStringResourceDataTag);
  }

  TNode<RawPtr<Uint64T>> Log10OffsetTable() {
    return ReinterpretCast<RawPtr<Uint64T>>(
        ExternalConstant(ExternalReference::address_of_log10_offset_table()));
  }

#if V8_ENABLE_WEBASSEMBLY
  // Returns WasmTrustedInstanceData|Smi.
  TNode<Object> LoadInstanceDataFromWasmImportData(
      TNode<WasmImportData> import_data) {
    return LoadProtectedPointerField(
        import_data, WasmImportData::kProtectedInstanceDataOffset);
  }

  // Returns WasmImportData or WasmTrustedInstanceData.
  TNode<TrustedObject> LoadImplicitArgFromWasmInternalFunction(
      TNode<WasmInternalFunction> object) {
    TNode<Object> obj = LoadProtectedPointerField(
        object, WasmInternalFunction::kProtectedImplicitArgOffset);
    CSA_DCHECK(this, TaggedIsNotSmi(obj));
    TNode<HeapObject> implicit_arg = CAST(obj);
    CSA_DCHECK(
        this,
        Word32Or(HasInstanceType(implicit_arg, WASM_TRUSTED_INSTANCE_DATA_TYPE),
                 HasInstanceType(implicit_arg, WASM_IMPORT_DATA_TYPE)));
    return CAST(implicit_arg);
  }

  TNode<RawPtrT> LoadWasmTypeInfoNativeTypePtr(TNode<WasmTypeInfo> object) {
    return LoadExternalPointerFromObject(
        object, WasmTypeInfo::kNativeTypeOffset, kWasmTypeInfoNativeTypeTag);
  }

  TNode<WasmInternalFunction> LoadWasmInternalFunctionFromFuncRef(
      TNode<WasmFuncRef> func_ref) {
    return CAST(LoadTrustedPointerFromObject(
        func_ref, WasmFuncRef::kTrustedInternalOffset,
        kWasmInternalFunctionIndirectPointerTag));
  }

  TNode<WasmInternalFunction> LoadWasmInternalFunctionFromFunctionData(
      TNode<WasmFunctionData> data) {
    return CAST(LoadProtectedPointerField(
        data, WasmFunctionData::kProtectedInternalOffset));
  }

  TNode<WasmTrustedInstanceData>
  LoadWasmTrustedInstanceDataFromWasmExportedFunctionData(
      TNode<WasmExportedFunctionData> data) {
    return CAST(LoadProtectedPointerField(
        data, WasmExportedFunctionData::kProtectedInstanceDataOffset));
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  TNode<RawPtrT> LoadJSTypedArrayExternalPointerPtr(
      TNode<JSTypedArray> holder) {
    return LoadSandboxedPointerFromObject(holder,
                                          JSTypedArray::kExternalPointerOffset);
  }

  void StoreJSTypedArrayExternalPointerPtr(TNode<JSTypedArray> holder,
                                           TNode<RawPtrT> value) {
    StoreSandboxedPointerToObject(holder, JSTypedArray::kExternalPointerOffset,
                                  value);
  }

  void InitializeJSAPIObjectWithEmbedderSlotsCppHeapWrapperPtr(
      TNode<JSAPIObjectWithEmbedderSlots> holder) {
    auto zero_constant =
#ifdef V8_COMPRESS_POINTERS
        Int32Constant(0);
#else   // !V8_COMPRESS_POINTERS
        IntPtrConstant(0);
#endif  // !V8_COMPRESS_POINTERS
    StoreObjectFieldNoWriteBarrier(
        holder, JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset,
        zero_constant);
  }

  // Load value from current parent frame by given offset in bytes.
  TNode<Object> LoadFromParentFrame(int offset);

  // Load an object pointer from a buffer that isn't in the heap.
  TNode<Object> LoadBufferObject(TNode<RawPtrT> buffer, int offset) {
    return LoadFullTagged(buffer, IntPtrConstant(offset));
  }
  template <typename T>
  TNode<T> LoadBufferData(TNode<RawPtrT> buffer, int offset) {
    return UncheckedCast<T>(
        Load(MachineTypeOf<T>::value, buffer, IntPtrConstant(offset)));
  }
  TNode<RawPtrT> LoadBufferPointer(TNode<RawPtrT> buffer, int offset) {
    return LoadBufferData<RawPtrT>(buffer, offset);
  }
  TNode<Smi> LoadBufferSmi(TNode<RawPtrT> buffer, int offset) {
    return CAST(LoadBufferObject(buffer, offset));
  }
  TNode<IntPtrT> LoadBufferIntptr(TNode<RawPtrT> buffer, int offset) {
    return LoadBufferData<IntPtrT>(buffer, offset);
  }
  TNode<Uint8T> LoadUint8Ptr(TNode<RawPtrT> ptr, TNode<IntPtrT> offset);
  TNode<Uint64T> LoadUint64Ptr(TNode<RawPtrT> ptr, TNode<IntPtrT> index);

  // Load a field from an object on the heap.
  template <typename T>
  TNode<T> LoadObjectField(TNode<HeapObject> object, int offset) {
    MachineType machine_type = MachineTypeOf<T>::value;
    TNode<IntPtrT> raw_offset = IntPtrConstant(offset - kHeapObjectTag);
    if constexpr (is_subtype_v<T, UntaggedT>) {
      // Load an untagged field.
      return UncheckedCast<T>(LoadFromObject(machine_type, object, raw_offset));
    } else {
      static_assert(is_subtype_v<T, Object>);
      // Load a tagged field.
      if constexpr (is_subtype_v<T, Map>) {
        // If this is potentially loading a map, we need to check the offset.
        if (offset == HeapObject::kMapOffset) {
          machine_type = MachineType::MapInHeader();
        }
      }
      return CAST(LoadFromObject(machine_type, object, raw_offset));
    }
  }
  TNode<Object> LoadObjectField(TNode<HeapObject> object, int offset) {
    return UncheckedCast<Object>(
        LoadFromObject(MachineType::AnyTagged(), object,
                       IntPtrConstant(offset - kHeapObjectTag)));
  }
  TNode<Object> LoadObjectField(TNode<HeapObject> object,
                                TNode<IntPtrT> offset) {
    return UncheckedCast<Object>(
        LoadFromObject(MachineType::AnyTagged(), object,
                       IntPtrSub(offset, IntPtrConstant(kHeapObjectTag))));
  }
  template <class T, typename std::enable_if<
                         std::is_convertible<TNode<T>, TNode<UntaggedT>>::value,
                         int>::type = 0>
  TNode<T> LoadObjectField(TNode<HeapObject> object, TNode<IntPtrT> offset) {
    return UncheckedCast<T>(
        LoadFromObject(MachineTypeOf<T>::value, object,
                       IntPtrSub(offset, IntPtrConstant(kHeapObjectTag))));
  }
  // Load a positive SMI field and untag it.
  TNode<IntPtrT> LoadAndUntagPositiveSmiObjectField(TNode<HeapObject> object,
                                                    int offset);
  // Load a SMI field, untag it, and convert to Word32.
  TNode<Int32T> LoadAndUntagToWord32ObjectField(TNode<HeapObject> object,
                                                int offset);

  TNode<MaybeObject> LoadMaybeWeakObjectField(TNode<HeapObject> object,
                                              int offset) {
    return UncheckedCast<MaybeObject>(LoadObjectField(object, offset));
  }

  TNode<Object> LoadConstructorOrBackPointer(TNode<Map> map) {
    return LoadObjectField(map,
                           Map::kConstructorOrBackPointerOrNativeContextOffset);
  }

  TNode<Simd128T> LoadSimd128(TNode<IntPtrT> ptr) {
    return Load<Simd128T>(ptr);
  }

  // Reference is the CSA-equivalent of a Torque reference value, representing
  // an inner pointer into a HeapObject.
  //
  // The object can be a HeapObject or an all-zero bitpattern. The latter is
  // used for off-heap data, in which case the offset holds the actual address
  // and the data must be untagged (i.e. accessed via the Load-/StoreReference
  // overloads for TNode<UntaggedT>-convertible types below).
  //
  // TODO(gsps): Remove in favor of flattened {Load,Store}Reference interface.
  struct Reference {
    TNode<Object> object;
    TNode<IntPtrT> offset;

    std::tuple<TNode<Object>, TNode<IntPtrT>> Flatten() const {
      return std::make_tuple(object, offset);
    }
  };

  template <class T, typename std::enable_if<
                         std::is_convertible<TNode<T>, TNode<Object>>::value,
                         int>::type = 0>
  TNode<T> LoadReference(Reference reference) {
    if (IsMapOffsetConstant(reference.offset)) {
      TNode<Map> map = LoadMap(CAST(reference.object));
      DCHECK((std::is_base_of<T, Map>::value));
      return ReinterpretCast<T>(map);
    }

    TNode<IntPtrT> offset =
        IntPtrSub(reference.offset, IntPtrConstant(kHeapObjectTag));
    CSA_DCHECK(this, TaggedIsNotSmi(reference.object));
    return CAST(
        LoadFromObject(MachineTypeOf<T>::value, reference.object, offset));
  }
  template <class T,
            typename std::enable_if<
                std::is_convertible<TNode<T>, TNode<UntaggedT>>::value ||
                    std::is_same<T, MaybeObject>::value,
                int>::type = 0>
  TNode<T> LoadReference(Reference reference) {
    DCHECK(!IsMapOffsetConstant(reference.offset));
    TNode<IntPtrT> offset =
        IntPtrSub(reference.offset, IntPtrConstant(kHeapObjectTag));
    return UncheckedCast<T>(
        LoadFromObject(MachineTypeOf<T>::value, reference.object, offset));
  }
  template <class T, typename std::enable_if<
                         std::is_convertible<TNode<T>, TNode<Object>>::value ||
                             std::is_same<T, MaybeObject>::value,
                         int>::type = 0>
  void StoreReference(Reference reference, TNode<T> value) {
    if (IsMapOffsetConstant(reference.offset)) {
      DCHECK((std::is_base_of<T, Map>::value));
      return StoreMap(CAST(reference.object), ReinterpretCast<Map>(value));
    }
    MachineRepresentation rep = MachineRepresentationOf<T>::value;
    StoreToObjectWriteBarrier write_barrier = StoreToObjectWriteBarrier::kFull;
    if (std::is_same<T, Smi>::value) {
      write_barrier = StoreToObjectWriteBarrier::kNone;
    } else if (std::is_same<T, Map>::value) {
      write_barrier = StoreToObjectWriteBarrier::kMap;
    }
    TNode<IntPtrT> offset =
        IntPtrSub(reference.offset, IntPtrConstant(kHeapObjectTag));
    CSA_DCHECK(this, TaggedIsNotSmi(reference.object));
    StoreToObject(rep, reference.object, offset, value, write_barrier);
  }
  template <class T, typename std::enable_if<
                         std::is_convertible<TNode<T>, TNode<UntaggedT>>::value,
                         int>::type = 0>
  void StoreReference(Reference reference, TNode<T> value) {
    DCHECK(!IsMapOffsetConstant(reference.offset));
    TNode<IntPtrT> offset =
        IntPtrSub(reference.offset, IntPtrConstant(kHeapObjectTag));
    StoreToObject(MachineRepresentationOf<T>::value, reference.object, offset,
                  value, StoreToObjectWriteBarrier::kNone);
  }

  TNode<RawPtrT> GCUnsafeReferenceToRawPtr(TNode<Object> object,
                                           TNode<IntPtrT> offset) {
    return ReinterpretCast<RawPtrT>(
        IntPtrAdd(BitcastTaggedToWord(object),
                  IntPtrSub(offset, IntPtrConstant(kHeapObjectTag))));
  }

  // Load the floating point value of a HeapNumber.
  TNode<Float64T> LoadHeapNumberValue(TNode<HeapObject> object);
  // Load the Map of an HeapObject.
  TNode<Map> LoadMap(TNode<HeapObject> object);
  // Load the instance type of an HeapObject.
  TNode<Uint16T> LoadInstanceType(TNode<HeapObject> object);
  // Compare the instance the type of the object against the provided one.
  TNode<BoolT> HasInstanceType(TNode<HeapObject> object, InstanceType type);
  TNode<BoolT> DoesntHaveInstanceType(TNode<HeapObject> object,
                                      InstanceType type);
  TNode<BoolT> TaggedDoesntHaveInstanceType(TNode<HeapObject> any_tagged,
                                            InstanceType type);

  TNode<Word32T> IsStringWrapperElementsKind(TNode<Map> map);
  void GotoIfMapHasSlowProperties(TNode<Map> map, Label* if_slow);

  // Load the properties backing store of a JSReceiver.
  TNode<HeapObject> LoadSlowProperties(TNode<JSReceiver> object);
  TNode<HeapObject> LoadFastProperties(TNode<JSReceiver> object,
                                       bool skip_empty_check = false);
  // Load the elements backing store of a JSObject.
  TNode<FixedArrayBase> LoadElements(TNode<JSObject> object) {
    return LoadJSObjectElements(object);
  }
  // Load the length of a JSArray instance.
  TNode<Object> LoadJSArgumentsObjectLength(TNode<Context> context,
                                            TNode<JSArgumentsObject> array);
  // Load the length of a fast JSArray instance. Returns a positive Smi.
  TNode<Smi> LoadFastJSArrayLength(TNode<JSArray> array);
  // Load the length of a fixed array base instance.
  TNode<Smi> LoadFixedArrayBaseLength(TNode<FixedArrayBase> array);
  template <typename Array>
  TNode<Smi> LoadSmiArrayLength(TNode<Array> array) {
    return LoadObjectField<Smi>(array, offsetof(Array, length_));
  }
  // Load the length of a fixed array base instance.
  TNode<IntPtrT> LoadAndUntagFixedArrayBaseLength(TNode<FixedArrayBase> array);
  TNode<Uint32T> LoadAndUntagFixedArrayBaseLengthAsUint32(
      TNode<FixedArrayBase> array);
  // Load the length of a WeakFixedArray.
  TNode<Smi> LoadWeakFixedArrayLength(TNode<WeakFixedArray> array);
  TNode<IntPtrT> LoadAndUntagWeakFixedArrayLength(TNode<WeakFixedArray> array);
  TNode<Uint32T> LoadAndUntagWeakFixedArrayLengthAsUint32(
      TNode<WeakFixedArray> array);
  // Load the length of a BytecodeArray.
  TNode<Uint32T> LoadAndUntagBytecodeArrayLength(TNode<BytecodeArray> array);
  // Load the number of descriptors in DescriptorArray.
  TNode<Int32T> LoadNumberOfDescriptors(TNode<DescriptorArray> array);
  // Load the number of own descriptors of a map.
  TNode<Int32T> LoadNumberOfOwnDescriptors(TNode<Map> map);
  // Load the bit field of a Map.
  TNode<Int32T> LoadMapBitField(TNode<Map> map);
  // Load bit field 2 of a map.
  TNode<Int32T> LoadMapBitField2(TNode<Map> map);
  // Load bit field 3 of a map.
  TNode<Uint32T> LoadMapBitField3(TNode<Map> map);
  // Load the instance type of a map.
  TNode<Uint16T> LoadMapInstanceType(TNode<Map> map);
  // Load the ElementsKind of a map.
  TNode<Int32T> LoadMapElementsKind(TNode<Map> map);
  TNode<Int32T> LoadElementsKind(TNode<HeapObject> object);
  // Load the instance descriptors of a map.
  TNode<DescriptorArray> LoadMapDescriptors(TNode<Map> map);
  // Load the prototype of a map.
  TNode<HeapObject> LoadMapPrototype(TNode<Map> map);
  // Load the instance size of a Map.
  TNode<IntPtrT> LoadMapInstanceSizeInWords(TNode<Map> map);
  // Load the inobject properties start of a Map (valid only for JSObjects).
  TNode<IntPtrT> LoadMapInobjectPropertiesStartInWords(TNode<Map> map);
  // Load the constructor function index of a Map (only for primitive maps).
  TNode<IntPtrT> LoadMapConstructorFunctionIndex(TNode<Map> map);
  // Load the constructor of a Map (equivalent to Map::GetConstructor()).
  TNode<Object> LoadMapConstructor(TNode<Map> map);
  // Load the EnumLength of a Map.
  TNode<Uint32T> LoadMapEnumLength(TNode<Map> map);
  // Load the back-pointer of a Map.
  TNode<Object> LoadMapBackPointer(TNode<Map> map);
  // Compute the used instance size in words of a map.
  TNode<IntPtrT> MapUsedInstanceSizeInWords(TNode<Map> map);
  // Compute the number of used inobject properties on a map.
  TNode<IntPtrT> MapUsedInObjectProperties(TNode<Map> map);
  // Checks that |map| has only simple properties, returns bitfield3.
  TNode<Uint32T> EnsureOnlyHasSimpleProperties(TNode<Map> map,
                                               TNode<Int32T> instance_type,
                                               Label* bailout);
  // Load the identity hash of a JSRececiver.
  TNode<Uint32T> LoadJSReceiverIdentityHash(TNode<JSReceiver> receiver,
                                            Label* if_no_hash = nullptr);

  // This is only used on a newly allocated PropertyArray which
  // doesn't have an existing hash.
  void InitializePropertyArrayLength(TNode<PropertyArray> property_array,
                                     TNode<IntPtrT> length);

  // Check if the map is set for slow properties.
  TNode<BoolT> IsDictionaryMap(TNode<Map> map);

  // Load the Name::hash() value of a name as an uint32 value.
  // If {if_hash_not_computed} label is specified then it also checks if
  // hash is actually computed.
  TNode<Uint32T> LoadNameHash(TNode<Name> name,
                              Label* if_hash_not_computed = nullptr);
  TNode<Uint32T> LoadNameHashAssumeComputed(TNode<Name> name);

  // Load the Name::RawHash() value of a name as an uint32 value. Follows
  // through the forwarding table.
  TNode<Uint32T> LoadNameRawHash(TNode<Name> name);

  // Load length field of a String object as Smi value.
  TNode<Smi> LoadStringLengthAsSmi(TNode<String> string);
  // Load length field of a String object as intptr_t value.
  TNode<IntPtrT> LoadStringLengthAsWord(TNode<String> string);
  // Load length field of a String object as uint32_t value.
  TNode<Uint32T> LoadStringLengthAsWord32(TNode<String> string);
  // Load value field of a JSPrimitiveWrapper object.
  TNode<Object> LoadJSPrimitiveWrapperValue(TNode<JSPrimitiveWrapper> object);

  // Figures out whether the value of maybe_object is:
  // - a SMI (jump to "if_smi", "extracted" will be the SMI value)
  // - a cleared weak reference (jump to "if_cleared", "extracted" will be
  // untouched)
  // - a weak reference (jump to "if_weak", "extracted" will be the object
  // pointed to)
  // - a strong reference (jump to "if_strong", "extracted" will be the object
  // pointed to)
  void DispatchMaybeObject(TNode<MaybeObject> maybe_object, Label* if_smi,
                           Label* if_cleared, Label* if_weak, Label* if_strong,
                           TVariable<Object>* extracted);
  // See Tagged<MaybeObject> for semantics of these functions.
  TNode<BoolT> IsStrong(TNode<MaybeObject> value);
  TNode<BoolT> IsStrong(TNode<HeapObjectReference> value);
  TNode<HeapObject> GetHeapObjectIfStrong(TNode<MaybeObject> value,
                                          Label* if_not_strong);
  TNode<HeapObject> GetHeapObjectIfStrong(TNode<HeapObjectReference> value,
                                          Label* if_not_strong);

  TNode<BoolT> IsWeakOrCleared(TNode<MaybeObject> value);
  TNode<BoolT> IsWeakOrCleared(TNode<HeapObjectReference> value);
  TNode<BoolT> IsCleared(TNode<MaybeObject> value);
  TNode<BoolT> IsNotCleared(TNode<MaybeObject> value) {
    return Word32BinaryNot(IsCleared(value));
  }

  // Removes the weak bit + asserts it was set.
  TNode<HeapObject> GetHeapObjectAssumeWeak(TNode<MaybeObject> value);

  TNode<HeapObject> GetHeapObjectAssumeWeak(TNode<MaybeObject> value,
                                            Label* if_cleared);

  // Checks if |maybe_object| is a weak reference to given |heap_object|.
  // Works for both any tagged |maybe_object| values.
  TNode<BoolT> IsWeakReferenceTo(TNode<MaybeObject> maybe_object,
                                 TNode<HeapObject> heap_object);
  // Returns true if the |object| is a HeapObject and |maybe_object| is a weak
  // reference to |object|.
  // The |maybe_object| must not be a Smi.
  TNode<BoolT> IsWeakReferenceToObject(TNode<MaybeObject> maybe_object,
                                       TNode<Object> object);

  TNode<HeapObjectReference> MakeWeak(TNode<HeapObject> value);
  TNode<MaybeObject> ClearedValue();

  void FixedArrayBoundsCheck(TNode<FixedArrayBase> array, TNode<Smi> index,
                             int additional_offset);
  void FixedArrayBoundsCheck(TNode<FixedArray> array, TNode<Smi> index,
                             int additional_offset) {
    FixedArrayBoundsCheck(UncheckedCast<FixedArrayBase>(array), index,
                          additional_offset);
  }

  void FixedArrayBoundsCheck(TNode<FixedArrayBase> array, TNode<IntPtrT> index,
                             int additional_offset);
  void FixedArrayBoundsCheck(TNode<FixedArray> array, TNode<IntPtrT> index,
                             int additional_offset) {
    FixedArrayBoundsCheck(UncheckedCast<FixedArrayBase>(array), index,
                          addit
```
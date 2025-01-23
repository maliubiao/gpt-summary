Response: My goal is to summarize the functionality of the provided C++ code snippet and illustrate its interaction with JavaScript. Here's a breakdown of the thinking process:

1. **Identify the Core Class:** The code is within the `CodeStubAssembler` class. This immediately suggests low-level code generation within the V8 JavaScript engine. Code stubs are small pieces of machine code generated on the fly.

2. **Scan for Key Operations:** Quickly read through the function names and their parameters. Notice recurring patterns like:
    * `Load...FromObject`
    * `Store...ToObject`
    * Operations involving `ExternalPointer`, `TrustedObject`, `Code`
    * Operations related to `Map` and object properties
    * Operations related to Typed Arrays and BigInts
    * Operations concerning `Context` and `ScopeInfo`
    * Operations related to `MaybeObject` (weak references)
    * Operations involving array lengths and elements
    * Helper functions like `Is...`, `Has...`, `DoesntHave...`

3. **Group Functionality:**  Based on the observed patterns, mentally group the functions:
    * **Memory Access (Object Fields):**  Loading and storing data within JavaScript objects. The `BoundedSize` and `ExternalPointer` variations hint at memory management strategies, possibly for security (sandboxing).
    * **Code and Trusted Pointers:**  Dealing with pointers to executable code and other "trusted" data within the engine. The `IndirectPointerHandle` concept is a key detail here, suggesting indirection.
    * **Object Structure (Maps):**  Functions for accessing the `Map` of an object, which defines its structure (type, properties, etc.). Operations like `LoadMap`, `LoadInstanceType`, and checks for slow properties are crucial.
    * **Array Handling:**  Loading lengths and elements of various array types (FixedArray, PropertyArray, TypedArrays, WeakFixedArrays). The template usage for `LoadArrayElement` indicates genericity.
    * **Typed Arrays and BigInts:** Specific functions for reading data from typed arrays and converting the raw data to JavaScript `BigInt` values, handling endianness and word size.
    * **Context and Scope:**  Accessing information within the current execution context, including scope information.
    * **Weak References:**  Handling `MaybeObject`, which can be strong references or weak references to objects.
    * **Helper/Utility Functions:**  Predicates like `IsStrong`, `IsWeakOrCleared`, and bounds checking functions.

4. **Focus on Conditional Compilation (`#ifdef V8_ENABLE_SANDBOX`):**  This preprocessor directive indicates that certain code paths are only active when sandboxing is enabled. Note how the load/store operations for `BoundedSize` and `ExternalPointer` have different implementations depending on this flag. This is a strong clue about the purpose of these variations.

5. **Infer Relationships with JavaScript:** Connect the C++ operations to corresponding JavaScript concepts:
    * **Object Fields:** Accessing properties of JavaScript objects (e.g., `object.property`).
    * **External Pointers:**  Likely related to accessing native resources or data structures that JavaScript interacts with. The sandboxing aspect suggests security boundaries.
    * **Code Pointers:**  Executing JavaScript functions or specific engine routines.
    * **Maps and Properties:**  The underlying mechanism for how JavaScript objects are structured and how property lookups work. "Slow properties" relate to the transition to dictionary-based storage.
    * **Arrays:**  Accessing elements in JavaScript arrays. Typed arrays provide a more direct mapping to C++ data types.
    * **Context and Scope:**  The concept of lexical scope in JavaScript and the variables accessible in a given part of the code.
    * **Weak References:**  Used for scenarios like finalizers or caches where the existence of an object shouldn't be the sole reason it's kept in memory.

6. **Construct JavaScript Examples:** For each key area, create simple JavaScript code snippets that would trigger the corresponding C++ functionality. Focus on demonstrating the *effect* of the C++ code, even if the direct calls are internal. For example:
    * `object.field` for loading/storing object fields.
    * Calling native functions or using `WebAssembly.Memory` for external pointers.
    * Function calls for code pointers.
    * Accessing properties that might trigger slow property behavior.
    * Array access (`array[i]`).
    * Creating and accessing typed arrays and big integers.
    * The concept of closures and scope.
    * The use of `WeakRef` for weak references.

7. **Refine the Summary:** Organize the findings into a clear and concise summary, using bullet points or numbered lists. Highlight the connection to JavaScript functionality. Emphasize the role of `CodeStubAssembler` in generating low-level code.

8. **Review and Iterate:** Read through the summary and examples to ensure accuracy and clarity. Are there any ambiguities?  Is the language accessible?  Could the examples be improved?  (Self-correction: Initially, I might not have explicitly mentioned sandboxing and its implications, but noticing the `#ifdef` blocks makes it an important point to include.)

By following these steps, I can systematically analyze the C++ code snippet and generate a comprehensive summary with illustrative JavaScript examples. The focus is on understanding the *purpose* and *impact* of the C++ code within the larger context of the V8 engine.
这个C++代码文件 `code-stub-assembler.cc` 的第 2 部分，延续了第 1 部分的功能，主要**提供了一系列用于在 V8 引擎中生成机器码指令的辅助函数，特别是用于加载和存储 JavaScript 堆对象中的各种数据。**  它构建在 `CodeStubAssembler` 类的基础上，提供了更高级别的抽象来操作内存和类型，隐藏了底层的机器指令细节。

**本部分主要关注以下功能：**

1. **安全边界大小的加载和存储（与沙箱相关）：**
   - `LoadBoundedSizeFromObject`:  从对象中加载一个有大小限制的值。当启用沙箱模式 (`V8_ENABLE_SANDBOX`) 时，它会执行额外的移位操作来解码存储的值，这是一种可能的安全机制。
   - `StoreBoundedSizeToObject`:  将一个有大小限制的值存储到对象中。同样，在沙箱模式下，它会执行移位操作来编码值。
   - 这部分代码旨在在沙箱环境中限制可以存储和加载的内存大小，增加安全性。

2. **外部指针的加载和存储（与本地代码交互相关）：**
   - `ExternalPointerTableAddress`: 获取外部指针表的地址（仅在沙箱模式下）。
   - `LoadExternalPointerFromObject`: 从对象中加载一个外部指针。在沙箱模式下，它会从一个全局的外部指针表中查找真正的指针地址，并通过索引和标签进行解码。这是一种更安全地管理外部资源的方式。
   - `StoreExternalPointerToObject`: 将一个外部指针存储到对象中。在沙箱模式下，它会将指针存储到外部指针表中，并在对象中存储一个指向该表的索引。
   - 这些函数用于与 V8 引擎外部的 C++ 代码交互，例如访问 WebAssembly 模块的内存或调用原生函数。沙箱模式下的实现增加了安全性，防止直接存储任意外部指针。

3. **受信任指针和代码指针的加载：**
   - `LoadTrustedPointerFromObject`: 加载一个受信任的指针（在沙箱模式下可能被重定向到 `LoadIndirectPointerFromObject`）。
   - `LoadCodePointerFromObject`: 加载一个代码指针，它是受信任指针的一种特殊类型。
   - `#ifdef V8_ENABLE_SANDBOX` 部分的 `LoadIndirectPointerFromObject`, `IsTrustedPointerHandle`, `ResolveIndirectPointerHandle`, `ResolveCodePointerHandle`, `ResolveTrustedPointerHandle`：  在沙箱模式下，这些函数处理间接指针句柄，用于安全地访问受信任的对象和代码。它们通过查表的方式来解析实际的指针地址。

4. **JS 调度表相关操作（与方法调用优化相关）：**
   - `#ifdef V8_ENABLE_LEAPTIERING` 部分的 `LoadCodeObjectFromJSDispatchTable`, `LoadParameterCountFromJSDispatchTable`:  当启用 Leap Tiering 优化时，这些函数从 JS 调度表中加载代码对象和参数数量。JS 调度表是一种用于快速查找方法实现的机制。
   - `ComputeJSDispatchTableEntryOffset`: 计算 JS 调度表条目的偏移量。

5. **代码入口点的加载：**
   - `LoadCodeEntrypointViaCodePointerField`: 通过代码指针字段加载代码入口点。
   - `LoadCodeEntryFromIndirectPointerHandle`: 从间接指针句柄加载代码入口点。

6. **动态参数数量的支持：**
   - `SetSupportsDynamicParameterCount`:  设置 JS 函数是否支持动态参数数量（例如，通过 `arguments` 对象）。

7. **无效调度句柄的常量：**
   - `InvalidDispatchHandleConstant`:  返回一个表示无效调度句柄的常量。

8. **访问父帧数据：**
   - `LoadFromParentFrame`: 从父调用帧加载数据。

9. **指针加载（RawPtrT）：**
   - `LoadUint8Ptr`, `LoadUint64Ptr`:  从原始指针加载不同大小的无符号整数。

10. **加载并取消标记的 Smi 对象字段：**
    - `LoadAndUntagPositiveSmiObjectField`: 加载一个对象字段，假设它是一个正 Smi 并取消标记。
    - `LoadAndUntagToWord32ObjectField`: 加载一个对象字段，并将其作为 32 位字取消标记（处理 Smi 的表示方式）。

11. **加载 HeapNumber 的值：**
    - `LoadHeapNumberValue`:  加载 `HeapNumber` 对象的数值。

12. **加载 Map 对象：**
    - `GetInstanceTypeMap`: 获取特定 `InstanceType` 的 Map 对象。
    - `LoadMap`: 加载一个对象的 Map 对象，它是描述对象类型和结构的元数据。

13. **加载 InstanceType：**
    - `LoadInstanceType`:  从对象的 Map 中加载实例类型。
    - `HasInstanceType`: 检查对象是否具有特定的实例类型。
    - `DoesntHaveInstanceType`: 检查对象是否不具有特定的实例类型。
    - `TaggedDoesntHaveInstanceType`: 检查一个标记的值是否不是特定的实例类型。
    - `IsSpecialReceiverMap`: 检查 Map 是否是特殊接收器 Map（例如，代理对象）。

14. **检查慢属性：**
    - `IsStringWrapperElementsKind`: 检查 Map 的元素类型是否为字符串包装器。
    - `GotoIfMapHasSlowProperties`:  如果 Map 具有慢属性（例如，字典模式），则跳转到指定标签。

15. **加载快慢属性：**
    - `LoadFastProperties`: 加载对象的快属性。
    - `LoadSlowProperties`: 加载对象的慢属性。

16. **加载 arguments 对象的长度：**
    - `LoadJSArgumentsObjectLength`: 加载 JS `arguments` 对象的长度。

17. **加载数组长度：**
    - `LoadFastJSArrayLength`: 加载快速 JS 数组的长度（假设是 Smi）。
    - `LoadFixedArrayBaseLength`: 加载 `FixedArrayBase` 的长度。
    - `LoadAndUntagFixedArrayBaseLength`: 加载并取消标记 `FixedArrayBase` 的长度。
    - `LoadAndUntagFixedArrayBaseLengthAsUint32`: 加载并取消标记 `FixedArrayBase` 的长度为 `uint32_t`。
    - `LoadFeedbackVectorLength`: 加载 `FeedbackVector` 的长度。
    - `LoadWeakFixedArrayLength`: 加载 `WeakFixedArray` 的长度。
    - `LoadAndUntagWeakFixedArrayLength`: 加载并取消标记 `WeakFixedArray` 的长度。
    - `LoadAndUntagWeakFixedArrayLengthAsUint32`: 加载并取消标记 `WeakFixedArray` 的长度为 `uint32_t`。
    - `LoadAndUntagBytecodeArrayLength`: 加载并取消标记 `BytecodeArray` 的长度。

18. **加载描述符数量：**
    - `LoadNumberOfDescriptors`: 加载 `DescriptorArray` 中的描述符数量。
    - `LoadNumberOfOwnDescriptors`: 加载 Map 的自有描述符数量。

19. **加载 Map 的各种字段：**
    - `LoadMapBitField`, `LoadMapBitField2`, `LoadMapBitField3`: 加载 Map 的位字段。
    - `LoadMapInstanceType`: 加载 Map 的实例类型。
    - `LoadMapElementsKind`: 加载 Map 的元素类型。
    - `LoadElementsKind`: 加载对象的元素类型。
    - `LoadMapDescriptors`: 加载 Map 的描述符数组。
    - `LoadMapPrototype`: 加载 Map 的原型对象。
    - `LoadMapInstanceSizeInWords`: 加载 Map 的实例大小（以字为单位）。
    - `LoadMapInobjectPropertiesStartInWords`: 加载 Map 的内联属性起始位置。
    - `MapUsedInstanceSizeInWords`: 计算 Map 使用的实例大小。
    - `MapUsedInObjectProperties`: 计算 Map 使用的内联属性数量。
    - `LoadMapConstructorFunctionIndex`: 加载 Map 的构造函数索引。
    - `LoadMapConstructor`: 加载 Map 的构造函数。
    - `LoadMapEnumLength`: 加载 Map 的枚举长度。
    - `LoadMapBackPointer`: 加载 Map 的后向指针。

20. **确保只具有简单属性：**
    - `EnsureOnlyHasSimpleProperties`: 检查 Map 是否只具有简单属性。

21. **加载 JSReceiver 的 IdentityHash：**
    - `LoadJSReceiverIdentityHash`: 加载 `JSReceiver` 的身份哈希值。

22. **加载 Name 对象的哈希值：**
    - `LoadNameHashAssumeComputed`: 加载 Name 对象的哈希值（假设已计算）。
    - `LoadNameHash`: 加载 Name 对象的哈希值。
    - `LoadNameRawHash`: 加载 Name 对象的原始哈希字段。

23. **加载字符串长度：**
    - `LoadStringLengthAsSmi`: 加载字符串的长度为 Smi。
    - `LoadStringLengthAsWord`: 加载字符串的长度为字。
    - `LoadStringLengthAsWord32`: 加载字符串的长度为 32 位字。

24. **加载 JSPrimitiveWrapper 的值：**
    - `LoadJSPrimitiveWrapperValue`: 加载 `JSPrimitiveWrapper` 对象包装的原始值。

25. **处理 MaybeObject（可能为空或弱引用）：**
    - `DispatchMaybeObject`:  根据 `MaybeObject` 的状态（Smi, 清空, 弱引用, 强引用）跳转到不同的标签。
    - `DcheckHasValidMap`: 检查 HeapObject 是否具有有效的 Map。
    - `IsStrong`: 检查 `MaybeObject` 或 `HeapObjectReference` 是否是强引用。
    - `GetHeapObjectIfStrong`: 如果是强引用，则返回 HeapObject。
    - `IsWeakOrCleared`: 检查 `MaybeObject` 或 `HeapObjectReference` 是否是弱引用或已清除。
    - `IsCleared`: 检查 `MaybeObject` 是否已清除。
    - `GetHeapObjectAssumeWeak`: 假设是弱引用，获取 HeapObject。
    - `IsWeakReferenceToObject`: 检查 `MaybeObject` 是否是到特定对象的弱引用。
    - `IsWeakReferenceTo`: 检查 `MaybeObject` 是否是对特定 `HeapObject` 的弱引用。
    - `MakeWeak`: 将 `HeapObject` 转换为弱引用。
    - `ClearedValue`: 返回一个表示已清除的 `MaybeObject`。

26. **加载不同类型数组的长度（模板函数）：**
    - `LoadArrayLength<T>`:  为不同类型的数组（`FixedArray`, `ClosureFeedbackCellArray`, `ScriptContextTable`, `RegExpMatchInfo`, `WeakFixedArray`, `PropertyArray`, `DescriptorArray`, `TransitionArray`, `TrustedFixedArray`）提供加载长度的模板函数。

27. **加载数组元素（模板函数）：**
    - `LoadArrayElement<Array, TIndex, TValue>`:  提供加载数组元素的模板函数，支持不同类型的数组、索引和值。

28. **加载 FixedArray 元素（模板函数）：**
    - `LoadFixedArrayElement<TIndex>`: 提供加载 `FixedArray` 元素的模板函数，支持不同类型的索引，并可选择进行边界检查。

29. **FixedArray 的边界检查：**
    - `FixedArrayBoundsCheck`:  在调试模式下检查访问 `FixedArray` 是否越界。

30. **加载 PropertyArray 元素和长度：**
    - `LoadPropertyArrayElement`: 加载 `PropertyArray` 的元素。
    - `LoadPropertyArrayLength`: 加载 `PropertyArray` 的长度。

31. **加载 JSTypedArray 的数据指针：**
    - `LoadJSTypedArrayDataPtr`:  计算并加载 `JSTypedArray` 的底层数据指针。

32. **加载 BigInt 数组元素：**
    - `LoadFixedBigInt64ArrayElementAsTagged`:  从 `BigInt64Array` 加载元素为 `BigInt` 对象。
    - `BigIntFromInt32Pair`, `BigIntFromInt64`, `BigIntFromUint32Pair`, `BigIntFromUint64`:  辅助函数，用于从整数对或单个整数创建 `BigInt` 对象，并处理符号和大小。
    - `LoadFixedBigUint64ArrayElementAsTagged`: 从 `BigUint64Array` 加载元素为 `BigInt` 对象。

33. **加载通用的 TypedArray 元素：**
    - `LoadFixedTypedArrayElementAsTagged`:  根据元素类型从 TypedArray 中加载元素并转换为 JavaScript 可用的类型 (Smi, HeapNumber, BigInt)。

34. **加载 FeedbackVector 的槽位：**
    - `LoadFeedbackVectorSlot`: 加载 `FeedbackVector` 中的反馈槽位。

35. **加载并取消标记的数组元素：**
    - `LoadAndUntagToWord32ArrayElement`:  加载数组元素并作为 32 位字取消标记。
    - `LoadAndUntagToWord32FixedArrayElement`: 加载并取消标记 `FixedArray` 的元素。

36. **加载 WeakFixedArray 元素：**
    - `LoadWeakFixedArrayElement`: 加载 `WeakFixedArray` 的元素。

37. **加载 FixedDoubleArray 元素：**
    - `LoadFixedDoubleArrayElement`: 加载 `FixedDoubleArray` 的浮点数元素，并可选择检查是否为孔（Hole）。

38. **加载不同元素类型的数组元素（更通用的版本）：**
    - `LoadFixedArrayBaseElementAsTagged`:  根据元素的种类，加载不同类型的数组 (`FixedArray`) 元素，并处理孔对象和访问器。

39. **检查 Double 是否为孔：**
    - `IsDoubleHole`: 检查存储在内存中的 double 值是否表示一个孔。

40. **加载带有孔检查的 Double 值：**
    - `LoadDoubleWithHoleCheck`: 加载 double 值，并可以选择检查是否为孔。

41. **加载 ScopeInfo：**
    - `LoadScopeInfo`: 加载 `Context` 的 `ScopeInfo`。
    - `LoadScopeInfoHasExtensionField`: 检查 `ScopeInfo` 是否有扩展字段。
    - `LoadScopeInfoClassScopeHasPrivateBrand`: 检查类作用域的 `ScopeInfo` 是否有私有品牌。

42. **存储 Context 元素（无写屏障）：**
    - `StoreContextElementNoWriteBarrier`:  在 `Context` 中存储元素，但不使用写屏障（可能用于优化，需要小心使用）。

43. **加载 NativeContext 和 ModuleContext：**
    - `LoadNativeContext`: 加载 `Context` 的 `NativeContext`。
    - `LoadModuleContext`:  加载 `Context` 的 `ModuleContext`。

44. **获取 ImportMeta 对象：**
    - `GetImportMetaObject`: 获取模块的 `import.meta` 对象。

45. **加载 Object 函数的初始 Map：**
    - `LoadObjectFunctionInitialMap`: 加载 `Object` 构造函数的初始 Map。

46. **加载缓存的 Map：**
    - `LoadCachedMap`: 从本地上下文的 Map 缓存中加载 Map 对象。

**与 JavaScript 的关系及示例：**

这些 C++ 代码最终支撑着 JavaScript 的各种运行时行为。以下是一些 JavaScript 示例，它们背后可能会涉及到本部分代码的功能：

```javascript
// 1. 安全边界大小
// (在 JavaScript 中没有直接对应的概念，这是 V8 内部的安全机制)

// 2. 外部指针
// 访问 WebAssembly 模块的内存
const buffer = new WebAssembly.Memory({ initial: 1 });
const array = new Uint8Array(buffer.buffer);
array[0] = 42; // 存储数据到 WebAssembly 内存，可能涉及 StoreExternalPointerToObject

// 调用原生 C++ 函数 (通过 Node.js Addon 或其他机制)
// 可能涉及 LoadExternalPointerFromObject 来获取 C++ 函数的指针

// 3. 受信任指针和代码指针
function foo() { return 1; } // 定义一个 JavaScript 函数
foo(); // 调用 JavaScript 函数，V8 需要加载 foo 的代码指针来执行

// 4. JS 调度表
class MyClass {
  method() { return 2; }
}
const obj = new MyClass();
obj.method(); // 调用对象的方法，V8 可能使用 JS 调度表来快速找到 MyClass.prototype.method 的实现

// 5. 代码入口点
// (当 JavaScript 函数被调用时，V8 需要找到函数的入口地址来开始执行)

// 6. 动态参数数量
function bar() { console.log(arguments.length); }
bar(1, 2, 3); // arguments 对象的使用，涉及 SetSupportsDynamicParameterCount

// 7. 无效调度句柄
// (V8 内部错误处理或特殊情况)

// 8. 访问父帧数据
function outer() {
  let x = 10;
  function inner() {
    console.log(x); // inner 函数访问了父作用域的变量 x，可能涉及 LoadFromParentFrame
  }
  inner();
}
outer();

// 9. 指针加载 (RawPtrT)
// (通常在 V8 内部处理，JavaScript 代码不直接操作原始指针)

// 10. 加载并取消标记的 Smi 对象字段
const obj2 = { count: 5 }; // count 的值是 Smi
console.log(obj2.count); // 访问对象属性，V8 需要加载并取消标记 count 的值

// 11. 加载 HeapNumber 的值
const num = 3.14; // num 是 HeapNumber
console.log(num + 1); // 对 HeapNumber 进行运算，需要加载其数值

// 12. 加载 Map 对象
const obj3 = {}; // 创建一个空对象
// V8 内部会为 obj3 分配一个 Map 对象来描述其结构

// 13. 加载 InstanceType
const arr = []; // 创建一个数组
// V8 内部会根据 arr 的类型设置 InstanceType

// 14. 检查慢属性
const obj4 = {};
for (let i = 0; i < 1000; i++) {
  obj4['prop' + i] = i; // 添加大量属性可能导致对象切换到慢属性模式
}

// 15. 加载快慢属性
console.log(obj4.prop0); // 访问快属性或慢属性

// 16. 加载 arguments 对象的长度
// (见第 6 点示例)

// 17. 加载数组长度
const myArray = [1, 2, 3];
console.log(myArray.length); // 获取数组长度

// 18. 加载描述符数量
class MyClass2 {
  constructor() {
    this.a = 1;
    this.b = 2;
  }
}
const instance = new MyClass2();
// V8 内部会记录 MyClass2 的实例的描述符数量（属性）

// 19. 加载 Map 的各种字段
// (这些操作是 V8 内部管理对象结构的细节)

// 20. 确保只具有简单属性
// (V8 内部优化相关的操作)

// 21. 加载 JSReceiver 的 IdentityHash
const obj5 = {};
const weakRef = new WeakRef(obj5);
// WeakRef 的实现可能需要用到 IdentityHash

// 22. 加载 Name 对象的哈希值
const symbolName = Symbol('mySymbol');
const obj6 = { [symbolName]: 1 };
// 访问 Symbol 属性时，可能需要加载 Symbol 对象的哈希值

// 23. 加载字符串长度
const str = "hello";
console.log(str.length);

// 24. 加载 JSPrimitiveWrapper 的值
const boolObj = new Boolean(true);
console.log(boolObj.valueOf());

// 25. 处理 MaybeObject
let ref = {};
let weakRef2 = new WeakRef(ref);
// V8 内部使用 MaybeObject 来表示可能被垃圾回收的对象

// 26. 加载不同类型数组的长度
// (见第 17 点示例)

// 27. 加载数组元素
const arr2 = [4, 5, 6];
console.log(arr2[1]);

// 28. 加载 FixedArray 元素
// (JavaScript 数组的底层实现可能使用 FixedArray)

// 29. FixedArray 的边界检查
const arr3 = [7, 8, 9];
// arr3[10]  // 越界访问在调试模式下可能触发断言 (如果开启了相关 flag)

// 30. 加载 PropertyArray 元素和长度
const obj7 = {};
obj7.p1 = 1;
obj7.p2 = 2;
// 当对象属性较少时，可能使用 PropertyArray 存储

// 31. 加载 JSTypedArray 的数据指针
const typedArray = new Uint32Array(10);
typedArray[0] = 100; // 写入 TypedArray，需要获取其数据指针

// 32. 加载 BigInt 数组元素
const bigIntArray = new BigInt64Array([1n, 2n]);
console.log(bigIntArray[0]);

// 33. 加载通用的 TypedArray 元素
const floatArray = new Float32Array([1.0, 2.0]);
console.log(floatArray[1]);

// 34. 加载 FeedbackVector 的槽位
// (V8 内部优化，用于记录函数调用的信息)

// 35. 加载并取消标记的数组元素
// (与加载 Smi 值类似)

// 36. 加载 WeakFixedArray 元素
let obj8 = {};
let weakSet = new WeakSet([obj8]);
// WeakSet 的底层可能使用 WeakFixedArray

// 37. 加载 FixedDoubleArray 元素
const doubleArray = [1.1, 2.2]; // JavaScript 数组底层可能使用 FixedDoubleArray 存储浮点数

// 38. 加载不同元素类型的数组元素
const mixedArray = [1, "hello", true]; // 混合类型的数组

// 39. 检查 Double 是否为孔
const sparseArray = [1, , 3]; // 稀疏数组中未赋值的元素是 "孔"

// 40. 加载带有孔检查的 Double 值
console.log(sparseArray[1]); // 访问稀疏数组的孔

// 41. 加载 ScopeInfo
function closureExample() {
  let localVar = 5;
  return function() {
    console.log(localVar); // 闭包访问外部变量，需要 ScopeInfo
  }
}
closureExample()();

// 42. 存储 Context 元素（无写屏障）
// (V8 内部优化，用于存储一些生命周期短的数据)

// 43. 加载 NativeContext 和 ModuleContext
// (V8 内部管理全局对象和模块的上下文)

// 44. 获取 ImportMeta 对象
// 在 ES 模块中使用 import.meta
// console.log(import.meta.url);

// 45. 加载 Object 函数的初始 Map
const emptyObj = new Object(); // 获取 Object 构造函数的初始 Map

// 46. 加载缓存的 Map
const obj9 = {};
const obj10 = {}; // 创建结构相同的对象，V8 可能尝试重用缓存的 Map
```

总而言之，`code-stub-assembler.cc` 的这一部分提供了 V8 引擎在执行 JavaScript 代码时进行底层内存操作的关键工具，尤其是在处理对象属性、数组元素、类型信息以及与外部代码交互等方面。它通过提供类型安全的加载和存储函数，并考虑了安全性和性能优化，为 V8 引擎的高效运行奠定了基础。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共12部分，请归纳一下它的功能
```

### 源代码
```
pObject> object, TNode<IntPtrT> field_offset) {
#ifdef V8_ENABLE_SANDBOX
  TNode<Uint64T> raw_value = LoadObjectField<Uint64T>(object, field_offset);
  TNode<Uint64T> shift_amount = Uint64Constant(kBoundedSizeShift);
  TNode<Uint64T> decoded_value = Word64Shr(raw_value, shift_amount);
  return ReinterpretCast<UintPtrT>(decoded_value);
#else
  return LoadObjectField<UintPtrT>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreBoundedSizeToObject(TNode<HeapObject> object,
                                                 TNode<IntPtrT> offset,
                                                 TNode<UintPtrT> value) {
#ifdef V8_ENABLE_SANDBOX
  CSA_DCHECK(this, UintPtrLessThanOrEqual(
                       value, IntPtrConstant(kMaxSafeBufferSizeForSandbox)));
  TNode<Uint64T> raw_value = ReinterpretCast<Uint64T>(value);
  TNode<Uint64T> shift_amount = Uint64Constant(kBoundedSizeShift);
  TNode<Uint64T> encoded_value = Word64Shl(raw_value, shift_amount);
  StoreObjectFieldNoWriteBarrier<Uint64T>(object, offset, encoded_value);
#else
  StoreObjectFieldNoWriteBarrier<UintPtrT>(object, offset, value);
#endif  // V8_ENABLE_SANDBOX
}

#ifdef V8_ENABLE_SANDBOX
TNode<RawPtrT> CodeStubAssembler::ExternalPointerTableAddress(
    ExternalPointerTag tag) {
  if (IsSharedExternalPointerType(tag)) {
    TNode<ExternalReference> table_address_address = ExternalConstant(
        ExternalReference::shared_external_pointer_table_address_address(
            isolate()));
    return UncheckedCast<RawPtrT>(
        Load(MachineType::Pointer(), table_address_address));
  }
  return ExternalConstant(
      ExternalReference::external_pointer_table_address(isolate()));
}
#endif  // V8_ENABLE_SANDBOX

TNode<RawPtrT> CodeStubAssembler::LoadExternalPointerFromObject(
    TNode<HeapObject> object, TNode<IntPtrT> offset, ExternalPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  TNode<RawPtrT> external_pointer_table_address =
      ExternalPointerTableAddress(tag);
  TNode<RawPtrT> table = UncheckedCast<RawPtrT>(
      Load(MachineType::Pointer(), external_pointer_table_address,
           UintPtrConstant(Internals::kExternalPointerTableBasePointerOffset)));

  TNode<ExternalPointerHandleT> handle =
      LoadObjectField<ExternalPointerHandleT>(object, offset);

  // Use UniqueUint32Constant instead of Uint32Constant here in order to ensure
  // that the graph structure does not depend on the configuration-specific
  // constant value (Uint32Constant uses cached nodes).
  TNode<Uint32T> index =
      Word32Shr(handle, UniqueUint32Constant(kExternalPointerIndexShift));
  TNode<IntPtrT> table_offset = ElementOffsetFromIndex(
      ChangeUint32ToWord(index), SYSTEM_POINTER_ELEMENTS, 0);

  TNode<UintPtrT> entry = Load<UintPtrT>(table, table_offset);
  entry = UncheckedCast<UintPtrT>(WordAnd(entry, UintPtrConstant(~tag)));
  return UncheckedCast<RawPtrT>(UncheckedCast<WordT>(entry));
#else
  return LoadObjectField<RawPtrT>(object, offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreExternalPointerToObject(TNode<HeapObject> object,
                                                     TNode<IntPtrT> offset,
                                                     TNode<RawPtrT> pointer,
                                                     ExternalPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  TNode<RawPtrT> external_pointer_table_address =
      ExternalPointerTableAddress(tag);
  TNode<RawPtrT> table = UncheckedCast<RawPtrT>(
      Load(MachineType::Pointer(), external_pointer_table_address,
           UintPtrConstant(Internals::kExternalPointerTableBasePointerOffset)));
  TNode<ExternalPointerHandleT> handle =
      LoadObjectField<ExternalPointerHandleT>(object, offset);

  // Use UniqueUint32Constant instead of Uint32Constant here in order to ensure
  // that the graph structure does not depend on the configuration-specific
  // constant value (Uint32Constant uses cached nodes).
  TNode<Uint32T> index =
      Word32Shr(handle, UniqueUint32Constant(kExternalPointerIndexShift));
  TNode<IntPtrT> table_offset = ElementOffsetFromIndex(
      ChangeUint32ToWord(index), SYSTEM_POINTER_ELEMENTS, 0);

  TNode<UintPtrT> value = UncheckedCast<UintPtrT>(pointer);
  value = UncheckedCast<UintPtrT>(WordOr(pointer, UintPtrConstant(tag)));
  StoreNoWriteBarrier(MachineType::PointerRepresentation(), table, table_offset,
                      value);
#else
  StoreObjectFieldNoWriteBarrier<RawPtrT>(object, offset, pointer);
#endif  // V8_ENABLE_SANDBOX
}

TNode<TrustedObject> CodeStubAssembler::LoadTrustedPointerFromObject(
    TNode<HeapObject> object, int field_offset, IndirectPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
  return LoadIndirectPointerFromObject(object, field_offset, tag);
#else
  return LoadObjectField<TrustedObject>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

TNode<Code> CodeStubAssembler::LoadCodePointerFromObject(
    TNode<HeapObject> object, int field_offset) {
  return UncheckedCast<Code>(LoadTrustedPointerFromObject(
      object, field_offset, kCodeIndirectPointerTag));
}

#ifdef V8_ENABLE_SANDBOX
TNode<TrustedObject> CodeStubAssembler::LoadIndirectPointerFromObject(
    TNode<HeapObject> object, int field_offset, IndirectPointerTag tag) {
  TNode<IndirectPointerHandleT> handle =
      LoadObjectField<IndirectPointerHandleT>(object, field_offset);
  return ResolveIndirectPointerHandle(handle, tag);
}

TNode<BoolT> CodeStubAssembler::IsTrustedPointerHandle(
    TNode<IndirectPointerHandleT> handle) {
  return Word32Equal(Word32And(handle, Int32Constant(kCodePointerHandleMarker)),
                     Int32Constant(0));
}

TNode<TrustedObject> CodeStubAssembler::ResolveIndirectPointerHandle(
    TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag) {
  // The tag implies which pointer table to use.
  if (tag == kUnknownIndirectPointerTag) {
    // In this case we have to rely on the handle marking to determine which
    // pointer table to use.
    return Select<TrustedObject>(
        IsTrustedPointerHandle(handle),
        [=, this] { return ResolveTrustedPointerHandle(handle, tag); },
        [=, this] { return ResolveCodePointerHandle(handle); });
  } else if (tag == kCodeIndirectPointerTag) {
    return ResolveCodePointerHandle(handle);
  } else {
    return ResolveTrustedPointerHandle(handle, tag);
  }
}

#ifdef V8_ENABLE_LEAPTIERING
TNode<Code> CodeStubAssembler::LoadCodeObjectFromJSDispatchTable(
    TNode<JSDispatchHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::js_dispatch_table_address());
  TNode<UintPtrT> offset = ComputeJSDispatchTableEntryOffset(handle);
  offset =
      UintPtrAdd(offset, UintPtrConstant(JSDispatchEntry::kCodeObjectOffset));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // The LSB is used as marking bit by the js dispatch table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  value = UncheckedCast<UintPtrT>(WordOr(
      WordShr(value, UintPtrConstant(JSDispatchEntry::kObjectPointerShift)),
      UintPtrConstant(kHeapObjectTag)));
  return CAST(BitcastWordToTagged(value));
}

TNode<Uint16T> CodeStubAssembler::LoadParameterCountFromJSDispatchTable(
    TNode<JSDispatchHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::js_dispatch_table_address());
  TNode<UintPtrT> offset = ComputeJSDispatchTableEntryOffset(handle);
  offset =
      UintPtrAdd(offset, UintPtrConstant(JSDispatchEntry::kCodeObjectOffset));
  static_assert(JSDispatchEntry::kParameterCountMask == 0xffff);
  return Load<Uint16T>(table, offset);
}
#endif  // V8_ENABLE_LEAPTIERING

TNode<Code> CodeStubAssembler::ResolveCodePointerHandle(
    TNode<IndirectPointerHandleT> handle) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::code_pointer_table_address());
  TNode<UintPtrT> offset = ComputeCodePointerTableEntryOffset(handle);
  offset = UintPtrAdd(offset,
                      UintPtrConstant(kCodePointerTableEntryCodeObjectOffset));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // The LSB is used as marking bit by the code pointer table, so here we have
  // to set it using a bitwise OR as it may or may not be set.
  value =
      UncheckedCast<UintPtrT>(WordOr(value, UintPtrConstant(kHeapObjectTag)));
  return CAST(BitcastWordToTagged(value));
}

TNode<TrustedObject> CodeStubAssembler::ResolveTrustedPointerHandle(
    TNode<IndirectPointerHandleT> handle, IndirectPointerTag tag) {
  TNode<RawPtrT> table = ExternalConstant(
      ExternalReference::trusted_pointer_table_base_address(isolate()));
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kTrustedPointerHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kTrustedPointerTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kTrustedPointerTableEntrySizeLog2)));
  TNode<UintPtrT> value = Load<UintPtrT>(table, offset);
  // Untag the pointer and remove the marking bit in one operation.
  value = UncheckedCast<UintPtrT>(
      WordAnd(value, UintPtrConstant(~(tag | kTrustedPointerTableMarkBit))));
  return CAST(BitcastWordToTagged(value));
}

TNode<UintPtrT> CodeStubAssembler::ComputeJSDispatchTableEntryOffset(
    TNode<JSDispatchHandleT> handle) {
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kJSDispatchHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kJSDispatchTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kJSDispatchTableEntrySizeLog2)));
  return offset;
}

TNode<UintPtrT> CodeStubAssembler::ComputeCodePointerTableEntryOffset(
    TNode<IndirectPointerHandleT> handle) {
  TNode<Uint32T> index =
      Word32Shr(handle, Uint32Constant(kCodePointerHandleShift));
  // We're using a 32-bit shift here to reduce code size, but for that we need
  // to be sure that the offset will always fit into a 32-bit integer.
  static_assert(kCodePointerTableReservationSize <= 4ULL * GB);
  TNode<UintPtrT> offset = ChangeUint32ToWord(
      Word32Shl(index, Uint32Constant(kCodePointerTableEntrySizeLog2)));
  return offset;
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeEntrypointViaCodePointerField(
    TNode<HeapObject> object, TNode<IntPtrT> field_offset,
    CodeEntrypointTag tag) {
  TNode<IndirectPointerHandleT> handle =
      LoadObjectField<IndirectPointerHandleT>(object, field_offset);
  return LoadCodeEntryFromIndirectPointerHandle(handle, tag);
}

TNode<RawPtrT> CodeStubAssembler::LoadCodeEntryFromIndirectPointerHandle(
    TNode<IndirectPointerHandleT> handle, CodeEntrypointTag tag) {
  TNode<RawPtrT> table =
      ExternalConstant(ExternalReference::code_pointer_table_address());
  TNode<UintPtrT> offset = ComputeCodePointerTableEntryOffset(handle);
  TNode<UintPtrT> entry = Load<UintPtrT>(table, offset);
  if (tag != 0) {
    entry = UncheckedCast<UintPtrT>(WordXor(entry, UintPtrConstant(tag)));
  }
  return UncheckedCast<RawPtrT>(UncheckedCast<WordT>(entry));
}

#endif  // V8_ENABLE_SANDBOX

void CodeStubAssembler::SetSupportsDynamicParameterCount(
    TNode<JSFunction> callee, TNode<JSDispatchHandleT> dispatch_handle) {
  TNode<Uint16T> dynamic_parameter_count;
#ifdef V8_ENABLE_LEAPTIERING
  dynamic_parameter_count =
      LoadParameterCountFromJSDispatchTable(dispatch_handle);
#else
  TNode<SharedFunctionInfo> shared = LoadJSFunctionSharedFunctionInfo(callee);
  dynamic_parameter_count =
      LoadSharedFunctionInfoFormalParameterCountWithReceiver(shared);
#endif
  SetDynamicJSParameterCount(dynamic_parameter_count);
}

TNode<JSDispatchHandleT> CodeStubAssembler::InvalidDispatchHandleConstant() {
  return UncheckedCast<JSDispatchHandleT>(
      Uint32Constant(kInvalidDispatchHandle));
}

TNode<Object> CodeStubAssembler::LoadFromParentFrame(int offset) {
  TNode<RawPtrT> frame_pointer = LoadParentFramePointer();
  return LoadFullTagged(frame_pointer, IntPtrConstant(offset));
}

TNode<Uint8T> CodeStubAssembler::LoadUint8Ptr(TNode<RawPtrT> ptr,
                                              TNode<IntPtrT> offset) {
  return Load<Uint8T>(IntPtrAdd(ReinterpretCast<IntPtrT>(ptr), offset));
}

TNode<Uint64T> CodeStubAssembler::LoadUint64Ptr(TNode<RawPtrT> ptr,
                                                TNode<IntPtrT> index) {
  return Load<Uint64T>(
      IntPtrAdd(ReinterpretCast<IntPtrT>(ptr),
                IntPtrMul(index, IntPtrConstant(sizeof(uint64_t)))));
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagPositiveSmiObjectField(
    TNode<HeapObject> object, int offset) {
  TNode<Int32T> value = LoadAndUntagToWord32ObjectField(object, offset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Signed(ChangeUint32ToWord(value));
}

TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32ObjectField(
    TNode<HeapObject> object, int offset) {
  // Please use LoadMap(object) instead.
  DCHECK_NE(offset, HeapObject::kMapOffset);
  if (SmiValuesAre32Bits()) {
#if V8_TARGET_LITTLE_ENDIAN
    offset += 4;
#endif
    return LoadObjectField<Int32T>(object, offset);
  } else {
    return SmiToInt32(LoadObjectField<Smi>(object, offset));
  }
}

TNode<Float64T> CodeStubAssembler::LoadHeapNumberValue(
    TNode<HeapObject> object) {
  CSA_DCHECK(this, Word32Or(IsHeapNumber(object), IsTheHole(object)));
  static_assert(offsetof(HeapNumber, value_) == Hole::kRawNumericValueOffset);
  return LoadObjectField<Float64T>(object, offsetof(HeapNumber, value_));
}

TNode<Map> CodeStubAssembler::GetInstanceTypeMap(InstanceType instance_type) {
  RootIndex map_idx = Map::TryGetMapRootIdxFor(instance_type).value();
  return HeapConstantNoHole(
      i::Cast<Map>(ReadOnlyRoots(isolate()).handle_at(map_idx)));
}

TNode<Map> CodeStubAssembler::LoadMap(TNode<HeapObject> object) {
  TNode<Map> map = LoadObjectField<Map>(object, HeapObject::kMapOffset);
#ifdef V8_MAP_PACKING
  // Check the loaded map is unpacked. i.e. the lowest two bits != 0b10
  CSA_DCHECK(this,
             WordNotEqual(WordAnd(BitcastTaggedToWord(map),
                                  IntPtrConstant(Internals::kMapWordXorMask)),
                          IntPtrConstant(Internals::kMapWordSignature)));
#endif
  return map;
}

TNode<Uint16T> CodeStubAssembler::LoadInstanceType(TNode<HeapObject> object) {
  return LoadMapInstanceType(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::HasInstanceType(TNode<HeapObject> object,
                                                InstanceType instance_type) {
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected_map =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      TNode<Map> map = LoadMap(object);
      return TaggedEqual(map, LoadRoot(*expected_map));
    }
  }
  return InstanceTypeEqual(LoadInstanceType(object), instance_type);
}

TNode<BoolT> CodeStubAssembler::DoesntHaveInstanceType(
    TNode<HeapObject> object, InstanceType instance_type) {
  if (V8_STATIC_ROOTS_BOOL) {
    if (std::optional<RootIndex> expected_map =
            InstanceTypeChecker::UniqueMapOfInstanceType(instance_type)) {
      TNode<Map> map = LoadMap(object);
      return TaggedNotEqual(map, LoadRoot(*expected_map));
    }
  }
  return Word32NotEqual(LoadInstanceType(object), Int32Constant(instance_type));
}

TNode<BoolT> CodeStubAssembler::TaggedDoesntHaveInstanceType(
    TNode<HeapObject> any_tagged, InstanceType type) {
  /* return Phi <TaggedIsSmi(val), DoesntHaveInstanceType(val, type)> */
  TNode<BoolT> tagged_is_smi = TaggedIsSmi(any_tagged);
  return Select<BoolT>(
      tagged_is_smi, [=]() { return tagged_is_smi; },
      [=, this]() { return DoesntHaveInstanceType(any_tagged, type); });
}

TNode<BoolT> CodeStubAssembler::IsSpecialReceiverMap(TNode<Map> map) {
  TNode<BoolT> is_special =
      IsSpecialReceiverInstanceType(LoadMapInstanceType(map));
  uint32_t mask = Map::Bits1::HasNamedInterceptorBit::kMask |
                  Map::Bits1::IsAccessCheckNeededBit::kMask;
  USE(mask);
  // Interceptors or access checks imply special receiver.
  CSA_DCHECK(this,
             SelectConstant<BoolT>(IsSetWord32(LoadMapBitField(map), mask),
                                   is_special, Int32TrueConstant()));
  return is_special;
}

TNode<Word32T> CodeStubAssembler::IsStringWrapperElementsKind(TNode<Map> map) {
  TNode<Int32T> kind = LoadMapElementsKind(map);
  return Word32Or(
      Word32Equal(kind, Int32Constant(FAST_STRING_WRAPPER_ELEMENTS)),
      Word32Equal(kind, Int32Constant(SLOW_STRING_WRAPPER_ELEMENTS)));
}

void CodeStubAssembler::GotoIfMapHasSlowProperties(TNode<Map> map,
                                                   Label* if_slow) {
  GotoIf(IsStringWrapperElementsKind(map), if_slow);
  GotoIf(IsSpecialReceiverMap(map), if_slow);
  GotoIf(IsDictionaryMap(map), if_slow);
}

TNode<HeapObject> CodeStubAssembler::LoadFastProperties(
    TNode<JSReceiver> object, bool skip_empty_check) {
  CSA_SLOW_DCHECK(this, Word32BinaryNot(IsDictionaryMap(LoadMap(object))));
  TNode<Object> properties = LoadJSReceiverPropertiesOrHash(object);
  if (skip_empty_check) {
    return CAST(properties);
  } else {
    // TODO(ishell): use empty_property_array instead of empty_fixed_array here.
    return Select<HeapObject>(
        TaggedIsSmi(properties),
        [=, this] { return EmptyFixedArrayConstant(); },
        [=, this] { return CAST(properties); });
  }
}

TNode<HeapObject> CodeStubAssembler::LoadSlowProperties(
    TNode<JSReceiver> object) {
  CSA_SLOW_DCHECK(this, IsDictionaryMap(LoadMap(object)));
  TNode<Object> properties = LoadJSReceiverPropertiesOrHash(object);
  NodeGenerator<HeapObject> make_empty = [=, this]() -> TNode<HeapObject> {
    if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      return EmptySwissPropertyDictionaryConstant();
    } else {
      return EmptyPropertyDictionaryConstant();
    }
  };
  NodeGenerator<HeapObject> cast_properties = [=, this] {
    TNode<HeapObject> dict = CAST(properties);
    CSA_DCHECK(this,
               Word32Or(IsPropertyDictionary(dict), IsGlobalDictionary(dict)));
    return dict;
  };
  return Select<HeapObject>(TaggedIsSmi(properties), make_empty,
                            cast_properties);
}

TNode<Object> CodeStubAssembler::LoadJSArgumentsObjectLength(
    TNode<Context> context, TNode<JSArgumentsObject> array) {
  CSA_DCHECK(this, IsJSArgumentsObjectWithLength(context, array));
  constexpr int offset = JSStrictArgumentsObject::kLengthOffset;
  static_assert(offset == JSSloppyArgumentsObject::kLengthOffset);
  return LoadObjectField(array, offset);
}

TNode<Smi> CodeStubAssembler::LoadFastJSArrayLength(TNode<JSArray> array) {
  TNode<Number> length = LoadJSArrayLength(array);
  CSA_DCHECK(this, Word32Or(IsFastElementsKind(LoadElementsKind(array)),
                            IsElementsKindInRange(
                                LoadElementsKind(array),
                                FIRST_ANY_NONEXTENSIBLE_ELEMENTS_KIND,
                                LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND)));
  // JSArray length is always a positive Smi for fast arrays.
  CSA_SLOW_DCHECK(this, TaggedIsPositiveSmi(length));
  return CAST(length);
}

TNode<Smi> CodeStubAssembler::LoadFixedArrayBaseLength(
    TNode<FixedArrayBase> array) {
  CSA_SLOW_DCHECK(this, IsNotWeakFixedArraySubclass(array));
  return LoadObjectField<Smi>(array, FixedArrayBase::kLengthOffset);
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagFixedArrayBaseLength(
    TNode<FixedArrayBase> array) {
  return LoadAndUntagPositiveSmiObjectField(array,
                                            FixedArrayBase::kLengthOffset);
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagFixedArrayBaseLengthAsUint32(
    TNode<FixedArrayBase> array) {
  TNode<Int32T> value =
      LoadAndUntagToWord32ObjectField(array, FixedArrayBase::kLengthOffset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Unsigned(value);
}

TNode<IntPtrT> CodeStubAssembler::LoadFeedbackVectorLength(
    TNode<FeedbackVector> vector) {
  TNode<Int32T> length =
      LoadObjectField<Int32T>(vector, FeedbackVector::kLengthOffset);
  return ChangePositiveInt32ToIntPtr(length);
}

TNode<Smi> CodeStubAssembler::LoadWeakFixedArrayLength(
    TNode<WeakFixedArray> array) {
  return LoadObjectField<Smi>(array, offsetof(WeakFixedArray, length_));
}

TNode<IntPtrT> CodeStubAssembler::LoadAndUntagWeakFixedArrayLength(
    TNode<WeakFixedArray> array) {
  return LoadAndUntagPositiveSmiObjectField(array,
                                            offsetof(WeakFixedArray, length_));
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagWeakFixedArrayLengthAsUint32(
    TNode<WeakFixedArray> array) {
  TNode<Int32T> length =
      LoadAndUntagToWord32ObjectField(array, offsetof(WeakFixedArray, length_));
  CSA_DCHECK(this, Int32GreaterThanOrEqual(length, Int32Constant(0)));
  return Unsigned(length);
}

TNode<Uint32T> CodeStubAssembler::LoadAndUntagBytecodeArrayLength(
    TNode<BytecodeArray> array) {
  TNode<Int32T> value =
      LoadAndUntagToWord32ObjectField(array, BytecodeArray::kLengthOffset);
  CSA_DCHECK(this, Int32GreaterThanOrEqual(value, Int32Constant(0)));
  return Unsigned(value);
}

TNode<Int32T> CodeStubAssembler::LoadNumberOfDescriptors(
    TNode<DescriptorArray> array) {
  return UncheckedCast<Int32T>(LoadObjectField<Int16T>(
      array, DescriptorArray::kNumberOfDescriptorsOffset));
}

TNode<Int32T> CodeStubAssembler::LoadNumberOfOwnDescriptors(TNode<Map> map) {
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  return UncheckedCast<Int32T>(
      DecodeWord32<Map::Bits3::NumberOfOwnDescriptorsBits>(bit_field3));
}

TNode<Int32T> CodeStubAssembler::LoadMapBitField(TNode<Map> map) {
  return UncheckedCast<Int32T>(
      LoadObjectField<Uint8T>(map, Map::kBitFieldOffset));
}

TNode<Int32T> CodeStubAssembler::LoadMapBitField2(TNode<Map> map) {
  return UncheckedCast<Int32T>(
      LoadObjectField<Uint8T>(map, Map::kBitField2Offset));
}

TNode<Uint32T> CodeStubAssembler::LoadMapBitField3(TNode<Map> map) {
  return LoadObjectField<Uint32T>(map, Map::kBitField3Offset);
}

TNode<Uint16T> CodeStubAssembler::LoadMapInstanceType(TNode<Map> map) {
  return LoadObjectField<Uint16T>(map, Map::kInstanceTypeOffset);
}

TNode<Int32T> CodeStubAssembler::LoadMapElementsKind(TNode<Map> map) {
  TNode<Int32T> bit_field2 = LoadMapBitField2(map);
  return Signed(DecodeWord32<Map::Bits2::ElementsKindBits>(bit_field2));
}

TNode<Int32T> CodeStubAssembler::LoadElementsKind(TNode<HeapObject> object) {
  return LoadMapElementsKind(LoadMap(object));
}

TNode<DescriptorArray> CodeStubAssembler::LoadMapDescriptors(TNode<Map> map) {
  return LoadObjectField<DescriptorArray>(map, Map::kInstanceDescriptorsOffset);
}

TNode<HeapObject> CodeStubAssembler::LoadMapPrototype(TNode<Map> map) {
  return LoadObjectField<HeapObject>(map, Map::kPrototypeOffset);
}

TNode<IntPtrT> CodeStubAssembler::LoadMapInstanceSizeInWords(TNode<Map> map) {
  return ChangeInt32ToIntPtr(
      LoadObjectField<Uint8T>(map, Map::kInstanceSizeInWordsOffset));
}

TNode<IntPtrT> CodeStubAssembler::LoadMapInobjectPropertiesStartInWords(
    TNode<Map> map) {
  // See Map::GetInObjectPropertiesStartInWords() for details.
  CSA_DCHECK(this, IsJSObjectMap(map));
  return ChangeInt32ToIntPtr(LoadObjectField<Uint8T>(
      map, Map::kInobjectPropertiesStartOrConstructorFunctionIndexOffset));
}

TNode<IntPtrT> CodeStubAssembler::MapUsedInstanceSizeInWords(TNode<Map> map) {
  TNode<IntPtrT> used_or_unused =
      ChangeInt32ToIntPtr(LoadMapUsedOrUnusedInstanceSizeInWords(map));

  return Select<IntPtrT>(
      UintPtrGreaterThanOrEqual(used_or_unused,
                                IntPtrConstant(JSObject::kFieldsAdded)),
      [=] { return used_or_unused; },
      [=, this] { return LoadMapInstanceSizeInWords(map); });
}

TNode<IntPtrT> CodeStubAssembler::MapUsedInObjectProperties(TNode<Map> map) {
  return IntPtrSub(MapUsedInstanceSizeInWords(map),
                   LoadMapInobjectPropertiesStartInWords(map));
}

TNode<IntPtrT> CodeStubAssembler::LoadMapConstructorFunctionIndex(
    TNode<Map> map) {
  // See Map::GetConstructorFunctionIndex() for details.
  CSA_DCHECK(this, IsPrimitiveInstanceType(LoadMapInstanceType(map)));
  return ChangeInt32ToIntPtr(LoadObjectField<Uint8T>(
      map, Map::kInobjectPropertiesStartOrConstructorFunctionIndexOffset));
}

TNode<Object> CodeStubAssembler::LoadMapConstructor(TNode<Map> map) {
  TVARIABLE(Object, result,
            LoadObjectField(
                map, Map::kConstructorOrBackPointerOrNativeContextOffset));

  Label done(this), loop(this, &result);
  Goto(&loop);
  BIND(&loop);
  {
    GotoIf(TaggedIsSmi(result.value()), &done);
    TNode<BoolT> is_map_type =
        InstanceTypeEqual(LoadInstanceType(CAST(result.value())), MAP_TYPE);
    GotoIfNot(is_map_type, &done);
    result =
        LoadObjectField(CAST(result.value()),
                        Map::kConstructorOrBackPointerOrNativeContextOffset);
    Goto(&loop);
  }
  BIND(&done);
  return result.value();
}

TNode<Uint32T> CodeStubAssembler::LoadMapEnumLength(TNode<Map> map) {
  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  return DecodeWord32<Map::Bits3::EnumLengthBits>(bit_field3);
}

TNode<Object> CodeStubAssembler::LoadMapBackPointer(TNode<Map> map) {
  TNode<HeapObject> object = CAST(LoadObjectField(
      map, Map::kConstructorOrBackPointerOrNativeContextOffset));
  return Select<Object>(
      IsMap(object), [=] { return object; },
      [=, this] { return UndefinedConstant(); });
}

TNode<Uint32T> CodeStubAssembler::EnsureOnlyHasSimpleProperties(
    TNode<Map> map, TNode<Int32T> instance_type, Label* bailout) {
  // This check can have false positives, since it applies to any
  // JSPrimitiveWrapper type.
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), bailout);

  TNode<Uint32T> bit_field3 = LoadMapBitField3(map);
  GotoIf(IsSetWord32(bit_field3, Map::Bits3::IsDictionaryMapBit::kMask),
         bailout);

  return bit_field3;
}

TNode<Uint32T> CodeStubAssembler::LoadJSReceiverIdentityHash(
    TNode<JSReceiver> receiver, Label* if_no_hash) {
  TVARIABLE(Uint32T, var_hash);
  Label done(this), if_smi(this), if_property_array(this),
      if_swiss_property_dictionary(this), if_property_dictionary(this),
      if_fixed_array(this);

  TNode<Object> properties_or_hash =
      LoadObjectField(receiver, JSReceiver::kPropertiesOrHashOffset);
  GotoIf(TaggedIsSmi(properties_or_hash), &if_smi);

  TNode<HeapObject> properties = CAST(properties_or_hash);
  TNode<Uint16T> properties_instance_type = LoadInstanceType(properties);

  GotoIf(InstanceTypeEqual(properties_instance_type, PROPERTY_ARRAY_TYPE),
         &if_property_array);
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    GotoIf(
        InstanceTypeEqual(properties_instance_type, SWISS_NAME_DICTIONARY_TYPE),
        &if_swiss_property_dictionary);
  }
  Branch(InstanceTypeEqual(properties_instance_type, NAME_DICTIONARY_TYPE),
         &if_property_dictionary, &if_fixed_array);

  BIND(&if_fixed_array);
  {
    var_hash = Uint32Constant(PropertyArray::kNoHashSentinel);
    Goto(&done);
  }

  BIND(&if_smi);
  {
    var_hash = PositiveSmiToUint32(CAST(properties_or_hash));
    Goto(&done);
  }

  BIND(&if_property_array);
  {
    TNode<Int32T> length_and_hash = LoadAndUntagToWord32ObjectField(
        properties, PropertyArray::kLengthAndHashOffset);
    var_hash = DecodeWord32<PropertyArray::HashField>(length_and_hash);
    Goto(&done);
  }
  if constexpr (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    BIND(&if_swiss_property_dictionary);
    {
      var_hash = LoadSwissNameDictionaryHash(CAST(properties));
      CSA_DCHECK(this, Uint32LessThanOrEqual(var_hash.value(),
                                             Uint32Constant(Smi::kMaxValue)));
      Goto(&done);
    }
  }

  BIND(&if_property_dictionary);
  {
    var_hash = PositiveSmiToUint32(CAST(LoadFixedArrayElement(
        CAST(properties), NameDictionary::kObjectHashIndex)));
    Goto(&done);
  }

  BIND(&done);
  if (if_no_hash != nullptr) {
    GotoIf(Word32Equal(var_hash.value(),
                       Uint32Constant(PropertyArray::kNoHashSentinel)),
           if_no_hash);
  }
  return var_hash.value();
}

TNode<Uint32T> CodeStubAssembler::LoadNameHashAssumeComputed(TNode<Name> name) {
  TNode<Uint32T> hash_field = LoadNameRawHash(name);
  CSA_DCHECK(this, IsClearWord32(hash_field, Name::kHashNotComputedMask));
  return DecodeWord32<Name::HashBits>(hash_field);
}

TNode<Uint32T> CodeStubAssembler::LoadNameHash(TNode<Name> name,
                                               Label* if_hash_not_computed) {
  TNode<Uint32T> raw_hash_field = LoadNameRawHashField(name);
  if (if_hash_not_computed != nullptr) {
    GotoIf(IsSetWord32(raw_hash_field, Name::kHashNotComputedMask),
           if_hash_not_computed);
  }
  return DecodeWord32<Name::HashBits>(raw_hash_field);
}

TNode<Uint32T> CodeStubAssembler::LoadNameRawHash(TNode<Name> name) {
  TVARIABLE(Uint32T, var_raw_hash);

  Label if_forwarding_index(this, Label::kDeferred), done(this);

  TNode<Uint32T> raw_hash_field = LoadNameRawHashField(name);
  GotoIf(IsSetWord32(raw_hash_field, Name::kHashNotComputedMask),
         &if_forwarding_index);

  var_raw_hash = raw_hash_field;
  Goto(&done);

  BIND(&if_forwarding_index);
  {
    CSA_DCHECK(this,
               IsEqualInWord32<Name::HashFieldTypeBits>(
                   raw_hash_field, Name::HashFieldType::kForwardingIndex));
    TNode<ExternalReference> function =
        ExternalConstant(ExternalReference::raw_hash_from_forward_table());
    const TNode<ExternalReference> isolate_ptr =
        ExternalConstant(ExternalReference::isolate_address());
    TNode<Uint32T> result = UncheckedCast<Uint32T>(CallCFunction(
        function, MachineType::Uint32(),
        std::make_pair(MachineType::Pointer(), isolate_ptr),
        std::make_pair(
            MachineType::Int32(),
            DecodeWord32<Name::ForwardingIndexValueBits>(raw_hash_field))));

    var_raw_hash = result;
    Goto(&done);
  }

  BIND(&done);
  return var_raw_hash.value();
}

TNode<Smi> CodeStubAssembler::LoadStringLengthAsSmi(TNode<String> string) {
  return SmiFromIntPtr(LoadStringLengthAsWord(string));
}

TNode<IntPtrT> CodeStubAssembler::LoadStringLengthAsWord(TNode<String> string) {
  return Signed(ChangeUint32ToWord(LoadStringLengthAsWord32(string)));
}

TNode<Uint32T> CodeStubAssembler::LoadStringLengthAsWord32(
    TNode<String> string) {
  return LoadObjectField<Uint32T>(string, offsetof(String, length_));
}

TNode<Object> CodeStubAssembler::LoadJSPrimitiveWrapperValue(
    TNode<JSPrimitiveWrapper> object) {
  return LoadObjectField(object, JSPrimitiveWrapper::kValueOffset);
}

void CodeStubAssembler::DispatchMaybeObject(TNode<MaybeObject> maybe_object,
                                            Label* if_smi, Label* if_cleared,
                                            Label* if_weak, Label* if_strong,
                                            TVariable<Object>* extracted) {
  Label inner_if_smi(this), inner_if_strong(this);

  GotoIf(TaggedIsSmi(maybe_object), &inner_if_smi);

  GotoIf(IsCleared(maybe_object), if_cleared);

  TNode<HeapObjectReference> object_ref = CAST(maybe_object);

  GotoIf(IsStrong(object_ref), &inner_if_strong);

  *extracted = GetHeapObjectAssumeWeak(maybe_object);
  Goto(if_weak);

  BIND(&inner_if_smi);
  *extracted = CAST(maybe_object);
  Goto(if_smi);

  BIND(&inner_if_strong);
  *extracted = CAST(maybe_object);
  Goto(if_strong);
}

void CodeStubAssembler::DcheckHasValidMap(TNode<HeapObject> object) {
#ifdef V8_MAP_PACKING
  // Test if the map is an unpacked and valid map
  CSA_DCHECK(this, IsMap(LoadMap(object)));
#endif
}

TNode<BoolT> CodeStubAssembler::IsStrong(TNode<MaybeObject> value) {
  return Word32Equal(Word32And(TruncateIntPtrToInt32(
                                   BitcastTaggedToWordForTagAndSmiBits(value)),
                               Int32Constant(kHeapObjectTagMask)),
                     Int32Constant(kHeapObjectTag));
}

TNode<BoolT> CodeStubAssembler::IsStrong(TNode<HeapObjectReference> value) {
  return IsNotSetWord32(
      TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
      kHeapObjectReferenceTagMask);
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectIfStrong(
    TNode<MaybeObject> value, Label* if_not_strong) {
  GotoIfNot(IsStrong(value), if_not_strong);
  return CAST(value);
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectIfStrong(
    TNode<HeapObjectReference> value, Label* if_not_strong) {
  GotoIfNot(IsStrong(value), if_not_strong);
  return ReinterpretCast<HeapObject>(value);
}

TNode<BoolT> CodeStubAssembler::IsWeakOrCleared(TNode<MaybeObject> value) {
  return Word32Equal(Word32And(TruncateIntPtrToInt32(
                                   BitcastTaggedToWordForTagAndSmiBits(value)),
                               Int32Constant(kHeapObjectTagMask)),
                     Int32Constant(kWeakHeapObjectTag));
}

TNode<BoolT> CodeStubAssembler::IsWeakOrCleared(
    TNode<HeapObjectReference> value) {
  return IsSetWord32(
      TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
      kHeapObjectReferenceTagMask);
}

TNode<BoolT> CodeStubAssembler::IsCleared(TNode<MaybeObject> value) {
  return Word32Equal(TruncateIntPtrToInt32(BitcastMaybeObjectToWord(value)),
                     Int32Constant(kClearedWeakHeapObjectLower32));
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectAssumeWeak(
    TNode<MaybeObject> value) {
  CSA_DCHECK(this, IsWeakOrCleared(value));
  CSA_DCHECK(this, IsNotCleared(value));
  return UncheckedCast<HeapObject>(BitcastWordToTagged(WordAnd(
      BitcastMaybeObjectToWord(value), IntPtrConstant(~kWeakHeapObjectMask))));
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectAssumeWeak(
    TNode<MaybeObject> value, Label* if_cleared) {
  GotoIf(IsCleared(value), if_cleared);
  return GetHeapObjectAssumeWeak(value);
}

// This version generates
//   (maybe_object & ~mask) == value
// It works for non-Smi |maybe_object| and for both Smi and HeapObject values
// but requires a big constant for ~mask.
TNode<BoolT> CodeStubAssembler::IsWeakReferenceToObject(
    TNode<MaybeObject> maybe_object, TNode<Object> value) {
  CSA_DCHECK(this, TaggedIsNotSmi(maybe_object));
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(
        Word32And(TruncateWordToInt32(BitcastMaybeObjectToWord(maybe_object)),
                  Uint32Constant(~static_cast<uint32_t>(kWeakHeapObjectMask))),
        TruncateWordToInt32(BitcastTaggedToWord(value)));
  } else {
    return WordEqual(WordAnd(BitcastMaybeObjectToWord(maybe_object),
                             IntPtrConstant(~kWeakHeapObjectMask)),
                     BitcastTaggedToWord(value));
  }
}

// This version generates
//   maybe_object == (heap_object | mask)
// It works for any |maybe_object| values and generates a better code because it
// uses a small constant for mask.
TNode<BoolT> CodeStubAssembler::IsWeakReferenceTo(
    TNode<MaybeObject> maybe_object, TNode<HeapObject> heap_object) {
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(
        TruncateWordToInt32(BitcastMaybeObjectToWord(maybe_object)),
        Word32Or(TruncateWordToInt32(BitcastTaggedToWord(heap_object)),
                 Int32Constant(kWeakHeapObjectMask)));
  } else {
    return WordEqual(BitcastMaybeObjectToWord(maybe_object),
                     WordOr(BitcastTaggedToWord(heap_object),
                            IntPtrConstant(kWeakHeapObjectMask)));
  }
}

TNode<HeapObjectReference> CodeStubAssembler::MakeWeak(
    TNode<HeapObject> value) {
  return ReinterpretCast<HeapObjectReference>(BitcastWordToTagged(
      WordOr(BitcastTaggedToWord(value), IntPtrConstant(kWeakHeapObjectTag))));
}

TNode<MaybeObject> CodeStubAssembler::ClearedValue() {
  return ReinterpretCast<MaybeObject>(
      BitcastWordToTagged(IntPtrConstant(kClearedWeakHeapObjectLower32)));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<FixedArray> array) {
  return LoadAndUntagFixedArrayBaseLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<ClosureFeedbackCellArray> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<ScriptContextTable> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<RegExpMatchInfo> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<WeakFixedArray> array) {
  return LoadAndUntagWeakFixedArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<PropertyArray> array) {
  return LoadPropertyArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<DescriptorArray> array) {
  return IntPtrMul(ChangeInt32ToIntPtr(LoadNumberOfDescriptors(array)),
                   IntPtrConstant(DescriptorArray::kEntrySize));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<TransitionArray> array) {
  return LoadAndUntagWeakFixedArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<TrustedFixedArray> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <typename Array, typename TIndex, typename TValue>
TNode<TValue> CodeStubAssembler::LoadArrayElement(TNode<Array> array,
                                                  int array_header_size,
                                                  TNode<TIndex> index_node,
                                                  int additional_offset) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(
      std::is_same<TIndex, Smi>::value ||
          std::is_same<TIndex, UintPtrT>::value ||
          std::is_same<TIndex, IntPtrT>::value ||
          std::is_same<TIndex, TaggedIndex>::value,
      "Only Smi, UintPtrT, IntPtrT or TaggedIndex indices are allowed");
  CSA_DCHECK(this, IntPtrGreaterThanOrEqual(ParameterToIntPtr(index_node),
                                            IntPtrConstant(0)));
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  int32_t header_size = array_header_size + additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index_node, HOLEY_ELEMENTS, header_size);
  CSA_DCHECK(this, IsOffsetInBounds(offset, LoadArrayLength(array),
                                    array_header_size));
  constexpr MachineType machine_type = MachineTypeOf<TValue>::value;
  return UncheckedCast<TValue>(LoadFromObject(machine_type, array, offset));
}

template V8_EXPORT_PRIVATE TNode<MaybeObject>
CodeStubAssembler::LoadArrayElement<TransitionArray, IntPtrT>(
    TNode<TransitionArray>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<FeedbackCell>
CodeStubAssembler::LoadArrayElement<ClosureFeedbackCellArray, UintPtrT>(
    TNode<ClosureFeedbackCellArray>, int, TNode<UintPtrT>, int);
template V8_EXPORT_PRIVATE TNode<Smi> CodeStubAssembler::LoadArrayElement<
    RegExpMatchInfo, IntPtrT>(TNode<RegExpMatchInfo>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<Context>
CodeStubAssembler::LoadArrayElement<ScriptContextTable, IntPtrT>(
    TNode<ScriptContextTable>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<MaybeObject>
CodeStubAssembler::LoadArrayElement<TrustedFixedArray, IntPtrT>(
    TNode<TrustedFixedArray>, int, TNode<IntPtrT>, int);

template <typename TIndex>
TNode<Object> CodeStubAssembler::LoadFixedArrayElement(
    TNode<FixedArray> object, TNode<TIndex> index, int additional_offset,
    CheckBounds check_bounds) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(
      std::is_same<TIndex, Smi>::value ||
          std::is_same<TIndex, UintPtrT>::value ||
          std::is_same<TIndex, IntPtrT>::value ||
          std::is_same<TIndex, TaggedIndex>::value,
      "Only Smi, UintPtrT, IntPtrT or TaggedIndex indexes are allowed");
  CSA_DCHECK(this, IsFixedArraySubclass(object));
  CSA_DCHECK(this, IsNotWeakFixedArraySubclass(object));

  if (NeedsBoundsCheck(check_bounds)) {
    FixedArrayBoundsCheck(object, index, additional_offset);
  }
  TNode<MaybeObject> element = LoadArrayElement(
      object, OFFSET_OF_DATA_START(FixedArray), index, additional_offset);
  return CAST(element);
}

template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<Smi>(TNode<FixedArray>, TNode<Smi>,
                                              int, CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<TaggedIndex>(TNode<FixedArray>,
                                                      TNode<TaggedIndex>, int,
                                                      CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<UintPtrT>(TNode<FixedArray>,
                                                   TNode<UintPtrT>, int,
                                                   CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<IntPtrT>(TNode<FixedArray>,
                                                  TNode<IntPtrT>, int,
                                                  CheckBounds);

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<Smi> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  TNode<Smi> effective_index;
  Tagged<Smi> constant_index;
  bool index_is_constant = TryToSmiConstant(index, &constant_index);
  if (index_is_constant) {
    effective_index = SmiConstant(Smi::ToInt(constant_index) +
                                  additional_offset / kTaggedSize);
  } else {
    effective_index =
        SmiAdd(index, SmiConstant(additional_offset / kTaggedSize));
  }
  CSA_CHECK(this, SmiBelow(effective_index, LoadFixedArrayBaseLength(array)));
}

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<IntPtrT> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  // IntPtrAdd does constant-folding automatically.
  TNode<IntPtrT> effective_index =
      IntPtrAdd(index, IntPtrConstant(additional_offset / kTaggedSize));
  CSA_CHECK(this, UintPtrLessThan(effective_index,
                                  LoadAndUntagFixedArrayBaseLength(array)));
}

TNode<Object> CodeStubAssembler::LoadPropertyArrayElement(
    TNode<PropertyArray> object, TNode<IntPtrT> index) {
  int additional_offset = 0;
  return CAST(LoadArrayElement(object, PropertyArray::kHeaderSize, index,
                               additional_offset));
}

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<TaggedIndex> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  // IntPtrAdd does constant-folding automatically.
  TNode<IntPtrT> effective_index =
      IntPtrAdd(TaggedIndexToIntPtr(index),
                IntPtrConstant(additional_offset / kTaggedSize));
  CSA_CHECK(this, UintPtrLessThan(effective_index,
                                  LoadAndUntagFixedArrayBaseLength(array)));
}

TNode<IntPtrT> CodeStubAssembler::LoadPropertyArrayLength(
    TNode<PropertyArray> object) {
  TNode<Int32T> value = LoadAndUntagToWord32ObjectField(
      object, PropertyArray::kLengthAndHashOffset);
  return Signed(
      ChangeUint32ToWord(DecodeWord32<PropertyArray::LengthField>(value)));
}

TNode<RawPtrT> CodeStubAssembler::LoadJSTypedArrayDataPtr(
    TNode<JSTypedArray> typed_array) {
  // Data pointer = external_pointer + static_cast<Tagged_t>(base_pointer).
  TNode<RawPtrT> external_pointer =
      LoadJSTypedArrayExternalPointerPtr(typed_array);

  TNode<IntPtrT> base_pointer;
  if (COMPRESS_POINTERS_BOOL) {
    TNode<Int32T> compressed_base =
        LoadObjectField<Int32T>(typed_array, JSTypedArray::kBasePointerOffset);
    // Zero-extend TaggedT to WordT according to current compression scheme
    // so that the addition with |external_pointer| (which already contains
    // compensated offset value) below will decompress the tagged value.
    // See JSTypedArray::ExternalPointerCompensationForOnHeapArray() for
    // details.
    base_pointer = Signed(ChangeUint32ToWord(compressed_base));
  } else {
    base_pointer =
        LoadObjectField<IntPtrT>(typed_array, JSTypedArray::kBasePointerOffset);
  }
  return RawPtrAdd(external_pointer, base_pointer);
}

TNode<BigInt> CodeStubAssembler::LoadFixedBigInt64ArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset) {
  if (Is64()) {
    TNode<IntPtrT> value = Load<IntPtrT>(data_pointer, offset);
    return BigIntFromInt64(value);
  } else {
    DCHECK(!Is64());
#if defined(V8_TARGET_BIG_ENDIAN)
    TNode<IntPtrT> high = Load<IntPtrT>(data_pointer, offset);
    TNode<IntPtrT> low = Load<IntPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#else
    TNode<IntPtrT> low = Load<IntPtrT>(data_pointer, offset);
    TNode<IntPtrT> high = Load<IntPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#endif
    return BigIntFromInt32Pair(low, high);
  }
}

TNode<BigInt> CodeStubAssembler::BigIntFromInt32Pair(TNode<IntPtrT> low,
                                                     TNode<IntPtrT> high) {
  DCHECK(!Is64());
  TVARIABLE(BigInt, var_result);
  TVARIABLE(Word32T, var_sign, Int32Constant(BigInt::SignBits::encode(false)));
  TVARIABLE(IntPtrT, var_high, high);
  TVARIABLE(IntPtrT, var_low, low);
  Label high_zero(this), negative(this), allocate_one_digit(this),
      allocate_two_digits(this), if_zero(this), done(this);

  GotoIf(IntPtrEqual(var_high.value(), IntPtrConstant(0)), &high_zero);
  Branch(IntPtrLessThan(var_high.value(), IntPtrConstant(0)), &negative,
         &allocate_two_digits);

  BIND(&high_zero);
  Branch(IntPtrEqual(var_low.value(), IntPtrConstant(0)), &if_zero,
         &allocate_one_digit);

  BIND(&negative);
  {
    var_sign = Int32Constant(BigInt::SignBits::encode(true));
    // We must negate the value by computing "0 - (high|low)", performing
    // both parts of the subtraction separately and manually taking care
    // of the carry bit (which is 1 iff low != 0).
    var_high = IntPtrSub(IntPtrConstant(0), var_high.value());
    Label carry(this), no_carry(this);
    Branch(IntPtrEqual(var_low.value(), IntPtrConstant(0)), &no_carry, &carry);
    BIND(&carry);
    var_high = IntPtrSub(var_high.value(), IntPtrConstant(1));
    Goto(&no_carry);
    BIND(&no_carry);
    var_low = IntPtrSub(IntPtrConstant(0), var_low.value());
    // var_high was non-zero going into this block, but subtracting the
    // carry bit from it could bring us back onto the "one digit" path.
    Branch(IntPtrEqual(var_high.value(), IntPtrConstant(0)),
           &allocate_one_digit, &allocate_two_digits);
  }

  BIND(&allocate_one_digit);
  {
    var_result = AllocateRawBigInt(IntPtrConstant(1));
    StoreBigIntBitfield(var_result.value(),
                        Word32Or(var_sign.value(),
                                 Int32Constant(BigInt::LengthBits::encode(1))));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(var_low.value()));
    Goto(&done);
  }

  BIND(&allocate_two_digits);
  {
    var_result = AllocateRawBigInt(IntPtrConstant(2));
    StoreBigIntBitfield(var_result.value(),
                        Word32Or(var_sign.value(),
                                 Int32Constant(BigInt::LengthBits::encode(2))));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(var_low.value()));
    StoreBigIntDigit(var_result.value(), 1, Unsigned(var_high.value()));
    Goto(&done);
  }

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::BigIntFromInt64(TNode<IntPtrT> value) {
  DCHECK(Is64());
  TVARIABLE(BigInt, var_result);
  Label done(this), if_positive(this), if_negative(this), if_zero(this);
  GotoIf(IntPtrEqual(value, IntPtrConstant(0)), &if_zero);
  var_result = AllocateRawBigInt(IntPtrConstant(1));
  Branch(IntPtrGreaterThan(value, IntPtrConstant(0)), &if_positive,
         &if_negative);

  BIND(&if_positive);
  {
    StoreBigIntBitfield(var_result.value(),
                        Int32Constant(BigInt::SignBits::encode(false) |
                                      BigInt::LengthBits::encode(1)));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(value));
    Goto(&done);
  }

  BIND(&if_negative);
  {
    StoreBigIntBitfield(var_result.value(),
                        Int32Constant(BigInt::SignBits::encode(true) |
                                      BigInt::LengthBits::encode(1)));
    StoreBigIntDigit(var_result.value(), 0,
                     Unsigned(IntPtrSub(IntPtrConstant(0), value)));
    Goto(&done);
  }

  BIND(&if_zero);
  {
    var_result = AllocateBigInt(IntPtrConstant(0));
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::LoadFixedBigUint64ArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset) {
  Label if_zero(this), done(this);
  if (Is64()) {
    TNode<UintPtrT> value = Load<UintPtrT>(data_pointer, offset);
    return BigIntFromUint64(value);
  } else {
    DCHECK(!Is64());
#if defined(V8_TARGET_BIG_ENDIAN)
    TNode<UintPtrT> high = Load<UintPtrT>(data_pointer, offset);
    TNode<UintPtrT> low = Load<UintPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#else
    TNode<UintPtrT> low = Load<UintPtrT>(data_pointer, offset);
    TNode<UintPtrT> high = Load<UintPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#endif
    return BigIntFromUint32Pair(low, high);
  }
}

TNode<BigInt> CodeStubAssembler::BigIntFromUint32Pair(TNode<UintPtrT> low,
                                                      TNode<UintPtrT> high) {
  DCHECK(!Is64());
  TVARIABLE(BigInt, var_result);
  Label high_zero(this), if_zero(this), done(this);

  GotoIf(IntPtrEqual(high, IntPtrConstant(0)), &high_zero);
  var_result = AllocateBigInt(IntPtrConstant(2));
  StoreBigIntDigit(var_result.value(), 0, low);
  StoreBigIntDigit(var_result.value(), 1, high);
  Goto(&done);

  BIND(&high_zero);
  GotoIf(IntPtrEqual(low, IntPtrConstant(0)), &if_zero);
  var_result = AllocateBigInt(IntPtrConstant(1));
  StoreBigIntDigit(var_result.value(), 0, low);
  Goto(&done);

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::BigIntFromUint64(TNode<UintPtrT> value) {
  DCHECK(Is64());
  TVARIABLE(BigInt, var_result);
  Label done(this), if_zero(this);
  GotoIf(IntPtrEqual(value, IntPtrConstant(0)), &if_zero);
  var_result = AllocateBigInt(IntPtrConstant(1));
  StoreBigIntDigit(var_result.value(), 0, value);
  Goto(&done);

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);
  BIND(&done);
  return var_result.value();
}

TNode<Numeric> CodeStubAssembler::LoadFixedTypedArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<UintPtrT> index,
    ElementsKind elements_kind) {
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(Signed(index), elements_kind, 0);
  switch (elements_kind) {
    case UINT8_ELEMENTS: /* fall through */
    case UINT8_CLAMPED_ELEMENTS:
      return SmiFromInt32(Load<Uint8T>(data_pointer, offset));
    case INT8_ELEMENTS:
      return SmiFromInt32(Load<Int8T>(data_pointer, offset));
    case UINT16_ELEMENTS:
      return SmiFromInt32(Load<Uint16T>(data_pointer, offset));
    case INT16_ELEMENTS:
      return SmiFromInt32(Load<Int16T>(data_pointer, offset));
    case UINT32_ELEMENTS:
      return ChangeUint32ToTagged(Load<Uint32T>(data_pointer, offset));
    case INT32_ELEMENTS:
      return ChangeInt32ToTagged(Load<Int32T>(data_pointer, offset));
    case FLOAT16_ELEMENTS:
      return AllocateHeapNumberWithValue(
          ChangeFloat16ToFloat64(Load<Float16RawBitsT>(data_pointer, offset)));
    case FLOAT32_ELEMENTS:
      return AllocateHeapNumberWithValue(
          ChangeFloat32ToFloat64(Load<Float32T>(data_pointer, offset)));
    case FLOAT64_ELEMENTS:
      return AllocateHeapNumberWithValue(Load<Float64T>(data_pointer, offset));
    case BIGINT64_ELEMENTS:
      return LoadFixedBigInt64ArrayElementAsTagged(data_pointer, offset);
    case BIGUINT64_ELEMENTS:
      return LoadFixedBigUint64ArrayElementAsTagged(data_pointer, offset);
    default:
      UNREACHABLE();
  }
}

TNode<Numeric> CodeStubAssembler::LoadFixedTypedArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<UintPtrT> index,
    TNode<Int32T> elements_kind) {
  TVARIABLE(Numeric, var_result);
  Label done(this), if_unknown_type(this, Label::kDeferred);
  int32_t elements_kinds[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) TYPE##_ELEMENTS,
      TYPED_ARRAYS(TYPED_ARRAY_CASE) RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) Label if_##type##array(this);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  Label* elements_kind_labels[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) &if_##type##array,
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      // The same labels again for RAB / GSAB. We dispatch RAB / GSAB elements
      // kinds to the corresponding non-RAB / GSAB elements kinds.
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };
  static_assert(arraysize(elements_kinds) == arraysize(elements_kind_labels));

  Switch(elements_kind, &if_unknown_type, elements_kinds, elements_kind_labels,
         arraysize(elements_kinds));

  BIND(&if_unknown_type);
  Unreachable();

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                        \
  BIND(&if_##type##array);                                               \
  {                                                                      \
    var_result = LoadFixedTypedArrayElementAsTagged(data_pointer, index, \
                                                    TYPE##_ELEMENTS);    \
    Goto(&done);                                                         \
  }
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  BIND(&done);
  return var_result.value();
}

template <typename TIndex>
TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<TIndex> slot,
    int additional_offset) {
  int32_t header_size = FeedbackVector::kRawFeedbackSlotsOffset +
                        additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(slot, HOLEY_ELEMENTS, header_size);
  CSA_SLOW_DCHECK(
      this, IsOffsetInBounds(offset, LoadFeedbackVectorLength(feedback_vector),
                             FeedbackVector::kHeaderSize));
  return Load<MaybeObject>(feedback_vector, offset);
}

template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<TaggedIndex> slot,
    int additional_offset);
template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<IntPtrT> slot,
    int additional_offset);
template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
    int additional_offset);

template <typename Array>
TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32ArrayElement(
    TNode<Array> object, int array_header_size, TNode<IntPtrT> index,
    int additional_offset) {
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  int endian_correction = 0;
#if V8_TARGET_LITTLE_ENDIAN
  if (SmiValuesAre32Bits()) endian_correction = 4;
#endif
  int32_t header_size = array_header_size + additional_offset - kHeapObjectTag +
                        endian_correction;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, HOLEY_ELEMENTS, header_size);
  CSA_DCHECK(this, IsOffsetInBounds(offset, LoadArrayLength(object),
                                    array_header_size + endian_correction));
  if (SmiValuesAre32Bits()) {
    return Load<Int32T>(object, offset);
  } else {
    return SmiToInt32(Load<Smi>(object, offset));
  }
}

TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32FixedArrayElement(
    TNode<FixedArray> object, TNode<IntPtrT> index, int additional_offset) {
  CSA_SLOW_DCHECK(this, IsFixedArraySubclass(object));
  return LoadAndUntagToWord32ArrayElement(
      object, OFFSET_OF_DATA_START(FixedArray), index, additional_offset);
}

TNode<MaybeObject> CodeStubAssembler::LoadWeakFixedArrayElement(
    TNode<WeakFixedArray> object, TNode<IntPtrT> index, int additional_offset) {
  return LoadArrayElement(object, OFFSET_OF_DATA_START(WeakFixedArray), index,
                          additional_offset);
}

TNode<Float64T> CodeStubAssembler::LoadFixedDoubleArrayElement(
    TNode<FixedDoubleArray> object, TNode<IntPtrT> index, Label* if_hole,
    MachineType machine_type) {
  int32_t header_size = OFFSET_OF_DATA_START(FixedDoubleArray) - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, HOLEY_DOUBLE_ELEMENTS, header_size);
  CSA_DCHECK(this,
             IsOffsetInBounds(offset, LoadAndUntagFixedArrayBaseLength(object),
                              OFFSET_OF_DATA_START(FixedDoubleArray),
                              HOLEY_DOUBLE_ELEMENTS));
  return LoadDoubleWithHoleCheck(object, offset, if_hole, machine_type);
}

TNode<Object> CodeStubAssembler::LoadFixedArrayBaseElementAsTagged(
    TNode<FixedArrayBase> elements, TNode<IntPtrT> index,
    TNode<Int32T> elements_kind, Label* if_accessor, Label* if_hole) {
  TVARIABLE(Object, var_result);
  Label done(this), if_packed(this), if_holey(this), if_packed_double(this),
      if_holey_double(this), if_dictionary(this, Label::kDeferred);

  int32_t kinds[] = {
      // Handled by if_packed.
      PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, PACKED_NONEXTENSIBLE_ELEMENTS,
      PACKED_SEALED_ELEMENTS, PACKED_FROZEN_ELEMENTS,
      // Handled by if_holey.
      HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS, HOLEY_NONEXTENSIBLE_ELEMENTS,
      HOLEY_SEALED_ELEMENTS, HOLEY_FROZEN_ELEMENTS,
      // Handled by if_packed_double.
      PACKED_DOUBLE_ELEMENTS,
      // Handled by if_holey_double.
      HOLEY_DOUBLE_ELEMENTS};
  Label* labels[] = {// PACKED_{SMI,}_ELEMENTS
                     &if_packed, &if_packed, &if_packed, &if_packed, &if_packed,
                     // HOLEY_{SMI,}_ELEMENTS
                     &if_holey, &if_holey, &if_holey, &if_holey, &if_holey,
                     // PACKED_DOUBLE_ELEMENTS
                     &if_packed_double,
                     // HOLEY_DOUBLE_ELEMENTS
                     &if_holey_double};
  Switch(elements_kind, &if_dictionary, kinds, labels, arraysize(kinds));

  BIND(&if_packed);
  {
    var_result = LoadFixedArrayElement(CAST(elements), index, 0);
    Goto(&done);
  }

  BIND(&if_holey);
  {
    var_result = LoadFixedArrayElement(CAST(elements), index);
    Branch(TaggedEqual(var_result.value(), TheHoleConstant()), if_hole, &done);
  }

  BIND(&if_packed_double);
  {
    var_result = AllocateHeapNumberWithValue(
        LoadFixedDoubleArrayElement(CAST(elements), index));
    Goto(&done);
  }

  BIND(&if_holey_double);
  {
    var_result = AllocateHeapNumberWithValue(
        LoadFixedDoubleArrayElement(CAST(elements), index, if_hole));
    Goto(&done);
  }

  BIND(&if_dictionary);
  {
    CSA_DCHECK(this, IsDictionaryElementsKind(elements_kind));
    var_result = BasicLoadNumberDictionaryElement(CAST(elements), index,
                                                  if_accessor, if_hole);
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsDoubleHole(TNode<Object> base,
                                             TNode<IntPtrT> offset) {
  // TODO(ishell): Compare only the upper part for the hole once the
  // compiler is able to fold addition of already complex |offset| with
  // |kIeeeDoubleExponentWordOffset| into one addressing mode.
  if (Is64()) {
    TNode<Uint64T> element = Load<Uint64T>(base, offset);
    return Word64Equal(element, Int64Constant(kHoleNanInt64));
  } else {
    TNode<Uint32T> element_upper = Load<Uint32T>(
        base, IntPtrAdd(offset, IntPtrConstant(kIeeeDoubleExponentWordOffset)));
    return Word32Equal(element_upper, Int32Constant(kHoleNanUpper32));
  }
}

TNode<Float64T> CodeStubAssembler::LoadDoubleWithHoleCheck(
    TNode<Object> base, TNode<IntPtrT> offset, Label* if_hole,
    MachineType machine_type) {
  if (if_hole) {
    GotoIf(IsDoubleHole(base, offset), if_hole);
  }
  if (machine_type.IsNone()) {
    // This means the actual value is not needed.
    return TNode<Float64T>();
  }
  return UncheckedCast<Float64T>(Load(machine_type, base, offset));
}

TNode<ScopeInfo> CodeStubAssembler::LoadScopeInfo(TNode<Context> context) {
  return CAST(LoadContextElement(context, Context::SCOPE_INFO_INDEX));
}

TNode<BoolT> CodeStubAssembler::LoadScopeInfoHasExtensionField(
    TNode<ScopeInfo> scope_info) {
  TNode<Uint32T> value =
      LoadObjectField<Uint32T>(scope_info, ScopeInfo::kFlagsOffset);
  return IsSetWord32<ScopeInfo::HasContextExtensionSlotBit>(value);
}

TNode<BoolT> CodeStubAssembler::LoadScopeInfoClassScopeHasPrivateBrand(
    TNode<ScopeInfo> scope_info) {
  TNode<Uint32T> value =
      LoadObjectField<Uint32T>(scope_info, ScopeInfo::kFlagsOffset);
  return IsSetWord32<ScopeInfo::ClassScopeHasPrivateBrandBit>(value);
}

void CodeStubAssembler::StoreContextElementNoWriteBarrier(
    TNode<Context> context, int slot_index, TNode<Object> value) {
  int offset = Context::SlotOffset(slot_index);
  StoreNoWriteBarrier(MachineRepresentation::kTagged, context,
                      IntPtrConstant(offset), value);
}

TNode<NativeContext> CodeStubAssembler::LoadNativeContext(
    TNode<Context> context) {
  TNode<Map> map = LoadMap(context);
  return CAST(LoadObjectField(
      map, Map::kConstructorOrBackPointerOrNativeContextOffset));
}

TNode<Context> CodeStubAssembler::LoadModuleContext(TNode<Context> context) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> module_map = CAST(
      LoadContextElement(native_context, Context::MODULE_CONTEXT_MAP_INDEX));
  TVariable<Object> cur_context(context, this);

  Label context_found(this);

  Label context_search(this, &cur_context);

  // Loop until cur_context->map() is module_map.
  Goto(&context_search);
  BIND(&context_search);
  {
    CSA_DCHECK(this, Word32BinaryNot(
                         TaggedEqual(cur_context.value(), native_context)));
    GotoIf(TaggedEqual(LoadMap(CAST(cur_context.value())), module_map),
           &context_found);

    cur_context =
        LoadContextElement(CAST(cur_context.value()), Context::PREVIOUS_INDEX);
    Goto(&context_search);
  }

  BIND(&context_found);
  return UncheckedCast<Context>(cur_context.value());
}

TNode<Object> CodeStubAssembler::GetImportMetaObject(TNode<Context> context) {
  const TNode<Context> module_context = LoadModuleContext(context);
  const TNode<HeapObject> module =
      CAST(LoadContextElement(module_context, Context::EXTENSION_INDEX));
  const TNode<Object> import_meta =
      LoadObjectField(module, SourceTextModule::kImportMetaOffset);

  TVARIABLE(Object, return_value, import_meta);

  Label end(this);
  GotoIfNot(IsTheHole(import_meta), &end);

  return_value = CallRuntime(Runtime::kGetImportMetaObject, context);
  Goto(&end);

  BIND(&end);
  return return_value.value();
}

TNode<Map> CodeStubAssembler::LoadObjectFunctionInitialMap(
    TNode<NativeContext> native_context) {
  TNode<JSFunction> object_function =
      CAST(LoadContextElement(native_context, Context::OBJECT_FUNCTION_INDEX));
  return CAST(LoadJSFunctionPrototypeOrInitialMap(object_function));
}

TNode<Map> CodeStubAssembler::LoadCachedMap(TNode<NativeContext> native_context,
                                            TNode<IntPtrT> number_of_properties,
                                            Label* runtime) {
  CSA_DCHECK(this, UintPtrLessThan(number_of_properties,
                                   IntPtrConstant(JSObject::kMapCacheSize)));
  TNode<WeakFixedArray> cache =
      CAST(LoadContextElement(native_context, Context::MAP_CACHE_INDEX));
  TNode<MaybeObject> value =
      LoadWeakFixedArrayElement(cache, number_of_properties, 0);
  TNode<Map> result = CAST(GetH
```
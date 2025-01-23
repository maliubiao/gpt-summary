Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for the functionalities of the provided C++ code snippet, specifically focusing on code related to type checking and object property access within the V8 JavaScript engine. It also touches upon the concept of Torque and its relationship to JavaScript.

2. **Initial Scan and Keyword Identification:** I quickly scan the code for recognizable patterns and keywords. I see many functions starting with `Is...`, `TaggedIs...`, `HasInstanceType`, and loads/stores of object properties. These immediately suggest type checking and potentially object structure manipulation. Keywords like `Map`, `HeapObject`, `Smi`, `String`, `Array`, etc., indicate the types being checked.

3. **Categorize Functionalities:** Based on the initial scan, I start grouping the functions by their apparent purpose. The dominant theme is clearly type checking. I see functions checking for:
    * Basic JavaScript types (number, string, boolean, null, undefined).
    * Object types (JSReceiver, JSObject, JSArray, JSFunction, etc.).
    * Internal V8 object types (Map, Code, FixedArray).
    * String subtypes (OneByteString, TwoByteString, InternalizedString, etc.).
    * Numeric subtypes (SafeInteger, Integer).

4. **Analyze Individual Function Blocks:**  I examine the implementation details of representative functions to confirm my initial categorization. For example:
    * `TaggedEqual`:  This clearly compares a tagged pointer with a map. This is a fundamental operation for type checking in V8.
    * `TaggedIsCallable`: This checks if an object is callable (a function). It handles both Smis (which are never callable) and HeapObjects, checking the object's map.
    * `IsJSArray`: This checks if a HeapObject is a JSArray by looking at its map's instance type.
    * The various `Is...InstanceType` functions directly compare the instance type of an object with a specific constant.

5. **Identify the Role of `CodeStubAssembler`:** The prefix `CodeStubAssembler::` for all these functions is significant. I know from general knowledge about compilers and runtime environments that an assembler is involved in generating low-level code. `CodeStub` suggests reusable code snippets. Therefore, `CodeStubAssembler` is likely a class that provides building blocks and utilities for generating machine code, and these type-checking functions are used within those code stubs.

6. **Address the Torque Question:** The prompt asks about `.tq` files. I know Torque is V8's type-safe dialect for generating C++ code. I recognize that the provided `.cc` file is the *output* of the Torque compiler, not the Torque source itself. This distinction is crucial.

7. **Connect to JavaScript Functionality:** The type checks in the C++ code directly correspond to JavaScript's `typeof` operator and other type-checking mechanisms (e.g., `Array.isArray()`, checking for callable objects). I select relevant JavaScript examples that demonstrate the purpose of these underlying C++ checks.

8. **Infer Code Logic and Examples:** Based on the function names and implementations, I infer the logic and create simple input/output examples. For instance, `TaggedIsCallable` will return `true` for a function object and `false` for a plain object.

9. **Identify Common Programming Errors:** Since these functions are about type checking, common errors involve assuming an object is of a certain type without verifying it, leading to runtime errors. I provide JavaScript examples where incorrect type assumptions would cause issues.

10. **Synthesize the Functionality Summary:** I combine my observations into a concise summary, highlighting the core purpose of the code: providing efficient type-checking primitives for the V8 engine's code generation process.

11. **Incorporate the "Part 10 of 23" Information:** This suggests the code is part of a larger system. I acknowledge this and frame the summary within the context of a component responsible for basic type and object property checks.

12. **Refine and Organize:** I review my answer for clarity, accuracy, and completeness. I ensure the JavaScript examples are clear and directly related to the C++ code's functionality. I organize the information logically with headings and bullet points for better readability.

By following these steps, I can systematically analyze the provided C++ code snippet and provide a comprehensive and accurate answer to the user's request, addressing all aspects of their query.
这是一个V8源代码文件 `v8/src/codegen/code-stub-assembler.cc` 的代码片段。根据你提供的信息，我们来分析一下它的功能：

**主要功能归纳：提供了一系列用于在 V8 的 CodeStubAssembler 中进行类型检查和对象属性判断的工具函数。**

**详细功能点：**

1. **类型检查工具:**  该代码片段定义了大量的函数，用于判断一个对象或其属性是否属于特定的 V8 类型。这些类型包括：
    * **基本类型:**  Smi (小整数), HeapNumber, Boolean, Null, Undefined, Oddball。
    * **字符串类型:** String (包括各种子类型如 SequentialString, ExternalString, OneByteString, TwoByteString, InternalizedString, SharedString)。
    * **函数和代码类型:** Callable, Constructor, Function, BoundFunction, Code。
    * **对象类型:** JSReceiver, JSObject (及其子类型如 JSArray, JSFunction, JSGlobalProxy, JSProxy, JSPrimitiveWrapper, JSTypedArray 等), Map, PropertyCell。
    * **集合类型:** FixedArray (及其子类型), PropertyArray, HashTable (及其子类型如 EphemeronHashTable, PropertyDictionary)。
    * **其他 V8 内部类型:**  Symbol, BigInt, PromiseReactionJobTask。

2. **基于 Map 的类型检查:** 很多函数，例如 `IsCallableMap`, `IsConstructorMap`, `IsJSArrayMap` 等，通过加载对象的 `Map` 并在其上进行位域检查或比较来判断类型。`Map` 是 V8 中用于描述对象结构和类型的关键内部对象。

3. **基于 Instance Type 的类型检查:** 另一类函数，例如 `IsStringInstanceType`, `IsJSArrayInstanceType`，直接检查对象的 `instance_type` 字段。`instance_type` 是 `Map` 中存储的一个枚举值，用于快速区分对象的基本类型。

4. **优化手段:**  在某些情况下，代码使用了 `#if V8_STATIC_ROOTS_BOOL` 这样的预编译指令，这表明 V8 为了性能，在某些编译配置下会使用静态根（预先分配好的常用对象）来进行更快速的类型检查。

5. **辅助函数:** 还有一些辅助性的类型判断函数，例如 `IsNullOrUndefined`, `IsNullOrJSReceiver`, `IsNumeric`, `IsSafeInteger`, `IsInteger` 等，用于更复杂的类型判断场景。

**关于 `.tq` 文件：**

你提供的信息是正确的。如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。Torque 是 V8 团队开发的一种领域特定语言，用于更安全、更易于维护地生成 V8 的 C++ 代码，特别是用于实现内置函数和运行时功能。

**与 JavaScript 功能的关系及 JavaScript 示例：**

这些 C++ 代码中的类型检查函数，直接对应于 JavaScript 中我们常用的类型判断操作和语言特性。

* **`typeof` 运算符:**
   ```javascript
   console.log(typeof 10);        // "number"
   console.log(typeof "hello");   // "string"
   console.log(typeof true);      // "boolean"
   console.log(typeof undefined); // "undefined"
   console.log(typeof null);      // "object" (这是一个历史遗留问题)
   console.log(typeof {});        // "object"
   console.log(typeof []);        // "object"
   console.log(typeof function(){}); // "function"
   ```
   V8 内部会使用类似 `TaggedIsSmi`, `IsHeapNumber`, `IsJSFunction` 这样的函数来支持 `typeof` 的判断。

* **`instanceof` 运算符:**
   ```javascript
   class MyClass {}
   const obj = new MyClass();
   console.log(obj instanceof MyClass); // true
   console.log(obj instanceof Object);  // true
   ```
   虽然 `instanceof` 的实现机制更复杂，涉及到原型链查找，但 V8 在某些情况下也会使用对象的 `Map` 和 `instance_type` 信息进行优化。

* **isArray, isNaN, isFinite 等全局函数:**
   ```javascript
   console.log(Array.isArray([]));   // true
   console.log(isNaN(NaN));         // true
   console.log(isFinite(100));       // true
   ```
   V8 内部的实现会用到类似的类型检查函数，例如 `IsJSArray` 来判断是否是数组， `IsHeapNumber` 来判断是否是数字（进而判断是否是 NaN 或有限数）。

* **其他内置对象和方法:**
   ```javascript
   const arr = [];
   console.log(arr instanceof Array); // true  (对应 C++ 中的 IsJSArray)

   const fn = () => {};
   console.log(typeof fn === 'function'); // true (对应 C++ 中的 IsJSFunction 或 TaggedIsCallable)
   ```

**代码逻辑推理及假设输入输出：**

假设我们调用 `CodeStubAssembler::IsJSArray` 函数，并传入一个代表 JavaScript 数组的 `HeapObject`。

* **假设输入:** `object` 指向一个 V8 堆中的 `JSArray` 对象。
* **内部逻辑:** `IsJSArray` 函数会调用 `LoadMap(object)` 获取该数组对象的 `Map`，然后调用 `IsJSArrayInstanceType(LoadMapInstanceType(map))` 来检查 `Map` 中存储的 `instance_type` 是否等于 `JS_ARRAY_TYPE`。
* **预期输出:**  如果输入确实是 `JSArray` 对象，则函数返回 `true` (`Int32TrueConstant()`)。否则返回 `false` (`Int32FalseConstant()`)。

**用户常见的编程错误举例：**

用户在 JavaScript 中常见的与类型相关的编程错误，往往是因为没有正确地进行类型检查，或者对某些类型的理解存在偏差。V8 的这些类型检查函数正是为了避免这些错误，或者在出现错误时提供更清晰的运行时信息。

* **错误地假设变量类型：**
   ```javascript
   function processInput(input) {
     // 错误地假设 input 是一个数组
     for (let i = 0; i < input.length; i++) { // 如果 input 不是数组，会报错
       console.log(input[i]);
     }
   }

   processInput("not an array"); // 运行时报错：input.length is undefined
   ```
   正确的做法是在循环前使用 `Array.isArray(input)` 进行检查。

* **`typeof null` 的误解：**
   ```javascript
   function handleObject(obj) {
     if (typeof obj === 'object') {
       // 认为 obj 一定是一个真正的对象
       console.log(obj.someProperty);
     }
   }

   handleObject(null); // 运行时报错：Cannot read properties of null
   ```
   应该先检查 `obj !== null`。

* **忘记考虑 `NaN` 的特殊性：**
   ```javascript
   function isNumberValid(num) {
     return num === num; // 只能排除 NaN
   }

   console.log(isNumberValid(10));    // true
   console.log(isNumberValid(NaN));   // false
   console.log(isNumberValid("hello")); // true (因为字符串比较自身是相等的)
   ```
   需要使用 `typeof num === 'number' && !isNaN(num)` 进行更全面的数字校验。

**第 10 部分，共 23 部分的功能归纳：**

考虑到这是代码库的第 10 部分，并且专注于类型检查和对象属性判断，我们可以推断这一部分的主要职责是为 V8 的代码生成器 (CodeStubAssembler) 提供**基础的、底层的类型判断和对象结构检查能力**。这些能力是构建更高级的语言特性和优化手段的基石。

简单来说，这部分代码就像是 V8 引擎的“类型识别器”，它能够快速准确地判断各种 V8 内部对象的类型，为后续的代码执行和优化提供必要的信息。这部分的功能是确保 V8 能够正确地理解和操作 JavaScript 代码的基础。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第10部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
STRICT_ARGUMENTS_MAP_INDEX);
  return TaggedEqual(arguments_map, map);
}

TNode<BoolT> CodeStubAssembler::TaggedIsCallable(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        return IsCallableMap(LoadMap(UncheckedCast<HeapObject>(object)));
      });
}

TNode<BoolT> CodeStubAssembler::IsCallable(TNode<HeapObject> object) {
  return IsCallableMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::TaggedIsCode(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] { return IsCode(UncheckedCast<HeapObject>(object)); });
}

TNode<BoolT> CodeStubAssembler::IsCode(TNode<HeapObject> object) {
  return HasInstanceType(object, CODE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsConstructorMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::IsConstructorBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsConstructor(TNode<HeapObject> object) {
  return IsConstructorMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsFunctionWithPrototypeSlotMap(TNode<Map> map) {
  return IsSetWord32<Map::Bits1::HasPrototypeSlotBit>(LoadMapBitField(map));
}

TNode<BoolT> CodeStubAssembler::IsSpecialReceiverInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(JS_GLOBAL_OBJECT_TYPE <= LAST_SPECIAL_RECEIVER_TYPE);
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_SPECIAL_RECEIVER_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsCustomElementsReceiverInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_CUSTOM_ELEMENTS_RECEIVER));
}

TNode<BoolT> CodeStubAssembler::IsStringInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(INTERNALIZED_TWO_BYTE_STRING_TYPE == FIRST_TYPE);
  return Int32LessThan(instance_type, Int32Constant(FIRST_NONSTRING_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsTemporalInstantInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_TEMPORAL_INSTANT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOneByteStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringEncodingMask)),
      Int32Constant(kOneByteStringTag));
}

TNode<BoolT> CodeStubAssembler::IsSequentialStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kSeqStringTag));
}

TNode<BoolT> CodeStubAssembler::IsSeqOneByteStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type,
                Int32Constant(kStringRepresentationAndEncodingMask)),
      Int32Constant(kSeqOneByteStringTag));
}

TNode<BoolT> CodeStubAssembler::IsConsStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kConsStringTag));
}

TNode<BoolT> CodeStubAssembler::IsIndirectStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  static_assert(kIsIndirectStringMask == 0x1);
  static_assert(kIsIndirectStringTag == 0x1);
  return UncheckedCast<BoolT>(
      Word32And(instance_type, Int32Constant(kIsIndirectStringMask)));
}

TNode<BoolT> CodeStubAssembler::IsExternalStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  return Word32Equal(
      Word32And(instance_type, Int32Constant(kStringRepresentationMask)),
      Int32Constant(kExternalStringTag));
}

TNode<BoolT> CodeStubAssembler::IsUncachedExternalStringInstanceType(
    TNode<Int32T> instance_type) {
  CSA_DCHECK(this, IsStringInstanceType(instance_type));
  static_assert(kUncachedExternalStringTag != 0);
  return IsSetWord32(instance_type, kUncachedExternalStringMask);
}

TNode<BoolT> CodeStubAssembler::IsJSReceiverInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  return Int32GreaterThanOrEqual(instance_type,
                                 Int32Constant(FIRST_JS_RECEIVER_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsSequentialStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  // Both sequential string maps are allocated at the start of the read only
  // heap, so we can use a single comparison to check for them.
  static_assert(
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.first == 0);
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kSeqString.second);
#else
  return IsSequentialStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsExternalStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kExternalString.first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kExternalString.second);
#else
  return IsExternalStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsUncachedExternalStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  return IsInRange(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kUncachedExternalString
          .first,
      InstanceTypeChecker::kUniqueMapRangeOfStringType::kUncachedExternalString
          .second);
#else
  return IsUncachedExternalStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsOneByteStringMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  CSA_DCHECK(this, IsStringInstanceType(LoadMapInstanceType(map)));

  // These static asserts make sure that the following bit magic on the map word
  // is safe. See the definition of kStringMapEncodingMask for an explanation.
#define VALIDATE_STRING_MAP_ENCODING_BIT(instance_type, size, name, Name) \
  static_assert(                                                          \
      ((instance_type & kStringEncodingMask) == kOneByteStringTag) ==     \
      ((StaticReadOnlyRoot::k##Name##Map &                                \
        InstanceTypeChecker::kStringMapEncodingMask) ==                   \
       InstanceTypeChecker::kOneByteStringMapBit));                       \
  static_assert(                                                          \
      ((instance_type & kStringEncodingMask) == kTwoByteStringTag) ==     \
      ((StaticReadOnlyRoot::k##Name##Map &                                \
        InstanceTypeChecker::kStringMapEncodingMask) ==                   \
       InstanceTypeChecker::kTwoByteStringMapBit));
  STRING_TYPE_LIST(VALIDATE_STRING_MAP_ENCODING_BIT)
#undef VALIDATE_STRING_TYPE_RANGES

  return Word32Equal(
      Word32And(TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
                Int32Constant(InstanceTypeChecker::kStringMapEncodingMask)),
      Int32Constant(InstanceTypeChecker::kOneByteStringMapBit));
#else
  return IsOneByteStringInstanceType(LoadMapInstanceType(map));
#endif
}

TNode<BoolT> CodeStubAssembler::IsJSReceiverMap(TNode<Map> map) {
  return IsJSReceiverInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::JSAnyIsNotPrimitiveMap(TNode<Map> map) {
#if V8_STATIC_ROOTS_BOOL
  // Assuming this is only called with primitive objects or js receivers.
  CSA_DCHECK(this, Word32Or(IsPrimitiveInstanceType(LoadMapInstanceType(map)),
                            IsJSReceiverMap(map)));
  // All primitive object's maps are allocated at the start of the read only
  // heap. Thus JS_RECEIVER's must have maps with larger (compressed) addresses.
  return Uint32GreaterThanOrEqual(
      TruncateIntPtrToInt32(BitcastTaggedToWord(map)),
      Int32Constant(InstanceTypeChecker::kNonJsReceiverMapLimit));
#else
  return IsJSReceiverMap(map);
#endif
}

TNode<BoolT> CodeStubAssembler::IsJSReceiver(TNode<HeapObject> object) {
  return IsJSReceiverMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::JSAnyIsNotPrimitive(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  return JSAnyIsNotPrimitiveMap(LoadMap(object));
#else
  return IsJSReceiver(object);
#endif
}

TNode<BoolT> CodeStubAssembler::IsNullOrJSReceiver(TNode<HeapObject> object) {
  return UncheckedCast<BoolT>(Word32Or(IsJSReceiver(object), IsNull(object)));
}

TNode<BoolT> CodeStubAssembler::IsNullOrUndefined(TNode<Object> value) {
  // TODO(ishell): consider using Select<BoolT>() here.
  return UncheckedCast<BoolT>(Word32Or(IsUndefined(value), IsNull(value)));
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxyInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_GLOBAL_PROXY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxyMap(TNode<Map> map) {
  return IsJSGlobalProxyInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSGlobalProxy(TNode<HeapObject> object) {
  return IsJSGlobalProxyMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSGeneratorMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map), JS_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSObjectInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(LAST_JS_OBJECT_TYPE == LAST_TYPE);
  return Int32GreaterThanOrEqual(instance_type,
                                 Int32Constant(FIRST_JS_OBJECT_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObjectInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_API_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSObjectMap(TNode<Map> map) {
  return IsJSObjectInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObjectMap(TNode<Map> map) {
  return IsJSApiObjectInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSObject(TNode<HeapObject> object) {
  return IsJSObjectMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSApiObject(TNode<HeapObject> object) {
  return IsJSApiObjectMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSFinalizationRegistryMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map),
                           JS_FINALIZATION_REGISTRY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFinalizationRegistry(
    TNode<HeapObject> object) {
  return IsJSFinalizationRegistryMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSPromiseMap(TNode<Map> map) {
  return InstanceTypeEqual(LoadMapInstanceType(map), JS_PROMISE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPromise(TNode<HeapObject> object) {
  return IsJSPromiseMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSProxy(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_PROXY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSStringIterator(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_STRING_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSShadowRealm(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_SHADOW_REALM_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRegExpStringIterator(
    TNode<HeapObject> object) {
  return HasInstanceType(object, JS_REG_EXP_STRING_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsMap(TNode<HeapObject> object) {
  return HasInstanceType(object, MAP_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapperInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_PRIMITIVE_WRAPPER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapper(TNode<HeapObject> object) {
  return IsJSPrimitiveWrapperMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSPrimitiveWrapperMap(TNode<Map> map) {
  return IsJSPrimitiveWrapperInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSWrappedFunction(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_WRAPPED_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSArray(TNode<HeapObject> object) {
  return IsJSArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayMap(TNode<Map> map) {
  return IsJSArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayIterator(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ARRAY_ITERATOR_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsAlwaysSharedSpaceJSObjectInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type, FIRST_ALWAYS_SHARED_SPACE_JS_OBJECT_TYPE,
                   LAST_ALWAYS_SHARED_SPACE_JS_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_SHARED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArrayMap(TNode<Map> map) {
  return IsJSSharedArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArray(TNode<HeapObject> object) {
  return IsJSSharedArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedArray(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        TNode<HeapObject> heap_object = CAST(object);
        return IsJSSharedArray(heap_object);
      });
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStructInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_SHARED_STRUCT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStructMap(TNode<Map> map) {
  return IsJSSharedStructInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStruct(TNode<HeapObject> object) {
  return IsJSSharedStructMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSSharedStruct(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32FalseConstant(); },
      [=, this] {
        TNode<HeapObject> heap_object = CAST(object);
        return IsJSSharedStruct(heap_object);
      });
}

TNode<BoolT> CodeStubAssembler::IsJSAsyncGeneratorObject(
    TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ASYNC_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFixedArray(TNode<HeapObject> object) {
  return HasInstanceType(object, FIXED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFixedArraySubclass(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(
      Word32And(Int32GreaterThanOrEqual(instance_type,
                                        Int32Constant(FIRST_FIXED_ARRAY_TYPE)),
                Int32LessThanOrEqual(instance_type,
                                     Int32Constant(LAST_FIXED_ARRAY_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsNotWeakFixedArraySubclass(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(Word32Or(
      Int32LessThan(instance_type, Int32Constant(FIRST_WEAK_FIXED_ARRAY_TYPE)),
      Int32GreaterThan(instance_type,
                       Int32Constant(LAST_WEAK_FIXED_ARRAY_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsPropertyArray(TNode<HeapObject> object) {
  return HasInstanceType(object, PROPERTY_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsPromiseReactionJobTask(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return IsInRange(instance_type, FIRST_PROMISE_REACTION_JOB_TASK_TYPE,
                   LAST_PROMISE_REACTION_JOB_TASK_TYPE);
}

// This complicated check is due to elements oddities. If a smi array is empty
// after Array.p.shift, it is replaced by the empty array constant. If it is
// later filled with a double element, we try to grow it but pass in a double
// elements kind. Usually this would cause a size mismatch (since the source
// fixed array has HOLEY_ELEMENTS and destination has
// HOLEY_DOUBLE_ELEMENTS), but we don't have to worry about it when the
// source array is empty.
// TODO(jgruber): It might we worth creating an empty_double_array constant to
// simplify this case.
TNode<BoolT> CodeStubAssembler::IsFixedArrayWithKindOrEmpty(
    TNode<FixedArrayBase> object, ElementsKind kind) {
  Label out(this);
  TVARIABLE(BoolT, var_result, Int32TrueConstant());

  GotoIf(IsFixedArrayWithKind(object, kind), &out);

  const TNode<Smi> length = LoadFixedArrayBaseLength(object);
  GotoIf(SmiEqual(length, SmiConstant(0)), &out);

  var_result = Int32FalseConstant();
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsFixedArrayWithKind(TNode<HeapObject> object,
                                                     ElementsKind kind) {
  if (IsDoubleElementsKind(kind)) {
    return IsFixedDoubleArray(object);
  } else {
    DCHECK(IsSmiOrObjectElementsKind(kind) || IsSealedElementsKind(kind) ||
           IsNonextensibleElementsKind(kind));
    return IsFixedArraySubclass(object);
  }
}

TNode<BoolT> CodeStubAssembler::IsBoolean(TNode<HeapObject> object) {
  return IsBooleanMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsPropertyCell(TNode<HeapObject> object) {
  return IsPropertyCellMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsHeapNumberInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, HEAP_NUMBER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNotAnyHole(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Word32BinaryNot(IsHoleInstanceType(
            LoadInstanceType(UncheckedCast<HeapObject>(object))));
      });
}

TNode<BoolT> CodeStubAssembler::IsHoleInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, HOLE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOddball(TNode<HeapObject> object) {
  return IsOddballInstanceType(LoadInstanceType(object));
}

TNode<BoolT> CodeStubAssembler::IsOddballInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, ODDBALL_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsName(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  TNode<Map> map = LoadMap(object);
  TNode<Word32T> map_as_word32 = ReinterpretCast<Word32T>(map);
  static_assert(InstanceTypeChecker::kStringMapUpperBound + Map::kSize ==
                StaticReadOnlyRoot::kSymbolMap);
  return Uint32LessThanOrEqual(map_as_word32,
                               Int32Constant(StaticReadOnlyRoot::kSymbolMap));
#else
  return IsNameInstanceType(LoadInstanceType(object));
#endif
}

TNode<BoolT> CodeStubAssembler::IsNameInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type, Int32Constant(LAST_NAME_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsString(TNode<HeapObject> object) {
#if V8_STATIC_ROOTS_BOOL
  TNode<Map> map = LoadMap(object);
  TNode<Word32T> map_as_word32 =
      TruncateIntPtrToInt32(BitcastTaggedToWord(map));
  return Uint32LessThanOrEqual(
      map_as_word32, Int32Constant(InstanceTypeChecker::kStringMapUpperBound));
#else
  return IsStringInstanceType(LoadInstanceType(object));
#endif
}

TNode<Word32T> CodeStubAssembler::IsStringWrapper(TNode<HeapObject> object) {
  return IsStringWrapperElementsKind(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsSeqOneByteString(TNode<HeapObject> object) {
  return IsSeqOneByteStringInstanceType(LoadInstanceType(object));
}

TNode<BoolT> CodeStubAssembler::IsSymbolInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, SYMBOL_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsInternalizedStringInstanceType(
    TNode<Int32T> instance_type) {
  static_assert(kNotInternalizedTag != 0);
  return Word32Equal(
      Word32And(instance_type,
                Int32Constant(kIsNotStringMask | kIsNotInternalizedMask)),
      Int32Constant(kStringTag | kInternalizedTag));
}

TNode<BoolT> CodeStubAssembler::IsSharedStringInstanceType(
    TNode<Int32T> instance_type) {
  TNode<BoolT> is_shared = Word32Equal(
      Word32And(instance_type,
                Int32Constant(kIsNotStringMask | kSharedStringMask)),
      Int32Constant(kStringTag | kSharedStringTag));
  // TODO(v8:12007): Internalized strings do not have kSharedStringTag until
  // the shared string table ships.
  return Word32Or(is_shared,
                  Word32And(HasSharedStringTableFlag(),
                            IsInternalizedStringInstanceType(instance_type)));
}

TNode<BoolT> CodeStubAssembler::IsUniqueName(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] { return Int32TrueConstant(); },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

// Semantics: guaranteed not to be an integer index (i.e. contains non-digit
// characters, or is outside MAX_SAFE_INTEGER/size_t range). Note that for
// non-TypedArray receivers, there are additional strings that must be treated
// as named property keys, namely the range [0xFFFFFFFF, MAX_SAFE_INTEGER].
// The hash could be a forwarding index to an integer index.
// For now we conservatively assume that all forwarded hashes could be integer
// indices, allowing false negatives.
// TODO(pthier): We could use 1 bit of the forward index to indicate whether the
// forwarded hash contains an integer index, if this is turns out to be a
// performance issue, at the cost of slowing down creating the forwarded string.
TNode<BoolT> CodeStubAssembler::IsUniqueNameNoIndex(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] {
        return IsSetWord32(LoadNameRawHashField(CAST(object)),
                           Name::kDoesNotContainIntegerOrForwardingIndexMask);
      },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

// Semantics: {object} is a Symbol, or a String that doesn't have a cached
// index. This returns {true} for strings containing representations of
// integers in the range above 9999999 (per kMaxCachedArrayIndexLength)
// and below MAX_SAFE_INTEGER. For CSA_DCHECKs ensuring correct usage, this is
// better than no checking; and we don't have a good/fast way to accurately
// check such strings for being within "array index" (uint32_t) range.
TNode<BoolT> CodeStubAssembler::IsUniqueNameNoCachedIndex(
    TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return Select<BoolT>(
      IsInternalizedStringInstanceType(instance_type),
      [=, this] {
        return IsSetWord32(LoadNameRawHash(CAST(object)),
                           Name::kDoesNotContainCachedArrayIndexMask);
      },
      [=, this] { return IsSymbolInstanceType(instance_type); });
}

TNode<BoolT> CodeStubAssembler::IsBigIntInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, BIGINT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsBigInt(TNode<HeapObject> object) {
  return IsBigIntInstanceType(LoadInstanceType(object));
}

void CodeStubAssembler::GotoIfLargeBigInt(TNode<BigInt> bigint,
                                          Label* true_label) {
  // Small BigInts are BigInts in the range [-2^63 + 1, 2^63 - 1] so that they
  // can fit in 64-bit registers. Excluding -2^63 from the range makes the check
  // simpler and faster. The other BigInts are seen as "large".
  // TODO(panq): We might need to reevaluate of the range of small BigInts.
  DCHECK(Is64());
  Label false_label(this);
  TNode<Uint32T> length =
      DecodeWord32<BigIntBase::LengthBits>(LoadBigIntBitfield(bigint));
  GotoIf(Word32Equal(length, Uint32Constant(0)), &false_label);
  GotoIfNot(Word32Equal(length, Uint32Constant(1)), true_label);
  Branch(WordEqual(UintPtrConstant(0),
                   WordAnd(LoadBigIntDigit(bigint, 0),
                           UintPtrConstant(static_cast<uintptr_t>(
                               1ULL << (sizeof(uintptr_t) * 8 - 1))))),
         &false_label, true_label);
  Bind(&false_label);
}

TNode<BoolT> CodeStubAssembler::IsPrimitiveInstanceType(
    TNode<Int32T> instance_type) {
  return Int32LessThanOrEqual(instance_type,
                              Int32Constant(LAST_PRIMITIVE_HEAP_OBJECT_TYPE));
}

TNode<BoolT> CodeStubAssembler::IsPrivateName(TNode<Symbol> symbol) {
  TNode<Uint32T> flags =
      LoadObjectField<Uint32T>(symbol, offsetof(Symbol, flags_));
  return IsSetWord32<Symbol::IsPrivateNameBit>(flags);
}

TNode<BoolT> CodeStubAssembler::IsHashTable(TNode<HeapObject> object) {
  TNode<Uint16T> instance_type = LoadInstanceType(object);
  return UncheckedCast<BoolT>(
      Word32And(Int32GreaterThanOrEqual(instance_type,
                                        Int32Constant(FIRST_HASH_TABLE_TYPE)),
                Int32LessThanOrEqual(instance_type,
                                     Int32Constant(LAST_HASH_TABLE_TYPE))));
}

TNode<BoolT> CodeStubAssembler::IsEphemeronHashTable(TNode<HeapObject> object) {
  return HasInstanceType(object, EPHEMERON_HASH_TABLE_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsPropertyDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, PROPERTY_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsOrderedNameDictionary(
    TNode<HeapObject> object) {
  return HasInstanceType(object, ORDERED_NAME_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsGlobalDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, GLOBAL_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNumberDictionary(TNode<HeapObject> object) {
  return HasInstanceType(object, NUMBER_DICTIONARY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSGeneratorObject(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_GENERATOR_OBJECT_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsFunctionInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type,
                   FIRST_JS_FUNCTION_OR_BOUND_FUNCTION_OR_WRAPPED_FUNCTION_TYPE,
                   LAST_JS_FUNCTION_OR_BOUND_FUNCTION_OR_WRAPPED_FUNCTION_TYPE);
}
TNode<BoolT> CodeStubAssembler::IsJSFunctionInstanceType(
    TNode<Int32T> instance_type) {
  return IsInRange(instance_type, FIRST_JS_FUNCTION_TYPE,
                   LAST_JS_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFunction(TNode<HeapObject> object) {
  return IsJSFunctionMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSBoundFunction(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_BOUND_FUNCTION_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSFunctionMap(TNode<Map> map) {
  return IsJSFunctionInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArrayInstanceType(
    TNode<Int32T> instance_type) {
  return InstanceTypeEqual(instance_type, JS_TYPED_ARRAY_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArrayMap(TNode<Map> map) {
  return IsJSTypedArrayInstanceType(LoadMapInstanceType(map));
}

TNode<BoolT> CodeStubAssembler::IsJSTypedArray(TNode<HeapObject> object) {
  return IsJSTypedArrayMap(LoadMap(object));
}

TNode<BoolT> CodeStubAssembler::IsJSArrayBuffer(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_ARRAY_BUFFER_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSDataView(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_DATA_VIEW_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRabGsabDataView(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_RAB_GSAB_DATA_VIEW_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsJSRegExp(TNode<HeapObject> object) {
  return HasInstanceType(object, JS_REG_EXP_TYPE);
}

TNode<BoolT> CodeStubAssembler::IsNumeric(TNode<Object> object) {
  return Select<BoolT>(
      TaggedIsSmi(object), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return UncheckedCast<BoolT>(
            Word32Or(IsHeapNumber(CAST(object)), IsBigInt(CAST(object))));
      });
}

TNode<BoolT> CodeStubAssembler::IsNumberNormalized(TNode<Number> number) {
  TVARIABLE(BoolT, var_result, Int32TrueConstant());
  Label out(this);

  GotoIf(TaggedIsSmi(number), &out);

  TNode<Float64T> value = LoadHeapNumberValue(CAST(number));
  TNode<Float64T> smi_min =
      Float64Constant(static_cast<double>(Smi::kMinValue));
  TNode<Float64T> smi_max =
      Float64Constant(static_cast<double>(Smi::kMaxValue));

  GotoIf(Float64LessThan(value, smi_min), &out);
  GotoIf(Float64GreaterThan(value, smi_max), &out);
  GotoIfNot(Float64Equal(value, value), &out);  // NaN.

  var_result = Int32FalseConstant();
  Goto(&out);

  BIND(&out);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsNumberPositive(TNode<Number> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return TaggedIsPositiveSmi(number); },
      [=, this] { return IsHeapNumberPositive(CAST(number)); });
}

// TODO(cbruni): Use TNode<HeapNumber> instead of custom name.
TNode<BoolT> CodeStubAssembler::IsHeapNumberPositive(TNode<HeapNumber> number) {
  TNode<Float64T> value = LoadHeapNumberValue(number);
  TNode<Float64T> float_zero = Float64Constant(0.);
  return Float64GreaterThanOrEqual(value, float_zero);
}

TNode<BoolT> CodeStubAssembler::IsNumberNonNegativeSafeInteger(
    TNode<Number> number) {
  return Select<BoolT>(
      // TODO(cbruni): Introduce TaggedIsNonNegateSmi to avoid confusion.
      TaggedIsSmi(number), [=, this] { return TaggedIsPositiveSmi(number); },
      [=, this] {
        TNode<HeapNumber> heap_number = CAST(number);
        return Select<BoolT>(
            IsInteger(heap_number),
            [=, this] { return IsHeapNumberPositive(heap_number); },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsSafeInteger(TNode<Object> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Select<BoolT>(
            IsHeapNumber(CAST(number)),
            [=, this] {
              return IsSafeInteger(UncheckedCast<HeapNumber>(number));
            },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsSafeInteger(TNode<HeapNumber> number) {
  // Load the actual value of {number}.
  TNode<Float64T> number_value = LoadHeapNumberValue(number);
  // Truncate the value of {number} to an integer (or an infinity).
  TNode<Float64T> integer = Float64Trunc(number_value);

  return Select<BoolT>(
      // Check if {number}s value matches the integer (ruling out the
      // infinities).
      Float64Equal(Float64Sub(number_value, integer), Float64Constant(0.0)),
      [=, this] {
        // Check if the {integer} value is in safe integer range.
        return Float64LessThanOrEqual(Float64Abs(integer),
                                      Float64Constant(kMaxSafeInteger));
      },
      [=, this] { return Int32FalseConstant(); });
}

TNode<BoolT> CodeStubAssembler::IsInteger(TNode<Object> number) {
  return Select<BoolT>(
      TaggedIsSmi(number), [=, this] { return Int32TrueConstant(); },
      [=, this] {
        return Select<BoolT>(
            IsHeapNumber(CAST(number)),
            [=, this] { return IsInteger(UncheckedCast<HeapNumber>(number)); },
            [=, this] { return Int32FalseConstant(); });
      });
}

TNode<BoolT> CodeStubAssembler::IsInteger(TNode<HeapNumber> number) {
  TNode<Float64T> number_value = LoadHeapNumberValue(number);
  // Truncate the value of {number} to an integer (or an infinity).
  TNode<Float64T> integer = Float64Trunc(number_value);
  // Check if {number}s value matches the integer (ruling out the infinities).
  return Float64Equal(Float64Sub(number_value, integer), Float64Constant(0.0));
}

TNode<BoolT> CodeStubAssembler::IsHeapNumberUint32(TNode<HeapNumber> number) {
  // Check that the HeapNumber is a valid uint32
  return Select<BoolT>(
      IsHeapNumberPositive(number),
      [=, this] {
        TNode<Float64T> value = LoadHeapNumberValue(nu
```
Response: The user wants me to summarize the functionality of a C++ source code file related to JavaScript call reduction in the V8 engine. The provided snippet focuses on handling calls to various built-in JavaScript functions.

Here's a breakdown of my thought process:

1. **Identify the core purpose:** The code snippet is a `switch` statement that handles different `Builtin` cases. Each case seems to correspond to a JavaScript built-in function (e.g., `Array`, `Boolean`, `Object`, `Math`, `String`, `Promise`, `Map`, `Set`, `Date`). The return value for each case is a call to a `Reduce...` function (e.g., `ReduceArrayConstructor`, `ReduceBooleanConstructor`). This strongly suggests the code's primary function is to optimize or transform calls to these built-in functions during compilation.

2. **Recognize the "reduction" concept:** The term "reduce" in the function names (`ReduceArrayConstructor`, etc.) and the class name (`JSCallReducer`) is a key indicator. In compiler optimization, "reduction" often refers to simplifying or rewriting an expression into a more efficient form. This means the code isn't *executing* the JavaScript built-ins but rather *transforming* the internal representation of their calls.

3. **Categorize the handled built-ins:**  The `switch` statement covers a wide range of JavaScript's core built-in objects and their methods. I can group them thematically:
    * **Constructors:** `Array`, `Boolean`, `Function`, `Object`, `Number`, `BigInt`, `Promise`, `String`, `TypedArray`
    * **Object methods:** `create`, `getPrototypeOf`, `is`, `hasOwnProperty`, `isPrototypeOf`
    * **Function methods:** `apply`, `bind`, `call`, `hasInstance`
    * **Reflect API:** `apply`, `construct`, `get`, `getPrototypeOf`, `has`
    * **Array methods:** `forEach`, `map`, `filter`, `reduce`, `reduceRight`, `find`, `findIndex`, `every`, `indexOf`, `includes`, `some`, `at`, `push`, `pop`, `slice`, `entries`, `keys`, `values`, `isArray`, `fromCharCode`, `fromCodePoint`
    * **TypedArray and DataView methods:** Accessors for byte length, byte offset, and various typed data reads/writes.
    * **Math object methods:**  A comprehensive list of `Math` functions like `abs`, `cos`, `sin`, `pow`, `min`, `max`, etc.
    * **Number object methods:** `isFinite`, `isInteger`, `isNaN`, `parseInt`
    * **Global functions:** `isFinite`, `isNaN`
    * **Map and Set methods:** `get`, `has`, `size`, `entries`, `keys`, `values`
    * **RegExp methods:** `test`
    * **String methods:** `indexOf`, `includes`, `charAt`, `charCodeAt`, `codePointAt`, `substring`, `slice`, `substr`, `startsWith`, `endsWith`, `localeCompare`, `toLowerCase`, `toUpperCase`, `concat`, `iterator`
    * **Promise methods:** `catch`, `finally`, `then`, `resolve`
    * **Iterator methods:** For arrays, strings, maps, and sets.
    * **Date methods:** `getTime`, `now`
    * **BigInt methods:** `asIntN`, `asUintN`
    * **Other:** `ReturnReceiver`, `GetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`

4. **Infer the "how":** The `Reduce...` function names suggest these functions are responsible for the actual simplification logic. The code doesn't provide the implementation of these functions, but the overall structure shows that the `JSCallReducer` identifies the specific built-in being called and dispatches to a specialized function to handle it.

5. **Connect to JavaScript:**  The whole purpose of this C++ code is to optimize JavaScript execution within V8. Each `Builtin::k...` case directly corresponds to a JavaScript feature. To illustrate the connection, I need to show how these built-in functions are used in JavaScript and how the compiler might optimize them.

6. **Formulate the summary:** Based on the above, I can formulate the following summary:
    * The code is part of the V8 JavaScript engine's compiler.
    * It's responsible for optimizing calls to built-in JavaScript functions.
    * It identifies the specific built-in being called.
    * It dispatches to a specialized "reduce" function to perform optimizations.
    * These optimizations likely involve replacing the built-in call with a more efficient sequence of lower-level operations.

7. **Provide JavaScript examples:** For each category of built-ins, I should provide simple JavaScript code snippets demonstrating their usage. This makes the connection between the C++ code and JavaScript concrete. I should choose common and illustrative examples.

8. **Address the "part 4 of 6" instruction:** This tells me that this specific file likely handles a subset of all possible JavaScript call reductions. The other parts would handle different aspects or categories of calls. I should include this information in the summary.
这个C++源代码文件（`v8/src/compiler/js-call-reducer.cc`）是V8 JavaScript引擎编译器的一部分，专门负责对JavaScript函数调用（`JSCall`）进行**简化和优化**，也被称为“归约”（reduction）。

**功能归纳：**

该文件的主要功能是识别特定的JavaScript内置函数调用模式，并将其转换为更低级、更高效的操作。它通过检查被调用函数的 `Builtin` ID 来判断是否是需要特殊处理的内置函数。

对于每个特定的内置函数，例如 `Array`, `Boolean`, `Object`, `Math`, `String` 等的构造函数和原型方法，以及 `Reflect` 对象的方法，该文件都定义了相应的 `Reduce...` 函数（例如 `ReduceArrayConstructor`, `ReduceStringPrototypeIndexOfIncludes`）。这些 `Reduce...` 函数包含了针对该特定内置函数的优化逻辑。

**与JavaScript功能的关联和JavaScript示例：**

该文件直接对应于JavaScript语言中提供的各种内置对象和函数。其优化的目标是提高这些内置函数在V8引擎中的执行效率。

以下是一些JavaScript示例，展示了该文件中处理的内置函数，并解释了可能的优化方向：

**1. 构造函数优化：**

* **JavaScript:**
  ```javascript
  const arr = new Array(10); // 调用 Array 构造函数
  const obj = new Object();   // 调用 Object 构造函数
  const bool = new Boolean(true); // 调用 Boolean 构造函数
  ```
* **优化方向:**  `ReduceArrayConstructor`, `ReduceObjectConstructor`, `ReduceBooleanConstructor` 等函数可能会将这些构造函数调用转换为直接创建对象和分配内存的操作，避免不必要的函数调用开销。例如，对于 `new Array(10)`, 如果已知数组长度，可以预先分配内存。

**2. `Function.prototype` 方法优化：**

* **JavaScript:**
  ```javascript
  function foo(a, b) { return a + b; }
  foo.call(null, 1, 2);       // 调用 Function.prototype.call
  foo.apply(null, [1, 2]);    // 调用 Function.prototype.apply
  const boundFoo = foo.bind(null, 1); // 调用 Function.prototype.bind
  ```
* **优化方向:** `ReduceFunctionPrototypeCall`, `ReduceFunctionPrototypeApply`, `ReduceFunctionPrototypeBind` 等函数会分析这些调用，例如，`bind` 可以直接创建一个绑定函数，而 `call` 和 `apply` 在某些情况下可以内联调用目标函数。

**3. `Object` 对象方法优化：**

* **JavaScript:**
  ```javascript
  const proto = { x: 1 };
  const obj = Object.create(proto); // 调用 Object.create
  Object.getPrototypeOf(obj);      // 调用 Object.getPrototypeOf
  Object.is(1, 1);                // 调用 Object.is
  obj.hasOwnProperty('x');         // 调用 Object.prototype.hasOwnProperty
  proto.isPrototypeOf(obj);        // 调用 Object.prototype.isPrototypeOf
  ```
* **优化方向:** `ReduceObjectCreate`, `ReduceObjectGetPrototypeOf`, `ReduceObjectIs`, `ReduceObjectPrototypeHasOwnProperty`, `ReduceObjectPrototypeIsPrototypeOf` 等函数会针对这些方法进行优化，例如 `Object.create` 可以直接创建指定原型的对象，避免查找原型链。

**4. `Reflect` API 优化：**

* **JavaScript:**
  ```javascript
  function sum(a, b) { return a + b; }
  Reflect.apply(sum, null, [1, 2]);    // 调用 Reflect.apply
  Reflect.construct(Date, []);       // 调用 Reflect.construct
  Reflect.get({ x: 1 }, 'x');        // 调用 Reflect.get
  Reflect.getPrototypeOf({});        // 调用 Reflect.getPrototypeOf
  Reflect.has({ x: 1 }, 'x');        // 调用 Reflect.has
  ```
* **优化方向:** `ReduceReflectApply`, `ReduceReflectConstruct`, `ReduceReflectGet`, `ReduceReflectGetPrototypeOf`, `ReduceReflectHas` 等函数会尝试优化这些反射操作，例如 `Reflect.get` 在已知对象结构的情况下可以直接访问属性。

**5. `Array` 原型方法优化：**

* **JavaScript:**
  ```javascript
  const arr = [1, 2, 3];
  arr.forEach(item => console.log(item)); // 调用 Array.prototype.forEach
  arr.map(item => item * 2);              // 调用 Array.prototype.map
  arr.filter(item => item > 1);             // 调用 Array.prototype.filter
  arr.reduce((acc, curr) => acc + curr, 0); // 调用 Array.prototype.reduce
  arr.indexOf(2);                         // 调用 Array.prototype.indexOf
  arr.push(4);                           // 调用 Array.prototype.push
  ```
* **优化方向:** `ReduceArrayForEach`, `ReduceArrayMap`, `ReduceArrayFilter`, `ReduceArrayReduce`, `ReduceArrayIndexOf`, `ReduceArrayPrototypePush` 等函数会针对这些常用的数组方法进行优化，例如，对于简单的 `map` 操作，可以生成优化的循环代码。

**6. `String` 原型方法优化：**

* **JavaScript:**
  ```javascript
  const str = "hello";
  str.indexOf("l");       // 调用 String.prototype.indexOf
  str.substring(1, 4);   // 调用 String.prototype.substring
  str.startsWith("he");  // 调用 String.prototype.startsWith
  ```
* **优化方向:** `ReduceStringPrototypeIndexOfIncludes`, `ReduceStringPrototypeSubstring`, `ReduceStringPrototypeStartsWith` 等函数会优化字符串操作，例如 `indexOf` 可以使用高效的字符串搜索算法。

**总结:**

这个代码片段是V8引擎在编译JavaScript代码时进行**关键性性能优化**的一部分。它针对JavaScript中常用的内置函数调用进行模式匹配和转换，将其替换为更高效的底层操作，从而显著提升JavaScript代码的执行速度。  作为第4部分，可以推测前面的部分可能处理了更通用的函数调用归约，而后续的部分可能涉及更特殊的优化或与代码生成相关的操作。

Prompt: 
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
  // Check for known builtin functions.

  Builtin builtin =
      shared.HasBuiltinId() ? shared.builtin_id() : Builtin::kNoBuiltinId;
  switch (builtin) {
    case Builtin::kArrayConstructor:
      return ReduceArrayConstructor(node);
    case Builtin::kBooleanConstructor:
      return ReduceBooleanConstructor(node);
    case Builtin::kFunctionPrototypeApply:
      return ReduceFunctionPrototypeApply(node);
    case Builtin::kFastFunctionPrototypeBind:
      return ReduceFunctionPrototypeBind(node);
    case Builtin::kFunctionPrototypeCall:
      return ReduceFunctionPrototypeCall(node);
    case Builtin::kFunctionPrototypeHasInstance:
      return ReduceFunctionPrototypeHasInstance(node);
    case Builtin::kObjectConstructor:
      return ReduceObjectConstructor(node);
    case Builtin::kObjectCreate:
      return ReduceObjectCreate(node);
    case Builtin::kObjectGetPrototypeOf:
      return ReduceObjectGetPrototypeOf(node);
    case Builtin::kObjectIs:
      return ReduceObjectIs(node);
    case Builtin::kObjectPrototypeGetProto:
      return ReduceObjectPrototypeGetProto(node);
    case Builtin::kObjectPrototypeHasOwnProperty:
      return ReduceObjectPrototypeHasOwnProperty(node);
    case Builtin::kObjectPrototypeIsPrototypeOf:
      return ReduceObjectPrototypeIsPrototypeOf(node);
    case Builtin::kReflectApply:
      return ReduceReflectApply(node);
    case Builtin::kReflectConstruct:
      return ReduceReflectConstruct(node);
    case Builtin::kReflectGet:
      return ReduceReflectGet(node);
    case Builtin::kReflectGetPrototypeOf:
      return ReduceReflectGetPrototypeOf(node);
    case Builtin::kReflectHas:
      return ReduceReflectHas(node);
    case Builtin::kArrayForEach:
      return ReduceArrayForEach(node, shared);
    case Builtin::kArrayMap:
      return ReduceArrayMap(node, shared);
    case Builtin::kArrayFilter:
      return ReduceArrayFilter(node, shared);
    case Builtin::kArrayReduce:
      return ReduceArrayReduce(node, shared);
    case Builtin::kArrayReduceRight:
      return ReduceArrayReduceRight(node, shared);
    case Builtin::kArrayPrototypeFind:
      return ReduceArrayFind(node, shared);
    case Builtin::kArrayPrototypeFindIndex:
      return ReduceArrayFindIndex(node, shared);
    case Builtin::kArrayEvery:
      return ReduceArrayEvery(node, shared);
    case Builtin::kArrayIndexOf:
      return ReduceArrayIndexOf(node);
    case Builtin::kArrayIncludes:
      return ReduceArrayIncludes(node);
    case Builtin::kArraySome:
      return ReduceArraySome(node, shared);
    case Builtin::kArrayPrototypeAt:
      return ReduceArrayPrototypeAt(node);
    case Builtin::kArrayPrototypePush:
      return ReduceArrayPrototypePush(node);
    case Builtin::kArrayPrototypePop:
      return ReduceArrayPrototypePop(node);
    // TODO(v8:14409): The current implementation of the inlined
    // ArrayPrototypeShift version doesn't seem to be beneficial and even
    // counter-productive at least for Object ElementsKinds. Disable it until
    // improvements/better heuristics have been implemented.
    // case Builtin::kArrayPrototypeShift:
    //   return ReduceArrayPrototypeShift(node);
    case Builtin::kArrayPrototypeSlice:
      return ReduceArrayPrototypeSlice(node);
    case Builtin::kArrayPrototypeEntries:
      return ReduceArrayIterator(node, ArrayIteratorKind::kArrayLike,
                                 IterationKind::kEntries);
    case Builtin::kArrayPrototypeKeys:
      return ReduceArrayIterator(node, ArrayIteratorKind::kArrayLike,
                                 IterationKind::kKeys);
    case Builtin::kArrayPrototypeValues:
      return ReduceArrayIterator(node, ArrayIteratorKind::kArrayLike,
                                 IterationKind::kValues);
    case Builtin::kArrayIteratorPrototypeNext:
      return ReduceArrayIteratorPrototypeNext(node);
    case Builtin::kArrayIsArray:
      return ReduceArrayIsArray(node);
    case Builtin::kArrayBufferIsView:
      return ReduceArrayBufferIsView(node);
    case Builtin::kDataViewPrototypeGetByteLength:
      // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
      return ReduceArrayBufferViewByteLengthAccessor(node, JS_DATA_VIEW_TYPE,
                                                     builtin);
    case Builtin::kDataViewPrototypeGetByteOffset:
      // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
      return ReduceArrayBufferViewByteOffsetAccessor(node, JS_DATA_VIEW_TYPE,
                                                     builtin);
    case Builtin::kDataViewPrototypeGetUint8:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalUint8Array);
    case Builtin::kDataViewPrototypeGetInt8:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalInt8Array);
    case Builtin::kDataViewPrototypeGetUint16:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalUint16Array);
    case Builtin::kDataViewPrototypeGetInt16:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalInt16Array);
    case Builtin::kDataViewPrototypeGetUint32:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalUint32Array);
    case Builtin::kDataViewPrototypeGetInt32:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalInt32Array);
    case Builtin::kDataViewPrototypeGetFloat32:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalFloat32Array);
    case Builtin::kDataViewPrototypeGetFloat64:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalFloat64Array);
    case Builtin::kDataViewPrototypeGetBigInt64:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalBigInt64Array);
    case Builtin::kDataViewPrototypeGetBigUint64:
      return ReduceDataViewAccess(node, DataViewAccess::kGet,
                                  ExternalArrayType::kExternalBigUint64Array);
    case Builtin::kDataViewPrototypeSetUint8:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalUint8Array);
    case Builtin::kDataViewPrototypeSetInt8:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalInt8Array);
    case Builtin::kDataViewPrototypeSetUint16:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalUint16Array);
    case Builtin::kDataViewPrototypeSetInt16:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalInt16Array);
    case Builtin::kDataViewPrototypeSetUint32:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalUint32Array);
    case Builtin::kDataViewPrototypeSetInt32:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalInt32Array);
    case Builtin::kDataViewPrototypeSetFloat32:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalFloat32Array);
    case Builtin::kDataViewPrototypeSetFloat64:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalFloat64Array);
    case Builtin::kDataViewPrototypeSetBigInt64:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalBigInt64Array);
    case Builtin::kDataViewPrototypeSetBigUint64:
      return ReduceDataViewAccess(node, DataViewAccess::kSet,
                                  ExternalArrayType::kExternalBigUint64Array);
    case Builtin::kTypedArrayPrototypeByteLength:
      return ReduceArrayBufferViewByteLengthAccessor(node, JS_TYPED_ARRAY_TYPE,
                                                     builtin);
    case Builtin::kTypedArrayPrototypeByteOffset:
      return ReduceArrayBufferViewByteOffsetAccessor(node, JS_TYPED_ARRAY_TYPE,
                                                     builtin);
    case Builtin::kTypedArrayPrototypeLength:
      return ReduceTypedArrayPrototypeLength(node);
    case Builtin::kTypedArrayPrototypeToStringTag:
      return ReduceTypedArrayPrototypeToStringTag(node);
    case Builtin::kMathAbs:
      return ReduceMathUnary(node, simplified()->NumberAbs());
    case Builtin::kMathAcos:
      return ReduceMathUnary(node, simplified()->NumberAcos());
    case Builtin::kMathAcosh:
      return ReduceMathUnary(node, simplified()->NumberAcosh());
    case Builtin::kMathAsin:
      return ReduceMathUnary(node, simplified()->NumberAsin());
    case Builtin::kMathAsinh:
      return ReduceMathUnary(node, simplified()->NumberAsinh());
    case Builtin::kMathAtan:
      return ReduceMathUnary(node, simplified()->NumberAtan());
    case Builtin::kMathAtanh:
      return ReduceMathUnary(node, simplified()->NumberAtanh());
    case Builtin::kMathCbrt:
      return ReduceMathUnary(node, simplified()->NumberCbrt());
    case Builtin::kMathCeil:
      return ReduceMathUnary(node, simplified()->NumberCeil());
    case Builtin::kMathCos:
      return ReduceMathUnary(node, simplified()->NumberCos());
    case Builtin::kMathCosh:
      return ReduceMathUnary(node, simplified()->NumberCosh());
    case Builtin::kMathExp:
      return ReduceMathUnary(node, simplified()->NumberExp());
    case Builtin::kMathExpm1:
      return ReduceMathUnary(node, simplified()->NumberExpm1());
    case Builtin::kMathFloor:
      return ReduceMathUnary(node, simplified()->NumberFloor());
    case Builtin::kMathFround:
      return ReduceMathUnary(node, simplified()->NumberFround());
    case Builtin::kMathLog:
      return ReduceMathUnary(node, simplified()->NumberLog());
    case Builtin::kMathLog1p:
      return ReduceMathUnary(node, simplified()->NumberLog1p());
    case Builtin::kMathLog10:
      return ReduceMathUnary(node, simplified()->NumberLog10());
    case Builtin::kMathLog2:
      return ReduceMathUnary(node, simplified()->NumberLog2());
    case Builtin::kMathRound:
      return ReduceMathUnary(node, simplified()->NumberRound());
    case Builtin::kMathSign:
      return ReduceMathUnary(node, simplified()->NumberSign());
    case Builtin::kMathSin:
      return ReduceMathUnary(node, simplified()->NumberSin());
    case Builtin::kMathSinh:
      return ReduceMathUnary(node, simplified()->NumberSinh());
    case Builtin::kMathSqrt:
      return ReduceMathUnary(node, simplified()->NumberSqrt());
    case Builtin::kMathTan:
      return ReduceMathUnary(node, simplified()->NumberTan());
    case Builtin::kMathTanh:
      return ReduceMathUnary(node, simplified()->NumberTanh());
    case Builtin::kMathTrunc:
      return ReduceMathUnary(node, simplified()->NumberTrunc());
    case Builtin::kMathAtan2:
      return ReduceMathBinary(node, simplified()->NumberAtan2());
    case Builtin::kMathPow:
      return ReduceMathBinary(node, simplified()->NumberPow());
    case Builtin::kMathClz32:
      return ReduceMathClz32(node);
    case Builtin::kMathImul:
      return ReduceMathImul(node);
    case Builtin::kMathMax:
      return ReduceMathMinMax(node, simplified()->NumberMax(),
                              jsgraph()->ConstantNoHole(-V8_INFINITY));
    case Builtin::kMathMin:
      return ReduceMathMinMax(node, simplified()->NumberMin(),
                              jsgraph()->ConstantNoHole(V8_INFINITY));
    case Builtin::kNumberIsFinite:
      return ReduceNumberIsFinite(node);
    case Builtin::kNumberIsInteger:
      return ReduceNumberIsInteger(node);
    case Builtin::kNumberIsSafeInteger:
      return ReduceNumberIsSafeInteger(node);
    case Builtin::kNumberIsNaN:
      return ReduceNumberIsNaN(node);
    case Builtin::kNumberParseInt:
      return ReduceNumberParseInt(node);
    case Builtin::kGlobalIsFinite:
      return ReduceGlobalIsFinite(node);
    case Builtin::kGlobalIsNaN:
      return ReduceGlobalIsNaN(node);
    case Builtin::kMapPrototypeGet:
      return ReduceMapPrototypeGet(node);
    case Builtin::kMapPrototypeHas:
      return ReduceMapPrototypeHas(node);
    case Builtin::kSetPrototypeHas:
      return ReduceSetPrototypeHas(node);
    case Builtin::kRegExpPrototypeTest:
      return ReduceRegExpPrototypeTest(node);
    case Builtin::kReturnReceiver:
      return ReduceReturnReceiver(node);
    case Builtin::kStringPrototypeIndexOf:
      return ReduceStringPrototypeIndexOfIncludes(
          node, StringIndexOfIncludesVariant::kIndexOf);
    case Builtin::kStringPrototypeIncludes:
      return ReduceStringPrototypeIndexOfIncludes(
          node, StringIndexOfIncludesVariant::kIncludes);
    case Builtin::kStringPrototypeCharAt:
      return ReduceStringPrototypeCharAt(node);
    case Builtin::kStringPrototypeCharCodeAt:
      return ReduceStringPrototypeStringAt(simplified()->StringCharCodeAt(),
                                           node);
    case Builtin::kStringPrototypeCodePointAt:
      return ReduceStringPrototypeStringAt(simplified()->StringCodePointAt(),
                                           node);
    case Builtin::kStringPrototypeSubstring:
      return ReduceStringPrototypeSubstring(node);
    case Builtin::kStringPrototypeSlice:
      return ReduceStringPrototypeSlice(node);
    case Builtin::kStringPrototypeSubstr:
      return ReduceStringPrototypeSubstr(node);
    case Builtin::kStringPrototypeStartsWith:
      return ReduceStringPrototypeStartsWith(node);
    case Builtin::kStringPrototypeEndsWith:
      return ReduceStringPrototypeEndsWith(node);
#ifdef V8_INTL_SUPPORT
    case Builtin::kStringPrototypeLocaleCompareIntl:
      return ReduceStringPrototypeLocaleCompareIntl(node);
    case Builtin::kStringPrototypeToLowerCaseIntl:
      return ReduceStringPrototypeToLowerCaseIntl(node);
    case Builtin::kStringPrototypeToUpperCaseIntl:
      return ReduceStringPrototypeToUpperCaseIntl(node);
#endif  // V8_INTL_SUPPORT
    case Builtin::kStringFromCharCode:
      return ReduceStringFromCharCode(node);
    case Builtin::kStringFromCodePoint:
      return ReduceStringFromCodePoint(node);
    case Builtin::kStringPrototypeIterator:
      return ReduceStringPrototypeIterator(node);
    case Builtin::kStringIteratorPrototypeNext:
      return ReduceStringIteratorPrototypeNext(node);
    case Builtin::kStringPrototypeConcat:
      return ReduceStringPrototypeConcat(node);
    case Builtin::kTypedArrayPrototypeEntries:
      return ReduceArrayIterator(node, ArrayIteratorKind::kTypedArray,
                                 IterationKind::kEntries);
    case Builtin::kTypedArrayPrototypeKeys:
      return ReduceArrayIterator(node, ArrayIteratorKind::kTypedArray,
                                 IterationKind::kKeys);
    case Builtin::kTypedArrayPrototypeValues:
      return ReduceArrayIterator(node, ArrayIteratorKind::kTypedArray,
                                 IterationKind::kValues);
    case Builtin::kPromisePrototypeCatch:
      return ReducePromisePrototypeCatch(node);
    case Builtin::kPromisePrototypeFinally:
      return ReducePromisePrototypeFinally(node);
    case Builtin::kPromisePrototypeThen:
      return ReducePromisePrototypeThen(node);
    case Builtin::kPromiseResolveTrampoline:
      return ReducePromiseResolveTrampoline(node);
    case Builtin::kMapPrototypeEntries:
      return ReduceCollectionIteration(node, CollectionKind::kMap,
                                       IterationKind::kEntries);
    case Builtin::kMapPrototypeKeys:
      return ReduceCollectionIteration(node, CollectionKind::kMap,
                                       IterationKind::kKeys);
    case Builtin::kMapPrototypeGetSize:
      return ReduceCollectionPrototypeSize(node, CollectionKind::kMap);
    case Builtin::kMapPrototypeValues:
      return ReduceCollectionIteration(node, CollectionKind::kMap,
                                       IterationKind::kValues);
    case Builtin::kMapIteratorPrototypeNext:
      return ReduceCollectionIteratorPrototypeNext(
          node, OrderedHashMap::kEntrySize, factory()->empty_ordered_hash_map(),
          FIRST_JS_MAP_ITERATOR_TYPE, LAST_JS_MAP_ITERATOR_TYPE);
    case Builtin::kSetPrototypeEntries:
      return ReduceCollectionIteration(node, CollectionKind::kSet,
                                       IterationKind::kEntries);
    case Builtin::kSetPrototypeGetSize:
      return ReduceCollectionPrototypeSize(node, CollectionKind::kSet);
    case Builtin::kSetPrototypeValues:
      return ReduceCollectionIteration(node, CollectionKind::kSet,
                                       IterationKind::kValues);
    case Builtin::kSetIteratorPrototypeNext:
      return ReduceCollectionIteratorPrototypeNext(
          node, OrderedHashSet::kEntrySize, factory()->empty_ordered_hash_set(),
          FIRST_JS_SET_ITERATOR_TYPE, LAST_JS_SET_ITERATOR_TYPE);
    case Builtin::kDatePrototypeGetTime:
      return ReduceDatePrototypeGetTime(node);
    case Builtin::kDateNow:
      return ReduceDateNow(node);
    case Builtin::kNumberConstructor:
      return ReduceNumberConstructor(node);
    case Builtin::kBigIntConstructor:
      return ReduceBigIntConstructor(node);
    case Builtin::kBigIntAsIntN:
    case Builtin::kBigIntAsUintN:
      return ReduceBigIntAsN(node, builtin);
#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    case Builtin::kGetContinuationPreservedEmbedderData:
      return ReduceGetContinuationPreservedEmbedderData(node);
    case Builtin::kSetContinuationPreservedEmbedderData:
      return ReduceSetContinuationPreservedEmbedderData(node);
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
    default:
      break;
  }

  if (shared.function_template_info(broker()).has_value()) {
    return ReduceCallApiFunction(node, shared);
  }

#if V8_ENABLE_WEBASSEMBLY
  if ((flags() & kInlineJSToWasmCalls) &&
      // Peek at the trusted object; ReduceCallWasmFunction will do that again
      // and crash if this is not a WasmExportedFunctionData any more then.
      IsWasmExportedFunctionData(shared.object()->GetTrustedData())) {
    return ReduceCallWasmFunction(node, shared);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  return NoChange();
}

TNode<Object> JSCallReducerAssembler::ReduceJSCallWithArrayLikeOrSpreadOfEmpty(
    std::unordered_set<Node*>* generated_calls_with_array_like_or_spread) {
  DCHECK_EQ(generated_calls_with_array_like_or_spread->count(node_ptr()), 0);
  JSCallWithArrayLikeOrSpreadNode n(node_ptr());
  CallParameters const& p = n.Parameters();
  TNode<Object> arguments_list = n.LastArgument();
  DCHECK_EQ(static_cast<Node*>(arguments_list)->opcode(),
            IrOpcode::kJSCreateEmptyLiteralArray);

  // Turn the JSCallWithArrayLike or JSCallWithSpread roughly into:
  //
  //      "arguments_list array is still empty?"
  //               |
  //               |
  //            Branch
  //           /      \
  //          /        \
  //      IfTrue      IfFalse
  //         |          |
  //         |          |
  //      JSCall    JSCallWithArrayLike/JSCallWithSpread
  //          \        /
  //           \      /
  //            Merge

  TNode<Number> length = TNode<Number>::UncheckedCast(
      LoadField(AccessBuilder::ForJSArrayLength(NO_ELEMENTS), arguments_list));
  return SelectIf<Object>(NumberEqual(length, ZeroConstant()))
      .Then([&]() {
        TNode<Object> call = CopyNode();
        static_cast<Node*>(call)->RemoveInput(n.LastArgumentIndex());
        NodeProperties::ChangeOp(
            call, javascript()->Call(p.arity() - 1, p.frequency(), p.feedback(),
                                     p.convert_mode(), p.speculation_mode(),
                                     p.feedback_relation()));
        return call;
      })
      .Else([&]() {
        TNode<Object> call = CopyNode();
        generated_calls_with_array_like_or_spread->insert(call);
        return call;
      })
      .ExpectFalse()
      .Value();
}

namespace {

// Check if the target is a class constructor.
// We need to check all cases where the target will be typed as Function
// to prevent later optimizations from using the CallFunction trampoline,
// skipping the instance type check.
bool TargetIsClassConstructor(Node* node, JSHeapBroker* broker) {
  Node* target = NodeProperties::GetValueInput(node, 0);
  OptionalSharedFunctionInfoRef shared;
  HeapObjectMatcher m(target);
  if (m.HasResolvedValue()) {
    ObjectRef target_ref = m.Ref(broker);
    if (target_ref.IsJSFunction()) {
      JSFunctionRef function = target_ref.AsJSFunction();
      shared = function.shared(broker);
    }
  } else if (target->opcode() == IrOpcode::kJSCreateClosure) {
    CreateClosureParameters const& ccp =
        JSCreateClosureNode{target}.Parameters();
    shared = ccp.shared_info();
  } else if (target->opcode() == IrOpcode::kCheckClosure) {
    FeedbackCellRef cell = MakeRef(broker, FeedbackCellOf(target->op()));
    shared = cell.shared_function_info(broker);
  }

  if (shared.has_value() && IsClassConstructor(shared->kind())) return true;

  return false;
}

}  // namespace

Reduction JSCallReducer::ReduceJSCallWithArrayLike(Node* node) {
  JSCallWithArrayLikeNode n(node);
  CallParameters const& p = n.Parameters();
  DCHECK_EQ(p.arity_without_implicit_args(), 1);  // The arraylike object.
  // Class constructors are callable, but [[Call]] will raise an exception.
  // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
  if (TargetIsClassConstructor(node, broker())) {
    return NoChange();
  }

  std::optional<Reduction> maybe_result =
      TryReduceJSCallMathMinMaxWithArrayLike(node);
  if (maybe_result.has_value()) {
    return maybe_result.value();
  }

  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), n.LastArgumentIndex(), p.frequency(),
      p.feedback(), p.speculation_mode(), p.feedback_relation(), n.target(),
      n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSCallWithSpread(Node* node) {
  JSCallWithSpreadNode n(node);
  CallParameters const& p = n.Parameters();
  DCHECK_GE(p.arity_without_implicit_args(), 1);  // At least the spread.
  // Class constructors are callable, but [[Call]] will raise an exception.
  // See ES6 section 9.2.1 [[Call]] ( thisArgument, argumentsList ).
  if (TargetIsClassConstructor(node, broker())) {
    return NoChange();
  }
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), n.LastArgumentIndex(), p.frequency(),
      p.feedback(), p.speculation_mode(), p.feedback_relation(), n.target(),
      n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstruct(Node* node) {
  if (broker()->StackHasOverflowed()) return NoChange();

  JSConstructNode n(node);
  ConstructParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  Node* target = n.target();
  Node* new_target = n.new_target();
  Effect effect = n.effect();
  Control control = n.control();

  if (p.feedback().IsValid()) {
    ProcessedFeedback const& feedback =
        broker()->GetFeedbackForCall(p.feedback());
    if (feedback.IsInsufficient()) {
      return ReduceForInsufficientFeedback(
          node, DeoptimizeReason::kInsufficientTypeFeedbackForConstruct);
    }

    OptionalHeapObjectRef feedback_target = feedback.AsCall().target();
    if (feedback_target.has_value() && feedback_target->IsAllocationSite()) {
      // The feedback is an AllocationSite, which means we have called the
      // Array function and collected transition (and pretenuring) feedback
      // for the resulting arrays.  This has to be kept in sync with the
      // implementation in Ignition.

      Node* array_function = jsgraph()->ConstantNoHole(
          native_context().array_function(broker()), broker());

      // Check that the {target} is still the {array_function}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(), target,
                                     array_function);
      effect = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kWrongCallTarget), check,
          effect, control);

      // Turn the {node} into a {JSCreateArray} call.
      NodeProperties::ReplaceEffectInput(node, effect);
      static_assert(JSConstructNode::NewTargetIndex() == 1);
      node->ReplaceInput(n.NewTargetIndex(), array_function);
      node->RemoveInput(n.FeedbackVectorIndex());
      NodeProperties::ChangeOp(
          node, javascript()->CreateArray(arity,
                                          feedback_target->AsAllocationSite()));
      return Changed(node);
    } else if (feedback_target.has_value() &&
               !HeapObjectMatcher(new_target).HasResolvedValue() &&
               feedback_target->map(broker()).is_constructor()) {
      Node* new_target_feedback =
          jsgraph()->ConstantNoHole(*feedback_target, broker());

      // Check that the {new_target} is still the {new_target_feedback}.
      Node* check = graph()->NewNode(simplified()->ReferenceEqual(), new_target,
                                     new_target_feedback);
      effect = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kWrongCallTarget), check,
          effect, control);

      // Specialize the JSConstruct node to the {new_target_feedback}.
      node->ReplaceInput(n.NewTargetIndex(), new_target_feedback);
      NodeProperties::ReplaceEffectInput(node, effect);
      if (target == new_target) {
        node->ReplaceInput(n.TargetIndex(), new_target_feedback);
      }

      // Try to further reduce the JSConstruct {node}.
      return Changed(node).FollowedBy(ReduceJSConstruct(node));
    }
  }

  // Try to specialize JSConstruct {node}s with constant {target}s.
  HeapObjectMatcher m(target);
  if (m.HasResolvedValue()) {
    HeapObjectRef target_ref = m.Ref(broker());

    // Raise a TypeError if the {target} is not a constructor.
    if (!target_ref.map(broker()).is_constructor()) {
      NodeProperties::ReplaceValueInputs(node, target);
      NodeProperties::ChangeOp(node,
                               javascript()->CallRuntime(
                                   Runtime::kThrowConstructedNonConstructable));
      return Changed(node);
    }

    if (target_ref.IsJSFunction()) {
      JSFunctionRef function = target_ref.AsJSFunction();

      // Do not reduce constructors with break points.
      // If this state changes during background compilation, the compilation
      // job will be aborted from the main thread (see
      // Debug::PrepareFunctionForDebugExecution()).
      SharedFunctionInfoRef sfi = function.shared(broker());
      if (sfi.HasBreakInfo(broker())) return NoChange();

      // Don't inline cross native context.
      if (!function.native_context(broker()).equals(native_context())) {
        return NoChange();
      }

      // Check for known builtin functions.
      Builtin builtin =
          sfi.HasBuiltinId() ? sfi.builtin_id() : Builtin::kNoBuiltinId;
      switch (builtin) {
        case Builtin::kArrayConstructor: {
          // TODO(bmeurer): Deal with Array subclasses here.
          // Turn the {node} into a {JSCreateArray} call.
          static_assert(JSConstructNode::NewTargetIndex() == 1);
          node->ReplaceInput(n.NewTargetIndex(), new_target);
          node->RemoveInput(n.FeedbackVectorIndex());
          NodeProperties::ChangeOp(
              node, javascript()->CreateArray(arity, std::nullopt));
          return Changed(node);
        }
        case Builtin::kObjectConstructor: {
          // If no value is passed, we can immediately lower to a simple
          // JSCreate and don't need to do any massaging of the {node}.
          if (arity == 0) {
            node->RemoveInput(n.FeedbackVectorIndex());
            NodeProperties::ChangeOp(node, javascript()->Create());
            return Changed(node);
          }

          // If {target} is not the same as {new_target} (i.e. the Object
          // constructor), {value} will be ignored and therefore we can lower
          // to {JSCreate}. See https://tc39.es/ecma262/#sec-object-value.
          HeapObjectMatcher mnew_target(new_target);
          if (mnew_target.HasResolvedValue() &&
              !mnew_target.Ref(broker()).equals(function)) {
            // Drop the value inputs.
            node->RemoveInput(n.FeedbackVectorIndex());
            for (int i = n.ArgumentCount() - 1; i >= 0; i--) {
              node->RemoveInput(n.ArgumentIndex(i));
            }
            NodeProperties::ChangeOp(node, javascript()->Create());
            return Changed(node);
          }
          break;
        }
        case Builtin::kPromiseConstructor:
          return ReducePromiseConstructor(node);
        case Builtin::kStringConstructor:
          return ReduceStringConstructor(node, function);
        case Builtin::kTypedArrayConstructor:
          return ReduceTypedArrayConstructor(node, function.shared(broker()));
        default:
          break;
      }
    } else if (target_ref.IsJSBoundFunction()) {
      JSBoundFunctionRef function = target_ref.AsJSBoundFunction();
      JSReceiverRef bound_target_function =
          function.bound_target_function(broker());
      FixedArrayRef bound_arguments = function.bound_arguments(broker());
      const uint32_t bound_arguments_length = bound_arguments.length();

      // TODO(jgruber): Inline this block below once TryGet is guaranteed to
      // succeed.
      static constexpr int kInlineSize = 16;  // Arbitrary.
      base::SmallVector<Node*, kInlineSize> args;
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        OptionalObjectRef maybe_arg = bound_arguments.TryGet(broker(), i);
        if (!maybe_arg.has_value()) {
          TRACE_BROKER_MISSING(broker(), "bound argument");
          return NoChange();
        }
        args.emplace_back(
            jsgraph()->ConstantNoHole(maybe_arg.value(), broker()));
      }

      // Patch {node} to use [[BoundTargetFunction]].
      node->ReplaceInput(n.TargetIndex(), jsgraph()->ConstantNoHole(
                                              bound_target_function, broker()));

      // Patch {node} to use [[BoundTargetFunction]]
      // as new.target if {new_target} equals {target}.
      if (target == new_target) {
        node->ReplaceInput(
            n.NewTargetIndex(),
            jsgraph()->ConstantNoHole(bound_target_function, broker()));
      } else {
        node->ReplaceInput(
            n.NewTargetIndex(),
            graph()->NewNode(
                common()->Select(MachineRepresentation::kTagged),
                graph()->NewNode(simplified()->ReferenceEqual(), target,
                                 new_target),
                jsgraph()->ConstantNoHole(bound_target_function, broker()),
                new_target));
      }

      // Insert the [[BoundArguments]] for {node}.
      for (uint32_t i = 0; i < bound_arguments_length; ++i) {
        node->InsertInput(graph()->zone(), n.ArgumentIndex(i), args[i]);
        arity++;
      }

      // Update the JSConstruct operator on {node}.
      NodeProperties::ChangeOp(
          node, javascript()->Construct(JSConstructNode::ArityForArgc(arity),
                                        p.frequency(), FeedbackSource()));

      // Try to further reduce the JSConstruct {node}.
      return Changed(node).FollowedBy(ReduceJSConstruct(node));
    }

    // TODO(bmeurer): Also support optimizing proxies here.
  }

  // If {target} is the result of a JSCreateBoundFunction operation,
  // we can just fold the construction and construct the bound target
  // function directly instead.
  if (target->opcode() == IrOpcode::kJSCreateBoundFunction) {
    Node* bound_target_function = NodeProperties::GetValueInput(target, 0);
    uint32_t const bound_arguments_length =
        static_cast<int>(CreateBoundFunctionParametersOf(target->op()).arity());

    // Patch the {node} to use [[BoundTargetFunction]].
    node->ReplaceInput(n.TargetIndex(), bound_target_function);

    // Patch {node} to use [[BoundTargetFunction]]
    // as new.target if {new_target} equals {target}.
    if (target == new_target) {
      node->ReplaceInput(n.NewTargetIndex(), bound_target_function);
    } else {
      node->ReplaceInput(
          n.NewTargetIndex(),
          graph()->NewNode(common()->Select(MachineRepresentation::kTagged),
                           graph()->NewNode(simplified()->ReferenceEqual(),
                                            target, new_target),
                           bound_target_function, new_target));
    }

    // Insert the [[BoundArguments]] for {node}.
    for (uint32_t i = 0; i < bound_arguments_length; ++i) {
      Node* value = NodeProperties::GetValueInput(target, 2 + i);
      node->InsertInput(graph()->zone(), n.ArgumentIndex(i), value);
      arity++;
    }

    // Update the JSConstruct operator on {node}.
    NodeProperties::ChangeOp(
        node, javascript()->Construct(JSConstructNode::ArityForArgc(arity),
                                      p.frequency(), FeedbackSource()));

    // Try to further reduce the JSConstruct {node}.
    return Changed(node).FollowedBy(ReduceJSConstruct(node));
  }

  return NoChange();
}

// ES #sec-string.prototype.indexof
// ES #sec-string.prototype.includes
Reduction JSCallReducer::ReduceStringPrototypeIndexOfIncludes(
    Node* node, StringIndexOfIncludesVariant variant) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  if (n.ArgumentCount() > 0) {
    Node* receiver = n.receiver();
    Node* new_receiver = effect = graph()->NewNode(
        simplified()->CheckString(p.feedback()), receiver, effect, control);

    Node* search_string = n.Argument(0);
    Node* new_search_string = effect =
        graph()->NewNode(simplified()->CheckString(p.feedback()), search_string,
                         effect, control);

    Node* new_position = jsgraph()->ZeroConstant();
    if (n.ArgumentCount() > 1) {
      Node* position = n.Argument(1);
      new_position = effect = graph()->NewNode(
          simplified()->CheckSmi(p.feedback()), position, effect, control);

      Node* receiver_length =
          graph()->NewNode(simplified()->StringLength(), new_receiver);
      new_position = graph()->NewNode(
          simplified()->NumberMin(),
          graph()->NewNode(simplified()->NumberMax(), new_position,
                           jsgraph()->ZeroConstant()),
          receiver_length);
    }

    NodeProperties::ReplaceEffectInput(node, effect);
    RelaxEffectsAndControls(node);
    node->ReplaceInput(0, new_receiver);
    node->ReplaceInput(1, new_search_string);
    node->ReplaceInput(2, new_position);
    node->TrimInputCount(3);
    NodeProperties::ChangeOp(node, simplified()->StringIndexOf());

    if (variant == StringIndexOfIncludesVariant::kIndexOf) {
      return Changed(node);
    } else {
      DCHECK(variant == StringIndexOfIncludesVariant::kIncludes);
      Node* result =
          graph()->NewNode(simplified()->BooleanNot(),
                           graph()->NewNode(simplified()->NumberEqual(), node,
                                            jsgraph()->SmiConstant(-1)));
      return Replace(result);
    }
  }
  return NoChange();
}

// ES #sec-string.prototype.substring
Reduction JSCallReducer::ReduceStringPrototypeSubstring(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSubstring();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.slice
Reduction JSCallReducer::ReduceStringPrototypeSlice(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeSlice();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES #sec-string.prototype.substr
Reduction JSCallReducer::ReduceStringPrototypeSubstr(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (n.ArgumentCount() < 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();
  Node* start = n.Argument(0);
  Node* end = n.ArgumentOrUndefined(1, jsgraph());

  receiver = effect = graph()->NewNode(simplified()->CheckString(p.feedback()),
                                       receiver, effect, control);

  start = effect = graph()->NewNode(simplified()->CheckSmi(p.feedback()), start,
                                    effect, control);

  Node* length = graph()->NewNode(simplified()->StringLength(), receiver);

  // Replace {end} argument with {length} if it is undefined.
  {
    Node* check = graph()->NewNode(simplified()->ReferenceEqual(), end,
                                   jsgraph()->UndefinedConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = length;

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = efalse = graph()->NewNode(
        simplified()->CheckSmi(p.feedback()), end, efalse, if_false);

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    end = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           vtrue, vfalse, control);
  }

  Node* initStart = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kFalse),
      graph()->NewNode(simplified()->NumberLessThan(), start,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(
          simplified()->NumberMax(),
          graph()->NewNode(simplified()->NumberAdd(), length, start),
          jsgraph()->ZeroConstant()),
      start);
  // The select above guarantees that initStart is non-negative, but
  // our typer can't figure that out yet.
  initStart = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()), initStart, effect, control);

  Node* resultLength = graph()->NewNode(
      simplified()->NumberMin(),
      graph()->NewNode(simplified()->NumberMax(), end,
                       jsgraph()->ZeroConstant()),
      graph()->NewNode(simplified()->NumberSubtract(), length, initStart));

  // The the select below uses {resultLength} only if {resultLength > 0},
  // but our typer can't figure that out yet.
  Node* to = effect = graph()->NewNode(
      common()->TypeGuard(Type::UnsignedSmall()),
      graph()->NewNode(simplified()->NumberAdd(), initStart, resultLength),
      effect, control);

  Node* result_string = nullptr;
  // Return empty string if {from} is smaller than {to}.
  {
    Node* check = graph()->NewNode(simplified()->NumberLessThan(),
                                   jsgraph()->ZeroConstant(), resultLength);

    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = etrue =
        graph()->NewNode(simplified()->StringSubstring(), receiver, initStart,
                         to, etrue, if_true);

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse = jsgraph()->EmptyStringConstant();

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    result_string =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                         vtrue, vfalse, control);
  }

  ReplaceWithValue(node, result_string, effect, control);
  return Replace(result_string);
}

Reduction JSCallReducer::ReduceJSConstructWithArrayLike(Node* node) {
  JSConstructWithArrayLikeNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int arraylike_index = n.LastArgumentIndex();
  DCHECK_EQ(n.ArgumentCount(), 1);  // The arraylike object.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), arraylike_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructWithSpread(Node* node) {
  JSConstructWithSpreadNode n(node);
  ConstructParameters const& p = n.Parameters();
  const int spread_index = n.LastArgumentIndex();
  DCHECK_GE(n.ArgumentCount(), 1);  // At least the spread.
  return ReduceCallOrConstructWithArrayLikeOrSpread(
      node, n.ArgumentCount(), spread_index, p.frequency(), p.feedback(),
      SpeculationMode::kDisallowSpeculation, CallFeedbackRelation::kTarget,
      n.target(), n.effect(), n.control());
}

Reduction JSCallReducer::ReduceJSConstructForwardAllArgs(Node* node) {
  JSConstructForwardAllArgsNode n(node);
  DCHECK_EQ(n.ArgumentCount(), 0);

  // If this frame is not being inlined, JSConstructForwardAllArgs will be
  // lowered later in JSGenericLowering to a builtin call.
  FrameState frame_state = n.frame_state();
  if (frame_state.outer_frame_state()->opcode() != IrOpcode::kFrameState) {
    return NoChange();
  }

  // Hook up the arguments directly when forwarding arguments of inlined frames.
  FrameState outer_state{frame_state.outer_frame_state()};
  FrameStateInfo outer_info = outer_state.frame_state_info();
  if (outer_info.type() == FrameStateType::kInlinedExtraArguments) {
    frame_state = outer_state;
  }

  int argc = 0;
  StateValuesAccess parameters_access(frame_state.parameters());
  for (auto it = parameters_access.begin_without_receiver(); !it.done(); ++it) {
    DCHECK_NOT_NULL(it.node());
    node->InsertInput(graph()->zone(),
                      JSCallOrConstructNode::ArgumentIndex(argc++), it.node());
  }

  ConstructParameters const& p = n.Parameters();
  NodeProperties::ChangeOp(
      node, javascript()->Construct(JSConstructNode::ArityForArgc(argc),
                                    p.frequency(), p.feedback()));
  CheckIfConstructor(node);
  return Changed(node).FollowedBy(ReduceJSConstruct(node));
}

Reduction JSCallReducer::ReduceReturnReceiver(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  ReplaceWithValue(node, receiver);
  return Replace(receiver);
}

Reduction JSCallReducer::ReduceForInsufficientFeedback(
    Node* node, DeoptimizeReason reason) {
  DCHECK(node->opcode() == IrOpcode::kJSCall ||
         node->opcode() == IrOpcode::kJSConstruct);
  if (!(flags() & kBailoutOnUninitialized)) return NoChange();

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* frame_state =
      NodeProperties::FindFrameStateBefore(node, jsgraph()->Dead());
  Node* deoptimize =
      graph()->NewNode(common()->Deoptimize(reason, FeedbackSource()),
                       frame_state, effect, control);
  MergeControlToEnd(graph(), common(), deoptimize);
  node->TrimInputCount(0);
  NodeProperties::ChangeOp(node, common()->Dead());
  return Changed(node);
}

Node* JSCallReducer::LoadReceiverElementsKind(Node* receiver, Effect* effect,
                                              Control control) {
  Node* effect_node = *effect;
  Node* receiver_map = effect_node =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect_node, control);
  Node* receiver_bit_field2 = effect_node = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect_node, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));
  *effect = effect_node;
  return receiver_elements_kind;
}

void JSCallReducer::CheckIfElementsKind(Node* receiver_elements_kind,
                                        ElementsKind kind, Node* control,
                                        Node** if_true, Node** if_false) {
  Node* is_packed_kind =
      graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                       jsgraph()->ConstantNoHole(GetPackedElementsKind(kind)));
  Node* packed_branch =
      graph()->NewNode(common()->Branch(), is_packed_kind, control);
  Node* if_packed = graph()->NewNode(common()->IfTrue(), packed_branch);

  if (IsHoleyElementsKind(kind)) {
    Node* if_not_packed = graph()->NewNode(common()->IfFalse(), packed_branch);
    Node* is_holey_kind =
        graph()->NewNode(simplified()->NumberEqual(), receiver_elements_kind,
                         jsgraph()->ConstantNoHole(GetHoleyElementsKind(kind)));
    Node* holey_branch =
        graph()->NewNode(common()->Branch(), is_holey_kind, if_not_packed);
    Node* if_holey = graph()->NewNode(common()->IfTrue(), holey_branch);

    Node* if_not_packed_not_holey =
        graph()->NewNode(common()->IfFalse(), holey_branch);

    *if_true = graph()->NewNode(common()->Merge(2), if_packed, if_holey);
    *if_false = if_not_packed_not_holey;
  } else {
    *if_true = if_packed;
    *if_false = graph()->NewNode(common()->IfFalse(), packed_branch);
  }
}

// ES6 section 23.1.3.1 Array.prototype.at ( )
Reduction JSCallReducer::ReduceArrayPrototypeAt(Node* node) {
  if (!v8_flags.turbo_inline_array_builtins) return NoChange();

  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();

  // Collecting maps, and checking if a fallback builtin call will be required
  // (it is required if at least one map doesn't support fast array iteration).
  ZoneVector<MapRef> maps(broker()->zone());
  bool needs_fallback_builtin_call = false;
  for (MapRef map : inference.GetMaps()) {
    if (map.supports_fast_array_iteration(broker())) {
      maps.push_back(map);
    } else {
      needs_fallback_builtin_call = true;
    }
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  if (maps.empty()) {
    // No map in the feedback supports fast iteration. Keeping the builtin call.
    return NoChange();
  }

  if (!dependencies()->DependOnNoElementsProtector()) {
    return NoChange();
  }

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph =
      a.ReduceArrayPrototypeAt(maps, needs_fallback_builtin_call);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.18 Array.prototype.push ( )
Reduction JSCallReducer::ReduceArrayPrototypePush(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds, true)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  IteratingArrayBuiltinReducerAssembler a(this, node);
  a.InitializeEffectControl(effect, control);

  TNode<Object> subgraph = a.ReduceArrayPrototypePush(&inference);
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES6 section 22.1.3.17 Array.prototype.pop ( )
Reduction JSCallReducer::ReduceArrayPrototypePop(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = n.receiver();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load the "length" property of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Check if the {receiver} has any elements.
    Node* check = graph()->NewNode(simplified()->NumberEqual(), length,
                                   jsgraph()->ZeroConstant());
    Node* branch =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check, control);

    Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
    Node* etrue = effect;
    Node* vtrue = jsgraph()->UndefinedConstant();

    Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
    Node* efalse = effect;
    Node* vfalse;
    {
      // TODO(turbofan): We should trim the backing store if the capacity is too
      // big, as implemented in elements.cc:ElementsAccessorBase::SetLengthImpl.

      // Load the elements backing store from the {receiver}.
      Node* elements = efalse = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
          receiver, efalse, if_false);

      // Ensure that we aren't popping from a copy-on-write backing store.
      if (IsSmiOrObjectElementsKind(kind)) {
        elements = efalse =
            graph()->NewNode(simplified()->EnsureWritableFastElements(),
                             receiver, elements, efalse, if_false);
      }

      // Compute the new {length}.
      Node* new_length = graph()->NewNode(simplified()->NumberSubtract(),
                                          length, jsgraph()->OneConstant());

      if (v8_flags.turbo_typer_hardening) {
        new_length = efalse = graph()->NewNode(
            simplified()->CheckBounds(p.feedback(),
                                      CheckBoundsFlag::kAbortOnOutOfBounds),
            new_length, length, efalse, if_false);
      }

      // Store the new {length} to the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreField(AccessBuilder::ForJSArrayLength(kind)),
          receiver, new_length, efalse, if_false);

      // Load the last entry from the {elements}.
      vfalse = efalse = graph()->NewNode(
          simplified()->LoadElement(AccessBuilder::ForFixedArrayElement(kind)),
          elements, new_length, efalse, if_false);

      // Store a hole to the element we just removed from the {receiver}.
      efalse = graph()->NewNode(
          simplified()->StoreElement(
              AccessBuilder::ForFixedArrayElement(GetHoleyElementsKind(kind))),
          elements, new_length, jsgraph()->TheHoleConstant(), efalse, if_false);
    }

    control = graph()->NewNode(common()->Merge(2), if_true, if_false);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
    value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue, vfalse, control);

    // Convert the hole to undefined. Do this last, so that we can optimize
    // conversion operator via some smart strength reduction in many cases.
    if (IsHoleyElementsKind(kind)) {
      value =
          graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
    }

    controls_to_merge.push_back(control);
    effects_to_merge.push_back(effect);
    values_to_merge.push_back(value);
  }

  if (controls_to_merge.size() > 1) {
    int const count = static_cast<int>(controls_to_merge.size());

    control = graph()->NewNode(common()->Merge(count), count,
                               &controls_to_merge.front());
    effects_to_merge.push_back(control);
    effect = graph()->NewNode(common()->EffectPhi(count), count + 1,
                              &effects_to_merge.front());
    values_to_merge.push_back(control);
    value =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                         count + 1, &values_to_merge.front());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 22.1.3.22 Array.prototype.shift ( )
// Currently disabled. See https://crbug.com/v8/14409
Reduction JSCallReducer::ReduceArrayPrototypeShift(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* target = n.target();
  Node* receiver = n.receiver();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  std::vector<ElementsKind> kinds;
  if (!CanInlineArrayResizingBuiltin(broker(), receiver_maps, &kinds)) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  std::vector<Node*> controls_to_merge;
  std::vector<Node*> effects_to_merge;
  std::vector<Node*> values_to_merge;
  Node* value = jsgraph()->UndefinedConstant();

  Node* receiver_elements_kind =
      LoadReceiverElementsKind(receiver, &effect, control);
  Node* next_control = control;
  Node* next_effect = effect;
  for (size_t i = 0; i < kinds.size(); i++) {
    ElementsKind kind = kinds[i];
    control = next_control;
    effect = next_effect;
    // We do not need branch for the last elements kind.
    if (i != kinds.size() - 1) {
      Node* control_node = control;
      CheckIfElementsKind(receiver_elements_kind, kind, control_node,
                          &control_node, &next_control);
      control = control_node;
    }

    // Load length of the {receiver}.
    Node* length = effect = graph()->NewNode(
        simplified()->LoadField(AccessBuilder::ForJSArrayLength(kind)),
        receiver, effect, control);

    // Return undefined if {receiver} has no elements.
    Node* check0 = graph()->NewNode(simplified()->NumberEqual(), length,
                                    jsgraph()->ZeroConstant());
    Node* branch0 =
        graph()->NewNode(common()->Branch(BranchHint::kFalse), check0, control);

    Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
    Node* etrue0 = effect;
    Node* vtrue0 = jsgraph()->UndefinedConstant();

    Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
    Node* efalse0 = effect;
    Node* vfalse0;
    {
      // Check if we should take the fast-path.
      Node* check1 = graph()->NewNode(
          simplified()->NumberLessThanOrEqual(), length,
          jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements));
      Node* branch1 = graph()->NewNode(common()->Branch(BranchHint::kTrue),
                                       check1, if_false0);

      Node* if_true1 = graph()->NewNode(common()->IfTrue(), branch1);
      Node* etrue1 = efalse0;
      Node* vtrue1;
      {
        Node* elements = etrue1 = graph()->NewNode(
            simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
            receiver, etrue1, if_true1);

        // Load the first element here, which we return below.
        vtrue1 = etrue1 = graph()->NewNode(
            simplified()->LoadElement(
                AccessBuilder::ForFixedArrayElement(kind)),
            elements, jsgraph()->ZeroConstant(), etrue1, if_true1);

        // Ensure that we aren't shifting a copy-on-write backing store.
        if (IsSmiOrObjectElementsKind(kind)) {
          elements = etrue1 =
              graph()->NewNode(simplified()->EnsureWritableFastElements(),
                               receiver, elements, etrue1, if_true1);
        }

        // Shift the remaining {elements} by one towards the start.
        Node* loop = graph()->NewNode(common()->Loop(2), if_true1, if_true1);
        Node* eloop =
            graph()->NewNode(common()->EffectPhi(2), etrue1, etrue1, loop);
        Node* terminate = graph()->NewNode(common()->Terminate(), eloop, loop);
        MergeControlToEnd(graph(), common(), terminate);

        Node* index = graph()->NewNode(
            common()->Phi(MachineRepresentation::kTagged, 2),
            jsgraph()->OneConstant(),
            jsgraph()->ConstantNoHole(JSArray::kMaxCopyElements - 1), loop);

        {
          Node* check2 =
              graph()->NewNode(simplified()->NumberLessThan(), index, length);
          Node* branch2 = graph()->NewNode(common()->Branch(), check2, loop);

          if_true1 = graph()->NewNode(common()->IfFalse(), branch2);
          etrue1 = eloop;

          Node* control2 = graph()->NewNode(common()->IfTrue(), branch2);
          Node* effect2 = etrue1;

          ElementAccess const access =
              AccessBuilder::ForFixedArrayElement(kind);

          // When disable v8_flags.turbo_loop_variable, typer cannot infer index
          // is in [1, kMaxCopyElements-1], and will break in representing
          // kRepFloat64 (Range(1, inf)) to kRepWord64 when converting
          // input for kLoadElement. So we need to add type guard here.
          // And we need to use index when using NumberLessThan to check
          // terminate and updating index, otherwise which will break inducing
          // variables in LoopVariableOptimizer.
          static_assert(JSArray::kMaxCopyElements < kSmiMaxValue);
          Node* index_retyped = effect2 =
              graph()->NewNode(common()->TypeGuard(Type::UnsignedSmall()),
                               index, effect2, control2);

          Node* value2 = effect2 =
              graph()->NewNode(simplified()->LoadElement(access), elements,
                               index_retyped, effect2, control2);
          effect2 = graph()->NewNode(
              simplified()->StoreElement(access), elements,
              graph()->NewNode(simplified()->NumberSubtract(), index_retyped,
                               jsgraph()->OneConstant()),
              value2, effect2, control2);

          loop->ReplaceInput(1, control2);
          eloop->ReplaceInput(1, effect2);
          index->ReplaceInput(1,
                              graph()->NewNode(simplified()->NumberAdd(), index,
                                               jsgraph()->OneConstant()));
        }

        // Compute the new {length}.
        Node* new_length = graph()->NewNode(simplified()->NumberSubtract(),
                                            length, jsgraph()->OneConstant());

        if (v8_flags.turbo_typer_hardening) {
          new_length = etrue1 = graph()->NewNode(
              simplified()->CheckBounds(p.feedback(),
                                        CheckBoundsFlag::kAbortOnOutOfBounds),
              new_length, length, etrue1, if_true1);
        }

        // Store the new {length} to the {receiver}.
        etrue1 = graph()->NewNode(
            simplified()->StoreField(AccessBuilder::ForJSArrayLength(kind)),
            receiver, new_length, etrue1, if_true1);

        // Store a hole to the element we just removed from the {receiver}.
        etrue1 = graph()->NewNode(
            simplified()->StoreElement(AccessBuilder::ForFixedArrayElement(
                GetHoleyElementsKind(kind))),
            elements, new_length, jsgraph()->TheHoleConstant(), etrue1,
            if_true1);
      }

      Node* if_false1 = graph()->NewNode(common()->IfFalse(), branch1);
      Node* efalse1 = efalse0;
      Node* vfalse1;
      {
        // Call the generic C++ implementation.
        const Builtin builtin = Builtin::kArrayShift;
        auto call_descriptor = Linkage::GetCEntryStubCallDescriptor(
            graph()->zone(), 1, BuiltinArguments::kNumExtraArgsWithReceiver,
            Builtins::name(builtin), node->op()->properties(),
            CallDescriptor::kNeedsFrameState);
        const bool has_builtin_exit_frame = true;
        Node* stub_code = jsgraph()->CEntryStubConstant(1, ArgvMode::kStack,
                                                        has_builtin_exit_frame);
        Address builtin_entry = Builtins::CppEntryOf(builtin);
        Node* entry = jsgraph()->ExternalConstant(
            ExternalReference::Create(builtin_entry));
        Node* argc = jsgraph()->ConstantNoHole(
            BuiltinArguments::kNumExtraArgsWithReceiver);
        static_assert(BuiltinArguments::kNewTargetIndex == 0);
        static_assert(BuiltinArguments::kTargetIndex == 1);
        static_assert(BuiltinArguments::kArgcIndex == 2);
        static_assert(BuiltinArguments::kPaddingIndex == 3);
        if_false1 = efalse1 = vfalse1 =
            graph()->NewNode(common()->Call(call_descriptor), stub_code,
                             receiver, jsgraph()->PaddingConstant(), argc,
                             target, jsgraph()->UndefinedConstant(), entry,
                             argc, context, frame_state, efalse1, if_false1);
      }

      if_false0 = graph()->NewNode(common()->Merge(2), if_true1, if_false1);
      efalse0 =
          graph()->NewNode(common()->EffectPhi(2), etrue1, efalse1, if_false0);
      vfalse0 =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           vtrue1, vfalse1, if_false0);
    }

    control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
    effect = graph()->NewNode(common()->EffectPhi(2), etrue0, efalse0, control);
    value = graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                             vtrue0, vfalse0, control);

    // Convert the hole to undefined. Do this last, so that we can optimize
    // conversion operator via some smart strength reduction in many cases.
    if (IsHoleyElementsKind(kind)) {
      value =
          graph()->NewNode(simplified()->ConvertTaggedHoleToUndefined(), value);
    }

    controls_to_merge.push_back(control);
    effects_to_merge.push_back(effect);
    values_to_merge.push_back(value);
  }

  if (controls_to_merge.size() > 1) {
    int const count = static_cast<int>(controls_to_merge.size());

    control = graph()->NewNode(common()->Merge(count), count,
                               &controls_to_merge.front());
    effects_to_merge.push_back(control);
    effect = graph()->NewNode(common()->EffectPhi(count), count + 1,
                              &effects_to_merge.front());
    values_to_merge.push_back(control);
    value =
        graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 
"""


```
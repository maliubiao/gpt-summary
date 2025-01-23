Response:
My thinking process to arrive at the summary and explanations goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided C++ code snippet, focusing on its functionality within the V8 JavaScript engine. It also asks to relate this to JavaScript, give examples, and identify potential programming errors.

2. **Initial Analysis of the Code:** The code is a large `switch` statement. The `switch`'s value is `builtin`, which suggests it's handling calls to specific built-in JavaScript functions. Each `case` corresponds to a different built-in function (e.g., `Array`, `Boolean`, `Object`, `Math`, `String`, `Promise`). The actions within each `case` are calls to `Reduce...` functions (e.g., `ReduceArrayConstructor`, `ReduceBooleanConstructor`). This immediately tells me the code is involved in *optimizing calls to built-in functions*.

3. **Inferring "Reduction":** The term "Reduce" in the function names strongly suggests that this code is part of an optimization pass in the V8 compiler. It's trying to *simplify* or *transform* the way these built-in functions are called, potentially replacing them with more efficient internal operations.

4. **Categorizing the Built-ins:**  I start grouping the `case` statements by the JavaScript built-in they relate to. This helps in structuring the explanation:
    * **Constructors:** `Array`, `Boolean`, `Function`, `Object`, `Number`, `BigInt`
    * **Object methods:** `Object.create`, `Object.getPrototypeOf`, `Object.is`, `Object.prototype.*`
    * **Function methods:** `Function.prototype.apply`, `Function.prototype.bind`, `Function.prototype.call`, `Function.prototype.hasInstance`
    * **Reflect methods:** `Reflect.apply`, `Reflect.construct`, `Reflect.get`, etc.
    * **Array methods:** `Array.isArray`, `Array.prototype.*` (including iterators)
    * **Typed Array methods:**  Various prototype methods
    * **Math methods:** `Math.abs`, `Math.sin`, `Math.max`, etc.
    * **Number methods:** `Number.isFinite`, `Number.parseInt`, etc.
    * **Global functions:** `isFinite`, `isNaN`
    * **Map and Set methods:** `Map.prototype.*`, `Set.prototype.*` (including iterators and size)
    * **RegExp methods:** `RegExp.prototype.test`
    * **String methods:** `String.prototype.*`, `String.fromCharCode`, `String.fromCodePoint` (including iterators)
    * **Promise methods:** `Promise.prototype.catch`, `Promise.prototype.finally`, `Promise.prototype.then`, `Promise.resolve`
    * **Date methods:** `Date.prototype.getTime`, `Date.now`

5. **Connecting to JavaScript Functionality:** For each category, I think about *what the corresponding JavaScript built-in does*. This allows me to explain the optimization's purpose in a JavaScript context. For instance:
    * `ReduceArrayConstructor` is about optimizing the creation of arrays.
    * `ReduceMathAbs` is about optimizing the calculation of absolute values.
    * `ReduceStringPrototypeSlice` is about optimizing the extraction of substrings.

6. **Illustrative JavaScript Examples:**  To make the explanation concrete, I provide simple JavaScript code snippets that would trigger the optimizations handled by the `js-call-reducer.cc` code. This directly answers the request for JavaScript examples.

7. **Considering Code Logic and Potential Optimizations:**  The "Reduce..." functions likely perform various optimizations. While the provided snippet doesn't show the *implementation* of these reductions, I can infer the *types* of optimizations based on the built-in functions. For example:
    * **Inlining:**  For simple Math functions, the reduction might involve directly inserting the underlying machine code for the operation, avoiding the overhead of a function call.
    * **Specialized Array Creation:**  `ReduceArrayConstructor` might detect cases where the array size is known and allocate memory more efficiently.
    * **Method Simplification:**  For methods like `String.prototype.indexOf`, the reducer might be able to use optimized internal string searching algorithms.

8. **Hypothetical Inputs and Outputs (Code Logic Inference):** I create simple scenarios with input JavaScript code and describe the *intended outcome* of the reduction. This illustrates the "before" and "after" of the optimization process from a conceptual standpoint. I focus on the *effect* of the reduction rather than the low-level implementation details.

9. **Identifying Common Programming Errors:** I consider common mistakes developers make when using the built-in functions covered by the code. This demonstrates the importance of these optimizations in handling real-world JavaScript code, even when it contains errors or suboptimal usage. Examples include incorrect arguments to `parseInt`, misuse of `apply` or `call`, and misunderstandings about the behavior of array methods.

10. **Addressing Specific Instructions:**
    * **`.tq` Extension:** I explicitly check for this and state that the file is C++ and not Torque based on the `.cc` extension.
    * **Part 7 of 12:** I acknowledge this and reiterate that the file focuses on call optimization within the larger compilation pipeline.

11. **Structuring the Output:** I organize the information logically with clear headings and bullet points to enhance readability and address all aspects of the request. I start with a high-level summary and then delve into more specific details.

12. **Refinement and Clarity:** I review the generated explanation to ensure it's accurate, easy to understand, and avoids overly technical jargon where possible. I aim to provide a concise yet comprehensive overview of the `js-call-reducer.cc` file's role.

By following this structured approach, I can effectively analyze the provided code snippet and generate a detailed and informative response that addresses all the requirements of the prompt.
好的，让我们来分析一下 `v8/src/compiler/js-call-reducer.cc` 这个 V8 源代码文件的功能。

**功能归纳:**

`v8/src/compiler/js-call-reducer.cc` 的主要功能是 **在 V8 编译器的优化阶段，针对特定的 JavaScript 函数调用（尤其是内置函数的调用）进行模式匹配和简化（reduction）**。 它的目的是将高层次的 JavaScript 操作转换为更低层次、更高效的中间表示（如 TurboFan 图中的节点），以便后续的优化和代码生成能够更好地利用 CPU 指令和架构特性。

**详细功能分解:**

1. **识别内置函数调用:** 代码首先检查被调用的函数是否是 V8 预定义的内置函数。它通过 `shared.HasBuiltinId()` 和 `shared.builtin_id()` 来获取函数的内置 ID。

2. **针对不同内置函数进行特化处理:** `switch` 语句针对不同的 `builtin` 值，执行不同的 `Reduce...` 函数。每个 `Reduce...` 函数负责处理特定内置函数的调用模式。

3. **内置函数优化示例 (基于代码片段):**
   - **构造函数优化:**  例如 `ReduceArrayConstructor`、`ReduceBooleanConstructor` 等，它们可能将对这些构造函数的调用转换为更直接的内存分配和对象初始化操作。
   - **原型方法优化:**  例如 `ReduceArrayPrototypeSlice`、`ReduceStringPrototypeIndexOf` 等，它们尝试识别这些方法调用的特定模式，并将其替换为更高效的内部操作。例如，如果 `Array.prototype.slice` 的参数是常量，它可以直接计算出结果，而无需在运行时执行完整的切片操作。
   - **Math 对象方法优化:** 例如 `ReduceMathAbs`、`ReduceMathSin` 等，这些方法通常可以直接映射到 CPU 的数学运算指令，从而避免函数调用的开销。
   - **Object 对象方法优化:** 例如 `ReduceObjectCreate`、`ReduceObjectGetPrototypeOf` 等，它们可以简化对象属性访问和原型链操作。
   - **Reflect API 优化:** 例如 `ReduceReflectApply`、`ReduceReflectConstruct` 等，它们处理 `Reflect` API 的调用，并尝试将其转换为更底层的操作。
   - **类型化数组 (TypedArray) 和 DataView 优化:** 针对类型化数组和 DataView 的操作，如 `ReduceDataViewAccess`、`ReduceTypedArrayPrototypeLength` 等，可以进行更底层的内存访问优化。
   - **Promise 优化:**  例如 `ReducePromisePrototypeThen` 等，可以对 Promise 的链式调用进行优化。
   - **Map 和 Set 优化:** 例如 `ReduceMapPrototypeGet`、`ReduceSetPrototypeHas` 等，可以优化 Map 和 Set 数据结构的访问。
   - **字符串优化:** 例如 `ReduceStringPrototypeConcat`、`ReduceStringPrototypeStartsWith` 等，可以优化字符串操作。

4. **处理 `JSCallWithArrayLike` 和 `JSCallWithSpread`:** 这部分处理使用展开语法 (`...`) 或类数组对象作为参数的函数调用，并尝试对其进行优化。

5. **处理 `JSConstruct` (构造函数调用):** 这部分负责优化构造函数的调用，例如 `new Array(...)`。它会尝试识别可以内联或简化的构造函数调用模式。

6. **处理 API 函数调用和 WebAssembly 函数调用:** 代码还包含处理 JavaScript 调用 C++ API 函数 (`ReduceCallApiFunction`) 和 WebAssembly 函数 (`ReduceCallWasmFunction`) 的逻辑。

**关于文件扩展名和 Torque:**

你提供的信息中提到，如果文件以 `.tq` 结尾，那么它是一个 V8 Torque 源代码。但 `v8/src/compiler/js-call-reducer.cc` 以 `.cc` 结尾，**因此它是一个标准的 C++ 源代码文件**，而不是 Torque 文件。Torque 是一种用于在 V8 中定义内置函数的领域特定语言。

**与 JavaScript 功能的关系和示例:**

`js-call-reducer.cc` 中处理的每一个内置函数都直接对应着 JavaScript 中的功能。以下是一些 JavaScript 示例，展示了 `js-call-reducer.cc` 可能会优化的场景：

```javascript
// Array 构造函数
const arr1 = new Array(10); // ReduceArrayConstructor 可能会优化数组的分配

// Array 原型方法
const arr2 = [1, 2, 3];
const slicedArr = arr2.slice(1); // ReduceArrayPrototypeSlice 可能会优化切片操作

// Math 对象方法
const absValue = Math.abs(-5); // ReduceMathAbs 可能会直接生成绝对值计算指令

// String 原型方法
const str = "hello world";
const index = str.indexOf("world"); // ReduceStringPrototypeIndexOf 可能会优化字符串查找

// Object 对象方法
const obj = {};
const proto = Object.getPrototypeOf(obj); // ReduceObjectGetPrototypeOf 可能会简化原型链访问

// Function 原型方法
function greet(name) { console.log(`Hello, ${name}!`); }
greet.call(null, "Alice"); // ReduceFunctionPrototypeCall 可能会优化函数调用
```

**代码逻辑推理和假设输入输出:**

以 `ReduceMathAbs` 为例：

**假设输入（TurboFan 图中的节点）：**

- 一个代表 `Math.abs()` 调用的 `JSCall` 节点。
- 该 `JSCall` 节点的参数是另一个节点，表示要取绝对值的数值（例如，一个常量节点 `-5` 或一个变量节点）。

**输出（经过 reduction 后的节点）：**

- 一个表示绝对值运算的更底层的节点，例如 `NumberAbs` 节点。该节点直接对应着执行绝对值计算的操作。

**用户常见的编程错误:**

`js-call-reducer.cc` 的优化工作可以间接地帮助缓解一些用户常见的编程错误带来的性能问题，但它主要关注的是优化合法的 JavaScript 代码。不过，理解它的工作方式可以帮助开发者编写更高效的代码。

一些与这里涉及的内置函数相关的常见编程错误包括：

1. **错误地使用 `parseInt`:**  例如，`parseInt("010")` 在某些旧版本浏览器中可能被解析为 8（八进制），现在默认为 10 进制，但最好明确指定基数 `parseInt("010", 10)`。`ReduceNumberParseInt` 可能会处理不同基数的解析。
2. **过度使用 `Function.prototype.apply` 或 `call`:** 虽然 `apply` 和 `call` 很强大，但如果能直接调用函数，通常会更高效。`ReduceFunctionPrototypeApply` 和 `ReduceFunctionPrototypeCall` 尝试优化这些调用。
3. **在循环中重复执行昂贵的字符串操作:** 例如，在循环中使用 `+` 运算符拼接大量字符串，会导致性能下降。`ReduceStringPrototypeConcat` 可能会尝试优化字符串连接。
4. **不了解数组方法的性能特性:** 例如，在数组头部插入或删除元素（使用 `unshift` 或 `shift`）通常比在尾部操作效率低。理解 `ReduceArrayPrototypePush` 和 `ReduceArrayPrototypePop` 的优化方式可以帮助选择更合适的方法。

**第7部分，共12部分的功能归纳:**

作为编译流程的第 7 部分（共 12 部分），`js-call-reducer.cc` **处于相对靠前的优化阶段**。在这个阶段，编译器已经构建了程序的中间表示，但还没有进行非常底层的机器码生成。`js-call-reducer.cc` 的作用是 **针对高层次的 JavaScript 函数调用进行模式匹配和转换，将它们转换为更易于后续优化的形式**。 它的输出会成为后续优化阶段的输入，例如类型推断、内联等。

总而言之，`v8/src/compiler/js-call-reducer.cc` 是 V8 编译器中一个关键的优化组件，它通过识别和简化常见的 JavaScript 函数调用模式，为生成高效的机器码奠定了基础。

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/js-call-reducer.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```
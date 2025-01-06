Response: The user wants to understand the functionality of the provided C++ code snippet, which is the second part of a larger file. The goal is to summarize its purpose and illustrate any connection to JavaScript with examples.

**Plan:**

1. **Identify the core functionality:** Scan the code for patterns and common themes. The `TypeTyper::Visitor` class and its methods like `TypeBuiltin`, `TypeJSCall`, and `Type<Operation>` suggest type inference or type checking.
2. **Focus on `TypeBuiltin`:** This method seems central to defining the return types of built-in JavaScript functions. Analyze the cases within the `switch` statement.
3. **Connect to JavaScript:** For each built-in function case in `TypeBuiltin`, determine the corresponding JavaScript function and its return type.
4. **Provide JavaScript examples:** Illustrate the connection by showing how these built-in functions are used in JavaScript and what their return types are.
5. **Summarize other methods:** Briefly describe the purpose of other `TypeTyper::Visitor` methods, grouping them by functionality (e.g., handling JS calls, runtime functions, simplified operators, type checks, loads/stores).
这是 `v8/src/compiler/turbofan-typer.cc` 文件的第二部分，延续了第一部分的功能，**主要负责为 Turbofan 编译器中的各种节点（Nodes）推断和确定其类型（Type）**。

与第一部分一样，这部分代码也是 `Typer::Visitor` 类的成员函数，用于访问和处理抽象语法树（AST）或中间表示（IR）中的不同节点。它定义了各种 `Type...` 函数，这些函数根据节点的类型和操作来返回相应的 V8 类型系统中的类型。

**具体来说，这部分代码的功能包括：**

1. **处理更多的内置函数（Built-ins）：** `TypeBuiltin` 函数包含了更多 JavaScript 内置对象的原型方法和构造函数的类型推断逻辑。例如：
    * `Math` 对象的方法 (如 `cbrt`, `cos`, `sin`, `sqrt`, `max`, `min` 等)
    * `Date` 对象的方法 (如 `getDate`, `getDay`, `getFullYear`, `getTime` 等)
    * `Symbol` 对象的方法 (如 `constructor`, `toString`, `valueOf`)
    * `BigInt` 对象的方法 (如 `constructor`)
    * `Number` 对象的方法 (如 `isFinite`, `isInteger`, `isNaN`, `parseFloat`, `parseInt`, `toString`)
    * `String` 对象的方法 (如 `charCodeAt`, `charAt`, `codePointAt`, `concat`, `indexOf`, `slice`, `toLowerCase`, `toUpperCase`, `trim` 等)
    * `Array` 对象的方法 (如 `isArray`, `concat`, `every`, `fill`, `filter`, `indexOf`, `join`, `map`, `push`, `slice`, `some`, `splice` 等)
    * `ArrayBuffer` 对象的方法 (如 `isView`)
    * `Object` 对象的方法 (如 `assign`, `create`, `is`, `hasOwnProperty`, `isPrototypeOf`, `toString`)
    * `Promise` 对象的方法 (如 `all`, `then`, `race`, `reject`, `resolve`)
    * `RegExp` 对象的方法 (如 `compile`, `exec`, `test`, `toString`)
    * `Function` 对象的方法 (如 `bind`, `hasInstance`)
    * 全局函数 (如 `decodeURI`, `encodeURI`, `isFinite`, `isNaN`)
    * `Map` 对象的方法 (如 `clear`, `delete`, `forEach`, `get`, `has`, `set`)
    * `Set` 对象的方法 (如 `add`, `clear`, `delete`, `forEach`, `has`)
    * `WeakMap` 和 `WeakSet` 对象的方法 (如 `delete`, `has`, `set`, `add`)

2. **处理 JavaScript 函数调用（JSCall）：**  `TypeJSCallForwardVarargs`, `TypeJSCall`, `TypeJSCallWithArrayLike`, `TypeJSCallWithSpread` 等函数用于推断 JavaScript 函数调用的返回类型。尽管代码中注释提到可以进行更精确的推断，但目前这些函数都统一使用了 `JSCallTyper`。

3. **处理运行时函数调用（JSCallRuntime）：** `TypeJSCallRuntime` 函数根据调用的具体运行时函数的 ID 来确定其返回类型。

4. **处理 for-in 循环相关节点：** `TypeJSForInEnumerate`, `TypeJSForInNext`, `TypeJSForInPrepare` 用于处理 `for...in` 循环中的类型。

5. **处理模块相关的节点：** `TypeJSLoadModule`, `TypeJSStoreModule`, `TypeJSGetImportMeta` 用于处理 JavaScript 模块的加载和存储。

6. **处理生成器（Generator）和异步函数（Async Function）相关的节点：** 例如 `TypeJSGeneratorStore`, `TypeJSAsyncFunctionEnter`, `TypeJSAsyncFunctionResolve` 等。

7. **处理 Promise 相关的节点：** 例如 `TypeJSFulfillPromise`, `TypeJSPerformPromiseThen`, `TypeJSPromiseResolve`, `TypeJSRejectPromise`, `TypeJSResolvePromise`。

8. **处理简化的运算符（Simplified Operators）：** 例如 `TypeBooleanNot`, `TypeNumberEqual`, `TypeNumberLessThan`, `TypeStringConcat` 等，这些是 Turbofan 编译器内部使用的、更底层的运算符。

9. **处理类型转换操作：** 例如 `TypeStringToNumber`, `TypePlainPrimitiveToNumber`, `TypePlainPrimitiveToWord32`, `TypePlainPrimitiveToFloat64`。

10. **处理各种类型检查节点（Check Nodes）：** 例如 `TypeCheckBounds`, `TypeCheckHeapObject`, `TypeCheckIf`, `TypeCheckInternalizedString`, `TypeCheckMaps`, `TypeCheckNumber`, `TypeCheckReceiver`, `TypeCheckString`, `TypeCheckSymbol` 等。这些节点用于在编译时进行类型断言和优化。

11. **处理内存分配和加载/存储操作：** 例如 `TypeAllocate`, `TypeLoadField`, `TypeLoadElement`, `TypeStoreField`, `TypeStoreElement` 等。

12. **处理各种 `Object.is...` 和 `Number.is...` 方法的类型检查：** 例如 `TypeObjectIsArrayBufferView`, `TypeObjectIsBigInt`, `TypeNumberIsFinite`, `TypeNumberIsNaN` 等。

13. **处理参数长度相关的节点：** `TypeArgumentsLength`, `TypeRestLength`。

14. **处理创建新对象或数据结构的节点：** 例如 `TypeNewDoubleElements`, `TypeNewSmiOrObjectElements`, `TypeNewConsString`。

15. **处理哈希表查找相关的节点：** `TypeFindOrderedHashMapEntry`, `TypeFindOrderedHashSetEntry`。

16. **处理运行时中止和类型断言相关的节点：** `TypeRuntimeAbort`, `TypeAssertType`, `TypeVerifyType`.

17. **处理常量节点：** `TypeConstant`。

18. **处理获取迭代器的节点：** `TypeJSGetIterator`.

**与 JavaScript 的关系和示例：**

这部分代码直接关联到 JavaScript 的功能，因为它负责推断和确定 JavaScript 代码中各种操作和内置函数的返回类型。这些类型信息对于 Turbofan 编译器进行优化至关重要。

以下是一些 JavaScript 示例，说明了代码中 `TypeBuiltin` 函数的处理：

**1. `Math` 对象的方法：**

```javascript
// Builtin::kMathSqrt
const squareRoot = Math.sqrt(9); // squareRoot 的类型会被推断为 Number

// Builtin::kMathMax
const maximum = Math.max(5, 10); // maximum 的类型会被推断为 Number
```

**2. `Date` 对象的方法：**

```javascript
// Builtin::kDatePrototypeGetFullYear
const now = new Date();
const year = now.getFullYear(); // year 的类型会被推断为表示年份的数值类型

// Builtin::kDatePrototypeGetTime
const timestamp = now.getTime(); // timestamp 的类型会被推断为表示时间戳的数值类型
```

**3. `String` 对象的方法：**

```javascript
// Builtin::kStringPrototypeCharAt
const str = "hello";
const char = str.charAt(1); // char 的类型会被推断为 String

// Builtin::kStringPrototypeIndexOf
const index = str.indexOf("l"); // index 的类型会被推断为表示索引的数值类型（可能包含 -1）
```

**4. `Array` 对象的方法：**

```javascript
// Builtin::kArrayIsArray
const arr = [1, 2, 3];
const isArray = Array.isArray(arr); // isArray 的类型会被推断为 Boolean

// Builtin::kArrayPrototypeMap
const doubled = arr.map(x => x * 2); // doubled 的类型会被推断为 Array
```

**5. `Object` 对象的方法：**

```javascript
// Builtin::kObjectAssign
const obj1 = { a: 1 };
const obj2 = { b: 2 };
const merged = Object.assign({}, obj1, obj2); // merged 的类型会被推断为 Object

// Builtin::kObjectIs
const areEqual = Object.is(5, 5); // areEqual 的类型会被推断为 Boolean
```

**总结:**

这部分 `turbofan-typer.cc` 代码的核心功能是为 Turbofan 编译器提供精确的类型信息，使其能够进行更有效的代码优化。它通过分析不同的节点类型和操作，特别是 JavaScript 的内置函数和对象方法，来确定这些操作的返回类型，从而为 V8 引擎的快速执行提供基础。这些类型信息直接反映了 JavaScript 语言的语义和行为。

Prompt: 
```
这是目录为v8/src/compiler/turbofan-typer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
iltin::kMathCbrt:
    case Builtin::kMathCos:
    case Builtin::kMathExpm1:
    case Builtin::kMathFround:
    case Builtin::kMathLog:
    case Builtin::kMathLog1p:
    case Builtin::kMathLog10:
    case Builtin::kMathLog2:
    case Builtin::kMathSin:
    case Builtin::kMathSqrt:
    case Builtin::kMathTan:
      return Type::Number();
    case Builtin::kMathSign:
      return t->cache_->kMinusOneToOneOrMinusZeroOrNaN;
    // Binary math functions.
    case Builtin::kMathAtan2:
    case Builtin::kMathPow:
    case Builtin::kMathMax:
    case Builtin::kMathMin:
    case Builtin::kMathHypot:
      return Type::Number();
    case Builtin::kMathImul:
      return Type::Signed32();
    case Builtin::kMathClz32:
      return t->cache_->kZeroToThirtyTwo;
    // Date functions.
    case Builtin::kDateNow:
      return t->cache_->kTimeValueType;
    case Builtin::kDatePrototypeGetDate:
      return t->cache_->kJSDateDayType;
    case Builtin::kDatePrototypeGetDay:
      return t->cache_->kJSDateWeekdayType;
    case Builtin::kDatePrototypeGetFullYear:
      return t->cache_->kJSDateYearType;
    case Builtin::kDatePrototypeGetHours:
      return t->cache_->kJSDateHourType;
    case Builtin::kDatePrototypeGetMilliseconds:
      return Type::Union(Type::Range(0.0, 999.0, t->zone()), Type::NaN(),
                         t->zone());
    case Builtin::kDatePrototypeGetMinutes:
      return t->cache_->kJSDateMinuteType;
    case Builtin::kDatePrototypeGetMonth:
      return t->cache_->kJSDateMonthType;
    case Builtin::kDatePrototypeGetSeconds:
      return t->cache_->kJSDateSecondType;
    case Builtin::kDatePrototypeGetTime:
      return t->cache_->kJSDateValueType;

    // Symbol functions.
    case Builtin::kSymbolConstructor:
      return Type::Symbol();
    case Builtin::kSymbolPrototypeToString:
      return Type::String();
    case Builtin::kSymbolPrototypeValueOf:
      return Type::Symbol();

    // BigInt functions.
    case Builtin::kBigIntConstructor:
      return Type::BigInt();

    // Number functions.
    case Builtin::kNumberConstructor:
      return Type::Number();
    case Builtin::kNumberIsFinite:
    case Builtin::kNumberIsInteger:
    case Builtin::kNumberIsNaN:
    case Builtin::kNumberIsSafeInteger:
      return Type::Boolean();
    case Builtin::kNumberParseFloat:
      return Type::Number();
    case Builtin::kNumberParseInt:
      return t->cache_->kIntegerOrMinusZeroOrNaN;
    case Builtin::kNumberToString:
      return Type::String();

    // String functions.
    case Builtin::kStringConstructor:
      return Type::String();
    case Builtin::kStringPrototypeCharCodeAt:
      return Type::Union(Type::Range(0, kMaxUInt16, t->zone()), Type::NaN(),
                         t->zone());
    case Builtin::kStringCharAt:
      return Type::String();
    case Builtin::kStringPrototypeCodePointAt:
      return Type::Union(Type::Range(0.0, String::kMaxCodePoint, t->zone()),
                         Type::Undefined(), t->zone());
    case Builtin::kStringPrototypeConcat:
    case Builtin::kStringFromCharCode:
    case Builtin::kStringFromCodePoint:
      return Type::String();
    case Builtin::kStringPrototypeIndexOf:
    case Builtin::kStringPrototypeLastIndexOf:
      return Type::Range(-1.0, String::kMaxLength, t->zone());
    case Builtin::kStringPrototypeEndsWith:
    case Builtin::kStringPrototypeIncludes:
      return Type::Boolean();
    case Builtin::kStringRaw:
    case Builtin::kStringRepeat:
    case Builtin::kStringPrototypeSlice:
      return Type::String();
    case Builtin::kStringPrototypeStartsWith:
      return Type::Boolean();
    case Builtin::kStringPrototypeSubstr:
    case Builtin::kStringSubstring:
    case Builtin::kStringPrototypeToString:
#ifdef V8_INTL_SUPPORT
    case Builtin::kStringPrototypeToLowerCaseIntl:
    case Builtin::kStringPrototypeToUpperCaseIntl:
#else
    case Builtin::kStringPrototypeToLowerCase:
    case Builtin::kStringPrototypeToUpperCase:
#endif
    case Builtin::kStringPrototypeTrim:
    case Builtin::kStringPrototypeTrimEnd:
    case Builtin::kStringPrototypeTrimStart:
    case Builtin::kStringPrototypeValueOf:
      return Type::String();

    case Builtin::kStringPrototypeIterator:
    case Builtin::kStringIteratorPrototypeNext:
      return Type::OtherObject();

    case Builtin::kArrayPrototypeEntries:
    case Builtin::kArrayPrototypeKeys:
    case Builtin::kArrayPrototypeValues:
    case Builtin::kTypedArrayPrototypeEntries:
    case Builtin::kTypedArrayPrototypeKeys:
    case Builtin::kTypedArrayPrototypeValues:
    case Builtin::kArrayIteratorPrototypeNext:
    case Builtin::kMapIteratorPrototypeNext:
    case Builtin::kSetIteratorPrototypeNext:
      return Type::OtherObject();
    case Builtin::kTypedArrayPrototypeToStringTag:
      return Type::Union(Type::InternalizedString(), Type::Undefined(),
                         t->zone());

    // Array functions.
    case Builtin::kArrayIsArray:
      return Type::Boolean();
    case Builtin::kArrayConcat:
      return Type::Receiver();
    case Builtin::kArrayEvery:
      return Type::Boolean();
    case Builtin::kArrayPrototypeFill:
    case Builtin::kArrayFilter:
      return Type::Receiver();
    case Builtin::kArrayPrototypeFindIndex:
      return Type::Range(-1, kMaxSafeInteger, t->zone());
    case Builtin::kArrayForEach:
      return Type::Undefined();
    case Builtin::kArrayIncludes:
      return Type::Boolean();
    case Builtin::kArrayIndexOf:
      return Type::Range(-1, kMaxSafeInteger, t->zone());
    case Builtin::kArrayPrototypeJoin:
      return Type::String();
    case Builtin::kArrayPrototypeLastIndexOf:
      return Type::Range(-1, kMaxSafeInteger, t->zone());
    case Builtin::kArrayMap:
      return Type::Receiver();
    case Builtin::kArrayPush:
      return t->cache_->kPositiveSafeInteger;
    case Builtin::kArrayPrototypeReverse:
    case Builtin::kArrayPrototypeSlice:
      return Type::Receiver();
    case Builtin::kArraySome:
      return Type::Boolean();
    case Builtin::kArrayPrototypeSplice:
      return Type::Receiver();
    case Builtin::kArrayUnshift:
      return t->cache_->kPositiveSafeInteger;

    // ArrayBuffer functions.
    case Builtin::kArrayBufferIsView:
      return Type::Boolean();

    // Object functions.
    case Builtin::kObjectAssign:
      return Type::Receiver();
    case Builtin::kObjectCreate:
      return Type::OtherObject();
    case Builtin::kObjectIs:
    case Builtin::kObjectHasOwn:
    case Builtin::kObjectPrototypeHasOwnProperty:
    case Builtin::kObjectPrototypeIsPrototypeOf:
      return Type::Boolean();
    case Builtin::kObjectToString:
      return Type::String();

    case Builtin::kPromiseAll:
      return Type::Receiver();
    case Builtin::kPromisePrototypeThen:
      return Type::Receiver();
    case Builtin::kPromiseRace:
      return Type::Receiver();
    case Builtin::kPromiseReject:
      return Type::Receiver();
    case Builtin::kPromiseResolveTrampoline:
      return Type::Receiver();

    // RegExp functions.
    case Builtin::kRegExpPrototypeCompile:
      return Type::OtherObject();
    case Builtin::kRegExpPrototypeExec:
      return Type::Union(Type::Array(), Type::Null(), t->zone());
    case Builtin::kRegExpPrototypeTest:
      return Type::Boolean();
    case Builtin::kRegExpPrototypeToString:
      return Type::String();

    // Function functions.
    case Builtin::kFunctionPrototypeBind:
      return Type::BoundFunction();
    case Builtin::kFunctionPrototypeHasInstance:
      return Type::Boolean();

    // Global functions.
    case Builtin::kGlobalDecodeURI:
    case Builtin::kGlobalDecodeURIComponent:
    case Builtin::kGlobalEncodeURI:
    case Builtin::kGlobalEncodeURIComponent:
    case Builtin::kGlobalEscape:
    case Builtin::kGlobalUnescape:
      return Type::String();
    case Builtin::kGlobalIsFinite:
    case Builtin::kGlobalIsNaN:
      return Type::Boolean();

    // Map functions.
    case Builtin::kMapPrototypeClear:
    case Builtin::kMapPrototypeForEach:
      return Type::Undefined();
    case Builtin::kMapPrototypeDelete:
    case Builtin::kMapPrototypeHas:
      return Type::Boolean();
    case Builtin::kMapPrototypeEntries:
    case Builtin::kMapPrototypeKeys:
    case Builtin::kMapPrototypeSet:
    case Builtin::kMapPrototypeValues:
      return Type::OtherObject();

    // Set functions.
    case Builtin::kSetPrototypeAdd:
    case Builtin::kSetPrototypeEntries:
    case Builtin::kSetPrototypeValues:
      return Type::OtherObject();
    case Builtin::kSetPrototypeClear:
    case Builtin::kSetPrototypeForEach:
      return Type::Undefined();
    case Builtin::kSetPrototypeDelete:
    case Builtin::kSetPrototypeHas:
      return Type::Boolean();

    // WeakMap functions.
    case Builtin::kWeakMapPrototypeDelete:
    case Builtin::kWeakMapPrototypeHas:
      return Type::Boolean();
    case Builtin::kWeakMapPrototypeSet:
      return Type::OtherObject();

    // WeakSet functions.
    case Builtin::kWeakSetPrototypeAdd:
      return Type::OtherObject();
    case Builtin::kWeakSetPrototypeDelete:
    case Builtin::kWeakSetPrototypeHas:
      return Type::Boolean();
    default:
      return Type::NonInternal();
  }
}

Type Typer::Visitor::TypeJSCallForwardVarargs(Node* node) {
  return TypeUnaryOp(node, JSCallTyper);
}

Type Typer::Visitor::TypeJSCall(Node* node) {
  // TODO(bmeurer): We could infer better types if we wouldn't ignore the
  // argument types for the JSCallTyper above.
  return TypeUnaryOp(node, JSCallTyper);
}

Type Typer::Visitor::TypeJSCallWithArrayLike(Node* node) {
  return TypeUnaryOp(node, JSCallTyper);
}

Type Typer::Visitor::TypeJSCallWithSpread(Node* node) {
  return TypeUnaryOp(node, JSCallTyper);
}

Type Typer::Visitor::TypeJSCallRuntime(Node* node) {
  switch (CallRuntimeParametersOf(node->op()).id()) {
    case Runtime::kInlineCreateIterResultObject:
      return Type::OtherObject();
    case Runtime::kHasInPrototypeChain:
      return Type::Boolean();
    default:
      break;
  }
  // TODO(turbofan): This should be Type::NonInternal(), but unfortunately we
  // have a few weird runtime calls that return the hole or even FixedArrays;
  // change this once those weird runtime calls have been removed.
  return Type::Any();
}

Type Typer::Visitor::TypeJSForInEnumerate(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeJSForInNext(Node* node) {
  return Type::Union(Type::String(), Type::Undefined(), zone());
}

Type Typer::Visitor::TypeJSForInPrepare(Node* node) {
  static_assert(Map::Bits3::EnumLengthBits::kMax <= FixedArray::kMaxLength);
  Type const cache_type =
      Type::Union(Type::SignedSmall(), Type::OtherInternal(), zone());
  Type const cache_array = Type::OtherInternal();
  Type const cache_length = typer_->cache_->kFixedArrayLengthType;
  return Type::Tuple(cache_type, cache_array, cache_length, zone());
}

Type Typer::Visitor::TypeJSLoadMessage(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSStoreMessage(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSLoadModule(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSStoreModule(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSGetImportMeta(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSGeneratorStore(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeJSGeneratorRestoreContinuation(Node* node) {
  return Type::SignedSmall();
}

Type Typer::Visitor::TypeJSGeneratorRestoreContext(Node* node) {
  return Type::Any();
}

Type Typer::Visitor::TypeJSGeneratorRestoreRegister(Node* node) {
  return Type::Any();
}

Type Typer::Visitor::TypeJSGeneratorRestoreInputOrDebugPos(Node* node) {
  return Type::Any();
}

Type Typer::Visitor::TypeJSStackCheck(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSDebugger(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeJSAsyncFunctionEnter(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSAsyncFunctionReject(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSAsyncFunctionResolve(Node* node) {
  return Type::OtherObject();
}

Type Typer::Visitor::TypeJSFulfillPromise(Node* node) {
  return Type::Undefined();
}

Type Typer::Visitor::TypeJSPerformPromiseThen(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSPromiseResolve(Node* node) {
  return Type::Receiver();
}

Type Typer::Visitor::TypeJSRejectPromise(Node* node) {
  return Type::Undefined();
}

Type Typer::Visitor::TypeJSResolvePromise(Node* node) {
  return Type::Undefined();
}

// Simplified operators.

Type Typer::Visitor::TypeBooleanNot(Node* node) { return Type::Boolean(); }

// static
Type Typer::Visitor::NumberEqualTyper(Type lhs, Type rhs, Typer* t) {
  return JSEqualTyper(ToNumber(lhs, t), ToNumber(rhs, t), t);
}

// static
Type Typer::Visitor::NumberLessThanTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(
      NumberCompareTyper(ToNumber(lhs, t), ToNumber(rhs, t), t), t);
}

// static
Type Typer::Visitor::NumberLessThanOrEqualTyper(Type lhs, Type rhs, Typer* t) {
  return FalsifyUndefined(
      Invert(JSCompareTyper(ToNumber(rhs, t), ToNumber(lhs, t), t), t), t);
}

// static
Type Typer::Visitor::BigIntCompareTyper(Type lhs, Type rhs, Typer* t) {
  if (lhs.IsNone() || rhs.IsNone()) {
    return Type::None();
  }
  return Type::Boolean();
}

Type Typer::Visitor::TypeNumberEqual(Node* node) {
  return TypeBinaryOp(node, NumberEqualTyper);
}

Type Typer::Visitor::TypeNumberLessThan(Node* node) {
  return TypeBinaryOp(node, NumberLessThanTyper);
}

Type Typer::Visitor::TypeNumberLessThanOrEqual(Node* node) {
  return TypeBinaryOp(node, NumberLessThanOrEqualTyper);
}

Type Typer::Visitor::TypeSpeculativeNumberEqual(Node* node) {
  return TypeBinaryOp(node, NumberEqualTyper);
}

Type Typer::Visitor::TypeSpeculativeNumberLessThan(Node* node) {
  return TypeBinaryOp(node, NumberLessThanTyper);
}

Type Typer::Visitor::TypeSpeculativeNumberLessThanOrEqual(Node* node) {
  return TypeBinaryOp(node, NumberLessThanOrEqualTyper);
}

#define BIGINT_COMPARISON_BINOP(Name)              \
  Type Typer::Visitor::Type##Name(Node* node) {    \
    return TypeBinaryOp(node, BigIntCompareTyper); \
  }
BIGINT_COMPARISON_BINOP(BigIntEqual)
BIGINT_COMPARISON_BINOP(BigIntLessThan)
BIGINT_COMPARISON_BINOP(BigIntLessThanOrEqual)
BIGINT_COMPARISON_BINOP(SpeculativeBigIntEqual)
BIGINT_COMPARISON_BINOP(SpeculativeBigIntLessThan)
BIGINT_COMPARISON_BINOP(SpeculativeBigIntLessThanOrEqual)
#undef BIGINT_COMPARISON_BINOP

Type Typer::Visitor::TypeStringConcat(Node* node) { return Type::String(); }

Type Typer::Visitor::TypeStringToNumber(Node* node) {
  return TypeUnaryOp(node, ToNumber);
}

Type Typer::Visitor::TypePlainPrimitiveToNumber(Node* node) {
  return TypeUnaryOp(node, ToNumber);
}

Type Typer::Visitor::TypePlainPrimitiveToWord32(Node* node) {
  return Type::Integral32();
}

Type Typer::Visitor::TypePlainPrimitiveToFloat64(Node* node) {
  return Type::Number();
}

// static
Type Typer::Visitor::ReferenceEqualTyper(Type lhs, Type rhs, Typer* t) {
  if (lhs.IsHeapConstant() && rhs.Is(lhs)) {
    return t->singleton_true_;
  }
  return Type::Boolean();
}

Type Typer::Visitor::TypeReferenceEqual(Node* node) {
  return TypeBinaryOp(node, ReferenceEqualTyper);
}

// static
Type Typer::Visitor::SameValueTyper(Type lhs, Type rhs, Typer* t) {
  return t->operation_typer()->SameValue(lhs, rhs);
}

// static
Type Typer::Visitor::SameValueNumbersOnlyTyper(Type lhs, Type rhs, Typer* t) {
  return t->operation_typer()->SameValueNumbersOnly(lhs, rhs);
}

Type Typer::Visitor::TypeSameValue(Node* node) {
  return TypeBinaryOp(node, SameValueTyper);
}

Type Typer::Visitor::TypeSameValueNumbersOnly(Node* node) {
  return TypeBinaryOp(node, SameValueNumbersOnlyTyper);
}

Type Typer::Visitor::TypeNumberSameValue(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStringEqual(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeStringLessThan(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeStringLessThanOrEqual(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::StringFromSingleCharCodeTyper(Type type, Typer* t) {
  return Type::String();
}

Type Typer::Visitor::StringFromSingleCodePointTyper(Type type, Typer* t) {
  return Type::String();
}

Type Typer::Visitor::TypeStringToLowerCaseIntl(Node* node) {
  return Type::String();
}

Type Typer::Visitor::TypeStringToUpperCaseIntl(Node* node) {
  return Type::String();
}

Type Typer::Visitor::TypeStringCharCodeAt(Node* node) {
  return typer_->cache_->kUint16;
}

Type Typer::Visitor::TypeStringCodePointAt(Node* node) {
  return Type::Range(0.0, String::kMaxCodePoint, zone());
}

Type Typer::Visitor::TypeStringFromSingleCharCode(Node* node) {
  return TypeUnaryOp(node, StringFromSingleCharCodeTyper);
}

Type Typer::Visitor::TypeStringFromSingleCodePoint(Node* node) {
  return TypeUnaryOp(node, StringFromSingleCodePointTyper);
}

Type Typer::Visitor::TypeStringFromCodePointAt(Node* node) {
  return Type::String();
}

Type Typer::Visitor::TypeStringIndexOf(Node* node) {
  return Type::Range(-1.0, String::kMaxLength, zone());
}

Type Typer::Visitor::TypeStringLength(Node* node) {
  return typer_->cache_->kStringLengthType;
}

Type Typer::Visitor::TypeStringWrapperLength(Node* node) {
  return typer_->cache_->kStringLengthType;
}

Type Typer::Visitor::TypeStringSubstring(Node* node) { return Type::String(); }

Type Typer::Visitor::TypeCheckBounds(Node* node) {
  return typer_->operation_typer_.CheckBounds(Operand(node, 0),
                                              Operand(node, 1));
}

Type Typer::Visitor::TypeCheckHeapObject(Node* node) {
  Type type = Operand(node, 0);
  return type;
}

Type Typer::Visitor::TypeCheckIf(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeCheckInternalizedString(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::InternalizedString(), zone());
}

Type Typer::Visitor::TypeCheckMaps(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeCompareMaps(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeCheckNumber(Node* node) {
  return typer_->operation_typer_.CheckNumber(Operand(node, 0));
}

Type Typer::Visitor::TypeCheckReceiver(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::Receiver(), zone());
}

Type Typer::Visitor::TypeCheckReceiverOrNullOrUndefined(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::ReceiverOrNullOrUndefined(), zone());
}

Type Typer::Visitor::TypeCheckSmi(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::SignedSmall(), zone());
}

Type Typer::Visitor::TypeCheckString(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::String(), zone());
}

Type Typer::Visitor::TypeCheckStringOrStringWrapper(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::StringOrStringWrapper(), zone());
}

Type Typer::Visitor::TypeCheckSymbol(Node* node) {
  Type arg = Operand(node, 0);
  return Type::Intersect(arg, Type::Symbol(), zone());
}

Type Typer::Visitor::TypeCheckFloat64Hole(Node* node) {
  return typer_->operation_typer_.CheckFloat64Hole(Operand(node, 0));
}

Type Typer::Visitor::TypeChangeFloat64HoleToTagged(Node* node) {
  return typer_->operation_typer_.CheckFloat64Hole(Operand(node, 0));
}

Type Typer::Visitor::TypeCheckNotTaggedHole(Node* node) {
  Type type = Operand(node, 0);
  type = Type::Intersect(type, Type::NonInternal(), zone());
  return type;
}

Type Typer::Visitor::TypeCheckClosure(Node* node) {
  FeedbackCellRef cell = MakeRef(typer_->broker(), FeedbackCellOf(node->op()));
  OptionalSharedFunctionInfoRef shared = cell.shared_function_info(broker());
  if (!shared.has_value()) return Type::Function();

  if (IsClassConstructor(shared->kind())) {
    return Type::ClassConstructor();
  } else {
    return Type::CallableFunction();
  }
}

Type Typer::Visitor::TypeConvertReceiver(Node* node) {
  Type arg = Operand(node, 0);
  return typer_->operation_typer_.ConvertReceiver(arg);
}

Type Typer::Visitor::TypeConvertTaggedHoleToUndefined(Node* node) {
  Type type = Operand(node, 0);
  return typer_->operation_typer()->ConvertTaggedHoleToUndefined(type);
}

Type Typer::Visitor::TypeCheckEqualsInternalizedString(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeCheckEqualsSymbol(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeAllocate(Node* node) {
  return AllocateTypeOf(node->op());
}

Type Typer::Visitor::TypeAllocateRaw(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoadFieldByIndex(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeLoadField(Node* node) {
  return FieldAccessOf(node->op()).type;
}

Type Typer::Visitor::TypeLoadMessage(Node* node) { return Type::Any(); }

Type Typer::Visitor::TypeLoadElement(Node* node) {
  return ElementAccessOf(node->op()).type;
}

Type Typer::Visitor::TypeLoadStackArgument(Node* node) {
  return Type::NonInternal();
}

Type Typer::Visitor::TypeLoadFromObject(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeLoadImmutableFromObject(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeLoadTypedElement(Node* node) {
  switch (ExternalArrayTypeOf(node->op())) {
#define TYPED_ARRAY_CASE(ElemType, type, TYPE, ctype) \
  case kExternal##ElemType##Array:                    \
    return typer_->cache_->k##ElemType;
    TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  }
  UNREACHABLE();
}

Type Typer::Visitor::TypeLoadDataViewElement(Node* node) {
  switch (ExternalArrayTypeOf(node->op())) {
#define TYPED_ARRAY_CASE(ElemType, type, TYPE, ctype) \
  case kExternal##ElemType##Array:                    \
    return typer_->cache_->k##ElemType;
    TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  }
  UNREACHABLE();
}

Type Typer::Visitor::TypeStoreField(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStoreMessage(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStoreElement(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStoreToObject(Node* node) { UNREACHABLE(); }
Type Typer::Visitor::TypeInitializeImmutableInObject(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeTransitionAndStoreElement(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeTransitionAndStoreNumberElement(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeTransitionAndStoreNonNumberElement(Node* node) {
  UNREACHABLE();
}

Type Typer::Visitor::TypeStoreSignedSmallElement(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStoreTypedElement(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeStoreDataViewElement(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeObjectIsArrayBufferView(Node* node) {
  return TypeUnaryOp(node, ObjectIsArrayBufferView);
}

Type Typer::Visitor::TypeObjectIsBigInt(Node* node) {
  return TypeUnaryOp(node, ObjectIsBigInt);
}

Type Typer::Visitor::TypeObjectIsCallable(Node* node) {
  return TypeUnaryOp(node, ObjectIsCallable);
}

Type Typer::Visitor::TypeObjectIsConstructor(Node* node) {
  return TypeUnaryOp(node, ObjectIsConstructor);
}

Type Typer::Visitor::TypeObjectIsDetectableCallable(Node* node) {
  return TypeUnaryOp(node, ObjectIsDetectableCallable);
}

Type Typer::Visitor::TypeObjectIsMinusZero(Node* node) {
  return TypeUnaryOp(node, ObjectIsMinusZero);
}

Type Typer::Visitor::TypeNumberIsMinusZero(Node* node) {
  return TypeUnaryOp(node, NumberIsMinusZero);
}

Type Typer::Visitor::TypeNumberIsFloat64Hole(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeNumberIsFinite(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeObjectIsFiniteNumber(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeNumberIsInteger(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeObjectIsSafeInteger(Node* node) {
  return Type::Boolean();
}

Type Typer::Visitor::TypeNumberIsSafeInteger(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeObjectIsInteger(Node* node) { return Type::Boolean(); }

Type Typer::Visitor::TypeObjectIsNaN(Node* node) {
  return TypeUnaryOp(node, ObjectIsNaN);
}

Type Typer::Visitor::TypeNumberIsNaN(Node* node) {
  return TypeUnaryOp(node, NumberIsNaN);
}

Type Typer::Visitor::TypeObjectIsNonCallable(Node* node) {
  return TypeUnaryOp(node, ObjectIsNonCallable);
}

Type Typer::Visitor::TypeObjectIsNumber(Node* node) {
  return TypeUnaryOp(node, ObjectIsNumber);
}

Type Typer::Visitor::TypeObjectIsReceiver(Node* node) {
  return TypeUnaryOp(node, ObjectIsReceiver);
}

Type Typer::Visitor::TypeObjectIsSmi(Node* node) {
  return TypeUnaryOp(node, ObjectIsSmi);
}

Type Typer::Visitor::TypeObjectIsString(Node* node) {
  return TypeUnaryOp(node, ObjectIsString);
}

Type Typer::Visitor::TypeObjectIsSymbol(Node* node) {
  return TypeUnaryOp(node, ObjectIsSymbol);
}

Type Typer::Visitor::TypeObjectIsUndetectable(Node* node) {
  return TypeUnaryOp(node, ObjectIsUndetectable);
}

Type Typer::Visitor::TypeArgumentsLength(Node* node) {
  return TypeCache::Get()->kArgumentsLengthType;
}

Type Typer::Visitor::TypeRestLength(Node* node) {
  return TypeCache::Get()->kArgumentsLengthType;
}

Type Typer::Visitor::TypeNewDoubleElements(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeNewSmiOrObjectElements(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeNewArgumentsElements(Node* node) {
  return Type::OtherInternal();
}

Type Typer::Visitor::TypeNewConsString(Node* node) { return Type::String(); }

Type Typer::Visitor::TypeFindOrderedHashMapEntry(Node* node) {
  return Type::Range(-1.0, FixedArray::kMaxLength, zone());
}

Type Typer::Visitor::TypeFindOrderedHashMapEntryForInt32Key(Node* node) {
  return Type::Range(-1.0, FixedArray::kMaxLength, zone());
}

Type Typer::Visitor::TypeFindOrderedHashSetEntry(Node* node) {
  return Type::Range(-1.0, FixedArray::kMaxLength, zone());
}

Type Typer::Visitor::TypeRuntimeAbort(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeAssertType(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeVerifyType(Node* node) { UNREACHABLE(); }

Type Typer::Visitor::TypeCheckTurboshaftTypeOf(Node* node) {
  return TypeOrNone(node->InputAt(0));
}

// Heap constants.

Type Typer::Visitor::TypeConstant(Handle<Object> value) {
  return Type::Constant(typer_->broker(), value, zone());
}

Type Typer::Visitor::TypeJSGetIterator(Node* node) { return Type::Any(); }

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""


```
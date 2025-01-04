Response: Let's break down the thought process for analyzing this Torque file.

1. **Understanding the Goal:** The request asks for a summary of the file's functionality, its relation to JavaScript, examples of its usage, logical inferences, and common programming errors it might help prevent.

2. **Initial Scan and Keyword Identification:** I started by quickly scanning the code for recurring keywords and patterns. The most prominent keyword is `Cast`, along with `Is`, `macro`, `extern macro`, `typeswitch`, `labels CastError`, `%RawDownCast`, and type names like `HeapObject`, `String`, `Number`, etc. This immediately suggests that the file is primarily concerned with type checking and conversion (casting).

3. **Focusing on `Cast` Macros:** The sheer number of `Cast` macros suggests they are the core functionality. I observed the pattern: `macro Cast<A : type extends ...>(...) : A labels CastError { ... }`. This structure implies:
    * `macro`:  This is a Torque macro definition.
    * `Cast<A ...>`:  The macro is named `Cast` and is generic with a type parameter `A`. The `type extends ...` part constrains the type.
    * `(...)`:  The macro takes an input parameter, often `o` of type `Object` or `HeapObject`.
    * `: A`: The macro is expected to return a value of type `A`.
    * `labels CastError`:  Indicates that if the cast is not possible, the code will jump to the `CastError` label.
    * `{ ... }`: The body of the macro, which performs the type checking and the actual cast.

4. **Analyzing the `Is` Macros:**  Following the `Cast` macros, the `Is` macros are also numerous and have a simple structure: `macro Is<A : type extends HeapObject>(o: HeapObject): bool { return Is<A>(o); }`. These are clearly type predicates, returning `true` if the object `o` is of the specified type `A`, and `false` otherwise.

5. **Identifying External Macros:** The `extern macro` declarations indicate functions implemented elsewhere (likely in C++ within the V8 codebase). These provide lower-level type checking capabilities (`IsBigInt`, `IsConstructor`, `TaggedToHeapObject`, etc.).

6. **Understanding the `typeswitch` Statement:** The `typeswitch` statement is used for more complex type checking scenarios where multiple possible types are considered. This is common when dealing with union types (e.g., `Number | BigInt`).

7. **Inferring Functionality:** Based on the observations above, I concluded that the primary function of this file is to provide safe type casting mechanisms in Torque. It ensures that an object is of the expected type before attempting to treat it as such, preventing potential runtime errors.

8. **Relating to JavaScript:**  I considered how these low-level type checks and casts relate to JavaScript. JavaScript is dynamically typed, but V8 internally needs to know the concrete types of objects for optimization and correct execution. The `cast.tq` file provides the tools for V8's Torque code to perform these type checks, which are essential for implementing JavaScript semantics. Examples like casting to `Number` or `String` directly map to JavaScript's primitive types. Casting to specific object types like `JSArray` or `JSFunction` relates to the internal representation of JavaScript objects.

9. **Constructing JavaScript Examples:** To illustrate the connection to JavaScript, I thought about common scenarios where type checks are implicitly or explicitly performed in JavaScript. Examples include:
    * Using `typeof`:  This is a high-level JavaScript way to check types.
    * Instanceof: Checks if an object is an instance of a constructor.
    * Type coercion: JavaScript often implicitly converts types (e.g., in arithmetic operations). The `cast.tq` file helps ensure these coercions are handled correctly within V8.
    * Function calls:  V8 needs to ensure the object being called is actually a function.

10. **Developing Logical Inferences (Assumptions and Outputs):** I considered how the `Cast` macros would behave with different inputs. The core idea is that if the input object matches the target type, the cast succeeds, and the object (or a downcasted version) is returned. If it doesn't match, the execution jumps to `CastError`.

11. **Identifying Common Programming Errors:**  I thought about common JavaScript errors related to incorrect type assumptions. `TypeError` is the most obvious one. Trying to call a non-function, access properties of `null` or `undefined`, or perform operations on incompatible types are all scenarios where the type checks in `cast.tq` play a crucial role in preventing or handling errors within the V8 engine.

12. **Structuring the Answer:** Finally, I organized the information into the requested categories: functionality, relation to JavaScript (with examples), logical inferences (with examples), and common programming errors (with examples). I used clear and concise language, explaining the purpose of the macros and how they contribute to V8's operation. I tried to link the low-level Torque code to the more familiar concepts of JavaScript. I made sure to highlight the "safety" aspect of the casting mechanism.
这个v8 Torque源代码文件 `cast.tq` 的主要功能是为 V8 引擎的 Torque 语言提供**类型转换（casting）**相关的宏定义。它定义了一系列用于安全地将一个对象从一个类型“转换”或断言为另一个类型的宏。

**功能归纳：**

1. **类型断言（Type Assertion）：**  `cast.tq` 定义了大量的 `Cast<T>(o)` 宏，这些宏试图将对象 `o` 断言为类型 `T`。如果 `o` 确实是类型 `T` 或其子类型，则返回 `o` (或其向下转型后的版本)。如果 `o` 不是类型 `T`，则会跳转到 `CastError` 标签，表明类型断言失败。

2. **类型判断（Type Checking）：**  `cast.tq` 也定义了 `Is<T>(o)` 宏，用于判断对象 `o` 是否是类型 `T`。这相当于一个布尔类型的检查，返回 `true` 或 `false`。

3. **不安全类型转换（Unsafe Casting）：**  `UnsafeCast<T>(o)` 宏提供了一种不安全的类型转换方式。它假设调用者已经确保了对象 `o` 的类型是 `T`，因此直接进行转换，如果类型不匹配可能会导致程序崩溃或未定义的行为。通常在性能关键且已知类型安全的情况下使用。

4. **处理联合类型：** 文件中还包含处理联合类型的 `Cast` 宏，例如 `Cast<Number|TheHole>(o)`，它可以将对象断言为 `Number` 或 `TheHole` 类型。

5. **特定类型的便捷宏：**  为了一些常用的类型，例如 `SeqOneByteString`，定义了更具体的 `Cast` 宏，这些宏可能包含额外的类型检查逻辑。

**与 JavaScript 功能的关系及 JavaScript 示例：**

虽然 Torque 是 V8 引擎内部使用的语言，与 JavaScript 没有直接的语法关系，但 `cast.tq` 中定义的类型转换与 JavaScript 的**类型系统和类型检查**密切相关。

在 JavaScript 中，变量是动态类型的，这意味着变量的类型可以在运行时改变。V8 引擎在执行 JavaScript 代码时，需要对变量的类型进行推断和检查，以确保操作的正确性。`cast.tq` 中定义的宏就是 V8 在其内部代码中进行这些类型检查和转换的工具。

例如，JavaScript 中的 `typeof` 运算符可以用来检查变量的类型：

```javascript
let x = 10;
console.log(typeof x === 'number'); // 输出 true

let y = "hello";
console.log(typeof y === 'string'); // 输出 true
```

在 V8 的 Torque 代码中，`IsNumber(o)` 和 `Is<String>(o)` 宏就类似于这种类型检查。

再例如，JavaScript 中的类型转换：

```javascript
let str = "123";
let num = Number(str); // 显式将字符串转换为数字

let value = 42;
let strValue = String(value); // 显式将数字转换为字符串
```

`cast.tq` 中的 `Cast<Number>(o)` 宏对应于 V8 内部尝试将一个对象安全地转换为 `Number` 类型的操作。如果 `o` 实际上不是数字或可以安全转换为数字的值，`Cast` 宏将会失败。

**代码逻辑推理及假设输入与输出：**

假设我们有以下 Torque 代码片段使用 `cast.tq` 中的宏：

```torque
macro MyFunction(o: Object) {
  if (Is<Number>(o)) {
    const num: Number = Cast<Number>(o) otherwise goto NotNumber;
    // 对 num 进行数字操作
    Print(num);
    return;
  }
  NotNumber: {
    Print("Not a number");
  }
}
```

**假设输入与输出：**

* **假设输入 1:** `o` 是一个 JavaScript 数字 `10`。
    * **推理:** `Is<Number>(o)` 将返回 `true`。`Cast<Number>(o)` 将成功，并将 `o` 断言为 `Number` 类型赋值给 `num`。`Print(num)` 将输出 `10`。
    * **输出:** 控制台打印 `10`。

* **假设输入 2:** `o` 是一个 JavaScript 字符串 `"hello"`。
    * **推理:** `Is<Number>(o)` 将返回 `false`。代码将跳转到 `NotNumber` 标签。
    * **输出:** 控制台打印 `Not a number`。

* **假设输入 3:** `o` 是一个 JavaScript 布尔值 `true`。
    * **推理:** `Is<Number>(o)` 将返回 `false`。代码将跳转到 `NotNumber` 标签。
    * **输出:** 控制台打印 `Not a number`。

**涉及用户常见的编程错误及示例：**

`cast.tq` 中定义的宏有助于 V8 引擎在内部避免由于类型假设错误而导致的崩溃或错误行为。然而，在 JavaScript 编程中，用户常常会犯与类型相关的错误，这些错误最终可能会被 V8 引擎的类型检查机制捕获。

**常见编程错误示例：**

1. **尝试调用非函数对象：**

   ```javascript
   let obj = { name: "Alice" };
   obj(); // TypeError: obj is not a function
   ```

   在 V8 内部执行这段代码时，当尝试调用 `obj()` 时，引擎会进行类型检查，发现 `obj` 不是一个函数，从而抛出 `TypeError`。`cast.tq` 中的类似 `Cast<Callable>(o)` 的宏就用于检查对象是否可调用。

2. **访问 `null` 或 `undefined` 的属性：**

   ```javascript
   let myVar = null;
   console.log(myVar.name); // TypeError: Cannot read properties of null (reading 'name')

   let anotherVar;
   console.log(anotherVar.length); // TypeError: Cannot read properties of undefined (reading 'length')
   ```

   V8 内部在尝试访问 `myVar.name` 时，会检查 `myVar` 是否为对象。由于 `myVar` 是 `null`，类型检查会失败，导致 `TypeError`。虽然 `cast.tq` 中没有直接针对 `null` 或 `undefined` 属性访问的宏，但它包含了对 `HeapObject` 等类型的检查，可以辅助识别这类错误。

3. **对类型不兼容的值进行操作：**

   ```javascript
   let num = 10;
   let str = "hello";
   console.log(num + str); // 输出 "10hello"，但有时可能导致意外结果

   let arr = [1, 2, 3];
   arr.toUpperCase(); // TypeError: arr.toUpperCase is not a function
   ```

   在第一个例子中，JavaScript 会进行隐式类型转换。但在 V8 内部，加法运算符会根据操作数的类型执行不同的操作。在第二个例子中，`toUpperCase` 是字符串的方法，尝试在数组上调用会导致 `TypeError`。V8 内部的类型检查机制（部分由 `cast.tq` 支持）会确保方法的调用者是正确的类型。

总而言之，`v8/src/builtins/cast.tq` 文件是 V8 引擎中一个关键的组成部分，它为 Torque 代码提供了强大的类型转换和断言机制，这对于确保 V8 引擎内部代码的类型安全和正确执行 JavaScript 代码至关重要。它与 JavaScript 的类型系统紧密相关，并且有助于防止和检测常见的 JavaScript 编程错误。

Prompt: 
```
这是目录为v8/src/builtins/cast.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern macro IsBigInt(HeapObject): bool;
extern macro IsConstructor(HeapObject): bool;
extern macro IsCustomElementsReceiverInstanceType(int32): bool;
extern macro IsExtensibleMap(Map): bool;
extern macro IsNumberNormalized(Number): bool;
extern macro IsSafeInteger(Object): bool;

@export
macro IsAccessorInfo(o: HeapObject): bool {
  return Is<AccessorInfo>(o);
}

@export
macro IsAccessorPair(o: HeapObject): bool {
  return Is<AccessorPair>(o);
}

@export
macro IsAllocationSite(o: HeapObject): bool {
  return Is<AllocationSite>(o);
}

@export
macro IsCell(o: HeapObject): bool {
  return Is<Cell>(o);
}

@export
macro IsInstructionStream(o: HeapObject): bool {
  return Is<InstructionStream>(o);
}

@export
macro IsCode(o: HeapObject): bool {
  return Is<Code>(o);
}

@export
macro IsContext(o: HeapObject): bool {
  return Is<Context>(o);
}

@export
macro IsCoverageInfo(o: HeapObject): bool {
  return Is<CoverageInfo>(o);
}

@export
macro IsDebugInfo(o: HeapObject): bool {
  return Is<DebugInfo>(o);
}

@export
macro IsFixedDoubleArray(o: HeapObject): bool {
  return Is<FixedDoubleArray>(o);
}

@export
macro IsFeedbackCell(o: HeapObject): bool {
  return Is<FeedbackCell>(o);
}

@export
macro IsFeedbackVector(o: HeapObject): bool {
  return Is<FeedbackVector>(o);
}

@export
macro IsHeapNumber(o: HeapObject): bool {
  return Is<HeapNumber>(o);
}

@export
macro IsNativeContext(o: HeapObject): bool {
  return Is<NativeContext>(o);
}

@export
macro IsNumber(o: Object): bool {
  return Is<Number>(o);
}

@export
macro IsPrivateSymbol(o: HeapObject): bool {
  return Is<PrivateSymbol>(o);
}

@export
macro IsPromiseCapability(o: HeapObject): bool {
  return Is<PromiseCapability>(o);
}

@export
macro IsPromiseFulfillReactionJobTask(o: HeapObject): bool {
  return Is<PromiseFulfillReactionJobTask>(o);
}

@export
macro IsPromiseReaction(o: HeapObject): bool {
  return Is<PromiseReaction>(o);
}

@export
macro IsPromiseRejectReactionJobTask(o: HeapObject): bool {
  return Is<PromiseRejectReactionJobTask>(o);
}

@export
macro IsSharedFunctionInfo(o: HeapObject): bool {
  return Is<SharedFunctionInfo>(o);
}

@export
macro IsSymbol(o: HeapObject): bool {
  return Is<Symbol>(o);
}

extern macro TaggedToHeapObject(Object): HeapObject
    labels CastError;
extern macro TaggedToSmi(Object): Smi
    labels CastError;
extern macro TaggedToPositiveSmi(Object): PositiveSmi
    labels CastError;
extern macro TaggedToDirectString(Object): DirectString
    labels CastError;
extern macro HeapObjectToCallable(HeapObject): Callable
    labels CastError;
extern macro HeapObjectToConstructor(HeapObject): Constructor
    labels CastError;
extern macro HeapObjectToJSFunctionWithPrototypeSlot(HeapObject):
    JSFunctionWithPrototypeSlot
    labels CastError;

macro Cast<A : type extends WeakHeapObject>(o: A|
                                               Object): A labels CastError {
  if (!IsWeakOrCleared(o)) goto CastError;
  return %RawDownCast<A>(o);
}

macro Cast<A : type extends Object>(
    implicit context: Context)(o: MaybeObject): A labels CastError {
  typeswitch (o) {
    case (WeakHeapObject): {
      goto CastError;
    }
    case (o: Object): {
      return Cast<A>(o) otherwise CastError;
    }
  }
}

Cast<Undefined>(o: MaybeObject): Undefined labels CastError {
  if (TaggedNotEqual(o, Undefined)) goto CastError;
  return %RawDownCast<Undefined>(o);
}

macro Cast<A : type extends Object>(implicit context: Context)(o: Object): A
    labels CastError {
  return Cast<A>(TaggedToHeapObject(o) otherwise CastError)
      otherwise CastError;
}

// This is required for casting MaybeObject to Object.
Cast<Smi>(o: Object): Smi
    labels CastError {
  return TaggedToSmi(o) otherwise CastError;
}

Cast<PositiveSmi>(o: Object): PositiveSmi
    labels CastError {
  return TaggedToPositiveSmi(o) otherwise CastError;
}

Cast<Zero>(o: Object): Zero labels CastError {
  if (TaggedEqual(o, SmiConstant(0))) return %RawDownCast<Zero>(o);
  goto CastError;
}

Cast<Number>(o: Object): Number
    labels CastError {
  typeswitch (o) {
    case (s: Smi): {
      return s;
    }
    case (n: HeapNumber): {
      return n;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Undefined>(o: Object): Undefined
    labels CastError {
  const o: MaybeObject = o;
  return Cast<Undefined>(o) otherwise CastError;
}

Cast<Numeric>(o: Object): Numeric labels CastError {
  typeswitch (o) {
    case (o: Number): {
      return o;
    }
    case (o: BigInt): {
      return o;
    }
    case (HeapObject): {
      goto CastError;
    }
  }
}

Cast<TheHole>(o: Object): TheHole labels CastError {
  if (o == TheHole) return %RawDownCast<TheHole>(o);
  goto CastError;
}

Cast<TheHole>(o: HeapObject): TheHole labels CastError {
  const o: Object = o;
  return Cast<TheHole>(o) otherwise CastError;
}

Cast<True>(o: Object): True labels CastError {
  if (o == True) return %RawDownCast<True>(o);
  goto CastError;
}

Cast<True>(o: HeapObject): True labels CastError {
  const o: Object = o;
  return Cast<True>(o) otherwise CastError;
}

Cast<False>(o: Object): False labels CastError {
  if (o == False) return %RawDownCast<False>(o);
  goto CastError;
}

Cast<False>(o: HeapObject): False labels CastError {
  const o: Object = o;
  return Cast<False>(o) otherwise CastError;
}

Cast<Boolean>(o: Object): Boolean labels CastError {
  typeswitch (o) {
    case (o: True): {
      return o;
    }
    case (o: False): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Boolean>(o: HeapObject): Boolean labels CastError {
  const o: Object = o;
  return Cast<Boolean>(o) otherwise CastError;
}

// TODO(turbofan): These trivial casts for union types should be generated
// automatically.

Cast<JSPrimitive>(o: Object): JSPrimitive labels CastError {
  typeswitch (o) {
    case (o: Numeric): {
      return o;
    }
    case (o: String): {
      return o;
    }
    case (o: Symbol): {
      return o;
    }
    case (o: Boolean): {
      return o;
    }
    case (o: Undefined): {
      return o;
    }
    case (o: Null): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<JSAny>(o: Object): JSAny labels CastError {
  typeswitch (o) {
    case (o: JSPrimitive): {
      return o;
    }
    case (o: JSReceiver): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<JSAny|TheHole>(o: Object): JSAny|TheHole labels CastError {
  typeswitch (o) {
    case (o: JSAny): {
      return o;
    }
    case (o: TheHole): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Number|TheHole>(o: Object): Number|TheHole labels CastError {
  typeswitch (o) {
    case (o: Number): {
      return o;
    }
    case (o: TheHole): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Context|Zero|Undefined>(o: Object): Context|Zero|Undefined
    labels CastError {
  typeswitch (o) {
    case (o: Context): {
      return o;
    }
    case (o: Zero): {
      return o;
    }
    case (o: Undefined): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

macro Cast<A : type extends HeapObject>(o: HeapObject): A
    labels CastError;

Cast<HeapObject>(o: HeapObject): HeapObject
labels _CastError {
  return o;
}

Cast<Null>(o: HeapObject): Null
    labels CastError {
  if (o != Null) goto CastError;
  return %RawDownCast<Null>(o);
}

Cast<Undefined>(o: HeapObject): Undefined
    labels CastError {
  const o: MaybeObject = o;
  return Cast<Undefined>(o) otherwise CastError;
}

Cast<EmptyFixedArray>(o: Object): EmptyFixedArray
    labels CastError {
  if (o != kEmptyFixedArray) goto CastError;
  return %RawDownCast<EmptyFixedArray>(o);
}
Cast<EmptyFixedArray>(o: HeapObject): EmptyFixedArray
    labels CastError {
  const o: Object = o;
  return Cast<EmptyFixedArray>(o) otherwise CastError;
}

Cast<(FixedDoubleArray | EmptyFixedArray)>(o: HeapObject): FixedDoubleArray|
    EmptyFixedArray labels CastError {
  typeswitch (o) {
    case (o: EmptyFixedArray): {
      return o;
    }
    case (o: FixedDoubleArray): {
      return o;
    }
    case (HeapObject): {
      goto CastError;
    }
  }
}

Cast<Callable>(o: HeapObject): Callable
    labels CastError {
  return HeapObjectToCallable(o) otherwise CastError;
}

Cast<Undefined|Callable>(o: HeapObject): Undefined|Callable
    labels CastError {
  if (o == Undefined) return Undefined;
  return HeapObjectToCallable(o) otherwise CastError;
}

Cast<Undefined|JSFunction>(o: HeapObject): Undefined|JSFunction
    labels CastError {
  if (o == Undefined) return Undefined;
  return Cast<JSFunction>(o) otherwise CastError;
}

macro Cast<T : type extends Symbol>(o: Symbol): T labels CastError;
Cast<PublicSymbol>(s: Symbol): PublicSymbol labels CastError {
  if (s.flags.is_private) goto CastError;
  return %RawDownCast<PublicSymbol>(s);
}
Cast<PrivateSymbol>(s: Symbol): PrivateSymbol labels CastError {
  if (s.flags.is_private) return %RawDownCast<PrivateSymbol>(s);
  goto CastError;
}
Cast<PublicSymbol>(o: HeapObject): PublicSymbol labels CastError {
  const s = Cast<Symbol>(o) otherwise CastError;
  return Cast<PublicSymbol>(s) otherwise CastError;
}
Cast<PrivateSymbol>(o: HeapObject): PrivateSymbol labels CastError {
  const s = Cast<Symbol>(o) otherwise CastError;
  return Cast<PrivateSymbol>(s) otherwise CastError;
}

Cast<DirectString>(o: String): DirectString
    labels CastError {
  return TaggedToDirectString(o) otherwise CastError;
}

Cast<Constructor>(o: HeapObject): Constructor
    labels CastError {
  return HeapObjectToConstructor(o) otherwise CastError;
}

Cast<JSFunctionWithPrototypeSlot>(o: HeapObject): JSFunctionWithPrototypeSlot
    labels CastError {
  return HeapObjectToJSFunctionWithPrototypeSlot(o) otherwise CastError;
}

Cast<BigInt>(o: HeapObject): BigInt labels CastError {
  if (IsBigInt(o)) return %RawDownCast<BigInt>(o);
  goto CastError;
}

Cast<JSRegExpResult>(implicit context: Context)(o: HeapObject): JSRegExpResult
    labels CastError {
  if (regexp::IsRegExpResult(o)) return %RawDownCast<JSRegExpResult>(o);
  goto CastError;
}

Cast<JSSloppyArgumentsObject>(
    implicit context: Context)(o: HeapObject): JSSloppyArgumentsObject
    labels CastError {
  const map: Map = o.map;
  if (IsFastAliasedArgumentsMap(map) || IsSloppyArgumentsMap(map) ||
      IsSlowAliasedArgumentsMap(map)) {
    return %RawDownCast<JSSloppyArgumentsObject>(o);
  }
  goto CastError;
}

Cast<JSStrictArgumentsObject>(
    implicit context: Context)(o: HeapObject): JSStrictArgumentsObject
    labels CastError {
  const map: Map = o.map;
  if (!IsStrictArgumentsMap(map)) goto CastError;
  return %RawDownCast<JSStrictArgumentsObject>(o);
}

Cast<JSArgumentsObjectWithLength>(
    implicit context: Context)(o: HeapObject): JSArgumentsObjectWithLength
    labels CastError {
  typeswitch (o) {
    case (o: JSStrictArgumentsObject): {
      return o;
    }
    case (o: JSSloppyArgumentsObject): {
      return o;
    }
    case (HeapObject): {
      goto CastError;
    }
  }
}

Cast<FastJSRegExp>(implicit context: Context)(o: HeapObject): FastJSRegExp
    labels CastError {
  // TODO(jgruber): Remove or redesign this. There is no single 'fast' regexp,
  // the conditions to make a regexp object fast differ based on the callsite.
  // For now, run the strict variant since replace (the only current callsite)
  // accesses flag getters.
  if (regexp::IsFastRegExpStrict(o)) {
    return %RawDownCast<FastJSRegExp>(o);
  }
  goto CastError;
}

Cast<FastJSArray>(implicit context: Context)(o: HeapObject): FastJSArray
    labels CastError {
  if (IsForceSlowPath()) goto CastError;

  if (!Is<JSArray>(o)) goto CastError;

  // Bailout if receiver has slow elements.
  const map: Map = o.map;
  const elementsKind: ElementsKind = LoadMapElementsKind(map);
  if (!IsFastElementsKind(elementsKind)) goto CastError;

  // Verify that our prototype is the initial array prototype.
  if (!IsPrototypeInitialArrayPrototype(map)) goto CastError;

  if (IsNoElementsProtectorCellInvalid()) goto CastError;
  return %RawDownCast<FastJSArray>(o);
}

Cast<FastJSArrayForRead>(
    implicit context: Context)(o: HeapObject): FastJSArrayForRead
    labels CastError {
  if (!Is<JSArray>(o)) goto CastError;

  // Bailout if receiver has slow elements.
  const map: Map = o.map;
  const elementsKind: ElementsKind = LoadMapElementsKind(map);
  if (!IsElementsKindLessThanOrEqual(
          elementsKind, ElementsKind::LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND))
    goto CastError;

  // Verify that our prototype is the initial array prototype.
  if (!IsPrototypeInitialArrayPrototype(map)) goto CastError;

  if (IsNoElementsProtectorCellInvalid()) goto CastError;
  return %RawDownCast<FastJSArrayForRead>(o);
}

Cast<FastJSArrayForCopy>(
    implicit context: Context)(o: HeapObject): FastJSArrayForCopy
    labels CastError {
  if (IsArraySpeciesProtectorCellInvalid()) goto CastError;
  // TODO(victorgomes): Check if we can cast from FastJSArrayForRead instead.
  const a = Cast<FastJSArray>(o) otherwise CastError;
  return %RawDownCast<FastJSArrayForCopy>(a);
}

Cast<FastJSArrayForConcat>(
    implicit context: Context)(o: HeapObject): FastJSArrayForConcat
    labels CastError {
  if (IsIsConcatSpreadableProtectorCellInvalid()) goto CastError;
  const a = Cast<FastJSArrayForCopy>(o) otherwise CastError;
  return %RawDownCast<FastJSArrayForConcat>(a);
}

Cast<FastJSArrayWithNoCustomIteration>(
    implicit context: Context)(o: HeapObject): FastJSArrayWithNoCustomIteration
    labels CastError {
  if (IsArrayIteratorProtectorCellInvalid()) goto CastError;
  const a = Cast<FastJSArray>(o) otherwise CastError;
  return %RawDownCast<FastJSArrayWithNoCustomIteration>(a);
}

Cast<FastJSArrayForReadWithNoCustomIteration>(
    implicit context: Context)(
    o: HeapObject): FastJSArrayForReadWithNoCustomIteration
    labels CastError {
  if (IsArrayIteratorProtectorCellInvalid()) goto CastError;
  const a = Cast<FastJSArrayForRead>(o) otherwise CastError;
  return %RawDownCast<FastJSArrayForReadWithNoCustomIteration>(a);
}

Cast<JSSetWithNoCustomIteration>(
    implicit context: Context)(o: HeapObject): JSSetWithNoCustomIteration
    labels CastError {
  if (IsSetIteratorProtectorCellInvalid()) goto CastError;
  const a = Cast<JSSet>(o) otherwise CastError;
  return %RawDownCast<JSSetWithNoCustomIteration>(a);
}

Cast<JSMapWithNoCustomIteration>(
    implicit context: Context)(o: HeapObject): JSMapWithNoCustomIteration
    labels CastError {
  if (IsMapIteratorProtectorCellInvalid()) goto CastError;
  const a = Cast<JSMap>(o) otherwise CastError;
  return %RawDownCast<JSMapWithNoCustomIteration>(a);
}

Cast<StableOrderedHashSet>(implicit context: Context)(o: HeapObject):
    StableOrderedHashSet labels CastError {
  const table = Cast<OrderedHashSet>(o) otherwise CastError;
  return %RawDownCast<StableOrderedHashSet>(table);
}

Cast<StableOrderedHashMap>(implicit context: Context)(o: HeapObject):
    StableOrderedHashMap labels CastError {
  const table = Cast<OrderedHashMap>(o) otherwise CastError;
  return %RawDownCast<StableOrderedHashMap>(table);
}

macro Cast<T: type>(o: String): T labels CastError;

Cast<SeqOneByteString>(o: HeapObject): SeqOneByteString labels CastError {
  return Cast<SeqOneByteString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<SeqOneByteString>(o: String): SeqOneByteString labels CastError {
  const instanceType = o.StringInstanceType();
  // Using & instead of && enables Turbofan to merge the two checks into one.
  if (!(instanceType.representation == StringRepresentationTag::kSeqStringTag &
        instanceType.is_one_byte)) {
    goto CastError;
  }
  return %RawDownCast<SeqOneByteString>(o);
}

Cast<SeqTwoByteString>(o: HeapObject): SeqTwoByteString labels CastError {
  return Cast<SeqTwoByteString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<SeqTwoByteString>(o: String): SeqTwoByteString labels CastError {
  const instanceType = o.StringInstanceType();
  // Using & instead of && enables Turbofan to merge the two checks into one.
  if (!(instanceType.representation == StringRepresentationTag::kSeqStringTag &
        !instanceType.is_one_byte)) {
    goto CastError;
  }
  return %RawDownCast<SeqTwoByteString>(o);
}

Cast<ThinString>(o: HeapObject): ThinString labels CastError {
  return Cast<ThinString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<ThinString>(o: String): ThinString labels CastError {
  const instanceType = o.StringInstanceType();
  if (instanceType.representation != StringRepresentationTag::kThinStringTag) {
    goto CastError;
  }
  return %RawDownCast<ThinString>(o);
}

Cast<ConsString>(o: HeapObject): ConsString labels CastError {
  return Cast<ConsString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<ConsString>(o: String): ConsString labels CastError {
  const instanceType = o.StringInstanceType();
  if (instanceType.representation != StringRepresentationTag::kConsStringTag) {
    goto CastError;
  }
  return %RawDownCast<ConsString>(o);
}

Cast<SlicedString>(o: HeapObject): SlicedString labels CastError {
  return Cast<SlicedString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<SlicedString>(o: String): SlicedString labels CastError {
  const instanceType = o.StringInstanceType();
  if (instanceType.representation !=
      StringRepresentationTag::kSlicedStringTag) {
    goto CastError;
  }
  return %RawDownCast<SlicedString>(o);
}

Cast<ExternalOneByteString>(o: HeapObject):
    ExternalOneByteString labels CastError {
  return Cast<ExternalOneByteString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<ExternalOneByteString>(o: String): ExternalOneByteString labels CastError {
  const instanceType = o.StringInstanceType();
  // Using & instead of && enables Turbofan to merge the two checks into one.
  if (!(instanceType.representation ==
            StringRepresentationTag::kExternalStringTag &
        instanceType.is_one_byte)) {
    goto CastError;
  }
  return %RawDownCast<ExternalOneByteString>(o);
}

Cast<ExternalTwoByteString>(o: HeapObject):
    ExternalTwoByteString labels CastError {
  return Cast<ExternalTwoByteString>(Cast<String>(o) otherwise CastError)
      otherwise CastError;
}

Cast<ExternalTwoByteString>(o: String): ExternalTwoByteString labels CastError {
  const instanceType = o.StringInstanceType();
  // Using & instead of && enables Turbofan to merge the two checks into one.
  if (!(instanceType.representation ==
            StringRepresentationTag::kExternalStringTag &
        !instanceType.is_one_byte)) {
    goto CastError;
  }
  return %RawDownCast<ExternalTwoByteString>(o);
}

Cast<JSReceiver|Null>(o: HeapObject): JSReceiver|Null
    labels CastError {
  typeswitch (o) {
    case (o: Null): {
      return o;
    }
    case (o: JSReceiver): {
      return o;
    }
    case (HeapObject): {
      goto CastError;
    }
  }
}

Cast<JSReceiver|Symbol>(implicit context: Context)(o: Object): JSReceiver|
    Symbol
    labels CastError {
  typeswitch (o) {
    case (o: JSReceiver): {
      return o;
    }
    case (o: Symbol): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Smi|PromiseReaction>(o: Object): Smi|PromiseReaction labels CastError {
  typeswitch (o) {
    case (o: Smi): {
      return o;
    }
    case (o: PromiseReaction): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<String|Callable>(implicit context: Context)(o: Object): String|
    Callable labels CastError {
  typeswitch (o) {
    case (o: String): {
      return o;
    }
    case (o: Callable): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<Zero|PromiseReaction>(implicit context: Context)(o: Object): Zero|
    PromiseReaction labels CastError {
  typeswitch (o) {
    case (o: Zero): {
      return o;
    }
    case (o: PromiseReaction): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<JSFunction|JSBoundFunction|JSWrappedFunction>(
    implicit context: Context)(o: Object): JSFunction|JSBoundFunction|
    JSWrappedFunction labels CastError {
  typeswitch (o) {
    case (o: JSFunction): {
      return o;
    }
    case (o: JSBoundFunction): {
      return o;
    }
    case (o: JSWrappedFunction): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<FixedArray|Undefined>(o: HeapObject): FixedArray|
    Undefined labels CastError {
  typeswitch (o) {
    case (o: Undefined): {
      return o;
    }
    case (o: FixedArray): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

Cast<JSProxy|Null>(o: HeapObject): JSProxy|Null labels CastError {
  typeswitch (o) {
    case (o: Null): {
      return o;
    }
    case (o: JSProxy): {
      return o;
    }
    case (Object): {
      goto CastError;
    }
  }
}

macro Is<A : type extends Object, B : type extends Object>(
    implicit context: Context)(o: B): bool {
  Cast<A>(o) otherwise return false;
  return true;
}

macro UnsafeCast<A : type extends Object>(
    implicit context: Context)(o: Object): A {
  dcheck(Is<A>(o));
  return %RawDownCast<A>(o);
}

macro UnsafeConstCast<T: type>(r: const &T):&T {
  return %RawDownCast<&T>(r);
}

UnsafeCast<RegExpMatchInfo>(
    implicit context: Context)(o: Object): RegExpMatchInfo {
  dcheck(Is<RegExpMatchInfo>(o));
  return %RawDownCast<RegExpMatchInfo>(o);
}

UnsafeCast<ArrayList>(implicit context: Context)(o: Object): ArrayList {
  dcheck(Is<ArrayList>(o));
  return %RawDownCast<ArrayList>(o);
}

macro UnsafeCast<A : type extends WeakHeapObject>(o: A|Object): A {
  dcheck(IsWeakOrCleared(o));
  return %RawDownCast<A>(o);
}

macro CastOrDefault<T: type, Arg: type, Default: type>(
    implicit context: Context)(x: Arg, default: Default): T|Default {
  return Cast<T>(x) otherwise return default;
}

// This is required for casting MaybeObject to Object.
Cast<Object>(o: Object): Object
labels _CastError {
  return o;
}

"""

```
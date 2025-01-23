Response: Let's break down the thought process for summarizing this Torque file.

1. **Initial Scan and Keyword Recognition:** The first step is a quick scan of the file, looking for recurring keywords and patterns. Immediately, terms like `type`, `macro`, `extern`, `intrinsic`, `builtin`, `transitioning`, `class`, `struct`, `enum`, `const`, and the inclusion of various header files (`builtins-regexp-gen.h`, `objects/`) stand out. This suggests the file is defining low-level types, functions, and constants used within the V8 engine, particularly related to built-in functionalities.

2. **Header File Analysis (Clue Identification):**  The included header files provide strong clues about the file's purpose.
    * `builtins-regexp-gen.h`:  Indicates involvement with regular expressions.
    * `builtins-utils-gen.h`: Suggests general utility functions for built-ins.
    * `builtins.h`: Confirms it's about built-in functions.
    * `codegen/code-factory.h`: Points to code generation aspects.
    * `heap/factory-inl.h`:  Relates to object allocation on the heap.
    * `objects/...`: A long list of object-related headers signifies definitions and manipulations of various JavaScript object types (arguments, bigint, functions, promises, etc.).
    * `torque/runtime-support.h`:  Implies interaction with the Torque framework's runtime environment.

3. **Type Definition Analysis:**  The `type` declarations are crucial.
    *  Basic types like `void`, `never`, `IntegerLiteral`.
    *  Core V8 types like `Tagged`, `StrongTagged`, `Smi`, `HeapObject`, `WeakHeapObject`. The hierarchy and relationships are important (e.g., `Smi` extends `StrongTagged`, which extends `Tagged`).
    *  JavaScript-related types like `PropertyKey`, `JSPrimitive`, `JSAny`, `JSReceiver`. This establishes the connection to the JavaScript language.
    *  Numeric types (`int32`, `uint32`, `float64`, `BigInt`).
    *  Specialized types like `BuiltinsName`, `UseCounterFeature`.
    *  The `Lazy<T>` type is interesting, suggesting deferred execution or computation.

4. **Macro and Intrinsic Analysis:**  These define reusable code blocks and interactions with the underlying C++ implementation.
    *  Weak reference manipulation (`MakeWeak`, `GetHeapObjectAssumeWeak`, `StrongToWeak`, `WeakToStrong`).
    *  Type conversions and checks (`MaybeObjectToStrong`, `IsWeakOrCleared`, `IsStrong`).
    *  Runtime functions (`IncrementUseCounter`).
    *  The `%RawDownCast` intrinsic signifies unsafe type casting, highlighting the low-level nature.
    *  The `Lazy` intrinsics (`%MakeLazy`, `RunLazy`) are used for creating and executing lazy computations.

5. **Structure, Class, and Enum Analysis:**
    * `struct float64_or_hole`: Defines a structure that can represent either a floating-point number or a "hole" (a special value).
    * `class JSInternalPrototypeBase` and its derived classes (`JSObjectPrototype`, `JSRegExpPrototype`, etc.):  Represents the prototype chain structure in JavaScript.
    * `class HashTable` and its subclasses: Defines the structure of hash tables used internally.
    * `enum` declarations (`UpdateFeedbackMode`, `CallFeedbackContent`, `UnicodeEncoding`, `PromiseState`, `ElementsKind`, `AllocationFlag`, etc.):  Define sets of named constants used for various internal states and options.

6. **Constant Analysis:** The `const` declarations define various constants used throughout the V8 engine. These include:
    *  Sizes (`kTaggedSize`, `kDoubleSize`).
    *  Special values (`V8_INFINITY`, `MINUS_V8_INFINITY`).
    *  Element kind constants (`NO_ELEMENTS`, `PACKED_SMI_ELEMENTS`, etc.).
    *  Limits (`kArrayBufferMaxByteLength`, `kStringMaxLength`).
    *  Predefined objects (`TheHole`, `Null`, `Undefined`, `True`, `False`, `kEmptyString`).
    *  String constants for common property names and symbols (`kLengthString`, `kIteratorSymbol`).

7. **Transitioning Macro and Builtin Analysis:**  The `transitioning macro` and `transitioning builtin` keywords indicate functions that might involve state transitions or interactions with the runtime. Examples include:
    * Type conversion functions (`ToIntegerImpl`, `ToNumber`).
    * Property access functions (`GetProperty`, `SetProperty`).
    * Error throwing functions (`ThrowRangeError`, `ThrowTypeError`).
    * Object creation functions (`ArraySpeciesCreate`, `ArrayCreate`).

8. **Operator Overloading Analysis:**  The `operator` declarations show how various operators are overloaded for V8's internal types. This is crucial for efficient and type-aware operations.

9. **Inferring Functionality:** Based on the types, macros, builtins, and constants, we can start to infer the overall functionality. This file seems to provide:
    * **Fundamental type definitions** for representing JavaScript values and internal V8 objects.
    * **Low-level operations** on these types, including memory manipulation (weak references), type conversions, and comparisons.
    * **Constants** that define the engine's behavior and limits.
    * **Basic building blocks** for implementing JavaScript built-in functions.
    * **Mechanisms for handling different data representations** (e.g., SMI, HeapObject, various element kinds for arrays).
    * **Support for error handling and control flow** (labels, `never` type).

10. **Connecting to JavaScript:**  The presence of `JSAny`, `JSPrimitive`, `JSReceiver`, and the object-related header files directly links this code to JavaScript's type system. The provided JavaScript examples illustrate how the concepts defined in this file manifest in user-level JavaScript code.

11. **Identifying Potential Errors:** The type constraints and explicit error throwing macros hint at potential programming errors. Examples like type mismatches, invalid array lengths, and calling non-callable objects are easily inferred.

12. **Structuring the Summary:** Finally, organize the findings into a coherent summary, covering the main areas: overall purpose, relationship to JavaScript, code logic (with examples), and common programming errors. Using headings and bullet points improves readability. The distinction between "definitions of types and constants" and "macros and builtins providing functionality" is a helpful way to structure the technical details.
这是一个V8 Torque源代码文件，主要定义了在V8引擎的builtins（内置函数）实现中使用的**基础类型、常量、宏和内置函数声明**。它的功能可以概括为：

**核心功能：为V8 builtins 提供底层的类型系统和操作支持。**

具体来说，它做了以下几件事：

1. **定义了 Torque 类型:**  引入了 V8 内部使用的各种类型，包括基础类型（如 `void`, `never`, `IntegerLiteral`），Tagged 指针类型（如 `Tagged`, `StrongTagged`, `Smi`），堆对象类型 (`HeapObject`)，以及 JavaScript 语言层面的类型（如 `JSPrimitive`, `JSAny`, `JSReceiver`）。这些类型定义了 builtins 代码中可以操作的数据种类。

2. **定义了常量:**  声明了大量的常量，包括字面量（如 `kZero`, `kNaN`, `true`, `false`），字符串常量（如 `kLengthString`, `kMessageString`），以及与 V8 内部机制相关的常量（如 `kTaggedSize`, `kDoubleSize`, `ElementsKind` 的各种值）。这些常量在 builtins 的实现中被广泛使用。

3. **声明了宏 (macros):**  定义了许多用于简化代码和实现特定操作的宏。这些宏通常是对底层 C++ 代码的封装或抽象，例如：
    * 类型转换宏 (`StrongToWeak`, `WeakToStrong`, `MaybeObjectToStrong`)
    * 内存操作宏 (`MakeWeak`, `GetHeapObjectAssumeWeak`)
    * 类型判断宏 (`IsWeakOrCleared`, `IsStrong`)
    * 内置函数的辅助宏 (`ToIntegerImpl`, `ToNumber`)
    * 错误处理宏 (`ThrowRangeError`, `ThrowTypeError`)
    * 对象操作宏 (`ArraySpeciesCreate`, `ArrayCreate`)
    * 数值运算和比较宏 (`SmiAdd`, `Float64Equal`, `NumberIsLessThan`)

4. **声明了内置函数 (builtins):**  声明了将在 Torque 代码中调用的内置函数，这些内置函数通常由 C++ 实现。例如：
    * 类型转换内置函数 (`ToInteger`)
    * 属性操作内置函数 (`SetProperty`, `DeleteProperty`, `HasProperty`)
    * 对象操作内置函数 (`ToObject`)
    * 字符串操作内置函数 (`StringLessThan`, `StringCompare`, `StringAdd_CheckNone`)
    * 底层运行时函数 (`IncrementUseCounter`, `Throw`)

5. **定义了结构体 (struct) 和枚举 (enum):**  定义了用于组织数据的结构体（如 `float64_or_hole`）和枚举类型（如 `PromiseState`, `ElementsKind`, `AllocationFlag`），这些用于表示 V8 内部的状态和配置。

6. **定义了外部类 (extern class):**  声明了在 Torque 代码中使用的 V8 内部的 C++ 类，例如 `JSObject`, `String`, `Array`, `Map` 等，以及它们的继承关系。

**与 JavaScript 的关系：**

这个文件定义的类型、常量和函数是 V8 引擎实现 JavaScript 语言特性的基础。许多这里定义的类型直接对应 JavaScript 的类型，或者用于表示 JavaScript 对象的内部结构。

**JavaScript 例子：**

* **类型:** `JSAny` 可以表示任何 JavaScript 值。例如，在 JavaScript 中：
  ```javascript
  let x = 10; // x 可以被认为是 JSAny
  let y = "hello"; // y 也可以被认为是 JSAny
  let obj = {}; // obj 同样是 JSAny
  ```

* **常量:** `kLengthString` 对应 JavaScript 中对象的 `length` 属性名。例如：
  ```javascript
  const arr = [1, 2, 3];
  console.log(arr.length); // 这里会用到 'length' 这个字符串
  ```

* **宏和内置函数:** `ToInteger` 宏和内置函数实现了 JavaScript 的 `ToInteger` 抽象操作。例如：
  ```javascript
  console.log(parseInt(3.14)); // JavaScript 引擎内部会调用类似 ToInteger 的操作
  console.log(3.9 >> 0);     // 位运算也会隐式地使用 ToInteger
  ```

* **枚举 `ElementsKind`:**  描述了 JavaScript 数组的不同元素类型存储方式。例如，当一个数组只包含整数时，V8 可能会使用 `PACKED_SMI_ELEMENTS` 来优化存储。
  ```javascript
  const integers = [1, 2, 3]; // 内部可能使用 PACKED_SMI_ELEMENTS
  const mixed = [1, "a", {}]; // 内部可能使用 PACKED_ELEMENTS
  const doubles = [1.1, 2.2];  // 内部可能使用 PACKED_DOUBLE_ELEMENTS
  ```

**代码逻辑推理与假设输入输出：**

考虑 `ToIntegerImpl` 宏，它的作用是将一个 `JSAny` 类型的值转换为一个整数 `Number` 类型。

**假设输入：** 一个 `JSAny` 类型的 JavaScript 值。

* **输入 1:**  `Smi` 类型的 `3`
    * **输出:** `Smi` 类型的 `3` (直接返回)

* **输入 2:** `HeapNumber` 类型的 `3.14`
    * **内部逻辑:** 将 `3.14` 截断为整数 `3`。
    * **输出:** `Smi` 类型的 `3`

* **输入 3:** `HeapNumber` 类型的 `NaN`
    * **内部逻辑:** `Float64IsNaN(value)` 返回 `true`，返回 `SmiConstant(0)`。
    * **输出:** `Smi` 类型的 `0`

* **输入 4:** `String` 类型的 `"10"`
    * **内部逻辑:** `conversion::NonNumberToNumber(a)` 会将字符串转换为数字 `10`。
    * **输出:** `Smi` 类型的 `10`

**用户常见的编程错误：**

* **类型错误:**  在 JavaScript 中，错误地假设变量的类型会导致 builtins 代码中进行类型转换或检查时抛出异常。例如，尝试对非对象调用需要对象的方法，可能会触发 `ThrowTypeError`。
  ```javascript
  let str = "hello";
  // 错误地尝试调用对象的属性方法
  // str.hasOwnProperty('length'); // 实际上可以直接访问 str.length
  ```

* **超出范围的访问:** 访问数组或字符串时，索引超出范围，可能会触发类似 `ThrowRangeError` 的错误。
  ```javascript
  const arr = [1, 2];
  console.log(arr[2]); //  访问了不存在的索引
  ```

* **调用非函数:** 尝试调用一个非函数的值，会触发 `ThrowTypeError`。
  ```javascript
  let notAFunction = 10;
  notAFunction(); // TypeError: notAFunction is not a function
  ```

**总结:**

`v8/src/builtins/base.tq` 是 V8 引擎 builtins 实现的基石，它定义了构建和操作 JavaScript 运行时环境所需的底层类型、常量和操作。理解这个文件的内容有助于深入理解 V8 引擎的工作原理以及 JavaScript 语言特性的实现方式。

### 提示词
```
这是目录为v8/src/builtins/base.tq的一个v8 torque源代码， 请归纳一下它的功能, 
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be:
// Context found in the LICENSE file.

#include 'src/builtins/builtins-regexp-gen.h'
#include 'src/builtins/builtins-utils-gen.h'
#include 'src/builtins/builtins.h'
#include 'src/codegen/code-factory.h'
#include 'src/heap/factory-inl.h'
#include 'src/objects/arguments.h'
#include 'src/objects/bigint.h'
#include 'src/objects/call-site-info.h'
#include 'src/objects/elements-kind.h'
#include 'src/objects/free-space.h'
#include 'src/objects/js-atomics-synchronization.h'
#include 'src/objects/js-disposable-stack.h'
#include 'src/objects/js-function.h'
#include 'src/objects/js-generator.h'
#include 'src/objects/js-iterator-helpers.h'
#include 'src/objects/js-promise.h'
#include 'src/objects/js-regexp-string-iterator.h'
#include 'src/objects/js-shadow-realm.h'
#include 'src/objects/js-shared-array.h'
#include 'src/objects/js-struct.h'
#include 'src/objects/js-weak-refs.h'
#include 'src/objects/objects.h'
#include 'src/objects/source-text-module.h'
#include 'src/objects/synthetic-module.h'
#include 'src/objects/template-objects.h'
#include 'src/torque/runtime-support.h'

type void;
type never;

type IntegerLiteral constexpr 'IntegerLiteral';

type Tagged generates 'TNode<MaybeObject>' constexpr 'MaybeObject';
type StrongTagged extends Tagged
    generates 'TNode<Object>' constexpr 'Object';
type Smi extends StrongTagged generates 'TNode<Smi>' constexpr 'Smi';
type TaggedIndex extends StrongTagged
    generates 'TNode<TaggedIndex>' constexpr 'TaggedIndex';
// A possibly cleared weak pointer with a bit pattern that distinguishes it from
// strong HeapObject pointers and Smi values.
type WeakHeapObject extends Tagged;
type Weak<T : type extends HeapObject> extends WeakHeapObject;

type Object = Smi|HeapObject;
type MaybeObject = Smi|HeapObject|WeakHeapObject;

// A Smi that is greater than or equal to 0. See TaggedIsPositiveSmi.
type PositiveSmi extends Smi;

// The Smi value zero, which is often used as null for HeapObject types.
type Zero extends PositiveSmi;
// A tagged value represented by an all-zero bitpattern.
type TaggedZeroPattern extends TaggedIndex;

// A value with the size of Tagged which may contain arbitrary data.
type Uninitialized extends Tagged;

type BuiltinsName extends int31 constexpr 'Builtin';

type UseCounterFeature extends int31
    constexpr 'v8::Isolate::UseCounterFeature';

extern macro MakeWeak(HeapObject): WeakHeapObject;
extern macro GetHeapObjectAssumeWeak(MaybeObject): HeapObject labels IfCleared;
extern macro GetHeapObjectIfStrong(MaybeObject): HeapObject labels IfNotStrong;
extern macro IsWeakOrCleared(MaybeObject): bool;
extern macro IsWeakReferenceToObject(MaybeObject, Object): bool;
extern macro IsStrong(MaybeObject): bool;
extern runtime IncrementUseCounter(Context, Smi): void;

macro StrongToWeak<T: type>(x: T): Weak<T> {
  return %RawDownCast<Weak<T>>(MakeWeak(x));
}
macro WeakToStrong<T: type>(x: Weak<T>): T labels ClearedWeakPointer {
  const x = GetHeapObjectAssumeWeak(x) otherwise ClearedWeakPointer;
  return %RawDownCast<T>(x);
}

macro MaybeObjectToStrong(maybeObject: MaybeObject):
    HeapObject labels IfCleared {
  dcheck(IsWeakOrCleared(maybeObject));
  const weakObject = %RawDownCast<Weak<HeapObject>>(maybeObject);
  return WeakToStrong(weakObject) otherwise IfCleared;
}

// Defined to coincide with https://tc39.es/ecma262/#sec-ispropertykey
// Doesn't include PrivateSymbol.
type PropertyKey = String|PublicSymbol;

// TODO(turbofan): PrivateSymbol is only exposed to JavaScript through the
// debugger API. We should reconsider this and try not to expose it at all. Then
// JSAny would not need to contain it.

// A JavaScript primitive value as defined in
// https://tc39.es/ecma262/#sec-primitive-value.
type JSPrimitive = Numeric|String|Symbol|Boolean|Null|Undefined;

// A user-exposed JavaScript value, as opposed to V8-internal values like Holes
// or a FixedArray.
type JSAny = JSPrimitive|JSReceiver;

type JSAnyNotNumeric = String|Symbol|Boolean|Null|Undefined|JSReceiver;
type JSAnyNotNumber = BigInt|JSAnyNotNumeric;

// This is the intersection of JSAny and HeapObject.
type JSAnyNotSmi = JSAnyNotNumber|HeapNumber;

type int32 generates 'TNode<Int32T>' constexpr 'int32_t';
type uint32 generates 'TNode<Uint32T>' constexpr 'uint32_t';
type int31 extends int32
    generates 'TNode<Int32T>' constexpr 'int31_t';
type uint31 extends uint32
    generates 'TNode<Uint32T>' constexpr 'uint32_t';
type int16 extends int31
    generates 'TNode<Int16T>' constexpr 'int16_t';
type uint16 extends uint31
    generates 'TNode<Uint16T>' constexpr 'uint16_t';
type int8 extends int16 generates 'TNode<Int8T>' constexpr 'int8_t';
type uint8 extends uint16
    generates 'TNode<Uint8T>' constexpr 'uint8_t';
type char8 extends uint8 constexpr 'char';
type char16 extends uint16 constexpr 'char16_t';
type int64 generates 'TNode<Int64T>' constexpr 'int64_t';
type uint64 generates 'TNode<Uint64T>' constexpr 'uint64_t';
type intptr generates 'TNode<IntPtrT>' constexpr 'intptr_t';
type uintptr generates 'TNode<UintPtrT>' constexpr 'uintptr_t';
type float16_raw_bits
    generates 'TNode<Float16RawBitsT>' constexpr 'uint16_t';
type float32 generates 'TNode<Float32T>' constexpr 'float';
type float64 generates 'TNode<Float64T>' constexpr 'double';
type bool generates 'TNode<BoolT>' constexpr 'bool';
type bint generates 'TNode<BInt>' constexpr 'BInt';
type string constexpr 'const char*';
type DispatchHandle generates 'TNode<JSDispatchHandleT>';

type Simd128 generates 'TNode<Simd128T>';
type I8X16 extends Simd128 generates 'TNode<I8x16T>';

// Represents a std::function which produces the generated TNode type of T.
// Useful for passing values to and from CSA code that uses LazyNode<T>, which
// is a typedef for std::function<TNode<T>()>. Can be created with %MakeLazy and
// accessed with RunLazy.
type Lazy<T: type>;

// Makes a Lazy. The first parameter is the name of a macro, which is looked up
// in the context where %MakeLazy is called, as a workaround for the fact that
// macros can't be used as values directly. The other parameters are saved and
// passed to the macro when somebody runs the resulting Lazy object. Torque
// syntax doesn't allow for arbitrary-length generic macros, but the internals
// support any number of parameters, so if you need more parameters, feel free
// to add additional declarations here.
intrinsic %MakeLazy<T: type>(getter: constexpr string): Lazy<T>;
intrinsic %MakeLazy<T: type, A1: type>(
    getter: constexpr string, arg1: A1): Lazy<T>;
intrinsic %MakeLazy<T: type, A1: type, A2: type>(
    getter: constexpr string, arg1: A1, arg2: A2): Lazy<T>;
intrinsic %MakeLazy<T: type, A1: type, A2: type, A3: type>(
    getter: constexpr string, arg1: A1, arg2: A2, arg3: A3): Lazy<T>;

// Executes a Lazy and returns the result. The CSA-side definition is a
// template, but Torque doesn't understand how to use templates for extern
// macros, so just add whatever overload definitions you need here.
extern macro RunLazy(Lazy<Smi>): Smi;
extern macro RunLazy(Lazy<JSAny>): JSAny;

// A Smi value containing a bitfield struct as its integer data.
@useParentTypeChecker type SmiTagged<T : type extends uint31> extends Smi;

// WARNING: The memory representation (i.e., in class fields and arrays) of
// float64_or_hole is just a float64 that may be the hole-representing
// signalling NaN bit-pattern. So it's memory size is that of float64 and
// loading and storing float64_or_hole emits special code.
struct float64_or_hole {
  macro Value(): float64 labels IfHole {
    if (this.is_hole) {
      goto IfHole;
    }
    return this.value;
  }
  macro ValueUnsafeAssumeNotHole(): float64 {
    dcheck(!this.is_hole);
    return this.value;
  }

  is_hole: bool;
  value: float64;
}
const kDoubleHole: float64_or_hole = float64_or_hole{is_hole: true, value: 0};

@doNotGenerateCast
@abstract
extern class JSInternalPrototypeBase extends JSObject
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSObjectPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSRegExpPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSPromisePrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSTypedArrayPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSSetPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSIteratorPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSArrayIteratorPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSMapIteratorPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSSetIteratorPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';
@doNotGenerateCast
extern class JSStringIteratorPrototype extends JSInternalPrototypeBase
    generates 'TNode<JSObject>';

// The HashTable inheritance hierarchy doesn't actually look like this in C++
// because it uses some class templates that we can't yet (and may never)
// express in Torque, but this is the expected organization of instance types.
@doNotGenerateCast
extern class HashTable extends FixedArray generates 'TNode<FixedArray>';
extern class OrderedHashMap extends HashTable;
extern class OrderedHashSet extends HashTable;
extern class OrderedNameDictionary extends HashTable;
extern class NameToIndexHashTable extends HashTable;
extern class RegisteredSymbolTable extends HashTable;
extern class NameDictionary extends HashTable;
extern class GlobalDictionary extends HashTable;
extern class SimpleNumberDictionary extends HashTable;
extern class EphemeronHashTable extends HashTable;
type ObjectHashTable extends HashTable
    generates 'TNode<ObjectHashTable>' constexpr 'ObjectHashTable';
extern class NumberDictionary extends HashTable;

type RawPtr generates 'TNode<RawPtrT>' constexpr 'Address';
type RawPtr<To: type> extends RawPtr;
type ExternalPointer
    generates 'TNode<ExternalPointerT>' constexpr 'ExternalPointer_t';
type CppHeapPointer
    generates 'TNode<CppHeapPointerT>' constexpr 'CppHeapPointer_t';
type TrustedPointer
    generates 'TNode<TrustedPointerT>' constexpr 'TrustedPointer_t';
type TrustedPointer<To : type extends ExposedTrustedObject> extends
    TrustedPointer;
type ProtectedPointer extends Tagged;
type ProtectedPointer<To : type extends TrustedObject> extends ProtectedPointer;
extern class InstructionStream extends TrustedObject;
type BuiltinPtr extends Smi generates 'TNode<BuiltinPtr>';

type Number = Smi|HeapNumber;
type Numeric = Number|BigInt;

extern class TransitionArray extends WeakFixedArray;

extern operator '.length_intptr' macro LoadAndUntagWeakFixedArrayLength(
    WeakFixedArray): intptr;

type InstanceType extends uint16 constexpr 'InstanceType';

type NoSharedNameSentinel extends Smi;

// Specialized types. The following three type definitions don't correspond to
// actual C++ classes, but have Is... methods that check additional constraints.

// A Foreign object whose raw pointer is not allowed to be null.
type NonNullForeign extends Foreign;

// A function built with InstantiateFunction for the public API.
type CallableApiObject extends JSObject;

// A JSProxy with the callable bit set.
type CallableJSProxy extends JSProxy;

type Callable = JSFunction|JSBoundFunction|JSWrappedFunction|CallableJSProxy|
    CallableApiObject;

type WriteBarrierMode
    generates 'TNode<Int32T>' constexpr 'WriteBarrierMode';

extern enum UpdateFeedbackMode {
  kOptionalFeedback,
  kGuaranteedFeedback,
  kNoFeedback
}
extern operator '==' macro UpdateFeedbackModeEqual(
    constexpr UpdateFeedbackMode, constexpr UpdateFeedbackMode): constexpr bool;

extern enum CallFeedbackContent extends int32 { kTarget, kReceiver }

extern enum UnicodeEncoding { UTF16, UTF32 }

// Promise constants
extern enum PromiseState extends int31 constexpr 'Promise::PromiseState' {
  kPending,
  kFulfilled,
  kRejected
}

const kTaggedSize: constexpr int31 generates 'kTaggedSize';
const kDoubleSize: constexpr int31 generates 'kDoubleSize';
const kVariableSizeSentinel:
    constexpr int31 generates 'kVariableSizeSentinel';

const kSmiTagSize: constexpr int31 generates 'kSmiTagSize';
const kHeapObjectTag: constexpr int31 generates 'kHeapObjectTag';
const V8_INFINITY: constexpr float64 generates 'V8_INFINITY';
const MINUS_V8_INFINITY: constexpr float64 generates '-V8_INFINITY';

extern enum ElementsKind extends int32 {
  NO_ELEMENTS,

  PACKED_SMI_ELEMENTS,
  HOLEY_SMI_ELEMENTS,
  PACKED_ELEMENTS,
  HOLEY_ELEMENTS,
  PACKED_DOUBLE_ELEMENTS,
  HOLEY_DOUBLE_ELEMENTS,
  LAST_ANY_NONEXTENSIBLE_ELEMENTS_KIND,
  DICTIONARY_ELEMENTS,

  UINT8_ELEMENTS,
  INT8_ELEMENTS,
  UINT16_ELEMENTS,
  INT16_ELEMENTS,
  UINT32_ELEMENTS,
  INT32_ELEMENTS,
  FLOAT16_ELEMENTS,
  FLOAT32_ELEMENTS,
  FLOAT64_ELEMENTS,
  UINT8_CLAMPED_ELEMENTS,
  BIGUINT64_ELEMENTS,
  BIGINT64_ELEMENTS,
  RAB_GSAB_UINT8_ELEMENTS,
  RAB_GSAB_INT8_ELEMENTS,
  RAB_GSAB_UINT16_ELEMENTS,
  RAB_GSAB_INT16_ELEMENTS,
  RAB_GSAB_UINT32_ELEMENTS,
  RAB_GSAB_INT32_ELEMENTS,
  RAB_GSAB_FLOAT16_ELEMENTS,
  RAB_GSAB_FLOAT32_ELEMENTS,
  RAB_GSAB_FLOAT64_ELEMENTS,
  RAB_GSAB_UINT8_CLAMPED_ELEMENTS,
  RAB_GSAB_BIGUINT64_ELEMENTS,
  RAB_GSAB_BIGINT64_ELEMENTS,
  // TODO(torque): Allow duplicate enum values.
  // FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  // FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  ...
}

const kFirstFixedTypedArrayElementsKind: constexpr ElementsKind =
    ElementsKind::UINT8_ELEMENTS;
const kFirstRabGsabFixedTypedArrayElementsKind: constexpr ElementsKind =
    ElementsKind::RAB_GSAB_UINT8_ELEMENTS;

extern enum AllocationFlag extends int32
    constexpr 'CodeStubAssembler::AllocationFlag' {
  kNone,
  kDoubleAlignment,
  kPretenured
}

extern enum SlackTrackingMode
    constexpr 'CodeStubAssembler::SlackTrackingMode' {
  kWithSlackTracking,
  kNoSlackTracking,
  kDontInitializeInObjectProperties
}

extern enum ExtractFixedArrayFlag
    constexpr 'CodeStubAssembler::ExtractFixedArrayFlag' {
  kFixedDoubleArrays,
  kAllFixedArrays,
  kFixedArrays,
  ...
}

const kBigIntMaxLengthBits:
    constexpr uintptr generates 'BigInt::kMaxLengthBits';
const kBigIntMaxLength: constexpr intptr generates 'BigInt::kMaxLength';
const kBigIntDigitSize: constexpr intptr generates 'kSystemPointerSize';
const kBitsPerByte: constexpr intptr generates 'kBitsPerByte';
const kBigIntDigitBits: intptr = kBigIntDigitSize * kBitsPerByte;

extern enum MessageTemplate {
  kAllPromisesRejected,
  kInvalid,
  kInvalidArrayBufferLength,
  kInvalidArrayLength,
  kInvalidIndex,
  kInvalidTypedArrayIndex,
  kNotConstructor,
  kNotGeneric,
  kCalledNonCallable,
  kCalledOnNullOrUndefined,
  kCannotConvertToPrimitive,
  kProtoObjectOrNull,
  kInvalidOffset,
  kInvalidTypedArrayLength,
  kFirstArgumentIteratorSymbolNonCallable,
  kIteratorValueNotAnObject,
  kNotIterable,
  kReduceNoInitial,
  kFirstArgumentNotRegExp,
  kBigIntMixedTypes,
  kTypedArrayTooShort,
  kTypedArrayTooLargeToSort,
  kInvalidCountValue,
  kConstructAbstractClass,
  kConstructorNotFunction,
  kSymbolToString,
  kSymbolIteratorInvalid,
  kPropertyNotFunction,
  kBigIntTooBig,
  kBigIntDivZero,
  kNotTypedArray,
  kDetachedOperation,
  kBadSortComparisonFunction,
  kIncompatibleMethodReceiver,
  kInvalidDataViewAccessorOffset,
  kTypedArraySetOffsetOutOfBounds,
  kInvalidArgument,
  kInvalidRegExpExecResult,
  kInvalidSizeValue,
  kRegExpNonRegExp,
  kRegExpNonObject,
  kPromiseNonCallable,
  kPromiseNewTargetUndefined,
  kResolverNotAFunction,
  kTooManyElementsInPromiseCombinator,
  kToRadixFormatRange,
  kCalledOnNonObject,
  kRegExpGlobalInvokedOnNonGlobal,
  kProxyNonObject,
  kProxyRevoked,
  kProxyTrapReturnedFalsishFor,
  kProxyPrivate,
  kProxyIsExtensibleInconsistent,
  kProxyPreventExtensionsExtensible,
  kProxyTrapReturnedFalsish,
  kProxyGetPrototypeOfInvalid,
  kProxyGetPrototypeOfNonExtensible,
  kProxySetPrototypeOfNonExtensible,
  kProxyDeletePropertyNonExtensible,
  kUndefinedOrNullToObject,
  kWeakRefsCleanupMustBeCallable,
  kWasmTrapUnreachable,
  kWasmTrapMemOutOfBounds,
  kWasmTrapUnalignedAccess,
  kWasmTrapDivByZero,
  kWasmTrapDivUnrepresentable,
  kWasmTrapRemByZero,
  kWasmTrapFloatUnrepresentable,
  kWasmTrapFuncSigMismatch,
  kWasmTrapDataSegmentOutOfBounds,
  kWasmTrapElementSegmentOutOfBounds,
  kWasmTrapJSTypeError,
  kWasmTrapTableOutOfBounds,
  kWasmTrapRethrowNull,
  kWasmTrapNullDereference,
  kWasmTrapIllegalCast,
  kWasmTrapArrayOutOfBounds,
  kWasmTrapArrayTooLarge,
  kWasmTrapStringOffsetOutOfBounds,
  kWasmObjectsAreOpaque,
  kWeakRefsRegisterTargetAndHoldingsMustNotBeSame,
  kInvalidWeakRefsRegisterTarget,
  kInvalidWeakRefsUnregisterToken,
  kInvalidWeakRefsWeakRefConstructorTarget,
  kObjectGetterCallable,
  kObjectSetterCallable,
  kPropertyDescObject,
  kMustBePositive,
  kIteratorReduceNoInitial,
  kSizeIsNaN,
  kArgumentIsNonObject,
  kKeysMethodInvalid,
  kGeneratorRunning,
  kFirstArgumentAsyncIteratorSymbolNonCallable,
  kIteratorResultNotAnObject,
  kFlattenPastSafeLength,
  kStrictReadOnlyProperty,
  kInvalidUsingInForInLoop,
  kIllegalInvocation,
  ...
}

extern enum PropertyAttributes extends int31 {
  NONE,
  READ_ONLY,
  DONT_ENUM,
  DONT_DELETE,
  ALL_ATTRIBUTES_MASK,
  FROZEN,
  ...
}

const kArrayBufferMaxByteLength:
    constexpr uintptr generates 'JSArrayBuffer::kMaxByteLength';
const kMaxTypedArrayInHeap:
    constexpr int31 generates 'JSTypedArray::kMaxSizeInHeap';
// CSA does not support 64-bit types on 32-bit platforms so as a workaround the
// kMaxSafeIntegerUint64 is defined as uintptr and allowed to be used only
// inside if constexpr (Is64()) i.e. on 64-bit architectures.
const kMaxSafeIntegerUint64: constexpr uintptr
    generates 'CodeStubAssembler::MaxSafeIntegerUintPtr()';
const kMaxSafeInteger: constexpr float64 generates 'kMaxSafeInteger';
const kMaxUInt32Double: constexpr float64 generates 'kMaxUInt32Double';
const kSmiMaxValue: constexpr uintptr generates 'kSmiMaxValue';
const kSmiMax: uintptr = kSmiMaxValue;
// TODO(v8:8996): Use uintptr version instead and drop this one.
const kStringMaxLength: constexpr int31 generates 'String::kMaxLength';
const kStringMaxLengthUintptr:
    constexpr uintptr generates 'String::kMaxLength';
const kFixedArrayMaxLength:
    constexpr int31 generates 'FixedArray::kMaxLength';
const kFixedDoubleArrayMaxLength:
    constexpr int31 generates 'FixedDoubleArray::kMaxLength';
const kObjectAlignmentMask: constexpr intptr
    generates 'kObjectAlignmentMask';
const kObjectAlignment: constexpr intptr
    generates 'kObjectAlignment';
const kMinAddedElementsCapacity:
    constexpr int31 generates 'JSObject::kMinAddedElementsCapacity';
const kMaxFastArrayLength:
    constexpr int31 generates 'JSArray::kMaxFastArrayLength';
const kMaxCopyElements:
    constexpr int31 generates 'JSArray::kMaxCopyElements';
const kMaxRegularHeapObjectSize: constexpr int31
    generates 'kMaxRegularHeapObjectSize';

const kMaxNewSpaceFixedArrayElements: constexpr int31
    generates 'FixedArray::kMaxRegularLength';

extern enum PrimitiveType { kString, kBoolean, kSymbol, kNumber }

const kNameDictionaryInitialCapacity:
    constexpr int32 generates 'NameDictionary::kInitialCapacity';
const kSwissNameDictionaryInitialCapacity:
    constexpr int32 generates 'SwissNameDictionary::kInitialCapacity';

const kWasmArrayHeaderSize:
    constexpr int32 generates 'WasmArray::kHeaderSize';

const kHeapObjectHeaderSize:
    constexpr int32 generates 'HeapObject::kHeaderSize';

type TheHole extends Hole;
type PromiseHole extends Hole;
type Exception extends Oddball;
type EmptyString extends String;

type NumberOrUndefined = Number|Undefined;

extern macro ConstructorStringConstant(): String;
extern macro DefaultStringConstant(): String;
extern macro DisposeSymbolConstant(): String;
extern macro EmptyStringConstant(): EmptyString;
extern macro ErrorStringConstant(): String;
extern macro ErrorsStringConstant(): String;
extern macro FalseConstant(): False;
extern macro GetStringConstant(): String;
extern macro HasStringConstant(): String;
extern macro Int32FalseConstant(): bool;
extern macro Int32TrueConstant(): bool;
extern macro IteratorStringConstant(): String;
extern macro IteratorSymbolConstant(): PublicSymbol;
extern macro KeysStringConstant(): String;
extern macro AsyncIteratorSymbolConstant(): PublicSymbol;
extern macro LengthStringConstant(): String;
extern macro MatchSymbolConstant(): Symbol;
extern macro MessageStringConstant(): String;
extern macro NanConstant(): NaN;
extern macro NameStringConstant(): String;
extern macro NextStringConstant(): String;
extern macro NullConstant(): Null;
extern macro NumberStringConstant(): String;
extern macro objectStringConstant(): String;
extern macro ReturnStringConstant(): String;
extern macro SearchSymbolConstant(): Symbol;
extern macro SizeStringConstant(): String;
extern macro StringStringConstant(): String;
extern macro SuppressedStringConstant(): String;
extern macro TheHoleConstant(): TheHole;
extern macro PromiseHoleConstant(): PromiseHole;
extern macro ToPrimitiveSymbolConstant(): PublicSymbol;
extern macro ToStringStringConstant(): String;
extern macro ToStringTagSymbolConstant(): PublicSymbol;
extern macro TrueConstant(): True;
extern macro UndefinedConstant(): Undefined;
extern macro ValueOfStringConstant(): String;
extern macro InvalidDispatchHandleConstant(): DispatchHandle;

const TheHole: TheHole = TheHoleConstant();
const PromiseHole: PromiseHole = PromiseHoleConstant();
const Null: Null = NullConstant();
const Undefined: Undefined = UndefinedConstant();
const True: True = TrueConstant();
const False: False = FalseConstant();
const kEmptyString: EmptyString = EmptyStringConstant();
const kLengthString: String = LengthStringConstant();
const kMessageString: String = MessageStringConstant();
const kNextString: String = NextStringConstant();
const kReturnString: String = ReturnStringConstant();
const kSizeString: String = SizeStringConstant();
const kHasString: String = HasStringConstant();
const kKeysString: String = KeysStringConstant();

const kNaN: NaN = NanConstant();
const kZero: Zero = %RawDownCast<Zero>(SmiConstant(0));
const kZeroBitPattern: TaggedZeroPattern = %RawDownCast<TaggedZeroPattern>(
    Convert<Tagged>(BitcastWordToTaggedSigned(Convert<intptr>(0))));

const true: constexpr bool generates 'true';
const false: constexpr bool generates 'false';

extern enum LanguageMode extends bool { kStrict, kSloppy }
type LanguageModeSmi extends Smi;

// Dispatch handle constant used when tailcalling into C++ builtins. As these
// currently don't use the dispatch handle parameter, we can just use a constant
// here. Alternatively, we could obtain the "real" dispatch handle (the one used
// for calling the torque builtin) through a new CSA function that accesses the
// kJSCallDispatchHandle parameter.
const kInvalidDispatchHandle: DispatchHandle = InvalidDispatchHandleConstant();

const SKIP_WRITE_BARRIER:
    constexpr WriteBarrierMode generates 'SKIP_WRITE_BARRIER';
const UNSAFE_SKIP_WRITE_BARRIER:
    constexpr WriteBarrierMode generates 'UNSAFE_SKIP_WRITE_BARRIER';

extern transitioning macro AllocateJSIteratorResult(
    implicit context: Context)(JSAny, Boolean): JSObject;

extern class Filler extends HeapObject generates 'TNode<HeapObject>';

// Various logical subclasses of JSObject, which have their own instance types
// but not their own class definitions:

// Like JSObject, but created from API function.
@apiExposedInstanceTypeValue(0x422)
@doNotGenerateCast
extern class JSApiObject extends JSAPIObjectWithEmbedderSlots
    generates 'TNode<JSObject>';

// TODO(gsathya): This only exists to make JSApiObject instance type into a
// range.
@apiExposedInstanceTypeValue(0x80A)
@doNotGenerateCast
@highestInstanceTypeWithinParentClassRange
extern class JSLastDummyApiObject extends JSApiObject
    generates 'TNode<JSObject>';

// Like JSApiObject, but requires access checks and/or has interceptors.
@apiExposedInstanceTypeValue(0x410)
extern class JSSpecialApiObject extends JSSpecialObject
    generates 'TNode<JSSpecialObject>';
extern class JSContextExtensionObject extends JSObject
    generates 'TNode<JSObject>';
extern class JSError extends JSObject generates 'TNode<JSObject>';

extern macro Is64(): constexpr bool;

extern macro SelectBooleanConstant(bool): Boolean;

extern macro Print(constexpr string): void;
extern macro Print(constexpr string, Object): void;
extern macro Print(Object): void;
extern macro Print(constexpr string, uintptr): void;
extern macro Print(constexpr string, float64): void;
extern macro PrintErr(constexpr string): void;
extern macro PrintErr(constexpr string, Object): void;
extern macro PrintErr(Object): void;
extern macro Comment(constexpr string): void;
extern macro DebugBreak(): void;

extern macro SetSupportsDynamicParameterCount(
    JSFunction, DispatchHandle): void;

// ES6 7.1.4 ToInteger ( argument )
transitioning macro ToIntegerImpl(
    implicit context: Context)(input: JSAny): Number {
  let input = input;

  while (true) {
    typeswitch (input) {
      case (s: Smi): {
        return s;
      }
      case (hn: HeapNumber): {
        let value = Convert<float64>(hn);
        if (Float64IsNaN(value)) return SmiConstant(0);
        value = math::Float64Trunc(value);
        // ToInteger normalizes -0 to +0.
        if (value == 0) return SmiConstant(0);
        const result = ChangeFloat64ToTagged(value);
        dcheck(IsNumberNormalized(result));
        return result;
      }
      case (a: JSAnyNotNumber): {
        input = conversion::NonNumberToNumber(a);
      }
    }
  }
  unreachable;
}

transitioning builtin ToInteger(
    implicit context: Context)(input: JSAny): Number {
  return ToIntegerImpl(input);
}

@export
transitioning macro ToInteger_Inline(
    implicit context: Context)(input: JSAny): Number {
  typeswitch (input) {
    case (s: Smi): {
      return s;
    }
    case (JSAny): {
      return ToInteger(input);
    }
  }
}

extern macro ToBigInt(Context, JSAny): BigInt;

extern enum BigIntHandling extends int32
    constexpr 'CodeStubAssembler::BigIntHandling' { kConvertToNumber, kThrow }

extern transitioning macro ToNumber(
    implicit context: Context)(JSAny, constexpr BigIntHandling): Number;

extern transitioning macro ToLength_Inline(
    implicit context: Context)(JSAny): Number;
extern transitioning macro ToNumber_Inline(
    implicit context: Context)(JSAny): Number;
extern transitioning macro ToString_Inline(
    implicit context: Context)(JSAny): String;
extern transitioning macro ToThisString(
    implicit context: Context)(JSAny, String): String;
extern transitioning macro ToThisValue(
    implicit context: Context)(JSAny, constexpr PrimitiveType,
    constexpr string): JSAny;
extern transitioning macro GetProperty(
    implicit context: Context)(JSAny, JSAny): JSAny;
extern macro IsInterestingProperty(Name): bool;
extern macro GetInterestingProperty(Context, JSReceiver, Name): JSAny
    labels NotFound;
extern transitioning builtin SetProperty(
    implicit context: Context)(JSAny, JSAny, JSAny): JSAny;
extern transitioning builtin SetPropertyIgnoreAttributes(
    implicit context: Context)(JSObject, String, JSAny, Smi): JSAny;
extern transitioning builtin CreateDataProperty(
    implicit context: Context)(JSAny, JSAny, JSAny): JSAny;
extern transitioning builtin DeleteProperty(
    implicit context: Context)(JSAny, JSAny|PrivateSymbol,
    LanguageModeSmi): Boolean;
extern transitioning builtin HasProperty(
    implicit context: Context)(JSAny, JSAny): Boolean;
extern transitioning macro HasProperty_Inline(
    implicit context: Context)(JSReceiver, JSAny): Boolean;
extern builtin LoadIC(
    Context, JSAny, JSAny, TaggedIndex, FeedbackVector): JSAny;

extern macro SetPropertyStrict(Context, Object, Object, Object): Object;

extern macro ThrowRangeError(
    implicit context: Context)(constexpr MessageTemplate): never;
extern macro ThrowRangeError(
    implicit context: Context)(constexpr MessageTemplate, Object): never;
extern macro ThrowRangeError(
    implicit context: Context)(constexpr MessageTemplate, Object,
    Object): never;
extern macro ThrowTypeError(
    implicit context: Context)(constexpr MessageTemplate): never;
extern macro ThrowTypeError(
    implicit context: Context)(constexpr MessageTemplate,
    constexpr string): never;
extern macro ThrowTypeError(
    implicit context: Context)(constexpr MessageTemplate, Object): never;
extern macro ThrowTypeError(
    implicit context: Context)(constexpr MessageTemplate, Object,
    Object): never;
extern macro ThrowTypeError(
    implicit context: Context)(constexpr MessageTemplate, Object, Object,
    Object): never;
extern transitioning runtime ThrowTypeErrorIfStrict(
    implicit context: Context)(Smi, Object, Object): void;
extern transitioning runtime ThrowIteratorError(
    implicit context: Context)(JSAny): never;
extern transitioning runtime ThrowCalledNonCallable(
    implicit context: Context)(JSAny): never;

extern transitioning macro ThrowIfNotJSReceiver(
    implicit context: Context)(JSAny, constexpr MessageTemplate,
    constexpr string): void;

extern macro TerminateExecution(implicit context: Context)(): never;

extern macro ArraySpeciesCreate(Context, JSAny, Number): JSReceiver;
extern macro ArrayCreate(implicit context: Context)(Number): JSArray;
extern macro BuildAppendJSArray(
    constexpr ElementsKind, FastJSArray, JSAny): void labels Bailout;

extern macro EnsureArrayPushable(implicit context: Context)(Map): ElementsKind
    labels Bailout;
// TODO: Reduce duplication once varargs are supported in macros.
extern macro Construct(implicit context: Context)(Constructor): JSReceiver;
extern macro Construct(
    implicit context: Context)(Constructor, JSAny): JSReceiver;
extern macro Construct(
    implicit context: Context)(Constructor, JSAny, JSAny): JSReceiver;
extern macro Construct(
    implicit context: Context)(Constructor, JSAny, JSAny, JSAny): JSReceiver;
extern macro ConstructWithTarget(
    implicit context: Context)(Constructor, JSReceiver): JSReceiver;
extern macro ConstructWithTarget(
    implicit context: Context)(Constructor, JSReceiver, JSAny): JSReceiver;
extern macro SpeciesConstructor(
    implicit context: Context)(JSAny, JSReceiver): JSReceiver;

extern macro ConstructorBuiltinsAssembler::IsDictionaryMap(Map): bool;
extern macro CodeStubAssembler::AllocateNameDictionary(constexpr int32):
    NameDictionary;
extern macro CodeStubAssembler::AllocateNameDictionary(intptr): NameDictionary;
extern macro CodeStubAssembler::AllocateNameDictionary(
    intptr, constexpr AllocationFlag): NameDictionary;
extern macro CodeStubAssembler::AllocateOrderedNameDictionary(constexpr int32):
    OrderedNameDictionary;
extern macro CodeStubAssembler::AllocateSwissNameDictionary(constexpr int32):
    SwissNameDictionary;

extern macro CodeStubAssembler::AddToDictionary(
    NameDictionary, Name, Object): void labels Bailout;
extern macro CodeStubAssembler::AddToDictionary(
    SwissNameDictionary, Name, Object): void labels Bailout;

extern macro AllocateOrderedHashSet(): OrderedHashSet;
extern macro AllocateOrderedHashMap(): OrderedHashMap;

extern builtin ToObject(Context, JSAny): JSReceiver;
extern macro ToObject_Inline(Context, JSAny): JSReceiver;
extern macro IsUndefined(Object): bool;
extern macro IsNullOrUndefined(Object): bool;
extern macro IsString(HeapObject): bool;
extern transitioning builtin NonPrimitiveToPrimitive_String(
    Context, JSAny): JSPrimitive;
extern transitioning builtin NonPrimitiveToPrimitive_Default(
    Context, JSAny): JSPrimitive;

transitioning macro ToPrimitiveDefault(
    implicit context: Context)(v: JSAny): JSPrimitive {
  typeswitch (v) {
    case (v: JSReceiver): {
      return NonPrimitiveToPrimitive_Default(context, v);
    }
    case (v: JSPrimitive): {
      return v;
    }
  }
}

extern transitioning runtime NormalizeElements(Context, JSObject): void;
extern transitioning runtime TransitionElementsKindWithKind(
    Context, JSObject, Smi): void;

extern macro ArrayListElements(ArrayList): FixedArray;

extern macro LoadObjectField(HeapObject, constexpr int32): Object;

extern macro LoadBufferObject(RawPtr, constexpr int32): Object;
extern macro LoadBufferPointer(RawPtr, constexpr int32): RawPtr;
extern macro LoadBufferSmi(RawPtr, constexpr int32): Smi;
extern macro LoadBufferIntptr(RawPtr, constexpr int32): intptr;

extern runtime StringEqual(Context, String, String): Oddball;
extern builtin StringLessThan(String, String): Boolean;
extern builtin StringCompare(String, String): Smi;
extern macro StringCharCodeAt(String, uintptr): char16;
extern macro StringFromSingleCharCode(char8): String;
extern macro StringFromSingleCharCode(char16): String;

extern macro NumberToString(Number): String;
extern macro StringToNumber(String): Number;
extern transitioning macro NonNumberToNumber(
    implicit context: Context)(JSAnyNotNumber): Number;
extern transitioning macro NonNumberToNumeric(
    implicit context: Context)(JSAnyNotNumber): Numeric;

extern macro Equal(JSAny, JSAny, Context): Boolean;
macro Equal(implicit context: Context)(left: JSAny, right: JSAny): Boolean {
  return Equal(left, right);
}

extern macro StrictEqual(JSAny, JSAny): Boolean;
extern macro SmiLexicographicCompare(Smi, Smi): Smi;

extern runtime ReThrowWithMessage(
    Context, JSAny, TheHole|JSMessageObject): never;
extern runtime Throw(implicit context: Context)(JSAny): never;
extern runtime ThrowInvalidStringLength(Context): never;

extern operator '==' macro WordEqual(RawPtr, RawPtr): bool;
extern operator '!=' macro WordNotEqual(RawPtr, RawPtr): bool;
extern operator '+' macro RawPtrAdd(RawPtr, intptr): RawPtr;
extern operator '+' macro RawPtrAdd(intptr, RawPtr): RawPtr;

extern operator '<' macro Int32LessThan(int32, int32): bool;
extern operator '<' macro Uint32LessThan(uint32, uint32): bool;
extern operator '>' macro Int32GreaterThan(int32, int32): bool;
extern operator '>' macro Uint32GreaterThan(uint32, uint32): bool;
extern operator '<=' macro Int32LessThanOrEqual(int32, int32): bool;
extern operator '<=' macro Uint32LessThanOrEqual(uint32, uint32): bool;
extern operator '>=' macro Int32GreaterThanOrEqual(int32, int32): bool;
extern operator '>=' macro Uint32GreaterThanOrEqual(uint32, uint32): bool;

extern operator '==' macro SmiEqual(Smi, Smi): bool;
extern operator '!=' macro SmiNotEqual(Smi, Smi): bool;
extern operator '<' macro SmiLessThan(Smi, Smi): bool;
extern operator '<=' macro SmiLessThanOrEqual(Smi, Smi): bool;
extern operator '>' macro SmiGreaterThan(Smi, Smi): bool;
extern operator '>=' macro SmiGreaterThanOrEqual(Smi, Smi): bool;

extern operator '==' macro ElementsKindEqual(
    constexpr ElementsKind, constexpr ElementsKind): constexpr bool;
extern operator '==' macro ElementsKindEqual(ElementsKind, ElementsKind): bool;
operator '!=' macro ElementsKindNotEqual(
    k1: ElementsKind, k2: ElementsKind): bool {
  return !ElementsKindEqual(k1, k2);
}
extern macro IsElementsKindLessThanOrEqual(
    ElementsKind, constexpr ElementsKind): bool;
extern macro IsElementsKindGreaterThan(
    ElementsKind, constexpr ElementsKind): bool;
extern macro IsElementsKindGreaterThanOrEqual(
    ElementsKind, constexpr ElementsKind): bool;
extern macro IsElementsKindInRange(
    ElementsKind, constexpr ElementsKind, constexpr ElementsKind): bool;

extern macro IsFastElementsKind(constexpr ElementsKind): constexpr bool;
extern macro IsFastPackedElementsKind(constexpr ElementsKind): constexpr bool;
extern macro IsDoubleElementsKind(constexpr ElementsKind): constexpr bool;

extern macro GetNonRabGsabElementsKind(ElementsKind): ElementsKind;

extern macro IsFastAliasedArgumentsMap(implicit context: Context)(Map): bool;
extern macro IsSlowAliasedArgumentsMap(implicit context: Context)(Map): bool;
extern macro IsSloppyArgumentsMap(implicit context: Context)(Map): bool;
extern macro IsStrictArgumentsMap(implicit context: Context)(Map): bool;
extern macro IsTuple2Map(Map): bool;

extern macro SmiAbove(Smi, Smi): bool;

extern operator '==' macro WordEqual(intptr, intptr): bool;
extern operator '==' macro WordEqual(uintptr, uintptr): bool;
extern operator '!=' macro WordNotEqual(intptr, intptr): bool;
extern operator '!=' macro WordNotEqual(uintptr, uintptr): bool;
extern operator '<' macro IntPtrLessThan(intptr, intptr): bool;
extern operator '<' macro UintPtrLessThan(uintptr, uintptr): bool;
extern operator '>' macro IntPtrGreaterThan(intptr, intptr): bool;
extern operator '>' macro UintPtrGreaterThan(uintptr, uintptr): bool;
extern operator '<=' macro IntPtrLessThanOrEqual(intptr, intptr): bool;
extern operator '<=' macro UintPtrLessThanOrEqual(uintptr, uintptr): bool;
extern operator '>=' macro IntPtrGreaterThanOrEqual(intptr, intptr): bool;
extern operator '>=' macro UintPtrGreaterThanOrEqual(uintptr, uintptr): bool;
extern operator '~' macro WordNot(intptr): intptr;
extern operator '~' macro WordNot(uintptr): uintptr;
extern operator '~' macro Word32BitwiseNot(int32): int32;
extern operator '~' macro Word64Not(uint64): uint64;
extern operator '~' macro Word64Not(int64): int64;
extern operator '~' macro ConstexprWordNot(constexpr intptr): constexpr intptr;
extern operator '~' macro ConstexprWordNot(constexpr uintptr):
    constexpr uintptr;

extern operator '==' macro Float64Equal(float64, float64): bool;
extern operator '!=' macro Float64NotEqual(float64, float64): bool;
extern operator '>' macro Float64GreaterThan(float64, float64): bool;
extern operator '>=' macro Float64GreaterThanOrEqual(float64, float64): bool;
extern operator '<' macro Float64LessThan(float64, float64): bool;
extern operator '<=' macro Float64LessThanOrEqual(float64, float64): bool;
extern macro Float64AlmostEqual(float64, float64, constexpr float64): bool;

extern macro BranchIfNumberEqual(Number, Number): never
    labels Taken, NotTaken;
operator '==' macro IsNumberEqual(a: Number, b: Number): bool {
  BranchIfNumberEqual(a, b) otherwise return true, return false;
}
operator '!=' macro IsNumberNotEqual(a: Number, b: Number): bool {
  return !(a == b);
}
extern macro BranchIfNumberLessThan(Number, Number): never
    labels Taken, NotTaken;
operator '<' macro NumberIsLessThan(a: Number, b: Number): bool {
  BranchIfNumberLessThan(a, b) otherwise return true, return false;
}
extern macro BranchIfNumberLessThanOrEqual(Number, Number): never
    labels Taken, NotTaken;
operator '<=' macro NumberIsLessThanOrEqual(a: Number, b: Number): bool {
  BranchIfNumberLessThanOrEqual(a, b) otherwise return true, return false;
}

operator '>' macro NumberIsGreaterThan(a: Number, b: Number): bool {
  return b < a;
}
operator '>=' macro NumberIsGreaterThanOrEqual(a: Number, b: Number): bool {
  return b <= a;
}

extern macro BranchIfFloat64IsNaN(float64): never
    labels Taken, NotTaken;
macro Float64IsNaN(n: float64): bool {
  BranchIfFloat64IsNaN(n) otherwise return true, return false;
}

// The type of all tagged values that can safely be compared with TaggedEqual.
@if(V8_ENABLE_WEBASSEMBLY)
  type TaggedWithIdentity = JSReceiver|FixedArrayBase|Oddball|Hole|Map|WeakCell|
      Context|EmptyString|Symbol|FunctionTemplateInfo|WasmFuncRef|WasmNull;
@ifnot(V8_ENABLE_WEBASSEMBLY)
  type TaggedWithIdentity = JSReceiver|FixedArrayBase|Oddball|Hole|Map|WeakCell|
      Context|EmptyString|Symbol|FunctionTemplateInfo;

extern operator '==' macro TaggedEqual(TaggedWithIdentity, Object): bool;
extern operator '==' macro TaggedEqual(Object, TaggedWithIdentity): bool;
extern operator '==' macro TaggedEqual(
    TaggedWithIdentity, TaggedWithIdentity): bool;
extern operator '==' macro TaggedEqual(WeakHeapObject, WeakHeapObject): bool;
extern operator '!=' macro TaggedNotEqual(TaggedWithIdentity, Object): bool;
extern operator '!=' macro TaggedNotEqual(Object, TaggedWithIdentity): bool;
extern operator '!=' macro TaggedNotEqual(
    TaggedWithIdentity, TaggedWithIdentity): bool;
extern operator '!=' macro TaggedNotEqual(WeakHeapObject, WeakHeapObject): bool;
// Do not overload == and != if it is unclear if object identity is the right
// equality.
extern macro TaggedEqual(MaybeObject, MaybeObject): bool;
extern macro TaggedNotEqual(MaybeObject, MaybeObject): bool;

extern operator '+' macro SmiAdd(Smi, Smi): Smi;
extern operator '-' macro SmiSub(Smi, Smi): Smi;
extern operator '&' macro SmiAnd(Smi, Smi): Smi;
extern operator '|' macro SmiOr(Smi, Smi): Smi;
extern operator '<<' macro SmiShl(Smi, constexpr int31): Smi;
extern operator '>>' macro SmiSar(Smi, constexpr int31): Smi;

extern operator '+' macro IntPtrAdd(intptr, intptr): intptr;
extern operator '+' macro ConstexprIntPtrAdd(
    constexpr intptr, constexpr intptr): constexpr intptr;
extern operator '+' macro ConstexprUintPtrAdd(
    constexpr uintptr, constexpr uintptr): constexpr intptr;
extern operator '+' macro Int64Add(int64, int64): int64;
extern operator '-' macro IntPtrSub(intptr, intptr): intptr;
extern operator '-' macro Int64Sub(int64, int64): int64;
extern operator '*' macro IntPtrMul(intptr, intptr): intptr;
extern operator '*' macro Int64Mul(int64, int64): int64;
extern operator '/' macro IntPtrDiv(intptr, intptr): intptr;
extern operator '/' macro Int64Div(int64, int64): int64;
extern operator '%' macro IntPtrMod(intptr, intptr): intptr;
extern operator '%' macro Int64Mod(int64, int64): int64;
extern operator '<<' macro WordShl(intptr, intptr): intptr;
extern operator '>>' macro WordSar(intptr, intptr): intptr;
extern operator '&' macro WordAnd(intptr, intptr): intptr;
extern operator '|' macro WordOr(intptr, intptr): intptr;

extern operator '+' macro UintPtrAdd(uintptr, uintptr): uintptr;
extern operator '+' macro Uint64Add(uint64, uint64): uint64;
extern operator '-' macro UintPtrSub(uintptr, uintptr): uintptr;
extern operator '-' macro Uint64Sub(uint64, uint64): uint64;
extern operator '*' macro Uint64Mul(uint64, uint64): uint64;
extern operator '<<' macro WordShl(uintptr, uintptr): uintptr;
extern operator '>>>' macro WordShr(uintptr, uintptr): uintptr;
extern operator '&' macro WordAnd(uintptr, uintptr): uintptr;
extern operator '|' macro WordOr(uintptr, uintptr): uintptr;

extern operator '+' macro Int32Add(int32, int32): int32;
extern operator '+' macro Uint32Add(uint32, uint32): uint32;
extern operator '+' macro ConstexprUint32Add(
    constexpr uint32, constexpr int32): constexpr uint32;
extern operator '+' macro ConstexprInt31Add(
    constexpr int31, constexpr int31): constexpr int31;
extern operator '+' macro ConstexprInt32Add(
    constexpr int32, constexpr int32): constexpr int32;
extern operator '*' macro ConstexprInt31Mul(
    constexpr int31, constexpr int31): constexpr int31;
extern operator '-' macro Int32Sub(int16, int16): int32;
extern operator '-' macro Int32Sub(int32, int32): int32;
extern operator '-' macro Uint32Sub(uint32, uint32): uint32;
extern operator '*' macro Int32Mul(int32, int32): int32;
extern operator '*' macro Uint32Mul(uint32, uint32): uint32;
extern operator '/' macro Int32Div(int32, int32): int32;
extern operator '/' macro Uint32Div(uint32, uint32): uint32;
extern operator '%' macro Int32Mod(int32, int32): int32;
extern operator '%' macro Uint32Mod(uint32, uint32): uint32;
extern operator '&' macro Word32And(int32, int32): int32;
extern operator '&' macro Word32And(uint32, uint32): uint32;
extern operator '==' macro ConstexprInt31Equal(
    constexpr int31, constexpr int31): constexpr bool;
extern operator '!=' macro ConstexprInt31NotEqual(
    constexpr int31, constexpr int31): constexpr bool;
extern operator '==' macro ConstexprUint32Equal(
    constexpr uint32, constexpr uint32): constexpr bool;
extern operator '!=' macro ConstexprUint32NotEqual(
    constexpr uint32, constexpr uint32): constexpr bool;
extern operator '>=' macro ConstexprInt31GreaterThanEqual(
    constexpr int31, constexpr int31): constexpr bool;
extern operator '==' macro ConstexprInt32Equal(
    constexpr int32, constexpr int32): constexpr bool;
extern operator '!=' macro ConstexprInt32NotEqual(
    constexpr int32, constexpr int32): constexpr bool;

// IntegerLiteral overloads
extern macro ConstexprIntegerLiteralToInt31(constexpr IntegerLiteral):
    constexpr int31;
extern macro ConstexprIntegerLiteralToInt32(constexpr IntegerLiteral):
    constexpr int32;
extern macro ConstexprIntegerLiteralToUint32(constexpr IntegerLiteral):
    constexpr uint32;
extern macro ConstexprIntegerLiteralToInt64(constexpr IntegerLiteral):
    constexpr int64;
extern macro ConstexprIntegerLiteralToUint64(constexpr IntegerLiteral):
    constexpr uint64;
extern macro ConstexprIntegerLiteralToIntptr(constexpr IntegerLiteral):
    constexpr intptr;
extern macro ConstexprIntegerLiteralToUintptr(constexpr IntegerLiteral):
    constexpr uintptr;
extern macro ConstexprIntegerLiteralToInt8(constexpr IntegerLiteral):
    constexpr int8;
extern macro ConstexprIntegerLiteralToUint8(constexpr IntegerLiteral):
    constexpr uint8;
extern macro ConstexprIntegerLiteralToFloat64(constexpr IntegerLiteral):
    constexpr float64;

extern operator '==' macro ConstexprIntegerLiteralEqual(
    constexpr IntegerLiteral, constexpr IntegerLiteral): constexpr bool;
extern operator '+' macro ConstexprIntegerLiteralAdd(
    constexpr IntegerLiteral,
    constexpr IntegerLiteral): constexpr IntegerLiteral;
extern operator '<<' macro ConstexprIntegerLiteralLeftShift(
    constexpr IntegerLiteral,
    constexpr IntegerLiteral): constexpr IntegerLiteral;
extern operator '|' macro ConstexprIntegerLiteralBitwiseOr(
    constexpr IntegerLiteral,
    constexpr IntegerLiteral): constexpr IntegerLiteral;

extern operator '==' macro Word32Equal(int32, int32): bool;
extern operator '==' macro Word32Equal(uint32, uint32): bool;
extern operator '!=' macro Word32NotEqual(int32, int32): bool;
extern operator '!=' macro Word32NotEqual(uint32, uint32): bool;
extern operator '>>>' macro Word32Shr(uint32, uint32): uint32;
extern operator '>>' macro Word32Sar(int32, int32): int32;
extern operator '<<' macro Word32Shl(int32, int32): int32;
extern operator '<<' macro Word32Shl(uint32, uint32): uint32;
extern operator '|' macro Word32Or(int32, int32): int32;
extern operator '|' macro Word32Or(uint32, uint32): uint32;
extern operator '&' macro Word32And(bool, bool): bool;
extern operator '|' macro Word32Or(bool, bool): bool;
extern operator '==' macro Word32Equal(bool, bool): bool;
extern operator '!=' macro Word32NotEqual(bool, bool): bool;
extern operator '|' macro ConstexprWord32Or(
    constexpr int32, constexpr int32): constexpr int32;
extern operator '^' macro Word32Xor(int32, int32): int32;
extern operator '^' macro Word32Xor(uint32, uint32): uint32;
extern operator '<<' macro ConstexprWord32Shl(
    constexpr uint32, constexpr int32): uint32;

extern operator '==' macro Word64Equal(int64, int64): bool;
extern operator '==' macro Word64Equal(uint64, uint64): bool;
extern operator '!=' macro Word64NotEqual(int64, int64): bool;
extern operator '!=' macro Word64NotEqual(uint64, uint64): bool;
extern operator '>>>' macro Word64Shr(uint64, uint64): uint64;
extern operator '>>' macro Word64Sar(int64, int64): int64;
extern operator '<<' macro Word64Shl(int64, int64): int64;
extern operator '<<' macro Word64Shl(uint64, uint64): uint64;
extern operator '|' macro Word64Or(int64, int64): int64;
extern operator '|' macro Word64Or(uint64, uint64): uint64;
extern operator '&' macro Word64And(uint64, uint64): uint64;
extern operator '^' macro Word64Xor(int64, int64): int64;
extern operator '^' macro Word64Xor(uint64, uint64): uint64;

extern operator '+' macro Float64Add(float64, float64): float64;
extern operator '-' macro Float64Sub(float64, float64): float64;
extern operator '*' macro Float64Mul(float64, float64): float64;
extern operator '/' macro Float64Div(float64, float64): float64;
extern operator '%' macro Float64Mod(float64, float64): float64;

extern operator '+' macro NumberAdd(Number, Number): Number;
extern operator '-' macro NumberSub(Number, Number): Number;
extern macro NumberMin(Number, Number): Number;
extern macro NumberMax(Number, Number): Number;
macro Min(x: Number, y: Number): Number {
  return NumberMin(x, y);
}
macro Max(x: Number, y: Number): Number {
  return NumberMax(x, y);
}

extern macro TryIntPtrAdd(intptr, intptr): intptr labels Overflow;
extern macro TryIntPtrSub(intptr, intptr): intptr labels Overflow;
extern macro TryInt32Mul(int32, int32): int32 labels Overflow;

extern operator '<' macro ConstexprUintPtrLessThan(
    constexpr uintptr, constexpr uintptr): constexpr bool;
extern operator '<<' macro ConstexprUintPtrShl(
    constexpr uintptr, constexpr int31): constexpr uintptr;
extern operator '>>>' macro ConstexprUintPtrShr(
    constexpr uintptr, constexpr int31): constexpr uintptr;

extern macro SmiMax(Smi, Smi): Smi;
extern macro SmiMin(Smi, Smi): Smi;
extern macro SmiMul(Smi, Smi): Number;
extern macro SmiMod(Smi, Smi): Number;

extern macro IntPtrMax(intptr, intptr): intptr;
extern macro IntPtrMin(intptr, intptr): intptr;
extern macro UintPtrMin(uintptr, uintptr): uintptr;

extern operator '!' macro ConstexprBoolNot(constexpr bool): constexpr bool;
extern operator '!' macro Word32BinaryNot(bool): bool;
extern operator '!' macro IsFalse(Boolean): bool;

extern operator '==' macro ConstexprInt31Equal(
    constexpr InstanceType, constexpr InstanceType): constexpr bool;
extern operator '-' macro ConstexprUint32Sub(
    constexpr InstanceType, constexpr InstanceType): constexpr int32;
extern operator '-' macro ConstexprInt32Sub(
    constexpr int32, constexpr int32): constexpr int32;

extern operator '.instanceType' macro LoadInstanceType(HeapObject):
    InstanceType;

operator '.length_uintptr' macro LoadJSArrayLengthAsUintPtr(array: JSArray):
    uintptr {
  return Convert<uintptr>(array.length);
}

extern operator '.length_intptr' macro LoadStringLengthAsWord(String): intptr;
operator '.length_uintptr' macro LoadStringLengthAsUintPtr(s: String): uintptr {
  return Unsigned(s.length_intptr);
}
extern operator '.length_uint32' macro LoadStringLengthAsWord32(String): uint32;
extern operator '.length_smi' macro LoadStringLengthAsSmi(String): Smi;

extern builtin StringAdd_CheckNone(
    implicit context: Context)(String, String): String;
operator '+' macro StringAdd(
    implicit context: Context)(a: String, b: String): String {
  return StringAdd_CheckNone(a, b);
}

operator '==' macro PromiseStateEquals(
    s1: PromiseState, s2: PromiseState): bool {
  return Word32Equal(s1, s2);
}

extern macro CountLeadingZeros64(uint64): int64;
extern macro CountTrailingZeros32(uint32): int32;
extern macro CountTrailingZeros64(uint64): int64;

extern macro TaggedIsSmi(Object): bool;
extern macro TaggedIsNotSmi(Object): bool;
extern macro TaggedIsPositiveSmi(Object): bool;
extern macro IsValidPositiveSmi(intptr): bool;

extern macro IsInteger(JSAny): bool;
extern macro IsInteger(HeapNumber): bool;

extern macro AllocateHeapNumberWithValue(float64): HeapNumber;
extern macro ChangeInt32ToTagged(int32): Number;
extern macro ChangeUint32ToTagged(uint32): Number;
extern macro ChangeUintPtrToFloat64(uintptr): float64;
extern macro ChangeUintPtrToTagged(uintptr): Number;
extern macro Unsigned(int64): uint64;
extern macro Unsigned(int32): uint32;
extern macro Unsigned(int16): uint16;
extern macro Unsigned(int8): uint8;
extern macro Unsigned(intptr): uintptr;
extern macro Unsigned(RawPtr): uintptr;
extern macro Signed(uint64): int64;
extern macro Signed(uint32): int32;
extern macro Signed(uint16): int16;
extern macro Signed(uint8): int8;
extern macro Signed(uintptr): intptr;
extern macro Signed(RawPtr): intptr;
extern macro TruncateIntPtrToInt32(intptr): int32;
extern macro TruncateInt64ToInt32(int64): int32;
extern macro SmiTag(intptr): Smi;
extern macro SmiFromInt32(int32): Smi;
extern macro SmiFromUint32(uint32): Smi;
extern macro SmiFromIntPtr(intptr): Smi;
extern macro SmiUntag(Smi): intptr;
macro SmiUntag<T: type>(value: SmiTagged<T>): T {
  return %RawDownCast<T>(Unsigned(SmiToInt32(Convert<Smi>(value))));
}
macro SmiTag<T : type extends uint31>(value: T): SmiTagged<T> {
  return %RawDownCast<SmiTagged<T>>(SmiFromUint32(value));
}
extern macro SmiToInt32(Smi): int32;
extern macro SmiToFloat64(Smi): float64;
extern macro TaggedIndexToIntPtr(TaggedIndex): intptr;
extern macro IntPtrToTaggedIndex(intptr): TaggedIndex;
extern macro TaggedIndexToSmi(TaggedIndex): Smi;
extern macro SmiToTaggedIndex(Smi): TaggedIndex;
extern macro RoundIntPtrToFloat64(intptr): float64;
extern macro IntPtrRoundUpToPowerOfTwo32(intptr): intptr;
extern macro ChangeFloat32ToFloat64(float32): float64;
extern macro RoundInt32ToFloat32(int32): float32;
extern macro ChangeNumberToFloat64(Number): float64;
extern macro ChangeTaggedNonSmiToInt32(
    implicit context: Context)(HeapObject): int32;
extern macro ChangeFloat16ToFloat64(float16_raw_bits): float64;
extern macro ChangeFloat32ToTagged(float32): Number;
extern macro ChangeTaggedToFloat64(implicit context: Context)(JSAny): float64;
extern macro ChangeFloat64ToTagged(float64): Number;
extern macro ChangeFloat64ToUintPtr(float64): uintptr;
extern macro ChangeFloat64ToIntPtr(float64): intptr;
extern macro ChangeBoolToInt32(bool): int32;
extern macro ChangeInt32ToFloat64(int32): float64;
extern macro ChangeInt32ToIntPtr(int32): intptr;  // Sign-extends.
extern macro ChangeUint32ToWord(uint32): uintptr;  // Doesn't sign-extend.
extern macro ChangeInt32ToInt64(int32): int64;  // Sign-extends.
extern macro ChangeUint32ToUint64(uint32): uint64;  // Doesn't sign-extend.
extern macro LoadNativeContext(Context): NativeContext;
extern macro TruncateFloat64ToFloat16(float64): float16_raw_bits;
extern macro TruncateFloat32ToFloat16(float32): float16_raw_bits;
extern macro TruncateFloat64ToFloat32(float64): float32;
extern macro TruncateHeapNumberValueToWord32(HeapNumber): int32;
extern macro LoadJSArrayElementsMap(
    constexpr ElementsKind, NativeContext): Map;
extern macro LoadJSArrayElementsMap(ElementsKind, NativeContext): Map;
extern macro NumberConstant(constexpr float64): Number;
extern macro NumberConstant(constexpr int32): Number;
extern macro NumberConstant(constexpr uint32): Number;
extern macro IntPtrConstant(constexpr int31): intptr;
extern macro IntPtrConstant(constexpr int32): intptr;
extern macro Uint16Constant(constexpr uint16): uint16;
extern macro Int32Constant(constexpr int31): int31;
extern macro Int32Constant(constexpr int32): int32;
macro Int32Constant(i: constexpr IntegerLiteral): int32 {
  return Int32Constant(ConstexprIntegerLiteralToInt32(i));
}
extern macro Int64Constant(constexpr int64): int64;
extern macro Uint64Constant(constexpr uint64): uint64;
extern macro Float64Constant(constexpr int32): float64;
extern macro Float64Constant(constexpr float64): float64;
extern macro Float64Constant(constexpr IntegerLiteral): float64;
extern macro SmiConstant(constexpr int31): Smi;
extern macro SmiConstant(constexpr Smi): Smi;
extern macro SmiConstant(constexpr MessageTemplate): Smi;
extern macro SmiConstant(constexpr bool): Smi;
extern macro SmiConstant(constexpr uint32): Smi;
macro SmiConstant(il: constexpr IntegerLiteral): Smi {
  return SmiConstant(ConstexprIntegerLiteralToInt31(il));
}
extern macro BoolConstant(constexpr bool): bool;
extern macro StringConstant(constexpr string): String;
extern macro IntPtrConstant(constexpr ContextSlot): ContextSlot;
extern macro IntPtrConstant(constexpr intptr): intptr;
macro IntPtrConstant(il: constexpr IntegerLiteral): intptr {
  return IntPtrConstant(ConstexprIntegerLiteralToIntptr(il));
}
extern macro PointerConstant(constexpr RawPtr): RawPtr;
extern macro SingleCharacterStringConstant(constexpr string): String;
extern macro Float64SilenceNaN(float64): float64;

extern macro BitcastFloat16ToUint32(float16_raw_bits): uint32;
extern macro BitcastUint32ToFloat16(uint32): float16_raw_bits;
extern macro BitcastWordToTaggedSigned(intptr): Smi;
extern macro BitcastWordToTaggedSigned(uintptr): Smi;
extern macro BitcastWordToTagged(intptr): Object;
extern macro BitcastWordToTagged(uintptr): Object;
extern macro BitcastWordToTagged(RawPtr): Object;
extern macro BitcastTaggedToWord(Object): intptr;
extern macro BitcastTaggedToWordForTagAndSmiBits(Tagged): intptr;

extern macro FixedArrayMapConstant(): Map;
extern macro FixedDoubleArrayMapConstant(): Map;
extern macro FixedCOWArrayMapConstant(): Map;
extern macro EmptyByteArrayConstant(): ByteArray;
extern macro EmptyFixedArrayConstant(): EmptyFixedArray;
extern macro PromiseCapabilityMapConstant(): Map;
extern macro SeqOneByteStringMapConstant(): Map;
extern macro SeqTwoByteStringMapConstant(): Map;
extern macro ConsOneByteStringMapConstant(): Map;
extern macro ConsTwoByteStringMapConstant(): Map;

const kFixedArrayMap: Map = FixedArrayMapConstant();
const kFixedDoubleArrayMap: Map = FixedDoubleArrayMapConstant();
const kCOWMap: Map = FixedCOWArrayMapConstant();
const kEmptyByteArray: ByteArray = EmptyByteArrayConstant();
const kEmptyFixedArray: EmptyFixedArray = EmptyFixedArrayConstant();
const kPromiseCapabilityMap: Map = PromiseCapabilityMapConstant();
// The map of a non-internalized internal SeqOneByteString.
const kSeqOneByteStringMap: Map = SeqOneByteStringMapConstant();
// The map of a non-internalized internal SeqTwoByteString.
const kSeqTwoByteStringMap: Map = SeqTwoByteStringMapConstant();
const kConsOneByteStringMap: Map = ConsOneByteStringMapConstant();
const kConsTwoByteStringMap: Map = ConsTwoByteStringMapConstant();

macro OutOfBounds<T: type, X: type>(index: T, length: X): bool {
  return UintPtrGreaterThanOrEqual(
      Convert<uintptr>(Convert<intptr>(index)),
      Convert<uintptr>(Convert<intptr>(length)));
}

extern macro IsPrototypeInitialArrayPrototype(
    implicit context: Context)(Map): bool;
extern macro IsNoElementsProtectorCellInvalid(): bool;
extern macro IsArrayIteratorProtectorCellInvalid(): bool;
extern macro IsArraySpeciesProtectorCellInvalid(): bool;
extern macro IsIsConcatSpreadableProtectorCellInvalid(): bool;
extern macro IsTypedArraySpeciesProtectorCellInvalid(): bool;
extern macro IsPromiseSpeciesProtectorCellInvalid(): bool;
extern macro IsMockArrayBufferAllocatorFlag(): bool;
extern macro HasBuiltinSubclassingFlag(): bool;
extern macro IsScriptContextMutableHeapNumberFlag(): bool;
extern macro IsPrototypeTypedArrayPrototype(
    implicit context: Context)(Map): bool;
extern macro IsSetIteratorProtectorCellInvalid(): bool;
extern macro IsMapIteratorProtectorCellInvalid(): bool;
extern macro InvalidateStringWrapperToPrimitiveProtector(): void;

extern operator '.data_ptr' macro LoadJSTypedArrayDataPtr(JSTypedArray): RawPtr;

extern operator '.elements_kind' macro LoadMapElementsKind(Map): ElementsKind;
extern operator '.elements_kind' macro LoadElementsKind(JSTypedArray):
    ElementsKind;

extern operator '.length' macro LoadFastJSArrayLength(FastJSArray): Smi;
operator '.length=' macro StoreFastJSArrayLength(
    array: FastJSArray, length: Smi): void {
  const array: JSArray = array;
  array.length = length;
}

extern macro GetNumberDictionaryNumberOfElements(NumberDictionary): Smi;

extern macro LoadConstructorOrBackPointer(Map): Object;

extern macro BasicLoadNumberDictionaryElement(NumberDictionary, intptr): JSAny
    labels NotData, IfHole;

extern macro IsFastElementsKind(ElementsKind): bool;
extern macro IsFastPackedElementsKind(ElementsKind): bool;
extern macro IsDoubleElementsKind(ElementsKind): bool;
extern macro IsFastSmiOrTaggedElementsKind(ElementsKind): bool;
extern macro IsFastSmiElementsKind(ElementsKind): bool;
extern macro IsHoleyFastElementsKind(ElementsKind): bool;

macro FastHoleyElementsKind(kind: ElementsKind): ElementsKind {
  if (kind == ElementsKind::PACKED_SMI_ELEMENTS) {
    return ElementsKind::HOLEY_SMI_ELEMENTS;
  } else if (kind == ElementsKind::PACKED_DOUBLE_ELEMENTS) {
    return ElementsKind::HOLEY_DOUBLE_ELEMENTS;
  }
  dcheck(kind == ElementsKind::PACKED_ELEMENTS);
  return ElementsKind::HOLEY_ELEMENTS;
}

macro AllowDoubleElements(kind: ElementsKind): ElementsKind {
  if (kind == ElementsKind::PACKED_SMI_ELEMENTS) {
    return ElementsKind::PACKED_DOUBLE_ELEMENTS;
  } else if (kind == ElementsKind::HOLEY_SMI_ELEMENTS) {
    return ElementsKind::HOLEY_DOUBLE_ELEMENTS;
  }
  return kind;
}

macro AllowNonNumberElements(kind: ElementsKind): ElementsKind {
  if (kind == ElementsKind::PACKED_SMI_ELEMENTS) {
    return ElementsKind::PACKED_ELEMENTS;
  } else if (kind == ElementsKind::HOLEY_SMI_ELEMENTS) {
    return ElementsKind::HOLEY_ELEMENTS;
  } else if (kind == ElementsKind::PACKED_DOUBLE_ELEMENTS) {
    return ElementsKind::PACKED_ELEMENTS;
  } else if (kind == ElementsKind::HOLEY_DOUBLE_ELEMENTS) {
    return ElementsKind::HOLEY_ELEMENTS;
  }
  return kind;
}

macro GetObjectFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::OBJECT_FUNCTION_INDEX);
}
macro GetArrayFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::ARRAY_FUNCTION_INDEX);
}
macro GetArrayBufferFunction(implicit context: Context)(): Constructor {
  return *NativeContextSlot(ContextSlot::ARRAY_BUFFER_FUN_INDEX);
}
macro GetArrayBufferNoInitFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::ARRAY_BUFFER_NOINIT_FUN_INDEX);
}
macro GetIteratorFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::ITERATOR_FUNCTION_INDEX);
}
macro GetStringFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::STRING_FUNCTION_INDEX);
}
macro GetFastPackedElementsJSArrayMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX);
}
macro GetFastPackedSmiElementsJSArrayMap(implicit context: Context)(): Map {
  return *NativeContextSlot(
      ContextSlot::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX);
}
macro GetProxyRevocableResultMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::PROXY_REVOCABLE_RESULT_MAP_INDEX);
}
macro GetIteratorResultMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::ITERATOR_RESULT_MAP_INDEX);
}
macro GetInitialStringIteratorMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::INITIAL_STRING_ITERATOR_MAP_INDEX);
}
macro GetReflectApply(implicit context: Context)(): Callable {
  return *NativeContextSlot(ContextSlot::REFLECT_APPLY_INDEX);
}
macro GetRegExpLastMatchInfo(implicit context: Context)(): RegExpMatchInfo {
  return *NativeContextSlot(ContextSlot::REGEXP_LAST_MATCH_INFO_INDEX);
}
macro GetStrictArgumentsMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::STRICT_ARGUMENTS_MAP_INDEX);
}
macro GetSloppyArgumentsMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::SLOPPY_ARGUMENTS_MAP_INDEX);
}
macro GetFastAliasedArgumentsMap(implicit context: Context)(): Map {
  return *NativeContextSlot(ContextSlot::FAST_ALIASED_ARGUMENTS_MAP_INDEX);
}
macro GetWeakCellMap(implicit context: Context)(): Map {
  return %GetClassMapConstant<WeakCell>();
}
macro GetPrototypeApplyFunction(implicit context: Context)(): JSFunction {
  return *NativeContextSlot(ContextSlot::FUNCTION_PROTOTYPE_APPLY_INDEX);
}
macro GetIteratorPrototype(implicit context: Context)(): JSObject {
  return *NativeContextSlot(ContextSlot::INITIAL_ITERATOR_PROTOTYPE_INDEX);
}

// Call(Context, Target, Receiver, ...Args)
// TODO(joshualitt): Assuming the context parameter is for throwing when Target
//                   is non-callable, then we should make it an implicit
//                   parameter.
extern transitioning macro Call(Context, JSAny, JSAny): JSAny;
extern transitioning macro Call(Context, JSAny, JSAny, JSAny): JSAny;
extern transitioning macro Call(Context, JSAny, JSAny, JSAny, JSAny): JSAny;
extern transitioning macro Call(
    Context, JSAny, JSAny, JSAny, JSAny, JSAny): JSAny;
extern transitioning macro Call(
    Context, JSAny, JSAny, JSAny, JSAny, JSAny, JSAny): JSAny;
extern transitioning macro Call(
    Context, JSAny, JSAny, JSAny, JSAny, JSAny, JSAny, JSAny): JSAny;

extern macro TransitionElementsKind(
    JSObject, Map, constexpr ElementsKind,
    constexpr ElementsKind): void labels Bailout;
extern macro PerformStackCheck(implicit context: Context)(): void;

extern macro Typeof(JSAny): String;

// Return true iff number is NaN.
macro NumberIsNaN(number: Number): bool {
  typeswitch (number) {
    case (Smi): {
      return false;
    }
    case (hn: HeapNumber): {
      const value: float64 = Convert<float64>(hn);
      return value != value;
    }
  }
}

extern macro GotoIfForceSlowPath(): void labels Taken;
macro IsForceSlowPath(): bool {
  GotoIfForceSlowPath() otherwise return true;
  return false;
}

extern macro BranchIfToBooleanIsTrue(JSAny): never
    labels Taken, NotTaken;
extern macro BranchIfToBooleanIsFalse(JSAny): never
    labels Taken, NotTaken;

macro ToBoolean(obj: JSAny): bool {
  BranchIfToBooleanIsTrue(obj) otherwise return true, return false;
}

@export
macro RequireObjectCoercible(
    implic
```
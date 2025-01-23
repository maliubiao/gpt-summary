Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Skim and High-Level Understanding:**

* **Keywords:** I immediately see `#ifndef`, `#define`, `#include`, `namespace v8`, `class Object`, `enum`, `struct`. This tells me it's a C++ header file defining classes, enums, and likely some foundational data structures for the V8 JavaScript engine.
* **Filename:** `v8/src/objects/objects.h` suggests this file is central to how V8 represents JavaScript objects internally. The `objects` directory strongly implies this is where the core object model is defined.
* **Copyright Notice:**  Confirms it's part of the V8 project.
* **Includes:** The included headers give clues about the file's dependencies and functionalities. I see things like memory management (`memory.h`), logging (`logging.h`), flags (`flags.h`), tagged pointers (`tagged.h`), and specific V8 concepts (`elements-kind.h`, `property-details.h`).

**2. Analyzing the Core Structure - The `Object` Class:**

* **Central Role:** The `class Object` declaration stands out. The comment "Object is the abstract superclass for all classes in the object hierarchy" confirms its fundamental importance.
* **No Virtual Functions:** The comment "Object does not use any virtual functions" is a significant performance optimization. It means polymorphism is likely handled through other mechanisms (like tagged pointers and type checking).
* **Single Data Member:** "There must only be a single data member in Object: the Address ptr..." This reinforces the idea of tagged pointers. The `Object` class itself is very lightweight, and the actual object data is stored elsewhere in the heap.
* **Static Methods:** A large number of `static` methods are present. This indicates that the `Object` class acts as a utility class, providing operations on JavaScript objects without requiring an instance of the `Object` class itself.
* **Method Names:**  Many method names closely resemble JavaScript operations (e.g., `IsArray`, `BooleanValue`, `Compare`, `Equals`, `ToObject`, `ToString`, `GetProperty`, `SetProperty`, `TypeOf`, `InstanceOf`). This strongly suggests a direct mapping between these C++ methods and the semantics of JavaScript.

**3. Examining Key Enums and Structs:**

* **`WriteBarrierMode`:**  Clearly related to garbage collection and memory management. The different modes (`SKIP`, `UNSAFE_SKIP`, `UPDATE`) hint at performance optimization strategies.
* **`PropertyNormalizationMode`:**  Related to object property manipulation, likely during optimization or conversion processes.
* **`TransitionFlag`, `TransitionKindFlag`:**  Suggest the implementation of object shape changes (transitions) in V8's hidden classes.
* **`DescriptorFlag`:**  Relates to how object property descriptors are handled.
* **`ComparisonResult`:** Directly maps to the result of JavaScript comparison operators.
* **`OnNonExistent`:**  Relates to how V8 handles accessing non-existent properties (throwing errors or returning undefined).
* **`ElementTypes`:**  Specifically for array-like object creation, indicating the types of elements to consider.
* **`EnforceDefineSemantics`:**  Highlights a nuance in property definition, with different behaviors for "set" and "define."

**4. Connecting to JavaScript Functionality:**

This is where the method names in the `Object` class become crucial. I look for methods whose names directly correspond to JavaScript concepts. For example:

* `IsArray`:  The JavaScript `Array.isArray()` method.
* `BooleanValue`: Implicit conversion to boolean in JavaScript (e.g., in `if` statements).
* `Compare`, `Equals`, `StrictEquals`: JavaScript comparison operators (`<`, `>`, `==`, `===`).
* `ToObject`, `ToNumber`, `ToString`, `ToPrimitive`:  JavaScript type conversion functions.
* `GetProperty`, `SetProperty`:  Accessing and modifying object properties.
* `TypeOf`: The `typeof` operator.
* `InstanceOf`: The `instanceof` operator.

**5. Considering Potential Programming Errors:**

The comments in the code itself provide hints. For example, the comments around `SetProperty` highlight the importance of handling `ShouldThrow` and how exceptions are managed. I also consider common JavaScript errors that might be related to the functionality exposed by this header:

* Trying to write to a read-only property.
* Accessing properties on `null` or `undefined`.
* Type errors when performing operations on incompatible types.

**6. Identifying Torque (Absence):**

The prompt specifically asks about `.tq` files. The lack of any mention of Torque or `.tq` extensions in the provided header file means it's a standard C++ header, not a Torque file.

**7. Structuring the Answer:**

Finally, I organize the information into logical sections, as requested by the prompt:

* **Core Functionality:**  Summarize the main purpose of the file.
* **Relationship to JavaScript:** Explicitly link C++ methods to JavaScript features with examples.
* **Code Logic Inference:**  Provide a simplified example to illustrate the behavior of a particular function.
* **Common Programming Errors:**  Give concrete JavaScript examples of errors that the V8 code in this header helps to handle or prevent.
* **Summary (Part 1):**  A concise recap of the file's overall role.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file *implements* JavaScript objects directly.
* **Correction:**  The single `Address ptr` member suggests it's more of a *representation* or *handle* to an object stored elsewhere. The actual object structure is likely defined in other related header files (as suggested by the includes).
* **Initial thought:**  The static methods are just utilities.
* **Refinement:** While they are utilities, they directly correspond to core JavaScript semantics, making this file a fundamental part of the engine's logic.

By following these steps,  I can systematically analyze the C++ header file and extract the necessary information to answer the prompt accurately and comprehensively.
好的，让我们来分析一下 `v8/src/objects/objects.h` 这个 V8 源代码文件的功能。

**文件功能归纳:**

`v8/src/objects/objects.h` 是 V8 JavaScript 引擎中一个非常核心的头文件。它主要定义了 V8 中所有 JavaScript 对象类型的基类 `Object` 以及与对象操作相关的各种基础结构、枚举和辅助函数。可以将其视为 V8 对象模型的蓝图和基础操作接口。

**具体功能列举:**

1. **定义了所有 V8 对象的基类 `Object`:**
   -  `Object` 类是 V8 中所有其他对象类型的抽象父类。
   -  它本身非常轻量级，主要包含一个指向实际堆内存的指针。
   -  它不使用虚函数，以避免 vtable 的开销，体现了 V8 对性能的极致追求。

2. **定义了与对象操作相关的枚举类型:**
   -  `WriteBarrierMode`: 定义了写屏障的不同模式，用于垃圾回收。
   -  `PropertyNormalizationMode`:  定义了属性规范化的模式。
   -  `TransitionFlag`, `TransitionKindFlag`: 定义了对象形状转换的相关标志。
   -  `DescriptorFlag`: 定义了属性描述符的标志。
   -  `ComparisonResult`:  定义了比较操作的结果。
   -  `OnNonExistent`: 定义了访问不存在属性时的行为。
   -  `ElementTypes`: 定义了创建类数组对象时的元素类型选择。
   -  `EnforceDefineSemantics`: 定义了属性定义语义。

3. **声明了大量的静态方法，用于执行各种 JavaScript 对象操作:** 这些方法涵盖了 JavaScript 规范中定义的各种抽象操作，例如：
   - **类型判断和转换:** `IsArray`, `BooleanValue`, `ToNumber`, `ToString`, `ToObject`, `ToPrimitive`, `ToArrayLength`, `ToArrayIndex` 等。
   - **比较操作:** `Compare`, `Equals`, `StrictEquals`, `GreaterThan`, `LessThan` 等。
   - **属性操作:** `GetProperty`, `SetProperty`, `GetMethod`, `AddDataProperty`, `TransitionAndWriteDataProperty` 等。
   - **原型链操作:** `OrdinaryHasInstance`, `InstanceOf`。
   - **其他操作:** `TypeOf`, `Add`, `CreateListFromArrayLike`, `GetLengthFromArrayLike`, `GetHash`, `SameValue`, `SameValueZero`, `ArraySpeciesConstructor`, `SpeciesConstructor`, `Share` 等。

4. **定义了一些辅助结构体和常量:**
   -  `InliningPosition`, `LookupIterator`, `PropertyDescriptorObject`, `ReadOnlyRoots`, `RootVisitor`, `PropertyKey`:  这些是其他 V8 内部组件使用的类型，与对象操作密切相关。
   -  `kVariableSizeSentinel`: 用于表示可变大小对象的哨兵值。
   -  `kStubMajorKeyBits`, `kStubMinorKeyBits`: 与代码存根相关的常量。
   -  `Brief`: 用于以简洁的方式打印对象信息。
   -  `Hasher`, `KeyEqualSafe`, `Comparer`, `FullPtrComparer`:  用于在哈希表和映射中比较对象的结构体。

5. **提供了与垃圾回收相关的辅助功能:**  例如 `WriteBarrierMode` 以及与弱引用相关的 `CanBeHeldWeakly`。

**如果 `v8/src/objects/objects.h` 以 `.tq` 结尾:**

如果文件名是 `objects.tq`，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 自研的一种类型化的领域特定语言 (DSL)，用于编写 V8 的内置函数和运行时代码。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例:**

`v8/src/objects/objects.h` 中定义的函数和结构体直接对应了 JavaScript 的各种语言特性。以下是一些 JavaScript 示例以及它们在 `objects.h` 中可能涉及到的函数：

**示例 1: 类型转换**

```javascript
let num = 10;
let str = String(num); // 调用 JavaScript 的 String() 函数进行类型转换
```

在 V8 内部，`String(num)` 的实现可能会调用 `objects.h` 中声明的 `Object::ToString(Isolate* isolate, Handle<Object> input)` 方法，将数字类型的 `num` 转换为字符串类型。

**示例 2: 属性访问**

```javascript
const obj = { name: "John", age: 30 };
console.log(obj.name); // 访问对象的属性
```

当 V8 执行 `obj.name` 时，会使用 `objects.h` 中声明的 `Object::GetPropertyOrElement(Isolate* isolate, Handle<JSAny> object, Handle<Name> name)` 方法来查找和获取 `obj` 对象的 `name` 属性的值。

**示例 3: 比较操作**

```javascript
const a = 5;
const b = "5";
console.log(a == b); // 使用 == 进行比较
```

JavaScript 的 `==` 运算符的实现会调用 `objects.h` 中声明的 `Object::Equals(Isolate* isolate, Handle<Object> x, Handle<Object> y)` 方法来执行抽象相等比较。

**示例 4: 创建数组**

```javascript
const arr = [1, 2, 3];
```

创建数组的操作可能涉及到 `objects.h` 中的与数组相关的对象类型定义（虽然具体定义可能在其他头文件中）以及分配内存和初始化数组元素等操作。

**代码逻辑推理 (假设输入与输出):**

假设我们调用 JavaScript 的 `Object.is(5, "5")`：

- **假设输入:** 两个 JavaScript 值，一个是数字 `5`，另一个是字符串 `"5"`。
- **涉及的 `objects.h` 函数:** `Object::SameValue(Tagged<Object> obj, Tagged<Object> other)`
- **代码逻辑推理:**
    1. V8 会将数字 `5` 和字符串 `"5"` 分别封装成 V8 的内部对象表示（例如，Smi 或 HeapNumber，以及 String）。
    2. `Object::SameValue` 方法会被调用，传入这两个内部对象。
    3. `SameValue` 内部会进行类型检查和值比较。由于数字 `5` 和字符串 `"5"` 类型不同，即使值看起来一样，`SameValue` 会返回 `false`。
- **输出:**  JavaScript 的 `Object.is(5, "5")` 将返回 `false`.

**用户常见的编程错误及示例:**

1. **尝试写入只读属性:**

   ```javascript
   "use strict";
   const obj = {};
   Object.defineProperty(obj, 'prop', {
     value: 42,
     writable: false
   });
   obj.prop = 99; // TypeError: Cannot assign to read only property 'prop' of object '#<Object>'
   ```

   V8 在执行 `obj.prop = 99` 时，会检查属性的 `writable` 属性。如果为 `false`，则会抛出一个 `TypeError`。这个检查逻辑可能涉及到 `objects.h` 中的属性描述符相关的结构和方法。

2. **访问 `null` 或 `undefined` 的属性:**

   ```javascript
   const obj = null;
   console.log(obj.name); // TypeError: Cannot read properties of null (reading 'name')
   ```

   V8 在尝试访问 `null` 的 `name` 属性时，会调用属性访问相关的函数（如 `Object::GetPropertyOrElement`），但由于 `obj` 是 `null`，V8 会检测到这个错误并抛出一个 `TypeError`。`objects.h` 中可能包含对 `null` 和 `undefined` 类型的特殊处理逻辑。

3. **对非对象类型调用对象方法:**

   ```javascript
   const str = "hello";
   str.toUpperCase(); // 可以正常工作，因为 JavaScript 会进行自动装箱
   str.myCustomMethod(); // TypeError: str.myCustomMethod is not a function
   ```

   对于内置方法，JavaScript 会进行自动装箱，将原始类型转换为临时对象。但对于自定义方法，如果原始类型没有该方法，V8 会抛出 `TypeError`。`objects.h` 中定义的类型检查和方法查找机制会参与这个过程。

**总结 (第 1 部分):**

`v8/src/objects/objects.h` 是 V8 引擎中定义 JavaScript 对象模型和基本操作的核心头文件。它定义了所有 V8 对象的基类 `Object`，以及大量的枚举、结构体和静态方法，这些方法直接对应了 JavaScript 规范中定义的各种对象操作、类型转换、比较运算等核心功能。理解这个文件对于深入了解 V8 引擎的内部工作原理至关重要。它不属于 Torque 源代码，因为它没有 `.tq` 扩展名。

### 提示词
```
这是目录为v8/src/objects/objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_OBJECTS_H_
#define V8_OBJECTS_OBJECTS_H_

#include <iosfwd>
#include <memory>

#include "include/v8-internal.h"
#include "include/v8config.h"
#include "src/base/bits.h"
#include "src/base/build_config.h"
#include "src/base/flags.h"
#include "src/base/logging.h"
#include "src/base/memory.h"
#include "src/codegen/constants-arch.h"
#include "src/common/assert-scope.h"
#include "src/common/checks.h"
#include "src/common/message-template.h"
#include "src/common/operation.h"
#include "src/common/ptr-compr.h"
#include "src/flags/flags.h"
#include "src/objects/elements-kind.h"
#include "src/objects/field-index.h"
#include "src/objects/object-list-macros.h"
#include "src/objects/objects-definitions.h"
#include "src/objects/property-details.h"
#include "src/objects/tagged-impl.h"
#include "src/objects/tagged.h"
#include "src/utils/utils.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

struct InliningPosition;
class LookupIterator;
class PropertyDescriptorObject;
class ReadOnlyRoots;
class RootVisitor;
class PropertyKey;

// UNSAFE_SKIP_WRITE_BARRIER skips the write barrier.
// SKIP_WRITE_BARRIER skips the write barrier and asserts that this is safe in
// the MemoryOptimizer
// UPDATE_WRITE_BARRIER is doing the full barrier, marking and generational.
enum WriteBarrierMode {
  SKIP_WRITE_BARRIER,
  UNSAFE_SKIP_WRITE_BARRIER,
  UPDATE_EPHEMERON_KEY_WRITE_BARRIER,
  UPDATE_WRITE_BARRIER
};

// PropertyNormalizationMode is used to specify whether to keep
// inobject properties when normalizing properties of a JSObject.
enum PropertyNormalizationMode {
  CLEAR_INOBJECT_PROPERTIES,
  KEEP_INOBJECT_PROPERTIES
};

// Indicates whether transitions can be added to a source map or not.
enum TransitionFlag { INSERT_TRANSITION, OMIT_TRANSITION };

// Indicates the kind of transition: the target map of the transition
// either extends the current map with a new property, or it modifies the
// property that was added last to the current map. Otherwise, it can
// be a prototype transition, or anything else.
enum TransitionKindFlag {
  SIMPLE_PROPERTY_TRANSITION,
  PROPERTY_TRANSITION,
  PROTOTYPE_TRANSITION,
  SPECIAL_TRANSITION
};

// Indicates whether we are only interested in the descriptors of a particular
// map, or in all descriptors in the descriptor array.
enum DescriptorFlag { ALL_DESCRIPTORS, OWN_DESCRIPTORS };

// Instance size sentinel for objects of variable size.
const int kVariableSizeSentinel = 0;

// We may store the unsigned bit field as signed Smi value and do not
// use the sign bit.
const int kStubMajorKeyBits = 8;
const int kStubMinorKeyBits = kSmiValueSize - kStubMajorKeyBits - 1;

// Result of an abstract relational comparison of x and y, implemented according
// to ES6 section 7.2.11 Abstract Relational Comparison.
enum class ComparisonResult {
  kLessThan = -1,    // x < y
  kEqual = 0,        // x = y
  kGreaterThan = 1,  // x > y
  kUndefined = 2     // at least one of x or y was undefined or NaN
};

// (Returns false whenever {result} is kUndefined.)
bool ComparisonResultToBool(Operation op, ComparisonResult result);

enum class OnNonExistent { kThrowReferenceError, kReturnUndefined };

// The element types selection for CreateListFromArrayLike.
enum class ElementTypes { kAll, kStringAndSymbol };

// Currently DefineOwnPropertyIgnoreAttributes invokes the setter
// interceptor and user-defined setters during define operations,
// even in places where it makes more sense to invoke the definer
// interceptor and not invoke the setter: e.g. both the definer and
// the setter interceptors are called in Object.defineProperty().
// kDefine allows us to implement the define semantics correctly
// in selected locations.
// TODO(joyee): see if we can deprecate the old behavior.
enum class EnforceDefineSemantics { kSet, kDefine };

// TODO(mythria): Move this to a better place.
ShouldThrow GetShouldThrow(Isolate* isolate, Maybe<ShouldThrow> should_throw);

// Object is the abstract superclass for all classes in the
// object hierarchy.
// Object does not use any virtual functions to avoid the
// allocation of the C++ vtable.
// There must only be a single data member in Object: the Address ptr,
// containing the tagged heap pointer that this Object instance refers to.
// For a design overview, see https://goo.gl/Ph4CGz.
class Object : public AllStatic {
 public:
  enum class Conversion {
    kToNumber,  // Number = Smi or HeapNumber
    kToNumeric  // Numeric = Smi or HeapNumber or BigInt
  };

  // ES6, #sec-isarray.  NOT to be confused with %_IsArray.
  V8_INLINE
  V8_WARN_UNUSED_RESULT static Maybe<bool> IsArray(Handle<Object> object);

  // Extract the double value of a Number (Smi or HeapNumber).
  static inline double NumberValue(Tagged<Number> obj);
  static inline double NumberValue(Tagged<Object> obj);
  static inline double NumberValue(Tagged<HeapNumber> obj);
  static inline double NumberValue(Tagged<Smi> obj);
  V8_EXPORT_PRIVATE static bool ToInt32(Tagged<Object> obj, int32_t* value);
  static inline bool ToUint32(Tagged<Object> obj, uint32_t* value);

  static inline Representation OptimalRepresentation(
      Tagged<Object> obj, PtrComprCageBase cage_base);

  static inline ElementsKind OptimalElementsKind(Tagged<Object> obj,
                                                 PtrComprCageBase cage_base);

  // If {allow_coercion} is true, then a Smi will be considered to fit
  // a Double representation, since it can be converted to a HeapNumber
  // and stored.
  static inline bool FitsRepresentation(Tagged<Object> obj,
                                        Representation representation,
                                        bool allow_coercion = true);

  static inline bool FilterKey(Tagged<Object> obj, PropertyFilter filter);

  static Handle<FieldType> OptimalType(Tagged<Object> obj, Isolate* isolate,
                                       Representation representation);

  V8_EXPORT_PRIVATE static Handle<UnionOf<JSAny, Hole>> NewStorageFor(
      Isolate* isolate, Handle<UnionOf<JSAny, Hole>> object,
      Representation representation);

  template <AllocationType allocation_type = AllocationType::kYoung,
            typename IsolateT>
  static Handle<JSAny> WrapForRead(IsolateT* isolate, Handle<JSAny> object,
                                   Representation representation);

  // Returns true if the object is of the correct type to be used as an
  // implementation of a JSObject's elements.
  static inline bool HasValidElements(Tagged<Object> obj);

  // ECMA-262 9.2.
  template <typename IsolateT>
  V8_EXPORT_PRIVATE static bool BooleanValue(Tagged<Object> obj,
                                             IsolateT* isolate);
  static Tagged<Object> ToBoolean(Tagged<Object> obj, Isolate* isolate);

  // ES6 section 7.2.11 Abstract Relational Comparison
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<ComparisonResult>
  Compare(Isolate* isolate, Handle<Object> x, Handle<Object> y);

  // ES6 section 7.2.12 Abstract Equality Comparison
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> Equals(
      Isolate* isolate, Handle<Object> x, Handle<Object> y);

  // ES6 section 7.2.13 Strict Equality Comparison
  V8_EXPORT_PRIVATE static bool StrictEquals(Tagged<Object> obj,
                                             Tagged<Object> that);

  // ES6 section 7.1.13 ToObject
  // Convert to a JSObject if needed.
  // native_context is used when creating wrapper object.
  //
  // Passing a non-null method_name allows us to give a more informative
  // error message for those cases where ToObject is being called on
  // the receiver of a built-in method.
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<JSReceiver> ToObject(
      Isolate* isolate, Handle<Object> object,
      const char* method_name = nullptr);
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSReceiver> ToObjectImpl(
      Isolate* isolate, DirectHandle<Object> object,
      const char* method_name = nullptr);

  // ES6 section 9.2.1.2, OrdinaryCallBindThis for sloppy callee.
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSReceiver> ConvertReceiver(
      Isolate* isolate, Handle<Object> object);

  // ES6 section 7.1.14 ToPropertyKey
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Name> ToName(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.1 ToPrimitive
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> ToPrimitive(
      Isolate* isolate, Handle<Object> input,
      ToPrimitiveHint hint = ToPrimitiveHint::kDefault);

  // ES6 section 7.1.3 ToNumber
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Number> ToNumber(
      Isolate* isolate, Handle<Object> input);

  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> ToNumeric(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.4 ToInteger
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Number> ToInteger(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.5 ToInt32
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Number> ToInt32(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.6 ToUint32
  V8_WARN_UNUSED_RESULT inline static MaybeHandle<Number> ToUint32(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.12 ToString
  // TODO(b/42203211): ToString is templatized so that passing a Handle<T>
  // is not ambiguous when T is a subtype of Object (it could be implicitly
  // converted both to Handle<Object> and to DirectHandle<Object>). Here, T
  // should be a subtype of Object, which is enforced by the second template
  // argument and the similar restriction on Handle's constructor. When the
  // migration to DirectHandle is complete, this function can accept simply
  // a DirectHandle<Object>.
  template <typename T, typename = std::enable_if_t<
                            std::is_convertible_v<Handle<T>, Handle<Object>>>>
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<String> ToString(
      Isolate* isolate, Handle<T> input);

  template <typename T, typename = std::enable_if_t<std::is_convertible_v<
                            DirectHandle<T>, DirectHandle<Object>>>>
  V8_WARN_UNUSED_RESULT static inline MaybeDirectHandle<String> ToString(
      Isolate* isolate, DirectHandle<T> input);

  V8_EXPORT_PRIVATE static MaybeDirectHandle<String> NoSideEffectsToMaybeString(
      Isolate* isolate, DirectHandle<Object> input);

  V8_EXPORT_PRIVATE static DirectHandle<String> NoSideEffectsToString(
      Isolate* isolate, DirectHandle<Object> input);

  // ES6 section 7.1.14 ToPropertyKey
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> ToPropertyKey(
      Isolate* isolate, Handle<Object> value);

  // ES6 section 7.1.15 ToLength
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> ToLength(
      Isolate* isolate, Handle<Object> input);

  // ES6 section 7.1.17 ToIndex
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> ToIndex(
      Isolate* isolate, Handle<Object> input, MessageTemplate error_index);

  // ES6 section 7.3.9 GetMethod
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> GetMethod(
      Isolate* isolate, Handle<JSReceiver> receiver, Handle<Name> name);

  // ES6 section 7.3.17 CreateListFromArrayLike
  V8_WARN_UNUSED_RESULT static MaybeHandle<FixedArray> CreateListFromArrayLike(
      Isolate* isolate, Handle<Object> object, ElementTypes element_types);

  // Get length property and apply ToLength.
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> GetLengthFromArrayLike(
      Isolate* isolate, Handle<JSReceiver> object);

  // ES6 section 12.5.6 The typeof Operator
  static Handle<String> TypeOf(Isolate* isolate, DirectHandle<Object> object);

  // ES6 section 12.7 Additive Operators
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> Add(Isolate* isolate,
                                                       Handle<Object> lhs,
                                                       Handle<Object> rhs);

  // ES6 section 12.9 Relational Operators
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> GreaterThan(Isolate* isolate,
                                                              Handle<Object> x,
                                                              Handle<Object> y);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> GreaterThanOrEqual(
      Isolate* isolate, Handle<Object> x, Handle<Object> y);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> LessThan(Isolate* isolate,
                                                           Handle<Object> x,
                                                           Handle<Object> y);
  V8_WARN_UNUSED_RESULT static inline Maybe<bool> LessThanOrEqual(
      Isolate* isolate, Handle<Object> x, Handle<Object> y);

  // ES6 section 7.3.19 OrdinaryHasInstance (C, O).
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> OrdinaryHasInstance(
      Isolate* isolate, Handle<JSAny> callable, Handle<JSAny> object);

  // ES6 section 12.10.4 Runtime Semantics: InstanceofOperator(O, C)
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> InstanceOf(
      Isolate* isolate, Handle<JSAny> object, Handle<JSAny> callable);

  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  GetProperty(LookupIterator* it, bool is_global_reference = false);

  // ES6 [[Set]] (when passed kDontThrow)
  // Invariants for this and related functions (unless stated otherwise):
  // 1) When the result is Nothing, an exception is pending.
  // 2) When passed kThrowOnError, the result is never Just(false).
  // In some cases, an exception is thrown regardless of the ShouldThrow
  // argument.  These cases are either in accordance with the spec or not
  // covered by it (eg., concerning API callbacks).
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> SetProperty(
      LookupIterator* it, Handle<Object> value, StoreOrigin store_origin,
      Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>());
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Object>
  SetProperty(Isolate* isolate, Handle<JSAny> object, Handle<Name> name,
              Handle<Object> value,
              StoreOrigin store_origin = StoreOrigin::kMaybeKeyed,
              Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>());
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> SetPropertyOrElement(
      Isolate* isolate, Handle<JSAny> object, Handle<Name> name,
      Handle<Object> value,
      Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>(),
      StoreOrigin store_origin = StoreOrigin::kMaybeKeyed);

  V8_WARN_UNUSED_RESULT static Maybe<bool> SetSuperProperty(
      LookupIterator* it, Handle<Object> value, StoreOrigin store_origin,
      Maybe<ShouldThrow> should_throw = Nothing<ShouldThrow>());

  V8_WARN_UNUSED_RESULT static Maybe<bool> CannotCreateProperty(
      Isolate* isolate, Handle<JSAny> receiver, Handle<Object> name,
      DirectHandle<Object> value, Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> WriteToReadOnlyProperty(
      LookupIterator* it, DirectHandle<Object> value,
      Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> WriteToReadOnlyProperty(
      Isolate* isolate, Handle<JSAny> receiver, Handle<Object> name,
      DirectHandle<Object> value, ShouldThrow should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> RedefineIncompatibleProperty(
      Isolate* isolate, Handle<Object> name, DirectHandle<Object> value,
      Maybe<ShouldThrow> should_throw);
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetDataProperty(
      LookupIterator* it, Handle<Object> value);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static Maybe<bool> AddDataProperty(
      LookupIterator* it, DirectHandle<Object> value,
      PropertyAttributes attributes, Maybe<ShouldThrow> should_throw,
      StoreOrigin store_origin,
      EnforceDefineSemantics semantics = EnforceDefineSemantics::kSet);

  V8_WARN_UNUSED_RESULT static Maybe<bool> TransitionAndWriteDataProperty(
      LookupIterator* it, DirectHandle<Object> value,
      PropertyAttributes attributes, Maybe<ShouldThrow> should_throw,
      StoreOrigin store_origin);

  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetPropertyOrElement(
      Isolate* isolate, Handle<JSAny> object, Handle<Name> name);
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetPropertyOrElement(
      Handle<JSAny> receiver, Handle<Name> name, Handle<JSReceiver> holder);
  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetProperty(
      Isolate* isolate, Handle<JSAny> object, Handle<Name> name);

  V8_WARN_UNUSED_RESULT static MaybeHandle<JSAny> GetPropertyWithAccessor(
      LookupIterator* it);
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetPropertyWithAccessor(
      LookupIterator* it, Handle<Object> value,
      Maybe<ShouldThrow> should_throw);

  V8_WARN_UNUSED_RESULT static MaybeHandle<JSAny> GetPropertyWithDefinedGetter(
      Handle<JSAny> receiver, Handle<JSReceiver> getter);
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetPropertyWithDefinedSetter(
      Handle<JSAny> receiver, Handle<JSReceiver> setter, Handle<Object> value,
      Maybe<ShouldThrow> should_throw);

  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> GetElement(
      Isolate* isolate, Handle<JSAny> object, uint32_t index);

  V8_WARN_UNUSED_RESULT static inline MaybeHandle<Object> SetElement(
      Isolate* isolate, Handle<JSAny> object, uint32_t index,
      Handle<Object> value, ShouldThrow should_throw);

  // Returns the permanent hash code associated with this object. May return
  // undefined if not yet created.
  static inline Tagged<Object> GetHash(Tagged<Object> obj);

  // Returns the permanent hash code associated with this object depending on
  // the actual object type. May create and store a hash code if needed and none
  // exists.
  V8_EXPORT_PRIVATE static Tagged<Smi> GetOrCreateHash(Tagged<Object> obj,
                                                       Isolate* isolate);

  // Checks whether this object has the same value as the given one.  This
  // function is implemented according to ES5, section 9.12 and can be used
  // to implement the Object.is function.
  V8_EXPORT_PRIVATE static bool SameValue(Tagged<Object> obj,
                                          Tagged<Object> other);

  // A part of SameValue which handles Number vs. Number case.
  // Treats NaN == NaN and +0 != -0.
  inline static bool SameNumberValue(double number1, double number2);

  // Checks whether this object has the same value as the given one.
  // +0 and -0 are treated equal. Everything else is the same as SameValue.
  // This function is implemented according to ES6, section 7.2.4 and is used
  // by ES6 Map and Set.
  static bool SameValueZero(Tagged<Object> obj, Tagged<Object> other);

  // ES6 section 9.4.2.3 ArraySpeciesCreate (part of it)
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> ArraySpeciesConstructor(
      Isolate* isolate, Handle<JSAny> original_array);

  // ES6 section 7.3.20 SpeciesConstructor ( O, defaultConstructor )
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> SpeciesConstructor(
      Isolate* isolate, Handle<JSReceiver> recv,
      Handle<JSFunction> default_ctor);

  // Tries to convert an object to an array length. Returns true and sets the
  // output parameter if it succeeds.
  static inline bool ToArrayLength(Tagged<Object> obj, uint32_t* index);

  // Tries to convert an object to an array index. Returns true and sets the
  // output parameter if it succeeds. Equivalent to ToArrayLength, but does not
  // allow kMaxUInt32.
  static V8_WARN_UNUSED_RESULT inline bool ToArrayIndex(Tagged<Object> obj,
                                                        uint32_t* index);

  // Tries to convert an object to an index (in the range 0..size_t::max).
  // Returns true and sets the output parameter if it succeeds.
  static inline bool ToIntegerIndex(Tagged<Object> obj, size_t* index);

  // Returns true if the result of iterating over the object is the same
  // (including observable effects) as simply accessing the properties between 0
  // and length.
  V8_EXPORT_PRIVATE static bool IterationHasObservableEffects(
      Tagged<Object> obj);

  // TC39 "Dynamic Code Brand Checks"
  static bool IsCodeLike(Tagged<Object> obj, Isolate* isolate);

  EXPORT_DECL_STATIC_VERIFIER(Object)

#ifdef VERIFY_HEAP
  // Verify a pointer is a valid (non-InstructionStream) object pointer.
  // When V8_EXTERNAL_CODE_SPACE is enabled InstructionStream objects are
  // not allowed.
  static void VerifyPointer(Isolate* isolate, Tagged<Object> p);
  // Verify a pointer is a valid (non-InstructionStream) object pointer,
  // potentially a weak one.
  // When V8_EXTERNAL_CODE_SPACE is enabled InstructionStream objects are
  // not allowed.
  static void VerifyMaybeObjectPointer(Isolate* isolate, Tagged<MaybeObject> p);
  // Verify a pointer is a valid object pointer.
  // InstructionStream objects are allowed regardless of the
  // V8_EXTERNAL_CODE_SPACE mode.
  static void VerifyAnyTagged(Isolate* isolate, Tagged<Object> p);
#endif

  // Layout description.
  static const int kHeaderSize = 0;  // Object does not take up any space.

  // For use with std::unordered_set.
  struct Hasher {
    size_t operator()(const Tagged<Object> o) const {
      return std::hash<v8::internal::Address>{}(static_cast<Tagged_t>(o.ptr()));
    }
  };

  // For use with std::unordered_set/unordered_map when one of the objects may
  // be located outside the main pointer compression cage, for example in
  // trusted space. In this case, we must use full pointer comparison.
  struct KeyEqualSafe {
    bool operator()(const Tagged<Object> a, const Tagged<Object> b) const {
      return a.SafeEquals(b);
    }
  };

  // For use with std::map.
  struct Comparer {
    bool operator()(const Tagged<Object> a, const Tagged<Object> b) const {
      return a < b;
    }
  };

  // Same as above, but can be used when one of the objects may be located
  // outside of the main pointer compression cage, for example in trusted
  // space. In this case, we must use full pointer comparison.
  struct FullPtrComparer {
    bool operator()(const Tagged<Object> a, const Tagged<Object> b) const {
      return a.ptr() < b.ptr();
    }
  };

  // If the receiver is the JSGlobalObject, the store was contextual. In case
  // the property did not exist yet on the global object itself, we have to
  // throw a reference error in strict mode.  In sloppy mode, we continue.
  // Returns false if the exception was thrown, otherwise true.
  static bool CheckContextualStoreToJSGlobalObject(
      LookupIterator* it, Maybe<ShouldThrow> should_throw);

  // Returns an equivalent value that's safe to share across Isolates if
  // possible. Acts as the identity function when value->IsShared().
  static inline MaybeHandle<Object> Share(
      Isolate* isolate, Handle<Object> value,
      ShouldThrow throw_if_cannot_be_shared);

  static MaybeHandle<Object> ShareSlow(Isolate* isolate,
                                       Handle<HeapObject> value,
                                       ShouldThrow throw_if_cannot_be_shared);

  // Whether this Object can be held weakly, i.e. whether it can be used as a
  // key in WeakMap, as a key in WeakSet, as the target of a WeakRef, or as a
  // target or unregister token of a FinalizationRegistry.
  static inline bool CanBeHeldWeakly(Tagged<Object> obj);

 private:
  friend class CompressedObjectSlot;
  friend class FullObjectSlot;
  friend class LookupIterator;
  friend class StringStream;

  // Return the map of the root of object's prototype chain.
  static Tagged<Map> GetPrototypeChainRootMap(Tagged<Object> obj,
                                              Isolate* isolate);

  // Returns a non-SMI for JSReceivers, but returns the hash code forp
  // simple objects.  This avoids a double lookup in the cases where
  // we know we will add the hash to the JSReceiver if it does not
  // already exist.
  //
  // Despite its size, this needs to be inlined for performance
  // reasons.
  static inline Tagged<Object> GetSimpleHash(Tagged<Object> object);

  // Helper for SetProperty and SetSuperProperty.
  // Return value is only meaningful if [found] is set to true on return.
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetPropertyInternal(
      LookupIterator* it, Handle<Object> value, Maybe<ShouldThrow> should_throw,
      StoreOrigin store_origin, bool* found);

  V8_WARN_UNUSED_RESULT static MaybeHandle<Name> ConvertToName(
      Isolate* isolate, Handle<Object> input);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Object> ConvertToPropertyKey(
      Isolate* isolate, Handle<Object> value);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<String>
  ConvertToString(Isolate* isolate, Handle<Object> input);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Number> ConvertToNumber(
      Isolate* isolate, Handle<Object> input);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Numeric> ConvertToNumeric(
      Isolate* isolate, Handle<Object> input);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Number>
  ConvertToInteger(Isolate* isolate, Handle<Object> input);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Number> ConvertToInt32(
      Isolate* isolate, Handle<Object> input);
  V8_WARN_UNUSED_RESULT static MaybeHandle<Number> ConvertToUint32(
      Isolate* isolate, Handle<Object> input);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Number>
  ConvertToLength(Isolate* isolate, Handle<Object> input);
  V8_EXPORT_PRIVATE V8_WARN_UNUSED_RESULT static MaybeHandle<Number>
  ConvertToIndex(Isolate* isolate, Handle<Object> input,
                 MessageTemplate error_index);
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           Tagged<Object> obj);
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           Object::Conversion kind);

struct Brief {
  template <HeapObjectReferenceType kRefType>
  explicit Brief(TaggedImpl<kRefType, Address> v) : value{v.ptr()} {}
  template <typename T>
  explicit Brief(T* v) : value{v->ptr()} {}
  // {value} is a tagged heap object reference (weak or strong), equivalent to
  // a MaybeObject's payload. It has a plain Address type to keep #includes
  // lightweight.
  const Address value;
};

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os, const Brief& v);

// Objects should never have the weak tag; this variant is for overzealous
// checking.
V8_INLINE static bool HasWeakHeapObjectTag(const Tagged<Object> value) {
  return HAS_WEAK_HEAP_OBJECT_TAG(value.ptr());
}

// For compatibility with TaggedImpl, and users of this header that don't pull
// in objects-inl.h
// TODO(leszeks): Remove once no longer needed.
template <HeapObjectReferenceType kRefType, typename StorageType>
V8_INLINE constexpr bool IsObject(TaggedImpl<kRefType, StorageType> obj) {
  return obj.IsObject();
}
template <HeapObjectReferenceType kRefType, typename StorageType>
V8_INLINE constexpr bool IsSmi(TaggedImpl<kRefType, StorageType> obj) {
  return obj.IsSmi();
}
template <HeapObjectReferenceType kRefType, typename StorageType>
V8_INLINE constexpr bool IsHeapObject(TaggedImpl<kRefType, StorageType> obj) {
  return obj.IsHeapObject();
}
template <typename StorageType>
V8_INLINE constexpr bool IsWeak(
    TaggedImpl<HeapObjectReferenceType::WEAK, StorageType> obj) {
  return obj.IsWeak();
}

// TODO(leszeks): These exist both as free functions and members of Tagged. They
// probably want to be cleaned up at some point.
V8_INLINE bool IsSmi(Tagged<Object> obj) { return obj.IsSmi(); }
V8_INLINE bool IsSmi(Tagged<HeapObject> obj) { return false; }
V8_INLINE bool IsSmi(Tagged<Smi> obj) { return true; }

V8_INLINE bool IsHeapObject(Tagged<Object> obj) { return obj.IsHeapObject(); }
V8_INLINE bool IsHeapObject(Tagged<HeapObject> obj) { return true; }
V8_INLINE bool IsHeapObject(Tagged<Smi> obj) { return false; }

V8_INLINE bool IsTaggedIndex(Tagged<Object> obj);

#define IS_TYPE_FUNCTION_DECL(Type)            \
  V8_INLINE bool Is##Type(Tagged<Object> obj); \
  V8_INLINE bool Is##Type(Tagged<Object> obj, PtrComprCageBase cage_base);
OBJECT_TYPE_LIST(IS_TYPE_FUNCTION_DECL)
HEAP_OBJECT_TYPE_LIST(IS_TYPE_FUNCTION_DECL)
IS_TYPE_FUNCTION_DECL(HashTableBase)
IS_TYPE_FUNCTION_DECL(SmallOrderedHashTable)
IS_TYPE_FUNCTION_DECL(PropertyDictionary)
#undef IS_TYPE_FUNCTION_DECL
V8_INLINE bool IsNumber(Tagged<Object> obj, ReadOnlyRoots roots);

// A wrapper around IsHole to make it easier to distinguish from specific hole
// checks (e.g. IsTheHole).
V8_INLINE bool IsAnyHole(Tagged<Object> obj, PtrComprCageBase cage_base);
V8_INLINE bool IsAnyHole(Tagged<Object> obj);

// Oddball checks are faster when they are raw pointer comparisons, so the
// isolate/read-only roots overloads should be preferred where possible.
#define IS_TYPE_FUNCTION_DECL(Type, Value, _)                         \
  V8_INLINE bool Is##Type(Tagged<Object> obj, Isolate* isolate);      \
  V8_INLINE bool Is##Type(Tagged<Object> obj, LocalIsolate* isolate); \
  V8_INLINE bool Is##Type(Tagged<Object> obj, ReadOnlyRoots roots);   \
  V8_INLINE bool Is##Type(Tagged<Object> obj);
ODDBALL_LIST(IS_TYPE_FUNCTION_DECL)
HOLE_LIST(IS_TYPE_FUNCTION_DECL)
IS_TYPE_FUNCTION_DECL(NullOrUndefined, , /* unused */)
#undef IS_TYPE_FUNCTION_DECL

V8_INLINE bool IsZero(Tagged<Object> obj);
V8_INLINE bool IsNoSharedNameSentinel(Tagged<Object> obj);
V8_INLINE bool IsPrivateSymbol(Tagged<Object> obj);
V8_INLINE bool IsPublicSymbol(Tagged<Object> obj);
#if !V8_ENABLE_WEBASSEMBLY
// Dummy implementation on builds without WebAssembly.
template <typename T>
V8_INLINE bool IsWasmObject(T obj, Isolate* = nullptr) {
  return false;
}
#endif

V8_INLINE bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<Object> obj);
V8_INLINE bool IsJSObjectThatCanBeTrackedAsPrototype(Tagged<HeapObject> obj);

V8_INLINE bool IsJSApiWrapperObject(Tagged<HeapObject> obj);
V8_INLINE bool IsJSApiWrapperObject(Tagged<Map> map);

#define DECL_STRUCT_PREDICATE(NAME, Name, name) \
  V8_INLINE bool Is##Name(Tagged<Object> obj);  \
  V8_INLINE bool Is##Name(Tagged<Object> obj, PtrComprCageBase cage_base);
STRUCT_LIST(DECL_STRUCT_PREDICATE)
#undef DECL_STRUCT_PREDICATE

V8_INLINE bool IsNaN(Tagged<Object> obj);
V8_INLINE bool IsMinusZero(Tagged<Object> obj);

// Returns whether the object is safe to share across Isolates.
//
// Currently, the following kinds of values can be safely shared across
// Isolates:
// - Smis
// - Objects in RO space when the RO space is shared
// - HeapNumbers in the shared old space
// - Strings for which String::IsShared() is true
// - JSSharedStructs
// - JSSharedArrays
inline bool IsShared(Tagged<Object> obj);

// Prints this object without details.
V8_EXPORT_PRIVATE void ShortPrint(Tagged<Object> obj, FILE* out = stdout);

// Prints this object without details to a message accumulator.
V8_EXPORT_PRIVATE void ShortPrint(Tagged<Object> obj,
                                  StringStream* accumulator);

V8_EXPORT_PRIVATE void ShortPrint(Tagged<Object> obj, std::ostream& os);

#ifdef OBJECT_PRINT
// For our gdb macros, we should perhaps change these in the future.
V8_EXPORT_PRIVATE void Print(Tagged<Object> obj);

// Prints this object with details.
V8_EXPORT_PRIVATE void Print(Tagged<Object> obj, std::ostream& os);

#else
inline void Print(Tagged<Object> obj) { ShortPrint(obj); }
inline void Print(Tagged<Object> obj, std::ostream& os) { ShortPrint(obj, os); }
#endif

// Heap objects typically have a map pointer in their first word.  However,
// during GC other data (e.g. mark bits, forwarding addresses) is sometimes
// encoded in the first word.  The class MapWord is an abstraction of the
// value in a heap object's first word.
//
// When external code space is enabled forwarding pointers are encoded as
// Smi values representing a diff from the source or map word host object
// address in kObjectAlignment chunks. Such a representation has the following
// properties:
// a) it can hold both positive an negative diffs for full pointer compression
//    cage size (HeapObject address has only valuable 30 bits while Smis have
//    31 bits),
// b) it's independent of the pointer compression base and pointer compression
//    scheme.
class MapWord {
 public:
  // Normal state: the map word contains a map pointer.

  // Create a map word from a map pointer.
  static inline MapWord FromMap(const Tagged<Map> map);

  // View this map
```
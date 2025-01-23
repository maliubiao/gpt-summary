Response:
Let's break down the thought process for analyzing this C++ header file.

**1. Initial Scan and High-Level Understanding:**

* **Keywords:** `#ifndef`, `#define`, `namespace`, `#define MESSAGE_TEMPLATES`, `T(...)`. These immediately suggest it's a header file defining macros and likely used for some kind of template instantiation or code generation.
* **Content Structure:** A large macro `MESSAGE_TEMPLATES` is defined. Inside it, there's a repetitive pattern: `T(Identifier, "String Literal")`. This strongly hints at a system for associating symbolic names (`Identifier`) with error or informational messages (`String Literal`).
* **Copyright and License:** Standard boilerplate indicating open-source nature and licensing terms.

**2. Deeper Dive into `MESSAGE_TEMPLATES`:**

* **Purpose of the Macro:** The name itself is a big clue. It likely defines a set of message templates used throughout the V8 engine.
* **Argument `T`:** The macro takes a single argument `T`. This suggests `T` is a placeholder for another macro or function that will be applied to each message template. This is a common C/C++ technique for code generation.
* **Categories:** Notice the comments `/* Error */`, `/* TypeError */`, `/* ReferenceError */`, `/* RangeError */`. This indicates a categorization of the messages based on the type of issue they represent. This is very helpful for organization and error handling.
* **Content of the String Literals:**  Many of the strings contain placeholders like `%`. This confirms they are *templates* and will likely have values substituted into them at runtime. The content of the strings clearly relates to JavaScript errors and internal V8 errors.

**3. Answering the Specific Questions (Mental Walkthrough):**

* **Functionality:**  Based on the analysis above, the primary function is to define a set of reusable message templates with associated identifiers, categorized by error type.

* **`.tq` Extension:**  The prompt provides the rule: ".tq" means Torque. Since the file ends in `.h`, it's *not* a Torque file. State this explicitly.

* **Relationship to JavaScript:** The content of the string literals directly mirrors common JavaScript error messages (e.g., `TypeError: Cannot read properties of undefined`, `ReferenceError: x is not defined`). This indicates a strong connection.

* **JavaScript Examples:**  Think of the JavaScript errors the message templates represent. Construct simple JavaScript code snippets that would trigger these errors. For example, `undefined.property` triggers a "Cannot read properties of undefined" error, which corresponds to `NonObjectPropertyLoadWithProperty`. `let x; console.log(x.y)` triggers "Cannot access 'x' before initialization", corresponding to `AccessedUninitializedVariable`.

* **Code Logic Inference (if applicable):** In this specific header, there isn't much explicit code logic. It's mostly data definition. However, the *existence* of this file implies logic elsewhere in V8 that *uses* these templates. This logic would involve:
    * Selecting the appropriate template based on the error condition.
    * Substituting values for the placeholders (`%`).
    * Potentially logging or displaying the formatted message.
    *  *Hypothetical Input/Output:* Imagine a function that takes an error identifier (e.g., `NonObjectPropertyLoadWithProperty`) and an object name ("foo") and property name ("bar"). The output would be the formatted string "Cannot read properties of foo (reading 'bar')".

* **Common Programming Errors:**  Relate the error messages back to mistakes developers often make in JavaScript. Examples include:
    * Accessing properties of `null` or `undefined`.
    * Forgetting to use `new` with constructors.
    * Using `await` outside of async functions.
    * Making mistakes with `try...catch` and unhandled exceptions.

* **Part 1 Summary:**  Combine all the findings into a concise summary of the file's purpose and key characteristics.

**4. Refinement and Structure:**

* Organize the answers logically, addressing each part of the prompt clearly.
* Use clear and concise language.
* Provide specific examples to illustrate the points.
* Emphasize the key takeaway: this file defines the *vocabulary* of errors and messages within V8.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just a list of strings.
* **Correction:** The `#define MESSAGE_TEMPLATES(T)` structure indicates more than just a simple list. It's a mechanism for generating code or data.
* **Initial thought:** The JavaScript examples should be complex.
* **Correction:** Simple, direct examples that clearly illustrate the error are more effective.
* **Initial thought:** Focus only on the technical aspects.
* **Correction:**  Remember to address the user-centric aspect of common programming errors.

By following this structured approach, combining keyword recognition, pattern analysis, and relating the content to JavaScript concepts, a comprehensive understanding of the `message-template.h` file can be achieved.
## 功能归纳：v8/src/common/message-template.h (第 1 部分)

这个头文件 `v8/src/common/message-template.h` 的主要功能是**定义了一系列预定义的错误和信息消息模板**，这些模板在 V8 引擎的各个部分被广泛使用，用于生成用户可见的错误消息和内部调试信息。

**具体功能点：**

1. **集中管理错误消息模板:**  它将大量的错误消息字符串集中在一个地方进行管理，方便查找、修改和维护。
2. **定义错误类型:**  通过注释 `/* Error */`, `/* TypeError */`, `/* ReferenceError */`, `/* RangeError */` 等，将消息模板组织成不同的错误类型，有助于 V8 内部的错误处理和分类。
3. **使用宏进行定义:**  使用 C++ 宏 `MESSAGE_TEMPLATES(T)` 来定义消息模板。这个宏接受一个参数 `T`，`T` 通常是一个用于生成具体消息的宏或函数。这种方式允许 V8 灵活地使用这些模板，例如，可以生成包含错误代码的消息，或者用于国际化翻译。
4. **提供占位符:**  很多消息模板中包含占位符 `%`，这些占位符在实际使用时会被具体的变量值替换，从而生成更详细的错误信息。
5. **覆盖多种错误场景:**  消息模板涵盖了各种 JavaScript 运行时可能出现的错误，例如类型错误、引用错误、范围错误、语法错误（虽然这里没有直接列出语法错误，但其他类型的错误也可能由语法问题导致）以及 V8 引擎内部的错误。

**关于文件扩展名和 Torque：**

你提供的信息是正确的。如果 `v8/src/common/message-template.h` 文件以 `.tq` 结尾，那么它很可能是一个 V8 Torque 源代码文件。Torque 是 V8 自定义的类型化汇编语言，用于编写 V8 的内置函数和运行时代码。

但根据你提供的代码片段，该文件以 `.h` 结尾，因此它是一个标准的 C++ 头文件，而不是 Torque 源代码。

**与 JavaScript 功能的关系（及 JavaScript 举例）：**

`v8/src/common/message-template.h` 中定义的消息模板直接对应着 JavaScript 运行时可能抛出的各种错误。当 JavaScript 代码执行出错时，V8 引擎会根据发生的错误类型，从这个头文件中选择相应的消息模板，并将具体的错误信息填充到占位符中，最终生成用户看到的 JavaScript 错误消息。

**JavaScript 示例：**

* **TypeError:**  `T(ApplyNonFunction, ...)` 对应于尝试调用非函数类型的值时抛出的错误。

   ```javascript
   let notAFunction = "hello";
   try {
     notAFunction(); // TypeError: notAFunction is not a function
   } catch (e) {
     console.error(e.message); // 输出类似 "hello is not a function" 的消息
   }
   ```

* **ReferenceError:** `T(NotDefined, "% is not defined")` 对应于访问未声明的变量时抛出的错误。

   ```javascript
   try {
     console.log(undeclaredVariable); // ReferenceError: undeclaredVariable is not defined
   } catch (e) {
     console.error(e.message); // 输出类似 "undeclaredVariable is not defined" 的消息
   }
   ```

* **RangeError:** `T(InvalidArrayLength, "Invalid array length")` 对应于尝试创建或修改具有无效长度的数组时抛出的错误。

   ```javascript
   try {
     let arr = new Array(-1); // RangeError: Invalid array length
   } catch (e) {
     console.error(e.message); // 输出 "Invalid array length"
   }
   ```

**代码逻辑推理和假设输入/输出：**

虽然这个头文件本身不包含直接的执行逻辑，但可以推断出 V8 内部有使用这些模板的逻辑。

**假设：** V8 内部有一个函数 `FormatErrorMessage(MessageTemplateId id, ...args)`，它接收一个消息模板 ID 和一些参数。

**假设输入：**

* `id`:  `TypeError::NonObjectPropertyLoadWithProperty` （对应 `T(NonObjectPropertyLoadWithProperty, "Cannot read properties of % (reading '%')")`)
* `args`:  `[null, "name"]`

**预期输出：**

`"Cannot read properties of null (reading 'name')"`

**用户常见的编程错误举例：**

这个头文件中列出的消息模板很多都直接反映了用户常见的编程错误：

* **`TypeError: Cannot read properties of undefined (reading '...')`:**  忘记检查变量是否为 `null` 或 `undefined` 就尝试访问其属性。
   ```javascript
   let obj = undefined;
   console.log(obj.name); // 导致此错误
   ```

* **`ReferenceError: ... is not defined`:**  使用了未声明的变量。
   ```javascript
   console.log(myVariable); // 如果 myVariable 没有被声明，则会报错
   ```

* **`TypeError: ... is not a function`:**  尝试调用一个非函数类型的值。
   ```javascript
   let notFunc = 10;
   notFunc(); // 导致此错误
   ```

* **`TypeError: ... called on null or undefined`:**  在 `null` 或 `undefined` 上调用了某个方法。
   ```javascript
   let str = null;
   str.toUpperCase(); // 导致此错误
   ```

**总结：**

`v8/src/common/message-template.h` (第 1 部分) 是 V8 引擎中一个至关重要的组成部分，它集中定义了各种预定义的错误和信息消息模板，这些模板用于向用户报告 JavaScript 运行时错误，并支持 V8 内部的调试和错误处理。 这些模板与 JavaScript 的错误类型和用户常见的编程错误息息相关。

### 提示词
```
这是目录为v8/src/common/message-template.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/common/message-template.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMMON_MESSAGE_TEMPLATE_H_
#define V8_COMMON_MESSAGE_TEMPLATE_H_

#include "src/base/logging.h"

namespace v8 {
namespace internal {

#define MESSAGE_TEMPLATES(T)                                                   \
  /* Error */                                                                  \
  T(None, "")                                                                  \
  T(ConflictingPrivateName,                                                    \
    "Operation is ambiguous because there are more than one private name"      \
    "'%' on the object")                                                       \
  T(CyclicProto, "Cyclic __proto__ value")                                     \
  T(Debugger, "Debugger: %")                                                   \
  T(DebuggerLoading, "Error loading debugger")                                 \
  T(DefaultOptionsMissing, "Internal % error. Default options are missing.")   \
  T(DeletePrivateField, "Private fields can not be deleted")                   \
  T(PlaceholderOnly, "%")                                                      \
  T(UncaughtException, "Uncaught %")                                           \
  T(Unsupported, "Not supported")                                              \
  T(WrongServiceType, "Internal error, wrong service type: %")                 \
  T(WrongValueType, "Internal error. Wrong value type.")                       \
  T(IcuError, "Internal error. Icu error.")                                    \
  /* TypeError */                                                              \
  T(ApplyNonFunction,                                                          \
    "Function.prototype.apply was called on %, which is % and not a "          \
    "function")                                                                \
  T(ArgumentsDisallowedInInitializerAndStaticBlock,                            \
    "'arguments' is not allowed in class field initializer or static "         \
    "initialization block")                                                    \
  T(ArgumentIsNonObject, "% argument must be an object")                       \
  T(ArgumentIsNonString, "% argument must be a string")                        \
  T(ArrayBufferDetachKeyDoesntMatch,                                           \
    "Provided key doesn't match [[ArrayBufferDetachKey]]")                     \
  T(ArrayBufferTooShort,                                                       \
    "Derived ArrayBuffer constructor created a buffer which was too small")    \
  T(ArrayBufferSpeciesThis,                                                    \
    "ArrayBuffer subclass returned this from species constructor")             \
  T(AwaitNotInAsyncContext,                                                    \
    "await is only valid in async functions and the top level bodies of "      \
    "modules")                                                                 \
  T(AwaitNotInDebugEvaluate,                                                   \
    "await can not be used when evaluating code "                              \
    "while paused in the debugger")                                            \
  T(AtomicsMutexNotOwnedByCurrentThread,                                       \
    "Atomics.Mutex is not owned by the current agent")                         \
  T(AtomicsOperationNotAllowed, "% cannot be called in this context")          \
  T(BadRoundingType, "RoundingType is not fractionDigits")                     \
  T(BadSortComparisonFunction,                                                 \
    "The comparison function must be either a function or undefined: %")       \
  T(BigIntFromNumber,                                                          \
    "The number % cannot be converted to a BigInt because it is not an "       \
    "integer")                                                                 \
  T(BigIntFromObject, "Cannot convert % to a BigInt")                          \
  T(BigIntMixedTypes,                                                          \
    "Cannot mix BigInt and other types, use explicit conversions")             \
  T(BigIntSerializeJSON, "Do not know how to serialize a BigInt")              \
  T(BigIntShr, "BigInts have no unsigned right shift, use >> instead")         \
  T(BigIntToNumber, "Cannot convert a BigInt value to a number")               \
  T(CalledNonCallable, "% is not a function")                                  \
  T(CalledOnNonObject, "% called on non-object")                               \
  T(CalledOnNullOrUndefined, "% called on null or undefined")                  \
  T(CallShadowRealmEvaluateThrew, "ShadowRealm evaluate threw (%)")            \
  T(CallSiteExpectsFunction,                                                   \
    "CallSite expects wasm object as first or function as second argument, "   \
    "got <%, %>")                                                              \
  T(CallSiteMethod, "CallSite method % expects CallSite as receiver")          \
  T(CallSiteMethodUnsupportedInShadowRealm,                                    \
    "CallSite method % is unsupported inside ShadowRealms")                    \
  T(CallWrappedFunctionThrew, "WrappedFunction threw (%)")                     \
  T(CannotBeShared, "% cannot be shared")                                      \
  T(CannotConvertToPrimitive, "Cannot convert object to primitive value")      \
  T(CannotPreventExt, "Cannot prevent extensions")                             \
  T(CannotFreeze, "Cannot freeze")                                             \
  T(CannotFreezeArrayBufferView,                                               \
    "Cannot freeze array buffer views with elements")                          \
  T(CannotSeal, "Cannot seal")                                                 \
  T(CannotWrap, "Cannot wrap target callable (%)")                             \
  T(CircularStructure, "Converting circular structure to JSON%")               \
  T(ConstructAbstractClass, "Abstract class % not directly constructable")     \
  T(ConstAssign, "Assignment to constant variable.")                           \
  T(ConstructorClassField, "Classes may not have a field named 'constructor'") \
  T(ConstructorNonCallable,                                                    \
    "Class constructor % cannot be invoked without 'new'")                     \
  T(AnonymousConstructorNonCallable,                                           \
    "Class constructors cannot be invoked without 'new'")                      \
  T(ConstructorNotFunction, "Constructor % requires 'new'")                    \
  T(ConstructorNotReceiver, "The .constructor property is not an object")      \
  T(CurrencyCode, "Currency code is required with currency style.")            \
  T(CyclicModuleDependency, "Detected cycle while resolving name '%' in '%'")  \
  T(DataViewNotArrayBuffer,                                                    \
    "First argument to DataView constructor must be an ArrayBuffer")           \
  T(DateType, "this is not a Date object.")                                    \
  T(DebuggerFrame, "Debugger: Invalid frame index.")                           \
  T(DebuggerType, "Debugger: Parameters have wrong types.")                    \
  T(DeclarationMissingInitializer, "Missing initializer in % declaration")     \
  T(DefineDisallowed, "Cannot define property %, object is not extensible")    \
  T(DefineDisallowedFixedLayout,                                               \
    "Cannot define property %, object has fixed layout")                       \
  T(DetachedOperation, "Cannot perform % on a detached ArrayBuffer")           \
  T(DoNotUse, "Do not use %; %")                                               \
  T(DuplicateTemplateProperty, "Object template has duplicate property '%'")   \
  T(ExtendsValueNotConstructor,                                                \
    "Class extends value % is not a constructor or null")                      \
  T(FirstArgumentNotRegExp,                                                    \
    "First argument to % must not be a regular expression")                    \
  T(FunctionBind, "Bind must be called on a function")                         \
  T(GeneratorRunning, "Generator is already running")                          \
  T(IllegalInvocation, "Illegal invocation")                                   \
  T(ImmutablePrototypeSet,                                                     \
    "Immutable prototype object '%' cannot have their prototype set")          \
  T(ImportAttributesDuplicateKey, "Import attribute has duplicate key '%'")    \
  T(ImportCallNotNewExpression, "Cannot use new with import")                  \
  T(ImportOutsideModule, "Cannot use import statement outside a module")       \
  T(ImportMetaOutsideModule, "Cannot use 'import.meta' outside a module")      \
  T(ImportMissingSpecifier, "import() requires a specifier")                   \
  T(ImportShadowRealmRejected, "Cannot import in ShadowRealm (%)")             \
  T(IncompatibleMethodReceiver, "Method % called on incompatible receiver %")  \
  T(InstanceofNonobjectProto,                                                  \
    "Function has non-object prototype '%' in instanceof check")               \
  T(InvalidArgument, "invalid_argument")                                       \
  T(InvalidArgumentForTemporal, "Invalid argument for Temporal %")             \
  T(InvalidInOperatorUse, "Cannot use 'in' operator to search for '%' in %")   \
  T(InvalidRawJsonValue, "Invalid value for JSON.rawJSON")                     \
  T(InvalidRegExpExecResult,                                                   \
    "RegExp exec method returned something other than an Object or null")      \
  T(InvalidUnit, "Invalid unit argument for %() '%'")                          \
  T(IsNotNumber, "Type of '%' must be 'number', found '%'")                    \
  T(IterableYieldedNonString, "Iterable yielded % which is not a string")      \
  T(IteratorReduceNoInitial,                                                   \
    "Reduce of a done iterator with no initial value")                         \
  T(IteratorResultNotAnObject, "Iterator result % is not an object")           \
  T(SpreadIteratorSymbolNonCallable,                                           \
    "Spread syntax requires ...iterable[Symbol.iterator] to be a function")    \
  T(FirstArgumentIteratorSymbolNonCallable,                                    \
    "% requires that the property of the first argument, "                     \
    "items[Symbol.iterator], when exists, be a function")                      \
  T(FirstArgumentAsyncIteratorSymbolNonCallable,                               \
    "% requires that the property of the first argument, "                     \
    "items[Symbol.asyncIterator], when exists, be a function")                 \
  T(IteratorValueNotAnObject, "Iterator value % is not an entry object")       \
  T(KeysMethodInvalid, "Result of the keys method is not an object")           \
  T(LanguageID, "Language ID should be string or object.")                     \
  T(LocaleNotEmpty,                                                            \
    "First argument to Intl.Locale constructor can't be empty or missing")     \
  T(LocaleBadParameters, "Incorrect locale information provided")              \
  T(ListFormatBadParameters, "Incorrect ListFormat information provided")      \
  T(MapperFunctionNonCallable, "flatMap mapper function is not callable")      \
  T(MethodInvokedOnWrongType, "Method invoked on an object that is not %.")    \
  T(NoAccess, "no access")                                                     \
  T(NonCallableInInstanceOfCheck,                                              \
    "Right-hand side of 'instanceof' is not callable")                         \
  T(NonCoercible, "Cannot destructure '%' as it is %.")                        \
  T(NonCoercibleWithProperty,                                                  \
    "Cannot destructure property '%' of '%' as it is %.")                      \
  T(NonExtensibleProto, "% is not extensible")                                 \
  T(NonObjectAttributesOption, "The 'with' option must be an object")          \
  T(NonObjectInInstanceOfCheck,                                                \
    "Right-hand side of 'instanceof' is not an object")                        \
  T(NonObjectPrivateNameAccess, "Cannot access private name % from %")         \
  T(NonObjectPropertyLoad, "Cannot read properties of %")                      \
  T(NonObjectPropertyLoadWithProperty,                                         \
    "Cannot read properties of % (reading '%')")                               \
  T(NonObjectPropertyStore, "Cannot set properties of %")                      \
  T(NonObjectPropertyStoreWithProperty,                                        \
    "Cannot set properties of % (setting '%')")                                \
  T(NonObjectImportArgument,                                                   \
    "The second argument to import() must be an object")                       \
  T(NonStringImportAttributeValue, "Import attribute value must be a string")  \
  T(NoSetterInCallback, "Cannot set property % of % which has only a getter")  \
  T(NotAnIterator, "% is not an iterator")                                     \
  T(PromiseNewTargetUndefined,                                                 \
    "Promise constructor cannot be invoked without 'new'")                     \
  T(NotConstructor, "% is not a constructor")                                  \
  T(NotDateObject, "this is not a Date object.")                               \
  T(NotGeneric, "% requires that 'this' be a %")                               \
  T(NotCallable, "% is not a function")                                        \
  T(NotCallableOrIterable,                                                     \
    "% is not a function or its return value is not iterable")                 \
  T(NotCallableOrAsyncIterable,                                                \
    "% is not a function or its return value is not async iterable")           \
  T(NotFiniteNumber, "Value need to be finite number for %()")                 \
  T(NotIterable, "% is not iterable")                                          \
  T(NotIterableNoSymbolLoad, "% is not iterable (cannot read property %)")     \
  T(NotAsyncIterable, "% is not async iterable")                               \
  T(NotPropertyName, "% is not a valid property name")                         \
  T(NotTypedArray, "this is not a typed array.")                               \
  T(NotSuperConstructor, "Super constructor % of % is not a constructor")      \
  T(NotSuperConstructorAnonymousClass,                                         \
    "Super constructor % of anonymous class is not a constructor")             \
  T(NotIntegerTypedArray, "% is not an integer typed array.")                  \
  T(NotInt32OrBigInt64TypedArray,                                              \
    "% is not an int32 or BigInt64 typed array.")                              \
  T(NotSharedTypedArray, "% is not a shared typed array.")                     \
  T(ObjectFixedLayout, "Cannot add property %, object has fixed layout")       \
  T(ObjectGetterExpectingFunction,                                             \
    "Object.prototype.__defineGetter__: Expecting function")                   \
  T(ObjectGetterCallable, "Getter must be a function: %")                      \
  T(ObjectNotExtensible, "Cannot add property %, object is not extensible")    \
  T(ObjectSetterExpectingFunction,                                             \
    "Object.prototype.__defineSetter__: Expecting function")                   \
  T(ObjectSetterCallable, "Setter must be a function: %")                      \
  T(OrdinaryFunctionCalledAsConstructor,                                       \
    "Function object that's not a constructor was created with new")           \
  T(PromiseCyclic, "Chaining cycle detected for promise %")                    \
  T(PromiseExecutorAlreadyInvoked,                                             \
    "Promise executor has already been invoked with non-undefined arguments")  \
  T(PromiseNonCallable, "Promise resolve or reject function is not callable")  \
  T(PropertyDescObject, "Property description must be an object: %")           \
  T(PropertyNotFunction,                                                       \
    "'%' returned for property '%' of object '%' is not a function")           \
  T(ProtoObjectOrNull, "Object prototype may only be an Object or null: %")    \
  T(PrototypeParentNotAnObject,                                                \
    "Class extends value does not have valid prototype property %")            \
  T(ProxyConstructNonObject,                                                   \
    "'construct' on proxy: trap returned non-object ('%')")                    \
  T(ProxyDefinePropertyNonConfigurable,                                        \
    "'defineProperty' on proxy: trap returned truish for defining "            \
    "non-configurable property '%' which is either non-existent or "           \
    "configurable in the proxy target")                                        \
  T(ProxyDefinePropertyNonConfigurableWritable,                                \
    "'defineProperty' on proxy: trap returned truish for defining "            \
    "non-configurable property '%' which cannot be non-writable, unless "      \
    "there exists a corresponding non-configurable, non-writable own "         \
    "property of the target object.")                                          \
  T(ProxyDefinePropertyNonExtensible,                                          \
    "'defineProperty' on proxy: trap returned truish for adding property '%' " \
    " to the non-extensible proxy target")                                     \
  T(ProxyDefinePropertyIncompatible,                                           \
    "'defineProperty' on proxy: trap returned truish for adding property '%' " \
    " that is incompatible with the existing property in the proxy target")    \
  T(ProxyDeletePropertyNonConfigurable,                                        \
    "'deleteProperty' on proxy: trap returned truish for property '%' which "  \
    "is non-configurable in the proxy target")                                 \
  T(ProxyDeletePropertyNonExtensible,                                          \
    "'deleteProperty' on proxy: trap returned truish for property '%' but "    \
    "the proxy target is non-extensible")                                      \
  T(ProxyGetNonConfigurableData,                                               \
    "'get' on proxy: property '%' is a read-only and "                         \
    "non-configurable data property on the proxy target but the proxy "        \
    "did not return its actual value (expected '%' but got '%')")              \
  T(ProxyGetNonConfigurableAccessor,                                           \
    "'get' on proxy: property '%' is a non-configurable accessor "             \
    "property on the proxy target and does not have a getter function, but "   \
    "the trap did not return 'undefined' (got '%')")                           \
  T(ProxyGetOwnPropertyDescriptorIncompatible,                                 \
    "'getOwnPropertyDescriptor' on proxy: trap returned descriptor for "       \
    "property '%' that is incompatible with the existing property in the "     \
    "proxy target")                                                            \
  T(ProxyGetOwnPropertyDescriptorInvalid,                                      \
    "'getOwnPropertyDescriptor' on proxy: trap returned neither object nor "   \
    "undefined for property '%'")                                              \
  T(ProxyGetOwnPropertyDescriptorNonConfigurable,                              \
    "'getOwnPropertyDescriptor' on proxy: trap reported non-configurability "  \
    "for property '%' which is either non-existent or configurable in the "    \
    "proxy target")                                                            \
  T(ProxyGetOwnPropertyDescriptorNonConfigurableWritable,                      \
    "'getOwnPropertyDescriptor' on proxy: trap reported non-configurable "     \
    "and non-writable for property '%' which is non-configurable, writable "   \
    "in the proxy target")                                                     \
  T(ProxyGetOwnPropertyDescriptorNonExtensible,                                \
    "'getOwnPropertyDescriptor' on proxy: trap returned undefined for "        \
    "property '%' which exists in the non-extensible proxy target")            \
  T(ProxyGetOwnPropertyDescriptorUndefined,                                    \
    "'getOwnPropertyDescriptor' on proxy: trap returned undefined for "        \
    "property '%' which is non-configurable in the proxy target")              \
  T(ProxyGetPrototypeOfInvalid,                                                \
    "'getPrototypeOf' on proxy: trap returned neither object nor null")        \
  T(ProxyGetPrototypeOfNonExtensible,                                          \
    "'getPrototypeOf' on proxy: proxy target is non-extensible but the "       \
    "trap did not return its actual prototype")                                \
  T(ProxyHasNonConfigurable,                                                   \
    "'has' on proxy: trap returned falsish for property '%' which exists in "  \
    "the proxy target as non-configurable")                                    \
  T(ProxyHasNonExtensible,                                                     \
    "'has' on proxy: trap returned falsish for property '%' but the proxy "    \
    "target is not extensible")                                                \
  T(ProxyIsExtensibleInconsistent,                                             \
    "'isExtensible' on proxy: trap result does not reflect extensibility of "  \
    "proxy target (which is '%')")                                             \
  T(ProxyNonObject,                                                            \
    "Cannot create proxy with a non-object as target or handler")              \
  T(ProxyOwnKeysMissing,                                                       \
    "'ownKeys' on proxy: trap result did not include '%'")                     \
  T(ProxyOwnKeysNonExtensible,                                                 \
    "'ownKeys' on proxy: trap returned extra keys but proxy target is "        \
    "non-extensible")                                                          \
  T(ProxyOwnKeysDuplicateEntries,                                              \
    "'ownKeys' on proxy: trap returned duplicate entries")                     \
  T(ProxyPreventExtensionsExtensible,                                          \
    "'preventExtensions' on proxy: trap returned truish but the proxy target " \
    "is extensible")                                                           \
  T(ProxyPrivate, "Cannot pass private property name to proxy trap")           \
  T(ProxyRevoked, "Cannot perform '%' on a proxy that has been revoked")       \
  T(ProxySetFrozenData,                                                        \
    "'set' on proxy: trap returned truish for property '%' which exists in "   \
    "the proxy target as a non-configurable and non-writable data property "   \
    "with a different value")                                                  \
  T(ProxySetFrozenAccessor,                                                    \
    "'set' on proxy: trap returned truish for property '%' which exists in "   \
    "the proxy target as a non-configurable and non-writable accessor "        \
    "property without a setter")                                               \
  T(ProxySetPrototypeOfNonExtensible,                                          \
    "'setPrototypeOf' on proxy: trap returned truish for setting a new "       \
    "prototype on the non-extensible proxy target")                            \
  T(ProxyTrapReturnedFalsish, "'%' on proxy: trap returned falsish")           \
  T(ProxyTrapReturnedFalsishFor,                                               \
    "'%' on proxy: trap returned falsish for property '%'")                    \
  T(RedefineDisallowed, "Cannot redefine property: %")                         \
  T(RedefineExternalArray,                                                     \
    "Cannot redefine a property of an object with external array elements")    \
  T(ReduceNoInitial, "Reduce of empty array with no initial value")            \
  T(RegExpFlags,                                                               \
    "Cannot supply flags when constructing one RegExp from another")           \
  T(RegExpNonObject, "% getter called on non-object %")                        \
  T(RegExpNonRegExp, "% getter called on non-RegExp object")                   \
  T(RegExpGlobalInvokedOnNonGlobal,                                            \
    "% called with a non-global RegExp argument")                              \
  T(RelativeDateTimeFormatterBadParameters,                                    \
    "Incorrect RelativeDateTimeFormatter provided")                            \
  T(ResolverNotAFunction, "Promise resolver % is not a function")              \
  T(ReturnMethodNotCallable, "The iterator's 'return' method is not callable") \
  T(SizeIsNaN, "The .size property is NaN")                                    \
  T(ShadowRealmErrorStackNonString,                                            \
    "Error stack is not a string in ShadowRealm (%)")                          \
  T(ShadowRealmErrorStackThrows,                                               \
    "Error stack getter threw in ShadowRealm (%)")                             \
  T(SharedArrayBufferTooShort,                                                 \
    "Derived SharedArrayBuffer constructor created a buffer which was too "    \
    "small")                                                                   \
  T(SharedArrayBufferSpeciesThis,                                              \
    "SharedArrayBuffer subclass returned this from species constructor")       \
  T(SharedStructTypeRegistryMismatch,                                          \
    "SharedStructType registered as '%' does not match")                       \
  T(StaticPrototype,                                                           \
    "Classes may not have a static property named 'prototype'")                \
  T(StrictDeleteProperty, "Cannot delete property '%' of %")                   \
  T(StrictPoisonPill,                                                          \
    "'caller', 'callee', and 'arguments' properties may not be accessed on "   \
    "strict mode functions or the arguments objects for calls to them")        \
  T(StrictReadOnlyProperty,                                                    \
    "Cannot assign to read only property '%' of % '%'")                        \
  T(StrictCannotCreateProperty, "Cannot create property '%' on % '%'")         \
  T(StringMatchAllNullOrUndefinedFlags,                                        \
    "The .flags property of the argument to String.prototype.matchAll cannot " \
    "be null or undefined")                                                    \
  T(SymbolIteratorInvalid,                                                     \
    "Result of the Symbol.iterator method is not an object")                   \
  T(SymbolAsyncIteratorInvalid,                                                \
    "Result of the Symbol.asyncIterator method is not an object")              \
  T(SymbolKeyFor, "% is not a symbol")                                         \
  T(SymbolToNumber, "Cannot convert a Symbol value to a number")               \
  T(SymbolToString, "Cannot convert a Symbol value to a string")               \
  T(ThrowMethodMissing, "The iterator does not provide a 'throw' method.")     \
  T(TopLevelAwaitStalled, "Top-level await promise never resolved")            \
  T(UndefinedOrNullToObject, "Cannot convert undefined or null to object")     \
  T(UsingAssign, "Assignment to using variable.")                              \
  T(ValueAndAccessor,                                                          \
    "Invalid property descriptor. Cannot both specify accessors and a value "  \
    "or writable attribute, %")                                                \
  T(VarRedeclaration, "Identifier '%' has already been declared")              \
  T(VarNotAllowedInEvalScope,                                                  \
    "Identifier '%' cannot be declared with 'var' in current evaluation "      \
    "scope, consider trying 'let' instead")                                    \
  T(WrongArgs, "%: Arguments list has wrong type")                             \
  /* ReferenceError */                                                         \
  T(NotDefined, "% is not defined")                                            \
  T(SuperAlreadyCalled, "Super constructor may only be called once")           \
  T(AccessedUninitializedVariable, "Cannot access '%' before initialization")  \
  T(UnsupportedSuper, "Unsupported reference to 'super'")                      \
  T(AccessedUnavailableVariable, "Cannot access '%' from debugger")            \
  T(DisposableStackIsDisposed,                                                 \
    "Cannot call % on an already-disposed DisposableStack")                    \
  T(NotAnAsyncDisposableStack, "Receiver is not an AsyncDisposableStack")      \
  /* RangeError */                                                             \
  T(BigIntDivZero, "Division by zero")                                         \
  T(BigIntTooBig, "Maximum BigInt size exceeded")                              \
  T(CantSetOptionXWhenYIsUsed, "Can't set option % when % is used")            \
  T(DateRange, "Provided date is not in valid range.")                         \
  T(ExpectedLocation,                                                          \
    "Expected letters optionally connected with underscores or hyphens for "   \
    "a location, got %")                                                       \
  T(InvalidArrayBufferLength, "Invalid array buffer length")                   \
  T(InvalidArrayBufferMaxLength, "Invalid array buffer max length")            \
  T(InvalidArrayBufferResizeLength, "%: Invalid length parameter")             \
  T(ArrayBufferAllocationFailed, "Array buffer allocation failed")             \
  T(Invalid, "Invalid % : %")                                                  \
  T(InvalidArrayLength, "Invalid array length")                                \
  T(InvalidAtomicAccessIndex, "Invalid atomic access index")                   \
  T(InvalidCalendar, "Invalid calendar specified: %")                          \
  T(InvalidCodePoint, "Invalid code point %")                                  \
  T(InvalidCountValue, "Invalid count value: %")                               \
  T(InvalidDataViewAccessorOffset,                                             \
    "Offset is outside the bounds of the DataView")                            \
  T(InvalidDataViewLength, "Invalid DataView length %")                        \
  T(InvalidOffset, "Start offset % is outside the bounds of the buffer")       \
  T(InvalidHint, "Invalid hint: %")                                            \
  T(InvalidIndex, "Invalid value: not (convertible to) a safe integer")        \
  T(InvalidLanguageTag, "Invalid language tag: %")                             \
  T(InvalidWeakMapKey, "Invalid value used as weak map key")                   \
  T(InvalidWeakSetValue, "Invalid value used in weak set")                     \
  T(InvalidShadowRealmEvaluateSourceText, "Invalid value used as source text") \
  T(InvalidStringLength, "Invalid string length")                              \
  T(InvalidTimeValue, "Invalid time value")                                    \
  T(InvalidTimeValueForTemporal, "Invalid time value for Temporal %")          \
  T(InvalidTimeZone, "Invalid time zone specified: %")                         \
  T(InvalidTypedArrayAlignment, "% of % should be a mul
```
Response:
Let's break down the thought process for analyzing this V8 builtins definition file.

1. **Understanding the Goal:** The primary goal is to understand the *functionality* of the provided C++ macro code snippet, which is part of V8's `builtins-definitions.h`. The request also asks about Torque, JavaScript relationships, code logic, common errors, and a summary specifically for this "part 3" of the file.

2. **Initial Assessment - It's not Torque:** The first instruction is to check if the file ends in `.tq`. It doesn't, so we immediately know it's not a Torque file. This simplifies things slightly as we don't need to consider the specifics of Torque syntax.

3. **Identifying the Core Functionality:** The code consists of a large macro invocation with various arguments. The structure `C(...)`, `TFC(...)`, `TFJ(...)`, `CPP(...)`, `ASM(...)`, `TFS(...)`, etc., strongly suggests it's defining *built-in functions*. The names within the parentheses (e.g., `ModulusSmi_Baseline`, `ObjectAssign`, `RegExpConstructor`) further reinforce this idea, as they resemble JavaScript functions and operators.

4. **Deconstructing the Macros:**  It's crucial to recognize that these are *macros*. They aren't the actual implementation of the built-ins, but rather *declarations* or *definitions* that will be expanded by the C++ preprocessor. We need to infer what these macros likely *do*.

    * **`C`, `TFC`, `TFJ`, `CPP`, `ASM`, `TFS`:**  These likely represent different categories or types of built-in functions. A reasonable hypothesis is that they differ in their implementation language (C++, Torque, Assembly), argument handling, or performance characteristics. The presence of "Baseline" and "WithFeedback" suffixes suggests different optimization levels.

    * **Arguments within the macros:** The arguments provide important clues. For example:
        * `ModulusSmi_Baseline, BinarySmiOp_Baseline`: Likely a modulus operation optimized for small integers (Smis).
        * `ObjectAssign, kDontAdaptArgumentsSentinel`: Suggests the `Object.assign` built-in. The `kDontAdaptArgumentsSentinel` likely relates to how arguments are passed.
        * `RegExpConstructor, kJSArgcReceiverSlots + 2, kReceiver, kPattern, kFlags`: Clearly defines the arguments for the `RegExp` constructor.
        * `NeedsContext::kYes`:  Indicates that the built-in needs access to the execution context.
        * `JSParameterCount(n)`:  Specifies the expected number of parameters.

5. **Connecting to JavaScript Functionality:**  Since the names within the macros closely match JavaScript built-in functions and operators, it's straightforward to connect them. The request specifically asks for JavaScript examples. We can take some of the more recognizable names and provide basic JavaScript usage. For example:

    * `ObjectAssign`: `Object.assign({}, {a: 1})`
    * `RegExpConstructor`: `new RegExp("pattern", "flags")`
    * `SetPrototypeAdd`: `new Set().add(1)`
    * Arithmetic/Comparison operators: Directly using operators like `+`, `-`, `===`, etc.

6. **Code Logic Inference (High-Level):** While this snippet doesn't contain *implementation* logic, we can infer *logical relationships*. The "Baseline" and "WithFeedback" versions suggest conditional execution based on runtime performance data. The different macros imply different execution paths or underlying implementations. For instance, `ASM` likely points to hand-optimized assembly code.

7. **Common Programming Errors:** Based on the function names, we can deduce common errors. For example:

    * Incorrect number of arguments to functions (especially evident with `JSParameterCount`).
    * Type mismatches in arithmetic or comparison operations.
    * Incorrect usage of `RegExp` (e.g., forgetting flags).
    * Misunderstanding the behavior of `Object.assign`.

8. **Focusing on "Part 3":**  The request emphasizes this is "part 3". We need to look at the specific sections in this snippet. This part primarily covers:

    * **Binary and Unary Operators:**  `Add`, `Subtract`, `Multiply`, `BitwiseAnd`, `Negate`, etc., with and without feedback.
    * **Comparison Operators:** `Equal`, `StrictEqual`, `LessThan`, etc., with and without feedback.
    * **`Object` Built-ins:** A significant portion dealing with `Object.assign`, `Object.create`, `Object.defineProperty`, etc.
    * **`instanceof` operator.**
    * **`for...in` loop helpers.**
    * **`Reflect` API.**
    * **`RegExp` built-ins and helpers.**
    * **`Set` built-ins.**
    * **`ShadowRealm` built-ins.**
    * **`SharedArrayBuffer` and `Atomics` built-ins.**
    * **`String` built-ins.**
    * **`Symbol` built-ins.**
    * **`TypedArray` built-ins.**
    * **`Wasm` built-in entries.**
    * **`WeakMap` and `WeakSet` built-ins.**
    * **JS Struct related built-ins.**

9. **Summarization:** The final step is to synthesize the information into a concise summary, hitting the key points: defining built-in functions, the presence of different implementation strategies (with/without feedback, different macros), the strong connection to JavaScript functionality, and the specific areas covered in this particular part of the file. Emphasize that it's a *definition* file, not the implementation itself.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe these are just function prototypes. **Correction:** The presence of macros and the specific naming conventions suggest more than just basic prototypes; they likely drive the generation of the actual built-in function entries.
* **Considering Torque:**  Even though it's not a `.tq` file, some built-ins might *eventually* be implemented in Torque. It's good to mention Torque's role in the broader V8 built-in system.
* **Overly Technical Explanation:**  Avoid going too deep into the low-level details of V8's internal workings unless explicitly necessary. Focus on the functional aspects and the connection to JavaScript.

By following this structured approach, combining code analysis with knowledge of JavaScript and V8 concepts, we can effectively understand the purpose and function of this type of V8 source code.
好的，让我们来分析一下这段 `v8/src/builtins/builtins-definitions.h` 的代码片段。

**功能列举:**

这段代码定义了 V8 引擎中大量的内置函数（built-ins）。这些内置函数是 JavaScript 语言规范中定义的全局函数、对象方法以及操作符的底层实现。

具体来说，这段代码片段涉及了以下功能的内置函数定义：

* **二元运算符 (Binary Operators):**
    * 算术运算符：加法 (`Add`), 减法 (`Subtract`), 乘法 (`Multiply`), 除法 (`Divide`), 取模 (`Modulus`), 指数 (`Exponentiate`)
    * 位运算符：按位与 (`BitwiseAnd`), 按位或 (`BitwiseOr`), 按位异或 (`BitwiseXor`), 左移 (`ShiftLeft`), 右移 (`ShiftRight`), 无符号右移 (`ShiftRightLogical`)
    * 针对小整数 (Smi) 优化的版本 (例如 `ModulusSmi_Baseline`)
    * 带有反馈收集的版本 (例如 `Add_WithFeedback`)，用于性能优化

* **比较运算符 (Compare Operators):**
    * 相等 (`Equal`), 严格相等 (`StrictEqual`), 小于 (`LessThan`), 大于 (`GreaterThan`), 小于等于 (`LessThanOrEqual`), 大于等于 (`GreaterThanOrEqual`)
    * 带有反馈收集的版本

* **一元运算符 (Unary Operators):**
    * 按位取反 (`BitwiseNot`), 递减 (`Decrement`), 递增 (`Increment`), 取负 (`Negate`)
    * 带有反馈收集的版本

* **`Object` 相关的内置函数:**
    * `Object.assign`
    * `Object.create`
    * `Object.defineProperty`, `Object.defineProperties`, `Object.defineGetter`, `Object.defineSetter`
    * `Object.entries`
    * `Object.freeze`
    * `Object.getOwnPropertyDescriptor`, `Object.getOwnPropertyDescriptors`
    * `Object.getOwnPropertyNames`, `Object.getOwnPropertySymbols`
    * `Object.hasOwn`
    * `Object.is`
    * `Object.isFrozen`, `Object.isSealed`
    * `Object.keys`
    * `Object.lookupGetter`, `Object.lookupSetter`
    * `Object.prototype.hasOwnProperty`, `Object.prototype.isPrototypeOf`, `Object.prototype.propertyIsEnumerable`, `Object.prototype.__proto__` (getter/setter)
    * `Object.seal`
    * `Object.prototype.toString`
    * `Object.values`

* **`instanceof` 运算符**

* **`for...in` 循环相关的内置函数**

* **`Reflect` 对象的方法:**
    * `Reflect.apply`
    * `Reflect.construct`
    * `Reflect.defineProperty`
    * `Reflect.ownKeys`
    * `Reflect.set`

* **`RegExp` (正则表达式) 相关的内置函数:**
    * 获取捕获组的 getter (例如 `RegExpCapture1Getter`)
    * `RegExp` 构造函数
    * 获取和设置 `RegExp` 属性的 getter/setter (例如 `RegExpInputGetter`, `RegExpInputSetter`)
    * `RegExp.prototype.compile`, `RegExp.prototype.toString`
    * `RegExp` 执行相关的辅助函数 (例如 `RegExpExecAtom`)

* **`Set` (集合) 相关的内置函数:**
    * `Set` 构造函数
    * `Set.prototype.has`, `Set.prototype.add`, `Set.prototype.delete`, `Set.prototype.clear`
    * `Set.prototype.entries`, `Set.prototype.size` (getter), `Set.prototype.forEach`, `Set.prototype.values`
    * `Set` 迭代器相关的函数

* **`ShadowRealm` 相关的内置函数 (用于创建隔离的 JavaScript 执行环境):**
    * `ShadowRealm` 构造函数
    * `ShadowRealm.prototype.evaluate`, `ShadowRealm.prototype.importValue`
    * 内部辅助函数

* **`SharedArrayBuffer` 和 `Atomics` 相关的内置函数 (用于处理共享内存和原子操作):**
    * `SharedArrayBuffer.prototype.byteLength` (getter), `SharedArrayBuffer.prototype.slice`, `SharedArrayBuffer.prototype.grow`
    * `Atomics.load`, `Atomics.store`, `Atomics.exchange`, `Atomics.compareExchange`, `Atomics.add`, `Atomics.sub`, `Atomics.and`, `Atomics.or`, `Atomics.xor`
    * `Atomics.notify`, `Atomics.isLockFree`, `Atomics.wait`, `Atomics.waitAsync`, `Atomics.pause`

* **`String` 相关的内置函数:**
    * `String.fromCodePoint`, `String.fromCharCode`
    * `String.prototype.lastIndexOf`, `String.prototype.matchAll`, `String.prototype.replace`, `String.prototype.split`
    * `String.raw`

* **`Symbol` 相关的内置函数:**
    * `Symbol` 构造函数
    * `Symbol.for`, `Symbol.keyFor`

* **`TypedArray` (类型化数组) 相关的内置函数:**
    * `TypedArray` 构造函数
    * `TypedArray.prototype.buffer` (getter), `TypedArray.prototype.byteLength` (getter), `TypedArray.prototype.byteOffset` (getter), `TypedArray.prototype.length` (getter)
    * `TypedArray.prototype.copyWithin`, `TypedArray.prototype.fill`, `TypedArray.prototype.includes`, `TypedArray.prototype.indexOf`, `TypedArray.prototype.lastIndexOf`, `TypedArray.prototype.reverse`
    * `TypedArray.prototype.@@toStringTag` (getter)
    * `TypedArray.prototype.map`

* **`Wasm` (WebAssembly) 相关的内置函数 (如果启用了 WebAssembly 支持):**
    * 用于 WebAssembly 模块执行的入口点和辅助函数

* **`WeakMap` 和 `WeakSet` (弱引用集合) 相关的内置函数:**
    * 构造函数
    * `WeakMap.prototype.get`, `WeakMap.prototype.has`, `WeakMap.prototype.set`, `WeakMap.prototype.delete`
    * `WeakSet.prototype.has`, `WeakSet.prototype.add`, `WeakSet.prototype.delete`

* **与 JS 结构体相关的内置函数 (可能用于 V8 的内部优化或实验性特性):**

**关于 `.tq` 结尾:**

你提供的信息是正确的。如果 `v8/src/builtins/builtins-definitions.h` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque** 源代码文件。 Torque 是 V8 团队开发的一种领域特定语言，用于更安全、更高效地编写内置函数。当前的这个文件没有 `.tq` 结尾，因此它是使用 C++ 宏来定义内置函数的。

**与 JavaScript 功能的关系及 JavaScript 示例:**

这段代码定义的内置函数直接对应于 JavaScript 中使用的各种功能。以下是一些示例：

* **算术运算:**
  ```javascript
  let a = 10;
  let b = 5;
  let sum = a + b; // 对应 Add_Baseline 或 Add_WithFeedback
  let product = a * b; // 对应 Multiply_Baseline 或 Multiply_WithFeedback
  ```

* **对象操作:**
  ```javascript
  const obj1 = { x: 1 };
  const obj2 = { y: 2 };
  Object.assign(obj1, obj2); // 对应 ObjectAssign
  ```

* **正则表达式:**
  ```javascript
  const regex = new RegExp("hello", "i"); // 对应 RegExpConstructor
  const str = "Hello World";
  regex.test(str);
  ```

* **集合 (Set):**
  ```javascript
  const mySet = new Set(); // 对应 SetConstructor
  mySet.add(1); // 对应 SetPrototypeAdd
  mySet.has(1); // 对应 SetPrototypeHas
  ```

* **`instanceof` 运算符:**
  ```javascript
  class MyClass {}
  const obj = new MyClass();
  obj instanceof MyClass; // 对应 InstanceOf_Baseline 或 InstanceOf_WithFeedback
  ```

* **`Reflect` API:**
  ```javascript
  const obj = { a: 1 };
  Reflect.defineProperty(obj, 'b', { value: 2 }); // 对应 ReflectDefineProperty
  ```

**代码逻辑推理 (假设输入与输出):**

由于这段代码是内置函数的 *定义*，而不是具体的 *实现*，所以直接进行逻辑推理比较困难。它更像是声明了函数的存在和一些元数据（例如参数数量）。

但是，我们可以根据函数名称推断其大致的输入和输出。例如：

* **`Add_Baseline(a, b)`:**
    * **假设输入:** 两个数字 `a` 和 `b`。
    * **预期输出:** `a + b` 的结果。

* **`ObjectGetOwnPropertyDescriptor(obj, prop)`:**
    * **假设输入:** 一个对象 `obj` 和一个属性名 `prop` (字符串或 Symbol)。
    * **预期输出:** 一个描述 `obj` 上 `prop` 属性的描述符对象，如果属性不存在则返回 `undefined`。

* **`SetPrototypeAdd(set, value)`:**
    * **假设输入:** 一个 `Set` 对象 `set` 和一个要添加的值 `value`。
    * **预期输出:** 修改后的 `set` 对象本身，添加了 `value` (如果 `value` 尚未存在于集合中)。

**用户常见的编程错误:**

这段代码中定义的内置函数在 JavaScript 编程中被广泛使用，因此与许多常见的编程错误相关：

* **类型错误:**
    * 对非数字类型进行算术运算 (`"hello" + 5`)。
    * 比较不同类型的变量时没有考虑类型转换 (`1 == "1"` vs. `1 === "1"`)。
    * 传递错误类型的参数给内置函数 (例如，传递一个字符串给 `Math.sqrt`)。

* **`undefined` 或 `null` 引用错误:**
    ```javascript
    let obj;
    obj.property; // TypeError: Cannot read properties of undefined
    ```
    这可能与 `Object` 相关的内置函数有关，例如尝试访问不存在的属性。

* **正则表达式使用错误:**
    * 正则表达式语法错误。
    * 未正确处理 `RegExp` 对象的状态或捕获组。

* **对 `Set` 或 `WeakSet` 的误用:**
    * 期望 `Set` 或 `WeakSet` 像数组一样有索引。
    * 在 `WeakSet` 或 `WeakMap` 中使用不可作为键的对象。

* **`Atomics` 使用错误:**
    * 在非共享的 `ArrayBuffer` 上使用 `Atomics` 操作。
    * 并发编程中出现竞态条件或死锁。

* **`ShadowRealm` 使用错误:**
    * 尝试在不同的 Realm 之间传递不可序列化的对象。
    * 错误地理解 Realm 的隔离性。

**第3部分功能归纳:**

这段作为第3部分的 `builtins-definitions.h` 代码片段，主要集中定义了以下几个方面的 V8 内置函数：

1. **基础的运算符实现:** 包括算术、位运算、比较和一元运算符，并区分了针对小整数优化的版本和带有性能反馈的版本。
2. **核心对象操作:**  涵盖了 `Object` 构造函数及其原型上的许多重要方法，例如属性定义、属性获取、冻结、密封等。
3. **反射 (Reflection) 功能:** 实现了 `Reflect` API，允许在运行时检查和修改代码结构。
4. **正则表达式处理:**  定义了 `RegExp` 构造函数、原型方法以及用于执行正则表达式匹配的底层辅助函数。
5. **集合 (Set) 数据结构:** 实现了 `Set` 构造函数及其原型方法，用于处理唯一值的集合。
6. **隔离的执行环境 (ShadowRealm):** 定义了用于创建和管理隔离 JavaScript 执行环境的内置函数。
7. **共享内存和原子操作:**  涵盖了 `SharedArrayBuffer` 和 `Atomics` API，用于处理多线程环境下的共享内存。
8. **字符串、Symbol 和类型化数组的常用操作:** 定义了 `String`, `Symbol`, 和 `TypedArray` 上的构造函数和原型方法。
9. **WebAssembly 支持 (如果启用):**  包含了 WebAssembly 代码执行相关的入口点。
10. **弱引用集合 (WeakMap 和 WeakSet):** 实现了 `WeakMap` 和 `WeakSet`，用于处理弱引用的键值对和对象集合。
11. **JS 结构体相关功能:**  定义了可能用于内部优化或实验性特性的 JS 结构体相关内置函数。

总而言之，这段代码是 V8 引擎实现 JavaScript 语言核心功能的重要组成部分，它定义了大量用于执行各种 JavaScript 操作的底层函数。

Prompt: 
```
这是目录为v8/src/builtins/builtins-definitions.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-definitions.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
C(ModulusSmi_Baseline, BinarySmiOp_Baseline)                               \
  TFC(Exponentiate_Baseline, BinaryOp_Baseline)                                \
  TFC(ExponentiateSmi_Baseline, BinarySmiOp_Baseline)                          \
  TFC(BitwiseAnd_Baseline, BinaryOp_Baseline)                                  \
  TFC(BitwiseAndSmi_Baseline, BinarySmiOp_Baseline)                            \
  TFC(BitwiseOr_Baseline, BinaryOp_Baseline)                                   \
  TFC(BitwiseOrSmi_Baseline, BinarySmiOp_Baseline)                             \
  TFC(BitwiseXor_Baseline, BinaryOp_Baseline)                                  \
  TFC(BitwiseXorSmi_Baseline, BinarySmiOp_Baseline)                            \
  TFC(ShiftLeft_Baseline, BinaryOp_Baseline)                                   \
  TFC(ShiftLeftSmi_Baseline, BinarySmiOp_Baseline)                             \
  TFC(ShiftRight_Baseline, BinaryOp_Baseline)                                  \
  TFC(ShiftRightSmi_Baseline, BinarySmiOp_Baseline)                            \
  TFC(ShiftRightLogical_Baseline, BinaryOp_Baseline)                           \
  TFC(ShiftRightLogicalSmi_Baseline, BinarySmiOp_Baseline)                     \
                                                                               \
  TFC(Add_WithFeedback, BinaryOp_WithFeedback)                                 \
  TFC(Subtract_WithFeedback, BinaryOp_WithFeedback)                            \
  TFC(Multiply_WithFeedback, BinaryOp_WithFeedback)                            \
  TFC(Divide_WithFeedback, BinaryOp_WithFeedback)                              \
  TFC(Modulus_WithFeedback, BinaryOp_WithFeedback)                             \
  TFC(Exponentiate_WithFeedback, BinaryOp_WithFeedback)                        \
  TFC(BitwiseAnd_WithFeedback, BinaryOp_WithFeedback)                          \
  TFC(BitwiseOr_WithFeedback, BinaryOp_WithFeedback)                           \
  TFC(BitwiseXor_WithFeedback, BinaryOp_WithFeedback)                          \
  TFC(ShiftLeft_WithFeedback, BinaryOp_WithFeedback)                           \
  TFC(ShiftRight_WithFeedback, BinaryOp_WithFeedback)                          \
  TFC(ShiftRightLogical_WithFeedback, BinaryOp_WithFeedback)                   \
                                                                               \
  /* Compare ops with feedback collection */                                   \
  TFC(Equal_Baseline, Compare_Baseline)                                        \
  TFC(StrictEqual_Baseline, Compare_Baseline)                                  \
  TFC(LessThan_Baseline, Compare_Baseline)                                     \
  TFC(GreaterThan_Baseline, Compare_Baseline)                                  \
  TFC(LessThanOrEqual_Baseline, Compare_Baseline)                              \
  TFC(GreaterThanOrEqual_Baseline, Compare_Baseline)                           \
                                                                               \
  TFC(Equal_WithFeedback, Compare_WithFeedback)                                \
  TFC(StrictEqual_WithFeedback, Compare_WithFeedback)                          \
  TFC(LessThan_WithFeedback, Compare_WithFeedback)                             \
  TFC(GreaterThan_WithFeedback, Compare_WithFeedback)                          \
  TFC(LessThanOrEqual_WithFeedback, Compare_WithFeedback)                      \
  TFC(GreaterThanOrEqual_WithFeedback, Compare_WithFeedback)                   \
                                                                               \
  /* Unary ops with feedback collection */                                     \
  TFC(BitwiseNot_Baseline, UnaryOp_Baseline)                                   \
  TFC(Decrement_Baseline, UnaryOp_Baseline)                                    \
  TFC(Increment_Baseline, UnaryOp_Baseline)                                    \
  TFC(Negate_Baseline, UnaryOp_Baseline)                                       \
  IF_TSA(TSC, TFC, BitwiseNot_WithFeedback, UnaryOp_WithFeedback)              \
  TFC(Decrement_WithFeedback, UnaryOp_WithFeedback)                            \
  TFC(Increment_WithFeedback, UnaryOp_WithFeedback)                            \
  TFC(Negate_WithFeedback, UnaryOp_WithFeedback)                               \
                                                                               \
  /* Object */                                                                 \
  /* ES #sec-object-constructor */                                             \
  TFJ(ObjectAssign, kDontAdaptArgumentsSentinel)                               \
  /* ES #sec-object.create */                                                  \
  TFJ(ObjectCreate, kDontAdaptArgumentsSentinel)                               \
  CPP(ObjectDefineGetter, JSParameterCount(2))                                 \
  CPP(ObjectDefineProperties, JSParameterCount(2))                             \
  CPP(ObjectDefineProperty, JSParameterCount(3))                               \
  CPP(ObjectDefineSetter, JSParameterCount(2))                                 \
  TFJ(ObjectEntries, kJSArgcReceiverSlots + 1, kReceiver, kObject)             \
  CPP(ObjectFreeze, kDontAdaptArgumentsSentinel)                               \
  TFJ(ObjectGetOwnPropertyDescriptor, kDontAdaptArgumentsSentinel)             \
  CPP(ObjectGetOwnPropertyDescriptors, kDontAdaptArgumentsSentinel)            \
  TFJ(ObjectGetOwnPropertyNames, kJSArgcReceiverSlots + 1, kReceiver, kObject) \
  CPP(ObjectGetOwnPropertySymbols, kDontAdaptArgumentsSentinel)                \
  TFJ(ObjectHasOwn, kJSArgcReceiverSlots + 2, kReceiver, kObject, kKey)        \
  TFJ(ObjectIs, kJSArgcReceiverSlots + 2, kReceiver, kLeft, kRight)            \
  CPP(ObjectIsFrozen, kDontAdaptArgumentsSentinel)                             \
  CPP(ObjectIsSealed, kDontAdaptArgumentsSentinel)                             \
  TFJ(ObjectKeys, kJSArgcReceiverSlots + 1, kReceiver, kObject)                \
  CPP(ObjectLookupGetter, JSParameterCount(1))                                 \
  CPP(ObjectLookupSetter, JSParameterCount(1))                                 \
  /* ES6 #sec-object.prototype.hasownproperty */                               \
  TFJ(ObjectPrototypeHasOwnProperty, kJSArgcReceiverSlots + 1, kReceiver,      \
      kKey)                                                                    \
  TFJ(ObjectPrototypeIsPrototypeOf, kJSArgcReceiverSlots + 1, kReceiver,       \
      kValue)                                                                  \
  CPP(ObjectPrototypePropertyIsEnumerable, kDontAdaptArgumentsSentinel)        \
  CPP(ObjectPrototypeGetProto, JSParameterCount(0))                            \
  CPP(ObjectPrototypeSetProto, JSParameterCount(1))                            \
  CPP(ObjectSeal, kDontAdaptArgumentsSentinel)                                 \
  TFS(ObjectToString, NeedsContext::kYes, kReceiver)                           \
  TFJ(ObjectValues, kJSArgcReceiverSlots + 1, kReceiver, kObject)              \
                                                                               \
  /* instanceof */                                                             \
  TFC(OrdinaryHasInstance, Compare)                                            \
  TFC(InstanceOf, Compare)                                                     \
  TFC(InstanceOf_WithFeedback, Compare_WithFeedback)                           \
  TFC(InstanceOf_Baseline, Compare_Baseline)                                   \
                                                                               \
  /* for-in */                                                                 \
  TFS(ForInEnumerate, NeedsContext::kYes, kReceiver)                           \
  TFC(ForInPrepare, ForInPrepare)                                              \
  TFS(ForInFilter, NeedsContext::kYes, kKey, kObject)                          \
                                                                               \
  /* Reflect */                                                                \
  ASM(ReflectApply, JSTrampoline)                                              \
  ASM(ReflectConstruct, JSTrampoline)                                          \
  CPP(ReflectDefineProperty, JSParameterCount(3))                              \
  CPP(ReflectOwnKeys, JSParameterCount(1))                                     \
  CPP(ReflectSet, kDontAdaptArgumentsSentinel)                                 \
                                                                               \
  /* RegExp */                                                                 \
  CPP(RegExpCapture1Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture2Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture3Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture4Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture5Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture6Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture7Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture8Getter, JSParameterCount(0))                               \
  CPP(RegExpCapture9Getter, JSParameterCount(0))                               \
  /* ES #sec-regexp-pattern-flags */                                           \
  TFJ(RegExpConstructor, kJSArgcReceiverSlots + 2, kReceiver, kPattern,        \
      kFlags)                                                                  \
  CPP(RegExpInputGetter, JSParameterCount(0))                                  \
  CPP(RegExpInputSetter, JSParameterCount(1))                                  \
  CPP(RegExpLastMatchGetter, JSParameterCount(0))                              \
  CPP(RegExpLastParenGetter, JSParameterCount(0))                              \
  CPP(RegExpLeftContextGetter, JSParameterCount(0))                            \
  /* ES #sec-regexp.prototype.compile */                                       \
  TFJ(RegExpPrototypeCompile, kJSArgcReceiverSlots + 2, kReceiver, kPattern,   \
      kFlags)                                                                  \
  CPP(RegExpPrototypeToString, kDontAdaptArgumentsSentinel)                    \
  CPP(RegExpRightContextGetter, JSParameterCount(0))                           \
                                                                               \
  /* RegExp helpers */                                                         \
  TFS(RegExpExecAtom, NeedsContext::kYes, kRegExp, kString, kLastIndex,        \
      kMatchInfo)                                                              \
  ASM(RegExpInterpreterTrampoline, RegExpTrampoline)                           \
  ASM(RegExpExperimentalTrampoline, RegExpTrampoline)                          \
                                                                               \
  /* Set */                                                                    \
  TFS(FindOrderedHashSetEntry, NeedsContext::kYes, kTable, kKey)               \
  TFJ(SetConstructor, kDontAdaptArgumentsSentinel)                             \
  TFJ(SetPrototypeHas, kJSArgcReceiverSlots + 1, kReceiver, kKey)              \
  TFJ(SetPrototypeAdd, kJSArgcReceiverSlots + 1, kReceiver, kKey)              \
  TFJ(SetPrototypeDelete, kJSArgcReceiverSlots + 1, kReceiver, kKey)           \
  CPP(SetPrototypeClear, JSParameterCount(0))                                  \
  /* ES #sec-set.prototype.entries */                                          \
  TFJ(SetPrototypeEntries, kJSArgcReceiverSlots, kReceiver)                    \
  /* ES #sec-get-set.prototype.size */                                         \
  TFJ(SetPrototypeGetSize, kJSArgcReceiverSlots, kReceiver)                    \
  /* ES #sec-set.prototype.foreach */                                          \
  TFJ(SetPrototypeForEach, kDontAdaptArgumentsSentinel)                        \
  /* ES #sec-set.prototype.values */                                           \
  TFJ(SetPrototypeValues, kJSArgcReceiverSlots, kReceiver)                     \
  /* ES #sec-%setiteratorprototype%.next */                                    \
  TFJ(SetIteratorPrototypeNext, kJSArgcReceiverSlots, kReceiver)               \
  TFS(SetOrSetIteratorToList, NeedsContext::kYes, kSource)                     \
                                                                               \
  /* ShadowRealm */                                                            \
  CPP(ShadowRealmConstructor, kDontAdaptArgumentsSentinel)                     \
  TFS(ShadowRealmGetWrappedValue, NeedsContext::kYes, kCreationContext,        \
      kTargetContext, kValue)                                                  \
  CPP(ShadowRealmPrototypeEvaluate, JSParameterCount(1))                       \
  TFJ(ShadowRealmPrototypeImportValue, kJSArgcReceiverSlots + 2, kReceiver,    \
      kSpecifier, kExportName)                                                 \
  TFJ(ShadowRealmImportValueFulfilled, kJSArgcReceiverSlots + 1, kReceiver,    \
      kExports)                                                                \
  TFJ(ShadowRealmImportValueRejected, kJSArgcReceiverSlots + 1, kReceiver,     \
      kException)                                                              \
                                                                               \
  /* SharedArrayBuffer */                                                      \
  CPP(SharedArrayBufferPrototypeGetByteLength, kDontAdaptArgumentsSentinel)    \
  CPP(SharedArrayBufferPrototypeSlice, JSParameterCount(2))                    \
  /* https://tc39.es/proposal-resizablearraybuffer/ */                         \
  CPP(SharedArrayBufferPrototypeGrow, JSParameterCount(1))                     \
                                                                               \
  TFJ(AtomicsLoad, kJSArgcReceiverSlots + 2, kReceiver, kArrayOrSharedObject,  \
      kIndexOrFieldName)                                                       \
  TFJ(AtomicsStore, kJSArgcReceiverSlots + 3, kReceiver, kArrayOrSharedObject, \
      kIndexOrFieldName, kValue)                                               \
  TFJ(AtomicsExchange, kJSArgcReceiverSlots + 3, kReceiver,                    \
      kArrayOrSharedObject, kIndexOrFieldName, kValue)                         \
  TFJ(AtomicsCompareExchange, kJSArgcReceiverSlots + 4, kReceiver,             \
      kArrayOrSharedObject, kIndexOrFieldName, kOldValue, kNewValue)           \
  TFJ(AtomicsAdd, kJSArgcReceiverSlots + 3, kReceiver, kArray, kIndex, kValue) \
  TFJ(AtomicsSub, kJSArgcReceiverSlots + 3, kReceiver, kArray, kIndex, kValue) \
  TFJ(AtomicsAnd, kJSArgcReceiverSlots + 3, kReceiver, kArray, kIndex, kValue) \
  TFJ(AtomicsOr, kJSArgcReceiverSlots + 3, kReceiver, kArray, kIndex, kValue)  \
  TFJ(AtomicsXor, kJSArgcReceiverSlots + 3, kReceiver, kArray, kIndex, kValue) \
  CPP(AtomicsNotify, JSParameterCount(3))                                      \
  CPP(AtomicsIsLockFree, JSParameterCount(1))                                  \
  CPP(AtomicsWait, JSParameterCount(4))                                        \
  CPP(AtomicsWaitAsync, JSParameterCount(4))                                   \
  CPP(AtomicsPause, kDontAdaptArgumentsSentinel)                               \
                                                                               \
  /* String */                                                                 \
  /* ES #sec-string.fromcodepoint */                                           \
  CPP(StringFromCodePoint, kDontAdaptArgumentsSentinel)                        \
  /* ES6 #sec-string.fromcharcode */                                           \
  IF_TSA(TSJ, TFJ, StringFromCharCode, kDontAdaptArgumentsSentinel)            \
  /* ES6 #sec-string.prototype.lastindexof */                                  \
  CPP(StringPrototypeLastIndexOf, kDontAdaptArgumentsSentinel)                 \
  /* ES #sec-string.prototype.matchAll */                                      \
  TFJ(StringPrototypeMatchAll, kJSArgcReceiverSlots + 1, kReceiver, kRegexp)   \
  /* ES6 #sec-string.prototype.replace */                                      \
  TFJ(StringPrototypeReplace, kJSArgcReceiverSlots + 2, kReceiver, kSearch,    \
      kReplace)                                                                \
  /* ES6 #sec-string.prototype.split */                                        \
  TFJ(StringPrototypeSplit, kDontAdaptArgumentsSentinel)                       \
  /* ES6 #sec-string.raw */                                                    \
  CPP(StringRaw, kDontAdaptArgumentsSentinel)                                  \
                                                                               \
  /* Symbol */                                                                 \
  /* ES #sec-symbol-constructor */                                             \
  CPP(SymbolConstructor, kDontAdaptArgumentsSentinel)                          \
  /* ES6 #sec-symbol.for */                                                    \
  CPP(SymbolFor, kDontAdaptArgumentsSentinel)                                  \
  /* ES6 #sec-symbol.keyfor */                                                 \
  CPP(SymbolKeyFor, kDontAdaptArgumentsSentinel)                               \
                                                                               \
  /* TypedArray */                                                             \
  /* ES #sec-typedarray-constructors */                                        \
  TFJ(TypedArrayBaseConstructor, kJSArgcReceiverSlots, kReceiver)              \
  TFJ(TypedArrayConstructor, kDontAdaptArgumentsSentinel)                      \
  CPP(TypedArrayPrototypeBuffer, kDontAdaptArgumentsSentinel)                  \
  /* ES6 #sec-get-%typedarray%.prototype.bytelength */                         \
  TFJ(TypedArrayPrototypeByteLength, kJSArgcReceiverSlots, kReceiver)          \
  /* ES6 #sec-get-%typedarray%.prototype.byteoffset */                         \
  TFJ(TypedArrayPrototypeByteOffset, kJSArgcReceiverSlots, kReceiver)          \
  /* ES6 #sec-get-%typedarray%.prototype.length */                             \
  TFJ(TypedArrayPrototypeLength, kJSArgcReceiverSlots, kReceiver)              \
  /* ES6 #sec-%typedarray%.prototype.copywithin */                             \
  CPP(TypedArrayPrototypeCopyWithin, kDontAdaptArgumentsSentinel)              \
  /* ES6 #sec-%typedarray%.prototype.fill */                                   \
  CPP(TypedArrayPrototypeFill, kDontAdaptArgumentsSentinel)                    \
  /* ES7 #sec-%typedarray%.prototype.includes */                               \
  CPP(TypedArrayPrototypeIncludes, kDontAdaptArgumentsSentinel)                \
  /* ES6 #sec-%typedarray%.prototype.indexof */                                \
  CPP(TypedArrayPrototypeIndexOf, kDontAdaptArgumentsSentinel)                 \
  /* ES6 #sec-%typedarray%.prototype.lastindexof */                            \
  CPP(TypedArrayPrototypeLastIndexOf, kDontAdaptArgumentsSentinel)             \
  /* ES6 #sec-%typedarray%.prototype.reverse */                                \
  CPP(TypedArrayPrototypeReverse, kDontAdaptArgumentsSentinel)                 \
  /* ES6 #sec-get-%typedarray%.prototype-@@tostringtag */                      \
  TFJ(TypedArrayPrototypeToStringTag, kJSArgcReceiverSlots, kReceiver)         \
  /* ES6 %TypedArray%.prototype.map */                                         \
  TFJ(TypedArrayPrototypeMap, kDontAdaptArgumentsSentinel)                     \
                                                                               \
  /* Wasm */                                                                   \
  IF_WASM_DRUMBRAKE(ASM, WasmInterpreterEntry, WasmDummy)                      \
  IF_WASM_DRUMBRAKE(ASM, GenericJSToWasmInterpreterWrapper, WasmDummy)         \
  IF_WASM_DRUMBRAKE(ASM, WasmInterpreterCWasmEntry, WasmDummy)                 \
  IF_WASM_DRUMBRAKE(ASM, GenericWasmToJSInterpreterWrapper, WasmDummy)         \
                                                                               \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I32LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I32LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I32LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I32LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem32S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem32U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_I64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_F32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2r_F64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem32S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem32U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I32LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I32LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I32LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I32LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem32S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem32U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_I64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_F32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2r_F64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem8S, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem8U, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem16S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem16U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem32S, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem32U, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F32LoadMem, WasmDummy)              \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F64LoadMem, WasmDummy)              \
                                                                               \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem8S_LocalSet, WasmDummy)   \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem8U_LocalSet, WasmDummy)   \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem16S_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem16U_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem8S_LocalSet, WasmDummy)   \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem8U_LocalSet, WasmDummy)   \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem16S_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem16U_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem32S_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem32U_LocalSet, WasmDummy)  \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadMem_LocalSet, WasmDummy)     \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadMem_LocalSet, WasmDummy)     \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F32LoadMem_LocalSet, WasmDummy)     \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F64LoadMem_LocalSet, WasmDummy)     \
                                                                               \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32StoreMem8, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32StoreMem16, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64StoreMem8, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64StoreMem16, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64StoreMem32, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F32StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F64StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32StoreMem8, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32StoreMem16, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64StoreMem8, WasmDummy)            \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64StoreMem16, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64StoreMem32, WasmDummy)           \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F32StoreMem, WasmDummy)             \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F64StoreMem, WasmDummy)             \
                                                                               \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I32LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_I64LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F32LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, r2s_F64LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I32LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_I64LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F32LoadStoreMem, WasmDummy)         \
  IF_WASM_DRUMBRAKE_INSTR_HANDLER(ASM, s2s_F64LoadStoreMem, WasmDummy)         \
                                                                               \
  IF_WASM(ASM, JSToWasmWrapperAsm, WasmJSToWasmWrapper)                        \
  IF_WASM(ASM, WasmReturnPromiseOnSuspendAsm, WasmJSToWasmWrapper)             \
  IF_WASM(ASM, JSToWasmStressSwitchStacksAsm, WasmJSToWasmWrapper)             \
  IF_WASM(ASM, WasmToJsWrapperAsm, WasmDummy)                                  \
  IF_WASM(TFC, WasmToJsWrapperCSA, WasmToJSWrapper)                            \
  IF_WASM(TFC, WasmToJsWrapperInvalidSig, WasmToJSWrapper)                     \
  IF_WASM(ASM, WasmSuspend, WasmSuspend)                                       \
  IF_WASM(ASM, WasmResume, WasmDummyWithJSLinkage)                             \
  IF_WASM(ASM, WasmReject, WasmDummyWithJSLinkage)                             \
  IF_WASM(ASM, WasmTrapHandlerLandingPad, WasmDummy)                           \
  IF_WASM(ASM, WasmCompileLazy, WasmDummy)                                     \
  IF_WASM(ASM, WasmLiftoffFrameSetup, WasmDummy)                               \
  IF_WASM(ASM, WasmDebugBreak, WasmDummy)                                      \
  IF_WASM(ASM, WasmOnStackReplace, WasmDummy)                                  \
  IF_WASM(ASM, WasmHandleStackOverflow, WasmHandleStackOverflow)               \
  IF_WASM(TFC, WasmFloat32ToNumber, WasmFloat32ToNumber)                       \
  IF_WASM(TFC, WasmFloat64ToNumber, WasmFloat64ToTagged)                       \
  IF_WASM(TFC, WasmFloat64ToString, WasmFloat64ToTagged)                       \
  IF_WASM(TFC, JSToWasmLazyDeoptContinuation, SingleParameterOnStack)          \
                                                                               \
  /* WeakMap */                                                                \
  TFJ(WeakMapConstructor, kDontAdaptArgumentsSentinel)                         \
  TFS(WeakMapLookupHashIndex, NeedsContext::kYes, kTable, kKey)                \
  TFJ(WeakMapGet, kJSArgcReceiverSlots + 1, kReceiver, kKey)                   \
  TFJ(WeakMapPrototypeHas, kJSArgcReceiverSlots + 1, kReceiver, kKey)          \
  TFJ(WeakMapPrototypeSet, kJSArgcReceiverSlots + 2, kReceiver, kKey, kValue)  \
  TFJ(WeakMapPrototypeDelete, kJSArgcReceiverSlots + 1, kReceiver, kKey)       \
                                                                               \
  /* WeakSet */                                                                \
  TFJ(WeakSetConstructor, kDontAdaptArgumentsSentinel)                         \
  TFJ(WeakSetPrototypeHas, kJSArgcReceiverSlots + 1, kReceiver, kKey)          \
  TFJ(WeakSetPrototypeAdd, kJSArgcReceiverSlots + 1, kReceiver, kValue)        \
  TFJ(WeakSetPrototypeDelete, kJSArgcReceiverSlots + 1, kReceiver, kValue)     \
                                                                               \
  /* WeakSet / WeakMap Helpers */                                              \
  TFS(WeakCollectionDelete, NeedsContext::kYes, kCollection, kKey)             \
  TFS(WeakCollectionSet, NeedsContext::kYes, kCollection, kKey, kValue)        \
                                                                               \
  /* JS Structs and friends */                                                 \
  CPP(SharedSpaceJSObjectHasInstance, kDontAdaptArgumentsSentinel)             \
  CPP(SharedStructTypeConstructor, kDontAdaptArgumentsSentinel)                \
  CPP(SharedStructTypeIsSharedStruct, JSParameterCount(1))                     \
  CPP(SharedStructConstructor, JSParameterCount(0))                            \
  CPP(SharedArrayConstructor, JSParameterCount(0))                             \
  CPP(SharedArrayIsSharedArray, JSParameterCount(1))                           \
  CPP(AtomicsMutexConstructor, JSParameterCount(0))                            \
  CPP(AtomicsMutexIsMutex, JSParameterCount(1))                                \
  CPP(AtomicsMutexLock, JSParameterCount(2))                                   \
  CPP(AtomicsMutexLockAsync, JSParameterCount(2))                              \
  CPP(AtomicsMutexLockWithTimeout, JSParameterCount(3))                        \
  CPP(AtomicsMutexTryLock, JSParameterCount(2))                                \
  CPP(AtomicsMutexAsyncUnlockResolveHandler, JSParameterCount(1))              \
  CPP(AtomicsMutexAsyncUnlockRejectHandler, JSParameterCount(1))               \
  CPP(AtomicsConditionConstructor, JSParameterCo
"""


```
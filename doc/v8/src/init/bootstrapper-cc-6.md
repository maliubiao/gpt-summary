Response:
The user wants to understand the functionality of a specific part of the V8 source code, `v8/src/init/bootstrapper.cc`, based on a provided code snippet. They have several specific questions:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  Is it a Torque file (determined by the `.tq` extension)?
3. **JavaScript Relation:** If related to JavaScript functionality, provide examples.
4. **Logic Inference:**  Provide example inputs and outputs if there's code logic.
5. **Common Errors:**  Highlight potential user programming errors related to the code.
6. **Overall Summary (Part 7 of 11):**  Summarize the function of this specific section within the larger context.

**Plan:**

1. **Analyze the Code:**  Examine the provided C++ code snippet for the types of objects and operations it involves. Look for patterns like `InstallFunction`, `SimpleInstallFunction`, `CreateArrayBuffer`, etc., which indicate setting up JavaScript built-in objects and their properties.
2. **Torque Check:** Verify if the filename ends in `.tq`. It doesn't, so it's C++.
3. **JavaScript Relationship:**  Identify the JavaScript built-in objects being set up (e.g., `Intl.DurationFormat`, `ArrayBuffer`, `SharedArrayBuffer`, `Atomics`, `TypedArray`, `DataView`, `Map`, `BigInt`, `Set`, `WeakMap`, `WeakSet`, `Proxy`, `Reflect`). This is the core link to JavaScript. Provide examples of how these are used in JavaScript.
4. **Logic Inference:** This code primarily *sets up* functionality rather than performing complex logic. The "logic" is in how these built-ins are *used* in JavaScript. Focus on the setup process and the connections being made. Inputs are generally the V8 isolate and global object; outputs are the modified global object with new built-ins.
5. **Common Errors:** Think about how users might misuse the built-ins being initialized here. For instance, trying to directly construct `TypedArray` or `DataView` without `new`, using `Atomics` incorrectly for non-shared memory, or misunderstanding the behavior of `WeakMap` and `WeakSet`.
6. **Summary of Part 7:**  Based on the identified built-ins, summarize the focus of this section. It appears to be about setting up various core data structures and utility objects within the JavaScript environment.

**Pre-computation/Pre-analysis:**

* **Keywords:**  The code is full of keywords related to JavaScript built-in objects. These are the key to understanding its purpose.
* **`InstallFunction` and related functions:**  These clearly indicate the registration of JavaScript functions and their properties.
* **`native_context()`:** This suggests interaction with the internal context of the JavaScript execution environment.

**Confidence Score:** 5/5 - The code snippet is quite explicit about its purpose.
好的，让我们来分析一下这段 `v8/src/init/bootstrapper.cc` 的代码片段。

**功能列举:**

这段代码的主要功能是**在 V8 引擎启动时，向全局对象（通常是 `window` 或 `globalThis`）上注册和初始化各种内置的 JavaScript 对象和函数，以及它们的属性和方法**。  它涵盖了以下几个方面：

1. **Intl (国际化 API):**
   - 初始化 `Intl` 对象及其子对象，例如 `Intl.DurationFormat`。
   - 安装 `Intl.DurationFormat` 构造函数及其原型上的方法 (`resolvedOptions`, `format`, `formatToParts`, `supportedLocalesOf`)。

2. **ArrayBuffer (数组缓冲区):**
   - 创建 `ArrayBuffer` 构造函数并添加到全局对象。
   - 安装 `ArrayBuffer` 的原型和相关方法 (`resize`, `transfer`, `transferToFixedLength`) 和访问器 (getter) (`maxByteLength`, `resizable`, `detached`)。
   - 创建一个内部使用的 `arrayBufferConstructor_DoNotInitialize` 函数。

3. **SharedArrayBuffer (共享数组缓冲区):**
   - 创建 `SharedArrayBuffer` 构造函数并添加到全局对象。
   - 安装 `SharedArrayBuffer` 的原型和相关方法 (`grow`) 和访问器 (`maxByteLength`, `growable`)。

4. **Atomics (原子操作):**
   - 创建 `Atomics` 对象并添加到全局对象。
   - 安装 `Atomics` 对象上的静态方法，用于执行原子操作 (`load`, `store`, `add`, `sub`, `and`, `or`, `xor`, `exchange`, `compareExchange`, `isLockFree`, `wait`, `waitAsync`, `notify`)。

5. **TypedArray (类型化数组):**
   - 创建抽象的 `TypedArray` 构造函数（它是所有具体类型化数组的基类）。
   - 安装 `TypedArray` 的静态方法 (`of`, `from`)。
   - 设置 `%TypedArrayPrototype%` 并安装其上的通用方法 (`entries`, `keys`, `values`, `at`, `copyWithin`, `every`, `fill`, `filter`, `find`, `findIndex`, `findLast`, `findLastIndex`, `forEach`, `includes`, `indexOf`, `join`, `lastIndexOf`, `map`, `reverse`, `reduce`, `reduceRight`, `set`, `slice`, `some`, `sort`, `subarray`, `toReversed`, `toSorted`, `with`, `toLocaleString`) 和访问器 (`buffer`, `byteOffset`, `byteLength`, `length`)。

6. **具体类型化数组 (Int8Array, Uint8Array, 等):**
   - 使用宏 `TYPED_ARRAYS_BASE` 批量安装各种具体的类型化数组构造函数 (如 `Int8Array`, `Uint8Array`, `Float64Array` 等)。

7. **DataView (数据视图):**
   - 创建 `DataView` 构造函数并添加到全局对象。
   - 安装 `DataView` 的原型和用于读写不同数据类型的方法 (`getInt8`, `setInt8`, `getUint8`, `setUint8`, 等)。

8. **Map (映射):**
   - 创建 `Map` 构造函数并添加到全局对象。
   - 安装 `Map` 的静态方法 (`groupBy`)。
   - 安装 `Map` 的原型方法 (`get`, `set`, `has`, `delete`, `clear`, `entries`, `forEach`, `keys`, `values`) 和访问器 (`size`)。

9. **BigInt (任意精度整数):**
   - 创建 `BigInt` 构造函数并添加到全局对象。
   - 安装 `BigInt` 的静态方法 (`asUintN`, `asIntN`)。
   - 安装 `BigInt` 的原型方法 (`toLocaleString`, `toString`, `valueOf`)。

10. **Set (集合):**
    - 创建 `Set` 构造函数并添加到全局对象。
    - 安装 `Set` 的原型方法 (`has`, `add`, `delete`, `clear`, `entries`, `forEach`) 和访问器 (`size`)。

11. **JSModuleNamespace (模块命名空间):**
    - 创建用于表示 ES 模块命名空间的内部 Map。

12. **Iterator Result (迭代器结果):**
    - 创建用于迭代器结果的内部 Map。

13. **WeakMap (弱映射):**
    - 创建 `WeakMap` 构造函数并添加到全局对象。
    - 安装 `WeakMap` 的原型方法 (`delete`, `get`, `set`, `has`)。

14. **WeakSet (弱集合):**
    - 创建 `WeakSet` 构造函数并添加到全局对象。
    - 安装 `WeakSet` 的原型方法 (`delete`, `has`, `add`)。

15. **Proxy (代理):**
    - 创建 `Proxy` 构造函数并添加到全局对象。
    - 安装 `Proxy` 的静态方法 (`revocable`)。

16. **Reflect (反射):**
    - 创建 `Reflect` 对象并添加到全局对象。
    - 安装 `Reflect` 上的静态方法，用于执行反射操作 (`defineProperty`, `deleteProperty`, `apply`, `construct`, `get`, `getOwnPropertyDescriptor`, `getPrototypeOf`, `has`, `isExtensible`, `ownKeys`, `preventExtensions`, `set`, `setPrototypeOf`)。

**关于 .tq 扩展名:**

如果 `v8/src/init/bootstrapper.cc` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。 然而，根据您提供的文件名，它以 `.cc` 结尾，所以这是一个 **C++ 源代码**文件。

**与 JavaScript 功能的关系及示例:**

这段代码直接关系到 JavaScript 的核心功能，因为它定义了 JavaScript 中最基础和常用的内置对象和函数。

**JavaScript 示例:**

```javascript
// Intl.DurationFormat
const df = new Intl.DurationFormat('en', { style: 'long' });
console.log(df.format({ years: 1, months: 2, days: 3 })); // "1 year, 2 months, 3 days"

// ArrayBuffer
const buffer = new ArrayBuffer(16);
console.log(buffer.byteLength); // 16

// SharedArrayBuffer
const sab = new SharedArrayBuffer(1024);

// Atomics
const int32Array = new Int32Array(sab, 0, 1);
Atomics.add(int32Array, 0, 5);
console.log(int32Array[0]); // 5

// TypedArray
const uint8 = new Uint8Array([1, 2, 3]);
console.log(uint8[0]); // 1

// DataView
const dataView = new DataView(buffer);
dataView.setInt32(0, 42);
console.log(dataView.getInt32(0)); // 42

// Map
const map = new Map();
map.set('a', 1);
console.log(map.get('a')); // 1

// BigInt
const bigInt = 9007199254740991n;
console.log(bigInt + 1n); // 9007199254740992n

// Set
const set = new Set([1, 2, 2, 3]);
console.log(set.size); // 3

// WeakMap
const wm = new WeakMap();
const key = {};
wm.set(key, 'value');
console.log(wm.get(key)); // value

// WeakSet
const ws = new WeakSet();
const obj = {};
ws.add(obj);
console.log(ws.has(obj)); // true

// Proxy
const target = {};
const handler = {
  get: function(target, prop) {
    return "Hello, Proxy!";
  }
};
const proxy = new Proxy(target, handler);
console.log(proxy.name); // "Hello, Proxy!"

// Reflect
const objReflect = { x: 10 };
Reflect.defineProperty(objReflect, 'y', { value: 20 });
console.log(objReflect.y); // 20
```

**代码逻辑推理 (假设输入与输出):**

这段代码主要是**声明式**的，用于注册和初始化对象。它不像执行特定算法那样有明显的输入和输出。

**假设输入:** V8 引擎的 Isolate 对象 (代表一个独立的 JavaScript 虚拟机实例) 和全局对象。

**输出:**  全局对象被修改，包含了新注册的内置对象和函数，以及它们的属性和方法。  例如，在代码执行后，你可以直接在 JavaScript 中使用 `ArrayBuffer`, `Map`, `Intl`, 等等。

**用户常见的编程错误:**

1. **误用 `Atomics`:**  `Atomics` API 只能用于 `SharedArrayBuffer`，尝试在普通的 `ArrayBuffer` 上使用会导致错误。

   ```javascript
   const buffer = new ArrayBuffer(4);
   const view = new Int32Array(buffer);
   // 错误：不能在非共享的 ArrayBuffer 上使用 Atomics
   Atomics.add(view, 0, 1); // TypeError: Cannot perform atomic operations on non-shared memory
   ```

2. **不理解 `WeakMap` 和 `WeakSet` 的弱引用:**  用户可能会期望 `WeakMap` 和 `WeakSet` 像普通的 `Map` 和 `Set` 一样保持键或值的存在，但实际上，一旦键或值（必须是对象）没有其他强引用指向它，垃圾回收器就会回收它，并且 `WeakMap` 和 `WeakSet` 中对应的条目也会消失。

   ```javascript
   let key = {};
   const weakMap = new WeakMap();
   weakMap.set(key, 'some info');
   key = null; // 移除 key 的强引用
   // 在某个时刻，垃圾回收器可能会回收 key 指向的对象
   // weakMap.get(key) 将返回 undefined
   ```

3. **直接操作类型化数组的 `buffer` 属性时出错:** 类型化数组提供了视图来操作底层的 `ArrayBuffer`。直接修改 `buffer` 可能会导致类型不一致或其他错误。

   ```javascript
   const uint8Array = new Uint8Array([1, 2, 3]);
   uint8Array.buffer[0] = 10; // 错误：不能直接通过索引访问 ArrayBuffer
   ```
   正确的做法是通过 `DataView` 或类型化数组自身的访问器来修改。

4. **误用 `Proxy`:**  `Proxy` 需要正确理解 `handler` 对象中各个 trap 的作用，如果 `handler` 实现不当，可能会导致意外行为或错误。

   ```javascript
   const target = {};
   const handler = {}; // 一个空的 handler，大部分操作会转发到 target
   const proxy = new Proxy(target, handler);
   proxy.someProperty = 10; // 正常工作，因为 get/set trap 默认转发
   delete proxy.someProperty; // 正常工作，因为 deleteProperty trap 默认转发

   const handlerWithError = {
       get: function() { /* 什么也不做，或者返回错误的值 */ }
   };
   const badProxy = new Proxy(target, handlerWithError);
   console.log(badProxy.someProperty); // 可能会返回 undefined 或抛出错误，取决于 handler 的实现
   ```

**第 7 部分功能归纳:**

这段代码是 V8 引擎启动过程中**初始化和注册一系列核心 JavaScript 内置对象和构造函数**的关键部分。它涵盖了国际化 (Intl)、数组缓冲区 (ArrayBuffer, SharedArrayBuffer)、原子操作 (Atomics)、类型化数组 (TypedArray)、数据视图 (DataView)、映射 (Map)、任意精度整数 (BigInt)、集合 (Set)、弱引用集合 (WeakMap, WeakSet)、代理 (Proxy) 和反射 (Reflect) 等功能。  **这一部分主要关注于为 JavaScript 提供操作各种数据结构、内存管理、并发控制以及元编程能力的基础工具。** 它是构建更高级 JavaScript 功能的基石。

### 提示词
```
这是目录为v8/src/init/bootstrapper.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/init/bootstrapper.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
map());
        native_context()->set_intl_segment_data_object_map(*map);
        native_context()->set_intl_segment_data_object_wordlike_map(
            *map_with_wordlike);
      }
    }

    {  // -- D u r a t i o n F o r m a t
      Handle<JSFunction> duration_format_fun = InstallFunction(
          isolate(), intl, "DurationFormat", JS_DURATION_FORMAT_TYPE,
          JSDurationFormat::kHeaderSize, 0, factory->the_hole_value(),
          Builtin::kDurationFormatConstructor, 0, kDontAdapt);
      InstallWithIntrinsicDefaultProto(
          isolate(), duration_format_fun,
          Context::INTL_DURATION_FORMAT_FUNCTION_INDEX);

      SimpleInstallFunction(
          isolate(), duration_format_fun, "supportedLocalesOf",
          Builtin::kDurationFormatSupportedLocalesOf, 1, kDontAdapt);

      Handle<JSObject> prototype(
          Cast<JSObject>(duration_format_fun->instance_prototype()), isolate());

      InstallToStringTag(isolate(), prototype, "Intl.DurationFormat");

      SimpleInstallFunction(isolate(), prototype, "resolvedOptions",
                            Builtin::kDurationFormatPrototypeResolvedOptions, 0,
                            kDontAdapt);

      SimpleInstallFunction(isolate(), prototype, "format",
                            Builtin::kDurationFormatPrototypeFormat, 1,
                            kDontAdapt);
      SimpleInstallFunction(isolate(), prototype, "formatToParts",
                            Builtin::kDurationFormatPrototypeFormatToParts, 1,
                            kDontAdapt);
    }
  }
#endif  // V8_INTL_SUPPORT

  {  // -- A r r a y B u f f e r
    Handle<String> name = factory->ArrayBuffer_string();
    Handle<JSFunction> array_buffer_fun = CreateArrayBuffer(name, ARRAY_BUFFER);
    JSObject::AddProperty(isolate_, global, name, array_buffer_fun, DONT_ENUM);
    InstallWithIntrinsicDefaultProto(isolate_, array_buffer_fun,
                                     Context::ARRAY_BUFFER_FUN_INDEX);
    InstallSpeciesGetter(isolate_, array_buffer_fun);

    DirectHandle<JSFunction> array_buffer_noinit_fun = SimpleCreateFunction(
        isolate_,
        factory->InternalizeUtf8String(
            "arrayBufferConstructor_DoNotInitialize"),
        Builtin::kArrayBufferConstructor_DoNotInitialize, 1, kDontAdapt);
    native_context()->set_array_buffer_noinit_fun(*array_buffer_noinit_fun);

    Handle<JSObject> array_buffer_prototype(
        Cast<JSObject>(array_buffer_fun->instance_prototype()), isolate_);
    SimpleInstallGetter(isolate_, array_buffer_prototype,
                        factory->max_byte_length_string(),
                        Builtin::kArrayBufferPrototypeGetMaxByteLength, kAdapt);
    SimpleInstallGetter(isolate_, array_buffer_prototype,
                        factory->resizable_string(),
                        Builtin::kArrayBufferPrototypeGetResizable, kAdapt);
    SimpleInstallFunction(isolate_, array_buffer_prototype, "resize",
                          Builtin::kArrayBufferPrototypeResize, 1, kAdapt);
    SimpleInstallFunction(isolate_, array_buffer_prototype, "transfer",
                          Builtin::kArrayBufferPrototypeTransfer, 0,
                          kDontAdapt);
    SimpleInstallFunction(
        isolate_, array_buffer_prototype, "transferToFixedLength",
        Builtin::kArrayBufferPrototypeTransferToFixedLength, 0, kDontAdapt);
    SimpleInstallGetter(isolate_, array_buffer_prototype,
                        factory->detached_string(),
                        Builtin::kArrayBufferPrototypeGetDetached, kAdapt);
  }

  {  // -- S h a r e d A r r a y B u f f e r
    Handle<String> name = factory->SharedArrayBuffer_string();
    Handle<JSFunction> shared_array_buffer_fun =
        CreateArrayBuffer(name, SHARED_ARRAY_BUFFER);
    InstallWithIntrinsicDefaultProto(isolate_, shared_array_buffer_fun,
                                     Context::SHARED_ARRAY_BUFFER_FUN_INDEX);
    InstallSpeciesGetter(isolate_, shared_array_buffer_fun);

    Handle<JSObject> shared_array_buffer_prototype(
        Cast<JSObject>(shared_array_buffer_fun->instance_prototype()),
        isolate_);
    SimpleInstallGetter(isolate_, shared_array_buffer_prototype,
                        factory->max_byte_length_string(),
                        Builtin::kSharedArrayBufferPrototypeGetMaxByteLength,
                        kAdapt);
    SimpleInstallGetter(
        isolate_, shared_array_buffer_prototype, factory->growable_string(),
        Builtin::kSharedArrayBufferPrototypeGetGrowable, kAdapt);
    SimpleInstallFunction(isolate_, shared_array_buffer_prototype, "grow",
                          Builtin::kSharedArrayBufferPrototypeGrow, 1, kAdapt);
  }

  {  // -- A t o m i c s
    Handle<JSObject> atomics_object =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate_, global, "Atomics", atomics_object,
                          DONT_ENUM);
    InstallToStringTag(isolate_, atomics_object, "Atomics");

    SimpleInstallFunction(isolate_, atomics_object, "load",
                          Builtin::kAtomicsLoad, 2, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "store",
                          Builtin::kAtomicsStore, 3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "add", Builtin::kAtomicsAdd,
                          3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "sub", Builtin::kAtomicsSub,
                          3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "and", Builtin::kAtomicsAnd,
                          3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "or", Builtin::kAtomicsOr,
                          3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "xor", Builtin::kAtomicsXor,
                          3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "exchange",
                          Builtin::kAtomicsExchange, 3, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "compareExchange",
                          Builtin::kAtomicsCompareExchange, 4, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "isLockFree",
                          Builtin::kAtomicsIsLockFree, 1, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "wait",
                          Builtin::kAtomicsWait, 4, kAdapt);
    SimpleInstallFunction(isolate(), atomics_object, "waitAsync",
                          Builtin::kAtomicsWaitAsync, 4, kAdapt);
    SimpleInstallFunction(isolate_, atomics_object, "notify",
                          Builtin::kAtomicsNotify, 3, kAdapt);
  }

  {  // -- T y p e d A r r a y
    Handle<JSFunction> typed_array_fun =
        CreateFunction(isolate_, factory->InternalizeUtf8String("TypedArray"),
                       JS_TYPED_ARRAY_TYPE, JSTypedArray::kHeaderSize, 0,
                       factory->the_hole_value(),
                       Builtin::kTypedArrayBaseConstructor, 0, kAdapt);
    typed_array_fun->shared()->set_native(false);
    InstallSpeciesGetter(isolate_, typed_array_fun);
    native_context()->set_typed_array_function(*typed_array_fun);

    SimpleInstallFunction(isolate_, typed_array_fun, "of",
                          Builtin::kTypedArrayOf, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, typed_array_fun, "from",
                          Builtin::kTypedArrayFrom, 1, kDontAdapt);

    // Setup %TypedArrayPrototype%.
    Handle<JSObject> prototype(
        Cast<JSObject>(typed_array_fun->instance_prototype()), isolate());
    native_context()->set_typed_array_prototype(*prototype);

    // Install the "buffer", "byteOffset", "byteLength", "length"
    // and @@toStringTag getters on the {prototype}.
    SimpleInstallGetter(isolate_, prototype, factory->buffer_string(),
                        Builtin::kTypedArrayPrototypeBuffer, kDontAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->byte_length_string(),
                        Builtin::kTypedArrayPrototypeByteLength, kAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->byte_offset_string(),
                        Builtin::kTypedArrayPrototypeByteOffset, kAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->length_string(),
                        Builtin::kTypedArrayPrototypeLength, kAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->to_string_tag_symbol(),
                        Builtin::kTypedArrayPrototypeToStringTag, kAdapt);

    // Install "keys", "values" and "entries" methods on the {prototype}.
    InstallFunctionWithBuiltinId(isolate_, prototype, "entries",
                                 Builtin::kTypedArrayPrototypeEntries, 0,
                                 kDontAdapt);

    InstallFunctionWithBuiltinId(isolate_, prototype, "keys",
                                 Builtin::kTypedArrayPrototypeKeys, 0,
                                 kDontAdapt);

    DirectHandle<JSFunction> values = InstallFunctionWithBuiltinId(
        isolate_, prototype, "values", Builtin::kTypedArrayPrototypeValues, 0,
        kDontAdapt);
    JSObject::AddProperty(isolate_, prototype, factory->iterator_symbol(),
                          values, DONT_ENUM);

    // TODO(caitp): alphasort accessors/methods
    SimpleInstallFunction(isolate_, prototype, "at",
                          Builtin::kTypedArrayPrototypeAt, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "copyWithin",
                          Builtin::kTypedArrayPrototypeCopyWithin, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "every",
                          Builtin::kTypedArrayPrototypeEvery, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "fill",
                          Builtin::kTypedArrayPrototypeFill, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "filter",
                          Builtin::kTypedArrayPrototypeFilter, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "find",
                          Builtin::kTypedArrayPrototypeFind, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "findIndex",
                          Builtin::kTypedArrayPrototypeFindIndex, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "findLast",
                          Builtin::kTypedArrayPrototypeFindLast, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "findLastIndex",
                          Builtin::kTypedArrayPrototypeFindLastIndex, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "forEach",
                          Builtin::kTypedArrayPrototypeForEach, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "includes",
                          Builtin::kTypedArrayPrototypeIncludes, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "indexOf",
                          Builtin::kTypedArrayPrototypeIndexOf, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "join",
                          Builtin::kTypedArrayPrototypeJoin, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "lastIndexOf",
                          Builtin::kTypedArrayPrototypeLastIndexOf, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "map",
                          Builtin::kTypedArrayPrototypeMap, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "reverse",
                          Builtin::kTypedArrayPrototypeReverse, 0, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "reduce",
                          Builtin::kTypedArrayPrototypeReduce, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "reduceRight",
                          Builtin::kTypedArrayPrototypeReduceRight, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "set",
                          Builtin::kTypedArrayPrototypeSet, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "slice",
                          Builtin::kTypedArrayPrototypeSlice, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "some",
                          Builtin::kTypedArrayPrototypeSome, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "sort",
                          Builtin::kTypedArrayPrototypeSort, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "subarray",
                          Builtin::kTypedArrayPrototypeSubArray, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toReversed",
                          Builtin::kTypedArrayPrototypeToReversed, 0,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "toSorted",
                          Builtin::kTypedArrayPrototypeToSorted, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "with",
                          Builtin::kTypedArrayPrototypeWith, 2, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "toLocaleString",
                          Builtin::kTypedArrayPrototypeToLocaleString, 0,
                          kDontAdapt);
    JSObject::AddProperty(isolate_, prototype, factory->toString_string(),
                          array_prototype_to_string_fun, DONT_ENUM);
  }

  {  // -- T y p e d A r r a y s
#define INSTALL_TYPED_ARRAY(Type, type, TYPE, ctype)                         \
  {                                                                          \
    Handle<JSFunction> fun = InstallTypedArray(                              \
        #Type "Array", TYPE##_ELEMENTS, TYPE##_TYPED_ARRAY_CONSTRUCTOR_TYPE, \
        Context::RAB_GSAB_##TYPE##_ARRAY_MAP_INDEX);                         \
    InstallWithIntrinsicDefaultProto(isolate_, fun,                          \
                                     Context::TYPE##_ARRAY_FUN_INDEX);       \
  }
    TYPED_ARRAYS_BASE(INSTALL_TYPED_ARRAY)
#undef INSTALL_TYPED_ARRAY
  }

  {  // -- D a t a V i e w
    Handle<JSFunction> data_view_fun = InstallFunction(
        isolate_, global, "DataView", JS_DATA_VIEW_TYPE,
        JSDataView::kSizeWithEmbedderFields, 0, factory->the_hole_value(),
        Builtin::kDataViewConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, data_view_fun,
                                     Context::DATA_VIEW_FUN_INDEX);

    // Setup %DataViewPrototype%.
    Handle<JSObject> prototype(
        Cast<JSObject>(data_view_fun->instance_prototype()), isolate());

    InstallToStringTag(isolate_, prototype, "DataView");

    // Setup objects needed for the JSRabGsabDataView.
    DirectHandle<Map> rab_gsab_data_view_map =
        factory->NewContextfulMapForCurrentContext(
            JS_RAB_GSAB_DATA_VIEW_TYPE, JSDataView::kSizeWithEmbedderFields,
            TERMINAL_FAST_ELEMENTS_KIND);
    Map::SetPrototype(isolate(), rab_gsab_data_view_map, prototype);
    rab_gsab_data_view_map->SetConstructor(*data_view_fun);
    native_context()->set_js_rab_gsab_data_view_map(*rab_gsab_data_view_map);

    // Install the "buffer", "byteOffset" and "byteLength" getters
    // on the {prototype}.
    SimpleInstallGetter(isolate_, prototype, factory->buffer_string(),
                        Builtin::kDataViewPrototypeGetBuffer, kDontAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->byte_length_string(),
                        Builtin::kDataViewPrototypeGetByteLength, kDontAdapt);
    SimpleInstallGetter(isolate_, prototype, factory->byte_offset_string(),
                        Builtin::kDataViewPrototypeGetByteOffset, kDontAdapt);

    SimpleInstallFunction(isolate_, prototype, "getInt8",
                          Builtin::kDataViewPrototypeGetInt8, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setInt8",
                          Builtin::kDataViewPrototypeSetInt8, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUint8",
                          Builtin::kDataViewPrototypeGetUint8, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUint8",
                          Builtin::kDataViewPrototypeSetUint8, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getInt16",
                          Builtin::kDataViewPrototypeGetInt16, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setInt16",
                          Builtin::kDataViewPrototypeSetInt16, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUint16",
                          Builtin::kDataViewPrototypeGetUint16, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUint16",
                          Builtin::kDataViewPrototypeSetUint16, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getInt32",
                          Builtin::kDataViewPrototypeGetInt32, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setInt32",
                          Builtin::kDataViewPrototypeSetInt32, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getUint32",
                          Builtin::kDataViewPrototypeGetUint32, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setUint32",
                          Builtin::kDataViewPrototypeSetUint32, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getFloat32",
                          Builtin::kDataViewPrototypeGetFloat32, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setFloat32",
                          Builtin::kDataViewPrototypeSetFloat32, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getFloat64",
                          Builtin::kDataViewPrototypeGetFloat64, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setFloat64",
                          Builtin::kDataViewPrototypeSetFloat64, 2, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getBigInt64",
                          Builtin::kDataViewPrototypeGetBigInt64, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setBigInt64",
                          Builtin::kDataViewPrototypeSetBigInt64, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "getBigUint64",
                          Builtin::kDataViewPrototypeGetBigUint64, 1,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "setBigUint64",
                          Builtin::kDataViewPrototypeSetBigUint64, 2,
                          kDontAdapt);
  }

  {  // -- M a p
    Handle<JSFunction> js_map_fun = InstallFunction(
        isolate_, global, "Map", JS_MAP_TYPE, JSMap::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kMapConstructor, 0, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, js_map_fun,
                                     Context::JS_MAP_FUN_INDEX);

    SimpleInstallFunction(isolate_, js_map_fun, "groupBy", Builtin::kMapGroupBy,
                          2, kAdapt);

    // Setup %MapPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(js_map_fun->instance_prototype()),
                               isolate());

    InstallToStringTag(isolate_, prototype, factory->Map_string());

    DirectHandle<JSFunction> map_get = SimpleInstallFunction(
        isolate_, prototype, "get", Builtin::kMapPrototypeGet, 1, kAdapt);
    native_context()->set_map_get(*map_get);

    DirectHandle<JSFunction> map_set = SimpleInstallFunction(
        isolate_, prototype, "set", Builtin::kMapPrototypeSet, 2, kAdapt);
    // Check that index of "set" function in JSCollection is correct.
    DCHECK_EQ(JSCollection::kAddFunctionDescriptorIndex,
              prototype->map()->LastAdded().as_int());
    native_context()->set_map_set(*map_set);

    DirectHandle<JSFunction> map_has = SimpleInstallFunction(
        isolate_, prototype, "has", Builtin::kMapPrototypeHas, 1, kAdapt);
    native_context()->set_map_has(*map_has);

    DirectHandle<JSFunction> map_delete = SimpleInstallFunction(
        isolate_, prototype, "delete", Builtin::kMapPrototypeDelete, 1, kAdapt);
    native_context()->set_map_delete(*map_delete);

    SimpleInstallFunction(isolate_, prototype, "clear",
                          Builtin::kMapPrototypeClear, 0, kAdapt);
    DirectHandle<JSFunction> entries =
        SimpleInstallFunction(isolate_, prototype, "entries",
                              Builtin::kMapPrototypeEntries, 0, kAdapt);
    JSObject::AddProperty(isolate_, prototype, factory->iterator_symbol(),
                          entries, DONT_ENUM);
    SimpleInstallFunction(isolate_, prototype, "forEach",
                          Builtin::kMapPrototypeForEach, 1, kDontAdapt);
    SimpleInstallFunction(isolate_, prototype, "keys",
                          Builtin::kMapPrototypeKeys, 0, kAdapt);
    SimpleInstallGetter(isolate_, prototype,
                        factory->InternalizeUtf8String("size"),
                        Builtin::kMapPrototypeGetSize, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "values",
                          Builtin::kMapPrototypeValues, 0, kAdapt);

    native_context()->set_initial_map_prototype_map(prototype->map());

    InstallSpeciesGetter(isolate_, js_map_fun);

    DCHECK(js_map_fun->HasFastProperties());

    native_context()->set_js_map_map(js_map_fun->initial_map());
  }

  {  // -- B i g I n t
    Handle<JSFunction> bigint_fun = InstallFunction(
        isolate_, global, "BigInt", JS_PRIMITIVE_WRAPPER_TYPE,
        JSPrimitiveWrapper::kHeaderSize, 0, factory->the_hole_value(),
        Builtin::kBigIntConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, bigint_fun,
                                     Context::BIGINT_FUNCTION_INDEX);

    // Install the properties of the BigInt constructor.
    // asUintN(bits, bigint)
    SimpleInstallFunction(isolate_, bigint_fun, "asUintN",
                          Builtin::kBigIntAsUintN, 2, kDontAdapt);
    // asIntN(bits, bigint)
    SimpleInstallFunction(isolate_, bigint_fun, "asIntN",
                          Builtin::kBigIntAsIntN, 2, kDontAdapt);

    // Set up the %BigIntPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(bigint_fun->instance_prototype()),
                               isolate_);
    JSFunction::SetPrototype(bigint_fun, prototype);

    // Install the properties of the BigInt.prototype.
    // "constructor" is created implicitly by InstallFunction() above.
    // toLocaleString([reserved1 [, reserved2]])
    SimpleInstallFunction(isolate_, prototype, "toLocaleString",
                          Builtin::kBigIntPrototypeToLocaleString, 0,
                          kDontAdapt);
    // toString([radix])
    SimpleInstallFunction(isolate_, prototype, "toString",
                          Builtin::kBigIntPrototypeToString, 0, kDontAdapt);
    // valueOf()
    SimpleInstallFunction(isolate_, prototype, "valueOf",
                          Builtin::kBigIntPrototypeValueOf, 0, kDontAdapt);
    // @@toStringTag
    InstallToStringTag(isolate_, prototype, factory->BigInt_string());
  }

  {  // -- S e t
    Handle<JSFunction> js_set_fun = InstallFunction(
        isolate_, global, "Set", JS_SET_TYPE, JSSet::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kSetConstructor, 0, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, js_set_fun,
                                     Context::JS_SET_FUN_INDEX);

    // Setup %SetPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(js_set_fun->instance_prototype()),
                               isolate());

    InstallToStringTag(isolate_, prototype, factory->Set_string());

    DirectHandle<JSFunction> set_has = SimpleInstallFunction(
        isolate_, prototype, "has", Builtin::kSetPrototypeHas, 1, kAdapt);
    native_context()->set_set_has(*set_has);

    DirectHandle<JSFunction> set_add = SimpleInstallFunction(
        isolate_, prototype, "add", Builtin::kSetPrototypeAdd, 1, kAdapt);
    // Check that index of "add" function in JSCollection is correct.
    DCHECK_EQ(JSCollection::kAddFunctionDescriptorIndex,
              prototype->map()->LastAdded().as_int());
    native_context()->set_set_add(*set_add);

    DirectHandle<JSFunction> set_delete = SimpleInstallFunction(
        isolate_, prototype, "delete", Builtin::kSetPrototypeDelete, 1, kAdapt);
    native_context()->set_set_delete(*set_delete);

    SimpleInstallFunction(isolate_, prototype, "clear",
                          Builtin::kSetPrototypeClear, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "entries",
                          Builtin::kSetPrototypeEntries, 0, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "forEach",
                          Builtin::kSetPrototypeForEach, 1, kDontAdapt);
    SimpleInstallGetter(isolate_, prototype,
                        factory->InternalizeUtf8String("size"),
                        Builtin::kSetPrototypeGetSize, kAdapt);
    DirectHandle<JSFunction> values = SimpleInstallFunction(
        isolate_, prototype, "values", Builtin::kSetPrototypeValues, 0, kAdapt);
    JSObject::AddProperty(isolate_, prototype, factory->keys_string(), values,
                          DONT_ENUM);
    JSObject::AddProperty(isolate_, prototype, factory->iterator_symbol(),
                          values, DONT_ENUM);

    native_context()->set_initial_set_prototype_map(prototype->map());
    native_context()->set_initial_set_prototype(*prototype);

    InstallSpeciesGetter(isolate_, js_set_fun);

    DCHECK(js_set_fun->HasFastProperties());

    native_context()->set_js_set_map(js_set_fun->initial_map());
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_SET_PROTOTYPE_TYPE);
  }

  {  // -- J S M o d u l e N a m e s p a c e
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_MODULE_NAMESPACE_TYPE, JSModuleNamespace::kSize,
        TERMINAL_FAST_ELEMENTS_KIND, JSModuleNamespace::kInObjectFieldCount);
    map->SetConstructor(native_context()->object_function());
    Map::SetPrototype(isolate(), map, isolate_->factory()->null_value());
    Map::EnsureDescriptorSlack(isolate_, map, 1);
    native_context()->set_js_module_namespace_map(*map);

    {  // Install @@toStringTag.
      PropertyAttributes attribs =
          static_cast<PropertyAttributes>(DONT_DELETE | DONT_ENUM | READ_ONLY);
      Descriptor d =
          Descriptor::DataField(isolate(), factory->to_string_tag_symbol(),
                                JSModuleNamespace::kToStringTagFieldIndex,
                                attribs, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
  }

  {  // -- I t e r a t o r R e s u l t
    std::array<Handle<Name>, 2> fields{factory->value_string(),
                                       factory->done_string()};
    DirectHandle<Map> map = CreateLiteralObjectMapFromCache(isolate(), fields);
    native_context()->set_iterator_result_map(*map);
  }

  {  // -- W e a k M a p
    Handle<JSFunction> cons =
        InstallFunction(isolate_, global, "WeakMap", JS_WEAK_MAP_TYPE,
                        JSWeakMap::kHeaderSize, 0, factory->the_hole_value(),
                        Builtin::kWeakMapConstructor, 0, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, cons,
                                     Context::JS_WEAK_MAP_FUN_INDEX);

    // Setup %WeakMapPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(cons->instance_prototype()),
                               isolate());

    DirectHandle<JSFunction> weakmap_delete =
        SimpleInstallFunction(isolate_, prototype, "delete",
                              Builtin::kWeakMapPrototypeDelete, 1, kAdapt);
    native_context()->set_weakmap_delete(*weakmap_delete);

    DirectHandle<JSFunction> weakmap_get = SimpleInstallFunction(
        isolate_, prototype, "get", Builtin::kWeakMapGet, 1, kAdapt);
    native_context()->set_weakmap_get(*weakmap_get);

    DirectHandle<JSFunction> weakmap_set = SimpleInstallFunction(
        isolate_, prototype, "set", Builtin::kWeakMapPrototypeSet, 2, kAdapt);
    // Check that index of "set" function in JSWeakCollection is correct.
    DCHECK_EQ(JSWeakCollection::kAddFunctionDescriptorIndex,
              prototype->map()->LastAdded().as_int());

    native_context()->set_weakmap_set(*weakmap_set);
    SimpleInstallFunction(isolate_, prototype, "has",
                          Builtin::kWeakMapPrototypeHas, 1, kAdapt);

    InstallToStringTag(isolate_, prototype, "WeakMap");

    native_context()->set_initial_weakmap_prototype_map(prototype->map());
  }

  {  // -- W e a k S e t
    Handle<JSFunction> cons =
        InstallFunction(isolate_, global, "WeakSet", JS_WEAK_SET_TYPE,
                        JSWeakSet::kHeaderSize, 0, factory->the_hole_value(),
                        Builtin::kWeakSetConstructor, 0, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, cons,
                                     Context::JS_WEAK_SET_FUN_INDEX);

    // Setup %WeakSetPrototype%.
    Handle<JSObject> prototype(Cast<JSObject>(cons->instance_prototype()),
                               isolate());

    SimpleInstallFunction(isolate_, prototype, "delete",
                          Builtin::kWeakSetPrototypeDelete, 1, kAdapt);
    SimpleInstallFunction(isolate_, prototype, "has",
                          Builtin::kWeakSetPrototypeHas, 1, kAdapt);

    DirectHandle<JSFunction> weakset_add = SimpleInstallFunction(
        isolate_, prototype, "add", Builtin::kWeakSetPrototypeAdd, 1, kAdapt);
    // Check that index of "add" function in JSWeakCollection is correct.
    DCHECK_EQ(JSWeakCollection::kAddFunctionDescriptorIndex,
              prototype->map()->LastAdded().as_int());

    native_context()->set_weakset_add(*weakset_add);

    InstallToStringTag(isolate_, prototype,
                       factory->InternalizeUtf8String("WeakSet"));

    native_context()->set_initial_weakset_prototype_map(prototype->map());
  }

  {  // -- P r o x y
    CreateJSProxyMaps();
    // Proxy function map has prototype slot for storing initial map but does
    // not have a prototype property.
    Handle<Map> proxy_function_map = Map::Copy(
        isolate_, isolate_->strict_function_without_prototype_map(), "Proxy");
    proxy_function_map->set_is_constructor(true);

    Handle<String> name = factory->Proxy_string();
    Handle<JSFunction> proxy_function =
        CreateFunctionForBuiltin(isolate(), name, proxy_function_map,
                                 Builtin::kProxyConstructor, 2, kAdapt);

    isolate_->proxy_map()->SetConstructor(*proxy_function);

    native_context()->set_proxy_function(*proxy_function);
    JSObject::AddProperty(isolate_, global, name, proxy_function, DONT_ENUM);

    DCHECK(!proxy_function->has_prototype_property());

    SimpleInstallFunction(isolate_, proxy_function, "revocable",
                          Builtin::kProxyRevocable, 2, kAdapt);
  }

  {  // -- R e f l e c t
    Handle<String> reflect_string = factory->InternalizeUtf8String("Reflect");
    Handle<JSObject> reflect =
        factory->NewJSObject(isolate_->object_function(), AllocationType::kOld);
    JSObject::AddProperty(isolate_, global, reflect_string, reflect, DONT_ENUM);
    InstallToStringTag(isolate_, reflect, reflect_string);

    SimpleInstallFunction(isolate_, reflect, "defineProperty",
                          Builtin::kReflectDefineProperty, 3, kAdapt);

    SimpleInstallFunction(isolate_, reflect, "deleteProperty",
                          Builtin::kReflectDeleteProperty, 2, kAdapt);

    DirectHandle<JSFunction> apply = SimpleInstallFunction(
        isolate_, reflect, "apply", Builtin::kReflectApply, 3, kDontAdapt);
    native_context()->set_reflect_apply(*apply);

    DirectHandle<JSFunction> construct =
        SimpleInstallFunction(isolate_, reflect, "construct",
                              Builtin::kReflectConstruct, 2, kDontAdapt);
    native_context()->set_reflect_construct(*construct);

    SimpleInstallFunction(isolate_, reflect, "get", Builtin::kReflectGet, 2,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, reflect, "getOwnPropertyDescriptor",
                          Builtin::kReflectGetOwnPropertyDescriptor, 2, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "getPrototypeOf",
                          Builtin::kReflectGetPrototypeOf, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "has", Builtin::kReflectHas, 2,
                          kAdapt);
    SimpleInstallFunction(isolate_, reflect, "isExtensible",
                          Builtin::kReflectIsExtensible, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "ownKeys",
                          Builtin:
```
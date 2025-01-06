Response: The user wants a summary of the provided C++ code, specifically focusing on its function and relationship to JavaScript. Since this is part 4 of 6, the summary should reflect the functionality within this specific segment.

The code primarily deals with setting up various built-in JavaScript objects and their prototypes within the V8 engine. It involves creating constructor functions and adding methods and properties to their prototypes.

Key areas covered in this section of the code include:

*   **Intl API (if enabled):** DurationFormat
*   **ArrayBuffer and SharedArrayBuffer:** Constructors, prototypes with methods like `resize`, `transfer`, `grow`, and getters for `maxByteLength`, `resizable`, `detached`, `growable`.
*   **Atomics:** The `Atomics` object with static methods like `load`, `store`, `add`, `sub`, `and`, `or`, `xor`, `exchange`, `compareExchange`, `isLockFree`, `wait`, `waitAsync`, and `notify`.
*   **Typed Arrays:** The base `TypedArray` constructor and prototype, and specific typed array constructors (Int8Array, Uint8Array, etc.)
*   **DataView:** The `DataView` constructor and prototype with methods for getting and setting different data types.
*   **Map:** The `Map` constructor and prototype with methods like `get`, `set`, `has`, `delete`, `clear`, `entries`, `forEach`, `keys`, `values`, and the `size` getter.
*   **BigInt:** The `BigInt` constructor and prototype with methods like `toLocaleString`, `toString`, and `valueOf`, and static methods `asUintN` and `asIntN`.
*   **Set:** The `Set` constructor and prototype with methods like `has`, `add`, `delete`, `clear`, `entries`, `forEach`, `values`, and the `size` getter.
*   **Module Namespace:** Setup for the `JSModuleNamespace` object.
*   **Iterator Result:** Setup for the structure of iterator results.
*   **WeakMap:** The `WeakMap` constructor and prototype with methods like `delete`, `get`, `set`, and `has`.
*   **WeakSet:** The `WeakSet` constructor and prototype with methods like `delete`, `has`, and `add`.
*   **Proxy:** Creation of maps for `Proxy` objects and the `Proxy` constructor with the `revocable` method.
*   **Reflect:** The `Reflect` object with static methods for various object manipulations like `defineProperty`, `deleteProperty`, `apply`, `construct`, `get`, `getOwnPropertyDescriptor`, `getPrototypeOf`, `has`, `isExtensible`, `ownKeys`, `preventExtensions`, `set`, and `setPrototypeOf`.
*   **Bound Function:** Creation of maps for bound functions.
*   **FinalizationRegistry:** The `FinalizationRegistry` constructor and prototype with methods like `register` and `unregister`.
*   **WeakRef:** The `WeakRef` constructor and prototype with the `deref` method.
*   **Arguments Objects:** Setup for sloppy and strict mode arguments objects.
*   **Context Extension:** Setup for context extension objects.
*   **Call-as-Function and Call-as-Constructor Delegates:** Setting up delegates for API calls.
*   **Helper function `InstallTypedArray`:**  A function to simplify the creation of specific Typed Array constructors and prototypes.
*   **Experimental Global Initialization:** Calls functions to initialize experimental JavaScript features.
*   **Extension Compilation:** Functionality to compile and execute V8 extensions.
*   **Iterator Functions Initialization:** Initialization of built-in iterator-related functions and prototypes for Set, Map, Generator, and AsyncGenerator.
*   **CallSite Builtins Initialization:** Setup for the `CallSite` object and its prototype methods (used in stack traces).
*   **Console Initialization:** Setup for the `console` object with methods like `log`, `warn`, `error`, etc.
*   **Iterator Helpers Initialization (if enabled):** Setup for the `Iterator` constructor and prototype with methods like `from`, `next`, and `return`.

The code establishes the fundamental building blocks for these JavaScript features within the V8 engine.

For JavaScript examples, consider how these built-in objects are used in everyday code.
这个C++代码片段是V8 JavaScript引擎初始化过程的一部分，主要负责 **创建和配置内置的JavaScript对象和构造函数，特别是关于类型化数组 (Typed Arrays)，数据视图 (DataView)，以及集合类型 (Map, Set, WeakMap, WeakSet)**。

以下是代码的主要功能归纳：

1. **Intl API (国际化支持):**  如果 `V8_INTL_SUPPORT` 宏定义被启用，则会创建和配置 `Intl.DurationFormat` 构造函数及其原型上的方法 (如 `supportedLocalesOf`, `resolvedOptions`, `format`, `formatToParts`)。

2. **ArrayBuffer:** 创建 `ArrayBuffer` 构造函数，并设置其原型，包括 `resize`, `transfer`, `transferToFixedLength` 方法，以及 `maxByteLength`, `resizable`, `detached` 属性的 getter。

3. **SharedArrayBuffer:** 创建 `SharedArrayBuffer` 构造函数，并设置其原型，包括 `grow` 方法，以及 `maxByteLength`, `growable` 属性的 getter。

4. **Atomics:** 创建全局对象 `Atomics`，并添加静态方法，例如 `load`, `store`, `add`, `sub`, `and`, `or`, `xor`, `exchange`, `compareExchange`, `isLockFree`, `wait`, `waitAsync`, `notify`。 这些方法用于在共享内存上执行原子操作。

5. **Typed Arrays:**
    *   创建抽象的 `TypedArray` 构造函数，并将其设置为 `native_context` 的属性。
    *   在 `TypedArray` 的原型上安装通用的方法，例如 `entries`, `keys`, `values`, `at`, `copyWithin`, `every`, `fill`, `filter`, `find`, `findIndex`, `findLast`, `findLastIndex`, `forEach`, `includes`, `indexOf`, `join`, `lastIndexOf`, `map`, `reverse`, `reduce`, `reduceRight`, `set`, `slice`, `some`, `sort`, `subarray`, `toReversed`, `toSorted`, `with`, `toLocaleString`。
    *   为各种具体的类型化数组（如 `Int8Array`, `Uint8Array`, `Float32Array` 等）调用 `InstallTypedArray` 函数，创建相应的构造函数并关联到各自的全局对象属性。

6. **DataView:** 创建 `DataView` 构造函数，并设置其原型，包括用于读取和写入不同数据类型的方法，例如 `getInt8`, `setInt8`, `getUint32`, `setUint32`, `getFloat64`, `setFloat64` 等。

7. **Map:** 创建 `Map` 构造函数，并设置其原型，包括 `get`, `set`, `has`, `delete`, `clear`, `entries`, `forEach`, `keys`, `values` 方法，以及 `size` 的 getter。

8. **BigInt:** 创建 `BigInt` 构造函数，并设置其原型，包括 `toLocaleString`, `toString`, `valueOf` 方法，以及静态方法 `asUintN`, `asIntN`。

9. **Set:** 创建 `Set` 构造函数，并设置其原型，包括 `has`, `add`, `delete`, `clear`, `entries`, `forEach`, `values` 方法，以及 `size` 的 getter。

10. **Module Namespace:** 创建 `JSModuleNamespace` 对象的 Map。

11. **Iterator Result:** 创建迭代器结果对象的 Map。

12. **WeakMap:** 创建 `WeakMap` 构造函数，并设置其原型，包括 `delete`, `get`, `set`, `has` 方法。

13. **WeakSet:** 创建 `WeakSet` 构造函数，并设置其原型，包括 `delete`, `has`, `add` 方法。

14. **Proxy:** 创建 `Proxy` 构造函数，并添加静态方法 `revocable`。

15. **Reflect:** 创建全局对象 `Reflect`，并添加静态方法，例如 `defineProperty`, `deleteProperty`, `apply`, `construct`, `get`, `getOwnPropertyDescriptor`, `getPrototypeOf`, `has`, `isExtensible`, `ownKeys`, `preventExtensions`, `set`, `setPrototypeOf`。

16. **Bound Function:** 创建 `JSBoundFunction` 对象的 Map。

17. **FinalizationRegistry:** 创建 `FinalizationRegistry` 构造函数，并设置其原型，包括 `register`, `unregister` 方法。

18. **WeakRef:** 创建 `WeakRef` 构造函数，并设置其原型，包括 `deref` 方法。

19. **Arguments 对象:** 设置 sloppy 模式和 strict 模式的 arguments 对象的 Map。

20. **Context Extension:** 创建 context extension 对象的构造函数。

21. **Call-as-Function 和 Call-as-Constructor Delegate:** 设置用于处理函数调用和构造函数调用的代理。

**与 JavaScript 的关系 (示例):**

这段代码直接关联着 JavaScript 中我们常用的内置对象。它在 C++ 层面定义了这些对象的结构和行为，使得 JavaScript 代码能够使用它们。

**例如，关于 `ArrayBuffer` 和 `Uint8Array`:**

**C++ (在 `bootstrapper.cc` 中):**

```c++
{  // -- A r r a y B u f f e r
    Handle<String> name = factory->ArrayBuffer_string();
    Handle<JSFunction> array_buffer_fun = CreateArrayBuffer(name, ARRAY_BUFFER);
    JSObject::AddProperty(isolate_, global, name, array_buffer_fun, DONT_ENUM);
    // ... 安装 ArrayBuffer 的原型方法和属性
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
    TYPED_ARRAYS_BASE(INSTALL_TYPED_ARRAY) // 其中会调用 INSTALL_TYPED_ARRAY(Uint8, uint8, UINT8, uint8_t)
#undef INSTALL_TYPED_ARRAY
}
```

**JavaScript:**

```javascript
// 在 JavaScript 中创建 ArrayBuffer 的实例
const buffer = new ArrayBuffer(10); // 这会调用 C++ 中创建的 ArrayBuffer 构造函数

// 创建 Uint8Array 的实例，它会关联到 ArrayBuffer 的内存
const uint8Array = new Uint8Array(buffer); // 这会调用 C++ 中创建的 Uint8Array 构造函数

uint8Array[0] = 255; // 设置 Uint8Array 的第一个元素
console.log(uint8Array[0]); // 输出 255

// 使用 ArrayBuffer 的方法
console.log(buffer.byteLength); // 输出 10
```

在这个例子中，C++ 代码负责创建 `ArrayBuffer` 和 `Uint8Array` 的构造函数，并定义了它们的基本行为和属性。JavaScript 代码通过 `new ArrayBuffer()` 和 `new Uint8Array()` 来实例化这些对象，并利用 C++ 中定义的功能。

**再例如，关于 `Map`:**

**C++ (在 `bootstrapper.cc` 中):**

```c++
{  // -- M a p
    Handle<JSFunction> js_map_fun = InstallFunction(
        isolate_, global, "Map", JS_MAP_TYPE, JSMap::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kMapConstructor, 0, kDontAdapt);
    // ... 安装 Map 的原型方法和属性，例如 get, set, has
}
```

**JavaScript:**

```javascript
// 在 JavaScript 中创建 Map 的实例
const map = new Map(); // 这会调用 C++ 中创建的 Map 构造函数

// 使用 Map 的方法
map.set('key1', 'value1'); // 这会调用 C++ 中定义的 Map 原型的 set 方法
console.log(map.get('key1')); // 输出 'value1'，这会调用 C++ 中定义的 Map 原型的 get 方法
console.log(map.has('key1')); // 输出 true，这会调用 C++ 中定义的 Map 原型的 has 方法
```

总之，这段 C++ 代码是 V8 引擎的基石，它定义了 JavaScript 中许多核心对象的蓝图，使得 JavaScript 代码能够在这些预定义好的结构上运行。

Prompt: 
```
这是目录为v8/src/init/bootstrapper.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
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
                          Builtin::kReflectOwnKeys, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "preventExtensions",
                          Builtin::kReflectPreventExtensions, 1, kAdapt);
    SimpleInstallFunction(isolate_, reflect, "set", Builtin::kReflectSet, 3,
                          kDontAdapt);
    SimpleInstallFunction(isolate_, reflect, "setPrototypeOf",
                          Builtin::kReflectSetPrototypeOf, 2, kAdapt);
  }

  {  // --- B o u n d F u n c t i o n
    Handle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_BOUND_FUNCTION_TYPE, JSBoundFunction::kHeaderSize,
        TERMINAL_FAST_ELEMENTS_KIND, 0);
    map->SetConstructor(native_context()->object_function());
    map->set_is_callable(true);
    Map::SetPrototype(isolate(), map, empty_function);

    PropertyAttributes roc_attribs =
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY);
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kLengthDescriptorIndex ==
          0);
      Descriptor d = Descriptor::AccessorConstant(
          factory->length_string(), factory->bound_function_length_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }

    {  // name
      static_assert(
          JSFunctionOrBoundFunctionOrWrappedFunction::kNameDescriptorIndex ==
          1);
      Descriptor d = Descriptor::AccessorConstant(
          factory->name_string(), factory->bound_function_name_accessor(),
          roc_attribs);
      map->AppendDescriptor(isolate(), &d);
    }
    native_context()->set_bound_function_without_constructor_map(*map);

    map = Map::Copy(isolate_, map, "IsConstructor");
    map->set_is_constructor(true);
    native_context()->set_bound_function_with_constructor_map(*map);
  }

  {  // -- F i n a l i z a t i o n R e g i s t r y
    Handle<JSFunction> finalization_registry_fun = InstallFunction(
        isolate_, global, factory->FinalizationRegistry_string(),
        JS_FINALIZATION_REGISTRY_TYPE, JSFinalizationRegistry::kHeaderSize, 0,
        factory->the_hole_value(), Builtin::kFinalizationRegistryConstructor, 1,
        kDontAdapt);
    InstallWithIntrinsicDefaultProto(
        isolate_, finalization_registry_fun,
        Context::JS_FINALIZATION_REGISTRY_FUNCTION_INDEX);

    Handle<JSObject> finalization_registry_prototype(
        Cast<JSObject>(finalization_registry_fun->instance_prototype()),
        isolate());

    InstallToStringTag(isolate_, finalization_registry_prototype,
                       factory->FinalizationRegistry_string());

    SimpleInstallFunction(isolate_, finalization_registry_prototype, "register",
                          Builtin::kFinalizationRegistryRegister, 2,
                          kDontAdapt);

    SimpleInstallFunction(
        isolate_, finalization_registry_prototype, "unregister",
        Builtin::kFinalizationRegistryUnregister, 1, kDontAdapt);

    // The cleanupSome function is created but not exposed, as it is used
    // internally by InvokeFinalizationRegistryCleanupFromTask.
    //
    // It is exposed by v8_flags.harmony_weak_refs_with_cleanup_some.
    DirectHandle<JSFunction> cleanup_some_fun = SimpleCreateFunction(
        isolate_, factory->InternalizeUtf8String("cleanupSome"),
        Builtin::kFinalizationRegistryPrototypeCleanupSome, 0, kDontAdapt);
    native_context()->set_finalization_registry_cleanup_some(*cleanup_some_fun);
  }

  {  // -- W e a k R e f
    Handle<JSFunction> weak_ref_fun =
        InstallFunction(isolate_, global, "WeakRef", JS_WEAK_REF_TYPE,
                        JSWeakRef::kHeaderSize, 0, factory->the_hole_value(),
                        Builtin::kWeakRefConstructor, 1, kDontAdapt);
    InstallWithIntrinsicDefaultProto(isolate_, weak_ref_fun,
                                     Context::JS_WEAK_REF_FUNCTION_INDEX);

    Handle<JSObject> weak_ref_prototype(
        Cast<JSObject>(weak_ref_fun->instance_prototype()), isolate());

    InstallToStringTag(isolate_, weak_ref_prototype, factory->WeakRef_string());

    SimpleInstallFunction(isolate_, weak_ref_prototype, "deref",
                          Builtin::kWeakRefDeref, 0, kAdapt);
  }

  {  // --- sloppy arguments map
    Handle<String> arguments_string = factory->Arguments_string();
    DirectHandle<JSFunction> function = CreateFunctionForBuiltinWithPrototype(
        isolate(), arguments_string, Builtin::kIllegal,
        isolate()->initial_object_prototype(), JS_ARGUMENTS_OBJECT_TYPE,
        JSSloppyArgumentsObject::kSize, 2, MUTABLE, 0, kDontAdapt);
    DirectHandle<Map> map(function->initial_map(), isolate());

    // Create the descriptor array for the arguments object.
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      Descriptor d =
          Descriptor::DataField(isolate(), factory->length_string(),
                                JSSloppyArgumentsObject::kLengthIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // callee
      Descriptor d =
          Descriptor::DataField(isolate(), factory->callee_string(),
                                JSSloppyArgumentsObject::kCalleeIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    // @@iterator method is added later.

    native_context()->set_sloppy_arguments_map(*map);

    DCHECK(!map->is_dictionary_map());
    DCHECK(IsObjectElementsKind(map->elements_kind()));
  }

  {  // --- fast and slow aliased arguments map
    Handle<Map> map = isolate_->sloppy_arguments_map();
    map = Map::Copy(isolate_, map, "FastAliasedArguments");
    map->set_elements_kind(FAST_SLOPPY_ARGUMENTS_ELEMENTS);
    DCHECK_EQ(2, map->GetInObjectProperties());
    native_context()->set_fast_aliased_arguments_map(*map);

    map = Map::Copy(isolate_, map, "SlowAliasedArguments");
    map->set_elements_kind(SLOW_SLOPPY_ARGUMENTS_ELEMENTS);
    DCHECK_EQ(2, map->GetInObjectProperties());
    native_context()->set_slow_aliased_arguments_map(*map);
  }

  {  // --- strict mode arguments map
    const PropertyAttributes attributes =
        static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

    // Create the ThrowTypeError function.
    Handle<AccessorPair> callee = factory->NewAccessorPair();

    DirectHandle<JSFunction> poison = GetThrowTypeErrorIntrinsic();

    // Install the ThrowTypeError function.
    callee->set_getter(*poison);
    callee->set_setter(*poison);

    // Create the map. Allocate one in-object field for length.
    DirectHandle<Map> map = factory->NewContextfulMapForCurrentContext(
        JS_ARGUMENTS_OBJECT_TYPE, JSStrictArgumentsObject::kSize,
        PACKED_ELEMENTS, 1);
    // Create the descriptor array for the arguments object.
    Map::EnsureDescriptorSlack(isolate_, map, 2);

    {  // length
      Descriptor d =
          Descriptor::DataField(isolate(), factory->length_string(),
                                JSStrictArgumentsObject::kLengthIndex,
                                DONT_ENUM, Representation::Tagged());
      map->AppendDescriptor(isolate(), &d);
    }
    {  // callee
      Descriptor d = Descriptor::AccessorConstant(factory->callee_string(),
                                                  callee, attributes);
      map->AppendDescriptor(isolate(), &d);
    }
    // @@iterator method is added later.

    DCHECK_EQ(native_context()->object_function()->prototype(),
              *isolate_->initial_object_prototype());
    Map::SetPrototype(isolate(), map, isolate_->initial_object_prototype());

    // Copy constructor from the sloppy arguments boilerplate.
    map->SetConstructor(
        native_context()->sloppy_arguments_map()->GetConstructor());

    native_context()->set_strict_arguments_map(*map);

    DCHECK(!map->is_dictionary_map());
    DCHECK(IsObjectElementsKind(map->elements_kind()));
  }

  {  // --- context extension
    // Create a function for the context extension objects.
    DirectHandle<JSFunction> context_extension_fun = CreateFunction(
        isolate_, factory->empty_string(), JS_CONTEXT_EXTENSION_OBJECT_TYPE,
        JSObject::kHeaderSize, 0, factory->the_hole_value(), Builtin::kIllegal,
        0, kDontAdapt);
    native_context()->set_context_extension_function(*context_extension_fun);
  }

  {
    // Set up the call-as-function delegate.
    DirectHandle<JSFunction> delegate = SimpleCreateFunction(
        isolate_, factory->empty_string(),
        Builtin::kHandleApiCallAsFunctionDelegate, 0, kDontAdapt);
    native_context()->set_call_as_function_delegate(*delegate);
  }

  {
    // Set up the call-as-constructor delegate.
    DirectHandle<JSFunction> delegate = SimpleCreateFunction(
        isolate_, factory->empty_string(),
        Builtin::kHandleApiCallAsConstructorDelegate, 0, kDontAdapt);
    native_context()->set_call_as_constructor_delegate(*delegate);
  }
}

Handle<JSFunction> Genesis::InstallTypedArray(const char* name,
                                              ElementsKind elements_kind,
                                              InstanceType constructor_type,
                                              int rab_gsab_initial_map_index) {
  Handle<JSObject> global =
      Handle<JSObject>(native_context()->global_object(), isolate());

  Handle<JSObject> typed_array_prototype = isolate()->typed_array_prototype();
  Handle<JSFunction> typed_array_function = isolate()->typed_array_function();

  Handle<JSFunction> result = InstallFunction(
      isolate(), global, name, JS_TYPED_ARRAY_TYPE,
      JSTypedArray::kSizeWithEmbedderFields, 0, factory()->the_hole_value(),
      Builtin::kTypedArrayConstructor, 3, kDontAdapt);
  result->initial_map()->set_elements_kind(elements_kind);

  CHECK(JSObject::SetPrototype(isolate(), result, typed_array_function, false,
                               kDontThrow)
            .FromJust());

  DirectHandle<Smi> bytes_per_element(
      Smi::FromInt(1 << ElementsKindToShiftSize(elements_kind)), isolate());

  InstallConstant(isolate(), result, "BYTES_PER_ELEMENT", bytes_per_element);

  // TODO(v8:11256, ishell): given the granularity of typed array constructor
  // protectors, consider creating only one constructor instance type for all
  // typed array constructors.
  SetConstructorInstanceType(isolate_, result, constructor_type);

  // Setup prototype object.
  DCHECK(IsJSObject(result->prototype()));
  Handle<JSObject> prototype(Cast<JSObject>(result->prototype()), isolate());

  CHECK(JSObject::SetPrototype(isolate(), prototype, typed_array_prototype,
                               false, kDontThrow)
            .FromJust());

  CHECK_NE(prototype->map().ptr(),
           isolate_->initial_object_prototype()->map().ptr());
  prototype->map()->set_instance_type(JS_TYPED_ARRAY_PROTOTYPE_TYPE);

  InstallConstant(isolate(), prototype, "BYTES_PER_ELEMENT", bytes_per_element);

  // RAB / GSAB backed TypedArrays don't have separate constructors, but they
  // have their own maps. Create the corresponding map here.
  DirectHandle<Map> rab_gsab_initial_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_TYPED_ARRAY_TYPE, JSTypedArray::kSizeWithEmbedderFields,
          GetCorrespondingRabGsabElementsKind(elements_kind), 0);
  rab_gsab_initial_map->SetConstructor(*result);

  native_context()->set(rab_gsab_initial_map_index, *rab_gsab_initial_map,
                        UPDATE_WRITE_BARRIER, kReleaseStore);
  Map::SetPrototype(isolate(), rab_gsab_initial_map, prototype);

  return result;
}

void Genesis::InitializeExperimentalGlobal() {
#define FEATURE_INITIALIZE_GLOBAL(id, descr) InitializeGlobal_##id();

  // Initialize features from more mature to less mature, because less mature
  // features may depend on more mature features having been initialized
  // already.
  HARMONY_SHIPPING(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_SHIPPING_FEATURES(FEATURE_INITIALIZE_GLOBAL)
  HARMONY_STAGED(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_STAGED_FEATURES(FEATURE_INITIALIZE_GLOBAL)
  HARMONY_INPROGRESS(FEATURE_INITIALIZE_GLOBAL)
  JAVASCRIPT_INPROGRESS_FEATURES(FEATURE_INITIALIZE_GLOBAL)
#undef FEATURE_INITIALIZE_GLOBAL
  InitializeGlobal_regexp_linear_flag();
  InitializeGlobal_sharedarraybuffer();
}

namespace {
class TryCallScope {
 public:
  explicit TryCallScope(Isolate* isolate) : top(isolate->thread_local_top()) {
    top->IncrementCallDepth<true>(this);
  }
  ~TryCallScope() { top->DecrementCallDepth(this); }

 private:
  friend class i::ThreadLocalTop;
  ThreadLocalTop* top;
  Address previous_stack_height_;
};
}  // namespace

bool Genesis::CompileExtension(Isolate* isolate, v8::Extension* extension) {
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<SharedFunctionInfo> function_info;

  Handle<String> source =
      isolate->factory()
          ->NewExternalStringFromOneByte(extension->source())
          .ToHandleChecked();
  DCHECK(source->IsOneByteRepresentation());

  // If we can't find the function in the cache, we compile a new
  // function and insert it into the cache.
  base::Vector<const char> name = base::CStrVector(extension->name());
  SourceCodeCache* cache = isolate->bootstrapper()->extensions_cache();
  Handle<Context> context(isolate->context(), isolate);
  DCHECK(IsNativeContext(*context));

  if (!cache->Lookup(isolate, name, &function_info)) {
    Handle<String> script_name =
        factory->NewStringFromUtf8(name).ToHandleChecked();
    ScriptCompiler::CompilationDetails compilation_details;
    MaybeDirectHandle<SharedFunctionInfo> maybe_function_info =
        Compiler::GetSharedFunctionInfoForScriptWithExtension(
            isolate, source, ScriptDetails(script_name), extension,
            ScriptCompiler::kNoCompileOptions, EXTENSION_CODE,
            &compilation_details);
    if (!maybe_function_info.ToHandle(&function_info)) return false;
    cache->Add(isolate, name, function_info);
  }

  // Set up the function context. Conceptually, we should clone the
  // function before overwriting the context but since we're in a
  // single-threaded environment it is not strictly necessary.
  Handle<JSFunction> fun =
      Factory::JSFunctionBuilder{isolate, function_info, context}.Build();

  // Call function using either the runtime object or the global
  // object as the receiver. Provide no parameters.
  Handle<Object> receiver = isolate->global_object();
  Handle<FixedArray> host_defined_options =
      isolate->factory()->empty_fixed_array();
  TryCallScope try_call_scope(isolate);
  // Blink generally assumes that context creation (where extension compilation
  // is part) cannot be interrupted.
  PostponeInterruptsScope postpone(isolate);
  return !Execution::TryCallScript(isolate, fun, receiver, host_defined_options)
              .is_null();
}

void Genesis::InitializeIteratorFunctions() {
  Isolate* isolate = isolate_;
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<NativeContext> native_context = isolate->native_context();
  Handle<JSObject> iterator_prototype(
      native_context->initial_iterator_prototype(), isolate);

  {  // -- G e n e r a t o r
    PrototypeIterator iter(isolate, native_context->generator_function_map());
    Handle<JSObject> generator_function_prototype(iter.GetCurrent<JSObject>(),
                                                  isolate);
    Handle<JSFunction> generator_function_function = CreateFunction(
        isolate, "GeneratorFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, generator_function_prototype,
        Builtin::kGeneratorFunctionConstructor, 1, kDontAdapt);
    generator_function_function->set_prototype_or_initial_map(
        native_context->generator_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(
        isolate, generator_function_function,
        Context::GENERATOR_FUNCTION_FUNCTION_INDEX);

    JSObject::ForceSetPrototype(isolate, generator_function_function,
                                isolate->function_function());
    JSObject::AddProperty(
        isolate, generator_function_prototype, factory->constructor_string(),
        generator_function_function,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    native_context->generator_function_map()->SetConstructor(
        *generator_function_function);
    native_context->generator_function_with_name_map()->SetConstructor(
        *generator_function_function);
  }

  {  // -- A s y n c G e n e r a t o r
    PrototypeIterator iter(isolate,
                           native_context->async_generator_function_map());
    Handle<JSObject> async_generator_function_prototype(
        iter.GetCurrent<JSObject>(), isolate);

    Handle<JSFunction> async_generator_function_function = CreateFunction(
        isolate, "AsyncGeneratorFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, async_generator_function_prototype,
        Builtin::kAsyncGeneratorFunctionConstructor, 1, kDontAdapt);
    async_generator_function_function->set_prototype_or_initial_map(
        native_context->async_generator_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(
        isolate, async_generator_function_function,
        Context::ASYNC_GENERATOR_FUNCTION_FUNCTION_INDEX);

    JSObject::ForceSetPrototype(isolate, async_generator_function_function,
                                isolate->function_function());

    JSObject::AddProperty(
        isolate, async_generator_function_prototype,
        factory->constructor_string(), async_generator_function_function,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    native_context->async_generator_function_map()->SetConstructor(
        *async_generator_function_function);
    native_context->async_generator_function_with_name_map()->SetConstructor(
        *async_generator_function_function);
  }

  {  // -- S e t I t e r a t o r
    // Setup %SetIteratorPrototype%.
    Handle<JSObject> prototype =
        factory->NewJSObject(isolate->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate, prototype, iterator_prototype);

    InstallToStringTag(isolate, prototype, factory->SetIterator_string());

    // Install the next function on the {prototype}.
    InstallFunctionWithBuiltinId(isolate, prototype, "next",
                                 Builtin::kSetIteratorPrototypeNext, 0, kAdapt);
    native_context->set_initial_set_iterator_prototype(*prototype);
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_SET_ITERATOR_PROTOTYPE_TYPE);

    // Setup SetIterator constructor.
    DirectHandle<JSFunction> set_iterator_function =
        CreateFunction(isolate, "SetIterator", JS_SET_VALUE_ITERATOR_TYPE,
                       JSSetIterator::kHeaderSize, 0, prototype,
                       Builtin::kIllegal, 0, kDontAdapt);
    set_iterator_function->shared()->set_native(false);

    Handle<Map> set_value_iterator_map(set_iterator_function->initial_map(),
                                       isolate);
    native_context->set_set_value_iterator_map(*set_value_iterator_map);

    DirectHandle<Map> set_key_value_iterator_map = Map::Copy(
        isolate, set_value_iterator_map, "JS_SET_KEY_VALUE_ITERATOR_TYPE");
    set_key_value_iterator_map->set_instance_type(
        JS_SET_KEY_VALUE_ITERATOR_TYPE);
    native_context->set_set_key_value_iterator_map(*set_key_value_iterator_map);
  }

  {  // -- M a p I t e r a t o r
    // Setup %MapIteratorPrototype%.
    Handle<JSObject> prototype =
        factory->NewJSObject(isolate->object_function(), AllocationType::kOld);
    JSObject::ForceSetPrototype(isolate, prototype, iterator_prototype);

    InstallToStringTag(isolate, prototype, factory->MapIterator_string());

    // Install the next function on the {prototype}.
    InstallFunctionWithBuiltinId(isolate, prototype, "next",
                                 Builtin::kMapIteratorPrototypeNext, 0, kAdapt);
    native_context->set_initial_map_iterator_prototype(*prototype);
    CHECK_NE(prototype->map().ptr(),
             isolate_->initial_object_prototype()->map().ptr());
    prototype->map()->set_instance_type(JS_MAP_ITERATOR_PROTOTYPE_TYPE);

    // Setup MapIterator constructor.
    DirectHandle<JSFunction> map_iterator_function =
        CreateFunction(isolate, "MapIterator", JS_MAP_KEY_ITERATOR_TYPE,
                       JSMapIterator::kHeaderSize, 0, prototype,
                       Builtin::kIllegal, 0, kDontAdapt);
    map_iterator_function->shared()->set_native(false);

    Handle<Map> map_key_iterator_map(map_iterator_function->initial_map(),
                                     isolate);
    native_context->set_map_key_iterator_map(*map_key_iterator_map);

    DirectHandle<Map> map_key_value_iterator_map = Map::Copy(
        isolate, map_key_iterator_map, "JS_MAP_KEY_VALUE_ITERATOR_TYPE");
    map_key_value_iterator_map->set_instance_type(
        JS_MAP_KEY_VALUE_ITERATOR_TYPE);
    native_context->set_map_key_value_iterator_map(*map_key_value_iterator_map);

    DirectHandle<Map> map_value_iterator_map =
        Map::Copy(isolate, map_key_iterator_map, "JS_MAP_VALUE_ITERATOR_TYPE");
    map_value_iterator_map->set_instance_type(JS_MAP_VALUE_ITERATOR_TYPE);
    native_context->set_map_value_iterator_map(*map_value_iterator_map);
  }

  {  // -- A s y n c F u n c t i o n
    // Builtin functions for AsyncFunction.
    PrototypeIterator iter(isolate, native_context->async_function_map());
    Handle<JSObject> async_function_prototype(iter.GetCurrent<JSObject>(),
                                              isolate);

    Handle<JSFunction> async_function_constructor = CreateFunction(
        isolate, "AsyncFunction", JS_FUNCTION_TYPE,
        JSFunction::kSizeWithPrototype, 0, async_function_prototype,
        Builtin::kAsyncFunctionConstructor, 1, kDontAdapt);
    async_function_constructor->set_prototype_or_initial_map(
        native_context->async_function_map(), kReleaseStore);
    InstallWithIntrinsicDefaultProto(isolate, async_function_constructor,
                                     Context::ASYNC_FUNCTION_FUNCTION_INDEX);

    native_context->set_async_function_constructor(*async_function_constructor);
    JSObject::ForceSetPrototype(isolate, async_function_constructor,
                                isolate->function_function());

    JSObject::AddProperty(
        isolate, async_function_prototype, factory->constructor_string(),
        async_function_constructor,
        static_cast<PropertyAttributes>(DONT_ENUM | READ_ONLY));

    // Async functions don't have a prototype, but they use generator objects
    // under the hood to model the suspend/resume (in await). Instead of using
    // the "prototype" / initial_map machinery (like for (async) generators),
    // there's one global (per native context) map here that is used for the
    // async function generator objects. These objects never escape to user
    // JavaScript anyways.
    DirectHandle<Map> async_function_object_map =
        factory->NewContextfulMapForCurrentContext(
            JS_ASYNC_FUNCTION_OBJECT_TYPE, JSAsyncFunctionObject::kHeaderSize);
    native_context->set_async_function_object_map(*async_function_object_map);

    isolate_->async_function_map()->SetConstructor(*async_function_constructor);
    isolate_->async_function_with_name_map()->SetConstructor(
        *async_function_constructor);
  }
}

void Genesis::InitializeCallSiteBuiltins() {
  Factory* factory = isolate()->factory();
  HandleScope scope(isolate());
  // -- C a l l S i t e
  // Builtin functions for CallSite.

  // CallSites are a special case; the constructor is for our private use
  // only, therefore we set it up as a builtin that throws. Internally, we use
  // CallSiteUtils::Construct to create CallSite objects.

  DirectHandle<JSFunction> callsite_fun = CreateFunction(
      isolate(), "CallSite", JS_OBJECT_TYPE, JSObject::kHeaderSize, 0,
      factory->the_hole_value(), Builtin::kUnsupportedThrower, 0, kDontAdapt);
  isolate()->native_context()->set_callsite_function(*callsite_fun);

  // Setup CallSite.prototype.
  Handle<JSObject> prototype(Cast<JSObject>(callsite_fun->instance_prototype()),
                             isolate());

  struct FunctionInfo {
    const char* name;
    Builtin id;
  };

  FunctionInfo infos[] = {
      {"getColumnNumber", Builtin::kCallSitePrototypeGetColumnNumber},
      {"getEnclosingColumnNumber",
       Builtin::kCallSitePrototypeGetEnclosingColumnNumber},
      {"getEnclosingLineNumber",
       Builtin::kCallSitePrototypeGetEnclosingLineNumber},
      {"getEvalOrigin", Builtin::kCallSitePrototypeGetEvalOrigin},
      {"getFileName", Builtin::kCallSitePrototypeGetFileName},
      {"getFunction", Builtin::kCallSitePrototypeGetFunction},
      {"getFunctionName", Builtin::kCallSitePrototypeGetFunctionName},
      {"getLineNumber", Builtin::kCallSitePrototypeGetLineNumber},
      {"getMethodName", Builtin::kCallSitePrototypeGetMethodName},
      {"getPosition", Builtin::kCallSitePrototypeGetPosition},
      {"getPromiseIndex", Builtin::kCallSitePrototypeGetPromiseIndex},
      {"getScriptNameOrSourceURL",
       Builtin::kCallSitePrototypeGetScriptNameOrSourceURL},
      {"getScriptHash", Builtin::kCallSitePrototypeGetScriptHash},
      {"getThis", Builtin::kCallSitePrototypeGetThis},
      {"getTypeName", Builtin::kCallSitePrototypeGetTypeName},
      {"isAsync", Builtin::kCallSitePrototypeIsAsync},
      {"isConstructor", Builtin::kCallSitePrototypeIsConstructor},
      {"isEval", Builtin::kCallSitePrototypeIsEval},
      {"isNative", Builtin::kCallSitePrototypeIsNative},
      {"isPromiseAll", Builtin::kCallSitePrototypeIsPromiseAll},
      {"isToplevel", Builtin::kCallSitePrototypeIsToplevel},
      {"toString", Builtin::kCallSitePrototypeToString}};

  PropertyAttributes attrs =
      static_cast<PropertyAttributes>(DONT_ENUM | DONT_DELETE | READ_ONLY);

  for (const FunctionInfo& info : infos) {
    SimpleInstallFunction(isolate(), prototype, info.name, info.id, 0, kAdapt,
                          attrs);
  }
}

void Genesis::InitializeConsole(Handle<JSObject> extras_binding) {
  HandleScope scope(isolate());
  Factory* factory = isolate_->factory();

  // -- C o n s o l e
  Handle<String> name = factory->console_string();

  Handle<NativeContext> context(isolate_->native_context());
  Handle<JSGlobalObject> global(context->global_object(), isolate());
  Handle<SharedFunctionInfo> info = factory->NewSharedFunctionInfoForBuiltin(
      name, Builtin::kIllegal, 0, kDontAdapt);
  info->set_language_mode(LanguageMode::kStrict);

  Handle<JSFunction> cons =
      Factory::JSFunctionBuilder{isolate(), info, context}.Build();
  Handle<JSObject> empty = factory->NewJSObject(isolate_->object_function());
  JSFunction::SetPrototype(cons, empty);

  Handle<JSObject> console = factory->NewJSObject(cons, AllocationType::kOld);
  DCHECK(IsJSObject(*console));

  JSObject::AddProperty(isolate_, extras_binding, name, console, DONT_ENUM);
  // TODO(v8:11989): remove this in the next release
  JSObject::AddProperty(isolate_, global, name, console, DONT_ENUM);

  SimpleInstallFunction(isolate_, console, "debug", Builtin::kConsoleDebug, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "error", Builtin::kConsoleError, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "info", Builtin::kConsoleInfo, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "log", Builtin::kConsoleLog, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "warn", Builtin::kConsoleWarn, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "dir", Builtin::kConsoleDir, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "dirxml", Builtin::kConsoleDirXml, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "table", Builtin::kConsoleTable, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "trace", Builtin::kConsoleTrace, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "group", Builtin::kConsoleGroup, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "groupCollapsed",
                        Builtin::kConsoleGroupCollapsed, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "groupEnd",
                        Builtin::kConsoleGroupEnd, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "clear", Builtin::kConsoleClear, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "count", Builtin::kConsoleCount, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "countReset",
                        Builtin::kConsoleCountReset, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "assert",
                        Builtin::kFastConsoleAssert, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "profile", Builtin::kConsoleProfile,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "profileEnd",
                        Builtin::kConsoleProfileEnd, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "time", Builtin::kConsoleTime, 0,
                        kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeLog", Builtin::kConsoleTimeLog,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeEnd", Builtin::kConsoleTimeEnd,
                        0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "timeStamp",
                        Builtin::kConsoleTimeStamp, 0, kDontAdapt, NONE);
  SimpleInstallFunction(isolate_, console, "context", Builtin::kConsoleContext,
                        1, kDontAdapt, NONE);
  InstallToStringTag(isolate_, console, "console");
}

#define EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(id) \
  void Genesis::InitializeGlobal_##id() {}

EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_import_attributes)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_regexp_modifiers)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_regexp_duplicate_named_groups)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(js_decorators)

#ifdef V8_INTL_SUPPORT
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_intl_best_fit_matcher)
EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE(harmony_remove_intl_locale_info_getters)
#endif  // V8_INTL_SUPPORT

#undef EMPTY_INITIALIZE_GLOBAL_FOR_FEATURE

void Genesis::InitializeGlobal_harmony_iterator_helpers() {
  if (!v8_flags.harmony_iterator_helpers) return;

  // --- Iterator
  Handle<JSGlobalObject> global(native_context()->global_object(), isolate());
  Handle<JSObject> iterator_prototype(
      native_context()->initial_iterator_prototype(), isolate());
  Handle<JSFunction> iterator_function = InstallFunction(
      isolate(), global, "Iterator", JS_OBJECT_TYPE, JSObject::kHeaderSize, 0,
      iterator_prototype, Builtin::kIteratorConstructor, 0, kAdapt);
  SimpleInstallFunction(isolate(), iterator_function, "from",
                        Builtin::kIteratorFrom, 1, kAdapt);
  InstallWithIntrinsicDefaultProto(isolate(), iterator_function,
                                   Context::ITERATOR_FUNCTION_INDEX);

  // --- %WrapForValidIteratorPrototype%
  Handle<JSObject> wrap_for_valid_iterator_prototype = factory()->NewJSObject(
      isolate()->object_function(), AllocationType::kOld);
  JSObject::ForceSetPrototype(isolate(), wrap_for_valid_iterator_prototype,
                              iterator_prototype);
  JSObject::AddProperty(isolate(), iterator_prototype,
                        factory()->constructor_string(), iterator_function,
                        DONT_ENUM);
  SimpleInstallFunction(isolate(), wrap_for_valid_iterator_prototype, "next",
                        Builtin::kWrapForValidIteratorPrototypeNext, 0, kAdapt);
  SimpleInstallFunction(isolate(), wrap_for_valid_iterator_prototype, "return",
                        Builtin::kWrapForValidIteratorPrototypeReturn, 0,
                        kAdapt);
  DirectHandle<Map> valid_iterator_wrapper_map =
      factory()->NewContextfulMapForCurrentContext(
          JS_VALID_ITERATOR_WRAPPER_TYPE, JSValidIteratorWrapper::kHeaderSize,
          TERMINAL_FAST_ELEMENTS_KIND, 0);
  Map::SetPrototype(isolate(), valid_iterator_wrapper_map,
              
"""


```
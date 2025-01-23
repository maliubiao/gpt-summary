Response: The user wants to understand the functionality of the C++ code in `v8/src/api/api.cc`, specifically the part provided in the snippet. They also want to see how it relates to JavaScript, with examples if possible. This is part 6 of 8, suggesting a focus on a particular set of functionalities within the file.

Based on the provided code, it seems to focus on the implementation of the V8 JavaScript API related to:

1. **Arrays (`v8::Array`)**: Creating, getting length, iterating.
2. **Maps (`v8::Map`)**: Creating, getting size, clearing, getting/setting/has/deleting entries, converting to array.
3. **Sets (`v8::Set`)**: Creating, getting size, clearing, adding/has/deleting entries, converting to array.
4. **Promises (`v8::Promise`, `v8::Promise::Resolver`)**: Creating resolvers, getting the promise, resolving/rejecting, then/catch handlers, checking handler presence, getting the result, checking state, marking as handled/silent.
5. **Proxies (`v8::Proxy`)**: Getting target/handler, checking revocation, revoking, creating new proxies.
6. **WebAssembly (`v8::WasmMemoryObject`, `v8::WasmModuleObject`, `v8::CompiledWasmModule`)**:  Working with compiled modules, getting wire bytes, creating module objects from compiled modules, compiling WebAssembly code.
7. **ArrayBuffers and Typed Arrays (`v8::ArrayBuffer`, `v8::TypedArray`, `v8::DataView`, `v8::SharedArrayBuffer`)**: Creating, detaching, getting/setting detach keys, getting byte length, creating backing stores (resizable and non-resizable), copying contents, getting contents, checking for a buffer, getting byte offset, and specific typed array constructors (`Int8Array`, `Uint8Array`, etc.).
8. **Symbols and Privates (`v8::Symbol`, `v8::Private`)**: Creating global and local symbols, well-known symbols, creating private symbols.
9. **Numbers and BigInts (`v8::Number`, `v8::Integer`, `v8::BigInt`)**: Creating new number and bigint objects.
10. **Isolate (`v8::Isolate`)**: Handling external memory interrupts, getting the heap profiler, setting idle state, getting the array buffer allocator, checking if in context, clearing kept objects, getting current/entered/incumbent context, getting host-defined options, throwing errors/exceptions, checking for pending exceptions, adding/removing GC callbacks, setting embedder roots handler, attaching C++ heap.
11. **TypecheckWitness (`v8::TypecheckWitness`)**: Updating the cached map.

The user specifically asked for relationships with JavaScript. Many of these C++ classes directly correspond to JavaScript built-in objects and functionalities.

**Plan:**

1. Summarize the functionalities of the provided code snippet, focusing on the V8 API exposed.
2. For each major category (Array, Map, Set, Promise, etc.), provide a corresponding JavaScript example illustrating the usage of the related functionality.
这个C++源代码文件（`v8/src/api/api.cc` 的第6部分）主要实现了 **V8 JavaScript 引擎提供给外部（例如 Node.js 或 Chromium）调用的 C++ API 的一部分**。  具体来说，这部分代码包含了以下功能的实现：

1. **数组 (Array)**: 提供了创建新的 JavaScript 数组实例的方法，包括指定长度的空数组和使用现有元素创建数组。还提供了获取数组长度以及迭代数组元素的方法。
2. **映射 (Map)**: 提供了创建新的 JavaScript Map 实例、获取大小、清空、设置/获取/检查/删除键值对以及将 Map 转换为数组的方法。
3. **集合 (Set)**: 提供了创建新的 JavaScript Set 实例、获取大小、清空、添加/检查/删除元素以及将 Set 转换为数组的方法。
4. **Promise**: 提供了创建 Promise 和 Promise 解析器 (Resolver) 的方法，以及 Promise 的 `then` 和 `catch` 方法，用于处理 Promise 的 resolve 和 reject 状态。还提供了检查 Promise 是否有处理器、获取 Promise 的结果和状态的方法。
5. **Proxy**: 提供了获取 Proxy 对象的 target 和 handler、检查 Proxy 是否被撤销以及撤销 Proxy 的方法，以及创建新 Proxy 的方法。
6. **WebAssembly 模块 (WasmModuleObject)** 和 **WebAssembly 内存 (WasmMemoryObject)**: 提供了创建和操作 WebAssembly 模块和内存的方法，包括序列化模块、获取 WebAssembly 字节码、从编译后的模块创建实例以及编译 WebAssembly 代码。
7. **ArrayBuffer 和 TypedArray**: 提供了创建和操作 ArrayBuffer（原始二进制数据缓冲区）以及各种类型的 TypedArray（例如 Int8Array、Uint32Array 等）的方法。包括创建新的 ArrayBuffer、设置/获取 ArrayBuffer 的数据、获取 ArrayBuffer 的长度、创建可调整大小的 ArrayBuffer、分离 ArrayBuffer 以及创建 DataView。
8. **SharedArrayBuffer**: 提供了创建和操作 SharedArrayBuffer（可在多个 JavaScript 上下文中共享的二进制数据缓冲区）的方法。
9. **Symbol 和 Private**: 提供了创建全局 Symbol 和本地 Symbol、以及 Private Symbol 的方法。
10. **Number 和 BigInt**: 提供了创建 JavaScript Number 和 BigInt 类型实例的方法。
11. **Isolate**: 提供了一些关于 V8 Isolate（一个独立的 JavaScript 虚拟机实例）的操作，例如处理外部内存中断、获取堆分析器、设置空闲状态、获取 ArrayBuffer 分配器、检查当前是否在上下文中、清除保留对象、获取当前/已进入/常驻上下文、抛出错误/异常、检查是否有待处理的异常、添加/移除垃圾回收回调、设置嵌入器根处理程序等。
12. **TypecheckWitness**: 提供了一个用于类型检查优化的机制，可以更新缓存的 Map 信息。

**与 JavaScript 的关系和示例**

这个 C++ 文件中的代码是 V8 引擎内部实现的一部分，它直接支持了 JavaScript 中许多内置对象和功能的行为。 你可以通过 V8 提供的 C++ API 来创建和操作这些 JavaScript 对象。

以下是一些 JavaScript 示例，展示了这些 C++ 代码所支持的 JavaScript 功能：

**1. 数组 (Array)**

```javascript
// 对应 v8::Array::New
const arr1 = new Array(5); // 创建一个长度为 5 的空数组
const arr2 = [1, 2, 3];   // 使用现有元素创建数组

// 对应 v8::Array::Length()
console.log(arr2.length); // 输出 3

// 对应 v8::Array::Iterate
arr2.forEach((element, index) => {
  console.log(`Index: ${index}, Element: ${element}`);
});
```

**2. 映射 (Map)**

```javascript
// 对应 v8::Map::New
const map = new Map();

// 对应 v8::Map::Set
map.set('a', 1);
map.set('b', 2);

// 对应 v8::Map::Get
console.log(map.get('a')); // 输出 1

// 对应 v8::Map::Has
console.log(map.has('b')); // 输出 true

// 对应 v8::Map::Delete
map.delete('a');

// 对应 v8::Map::Clear
// map.clear();

// 对应 v8::Map::AsArray
console.log([...map]); // 将 Map 转换为数组 (输出类似: [['b', 2]])
```

**3. 集合 (Set)**

```javascript
// 对应 v8::Set::New
const set = new Set();

// 对应 v8::Set::Add
set.add(1);
set.add(2);
set.add(2); // 重复添加无效

// 对应 v8::Set::Has
console.log(set.has(1)); // 输出 true

// 对应 v8::Set::Delete
set.delete(2);

// 对应 v8::Set::Clear
// set.clear();

// 对应 v8::Set::AsArray
console.log([...set]); // 将 Set 转换为数组 (输出类似: [1])
```

**4. Promise**

```javascript
// 对应 v8::Promise::Resolver::New 和 v8::Promise::Resolver::GetPromise
const promise = new Promise((resolve, reject) => {
  setTimeout(() => {
    // 对应 v8::Promise::Resolver::Resolve
    resolve('成功了!');
  }, 1000);
});

// 对应 v8::Promise::Then
promise.then(value => {
  console.log(value); // 输出 '成功了!'
});

// 对应 v8::Promise::Catch
const rejectedPromise = Promise.reject('失败了!');
rejectedPromise.catch(error => {
  console.error(error); // 输出 '失败了!'
});
```

**5. Proxy**

```javascript
// 对应 v8::Proxy::New
const target = {};
const handler = {
  get: function(obj, prop) {
    return `访问了属性: ${prop}`;
  }
};
const proxy = new Proxy(target, handler);

console.log(proxy.someProperty); // 输出 "访问了属性: someProperty"
```

**6. ArrayBuffer 和 TypedArray**

```javascript
// 对应 v8::ArrayBuffer::New
const buffer = new ArrayBuffer(16); // 创建一个 16 字节的 ArrayBuffer

// 对应 v8::Int32Array::New
const view = new Int32Array(buffer); // 创建一个指向 ArrayBuffer 的 Int32Array 视图

view[0] = 42;
console.log(view[0]); // 输出 42
```

**7. Symbol**

```javascript
// 对应 v8::Symbol::New
const mySymbol = Symbol('mySymbol');
console.log(mySymbol);

// 对应 v8::Symbol::For
const globalSymbol = Symbol.for('globalSymbol');
const anotherGlobalSymbol = Symbol.for('globalSymbol');
console.log(globalSymbol === anotherGlobalSymbol); // 输出 true
```

**8. BigInt**

```javascript
// 对应 v8::BigInt::New
const largeNumber = 9007199254740991n;
console.log(largeNumber);
```

总而言之，`v8/src/api/api.cc` 的这一部分是 V8 引擎的核心组成部分，它提供了将 JavaScript 的高级概念映射到底层 C++ 实现的关键接口，使得外部程序可以通过 C++ API 与 V8 引擎进行交互，并创建和操作 JavaScript 对象。

### 提示词
```
这是目录为v8/src/api/api.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```
ray> v8::Array::New(Isolate* v8_isolate, int length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  int real_length = length > 0 ? length : 0;
  i::Handle<i::JSArray> obj = i_isolate->factory()->NewJSArray(real_length);
  i::DirectHandle<i::Number> length_obj =
      i_isolate->factory()->NewNumberFromInt(real_length);
  obj->set_length(*length_obj);
  return Utils::ToLocal(obj);
}

Local<v8::Array> v8::Array::New(Isolate* v8_isolate, Local<Value>* elements,
                                size_t length) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Factory* factory = i_isolate->factory();
  API_RCS_SCOPE(i_isolate, Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  int len = static_cast<int>(length);

  i::DirectHandle<i::FixedArray> result = factory->NewFixedArray(len);
  for (int i = 0; i < len; i++) {
    auto element = Utils::OpenDirectHandle(*elements[i]);
    result->set(i, *element);
  }

  return Utils::ToLocal(
      factory->NewJSArrayWithElements(result, i::PACKED_ELEMENTS, len));
}

// static
MaybeLocal<v8::Array> v8::Array::New(
    Local<Context> context, size_t length,
    std::function<MaybeLocal<v8::Value>()> next_value_callback) {
  PREPARE_FOR_EXECUTION(context, Array, New);
  // We should never see an exception here as V8 will not create an
  // exception and the callback is invoked by the embedder where the exception
  // is already scheduled.
  USE(has_exception);
  i::Factory* factory = i_isolate->factory();
  const int len = static_cast<int>(length);
  i::DirectHandle<i::FixedArray> backing = factory->NewFixedArray(len);
  v8::Local<v8::Value> value;
  for (int i = 0; i < len; i++) {
    MaybeLocal<v8::Value> maybe_value = next_value_callback();
    // The embedder may signal to abort creation on exception via an empty
    // local.
    if (!maybe_value.ToLocal(&value)) {
      CHECK(i_isolate->has_exception());
      return {};
    }
    backing->set(i, *Utils::OpenDirectHandle(*value));
  }
  RETURN_ESCAPED(Utils::ToLocal(
      factory->NewJSArrayWithElements(backing, i::PACKED_ELEMENTS, len)));
}

namespace internal {

uint32_t GetLength(Tagged<JSArray> array) {
  Tagged<Number> length = array->length();
  if (IsSmi(length)) return Smi::ToInt(length);
  return static_cast<uint32_t>(Object::NumberValue(length));
}

}  // namespace internal

uint32_t v8::Array::Length() const {
  return i::GetLength(*Utils::OpenDirectHandle(this));
}

namespace internal {

bool CanUseFastIteration(Isolate* isolate, DirectHandle<JSArray> array) {
  if (IsCustomElementsReceiverMap(array->map())) return false;
  if (array->GetElementsAccessor()->HasAccessors(*array)) return false;
  if (!JSObject::PrototypeHasNoElements(isolate, *array)) return false;
  return true;
}

enum class FastIterateResult {
  kException = static_cast<int>(v8::Array::CallbackResult::kException),
  kBreak = static_cast<int>(v8::Array::CallbackResult::kBreak),
  kSlowPath,
  kFinished,
};

FastIterateResult FastIterateArray(DirectHandle<JSArray> array,
                                   Isolate* isolate,
                                   v8::Array::IterationCallback callback,
                                   void* callback_data) {
  // Instead of relying on callers to check condition, this function returns
  // {kSlowPath} for situations it can't handle.
  // Most code paths below don't allocate, and rely on {callback} not allocating
  // either, but this isn't enforced with {DisallowHeapAllocation} to allow
  // embedders to allocate error objects before terminating the iteration.
  // Since {callback} must not allocate anyway, we can get away with fake
  // handles, reducing per-element overhead.
  if (!CanUseFastIteration(isolate, array)) return FastIterateResult::kSlowPath;
  using Result = v8::Array::CallbackResult;
  DisallowJavascriptExecution no_js(isolate);
  uint32_t length = GetLength(*array);
  if (length == 0) return FastIterateResult::kFinished;
  switch (array->GetElementsKind()) {
    case PACKED_SMI_ELEMENTS:
    case PACKED_ELEMENTS:
    case PACKED_FROZEN_ELEMENTS:
    case PACKED_SEALED_ELEMENTS:
    case PACKED_NONEXTENSIBLE_ELEMENTS: {
      Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        Tagged<Object> element = elements->get(static_cast<int>(i));
        // TODO(13270): When we switch to CSS, we can pass {element} to
        // the callback directly, without {fake_handle}.
        Handle<Object> fake_handle(reinterpret_cast<Address*>(&element));
        Result result = callback(i, Utils::ToLocal(fake_handle), callback_data);
        if (result != Result::kContinue) {
          return static_cast<FastIterateResult>(result);
        }
        DCHECK(CanUseFastIteration(isolate, array));
      }
      return FastIterateResult::kFinished;
    }
    case HOLEY_SMI_ELEMENTS:
    case HOLEY_FROZEN_ELEMENTS:
    case HOLEY_SEALED_ELEMENTS:
    case HOLEY_NONEXTENSIBLE_ELEMENTS:
    case HOLEY_ELEMENTS: {
      Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
      for (uint32_t i = 0; i < length; i++) {
        Tagged<Object> element = elements->get(static_cast<int>(i));
        // TODO(13270): When we switch to CSS, we can pass {element} to
        // the callback directly, without {fake_handle}.
        auto fake_handle =
            IsTheHole(element)
                ? isolate->factory()->undefined_value()
                : Handle<Object>(reinterpret_cast<Address*>(&element));
        Result result = callback(i, Utils::ToLocal(fake_handle), callback_data);
        if (result != Result::kContinue) {
          return static_cast<FastIterateResult>(result);
        }
        DCHECK(CanUseFastIteration(isolate, array));
      }
      return FastIterateResult::kFinished;
    }
    case HOLEY_DOUBLE_ELEMENTS:
    case PACKED_DOUBLE_ELEMENTS: {
      DCHECK_NE(length, 0);  // Cast to FixedDoubleArray would be invalid.
      DirectHandle<FixedDoubleArray> elements(
          Cast<FixedDoubleArray>(array->elements()), isolate);
      FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
        Handle<Object> value =
            elements->is_the_hole(i)
                ? Handle<Object>(isolate->factory()->undefined_value())
                : isolate->factory()->NewNumber(elements->get_scalar(i));
        Result result = callback(i, Utils::ToLocal(value), callback_data);
        if (result != Result::kContinue) {
          return static_cast<FastIterateResult>(result);
        }
        DCHECK(CanUseFastIteration(isolate, array));
      });
      return FastIterateResult::kFinished;
    }
    case DICTIONARY_ELEMENTS: {
      DisallowGarbageCollection no_gc;
      Tagged<NumberDictionary> dict = array->element_dictionary();
      struct Entry {
        uint32_t index;
        InternalIndex entry;
      };
      std::vector<Entry> sorted;
      sorted.reserve(dict->NumberOfElements());
      ReadOnlyRoots roots(isolate);
      for (InternalIndex i : dict->IterateEntries()) {
        Tagged<Object> key = dict->KeyAt(isolate, i);
        if (!dict->IsKey(roots, key)) continue;
        uint32_t index =
            static_cast<uint32_t>(Object::NumberValue(Cast<Number>(key)));
        sorted.push_back({index, i});
      }
      std::sort(
          sorted.begin(), sorted.end(),
          [](const Entry& a, const Entry& b) { return a.index < b.index; });
      for (const Entry& entry : sorted) {
        Tagged<Object> value = dict->ValueAt(entry.entry);
        // TODO(13270): When we switch to CSS, we can pass {element} to
        // the callback directly, without {fake_handle}.
        Handle<Object> fake_handle(reinterpret_cast<Address*>(&value));
        Result result =
            callback(entry.index, Utils::ToLocal(fake_handle), callback_data);
        if (result != Result::kContinue) {
          return static_cast<FastIterateResult>(result);
        }
        SLOW_DCHECK(CanUseFastIteration(isolate, array));
      }
      return FastIterateResult::kFinished;
    }
    case NO_ELEMENTS:
      return FastIterateResult::kFinished;
    case FAST_SLOPPY_ARGUMENTS_ELEMENTS:
    case SLOW_SLOPPY_ARGUMENTS_ELEMENTS:
      // Probably not worth implementing. Take the slow path.
      return FastIterateResult::kSlowPath;
    case WASM_ARRAY_ELEMENTS:
    case FAST_STRING_WRAPPER_ELEMENTS:
    case SLOW_STRING_WRAPPER_ELEMENTS:
    case SHARED_ARRAY_ELEMENTS:
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) case TYPE##_ELEMENTS:
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
      // These are never used by v8::Array instances.
      UNREACHABLE();
  }
}

}  // namespace internal

Maybe<void> v8::Array::Iterate(Local<Context> context,
                               v8::Array::IterationCallback callback,
                               void* callback_data) {
  auto array = Utils::OpenHandle(this);
  i::Isolate* isolate = array->GetIsolate();
  i::FastIterateResult fast_result =
      i::FastIterateArray(array, isolate, callback, callback_data);
  if (fast_result == i::FastIterateResult::kException) return Nothing<void>();
  // Early breaks and completed iteration both return successfully.
  if (fast_result != i::FastIterateResult::kSlowPath) return JustVoid();

  // Slow path: retrieving elements could have side effects.
  ENTER_V8(isolate, context, Array, Iterate, i::HandleScope);
  for (uint32_t i = 0; i < i::GetLength(*array); ++i) {
    i::Handle<i::Object> element;
    has_exception =
        !i::JSReceiver::GetElement(isolate, array, i).ToHandle(&element);
    RETURN_ON_FAILED_EXECUTION_PRIMITIVE(void);
    using Result = v8::Array::CallbackResult;
    Result result = callback(i, Utils::ToLocal(element), callback_data);
    if (result == Result::kException) return Nothing<void>();
    if (result == Result::kBreak) return JustVoid();
  }
  return JustVoid();
}

v8::TypecheckWitness::TypecheckWitness(Isolate* isolate)
#ifdef V8_ENABLE_DIRECT_HANDLE
    // An empty local suffices.
    : cached_map_()
#else
    // We need to reserve a handle that we can patch later.
    // We initialize it with something that cannot compare equal to any map.
    : cached_map_(v8::Number::New(isolate, 1))
#endif
{
}

void v8::TypecheckWitness::Update(Local<Value> baseline) {
  i::Tagged<i::Object> obj = *Utils::OpenDirectHandle(*baseline);
#ifdef V8_ENABLE_DIRECT_HANDLE
  if (IsSmi(obj)) {
    cached_map_ = Local<Data>();
  } else {
    i::Tagged<i::HeapObject> map = i::Cast<i::HeapObject>(obj)->map();
    cached_map_ = Local<Data>::FromAddress(map->ptr());
  }
#else
  i::Tagged<i::Object> map = i::Smi::zero();
  if (!IsSmi(obj)) map = i::Cast<i::HeapObject>(obj)->map();
  // Design overview: in the {TypecheckWitness} constructor, we create
  // a single handle for the witness value. Whenever {Update} is called, we
  // make this handle point at the fresh baseline/witness; the intention is
  // to allow having short-lived HandleScopes (e.g. in {FastIterateArray}
  // above) while a {TypecheckWitness} is alive: it therefore cannot hold
  // on to one of the short-lived handles.
  // Calling {OpenIndirectHandle} on the {cached_map_} only serves to
  // "reinterpret_cast" it to an {i::IndirectHandle} on which we can call
  // {PatchValue}.
  auto cache = Utils::OpenIndirectHandle(*cached_map_);
  cache.PatchValue(map);
#endif
}

Local<v8::Map> v8::Map::New(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Map, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSMap> obj = i_isolate->factory()->NewJSMap();
  return Utils::ToLocal(obj);
}

size_t v8::Map::Size() const {
  auto obj = Utils::OpenDirectHandle(this);
  return i::Cast<i::OrderedHashMap>(obj->table())->NumberOfElements();
}

void Map::Clear() {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  API_RCS_SCOPE(i_isolate, Map, Clear);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::JSMap::Clear(i_isolate, self);
}

MaybeLocal<Value> Map::Get(Local<Context> context, Local<Value> key) {
  PREPARE_FOR_EXECUTION(context, Map, Get);
  auto self = Utils::OpenHandle(this);
  Local<Value> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception =
      !ToLocal<Value>(i::Execution::CallBuiltin(i_isolate, i_isolate->map_get(),
                                                self, arraysize(argv), argv),
                      &result);
  RETURN_ON_FAILED_EXECUTION(Value);
  RETURN_ESCAPED(result);
}

MaybeLocal<Map> Map::Set(Local<Context> context, Local<Value> key,
                         Local<Value> value) {
  PREPARE_FOR_EXECUTION(context, Map, Set);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key),
                                 Utils::OpenHandle(*value)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->map_set(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Map);
  RETURN_ESCAPED(Local<Map>::Cast(Utils::ToLocal(result)));
}

Maybe<bool> Map::Has(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Map, Has, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->map_has(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

Maybe<bool> Map::Delete(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Map, Delete, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->map_delete(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

namespace {

enum class MapAsArrayKind {
  kEntries = i::JS_MAP_KEY_VALUE_ITERATOR_TYPE,
  kKeys = i::JS_MAP_KEY_ITERATOR_TYPE,
  kValues = i::JS_MAP_VALUE_ITERATOR_TYPE
};

enum class SetAsArrayKind {
  kEntries = i::JS_SET_KEY_VALUE_ITERATOR_TYPE,
  kValues = i::JS_SET_VALUE_ITERATOR_TYPE
};

i::Handle<i::JSArray> MapAsArray(i::Isolate* i_isolate,
                                 i::Tagged<i::Object> table_obj, int offset,
                                 MapAsArrayKind kind) {
  i::Factory* factory = i_isolate->factory();
  i::DirectHandle<i::OrderedHashMap> table(
      i::Cast<i::OrderedHashMap>(table_obj), i_isolate);
  const bool collect_keys =
      kind == MapAsArrayKind::kEntries || kind == MapAsArrayKind::kKeys;
  const bool collect_values =
      kind == MapAsArrayKind::kEntries || kind == MapAsArrayKind::kValues;
  int capacity = table->UsedCapacity();
  int max_length =
      (capacity - offset) * ((collect_keys && collect_values) ? 2 : 1);
  i::DirectHandle<i::FixedArray> result = factory->NewFixedArray(max_length);
  int result_index = 0;
  {
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::Hole> hash_table_hole =
        i::ReadOnlyRoots(i_isolate).hash_table_hole_value();
    for (int i = offset; i < capacity; ++i) {
      i::InternalIndex entry(i);
      i::Tagged<i::Object> key = table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      if (collect_keys) result->set(result_index++, key);
      if (collect_values) result->set(result_index++, table->ValueAt(entry));
    }
  }
  DCHECK_GE(max_length, result_index);
  if (result_index == 0) return factory->NewJSArray(0);
  result->RightTrim(i_isolate, result_index);
  return factory->NewJSArrayWithElements(result, i::PACKED_ELEMENTS,
                                         result_index);
}

}  // namespace

Local<Array> Map::AsArray() const {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  API_RCS_SCOPE(i_isolate, Map, AsArray);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return Utils::ToLocal(
      MapAsArray(i_isolate, obj->table(), 0, MapAsArrayKind::kEntries));
}

Local<v8::Set> v8::Set::New(Isolate* v8_isolate) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Set, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::JSSet> obj = i_isolate->factory()->NewJSSet();
  return Utils::ToLocal(obj);
}

size_t v8::Set::Size() const {
  auto obj = Utils::OpenDirectHandle(this);
  return i::Cast<i::OrderedHashSet>(obj->table())->NumberOfElements();
}

void Set::Clear() {
  auto self = Utils::OpenHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  API_RCS_SCOPE(i_isolate, Set, Clear);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::JSSet::Clear(i_isolate, self);
}

MaybeLocal<Set> Set::Add(Local<Context> context, Local<Value> key) {
  PREPARE_FOR_EXECUTION(context, Set, Add);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->set_add(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Set);
  RETURN_ESCAPED(Local<Set>::Cast(Utils::ToLocal(result)));
}

Maybe<bool> Set::Has(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Set, Has, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->set_has(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

Maybe<bool> Set::Delete(Local<Context> context, Local<Value> key) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Set, Delete, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> result;
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*key)};
  has_exception = !i::Execution::CallBuiltin(i_isolate, i_isolate->set_delete(),
                                             self, arraysize(argv), argv)
                       .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(i::IsTrue(*result, i_isolate));
}

namespace {
i::Handle<i::JSArray> SetAsArray(i::Isolate* i_isolate,
                                 i::Tagged<i::Object> table_obj, int offset,
                                 SetAsArrayKind kind) {
  i::Factory* factory = i_isolate->factory();
  i::DirectHandle<i::OrderedHashSet> table(
      i::Cast<i::OrderedHashSet>(table_obj), i_isolate);
  // Elements skipped by |offset| may already be deleted.
  int capacity = table->UsedCapacity();
  const bool collect_key_values = kind == SetAsArrayKind::kEntries;
  int max_length = (capacity - offset) * (collect_key_values ? 2 : 1);
  if (max_length == 0) return factory->NewJSArray(0);
  i::DirectHandle<i::FixedArray> result = factory->NewFixedArray(max_length);
  int result_index = 0;
  {
    i::DisallowGarbageCollection no_gc;
    i::Tagged<i::Hole> hash_table_hole =
        i::ReadOnlyRoots(i_isolate).hash_table_hole_value();
    for (int i = offset; i < capacity; ++i) {
      i::InternalIndex entry(i);
      i::Tagged<i::Object> key = table->KeyAt(entry);
      if (key == hash_table_hole) continue;
      result->set(result_index++, key);
      if (collect_key_values) result->set(result_index++, key);
    }
  }
  DCHECK_GE(max_length, result_index);
  if (result_index == 0) return factory->NewJSArray(0);
  result->RightTrim(i_isolate, result_index);
  return factory->NewJSArrayWithElements(result, i::PACKED_ELEMENTS,
                                         result_index);
}
}  // namespace

Local<Array> Set::AsArray() const {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  API_RCS_SCOPE(i_isolate, Set, AsArray);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  return Utils::ToLocal(
      SetAsArray(i_isolate, obj->table(), 0, SetAsArrayKind::kValues));
}

MaybeLocal<Promise::Resolver> Promise::Resolver::New(Local<Context> context) {
  PREPARE_FOR_EXECUTION(context, Promise_Resolver, New);
  Local<Promise::Resolver> result;
  has_exception = !ToLocal<Promise::Resolver>(
      i_isolate->factory()->NewJSPromise(), &result);
  RETURN_ON_FAILED_EXECUTION(Promise::Resolver);
  RETURN_ESCAPED(result);
}

Local<Promise> Promise::Resolver::GetPromise() {
  auto promise = Utils::OpenDirectHandle(this);
  return Local<Promise>::Cast(Utils::ToLocal(promise));
}

Maybe<bool> Promise::Resolver::Resolve(Local<Context> context,
                                       Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Promise_Resolver, Resolve, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto promise = i::Cast<i::JSPromise>(self);

  if (promise->status() != Promise::kPending) {
    return Just(true);
  }

  has_exception =
      i::JSPromise::Resolve(promise, Utils::OpenHandle(*value)).is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

Maybe<bool> Promise::Resolver::Reject(Local<Context> context,
                                      Local<Value> value) {
  auto i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8(i_isolate, context, Promise_Resolver, Reject, i::HandleScope);
  auto self = Utils::OpenHandle(this);
  auto promise = i::Cast<i::JSPromise>(self);

  if (promise->status() != Promise::kPending) {
    return Just(true);
  }

  has_exception =
      i::JSPromise::Reject(promise, Utils::OpenHandle(*value)).is_null();
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

MaybeLocal<Promise> Promise::Catch(Local<Context> context,
                                   Local<Function> handler) {
  PREPARE_FOR_EXECUTION(context, Promise, Catch);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> argv[] = {i_isolate->factory()->undefined_value(),
                                 Utils::OpenHandle(*handler)};
  i::Handle<i::Object> result;
  // Do not call the built-in Promise.prototype.catch!
  // v8::Promise should not call out to a monkeypatched Promise.prototype.then
  // as the implementation of Promise.prototype.catch does.
  has_exception =
      !i::Execution::CallBuiltin(i_isolate, i_isolate->promise_then(), self,
                                 arraysize(argv), argv)
           .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Promise);
  RETURN_ESCAPED(Local<Promise>::Cast(Utils::ToLocal(result)));
}

MaybeLocal<Promise> Promise::Then(Local<Context> context,
                                  Local<Function> handler) {
  PREPARE_FOR_EXECUTION(context, Promise, Then);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*handler)};
  i::Handle<i::Object> result;
  has_exception =
      !i::Execution::CallBuiltin(i_isolate, i_isolate->promise_then(), self,
                                 arraysize(argv), argv)
           .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Promise);
  RETURN_ESCAPED(Local<Promise>::Cast(Utils::ToLocal(result)));
}

MaybeLocal<Promise> Promise::Then(Local<Context> context,
                                  Local<Function> on_fulfilled,
                                  Local<Function> on_rejected) {
  PREPARE_FOR_EXECUTION(context, Promise, Then);
  auto self = Utils::OpenHandle(this);
  i::Handle<i::Object> argv[] = {Utils::OpenHandle(*on_fulfilled),
                                 Utils::OpenHandle(*on_rejected)};
  i::Handle<i::Object> result;
  has_exception =
      !i::Execution::CallBuiltin(i_isolate, i_isolate->promise_then(), self,
                                 arraysize(argv), argv)
           .ToHandle(&result);
  RETURN_ON_FAILED_EXECUTION(Promise);
  RETURN_ESCAPED(Local<Promise>::Cast(Utils::ToLocal(result)));
}

bool Promise::HasHandler() const {
  i::Tagged<i::JSReceiver> promise = *Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = promise->GetIsolate();
  API_RCS_SCOPE(i_isolate, Promise, HasRejectHandler);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!IsJSPromise(promise)) return false;
  return i::Cast<i::JSPromise>(promise)->has_handler();
}

Local<Value> Promise::Result() {
  auto promise = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = promise->GetIsolate();
  API_RCS_SCOPE(i_isolate, Promise, Result);
  auto js_promise = i::Cast<i::JSPromise>(promise);
  Utils::ApiCheck(js_promise->status() != kPending, "v8_Promise_Result",
                  "Promise is still pending");
  return Utils::ToLocal(i::direct_handle(js_promise->result(), i_isolate));
}

Promise::PromiseState Promise::State() {
  auto promise = Utils::OpenDirectHandle(this);
  API_RCS_SCOPE(promise->GetIsolate(), Promise, Status);
  auto js_promise = i::Cast<i::JSPromise>(promise);
  return static_cast<PromiseState>(js_promise->status());
}

void Promise::MarkAsHandled() {
  Utils::OpenDirectHandle(this)->set_has_handler(true);
}

void Promise::MarkAsSilent() {
  Utils::OpenDirectHandle(this)->set_is_silent(true);
}

Local<Value> Proxy::GetTarget() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return Utils::ToLocal(i::direct_handle(self->target(), i_isolate));
}

Local<Value> Proxy::GetHandler() {
  auto self = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = self->GetIsolate();
  return Utils::ToLocal(i::direct_handle(self->handler(), i_isolate));
}

bool Proxy::IsRevoked() const {
  return Utils::OpenDirectHandle(this)->IsRevoked();
}

void Proxy::Revoke() {
  auto self = Utils::OpenHandle(this);
  i::JSProxy::Revoke(self);
}

MaybeLocal<Proxy> Proxy::New(Local<Context> context, Local<Object> local_target,
                             Local<Object> local_handler) {
  PREPARE_FOR_EXECUTION(context, Proxy, New);
  auto target = Utils::OpenHandle(*local_target);
  auto handler = Utils::OpenHandle(*local_handler);
  Local<Proxy> result;
  has_exception =
      !ToLocal<Proxy>(i::JSProxy::New(i_isolate, target, handler), &result);
  RETURN_ON_FAILED_EXECUTION(Proxy);
  RETURN_ESCAPED(result);
}

CompiledWasmModule::CompiledWasmModule(
    std::shared_ptr<internal::wasm::NativeModule> native_module,
    const char* source_url, size_t url_length)
    : native_module_(std::move(native_module)),
      source_url_(source_url, url_length) {
  CHECK_NOT_NULL(native_module_);
}

OwnedBuffer CompiledWasmModule::Serialize() {
#if V8_ENABLE_WEBASSEMBLY
  TRACE_EVENT0("v8.wasm", "wasm.SerializeModule");
  i::wasm::WasmSerializer wasm_serializer(native_module_.get());
  size_t buffer_size = wasm_serializer.GetSerializedNativeModuleSize();
  std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_size]);
  if (!wasm_serializer.SerializeNativeModule({buffer.get(), buffer_size}))
    return {};
  return {std::move(buffer), buffer_size};
#else
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

MemorySpan<const uint8_t> CompiledWasmModule::GetWireBytesRef() {
#if V8_ENABLE_WEBASSEMBLY
  base::Vector<const uint8_t> bytes_vec = native_module_->wire_bytes();
  return {bytes_vec.begin(), bytes_vec.size()};
#else
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

Local<ArrayBuffer> v8::WasmMemoryObject::Buffer() {
#if V8_ENABLE_WEBASSEMBLY
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  return Utils::ToLocal(i::direct_handle(obj->array_buffer(), i_isolate));
#else
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

CompiledWasmModule WasmModuleObject::GetCompiledModule() {
#if V8_ENABLE_WEBASSEMBLY
  auto obj = i::Cast<i::WasmModuleObject>(Utils::OpenDirectHandle(this));
  auto url = i::direct_handle(i::Cast<i::String>(obj->script()->name()),
                              obj->GetIsolate());
  size_t length;
  std::unique_ptr<char[]> cstring = url->ToCString(&length);
  return CompiledWasmModule(std::move(obj->shared_native_module()),
                            cstring.get(), length);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

MaybeLocal<WasmModuleObject> WasmModuleObject::FromCompiledModule(
    Isolate* v8_isolate, const CompiledWasmModule& compiled_module) {
#if V8_ENABLE_WEBASSEMBLY
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  i::Handle<i::WasmModuleObject> module_object =
      i::wasm::GetWasmEngine()->ImportNativeModule(
          i_isolate, compiled_module.native_module_,
          base::VectorOf(compiled_module.source_url()));
  return Utils::ToLocal(module_object);
#else
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

MaybeLocal<WasmModuleObject> WasmModuleObject::Compile(
    Isolate* v8_isolate, MemorySpan<const uint8_t> wire_bytes) {
#if V8_ENABLE_WEBASSEMBLY
  const uint8_t* start = wire_bytes.data();
  size_t length = wire_bytes.size();
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  if (!i::wasm::IsWasmCodegenAllowed(i_isolate, i_isolate->native_context())) {
    return MaybeLocal<WasmModuleObject>();
  }
  i::MaybeHandle<i::WasmModuleObject> maybe_compiled;
  {
    i::wasm::ErrorThrower thrower(i_isolate, "WasmModuleObject::Compile()");
    auto enabled_features =
        i::wasm::WasmEnabledFeatures::FromIsolate(i_isolate);
    // TODO(14179): Provide an API method that supports compile options.
    maybe_compiled = i::wasm::GetWasmEngine()->SyncCompile(
        i_isolate, enabled_features, i::wasm::CompileTimeImports{}, &thrower,
        i::wasm::ModuleWireBytes(start, start + length));
  }
  CHECK_EQ(maybe_compiled.is_null(), i_isolate->has_exception());
  if (maybe_compiled.is_null()) {
    return MaybeLocal<WasmModuleObject>();
  }
  return Utils::ToLocal(maybe_compiled.ToHandleChecked());
#else
  Utils::ApiCheck(false, "WasmModuleObject::Compile",
                  "WebAssembly support is not enabled");
  UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
}

void* v8::ArrayBuffer::Allocator::Reallocate(void* data, size_t old_length,
                                             size_t new_length) {
  if (old_length == new_length) return data;
  uint8_t* new_data =
      reinterpret_cast<uint8_t*>(AllocateUninitialized(new_length));
  if (new_data == nullptr) return nullptr;
  size_t bytes_to_copy = std::min(old_length, new_length);
  memcpy(new_data, data, bytes_to_copy);
  if (new_length > bytes_to_copy) {
    memset(new_data + bytes_to_copy, 0, new_length - bytes_to_copy);
  }
  Free(data, old_length);
  return new_data;
}

// static
v8::ArrayBuffer::Allocator* v8::ArrayBuffer::Allocator::NewDefaultAllocator() {
  return new ArrayBufferAllocator();
}

bool v8::ArrayBuffer::IsDetachable() const {
  return Utils::OpenDirectHandle(this)->is_detachable();
}

bool v8::ArrayBuffer::WasDetached() const {
  return Utils::OpenDirectHandle(this)->was_detached();
}

namespace {
std::shared_ptr<i::BackingStore> ToInternal(
    std::shared_ptr<i::BackingStoreBase> backing_store) {
  return std::static_pointer_cast<i::BackingStore>(backing_store);
}
}  // namespace

Maybe<bool> v8::ArrayBuffer::Detach(v8::Local<v8::Value> key) {
  auto obj = Utils::OpenHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  Utils::ApiCheck(obj->is_detachable(), "v8::ArrayBuffer::Detach",
                  "Only detachable ArrayBuffers can be detached");
  Local<Context> context =
      reinterpret_cast<v8::Isolate*>(i_isolate)->GetCurrentContext();
  // TODO(verwaest): Remove this case after forcing the embedder to enter the
  // context.
  if (context.IsEmpty()) {
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
    if (key.IsEmpty()) {
      i::JSArrayBuffer::Detach(obj).Check();
    } else {
      auto i_key = Utils::OpenHandle(*key);
      constexpr bool kForceForWasmMemory = false;
      i::JSArrayBuffer::Detach(obj, kForceForWasmMemory, i_key).Check();
    }
    return Just(true);
  }
  ENTER_V8_NO_SCRIPT(i_isolate, context, ArrayBuffer, Detach, i::HandleScope);
  if (!key.IsEmpty()) {
    auto i_key = Utils::OpenHandle(*key);
    constexpr bool kForceForWasmMemory = false;
    has_exception =
        i::JSArrayBuffer::Detach(obj, kForceForWasmMemory, i_key).IsNothing();
  } else {
    has_exception = i::JSArrayBuffer::Detach(obj).IsNothing();
  }
  RETURN_ON_FAILED_EXECUTION_PRIMITIVE(bool);
  return Just(true);
}

void v8::ArrayBuffer::Detach() { Detach(Local<Value>()).Check(); }

void v8::ArrayBuffer::SetDetachKey(v8::Local<v8::Value> key) {
  auto obj = Utils::OpenDirectHandle(this);
  auto i_key = Utils::OpenDirectHandle(*key);
  obj->set_detach_key(*i_key);
}

size_t v8::ArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::ArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

namespace {
i::InitializedFlag GetInitializedFlag(
    BackingStoreInitializationMode initialization_mode) {
  switch (initialization_mode) {
    case BackingStoreInitializationMode::kUninitialized:
      return i::InitializedFlag::kUninitialized;
    case BackingStoreInitializationMode::kZeroInitialized:
      return i::InitializedFlag::kZeroInitialized;
  }
  UNREACHABLE();
}
}  // namespace

MaybeLocal<ArrayBuffer> v8::ArrayBuffer::MaybeNew(
    Isolate* isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, MaybeNew);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    return MaybeLocal<ArrayBuffer>();
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::MaybeHandle<i::JSArrayBuffer> result =
      i_isolate->factory()->NewJSArrayBufferAndBackingStore(
          byte_length, GetInitializedFlag(initialization_mode));

  i::Handle<i::JSArrayBuffer> array_buffer;
  if (!result.ToHandle(&array_buffer)) {
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::ArrayBuffer::New");
  }

  return Utils::ToLocal(array_buffer);
}

Local<ArrayBuffer> v8::ArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(
      ToInternal(std::move(backing_store)));
  Utils::ApiCheck(
      !i_backing_store->is_shared(), "v8_ArrayBuffer_New",
      "Cannot construct ArrayBuffer with a BackingStore of SharedArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocal(obj);
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, ArrayBuffer, NewBackingStore);
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length,
                                i::SharedFlag::kNotShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::ArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::ArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
#ifdef V8_ENABLE_SANDBOX
  Utils::ApiCheck(!data || i::GetProcessWideSandbox()->Contains(data),
                  "v8_ArrayBuffer_NewBackingStore",
                  "When the V8 Sandbox is enabled, ArrayBuffer backing stores "
                  "must be allocated inside the sandbox address space. Please "
                  "use an appropriate ArrayBuffer::Allocator to allocate these "
                  "buffers, or disable the sandbox.");
#endif  // V8_ENABLE_SANDBOX

  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kNotShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

// static
std::unique_ptr<BackingStore> v8::ArrayBuffer::NewResizableBackingStore(
    size_t byte_length, size_t max_byte_length) {
  Utils::ApiCheck(byte_length <= max_byte_length,
                  "v8::ArrayBuffer::NewResizableBackingStore",
                  "Cannot construct resizable ArrayBuffer, byte_length must be "
                  "<= max_byte_length");
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::ArrayBuffer::NewResizableBackingStore",
      "Cannot construct resizable ArrayBuffer, requested length is too big");

  size_t page_size, initial_pages, max_pages;
  if (i::JSArrayBuffer::GetResizableBackingStorePageConfiguration(
          nullptr, byte_length, max_byte_length, i::kDontThrow, &page_size,
          &initial_pages, &max_pages)
          .IsNothing()) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::TryAllocateAndPartiallyCommitMemory(
          nullptr, byte_length, max_byte_length, page_size, initial_pages,
          max_pages, i::WasmMemoryFlag::kNotWasm, i::SharedFlag::kNotShared);
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(nullptr,
                                   "v8::ArrayBuffer::NewResizableBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<ArrayBuffer> v8::ArrayBufferView::Buffer() {
  auto obj = Utils::OpenDirectHandle(this);
  i::Isolate* i_isolate = obj->GetIsolate();
  if (i::IsJSDataView(*obj)) {
    i::DirectHandle<i::JSDataView> data_view(i::Cast<i::JSDataView>(*obj),
                                             i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else if (i::IsJSRabGsabDataView(*obj)) {
    i::DirectHandle<i::JSRabGsabDataView> data_view(
        i::Cast<i::JSRabGsabDataView>(*obj), i_isolate);
    DCHECK(IsJSArrayBuffer(data_view->buffer()));
    return Utils::ToLocal(i::direct_handle(
        i::Cast<i::JSArrayBuffer>(data_view->buffer()), i_isolate));
  } else {
    DCHECK(IsJSTypedArray(*obj));
    return Utils::ToLocal(i::Cast<i::JSTypedArray>(*obj)->GetBuffer());
  }
}

size_t v8::ArrayBufferView::CopyContents(void* dest, size_t byte_length) {
  auto self = Utils::OpenDirectHandle(this);
  size_t bytes_to_copy = std::min(byte_length, self->byte_length());
  if (bytes_to_copy) {
    i::DisallowGarbageCollection no_gc;
    const char* source;
    if (i::IsJSTypedArray(*self)) {
      i::Tagged<i::JSTypedArray> array = i::Cast<i::JSTypedArray>(*self);
      source = reinterpret_cast<char*>(array->DataPtr());
    } else {
      DCHECK(i::IsJSDataView(*self) || i::IsJSRabGsabDataView(*self));
      i::Tagged<i::JSDataViewOrRabGsabDataView> data_view =
          i::Cast<i::JSDataViewOrRabGsabDataView>(*self);
      source = reinterpret_cast<char*>(data_view->data_pointer());
    }
    memcpy(dest, source, bytes_to_copy);
  }
  return bytes_to_copy;
}

v8::MemorySpan<uint8_t> v8::ArrayBufferView::GetContents(
    v8::MemorySpan<uint8_t> storage) {
  internal::DisallowGarbageCollection no_gc;
  auto self = Utils::OpenDirectHandle(this);
  if (self->WasDetached()) {
    return {};
  }
  if (internal::IsJSTypedArray(*self)) {
    i::Tagged<i::JSTypedArray> typed_array = i::Cast<i::JSTypedArray>(*self);
    if (typed_array->is_on_heap()) {
      // The provided storage does not have enough capacity for the content of
      // the TypedArray.
      size_t bytes_to_copy = self->byte_length();
      CHECK_LE(bytes_to_copy, storage.size());
      const uint8_t* source =
          reinterpret_cast<uint8_t*>(typed_array->DataPtr());
      memcpy(reinterpret_cast<void*>(storage.data()), source, bytes_to_copy);
      return {storage.data(), bytes_to_copy};
    }
    // The TypedArray already has off-heap storage, just return a view on it.
    return {reinterpret_cast<uint8_t*>(typed_array->DataPtr()),
            typed_array->GetByteLength()};
  }
  if (i::IsJSDataView(*self)) {
    i::Tagged<i::JSDataView> data_view = i::Cast<i::JSDataView>(*self);
    return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
            data_view->byte_length()};
  }
  // Other types of ArrayBufferView always have an off-heap storage.
  DCHECK(i::IsJSRabGsabDataView(*self));
  i::Tagged<i::JSRabGsabDataView> data_view =
      i::Cast<i::JSRabGsabDataView>(*self);
  return {reinterpret_cast<uint8_t*>(data_view->data_pointer()),
          data_view->GetByteLength()};
}

bool v8::ArrayBufferView::HasBuffer() const {
  auto self = Utils::OpenDirectHandle(this);
  if (!IsJSTypedArray(*self)) return true;
  auto typed_array = i::Cast<i::JSTypedArray>(self);
  return !typed_array->is_on_heap();
}

size_t v8::ArrayBufferView::ByteOffset() {
  auto obj = Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->byte_offset();
}

size_t v8::ArrayBufferView::ByteLength() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSArrayBufferView> obj = *Utils::OpenDirectHandle(this);
  if (obj->WasDetached()) {
    return 0;
  }
  if (i::IsJSTypedArray(obj)) {
    return i::Cast<i::JSTypedArray>(obj)->GetByteLength();
  }
  if (i::IsJSDataView(obj)) {
    return i::Cast<i::JSDataView>(obj)->byte_length();
  }
  return i::Cast<i::JSRabGsabDataView>(obj)->GetByteLength();
}

size_t v8::TypedArray::Length() {
  i::DisallowGarbageCollection no_gc;
  i::Tagged<i::JSTypedArray> obj = *Utils::OpenDirectHandle(this);
  return obj->WasDetached() ? 0 : obj->GetLength();
}

static_assert(v8::TypedArray::kMaxByteLength == i::JSTypedArray::kMaxByteLength,
              "v8::TypedArray::kMaxByteLength must match "
              "i::JSTypedArray::kMaxByteLength");

#define TYPED_ARRAY_NEW(Type, type, TYPE, ctype)                            \
  Local<Type##Array> Type##Array::New(Local<ArrayBuffer> array_buffer,      \
                                      size_t byte_offset, size_t length) {  \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*array_buffer)->GetIsolate();               \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(length <= kMaxLength,                              \
                         "v8::" #Type                                       \
                         "Array::New(Local<ArrayBuffer>, size_t, size_t)",  \
                         "length exceeds max allowed value")) {             \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*array_buffer);                         \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }                                                                         \
  Local<Type##Array> Type##Array::New(                                      \
      Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,     \
      size_t length) {                                                      \
    i::Isolate* i_isolate =                                                 \
        Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();        \
    API_RCS_SCOPE(i_isolate, Type##Array, New);                             \
    ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);                             \
    if (!Utils::ApiCheck(                                                   \
            length <= kMaxLength,                                           \
            "v8::" #Type                                                    \
            "Array::New(Local<SharedArrayBuffer>, size_t, size_t)",         \
            "length exceeds max allowed value")) {                          \
      return Local<Type##Array>();                                          \
    }                                                                       \
    auto buffer = Utils::OpenHandle(*shared_array_buffer);                  \
    i::DirectHandle<i::JSTypedArray> obj =                                  \
        i_isolate->factory()->NewJSTypedArray(i::kExternal##Type##Array,    \
                                              buffer, byte_offset, length); \
    return Utils::ToLocal##Type##Array(obj);                                \
  }

TYPED_ARRAYS_BASE(TYPED_ARRAY_NEW)
#undef TYPED_ARRAY_NEW

Local<Float16Array> Float16Array::New(Local<ArrayBuffer> array_buffer,
                                      size_t byte_offset, size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate = Utils::OpenDirectHandle(*array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<ArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}
Local<Float16Array> Float16Array::New(
    Local<SharedArrayBuffer> shared_array_buffer, size_t byte_offset,
    size_t length) {
  Utils::ApiCheck(i::v8_flags.js_float16array, "v8::Float16Array::New",
                  "Float16Array is not supported");
  i::Isolate* i_isolate =
      Utils::OpenDirectHandle(*shared_array_buffer)->GetIsolate();
  API_RCS_SCOPE(i_isolate, Float16Array, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (!Utils::ApiCheck(
          length <= kMaxLength,
          "v8::Float16Array::New(Local<SharedArrayBuffer>, size_t, size_t)",
          "length exceeds max allowed value")) {
    return Local<Float16Array>();
  }
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::DirectHandle<i::JSTypedArray> obj = i_isolate->factory()->NewJSTypedArray(
      i::kExternalFloat16Array, buffer, byte_offset, length);
  return Utils::ToLocalFloat16Array(obj);
}

// TODO(v8:11111): Support creating length tracking DataViews via the API.
Local<DataView> DataView::New(Local<ArrayBuffer> array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

Local<DataView> DataView::New(Local<SharedArrayBuffer> shared_array_buffer,
                              size_t byte_offset, size_t byte_length) {
  auto buffer = Utils::OpenHandle(*shared_array_buffer);
  i::Isolate* i_isolate = buffer->GetIsolate();
  API_RCS_SCOPE(i_isolate, DataView, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto obj = i::Cast<i::JSDataView>(
      i_isolate->factory()->NewJSDataViewOrRabGsabDataView(buffer, byte_offset,
                                                           byte_length));
  return Utils::ToLocal(obj);
}

size_t v8::SharedArrayBuffer::ByteLength() const {
  return Utils::OpenDirectHandle(this)->GetByteLength();
}

size_t v8::SharedArrayBuffer::MaxByteLength() const {
  return Utils::OpenDirectHandle(this)->max_byte_length();
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);

  std::unique_ptr<i::BackingStore> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));

  if (!backing_store) {
    // TODO(jbroman): It may be useful in the future to provide a MaybeLocal
    // version that throws an exception or otherwise does not crash.
    i::V8::FatalProcessOutOfMemory(i_isolate, "v8::SharedArrayBuffer::New");
  }

  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(backing_store));
  return Utils::ToLocalShared(obj);
}

Local<SharedArrayBuffer> v8::SharedArrayBuffer::New(
    Isolate* v8_isolate, std::shared_ptr<BackingStore> backing_store) {
  CHECK_IMPLIES(backing_store->ByteLength() != 0,
                backing_store->Data() != nullptr);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::shared_ptr<i::BackingStore> i_backing_store(ToInternal(backing_store));
  Utils::ApiCheck(
      i_backing_store->is_shared(), "v8::SharedArrayBuffer::New",
      "Cannot construct SharedArrayBuffer with BackingStore of ArrayBuffer");
  i::Handle<i::JSArrayBuffer> obj =
      i_isolate->factory()->NewJSSharedArrayBuffer(std::move(i_backing_store));
  return Utils::ToLocalShared(obj);
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    Isolate* v8_isolate, size_t byte_length,
    BackingStoreInitializationMode initialization_mode) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, SharedArrayBuffer, NewBackingStore);
  Utils::ApiCheck(
      byte_length <= i::JSArrayBuffer::kMaxByteLength,
      "v8::SharedArrayBuffer::NewBackingStore",
      "Cannot construct SharedArrayBuffer, requested length is too big");
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::Allocate(i_isolate, byte_length, i::SharedFlag::kShared,
                                GetInitializedFlag(initialization_mode));
  if (!backing_store) {
    i::V8::FatalProcessOutOfMemory(i_isolate,
                                   "v8::SharedArrayBuffer::NewBackingStore");
  }
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

std::unique_ptr<v8::BackingStore> v8::SharedArrayBuffer::NewBackingStore(
    void* data, size_t byte_length, v8::BackingStore::DeleterCallback deleter,
    void* deleter_data) {
  CHECK_LE(byte_length, i::JSArrayBuffer::kMaxByteLength);
  std::unique_ptr<i::BackingStoreBase> backing_store =
      i::BackingStore::WrapAllocation(data, byte_length, deleter, deleter_data,
                                      i::SharedFlag::kShared);
  return std::unique_ptr<v8::BackingStore>(
      static_cast<v8::BackingStore*>(backing_store.release()));
}

Local<Symbol> v8::Symbol::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Symbol, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> result = i_isolate->factory()->NewSymbol();
  if (!name.IsEmpty()) result->set_description(*Utils::OpenDirectHandle(*name));
  return Utils::ToLocal(result);
}

Local<Symbol> v8::Symbol::For(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kPublicSymbolTable, i_name, false));
}

Local<Symbol> v8::Symbol::ForApi(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  return Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kApiSymbolTable, i_name, false));
}

#define WELL_KNOWN_SYMBOLS(V)                 \
  V(AsyncIterator, async_iterator)            \
  V(HasInstance, has_instance)                \
  V(IsConcatSpreadable, is_concat_spreadable) \
  V(Iterator, iterator)                       \
  V(Match, match)                             \
  V(Replace, replace)                         \
  V(Search, search)                           \
  V(Split, split)                             \
  V(ToPrimitive, to_primitive)                \
  V(ToStringTag, to_string_tag)               \
  V(Unscopables, unscopables)

#define SYMBOL_GETTER(Name, name)                                      \
  Local<Symbol> v8::Symbol::Get##Name(Isolate* v8_isolate) {           \
    i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate); \
    return Utils::ToLocal(i_isolate->factory()->name##_symbol());      \
  }

WELL_KNOWN_SYMBOLS(SYMBOL_GETTER)

#undef SYMBOL_GETTER
#undef WELL_KNOWN_SYMBOLS

Local<Private> v8::Private::New(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  API_RCS_SCOPE(i_isolate, Private, New);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::Symbol> symbol = i_isolate->factory()->NewPrivateSymbol();
  if (!name.IsEmpty()) symbol->set_description(*Utils::OpenDirectHandle(*name));
  Local<Symbol> result = Utils::ToLocal(symbol);
  return result.UnsafeAs<Private>();
}

Local<Private> v8::Private::ForApi(Isolate* v8_isolate, Local<String> name) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  auto i_name = Utils::OpenHandle(*name);
  Local<Symbol> result = Utils::ToLocal(
      i_isolate->SymbolFor(i::RootIndex::kApiPrivateSymbolTable, i_name, true));
  return result.UnsafeAs<Private>();
}

Local<Number> v8::Number::New(Isolate* v8_isolate, double value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  DCHECK_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (std::isnan(value)) {
    // Introduce only canonical NaN value into the VM, to avoid signaling NaNs.
    value = std::numeric_limits<double>::quiet_NaN();
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::NumberToLocal(result);
}

Local<Integer> v8::Integer::New(Isolate* v8_isolate, int32_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  if (i::Smi::IsValid(value)) {
    return Utils::IntegerToLocal(
        i::Handle<i::Object>(i::Smi::FromInt(value), i_isolate));
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::IntegerToLocal(result);
}

Local<Integer> v8::Integer::NewFromUnsigned(Isolate* v8_isolate,
                                            uint32_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  bool fits_into_int32_t = (value & (1 << 31)) == 0;
  if (fits_into_int32_t) {
    return Integer::New(v8_isolate, static_cast<int32_t>(value));
  }
  i::Handle<i::Object> result = i_isolate->factory()->NewNumber(value);
  return Utils::IntegerToLocal(result);
}

Local<BigInt> v8::BigInt::New(Isolate* v8_isolate, int64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::BigInt> result = i::BigInt::FromInt64(i_isolate, value);
  return Utils::ToLocal(result);
}

Local<BigInt> v8::BigInt::NewFromUnsigned(Isolate* v8_isolate, uint64_t value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
  ENTER_V8_NO_SCRIPT_NO_EXCEPTION(i_isolate);
  i::Handle<i::BigInt> result = i::BigInt::FromUint64(i_isolate, value);
  return Utils::ToLocal(result);
}

MaybeLocal<BigInt> v8::BigInt::NewFromWords(Local<Context> context,
                                            int sign_bit, int word_count,
                                            const uint64_t* words) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(context->GetIsolate());
  ENTER_V8_NO_SCRIPT(i_isolate, context, BigInt, NewFromWords,
                     InternalEscapableScope);
  i::MaybeHandle<i::BigInt> result =
      i::BigInt::FromWords64(i_isolate, sign_bit, word_count, words);
  has_exception = result.is_null();
  RETURN_ON_FAILED_EXECUTION(BigInt);
  RETURN_ESCAPED(Utils::ToLocal(result.ToHandleChecked()));
}

uint64_t v8::BigInt::Uint64Value(bool* lossless) const {
  return Utils::OpenDirectHandle(this)->AsUint64(lossless);
}

int64_t v8::BigInt::Int64Value(bool* lossless) const {
  return Utils::OpenDirectHandle(this)->AsInt64(lossless);
}

int BigInt::WordCount() const {
  return Utils::OpenDirectHandle(this)->Words64Count();
}

void BigInt::ToWordsArray(int* sign_bit, int* word_count,
                          uint64_t* words) const {
  // TODO(saelo): consider migrating the public API to also use uint32_t or
  // size_t for length and count values.
  uint32_t unsigned_word_count = *word_count;
  Utils::OpenDirectHandle(this)->ToWordsArray64(sign_bit, &unsigned_word_count,
                                                words);
  *word_count = base::checked_cast<int>(unsigned_word_count);
}

void Isolate::HandleExternalMemoryInterrupt() {
  i::Heap* heap = reinterpret_cast<i::Isolate*>(this)->heap();
  if (heap->gc_state() != i::Heap::NOT_IN_GC) return;
  heap->HandleExternalMemoryInterrupt();
}

HeapProfiler* Isolate::GetHeapProfiler() {
  i::HeapProfiler* heap_profiler =
      reinterpret_cast<i::Isolate*>(this)->heap_profiler();
  return reinterpret_cast<HeapProfiler*>(heap_profiler);
}

void Isolate::SetIdle(bool is_idle) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->SetIdle(is_idle);
}

ArrayBuffer::Allocator* Isolate::GetArrayBufferAllocator() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return i_isolate->array_buffer_allocator();
}

bool Isolate::InContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  return !i_isolate->context().is_null();
}

void Isolate::ClearKeptObjects() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->ClearKeptObjects();
}

v8::Local<v8::Context> Isolate::GetCurrentContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Tagged<i::Context> context = i_isolate->context();
  if (context.is_null()) return Local<Context>();
  i::Tagged<i::NativeContext> native_context = context->native_context();
  return Utils::ToLocal(i::direct_handle(native_context, i_isolate));
}

// TODO(ishell): rename back to GetEnteredContext().
v8::Local<v8::Context> Isolate::GetEnteredOrMicrotaskContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::NativeContext> last =
      i_isolate->handle_scope_implementer()->LastEnteredContext();
  if (last.is_null()) return Local<Context>();
  return Utils::ToLocal(last);
}

v8::Local<v8::Context> Isolate::GetIncumbentContext() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::NativeContext> context = i_isolate->GetIncumbentContext();
  return Utils::ToLocal(context);
}

v8::MaybeLocal<v8::Data> Isolate::GetCurrentHostDefinedOptions() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i::Handle<i::Script> script;
  if (!i_isolate->CurrentReferrerScript().ToHandle(&script)) {
    return MaybeLocal<v8::Data>();
  }
  return ToApiHandle<Data>(
      i::direct_handle(script->host_defined_options(), i_isolate));
}

v8::Local<Value> Isolate::ThrowError(v8::Local<v8::String> message) {
  return ThrowException(v8::Exception::Error(message));
}

v8::Local<Value> Isolate::ThrowException(v8::Local<v8::Value> value) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  ENTER_V8_BASIC(i_isolate);
  i_isolate->clear_internal_exception();
  // If we're passed an empty handle, we throw an undefined exception
  // to deal more gracefully with out of memory situations.
  if (value.IsEmpty()) {
    i_isolate->Throw(i::ReadOnlyRoots(i_isolate).undefined_value());
  } else {
    i_isolate->Throw(*Utils::OpenDirectHandle(*value));
  }
  return v8::Undefined(reinterpret_cast<v8::Isolate*>(i_isolate));
}

bool Isolate::HasPendingException() {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  if (i_isolate->has_exception()) {
    return true;
  }
  v8::TryCatch* try_catch_handler =
      i_isolate->thread_local_top()->try_catch_handler_;
  return try_catch_handler && try_catch_handler->HasCaught();
}

void Isolate::AddGCPrologueCallback(GCCallbackWithData callback, void* data,
                                    GCType gc_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddGCPrologueCallback(callback, gc_type, data);
}

void Isolate::RemoveGCPrologueCallback(GCCallbackWithData callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveGCPrologueCallback(callback, data);
}

void Isolate::AddGCEpilogueCallback(GCCallbackWithData callback, void* data,
                                    GCType gc_type) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->AddGCEpilogueCallback(callback, gc_type, data);
}

void Isolate::RemoveGCEpilogueCallback(GCCallbackWithData callback,
                                       void* data) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->RemoveGCEpilogueCallback(callback, data);
}

static void CallGCCallbackWithoutData(Isolate* v8_isolate, GCType type,
                                      GCCallbackFlags flags, void* data) {
  reinterpret_cast<Isolate::GCCallback>(data)(v8_isolate, type, flags);
}

void Isolate::AddGCPrologueCallback(GCCallback callback, GCType gc_type) {
  void* data = reinterpret_cast<void*>(callback);
  AddGCPrologueCallback(CallGCCallbackWithoutData, data, gc_type);
}

void Isolate::RemoveGCPrologueCallback(GCCallback callback) {
  void* data = reinterpret_cast<void*>(callback);
  RemoveGCPrologueCallback(CallGCCallbackWithoutData, data);
}

void Isolate::AddGCEpilogueCallback(GCCallback callback, GCType gc_type) {
  void* data = reinterpret_cast<void*>(callback);
  AddGCEpilogueCallback(CallGCCallbackWithoutData, data, gc_type);
}

void Isolate::RemoveGCEpilogueCallback(GCCallback callback) {
  void* data = reinterpret_cast<void*>(callback);
  RemoveGCEpilogueCallback(CallGCCallbackWithoutData, data);
}

void Isolate::SetEmbedderRootsHandler(EmbedderRootsHandler* handler) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(this);
  i_isolate->heap()->SetEmbedderRootsHandler(handler);
}

void Isolate::AttachCppHeap(CppHeap* cpp_heap) {
  i::Isolate* i_isolate = reinterpret_cast<i::Isol
```
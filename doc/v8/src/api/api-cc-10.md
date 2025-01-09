Response:
Let's break down the thought process for analyzing this V8 `api.cc` code snippet.

1. **Understanding the Request:** The core task is to analyze a C++ source file from V8, identify its functions, explain their purpose, and relate them to JavaScript concepts where applicable. Key instructions include noting if it *were* a Torque file (it's not), providing JavaScript examples, explaining logic, highlighting common errors, and summarizing the overall function. The "part 11 of 15" suggests it's part of a larger API definition.

2. **Initial Scan for Key Structures:** I'd first quickly scan the code for prominent V8 API classes. The names `Array`, `Map`, `Set`, `Promise`, `Proxy`, `WasmModuleObject`, and `ArrayBuffer` jump out. These are high-level JavaScript objects with corresponding C++ representations in the V8 API.

3. **Analyzing Individual Classes/Functions:** For each identified class, I'd go through the provided methods. Let's take `v8::Array` as an example:

    * **`New(Isolate*, int length)`:**  This clearly creates a new JavaScript array with a specified length. The internal implementation details (using `i::Isolate`, `i::JSArray`, `i::Number`) are V8-specific. The important takeaway is the connection to `new Array(length)` in JavaScript.

    * **`New(Isolate*, Local<Value>*, size_t length)`:** This version initializes the array with given elements. Again, the internal details are less important than the JavaScript equivalent of `new Array(element1, element2, ...)`.

    * **`New(Local<Context>, size_t length, std::function<...>)`:** This is a more advanced form, using a callback to generate array elements. This might correspond to more complex array creation scenarios or lazy initialization in JavaScript (though JavaScript doesn't directly expose this callback mechanism).

    * **`Length() const`:**  This is straightforward: it returns the length of the array, directly corresponding to the `array.length` property in JavaScript.

    * **`Iterate(...)`:** This function allows iterating over the array's elements. The code has both "fast path" and "slow path" implementations, indicating optimization considerations. The JavaScript equivalent is the `for...of` loop or array methods like `forEach`. The `IterationCallback` parameter hints at a user-defined function being executed for each element.

    * **`TypecheckWitness`:** This is a bit more internal, likely related to V8's type system and optimizations. It helps track the "shape" of objects. While not directly exposed in JavaScript, its existence reflects V8's internal workings for performance.

4. **Repeating the Process for Other Classes:** I'd apply the same function-by-function analysis to `v8::Map`, `v8::Set`, `v8::Promise`, etc. For each function, I'd try to determine:

    * **What it does:**  A concise description of its action.
    * **How it relates to JavaScript:**  Is there a direct JavaScript counterpart (constructor, method, property)?
    * **Internal mechanisms:** Briefly mention the internal V8 types and operations if they are key to understanding the functionality (e.g., `i::JSMap`, `i::OrderedHashMap`).
    * **Potential errors:** Think about common mistakes a programmer might make when using the corresponding JavaScript feature.

5. **Addressing Specific Instructions:**

    * **Torque:**  The code explicitly checks for the `.tq` extension. Since it's `.cc`, it's C++, and this is noted.
    * **JavaScript Examples:**  For functions clearly related to JavaScript, concrete examples using JavaScript syntax are essential.
    * **Logic and Assumptions:**  For functions with internal logic (like `FastIterateArray`), briefly describe the assumptions (e.g., array element types) and the different execution paths. Input/output examples can be simple, like "Input: `Array::New(isolate, 5)`, Output: A new array with length 5."
    * **Common Errors:**  Think about typical mistakes with arrays, maps, promises, etc. For example, accessing array elements out of bounds, using `Map` without understanding key uniqueness, or not handling promise rejections.

6. **Summarizing the Functionality:**  After analyzing the individual parts, I would synthesize a summary that captures the overall purpose of the code. In this case, it's clearly about providing the C++ API for creating and manipulating fundamental JavaScript objects like arrays, maps, sets, and promises, as well as interacting with WebAssembly modules.

7. **Review and Refinement:** Finally, I'd review my analysis for clarity, accuracy, and completeness, making sure to address all parts of the original request. I'd check if the JavaScript examples are correct and if the explanations of internal mechanisms are understandable without being overly detailed. I would ensure the "part 11 of 15" context is considered in the summary.

**Self-Correction/Refinement Example During the Process:**

Initially, when looking at the `FastIterateArray` function, I might get bogged down in the different element kind cases (`PACKED_SMI_ELEMENTS`, `HOLEY_ELEMENTS`, etc.). I would then realize that the *core functionality* is to iterate over the array efficiently, and the different cases are optimizations based on how the array's elements are stored internally. My explanation should focus on the iteration itself and the callback mechanism, rather than getting lost in the low-level details of each element kind (unless specifically asked for). I'd also make sure to highlight the "fast path" vs. "slow path" concept.

By following this structured approach, I can systematically analyze the V8 source code and provide a comprehensive and informative response.好的，让我们来分析一下这段 `v8/src/api/api.cc` 的代码片段。

**1. 文件类型判断:**

代码片段的路径是 `v8/src/api/api.cc`，以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 文件。

**2. 功能列举:**

这段代码主要提供了 V8 C++ API 中关于以下 JavaScript 对象的操作：

* **`v8::Array` (数组):**
    * 创建新的 `v8::Array` 对象，可以指定长度或者使用已有的元素。
    * 获取数组的长度 (`Length()`).
    * 快速迭代数组元素 (`Iterate()`)，提供了优化的路径来遍历数组，并通过回调函数处理每个元素。
* **`v8::TypecheckWitness` (类型检查凭证):**
    *  用于在快速迭代等场景中优化类型检查，跟踪对象的基础类型信息。
* **`v8::Map` (映射):**
    * 创建新的 `v8::Map` 对象。
    * 获取 `Map` 的大小 (`Size()`).
    * 清空 `Map` (`Clear()`).
    * 获取指定键的值 (`Get()`).
    * 设置键值对 (`Set()`).
    * 检查是否包含指定的键 (`Has()`).
    * 删除指定键的键值对 (`Delete()`).
    * 将 `Map` 转换为数组 (`AsArray()`)，数组的元素是 `[key, value]` 对。
* **`v8::Set` (集合):**
    * 创建新的 `v8::Set` 对象。
    * 获取 `Set` 的大小 (`Size()`).
    * 清空 `Set` (`Clear()`).
    * 向 `Set` 中添加元素 (`Add()`).
    * 检查是否包含指定的元素 (`Has()`).
    * 删除指定的元素 (`Delete()`).
    * 将 `Set` 转换为数组 (`AsArray()`)，数组的元素是 `Set` 中的值。
* **`v8::Promise` (Promise):**
    * 创建 `Promise::Resolver`，用于控制 `Promise` 的状态。
    * 获取 `Promise::Resolver` 关联的 `Promise` 对象 (`GetPromise()`).
    * 解析 (fulfill) `Promise` (`Resolve()`).
    * 拒绝 (reject) `Promise` (`Reject()`).
    * 为 `Promise` 添加 `catch` 回调 (`Catch()`).
    * 为 `Promise` 添加 `then` 回调 (`Then()`)，可以指定 fulfilled 和 rejected 时的处理函数。
    * 检查 `Promise` 是否有处理器 (`HasHandler()`).
    * 获取 `Promise` 的结果 (`Result()`)，仅当 `Promise` 已完成时有效。
    * 获取 `Promise` 的状态 (`State()`).
    * 将 `Promise` 标记为已处理 (`MarkAsHandled()`).
    * 将 `Promise` 标记为静默（不触发未处理的 rejection 警告） (`MarkAsSilent()`).
* **`v8::Proxy` (代理):**
    * 获取 `Proxy` 的目标对象 (`GetTarget()`).
    * 获取 `Proxy` 的处理器对象 (`GetHandler()`).
    * 检查 `Proxy` 是否已被撤销 (`IsRevoked()`).
    * 撤销 `Proxy` (`Revoke()`).
    * 创建新的 `Proxy` 对象 (`New()`).
* **`v8::CompiledWasmModule` (已编译的 WebAssembly 模块):**
    *  封装已编译的 WebAssembly 模块，包含原生模块和源 URL。
    *  序列化已编译的 WebAssembly 模块 (`Serialize()`).
    *  获取 WebAssembly 模块的原始字节引用 (`GetWireBytesRef()`).
* **`v8::WasmMemoryObject` (WebAssembly 内存对象):**
    * 获取 WebAssembly 内存对象关联的 `ArrayBuffer` (`Buffer()`).
* **`v8::WasmModuleObject` (WebAssembly 模块对象):**
    * 获取 `WasmModuleObject` 中包含的已编译的 WebAssembly 模块 (`GetCompiledModule()`).
    * 从已编译的 WebAssembly 模块创建 `WasmModuleObject` (`FromCompiledModule()`).
    * 编译 WebAssembly 字节码并创建 `WasmModuleObject` (`Compile()`).
* **`v8::ArrayBuffer` (ArrayBuffer):**
    * 提供自定义的 `Allocator` 用于 `ArrayBuffer` 的内存管理。
    * 判断 `ArrayBuffer` 是否可分离 (`IsDetachable()`).
    * 判断 `ArrayBuffer` 是否已被分离 (`WasDetached()`).
    * 分离 `ArrayBuffer` 的底层内存 (`Detach()`).

**3. 与 JavaScript 功能的关系及举例:**

这段 C++ 代码是 V8 引擎实现 JavaScript 相应功能的底层 API。以下是一些 JavaScript 例子来说明它们之间的关系：

* **`v8::Array::New`:**

```javascript
// 对应 v8::Array::New(Isolate* v8_isolate, int length)
const arr1 = new Array(5); // 创建一个长度为 5 的数组

// 对应 v8::Array::New(Isolate* v8_isolate, Local<Value>* elements, size_t length)
const arr2 = [1, 'hello', true];
```

* **`v8::Array::Length`:**

```javascript
const arr = [1, 2, 3];
console.log(arr.length); // 对应 v8::Array::Length()
```

* **`v8::Array::Iterate`:**

```javascript
const arr = [10, 20, 30];
arr.forEach((element, index) => { // 对应 v8::Array::Iterate() 的慢速路径
  console.log(`Index: ${index}, Element: ${element}`);
});

for (const element of arr) { // 对应 v8::Array::Iterate() 的快速路径 (在某些情况下)
  console.log(element);
}
```

* **`v8::Map` 的操作:**

```javascript
const map = new Map(); // 对应 v8::Map::New()
map.set('a', 1);      // 对应 v8::Map::Set()
map.get('a');          // 对应 v8::Map::Get()
map.has('a');          // 对应 v8::Map::Has()
map.delete('a');       // 对应 v8::Map::Delete()
map.clear();           // 对应 v8::Map::Clear()
map.size;              // 对应 v8::Map::Size()
[...map];             // 对应 v8::Map::AsArray()
```

* **`v8::Set` 的操作:**

```javascript
const set = new Set(); // 对应 v8::Set::New()
set.add(1);            // 对应 v8::Set::Add()
set.has(1);            // 对应 v8::Set::Has()
set.delete(1);         // 对应 v8::Set::Delete()
set.clear();           // 对应 v8::Set::Clear()
set.size;              // 对应 v8::Set::Size()
[...set];             // 对应 v8::Set::AsArray()
```

* **`v8::Promise` 的操作:**

```javascript
const promise = new Promise((resolve, reject) => { // 对应 v8::Promise::Resolver::New()
  // ... 异步操作
  if (/* 成功 */) {
    resolve(value); // 对应 v8::Promise::Resolver::Resolve()
  } else {
    reject(error);  // 对应 v8::Promise::Resolver::Reject()
  }
});

promise.then((result) => { /* 处理成功 */ }) // 对应 v8::Promise::Then()
       .catch((error) => { /* 处理错误 */ }); // 对应 v8::Promise::Catch()

promise.then(() => {}, () => {}); // 对应 v8::Promise::Then() 的另一种形式

promise.finally(() => {}); // 注意：`finally` 在这段代码中没有直接体现，但 Promise 的基本机制是相同的
```

* **`v8::Proxy` 的操作:**

```javascript
const target = {};
const handler = {
  get: function(obj, prop) {
    console.log(`有人访问了 ${prop}`);
    return obj[prop];
  }
};
const proxy = new Proxy(target, handler); // 对应 v8::Proxy::New()

proxy.someProperty; // 会触发 handler.get

// Proxy 的撤销 (对应 v8::Proxy::Revoke()) 在 JavaScript 中通过创建可撤销的 Proxy 实现
const revocableProxy = Proxy.revocable(target, handler);
revocableProxy.proxy.someProperty;
revocableProxy.revoke();
// revocableProxy.proxy.someProperty; // 抛出 TypeError
```

* **WebAssembly 相关:**

```javascript
// 编译 WebAssembly 模块 (对应 v8::WasmModuleObject::Compile())
WebAssembly.compile(wasmBuffer)
  .then(module => {
    // 从已编译的模块实例化 (没有直接对应的 C++ API，但 v8::WasmModuleObject::FromCompiledModule 可能在内部使用)
    const instance = new WebAssembly.Instance(module);
    // ... 使用 WebAssembly 实例
  });

// 创建 WebAssembly 内存 (对应 v8::ArrayBuffer 的使用)
const memory = new WebAssembly.Memory({ initial: 10 });
```

* **`v8::ArrayBuffer` 的操作:**

```javascript
const buffer = new ArrayBuffer(16); // 创建一个 16 字节的 ArrayBuffer
console.log(buffer.isDetachable()); // 对应 v8::ArrayBuffer::IsDetachable()

// 分离 ArrayBuffer (对应 v8::ArrayBuffer::Detach())
buffer.detach();
console.log(buffer.isDetachable());
console.log(buffer.wasDetached());
```

**4. 代码逻辑推理及假设输入输出:**

* **`v8::Array::New(Isolate* v8_isolate, int length)`:**
    * **假设输入:** `length = 5`
    * **输出:** 一个新的 `v8::Array` 对象，其内部 JavaScript 表示形式类似于 `new Array(5)`，包含 5 个空的槽位。

* **`v8::Array::Iterate` (快速路径):**
    * **假设输入:** 一个 packed 类型的数组 `arr = [1, 2, 3]`，以及一个简单的回调函数 `callback(index, value, data)`，`data` 为 `nullptr`。
    * **输出:** 回调函数会被调用三次：
        * `callback(0, 1, nullptr)`
        * `callback(1, 2, nullptr)`
        * `callback(2, 3, nullptr)`

* **`v8::Map::Set`:**
    * **假设输入:** 一个空的 `v8::Map` 对象 `map`，键 `key` 为字符串 "name"，值 `value` 为字符串 "Alice"。
    * **输出:** `map` 对象现在包含一个键值对 `{"name" => "Alice"}`，函数返回 `MaybeLocal<Map>`，成功时包含修改后的 `Map` 对象。

**5. 用户常见的编程错误:**

* **对未初始化的 `Array` 进行操作:**  虽然可以创建指定长度的数组，但其元素最初是空的。直接访问可能导致未定义行为或错误。
    ```javascript
    const arr = new Array(5);
    console.log(arr[0].toUpperCase()); // 错误：arr[0] 是 undefined
    ```
* **尝试修改 `Map` 或 `Set` 的键:** JavaScript 中 `Map` 和 `Set` 的键是不可变的（对于对象类型的键，是引用不可变）。尝试直接修改键不会生效。
    ```javascript
    const map = new Map();
    const key = { id: 1 };
    map.set(key, 'value');
    key.id = 2;
    console.log(map.get({ id: 2 })); // 输出 undefined，因为键是原始的 { id: 1 } 对象的引用
    ```
* **在 Promise 中忘记处理 rejection:** 如果 Promise 被拒绝且没有提供 `catch` 或第二个 `then` 回调，会导致 unhandled promise rejection 错误。
    ```javascript
    const promise = new Promise((resolve, reject) => {
      reject('Something went wrong!');
    });
    // 没有 .catch() 处理 rejection
    ```
* **在 Proxy 的 handler 中发生错误:**  如果 `Proxy` 的处理器 (`handler`) 中的方法抛出错误，可能会导致意想不到的行为。
    ```javascript
    const target = {};
    const handler = {
      get: function() {
        throw new Error('访问属性时出错！');
      }
    };
    const proxy = new Proxy(target, handler);
    proxy.someProperty; // 抛出错误
    ```
* **尝试操作已分离的 `ArrayBuffer`:**  一旦 `ArrayBuffer` 被分离，就不能再对其进行读写操作。
    ```javascript
    const buffer = new ArrayBuffer(10);
    buffer.detach();
    const view = new Uint8Array(buffer); // 尝试创建视图会报错
    ```

**6. 功能归纳 (第 11 部分，共 15 部分):**

作为第 11 部分，这段代码主要负责提供 V8 引擎的 **核心对象类型** (数组, 映射, 集合, Promise, 代理) 以及 **WebAssembly 支持** 的 C++ API。它定义了如何创建、操作这些对象，以及如何在 C++ 代码中与 JavaScript 环境中的这些对象进行交互。考虑到这是系列的一部分，可以推测之前的章节可能涉及了更基础的 API 组件，而后续章节可能会涉及更高级或特定的功能，例如模块加载、错误处理、或者与其他 V8 子系统的集成。

总而言之，这段 `v8/src/api/api.cc` 代码是 V8 引擎暴露给 C++ 嵌入器用于操作 JavaScript 核心对象和 WebAssembly 功能的关键接口。

Prompt: 
```
这是目录为v8/src/api/api.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/api/api.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共15部分，请归纳一下它的功能

"""
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
  
"""


```
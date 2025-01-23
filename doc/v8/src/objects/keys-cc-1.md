Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/objects/keys.cc`. The request has several parts:

1. **List the functionalities:** I need to analyze the code and summarize its purpose.
2. **Torque source:** Check if the filename ends with `.tq`.
3. **JavaScript relation:** If the code relates to JavaScript features, provide JavaScript examples.
4. **Logic reasoning:** Provide input/output examples for code logic.
5. **Common errors:**  Point out potential programming mistakes this code might help avoid or detect.
6. **Summary of functionality:**  Provide a concise overview.

Let's break down the code snippet. It seems to be related to collecting keys (property names) of JavaScript objects. I see functions like `CollectOwnPropertyNamesInternal`, `CopyEnumKeysTo`, `CollectKeysFromDictionary`, `CollectOwnKeys`, `CollectOwnJSProxyKeys`, and `GetOwnEnumPropertyKeys`. These names strongly suggest key enumeration and handling of different object types (JSObject, JSGlobalObject, JSProxy).

**Functionality Breakdown:**

* **`CollectOwnPropertyNamesInternal`:**  Appears to iterate through an object's own properties (descriptors) and collect keys (strings or symbols). It seems to differentiate between enumerable and non-enumerable properties and handle symbols separately.
* **`CommonCopyEnumKeysTo`:**  A helper function for copying enumerable keys from a dictionary-like structure to a fixed array.
* **`CopyEnumKeysTo`:**  Copies enumerable keys from different dictionary implementations (like `SwissNameDictionary` and regular dictionaries) to a pre-allocated fixed array, potentially sorting them.
* **`GetOwnEnumPropertyDictionaryKeys`:**  Retrieves the own enumerable property keys from a dictionary.
* **`CollectKeysFromDictionary`:**  Collects keys from a dictionary, handling filtering and sorting based on creation order.
* **`KeyAccumulator::CollectOwnPropertyNames`:** The core function for gathering own property names. It handles fast properties, global objects, and different dictionary types. It also deals with module namespace objects and interceptors.
* **`KeyAccumulator::CollectPrivateNames`:** Specifically collects private names/symbols.
* **`KeyAccumulator::CollectAccessCheckInterceptorKeys`:** Handles keys provided by access check interceptors.
* **`KeyAccumulator::CollectOwnKeys`:** The main entry point for collecting own keys, handling access checks, elements, and property names.
* **`KeyAccumulator::GetOwnEnumPropertyKeys`:**  A static helper to get own enumerable property keys based on the object's property storage type.
* **`KeyAccumulator::CollectOwnJSProxyKeys`:** Implements the logic for the `ownKeys` trap in JavaScript proxies. It validates the trap's return value and ensures consistency with the target object's properties.
* **`KeyAccumulator::CollectOwnJSProxyTargetKeys`:**  A helper function to collect own keys from the target of a proxy.

**Torque Source Check:** The filename ends with `.cc`, not `.tq`.

**JavaScript Relation:** This code directly implements the underlying mechanisms for JavaScript operations related to retrieving object keys, such as:

* `Object.keys()`:  Returns an array of a given object's own enumerable property names.
* `Object.getOwnPropertyNames()`: Returns an array of all own property names (enumerable or not) of an object.
* `Object.getOwnPropertySymbols()`: Returns an array of all own symbol properties of an object.
* `Reflect.ownKeys()`: Returns an array of all own property keys (symbols and strings), including non-enumerable ones.
* Proxy `ownKeys` handler:  The code specifically handles the implementation of this trap.

**Logic Reasoning:**

Let's consider `CollectOwnPropertyNamesInternal`.

* **Hypothetical Input:**  A simple JS object `{ a: 1, b: 2 }` with fast properties, meaning its properties are stored directly in the object.
* **Expected Output:** If `filter_` doesn't exclude any properties, the accumulator will contain the keys "a" and "b". The order might be based on the order of descriptors in the `DescriptorArray`.

For `CollectOwnJSProxyKeys`:

* **Hypothetical Input:** A JSProxy with a target object `{ c: 3 }` and an `ownKeys` handler that returns `['c', 'd']`.
* **Expected Output:** The `KeyAccumulator` will contain the keys `['c', 'd']`. The code validates if the handler's result is consistent with the target's non-configurable properties.

**Common Errors:**

* **Incorrectly implementing the `ownKeys` handler in a Proxy:** The code in `CollectOwnJSProxyKeys` performs checks to ensure the handler's result is valid. A common error is returning keys that don't exist on the target or omitting non-configurable keys. This code helps detect such errors and throws a `TypeError`.
* **Forgetting to handle non-enumerable properties when using `Object.getOwnPropertyNames` or `Reflect.ownKeys`:** The different collection modes and filters within the `KeyAccumulator` highlight the distinction between enumerable and non-enumerable properties.

**Summary of Functionality (Part 2):**

This part of the `v8/src/objects/keys.cc` file focuses on the implementation details of collecting keys (property names) from various JavaScript object types, including regular objects, global objects, and proxies. It handles different scenarios like collecting only own keys, including prototype keys, filtering by property attributes (enumerable, configurable), and specifically dealing with private names/symbols. A significant portion of this code is dedicated to implementing the `ownKeys` trap for JavaScript proxies, ensuring the correctness and consistency of the handler's return value with the target object's properties.
这是目录为v8/src/objects/keys.cc的一个v8源代码的第二部分，延续了第一部分关于收集JavaScript对象键的功能。以下是其功能的归纳：

**核心功能：实现 JavaScript 中获取对象自身属性键的机制，特别是针对不同对象类型和场景进行了优化和处理。**

具体来说，这部分代码主要负责以下几个方面：

1. **处理不同类型的对象:**
   - **快速属性对象 (Fast Properties):**  继续利用存储在 `DescriptorArray` 中的信息高效地收集键，区分字符串键和 Symbol 键，并根据需要过滤非枚举属性。
   - **字典属性对象 (Dictionary Properties):**  处理存储在 `HashTable` 或 `SwissNameDictionary` 中的属性，根据创建顺序收集键，并考虑属性的枚举性和可配置性。
   - **全局对象 (Global Objects):** 特殊处理全局对象的属性字典。
   - **模块命名空间对象 (Module Namespace Objects):**  在收集枚举属性时，模拟 `[[GetOwnProperty]]` 以检查导出的初始化状态，如果未初始化则可能返回 `Nothing<bool>()`。
   - **代理对象 (Proxy Objects):**  实现了 ES6 规范中关于 Proxy 对象 `ownKeys` 陷阱的逻辑，包括：
      - 调用 Proxy 的 handler 上的 `ownKeys` 方法。
      - 验证 `ownKeys` 方法返回的结果是否符合规范，例如不能有重复的键，必须包含目标对象所有不可配置的键，且在目标对象不可扩展的情况下，返回的键必须是目标对象自身属性的子集。
      - 如果 handler 的 `ownKeys` 方法未定义，则回退到收集目标对象的自身属性键。

2. **KeyAccumulator 类的进一步使用:**
   - **`CollectOwnPropertyNames`:**  作为收集自身属性名的核心函数，根据对象类型和过滤器调用不同的内部方法。
   - **`CollectPrivateNames`:**  专门用于收集私有 Symbol 键。
   - **`CollectAccessCheckInterceptorKeys`:**  处理通过访问检查拦截器提供的键。
   - **`CollectOwnKeys`:**  作为收集自身所有键（包括元素索引和属性名）的入口点，并处理访问检查。
   - **`GetOwnEnumPropertyKeys`:**  静态辅助函数，根据对象类型获取自身可枚举的属性键。
   - **`CollectOwnJSProxyKeys` 和 `CollectOwnJSProxyTargetKeys`:**  实现了 Proxy 对象 `ownKeys` 陷阱的具体逻辑。

3. **优化和效率:**
   - **避免不必要的转换:**  使用 `DO_NOT_CONVERT` 标志来避免在添加到 `KeyAccumulator` 时进行不必要的类型转换。
   - **使用预分配的固定数组:**  在已知键数量的情况下，使用 `FixedArray` 来存储键，提高效率。
   - **排序:**  对于某些类型的字典，在收集完键后进行排序以保证枚举顺序。

4. **错误处理和规范遵从:**
   - **检查未初始化的导出:**  针对模块命名空间对象，检查导出的初始化状态。
   - **Proxy 陷阱验证:**  严格按照 ES6 规范验证 Proxy 的 `ownKeys` 陷阱的返回值，并在发现不符合规范的情况时抛出 `TypeError`。

**JavaScript 示例:**

```javascript
const obj = { a: 1, b: 2, [Symbol('c')]: 3 };
Object.defineProperty(obj, 'd', { value: 4, enumerable: false });

// 对应 KeyAccumulator::CollectOwnPropertyNames (filter_ == ENUMERABLE_STRINGS)
console.log(Object.keys(obj)); // 输出: ['a', 'b']

// 对应 KeyAccumulator::CollectOwnPropertyNames (没有过滤器或包含非枚举)
console.log(Object.getOwnPropertyNames(obj)); // 输出: ['a', 'b', 'd']
console.log(Object.getOwnPropertySymbols(obj)); // 输出: [Symbol(c)]
console.log(Reflect.ownKeys(obj)); // 输出: ['a', 'b', 'd', Symbol(c)]

// 对应 KeyAccumulator::CollectOwnJSProxyKeys
const target = { e: 5 };
Object.defineProperty(target, 'f', { value: 6, configurable: false });
const handler = {
  ownKeys: function(tgt) {
    return ['e', 'f', 'g']; // 包含 target 的不可配置属性 'f'，且新增了 'g'
  }
};
const proxy = new Proxy(target, handler);
console.log(Reflect.ownKeys(proxy)); // 输出: ['e', 'f', 'g']

const handler2 = {
  ownKeys: function(tgt) {
    return ['e', 'g']; // 缺少 target 的不可配置属性 'f'，会抛出 TypeError
  }
};
const proxy2 = new Proxy(target, handler2);
try {
  Reflect.ownKeys(proxy2);
} catch (e) {
  console.error(e); // 输出 TypeError
}
```

**代码逻辑推理示例:**

假设 `KeyAccumulator::CollectOwnPropertyNames` 接收到一个快速属性的普通对象 `obj = { a: 1, b: 2 }`，且 `filter_` 为空，表示收集所有自身属性名。

**假设输入:**
- `receiver`: 指向 `obj` 的 `JSReceiver` 句柄。
- `object`: 指向 `obj` 的 `JSObject` 句柄。
- `filter_`:  默认值，不进行过滤。

**推理过程:**
1. 代码会进入 `object->HasFastProperties()` 的分支。
2. 获取 `obj` 的 `DescriptorArray`。
3. `CollectOwnPropertyNamesInternal<true>` 会被调用，遍历 `DescriptorArray`，将字符串键 "a" 和 "b" 添加到 `KeyAccumulator` 中。
4. 由于没有 Symbol 属性，`first_symbol` 将为 -1。
5. `CollectOwnPropertyNamesInternal<false>` 不会被调用。
6. 函数返回 `Just(true)`。

**假设输出 (存储在 KeyAccumulator 中):**
- `keys_`: 包含 "a" 和 "b" 的 `FixedArray`。

**常见的编程错误示例:**

- **Proxy 的 `ownKeys` 陷阱返回不合法的键:**  如上面的 JavaScript 示例所示，忘记包含目标对象的不可配置属性会导致 `TypeError`。这个 C++ 代码正是为了检测和防止这类错误。

**归纳一下它的功能 (第 2 部分):**

总而言之，`v8/src/objects/keys.cc` 的第二部分继续深入实现了 V8 引擎中收集 JavaScript 对象自身属性键的关键逻辑。它专注于处理不同类型的对象存储结构，并特别关注了 ES6 引入的 Proxy 对象的 `ownKeys` 陷阱的实现和规范性验证。这部分代码确保了 JavaScript 中获取对象自身属性键操作的正确性、效率和符合语言规范。它在底层支撑了 `Object.keys()`, `Object.getOwnPropertyNames()`, `Object.getOwnPropertySymbols()` 和 `Reflect.ownKeys()` 等 JavaScript API 的实现。

### 提示词
```
这是目录为v8/src/objects/keys.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/keys.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
continue;
    } else {
      if (keys->AddKey(key, DO_NOT_CONVERT) != ExceptionStatus::kSuccess) {
        return std::optional<int>();
      }
    }
  }
  return first_skipped;
}

// Logic shared between different specializations of CopyEnumKeysTo.
template <typename Dictionary>
void CommonCopyEnumKeysTo(Isolate* isolate, Handle<Dictionary> dictionary,
                          DirectHandle<FixedArray> storage,
                          KeyCollectionMode mode, KeyAccumulator* accumulator) {
  DCHECK_IMPLIES(mode != KeyCollectionMode::kOwnOnly, accumulator != nullptr);
  int length = storage->length();
  int properties = 0;
  ReadOnlyRoots roots(isolate);

  AllowGarbageCollection allow_gc;
  for (InternalIndex i : dictionary->IterateEntries()) {
    Tagged<Object> key;
    if (!dictionary->ToKey(roots, i, &key)) continue;
    bool is_shadowing_key = false;
    if (IsSymbol(key)) continue;
    PropertyDetails details = dictionary->DetailsAt(i);
    if (details.IsDontEnum()) {
      if (mode == KeyCollectionMode::kIncludePrototypes) {
        is_shadowing_key = true;
      } else {
        continue;
      }
    }
    if (is_shadowing_key) {
      // This might allocate, but {key} is not used afterwards.
      accumulator->AddShadowingKey(key, &allow_gc);
      continue;
    } else {
      if (Dictionary::kIsOrderedDictionaryType) {
        storage->set(properties, Cast<Name>(key));
      } else {
        // If the dictionary does not store elements in enumeration order,
        // we need to sort it afterwards in CopyEnumKeysTo. To enable this we
        // need to store indices at this point, rather than the values at the
        // given indices.
        storage->set(properties, Smi::FromInt(i.as_int()));
      }
    }
    properties++;
    if (mode == KeyCollectionMode::kOwnOnly && properties == length) break;
  }

  CHECK_EQ(length, properties);
}

// Copies enumerable keys to preallocated fixed array.
// Does not throw for uninitialized exports in module namespace objects, so
// this has to be checked separately.
template <typename Dictionary>
void CopyEnumKeysTo(Isolate* isolate, Handle<Dictionary> dictionary,
                    Handle<FixedArray> storage, KeyCollectionMode mode,
                    KeyAccumulator* accumulator) {
  static_assert(!Dictionary::kIsOrderedDictionaryType);

  CommonCopyEnumKeysTo<Dictionary>(isolate, dictionary, storage, mode,
                                   accumulator);

  int length = storage->length();

  DisallowGarbageCollection no_gc;
  Tagged<Dictionary> raw_dictionary = *dictionary;
  Tagged<FixedArray> raw_storage = *storage;
  EnumIndexComparator<Dictionary> cmp(raw_dictionary);
  // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
  // store operations that are safe for concurrent marking.
  AtomicSlot start(storage->RawFieldOfFirstElement());
  std::sort(start, start + length, cmp);
  for (int i = 0; i < length; i++) {
    InternalIndex index(Smi::ToInt(raw_storage->get(i)));
    raw_storage->set(i, raw_dictionary->NameAt(index));
  }
}

template <>
void CopyEnumKeysTo(Isolate* isolate, Handle<SwissNameDictionary> dictionary,
                    Handle<FixedArray> storage, KeyCollectionMode mode,
                    KeyAccumulator* accumulator) {
  CommonCopyEnumKeysTo<SwissNameDictionary>(isolate, dictionary, storage, mode,
                                            accumulator);

  // No need to sort, as CommonCopyEnumKeysTo on OrderedNameDictionary
  // adds entries to |storage| in the dict's insertion order
  // Further, the template argument true above means that |storage|
  // now contains the actual values from |dictionary|, rather than indices.
}

template <class T>
Handle<FixedArray> GetOwnEnumPropertyDictionaryKeys(
    Isolate* isolate, KeyCollectionMode mode, KeyAccumulator* accumulator,
    DirectHandle<JSObject> object, Tagged<T> raw_dictionary) {
  Handle<T> dictionary(raw_dictionary, isolate);
  if (dictionary->NumberOfElements() == 0) {
    return isolate->factory()->empty_fixed_array();
  }
  int length = dictionary->NumberOfEnumerableProperties();
  Handle<FixedArray> storage = isolate->factory()->NewFixedArray(length);
  CopyEnumKeysTo(isolate, dictionary, storage, mode, accumulator);
  return storage;
}

// Collect the keys from |dictionary| into |keys|, in ascending chronological
// order of property creation.
template <typename Dictionary>
ExceptionStatus CollectKeysFromDictionary(Handle<Dictionary> dictionary,
                                          KeyAccumulator* keys) {
  Isolate* isolate = keys->isolate();
  ReadOnlyRoots roots(isolate);
  // TODO(jkummerow): Consider using a std::unique_ptr<InternalIndex[]> instead.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(dictionary->NumberOfElements());
  int array_size = 0;
  PropertyFilter filter = keys->filter();
  // Handle enumerable strings in CopyEnumKeysTo.
  DCHECK_NE(keys->filter(), ENUMERABLE_STRINGS);
  {
    DisallowGarbageCollection no_gc;
    for (InternalIndex i : dictionary->IterateEntries()) {
      Tagged<Object> key;
      Tagged<Dictionary> raw_dictionary = *dictionary;
      if (!raw_dictionary->ToKey(roots, i, &key)) continue;
      if (Object::FilterKey(key, filter)) continue;
      PropertyDetails details = raw_dictionary->DetailsAt(i);
      if ((int{details.attributes()} & filter) != 0) {
        AllowGarbageCollection gc;
        // This might allocate, but {key} is not used afterwards.
        keys->AddShadowingKey(key, &gc);
        continue;
      }
      // TODO(emrich): consider storing keys instead of indices into the array
      // in case of ordered dictionary type.
      array->set(array_size++, Smi::FromInt(i.as_int()));
    }
    if (!Dictionary::kIsOrderedDictionaryType) {
      // Sorting only needed if it's an unordered dictionary,
      // otherwise we traversed elements in insertion order

      EnumIndexComparator<Dictionary> cmp(*dictionary);
      // Use AtomicSlot wrapper to ensure that std::sort uses atomic load and
      // store operations that are safe for concurrent marking.
      AtomicSlot start(array->RawFieldOfFirstElement());
      std::sort(start, start + array_size, cmp);
    }
  }

  bool has_seen_symbol = false;
  for (int i = 0; i < array_size; i++) {
    InternalIndex index(Smi::ToInt(array->get(i)));
    Tagged<Object> key = dictionary->NameAt(index);
    if (IsSymbol(key)) {
      has_seen_symbol = true;
      continue;
    }
    ExceptionStatus status = keys->AddKey(key, DO_NOT_CONVERT);
    if (!status) return status;
  }
  if (has_seen_symbol) {
    for (int i = 0; i < array_size; i++) {
      InternalIndex index(Smi::ToInt(array->get(i)));
      Tagged<Object> key = dictionary->NameAt(index);
      if (!IsSymbol(key)) continue;
      ExceptionStatus status = keys->AddKey(key, DO_NOT_CONVERT);
      if (!status) return status;
    }
  }
  return ExceptionStatus::kSuccess;
}

}  // namespace

Maybe<bool> KeyAccumulator::CollectOwnPropertyNames(
    DirectHandle<JSReceiver> receiver, Handle<JSObject> object) {
  if (filter_ == ENUMERABLE_STRINGS) {
    DirectHandle<FixedArray> enum_keys;
    if (object->HasFastProperties()) {
      enum_keys = KeyAccumulator::GetOwnEnumPropertyKeys(isolate_, object);
      // If the number of properties equals the length of enumerable properties
      // we do not have to filter out non-enumerable ones
      Tagged<Map> map = object->map();
      int nof_descriptors = map->NumberOfOwnDescriptors();
      if (enum_keys->length() != nof_descriptors) {
        if (map->prototype(isolate_) != ReadOnlyRoots(isolate_).null_value()) {
          AllowGarbageCollection allow_gc;
          DirectHandle<DescriptorArray> descs(
              map->instance_descriptors(isolate_), isolate_);
          for (InternalIndex i : InternalIndex::Range(nof_descriptors)) {
            PropertyDetails details = descs->GetDetails(i);
            if (!details.IsDontEnum()) continue;
            this->AddShadowingKey(descs->GetKey(i), &allow_gc);
          }
        }
      }
    } else if (IsJSGlobalObject(*object)) {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object,
          Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad));
    } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object, object->property_dictionary_swiss());
    } else {
      enum_keys = GetOwnEnumPropertyDictionaryKeys(
          isolate_, mode_, this, object, object->property_dictionary());
    }
    if (IsJSModuleNamespace(*object)) {
      // Simulate [[GetOwnProperty]] for establishing enumerability, which
      // throws for uninitialized exports.
      for (int i = 0, n = enum_keys->length(); i < n; ++i) {
        Handle<String> key(Cast<String>(enum_keys->get(i)), isolate_);
        if (Cast<JSModuleNamespace>(object)
                ->GetExport(isolate(), key)
                .is_null()) {
          return Nothing<bool>();
        }
      }
    }
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(AddKeys(enum_keys, DO_NOT_CONVERT));
  } else {
    if (object->HasFastProperties()) {
      int limit = object->map()->NumberOfOwnDescriptors();
      DirectHandle<DescriptorArray> descs(
          object->map()->instance_descriptors(isolate_), isolate_);
      // First collect the strings,
      std::optional<int> first_symbol =
          CollectOwnPropertyNamesInternal<true>(object, this, descs, 0, limit);
      // then the symbols.
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(first_symbol);
      if (first_symbol.value() != -1) {
        RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectOwnPropertyNamesInternal<false>(
            object, this, descs, first_symbol.value(), limit));
      }
    } else if (IsJSGlobalObject(*object)) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
                 isolate_),
          this));
    } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(object->property_dictionary_swiss(), isolate_), this));
    } else {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(object->property_dictionary(), isolate_), this));
    }
  }
  // Add the property keys from the interceptor.
  return CollectInterceptorKeys(receiver, object, kNamed);
}

ExceptionStatus KeyAccumulator::CollectPrivateNames(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object) {
  DCHECK_EQ(mode_, KeyCollectionMode::kOwnOnly);
  if (object->HasFastProperties()) {
    int limit = object->map()->NumberOfOwnDescriptors();
    DirectHandle<DescriptorArray> descs(
        object->map()->instance_descriptors(isolate_), isolate_);
    CollectOwnPropertyNamesInternal<false>(object, this, descs, 0, limit);
  } else if (IsJSGlobalObject(*object)) {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad),
               isolate_),
        this));
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(object->property_dictionary_swiss(), isolate_), this));
  } else {
    RETURN_FAILURE_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
        handle(object->property_dictionary(), isolate_), this));
  }
  return ExceptionStatus::kSuccess;
}

Maybe<bool> KeyAccumulator::CollectAccessCheckInterceptorKeys(
    DirectHandle<AccessCheckInfo> access_check_info,
    DirectHandle<JSReceiver> receiver, DirectHandle<JSObject> object) {
  if (!skip_indices_) {
    MAYBE_RETURN((CollectInterceptorKeysInternal(
                     receiver, object,
                     handle(Cast<InterceptorInfo>(
                                access_check_info->indexed_interceptor()),
                            isolate_),
                     kIndexed)),
                 Nothing<bool>());
  }
  MAYBE_RETURN(
      (CollectInterceptorKeysInternal(
          receiver, object,
          handle(Cast<InterceptorInfo>(access_check_info->named_interceptor()),
                 isolate_),
          kNamed)),
      Nothing<bool>());
  return Just(true);
}

// Returns |true| on success, |false| if prototype walking should be stopped,
// |nothing| if an exception was thrown.
Maybe<bool> KeyAccumulator::CollectOwnKeys(DirectHandle<JSReceiver> receiver,
                                           Handle<JSObject> object) {
  // Check access rights if required.
  if (IsAccessCheckNeeded(*object) &&
      !isolate_->MayAccess(isolate_->native_context(), object)) {
    // The cross-origin spec says that [[Enumerate]] shall return an empty
    // iterator when it doesn't have access...
    if (mode_ == KeyCollectionMode::kIncludePrototypes) {
      return Just(false);
    }
    // ...whereas [[OwnPropertyKeys]] shall return allowlisted properties.
    DCHECK_EQ(KeyCollectionMode::kOwnOnly, mode_);
    Handle<AccessCheckInfo> access_check_info;
    {
      DisallowGarbageCollection no_gc;
      Tagged<AccessCheckInfo> maybe_info =
          AccessCheckInfo::Get(isolate_, object);
      if (!maybe_info.is_null()) {
        access_check_info = handle(maybe_info, isolate_);
      }
    }
    // We always have both kinds of interceptors or none.
    if (!access_check_info.is_null() &&
        access_check_info->named_interceptor() != Tagged<Object>()) {
      MAYBE_RETURN(CollectAccessCheckInterceptorKeys(access_check_info,
                                                     receiver, object),
                   Nothing<bool>());
    }
    return Just(false);
  }
  if (filter_ & PRIVATE_NAMES_ONLY) {
    RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectPrivateNames(receiver, object));
    return Just(true);
  }

  if (may_have_elements_) {
    MAYBE_RETURN(CollectOwnElementIndices(receiver, object), Nothing<bool>());
  }
  MAYBE_RETURN(CollectOwnPropertyNames(receiver, object), Nothing<bool>());
  return Just(true);
}

// static
Handle<FixedArray> KeyAccumulator::GetOwnEnumPropertyKeys(
    Isolate* isolate, DirectHandle<JSObject> object) {
  if (object->HasFastProperties()) {
    return GetFastEnumPropertyKeys(isolate, object);
  } else if (IsJSGlobalObject(*object)) {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        Cast<JSGlobalObject>(*object)->global_dictionary(kAcquireLoad));
  } else if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        object->property_dictionary_swiss());
  } else {
    return GetOwnEnumPropertyDictionaryKeys(
        isolate, KeyCollectionMode::kOwnOnly, nullptr, object,
        object->property_dictionary());
  }
}

namespace {

class NameComparator {
 public:
  explicit NameComparator(Isolate* isolate) : isolate_(isolate) {}

  bool operator()(uint32_t hash1, uint32_t hash2, const Handle<Name>& key1,
                  const Handle<Name>& key2) const {
    return Name::Equals(isolate_, key1, key2);
  }

 private:
  Isolate* isolate_;
};

}  // namespace

// ES6 #sec-proxy-object-internal-methods-and-internal-slots-ownpropertykeys
// Returns |true| on success, |nothing| in case of exception.
Maybe<bool> KeyAccumulator::CollectOwnJSProxyKeys(
    DirectHandle<JSReceiver> receiver, DirectHandle<JSProxy> proxy) {
  STACK_CHECK(isolate_, Nothing<bool>());
  if (filter_ == PRIVATE_NAMES_ONLY) {
    if (V8_ENABLE_SWISS_NAME_DICTIONARY_BOOL) {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(proxy->property_dictionary_swiss(), isolate_), this));
    } else {
      RETURN_NOTHING_IF_NOT_SUCCESSFUL(CollectKeysFromDictionary(
          handle(proxy->property_dictionary(), isolate_), this));
    }
    return Just(true);
  }

  // 1. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate_);
  // 2. If handler is null, throw a TypeError exception.
  // 3. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, isolate_->factory()->ownKeys_string()));
    return Nothing<bool>();
  }
  // 4. Let target be the value of the [[ProxyTarget]] internal slot of O.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate_);
  // 5. Let trap be ? GetMethod(handler, "ownKeys").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap,
      Object::GetMethod(isolate_, Cast<JSReceiver>(handler),
                        isolate_->factory()->ownKeys_string()),
      Nothing<bool>());
  // 6. If trap is undefined, then
  if (IsUndefined(*trap, isolate_)) {
    // 6a. Return target.[[OwnPropertyKeys]]().
    return CollectOwnJSProxyTargetKeys(proxy, target);
  }
  // 7. Let trapResultArray be Call(trap, handler, «target»).
  Handle<Object> trap_result_array;
  Handle<Object> args[] = {target};
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap_result_array,
      Execution::Call(isolate_, trap, handler, arraysize(args), args),
      Nothing<bool>());
  // 8. Let trapResult be ? CreateListFromArrayLike(trapResultArray,
  //    «String, Symbol»).
  Handle<FixedArray> trap_result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, trap_result,
      Object::CreateListFromArrayLike(isolate_, trap_result_array,
                                      ElementTypes::kStringAndSymbol),
      Nothing<bool>());
  // 9. If trapResult contains any duplicate entries, throw a TypeError
  // exception. Combine with step 18
  // 18. Let uncheckedResultKeys be a new List which is a copy of trapResult.
  Zone set_zone(isolate_->allocator(), ZONE_NAME);

  const int kPresent = 1;
  const int kGone = 0;
  using ZoneHashMapImpl =
      base::TemplateHashMapImpl<Handle<Name>, int, NameComparator,
                                ZoneAllocationPolicy>;
  ZoneHashMapImpl unchecked_result_keys(
      ZoneHashMapImpl::kDefaultHashMapCapacity, NameComparator(isolate_),
      ZoneAllocationPolicy(&set_zone));
  int unchecked_result_keys_size = 0;
  for (int i = 0; i < trap_result->length(); ++i) {
    Handle<Name> key(Cast<Name>(trap_result->get(i)), isolate_);
    auto entry = unchecked_result_keys.LookupOrInsert(key, key->EnsureHash());
    if (entry->value != kPresent) {
      entry->value = kPresent;
      unchecked_result_keys_size++;
    } else {
      // found dupes, throw exception
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysDuplicateEntries));
      return Nothing<bool>();
    }
  }
  // 10. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> maybe_extensible = JSReceiver::IsExtensible(isolate_, target);
  MAYBE_RETURN(maybe_extensible, Nothing<bool>());
  bool extensible_target = maybe_extensible.FromJust();
  // 11. Let targetKeys be ? target.[[OwnPropertyKeys]]().
  Handle<FixedArray> target_keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, target_keys, JSReceiver::OwnPropertyKeys(isolate_, target),
      Nothing<bool>());
  // 12, 13. (Assert)
  // 14. Let targetConfigurableKeys be an empty List.
  // To save memory, we're re-using target_keys and will modify it in-place.
  DirectHandle<FixedArray> target_configurable_keys = target_keys;
  // 15. Let targetNonconfigurableKeys be an empty List.
  DirectHandle<FixedArray> target_nonconfigurable_keys =
      isolate_->factory()->NewFixedArray(target_keys->length());
  int nonconfigurable_keys_length = 0;
  // 16. Repeat, for each element key of targetKeys:
  for (int i = 0; i < target_keys->length(); ++i) {
    // 16a. Let desc be ? target.[[GetOwnProperty]](key).
    PropertyDescriptor desc;
    Maybe<bool> found = JSReceiver::GetOwnPropertyDescriptor(
        isolate_, target, handle(target_keys->get(i), isolate_), &desc);
    MAYBE_RETURN(found, Nothing<bool>());
    // 16b. If desc is not undefined and desc.[[Configurable]] is false, then
    if (found.FromJust() && !desc.configurable()) {
      // 16b i. Append key as an element of targetNonconfigurableKeys.
      target_nonconfigurable_keys->set(nonconfigurable_keys_length,
                                       target_keys->get(i));
      nonconfigurable_keys_length++;
      // The key was moved, null it out in the original list.
      target_keys->set(i, Smi::zero());
    } else {
      // 16c. Else,
      // 16c i. Append key as an element of targetConfigurableKeys.
      // (No-op, just keep it in |target_keys|.)
    }
  }
  // 17. If extensibleTarget is true and targetNonconfigurableKeys is empty,
  //     then:
  if (extensible_target && nonconfigurable_keys_length == 0) {
    // 17a. Return trapResult.
    return AddKeysFromJSProxy(proxy, trap_result);
  }
  // 18. (Done in step 9)
  // 19. Repeat, for each key that is an element of targetNonconfigurableKeys:
  for (int i = 0; i < nonconfigurable_keys_length; ++i) {
    Tagged<Object> raw_key = target_nonconfigurable_keys->get(i);
    Handle<Name> key(Cast<Name>(raw_key), isolate_);
    // 19a. If key is not an element of uncheckedResultKeys, throw a
    //      TypeError exception.
    auto found = unchecked_result_keys.Lookup(key, key->hash());
    if (found == nullptr || found->value == kGone) {
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysMissing, key));
      return Nothing<bool>();
    }
    // 19b. Remove key from uncheckedResultKeys.
    found->value = kGone;
    unchecked_result_keys_size--;
  }
  // 20. If extensibleTarget is true, return trapResult.
  if (extensible_target) {
    return AddKeysFromJSProxy(proxy, trap_result);
  }
  // 21. Repeat, for each key that is an element of targetConfigurableKeys:
  for (int i = 0; i < target_configurable_keys->length(); ++i) {
    Tagged<Object> raw_key = target_configurable_keys->get(i);
    if (IsSmi(raw_key)) continue;  // Zapped entry, was nonconfigurable.
    Handle<Name> key(Cast<Name>(raw_key), isolate_);
    // 21a. If key is not an element of uncheckedResultKeys, throw a
    //      TypeError exception.
    auto found = unchecked_result_keys.Lookup(key, key->hash());
    if (found == nullptr || found->value == kGone) {
      isolate_->Throw(*isolate_->factory()->NewTypeError(
          MessageTemplate::kProxyOwnKeysMissing, key));
      return Nothing<bool>();
    }
    // 21b. Remove key from uncheckedResultKeys.
    found->value = kGone;
    unchecked_result_keys_size--;
  }
  // 22. If uncheckedResultKeys is not empty, throw a TypeError exception.
  if (unchecked_result_keys_size != 0) {
    DCHECK_GT(unchecked_result_keys_size, 0);
    isolate_->Throw(*isolate_->factory()->NewTypeError(
        MessageTemplate::kProxyOwnKeysNonExtensible));
    return Nothing<bool>();
  }
  // 23. Return trapResult.
  return AddKeysFromJSProxy(proxy, trap_result);
}

Maybe<bool> KeyAccumulator::CollectOwnJSProxyTargetKeys(
    DirectHandle<JSProxy> proxy, Handle<JSReceiver> target) {
  // TODO(cbruni): avoid creating another KeyAccumulator
  Handle<FixedArray> keys;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate_, keys,
      KeyAccumulator::GetKeys(
          isolate_, target, KeyCollectionMode::kOwnOnly, ALL_PROPERTIES,
          GetKeysConversion::kConvertToString, is_for_in_, skip_indices_),
      Nothing<bool>());
  Maybe<bool> result = AddKeysFromJSProxy(proxy, keys);
  return result;
}

#undef RETURN_NOTHING_IF_NOT_SUCCESSFUL
#undef RETURN_FAILURE_IF_NOT_SUCCESSFUL
}  // namespace v8::internal
```
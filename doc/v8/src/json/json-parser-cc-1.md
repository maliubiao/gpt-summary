Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:**  The code heavily uses terms like `JsonParser`, `JsonProperty`, `JsonObject`, `JsonArray`, `ParseJsonValue`, `BuildJsonObject`, etc. This immediately signals that the primary function of this code is to parse JSON (JavaScript Object Notation) strings.

2. **Break Down into Key Components:** I look for distinct classes and methods that contribute to the overall goal. The code seems to revolve around the `JsonParser` class and supporting structures like `JsonProperty` and `JsonContinuation`. I also notice inner classes like `NamedPropertyValueIterator` and `NamedPropertyIterator`.

3. **Analyze Class Functionality:**

   * **`JSDataObjectBuilder`:** This class seems responsible for efficiently constructing JavaScript objects during parsing. It optimizes for different property types and counts, handling cases like dictionary maps (for sparse objects) and in-object properties (for denser objects). The logic around `HeapNumberMode` hints at optimization related to number representation.

   * **`NamedPropertyValueIterator`:** This is a simple iterator for traversing the values of named properties. It filters out index-based properties, suggesting a distinction between named and indexed properties in the parsed JSON.

   * **`JsonParser::NamedPropertyIterator`:**  This is a more complex iterator associated directly with the `JsonParser`. It iterates through named properties, providing access to keys (with potential hints for optimization) and values. The `RevisitValues` method suggests the need to potentially iterate over the values multiple times.

   * **`JsonParser`:** This is the main class. Its methods like `BuildJsonObject`, `BuildJsonArray`, `ParseJsonValueRecursive`, `ParseJsonObject`, and `ParseJsonArray` clearly indicate the parsing process for different JSON structures. The presence of `ScanJsonString`, `ParseJsonNumber`, and `ScanLiteral` confirms the lexical analysis aspect of parsing. The `TryFastTransitionToPropertyKey` and `TryGeneralizeFieldToValue` methods suggest optimization strategies for object construction based on expected property types and transitions between map layouts.

4. **Infer Functionality from Method Names and Logic:** I examine individual methods to understand their specific roles:

   * **`BuildJsonObject`:**  Handles the creation of JavaScript objects from the parsed properties. It decides whether to use slow (dictionary) or fast (in-object) properties based on efficiency. The `JSDataObjectBuilder` is used here.
   * **`BuildJsonArray`:**  Creates JavaScript arrays, optimizing for different element types (SMI, double, generic objects).
   * **`ParseJsonValueRecursive`:** A recursive function (or iterative equivalent using a stack) that handles parsing of any valid JSON value (object, array, primitive).
   * **`ParseJsonObject`:** Specifically parses JSON objects, handling property keys and values.
   * **`ParseJsonArray`:** Parses JSON arrays, processing elements.
   * **`ParseRawJson`:**  Seems to handle parsing a "raw" JSON value, likely without the surrounding object or array structure.
   * **Methods involving `expected_final_map_`:** This suggests an optimization technique where the parser tries to predict the final shape (map) of the object to be created, potentially speeding up property addition.

5. **Connect to JavaScript Functionality:**  Since this is V8 source code, it directly relates to how JavaScript's built-in `JSON.parse()` function works. I can illustrate the C++ code's actions with equivalent JavaScript:

   * Parsing `"{\"a\": 1}"` in JavaScript corresponds to the `ParseJsonObject` and `BuildJsonObject` functions in the C++ code.
   * Parsing `"[1, 2]"` maps to `ParseJsonArray` and `BuildJsonArray`.
   * The optimization techniques in the C++ code (like predicting the final map) aim to make `JSON.parse()` faster.

6. **Identify Potential Errors:**  Based on the parsing logic, I can deduce common user errors:

   * **Syntax Errors:**  Missing commas, colons, incorrect brackets/braces will be caught by the `Expect` and `ExpectNext` methods, leading to `SyntaxError` exceptions (like the "expected comma or RBRACE" messages).
   * **Invalid JSON:**  Trying to parse non-JSON strings will fail at the tokenization or parsing stages.
   * **Stack Overflow:** The recursive nature of parsing nested objects/arrays could potentially lead to stack overflow errors for very deeply nested JSON, which the `StackLimitCheck` tries to mitigate (and falls back to a non-recursive parse).

7. **Consider `.tq` Extension:** The mention of `.tq` (Torque) suggests that some parts of the JSON parsing might be implemented using V8's Torque language, a higher-level language for implementing V8 internals. If this file *were* a `.tq` file, it would indicate a more high-level, potentially more readable (though still V8-specific) implementation of the parsing logic. The current `.cc` extension means it's standard C++.

8. **Summarize Functionality:** Finally, I synthesize the gathered information into a concise summary, highlighting the core purpose, key functionalities, and optimizations.

By following these steps, I can effectively analyze the given C++ code snippet and understand its role in V8's JSON parsing implementation. The focus is on understanding the *what* and *why* of the code, rather than getting bogged down in the minute details of every line.
这是v8/src/json/json-parser.cc的第二部分代码，延续了第一部分的功能，主要负责**构建解析后的JSON数据结构**，包括JavaScript对象和数组，并进行了一些优化。

让我们来归纳一下这部分代码的功能：

**核心功能：构建 JavaScript 对象和数组**

这部分代码的核心职责是根据解析器在之前的阶段识别出的 JSON 结构（例如，键值对，数组元素），最终构建出 V8 可以使用的 JavaScript 对象 (`JSObject`) 和数组 (`JSArray`)。

**关键类和方法：**

* **`JSDataObjectBuilder`:**  这是一个辅助类，用于高效地构建 JavaScript 对象。它处理了对象属性的添加，并考虑了不同的存储方式（例如，快速属性、慢速属性，也称为字典模式），以优化内存使用和访问速度。它还处理了在对象创建过程中可能需要的堆数字的分配。
* **`NamedPropertyValueIterator`:**  一个迭代器，用于遍历 JSON 对象中的命名属性的键值对。
* **`JsonParser::NamedPropertyIterator`:**  `JsonParser` 类内部的迭代器，用于遍历 JSON 对象中的命名属性，提供了获取键的字符表示、`Handle<String>` 对象和值的功能。
* **`JsonParser::BuildJsonObject`:**  负责根据解析到的属性信息构建 `JSObject`。它会根据属性的数量和类型选择合适的元素种类（例如，`HOLEY_ELEMENTS`，`DICTIONARY_ELEMENTS`），并使用 `JSDataObjectBuilder` 来高效地创建对象。它还处理了当 JSON 中存在索引属性（数组元素形式的属性名）时，将其作为数组元素存储。
* **`JsonParser::BuildJsonArray`:**  负责根据解析到的元素构建 `JSArray`。它会根据元素的类型选择合适的元素种类（例如，`PACKED_SMI_ELEMENTS`，`PACKED_DOUBLE_ELEMENTS`，`PACKED_ELEMENTS`），并创建相应的数组。
* **`JsonParser::ParseRawJson`:**  用于解析“原始”的 JSON 值，这可能是指不包含在对象或数组中的独立 JSON 值（例如，单独的字符串、数字等）。
* **`JsonParser::ParseJsonValueRecursive`:**  一个递归函数，用于解析各种 JSON 值（对象、数组、基本类型）。
* **`JsonParser::ParseJsonObject`:**  专门用于解析 JSON 对象，处理花括号 `{}` 和内部的键值对。
* **`JsonParser::ParseJsonArray`:**  专门用于解析 JSON 数组，处理方括号 `[]` 和内部的元素。
* **`JsonParser::ParseJsonValue`:**  作为入口点，解析任何可能的 JSON 值，并使用了状态机的方式（通过 `cont_stack` 和 `JsonContinuation`）来处理嵌套的 JSON 结构。

**优化：**

* **`JSDataObjectBuilder` 的快速属性路径:**  代码中大量使用了 `JSDataObjectBuilder`，这表明 V8 尝试以最高效的方式创建对象，优先使用快速属性。
* **预期最终 Map (Expected Final Map):** 代码中出现了 `expected_final_map_` 成员变量和相关逻辑。这是一种优化策略，V8 尝试预测最终对象的 Map (对象的结构信息)，并尝试直接过渡到这个 Map，避免多次 Map 转换，从而提高性能。
* **根据元素类型选择数组元素种类:**  `BuildJsonArray` 会根据解析到的元素类型选择最合适的数组元素种类，例如，如果所有元素都是小的整数，则使用 `PACKED_SMI_ELEMENTS`，这样可以节省内存和提高访问速度。
* **慢速元素（字典模式）的转换:**  `BuildJsonObject` 中判断是否使用 `DICTIONARY_ELEMENTS` 来存储元素，这用于处理稀疏数组或包含大量非数字键的对象。

**与 JavaScript 的关系（`JSON.parse()`）:**

这段 C++ 代码是 V8 引擎实现 `JSON.parse()` 功能的核心部分。当你调用 JavaScript 中的 `JSON.parse()` 函数时，V8 内部就会使用类似的逻辑来解析 JSON 字符串并创建对应的 JavaScript 对象或数组。

**JavaScript 示例:**

```javascript
const jsonString = '{"name": "John", "age": 30, "city": "New York", "hobbies": ["reading", "coding"]}';
const parsedObject = JSON.parse(jsonString);

console.log(parsedObject.name); // 输出 "John"
console.log(parsedObject.hobbies[0]); // 输出 "reading"

const jsonArrayString = '[1, "hello", true, null]';
const parsedArray = JSON.parse(jsonArrayString);

console.log(parsedArray[1]); // 输出 "hello"
```

这段 C++ 代码的核心功能就是将类似 `jsonString` 和 `jsonArrayString` 这样的 JSON 字符串转换为 JavaScript 中可操作的 `parsedObject` 和 `parsedArray`。

**代码逻辑推理 (假设输入与输出):**

**假设输入:**  一个简单的 JSON 对象字符串: `"{"a": 1, "b": "hello"}"`

**代码逻辑推理:**

1. **`ParseJsonValue` 或 `ParseJsonObject` 被调用。**
2. **解析器识别出左花括号 `{`，进入对象解析状态。**
3. **解析器识别出字符串 "a"，作为属性名。**
4. **解析器识别出冒号 `:`。**
5. **`ParseJsonValueRecursive` 被调用来解析属性值。**
6. **解析器识别出数字 `1`。**
7. **`property_stack_` 存储属性名 "a" 和值 1。**
8. **解析器识别出逗号 `,`。**
9. **解析器识别出字符串 "b"，作为属性名。**
10. **解析器识别出冒号 `:`。**
11. **`ParseJsonValueRecursive` 被调用来解析属性值。**
12. **解析器识别出字符串 "hello"。**
13. **`property_stack_` 存储属性名 "b" 和值 "hello"。**
14. **解析器识别出右花括号 `}`。**
15. **`BuildJsonObject` 被调用，根据 `property_stack_` 中的信息构建 `JSObject`。**
16. **`JSDataObjectBuilder` 被用来创建对象，添加属性 "a" 和 "b"。**

**假设输出:** 一个 V8 的 `JSObject`，其内部表示类似于 JavaScript 中的 `{ a: 1, b: "hello" }`。

**用户常见的编程错误:**

* **JSON 格式错误:**  这是最常见的错误。例如：
    * **缺少引号:**  `{ a: 1 }` (应该是 `{"a": 1}`)
    * **缺少逗号或冒号:** `{"a": 1 "b": 2}` (应该是 `{"a": 1, "b": 2}`) 或 `{"a" 1}` (应该是 `{"a": 1}`)
    * **结尾多余的逗号:** `{"a": 1,}`
    * **不匹配的括号:** `{"a": [1,}`
* **尝试解析非 JSON 字符串:**  将任意字符串传递给 `JSON.parse()` 而不是有效的 JSON 字符串。
* **超出堆栈限制的深层嵌套:**  虽然 V8 有保护措施，但解析非常深层嵌套的 JSON 结构理论上可能导致堆栈溢出。

**总结:**

这部分 `v8/src/json/json-parser.cc` 代码是 V8 引擎中负责将解析后的 JSON 数据转换为实际 JavaScript 对象和数组的关键组件。它使用了多种优化技术来提高性能，并且直接关联着 JavaScript 中常用的 `JSON.parse()` 功能。理解这部分代码有助于深入理解 V8 引擎如何高效地处理 JSON 数据。

Prompt: 
```
这是目录为v8/src/json/json-parser.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/json/json-parser.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
N);
    Handle<Map> next_map;
    if (!maybe_map.ToHandle(&next_map)) return false;
    if (next_map->is_dictionary_map()) return false;

    map_ = next_map;
    if (representation.IsDouble()) {
      RegisterFieldNeedsFreshHeapNumber(value);
    }
    AdvanceToNextProperty();
    return true;
  }

  template <typename ValueIterator>
  V8_INLINE void CreateAndInitialiseObject(
      ValueIterator value_it, DirectHandle<FixedArrayBase> elements) {
    // We've created a map for the first `i` property stack values (which might
    // be all of them). We need to write these properties to a newly allocated
    // object.
    DCHECK(object_.is_null());

    if (current_property_index_ < property_count_in_expected_final_map_) {
      // If we were on the expected map fast path all the way, but never reached
      // the expected final map itself, then finalize the map by rewinding to
      // the one whose property is the actual current property index.
      //
      // TODO(leszeks): Do we actually want to use the final map fast path when
      // we know that the current map _can't_ reach the final map? Will we even
      // hit this case given that we check for matching instance size?
      RewindExpectedFinalMapFastPathToBeforeCurrent();
    }

    if (map_->is_dictionary_map()) {
      // It's only safe to emit a dictionary map when we've not set up any
      // properties, as the caller assumes it can set up the first N properties
      // as fast data properties.
      DCHECK_EQ(current_property_index_, 0);

      Handle<JSObject> object = isolate_->factory()->NewSlowJSObjectFromMap(
          map_, expected_property_count_);
      object->set_elements(*elements);
      object_ = object;
      return;
    }

    // The map should have as many own descriptors as the number of properties
    // we've created so far...
    DCHECK_EQ(current_property_index_, map_->NumberOfOwnDescriptors());

    // ... and all of those properties should be in-object data properties.
    DCHECK_EQ(current_property_index_,
              map_->GetInObjectProperties() - map_->UnusedInObjectProperties());

    // Create a folded mutable HeapNumber allocation area before allocating the
    // object -- this ensures that there is no allocation between the object
    // allocation and its initial fields being initialised, where the verifier
    // would see invalid double field state.
    FoldedMutableHeapNumberAllocation hn_allocation(isolate_,
                                                    extra_heap_numbers_needed_);

    // Allocate the object then immediately start a no_gc scope -- again, this
    // is so the verifier doesn't see invalid double field state.
    Handle<JSObject> object = isolate_->factory()->NewJSObjectFromMap(map_);
    DisallowGarbageCollection no_gc;
    Tagged<JSObject> raw_object = *object;

    raw_object->set_elements(*elements);
    Tagged<DescriptorArray> descriptors =
        raw_object->map()->instance_descriptors();

    WriteBarrierMode mode = raw_object->GetWriteBarrierMode(no_gc);
    FoldedMutableHeapNumberAllocator hn_allocator(isolate_, &hn_allocation,
                                                  no_gc);

    ReadOnlyRoots roots(isolate_);

    // Initialize the in-object properties up to the last added property.
    int current_property_offset = raw_object->GetInObjectPropertyOffset(0);
    for (int i = 0; i < current_property_index_; ++i, ++value_it) {
      InternalIndex descriptor_index(i);
      Tagged<Object> value = **value_it;

      // See comment in RegisterFieldNeedsFreshHeapNumber, we need to allocate
      // HeapNumbers for double representation fields when we can't make
      // existing HeapNumbers mutable, or when we only have a Smi value.
      if (heap_number_mode_ != kHeapNumbersGuaranteedUniquelyOwned ||
          IsSmi(value)) {
        PropertyDetails details = descriptors->GetDetails(descriptor_index);
        if (details.representation().IsDouble()) {
          value = hn_allocator.AllocateNext(
              roots, Float64(Object::NumberValue(value)));
        }
      }

      DCHECK(FieldIndex::ForPropertyIndex(object->map(), i).is_inobject());
      DCHECK_EQ(current_property_offset,
                FieldIndex::ForPropertyIndex(object->map(), i).offset());
      DCHECK_EQ(current_property_offset,
                object->map()->GetInObjectPropertyOffset(i));
      FieldIndex index = FieldIndex::ForInObjectOffset(current_property_offset,
                                                       FieldIndex::kTagged);
      raw_object->RawFastInobjectPropertyAtPut(index, value, mode);
      current_property_offset += kTaggedSize;
    }
    DCHECK_EQ(current_property_offset, object->map()->GetInObjectPropertyOffset(
                                           current_property_index_));

    object_ = object;
  }

  void AddSlowProperty(Handle<String> key, Handle<Object> value) {
    DCHECK(!object_.is_null());

    LookupIterator it(isolate_, object_, key, object_, LookupIterator::OWN);
    JSObject::DefineOwnPropertyIgnoreAttributes(&it, value, NONE).Check();
  }

  Handle<JSObject> object() {
    DCHECK(!object_.is_null());
    return object_;
  }

 private:
  template <typename Char, typename GetKeyFunction>
  V8_INLINE bool TryFastTransitionToPropertyKey(
      base::Vector<const Char> key_chars, GetKeyFunction&& get_key,
      Handle<String>* key_out) {
    Handle<String> expected_key;
    Handle<Map> target_map;

    InternalIndex descriptor_index(current_property_index_);
    if (IsOnExpectedFinalMapFastPath()) {
      expected_key = handle(
          Cast<String>(
              expected_final_map_->instance_descriptors(isolate_)->GetKey(
                  descriptor_index)),
          isolate_);
      target_map = expected_final_map_;
    } else {
      TransitionsAccessor transitions(isolate_, *map_);
      auto expected_transition = transitions.ExpectedTransition(key_chars);
      if (!expected_transition.first.is_null()) {
        // Directly read out the target while reading out the key, otherwise it
        // might die if `get_key` can allocate.
        target_map = expected_transition.second;

        // We were successful and we are done.
        DCHECK_EQ(target_map->instance_descriptors()
                      ->GetDetails(descriptor_index)
                      .location(),
                  PropertyLocation::kField);
        map_ = target_map;
        return true;
      }
    }

    Handle<String> key = *key_out = get_key(expected_key);
    if (key.is_identical_to(expected_key)) {
      // We were successful and we are done.
      DCHECK_EQ(target_map->instance_descriptors()
                    ->GetDetails(descriptor_index)
                    .location(),
                PropertyLocation::kField);
      map_ = target_map;
      return true;
    }

    if (IsOnExpectedFinalMapFastPath()) {
      // We were on the expected map fast path, but this missed that fast
      // path, so rewind the optimistic setting of the current map and disable
      // this fast path.
      RewindExpectedFinalMapFastPathToBeforeCurrent();
      property_count_in_expected_final_map_ = 0;
    }

    MaybeHandle<Map> maybe_target =
        TransitionsAccessor(isolate_, *map_).FindTransitionToField(key);
    if (!maybe_target.ToHandle(&target_map)) return false;

    map_ = target_map;
    return true;
  }

  V8_INLINE bool TryGeneralizeFieldToValue(DirectHandle<Object> value) {
    DCHECK_LT(current_property_index_, map_->NumberOfOwnDescriptors());

    InternalIndex descriptor_index(current_property_index_);
    PropertyDetails current_details =
        map_->instance_descriptors(isolate_)->GetDetails(descriptor_index);
    Representation expected_representation = current_details.representation();

    DCHECK_EQ(current_details.kind(), PropertyKind::kData);
    DCHECK_EQ(current_details.location(), PropertyLocation::kField);

    if (!Object::FitsRepresentation(*value, expected_representation)) {
      Representation representation =
          Object::OptimalRepresentation(*value, isolate_);
      representation = representation.generalize(expected_representation);
      if (!expected_representation.CanBeInPlaceChangedTo(representation)) {
        // Reconfigure the map for the value, deprecating if necessary. This
        // will only happen for double representation fields.
        if (IsOnExpectedFinalMapFastPath()) {
          // If we're on the fast path, we will have advanced the current map
          // all the way to the final expected map. Make sure to rewind to the
          // "real" current map if this happened.
          //
          // An alternative would be to deprecate the expected final map,
          // migrate it to the new representation, and stay on the fast path.
          // However, this would mean allocating all-new maps (with the new
          // representation) all the way between the current map and the new
          // expected final map; if we later fall off the fast path anyway, then
          // all those newly allocated maps will end up unused.
          RewindExpectedFinalMapFastPathToIncludeCurrent();
          property_count_in_expected_final_map_ = 0;
        }
        MapUpdater mu(isolate_, map_);
        Handle<Map> new_map = mu.ReconfigureToDataField(
            descriptor_index, current_details.attributes(),
            current_details.constness(), representation,
            FieldType::Any(isolate_));

        // We only want to stay on the fast path if we got a fast map.
        if (new_map->is_dictionary_map()) return false;
        map_ = new_map;
        DCHECK(representation.IsDouble());
        RegisterFieldNeedsFreshHeapNumber(value);
      } else {
        // Do the in-place reconfiguration.
        DCHECK(!representation.IsDouble());
        Handle<FieldType> value_type =
            Object::OptimalType(*value, isolate_, representation);
        MapUpdater::GeneralizeField(isolate_, map_, descriptor_index,
                                    current_details.constness(), representation,
                                    value_type);
      }
    } else if (expected_representation.IsHeapObject() &&
               !FieldType::NowContains(
                   map_->instance_descriptors(isolate_)->GetFieldType(
                       descriptor_index),
                   value)) {
      Handle<FieldType> value_type =
          Object::OptimalType(*value, isolate_, expected_representation);
      MapUpdater::GeneralizeField(isolate_, map_, descriptor_index,
                                  current_details.constness(),
                                  expected_representation, value_type);
    } else if (expected_representation.IsDouble()) {
      RegisterFieldNeedsFreshHeapNumber(value);
    }

    DCHECK(FieldType::NowContains(
        map_->instance_descriptors(isolate_)->GetFieldType(descriptor_index),
        value));
    return true;
  }

  bool TryInitializeMapFromExpectedFinalMap() {
    if (expected_final_map_.is_null()) return false;
    if (expected_final_map_->elements_kind() != elements_kind_) return false;

    int property_count_in_expected_final_map =
        expected_final_map_->NumberOfOwnDescriptors();
    if (property_count_in_expected_final_map < expected_property_count_)
      return false;

    map_ = expected_final_map_;
    property_count_in_expected_final_map_ =
        property_count_in_expected_final_map;
    return true;
  }

  void InitializeMapFromZero() {
    // Must be called before any properties are registered.
    DCHECK_EQ(current_property_index_, 0);

    map_ = isolate_->factory()->ObjectLiteralMapFromCache(
        isolate_->native_context(), expected_property_count_);
    if (elements_kind_ == DICTIONARY_ELEMENTS) {
      map_ = Map::AsElementsKind(isolate_, map_, elements_kind_);
    } else {
      DCHECK_EQ(map_->elements_kind(), elements_kind_);
    }
  }

  V8_INLINE bool IsOnExpectedFinalMapFastPath() const {
    DCHECK_IMPLIES(property_count_in_expected_final_map_ > 0,
                   !expected_final_map_.is_null());
    return current_property_index_ < property_count_in_expected_final_map_;
  }

  void RewindExpectedFinalMapFastPathToBeforeCurrent() {
    DCHECK_GT(property_count_in_expected_final_map_, 0);
    if (current_property_index_ == 0) {
      InitializeMapFromZero();
      DCHECK_EQ(0, map_->NumberOfOwnDescriptors());
    }
    if (current_property_index_ == 0) {
      return;
    }
    DCHECK_EQ(*map_, *expected_final_map_);
    map_ = handle(map_->FindFieldOwner(
                      isolate_, InternalIndex(current_property_index_ - 1)),
                  isolate_);
  }

  void RewindExpectedFinalMapFastPathToIncludeCurrent() {
    DCHECK_EQ(*map_, *expected_final_map_);
    map_ = handle(expected_final_map_->FindFieldOwner(
                      isolate_, InternalIndex(current_property_index_)),
                  isolate_);
  }

  V8_INLINE void RegisterFieldNeedsFreshHeapNumber(DirectHandle<Object> value) {
    // We need to allocate a new HeapNumber for double representation fields if
    // the HeapNumber values is not guaranteed to be uniquely owned by this
    // object (and therefore can't be made mutable), or if the value is a Smi
    // and there is no HeapNumber box for this value yet at all.
    if (heap_number_mode_ == kHeapNumbersGuaranteedUniquelyOwned &&
        !IsSmi(*value)) {
      DCHECK(IsHeapNumber(*value));
      return;
    }
    extra_heap_numbers_needed_++;
  }

  V8_INLINE void AdvanceToNextProperty() { current_property_index_++; }

  Isolate* isolate_;
  ElementsKind elements_kind_;
  int expected_property_count_;
  HeapNumberMode heap_number_mode_;

  Handle<Map> map_;
  int current_property_index_ = 0;
  int extra_heap_numbers_needed_ = 0;

  Handle<JSObject> object_;

  Handle<Map> expected_final_map_ = {};
  int property_count_in_expected_final_map_ = 0;
};

class NamedPropertyValueIterator {
 public:
  NamedPropertyValueIterator(const JsonProperty* it, const JsonProperty* end)
      : it_(it), end_(end) {
    DCHECK_LE(it_, end_);
    DCHECK_IMPLIES(it_ != end_, !it_->string.is_index());
  }

  NamedPropertyValueIterator& operator++() {
    DCHECK_LT(it_, end_);
    do {
      it_++;
    } while (it_ != end_ && it_->string.is_index());
    return *this;
  }

  Handle<Object> operator*() { return it_->value; }

  bool operator!=(const NamedPropertyValueIterator& other) const {
    return it_ != other.it_;
  }

 private:
  // We need to store both the current iterator and the iterator end, since we
  // don't want to iterate past the end on operator++ if the last property is an
  // index property.
  const JsonProperty* it_;
  const JsonProperty* end_;
};

template <typename Char>
class JsonParser<Char>::NamedPropertyIterator {
 public:
  NamedPropertyIterator(JsonParser<Char>& parser, const JsonProperty* it,
                        const JsonProperty* end)
      : parser_(parser), it_(it), end_(end) {
    DCHECK_LE(it_, end_);
    while (it_ != end_ && it_->string.is_index()) {
      it_++;
    }
    start_ = it_;
  }

  void Advance() {
    DCHECK_LT(it_, end_);
    do {
      it_++;
    } while (it_ != end_ && it_->string.is_index());
  }

  bool Done() const {
    DCHECK_LE(it_, end_);
    return it_ == end_;
  }

  base::Vector<const Char> GetKeyChars() {
    return parser_.GetKeyChars(it_->string);
  }
  Handle<String> GetKey(Handle<String> expected_key_hint) {
    return parser_.MakeString(it_->string, expected_key_hint);
  }
  Handle<Object> GetValue(bool will_revisit_value) {
    // Revisiting values is free, so we don't need to cache the value anywhere.
    return it_->value;
  }
  NamedPropertyValueIterator RevisitValues() {
    return NamedPropertyValueIterator(start_, it_);
  }

 private:
  JsonParser<Char>& parser_;

  const JsonProperty* start_;
  const JsonProperty* it_;
  const JsonProperty* end_;
};

template <typename Char>
template <bool should_track_json_source>
Handle<JSObject> JsonParser<Char>::BuildJsonObject(const JsonContinuation& cont,
                                                   Handle<Map> feedback) {
  if (!feedback.is_null() && feedback->is_deprecated()) {
    feedback = Map::Update(isolate_, feedback);
  }
  size_t start = cont.index;
  DCHECK_LE(start, property_stack_.size());
  int length = static_cast<int>(property_stack_.size() - start);
  int named_length = length - cont.elements;
  DCHECK_LE(0, named_length);

  Handle<FixedArrayBase> elements;
  ElementsKind elements_kind = HOLEY_ELEMENTS;

  // First store the elements.
  if (cont.elements > 0) {
    // Store as dictionary elements if that would use less memory.
    if (ShouldConvertToSlowElements(cont.elements, cont.max_index + 1)) {
      Handle<NumberDictionary> elms =
          NumberDictionary::New(isolate_, cont.elements);
      for (int i = 0; i < length; i++) {
        const JsonProperty& property = property_stack_[start + i];
        if (!property.string.is_index()) continue;
        uint32_t index = property.string.index();
        Handle<Object> value = property.value;
        NumberDictionary::UncheckedSet(isolate_, elms, index, value);
      }
      elms->SetInitialNumberOfElements(cont.elements);
      elms->UpdateMaxNumberKey(cont.max_index, Handle<JSObject>::null());
      elements_kind = DICTIONARY_ELEMENTS;
      elements = elms;
    } else {
      Handle<FixedArray> elms =
          factory()->NewFixedArrayWithHoles(cont.max_index + 1);
      DisallowGarbageCollection no_gc;
      Tagged<FixedArray> raw_elements = *elms;
      WriteBarrierMode mode = raw_elements->GetWriteBarrierMode(no_gc);

      for (int i = 0; i < length; i++) {
        const JsonProperty& property = property_stack_[start + i];
        if (!property.string.is_index()) continue;
        uint32_t index = property.string.index();
        DirectHandle<Object> value = property.value;
        raw_elements->set(static_cast<int>(index), *value, mode);
      }
      elements = elms;
    }
  } else {
    elements = factory()->empty_fixed_array();
  }

  // When tracking JSON source with a reviver, do not use mutable HeapNumbers.
  // In this mode, values are snapshotted at the beginning because the source is
  // only passed to the reviver if the reviver does not muck with the original
  // value. Mutable HeapNumbers would make the snapshot incorrect.
  JSDataObjectBuilder js_data_object_builder(
      isolate_, elements_kind, named_length, feedback,
      should_track_json_source
          ? JSDataObjectBuilder::kNormalHeapNumbers
          : JSDataObjectBuilder::kHeapNumbersGuaranteedUniquelyOwned);

  NamedPropertyIterator it(*this, property_stack_.begin() + start,
                           property_stack_.end());

  return js_data_object_builder.BuildFromIterator(it, elements);
}

template <typename Char>
Handle<Object> JsonParser<Char>::BuildJsonArray(size_t start) {
  int length = static_cast<int>(element_stack_.size() - start);

  ElementsKind kind = PACKED_SMI_ELEMENTS;
  for (size_t i = start; i < element_stack_.size(); i++) {
    Tagged<Object> value = *element_stack_[i];
    if (IsHeapObject(value)) {
      if (IsHeapNumber(Cast<HeapObject>(value))) {
        kind = PACKED_DOUBLE_ELEMENTS;
      } else {
        kind = PACKED_ELEMENTS;
        break;
      }
    }
  }

  Handle<JSArray> array = factory()->NewJSArray(kind, length, length);
  if (kind == PACKED_DOUBLE_ELEMENTS) {
    DisallowGarbageCollection no_gc;
    Tagged<FixedDoubleArray> elements =
        Cast<FixedDoubleArray>(array->elements());
    for (int i = 0; i < length; i++) {
      elements->set(i, Object::NumberValue(*element_stack_[start + i]));
    }
  } else {
    DisallowGarbageCollection no_gc;
    Tagged<FixedArray> elements = Cast<FixedArray>(array->elements());
    WriteBarrierMode mode = kind == PACKED_SMI_ELEMENTS
                                ? SKIP_WRITE_BARRIER
                                : elements->GetWriteBarrierMode(no_gc);
    for (int i = 0; i < length; i++) {
      elements->set(i, *element_stack_[start + i], mode);
    }
  }
  return array;
}

// Parse rawJSON value.
template <typename Char>
bool JsonParser<Char>::ParseRawJson() {
  if (end_ == cursor_) {
    isolate_->Throw(*isolate_->factory()->NewSyntaxError(
        MessageTemplate::kInvalidRawJsonValue));
    return false;
  }
  next_ = GetTokenForCharacter(*cursor_);
  switch (peek()) {
    case JsonToken::STRING:
      Consume(JsonToken::STRING);
      ScanJsonString(false);
      break;

    case JsonToken::NUMBER:
      ParseJsonNumber();
      break;

    case JsonToken::TRUE_LITERAL:
      ScanLiteral("true");
      break;

    case JsonToken::FALSE_LITERAL:
      ScanLiteral("false");
      break;

    case JsonToken::NULL_LITERAL:
      ScanLiteral("null");
      break;

    default:
      ReportUnexpectedCharacter(CurrentCharacter());
      return false;
  }
  if (isolate_->has_exception()) return false;
  if (cursor_ != end_) {
    isolate_->Throw(*isolate_->factory()->NewSyntaxError(
        MessageTemplate::kInvalidRawJsonValue));
    return false;
  }
  return true;
}

template <typename Char>
V8_INLINE MaybeHandle<Object> JsonParser<Char>::ParseJsonValueRecursive(
    Handle<Map> feedback) {
  SkipWhitespace();
  switch (peek()) {
    case JsonToken::NUMBER:
      return ParseJsonNumber();
    case JsonToken::STRING:
      Consume(JsonToken::STRING);
      return MakeString(ScanJsonString(false));

    case JsonToken::TRUE_LITERAL:
      ScanLiteral("true");
      return factory()->true_value();
    case JsonToken::FALSE_LITERAL:
      ScanLiteral("false");
      return factory()->false_value();
    case JsonToken::NULL_LITERAL:
      ScanLiteral("null");
      return factory()->null_value();

    case JsonToken::LBRACE:
      return ParseJsonObject(feedback);
    case JsonToken::LBRACK:
      return ParseJsonArray();

    case JsonToken::COLON:
    case JsonToken::COMMA:
    case JsonToken::ILLEGAL:
    case JsonToken::RBRACE:
    case JsonToken::RBRACK:
    case JsonToken::EOS:
      ReportUnexpectedCharacter(CurrentCharacter());
      // Pop the continuation stack to correctly tear down handle scopes.
      return MaybeHandle<Object>();

    case JsonToken::WHITESPACE:
      UNREACHABLE();
  }
}

template <typename Char>
MaybeHandle<Object> JsonParser<Char>::ParseJsonObject(Handle<Map> feedback) {
  {
    StackLimitCheck check(isolate_);
    if (V8_UNLIKELY(check.HasOverflowed())) {
      return ParseJsonValue<false>();
    }
  }

  Consume(JsonToken::LBRACE);
  if (Check(JsonToken::RBRACE)) {
    return factory()->NewJSObject(object_constructor_);
  }

  JsonContinuation cont(isolate_, JsonContinuation::kObjectProperty,
                        property_stack_.size());
  bool first = true;
  do {
    ExpectNext(
        JsonToken::STRING,
        first ? MessageTemplate::kJsonParseExpectedPropNameOrRBrace
              : MessageTemplate::kJsonParseExpectedDoubleQuotedPropertyName);
    JsonString key = ScanJsonPropertyKey(&cont);
    ExpectNext(JsonToken::COLON,
               MessageTemplate::kJsonParseExpectedColonAfterPropertyName);
    Handle<Object> value;
    if (V8_UNLIKELY(!ParseJsonValueRecursive().ToHandle(&value))) return {};
    property_stack_.emplace_back(key, value);
    first = false;
  } while (Check(JsonToken::COMMA));

  Expect(JsonToken::RBRACE, MessageTemplate::kJsonParseExpectedCommaOrRBrace);
  Handle<Object> result = BuildJsonObject<false>(cont, feedback);
  property_stack_.resize_no_init(cont.index);
  return cont.scope.CloseAndEscape(result);
}

template <typename Char>
MaybeHandle<Object> JsonParser<Char>::ParseJsonArray() {
  {
    StackLimitCheck check(isolate_);
    if (V8_UNLIKELY(check.HasOverflowed())) {
      return ParseJsonValue<false>();
    }
  }

  Consume(JsonToken::LBRACK);
  if (Check(JsonToken::RBRACK)) {
    return factory()->NewJSArray(0, PACKED_SMI_ELEMENTS);
  }

  HandleScope handle_scope(isolate_);
  size_t start = element_stack_.size();
  Handle<Object> value;
  if (V8_UNLIKELY(!ParseJsonValueRecursive().ToHandle(&value))) return {};
  element_stack_.emplace_back(value);
  while (Check(JsonToken::COMMA)) {
    Handle<Map> feedback;
    if (IsJSObject(*value)) {
      Tagged<Map> maybe_feedback = Cast<JSObject>(*value)->map();
      // Don't consume feedback from objects with a map that's detached
      // from the transition tree.
      if (!maybe_feedback->IsDetached(isolate_)) {
        feedback = handle(maybe_feedback, isolate_);
      }
    }
    if (V8_UNLIKELY(!ParseJsonValueRecursive(feedback).ToHandle(&value))) {
      return {};
    }
    element_stack_.emplace_back(value);
  }

  Expect(JsonToken::RBRACK, MessageTemplate::kJsonParseExpectedCommaOrRBrack);
  Handle<Object> result = BuildJsonArray(start);
  element_stack_.resize_no_init(start);
  return handle_scope.CloseAndEscape(result);
}

// Parse any JSON value.
template <typename Char>
template <bool should_track_json_source>
MaybeHandle<Object> JsonParser<Char>::ParseJsonValue() {
  std::vector<JsonContinuation> cont_stack;

  cont_stack.reserve(16);

  JsonContinuation cont(isolate_, JsonContinuation::kReturn, 0);

  Handle<Object> value;

  // When should_track_json_source is true, we use val_node to record current
  // JSON value's parse node.
  //
  // For primitive values, the val_node is the source string of the JSON value.
  //
  // For JSObject values, the val_node is an ObjectHashTable in which the key is
  // the property name and the first value is the property value's parse
  // node. The order in which properties are defined may be different from the
  // order in which properties are enumerated when calling
  // InternalizeJSONProperty for the JSObject value. E.g., the JSON source
  // string is '{"a": 1, "1": 2}', and the properties enumerate order is ["1",
  // "a"]. Moreover, properties may be defined repeatedly in the JSON string.
  // E.g., the JSON string is '{"a": 1, "a": 1}', and the properties enumerate
  // order is ["a"]. So we cannot use the FixedArray to record the properties's
  // parse node by the order in which properties are defined and we use a
  // ObjectHashTable here to record the property name and the property's parse
  // node. We then look up the property's parse node by the property name when
  // calling InternalizeJSONProperty. The second value associated with the key
  // is the property value's snapshot.
  //
  // For JSArray values, the val_node is a FixedArray containing the parse nodes
  // and snapshots of the elements.
  //
  // For information about snapshotting, see below.
  Handle<Object> val_node;
  // Record the start position and end position for the primitive values.
  int start_position;
  int end_position;

  // Workaround for -Wunused-but-set-variable on old gcc versions (version < 8).
  USE(start_position);
  USE(end_position);

  // element_val_node_stack is used to track all the elements's
  // parse nodes. And we use this to construct the JSArray's
  // parse node and value snapshot.
  SmallVector<Handle<Object>> element_val_node_stack;
  // property_val_node_stack is used to track all the property
  // value's parse nodes. And we use this to construct the
  // JSObject's parse node and value snapshot.
  SmallVector<Handle<Object>> property_val_node_stack;
  while (true) {
    // Produce a json value.
    //
    // Iterate until a value is produced. Starting but not immediately finishing
    // objects and arrays will cause the loop to continue until a first member
    // is completed.
    while (true) {
      SkipWhitespace();
      // The switch is immediately followed by 'break' so we can use 'break' to
      // break out of the loop, and 'continue' to continue the loop.

      if constexpr (should_track_json_source) {
        start_position = position();
      }
      switch (peek()) {
        case JsonToken::STRING:
          Consume(JsonToken::STRING);
          value = MakeString(ScanJsonString(false));
          if constexpr (should_track_json_source) {
            end_position = position();
            val_node = isolate_->factory()->NewSubString(
                source_, start_position, end_position);
          }
          break;

        case JsonToken::NUMBER:
          value = ParseJsonNumber();
          if constexpr (should_track_json_source) {
            end_position = position();
            val_node = isolate_->factory()->NewSubString(
                source_, start_position, end_position);
          }
          break;

        case JsonToken::LBRACE: {
          Consume(JsonToken::LBRACE);
          if (Check(JsonToken::RBRACE)) {
            // TODO(verwaest): Directly use the map instead.
            value = factory()->NewJSObject(object_constructor_);
            if constexpr (should_track_json_source) {
              val_node = ObjectTwoHashTable::New(isolate_, 0);
            }
            break;
          }

          // Start parsing an object with properties.
          cont_stack.emplace_back(std::move(cont));
          cont = JsonContinuation(isolate_, JsonContinuation::kObjectProperty,
                                  property_stack_.size());

          // Parse the property key.
          ExpectNext(JsonToken::STRING,
                     MessageTemplate::kJsonParseExpectedPropNameOrRBrace);
          property_stack_.emplace_back(ScanJsonPropertyKey(&cont));
          if constexpr (should_track_json_source) {
            property_val_node_stack.emplace_back(Handle<Object>());
          }

          ExpectNext(JsonToken::COLON,
                     MessageTemplate::kJsonParseExpectedColonAfterPropertyName);

          // Continue to start producing the first property value.
          continue;
        }

        case JsonToken::LBRACK:
          Consume(JsonToken::LBRACK);
          if (Check(JsonToken::RBRACK)) {
            value = factory()->NewJSArray(0, PACKED_SMI_ELEMENTS);
            if constexpr (should_track_json_source) {
              val_node = factory()->NewFixedArray(0);
            }
            break;
          }

          // Start parsing an array with elements.
          cont_stack.emplace_back(std::move(cont));
          cont = JsonContinuation(isolate_, JsonContinuation::kArrayElement,
                                  element_stack_.size());

          // Continue to start producing the first array element.
          continue;

        case JsonToken::TRUE_LITERAL:
          ScanLiteral("true");
          value = factory()->true_value();
          if constexpr (should_track_json_source) {
            val_node = isolate_->factory()->true_string();
          }
          break;

        case JsonToken::FALSE_LITERAL:
          ScanLiteral("false");
          value = factory()->false_value();
          if constexpr (should_track_json_source) {
            val_node = isolate_->factory()->false_string();
          }
          break;

        case JsonToken::NULL_LITERAL:
          ScanLiteral("null");
          value = factory()->null_value();
          if constexpr (should_track_json_source) {
            val_node = isolate_->factory()->null_string();
          }
          break;

        case JsonToken::COLON:
        case JsonToken::COMMA:
        case JsonToken::ILLEGAL:
        case JsonToken::RBRACE:
        case JsonToken::RBRACK:
        case JsonToken::EOS:
          ReportUnexpectedCharacter(CurrentCharacter());
          // Pop the continuation stack to correctly tear down handle scopes.
          while (!cont_stack.empty()) {
            cont = std::move(cont_stack.back());
            cont_stack.pop_back();
          }
          return MaybeHandle<Object>();

        case JsonToken::WHITESPACE:
          UNREACHABLE();
      }
      // Done producing a value, consume it.
      break;
    }

    // Consume a produced json value.
    //
    // Iterate as long as values are produced (arrays or object literals are
    // finished).
    while (true) {
      // The switch is immediately followed by 'break' so we can use 'break' to
      // break out of the loop, and 'continue' to continue the loop.
      switch (cont.type()) {
        case JsonContinuation::kReturn:
          if constexpr (should_track_json_source) {
            DCHECK(!val_node.is_null());
            Tagged<Object> raw_value = *value;
            parsed_val_node_ = cont.scope.CloseAndEscape(val_node);
            return cont.scope.CloseAndEscape(handle(raw_value, isolate_));
          } else {
            return cont.scope.CloseAndEscape(value);
          }

        case JsonContinuation::kObjectProperty: {
          // Store the previous property value into its property info.
          property_stack_.back().value = value;
          if constexpr (should_track_json_source) {
            property_val_no
"""


```
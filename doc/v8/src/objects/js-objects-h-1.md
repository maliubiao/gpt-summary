Response:
The user wants a summary of the functionality of the provided C++ header file `v8/src/objects/js-objects.h`.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core purpose:** The file is named `js-objects.h`, suggesting it defines the structure and behavior of JavaScript objects within the V8 engine. The header includes definitions for various kinds of JS objects like `JSObject`, `JSGlobalObject`, `JSArray`, etc.

2. **Examine key data structures and methods:**  Scan the header for important class definitions and methods. Look for patterns and recurring themes. Notice the `V8_EXPORT_PRIVATE` markings, indicating internal V8 functionality.

3. **Group related functionalities:** Cluster the methods and data structures based on their purpose. For instance, there's a section related to property management (normalization, migration, access), another for prototypes, another for elements, and so on.

4. **Look for JavaScript connections:** The prompt specifically asks about relationships with JavaScript. Consider how the defined C++ structures and methods enable JavaScript features. Think about core JavaScript concepts like object properties, prototypes, extensibility, and different object types.

5. **Address the `.tq` question:**  The prompt asks about `.tq` files. Note that this file is `.h`, so it's C++. Explain the role of Torque and how `.tq` relates to generating C++ code.

6. **Provide JavaScript examples:**  For functionalities related to JavaScript, provide simple JavaScript code snippets to illustrate the concepts. This makes the explanation more concrete.

7. **Consider code logic and examples:** Look for methods that seem to perform specific operations on objects. Think about what inputs they might take and what outputs they would produce. While full implementation details aren't in the header, the method names often provide clues. For instance, `NormalizeProperties` suggests taking an object and modifying its properties.

8. **Address common programming errors:** Reflect on typical mistakes developers make when working with JavaScript objects. Relate these errors to the functionalities exposed in the header. For example, issues with adding properties to non-extensible objects.

9. **Structure the response:** Organize the information logically with clear headings and bullet points. Start with a general overview and then delve into more specific functionalities.

10. **Review and refine:** Read through the generated explanation to ensure accuracy, clarity, and completeness. Check if all parts of the prompt have been addressed. For example, ensure the distinction between fast and slow properties/elements is mentioned as it's a key performance optimization in V8.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the individual methods.
* **Correction:** Realize that grouping functionalities by purpose provides a better high-level understanding.

* **Initial thought:**  Only explain the C++ code.
* **Correction:**  Emphasize the connection to JavaScript and provide illustrative examples.

* **Initial thought:**  Ignore the `.tq` question since this file is `.h`.
* **Correction:** Explicitly address the `.tq` condition to answer all parts of the prompt.

* **Initial thought:** Explain each method in detail.
* **Correction:** Summarize the general purpose of groups of methods, as full details aren't evident from the header alone. Focus on the *what* rather than the *how*.

By following these steps, and iterating as needed, a comprehensive and informative summary of the `js-objects.h` file can be produced.
好的，这是 `v8/src/objects/js-objects.h` 文件第二部分的分析归纳。综合第一部分的内容，我们可以总结出这个头文件的主要功能是：

**`v8/src/objects/js-objects.h` 的主要功能：**

这个头文件定义了 V8 引擎中各种 JavaScript 对象的 C++ 类结构和相关的操作接口。它是 V8 引擎对象模型的核心组成部分，涵盖了 JavaScript 对象在内存中的布局、属性管理、原型链操作、以及与其他 V8 内部机制的交互。

**具体功能归纳如下：**

1. **定义 JavaScript 对象的 C++ 类结构:**
    *   定义了 `JSObject` 类作为所有 JavaScript 对象的基类，以及各种派生类，如 `JSGlobalObject`, `JSArray`, `JSFunction`, `JSString`, `JSNumber`, `JSBoolean`, `JSDate`, `JSMap`, `Set` 等。
    *   定义了用于描述对象属性的元数据结构，如 `PropertyDetails` 和 `FieldIndex`。

2. **管理对象的属性 (Properties):**
    *   提供了添加、删除、读取和更新对象属性的方法，包括快速属性 (Fast Properties) 和慢速属性 (Slow Properties) 的处理机制。
    *   `NormalizeProperties`:  将对象的属性存储方式标准化，可以预分配空间以优化性能。
    *   `NormalizeElements`: 将对象的元素存储方式转换为字典模式。
    *   `MigrateSlowToFast`:  将慢速属性转换为快速属性以提升性能。
    *   `DictionaryPropertyAt`: 访问字典模式对象的属性。
    *   `FastPropertyAt`: 访问快速模式对象的属性。
    *   `FastPropertyAtPut`: 设置快速模式对象的属性。

3. **管理对象的元素 (Elements):**
    *   定义了用于存储数组元素的各种后端存储类型（如 `FixedArray`, `NumberDictionary`）。
    *   提供了访问和操作对象元素的方法。

4. **管理对象的原型链 (Prototype Chain):**
    *   `SetPrototype`: 设置对象的原型。
    *   `SetImmutableProto`: 使对象的原型不可变。

5. **控制对象的扩展性 (Extensibility):**
    *   `PreventExtensions`: 禁止向对象添加新属性。
    *   `IsExtensible`: 检查对象是否可扩展。

6. **处理对象的完整性 (Integrity):**
    *   `TestIntegrityLevel`: 检查对象的完整性级别（如 sealed, frozen）。

7. **对象内存布局和初始化:**
    *   `InitializeBody`: 初始化对象的内存空间。

8. **调试和诊断支持:**
    *   提供了打印对象信息的方法 (`JSObjectShortPrint`, `PrintProperties`, `PrintElements`, `PrintTransitions`)，用于调试和性能分析。
    *   定义了 `SpillInformation` 结构用于收集对象溢出信息。

9. **与其他 V8 内部机制的交互:**
    *   涉及到与 `Isolate` (V8 引擎的独立实例), `Heap` (V8 堆), `Map` (对象的形状描述符) 等核心组件的交互。

10. **定义特定类型的 JavaScript 对象:**
    *   定义了 `JSExternalObject` 用于包装外部 C++ 指针。
    *   定义了 `JSAccessorPropertyDescriptor` 和 `JSDataPropertyDescriptor` 用于描述属性的特性。
    *   定义了 `JSIteratorResult` 用于表示迭代器的结果。
    *   定义了 `JSGlobalProxy` 和 `JSGlobalObject` 用于表示全局对象。
    *   定义了 `JSPrimitiveWrapper` 用于包装原始值类型。
    *   定义了 `JSDate` 用于表示日期对象。
    *   定义了 `JSMessageObject` 用于表示错误消息对象。
    *   定义了 `JSAsyncFromSyncIterator`, `JSStringIterator`, `JSValidIteratorWrapper` 用于支持迭代器。
    *   定义了 `JSPromiseWithResolversResult` 用于 Promise 相关的操作。

**关于 `.tq` 文件：**

正如第一部分所述，如果 `v8/src/objects/js-objects.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，尤其是在对象操作和类型检查方面。由于这个文件实际上是 `.h` 文件，所以它是直接用 C++ 编写的。

**与 JavaScript 的关系及示例：**

这个头文件中定义的所有类和方法都直接对应于 JavaScript 的运行时行为。例如：

*   当你创建一个 JavaScript 对象 `const obj = {};` 时，V8 内部会创建一个 `JSObject` 的实例。
*   当你添加属性 `obj.name = 'test';` 时，V8 内部会调用类似于 `FastPropertyAtPut` 或涉及属性规范化的方法。
*   当你访问属性 `const name = obj.name;` 时，V8 内部会调用类似于 `FastPropertyAt` 或 `DictionaryPropertyAt` 的方法。
*   当你使用 `Object.setPrototypeOf(obj, proto);` 时，会调用 `JSObject::SetPrototype`。
*   当你使用 `Object.preventExtensions(obj);` 时，会调用 `JSObject::PreventExtensions`。

**代码逻辑推理和假设输入/输出：**

以 `NormalizeProperties` 方法为例：

**假设输入：**

*   `isolate`: 当前 V8 引擎的 Isolate 实例。
*   `object`: 一个需要规范化属性的 `JSObject` 实例。
*   `mode`:  `PropertyNormalizationMode` 枚举值，指定规范化的模式（例如，预分配空间）。
*   `expected_additional_properties`: 期望添加的额外属性数量。
*   `reason`: 规范化的原因字符串（用于调试）。

**可能的输出：**

*   修改 `object` 的内部结构，使其属性存储方式更高效，例如，分配足够的空间来容纳预期的属性数量。
*   不会直接返回一个值，而是修改了输入的对象。

**用户常见的编程错误：**

*   **尝试向不可扩展的对象添加属性：**

    ```javascript
    const obj = {};
    Object.preventExtensions(obj);
    obj.newProp = 'value'; // TypeError: Cannot add property newProp, object is not extensible
    ```

    V8 内部会检查对象的 `Map`，发现对象不可扩展，从而抛出 `TypeError`。`JSObject::PreventExtensions` 方法就是用于设置对象不可扩展的标志。

*   **错误地理解原型链导致属性查找失败：**

    ```javascript
    function Parent() {
      this.parentProp = 'parent';
    }
    function Child() {}
    Child.prototype = new Parent();
    const child = new Child();
    console.log(child.parentProp); // 输出 "parent"
    console.log(child.nonExistentProp); // 输出 undefined
    ```

    V8 内部会沿着 `child` 的原型链向上查找 `parentProp` 和 `nonExistentProp`。这个过程涉及到对 `JSObject` 原型的访问和属性查找机制。

总而言之，`v8/src/objects/js-objects.h` 是理解 V8 引擎如何表示和操作 JavaScript 对象的基础。它定义了关键的数据结构和算法，为 V8 引擎的性能和功能提供了支撑。

Prompt: 
```
这是目录为v8/src/objects/js-objects.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/js-objects.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
xpected to have additional properties
  // added this number can be indicated to have the backing store allocated to
  // an initial capacity for holding these properties.
  V8_EXPORT_PRIVATE static void NormalizeProperties(
      Isolate* isolate, DirectHandle<JSObject> object,
      PropertyNormalizationMode mode, int expected_additional_properties,
      bool use_cache, const char* reason);

  V8_EXPORT_PRIVATE static void NormalizeProperties(
      Isolate* isolate, DirectHandle<JSObject> object,
      PropertyNormalizationMode mode, int expected_additional_properties,
      const char* reason) {
    const bool kUseCache = true;
    NormalizeProperties(isolate, object, mode, expected_additional_properties,
                        kUseCache, reason);
  }

  // Convert and update the elements backing store to be a
  // NumberDictionary dictionary.  Returns the backing after conversion.
  V8_EXPORT_PRIVATE static Handle<NumberDictionary> NormalizeElements(
      Handle<JSObject> object);

  void RequireSlowElements(Tagged<NumberDictionary> dictionary);

  // Transform slow named properties to fast variants.
  V8_EXPORT_PRIVATE static void MigrateSlowToFast(DirectHandle<JSObject> object,
                                                  int unused_property_fields,
                                                  const char* reason);

  // Access property in dictionary mode object at the given dictionary index.
  static Handle<Object> DictionaryPropertyAt(Isolate* isolate,
                                             DirectHandle<JSObject> object,
                                             InternalIndex dict_index);
  // Same as above, but it will return {} if we would be reading out of the
  // bounds of the object or if the dictionary is pending allocation. Use this
  // version for concurrent access.
  static std::optional<Tagged<Object>> DictionaryPropertyAt(
      DirectHandle<JSObject> object, InternalIndex dict_index, Heap* heap);

  // Access fast-case object properties at index.
  static Handle<JSAny> FastPropertyAt(Isolate* isolate,
                                      DirectHandle<JSObject> object,
                                      Representation representation,
                                      FieldIndex index);
  static Handle<JSAny> FastPropertyAt(Isolate* isolate,
                                      DirectHandle<JSObject> object,
                                      Representation representation,
                                      FieldIndex index, SeqCstAccessTag tag);
  inline Tagged<JSAny> RawFastPropertyAt(FieldIndex index) const;
  inline Tagged<JSAny> RawFastPropertyAt(PtrComprCageBase cage_base,
                                         FieldIndex index) const;
  inline Tagged<JSAny> RawFastPropertyAt(FieldIndex index,
                                         SeqCstAccessTag tag) const;
  inline Tagged<JSAny> RawFastPropertyAt(PtrComprCageBase cage_base,
                                         FieldIndex index,
                                         SeqCstAccessTag tag) const;

  // See comment in the body of the method to understand the conditions
  // in which this method is meant to be used, and what guarantees it
  // provides against invalid reads from another thread during object
  // mutation.
  inline std::optional<Tagged<Object>> RawInobjectPropertyAt(
      PtrComprCageBase cage_base, Tagged<Map> original_map,
      FieldIndex index) const;

  inline void FastPropertyAtPut(FieldIndex index, Tagged<Object> value,
                                WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline void FastPropertyAtPut(FieldIndex index, Tagged<Object> value,
                                SeqCstAccessTag tag);
  inline void RawFastInobjectPropertyAtPut(
      FieldIndex index, Tagged<Object> value,
      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);
  inline void RawFastInobjectPropertyAtPut(FieldIndex index,
                                           Tagged<Object> value,
                                           SeqCstAccessTag tag);
  inline void WriteToField(InternalIndex descriptor, PropertyDetails details,
                           Tagged<Object> value);

  inline Tagged<Object> RawFastInobjectPropertyAtSwap(FieldIndex index,
                                                      Tagged<Object> value,
                                                      SeqCstAccessTag tag);
  inline Tagged<Object> RawFastPropertyAtSwap(FieldIndex index,
                                              Tagged<Object> value,
                                              SeqCstAccessTag tag);
  Tagged<Object> RawFastPropertyAtCompareAndSwap(FieldIndex index,
                                                 Tagged<Object> expected,
                                                 Tagged<Object> value,
                                                 SeqCstAccessTag tag);
  inline Tagged<Object> RawFastInobjectPropertyAtCompareAndSwap(
      FieldIndex index, Tagged<Object> expected, Tagged<Object> value,
      SeqCstAccessTag tag);

  // Access to in object properties.
  inline int GetInObjectPropertyOffset(int index);
  inline Tagged<Object> InObjectPropertyAt(int index);
  inline Tagged<Object> InObjectPropertyAtPut(
      int index, Tagged<Object> value,
      WriteBarrierMode mode = UPDATE_WRITE_BARRIER);

  // Set the object's prototype (only JSReceiver and null are allowed values).
  V8_WARN_UNUSED_RESULT static Maybe<bool> SetPrototype(
      Isolate* isolate, Handle<JSObject> object, Handle<Object> value,
      bool from_javascript, ShouldThrow should_throw);

  // Makes the object prototype immutable
  // Never called from JavaScript
  static void SetImmutableProto(Isolate* isolate,
                                DirectHandle<JSObject> object);

  // Initializes the body starting at |start_offset|. It is responsibility of
  // the caller to initialize object header. Fill the pre-allocated fields with
  // undefined_value and the rest with filler_map.
  // Note: this call does not update write barrier, the caller is responsible
  // to ensure that |filler_map| can be collected without WB here.
  inline void InitializeBody(Tagged<Map> map, int start_offset,
                             bool is_slack_tracking_in_progress,
                             MapWord filler_map,
                             Tagged<Object> undefined_value);

  // Check whether this object references another object
  bool ReferencesObject(Tagged<Object> obj);

  V8_WARN_UNUSED_RESULT static Maybe<bool> TestIntegrityLevel(
      Isolate* isolate, Handle<JSObject> object, IntegrityLevel lvl);

  V8_WARN_UNUSED_RESULT static Maybe<bool> PreventExtensions(
      Isolate* isolate, Handle<JSObject> object, ShouldThrow should_throw);

  static bool IsExtensible(Isolate* isolate, Handle<JSObject> object);

  static MaybeHandle<Object> ReadFromOptionsBag(Handle<Object> options,
                                                Handle<String> option_name,
                                                Isolate* isolate);

  // Dispatched behavior.
  void JSObjectShortPrint(StringStream* accumulator);
  DECL_PRINTER(JSObject)
  DECL_VERIFIER(JSObject)
#ifdef OBJECT_PRINT
  bool PrintProperties(std::ostream& os);
  void PrintElements(std::ostream& os);
#endif
#if defined(DEBUG) || defined(OBJECT_PRINT)
  void PrintTransitions(std::ostream& os);
#endif

  static void PrintElementsTransition(
      FILE* file, DirectHandle<JSObject> object, ElementsKind from_kind,
      DirectHandle<FixedArrayBase> from_elements, ElementsKind to_kind,
      DirectHandle<FixedArrayBase> to_elements);

  void PrintInstanceMigration(FILE* file, Tagged<Map> original_map,
                              Tagged<Map> new_map);

#ifdef DEBUG
  // Structure for collecting spill information about JSObjects.
  class SpillInformation {
   public:
    void Clear();
    void Print();
    int number_of_objects_;
    int number_of_objects_with_fast_properties_;
    int number_of_objects_with_fast_elements_;
    int number_of_fast_used_fields_;
    int number_of_fast_unused_fields_;
    int number_of_slow_used_properties_;
    int number_of_slow_unused_properties_;
    int number_of_fast_used_elements_;
    int number_of_fast_unused_elements_;
    int number_of_slow_used_elements_;
    int number_of_slow_unused_elements_;
  };

  void IncrementSpillStatistics(Isolate* isolate, SpillInformation* info);
#endif

#ifdef VERIFY_HEAP
  // If a GC was caused while constructing this object, the elements pointer
  // may point to a one pointer filler map. The object won't be rooted, but
  // our heap verification code could stumble across it.
  V8_EXPORT_PRIVATE bool ElementsAreSafeToExamine(
      PtrComprCageBase cage_base) const;
#endif

  Tagged<Object> SlowReverseLookup(Tagged<Object> value);

  // Maximal number of elements (numbered 0 .. kMaxElementCount - 1).
  // Also maximal value of JSArray's length property.
  static constexpr uint32_t kMaxElementCount = kMaxUInt32;
  static constexpr uint32_t kMaxElementIndex = kMaxElementCount - 1;

  // Constants for heuristics controlling conversion of fast elements
  // to slow elements.

  // Maximal gap that can be introduced by adding an element beyond
  // the current elements length.
  static const uint32_t kMaxGap = 1024;

  // Maximal length of fast elements array that won't be checked for
  // being dense enough on expansion.
  static const int kMaxUncheckedFastElementsLength = 5000;

  // Same as above but for old arrays. This limit is more strict. We
  // don't want to be wasteful with long lived objects.
  static const int kMaxUncheckedOldFastElementsLength = 500;

  // This constant applies only to the initial map of "global.Object" and
  // not to arbitrary other JSObject maps.
  static const int kInitialGlobalObjectUnusedPropertiesCount = 4;

  static const int kMaxInstanceSize = 255 * kTaggedSize;
  // kMaxInstanceSize in words must fit in one byte.
  static_assert((kMaxInstanceSize >> kTaggedSizeLog2) <= kMaxUInt8);

  static const int kMapCacheSize = 128;

  // When extending the backing storage for property values, we increase
  // its size by more than the 1 entry necessary, so sequentially adding fields
  // to the same object requires fewer allocations and copies.
  static const int kFieldsAdded = 3;
  static_assert(kMaxNumberOfDescriptors + kFieldsAdded <=
                PropertyArray::kMaxLength);

  static_assert(kHeaderSize == Internals::kJSObjectHeaderSize);
  static const int kMaxInObjectProperties =
      (kMaxInstanceSize - kHeaderSize) >> kTaggedSizeLog2;
  static_assert(kMaxInObjectProperties <= kMaxNumberOfDescriptors);

  static const int kMaxFirstInobjectPropertyOffset =
      (1 << kFirstInobjectPropertyOffsetBitCount) - 1;
  static const int kMaxEmbedderFields =
      (kMaxFirstInobjectPropertyOffset - kHeaderSize) / kEmbedderDataSlotSize;
  static_assert(kHeaderSize +
                    kMaxEmbedderFields * kEmbedderDataSlotSizeInTaggedSlots <=
                kMaxInstanceSize);

  static constexpr int kMaxJSApiObjectInObjectProperties =
      (kMaxInstanceSize - kHeaderSize - kCppHeapPointerSlotSize) >>
      kTaggedSizeLog2;
  static constexpr int kMaxJSApiObjectEmbedderFields =
      (kMaxFirstInobjectPropertyOffset - kHeaderSize -
       kCppHeapPointerSlotSize) /
      kEmbedderDataSlotSize;

  class BodyDescriptor;

  class FastBodyDescriptor;

  // Gets the number of currently used elements.
  int GetFastElementsUsage();

  template <typename Dictionary>
  static void ApplyAttributesToDictionary(Isolate* isolate, ReadOnlyRoots roots,
                                          Handle<Dictionary> dictionary,
                                          const PropertyAttributes attributes);

 private:
  friend class JSReceiver;
  friend class Object;

  // Used from Object::GetProperty().
  V8_WARN_UNUSED_RESULT static MaybeHandle<JSAny>
  GetPropertyWithFailedAccessCheck(LookupIterator* it);

  V8_WARN_UNUSED_RESULT static Maybe<bool> SetPropertyWithFailedAccessCheck(
      LookupIterator* it, Handle<Object> value,
      Maybe<ShouldThrow> should_throw);

  V8_WARN_UNUSED_RESULT static Maybe<InterceptorResult>
  DeletePropertyWithInterceptor(LookupIterator* it, ShouldThrow should_throw);

  bool ReferencesObjectFromElements(Tagged<FixedArray> elements,
                                    ElementsKind kind, Tagged<Object> object);

  // Helper for fast versions of preventExtensions, seal, and freeze.
  // attrs is one of NONE, SEALED, or FROZEN (depending on the operation).
  template <PropertyAttributes attrs>
  V8_WARN_UNUSED_RESULT static Maybe<bool> PreventExtensionsWithTransition(
      Isolate* isolate, Handle<JSObject> object, ShouldThrow should_throw);

  inline Tagged<Object> RawFastPropertyAtCompareAndSwapInternal(
      FieldIndex index, Tagged<Object> expected, Tagged<Object> value,
      SeqCstAccessTag tag);

  TQ_OBJECT_CONSTRUCTORS(JSObject)
};

// A JSObject created through the public api which wraps an external pointer.
// See v8::External.
class JSExternalObject
    : public TorqueGeneratedJSExternalObject<JSExternalObject, JSObject> {
 public:
  // [value]: field containing the pointer value.
  DECL_EXTERNAL_POINTER_ACCESSORS(value, void*)

  static constexpr int kEndOfTaggedFieldsOffset = JSObject::kHeaderSize;

  DECL_PRINTER(JSExternalObject)

  class BodyDescriptor;

 private:
  TQ_OBJECT_CONSTRUCTORS(JSExternalObject)
};

// An abstract superclass for JSObjects that may contain EmbedderDataSlots.
class JSObjectWithEmbedderSlots
    : public TorqueGeneratedJSObjectWithEmbedderSlots<JSObjectWithEmbedderSlots,
                                                      JSObject> {
 public:
  static_assert(kHeaderSize == JSObject::kHeaderSize);
  TQ_OBJECT_CONSTRUCTORS(JSObjectWithEmbedderSlots)
};

// An abstract superclass for JSObjects that may contain EmbedderDataSlots and
// are used as API wrapper objects.
class JSAPIObjectWithEmbedderSlots
    : public TorqueGeneratedJSAPIObjectWithEmbedderSlots<
          JSAPIObjectWithEmbedderSlots, JSObject> {
 public:
  class BodyDescriptor;

  TQ_OBJECT_CONSTRUCTORS(JSAPIObjectWithEmbedderSlots)
};

// An abstract superclass for JSObjects that may have elements while having an
// empty fixed array as elements backing store. It doesn't carry any
// functionality but allows function classes to be identified in the type
// system.
class JSCustomElementsObject
    : public TorqueGeneratedJSCustomElementsObject<JSCustomElementsObject,
                                                   JSObject> {
 public:
  static_assert(kHeaderSize == JSObject::kHeaderSize);
  TQ_OBJECT_CONSTRUCTORS(JSCustomElementsObject)
};

// An abstract superclass for JSObjects that require non-standard element
// access. It doesn't carry any functionality but allows function classes to be
// identified in the type system.
// These may also contain EmbedderDataSlots, but can't currently inherit from
// JSAPIObjectWithEmbedderSlots due to instance_type constraints.
class JSSpecialObject
    : public TorqueGeneratedJSSpecialObject<JSSpecialObject,
                                            JSCustomElementsObject> {
 public:
  TQ_OBJECT_CONSTRUCTORS(JSSpecialObject)
};

// Helper union that doesn't actually exist as type. Use by value.
class JSApiWrapper {
 public:
  V8_INLINE explicit JSApiWrapper(Tagged<JSObject> object);

  template <CppHeapPointerTag tag>
  V8_INLINE void SetCppHeapWrappable(IsolateForPointerCompression isolate,
                                     void*);
  V8_INLINE void SetCppHeapWrappable(IsolateForPointerCompression isolate,
                                     void*, CppHeapPointerTag tag);
  template <CppHeapPointerTag lower_bound, CppHeapPointerTag upper_bound>
  V8_INLINE void* GetCppHeapWrappable(
      IsolateForPointerCompression isolate) const;
  V8_INLINE void* GetCppHeapWrappable(IsolateForPointerCompression isolate,
                                      CppHeapPointerTagRange tag_range) const;

 private:
  static_assert(JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset ==
                JSSpecialObject::kCppHeapWrappableOffset);
  static constexpr int kCppHeapWrappableOffset =
      JSAPIObjectWithEmbedderSlots::kCppHeapWrappableOffset;

  Tagged<JSObject> object_;
};

// JSAccessorPropertyDescriptor is just a JSObject with a specific initial
// map. This initial map adds in-object properties for "get", "set",
// "enumerable" and "configurable" properties, as assigned by the
// FromPropertyDescriptor function for regular accessor properties.
class JSAccessorPropertyDescriptor : public JSObject {
 public:
  // Layout description.
#define JS_ACCESSOR_PROPERTY_DESCRIPTOR_FIELDS(V) \
  V(kGetOffset, kTaggedSize)                      \
  V(kSetOffset, kTaggedSize)                      \
  V(kEnumerableOffset, kTaggedSize)               \
  V(kConfigurableOffset, kTaggedSize)             \
  /* Total size. */                               \
  V(kSize, 0)

  DEFINE_FIELD_OFFSET_CONSTANTS(JSObject::kHeaderSize,
                                JS_ACCESSOR_PROPERTY_DESCRIPTOR_FIELDS)
#undef JS_ACCESSOR_PROPERTY_DESCRIPTOR_FIELDS

  // Indices of in-object properties.
  static const int kGetIndex = 0;
  static const int kSetIndex = 1;
  static const int kEnumerableIndex = 2;
  static const int kConfigurableIndex = 3;

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(JSAccessorPropertyDescriptor);
};

// JSDataPropertyDescriptor is just a JSObject with a specific initial map.
// This initial map adds in-object properties for "value", "writable",
// "enumerable" and "configurable" properties, as assigned by the
// FromPropertyDescriptor function for regular data properties.
class JSDataPropertyDescriptor : public JSObject {
 public:
  // Layout description.
#define JS_DATA_PROPERTY_DESCRIPTOR_FIELDS(V) \
  V(kValueOffset, kTaggedSize)                \
  V(kWritableOffset, kTaggedSize)             \
  V(kEnumerableOffset, kTaggedSize)           \
  V(kConfigurableOffset, kTaggedSize)         \
  /* Total size. */                           \
  V(kSize, 0)

  DEFINE_FIELD_OFFSET_CONSTANTS(JSObject::kHeaderSize,
                                JS_DATA_PROPERTY_DESCRIPTOR_FIELDS)
#undef JS_DATA_PROPERTY_DESCRIPTOR_FIELDS

  // Indices of in-object properties.
  static const int kValueIndex = 0;
  static const int kWritableIndex = 1;
  static const int kEnumerableIndex = 2;
  static const int kConfigurableIndex = 3;

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(JSDataPropertyDescriptor);
};

// JSIteratorResult is just a JSObject with a specific initial map.
// This initial map adds in-object properties for "done" and "value",
// as specified by ES6 section 25.1.1.3 The IteratorResult Interface.
class JSIteratorResult : public JSObject {
 public:
  DECL_ACCESSORS(value, Tagged<Object>)

  DECL_ACCESSORS(done, Tagged<Object>)

  // Layout description.
#define JS_ITERATOR_RESULT_FIELDS(V) \
  V(kValueOffset, kTaggedSize)       \
  V(kDoneOffset, kTaggedSize)        \
  /* Total size. */                  \
  V(kSize, 0)

  DEFINE_FIELD_OFFSET_CONSTANTS(JSObject::kHeaderSize,
                                JS_ITERATOR_RESULT_FIELDS)
#undef JS_ITERATOR_RESULT_FIELDS

  // Indices of in-object properties.
  static const int kValueIndex = 0;
  static const int kDoneIndex = 1;

  OBJECT_CONSTRUCTORS(JSIteratorResult, JSObject);
};

// JSGlobalProxy's prototype must be a JSGlobalObject or null,
// and the prototype is hidden. JSGlobalProxy always delegates
// property accesses to its prototype if the prototype is not null.
//
// A JSGlobalProxy can be reinitialized which will preserve its identity.
//
// Accessing a JSGlobalProxy requires security check.

class JSGlobalProxy
    : public TorqueGeneratedJSGlobalProxy<JSGlobalProxy, JSSpecialObject> {
 public:
  inline bool IsDetachedFrom(Tagged<JSGlobalObject> global) const;
  V8_EXPORT_PRIVATE bool IsDetached();

  static int SizeWithEmbedderFields(int embedder_field_count);

  // Dispatched behavior.
  DECL_PRINTER(JSGlobalProxy)
  DECL_VERIFIER(JSGlobalProxy)

  TQ_OBJECT_CONSTRUCTORS(JSGlobalProxy)
};

// JavaScript global object.
class JSGlobalObject
    : public TorqueGeneratedJSGlobalObject<JSGlobalObject, JSSpecialObject> {
 public:
  DECL_RELEASE_ACQUIRE_ACCESSORS(global_dictionary, Tagged<GlobalDictionary>)

  static void InvalidatePropertyCell(DirectHandle<JSGlobalObject> object,
                                     Handle<Name> name);

  inline bool IsDetached();
  inline Tagged<NativeContext> native_context();

  // Dispatched behavior.
  DECL_PRINTER(JSGlobalObject)
  DECL_VERIFIER(JSGlobalObject)

  TQ_OBJECT_CONSTRUCTORS(JSGlobalObject)
};

// Representation for JS Wrapper objects, String, Number, Boolean, etc.
class JSPrimitiveWrapper
    : public TorqueGeneratedJSPrimitiveWrapper<JSPrimitiveWrapper,
                                               JSCustomElementsObject> {
 public:
  // Dispatched behavior.
  DECL_PRINTER(JSPrimitiveWrapper)

  TQ_OBJECT_CONSTRUCTORS(JSPrimitiveWrapper)
};

class DateCache;

// Representation for JS date objects.
class JSDate : public TorqueGeneratedJSDate<JSDate, JSObject> {
 public:
  static V8_WARN_UNUSED_RESULT MaybeHandle<JSDate> New(
      Handle<JSFunction> constructor, Handle<JSReceiver> new_target, double tv);

  // Returns the time value (UTC) identifying the current time in milliseconds.
  static int64_t CurrentTimeValue(Isolate* isolate);

  // Returns the date field with the specified index.
  // See FieldIndex for the list of date fields.
  // Arguments and result are raw Address values because this is called
  // via ExternalReference.
  // {raw_date} is a tagged Object pointer.
  // {smi_index} is a tagged Smi.
  // The return value is a tagged Object pointer.
  static Address GetField(Isolate* isolate, Address raw_date,
                          Address smi_index);

  void SetValue(double v);
  void SetNanValue();

  // Dispatched behavior.
  DECL_PRINTER(JSDate)
  DECL_VERIFIER(JSDate)

  // The order is important. It must be kept in sync with date macros
  // in macros.py.
  enum FieldIndex {
    kYear,
    kMonth,
    kDay,
    kWeekday,
    kHour,
    kMinute,
    kSecond,
    kFirstUncachedField,
    kMillisecond = kFirstUncachedField,
    kDays,
    kTimeInDay,
    kFirstUTCField,
    kYearUTC = kFirstUTCField,
    kMonthUTC,
    kDayUTC,
    kWeekdayUTC,
    kHourUTC,
    kMinuteUTC,
    kSecondUTC,
    kMillisecondUTC,
    kDaysUTC,
    kTimeInDayUTC,
    kTimezoneOffset
  };

  class BodyDescriptor;

 private:
  Tagged<Object> DoGetField(Isolate* isolate, FieldIndex index);
  Tagged<Object> GetUTCField(FieldIndex index, double value,
                             DateCache* date_cache);

  // Computes and caches the cacheable fields of the date.
  inline void SetCachedFields(int64_t local_time_ms, DateCache* date_cache);

  TQ_OBJECT_CONSTRUCTORS(JSDate)
};

// Representation of message objects used for error reporting through
// the API. The messages are formatted in JavaScript so this object is
// a real JavaScript object. The information used for formatting the
// error messages are not directly accessible from JavaScript to
// prevent leaking information to user code called during error
// formatting.
class JSMessageObject
    : public TorqueGeneratedJSMessageObject<JSMessageObject, JSObject> {
 public:
  // [type]: the type of error message.
  inline MessageTemplate type() const;
  inline void set_type(MessageTemplate value);

  // Initializes the source positions in the object if possible. Does nothing if
  // called more than once. If called when stack space is exhausted, then the
  // source positions will be not be set and calling it again when there is more
  // stack space will not have any effect.
  static inline void EnsureSourcePositionsAvailable(
      Isolate* isolate, DirectHandle<JSMessageObject> message);

  // Gets the start and end positions for the message.
  // EnsureSourcePositionsAvailable must have been called before calling these.
  inline int GetStartPosition() const;
  inline int GetEndPosition() const;

  // Returns the line number for the error message (1-based), or
  // Message::kNoLineNumberInfo if the line cannot be determined.
  // EnsureSourcePositionsAvailable must have been called before calling this.
  V8_EXPORT_PRIVATE int GetLineNumber() const;

  // Returns the offset of the given position within the containing line.
  // EnsureSourcePositionsAvailable must have been called before calling this.
  V8_EXPORT_PRIVATE int GetColumnNumber() const;

  // Returns the source code
  V8_EXPORT_PRIVATE Tagged<String> GetSource() const;

  // Returns the source code line containing the given source
  // position, or the empty string if the position is invalid.
  // EnsureSourcePositionsAvailable must have been called before calling this.
  Handle<String> GetSourceLine() const;

  DECL_INT_ACCESSORS(error_level)

  // Dispatched behavior.
  DECL_PRINTER(JSMessageObject)

  // TODO(v8:8989): [torque] Support marker constants.
  static const int kPointerFieldsEndOffset = kStartPositionOffset;

  using BodyDescriptor =
      FixedBodyDescriptor<HeapObject::kMapOffset, kPointerFieldsEndOffset,
                          kHeaderSize>;

 private:
  friend class Factory;

  inline bool DidEnsureSourcePositionsAvailable() const;
  static void V8_PRESERVE_MOST V8_EXPORT_PRIVATE InitializeSourcePositions(
      Isolate* isolate, DirectHandle<JSMessageObject> message);

  // [shared]: optional SharedFunctionInfo that can be used to reconstruct the
  // source position if not available when the message was generated.
  DECL_ACCESSORS(shared_info, Tagged<Object>)

  // [bytecode_offset]: optional offset using along with |shared| to generation
  // source positions.
  DECL_ACCESSORS(bytecode_offset, Tagged<Smi>)

  // [start_position]: the start position in the script for the error message.
  DECL_INT_ACCESSORS(start_position)

  // [end_position]: the end position in the script for the error message.
  DECL_INT_ACCESSORS(end_position)

  DECL_INT_ACCESSORS(raw_type)

  // Hide generated accessors; custom accessors are named "raw_type".
  DECL_INT_ACCESSORS(message_type)

  TQ_OBJECT_CONSTRUCTORS(JSMessageObject)
};

// The [Async-from-Sync Iterator] object
// (proposal-async-iteration/#sec-async-from-sync-iterator-objects)
// An object which wraps an ordinary Iterator and converts it to behave
// according to the Async Iterator protocol.
// (See https://tc39.github.io/proposal-async-iteration/#sec-iteration)
class JSAsyncFromSyncIterator
    : public TorqueGeneratedJSAsyncFromSyncIterator<JSAsyncFromSyncIterator,
                                                    JSObject> {
 public:
  DECL_PRINTER(JSAsyncFromSyncIterator)

  // Async-from-Sync Iterator instances are ordinary objects that inherit
  // properties from the %AsyncFromSyncIteratorPrototype% intrinsic object.
  // Async-from-Sync Iterator instances are initially created with the internal
  // slots listed in Table 4.
  // (proposal-async-iteration/#table-async-from-sync-iterator-internal-slots)

  TQ_OBJECT_CONSTRUCTORS(JSAsyncFromSyncIterator)
};

class JSStringIterator
    : public TorqueGeneratedJSStringIterator<JSStringIterator, JSObject> {
 public:
  // Dispatched behavior.
  DECL_PRINTER(JSStringIterator)
  DECL_VERIFIER(JSStringIterator)

  TQ_OBJECT_CONSTRUCTORS(JSStringIterator)
};

// The valid iterator wrapper is the wrapper object created by
// Iterator.from(obj), which attempts to wrap iterator-like objects into an
// actual iterator with %Iterator.prototype%.
class JSValidIteratorWrapper
    : public TorqueGeneratedJSValidIteratorWrapper<JSValidIteratorWrapper,
                                                   JSObject> {
 public:
  DECL_PRINTER(JSValidIteratorWrapper)

  TQ_OBJECT_CONSTRUCTORS(JSValidIteratorWrapper)
};

// JSPromiseWithResolversResult is just a JSObject with a specific initial map.
// This initial map adds in-object properties for "promise", "resolve", and
// "reject", in that order.
class JSPromiseWithResolversResult : public JSObject {
 public:
  DECL_ACCESSORS(promise, Tagged<Object>)

  DECL_ACCESSORS(resolve, Tagged<Object>)

  DECL_ACCESSORS(reject, Tagged<Object>)

  // Layout description.
#define JS_PROMISE_WITHRESOLVERS_RESULT_FIELDS(V) \
  V(kPromiseOffset, kTaggedSize)                  \
  V(kResolveOffset, kTaggedSize)                  \
  V(kRejectOffset, kTaggedSize)                   \
  /* Total size. */                               \
  V(kSize, 0)

  DEFINE_FIELD_OFFSET_CONSTANTS(JSObject::kHeaderSize,
                                JS_PROMISE_WITHRESOLVERS_RESULT_FIELDS)
#undef JS_PROMISE_WITHRESOLVERS_RESULT_FIELDS

  // Indices of in-object properties.
  static const int kPromiseIndex = 0;
  static const int kResolveIndex = 1;
  static const int kRejectIndex = 2;

  OBJECT_CONSTRUCTORS(JSPromiseWithResolversResult, JSObject);
};

}  // namespace v8::internal

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_JS_OBJECTS_H_

"""


```
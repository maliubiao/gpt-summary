Response:
The user wants a summary of the C++ header file `v8/src/compiler/heap-refs.h`.
This is the second part of a two-part request, so I need to consider the information provided in both parts to give a comprehensive summary.

**Part 1 Analysis (Based on the file path and common V8 practices):**

*   The file likely defines "references" or "wrappers" around V8 heap objects.
*   These references are probably used within the compiler pipeline for type analysis, optimization, and code generation.
*   The `.h` extension indicates a header file containing declarations.

**Part 2 Analysis (Content of the header file):**

*   The file defines a set of C++ classes, mostly ending with "Ref", such as `HeapObjectRef`, `MapRef`, `StringRef`, etc.
*   These classes appear to be lightweight wrappers around raw pointers to V8 heap objects.
*   They provide methods to access properties and metadata of the underlying heap objects in a type-safe manner.
*   The presence of `JSHeapBroker* broker` arguments suggests these references operate within the context of a heap snapshot or analysis environment.
*   The `DEFINE_REF_CONSTRUCTOR` macro likely simplifies the creation of these reference types.
*   There are classes like `HolderLookupResult` which seem to be helper structures for specific compiler tasks.
*   The `INSTANCE_TYPE_CHECKERS` macro suggests a way to check the specific type of the referenced heap object.
*   There's a notion of "Optional" references (e.g., `OptionalMapRef`), likely to handle cases where a referenced object might not exist or meet certain criteria.
*   The file includes definitions for accessing various properties of `Map` objects, which are crucial for understanding object layout and type information.
*   There are specific references for common JavaScript types like `String`, `Array`, `Function`, etc.
*   The file also includes utility functions like `AnyMapIsHeapNumber`.

**Combining Insights from Both Parts:**

*   The file is indeed defining C++ wrappers for V8 heap objects.
*   The `.h` extension confirms it's a header file. The initial statement about `.tq` is irrelevant since the file ends in `.h`.
*   The file is deeply related to the internal workings of the V8 compiler and how it represents and manipulates JavaScript objects.
*   While not direct JavaScript code, the structures and methods reflect the underlying structure of JavaScript objects in the V8 heap.

**Plan for the Summary:**

1. Start by reiterating that this is the second part and build upon the general understanding from part 1.
2. Explain the core concept of "Ref" classes as wrappers for heap objects.
3. Highlight the purpose of these wrappers in the compiler.
4. Mention the role of `JSHeapBroker`.
5. Describe the types of information accessible through these references (properties, metadata, etc.).
6. Point out the connection to JavaScript object structure.
7. Summarize the utility functions provided.
这是对 `v8/src/compiler/heap-refs.h` 文件功能的归纳总结：

该头文件定义了一系列 C++ 类，这些类充当 V8 堆中各种对象的轻量级**引用 (References)**。这些 "Ref" 类，例如 `HeapObjectRef`, `MapRef`, `StringRef` 等，并非直接持有堆对象的指针，而是在编译器的特定上下文中，提供了一种类型安全的方式来访问和操作这些堆对象的信息。

**主要功能归纳:**

1. **类型安全的堆对象访问:** 这些 "Ref" 类为编译器提供了一种结构化的方式来访问 V8 堆中的对象，避免直接使用原始指针可能导致的错误。每个 "Ref" 类都对应着一种特定的 V8 堆对象类型（例如 `Map`, `String`, `JSObject`），并提供了一组与其类型相关的访问方法。

2. **编译器内部表示:**  这些引用主要在 V8 编译器的各个阶段中使用，例如类型推断、优化和代码生成。它们帮助编译器理解和操作 JavaScript 程序的运行时状态，而无需进行实际的堆操作。

3. **抽象层:** "Ref" 类在编译器的代码和实际的 V8 堆结构之间提供了一个抽象层。这使得编译器代码更加简洁易懂，并且在 V8 内部堆结构发生变化时，可以减少需要修改的代码量。

4. **信息提取:** 这些 "Ref" 类提供了大量的方法来提取堆对象的各种属性和元数据，例如：
    *   对象的类型 (`_type()`, `IsJSObjectMap()`, `IsStringMap()` 等)。
    *   对象的布局信息 (`GetInObjectProperties()`, `GetInObjectPropertyOffset()`)，这对于理解对象的内存结构至关重要。
    *   Map 对象的属性信息 (`NumberOfOwnDescriptors()`, `GetPropertyDetails()`)，用于属性查找和访问优化。
    *   函数的信息 (`is_callable()`, `function_template_info()`)。
    *   数组的信息 (`length()`)。
    *   字符串的信息 (`length()`, `GetChar()`)。
    *   以及其他各种特定类型对象的属性。

5. **与 `JSHeapBroker` 协作:** 大部分 "Ref" 类的方法都接收一个 `JSHeapBroker* broker` 参数。`JSHeapBroker` 是一个在编译器中用于访问堆信息的组件。这些 "Ref" 类需要 `JSHeapBroker` 来获取实际的堆数据。

6. **辅助结构:**  文件中还定义了一些辅助结构，例如 `HolderLookupResult`，用于特定的编译器任务，例如查找属性的持有者。

7. **可选值:** 一些方法返回 `Optional<T>` 或 `OptionalObjectRef`，表示该属性可能不存在或无法获取，这在处理动态类型语言的特性时非常重要。

**总结来说，`v8/src/compiler/heap-refs.h` 定义了一套用于在 V8 编译器内部表示和操作堆对象的类型安全接口，它提供了访问对象属性和元数据的各种方法，是编译器进行类型分析、优化和代码生成的重要基础设施。**

虽然这个头文件本身不是 Torque 代码（因为它以 `.h` 结尾），但它定义的 C++ 结构很可能被 Torque 代码使用。Torque 是一种用于编写 V8 内部函数的领域特定语言，它可以调用 C++ 代码。

虽然这个头文件没有直接的 JavaScript 代码，但它描述的结构和概念直接对应于 JavaScript 的运行时对象模型。例如，`MapRef` 对应于 JavaScript 对象的 "形状" 或 "类"，它决定了对象的属性布局。`JSObjectRef` 对应于 JavaScript 中的普通对象。

**与 JavaScript 功能的关系示例:**

假设在 JavaScript 中有以下代码：

```javascript
const obj = { x: 1, y: 2 };
```

在 V8 编译器的内部表示中，`obj` 这个 JavaScript 对象可能会被表示为一个 `JSObjectRef`。编译器可以通过 `JSObjectRef` 获取 `obj` 的 `MapRef`，进而通过 `MapRef` 的方法了解到 `obj` 拥有两个 in-object 属性 (`x` 和 `y`)，以及它们在对象内存中的偏移量 (`GetInObjectPropertyOffset()`)。

**代码逻辑推理示例:**

假设有以下输入：

*   一个 `MapRef` 对象 `map_ref`，代表一个 JavaScript 对象的 Map。

通过调用 `map_ref.GetInObjectProperties()`，可以得到该 Map 描述的对象的 in-object 属性的数量。
通过调用 `map_ref.GetInObjectPropertyOffset(0)`，可以得到第一个 in-object 属性在对象内存中的偏移量（以字为单位）。

**用户常见的编程错误（与概念相关）：**

虽然这个头文件是 V8 内部的，但理解其背后的概念可以帮助理解一些 JavaScript 性能问题。例如：

*   **属性顺序和隐藏类（Maps）:**  V8 依赖于 Maps 来优化属性访问。如果以不同的顺序添加属性，或者在对象创建后动态添加或删除属性，会导致创建新的 Map，从而可能影响性能。`heap-refs.h` 中的 `MapRef` 及其相关方法就反映了这种内部机制。

    ```javascript
    // 避免这种情况，因为 o1 和 o2 可能有不同的 Map
    const o1 = { a: 1, b: 2 };
    const o2 = { b: 2, a: 1 };

    // 尽量保持对象形状一致
    class Point {
      constructor(x, y) {
        this.x = x;
        this.y = y;
      }
    }
    const p1 = new Point(1, 2);
    const p2 = new Point(3, 4);
    ```

*   **访问不存在的属性:** 虽然在 JavaScript 中访问不存在的属性会返回 `undefined` 而不会报错，但在 V8 内部，编译器需要进行属性查找。理解 `MapRef` 如何存储属性信息有助于理解属性查找的效率。

总而言之，`v8/src/compiler/heap-refs.h` 是 V8 编译器理解和操作 JavaScript 对象的基础，它定义了一组强大的工具来访问和分析堆对象的结构和元数据。

### 提示词
```
这是目录为v8/src/compiler/heap-refs.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/heap-refs.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
_type() const;
  int GetInObjectProperties() const;
  int GetInObjectPropertiesStartInWords() const;
  int NumberOfOwnDescriptors() const;
  int GetInObjectPropertyOffset(int index) const;
  int constructor_function_index() const;
  int NextFreePropertyIndex() const;
  int UnusedPropertyFields() const;
  ElementsKind elements_kind() const;
  bool is_stable() const;
  bool is_constructor() const;
  bool has_prototype_slot() const;
  bool is_access_check_needed() const;
  bool is_deprecated() const;
  bool CanBeDeprecated() const;
  bool CanTransition() const;
  bool IsInobjectSlackTrackingInProgress() const;
  bool is_dictionary_map() const;
  bool IsFixedCowArrayMap(JSHeapBroker* broker) const;
  bool IsPrimitiveMap() const;
  bool is_undetectable() const;
  bool is_callable() const;
  bool has_indexed_interceptor() const;
  int construction_counter() const;
  bool is_migration_target() const;
  bool supports_fast_array_iteration(JSHeapBroker* broker) const;
  bool supports_fast_array_resize(JSHeapBroker* broker) const;
  bool is_abandoned_prototype_map() const;

  OddballType oddball_type(JSHeapBroker* broker) const;

  bool CanInlineElementAccess() const;

  // Note: Only returns a value if the requested elements kind matches the
  // current kind, or if the current map is an unmodified JSArray initial map.
  OptionalMapRef AsElementsKind(JSHeapBroker* broker, ElementsKind kind) const;

#define DEF_TESTER(Type, ...) bool Is##Type##Map() const;
  INSTANCE_TYPE_CHECKERS(DEF_TESTER)
#undef DEF_TESTER

  bool IsBooleanMap(JSHeapBroker* broker) const;

  HeapObjectRef GetBackPointer(JSHeapBroker* broker) const;

  HeapObjectRef prototype(JSHeapBroker* broker) const;

  bool PrototypesElementsDoNotHaveAccessorsOrThrow(
      JSHeapBroker* broker, ZoneVector<MapRef>* prototype_maps);

  // Concerning the underlying instance_descriptors:
  DescriptorArrayRef instance_descriptors(JSHeapBroker* broker) const;
  MapRef FindFieldOwner(JSHeapBroker* broker,
                        InternalIndex descriptor_index) const;
  PropertyDetails GetPropertyDetails(JSHeapBroker* broker,
                                     InternalIndex descriptor_index) const;
  NameRef GetPropertyKey(JSHeapBroker* broker,
                         InternalIndex descriptor_index) const;
  FieldIndex GetFieldIndexFor(InternalIndex descriptor_index) const;
  OptionalObjectRef GetStrongValue(JSHeapBroker* broker,
                                   InternalIndex descriptor_number) const;

  MapRef FindRootMap(JSHeapBroker* broker) const;
  ObjectRef GetConstructor(JSHeapBroker* broker) const;
};

struct HolderLookupResult {
  HolderLookupResult(CallOptimization::HolderLookup lookup_ =
                         CallOptimization::kHolderNotFound,
                     OptionalJSObjectRef holder_ = std::nullopt)
      : lookup(lookup_), holder(holder_) {}
  CallOptimization::HolderLookup lookup;
  OptionalJSObjectRef holder;
};

class FunctionTemplateInfoRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FunctionTemplateInfo, HeapObjectRef)

  IndirectHandle<FunctionTemplateInfo> object() const;

  bool is_signature_undefined(JSHeapBroker* broker) const;
  bool accept_any_receiver() const;
  int16_t allowed_receiver_instance_type_range_start() const;
  int16_t allowed_receiver_instance_type_range_end() const;

  // Function pointer and a data value that should be passed to the callback.
  // The |callback_data| must be read before the |callback|.
  Address callback(JSHeapBroker* broker) const;
  OptionalObjectRef callback_data(JSHeapBroker* broker) const;

  ZoneVector<Address> c_functions(JSHeapBroker* broker) const;
  ZoneVector<const CFunctionInfo*> c_signatures(JSHeapBroker* broker) const;
  HolderLookupResult LookupHolderOfExpectedType(JSHeapBroker* broker,
                                                MapRef receiver_map);
};

class FixedArrayBaseRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FixedArrayBase, HeapObjectRef)

  IndirectHandle<FixedArrayBase> object() const;

  uint32_t length() const;
};

class ArrayBoilerplateDescriptionRef : public HeapObjectRef {
 public:
  using HeapObjectRef::HeapObjectRef;
  IndirectHandle<ArrayBoilerplateDescription> object() const;

  int constants_elements_length() const;
};

class FixedArrayRef : public FixedArrayBaseRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FixedArray, FixedArrayBaseRef)

  IndirectHandle<FixedArray> object() const;

  OptionalObjectRef TryGet(JSHeapBroker* broker, int i) const;
};

class FixedDoubleArrayRef : public FixedArrayBaseRef {
 public:
  DEFINE_REF_CONSTRUCTOR(FixedDoubleArray, FixedArrayBaseRef)

  IndirectHandle<FixedDoubleArray> object() const;

  // Due to 64-bit unaligned reads, only usable for
  // immutable-after-initialization FixedDoubleArrays protected by
  // acquire-release semantics (such as boilerplate elements).
  Float64 GetFromImmutableFixedDoubleArray(int i) const;
};

class BytecodeArrayRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(BytecodeArray, HeapObjectRef)

  IndirectHandle<BytecodeArray> object() const;

  // NOTE: Concurrent reads of the actual bytecodes as well as the constant pool
  // (both immutable) do not go through BytecodeArrayRef but are performed
  // directly through the handle by BytecodeArrayIterator.

  int length() const;

  int register_count() const;
  uint16_t parameter_count() const;
  uint16_t parameter_count_without_receiver() const;
  uint16_t max_arguments() const;
  interpreter::Register incoming_new_target_or_generator_register() const;

  IndirectHandle<TrustedByteArray> SourcePositionTable(
      JSHeapBroker* broker) const;

  // Exception handler table.
  Address handler_table_address() const;
  int handler_table_size() const;
};

class ScriptContextTableRef : public FixedArrayBaseRef {
 public:
  DEFINE_REF_CONSTRUCTOR(ScriptContextTable, FixedArrayBaseRef)

  IndirectHandle<ScriptContextTable> object() const;
};

class ObjectBoilerplateDescriptionRef : public FixedArrayRef {
 public:
  DEFINE_REF_CONSTRUCTOR(ObjectBoilerplateDescription, FixedArrayRef)

  IndirectHandle<ObjectBoilerplateDescription> object() const;

  int boilerplate_properties_count() const;
};

class JSArrayRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSArray, JSObjectRef)

  IndirectHandle<JSArray> object() const;

  // The `length` property of boilerplate JSArray objects. Boilerplates are
  // immutable after initialization. Must not be used for non-boilerplate
  // JSArrays.
  ObjectRef GetBoilerplateLength(JSHeapBroker* broker) const;

  // Return the element at key {index} if the array has a copy-on-write elements
  // storage and {index} is known to be an own data property.
  // Note the value returned by this function is only valid if we ensure at
  // runtime that the backing store has not changed.
  OptionalObjectRef GetOwnCowElement(JSHeapBroker* broker,
                                     FixedArrayBaseRef elements_ref,
                                     uint32_t index) const;

  // The `JSArray::length` property; not safe to use in general, but can be
  // used in some special cases that guarantee a valid `length` value despite
  // concurrent reads. The result needs to be optional in case the
  // return value was created too recently to pass the gc predicate.
  OptionalObjectRef length_unsafe(JSHeapBroker* broker) const;
};

class ScopeInfoRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(ScopeInfo, HeapObjectRef)

  IndirectHandle<ScopeInfo> object() const;

  int ContextLength() const;
  bool HasContext() const;
  bool HasOuterScopeInfo() const;
  bool HasContextExtensionSlot() const;
  bool SomeContextHasExtension() const;
  bool ClassScopeHasPrivateBrand() const;
  bool SloppyEvalCanExtendVars() const;
  ScopeType scope_type() const;

  ScopeInfoRef OuterScopeInfo(JSHeapBroker* broker) const;
};

#define BROKER_SFI_FIELDS(V)                               \
  V(int, internal_formal_parameter_count_with_receiver)    \
  V(int, internal_formal_parameter_count_without_receiver) \
  V(bool, IsDontAdaptArguments)                            \
  V(bool, has_simple_parameters)                           \
  V(bool, has_duplicate_parameters)                        \
  V(int, function_map_index)                               \
  V(FunctionKind, kind)                                    \
  V(LanguageMode, language_mode)                           \
  V(bool, native)                                          \
  V(bool, HasBuiltinId)                                    \
  V(bool, construct_as_builtin)                            \
  V(bool, HasBytecodeArray)                                \
  V(int, StartPosition)                                    \
  V(bool, is_compiled)                                     \
  V(bool, IsUserJavaScript)                                \
  V(bool, requires_instance_members_initializer)

class V8_EXPORT_PRIVATE SharedFunctionInfoRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(SharedFunctionInfo, HeapObjectRef)

  IndirectHandle<SharedFunctionInfo> object() const;

  Builtin builtin_id() const;
  int context_header_size() const;
  int context_parameters_start() const;
  BytecodeArrayRef GetBytecodeArray(JSHeapBroker* broker) const;
  bool HasBreakInfo(JSHeapBroker* broker) const;
  SharedFunctionInfo::Inlineability GetInlineability(
      JSHeapBroker* broker) const;
  OptionalFunctionTemplateInfoRef function_template_info(
      JSHeapBroker* broker) const;
  ScopeInfoRef scope_info(JSHeapBroker* broker) const;

#define DECL_ACCESSOR(type, name) type name() const;
  BROKER_SFI_FIELDS(DECL_ACCESSOR)
#undef DECL_ACCESSOR

  bool IsInlineable(JSHeapBroker* broker) const {
    return GetInlineability(broker) == SharedFunctionInfo::kIsInlineable;
  }
};

class StringRef : public NameRef {
 public:
  DEFINE_REF_CONSTRUCTOR(String, NameRef)

  IndirectHandle<String> object() const;

  // With concurrent inlining on, we return std::nullopt due to not being able
  // to use LookupIterator in a thread-safe way.
  OptionalObjectRef GetCharAsStringOrUndefined(JSHeapBroker* broker,
                                               uint32_t index) const;

  // When concurrently accessing non-read-only non-supported strings, we return
  // std::nullopt for these methods.
  std::optional<Handle<String>> ObjectIfContentAccessible(JSHeapBroker* broker);
  uint32_t length() const;
  std::optional<uint16_t> GetFirstChar(JSHeapBroker* broker) const;
  std::optional<uint16_t> GetChar(JSHeapBroker* broker, uint32_t index) const;
  std::optional<double> ToNumber(JSHeapBroker* broker);
  std::optional<double> ToInt(JSHeapBroker* broker, int radix);

  bool IsSeqString() const;
  bool IsExternalString() const;

  bool IsContentAccessible() const;
  bool IsOneByteRepresentation() const;

 private:
  // With concurrent inlining on, we currently support reading directly
  // internalized strings, and thin strings (which are pointers to internalized
  // strings).
  bool SupportedStringKind() const;
};

class SymbolRef : public NameRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Symbol, NameRef)

  IndirectHandle<Symbol> object() const;
};

class JSTypedArrayRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSTypedArray, JSObjectRef)

  IndirectHandle<JSTypedArray> object() const;

  bool is_on_heap() const;
  size_t length() const;
  void* data_ptr() const;
  HeapObjectRef buffer(JSHeapBroker* broker) const;
};

class JSPrimitiveWrapperRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSPrimitiveWrapper, JSObjectRef)

  bool IsStringWrapper(JSHeapBroker* broker) const;

  IndirectHandle<JSPrimitiveWrapper> object() const;
};

class SourceTextModuleRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(SourceTextModule, HeapObjectRef)

  IndirectHandle<SourceTextModule> object() const;

  OptionalCellRef GetCell(JSHeapBroker* broker, int cell_index) const;
  OptionalObjectRef import_meta(JSHeapBroker* broker) const;
};

class TemplateObjectDescriptionRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(TemplateObjectDescription, HeapObjectRef)

  IndirectHandle<TemplateObjectDescription> object() const;
};

class CellRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Cell, HeapObjectRef)

  IndirectHandle<Cell> object() const;
};

class JSGlobalObjectRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSGlobalObject, JSObjectRef)

  IndirectHandle<JSGlobalObject> object() const;

  bool IsDetachedFrom(JSGlobalProxyRef proxy) const;

  // Can be called even when there is no property cell for the given name.
  OptionalPropertyCellRef GetPropertyCell(JSHeapBroker* broker,
                                          NameRef name) const;
};

class JSGlobalProxyRef : public JSObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(JSGlobalProxy, JSObjectRef)

  IndirectHandle<JSGlobalProxy> object() const;
};

class CodeRef : public HeapObjectRef {
 public:
  DEFINE_REF_CONSTRUCTOR(Code, HeapObjectRef)

  IndirectHandle<Code> object() const;

  unsigned GetInlinedBytecodeSize() const;
};

class InternalizedStringRef : public StringRef {
 public:
  DEFINE_REF_CONSTRUCTOR(InternalizedString, StringRef)

  IndirectHandle<InternalizedString> object() const;
};

#undef DEFINE_REF_CONSTRUCTOR

#define V(Name)                                                   \
  /* Refs should contain only one pointer. */                     \
  static_assert(sizeof(Name##Ref) == kSystemPointerSize);         \
  static_assert(sizeof(OptionalName##Ref) == kSystemPointerSize); \
  /* Refs should be trivial to copy, move and destroy. */         \
  static_assert(std::is_trivially_copyable_v<Name##Ref>);         \
  static_assert(std::is_trivially_copyable_v<OptionalName##Ref>); \
  static_assert(std::is_trivially_destructible_v<Name##Ref>);     \
  static_assert(std::is_trivially_destructible_v<OptionalName##Ref>);

V(Object) HEAP_BROKER_OBJECT_LIST(V)
#undef V

}  // namespace compiler

template <typename T>
struct ZoneCompactSetTraits<T, std::enable_if_t<compiler::is_ref<T>::value>> {
  using handle_type = T;
  using data_type = compiler::ObjectData;

  static data_type* HandleToPointer(handle_type handle) {
    return handle.data();
  }
  static handle_type PointerToHandle(data_type* ptr) {
    return handle_type(ptr);
  }
};

namespace compiler {

template <typename T>
using ZoneRefSet = ZoneCompactSet<typename ref_traits<T>::ref_type>;

inline bool AnyMapIsHeapNumber(const ZoneRefSet<Map>& maps) {
  return std::any_of(maps.begin(), maps.end(),
                     [](MapRef map) { return map.IsHeapNumberMap(); });
}

inline bool AnyMapIsHeapNumber(const base::Vector<const MapRef>& maps) {
  return std::any_of(maps.begin(), maps.end(),
                     [](MapRef map) { return map.IsHeapNumberMap(); });
}

}  // namespace compiler

}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_HEAP_REFS_H_
```
Response:
The user wants a summary of the provided C++ header file `v8/src/maglev/maglev-ir.h`. The summary should include:

1. **Functionality:** What does this code do?
2. **Torque Source:** Is it a Torque file (ends with `.tq`)?
3. **JavaScript Relation:** If related to JavaScript, provide JavaScript examples.
4. **Code Logic Inference:**  If there's logic, give example inputs and outputs.
5. **Common Programming Errors:**  Mention any common mistakes this code might help prevent or related to its use.
6. **Overall Function:** A concise summary.
7. **Part Number:** Acknowledge this is part 9 of 12.

Let's break down the provided C++ code:

- **Macros `LOAD_TYPED_ARRAY` and `STORE_TYPED_ARRAY`:** These macros define classes for loading and storing elements in TypedArrays. They create classes with specific properties, input types, and methods for different TypedArray element kinds (e.g., Int8, Uint32, Float64).
- **`StoreSignedIntDataViewElement` and `StoreDoubleDataViewElement`:** These classes handle storing elements in DataView objects, which allow for byte-level manipulation of ArrayBuffers. They take into account endianness.
- **`StoreDoubleField`, `StoreFloat64`, `StoreTaggedFieldNoWriteBarrier`, `StoreMap`, `StoreTaggedFieldWithWriteBarrier`, `StoreScriptContextSlotWithWriteBarrier`, `StoreTrustedPointerFieldWithWriteBarrier`:** These classes deal with storing values into object properties or fields. They differ in the type of value being stored (double, tagged pointer), whether a write barrier is needed (for garbage collection), and specific contexts (like script contexts or trusted pointers). `StoreMap` is specifically for updating the object's map (type information).
- **`LoadGlobal` and `StoreGlobal`:** These classes handle accessing global variables.
- **`UpdateJSArrayLength`:** This class updates the length property of a JavaScript array.
- **`LoadNamedGeneric` and related `LoadNamedFromSuperGeneric`, `SetNamedGeneric`, `DefineNamedOwnGeneric`:** These classes represent generic operations for accessing and modifying object properties by name. "Generic" implies these are fallback cases when more optimized operations aren't applicable.
- **`LoadEnumCacheLength`:** This class retrieves the length of an enumeration cache, used for iterating over object properties.
- **`StringAt`, `StringLength`, `StringConcat`, `StringWrapperConcat`:** These classes perform operations on JavaScript strings: accessing a character at a specific index, getting the length, and concatenating strings.
- **`StoreInArrayLiteralGeneric`:**  Handles storing elements within array literals.
- **`GetKeyedGeneric`:**  Represents a generic operation for accessing object properties by a key (which can be a string or symbol).

**High-Level Goal:** This header file defines the *Intermediate Representation (IR)* nodes for the *Maglev* compiler in V8. These nodes represent various operations that can occur in JavaScript code, but in a form that's easier for the compiler to analyze and optimize before generating machine code.

**Planning the Response:**

1. **Functionality:** Describe it as defining IR nodes for Maglev, focusing on memory access (fields, arrays, typed arrays, data views), global variable access, string operations, and generic property access.
2. **Torque:**  State it's a C++ header, not a Torque file.
3. **JavaScript Relation:**  For each category of IR nodes (memory access, globals, strings, generic access), provide relevant JavaScript examples.
4. **Code Logic:**  The "logic" is the mapping of JavaScript operations to these IR nodes. Provide simple examples of how a JavaScript expression might translate.
5. **Common Errors:**  Relate errors to the *kind* of operations:  out-of-bounds access for arrays, incorrect type assumptions when dealing with typed arrays or data views, and issues with global variable scope.
6. **Overall Function:** Summarize it as the core IR definitions for Maglev.
7. **Part Number:** Acknowledge.
```cpp
pProperties::CanRead() | properties;                          \
    static constexpr typename Base::InputTypes kInputTypes{            \
        ValueRepresentation::kTagged, ValueRepresentation::kUint32};   \
                                                                       \
    static constexpr int kObjectIndex = 0;                             \
    static constexpr int kIndexIndex = 1;                              \
    Input& object_input() { return input(kObjectIndex); }              \
    Input& index_input() { return input(kIndexIndex); }                \
                                                                       \
    void SetValueLocationConstraints();                                \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);       \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}     \
                                                                       \
    auto options() const { return std::tuple{elements_kind_}; }        \
                                                                       \
    ElementsKind elements_kind() const { return elements_kind_; }      \
                                                                       \
   private:                                                            \
    ElementsKind elements_kind_;                                       \
  };

LOAD_TYPED_ARRAY(LoadSignedIntTypedArrayElement, OpProperties::Int32(),
                 INT8_ELEMENTS, INT16_ELEMENTS, INT32_ELEMENTS)

LOAD_TYPED_ARRAY(LoadUnsignedIntTypedArrayElement, OpProperties::Uint32(),
                 UINT8_ELEMENTS, UINT8_CLAMPED_ELEMENTS, UINT16_ELEMENTS,
                 UINT16_ELEMENTS, UINT32_ELEMENTS)

LOAD_TYPED_ARRAY(LoadDoubleTypedArrayElement, OpProperties::Float64(),
                 FLOAT32_ELEMENTS, FLOAT64_ELEMENTS)

#undef LOAD_TYPED_ARRAY

#define STORE_TYPED_ARRAY(name, properties, type, ...)                     \
  class name : public FixedInputNodeT<3, name> {                           \
    using Base = FixedInputNodeT<3, name>;                                 \
                                                                           \
   public:                                                                 \
    explicit name(uint64_t bitfield, ElementsKind elements_kind)           \
        : Base(bitfield), elements_kind_(elements_kind) {                  \
      DCHECK(elements_kind ==                                              \
             v8::internal::compiler::turboshaft::any_of(__VA_ARGS__));     \
    }                                                                      \
                                                                           \
    static constexpr OpProperties kProperties = properties;                \
    static constexpr typename Base::InputTypes kInputTypes{                \
        ValueRepresentation::kTagged, ValueRepresentation::kUint32, type}; \
                                                                           \
    static constexpr int kObjectIndex = 0;                                 \
    static constexpr int kIndexIndex = 1;                                  \
    static constexpr int kValueIndex = 2;                                  \
    Input& object_input() { return input(kObjectIndex); }                  \
    Input& index_input() { return input(kIndexIndex); }                    \
    Input& value_input() { return input(kValueIndex); }                    \
                                                                           \
    void SetValueLocationConstraints();                                    \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);           \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}         \
                                                                           \
    ElementsKind elements_kind() const { return elements_kind_; }          \
                                                                           \
   private:                                                                \
    ElementsKind elements_kind_;                                           \
  };

STORE_TYPED_ARRAY(StoreIntTypedArrayElement, OpProperties::CanWrite(),
                  ValueRepresentation::kInt32, INT8_ELEMENTS, INT16_ELEMENTS,
                  INT32_ELEMENTS, UINT8_ELEMENTS, UINT8_CLAMPED_ELEMENTS,
                  UINT16_ELEMENTS, UINT16_ELEMENTS, UINT32_ELEMENTS)
STORE_TYPED_ARRAY(StoreDoubleTypedArrayElement, OpProperties::CanWrite(),
                  ValueRepresentation::kHoleyFloat64, FLOAT32_ELEMENTS,
                  FLOAT64_ELEMENTS)
#undef STORE_TYPED_ARRAY

class StoreSignedIntDataViewElement
    : public FixedInputNodeT<4, StoreSignedIntDataViewElement> {
  using Base = FixedInputNodeT<4, StoreSignedIntDataViewElement>;

 public:
  explicit StoreSignedIntDataViewElement(uint64_t bitfield,
                                         ExternalArrayType type)
      : Base(bitfield), type_(type) {
    DCHECK(type == ExternalArrayType::kExternalInt8Array ||
           type == ExternalArrayType::kExternalInt16Array ||
           type == ExternalArrayType::kExternalInt32Array);
  }

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kInt32, ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  static constexpr int kIsLittleEndianIndex = 3;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  ExternalArrayType type() const { return type_; }

 private:
  ExternalArrayType type_;
};

class StoreDoubleDataViewElement
    : public FixedInputNodeT<4, StoreDoubleDataViewElement> {
  using Base = FixedInputNodeT<4, StoreDoubleDataViewElement>;

 public:
  explicit StoreDoubleDataViewElement(uint64_t bitfield, ExternalArrayType type)
      : Base(bitfield) {
    DCHECK_EQ(type, ExternalArrayType::kExternalFloat64Array);
  }

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kHoleyFloat64, ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  static constexpr int kIsLittleEndianIndex = 3;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StoreDoubleField : public FixedInputNodeT<2, StoreDoubleField> {
  using Base = FixedInputNodeT<2, StoreDoubleField>;

 public:
  explicit StoreDoubleField(uint64_t bitfield, int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kFloat64};

  int offset() const { return offset_; }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int offset_;
};

class StoreFloat64 : public FixedInputNodeT<2, StoreFloat64> {
  using Base = FixedInputNodeT<2, StoreFloat64>;

 public:
  explicit StoreFloat64(uint64_t bitfield, int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kFloat64};

  int offset() const { return offset_; }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int offset_;
};

enum class StoreTaggedMode : uint8_t {
  kDefault,
  kInitializing,
  kTransitioning
};
inline bool IsInitializingOrTransitioning(StoreTaggedMode mode) {
  return mode == StoreTaggedMode::kInitializing ||
         mode == StoreTaggedMode::kTransitioning;
}

class StoreTaggedFieldNoWriteBarrier
    : public FixedInputNodeT<2, StoreTaggedFieldNoWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTaggedFieldNoWriteBarrier>;

 public:
  explicit StoreTaggedFieldNoWriteBarrier(uint64_t bitfield, int offset,
                                          StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset) {}

  // StoreTaggedFieldNoWriteBarrier never does a Deferred Call. However,
  // PhiRepresentationSelector can cause some StoreTaggedFieldNoWriteBarrier to
  // become StoreTaggedFieldWithWriteBarrier, which can do Deferred Calls, and
  // thus need the register snapshot. We thus set the DeferredCall property in
  // StoreTaggedFieldNoWriteBarrier so that it's allocated with enough space for
  // the register snapshot.
  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // Don't need to decompress value to store it.
  }
#endif

  int MaxCallStackArgs() const {
    // StoreTaggedFieldNoWriteBarrier never really does any call.
    return 0;
  }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
};

class StoreMap : public FixedInputNodeT<1, StoreMap> {
  using Base = FixedInputNodeT<1, StoreMap>;

 public:
  enum class Kind {
    kInitializing,
    kInitializingYoung,
    kTransitioning,
  };
  explicit StoreMap(uint64_t bitfield, compiler::MapRef map, Kind kind)
      : Base(bitfield | KindField::encode(kind)), map_(map) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  compiler::MapRef map() const { return map_; }
  Kind kind() const { return KindField::decode(bitfield()); }
  static Kind initializing_kind(AllocationType type) {
    return type == AllocationType::kYoung ? Kind::kInitializingYoung
                                          : Kind::kInitializing;
  }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  void ClearUnstableNodeAspects(KnownNodeAspects&);

 private:
  using KindField = NextBitField<Kind, 3>;
  const compiler::MapRef map_;
};
std::ostream& operator<<(std::ostream& os, StoreMap::Kind);

class StoreTaggedFieldWithWriteBarrier
    : public FixedInputNodeT<2, StoreTaggedFieldWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTaggedFieldWithWriteBarrier>;

 public:
  explicit StoreTaggedFieldWithWriteBarrier(uint64_t bitfield, int offset,
                                            StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // Don't need to decompress value to store it.
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
};

class StoreScriptContextSlotWithWriteBarrier
    : public FixedInputNodeT<2, StoreScriptContextSlotWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreScriptContextSlotWithWriteBarrier>;

 public:
  explicit StoreScriptContextSlotWithWriteBarrier(uint64_t bitfield, int index)
      : Base(bitfield), index_(index) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::EagerDeopt();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return Context::OffsetOfElementAt(index()); }
  int index() const { return index_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kNewValueIndex = 1;
  Input& context_input() { return input(kContextIndex); }
  Input& new_value_input() { return input(kNewValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    context_input().node()->SetTaggedResultNeedsDecompress();
    new_value_input().node()->SetTaggedResultNeedsDecompress();
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int index_;
};

class StoreTrustedPointerFieldWithWriteBarrier
    : public FixedInputNodeT<2, StoreTrustedPointerFieldWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTrustedPointerFieldWithWriteBarrier>;

 public:
  explicit StoreTrustedPointerFieldWithWriteBarrier(uint64_t bitfield,
                                                    int offset,
                                                    IndirectPointerTag tag,
                                                    StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset),
        tag_(tag) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  IndirectPointerTag tag() const { return tag_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // value is never compressed.
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
  const IndirectPointerTag tag_;
};

class LoadGlobal : public FixedInputValueNodeT<1, LoadGlobal> {
  using Base = FixedInputValueNodeT<1, LoadGlobal>;

 public:
  explicit LoadGlobal(uint64_t bitfield, compiler::NameRef name,
                      const compiler::FeedbackSource& feedback,
                      TypeofMode typeof_mode)
      : Base(bitfield),
        name_(name),
        feedback_(feedback),
        typeof_mode_(typeof_mode) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }
  TypeofMode typeof_mode() const { return typeof_mode_; }

  Input& context() { return input(0); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
  const TypeofMode typeof_mode_;
};

class StoreGlobal : public FixedInputValueNodeT<2, StoreGlobal> {
  using Base = FixedInputValueNodeT<2, StoreGlobal>;

 public:
  explicit StoreGlobal(uint64_t bitfield, compiler::NameRef name,
                       const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  Input& context() { return input(0); }
  Input& value() { return input(1); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class UpdateJSArrayLength
    : public FixedInputValueNodeT<3, UpdateJSArrayLength> {
  using Base = FixedInputValueNodeT<3, UpdateJSArrayLength>;

 public:
  explicit UpdateJSArrayLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kInt32, ValueRepresentation::kTagged,
      ValueRepresentation::kInt32};

  // TODO(pthier): Use a more natural order once we can define the result
  // register to be equal to any input register.
  // The current order avoids any extra moves in the common case where index is
  // less than length
  static constexpr int kLengthIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kIndexIndex = 2;
  Input& length_input() { return input(kLengthIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadNamedGeneric : public FixedInputValueNodeT<2, LoadNamedGeneric> {
  using Base = FixedInputValueNodeT<2, LoadNamedGeneric>;

 public:
  explicit LoadNamedGeneric(uint64_t bitfield, compiler::NameRef name,
                            const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class LoadNamedFromSuperGeneric
    : public FixedInputValueNodeT<3, LoadNamedFromSuperGeneric> {
  using Base = FixedInputValueNodeT<3, LoadNamedFromSuperGeneric>;

 public:
  explicit LoadNamedFromSuperGeneric(uint64_t bitfield, compiler::NameRef name,
                                     const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kReceiverIndex = 1;
  static constexpr int kLookupStartObjectIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& receiver() { return input(kReceiverIndex); }
  Input& lookup_start_object() { return input(kLookupStartObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class SetNamedGeneric : public FixedInputValueNodeT<3, SetNamedGeneric> {
  using Base = FixedInputValueNodeT<3, SetNamedGeneric>;

 public:
  explicit SetNamedGeneric(uint64_t bitfield, compiler::NameRef name,
                           const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class LoadEnumCacheLength
    : public FixedInputValueNodeT<1, LoadEnumCacheLength> {
  using Base = FixedInputValueNodeT<1, LoadEnumCacheLength>;

 public:
  explicit LoadEnumCacheLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kMapInput = 0;
  Input& map_input() { return input(kMapInput); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringAt : public FixedInputValueNodeT<2, StringAt> {
  using Base = FixedInputValueNodeT<2, StringAt>;

 public:
  explicit StringAt(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead() |
                                              OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kStringIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& string_input() { return input(kStringIndex); }
  Input& index_input() { return input(kIndexIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringLength : public FixedInputValueNodeT<1, StringLength> {
  using Base = FixedInputValueNodeT<1, StringLength>;

 public:
  explicit StringLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringConcat : public FixedInputValueNodeT<2, StringConcat> {
  using Base = FixedInputValueNodeT<2, StringConcat>;

 public:
  explicit StringConcat(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Call() |
                                              OpProperties::LazyDeopt() |
                                              OpProperties::CanThrow();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  Input& lhs() { return Node::input(0); }
  Input& rhs() { return Node::input(1); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringWrapperConcat
    : public FixedInputValueNodeT<2, StringWrapperConcat> {
  using Base = FixedInputValueNodeT<2, StringWrapperConcat>;

 public:
  explicit StringWrapperConcat(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Call() |
                                              OpProperties::LazyDeopt() |
                                              OpProperties::CanThrow();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  Input& lhs() { return Node::input(0); }
  Input& rhs() { return Node::input(1); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class DefineNamedOwnGeneric
    : public FixedInputValueNodeT<3, DefineNamedOwnGeneric> {
  using Base = FixedInputValueNode
### 提示词
```
这是目录为v8/src/maglev/maglev-ir.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-ir.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第9部分，共12部分，请归纳一下它的功能
```

### 源代码
```c
pProperties::CanRead() | properties;                          \
    static constexpr typename Base::InputTypes kInputTypes{            \
        ValueRepresentation::kTagged, ValueRepresentation::kUint32};   \
                                                                       \
    static constexpr int kObjectIndex = 0;                             \
    static constexpr int kIndexIndex = 1;                              \
    Input& object_input() { return input(kObjectIndex); }              \
    Input& index_input() { return input(kIndexIndex); }                \
                                                                       \
    void SetValueLocationConstraints();                                \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);       \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}     \
                                                                       \
    auto options() const { return std::tuple{elements_kind_}; }        \
                                                                       \
    ElementsKind elements_kind() const { return elements_kind_; }      \
                                                                       \
   private:                                                            \
    ElementsKind elements_kind_;                                       \
  };

LOAD_TYPED_ARRAY(LoadSignedIntTypedArrayElement, OpProperties::Int32(),
                 INT8_ELEMENTS, INT16_ELEMENTS, INT32_ELEMENTS)

LOAD_TYPED_ARRAY(LoadUnsignedIntTypedArrayElement, OpProperties::Uint32(),
                 UINT8_ELEMENTS, UINT8_CLAMPED_ELEMENTS, UINT16_ELEMENTS,
                 UINT16_ELEMENTS, UINT32_ELEMENTS)

LOAD_TYPED_ARRAY(LoadDoubleTypedArrayElement, OpProperties::Float64(),
                 FLOAT32_ELEMENTS, FLOAT64_ELEMENTS)

#undef LOAD_TYPED_ARRAY

#define STORE_TYPED_ARRAY(name, properties, type, ...)                     \
  class name : public FixedInputNodeT<3, name> {                           \
    using Base = FixedInputNodeT<3, name>;                                 \
                                                                           \
   public:                                                                 \
    explicit name(uint64_t bitfield, ElementsKind elements_kind)           \
        : Base(bitfield), elements_kind_(elements_kind) {                  \
      DCHECK(elements_kind ==                                              \
             v8::internal::compiler::turboshaft::any_of(__VA_ARGS__));     \
    }                                                                      \
                                                                           \
    static constexpr OpProperties kProperties = properties;                \
    static constexpr typename Base::InputTypes kInputTypes{                \
        ValueRepresentation::kTagged, ValueRepresentation::kUint32, type}; \
                                                                           \
    static constexpr int kObjectIndex = 0;                                 \
    static constexpr int kIndexIndex = 1;                                  \
    static constexpr int kValueIndex = 2;                                  \
    Input& object_input() { return input(kObjectIndex); }                  \
    Input& index_input() { return input(kIndexIndex); }                    \
    Input& value_input() { return input(kValueIndex); }                    \
                                                                           \
    void SetValueLocationConstraints();                                    \
    void GenerateCode(MaglevAssembler*, const ProcessingState&);           \
    void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}         \
                                                                           \
    ElementsKind elements_kind() const { return elements_kind_; }          \
                                                                           \
   private:                                                                \
    ElementsKind elements_kind_;                                           \
  };

STORE_TYPED_ARRAY(StoreIntTypedArrayElement, OpProperties::CanWrite(),
                  ValueRepresentation::kInt32, INT8_ELEMENTS, INT16_ELEMENTS,
                  INT32_ELEMENTS, UINT8_ELEMENTS, UINT8_CLAMPED_ELEMENTS,
                  UINT16_ELEMENTS, UINT16_ELEMENTS, UINT32_ELEMENTS)
STORE_TYPED_ARRAY(StoreDoubleTypedArrayElement, OpProperties::CanWrite(),
                  ValueRepresentation::kHoleyFloat64, FLOAT32_ELEMENTS,
                  FLOAT64_ELEMENTS)
#undef STORE_TYPED_ARRAY

class StoreSignedIntDataViewElement
    : public FixedInputNodeT<4, StoreSignedIntDataViewElement> {
  using Base = FixedInputNodeT<4, StoreSignedIntDataViewElement>;

 public:
  explicit StoreSignedIntDataViewElement(uint64_t bitfield,
                                         ExternalArrayType type)
      : Base(bitfield), type_(type) {
    DCHECK(type == ExternalArrayType::kExternalInt8Array ||
           type == ExternalArrayType::kExternalInt16Array ||
           type == ExternalArrayType::kExternalInt32Array);
  }

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kInt32, ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  static constexpr int kIsLittleEndianIndex = 3;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

  ExternalArrayType type() const { return type_; }

 private:
  ExternalArrayType type_;
};

class StoreDoubleDataViewElement
    : public FixedInputNodeT<4, StoreDoubleDataViewElement> {
  using Base = FixedInputNodeT<4, StoreDoubleDataViewElement>;

 public:
  explicit StoreDoubleDataViewElement(uint64_t bitfield, ExternalArrayType type)
      : Base(bitfield) {
    DCHECK_EQ(type, ExternalArrayType::kExternalFloat64Array);
  }

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32,
      ValueRepresentation::kHoleyFloat64, ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  static constexpr int kIndexIndex = 1;
  static constexpr int kValueIndex = 2;
  static constexpr int kIsLittleEndianIndex = 3;
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }
  Input& value_input() { return input(kValueIndex); }
  Input& is_little_endian_input() { return input(kIsLittleEndianIndex); }

  bool is_little_endian_constant() {
    return IsConstantNode(is_little_endian_input().node()->opcode());
  }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StoreDoubleField : public FixedInputNodeT<2, StoreDoubleField> {
  using Base = FixedInputNodeT<2, StoreDoubleField>;

 public:
  explicit StoreDoubleField(uint64_t bitfield, int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kFloat64};

  int offset() const { return offset_; }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int offset_;
};

class StoreFloat64 : public FixedInputNodeT<2, StoreFloat64> {
  using Base = FixedInputNodeT<2, StoreFloat64>;

 public:
  explicit StoreFloat64(uint64_t bitfield, int offset)
      : Base(bitfield), offset_(offset) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kFloat64};

  int offset() const { return offset_; }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int offset_;
};

enum class StoreTaggedMode : uint8_t {
  kDefault,
  kInitializing,
  kTransitioning
};
inline bool IsInitializingOrTransitioning(StoreTaggedMode mode) {
  return mode == StoreTaggedMode::kInitializing ||
         mode == StoreTaggedMode::kTransitioning;
}

class StoreTaggedFieldNoWriteBarrier
    : public FixedInputNodeT<2, StoreTaggedFieldNoWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTaggedFieldNoWriteBarrier>;

 public:
  explicit StoreTaggedFieldNoWriteBarrier(uint64_t bitfield, int offset,
                                          StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset) {}

  // StoreTaggedFieldNoWriteBarrier never does a Deferred Call. However,
  // PhiRepresentationSelector can cause some StoreTaggedFieldNoWriteBarrier to
  // become StoreTaggedFieldWithWriteBarrier, which can do Deferred Calls, and
  // thus need the register snapshot. We thus set the DeferredCall property in
  // StoreTaggedFieldNoWriteBarrier so that it's allocated with enough space for
  // the register snapshot.
  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // Don't need to decompress value to store it.
  }
#endif

  int MaxCallStackArgs() const {
    // StoreTaggedFieldNoWriteBarrier never really does any call.
    return 0;
  }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
};

class StoreMap : public FixedInputNodeT<1, StoreMap> {
  using Base = FixedInputNodeT<1, StoreMap>;

 public:
  enum class Kind {
    kInitializing,
    kInitializingYoung,
    kTransitioning,
  };
  explicit StoreMap(uint64_t bitfield, compiler::MapRef map, Kind kind)
      : Base(bitfield | KindField::encode(kind)), map_(map) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  compiler::MapRef map() const { return map_; }
  Kind kind() const { return KindField::decode(bitfield()); }
  static Kind initializing_kind(AllocationType type) {
    return type == AllocationType::kYoung ? Kind::kInitializingYoung
                                          : Kind::kInitializing;
  }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

  void ClearUnstableNodeAspects(KnownNodeAspects&);

 private:
  using KindField = NextBitField<Kind, 3>;
  const compiler::MapRef map_;
};
std::ostream& operator<<(std::ostream& os, StoreMap::Kind);

class StoreTaggedFieldWithWriteBarrier
    : public FixedInputNodeT<2, StoreTaggedFieldWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTaggedFieldWithWriteBarrier>;

 public:
  explicit StoreTaggedFieldWithWriteBarrier(uint64_t bitfield, int offset,
                                            StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // Don't need to decompress value to store it.
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
};

class StoreScriptContextSlotWithWriteBarrier
    : public FixedInputNodeT<2, StoreScriptContextSlotWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreScriptContextSlotWithWriteBarrier>;

 public:
  explicit StoreScriptContextSlotWithWriteBarrier(uint64_t bitfield, int index)
      : Base(bitfield), index_(index) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite() |
                                              OpProperties::DeferredCall() |
                                              OpProperties::EagerDeopt();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return Context::OffsetOfElementAt(index()); }
  int index() const { return index_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kNewValueIndex = 1;
  Input& context_input() { return input(kContextIndex); }
  Input& new_value_input() { return input(kNewValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    context_input().node()->SetTaggedResultNeedsDecompress();
    new_value_input().node()->SetTaggedResultNeedsDecompress();
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const int index_;
};

class StoreTrustedPointerFieldWithWriteBarrier
    : public FixedInputNodeT<2, StoreTrustedPointerFieldWithWriteBarrier> {
  using Base = FixedInputNodeT<2, StoreTrustedPointerFieldWithWriteBarrier>;

 public:
  explicit StoreTrustedPointerFieldWithWriteBarrier(uint64_t bitfield,
                                                    int offset,
                                                    IndirectPointerTag tag,
                                                    StoreTaggedMode store_mode)
      : Base(bitfield | InitializingOrTransitioningField::encode(
                            IsInitializingOrTransitioning(store_mode))),
        offset_(offset),
        tag_(tag) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanWrite() | OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  int offset() const { return offset_; }
  IndirectPointerTag tag() const { return tag_; }
  bool initializing_or_transitioning() const {
    return InitializingOrTransitioningField::decode(bitfield());
  }

  static constexpr int kObjectIndex = 0;
  static constexpr int kValueIndex = 1;
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

#ifdef V8_COMPRESS_POINTERS
  void MarkTaggedInputsAsDecompressing() {
    object_input().node()->SetTaggedResultNeedsDecompress();
    // value is never compressed.
  }
#endif

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  using InitializingOrTransitioningField = NextBitField<bool, 1>;

  const int offset_;
  const IndirectPointerTag tag_;
};

class LoadGlobal : public FixedInputValueNodeT<1, LoadGlobal> {
  using Base = FixedInputValueNodeT<1, LoadGlobal>;

 public:
  explicit LoadGlobal(uint64_t bitfield, compiler::NameRef name,
                      const compiler::FeedbackSource& feedback,
                      TypeofMode typeof_mode)
      : Base(bitfield),
        name_(name),
        feedback_(feedback),
        typeof_mode_(typeof_mode) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }
  TypeofMode typeof_mode() const { return typeof_mode_; }

  Input& context() { return input(0); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
  const TypeofMode typeof_mode_;
};

class StoreGlobal : public FixedInputValueNodeT<2, StoreGlobal> {
  using Base = FixedInputValueNodeT<2, StoreGlobal>;

 public:
  explicit StoreGlobal(uint64_t bitfield, compiler::NameRef name,
                       const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  Input& context() { return input(0); }
  Input& value() { return input(1); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class UpdateJSArrayLength
    : public FixedInputValueNodeT<3, UpdateJSArrayLength> {
  using Base = FixedInputValueNodeT<3, UpdateJSArrayLength>;

 public:
  explicit UpdateJSArrayLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanWrite();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kInt32, ValueRepresentation::kTagged,
      ValueRepresentation::kInt32};

  // TODO(pthier): Use a more natural order once we can define the result
  // register to be equal to any input register.
  // The current order avoids any extra moves in the common case where index is
  // less than length
  static constexpr int kLengthIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kIndexIndex = 2;
  Input& length_input() { return input(kLengthIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& index_input() { return input(kIndexIndex); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class LoadNamedGeneric : public FixedInputValueNodeT<2, LoadNamedGeneric> {
  using Base = FixedInputValueNodeT<2, LoadNamedGeneric>;

 public:
  explicit LoadNamedGeneric(uint64_t bitfield, compiler::NameRef name,
                            const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class LoadNamedFromSuperGeneric
    : public FixedInputValueNodeT<3, LoadNamedFromSuperGeneric> {
  using Base = FixedInputValueNodeT<3, LoadNamedFromSuperGeneric>;

 public:
  explicit LoadNamedFromSuperGeneric(uint64_t bitfield, compiler::NameRef name,
                                     const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kReceiverIndex = 1;
  static constexpr int kLookupStartObjectIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& receiver() { return input(kReceiverIndex); }
  Input& lookup_start_object() { return input(kLookupStartObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class SetNamedGeneric : public FixedInputValueNodeT<3, SetNamedGeneric> {
  using Base = FixedInputValueNodeT<3, SetNamedGeneric>;

 public:
  explicit SetNamedGeneric(uint64_t bitfield, compiler::NameRef name,
                           const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class LoadEnumCacheLength
    : public FixedInputValueNodeT<1, LoadEnumCacheLength> {
  using Base = FixedInputValueNodeT<1, LoadEnumCacheLength>;

 public:
  explicit LoadEnumCacheLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kMapInput = 0;
  Input& map_input() { return input(kMapInput); }

  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringAt : public FixedInputValueNodeT<2, StringAt> {
  using Base = FixedInputValueNodeT<2, StringAt>;

 public:
  explicit StringAt(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::CanRead() |
                                              OpProperties::CanAllocate() |
                                              OpProperties::DeferredCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kInt32};

  static constexpr int kStringIndex = 0;
  static constexpr int kIndexIndex = 1;
  Input& string_input() { return input(kStringIndex); }
  Input& index_input() { return input(kIndexIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringLength : public FixedInputValueNodeT<1, StringLength> {
  using Base = FixedInputValueNodeT<1, StringLength>;

 public:
  explicit StringLength(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties =
      OpProperties::CanRead() | OpProperties::Int32();
  static constexpr
      typename Base::InputTypes kInputTypes{ValueRepresentation::kTagged};

  static constexpr int kObjectIndex = 0;
  Input& object_input() { return input(kObjectIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringConcat : public FixedInputValueNodeT<2, StringConcat> {
  using Base = FixedInputValueNodeT<2, StringConcat>;

 public:
  explicit StringConcat(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Call() |
                                              OpProperties::LazyDeopt() |
                                              OpProperties::CanThrow();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  Input& lhs() { return Node::input(0); }
  Input& rhs() { return Node::input(1); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class StringWrapperConcat
    : public FixedInputValueNodeT<2, StringWrapperConcat> {
  using Base = FixedInputValueNodeT<2, StringWrapperConcat>;

 public:
  explicit StringWrapperConcat(uint64_t bitfield) : Base(bitfield) {}

  static constexpr OpProperties kProperties = OpProperties::Call() |
                                              OpProperties::LazyDeopt() |
                                              OpProperties::CanThrow();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  Input& lhs() { return Node::input(0); }
  Input& rhs() { return Node::input(1); }

  int MaxCallStackArgs() const { return 0; }
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}
};

class DefineNamedOwnGeneric
    : public FixedInputValueNodeT<3, DefineNamedOwnGeneric> {
  using Base = FixedInputValueNodeT<3, DefineNamedOwnGeneric>;

 public:
  explicit DefineNamedOwnGeneric(uint64_t bitfield, compiler::NameRef name,
                                 const compiler::FeedbackSource& feedback)
      : Base(bitfield), name_(name), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::NameRef name() const { return name_; }
  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kValueIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const;

 private:
  const compiler::NameRef name_;
  const compiler::FeedbackSource feedback_;
};

class StoreInArrayLiteralGeneric
    : public FixedInputValueNodeT<4, StoreInArrayLiteralGeneric> {
  using Base = FixedInputValueNodeT<4, StoreInArrayLiteralGeneric>;

 public:
  explicit StoreInArrayLiteralGeneric(uint64_t bitfield,
                                      const compiler::FeedbackSource& feedback)
      : Base(bitfield), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged, ValueRepresentation::kTagged};

  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kNameIndex = 2;
  static constexpr int kValueIndex = 3;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& name_input() { return input(kNameIndex); }
  Input& value_input() { return input(kValueIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocationConstraints();
  void GenerateCode(MaglevAssembler*, const ProcessingState&);
  void PrintParams(std::ostream&, MaglevGraphLabeller*) const {}

 private:
  const compiler::FeedbackSource feedback_;
};

class GetKeyedGeneric : public FixedInputValueNodeT<3, GetKeyedGeneric> {
  using Base = FixedInputValueNodeT<3, GetKeyedGeneric>;

 public:
  explicit GetKeyedGeneric(uint64_t bitfield,
                           const compiler::FeedbackSource& feedback)
      : Base(bitfield), feedback_(feedback) {}

  // The implementation currently calls runtime.
  static constexpr OpProperties kProperties = OpProperties::JSCall();
  static constexpr typename Base::InputTypes kInputTypes{
      ValueRepresentation::kTagged, ValueRepresentation::kTagged,
      ValueRepresentation::kTagged};

  compiler::FeedbackSource feedback() const { return feedback_; }

  static constexpr int kContextIndex = 0;
  static constexpr int kObjectIndex = 1;
  static constexpr int kKeyIndex = 2;
  Input& context() { return input(kContextIndex); }
  Input& object_input() { return input(kObjectIndex); }
  Input& key_input() { return input(kKeyIndex); }

  int MaxCallStackArgs() const;
  void SetValueLocat
```
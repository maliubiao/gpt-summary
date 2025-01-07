Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/codegen/code-stub-assembler.h`. They have several specific questions about it, including:

1. **General Functionality:** What does this code do?
2. **Torque Source:**  If the filename ended in `.tq`, would it be a Torque source file?
3. **JavaScript Relation:** Does it relate to JavaScript functionality? If so, provide a JavaScript example.
4. **Code Logic Inference:**  Are there any code logic inferences possible? If so, provide example inputs and outputs.
5. **Common Programming Errors:** Does it help prevent common programming errors? If so, provide examples.
6. **Summary of Functionality:**  Provide a concise summary of its purpose.
7. **Part Number:** Acknowledge this is part 7 of 8.

**Plan:**

1. **Analyze the Code:** Read through the provided C++ code, paying attention to the function names, arguments, and return types. Identify the key functionalities.
2. **Address Torque Question:**  Answer the question about `.tq` files.
3. **Connect to JavaScript:** Identify functions or concepts that directly relate to JavaScript features. Create JavaScript examples to illustrate these connections.
4. **Infer Code Logic:** Look for functions with clear input/output relationships that can be demonstrated with examples.
5. **Identify Error Prevention:** Determine if any parts of the code help prevent common programming errors. Provide illustrative examples.
6. **Summarize Functionality:**  Provide a high-level overview of the purpose of the `CodeStubAssembler`.
7. **Acknowledge Part Number:**  State that this is part 7 of 8.
```cpp
e
  // call descriptor). It's not clear if that's worth the effort though for the
  // handful of builtins that need this.
  void SetSupportsDynamicParameterCount(
      TNode<JSFunction> callee, TNode<JSDispatchHandleT> dispatch_handle);

  // Figure out the SFI's code object using its data field.
  // If |data_type_out| is provided, the instance type of the function data will
  // be stored in it. In case the code object is a builtin (data is a Smi),
  // data_type_out will be set to 0.
  // If |if_compile_lazy| is provided then the execution will go to the given
  // label in case of an CompileLazy code object.
  TNode<Code> GetSharedFunctionInfoCode(
      TNode<SharedFunctionInfo> shared_info,
      TVariable<Uint16T>* data_type_out = nullptr,
      Label* if_compile_lazy = nullptr);

  TNode<JSFunction> AllocateRootFunctionWithContext(
      RootIndex function, TNode<Context> context,
      std::optional<TNode<NativeContext>> maybe_native_context);
  // Used from Torque because Torque
  TNode<JSFunction> AllocateRootFunctionWithContext(
      intptr_t function, TNode<Context> context,
      TNode<NativeContext> native_context) {
    return AllocateRootFunctionWithContext(static_cast<RootIndex>(function),
                                           context, native_context);
  }

  // Promise helpers
  TNode<Uint32T> PromiseHookFlags();
  TNode<BoolT> HasAsyncEventDelegate();
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  TNode<BoolT> IsContextPromiseHookEnabled(TNode<Uint32T> flags);
#endif
  TNode<BoolT> IsIsolatePromiseHookEnabled(TNode<Uint32T> flags);
  TNode<BoolT> IsAnyPromiseHookEnabled(TNode<Uint32T> flags);
  TNode<BoolT> IsAnyPromiseHookEnabled() {
    return IsAnyPromiseHookEnabled(PromiseHookFlags());
  }
  TNode<BoolT> IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
      TNode<Uint32T> flags);
  TNode<BoolT> IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate() {
    return IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
        PromiseHookFlags());
  }
  TNode<BoolT>
  IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
      TNode<Uint32T> flags);
  TNode<BoolT>
  IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate() {
    return IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
        PromiseHookFlags());
  }

  TNode<BoolT> NeedsAnyPromiseHooks(TNode<Uint32T> flags);
  TNode<BoolT> NeedsAnyPromiseHooks() {
    return NeedsAnyPromiseHooks(PromiseHookFlags());
  }

  // for..in helpers
  void CheckPrototypeEnumCache(TNode<JSReceiver> receiver,
                               TNode<Map> receiver_map, Label* if_fast,
                               Label* if_slow);
  TNode<Map> CheckEnumCache(TNode<JSReceiver> receiver, Label* if_empty,
                            Label* if_runtime);

  TNode<Object> GetArgumentValue(TorqueStructArguments args,
                                 TNode<IntPtrT> index);

  void SetArgumentValue(TorqueStructArguments args, TNode<IntPtrT> index,
                        TNode<Object> value);

  enum class FrameArgumentsArgcType {
    kCountIncludesReceiver,
    kCountExcludesReceiver
  };

  TorqueStructArguments GetFrameArguments(
      TNode<RawPtrT> frame, TNode<IntPtrT> argc,
      FrameArgumentsArgcType argc_type =
          FrameArgumentsArgcType::kCountExcludesReceiver);

  inline TNode<Int32T> JSParameterCount(int argc_without_receiver) {
    return Int32Constant(argc_without_receiver + kJSArgcReceiverSlots);
  }
  inline TNode<Word32T> JSParameterCount(TNode<Word32T> argc_without_receiver) {
    return Int32Add(argc_without_receiver, Int32Constant(kJSArgcReceiverSlots));
  }

  // Support for printf-style debugging
  void Print(const char* s);
  void Print(const char* prefix, TNode<MaybeObject> tagged_value);
  void Print(TNode<MaybeObject> tagged_value) {
    return Print(nullptr, tagged_value);
  }
  void Print(const char* prefix, TNode<UintPtrT> value);
  void Print(const char* prefix, TNode<Float64T> value);
  void PrintErr(const char* s);
  void PrintErr(const char* prefix, TNode<MaybeObject> tagged_value);
  void PrintErr(TNode<MaybeObject> tagged_value) {
    return PrintErr(nullptr, tagged_value);
  }
  void PrintToStream(const char* s, int stream);
  void PrintToStream(const char* prefix, TNode<MaybeObject> tagged_value,
                     int stream);
  void PrintToStream(const char* prefix, TNode<UintPtrT> value, int stream);
  void PrintToStream(const char* prefix, TNode<Float64T> value, int stream);

  template <class... TArgs>
  TNode<HeapObject> MakeTypeError(MessageTemplate message,
                                  TNode<Context> context, TArgs... args) {
    static_assert(sizeof...(TArgs) <= 3);
    return CAST(CallRuntime(Runtime::kNewTypeError, context,
                            SmiConstant(message), args...));
  }

  void Abort(AbortReason reason) {
    CallRuntime(Runtime::kAbort, NoContextConstant(), SmiConstant(reason));
    Unreachable();
  }

  bool ConstexprBoolNot(bool value) { return !value; }
  int31_t ConstexprIntegerLiteralToInt31(const IntegerLiteral& i) {
    return int31_t(i.To<int32_t>());
  }
  int32_t ConstexprIntegerLiteralToInt32(const IntegerLiteral& i) {
    return i.To<int32_t>();
  }
  uint32_t ConstexprIntegerLiteralToUint32(const IntegerLiteral& i) {
    return i.To<uint32_t>();
  }
  int8_t ConstexprIntegerLiteralToInt8(const IntegerLiteral& i) {
    return i.To<int8_t>();
  }
  uint8_t ConstexprIntegerLiteralToUint8(const IntegerLiteral& i) {
    return i.To<uint8_t>();
  }
  int64_t ConstexprIntegerLiteralToInt64(const IntegerLiteral& i) {
    return i.To<int64_t>();
  }
  uint64_t ConstexprIntegerLiteralToUint64(const IntegerLiteral& i) {
    return i.To<uint64_t>();
  }
  intptr_t ConstexprIntegerLiteralToIntptr(const IntegerLiteral& i) {
    return i.To<intptr_t>();
  }
  uintptr_t ConstexprIntegerLiteralToUintptr(const IntegerLiteral& i) {
    return i.To<uintptr_t>();
  }
  double ConstexprIntegerLiteralToFloat64(const IntegerLiteral& i) {
    int64_t i_value = i.To<int64_t>();
    double d_value = static_cast<double>(i_value);
    CHECK_EQ(i_value, static_cast<int64_t>(d_value));
    return d_value;
  }
  bool ConstexprIntegerLiteralEqual(IntegerLiteral lhs, IntegerLiteral rhs) {
    return lhs == rhs;
  }
  IntegerLiteral ConstexprIntegerLiteralAdd(const IntegerLiteral& lhs,
                                            const IntegerLiteral& rhs);
  IntegerLiteral ConstexprIntegerLiteralLeftShift(const IntegerLiteral& lhs,
                                                  const IntegerLiteral& rhs);
  IntegerLiteral ConstexprIntegerLiteralBitwiseOr(const IntegerLiteral& lhs,
                                                  const IntegerLiteral& rhs);

  bool ConstexprInt31Equal(int31_t a, int31_t b) { return a == b; }
  bool ConstexprInt31NotEqual(int31_t a, int31_t b) { return a != b; }
  bool ConstexprInt31GreaterThanEqual(int31_t a, int31_t b) { return a >= b; }
  bool ConstexprUint32Equal(uint32_t a, uint32_t b) { return a == b; }
  bool ConstexprUint32NotEqual(uint32_t a, uint32_t b) { return a != b; }
  bool ConstexprInt32Equal(int32_t a, int32_t b) { return a == b; }
  bool ConstexprInt32NotEqual(int32_t a, int32_t b) { return a != b; }
  bool ConstexprInt32GreaterThanEqual(int32_t a, int32_t b) { return a >= b; }
  uint32_t ConstexprUint32Add(uint32_t a, uint32_t b) { return a + b; }
  int32_t ConstexprUint32Sub(uint32_t a, uint32_t b) { return a - b; }
  int32_t ConstexprInt32Sub(int32_t a, int32_t b) { return a - b; }
  int32_t ConstexprInt32Add(int32_t a, int32_t b) { return a + b; }
  int31_t ConstexprInt31Add(int31_t a, int31_t b) {
    int32_t val;
    CHECK(!base::bits::SignedAddOverflow32(a, b, &val));
    return val;
  }
  int31_t ConstexprInt31Mul(int31_t a, int31_t b) {
    int32_t val;
    CHECK(!base::bits::SignedMulOverflow32(a, b, &val));
    return val;
  }

  int32_t ConstexprWord32Or(int32_t a, int32_t b) { return a | b; }
  uint32_t ConstexprWord32Shl(uint32_t a, int32_t b) { return a << b; }

  bool ConstexprUintPtrLessThan(uintptr_t a, uintptr_t b) { return a < b; }

  // CSA does not support 64-bit types on 32-bit platforms so as a workaround
  // the kMaxSafeIntegerUint64 is defined as uintptr and allowed to be used only
  // inside if constexpr (Is64()) i.e. on 64-bit architectures.
  static uintptr_t MaxSafeIntegerUintPtr() {
#if defined(V8_HOST_ARCH_64_BIT)
    // This ifdef is required to avoid build issues on 32-bit MSVC which
    // complains about static_cast<uintptr_t>(kMaxSafeIntegerUint64).
    return kMaxSafeIntegerUint64;
#else
    UNREACHABLE();
#endif
  }

  void PerformStackCheck(TNode<Context> context);

  void SetPropertyLength(TNode<Context> context, TNode<Object> array,
                         TNode<Number> length);

  // Implements DescriptorArray::Search().
  void DescriptorLookup(TNode<Name> unique_name,
                        TNode<DescriptorArray> descriptors,
                        TNode<Uint32T> bitfield3, Label* if_found,
                        TVariable<IntPtrT>* var_name_index,
                        Label* if_not_found);

  // Implements TransitionArray::SearchName() - searches for first transition
  // entry with given name (note that there could be multiple entries with
  // the same name).
  void TransitionLookup(TNode<Name> unique_name,
                        TNode<TransitionArray> transitions, Label* if_found,
                        TVariable<IntPtrT>* var_name_index,
                        Label* if_not_found);

  // Implements generic search procedure like i::Search<Array>().
  template <typename Array>
  void Lookup(TNode<Name> unique_name, TNode<Array> array,
              TNode<Uint32T> number_of_valid_entries, Label* if_found,
              TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Implements generic linear search procedure like i::LinearSearch<Array>().
  template <typename Array>
  void LookupLinear(TNode<Name> unique_name, TNode<Array> array,
                    TNode<Uint32T> number_of_valid_entries, Label* if_found,
                    TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Implements generic binary search procedure like i::BinarySearch<Array>().
  template <typename Array>
  void LookupBinary(TNode<Name> unique_name, TNode<Array> array,
                    TNode<Uint32T> number_of_valid_entries, Label* if_found,
                    TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Converts [Descriptor/Transition]Array entry number to a fixed array index.
  template <typename Array>
  TNode<IntPtrT> EntryIndexToIndex(TNode<Uint32T> entry_index);

  // Implements [Descriptor/Transition]Array::ToKeyIndex.
  template <typename Array>
  TNode<IntPtrT> ToKeyIndex(TNode<Uint32T> entry_index);

  // Implements [Descriptor/Transition]Array::GetKey.
  template <typename Array>
  TNode<Name> GetKey(TNode<Array> array, TNode<Uint32T> entry_index);

  // Implements DescriptorArray::GetDetails.
  TNode<Uint32T> DescriptorArrayGetDetails(TNode<DescriptorArray> descriptors,
                                           TNode<Uint32T> descriptor_number);

  using ForEachDescriptorBodyFunction =
      std::function<void(TNode<IntPtrT> descriptor_key_index)>;

  // Descriptor array accessors based on key_index, which is equal to
  // DescriptorArray::ToKeyIndex(descriptor).
  TNode<Name> LoadKeyByKeyIndex(TNode<DescriptorArray> container,
                                TNode<IntPtrT> key_index);
  TNode<Uint32T> LoadDetailsByKeyIndex(TNode<DescriptorArray> container,
                                       TNode<IntPtrT> key_index);
  TNode<Object> LoadValueByKeyIndex(TNode<DescriptorArray> container,
                                    TNode<IntPtrT> key_index);
  TNode<MaybeObject> LoadFieldTypeByKeyIndex(TNode<DescriptorArray> container,
                                             TNode<IntPtrT> key_index);

  TNode<IntPtrT> DescriptorEntryToIndex(TNode<IntPtrT> descriptor);

  // Descriptor array accessors based on descriptor.
  TNode<Name> LoadKeyByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                       TNode<IntPtrT> descriptor);
  TNode<Name> LoadKeyByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                       int descriptor);
  TNode<Uint32T> LoadDetailsByDescriptorEntry(
      TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor);
  TNode<Uint32T> LoadDetailsByDescriptorEntry(
      TNode<DescriptorArray> descriptors, int descriptor);
  TNode<Object> LoadValueByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                           TNode<IntPtrT> descriptor);
  TNode<Object> LoadValueByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                           int descriptor);
  TNode<MaybeObject> LoadFieldTypeByDescriptorEntry(
      TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor);

  using ForEachKeyValueFunction =
      std::function<void(TNode<Name> key, LazyNode<Object> value)>;

  // For each JSObject property (in DescriptorArray order), check if the key is
  // enumerable, and if so, load the value from the receiver and evaluate the
  // closure. The value is provided as a LazyNode, which lazily evaluates
  // accessors if present.
  void ForEachEnumerableOwnProperty(TNode<Context> context, TNode<Map> map,
                                    TNode<JSObject> object,
                                    PropertiesEnumerationMode mode,
                                    const ForEachKeyValueFunction& body,
                                    Label* bailout);

  TNode<Object> CallGetterIfAccessor(
      TNode<Object> value, TNode<HeapObject> holder, TNode<Uint32T> details,
      TNode<Context> context, TNode<Object> receiver, TNode<Object> name,
      Label* if_bailout,
      GetOwnPropertyMode mode = kCallJSGetterDontUseCachedName,
      ExpectedReceiverMode expected_receiver_mode = kExpectingJSReceiver);

  TNode<IntPtrT> TryToIntptr(TNode<Object> key, Label* if_not_intptr,
                             TVariable<Int32T>* var_instance_type = nullptr);

  TNode<JSArray> ArrayCreate(TNode<Context> context, TNode<Number> length);

  // Allocate a clone of a mutable primitive, if {object} is a mutable
  // HeapNumber.
  TNode<Object> CloneIfMutablePrimitive(TNode<Object> object);

  TNode<Smi> RefillMathRandom(TNode<NativeContext> native_context);

  void RemoveFinalizationRegistryCellFromUnregisterTokenMap(
      TNode<JSFinalizationRegistry> finalization_registry,
      TNode<WeakCell> weak_cell);

  TNode<IntPtrT> FeedbackIteratorEntrySize() {
    return IntPtrConstant(FeedbackIterator::kEntrySize);
  }

  TNode<IntPtrT> FeedbackIteratorHandlerOffset() {
    return IntPtrConstant(FeedbackIterator::kHandlerOffset);
  }

  TNode<SwissNameDictionary> AllocateSwissNameDictionary(
      TNode<IntPtrT> at_least_space_for);
  TNode<SwissNameDictionary> AllocateSwissNameDictionary(
      int at_least_space_for);

  TNode<SwissNameDictionary> AllocateSwissNameDictionaryWithCapacity(
      TNode<IntPtrT> capacity);

  // MT stands for "minus tag".
  TNode<IntPtrT> SwissNameDictionaryOffsetIntoDataTableMT(
      TNode<SwissNameDictionary> dict, TNode<IntPtrT> index, int field_index);

  // MT stands for "minus tag".
  TNode<IntPtrT> SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(
      TNode<SwissNameDictionary> dict, TNode<IntPtrT> capacity,
      TNode<IntPtrT> index);

  TNode<IntPtrT> LoadSwissNameDictionaryNumberOfElements(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity);

  TNode<IntPtrT> LoadSwissNameDictionaryNumberOfDeletedElements(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity);

  // Specialized operation to be used when adding entries:
  // If used capacity (= number of present + deleted elements) is less than
  // |max_usable|, increment the number of present entries and return the used
  // capacity value (prior to the incrementation). Otherwise, goto |bailout|.
  TNode<Uint32T> SwissNameDictionaryIncreaseElementCountOrBailout(
      TNode<ByteArray> meta_table, TNode<IntPtrT> capacity,
      TNode<Uint32T> max_usable_capacity, Label* bailout);

  // Specialized operation to be used when deleting entries: Decreases the
  // number of present entries and increases the number of deleted ones. Returns
  // new (= decremented) number of present entries.
  TNode<Uint32T> SwissNameDictionaryUpdateCountsForDeletion(
      TNode<ByteArray> meta_table, TNode<IntPtrT> capacity);

  void StoreSwissNameDictionaryCapacity(TNode<SwissNameDictionary> table,
                                        TNode<Int32T> capacity);

  void StoreSwissNameDictionaryEnumToEntryMapping(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
      TNode<IntPtrT> enum_index, TNode<Int32T> entry);

  TNode<Name> LoadSwissNameDictionaryKey(TNode<SwissNameDictionary> dict,
                                         TNode<IntPtrT> entry);

  void StoreSwissNameDictionaryKeyAndValue(TNode<SwissNameDictionary> dict,
                                           TNode<IntPtrT> entry,
                                           TNode<Object> key,
                                           TNode<Object> value);

  // Equivalent to SwissNameDictionary::SetCtrl, therefore preserves the copy of
  // the first group at the end of the control table.
  void SwissNameDictionarySetCtrl(TNode<SwissNameDictionary> table,
                                  TNode<IntPtrT> capacity, TNode<IntPtrT> entry,
                                  TNode<Uint8T> ctrl);

  TNode<Uint64T> LoadSwissNameDictionaryCtrlTableGroup(TNode<IntPtrT> address);

  TNode<Uint8T> LoadSwissNameDictionaryPropertyDetails(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
      TNode<IntPtrT> entry);

  void StoreSwissNameDictionaryPropertyDetails(TNode<SwissNameDictionary> table,
                                               TNode<IntPtrT> capacity,
                                               TNode<IntPtrT> entry,
                                               TNode<Uint8T> details);

  TNode<SwissNameDictionary> CopySwissNameDictionary(
      TNode<SwissNameDictionary> original);

  void SwissNameDictionaryFindEntry(TNode<SwissNameDictionary> table,
                                    TNode<Name> key, Label* found,
                                    TVariable<IntPtrT>* var_found_entry,
                                    Label* not_found);

  void SwissNameDictionaryAdd(TNode<SwissNameDictionary> table, TNode<Name> key,
                              TNode<Object> value,
                              TNode<Uint8T> property_details,
                              Label* needs_resize);

  TNode<BoolT> IsMarked(TNode<Object> object);

  void GetMarkBit(TNode<IntPtrT> object, TNode<IntPtrT>* cell,
                  TNode<IntPtrT>* mask);

  TNode<BoolT> IsPageFlagSet(TNode<IntPtrT> object, int mask) {
    TNode<IntPtrT> header = MemoryChunkFromAddress(object);
    TNode<IntPtrT> flags = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), header,
             IntPtrConstant(MemoryChunk::FlagsOffset())));
    return WordNotEqual(WordAnd(flags, IntPtrConstant(mask)),
                        IntPtrConstant(0));
  }

  TNode<BoolT> IsPageFlagReset(TNode<IntPtrT> object, int mask) {
    TNode<IntPtrT> header = MemoryChunkFromAddress(object);
    TNode<IntPtrT> flags = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), header,
             IntPtrConstant(MemoryChunk::FlagsOffset())));
    return WordEqual(WordAnd(flags, IntPtrConstant(mask)), IntPtrConstant(0));
  }

 private:
  friend class CodeStubArguments;

  void BigInt64Comparison(Operation op, TNode<Object>& left,
                          TNode<Object>& right, Label* return_true,
                          Label* return_false);

  void HandleBreakOnNode();

  TNode<HeapObject> AllocateRawDoubleAligned(TNode<IntPtrT> size_in_bytes,
                                             AllocationFlags flags,
                                             TNode<RawPtrT> top_address,
                                             TNode<RawPtrT> limit_address);
  TNode<HeapObject> AllocateRawUnaligned(TNode<IntPtrT> size_in_bytes,
                                         AllocationFlags flags,
                                         TNode<RawPtrT> top_address,
                                         TNode<RawPtrT> limit_address);
  TNode<HeapObject> AllocateRaw(TNode<IntPtrT> size_in_bytes,
                                AllocationFlags flags,
                                TNode<RawPtrT> top_address,
                                TNode<RawPtrT> limit_address);

  // Allocate and return a JSArray of given total size in bytes with header
  // fields initialized.
  TNode<JSArray> AllocateUninitializedJSArray(
      TNode<Map> array_map, TNode<Smi> length,
      std::optional<TNode<AllocationSite>> allocation_site,
      TNode<IntPtrT> size_in_bytes);

  // Increases the provided capacity to the next valid value, if necessary.
  template <typename CollectionType>
  TNode<CollectionType> AllocateOrderedHashTable(TNode<IntPtrT> capacity);

  // Uses the provided capacity (which must be valid) in verbatim.
  template <typename CollectionType>
  TNode<CollectionType> AllocateOrderedHashTableWithCapacity(
      TNode<IntPtrT> capacity);

  TNode<IntPtrT> SmiShiftBitsConstant() {
    return IntPtrConstant(kSmiShiftSize + kSmiTagSize);
  }
  TNode<Int32T> SmiShiftBitsConstant32() {
    return Int32Constant(kSmiShiftSize + kSmiTagSize);
  }

  TNode<String> AllocateSlicedString(RootIndex map_root_index,
                                     TNode<Uint32T> length,
                                     TNode<String> parent, TNode<Smi> offset);

  // Implements [Descriptor/Transition]Array::number_of_entries.
  template <typename Array>
  TNode<Uint32T> NumberOfEntries(TNode<Array> array);

  template <typename Array>
  constexpr int MaxNumberOfEntries();

  // Implements [Descriptor/Transition]Array::GetSortedKeyIndex.
  template <typename Array>
  TNode<Uint32T> GetSortedKeyIndex(TNode<Array> descriptors,
                                   TNode<Uint32T> entry_index);

  TNode<Smi> CollectFeedbackForString(TNode<Int32T> instance_type);
  void GenerateEqual_Same(TNode<Object> value, Label* if_equal,
                          Label* if_notequal,
                          TVariable<Smi>* var_type_feedback = nullptr);

  static const int kElementLoopUnrollThreshold = 8;

  // {convert_bigint} is only meaningful when {mode} == kToNumber.
  TNode<Numeric> NonNumberToNumberOrNumeric(
      TNode<Context> context, TNode<HeapObject> input, Object::Conversion mode,
      BigIntHandling bigint_handling = BigIntHandling::kThrow);

  enum IsKnownTaggedPointer { kNo, kYes };
  template <Object::Conversion conversion>
  void TaggedToWord32OrBigIntImpl(
      TNode<Context> context, TNode<Object> value, Label* if_number,
      TVariable<Word32T>* var_word32,
      IsKnownTaggedPointer is_known_tagged_pointer,
      const FeedbackValues& feedback, Label* if_bigint = nullptr,
      Label* if_bigint64 = nullptr,
      TVariable<BigInt>* var_maybe_bigint = nullptr);

  // Low-level accessors for Descriptor arrays.
  template <typename T>
  TNode<T> LoadDescriptorArrayElement(TNode<DescriptorArray> object,
                                      TNode<IntPtrT> index,
                                      int additional_offset);

  // Hide LoadRoot for subclasses of CodeStubAssembler. If you get an error
  // complaining about this method, don't make it public, add your root to
  // HEAP_(IM)MUTABLE_IMMOVABLE_OBJECT_LIST instead. If you *really* need
  // LoadRoot, use CodeAssembler::LoadRoot.
  TNode<Object> LoadRoot(RootIndex root_index) {
    return CodeAssembler::LoadRoot(root_index);
  }

  TNode<AnyTaggedT> LoadRootMapWord(RootIndex root_index) {
    return CodeAssembler::LoadRootMapWord(root_index);
  }

  template <typename TIndex>
  void StoreFixedArrayOrPropertyArrayElement(
      TNode<UnionOf<FixedArray, PropertyArray>> array, TNode<TIndex> index,
      TNode<Object> value, WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0);

  template <typename TIndex>
  void StoreElementTypedArrayBigInt(TNode<RawPtrT> elements, ElementsKind kind,
                                    TNode<TIndex> index, TNode<BigInt> value);

  template <typename TIndex>
  void StoreElementTypedArrayWord32(TNode<RawPtrT> elements, ElementsKind kind,
                                    TNode<TIndex> index, TNode<Word32T> value);

  // Store value to an elements array with given elements kind.
  // TODO(turbofan): For BIGINT64_ELEMENTS and BIGUINT64_ELEMENTS
  // we pass {value} as BigInt object instead of int64_t. We should
  // teach TurboFan to handle int64_t on 32-bit platforms eventually.
  // TODO(solanes): This method can go away and simplify into only one version
  // of StoreElement once we have "if constexpr" available to use.
  template <typename TArray, typename TIndex, typename TValue>
  void StoreElementTypedArray(TNode<TArray> elements, ElementsKind kind,
                              TNode<TIndex> index, TNode<TValue> value);

  template <typename TIndex>
  void StoreElement(TNode<FixedArrayBase> elements, ElementsKind kind,
                    TNode<TIndex> index, TNode<Object> value);

  template <typename TIndex>
  void StoreElement(TNode<FixedArrayBase> elements, ElementsKind kind,
                    TNode<TIndex> index, TNode<Float64T> value);

  // Converts {input} to a number if {input} is a plain primitve (i.e. String or
  // Oddball) and stores the result in {var_result}. Otherwise, it bails out to
  // {if_bailout}.
  void TryPlainPrimitiveNonNumberToNumber(TNode<HeapObject> input,
                                          TVariable<Number>* var_result,
                                          Label* if_bailout);

  void DcheckHasValidMap(TNode<HeapObject> object);

  template <typename TValue>
  void EmitElementStoreTypedArray(TNode<JSTypedArray> typed_array,
                                  TNode<IntPtrT> key, TNode<Object> value,
                                  ElementsKind elements_kind,
                                  KeyedAccessStoreMode store_mode,
                                  Label* bailout, TNode<Context> context,
                                  TVariable<Object>* maybe_converted_value);

  template <typename TValue>
  void EmitElementStoreTypedArrayUpdateValue(
      TNode<Object> value, ElementsKind elements_kind,
      TNode<TValue> converted_value, TVariable<Object>* maybe_converted_value);
};

class V8_EXPORT_PRIVATE CodeStubArguments {
 public:
  // |argc| specifies the number of arguments passed to the builtin.
  CodeStubArguments(CodeStubAssembler* assembler, TNode<IntPtrT> argc)
      : CodeStubArguments(assembler, argc, TNode<RawPtrT>()) {}
  CodeStubArguments(CodeStubAssembler* assembler, TNode<Int32T> argc)
      : CodeStubArguments(assembler, assembler->ChangeInt32ToIntPtr(argc)) {}
  CodeStubArguments(CodeStubAssembler* assembler, TNode<IntPtrT> argc,
                    TNode<RawPtrT> fp);

  // Used by Torque to construct arguments based on a Torque-defined
  // struct of values.
  CodeStubArguments(CodeStubAssembler* assembler,
                    TorqueStructArguments torque_arguments)
      : assembler_(assembler),
        
Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第7部分，共8部分，请归纳一下它的功能

"""
e
  // call descriptor). It's not clear if that's worth the effort though for the
  // handful of builtins that need this.
  void SetSupportsDynamicParameterCount(
      TNode<JSFunction> callee, TNode<JSDispatchHandleT> dispatch_handle);

  // Figure out the SFI's code object using its data field.
  // If |data_type_out| is provided, the instance type of the function data will
  // be stored in it. In case the code object is a builtin (data is a Smi),
  // data_type_out will be set to 0.
  // If |if_compile_lazy| is provided then the execution will go to the given
  // label in case of an CompileLazy code object.
  TNode<Code> GetSharedFunctionInfoCode(
      TNode<SharedFunctionInfo> shared_info,
      TVariable<Uint16T>* data_type_out = nullptr,
      Label* if_compile_lazy = nullptr);

  TNode<JSFunction> AllocateRootFunctionWithContext(
      RootIndex function, TNode<Context> context,
      std::optional<TNode<NativeContext>> maybe_native_context);
  // Used from Torque because Torque
  TNode<JSFunction> AllocateRootFunctionWithContext(
      intptr_t function, TNode<Context> context,
      TNode<NativeContext> native_context) {
    return AllocateRootFunctionWithContext(static_cast<RootIndex>(function),
                                           context, native_context);
  }

  // Promise helpers
  TNode<Uint32T> PromiseHookFlags();
  TNode<BoolT> HasAsyncEventDelegate();
#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  TNode<BoolT> IsContextPromiseHookEnabled(TNode<Uint32T> flags);
#endif
  TNode<BoolT> IsIsolatePromiseHookEnabled(TNode<Uint32T> flags);
  TNode<BoolT> IsAnyPromiseHookEnabled(TNode<Uint32T> flags);
  TNode<BoolT> IsAnyPromiseHookEnabled() {
    return IsAnyPromiseHookEnabled(PromiseHookFlags());
  }
  TNode<BoolT> IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
      TNode<Uint32T> flags);
  TNode<BoolT> IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate() {
    return IsIsolatePromiseHookEnabledOrHasAsyncEventDelegate(
        PromiseHookFlags());
  }
  TNode<BoolT>
  IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
      TNode<Uint32T> flags);
  TNode<BoolT>
  IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate() {
    return IsIsolatePromiseHookEnabledOrDebugIsActiveOrHasAsyncEventDelegate(
        PromiseHookFlags());
  }

  TNode<BoolT> NeedsAnyPromiseHooks(TNode<Uint32T> flags);
  TNode<BoolT> NeedsAnyPromiseHooks() {
    return NeedsAnyPromiseHooks(PromiseHookFlags());
  }

  // for..in helpers
  void CheckPrototypeEnumCache(TNode<JSReceiver> receiver,
                               TNode<Map> receiver_map, Label* if_fast,
                               Label* if_slow);
  TNode<Map> CheckEnumCache(TNode<JSReceiver> receiver, Label* if_empty,
                            Label* if_runtime);

  TNode<Object> GetArgumentValue(TorqueStructArguments args,
                                 TNode<IntPtrT> index);

  void SetArgumentValue(TorqueStructArguments args, TNode<IntPtrT> index,
                        TNode<Object> value);

  enum class FrameArgumentsArgcType {
    kCountIncludesReceiver,
    kCountExcludesReceiver
  };

  TorqueStructArguments GetFrameArguments(
      TNode<RawPtrT> frame, TNode<IntPtrT> argc,
      FrameArgumentsArgcType argc_type =
          FrameArgumentsArgcType::kCountExcludesReceiver);

  inline TNode<Int32T> JSParameterCount(int argc_without_receiver) {
    return Int32Constant(argc_without_receiver + kJSArgcReceiverSlots);
  }
  inline TNode<Word32T> JSParameterCount(TNode<Word32T> argc_without_receiver) {
    return Int32Add(argc_without_receiver, Int32Constant(kJSArgcReceiverSlots));
  }

  // Support for printf-style debugging
  void Print(const char* s);
  void Print(const char* prefix, TNode<MaybeObject> tagged_value);
  void Print(TNode<MaybeObject> tagged_value) {
    return Print(nullptr, tagged_value);
  }
  void Print(const char* prefix, TNode<UintPtrT> value);
  void Print(const char* prefix, TNode<Float64T> value);
  void PrintErr(const char* s);
  void PrintErr(const char* prefix, TNode<MaybeObject> tagged_value);
  void PrintErr(TNode<MaybeObject> tagged_value) {
    return PrintErr(nullptr, tagged_value);
  }
  void PrintToStream(const char* s, int stream);
  void PrintToStream(const char* prefix, TNode<MaybeObject> tagged_value,
                     int stream);
  void PrintToStream(const char* prefix, TNode<UintPtrT> value, int stream);
  void PrintToStream(const char* prefix, TNode<Float64T> value, int stream);

  template <class... TArgs>
  TNode<HeapObject> MakeTypeError(MessageTemplate message,
                                  TNode<Context> context, TArgs... args) {
    static_assert(sizeof...(TArgs) <= 3);
    return CAST(CallRuntime(Runtime::kNewTypeError, context,
                            SmiConstant(message), args...));
  }

  void Abort(AbortReason reason) {
    CallRuntime(Runtime::kAbort, NoContextConstant(), SmiConstant(reason));
    Unreachable();
  }

  bool ConstexprBoolNot(bool value) { return !value; }
  int31_t ConstexprIntegerLiteralToInt31(const IntegerLiteral& i) {
    return int31_t(i.To<int32_t>());
  }
  int32_t ConstexprIntegerLiteralToInt32(const IntegerLiteral& i) {
    return i.To<int32_t>();
  }
  uint32_t ConstexprIntegerLiteralToUint32(const IntegerLiteral& i) {
    return i.To<uint32_t>();
  }
  int8_t ConstexprIntegerLiteralToInt8(const IntegerLiteral& i) {
    return i.To<int8_t>();
  }
  uint8_t ConstexprIntegerLiteralToUint8(const IntegerLiteral& i) {
    return i.To<uint8_t>();
  }
  int64_t ConstexprIntegerLiteralToInt64(const IntegerLiteral& i) {
    return i.To<int64_t>();
  }
  uint64_t ConstexprIntegerLiteralToUint64(const IntegerLiteral& i) {
    return i.To<uint64_t>();
  }
  intptr_t ConstexprIntegerLiteralToIntptr(const IntegerLiteral& i) {
    return i.To<intptr_t>();
  }
  uintptr_t ConstexprIntegerLiteralToUintptr(const IntegerLiteral& i) {
    return i.To<uintptr_t>();
  }
  double ConstexprIntegerLiteralToFloat64(const IntegerLiteral& i) {
    int64_t i_value = i.To<int64_t>();
    double d_value = static_cast<double>(i_value);
    CHECK_EQ(i_value, static_cast<int64_t>(d_value));
    return d_value;
  }
  bool ConstexprIntegerLiteralEqual(IntegerLiteral lhs, IntegerLiteral rhs) {
    return lhs == rhs;
  }
  IntegerLiteral ConstexprIntegerLiteralAdd(const IntegerLiteral& lhs,
                                            const IntegerLiteral& rhs);
  IntegerLiteral ConstexprIntegerLiteralLeftShift(const IntegerLiteral& lhs,
                                                  const IntegerLiteral& rhs);
  IntegerLiteral ConstexprIntegerLiteralBitwiseOr(const IntegerLiteral& lhs,
                                                  const IntegerLiteral& rhs);

  bool ConstexprInt31Equal(int31_t a, int31_t b) { return a == b; }
  bool ConstexprInt31NotEqual(int31_t a, int31_t b) { return a != b; }
  bool ConstexprInt31GreaterThanEqual(int31_t a, int31_t b) { return a >= b; }
  bool ConstexprUint32Equal(uint32_t a, uint32_t b) { return a == b; }
  bool ConstexprUint32NotEqual(uint32_t a, uint32_t b) { return a != b; }
  bool ConstexprInt32Equal(int32_t a, int32_t b) { return a == b; }
  bool ConstexprInt32NotEqual(int32_t a, int32_t b) { return a != b; }
  bool ConstexprInt32GreaterThanEqual(int32_t a, int32_t b) { return a >= b; }
  uint32_t ConstexprUint32Add(uint32_t a, uint32_t b) { return a + b; }
  int32_t ConstexprUint32Sub(uint32_t a, uint32_t b) { return a - b; }
  int32_t ConstexprInt32Sub(int32_t a, int32_t b) { return a - b; }
  int32_t ConstexprInt32Add(int32_t a, int32_t b) { return a + b; }
  int31_t ConstexprInt31Add(int31_t a, int31_t b) {
    int32_t val;
    CHECK(!base::bits::SignedAddOverflow32(a, b, &val));
    return val;
  }
  int31_t ConstexprInt31Mul(int31_t a, int31_t b) {
    int32_t val;
    CHECK(!base::bits::SignedMulOverflow32(a, b, &val));
    return val;
  }

  int32_t ConstexprWord32Or(int32_t a, int32_t b) { return a | b; }
  uint32_t ConstexprWord32Shl(uint32_t a, int32_t b) { return a << b; }

  bool ConstexprUintPtrLessThan(uintptr_t a, uintptr_t b) { return a < b; }

  // CSA does not support 64-bit types on 32-bit platforms so as a workaround
  // the kMaxSafeIntegerUint64 is defined as uintptr and allowed to be used only
  // inside if constexpr (Is64()) i.e. on 64-bit architectures.
  static uintptr_t MaxSafeIntegerUintPtr() {
#if defined(V8_HOST_ARCH_64_BIT)
    // This ifdef is required to avoid build issues on 32-bit MSVC which
    // complains about static_cast<uintptr_t>(kMaxSafeIntegerUint64).
    return kMaxSafeIntegerUint64;
#else
    UNREACHABLE();
#endif
  }

  void PerformStackCheck(TNode<Context> context);

  void SetPropertyLength(TNode<Context> context, TNode<Object> array,
                         TNode<Number> length);

  // Implements DescriptorArray::Search().
  void DescriptorLookup(TNode<Name> unique_name,
                        TNode<DescriptorArray> descriptors,
                        TNode<Uint32T> bitfield3, Label* if_found,
                        TVariable<IntPtrT>* var_name_index,
                        Label* if_not_found);

  // Implements TransitionArray::SearchName() - searches for first transition
  // entry with given name (note that there could be multiple entries with
  // the same name).
  void TransitionLookup(TNode<Name> unique_name,
                        TNode<TransitionArray> transitions, Label* if_found,
                        TVariable<IntPtrT>* var_name_index,
                        Label* if_not_found);

  // Implements generic search procedure like i::Search<Array>().
  template <typename Array>
  void Lookup(TNode<Name> unique_name, TNode<Array> array,
              TNode<Uint32T> number_of_valid_entries, Label* if_found,
              TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Implements generic linear search procedure like i::LinearSearch<Array>().
  template <typename Array>
  void LookupLinear(TNode<Name> unique_name, TNode<Array> array,
                    TNode<Uint32T> number_of_valid_entries, Label* if_found,
                    TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Implements generic binary search procedure like i::BinarySearch<Array>().
  template <typename Array>
  void LookupBinary(TNode<Name> unique_name, TNode<Array> array,
                    TNode<Uint32T> number_of_valid_entries, Label* if_found,
                    TVariable<IntPtrT>* var_name_index, Label* if_not_found);

  // Converts [Descriptor/Transition]Array entry number to a fixed array index.
  template <typename Array>
  TNode<IntPtrT> EntryIndexToIndex(TNode<Uint32T> entry_index);

  // Implements [Descriptor/Transition]Array::ToKeyIndex.
  template <typename Array>
  TNode<IntPtrT> ToKeyIndex(TNode<Uint32T> entry_index);

  // Implements [Descriptor/Transition]Array::GetKey.
  template <typename Array>
  TNode<Name> GetKey(TNode<Array> array, TNode<Uint32T> entry_index);

  // Implements DescriptorArray::GetDetails.
  TNode<Uint32T> DescriptorArrayGetDetails(TNode<DescriptorArray> descriptors,
                                           TNode<Uint32T> descriptor_number);

  using ForEachDescriptorBodyFunction =
      std::function<void(TNode<IntPtrT> descriptor_key_index)>;

  // Descriptor array accessors based on key_index, which is equal to
  // DescriptorArray::ToKeyIndex(descriptor).
  TNode<Name> LoadKeyByKeyIndex(TNode<DescriptorArray> container,
                                TNode<IntPtrT> key_index);
  TNode<Uint32T> LoadDetailsByKeyIndex(TNode<DescriptorArray> container,
                                       TNode<IntPtrT> key_index);
  TNode<Object> LoadValueByKeyIndex(TNode<DescriptorArray> container,
                                    TNode<IntPtrT> key_index);
  TNode<MaybeObject> LoadFieldTypeByKeyIndex(TNode<DescriptorArray> container,
                                             TNode<IntPtrT> key_index);

  TNode<IntPtrT> DescriptorEntryToIndex(TNode<IntPtrT> descriptor);

  // Descriptor array accessors based on descriptor.
  TNode<Name> LoadKeyByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                       TNode<IntPtrT> descriptor);
  TNode<Name> LoadKeyByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                       int descriptor);
  TNode<Uint32T> LoadDetailsByDescriptorEntry(
      TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor);
  TNode<Uint32T> LoadDetailsByDescriptorEntry(
      TNode<DescriptorArray> descriptors, int descriptor);
  TNode<Object> LoadValueByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                           TNode<IntPtrT> descriptor);
  TNode<Object> LoadValueByDescriptorEntry(TNode<DescriptorArray> descriptors,
                                           int descriptor);
  TNode<MaybeObject> LoadFieldTypeByDescriptorEntry(
      TNode<DescriptorArray> descriptors, TNode<IntPtrT> descriptor);

  using ForEachKeyValueFunction =
      std::function<void(TNode<Name> key, LazyNode<Object> value)>;

  // For each JSObject property (in DescriptorArray order), check if the key is
  // enumerable, and if so, load the value from the receiver and evaluate the
  // closure. The value is provided as a LazyNode, which lazily evaluates
  // accessors if present.
  void ForEachEnumerableOwnProperty(TNode<Context> context, TNode<Map> map,
                                    TNode<JSObject> object,
                                    PropertiesEnumerationMode mode,
                                    const ForEachKeyValueFunction& body,
                                    Label* bailout);

  TNode<Object> CallGetterIfAccessor(
      TNode<Object> value, TNode<HeapObject> holder, TNode<Uint32T> details,
      TNode<Context> context, TNode<Object> receiver, TNode<Object> name,
      Label* if_bailout,
      GetOwnPropertyMode mode = kCallJSGetterDontUseCachedName,
      ExpectedReceiverMode expected_receiver_mode = kExpectingJSReceiver);

  TNode<IntPtrT> TryToIntptr(TNode<Object> key, Label* if_not_intptr,
                             TVariable<Int32T>* var_instance_type = nullptr);

  TNode<JSArray> ArrayCreate(TNode<Context> context, TNode<Number> length);

  // Allocate a clone of a mutable primitive, if {object} is a mutable
  // HeapNumber.
  TNode<Object> CloneIfMutablePrimitive(TNode<Object> object);

  TNode<Smi> RefillMathRandom(TNode<NativeContext> native_context);

  void RemoveFinalizationRegistryCellFromUnregisterTokenMap(
      TNode<JSFinalizationRegistry> finalization_registry,
      TNode<WeakCell> weak_cell);

  TNode<IntPtrT> FeedbackIteratorEntrySize() {
    return IntPtrConstant(FeedbackIterator::kEntrySize);
  }

  TNode<IntPtrT> FeedbackIteratorHandlerOffset() {
    return IntPtrConstant(FeedbackIterator::kHandlerOffset);
  }

  TNode<SwissNameDictionary> AllocateSwissNameDictionary(
      TNode<IntPtrT> at_least_space_for);
  TNode<SwissNameDictionary> AllocateSwissNameDictionary(
      int at_least_space_for);

  TNode<SwissNameDictionary> AllocateSwissNameDictionaryWithCapacity(
      TNode<IntPtrT> capacity);

  // MT stands for "minus tag".
  TNode<IntPtrT> SwissNameDictionaryOffsetIntoDataTableMT(
      TNode<SwissNameDictionary> dict, TNode<IntPtrT> index, int field_index);

  // MT stands for "minus tag".
  TNode<IntPtrT> SwissNameDictionaryOffsetIntoPropertyDetailsTableMT(
      TNode<SwissNameDictionary> dict, TNode<IntPtrT> capacity,
      TNode<IntPtrT> index);

  TNode<IntPtrT> LoadSwissNameDictionaryNumberOfElements(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity);

  TNode<IntPtrT> LoadSwissNameDictionaryNumberOfDeletedElements(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity);

  // Specialized operation to be used when adding entries:
  // If used capacity (= number of present + deleted elements) is less than
  // |max_usable|, increment the number of present entries and return the used
  // capacity value (prior to the incrementation). Otherwise, goto |bailout|.
  TNode<Uint32T> SwissNameDictionaryIncreaseElementCountOrBailout(
      TNode<ByteArray> meta_table, TNode<IntPtrT> capacity,
      TNode<Uint32T> max_usable_capacity, Label* bailout);

  // Specialized operation to be used when deleting entries: Decreases the
  // number of present entries and increases the number of deleted ones. Returns
  // new (= decremented) number of present entries.
  TNode<Uint32T> SwissNameDictionaryUpdateCountsForDeletion(
      TNode<ByteArray> meta_table, TNode<IntPtrT> capacity);

  void StoreSwissNameDictionaryCapacity(TNode<SwissNameDictionary> table,
                                        TNode<Int32T> capacity);

  void StoreSwissNameDictionaryEnumToEntryMapping(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
      TNode<IntPtrT> enum_index, TNode<Int32T> entry);

  TNode<Name> LoadSwissNameDictionaryKey(TNode<SwissNameDictionary> dict,
                                         TNode<IntPtrT> entry);

  void StoreSwissNameDictionaryKeyAndValue(TNode<SwissNameDictionary> dict,
                                           TNode<IntPtrT> entry,
                                           TNode<Object> key,
                                           TNode<Object> value);

  // Equivalent to SwissNameDictionary::SetCtrl, therefore preserves the copy of
  // the first group at the end of the control table.
  void SwissNameDictionarySetCtrl(TNode<SwissNameDictionary> table,
                                  TNode<IntPtrT> capacity, TNode<IntPtrT> entry,
                                  TNode<Uint8T> ctrl);

  TNode<Uint64T> LoadSwissNameDictionaryCtrlTableGroup(TNode<IntPtrT> address);

  TNode<Uint8T> LoadSwissNameDictionaryPropertyDetails(
      TNode<SwissNameDictionary> table, TNode<IntPtrT> capacity,
      TNode<IntPtrT> entry);

  void StoreSwissNameDictionaryPropertyDetails(TNode<SwissNameDictionary> table,
                                               TNode<IntPtrT> capacity,
                                               TNode<IntPtrT> entry,
                                               TNode<Uint8T> details);

  TNode<SwissNameDictionary> CopySwissNameDictionary(
      TNode<SwissNameDictionary> original);

  void SwissNameDictionaryFindEntry(TNode<SwissNameDictionary> table,
                                    TNode<Name> key, Label* found,
                                    TVariable<IntPtrT>* var_found_entry,
                                    Label* not_found);

  void SwissNameDictionaryAdd(TNode<SwissNameDictionary> table, TNode<Name> key,
                              TNode<Object> value,
                              TNode<Uint8T> property_details,
                              Label* needs_resize);

  TNode<BoolT> IsMarked(TNode<Object> object);

  void GetMarkBit(TNode<IntPtrT> object, TNode<IntPtrT>* cell,
                  TNode<IntPtrT>* mask);

  TNode<BoolT> IsPageFlagSet(TNode<IntPtrT> object, int mask) {
    TNode<IntPtrT> header = MemoryChunkFromAddress(object);
    TNode<IntPtrT> flags = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), header,
             IntPtrConstant(MemoryChunk::FlagsOffset())));
    return WordNotEqual(WordAnd(flags, IntPtrConstant(mask)),
                        IntPtrConstant(0));
  }

  TNode<BoolT> IsPageFlagReset(TNode<IntPtrT> object, int mask) {
    TNode<IntPtrT> header = MemoryChunkFromAddress(object);
    TNode<IntPtrT> flags = UncheckedCast<IntPtrT>(
        Load(MachineType::Pointer(), header,
             IntPtrConstant(MemoryChunk::FlagsOffset())));
    return WordEqual(WordAnd(flags, IntPtrConstant(mask)), IntPtrConstant(0));
  }

 private:
  friend class CodeStubArguments;

  void BigInt64Comparison(Operation op, TNode<Object>& left,
                          TNode<Object>& right, Label* return_true,
                          Label* return_false);

  void HandleBreakOnNode();

  TNode<HeapObject> AllocateRawDoubleAligned(TNode<IntPtrT> size_in_bytes,
                                             AllocationFlags flags,
                                             TNode<RawPtrT> top_address,
                                             TNode<RawPtrT> limit_address);
  TNode<HeapObject> AllocateRawUnaligned(TNode<IntPtrT> size_in_bytes,
                                         AllocationFlags flags,
                                         TNode<RawPtrT> top_address,
                                         TNode<RawPtrT> limit_address);
  TNode<HeapObject> AllocateRaw(TNode<IntPtrT> size_in_bytes,
                                AllocationFlags flags,
                                TNode<RawPtrT> top_address,
                                TNode<RawPtrT> limit_address);

  // Allocate and return a JSArray of given total size in bytes with header
  // fields initialized.
  TNode<JSArray> AllocateUninitializedJSArray(
      TNode<Map> array_map, TNode<Smi> length,
      std::optional<TNode<AllocationSite>> allocation_site,
      TNode<IntPtrT> size_in_bytes);

  // Increases the provided capacity to the next valid value, if necessary.
  template <typename CollectionType>
  TNode<CollectionType> AllocateOrderedHashTable(TNode<IntPtrT> capacity);

  // Uses the provided capacity (which must be valid) in verbatim.
  template <typename CollectionType>
  TNode<CollectionType> AllocateOrderedHashTableWithCapacity(
      TNode<IntPtrT> capacity);

  TNode<IntPtrT> SmiShiftBitsConstant() {
    return IntPtrConstant(kSmiShiftSize + kSmiTagSize);
  }
  TNode<Int32T> SmiShiftBitsConstant32() {
    return Int32Constant(kSmiShiftSize + kSmiTagSize);
  }

  TNode<String> AllocateSlicedString(RootIndex map_root_index,
                                     TNode<Uint32T> length,
                                     TNode<String> parent, TNode<Smi> offset);

  // Implements [Descriptor/Transition]Array::number_of_entries.
  template <typename Array>
  TNode<Uint32T> NumberOfEntries(TNode<Array> array);

  template <typename Array>
  constexpr int MaxNumberOfEntries();

  // Implements [Descriptor/Transition]Array::GetSortedKeyIndex.
  template <typename Array>
  TNode<Uint32T> GetSortedKeyIndex(TNode<Array> descriptors,
                                   TNode<Uint32T> entry_index);

  TNode<Smi> CollectFeedbackForString(TNode<Int32T> instance_type);
  void GenerateEqual_Same(TNode<Object> value, Label* if_equal,
                          Label* if_notequal,
                          TVariable<Smi>* var_type_feedback = nullptr);

  static const int kElementLoopUnrollThreshold = 8;

  // {convert_bigint} is only meaningful when {mode} == kToNumber.
  TNode<Numeric> NonNumberToNumberOrNumeric(
      TNode<Context> context, TNode<HeapObject> input, Object::Conversion mode,
      BigIntHandling bigint_handling = BigIntHandling::kThrow);

  enum IsKnownTaggedPointer { kNo, kYes };
  template <Object::Conversion conversion>
  void TaggedToWord32OrBigIntImpl(
      TNode<Context> context, TNode<Object> value, Label* if_number,
      TVariable<Word32T>* var_word32,
      IsKnownTaggedPointer is_known_tagged_pointer,
      const FeedbackValues& feedback, Label* if_bigint = nullptr,
      Label* if_bigint64 = nullptr,
      TVariable<BigInt>* var_maybe_bigint = nullptr);

  // Low-level accessors for Descriptor arrays.
  template <typename T>
  TNode<T> LoadDescriptorArrayElement(TNode<DescriptorArray> object,
                                      TNode<IntPtrT> index,
                                      int additional_offset);

  // Hide LoadRoot for subclasses of CodeStubAssembler. If you get an error
  // complaining about this method, don't make it public, add your root to
  // HEAP_(IM)MUTABLE_IMMOVABLE_OBJECT_LIST instead. If you *really* need
  // LoadRoot, use CodeAssembler::LoadRoot.
  TNode<Object> LoadRoot(RootIndex root_index) {
    return CodeAssembler::LoadRoot(root_index);
  }

  TNode<AnyTaggedT> LoadRootMapWord(RootIndex root_index) {
    return CodeAssembler::LoadRootMapWord(root_index);
  }

  template <typename TIndex>
  void StoreFixedArrayOrPropertyArrayElement(
      TNode<UnionOf<FixedArray, PropertyArray>> array, TNode<TIndex> index,
      TNode<Object> value, WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0);

  template <typename TIndex>
  void StoreElementTypedArrayBigInt(TNode<RawPtrT> elements, ElementsKind kind,
                                    TNode<TIndex> index, TNode<BigInt> value);

  template <typename TIndex>
  void StoreElementTypedArrayWord32(TNode<RawPtrT> elements, ElementsKind kind,
                                    TNode<TIndex> index, TNode<Word32T> value);

  // Store value to an elements array with given elements kind.
  // TODO(turbofan): For BIGINT64_ELEMENTS and BIGUINT64_ELEMENTS
  // we pass {value} as BigInt object instead of int64_t. We should
  // teach TurboFan to handle int64_t on 32-bit platforms eventually.
  // TODO(solanes): This method can go away and simplify into only one version
  // of StoreElement once we have "if constexpr" available to use.
  template <typename TArray, typename TIndex, typename TValue>
  void StoreElementTypedArray(TNode<TArray> elements, ElementsKind kind,
                              TNode<TIndex> index, TNode<TValue> value);

  template <typename TIndex>
  void StoreElement(TNode<FixedArrayBase> elements, ElementsKind kind,
                    TNode<TIndex> index, TNode<Object> value);

  template <typename TIndex>
  void StoreElement(TNode<FixedArrayBase> elements, ElementsKind kind,
                    TNode<TIndex> index, TNode<Float64T> value);

  // Converts {input} to a number if {input} is a plain primitve (i.e. String or
  // Oddball) and stores the result in {var_result}. Otherwise, it bails out to
  // {if_bailout}.
  void TryPlainPrimitiveNonNumberToNumber(TNode<HeapObject> input,
                                          TVariable<Number>* var_result,
                                          Label* if_bailout);

  void DcheckHasValidMap(TNode<HeapObject> object);

  template <typename TValue>
  void EmitElementStoreTypedArray(TNode<JSTypedArray> typed_array,
                                  TNode<IntPtrT> key, TNode<Object> value,
                                  ElementsKind elements_kind,
                                  KeyedAccessStoreMode store_mode,
                                  Label* bailout, TNode<Context> context,
                                  TVariable<Object>* maybe_converted_value);

  template <typename TValue>
  void EmitElementStoreTypedArrayUpdateValue(
      TNode<Object> value, ElementsKind elements_kind,
      TNode<TValue> converted_value, TVariable<Object>* maybe_converted_value);
};

class V8_EXPORT_PRIVATE CodeStubArguments {
 public:
  // |argc| specifies the number of arguments passed to the builtin.
  CodeStubArguments(CodeStubAssembler* assembler, TNode<IntPtrT> argc)
      : CodeStubArguments(assembler, argc, TNode<RawPtrT>()) {}
  CodeStubArguments(CodeStubAssembler* assembler, TNode<Int32T> argc)
      : CodeStubArguments(assembler, assembler->ChangeInt32ToIntPtr(argc)) {}
  CodeStubArguments(CodeStubAssembler* assembler, TNode<IntPtrT> argc,
                    TNode<RawPtrT> fp);

  // Used by Torque to construct arguments based on a Torque-defined
  // struct of values.
  CodeStubArguments(CodeStubAssembler* assembler,
                    TorqueStructArguments torque_arguments)
      : assembler_(assembler),
        argc_(torque_arguments.actual_count),
        base_(torque_arguments.base),
        fp_(torque_arguments.frame) {}

  // Return true if there may be additional padding arguments, false otherwise.
  bool MayHavePaddingArguments() const;

  TNode<Object> GetReceiver() const;
  // Replaces receiver argument on the expression stack. Should be used only
  // for manipulating arguments in trampoline builtins before tail calling
  // further with passing all the JS arguments as is.
  void SetReceiver(TNode<Object> object) const;

  // Computes address of the index'th argument.
  TNode<RawPtrT> AtIndexPtr(TNode<IntPtrT> index) const;

  // |index| is zero-based and does not include the receiver
  TNode<Object> AtIndex(TNode<IntPtrT> index) const;
  TNode<Object> AtIndex(int index) const;

  // Return the number of arguments (excluding the receiver).
  TNode<IntPtrT> GetLengthWithoutReceiver() const;
  // Return the number of arguments (including the receiver).
  TNode<IntPtrT> GetLengthWithReceiver() const;

  TorqueStructArguments GetTorqueArguments() const {
    return TorqueStructArguments{fp_, base_, GetLengthWithoutReceiver(), argc_};
  }

  TNode<Object> GetOptionalArgumentValue(TNode<IntPtrT> index,
                                         TNode<Object> default_value);
  TNode<Object> GetOptionalArgumentValue(TNode<IntPtrT> index) {
    return GetOptionalArgumentValue(index, assembler_->UndefinedConstant());
  }
  TNode<Object> GetOptionalArgumentValue(int index) {
    return GetOptionalArgumentValue(assembler_->IntPtrConstant(index));
  }

  void SetArgumentValue(TNode<IntPtrT> index, TNode<Object> value);

  // Iteration doesn't include the receiver. |first| and |last| are zero-based.
  using ForEachBodyFunction = std::function<void(TNode<Object> arg)>;
  void ForEach(const ForEachBodyFunction& body, TNode<IntPtrT> first = {},
               TNode<IntPtrT> last = {}) const {
    CodeStubAssembler::VariableList list(0, assembler_->zone());
    ForEach(list, body, first, last);
  }
  void ForEach(const CodeStubAssembler::VariableList& vars,
               const ForEachBodyFunction& body, TNode<IntPtrT> first = {},
               TNode<IntPtrT> last = {}) const;

  void PopAndReturn(TNode<Object> value);

 private:
  CodeStubAssembler* assembler_;
  TNode<IntPtrT> argc_;
  TNode<RawPtrT> base_;
  TNode<RawPtrT> fp_;
};

class ToDirectStringAssembler : public CodeStubAssembler {
 private:
  enum StringPointerKind { PTR_TO_DATA, PTR_TO_STRING };

 public:
  enum Flag {
    kDontUnpackSlicedStrings = 1 << 0,
  };
  using Flags = base::Flags<Flag>;

  ToDirectStringAssembler(compiler::CodeAssemblerState* state,
                          TNode<String> string, Flags flags = Flags());

  // Converts flat cons, thin, and sliced strings and returns the direct
  // string. The result can be either a sequential or external string.
  // Jumps to if_bailout if the string if the string is indirect and cannot
  // be unpacked.
  TNode<String> TryToDirect(Label* if_bailout);

  // As above, but flattens in runtime if the string cannot be unpacked
  // otherwise.
  TNode<String> ToDirect();

  // Returns a pointer to the beginning of the string data.
  // Jumps to if_bailout if the external string cannot be unpacked.
  TNode<RawPtrT> PointerToData(Label* if_bailout) {
    return TryToSequential(PTR_TO_DATA, if_bailout);
  }

  // Returns a pointer that, offset-wise, looks like a String.
  // Jumps to if_bailout if the external string cannot be unpacked.
  TNode<RawPtrT> PointerToString(Label* if_bailout) {
    return TryToSequential(PTR_TO_STRING, if_bailout);
  }

  TNode<BoolT> IsOneByte();

  TNode<String> string() { return var_string_.value(); }
  TNode<IntPtrT> offset() { return var_offset_.value(); }
  TNode<Word32T> is_external() { return var_is_external_.value(); }

 private:
  TNode<RawPtrT> TryToSequential(StringPointerKind ptr_kind, Label* if_bailout);

  TVariable<String> var_string_;
#if V8_STATIC_ROOTS_BOOL
  TVariable<Map> var_map_;
#else
  TVariable<Int32T> var_instance_type_;
#endif
  // TODO(v8:9880): Use UintPtrT here.
  TVariable<IntPtrT> var_offset_;
  TVariable<Word32T> var_is_external_;

  const Flags flags_;
};

// Performs checks on a given prototype (e.g. map identity, property
// verification), intended for use in fast path checks.
class PrototypeCheckAssembler : public CodeStubAssembler {
 public:
  enum Flag {
    kCheckPrototypePropertyConstness = 1 << 0,
    kCheckPrototypePropertyIdentity = 1 << 1,
    kCheckFull =
        kCheckPrototypePropertyConstness | kCheckPrototypePropertyIdentity,
  };
  using Flags = base::Flags<Flag>;

  // A tuple describing a relevant property. It contains the descriptor index of
  // the property (within the descriptor array), the property's expected name
  // (stored as a root), and the property's expected value (stored on the native
  // context).
  struct DescriptorIndexNameValue {
    int descriptor_index;
    RootIndex name_root_index;
    int expected_value_context_index;
  };

  PrototypeCheckAssembler(compiler::CodeAssemblerState* state, Flags flags,
                          TNode<NativeContext> native_context,
                          TNode<Map> initial_prototype_map,
                          base::Vector<DescriptorIndexNameValue> properties);

  void Che
"""


```
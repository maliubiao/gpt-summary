Response:
The user wants to understand the functionality of the provided C++ header file `v8/src/heap/factory.h`.
I need to analyze the listed methods and their purpose within the V8 JavaScript engine, particularly focusing on object creation.

Here's a breakdown of the requested information:

1. **Functionality Listing:**  Describe what the header file does in V8.
2. **Torque Source:** Determine if the file is a Torque source based on its extension.
3. **JavaScript Relation:**  If the functionality relates to JavaScript, provide JavaScript examples.
4. **Code Logic Reasoning:** If there are methods with clear input/output logic, explain with examples.
5. **Common Programming Errors:** Identify potential user errors related to the functionalities.
6. **Summary of Functionality (Part 2):**  Summarize the functionalities presented in the provided code snippet.

**Plan:**

* **Analyze each method:**  Examine the name, parameters, and return type of each method to infer its purpose. Most methods seem to be related to creating different types of V8 objects (JS objects, arrays, functions, etc.).
* **Torque Check:** Verify if the filename ends with `.tq`.
* **JavaScript Examples:** For relevant methods, construct simple JavaScript code that would involve the creation of corresponding V8 objects.
* **Input/Output Examples:** For methods like `SizeToString` or those creating basic data structures, define hypothetical inputs and their expected outputs.
* **Error Scenarios:**  Think about common mistakes developers might make when interacting with JavaScript concepts that relate to these internal V8 mechanisms (e.g., incorrect array lengths, type mismatches, etc.).
* **Summarize Part 2:** Combine the understanding of individual methods in the provided snippet into a concise summary of its role.
```cpp
t> NewWasmStruct(const wasm::StructType* type,
                                   wasm::WasmValue* args,
                                   DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArray(wasm::ValueType element_type, uint32_t length,
                                 wasm::WasmValue initial_value,
                                 DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArrayFromElements(
      const wasm::ArrayType* type, base::Vector<wasm::WasmValue> elements,
      DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArrayFromMemory(uint32_t length,
                                           DirectHandle<Map> map,
                                           Address source);
  // Returns a handle to a WasmArray if successful, or a Smi containing a
  // {MessageTemplate} if computing the array's elements leads to an error.
  Handle<Object> NewWasmArrayFromElementSegment(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
      uint32_t segment_index, uint32_t start_offset, uint32_t length,
      DirectHandle<Map> map);
  Handle<WasmContinuationObject> NewWasmContinuationObject(
      Address jmpbuf, wasm::StackMemory* stack, DirectHandle<HeapObject> parent,
      AllocationType allocation = AllocationType::kYoung);

  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmExportedFunction(
      DirectHandle<String> name, DirectHandle<WasmExportedFunctionData> data,
      int len, AdaptArguments adapt);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmJSFunction(
      DirectHandle<String> name, DirectHandle<WasmJSFunctionData> data);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmResume(
      DirectHandle<WasmResumeData> data);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmCapiFunction(
      DirectHandle<WasmCapiFunctionData> data);
#endif  // V8_ENABLE_WEBASSEMBLY

  Handle<SourceTextModule> NewSourceTextModule(
      DirectHandle<SharedFunctionInfo> code);
  Handle<SyntheticModule> NewSyntheticModule(
      DirectHandle<String> module_name, DirectHandle<FixedArray> export_names,
      v8::Module::SyntheticModuleEvaluationSteps evaluation_steps);

  Handle<JSArrayBuffer> NewJSArrayBuffer(
      std::shared_ptr<BackingStore> backing_store,
      AllocationType allocation = AllocationType::kYoung);

  MaybeHandle<JSArrayBuffer> NewJSArrayBufferAndBackingStore(
      size_t byte_length, InitializedFlag initialized,
      AllocationType allocation = AllocationType::kYoung);

  MaybeHandle<JSArrayBuffer> NewJSArrayBufferAndBackingStore(
      size_t byte_length, size_t max_byte_length, InitializedFlag initialized,
      ResizableFlag resizable = ResizableFlag::kNotResizable,
      AllocationType allocation = AllocationType::kYoung);

  Handle<JSArrayBuffer> NewJSSharedArrayBuffer(
      std::shared_ptr<BackingStore> backing_store);

  static void TypeAndSizeForElementsKind(ElementsKind kind,
                                         ExternalArrayType* array_type,
                                         size_t* element_size);

  // Creates a new JSTypedArray with the specified buffer.
  Handle<JSTypedArray> NewJSTypedArray(ExternalArrayType type,
                                       DirectHandle<JSArrayBuffer> buffer,
                                       size_t byte_offset, size_t length,
                                       bool is_length_tracking = false);

  Handle<JSDataViewOrRabGsabDataView> NewJSDataViewOrRabGsabDataView(
      DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
      size_t byte_length, bool is_length_tracking = false);

  Handle<JSIteratorResult> NewJSIteratorResult(DirectHandle<Object> value,
                                               bool done);
  Handle<JSAsyncFromSyncIterator> NewJSAsyncFromSyncIterator(
      DirectHandle<JSReceiver> sync_iterator, DirectHandle<Object> next);

  Handle<JSMap> NewJSMap();
  Handle<JSSet> NewJSSet();

  // Allocates a bound function. If direct handles are enabled, it is the
  // responsibility of the caller to ensure that the memory pointed to by
  // `bound_args` is scanned during CSS, e.g., it comes from a
  // `DirectHandleVector<Object>`.
  MaybeHandle<JSBoundFunction> NewJSBoundFunction(
      DirectHandle<JSReceiver> target_function, DirectHandle<JSAny> bound_this,
      base::Vector<DirectHandle<Object>> bound_args,
      Handle<JSPrototype> prototype);

  // Allocates a Harmony proxy.
  Handle<JSProxy> NewJSProxy(DirectHandle<JSReceiver> target,
                             DirectHandle<JSReceiver> handler);

  // Reinitialize an JSGlobalProxy based on a constructor. The object
  // must have the same size as objects allocated using the
  // constructor. The object is reinitialized and behaves as an
  // object that has been freshly allocated using the constructor.
  void ReinitializeJSGlobalProxy(DirectHandle<JSGlobalProxy> global,
                                 DirectHandle<JSFunction> constructor);

  Handle<JSGlobalProxy> NewUninitializedJSGlobalProxy(int size);

  // For testing only. Creates a sloppy function without code.
  Handle<JSFunction> NewFunctionForTesting(DirectHandle<String> name);

  // Create an External object for V8's external API.
  Handle<JSObject> NewExternal(
      void* value, AllocationType allocation = AllocationType::kYoung);

  // Allocates a new code object and initializes it to point to the given
  // off-heap entry point.
  //
  // Note it wouldn't be strictly necessary to create new Code objects, instead
  // Code::instruction_start and instruction_stream could be reset. But creating
  // a new Code object doesn't hurt much (it only makes mksnapshot slightly more
  // expensive) and has real benefits:
  // - it moves all special-casing to mksnapshot-time; at normal runtime, the
  //   system only sees a) non-builtin Code objects (not in RO space, with
  //   instruction_stream set) and b) builtin Code objects (maybe in RO space,
  //   without instruction_stream set).
  // - it's a convenient bottleneck to make the RO-space allocation decision.
  Handle<Code> NewCodeObjectForEmbeddedBuiltin(DirectHandle<Code> code,
                                               Address off_heap_entry);

  Handle<BytecodeArray> CopyBytecodeArray(DirectHandle<BytecodeArray>);

  // Interface for creating error objects.
  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            DirectHandle<String> message,
                            Handle<Object> options = {});

  Handle<Object> NewInvalidStringLengthError();

  inline Handle<Object> NewURIError();

  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            MessageTemplate template_index,
                            base::Vector<const DirectHandle<Object>> args);

  Handle<JSObject> NewSuppressedErrorAtDisposal(
      Isolate* isolate, Handle<Object> error, Handle<Object> suppressed_error);

  template <typename... Args,
            typename = std::enable_if_t<std::conjunction_v<
                std::is_convertible<Args, DirectHandle<Object>>...>>>
  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            MessageTemplate template_index, Args... args) {
    return NewError(constructor, template_index,
                    base::VectorOf<DirectHandle<Object>>({args...}));
  }

  // https://tc39.es/proposal-shadowrealm/#sec-create-type-error-copy
  Handle<JSObject> ShadowRealmNewTypeErrorCopy(
      Handle<Object> original, MessageTemplate template_index,
      base::Vector<const DirectHandle<Object>> args);

  template <typename... Args,
            typename = std::enable_if_t<std::conjunction_v<
                std::is_convertible<Args, DirectHandle<Object>>...>>>
  Handle<JSObject> ShadowRealmNewTypeErrorCopy(Handle<Object> original,
                                               MessageTemplate template_index,
                                               Args... args) {
    return ShadowRealmNewTypeErrorCopy(
        original, template_index,
        base::VectorOf<DirectHandle<Object>>({args...}));
  }

#define DECLARE_ERROR(NAME)                                                  \
  Handle<JSObject> New##NAME(MessageTemplate template_index,                 \
                             base::Vector<const DirectHandle<Object>> args); \
                                                                             \
  template <typename... Args,                                                \
            typename = std::enable_if_t<std::conjunction_v<                  \
                std::is_convertible<Args, DirectHandle<Object>>...>>>        \
  Handle<JSObject> New##NAME(MessageTemplate template_index, Args... args) { \
    return New##NAME(template_index,                                         \
                     base::VectorOf<DirectHandle<Object>>({args...}));       \
  }
  DECLARE_ERROR(Error)
  DECLARE_ERROR(EvalError)
  DECLARE_ERROR(RangeError)
  DECLARE_ERROR(ReferenceError)
  DECLARE_ERROR(SuppressedError)
  DECLARE_ERROR(SyntaxError)
  DECLARE_ERROR(TypeError)
  DECLARE_ERROR(WasmCompileError)
  DECLARE_ERROR(WasmLinkError)
  DECLARE_ERROR(WasmRuntimeError)
  DECLARE_ERROR(WasmExceptionError)
#undef DECLARE_ERROR

  Handle<String> SizeToString(size_t value, bool check_cache = true);
  inline Handle<String> Uint32ToString(uint32_t value,
                                       bool check_cache = true) {
    return SizeToString(value, check_cache);
  }

#define ROOT_ACCESSOR(Type, name, CamelName) inline Handle<Type> name();
  MUTABLE_ROOT_LIST(ROOT_ACCESSOR)
#undef ROOT_ACCESSOR

  // Allocates a new SharedFunctionInfo object.
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForApiFunction(
      MaybeDirectHandle<String> maybe_name,
      DirectHandle<FunctionTemplateInfo> function_template_info,
      FunctionKind kind);

  Handle<SharedFunctionInfo> NewSharedFunctionInfoForBuiltin(
      MaybeDirectHandle<String> name, Builtin builtin, int len,
      AdaptArguments adapt, FunctionKind kind = FunctionKind::kNormalFunction);

  Handle<InterpreterData> NewInterpreterData(
      DirectHandle<BytecodeArray> bytecode_array, DirectHandle<Code> code);

  static bool IsFunctionModeWithPrototype(FunctionMode function_mode) {
    return (function_mode & kWithPrototypeBits) != 0;
  }

  static bool IsFunctionModeWithWritablePrototype(FunctionMode function_mode) {
    return (function_mode & kWithWritablePrototypeBit) != 0;
  }

  static bool IsFunctionModeWithName(FunctionMode function_mode) {
    return (function_mode & kWithNameBit) != 0;
  }

  Handle<Map> CreateSloppyFunctionMap(
      FunctionMode function_mode, MaybeHandle<JSFunction> maybe_empty_function);

  Handle<Map> CreateStrictFunctionMap(FunctionMode function_mode,
                                      Handle<JSFunction> empty_function);

  Handle<Map> CreateClassFunctionMap(Handle<JSFunction> empty_function);

  // Allocates a new JSMessageObject object.
  Handle<JSMessageObject> NewJSMessageObject(
      MessageTemplate message, DirectHandle<Object> argument,
      int start_position, int end_position,
      DirectHandle<SharedFunctionInfo> shared_info, int bytecode_offset,
      DirectHandle<Script> script,
      DirectHandle<StackTraceInfo> stack_trace =
          DirectHandle<StackTraceInfo>::null());

  Handle<DebugInfo> NewDebugInfo(DirectHandle<SharedFunctionInfo> shared);

  // Return a map for given number of properties using the map cache in the
  // native context.
  Handle<Map> ObjectLiteralMapFromCache(
      DirectHandle<NativeContext> native_context, int number_of_properties);

  Handle<LoadHandler> NewLoadHandler(
      int data_count, AllocationType allocation = AllocationType::kOld);
  Handle<StoreHandler> NewStoreHandler(int data_count);
  Handle<MegaDomHandler> NewMegaDomHandler(MaybeObjectHandle accessor,
                                           MaybeObjectHandle context);

  // Creates a new FixedArray that holds the data associated with the
  // atom regexp and stores it in the regexp.
  void SetRegExpAtomData(DirectHandle<JSRegExp> regexp,
                         DirectHandle<String> source, JSRegExp::Flags flags,
                         DirectHandle<String> match_pattern);

  // Creates a new FixedArray that holds the data associated with the
  // irregexp regexp and stores it in the regexp.
  void SetRegExpIrregexpData(DirectHandle<JSRegExp> regexp,
                             DirectHandle<String> source, JSRegExp::Flags flags,
                             int capture_count, uint32_t backtrack_limit);

  // Creates a new FixedArray that holds the data associated with the
  // experimental regexp and stores it in the regexp.
  void SetRegExpExperimentalData(DirectHandle<JSRegExp> regexp,
                                 DirectHandle<String> source,
                                 JSRegExp::Flags flags, int capture_count);

  Handle<RegExpData> NewAtomRegExpData(DirectHandle<String> source,
                                       JSRegExp::Flags flags,
                                       DirectHandle<String> pattern);
  Handle<RegExpData> NewIrRegExpData(DirectHandle<String> source,
                                     JSRegExp::Flags flags, int capture_count,
                                     uint32_t backtrack_limit);
  Handle<RegExpData> NewExperimentalRegExpData(DirectHandle<String> source,
                                               JSRegExp::Flags flags,
                                               int capture_count);

  // Returns the value for a known global constant (a property of the global
  // object which is neither configurable nor writable) like 'undefined'.
  // Returns a null handle when the given name is unknown.
  Handle<Object> GlobalConstantFor(Handle<Name> name);

  // Converts the given ToPrimitive hint to its string representation.
  Handle<String> ToPrimitiveHintString(ToPrimitiveHint hint);

  Handle<JSPromise> NewJSPromiseWithoutHook();
  Handle<JSPromise> NewJSPromise();

  Tagged<HeapObject> NewForTest(DirectHandle<Map> map,
                                AllocationType allocation) {
    return New(map, allocation);
  }

  Handle<JSSharedStruct> NewJSSharedStruct(
      Handle<JSFunction> constructor,
      MaybeHandle<NumberDictionary> maybe_elements_template);

  Handle<JSSharedArray> NewJSSharedArray(Handle<JSFunction> constructor,
                                         int length);

  Handle<JSAtomicsMutex> NewJSAtomicsMutex();

  Handle<JSAtomicsCondition> NewJSAtomicsCondition();

  Handle<FunctionTemplateInfo> NewFunctionTemplateInfo(int length,
                                                       bool do_not_cache);

  Handle<ObjectTemplateInfo> NewObjectTemplateInfo(
      DirectHandle<FunctionTemplateInfo> constructor, bool do_not_cache);

  Handle<DictionaryTemplateInfo> NewDictionaryTemplateInfo(
      DirectHandle<FixedArray> property_names);

  // Helper class for creating JSFunction objects.
  class V8_EXPORT_PRIVATE JSFunctionBuilder final {
   public:
    JSFunctionBuilder(Isolate* isolate, DirectHandle<SharedFunctionInfo> sfi,
                      DirectHandle<Context> context);

    V8_WARN_UNUSED_RESULT Handle<JSFunction> Build();

    JSFunctionBuilder& set_map(DirectHandle<Map> v) {
      maybe_map_ = v;
      return *this;
    }
    JSFunctionBuilder& set_allocation_type(AllocationType v) {
      allocation_type_ = v;
      return *this;
    }
    JSFunctionBuilder& set_feedback_cell(DirectHandle<FeedbackCell> v) {
      maybe_feedback_cell_ = v;
      return *this;
    }

   private:
    void PrepareMap();
    void PrepareFeedbackCell();

    V8_WARN_UNUSED_RESULT Handle<JSFunction> BuildRaw(DirectHandle<Code> code);

    Isolate* const isolate_;
    DirectHandle<SharedFunctionInfo> sfi_;
    DirectHandle<Context> context_;
    MaybeDirectHandle<Map> maybe_map_;
    MaybeDirectHandle<FeedbackCell> maybe_feedback_cell_;
    AllocationType allocation_type_ = AllocationType::kOld;

    friend class Factory;
  };

  // Allows creation of InstructionStream objects. It provides two build
  // methods, one of which tries to gracefully handle allocation failure.
  class V8_EXPORT_PRIVATE CodeBuilder final {
   public:
    CodeBuilder(Isolate* isolate, const CodeDesc& desc, CodeKind kind);

    // TODO(victorgomes): Remove Isolate dependency from CodeBuilder.
    CodeBuilder(LocalIsolate* local_isolate, const CodeDesc& desc,
                CodeKind kind);

    // Builds a new code object (fully initialized). All header fields of the
    // associated InstructionStream are immutable and the InstructionStream
    // object is write protected.
    V8_WARN_UNUSED_RESULT Handle<Code> Build();
    // Like Build, builds a new code object. May return an empty handle if the
    // allocation fails.
    V8_WARN_UNUSED_RESULT MaybeHandle<Code> TryBuild();

    // Sets the self-reference object in which a reference to the code object is
    // stored. This allows generated code to reference its own InstructionStream
    // object by using this handle.
    CodeBuilder& set_self_reference(Handle<Object> self_reference) {
      DCHECK(!self_reference.is_null());
      self_reference_ = self_reference;
      return *this;
    }

    CodeBuilder& set_builtin(Builtin builtin) {
      DCHECK_IMPLIES(builtin != Builtin::kNoBuiltinId,
                     !CodeKindIsJSFunction(kind_));
      builtin_ = builtin;
      return *this;
    }

    CodeBuilder& set_inlined_bytecode_size(uint32_t size) {
      DCHECK_IMPLIES(size != 0, CodeKindIsOptimizedJSFunction(kind_));
      inlined_bytecode_size_ = size;
      return *this;
    }

    CodeBuilder& set_osr_offset(BytecodeOffset offset) {
      DCHECK_IMPLIES(!offset.IsNone(), CodeKindCanOSR(kind_));
      osr_offset_ = offset;
      return *this;
    }

    CodeBuilder& set_source_position_table(Handle<TrustedByteArray> table) {
      DCHECK_NE(kind_, CodeKind::BASELINE);
      DCHECK(!table.is_null());
      source_position_table_ = table;
      return *this;
    }

    inline CodeBuilder& set_empty_source_position_table();

    CodeBuilder& set_bytecode_offset_table(Handle<TrustedByteArray> table) {
      DCHECK_EQ(kind_, CodeKind::BASELINE);
      DCHECK(!table.is_null());
      bytecode_offset_table_ = table;
      return *this;
    }

    CodeBuilder& set_deoptimization_data(
        Handle<DeoptimizationData> deopt_data) {
      DCHECK_NE(kind_, CodeKind::BASELINE);
      DCHECK(!deopt_data.is_null());
      deoptimization_data_ = deopt_data;
      return *this;
    }

    inline CodeBuilder& set_interpreter_data(
        Handle<TrustedObject> interpreter_data);

    CodeBuilder& set_is_context_specialized() {
      DCHECK(!CodeKindIsUnoptimizedJSFunction(kind_));
      is_context_specialized_ = true;
      return *this;
    }

    CodeBuilder& set_is_turbofanned() {
      DCHECK(!CodeKindIsUnoptimizedJSFunction(kind_));
      is_turbofanned_ = true;
      return *this;
    }

    CodeBuilder& set_stack_slots(int stack_slots) {
      stack_slots_ = stack_slots;
      return *this;
    }

    CodeBuilder& set_parameter_count(uint16_t parameter_count) {
      parameter_count_ = parameter_count;
      return *this;
    }

    CodeBuilder& set_profiler_data(BasicBlockProfilerData* profiler_data) {
      profiler_data_ = profiler_data;
      return *this;
    }

   private:
    MaybeHandle<Code> BuildInternal(bool retry_allocation_or_fail);

    Handle<TrustedByteArray> NewTrustedByteArray(int length);
    // Return an allocation suitable for InstructionStreams but without writing
    // the map.
    Tagged<HeapObject> AllocateUninitializedInstructionStream(
        bool retry_allocation_or_fail);
    Handle<Code> NewCode(const NewCodeOptions& options);

    Isolate* const isolate_;
    LocalIsolate* local_isolate_;
    const CodeDesc& code_desc_;
    const CodeKind kind_;

    MaybeHandle<Object> self_reference_;
    Builtin builtin_ = Builtin::kNoBuiltinId;
    uint32_t inlined_bytecode_size_ = 0;
    BytecodeOffset osr_offset_ = BytecodeOffset::None();
    MaybeHandle<TrustedByteArray> bytecode_offset_table_;
    MaybeHandle<TrustedByteArray> source_position_table_;
    MaybeHandle<DeoptimizationData> deoptimization_data_;
    MaybeHandle<TrustedObject> interpreter_data_;
    BasicBlockProfilerData* profiler_data_ = nullptr;
    bool is_context_specialized_ = false;
    bool is_turbofanned_ = false;
    uint32_t stack_slots_ = 0;
    uint16_t parameter_count_ = 0;
  };

 private:
  friend class FactoryBase<Factory>;

  // ------
  // Customization points for FactoryBase
  Tagged<HeapObject> AllocateRaw(
      int size, AllocationType allocation,
      AllocationAlignment alignment = kTaggedAligned);

  Isolate* isolate() const {
    // Downcast to the privately inherited sub-class using c-style casts to
    // avoid undefined behavior (as static_cast cannot cast across private
    // bases).
    // NOLINTNEXTLINE (google-readability-casting)
    return (Isolate*)this;  // NOLINT(readability/casting)
  }

  V8_INLINE HeapAllocator* allocator() const;

  bool CanAllocateInReadOnlySpace();
  bool EmptyStringRootIsInitialized();
  AllocationType AllocationTypeForInPlaceInternalizableString();

  void ProcessNewScript(Handle<Script> shared,
                        ScriptEventType script_event_type);
  // ------

  // MetaMapProviderFunc is supposed to be a function returning Tagged<Map>.
  // For example,  std::function<Tagged<Map>()>.
  template <typename MetaMapProviderFunc>
  V8_INLINE Handle<Map> NewMapImpl(
      MetaMapProviderFunc&& meta_map_provider, InstanceType type,
      int instance_size,
      ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND,
      int inobject_properties = 0,
      AllocationType allocation_type = AllocationType::kMap);

  Tagged<HeapObject> AllocateRawWithAllocationSite(
      DirectHandle<Map> map, AllocationType allocation,
      DirectHandle<AllocationSite> allocation_site);

  Handle<JSArrayBufferView> NewJSArrayBufferView(
      DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements,
      DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
      size_t byte_length);

  Tagged<Symbol> NewSymbolInternal(
      AllocationType allocation = AllocationType::kOld);

  // Allocates new context with given map, sets length and initializes the
  // after-header part with uninitialized values and leaves the context header
  // uninitialized.
  Tagged<Context> NewContextInternal(DirectHandle<Map> map, int size,
                                     int variadic_part_length,
                                     AllocationType allocation);

  template <typename T>
  Handle<T> AllocateSmallOrderedHashTable(DirectHandle<Map> map, int capacity,
                                          AllocationType allocation);

  // Creates a heap object based on the map. The fields of the heap object are
  // not initialized, it's the responsibility of the caller to do that.
  Tagged<HeapObject> New(DirectHandle<Map> map, AllocationType allocation);

  template <typename T>
  Handle<T> CopyArrayWithMap(
      DirectHandle<T> src, DirectHandle<Map> map,
      AllocationType allocation = AllocationType::kYoung);
  template <typename T>
  Handle<T> CopyArrayAndGrow(DirectHandle<T> src, int grow_by,
                             AllocationType allocation);

  MaybeHandle<String> NewStringFromTwoByte(const base::uc16* string, int length,
                                           AllocationType allocation);

  // Functions to get the hash of a number for the number_string_cache.
  int NumberToStringCacheHash(Tagged<Smi> number);
  int NumberToStringCacheHash(double number);

  // Attempt to find the number in a small cache. If we finds it, return
  // the string representation of the number. Otherwise return undefined.
  V8_INLINE Handle<Object> NumberToStringCacheGet(Tagged<Object> number,
                                                  int hash);

  // Update the cache with a new number-string pair.
  V8_INLINE void NumberToStringCacheSet(DirectHandle<Object> number, int hash,
                                        DirectHandle<String> js_string);

  // Creates a new JSArray with the given backing storage. Performs no
  // verification of the backing storage because it may not yet be filled.
  Handle<JSArray> NewJSArrayWithUnverifiedElements(
      DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
      int length, AllocationType allocation = AllocationType::kYoung);
  Handle<JSArray> NewJSArrayWithUnverifiedElements(
      DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements, int length,
      AllocationType allocation = AllocationType::kYoung);

  // Creates the backing storage for a JSArray. This handle must be discarded
  // before returning the JSArray reference to code outside Factory, which might
  // decide to left-trim the backing store. To avoid unnecessary HandleScopes,
  // this method requires capacity greater than zero.
  Handle<FixedArrayBase> NewJSArrayStorage(
      ElementsKind elements_kind, int capacity,
      ArrayStorageAllocationMode mode =
          ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS);

  void InitializeAllocationMemento(Tagged<AllocationMemento> memento,
                                   Tagged<AllocationSite> allocation_site);

  // Initializes a JSObject based on its map.
  void InitializeJSObjectFromMap(
      Tagged<JSObject> obj, Tagged<Object> properties, Tagged<Map> map,
      NewJSObjectType = NewJSObjectType::kNoAPIWrapper);
  // Initializes JSObject body starting at given offset.
  void InitializeJSObjectBody(Tagged<JSObject> obj, Tagged<Map> map,
                              int start_offset);
  void InitializeCppHeapWrapper(Tagged<JSObject> obj);

  Handle<WeakArrayList> NewUninitializedWeakArrayList(
      int capacity, AllocationType allocation = AllocationType::kYoung);

#if V8_ENABLE_WEBASSEMBLY
  // The resulting array will be uninitialized, which means GC might fail for
  // reference arrays until initialization. Follow this up with a
  // {DisallowGarbageCollection} scope until initialization.
  Tagged<WasmArray> NewWasmArrayUninitialized(uint32_t length,
                                              DirectHandle<Map> map);

#if V8_ENABLE_DRUMBRAKE
  // The resulting struct will be uninitialized, which means GC might fail for
  // reference structs until initialization. Follow this up with a
  // {DisallowGarbageCollection} scope until initialization.
  Handle<WasmStruct> NewWasmStructUninitialized(const wasm::StructType* type,
                                                Handle<Map> map);

  // WasmInterpreterRuntime needs to call NewWasmStructUninitialized and
  // NewWasmArrayUninitialized.
  friend class wasm::WasmInterpreterRuntime;
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_FACTORY_H_
```

## 功能列举

`v8/src/heap/factory.h` 是 V8 引擎中用于创建各种堆上对象的工厂类 `Factory` 的头文件。它提供了一系列 `New...` 方法，用于分配和初始化不同类型的 V8 内部对象。其主要功能包括：

1. **创建 JavaScript 对象:**
   - `NewJSObject`: 创建通用的 JavaScript 对象。
   - `NewJSArray`: 创建 JavaScript 数组。
   - `NewJSFunction`: 创建 JavaScript 函数。
   - `NewJSBoundFunction`: 创建绑定函数。
   - `NewJSProxy`: 创建代理对象。
   - `NewJSMap`, `NewJSSet`: 创建 Map 和 Set 对象。
   - `NewJSPromise`: 创建 Promise 对象。
   - `NewJSSharedStruct`, `NewJSSharedArray`: 创建 Shared Struct 和 Shared Array 对象。
   - `NewExternal`:  为外部 C++ 对象创建包装器。

2. **创建 JavaScript 基本类型包装对象:** (虽然这里没有直接列出，但可以通过创建 `JSObject` 并设置其内部属性来实现)

3. **创建 JavaScript 模块相关的对象:**
   - `NewSourceTextModule`: 创建 ES 模块。
   - `NewSyntheticModule`: 创建合成模块。

4. **创建 WebAssembly 相关的对象 (在 `V8_ENABLE_WEBASSEMBLY` 宏定义下):**
   - `NewWasmStruct`: 创建 WebAssembly 结构体实例。
   - `NewWasmArray`: 创建 WebAssembly 数组实例。
   - `NewWasmContinuationObject`: 创建 WebAssembly Continuation 对象。
   - `NewSharedFunctionInfoForWasm...`: 创建 WebAssembly 函数的 `SharedFunctionInfo`。

5. **创建类型化数组和 DataView:**
   - `NewJSArrayBuffer`: 创建 ArrayBuffer 对象。
   - `NewJSSharedArrayBuffer`: 创建 SharedArrayBuffer 对象。
   - `NewJSTypedArray`: 创建类型化数组 (如 Uint8Array, Float64Array)。
   - `NewJSDataViewOrRabGsabDataView`: 创建 DataView 对象。

6. **创建迭代器结果:**
   - `NewJSIteratorResult`: 创建迭代器结果对象。
   - `NewJSAsyncFromSyncIterator`: 创建异步迭代器。

7. **创建函数相关的对象:**
   - `NewSharedFunctionInfoForApiFunction`:  为 C++ API 函数创建 `SharedFunctionInfo`.
   - `NewSharedFunctionInfoForBuiltin`: 为内置函数创建 `SharedFunctionInfo`.
   - `NewInterpreterData`: 创建解释器数据。
   - `NewFunctionTemplateInfo`, `NewObjectTemplateInfo`, `NewDictionaryTemplateInfo`:  创建模板信息对象，用于 C++ API。

8. **创建错误对象:**
   - `NewError`: 创建通用的 Error 对象。
   - `New...Error`: 创建各种特定的错误对象 (TypeError, RangeError 等)。
   - `NewSuppressedErrorAtDisposal`: 创建被抑制的错误对象。
   - `ShadowRealmNewTypeErrorCopy`: 为 ShadowRealm 创建类型错误副本。

9. **创建代码对象:**
   - `NewCodeObjectForEmbeddedBuiltin`: 为嵌入式内置函数创建代码对象。
   - `CopyBytecodeArray`: 复制字节码数组。

10. **创建调试和性能分析相关的对象:**
    - `NewJSMessageObject`: 创建消息对象，用于错误报告等。
    - `NewDebugInfo`: 创建调试信息对象。

11. **创建正则表达式相关的对象:**
    - `SetRegExpAtomData`, `SetRegExpIrregexpData`, `SetRegExpExperimentalData`: 设置正则表达式数据。
    - `NewAtomRegExpData`, `NewIrRegExpData`, `NewExperimentalRegExpData`: 创建正则表达式数据对象。

12. **创建同步原语相关的对象:**
    - `NewJSAtomicsMutex`: 创建互斥锁对象。
    - `NewJSAtomicsCondition`: 创建条件变量对象。

13. **实用工具方法:**
    - `SizeToString`, `Uint32ToString`: 将数字转换为字符串。
    - `GlobalConstantFor`: 获取全局常量的值 (如 `undefined`)。

Prompt: 
```
这是目录为v8/src/heap/factory.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/factory.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
t> NewWasmStruct(const wasm::StructType* type,
                                   wasm::WasmValue* args,
                                   DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArray(wasm::ValueType element_type, uint32_t length,
                                 wasm::WasmValue initial_value,
                                 DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArrayFromElements(
      const wasm::ArrayType* type, base::Vector<wasm::WasmValue> elements,
      DirectHandle<Map> map);
  Handle<WasmArray> NewWasmArrayFromMemory(uint32_t length,
                                           DirectHandle<Map> map,
                                           Address source);
  // Returns a handle to a WasmArray if successful, or a Smi containing a
  // {MessageTemplate} if computing the array's elements leads to an error.
  Handle<Object> NewWasmArrayFromElementSegment(
      Handle<WasmTrustedInstanceData> trusted_instance_data,
      Handle<WasmTrustedInstanceData> shared_trusted_instance_data,
      uint32_t segment_index, uint32_t start_offset, uint32_t length,
      DirectHandle<Map> map);
  Handle<WasmContinuationObject> NewWasmContinuationObject(
      Address jmpbuf, wasm::StackMemory* stack, DirectHandle<HeapObject> parent,
      AllocationType allocation = AllocationType::kYoung);

  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmExportedFunction(
      DirectHandle<String> name, DirectHandle<WasmExportedFunctionData> data,
      int len, AdaptArguments adapt);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmJSFunction(
      DirectHandle<String> name, DirectHandle<WasmJSFunctionData> data);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmResume(
      DirectHandle<WasmResumeData> data);
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForWasmCapiFunction(
      DirectHandle<WasmCapiFunctionData> data);
#endif  // V8_ENABLE_WEBASSEMBLY

  Handle<SourceTextModule> NewSourceTextModule(
      DirectHandle<SharedFunctionInfo> code);
  Handle<SyntheticModule> NewSyntheticModule(
      DirectHandle<String> module_name, DirectHandle<FixedArray> export_names,
      v8::Module::SyntheticModuleEvaluationSteps evaluation_steps);

  Handle<JSArrayBuffer> NewJSArrayBuffer(
      std::shared_ptr<BackingStore> backing_store,
      AllocationType allocation = AllocationType::kYoung);

  MaybeHandle<JSArrayBuffer> NewJSArrayBufferAndBackingStore(
      size_t byte_length, InitializedFlag initialized,
      AllocationType allocation = AllocationType::kYoung);

  MaybeHandle<JSArrayBuffer> NewJSArrayBufferAndBackingStore(
      size_t byte_length, size_t max_byte_length, InitializedFlag initialized,
      ResizableFlag resizable = ResizableFlag::kNotResizable,
      AllocationType allocation = AllocationType::kYoung);

  Handle<JSArrayBuffer> NewJSSharedArrayBuffer(
      std::shared_ptr<BackingStore> backing_store);

  static void TypeAndSizeForElementsKind(ElementsKind kind,
                                         ExternalArrayType* array_type,
                                         size_t* element_size);

  // Creates a new JSTypedArray with the specified buffer.
  Handle<JSTypedArray> NewJSTypedArray(ExternalArrayType type,
                                       DirectHandle<JSArrayBuffer> buffer,
                                       size_t byte_offset, size_t length,
                                       bool is_length_tracking = false);

  Handle<JSDataViewOrRabGsabDataView> NewJSDataViewOrRabGsabDataView(
      DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
      size_t byte_length, bool is_length_tracking = false);

  Handle<JSIteratorResult> NewJSIteratorResult(DirectHandle<Object> value,
                                               bool done);
  Handle<JSAsyncFromSyncIterator> NewJSAsyncFromSyncIterator(
      DirectHandle<JSReceiver> sync_iterator, DirectHandle<Object> next);

  Handle<JSMap> NewJSMap();
  Handle<JSSet> NewJSSet();

  // Allocates a bound function. If direct handles are enabled, it is the
  // responsibility of the caller to ensure that the memory pointed to by
  // `bound_args` is scanned during CSS, e.g., it comes from a
  // `DirectHandleVector<Object>`.
  MaybeHandle<JSBoundFunction> NewJSBoundFunction(
      DirectHandle<JSReceiver> target_function, DirectHandle<JSAny> bound_this,
      base::Vector<DirectHandle<Object>> bound_args,
      Handle<JSPrototype> prototype);

  // Allocates a Harmony proxy.
  Handle<JSProxy> NewJSProxy(DirectHandle<JSReceiver> target,
                             DirectHandle<JSReceiver> handler);

  // Reinitialize an JSGlobalProxy based on a constructor.  The object
  // must have the same size as objects allocated using the
  // constructor.  The object is reinitialized and behaves as an
  // object that has been freshly allocated using the constructor.
  void ReinitializeJSGlobalProxy(DirectHandle<JSGlobalProxy> global,
                                 DirectHandle<JSFunction> constructor);

  Handle<JSGlobalProxy> NewUninitializedJSGlobalProxy(int size);

  // For testing only. Creates a sloppy function without code.
  Handle<JSFunction> NewFunctionForTesting(DirectHandle<String> name);

  // Create an External object for V8's external API.
  Handle<JSObject> NewExternal(
      void* value, AllocationType allocation = AllocationType::kYoung);

  // Allocates a new code object and initializes it to point to the given
  // off-heap entry point.
  //
  // Note it wouldn't be strictly necessary to create new Code objects, instead
  // Code::instruction_start and instruction_stream could be reset. But creating
  // a new Code object doesn't hurt much (it only makes mksnapshot slightly more
  // expensive) and has real benefits:
  // - it moves all special-casing to mksnapshot-time; at normal runtime, the
  //   system only sees a) non-builtin Code objects (not in RO space, with
  //   instruction_stream set) and b) builtin Code objects (maybe in RO space,
  //   without instruction_stream set).
  // - it's a convenient bottleneck to make the RO-space allocation decision.
  Handle<Code> NewCodeObjectForEmbeddedBuiltin(DirectHandle<Code> code,
                                               Address off_heap_entry);

  Handle<BytecodeArray> CopyBytecodeArray(DirectHandle<BytecodeArray>);

  // Interface for creating error objects.
  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            DirectHandle<String> message,
                            Handle<Object> options = {});

  Handle<Object> NewInvalidStringLengthError();

  inline Handle<Object> NewURIError();

  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            MessageTemplate template_index,
                            base::Vector<const DirectHandle<Object>> args);

  Handle<JSObject> NewSuppressedErrorAtDisposal(
      Isolate* isolate, Handle<Object> error, Handle<Object> suppressed_error);

  template <typename... Args,
            typename = std::enable_if_t<std::conjunction_v<
                std::is_convertible<Args, DirectHandle<Object>>...>>>
  Handle<JSObject> NewError(Handle<JSFunction> constructor,
                            MessageTemplate template_index, Args... args) {
    return NewError(constructor, template_index,
                    base::VectorOf<DirectHandle<Object>>({args...}));
  }

  // https://tc39.es/proposal-shadowrealm/#sec-create-type-error-copy
  Handle<JSObject> ShadowRealmNewTypeErrorCopy(
      Handle<Object> original, MessageTemplate template_index,
      base::Vector<const DirectHandle<Object>> args);

  template <typename... Args,
            typename = std::enable_if_t<std::conjunction_v<
                std::is_convertible<Args, DirectHandle<Object>>...>>>
  Handle<JSObject> ShadowRealmNewTypeErrorCopy(Handle<Object> original,
                                               MessageTemplate template_index,
                                               Args... args) {
    return ShadowRealmNewTypeErrorCopy(
        original, template_index,
        base::VectorOf<DirectHandle<Object>>({args...}));
  }

#define DECLARE_ERROR(NAME)                                                  \
  Handle<JSObject> New##NAME(MessageTemplate template_index,                 \
                             base::Vector<const DirectHandle<Object>> args); \
                                                                             \
  template <typename... Args,                                                \
            typename = std::enable_if_t<std::conjunction_v<                  \
                std::is_convertible<Args, DirectHandle<Object>>...>>>        \
  Handle<JSObject> New##NAME(MessageTemplate template_index, Args... args) { \
    return New##NAME(template_index,                                         \
                     base::VectorOf<DirectHandle<Object>>({args...}));       \
  }
  DECLARE_ERROR(Error)
  DECLARE_ERROR(EvalError)
  DECLARE_ERROR(RangeError)
  DECLARE_ERROR(ReferenceError)
  DECLARE_ERROR(SuppressedError)
  DECLARE_ERROR(SyntaxError)
  DECLARE_ERROR(TypeError)
  DECLARE_ERROR(WasmCompileError)
  DECLARE_ERROR(WasmLinkError)
  DECLARE_ERROR(WasmRuntimeError)
  DECLARE_ERROR(WasmExceptionError)
#undef DECLARE_ERROR

  Handle<String> SizeToString(size_t value, bool check_cache = true);
  inline Handle<String> Uint32ToString(uint32_t value,
                                       bool check_cache = true) {
    return SizeToString(value, check_cache);
  }

#define ROOT_ACCESSOR(Type, name, CamelName) inline Handle<Type> name();
  MUTABLE_ROOT_LIST(ROOT_ACCESSOR)
#undef ROOT_ACCESSOR

  // Allocates a new SharedFunctionInfo object.
  Handle<SharedFunctionInfo> NewSharedFunctionInfoForApiFunction(
      MaybeDirectHandle<String> maybe_name,
      DirectHandle<FunctionTemplateInfo> function_template_info,
      FunctionKind kind);

  Handle<SharedFunctionInfo> NewSharedFunctionInfoForBuiltin(
      MaybeDirectHandle<String> name, Builtin builtin, int len,
      AdaptArguments adapt, FunctionKind kind = FunctionKind::kNormalFunction);

  Handle<InterpreterData> NewInterpreterData(
      DirectHandle<BytecodeArray> bytecode_array, DirectHandle<Code> code);

  static bool IsFunctionModeWithPrototype(FunctionMode function_mode) {
    return (function_mode & kWithPrototypeBits) != 0;
  }

  static bool IsFunctionModeWithWritablePrototype(FunctionMode function_mode) {
    return (function_mode & kWithWritablePrototypeBit) != 0;
  }

  static bool IsFunctionModeWithName(FunctionMode function_mode) {
    return (function_mode & kWithNameBit) != 0;
  }

  Handle<Map> CreateSloppyFunctionMap(
      FunctionMode function_mode, MaybeHandle<JSFunction> maybe_empty_function);

  Handle<Map> CreateStrictFunctionMap(FunctionMode function_mode,
                                      Handle<JSFunction> empty_function);

  Handle<Map> CreateClassFunctionMap(Handle<JSFunction> empty_function);

  // Allocates a new JSMessageObject object.
  Handle<JSMessageObject> NewJSMessageObject(
      MessageTemplate message, DirectHandle<Object> argument,
      int start_position, int end_position,
      DirectHandle<SharedFunctionInfo> shared_info, int bytecode_offset,
      DirectHandle<Script> script,
      DirectHandle<StackTraceInfo> stack_trace =
          DirectHandle<StackTraceInfo>::null());

  Handle<DebugInfo> NewDebugInfo(DirectHandle<SharedFunctionInfo> shared);

  // Return a map for given number of properties using the map cache in the
  // native context.
  Handle<Map> ObjectLiteralMapFromCache(
      DirectHandle<NativeContext> native_context, int number_of_properties);

  Handle<LoadHandler> NewLoadHandler(
      int data_count, AllocationType allocation = AllocationType::kOld);
  Handle<StoreHandler> NewStoreHandler(int data_count);
  Handle<MegaDomHandler> NewMegaDomHandler(MaybeObjectHandle accessor,
                                           MaybeObjectHandle context);

  // Creates a new FixedArray that holds the data associated with the
  // atom regexp and stores it in the regexp.
  void SetRegExpAtomData(DirectHandle<JSRegExp> regexp,
                         DirectHandle<String> source, JSRegExp::Flags flags,
                         DirectHandle<String> match_pattern);

  // Creates a new FixedArray that holds the data associated with the
  // irregexp regexp and stores it in the regexp.
  void SetRegExpIrregexpData(DirectHandle<JSRegExp> regexp,
                             DirectHandle<String> source, JSRegExp::Flags flags,
                             int capture_count, uint32_t backtrack_limit);

  // Creates a new FixedArray that holds the data associated with the
  // experimental regexp and stores it in the regexp.
  void SetRegExpExperimentalData(DirectHandle<JSRegExp> regexp,
                                 DirectHandle<String> source,
                                 JSRegExp::Flags flags, int capture_count);

  Handle<RegExpData> NewAtomRegExpData(DirectHandle<String> source,
                                       JSRegExp::Flags flags,
                                       DirectHandle<String> pattern);
  Handle<RegExpData> NewIrRegExpData(DirectHandle<String> source,
                                     JSRegExp::Flags flags, int capture_count,
                                     uint32_t backtrack_limit);
  Handle<RegExpData> NewExperimentalRegExpData(DirectHandle<String> source,
                                               JSRegExp::Flags flags,
                                               int capture_count);

  // Returns the value for a known global constant (a property of the global
  // object which is neither configurable nor writable) like 'undefined'.
  // Returns a null handle when the given name is unknown.
  Handle<Object> GlobalConstantFor(Handle<Name> name);

  // Converts the given ToPrimitive hint to its string representation.
  Handle<String> ToPrimitiveHintString(ToPrimitiveHint hint);

  Handle<JSPromise> NewJSPromiseWithoutHook();
  Handle<JSPromise> NewJSPromise();

  Tagged<HeapObject> NewForTest(DirectHandle<Map> map,
                                AllocationType allocation) {
    return New(map, allocation);
  }

  Handle<JSSharedStruct> NewJSSharedStruct(
      Handle<JSFunction> constructor,
      MaybeHandle<NumberDictionary> maybe_elements_template);

  Handle<JSSharedArray> NewJSSharedArray(Handle<JSFunction> constructor,
                                         int length);

  Handle<JSAtomicsMutex> NewJSAtomicsMutex();

  Handle<JSAtomicsCondition> NewJSAtomicsCondition();

  Handle<FunctionTemplateInfo> NewFunctionTemplateInfo(int length,
                                                       bool do_not_cache);

  Handle<ObjectTemplateInfo> NewObjectTemplateInfo(
      DirectHandle<FunctionTemplateInfo> constructor, bool do_not_cache);

  Handle<DictionaryTemplateInfo> NewDictionaryTemplateInfo(
      DirectHandle<FixedArray> property_names);

  // Helper class for creating JSFunction objects.
  class V8_EXPORT_PRIVATE JSFunctionBuilder final {
   public:
    JSFunctionBuilder(Isolate* isolate, DirectHandle<SharedFunctionInfo> sfi,
                      DirectHandle<Context> context);

    V8_WARN_UNUSED_RESULT Handle<JSFunction> Build();

    JSFunctionBuilder& set_map(DirectHandle<Map> v) {
      maybe_map_ = v;
      return *this;
    }
    JSFunctionBuilder& set_allocation_type(AllocationType v) {
      allocation_type_ = v;
      return *this;
    }
    JSFunctionBuilder& set_feedback_cell(DirectHandle<FeedbackCell> v) {
      maybe_feedback_cell_ = v;
      return *this;
    }

   private:
    void PrepareMap();
    void PrepareFeedbackCell();

    V8_WARN_UNUSED_RESULT Handle<JSFunction> BuildRaw(DirectHandle<Code> code);

    Isolate* const isolate_;
    DirectHandle<SharedFunctionInfo> sfi_;
    DirectHandle<Context> context_;
    MaybeDirectHandle<Map> maybe_map_;
    MaybeDirectHandle<FeedbackCell> maybe_feedback_cell_;
    AllocationType allocation_type_ = AllocationType::kOld;

    friend class Factory;
  };

  // Allows creation of InstructionStream objects. It provides two build
  // methods, one of which tries to gracefully handle allocation failure.
  class V8_EXPORT_PRIVATE CodeBuilder final {
   public:
    CodeBuilder(Isolate* isolate, const CodeDesc& desc, CodeKind kind);

    // TODO(victorgomes): Remove Isolate dependency from CodeBuilder.
    CodeBuilder(LocalIsolate* local_isolate, const CodeDesc& desc,
                CodeKind kind);

    // Builds a new code object (fully initialized). All header fields of the
    // associated InstructionStream are immutable and the InstructionStream
    // object is write protected.
    V8_WARN_UNUSED_RESULT Handle<Code> Build();
    // Like Build, builds a new code object. May return an empty handle if the
    // allocation fails.
    V8_WARN_UNUSED_RESULT MaybeHandle<Code> TryBuild();

    // Sets the self-reference object in which a reference to the code object is
    // stored. This allows generated code to reference its own InstructionStream
    // object by using this handle.
    CodeBuilder& set_self_reference(Handle<Object> self_reference) {
      DCHECK(!self_reference.is_null());
      self_reference_ = self_reference;
      return *this;
    }

    CodeBuilder& set_builtin(Builtin builtin) {
      DCHECK_IMPLIES(builtin != Builtin::kNoBuiltinId,
                     !CodeKindIsJSFunction(kind_));
      builtin_ = builtin;
      return *this;
    }

    CodeBuilder& set_inlined_bytecode_size(uint32_t size) {
      DCHECK_IMPLIES(size != 0, CodeKindIsOptimizedJSFunction(kind_));
      inlined_bytecode_size_ = size;
      return *this;
    }

    CodeBuilder& set_osr_offset(BytecodeOffset offset) {
      DCHECK_IMPLIES(!offset.IsNone(), CodeKindCanOSR(kind_));
      osr_offset_ = offset;
      return *this;
    }

    CodeBuilder& set_source_position_table(Handle<TrustedByteArray> table) {
      DCHECK_NE(kind_, CodeKind::BASELINE);
      DCHECK(!table.is_null());
      source_position_table_ = table;
      return *this;
    }

    inline CodeBuilder& set_empty_source_position_table();

    CodeBuilder& set_bytecode_offset_table(Handle<TrustedByteArray> table) {
      DCHECK_EQ(kind_, CodeKind::BASELINE);
      DCHECK(!table.is_null());
      bytecode_offset_table_ = table;
      return *this;
    }

    CodeBuilder& set_deoptimization_data(
        Handle<DeoptimizationData> deopt_data) {
      DCHECK_NE(kind_, CodeKind::BASELINE);
      DCHECK(!deopt_data.is_null());
      deoptimization_data_ = deopt_data;
      return *this;
    }

    inline CodeBuilder& set_interpreter_data(
        Handle<TrustedObject> interpreter_data);

    CodeBuilder& set_is_context_specialized() {
      DCHECK(!CodeKindIsUnoptimizedJSFunction(kind_));
      is_context_specialized_ = true;
      return *this;
    }

    CodeBuilder& set_is_turbofanned() {
      DCHECK(!CodeKindIsUnoptimizedJSFunction(kind_));
      is_turbofanned_ = true;
      return *this;
    }

    CodeBuilder& set_stack_slots(int stack_slots) {
      stack_slots_ = stack_slots;
      return *this;
    }

    CodeBuilder& set_parameter_count(uint16_t parameter_count) {
      parameter_count_ = parameter_count;
      return *this;
    }

    CodeBuilder& set_profiler_data(BasicBlockProfilerData* profiler_data) {
      profiler_data_ = profiler_data;
      return *this;
    }

   private:
    MaybeHandle<Code> BuildInternal(bool retry_allocation_or_fail);

    Handle<TrustedByteArray> NewTrustedByteArray(int length);
    // Return an allocation suitable for InstructionStreams but without writing
    // the map.
    Tagged<HeapObject> AllocateUninitializedInstructionStream(
        bool retry_allocation_or_fail);
    Handle<Code> NewCode(const NewCodeOptions& options);

    Isolate* const isolate_;
    LocalIsolate* local_isolate_;
    const CodeDesc& code_desc_;
    const CodeKind kind_;

    MaybeHandle<Object> self_reference_;
    Builtin builtin_ = Builtin::kNoBuiltinId;
    uint32_t inlined_bytecode_size_ = 0;
    BytecodeOffset osr_offset_ = BytecodeOffset::None();
    MaybeHandle<TrustedByteArray> bytecode_offset_table_;
    MaybeHandle<TrustedByteArray> source_position_table_;
    MaybeHandle<DeoptimizationData> deoptimization_data_;
    MaybeHandle<TrustedObject> interpreter_data_;
    BasicBlockProfilerData* profiler_data_ = nullptr;
    bool is_context_specialized_ = false;
    bool is_turbofanned_ = false;
    uint32_t stack_slots_ = 0;
    uint16_t parameter_count_ = 0;
  };

 private:
  friend class FactoryBase<Factory>;

  // ------
  // Customization points for FactoryBase
  Tagged<HeapObject> AllocateRaw(
      int size, AllocationType allocation,
      AllocationAlignment alignment = kTaggedAligned);

  Isolate* isolate() const {
    // Downcast to the privately inherited sub-class using c-style casts to
    // avoid undefined behavior (as static_cast cannot cast across private
    // bases).
    // NOLINTNEXTLINE (google-readability-casting)
    return (Isolate*)this;  // NOLINT(readability/casting)
  }

  V8_INLINE HeapAllocator* allocator() const;

  bool CanAllocateInReadOnlySpace();
  bool EmptyStringRootIsInitialized();
  AllocationType AllocationTypeForInPlaceInternalizableString();

  void ProcessNewScript(Handle<Script> shared,
                        ScriptEventType script_event_type);
  // ------

  // MetaMapProviderFunc is supposed to be a function returning Tagged<Map>.
  // For example,  std::function<Tagged<Map>()>.
  template <typename MetaMapProviderFunc>
  V8_INLINE Handle<Map> NewMapImpl(
      MetaMapProviderFunc&& meta_map_provider, InstanceType type,
      int instance_size,
      ElementsKind elements_kind = TERMINAL_FAST_ELEMENTS_KIND,
      int inobject_properties = 0,
      AllocationType allocation_type = AllocationType::kMap);

  Tagged<HeapObject> AllocateRawWithAllocationSite(
      DirectHandle<Map> map, AllocationType allocation,
      DirectHandle<AllocationSite> allocation_site);

  Handle<JSArrayBufferView> NewJSArrayBufferView(
      DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements,
      DirectHandle<JSArrayBuffer> buffer, size_t byte_offset,
      size_t byte_length);

  Tagged<Symbol> NewSymbolInternal(
      AllocationType allocation = AllocationType::kOld);

  // Allocates new context with given map, sets length and initializes the
  // after-header part with uninitialized values and leaves the context header
  // uninitialized.
  Tagged<Context> NewContextInternal(DirectHandle<Map> map, int size,
                                     int variadic_part_length,
                                     AllocationType allocation);

  template <typename T>
  Handle<T> AllocateSmallOrderedHashTable(DirectHandle<Map> map, int capacity,
                                          AllocationType allocation);

  // Creates a heap object based on the map. The fields of the heap object are
  // not initialized, it's the responsibility of the caller to do that.
  Tagged<HeapObject> New(DirectHandle<Map> map, AllocationType allocation);

  template <typename T>
  Handle<T> CopyArrayWithMap(
      DirectHandle<T> src, DirectHandle<Map> map,
      AllocationType allocation = AllocationType::kYoung);
  template <typename T>
  Handle<T> CopyArrayAndGrow(DirectHandle<T> src, int grow_by,
                             AllocationType allocation);

  MaybeHandle<String> NewStringFromTwoByte(const base::uc16* string, int length,
                                           AllocationType allocation);

  // Functions to get the hash of a number for the number_string_cache.
  int NumberToStringCacheHash(Tagged<Smi> number);
  int NumberToStringCacheHash(double number);

  // Attempt to find the number in a small cache.  If we finds it, return
  // the string representation of the number.  Otherwise return undefined.
  V8_INLINE Handle<Object> NumberToStringCacheGet(Tagged<Object> number,
                                                  int hash);

  // Update the cache with a new number-string pair.
  V8_INLINE void NumberToStringCacheSet(DirectHandle<Object> number, int hash,
                                        DirectHandle<String> js_string);

  // Creates a new JSArray with the given backing storage. Performs no
  // verification of the backing storage because it may not yet be filled.
  Handle<JSArray> NewJSArrayWithUnverifiedElements(
      DirectHandle<FixedArrayBase> elements, ElementsKind elements_kind,
      int length, AllocationType allocation = AllocationType::kYoung);
  Handle<JSArray> NewJSArrayWithUnverifiedElements(
      DirectHandle<Map> map, DirectHandle<FixedArrayBase> elements, int length,
      AllocationType allocation = AllocationType::kYoung);

  // Creates the backing storage for a JSArray. This handle must be discarded
  // before returning the JSArray reference to code outside Factory, which might
  // decide to left-trim the backing store. To avoid unnecessary HandleScopes,
  // this method requires capacity greater than zero.
  Handle<FixedArrayBase> NewJSArrayStorage(
      ElementsKind elements_kind, int capacity,
      ArrayStorageAllocationMode mode =
          ArrayStorageAllocationMode::DONT_INITIALIZE_ARRAY_ELEMENTS);

  void InitializeAllocationMemento(Tagged<AllocationMemento> memento,
                                   Tagged<AllocationSite> allocation_site);

  // Initializes a JSObject based on its map.
  void InitializeJSObjectFromMap(
      Tagged<JSObject> obj, Tagged<Object> properties, Tagged<Map> map,
      NewJSObjectType = NewJSObjectType::kNoAPIWrapper);
  // Initializes JSObject body starting at given offset.
  void InitializeJSObjectBody(Tagged<JSObject> obj, Tagged<Map> map,
                              int start_offset);
  void InitializeCppHeapWrapper(Tagged<JSObject> obj);

  Handle<WeakArrayList> NewUninitializedWeakArrayList(
      int capacity, AllocationType allocation = AllocationType::kYoung);

#if V8_ENABLE_WEBASSEMBLY
  // The resulting array will be uninitialized, which means GC might fail for
  // reference arrays until initialization. Follow this up with a
  // {DisallowGarbageCollection} scope until initialization.
  Tagged<WasmArray> NewWasmArrayUninitialized(uint32_t length,
                                              DirectHandle<Map> map);

#if V8_ENABLE_DRUMBRAKE
  // The resulting struct will be uninitialized, which means GC might fail for
  // reference structs until initialization. Follow this up with a
  // {DisallowGarbageCollection} scope until initialization.
  Handle<WasmStruct> NewWasmStructUninitialized(const wasm::StructType* type,
                                                Handle<Map> map);

  // WasmInterpreterRuntime needs to call NewWasmStructUninitialized and
  // NewWasmArrayUninitialized.
  friend class wasm::WasmInterpreterRuntime;
#endif  // V8_ENABLE_DRUMBRAKE
#endif  // V8_ENABLE_WEBASSEMBLY
};

}  // namespace internal
}  // namespace v8

#endif  // V8_HEAP_FACTORY_H_

"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/profiler/heap-snapshot-generator.cc`.

Here's a breakdown of the code's purpose and key features:

1. **Object Exploration:** The code is designed to traverse the V8 heap and extract information about objects.
2. **Heap Snapshot Generation:** This information is used to generate heap snapshots, which are essentially detailed records of the memory used by the JavaScript engine at a specific point in time.
3. **Object Classification:** It categorizes objects into different types (e.g., JSObject, String, Code, Map) and assigns them meaningful names for the snapshot.
4. **Reference Tracking:** The code identifies and records references between objects, showing how they are connected in memory. This includes strong and weak references.
5. **Location Information:** It attempts to pinpoint the JavaScript code location (script ID, line number, column number) where objects were created.
6. **System Internals:** It handles V8 internal objects (like Maps, Contexts, SharedFunctionInfo) and represents them in the snapshot.
7. **Wasm Support:**  It includes specific handling for WebAssembly objects.
8. **Embedder Integration:** It acknowledges the concept of embedder fields.

Considering the prompt's instructions, I need to:

*   List the functionalities of the code.
*   Confirm it's not Torque code (it doesn't end with `.tq`).
*   Illustrate its connection to JavaScript functionality with an example.
*   Provide a code logic inference example with input and output.
*   Mention common programming errors related to heap snapshots.
*   Synthesize a concise summary of its functionality for this "Part 2".
这是 `v8/src/profiler/heap-snapshot-generator.cc` 的第二部分代码，其主要功能是**详细分析和记录V8堆中的对象信息，以便生成堆快照**。

以下是该部分代码功能的归纳：

1. **提取对象的位置信息：**
    *   `ExtractLocation` 函数根据给定的堆对象，尝试找到定义该对象的 JavaScript 函数。
    *   `ExtractLocationForJSFunction` 函数根据 JSFunction 的 `SharedFunctionInfo` 中的脚本信息，获取代码的行号和列号，并将其添加到快照中。
    *   这部分功能与 JavaScript 的源代码调试和性能分析密切相关。

2. **为堆条目添加名称和类型：**
    *   `AddEntry(Tagged<HeapObject> object)` 函数根据对象的类型（如 JSObject, String, Symbol 等）为其生成一个人类可读的名称，并确定其在堆快照中的类型（如 kClosure, kRegExp, kObject, kString 等）。
    *   它会处理不同类型的 JavaScript 对象和 V8 内部对象，并根据其特性生成相应的名称。例如，JSFunction 会使用其函数名，而字符串会使用其内容（如果适用）。
    *   它还处理了 WebAssembly 相关的对象类型。
    *   对于某些系统内部对象，会使用 "system / " 前缀进行标记。
    *   `AddEntry(Tagged<HeapObject> object, HeapEntry::Type type, const char* name)` 和 `AddEntry(Address address, HeapEntry::Type type, const char* name, size_t size)` 是重载的辅助函数，用于实际添加带有类型和名称的堆条目。

3. **获取系统条目的名称和类型：**
    *   `GetSystemEntryName` 函数为一些 V8 内部对象（如 Map, FixedArray 等）生成默认的名称，通常带有 "system / " 前缀。
    *   `GetSystemEntryType` 函数根据对象的类型，确定其在堆快照中的通用类型，例如 kCode (用于代码相关的对象), kArray, kObjectShape, kHidden。

4. **填充脚本的行尾信息：**
    *   `PopulateLineEnds` 函数遍历所有的 JavaScript 脚本，并为尚未计算行尾信息的脚本计算并添加到快照中。这对于准确映射堆对象到源代码位置至关重要。

5. **估计对象数量：**
    *   `EstimateObjectsCount` 函数遍历堆，估计堆中对象的总数。这可以用于显示生成快照的进度。

6. **提取对象的引用关系：**
    *   `IndexedReferencesExtractor` 是一个辅助类，用于遍历对象的内部字段，并记录对象之间的引用关系。
    *   `ExtractReferences` 函数根据对象的类型，调用相应的函数来提取该对象指向其他对象的引用。这包括 JSObject 的属性和元素，字符串的内部结构，以及其他 V8 内部对象的引用关系。
    *   针对不同类型的对象（如 JSGlobalProxy, JSArrayBuffer, JSWeakSet, JSMap, JSPromise 等）都有特定的引用提取逻辑。
    *   对于 WeakMap 等弱引用结构，会特殊处理。

7. **具体的引用提取逻辑：**
    *   代码中包含了大量的 `ExtractXXXReferences` 函数，例如 `ExtractJSObjectReferences`, `ExtractStringReferences`, `ExtractMapReferences` 等，这些函数负责根据对象的布局和内部结构，找出其引用的其他对象，并将其添加到堆快照中。
    *   例如，`ExtractJSObjectReferences` 会提取对象的属性、元素、原型、内部槽（如 `__proto__`，bindings 等）、代码对象、上下文等引用。
    *   对于特定的对象类型，如 `JSBoundFunction`，会提取其绑定的参数、 `this` 值和目标函数。

**关于您的问题：**

*   **`v8/src/profiler/heap-snapshot-generator.cc` 以 `.tq` 结尾吗？**  否，该文件名以 `.cc` 结尾，因此它是一个 C++ 源代码文件，而不是 v8 Torque 源代码。
*   **它与 javascript 的功能有关系吗？** 是的，该代码是 V8 JavaScript 引擎的一部分，其核心功能是分析 JavaScript 堆内存，为生成堆快照提供基础数据。

**JavaScript 示例：**

```javascript
function MyClass() {
  this.name = "example";
  this.data = [1, 2, 3];
}

let instance = new MyClass();
```

当生成堆快照时，`heap-snapshot-generator.cc` 中的代码会识别 `instance` 对象，并提取其属性（`name` 指向一个字符串对象，`data` 指向一个数组对象）。它还会识别 `MyClass` 函数对象。快照会记录这些对象以及它们之间的引用关系。

**代码逻辑推理示例：**

**假设输入：**  一个 `Tagged<JSFunction>` 对象 `func`，其 `shared()` 指向的 `SharedFunctionInfo` 的 `script()` 不为空，且 `has_line_ends()` 为 true，`StartPosition()` 返回 10。`Script::GetPositionInfo(10, &info)` 将 `info.line` 设置为 5，`info.column` 设置为 2。

**输出：**  `ExtractLocationForJSFunction` 函数会调用 `snapshot_->AddLocation(entry, scriptId, 5, 2)`，将该函数在代码中第 5 行第 2 列的位置信息添加到堆条目 `entry` 中。

**用户常见的编程错误（与堆快照分析相关）：**

用户在使用 JavaScript 时，可能会遇到由于内存泄漏导致的性能问题。堆快照分析可以帮助定位这些问题。常见的编程错误包括：

*   **意外的全局变量：** 未使用 `var`、`let` 或 `const` 声明的变量会成为全局变量，可能导致意外的内存占用。
*   **闭包导致的内存泄漏：** 闭包引用了外部作用域的变量，如果闭包长期存在，这些变量也无法被垃圾回收。
*   **未取消的事件监听器或定时器：** 如果事件监听器或定时器持续引用某些对象，即使这些对象不再需要，也无法被回收。
*   **缓存大量不再需要的对象：**  为了优化性能而进行的缓存，如果没有适当的清理机制，可能会导致内存占用过高。

**总结（针对第 2 部分）：**

该部分代码专注于 V8 堆内存的深度探索，负责识别堆中不同类型的对象，为其赋予有意义的名称和分类，并提取对象之间的引用关系和源代码位置信息。这是生成详细堆快照的关键步骤，为后续的内存分析和性能诊断提供了必要的数据基础。

Prompt: 
```
这是目录为v8/src/profiler/heap-snapshot-generator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/profiler/heap-snapshot-generator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能

"""
aybe_constructor;
  }

  return JSFunction();
}

void V8HeapExplorer::ExtractLocation(HeapEntry* entry,
                                     Tagged<HeapObject> object) {
  DisallowHeapAllocation no_gc;
  Tagged<JSFunction> func = GetLocationFunction(object);
  if (!func.is_null()) {
    ExtractLocationForJSFunction(entry, func);
  }
}

void V8HeapExplorer::ExtractLocationForJSFunction(HeapEntry* entry,
                                                  Tagged<JSFunction> func) {
  if (!IsScript(func->shared()->script())) return;
  Tagged<Script> script = Cast<Script>(func->shared()->script());
  int scriptId = script->id();
  int start = func->shared()->StartPosition();
  Script::PositionInfo info;
  if (script->has_line_ends()) {
    script->GetPositionInfo(start, &info);
  } else {
    script->GetPositionInfoWithLineEnds(
        start, &info, snapshot_->GetScriptLineEnds(script->id()));
  }
  snapshot_->AddLocation(entry, scriptId, info.line, info.column);
}

namespace {
// Templatized struct to statically generate the string "system / Managed<Foo>"
// from "kFooTag".
template <const char kTagNameCStr[]>
struct ManagedName {
  static constexpr std::string_view kTagName = kTagNameCStr;
  static_assert(kTagName.starts_with("k"));
  static_assert(kTagName.ends_with("Tag"));

  static constexpr std::string_view prefix = "system / Managed<";
  static constexpr std::string_view suffix = ">";

  // We strip four characters, but add prefix and suffix and null termination.
  static constexpr size_t kManagedNameLength =
      kTagName.size() - 4 + prefix.size() + suffix.size() + 1;

  static constexpr auto str_arr =
      base::make_array<kManagedNameLength>([](std::size_t i) {
        if (i < prefix.size()) return prefix[i];
        if (i == kManagedNameLength - 2) return suffix[0];
        if (i == kManagedNameLength - 1) return '\0';
        return kTagName[i - prefix.size() + 1];
      });

  // Ignore "kFirstManagedResourceTag".
  static constexpr bool ignore_me = kTagName == "kFirstManagedResourceTag";
};

// A little inline test:
constexpr const char kTagNameForTesting[] = "kFooTag";
static_assert(std::string_view{
                  ManagedName<kTagNameForTesting>::str_arr.data()} ==
              std::string_view{"system / Managed<Foo>"});
}  // namespace

HeapEntry* V8HeapExplorer::AddEntry(Tagged<HeapObject> object) {
  PtrComprCageBase cage_base(isolate());
  InstanceType instance_type = object->map(cage_base)->instance_type();
  if (InstanceTypeChecker::IsJSObject(instance_type)) {
    if (InstanceTypeChecker::IsJSFunction(instance_type)) {
      Tagged<JSFunction> func = Cast<JSFunction>(object);
      Tagged<SharedFunctionInfo> shared = func->shared();
      const char* name = names_->GetName(shared->Name());
      return AddEntry(object, HeapEntry::kClosure, name);

    } else if (InstanceTypeChecker::IsJSBoundFunction(instance_type)) {
      return AddEntry(object, HeapEntry::kClosure, "native_bind");
    }
    if (InstanceTypeChecker::IsJSRegExp(instance_type)) {
      Tagged<JSRegExp> re = Cast<JSRegExp>(object);
      return AddEntry(object, HeapEntry::kRegExp,
                      names_->GetName(re->source()));
    }
    // TODO(v8:12674) Fix and run full gcmole.
    DisableGCMole no_gcmole;
    const char* name = names_->GetName(
        GetConstructorName(heap_->isolate(), Cast<JSObject>(object)));
    if (InstanceTypeChecker::IsJSGlobalObject(instance_type)) {
      auto it = global_object_tag_map_.find(Cast<JSGlobalObject>(object));
      if (it != global_object_tag_map_.end()) {
        name = names_->GetFormatted("%s / %s", name, it->second);
      }
    }
    return AddEntry(object, HeapEntry::kObject, name);

  } else if (InstanceTypeChecker::IsString(instance_type)) {
    Tagged<String> string = Cast<String>(object);
    if (IsConsString(string, cage_base)) {
      return AddEntry(object, HeapEntry::kConsString, "(concatenated string)");
    } else if (IsSlicedString(string, cage_base)) {
      return AddEntry(object, HeapEntry::kSlicedString, "(sliced string)");
    } else {
      return AddEntry(object, HeapEntry::kString,
                      names_->GetName(Cast<String>(object)));
    }
  } else if (InstanceTypeChecker::IsSymbol(instance_type)) {
    if (Cast<Symbol>(object)->is_private())
      return AddEntry(object, HeapEntry::kHidden, "private symbol");
    else
      return AddEntry(object, HeapEntry::kSymbol, "symbol");

  } else if (InstanceTypeChecker::IsBigInt(instance_type)) {
    return AddEntry(object, HeapEntry::kBigInt, "bigint");

  } else if (InstanceTypeChecker::IsInstructionStream(instance_type) ||
             InstanceTypeChecker::IsCode(instance_type)) {
    return AddEntry(object, HeapEntry::kCode, "");

  } else if (InstanceTypeChecker::IsSharedFunctionInfo(instance_type)) {
    Tagged<String> name = Cast<SharedFunctionInfo>(object)->Name();
    return AddEntry(object, HeapEntry::kCode, names_->GetName(name));

  } else if (InstanceTypeChecker::IsScript(instance_type)) {
    Tagged<Object> name = Cast<Script>(object)->name();
    return AddEntry(object, HeapEntry::kCode,
                    IsString(name) ? names_->GetName(Cast<String>(name)) : "");

  } else if (InstanceTypeChecker::IsNativeContext(instance_type)) {
    return AddEntry(object, HeapEntry::kHidden, "system / NativeContext");

  } else if (InstanceTypeChecker::IsContext(instance_type)) {
    return AddEntry(object, HeapEntry::kObject, "system / Context");

  } else if (InstanceTypeChecker::IsHeapNumber(instance_type)) {
    return AddEntry(object, HeapEntry::kHeapNumber, "heap number");
  }
#if V8_ENABLE_WEBASSEMBLY
  if (InstanceTypeChecker::IsWasmObject(instance_type)) {
    Tagged<WasmTypeInfo> info = object->map()->wasm_type_info();
    // Getting the trusted data is safe; structs and arrays always have their
    // trusted data defined.
    wasm::NamesProvider* names =
        info->trusted_data(isolate())->native_module()->GetNamesProvider();
    wasm::StringBuilder sb;
    names->PrintTypeName(sb, info->type_index());
    sb << " (wasm)" << '\0';
    const char* name = names_->GetCopy(sb.start());
    return AddEntry(object, HeapEntry::kObject, name);
  }
  if (InstanceTypeChecker::IsWasmNull(instance_type)) {
    // Inlined copies of {GetSystemEntryType}, {GetSystemEntryName}, and
    // {AddEntry}, allowing us to override the size.
    // The actual object's size is fairly large (at the time of this writing,
    // just over 64 KB) and mostly includes a guard region. We report it as
    // much smaller to avoid confusion.
    static constexpr size_t kSize = WasmNull::kHeaderSize;
    return AddEntry(object.address(), HeapEntry::kHidden, "system / WasmNull",
                    kSize);
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (InstanceTypeChecker::IsForeign(instance_type)) {
    Tagged<Foreign> foreign = Cast<Foreign>(object);
    ExternalPointerTag tag = foreign->GetTag();
    if (tag >= kFirstManagedResourceTag && tag < kLastManagedResourceTag) {
      // First handle special cases with more information.
#if V8_ENABLE_WEBASSEMBLY
      if (tag == kWasmNativeModuleTag) {
        wasm::NativeModule* native_module =
            Cast<Managed<wasm::NativeModule>>(foreign)->raw();
        size_t size = native_module->EstimateCurrentMemoryConsumption();
        return AddEntry(object.address(), HeapEntry::kHidden,
                        "system / Managed<wasm::NativeModule>", size);
      }
#endif  // V8_ENABLE_WEBASSEMBLY
#define MANAGED_TAG(name, ...)                                \
  if (tag == name) {                                          \
    static constexpr const char kTagName[] = #name;           \
    if constexpr (!ManagedName<kTagName>::ignore_me) {        \
      return AddEntry(object, HeapEntry::kHidden,             \
                      ManagedName<kTagName>::str_arr.data()); \
    }                                                         \
  }
      PER_ISOLATE_EXTERNAL_POINTER_TAGS(MANAGED_TAG)
#undef MANAGED_TAG
    }
  }

  return AddEntry(object, GetSystemEntryType(object),
                  GetSystemEntryName(object));
}

HeapEntry* V8HeapExplorer::AddEntry(Tagged<HeapObject> object,
                                    HeapEntry::Type type, const char* name) {
  PtrComprCageBase cage_base(isolate());
  return AddEntry(object.address(), type, name, object->Size(cage_base));
}

HeapEntry* V8HeapExplorer::AddEntry(Address address, HeapEntry::Type type,
                                    const char* name, size_t size) {
  if (v8_flags.heap_profiler_show_hidden_objects &&
      type == HeapEntry::kHidden) {
    type = HeapEntry::kNative;
  }
  SnapshotObjectId object_id = heap_object_map_->FindOrAddEntry(
      address, static_cast<unsigned int>(size));
  unsigned trace_node_id = 0;
  if (AllocationTracker* allocation_tracker =
          snapshot_->profiler()->allocation_tracker()) {
    trace_node_id =
        allocation_tracker->address_to_trace()->GetTraceNodeId(address);
  }
  return snapshot_->AddEntry(type, name, object_id, size, trace_node_id);
}

const char* V8HeapExplorer::GetSystemEntryName(Tagged<HeapObject> object) {
  if (IsMap(object)) {
    switch (Cast<Map>(object)->instance_type()) {
#define MAKE_STRING_MAP_CASE(instance_type, size, name, Name) \
  case instance_type:                                         \
    return "system / Map (" #Name ")";
      STRING_TYPE_LIST(MAKE_STRING_MAP_CASE)
#undef MAKE_STRING_MAP_CASE
      default:
        return "system / Map";
    }
  }

  InstanceType type = object->map()->instance_type();

  // Empty string names are special: TagObject can overwrite them, and devtools
  // will report them as "(internal array)".
  if (InstanceTypeChecker::IsFixedArray(type) ||
      InstanceTypeChecker::IsFixedDoubleArray(type) ||
      InstanceTypeChecker::IsByteArray(type)) {
    return "";
  }

  switch (type) {
#define MAKE_TORQUE_CASE(Name, TYPE) \
  case TYPE:                         \
    return "system / " #Name;
    // The following lists include every non-String instance type.
    // This includes a few types that already have non-"system" names assigned
    // by AddEntry, but this is a convenient way to avoid manual upkeep here.
    TORQUE_INSTANCE_CHECKERS_SINGLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_MULTIPLE_FULLY_DEFINED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_SINGLE_ONLY_DECLARED(MAKE_TORQUE_CASE)
    TORQUE_INSTANCE_CHECKERS_MULTIPLE_ONLY_DECLARED(MAKE_TORQUE_CASE)
#undef MAKE_TORQUE_CASE

    // Strings were already handled by AddEntry.
#define MAKE_STRING_CASE(instance_type, size, name, Name) \
  case instance_type:                                     \
    UNREACHABLE();
    STRING_TYPE_LIST(MAKE_STRING_CASE)
#undef MAKE_STRING_CASE
  }
}

HeapEntry::Type V8HeapExplorer::GetSystemEntryType(Tagged<HeapObject> object) {
  InstanceType type = object->map()->instance_type();
  if (InstanceTypeChecker::IsAllocationSite(type) ||
      InstanceTypeChecker::IsArrayBoilerplateDescription(type) ||
      InstanceTypeChecker::IsBytecodeArray(type) ||
      InstanceTypeChecker::IsBytecodeWrapper(type) ||
      InstanceTypeChecker::IsClosureFeedbackCellArray(type) ||
      InstanceTypeChecker::IsCode(type) ||
      InstanceTypeChecker::IsCodeWrapper(type) ||
      InstanceTypeChecker::IsFeedbackCell(type) ||
      InstanceTypeChecker::IsFeedbackMetadata(type) ||
      InstanceTypeChecker::IsFeedbackVector(type) ||
      InstanceTypeChecker::IsInstructionStream(type) ||
      InstanceTypeChecker::IsInterpreterData(type) ||
      InstanceTypeChecker::IsLoadHandler(type) ||
      InstanceTypeChecker::IsObjectBoilerplateDescription(type) ||
      InstanceTypeChecker::IsPreparseData(type) ||
      InstanceTypeChecker::IsRegExpBoilerplateDescription(type) ||
      InstanceTypeChecker::IsScopeInfo(type) ||
      InstanceTypeChecker::IsStoreHandler(type) ||
      InstanceTypeChecker::IsTemplateObjectDescription(type) ||
      InstanceTypeChecker::IsTurbofanType(type) ||
      InstanceTypeChecker::IsUncompiledData(type)) {
    return HeapEntry::kCode;
  }

  // This check must come second, because some subtypes of FixedArray are
  // determined above to represent code content.
  if (InstanceTypeChecker::IsFixedArray(type) ||
      InstanceTypeChecker::IsFixedDoubleArray(type) ||
      InstanceTypeChecker::IsByteArray(type)) {
    return HeapEntry::kArray;
  }

  // Maps in read-only space are for internal V8 data, not user-defined object
  // shapes.
  if ((InstanceTypeChecker::IsMap(type) &&
       !MemoryChunk::FromHeapObject(object)->InReadOnlySpace()) ||
      InstanceTypeChecker::IsDescriptorArray(type) ||
      InstanceTypeChecker::IsTransitionArray(type) ||
      InstanceTypeChecker::IsPrototypeInfo(type) ||
      InstanceTypeChecker::IsEnumCache(type)) {
    return HeapEntry::kObjectShape;
  }

  return HeapEntry::kHidden;
}

void V8HeapExplorer::PopulateLineEnds() {
  std::vector<Handle<Script>> scripts;
  HandleScope scope(isolate());

  {
    Script::Iterator iterator(isolate());
    for (Tagged<Script> script = iterator.Next(); !script.is_null();
         script = iterator.Next()) {
      if (!script->has_line_ends()) {
        scripts.push_back(handle(script, isolate()));
      }
    }
  }

  for (auto& script : scripts) {
    snapshot_->AddScriptLineEnds(script->id(),
                                 Script::GetLineEnds(isolate(), script));
  }
}

uint32_t V8HeapExplorer::EstimateObjectsCount() {
  CombinedHeapObjectIterator it(heap_, HeapObjectIterator::kNoFiltering);
  uint32_t objects_count = 0;
  // Avoid overflowing the objects count. In worst case, we will show the same
  // progress for a longer period of time, but we do not expect to have that
  // many objects.
  while (!it.Next().is_null() &&
         objects_count != std::numeric_limits<uint32_t>::max())
    ++objects_count;
  return objects_count;
}

#ifdef V8_TARGET_BIG_ENDIAN
namespace {
int AdjustEmbedderFieldIndex(Tagged<HeapObject> heap_obj, int field_index) {
  Tagged<Map> map = heap_obj->map();
  if (JSObject::MayHaveEmbedderFields(map)) {
    int emb_start_index = (JSObject::GetEmbedderFieldsStartOffset(map) +
                           EmbedderDataSlot::kTaggedPayloadOffset) /
                          kTaggedSize;
    int emb_field_count = JSObject::GetEmbedderFieldCount(map);
    int emb_end_index = emb_start_index + emb_field_count;
    if (base::IsInRange(field_index, emb_start_index, emb_end_index)) {
      return -EmbedderDataSlot::kTaggedPayloadOffset / kTaggedSize;
    }
  }
  return 0;
}
}  // namespace
#endif  // V8_TARGET_BIG_ENDIAN
class IndexedReferencesExtractor : public ObjectVisitorWithCageBases {
 public:
  IndexedReferencesExtractor(V8HeapExplorer* generator,
                             Tagged<HeapObject> parent_obj, HeapEntry* parent)
      : ObjectVisitorWithCageBases(generator->isolate()),
        generator_(generator),
        parent_obj_(parent_obj),
        parent_start_(parent_obj_->RawMaybeWeakField(0)),
        parent_end_(
            parent_obj_->RawMaybeWeakField(parent_obj_->Size(cage_base()))),
        parent_(parent),
        next_index_(0) {}
  void VisitPointers(Tagged<HeapObject> host, ObjectSlot start,
                     ObjectSlot end) override {
    VisitPointers(host, MaybeObjectSlot(start), MaybeObjectSlot(end));
  }
  void VisitMapPointer(Tagged<HeapObject> object) override {
    VisitSlotImpl(cage_base(), object->map_slot());
  }
  void VisitPointers(Tagged<HeapObject> host, MaybeObjectSlot start,
                     MaybeObjectSlot end) override {
    // [start,end) must be a sub-region of [parent_start_, parent_end), i.e.
    // all the slots must point inside the object.
    CHECK_LE(parent_start_, start);
    CHECK_LE(end, parent_end_);
    for (MaybeObjectSlot slot = start; slot < end; ++slot) {
      VisitSlotImpl(cage_base(), slot);
    }
  }

  void VisitInstructionStreamPointer(Tagged<Code> host,
                                     InstructionStreamSlot slot) override {
    VisitSlotImpl(code_cage_base(), slot);
  }

  void VisitCodeTarget(Tagged<InstructionStream> host,
                       RelocInfo* rinfo) override {
    Tagged<InstructionStream> target =
        InstructionStream::FromTargetAddress(rinfo->target_address());
    VisitHeapObjectImpl(target, -1);
  }

  void VisitEmbeddedPointer(Tagged<InstructionStream> host,
                            RelocInfo* rinfo) override {
    Tagged<HeapObject> object = rinfo->target_object(cage_base());
    Tagged<Code> code = UncheckedCast<Code>(host->raw_code(kAcquireLoad));
    if (code->IsWeakObject(object)) {
      generator_->SetWeakReference(parent_, next_index_++, object, {});
    } else {
      VisitHeapObjectImpl(object, -1);
    }
  }

  void VisitIndirectPointer(Tagged<HeapObject> host, IndirectPointerSlot slot,
                            IndirectPointerMode mode) override {
    VisitSlotImpl(generator_->isolate(), slot);
  }

  void VisitProtectedPointer(Tagged<TrustedObject> host,
                             ProtectedPointerSlot slot) override {
    // TODO(saelo): the cage base doesn't currently matter as it isn't used,
    // but technically we should either use the trusted cage base here or
    // remove the cage_base parameter.
    const PtrComprCageBase unused_cage_base(kNullAddress);
    VisitSlotImpl(unused_cage_base, slot);
  }

  void VisitJSDispatchTableEntry(Tagged<HeapObject> host,
                                 JSDispatchHandle handle) override {
#ifdef V8_ENABLE_LEAPTIERING
    // TODO(saelo): implement proper support for these fields here, similar to
    // how we handle indirect pointer or protected pointer fields.
    // Currently we only expect to see FeedbackCells or JSFunctions here.
    if (IsJSFunction(host)) {
      int field_index = JSFunction::kDispatchHandleOffset / kTaggedSize;
      CHECK(generator_->visited_fields_[field_index]);
      generator_->visited_fields_[field_index] = false;
    } else if (IsFeedbackCell(host)) {
      // Nothing to do: the Code object is tracked as part of the JSFunction.
    } else {
      UNREACHABLE();
    }
#endif  // V8_ENABLE_LEAPTIERING
  }

 private:
  template <typename TIsolateOrCageBase, typename TSlot>
  V8_INLINE void VisitSlotImpl(TIsolateOrCageBase isolate_or_cage_base,
                               TSlot slot) {
    int field_index =
        static_cast<int>(slot.address() - parent_start_.address()) /
        TSlot::kSlotDataSize;
#ifdef V8_TARGET_BIG_ENDIAN
    field_index += AdjustEmbedderFieldIndex(parent_obj_, field_index);
#endif
    DCHECK_GE(field_index, 0);
    if (generator_->visited_fields_[field_index]) {
      generator_->visited_fields_[field_index] = false;
    } else {
      Tagged<HeapObject> heap_object;
      auto loaded_value = slot.load(isolate_or_cage_base);
      if (loaded_value.GetHeapObjectIfStrong(&heap_object)) {
        VisitHeapObjectImpl(heap_object, field_index);
      } else if (loaded_value.GetHeapObjectIfWeak(&heap_object)) {
        generator_->SetWeakReference(parent_, next_index_++, heap_object, {});
      }
    }
  }

  V8_INLINE void VisitHeapObjectImpl(Tagged<HeapObject> heap_object,
                                     int field_index) {
    DCHECK_LE(-1, field_index);
    // The last parameter {field_offset} is only used to check some well-known
    // skipped references, so passing -1 * kTaggedSize for objects embedded
    // into code is fine.
    generator_->SetHiddenReference(parent_obj_, parent_, next_index_++,
                                   heap_object, field_index * kTaggedSize);
  }

  V8HeapExplorer* generator_;
  Tagged<HeapObject> parent_obj_;
  MaybeObjectSlot parent_start_;
  MaybeObjectSlot parent_end_;
  HeapEntry* parent_;
  int next_index_;
};

void V8HeapExplorer::ExtractReferences(HeapEntry* entry,
                                       Tagged<HeapObject> obj) {
  if (IsJSGlobalProxy(obj)) {
    ExtractJSGlobalProxyReferences(entry, Cast<JSGlobalProxy>(obj));
  } else if (IsJSArrayBuffer(obj)) {
    ExtractJSArrayBufferReferences(entry, Cast<JSArrayBuffer>(obj));
  } else if (IsJSObject(obj)) {
    if (IsJSWeakSet(obj)) {
      ExtractJSWeakCollectionReferences(entry, Cast<JSWeakSet>(obj));
    } else if (IsJSWeakMap(obj)) {
      ExtractJSWeakCollectionReferences(entry, Cast<JSWeakMap>(obj));
    } else if (IsJSSet(obj)) {
      ExtractJSCollectionReferences(entry, Cast<JSSet>(obj));
    } else if (IsJSMap(obj)) {
      ExtractJSCollectionReferences(entry, Cast<JSMap>(obj));
    } else if (IsJSPromise(obj)) {
      ExtractJSPromiseReferences(entry, Cast<JSPromise>(obj));
    } else if (IsJSGeneratorObject(obj)) {
      ExtractJSGeneratorObjectReferences(entry, Cast<JSGeneratorObject>(obj));
    } else if (IsJSWeakRef(obj)) {
      ExtractJSWeakRefReferences(entry, Cast<JSWeakRef>(obj));
#if V8_ENABLE_WEBASSEMBLY
    } else if (IsWasmInstanceObject(obj)) {
      ExtractWasmInstanceObjectReferences(Cast<WasmInstanceObject>(obj), entry);
    } else if (IsWasmModuleObject(obj)) {
      ExtractWasmModuleObjectReferences(Cast<WasmModuleObject>(obj), entry);
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    ExtractJSObjectReferences(entry, Cast<JSObject>(obj));
  } else if (IsString(obj)) {
    ExtractStringReferences(entry, Cast<String>(obj));
  } else if (IsSymbol(obj)) {
    ExtractSymbolReferences(entry, Cast<Symbol>(obj));
  } else if (IsMap(obj)) {
    ExtractMapReferences(entry, Cast<Map>(obj));
  } else if (IsSharedFunctionInfo(obj)) {
    ExtractSharedFunctionInfoReferences(entry, Cast<SharedFunctionInfo>(obj));
  } else if (IsScript(obj)) {
    ExtractScriptReferences(entry, Cast<Script>(obj));
  } else if (IsAccessorInfo(obj)) {
    ExtractAccessorInfoReferences(entry, Cast<AccessorInfo>(obj));
  } else if (IsAccessorPair(obj)) {
    ExtractAccessorPairReferences(entry, Cast<AccessorPair>(obj));
  } else if (IsCode(obj)) {
    ExtractCodeReferences(entry, Cast<Code>(obj));
  } else if (IsInstructionStream(obj)) {
    ExtractInstructionStreamReferences(entry, Cast<InstructionStream>(obj));
  } else if (IsCell(obj)) {
    ExtractCellReferences(entry, Cast<Cell>(obj));
  } else if (IsFeedbackCell(obj)) {
    ExtractFeedbackCellReferences(entry, Cast<FeedbackCell>(obj));
  } else if (IsPropertyCell(obj)) {
    ExtractPropertyCellReferences(entry, Cast<PropertyCell>(obj));
  } else if (IsPrototypeInfo(obj)) {
    ExtractPrototypeInfoReferences(entry, Cast<PrototypeInfo>(obj));
  } else if (IsAllocationSite(obj)) {
    ExtractAllocationSiteReferences(entry, Cast<AllocationSite>(obj));
  } else if (IsArrayBoilerplateDescription(obj)) {
    ExtractArrayBoilerplateDescriptionReferences(
        entry, Cast<ArrayBoilerplateDescription>(obj));
  } else if (IsRegExpBoilerplateDescription(obj)) {
    ExtractRegExpBoilerplateDescriptionReferences(
        entry, Cast<RegExpBoilerplateDescription>(obj));
  } else if (IsFeedbackVector(obj)) {
    ExtractFeedbackVectorReferences(entry, Cast<FeedbackVector>(obj));
  } else if (IsDescriptorArray(obj)) {
    ExtractDescriptorArrayReferences(entry, Cast<DescriptorArray>(obj));
  } else if (IsEnumCache(obj)) {
    ExtractEnumCacheReferences(entry, Cast<EnumCache>(obj));
  } else if (IsTransitionArray(obj)) {
    ExtractTransitionArrayReferences(entry, Cast<TransitionArray>(obj));
  } else if (IsWeakFixedArray(obj)) {
    ExtractWeakArrayReferences(OFFSET_OF_DATA_START(WeakFixedArray), entry,
                               Cast<WeakFixedArray>(obj));
  } else if (IsWeakArrayList(obj)) {
    ExtractWeakArrayReferences(WeakArrayList::kHeaderSize, entry,
                               Cast<WeakArrayList>(obj));
  } else if (IsContext(obj)) {
    ExtractContextReferences(entry, Cast<Context>(obj));
  } else if (IsEphemeronHashTable(obj)) {
    ExtractEphemeronHashTableReferences(entry, Cast<EphemeronHashTable>(obj));
  } else if (IsFixedArray(obj)) {
    ExtractFixedArrayReferences(entry, Cast<FixedArray>(obj));
  } else if (IsWeakCell(obj)) {
    ExtractWeakCellReferences(entry, Cast<WeakCell>(obj));
  } else if (IsHeapNumber(obj)) {
    if (snapshot_->capture_numeric_value()) {
      ExtractNumberReference(entry, obj);
    }
  } else if (IsBytecodeArray(obj)) {
    ExtractBytecodeArrayReferences(entry, Cast<BytecodeArray>(obj));
  } else if (IsScopeInfo(obj)) {
    ExtractScopeInfoReferences(entry, Cast<ScopeInfo>(obj));
#if V8_ENABLE_WEBASSEMBLY
  } else if (IsWasmStruct(obj)) {
    ExtractWasmStructReferences(Cast<WasmStruct>(obj), entry);
  } else if (IsWasmArray(obj)) {
    ExtractWasmArrayReferences(Cast<WasmArray>(obj), entry);
  } else if (IsWasmTrustedInstanceData(obj)) {
    ExtractWasmTrustedInstanceDataReferences(Cast<WasmTrustedInstanceData>(obj),
                                             entry);
#endif  // V8_ENABLE_WEBASSEMBLY
  }
}

void V8HeapExplorer::ExtractJSGlobalProxyReferences(
    HeapEntry* entry, Tagged<JSGlobalProxy> proxy) {}

void V8HeapExplorer::ExtractJSObjectReferences(HeapEntry* entry,
                                               Tagged<JSObject> js_obj) {
  Tagged<HeapObject> obj = js_obj;
  ExtractPropertyReferences(js_obj, entry);
  ExtractElementReferences(js_obj, entry);
  ExtractInternalReferences(js_obj, entry);
  Isolate* isolate = Isolate::FromHeap(heap_);
  PrototypeIterator iter(isolate, js_obj);
  ReadOnlyRoots roots(isolate);
  SetPropertyReference(entry, roots.proto_string(), iter.GetCurrent());
  if (IsJSBoundFunction(obj)) {
    Tagged<JSBoundFunction> js_fun = Cast<JSBoundFunction>(obj);
    TagObject(js_fun->bound_arguments(), "(bound arguments)");
    SetInternalReference(entry, "bindings", js_fun->bound_arguments(),
                         JSBoundFunction::kBoundArgumentsOffset);
    SetInternalReference(entry, "bound_this", js_fun->bound_this(),
                         JSBoundFunction::kBoundThisOffset);
    SetInternalReference(entry, "bound_function",
                         js_fun->bound_target_function(),
                         JSBoundFunction::kBoundTargetFunctionOffset);
    Tagged<FixedArray> bindings = js_fun->bound_arguments();
    for (int i = 0; i < bindings->length(); i++) {
      const char* reference_name = names_->GetFormatted("bound_argument_%d", i);
      SetNativeBindReference(entry, reference_name, bindings->get(i));
    }
  } else if (IsJSFunction(obj)) {
    Tagged<JSFunction> js_fun = Cast<JSFunction>(js_obj);
    if (js_fun->has_prototype_slot()) {
      Tagged<Object> proto_or_map =
          js_fun->prototype_or_initial_map(kAcquireLoad);
      if (!IsTheHole(proto_or_map, isolate)) {
        if (!IsMap(proto_or_map)) {
          SetPropertyReference(entry, roots.prototype_string(), proto_or_map,
                               nullptr,
                               JSFunction::kPrototypeOrInitialMapOffset);
        } else {
          SetPropertyReference(entry, roots.prototype_string(),
                               js_fun->prototype());
          SetInternalReference(entry, "initial_map", proto_or_map,
                               JSFunction::kPrototypeOrInitialMapOffset);
        }
      }
    }
    Tagged<SharedFunctionInfo> shared_info = js_fun->shared();
    TagObject(js_fun->raw_feedback_cell(), "(function feedback cell)");
    SetInternalReference(entry, "feedback_cell", js_fun->raw_feedback_cell(),
                         JSFunction::kFeedbackCellOffset);
    TagObject(shared_info, "(shared function info)");
    SetInternalReference(entry, "shared", shared_info,
                         JSFunction::kSharedFunctionInfoOffset);
    TagObject(js_fun->context(), "(context)");
    SetInternalReference(entry, "context", js_fun->context(),
                         JSFunction::kContextOffset);
#ifdef V8_ENABLE_LEAPTIERING
    SetInternalReference(entry, "code", js_fun->code(isolate),
                         JSFunction::kDispatchHandleOffset);
#else
    SetInternalReference(entry, "code", js_fun->code(isolate),
                         JSFunction::kCodeOffset);
#endif  // V8_ENABLE_LEAPTIERING
  } else if (IsJSGlobalObject(obj)) {
    Tagged<JSGlobalObject> global_obj = Cast<JSGlobalObject>(obj);
    SetInternalReference(entry, "global_proxy", global_obj->global_proxy(),
                         JSGlobalObject::kGlobalProxyOffset);
  } else if (IsJSArrayBufferView(obj)) {
    Tagged<JSArrayBufferView> view = Cast<JSArrayBufferView>(obj);
    SetInternalReference(entry, "buffer", view->buffer(),
                         JSArrayBufferView::kBufferOffset);
  }

  TagObject(js_obj->raw_properties_or_hash(), "(object properties)");
  SetInternalReference(entry, "properties", js_obj->raw_properties_or_hash(),
                       JSObject::kPropertiesOrHashOffset);

  TagObject(js_obj->elements(), "(object elements)");
  SetInternalReference(entry, "elements", js_obj->elements(),
                       JSObject::kElementsOffset);
}

void V8HeapExplorer::ExtractStringReferences(HeapEntry* entry,
                                             Tagged<String> string) {
  if (IsConsString(string)) {
    Tagged<ConsString> cs = Cast<ConsString>(string);
    SetInternalReference(entry, "first", cs->first(),
                         offsetof(ConsString, first_));
    SetInternalReference(entry, "second", cs->second(),
                         offsetof(ConsString, second_));
  } else if (IsSlicedString(string)) {
    Tagged<SlicedString> ss = Cast<SlicedString>(string);
    SetInternalReference(entry, "parent", ss->parent(),
                         offsetof(SlicedString, parent_));
  } else if (IsThinString(string)) {
    Tagged<ThinString> ts = Cast<ThinString>(string);
    SetInternalReference(entry, "actual", ts->actual(),
                         offsetof(ThinString, actual_));
  }
}

void V8HeapExplorer::ExtractSymbolReferences(HeapEntry* entry,
                                             Tagged<Symbol> symbol) {
  SetInternalReference(entry, "name", symbol->description(),
                       offsetof(Symbol, description_));
}

void V8HeapExplorer::ExtractJSCollectionReferences(
    HeapEntry* entry, Tagged<JSCollection> collection) {
  SetInternalReference(entry, "table", collection->table(),
                       JSCollection::kTableOffset);
}

void V8HeapExplorer::ExtractJSWeakCollectionReferences(
    HeapEntry* entry, Tagged<JSWeakCollection> obj) {
  SetInternalReference(entry, "table", obj->table(),
                       JSWeakCollection::kTableOffset);
}

void V8HeapExplorer::ExtractEphemeronHashTableReferences(
    HeapEntry* entry, Tagged<EphemeronHashTable> table) {
  for (InternalIndex i : table->IterateEntries()) {
    int key_index = EphemeronHashTable::EntryToIndex(i) +
                    EphemeronHashTable::kEntryKeyIndex;
    int value_index = EphemeronHashTable::EntryToValueIndex(i);
    Tagged<Object> key = table->get(key_index);
    Tagged<Object> value = table->get(value_index);
    SetWeakReference(entry, key_index, key,
                     table->OffsetOfElementAt(key_index));
    SetWeakReference(entry, value_index, value,
                     table->OffsetOfElementAt(value_index));
    HeapEntry* key_entry = GetEntry(key);
    HeapEntry* value_entry = GetEntry(value);
    HeapEntry* table_entry = GetEntry(table);
    if (key_entry && value_entry && !IsUndefined(key)) {
      const char* edge_name = names_->GetFormatted(
          "part of key (%s @%u) -> value (%s @%u) pair in WeakMap (table @%u)",
          key_entry->name(), key_entry->id(), value_entry->name(),
          value_entry->id(), table_entry->id());
      key_entry->SetNamedAutoIndexReference(HeapGraphEdge::kInternal, edge_name,
                                            value_entry, names_, generator_,
                                            HeapEntry::kEphemeron);
      table_entry->SetNamedAutoIndexReference(
          HeapGraphEdge::kInternal, edge_name, value_entry, names_, generator_,
          HeapEntry::kEphemeron);
    }
  }
}

// These static arrays are used to prevent excessive code-size in
// ExtractContextReferences below, which would happen if we called
// SetInternalReference for every native context field in a macro.
static const struct {
  int index;
  const char* name;
} native_context_names[] = {
#define CONTEXT_FIELD_INDEX_NAME(index, _, name) {Context::index, #name},
    NATIVE_CONTEXT_FIELDS(CONTEXT_FIELD_INDEX_NAME)
#undef CONTEXT_FIELD_INDEX_NAME
};

void V8HeapExplorer::ExtractContextReferences(HeapEntry* entry,
                                              Tagged<Context> context) {
  DisallowGarbageCollection no_gc;
  if (!IsNativeContext(context) && context->is_declaration_context()) {
    Tagged<ScopeInfo> scope_info = context->scope_info();
    // Add context allocated locals.
    for (auto it : ScopeInfo::IterateLocalNames(scope_info, no_gc)) 
"""


```
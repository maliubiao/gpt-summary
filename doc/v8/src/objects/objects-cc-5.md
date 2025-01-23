Response:
My thought process to analyze the provided C++ code snippet and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the provided C++ code, which is a part of the V8 JavaScript engine, specifically from the `v8/src/objects/objects.cc` file. The request also asks for specific connections to JavaScript, Torque if applicable, code logic analysis, common errors, and a summary.

2. **Initial Scan and Keyword Identification:** I'll quickly scan the code for recognizable keywords and patterns related to JavaScript and V8 internals. I see terms like `String`, `Script`, `JSArray`, `JSProxy`, `JSPromise`, `Isolate`, `Handle`, `Factory`, `Object`, `SharedFunctionInfo`, `SourcePosition`, `LineEnds`, `Promise`, `status`, `Fulfill`, `Reject`, `Resolve`, etc. These immediately tell me the code deals with core JavaScript concepts and V8's object representation.

3. **Section-wise Analysis:**  I'll break down the code snippet into logical blocks based on the class or functionality being implemented.

    * **Oddball Initialization:** The first function `Initialize` clearly sets up internal properties of "oddball" objects (like `null`, `undefined`, `true`, `false`). The code sets their string representation, type, and numeric value if applicable.

    * **Script Handling:**  The next set of functions deals with the `Script` object. I see functions to get the evaluation position, calculate line endings, set the source code, and retrieve position information (line and column) from a given code offset. The `GetScriptHash` function calculates a SHA-256 hash of the script's source. `FindSharedFunctionInfo` seems to link a `FunctionLiteral` to its compiled representation. The `Iterator` class allows iterating through all loaded scripts.

    * **JSArray Manipulation:**  The `JSArray` functions focus on initializing arrays with a specific capacity and length, and importantly, setting the array's `length` property. The `SetLengthWouldNormalize` function hints at the internal representation of arrays and potential transitions between "fast" and "slow" modes. `HasReadOnlyLength` and `WouldChangeReadOnlyLength` deal with the mutability of the `length` property.

    * **JSProxy Handling:**  The `JSProxy::SetPrototype` function implements the behavior of setting the prototype of a proxy, respecting the proxy's traps (like `setPrototypeOf`).

    * **Allocation Site Tracking:** The `AllocationSite` functions are related to memory management and object allocation within V8. They track where objects are allocated and whether they should be placed in old or young generation heaps.

    * **Symbol Handling:** The `Symbol::PrivateSymbolToName` function provides a way to get a string representation of internal (private) symbols used by V8.

    * **JSPromise Implementation:** This is a significant portion of the code. The `JSPromise` functions implement the core logic of JavaScript Promises, including getting and setting the promise state (`status`), fulfilling promises (`Fulfill`), rejecting promises (`Reject`), and resolving promises (`Resolve`). The `TriggerPromiseReactions` function handles the execution of `then` and `catch` callbacks.

4. **Connect to JavaScript:**  As I analyze each section, I'll try to link the C++ code to corresponding JavaScript features.

    * Oddballs:  Directly map to `null`, `undefined`, `true`, `false`.
    * Scripts: Represent JavaScript code loaded and executed. Line endings are crucial for error reporting and debugging.
    * Arrays:  The C++ code manages the internal storage and length of JavaScript arrays.
    * Proxies: The C++ code implements the low-level mechanisms of JavaScript proxies and their handlers.
    * Promises:  The `JSPromise` section is a direct implementation of the JavaScript `Promise` API.

5. **Torque Consideration:** The prompt mentions `.tq` files and Torque. I'll note that this specific `.cc` file doesn't seem to be generated from Torque, as there's no obvious Torque syntax.

6. **Code Logic and Examples:** For interesting logic (like `Script::GetEvalPosition`, `Script::GetPositionInfo`, `JSArray::SetLength`, `JSPromise::Resolve`), I'll try to create hypothetical inputs and outputs or explain the core algorithm.

7. **Common Errors:** I'll consider common JavaScript errors that relate to the functionality in the C++ code. For example, trying to set the length of an array to an invalid value, or errors related to promise resolution and rejection.

8. **Summarization:** Finally, I'll synthesize the findings into a concise summary of the file's purpose.

9. **Structure and Refinement:** I'll organize the information clearly, using headings and bullet points, and refine the language to be understandable to someone familiar with JavaScript but possibly not with V8 internals. I will make sure to address all parts of the user's prompt.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and informative response that addresses the user's request. The key is to break down the complex code into manageable parts and connect it back to familiar JavaScript concepts.
```cpp
lizeUtf8String(to_string);
  DirectHandle<String> internalized_type_of =
      isolate->factory()->InternalizeUtf8String(type_of);
  if (IsHeapNumber(*to_number)) {
    oddball->set_to_number_raw_as_bits(
        Cast<HeapNumber>(to_number)->value_as_bits());
  } else {
    oddball->set_to_number_raw(Object::NumberValue(*to_number));
  }
  oddball->set_to_number(*to_number);
  oddball->set_to_string(*internalized_to_string);
  oddball->set_type_of(*internalized_type_of);
  oddball->set_kind(kind);
}

// static
int Script::GetEvalPosition(Isolate* isolate, DirectHandle<Script> script) {
  DCHECK(script->compilation_type() == Script::CompilationType::kEval);
  int position = script->eval_from_position();
  if (position < 0) {
    // Due to laziness, the position may not have been translated from code
    // offset yet, which would be encoded as negative integer. In that case,
    // translate and set the position.
    if (!script->has_eval_from_shared()) {
      position = 0;
    } else {
      Handle<SharedFunctionInfo> shared =
          handle(script->eval_from_shared(), isolate);
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared);
      position =
          shared->abstract_code(isolate)->SourcePosition(isolate, -position);
    }
    DCHECK_GE(position, 0);
    script->set_eval_from_position(position);
  }
  return position;
}

String::LineEndsVector Script::GetLineEnds(Isolate* isolate,
                                           DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  Tagged<Object> src_obj = script->source();
  if (IsString(src_obj)) {
    Handle<String> src(Cast<String>(src_obj), isolate);
    return String::CalculateLineEndsVector(isolate, src, true);
  }

  return String::LineEndsVector();
}

template <typename IsolateT>
// static
void Script::InitLineEndsInternal(IsolateT* isolate,
                                  DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  DCHECK(script->CanHaveLineEnds());
  Tagged<Object> src_obj = script->source();
  if (!IsString(src_obj)) {
    DCHECK(IsUndefined(src_obj, isolate));
    script->set_line_ends(ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    DCHECK(IsString(src_obj));
    Handle<String> src(Cast<String>(src_obj), isolate);
    DirectHandle<FixedArray> array =
        String::CalculateLineEnds(isolate, src, true);
    script->set_line_ends(*array);
  }
  DCHECK(IsFixedArray(script->line_ends()));
  DCHECK(script->has_line_ends());
}

void Script::SetSource(Isolate* isolate, DirectHandle<Script> script,
                       DirectHandle<String> source) {
  script->set_source(*source);
  if (isolate->NeedsSourcePositions()) {
    InitLineEnds(isolate, script);
  } else if (script->line_ends() ==
             ReadOnlyRoots(isolate).empty_fixed_array()) {
    DCHECK(script->has_line_ends());
    script->set_line_ends(Smi::zero());
    DCHECK(!script->has_line_ends());
  }
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(Isolate* isolate,
                                                         DirectHandle<Script>
                                                             script);
template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(LocalIsolate* isolate,
                                                         DirectHandle<Script>
                                                             script);

bool Script::GetPositionInfo(DirectHandle<Script> script, int position,
                             PositionInfo* info, OffsetFlag offset_flag) {
#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we do not create an artificial line_ends array, but do the
  // translation directly.
#ifdef DEBUG
  if (script->type() == Type::kWasm) {
    DCHECK(script->has_line_ends());
    DCHECK_EQ(Cast<FixedArray>(script->line_ends())->length(), 0);
  }
#endif  // DEBUG
#endif  // V8_ENABLE_WEBASSEMBLY
  InitLineEnds(script->GetIsolate(), script);
  return script->GetPositionInfo(position, info, offset_flag);
}

bool Script::IsSubjectToDebugging() const {
  switch (type()) {
    case Type::kNormal:
#if V8_ENABLE_WEBASSEMBLY
    case Type::kWasm:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;
    case Type::kNative:
    case Type::kInspector:
    case Type::kExtension:
      return false;
  }
  UNREACHABLE();
}

bool Script::IsUserJavaScript() const {
  return type() == Script::Type::kNormal;
}

#if V8_ENABLE_WEBASSEMBLY
bool Script::ContainsAsmModule() {
  DisallowGarbageCollection no_gc;
  SharedFunctionInfo::ScriptIterator iter(this->GetIsolate(), *this);
  for (Tagged<SharedFunctionInfo> sfi = iter.Next(); !sfi.is_null();
       sfi = iter.Next()) {
    if (sfi->HasAsmWasmData()) return true;
  }
  return false;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

template <typename Char>
bool GetPositionInfoSlowImpl(base::Vector<Char> source, int position,
                             Script::PositionInfo* info) {
  DCHECK(DisallowPositionInfoSlow::IsAllowed());
  if (position < 0) {
    position = 0;
  }
  int line = 0;
  const auto begin = std::cbegin(source);
  const auto end = std::cend(source);
  for (auto line_begin = begin; line_begin < end;) {
    const auto line_end = std::find(line_begin, end, '\n');
    if (position <= (line_end - begin)) {
      info->line = line;
      info->column = static_cast<int>((begin + position) - line_begin);
      info->line_start = static_cast<int>(line_begin - begin);
      info->line_end = static_cast<int>(line_end - begin);
      return true;
    }
    ++line;
    line_begin = line_end + 1;
  }
  return false;
}
bool GetPositionInfoSlow(const Tagged<Script> script, int position,
                         const DisallowGarbageCollection& no_gc,
                         Script::PositionInfo* info) {
  if (!IsString(script->source())) {
    return false;
  }
  auto source = Cast<String>(script->source());
  const auto flat = source->GetFlatContent(no_gc);
  return flat.IsOneByte()
             ? GetPositionInfoSlowImpl(flat.ToOneByteVector(), position, info)
             : GetPositionInfoSlowImpl(flat.ToUC16Vector(), position, info);
}

int GetLineEnd(const String::LineEndsVector& vector, int line) {
  return vector[line];
}

int GetLineEnd(const Tagged<FixedArray>& array, int line) {
  return Smi::ToInt(array->get(line));
}

int GetLength(const String::LineEndsVector& vector) {
  return static_cast<int>(vector.size());
}

int GetLength(const Tagged<FixedArray>& array) { return array->length(); }

template <typename LineEndsContainer>
bool GetLineEndsContainerPositionInfo(const LineEndsContainer& ends,
                                      int position, Script::PositionInfo* info,
                                      const DisallowGarbageCollection& no_gc) {
  const int ends_len = GetLength(ends);
  if (ends_len == 0) return false;

  // Return early on invalid positions. Negative positions behave as if 0 was
  // passed, and positions beyond the end of the script return as failure.
  if (position < 0) {
    position = 0;
  } else if (position > GetLineEnd(ends, ends_len - 1)) {
    return false;
  }

  // Determine line number by doing a binary search on the line ends array.
  if (GetLineEnd(ends, 0) >= position) {
    info->line = 0;
    info->line_start = 0;
    info->column = position;
  } else {
    int left = 0;
    int right = ends_len - 1;

    while (right > 0) {
      DCHECK_LE(left, right);
      const int mid = left + (right - left) / 2;
      if (position > GetLineEnd(ends, mid)) {
        left = mid + 1;
      } else if (position <= GetLineEnd(ends, mid - 1)) {
        right = mid - 1;
      } else {
        info->line = mid;
        break;
      }
    }
    DCHECK(GetLineEnd(ends, info->line) >= position &&
           GetLineEnd(ends, info->line - 1) < position);
    info->line_start = GetLineEnd(ends, info->line - 1) + 1;
    info->column = position - info->line_start;
  }

  return true;
}

}  // namespace

void Script::AddPositionInfoOffset(PositionInfo* info,
                                   OffsetFlag offset_flag) const {
  // Add offsets if requested.
  if (offset_flag == OffsetFlag::kWithOffset) {
    if (info->line == 0) {
      info->column += column_offset();
    }
    info->line += line_offset();
  } else {
    DCHECK_EQ(offset_flag, OffsetFlag::kNoOffset);
  }
}

template <typename LineEndsContainer>
bool Script::GetPositionInfoInternal(
    const LineEndsContainer& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const {
  if (!GetLineEndsContainerPositionInfo(ends, position, info, no_gc))
    return false;

  // Line end is position of the linebreak character.
  info->line_end = GetLineEnd(ends, info->line);
  if (info->line_end > 0) {
    DCHECK(IsString(source()));
    Tagged<String> src = Cast<String>(source());
    if (src->length() >= static_cast<uint32_t>(info->line_end) &&
        src->Get(info->line_end - 1) == '\r') {
      info->line_end--;
    }
  }

  return true;
}

template bool Script::GetPositionInfoInternal<String::LineEndsVector>(
    const String::LineEndsVector& ends, int position,
    Script::PositionInfo* info, const DisallowGarbageCollection& no_gc) const;
template bool Script::GetPositionInfoInternal<Tagged<FixedArray>>(
    const Tagged<FixedArray>& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const;

bool Script::GetPositionInfo(int position, PositionInfo* info,
                             OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;

#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we use the byte offset as the column.
  if (type() == Script::Type::kWasm) {
    DCHECK_LE(0, position);
    wasm::NativeModule* native_module = wasm_native_module();
    const wasm::WasmModule* module = native_module->module();
    if (module->functions.empty()) return false;
    info->line = 0;
    info->column = position;
    info->line_start = module->functions[0].code.offset();
    info->line_end = module->functions.back().code.end_offset();
    return true;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (!has_line_ends()) {
    // Slow mode: we do not have line_ends. We have to iterate through source.
    if (!GetPositionInfoSlow(*this, position, no_gc, info)) {
      return false;
    }
  } else {
    DCHECK(has_line_ends());
    Tagged<FixedArray> ends = Cast<FixedArray>(line_ends());

    if (!GetPositionInfoInternal(ends, position, info, no_gc)) return false;
  }

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetPositionInfoWithLineEnds(
    int position, PositionInfo* info, const String::LineEndsVector& line_ends,
    OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;
  if (!GetPositionInfoInternal(line_ends, position, info, no_gc)) return false;

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetLineColumnWithLineEnds(
    int position, int& line, int& column,
    const String::LineEndsVector& line_ends) {
  DisallowGarbageCollection no_gc;
  PositionInfo info;
  if (!GetLineEndsContainerPositionInfo(line_ends, position, &info, no_gc)) {
    line = -1;
    column = -1;
    return false;
  }

  line = info.line;
  column = info.column;

  return true;
}

int Script::GetColumnNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.column;
}

int Script::GetColumnNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.column;
}

int Script::GetLineNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.line;
}

int Script::GetLineNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.line;
}

Tagged<Object> Script::GetNameOrSourceURL() {
  // Keep in sync with ScriptNameOrSourceURL in messages.js.
  if (!IsUndefined(source_url())) return source_url();
  return name();
}

// static
Handle<String> Script::GetScriptHash(Isolate* isolate,
                                     DirectHandle<Script> script,
                                     bool forceForInspector) {
  if (script->origin_options().IsOpaque() && !forceForInspector) {
    return isolate->factory()->empty_string();
  }

  PtrComprCageBase cage_base(isolate);
  {
    Tagged<Object> maybe_source_hash = script->source_hash(cage_base);
    if (IsString(maybe_source_hash, cage_base)) {
      Handle<String> precomputed(Cast<String>(maybe_source_hash), isolate);
      if (precomputed->length() > 0) {
        return precomputed;
      }
    }
  }

  DirectHandle<String> src_text;
  {
    Tagged<Object> maybe_script_source = script->source(cage_base);

    if (!IsString(maybe_script_source, cage_base)) {
      return isolate->factory()->empty_string();
    }
    src_text = direct_handle(Cast<String>(maybe_script_source), isolate);
  }

  char formatted_hash[kSizeOfFormattedSha256Digest];

  std::unique_ptr<char[]> string_val = src_text->ToCString();
  size_t len = strlen(string_val.get());
  uint8_t hash[kSizeOfSha256Digest];
  SHA256_hash(string_val.get(), len, hash);
  FormatBytesToHex(formatted_hash, kSizeOfFormattedSha256Digest, hash,
                   kSizeOfSha256Digest);
  formatted_hash[kSizeOfSha256Digest * 2] = '\0';

  Handle<String> result =
      isolate->factory()->NewStringFromAsciiChecked(formatted_hash);
  script->set_source_hash(*result);
  return result;
}

template <typename IsolateT>
MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, IsolateT* isolate,
    FunctionLiteral* function_literal) {
  DCHECK(function_literal->shared_function_info().is_null());
  int function_literal_id = function_literal->function_literal_id();
  CHECK_NE(function_literal_id, kInvalidInfoId);
  // If this check fails, the problem is most probably the function id
  // renumbering done by AstFunctionLiteralIdReindexer; in particular, that
  // AstTraversalVisitor doesn't recurse properly in the construct which
  // triggers the mismatch.
  CHECK_LT(function_literal_id, script->infos()->length());
  Tagged<MaybeObject> shared = script->infos()->get(function_literal_id);
  Tagged<HeapObject> heap_object;
  if (!shared.GetHeapObject(&heap_object) ||
      IsUndefined(heap_object, isolate)) {
    return MaybeHandle<SharedFunctionInfo>();
  }
  Handle<SharedFunctionInfo> result(Cast<SharedFunctionInfo>(heap_object),
                                    isolate);
  function_literal->set_shared_function_info(result);
  return result;
}
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, Isolate* isolate,
    FunctionLiteral* function_literal);
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, LocalIsolate* isolate,
    FunctionLiteral* function_literal);

Script::Iterator::Iterator(Isolate* isolate)
    : iterator_(isolate->heap()->script_list()) {}

Tagged<Script> Script::Iterator::Next() {
  Tagged<Object> o = iterator_.Next();
  if (o != Tagged<Object>()) {
    return Cast<Script>(o);
  }
  return Script();
}

// static
void JSArray::Initialize(DirectHandle<JSArray> array, int capacity,
                         int length) {
  DCHECK_GE(capacity, 0);
  array->GetIsolate()->factory()->NewJSArrayStorage(
      array, length, capacity,
      ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
}

Maybe<bool> JSArray::SetLength(Handle<JSArray> array, uint32_t new_length) {
  if (array->SetLengthWouldNormalize(new_length)) {
    JSObject::NormalizeElements(array);
  }
  return array->GetElementsAccessor()->SetLength(array, new_length);
}

// ES6: 9.5.2 [[SetPrototypeOf]] (V)
// static
Maybe<bool> JSProxy::SetPrototype(Isolate* isolate, DirectHandle<JSProxy> proxy,
                                  Handle<Object> value, bool from_javascript,
                                  ShouldThrow should_throw) {
  STACK_CHECK(isolate, Nothing<bool>());
  Handle<Name> trap_name = isolate->factory()->setPrototypeOf_string();
  // 1. Assert: Either Type(V) is Object or Type(V) is Null.
  DCHECK(IsJSReceiver(*value) || IsNull(*value, isolate));
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "getPrototypeOf").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then return target.[[SetPrototypeOf]]().
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::SetPrototype(isolate, target, value, from_javascript,
                                    should_throw);
  }
  // 8. Let booleanTrapResult be ToBoolean(? Call(trap, handler, «target, V»)).
  Handle<Object> argv[] = {target, value};
  Handle<Object> trap_result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(argv), argv),
      Nothing<bool>());
  bool bool_trap_result = Object::BooleanValue(*trap_result, isolate);
  // 9. If booleanTrapResult is false, return false.
  if (!bool_trap_result) {
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 10. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> is_extensible = JSReceiver::IsExtensible(isolate, target);
  if (is_extensible.IsNothing()) return Nothing<bool>();
  // 11. If extensibleTarget is true, return true.
  if (is_extensible.FromJust()) {
    if (bool_trap_result) return Just(true);
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 12. Let targetProto be ? target.[[GetPrototypeOf]]().
  Handle<Object> target_proto;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_proto,
                                   JSReceiver::GetPrototype(isolate, target),
                                   Nothing<bool>());
  // 13. If SameValue(V, targetProto) is false, throw a TypeError exception.
  if (bool_trap_result && !Object::SameValue(*value, *target_proto)) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxySetPrototypeOfNonExtensible));
    return Nothing<bool>();
  }
  // 14. Return true.
  return Just(true);
}

bool JSArray::SetLengthWouldNormalize(uint32_t new_length) {
  if (!HasFastElements()) return false;
  uint32_t capacity = static_cast<uint32_t>(elements()->length());
  uint32_t new_capacity;
  return JSArray::SetLengthWouldNormalize(GetHeap(), new_length) &&
         ShouldConvertToSlowElements(*this, capacity, new_length - 1,
                                     &new_capacity);
}

void AllocationSite::ResetPretenureDecision() {
  set_pretenure_decision(kUndecided);
  set_memento_found_count(0);
  set_memento_create_count(0);
}

AllocationType AllocationSite::GetAllocationType() const {
  PretenureDecision mode = pretenure_decision();
  // Zombie objects "decide" to be untenured.
  return mode == kTenure ? AllocationType::kOld : AllocationType::kYoung;
}

bool AllocationSite::IsNested() {
  DCHECK(v8_flags.trace_track_allocation_sites);
  Tagged<Object> current = boilerplate()->GetHeap()->allocation_sites_list();
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> current_site = Cast<AllocationSite>(current);
    if (current_site->nested_site() == *this) {
      return true;
    }
    current = current_site->weak_next();
  }
  return false;
}

bool AllocationSite::ShouldTrack(ElementsKind from, ElementsKind to) {
  if (!V8_ALLOCATION_SITE_TRACKING_BOOL) return false;
  return IsMoreGeneralElementsKindTransition(from, to);
}

const char* AllocationSite::PretenureDecisionName(PretenureDecision decision) {
  switch (decision) {
    case kUndecided:
      return "undecided";
    case kDontTenure:
      return "don't tenure";
    case kMaybeTenure:
      return "maybe tenure";
    case kTenure:
      return "tenure";
    case kZombie:
      return "zombie";
    default:
      UNREACHABLE();
  }
}

// static
bool JSArray::MayHaveReadOnlyLength(Tagged<Map> js_array_map) {
  DCHECK(IsJSArrayMap(js_array_map));
  if (js_array_map->is_dictionary_map()) return true;

  // Fast path: "length" is the first fast property of arrays with non
  // dictionary properties. Since it's not configurable, it's guaranteed to be
  // the first in the descriptor array.
  InternalIndex first(0);
  DCHECK(js_array_map->instance_descriptors()->GetKey(first) ==
         js_array_map->GetReadOnlyRoots().length_string());
  return js_array_map->instance_descriptors()->GetDetails(first).IsReadOnly();
}

bool JSArray::HasReadOnlyLength(Handle<JSArray> array) {
  Tagged<Map> map = array->map();

  // If map guarantees that there can't be a read-only length, we are done.
  if (!MayHaveReadOnlyLength(map)) return false;

  // Look at the object.
  Isolate* isolate = array->GetIsolate();
  LookupIterator it(isolate, array, isolate->factory()->length_string(), array,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_EQ(LookupIterator::ACCESSOR, it.state());
  return it.IsReadOnly();
}

bool JSArray::WouldChangeReadOnlyLength(Handle<JSArray> array, uint32_t index) {
  uint32_t length = 0;
  CHECK(Object::ToArrayLength(array->length(), &length));
  if (length <= index) return HasReadOnlyLength(array);
  return false;
}

const char* Symbol::PrivateSymbolToName() const {
  ReadOnlyRoots roots = GetReadOnlyRoots();
#define SYMBOL_CHECK_AND_PRINT(_, name) \
  if (this == roots.name()) return #name;
  PRIVATE_SYMBOL_LIST_GENERATOR(SYMBOL_CHECK_AND_PRINT, /* not used */)
#undef SYMBOL_CHECK_AND_PRINT
  return "UNKNOWN";
}

v8::Promise::PromiseState JSPromise::status() const {
  int value = flags() & StatusBits::kMask;
  DCHECK(value == 0 || value == 1 || value == 2);
  return static_cast<v8::Promise::PromiseState>(value);
}

void JSPromise::set_status(Promise::PromiseState status) {
  int value = flags() & ~StatusBits::kMask;
  set_flags(value | status);
}

// static
const char* JSPromise::Status(v8::Promise::PromiseState status) {
  switch (status) {
    case v8::Promise::kFulfilled:
      return "fulfilled";
    case v8::Promise::kPending:
      return "pending";
    case v8::Promise::kRejected:
      return "rejected";
  }
  UNREACHABLE();
}

// static
Handle<Object> JSPromise::Fulfill(DirectHandle<JSPromise> promise,
                                  DirectHandle<Object> value) {
  Isolate* const isolate = promise->GetIsolate();

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  if (isolate->HasContextPromiseHooks()) {
    isolate->raw_native_context()->RunPromiseHook(
        PromiseHookType::kResolve, indirect_handle(promise, isolate),
        isolate->factory()->undefined_value());
  }
#endif

  // 1. Assert: The value of promise.[[PromiseState]] is "pending".
  CHECK_EQ(Promise::kPending, promise->status());

  // 2. Let reactions be promise.[[PromiseFulfillReactions]].
  DirectHandle<Object> reactions(promise->reactions(), isolate);


### 提示词
```
这是目录为v8/src/objects/objects.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/objects.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
lizeUtf8String(to_string);
  DirectHandle<String> internalized_type_of =
      isolate->factory()->InternalizeUtf8String(type_of);
  if (IsHeapNumber(*to_number)) {
    oddball->set_to_number_raw_as_bits(
        Cast<HeapNumber>(to_number)->value_as_bits());
  } else {
    oddball->set_to_number_raw(Object::NumberValue(*to_number));
  }
  oddball->set_to_number(*to_number);
  oddball->set_to_string(*internalized_to_string);
  oddball->set_type_of(*internalized_type_of);
  oddball->set_kind(kind);
}

// static
int Script::GetEvalPosition(Isolate* isolate, DirectHandle<Script> script) {
  DCHECK(script->compilation_type() == Script::CompilationType::kEval);
  int position = script->eval_from_position();
  if (position < 0) {
    // Due to laziness, the position may not have been translated from code
    // offset yet, which would be encoded as negative integer. In that case,
    // translate and set the position.
    if (!script->has_eval_from_shared()) {
      position = 0;
    } else {
      Handle<SharedFunctionInfo> shared =
          handle(script->eval_from_shared(), isolate);
      SharedFunctionInfo::EnsureSourcePositionsAvailable(isolate, shared);
      position =
          shared->abstract_code(isolate)->SourcePosition(isolate, -position);
    }
    DCHECK_GE(position, 0);
    script->set_eval_from_position(position);
  }
  return position;
}

String::LineEndsVector Script::GetLineEnds(Isolate* isolate,
                                           DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  Tagged<Object> src_obj = script->source();
  if (IsString(src_obj)) {
    Handle<String> src(Cast<String>(src_obj), isolate);
    return String::CalculateLineEndsVector(isolate, src, true);
  }

  return String::LineEndsVector();
}

template <typename IsolateT>
// static
void Script::InitLineEndsInternal(IsolateT* isolate,
                                  DirectHandle<Script> script) {
  DCHECK(!script->has_line_ends());
  DCHECK(script->CanHaveLineEnds());
  Tagged<Object> src_obj = script->source();
  if (!IsString(src_obj)) {
    DCHECK(IsUndefined(src_obj, isolate));
    script->set_line_ends(ReadOnlyRoots(isolate).empty_fixed_array());
  } else {
    DCHECK(IsString(src_obj));
    Handle<String> src(Cast<String>(src_obj), isolate);
    DirectHandle<FixedArray> array =
        String::CalculateLineEnds(isolate, src, true);
    script->set_line_ends(*array);
  }
  DCHECK(IsFixedArray(script->line_ends()));
  DCHECK(script->has_line_ends());
}

void Script::SetSource(Isolate* isolate, DirectHandle<Script> script,
                       DirectHandle<String> source) {
  script->set_source(*source);
  if (isolate->NeedsSourcePositions()) {
    InitLineEnds(isolate, script);
  } else if (script->line_ends() ==
             ReadOnlyRoots(isolate).empty_fixed_array()) {
    DCHECK(script->has_line_ends());
    script->set_line_ends(Smi::zero());
    DCHECK(!script->has_line_ends());
  }
}

template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(Isolate* isolate,
                                                         DirectHandle<Script>
                                                             script);
template EXPORT_TEMPLATE_DEFINE(
    V8_EXPORT_PRIVATE) void Script::InitLineEndsInternal(LocalIsolate* isolate,
                                                         DirectHandle<Script>
                                                             script);

bool Script::GetPositionInfo(DirectHandle<Script> script, int position,
                             PositionInfo* info, OffsetFlag offset_flag) {
#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we do not create an artificial line_ends array, but do the
  // translation directly.
#ifdef DEBUG
  if (script->type() == Type::kWasm) {
    DCHECK(script->has_line_ends());
    DCHECK_EQ(Cast<FixedArray>(script->line_ends())->length(), 0);
  }
#endif  // DEBUG
#endif  // V8_ENABLE_WEBASSEMBLY
  InitLineEnds(script->GetIsolate(), script);
  return script->GetPositionInfo(position, info, offset_flag);
}

bool Script::IsSubjectToDebugging() const {
  switch (type()) {
    case Type::kNormal:
#if V8_ENABLE_WEBASSEMBLY
    case Type::kWasm:
#endif  // V8_ENABLE_WEBASSEMBLY
      return true;
    case Type::kNative:
    case Type::kInspector:
    case Type::kExtension:
      return false;
  }
  UNREACHABLE();
}

bool Script::IsUserJavaScript() const {
  return type() == Script::Type::kNormal;
}

#if V8_ENABLE_WEBASSEMBLY
bool Script::ContainsAsmModule() {
  DisallowGarbageCollection no_gc;
  SharedFunctionInfo::ScriptIterator iter(this->GetIsolate(), *this);
  for (Tagged<SharedFunctionInfo> sfi = iter.Next(); !sfi.is_null();
       sfi = iter.Next()) {
    if (sfi->HasAsmWasmData()) return true;
  }
  return false;
}
#endif  // V8_ENABLE_WEBASSEMBLY

namespace {

template <typename Char>
bool GetPositionInfoSlowImpl(base::Vector<Char> source, int position,
                             Script::PositionInfo* info) {
  DCHECK(DisallowPositionInfoSlow::IsAllowed());
  if (position < 0) {
    position = 0;
  }
  int line = 0;
  const auto begin = std::cbegin(source);
  const auto end = std::cend(source);
  for (auto line_begin = begin; line_begin < end;) {
    const auto line_end = std::find(line_begin, end, '\n');
    if (position <= (line_end - begin)) {
      info->line = line;
      info->column = static_cast<int>((begin + position) - line_begin);
      info->line_start = static_cast<int>(line_begin - begin);
      info->line_end = static_cast<int>(line_end - begin);
      return true;
    }
    ++line;
    line_begin = line_end + 1;
  }
  return false;
}
bool GetPositionInfoSlow(const Tagged<Script> script, int position,
                         const DisallowGarbageCollection& no_gc,
                         Script::PositionInfo* info) {
  if (!IsString(script->source())) {
    return false;
  }
  auto source = Cast<String>(script->source());
  const auto flat = source->GetFlatContent(no_gc);
  return flat.IsOneByte()
             ? GetPositionInfoSlowImpl(flat.ToOneByteVector(), position, info)
             : GetPositionInfoSlowImpl(flat.ToUC16Vector(), position, info);
}

int GetLineEnd(const String::LineEndsVector& vector, int line) {
  return vector[line];
}

int GetLineEnd(const Tagged<FixedArray>& array, int line) {
  return Smi::ToInt(array->get(line));
}

int GetLength(const String::LineEndsVector& vector) {
  return static_cast<int>(vector.size());
}

int GetLength(const Tagged<FixedArray>& array) { return array->length(); }

template <typename LineEndsContainer>
bool GetLineEndsContainerPositionInfo(const LineEndsContainer& ends,
                                      int position, Script::PositionInfo* info,
                                      const DisallowGarbageCollection& no_gc) {
  const int ends_len = GetLength(ends);
  if (ends_len == 0) return false;

  // Return early on invalid positions. Negative positions behave as if 0 was
  // passed, and positions beyond the end of the script return as failure.
  if (position < 0) {
    position = 0;
  } else if (position > GetLineEnd(ends, ends_len - 1)) {
    return false;
  }

  // Determine line number by doing a binary search on the line ends array.
  if (GetLineEnd(ends, 0) >= position) {
    info->line = 0;
    info->line_start = 0;
    info->column = position;
  } else {
    int left = 0;
    int right = ends_len - 1;

    while (right > 0) {
      DCHECK_LE(left, right);
      const int mid = left + (right - left) / 2;
      if (position > GetLineEnd(ends, mid)) {
        left = mid + 1;
      } else if (position <= GetLineEnd(ends, mid - 1)) {
        right = mid - 1;
      } else {
        info->line = mid;
        break;
      }
    }
    DCHECK(GetLineEnd(ends, info->line) >= position &&
           GetLineEnd(ends, info->line - 1) < position);
    info->line_start = GetLineEnd(ends, info->line - 1) + 1;
    info->column = position - info->line_start;
  }

  return true;
}

}  // namespace

void Script::AddPositionInfoOffset(PositionInfo* info,
                                   OffsetFlag offset_flag) const {
  // Add offsets if requested.
  if (offset_flag == OffsetFlag::kWithOffset) {
    if (info->line == 0) {
      info->column += column_offset();
    }
    info->line += line_offset();
  } else {
    DCHECK_EQ(offset_flag, OffsetFlag::kNoOffset);
  }
}

template <typename LineEndsContainer>
bool Script::GetPositionInfoInternal(
    const LineEndsContainer& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const {
  if (!GetLineEndsContainerPositionInfo(ends, position, info, no_gc))
    return false;

  // Line end is position of the linebreak character.
  info->line_end = GetLineEnd(ends, info->line);
  if (info->line_end > 0) {
    DCHECK(IsString(source()));
    Tagged<String> src = Cast<String>(source());
    if (src->length() >= static_cast<uint32_t>(info->line_end) &&
        src->Get(info->line_end - 1) == '\r') {
      info->line_end--;
    }
  }

  return true;
}

template bool Script::GetPositionInfoInternal<String::LineEndsVector>(
    const String::LineEndsVector& ends, int position,
    Script::PositionInfo* info, const DisallowGarbageCollection& no_gc) const;
template bool Script::GetPositionInfoInternal<Tagged<FixedArray>>(
    const Tagged<FixedArray>& ends, int position, Script::PositionInfo* info,
    const DisallowGarbageCollection& no_gc) const;

bool Script::GetPositionInfo(int position, PositionInfo* info,
                             OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;

#if V8_ENABLE_WEBASSEMBLY
  // For wasm, we use the byte offset as the column.
  if (type() == Script::Type::kWasm) {
    DCHECK_LE(0, position);
    wasm::NativeModule* native_module = wasm_native_module();
    const wasm::WasmModule* module = native_module->module();
    if (module->functions.empty()) return false;
    info->line = 0;
    info->column = position;
    info->line_start = module->functions[0].code.offset();
    info->line_end = module->functions.back().code.end_offset();
    return true;
  }
#endif  // V8_ENABLE_WEBASSEMBLY

  if (!has_line_ends()) {
    // Slow mode: we do not have line_ends. We have to iterate through source.
    if (!GetPositionInfoSlow(*this, position, no_gc, info)) {
      return false;
    }
  } else {
    DCHECK(has_line_ends());
    Tagged<FixedArray> ends = Cast<FixedArray>(line_ends());

    if (!GetPositionInfoInternal(ends, position, info, no_gc)) return false;
  }

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetPositionInfoWithLineEnds(
    int position, PositionInfo* info, const String::LineEndsVector& line_ends,
    OffsetFlag offset_flag) const {
  DisallowGarbageCollection no_gc;
  if (!GetPositionInfoInternal(line_ends, position, info, no_gc)) return false;

  AddPositionInfoOffset(info, offset_flag);

  return true;
}

bool Script::GetLineColumnWithLineEnds(
    int position, int& line, int& column,
    const String::LineEndsVector& line_ends) {
  DisallowGarbageCollection no_gc;
  PositionInfo info;
  if (!GetLineEndsContainerPositionInfo(line_ends, position, &info, no_gc)) {
    line = -1;
    column = -1;
    return false;
  }

  line = info.line;
  column = info.column;

  return true;
}

int Script::GetColumnNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.column;
}

int Script::GetColumnNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.column;
}

int Script::GetLineNumber(DirectHandle<Script> script, int code_pos) {
  PositionInfo info;
  GetPositionInfo(script, code_pos, &info);
  return info.line;
}

int Script::GetLineNumber(int code_pos) const {
  PositionInfo info;
  GetPositionInfo(code_pos, &info);
  return info.line;
}

Tagged<Object> Script::GetNameOrSourceURL() {
  // Keep in sync with ScriptNameOrSourceURL in messages.js.
  if (!IsUndefined(source_url())) return source_url();
  return name();
}

// static
Handle<String> Script::GetScriptHash(Isolate* isolate,
                                     DirectHandle<Script> script,
                                     bool forceForInspector) {
  if (script->origin_options().IsOpaque() && !forceForInspector) {
    return isolate->factory()->empty_string();
  }

  PtrComprCageBase cage_base(isolate);
  {
    Tagged<Object> maybe_source_hash = script->source_hash(cage_base);
    if (IsString(maybe_source_hash, cage_base)) {
      Handle<String> precomputed(Cast<String>(maybe_source_hash), isolate);
      if (precomputed->length() > 0) {
        return precomputed;
      }
    }
  }

  DirectHandle<String> src_text;
  {
    Tagged<Object> maybe_script_source = script->source(cage_base);

    if (!IsString(maybe_script_source, cage_base)) {
      return isolate->factory()->empty_string();
    }
    src_text = direct_handle(Cast<String>(maybe_script_source), isolate);
  }

  char formatted_hash[kSizeOfFormattedSha256Digest];

  std::unique_ptr<char[]> string_val = src_text->ToCString();
  size_t len = strlen(string_val.get());
  uint8_t hash[kSizeOfSha256Digest];
  SHA256_hash(string_val.get(), len, hash);
  FormatBytesToHex(formatted_hash, kSizeOfFormattedSha256Digest, hash,
                   kSizeOfSha256Digest);
  formatted_hash[kSizeOfSha256Digest * 2] = '\0';

  Handle<String> result =
      isolate->factory()->NewStringFromAsciiChecked(formatted_hash);
  script->set_source_hash(*result);
  return result;
}

template <typename IsolateT>
MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, IsolateT* isolate,
    FunctionLiteral* function_literal) {
  DCHECK(function_literal->shared_function_info().is_null());
  int function_literal_id = function_literal->function_literal_id();
  CHECK_NE(function_literal_id, kInvalidInfoId);
  // If this check fails, the problem is most probably the function id
  // renumbering done by AstFunctionLiteralIdReindexer; in particular, that
  // AstTraversalVisitor doesn't recurse properly in the construct which
  // triggers the mismatch.
  CHECK_LT(function_literal_id, script->infos()->length());
  Tagged<MaybeObject> shared = script->infos()->get(function_literal_id);
  Tagged<HeapObject> heap_object;
  if (!shared.GetHeapObject(&heap_object) ||
      IsUndefined(heap_object, isolate)) {
    return MaybeHandle<SharedFunctionInfo>();
  }
  Handle<SharedFunctionInfo> result(Cast<SharedFunctionInfo>(heap_object),
                                    isolate);
  function_literal->set_shared_function_info(result);
  return result;
}
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, Isolate* isolate,
    FunctionLiteral* function_literal);
template MaybeHandle<SharedFunctionInfo> Script::FindSharedFunctionInfo(
    DirectHandle<Script> script, LocalIsolate* isolate,
    FunctionLiteral* function_literal);

Script::Iterator::Iterator(Isolate* isolate)
    : iterator_(isolate->heap()->script_list()) {}

Tagged<Script> Script::Iterator::Next() {
  Tagged<Object> o = iterator_.Next();
  if (o != Tagged<Object>()) {
    return Cast<Script>(o);
  }
  return Script();
}

// static
void JSArray::Initialize(DirectHandle<JSArray> array, int capacity,
                         int length) {
  DCHECK_GE(capacity, 0);
  array->GetIsolate()->factory()->NewJSArrayStorage(
      array, length, capacity,
      ArrayStorageAllocationMode::INITIALIZE_ARRAY_ELEMENTS_WITH_HOLE);
}

Maybe<bool> JSArray::SetLength(Handle<JSArray> array, uint32_t new_length) {
  if (array->SetLengthWouldNormalize(new_length)) {
    JSObject::NormalizeElements(array);
  }
  return array->GetElementsAccessor()->SetLength(array, new_length);
}

// ES6: 9.5.2 [[SetPrototypeOf]] (V)
// static
Maybe<bool> JSProxy::SetPrototype(Isolate* isolate, DirectHandle<JSProxy> proxy,
                                  Handle<Object> value, bool from_javascript,
                                  ShouldThrow should_throw) {
  STACK_CHECK(isolate, Nothing<bool>());
  Handle<Name> trap_name = isolate->factory()->setPrototypeOf_string();
  // 1. Assert: Either Type(V) is Object or Type(V) is Null.
  DCHECK(IsJSReceiver(*value) || IsNull(*value, isolate));
  // 2. Let handler be the value of the [[ProxyHandler]] internal slot of O.
  Handle<Object> handler(proxy->handler(), isolate);
  // 3. If handler is null, throw a TypeError exception.
  // 4. Assert: Type(handler) is Object.
  if (proxy->IsRevoked()) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxyRevoked, trap_name));
    return Nothing<bool>();
  }
  // 5. Let target be the value of the [[ProxyTarget]] internal slot.
  Handle<JSReceiver> target(Cast<JSReceiver>(proxy->target()), isolate);
  // 6. Let trap be ? GetMethod(handler, "getPrototypeOf").
  Handle<Object> trap;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap,
      Object::GetMethod(isolate, Cast<JSReceiver>(handler), trap_name),
      Nothing<bool>());
  // 7. If trap is undefined, then return target.[[SetPrototypeOf]]().
  if (IsUndefined(*trap, isolate)) {
    return JSReceiver::SetPrototype(isolate, target, value, from_javascript,
                                    should_throw);
  }
  // 8. Let booleanTrapResult be ToBoolean(? Call(trap, handler, «target, V»)).
  Handle<Object> argv[] = {target, value};
  Handle<Object> trap_result;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(
      isolate, trap_result,
      Execution::Call(isolate, trap, handler, arraysize(argv), argv),
      Nothing<bool>());
  bool bool_trap_result = Object::BooleanValue(*trap_result, isolate);
  // 9. If booleanTrapResult is false, return false.
  if (!bool_trap_result) {
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 10. Let extensibleTarget be ? IsExtensible(target).
  Maybe<bool> is_extensible = JSReceiver::IsExtensible(isolate, target);
  if (is_extensible.IsNothing()) return Nothing<bool>();
  // 11. If extensibleTarget is true, return true.
  if (is_extensible.FromJust()) {
    if (bool_trap_result) return Just(true);
    RETURN_FAILURE(
        isolate, should_throw,
        NewTypeError(MessageTemplate::kProxyTrapReturnedFalsish, trap_name));
  }
  // 12. Let targetProto be ? target.[[GetPrototypeOf]]().
  Handle<Object> target_proto;
  ASSIGN_RETURN_ON_EXCEPTION_VALUE(isolate, target_proto,
                                   JSReceiver::GetPrototype(isolate, target),
                                   Nothing<bool>());
  // 13. If SameValue(V, targetProto) is false, throw a TypeError exception.
  if (bool_trap_result && !Object::SameValue(*value, *target_proto)) {
    isolate->Throw(*isolate->factory()->NewTypeError(
        MessageTemplate::kProxySetPrototypeOfNonExtensible));
    return Nothing<bool>();
  }
  // 14. Return true.
  return Just(true);
}

bool JSArray::SetLengthWouldNormalize(uint32_t new_length) {
  if (!HasFastElements()) return false;
  uint32_t capacity = static_cast<uint32_t>(elements()->length());
  uint32_t new_capacity;
  return JSArray::SetLengthWouldNormalize(GetHeap(), new_length) &&
         ShouldConvertToSlowElements(*this, capacity, new_length - 1,
                                     &new_capacity);
}

void AllocationSite::ResetPretenureDecision() {
  set_pretenure_decision(kUndecided);
  set_memento_found_count(0);
  set_memento_create_count(0);
}

AllocationType AllocationSite::GetAllocationType() const {
  PretenureDecision mode = pretenure_decision();
  // Zombie objects "decide" to be untenured.
  return mode == kTenure ? AllocationType::kOld : AllocationType::kYoung;
}

bool AllocationSite::IsNested() {
  DCHECK(v8_flags.trace_track_allocation_sites);
  Tagged<Object> current = boilerplate()->GetHeap()->allocation_sites_list();
  while (IsAllocationSite(current)) {
    Tagged<AllocationSite> current_site = Cast<AllocationSite>(current);
    if (current_site->nested_site() == *this) {
      return true;
    }
    current = current_site->weak_next();
  }
  return false;
}

bool AllocationSite::ShouldTrack(ElementsKind from, ElementsKind to) {
  if (!V8_ALLOCATION_SITE_TRACKING_BOOL) return false;
  return IsMoreGeneralElementsKindTransition(from, to);
}

const char* AllocationSite::PretenureDecisionName(PretenureDecision decision) {
  switch (decision) {
    case kUndecided:
      return "undecided";
    case kDontTenure:
      return "don't tenure";
    case kMaybeTenure:
      return "maybe tenure";
    case kTenure:
      return "tenure";
    case kZombie:
      return "zombie";
    default:
      UNREACHABLE();
  }
}

// static
bool JSArray::MayHaveReadOnlyLength(Tagged<Map> js_array_map) {
  DCHECK(IsJSArrayMap(js_array_map));
  if (js_array_map->is_dictionary_map()) return true;

  // Fast path: "length" is the first fast property of arrays with non
  // dictionary properties. Since it's not configurable, it's guaranteed to be
  // the first in the descriptor array.
  InternalIndex first(0);
  DCHECK(js_array_map->instance_descriptors()->GetKey(first) ==
         js_array_map->GetReadOnlyRoots().length_string());
  return js_array_map->instance_descriptors()->GetDetails(first).IsReadOnly();
}

bool JSArray::HasReadOnlyLength(Handle<JSArray> array) {
  Tagged<Map> map = array->map();

  // If map guarantees that there can't be a read-only length, we are done.
  if (!MayHaveReadOnlyLength(map)) return false;

  // Look at the object.
  Isolate* isolate = array->GetIsolate();
  LookupIterator it(isolate, array, isolate->factory()->length_string(), array,
                    LookupIterator::OWN_SKIP_INTERCEPTOR);
  CHECK_EQ(LookupIterator::ACCESSOR, it.state());
  return it.IsReadOnly();
}

bool JSArray::WouldChangeReadOnlyLength(Handle<JSArray> array, uint32_t index) {
  uint32_t length = 0;
  CHECK(Object::ToArrayLength(array->length(), &length));
  if (length <= index) return HasReadOnlyLength(array);
  return false;
}

const char* Symbol::PrivateSymbolToName() const {
  ReadOnlyRoots roots = GetReadOnlyRoots();
#define SYMBOL_CHECK_AND_PRINT(_, name) \
  if (this == roots.name()) return #name;
  PRIVATE_SYMBOL_LIST_GENERATOR(SYMBOL_CHECK_AND_PRINT, /* not used */)
#undef SYMBOL_CHECK_AND_PRINT
  return "UNKNOWN";
}

v8::Promise::PromiseState JSPromise::status() const {
  int value = flags() & StatusBits::kMask;
  DCHECK(value == 0 || value == 1 || value == 2);
  return static_cast<v8::Promise::PromiseState>(value);
}

void JSPromise::set_status(Promise::PromiseState status) {
  int value = flags() & ~StatusBits::kMask;
  set_flags(value | status);
}

// static
const char* JSPromise::Status(v8::Promise::PromiseState status) {
  switch (status) {
    case v8::Promise::kFulfilled:
      return "fulfilled";
    case v8::Promise::kPending:
      return "pending";
    case v8::Promise::kRejected:
      return "rejected";
  }
  UNREACHABLE();
}

// static
Handle<Object> JSPromise::Fulfill(DirectHandle<JSPromise> promise,
                                  DirectHandle<Object> value) {
  Isolate* const isolate = promise->GetIsolate();

#ifdef V8_ENABLE_JAVASCRIPT_PROMISE_HOOKS
  if (isolate->HasContextPromiseHooks()) {
    isolate->raw_native_context()->RunPromiseHook(
        PromiseHookType::kResolve, indirect_handle(promise, isolate),
        isolate->factory()->undefined_value());
  }
#endif

  // 1. Assert: The value of promise.[[PromiseState]] is "pending".
  CHECK_EQ(Promise::kPending, promise->status());

  // 2. Let reactions be promise.[[PromiseFulfillReactions]].
  DirectHandle<Object> reactions(promise->reactions(), isolate);

  // 3. Set promise.[[PromiseResult]] to value.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise->set_reactions_or_result(Cast<JSAny>(*value));

  // 6. Set promise.[[PromiseState]] to "fulfilled".
  promise->set_status(Promise::kFulfilled);

  // 7. Return TriggerPromiseReactions(reactions, value).
  return TriggerPromiseReactions(isolate, reactions, value,
                                 PromiseReaction::kFulfill);
}

static void MoveMessageToPromise(Isolate* isolate, Handle<JSPromise> promise) {
  if (!isolate->has_pending_message()) return;

  if (isolate->debug()->is_active()) {
    Handle<Object> message = handle(isolate->pending_message(), isolate);
    Handle<Symbol> key = isolate->factory()->promise_debug_message_symbol();
    Object::SetProperty(isolate, promise, key, message,
                        StoreOrigin::kMaybeKeyed,
                        Just(ShouldThrow::kThrowOnError))
        .Assert();
  }

  // The message object for a rejected promise was only stored for this purpose.
  // Clear it, otherwise we might leak memory.
  isolate->clear_pending_message();
}

// static
Handle<Object> JSPromise::Reject(Handle<JSPromise> promise,
                                 Handle<Object> reason, bool debug_event) {
  Isolate* const isolate = promise->GetIsolate();
  DCHECK(
      !reinterpret_cast<v8::Isolate*>(isolate)->GetCurrentContext().IsEmpty());

  MoveMessageToPromise(isolate, promise);

  if (debug_event) isolate->debug()->OnPromiseReject(promise, reason);
  isolate->RunAllPromiseHooks(PromiseHookType::kResolve, promise,
                              isolate->factory()->undefined_value());

  // 1. Assert: The value of promise.[[PromiseState]] is "pending".
  CHECK_EQ(Promise::kPending, promise->status());

  // 2. Let reactions be promise.[[PromiseRejectReactions]].
  DirectHandle<Object> reactions(promise->reactions(), isolate);

  // 3. Set promise.[[PromiseResult]] to reason.
  // 4. Set promise.[[PromiseFulfillReactions]] to undefined.
  // 5. Set promise.[[PromiseRejectReactions]] to undefined.
  promise->set_reactions_or_result(Cast<JSAny>(*reason));

  // 6. Set promise.[[PromiseState]] to "rejected".
  promise->set_status(Promise::kRejected);

  // 7. If promise.[[PromiseIsHandled]] is false, perform
  //    HostPromiseRejectionTracker(promise, "reject").
  if (!promise->has_handler()) {
    isolate->ReportPromiseReject(promise, reason, kPromiseRejectWithNoHandler);
  }

  // 8. Return TriggerPromiseReactions(reactions, reason).
  return TriggerPromiseReactions(isolate, reactions, reason,
                                 PromiseReaction::kReject);
}

// https://tc39.es/ecma262/#sec-promise-resolve-functions
// static
MaybeHandle<Object> JSPromise::Resolve(Handle<JSPromise> promise,
                                       Handle<Object> resolution_obj) {
  Isolate* const isolate = promise->GetIsolate();
  DCHECK(
      !reinterpret_cast<v8::Isolate*>(isolate)->GetCurrentContext().IsEmpty());

  isolate->RunPromiseHook(PromiseHookType::kResolve, promise,
                          isolate->factory()->undefined_value());

  // 7. If SameValue(resolution, promise) is true, then
  if (promise.is_identical_to(resolution_obj)) {
    // a. Let selfResolutionError be a newly created TypeError object.
    Handle<Object> self_resolution_error = isolate->factory()->NewTypeError(
        MessageTemplate::kPromiseCyclic, resolution_obj);
    // b. Return RejectPromise(promise, selfResolutionError).
    return Reject(promise, self_resolution_error);
  }

  // 8. If Type(resolution) is not Object, then
  Handle<JSReceiver> resolution_recv;
  if (!TryCast<JSReceiver>(resolution_obj, &resolution_recv)) {
    // a. Return FulfillPromise(promise, resolution).
    return Fulfill(promise, resolution_obj);
  }

  // 9. Let then be Get(resolution, "then").
  MaybeHandle<Object> then;

  // Make sure a lookup of "then" on any JSPromise whose [[Prototype]] is the
  // initial %PromisePrototype% yields the initial method. In addition this
  // protector also guards the negative lookup of "then" on the intrinsic
  // %ObjectPrototype%, meaning that such lookups are guaranteed to yield
  // undefined without triggering any side-effects.
  if (IsJSPromise(*resolution_recv) &&
      resolution_recv->map()->prototype()->map()->instance_type() ==
          JS_PROMISE_PROTOTYPE_TYPE &&
      Protectors::IsPromiseThenLookupChainIntact(isolate)) {
    // We can skip the "then" lookup on {resolution} if its [[Prototype]]
    // is the (initial) Promise.prototype and the Promise#then protector
    // is intact, as that guards the lookup path for the "then" property
    // on JSPromise instances which have the (initial) %PromisePrototype%.
    then = isolate->promise_then();
  } else {
    then = JSReceiver::GetProperty(isolate, resolution_recv,
                                   isolate->factory()->then_string());
  }

  // 10. If then is an abrupt completion, then
  Handle<Object> then_action;
  if (!then.ToHandle(&then_action)) {
    // The "then" lookup can cause termination.
    if (!isolate->is_catchable_by_javascript(isolate->exception())) {
      return kNullMaybeHandle;
    }

    // a. Return RejectPromise(promise, then.[[Value]]).
    Handle<Object> reason(isolate->exception(), isolate);
    isolate->clear_exception();
    return Reject(promise, reason, false);
  }

  // 11. Let thenAction be then.[[Value]].
  // 12. If IsCallable(thenAction) is false, then
  if (!IsCallable(*then_action)) {
    // a. Return FulfillPromise(promise, resolution).
    return Fulfill(promise, resolution_recv);
  }

  // 13. Let job be NewPromiseResolveThenableJob(promise, resolution,
  //                                             thenAction).
  Handle<NativeContext> then_context;
  if (!JSReceiver::GetContextForMicrotask(Cast<JSReceiver>(then_action))
           .ToHandle(&then_context)) {
    then_context = isolate->native_context();
  }

  DirectHandle<PromiseResolveThenableJobTask> task =
      isolate->factory()->NewPromiseResolveThenableJobTask(
          promise, resolution_recv, Cast<JSReceiver>(then_action),
          then_context);
  if (isolate->debug()->is_active() && IsJSPromise(*resolution_recv)) {
    // Mark the dependency of the new {promise} on the {resolution}.
    Object::SetProperty(isolate, resolution_recv,
                        isolate->factory()->promise_handled_by_symbol(),
                        promise)
        .Check();
  }
  MicrotaskQueue* microtask_queue = then_context->microtask_queue();
  if (microtask_queue) microtask_queue->EnqueueMicrotask(*task);

  // 15. Return undefined.
  return isolate->factory()->undefined_value();
}

// static
Handle<Object> JSPromise::TriggerPromiseReactions(
    Isolate* isolate, DirectHandle<Object> reactions,
    DirectHandle<Object> argument, PromiseReaction::Type type) {
  CHECK(IsSmi(*reactions) || IsPromiseReaction(*reactions));

  // We need to reverse the {reactions} here, since we record them
  // on the JSPromise in the reverse order.
  {
    DisallowGarbageCollection no_gc;
    Tagged<UnionOf<Smi, PromiseReaction>> current =
        Cast<UnionOf<Smi, PromiseReaction>>(*reactions);
    Tagged<UnionOf<Smi, PromiseReaction>> reversed = Smi::zero();
    while (!IsSmi(current)) {
      Tagged<UnionOf<Smi, PromiseReaction>> next =
          Cast<PromiseReaction>(current)->next();
      Cast<PromiseReaction>(current)->set_next(reversed);
      reversed = current;
      current = next;
    }
    reactions = direct_handle(reversed, isolate);
  }

  // Morph the {reactions} into PromiseReactionJobTasks
  // and push them onto the microtask queue.
  while (!IsSmi(*reactions)) {
    auto task = Cast<HeapObject>(reactions);
    auto reaction = Cast<PromiseReaction>(task);
    reactions = direct_handle(reaction->next(), isolate);

    // According to HTML, we use the context of the appropriate handler as the
    // context of the microtask. See step 3 of HTML's EnqueueJob:
    // https://html.spec.whatwg.org/C/#enqueuejob(queuename,-job,-arguments)
    DirectHandle<NativeContext> handler_context;

    DirectHandle<UnionOf<Undefined, JSCallable>> primary_handler;
    DirectHandle<UnionOf<Undefined, JSCallable>> secondary_handler;
    if (type == PromiseReaction::kFulfill) {
      primary_handler = direct_handle(reaction->fulfill_handler(), isolate);
      secondary_handler = direct_handle(reaction->reject_handler(), isolate);
    } else {
      primary_handler = direct_handle(reaction->reject_handler(), isolate);
      secondary_handler = direct_handle(reaction->fulfill_handler(), isolate);
    }

    bool has_handler_context = false;
    if (IsJSReceiver(*primary_handler)) {
      has_handler_context =
          JSReceiver::GetContextForMicrotask(Cast<JSReceiver>(primary_handler))
              .ToHandle(&handler_context);
    }
    if (!has_handler_context && IsJSReceiver(*secondary_handler)) {
      has_handler_context = JSReceiver::GetContextForMicrotask(
```
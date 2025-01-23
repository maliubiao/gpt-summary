Response:
Let's break down the thought process for analyzing the provided C++ code and answering the user's request.

**1. Understanding the Request:**

The core request is to understand the functionality of `v8/src/builtins/builtins.cc`. The user also asks about specific scenarios: Torque files, JavaScript relevance, code logic, and common errors.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code for keywords and structural elements that provide clues about its purpose. I'm looking for:

* **File Headers:** Copyright notices, include statements. These often indicate the project and dependencies.
* **Namespaces:** `v8::internal`. This confirms we're inside the V8 engine's internal workings.
* **`BUILTIN_LIST`:** This macro stands out. It suggests this file is central to defining and managing built-in functions.
* **`Builtin_` prefixes:** These likely represent the actual C++ implementations of built-ins.
* **Data structures:** `BuiltinMetadata`, `KindSpecificData`. These suggest a structured way of storing information about built-ins.
* **Functions:**  `Lookup`, `GetContinuationBytecodeOffset`, `CallInterfaceDescriptorFor`, `CallableFor`, `name`, `KindOf`, etc. These indicate the operations this file enables.
* **Conditional compilation:** `#if V8_ENABLE_WEBASSEMBLY`, `#ifdef ENABLE_DISASSEMBLER`. These point to features that might be optionally included.

**3. Deconstructing the `BUILTIN_LIST`:**

This is crucial. The macros used within `BUILTIN_LIST` (like `DECL_CPP`, `DECL_TSJ`, `DECL_TFJ`, etc.) reveal the *types* of built-ins and their associated data. I'd make a mental or written note of these:

* `DECL_CPP`:  Likely C++ implemented built-ins.
* `DECL_TSJ`, `DECL_TFJ`:  Probably related to Torque/TurboFan, suggesting optimized or generated code.
* `DECL_BCH`:  Likely bytecode handlers for the interpreter.

**4. Analyzing the `BuiltinMetadata` Structure:**

This structure confirms the different types of built-ins and the data associated with each:

* `name`:  The human-readable name of the built-in.
* `kind`:  The type of built-in (CPP, TSJ, TFJ, etc.).
* `data`: A union holding type-specific information (function pointers, parameter counts, bytecode info).

**5. Identifying Key Functionalities:**

Based on the spotted keywords and data structures, I start forming a list of functionalities:

* **Registration of Built-ins:** The `BUILTIN_LIST` and `builtin_metadata` are the core of this.
* **Lookup of Built-ins:** The `Lookup` function suggests finding built-ins by address.
* **Accessing Built-in Information:** Functions like `name`, `KindOf`, `GetStackParameterCount`, `CallInterfaceDescriptorFor` provide metadata about built-ins.
* **Code Management:**  `code`, `code_handle`, `set_code` indicate managing the actual executable code for built-ins.
* **Bytecode Handling:** The `BCH` kind and functions like `GetContinuationBytecodeOffset` relate to the interpreter.
* **Stack Traces:**  `NameForStackTrace` suggests how built-ins are represented in error messages.
* **Code Dumping/Disassembly:** `PrintBuiltinCode`, `PrintBuiltinSize`.
* **Isolate Initialization:** `InitializeIsolateDataTables`, `EmitCodeCreateEvents`.
* **Security:** `AllowDynamicFunction`.

**6. Addressing the Specific Questions:**

* **Functionality:**  The list of functionalities derived in step 5 answers this directly.
* **Torque:**  The presence of `DECL_TSJ`, `DECL_TFJ` and the mention of Torque function pointers strongly suggests that if the file ended in `.tq`, it would be a Torque source file. The code *mentions* Torque but isn't a Torque file itself.
* **JavaScript Relevance:**  This is a key area. I need to connect the C++ built-ins to their JavaScript counterparts. I would think about common JavaScript functions that are likely implemented as built-ins for performance reasons (e.g., `Array.prototype.push`, `String.prototype.indexOf`, `Math.sin`). The `NameForStackTrace` function provides explicit examples related to `DataView` and `String`.
* **Code Logic Inference:** Look for functions with clear input/output relationships. `GetStackParameterCount` is a good example: given a `Builtin` enum value, it returns the parameter count. `Lookup` takes an address and returns the built-in name (or null).
* **Common Programming Errors:** Think about how developers might misuse built-in functionality or encounter errors related to them. Examples include calling methods on null/undefined, type errors when using `DataView`, or issues with dynamic code generation.

**7. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Address each part of the user's query.

* Start with a general overview of the file's purpose.
* Explain the different categories of built-ins.
* Provide concrete JavaScript examples where applicable.
* Give simple, illustrative examples for code logic.
* Suggest common programming errors related to built-in functionality.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this file responsible for *implementing* all built-ins?  **Correction:** No, it seems more like a *registry* or *definition* file. The actual implementations are likely in other `.cc` files.
* **Focus on the `BUILTIN_LIST`:**  Realizing the significance of this macro is key to understanding the file's structure and purpose.
* **Connecting C++ to JavaScript:**  Actively think about how these low-level C++ functions relate to the higher-level JavaScript API.

By following this systematic approach, combining code analysis with domain knowledge about JavaScript engines, it's possible to generate a comprehensive and accurate answer to the user's request.
This C++ source code file, `v8/src/builtins/builtins.cc`, plays a crucial role in the V8 JavaScript engine. It serves as a central registry and definition point for built-in functions and bytecode handlers. Think of it as a configuration file that tells V8 about all the pre-defined functionalities it offers.

Here's a breakdown of its functionalities:

**1. Defining and Registering Built-ins:**

* **`BUILTIN_LIST` Macro:** This is the heart of the file. It uses a series of `DECL_...` macros (like `DECL_CPP`, `DECL_TSJ`, `DECL_BCH`) to declare and register different types of built-in functions.
    * **`DECL_CPP`:**  Registers built-ins implemented directly in C++. These are highly optimized, low-level functions.
    * **`DECL_TSJ` and `DECL_TFJ`:** Register built-ins written in Torque (a V8-specific language that compiles to optimized machine code). `TSJ` likely stands for Torque Static JavaScript and `TFJ` for Torque Function JavaScript.
    * **`DECL_BCH`:** Registers bytecode handlers. These are the implementations for individual bytecode instructions used by V8's interpreter.
    * Other `DECL_...` macros likely represent other categories of built-ins or specific compiler pipeline stages.
* **`builtin_metadata` Array:** This array stores metadata about each registered built-in, such as its name, kind (CPP, TSJ, BCH, etc.), and kind-specific data (like the C++ function pointer, parameter count, or bytecode and operand scale).

**2. Providing Information About Built-ins:**

* **`Builtins::name(Builtin builtin)`:**  Returns the symbolic name of a built-in.
* **`Builtins::KindOf(Builtin builtin)`:**  Returns the type or "kind" of a built-in (e.g., CPP, TSJ, BCH).
* **`Builtins::GetStackParameterCount(Builtin builtin)`:** For JavaScript built-ins, returns the expected number of parameters.
* **`Builtins::CallInterfaceDescriptorFor(Builtin builtin)`:**  Provides information about the calling convention of a built-in.
* **`Builtins::CallableFor(Isolate* isolate, Builtin builtin)`:**  Returns a `Callable` object representing the built-in, which encapsulates its code and calling convention.
* **`Builtins::Lookup(Address pc)`:** Given a program counter (memory address), attempts to find the corresponding built-in function.
* **`Builtins::NameForStackTrace(Isolate* isolate, Builtin builtin)`:** Provides a user-friendly name for a built-in when it appears in a stack trace.

**3. Managing Built-in Code:**

* **`Builtins::code(Builtin builtin)` and `Builtins::code_handle(Builtin builtin)`:** Retrieve the compiled `Code` object associated with a built-in. This is the actual machine code that gets executed.
* **`Builtins::set_code(Builtin builtin, Tagged<Code> code)`:**  Sets the compiled `Code` object for a built-in. This is typically done during V8 initialization.
* **`Builtins::PrintBuiltinCode()` and `Builtins::PrintBuiltinSize()`:**  (Conditional compilation) Allow for debugging by printing the disassembled code or size of built-ins.

**4. Integration with the Interpreter and Compiler:**

* **`Builtins::GetContinuationBytecodeOffset(Builtin builtin)` and `Builtins::GetBuiltinFromBytecodeOffset(BytecodeOffset id)`:** These functions relate to how built-in functions are called and managed within the V8 interpreter's bytecode execution.
* **`Builtins::EntrypointTagFor(Builtin builtin)`:**  Specifies the entry point type (e.g., JavaScript, bytecode handler) for a built-in.

**5. Initialization and Teardown:**

* **`Builtins::TearDown()`:**  Handles the cleanup of built-in related resources.
* **`Builtins::InitializeIsolateDataTables(Isolate* isolate)`:**  Initializes data structures related to built-ins when a new V8 isolate is created.
* **`Builtins::EmitCodeCreateEvents(Isolate* isolate)`:** (Conditional compilation)  Logs the creation of built-in code for profiling and debugging purposes.

**If `v8/src/builtins/builtins.cc` ended with `.tq`:**

You are correct. If the file extension was `.tq`, then the file would be a **V8 Torque source code file**. Torque is V8's domain-specific language for writing built-in functions in a more structured and type-safe way than raw assembly or C++. Torque code is then compiled into optimized machine code that gets used by V8. The current file, being `.cc`, is the C++ file that *registers* and *manages* these Torque-compiled built-ins (among others).

**Relationship with JavaScript and Examples:**

This file has a direct and fundamental relationship with JavaScript. The built-in functions defined and registered here are the underlying implementations of many core JavaScript features.

**JavaScript Examples:**

Let's illustrate with some examples:

* **`Array.prototype.push()`:**  The C++ built-in corresponding to this might be registered using `DECL_CPP` with a name like `ArrayPrototypePush`. When you call `[1, 2, 3].push(4)`, V8 will eventually execute the C++ code associated with this built-in for efficient array manipulation.

```javascript
const arr = [1, 2, 3];
arr.push(4); // Internally calls a C++ built-in
console.log(arr); // Output: [1, 2, 3, 4]
```

* **`String.prototype.indexOf()`:**  Similarly, the `indexOf` method on strings is likely implemented as a C++ built-in for performance.

```javascript
const str = "hello world";
const index = str.indexOf("world"); // Internally calls a C++ built-in
console.log(index); // Output: 6
```

* **`Math.sin()`:** The trigonometric functions in the `Math` object are also implemented as optimized C++ built-ins.

```javascript
const result = Math.sin(Math.PI / 2); // Internally calls a C++ built-in
console.log(result); // Output: 1
```

* **Bytecode Handlers:** When the V8 interpreter executes JavaScript code, it translates it into bytecode. For a simple addition like `a + b`, there will be a corresponding bytecode instruction (e.g., `Add`). The `builtins.cc` file registers a bytecode handler (using `DECL_BCH`) that contains the actual C++ code to perform the addition.

```javascript
function add(a, b) {
  return a + b; // This '+' operation will be handled by a bytecode handler
}
console.log(add(5, 3)); // Output: 8
```

**Code Logic Inference (Hypothetical Example):**

Let's imagine a simplified built-in called `StringLength` that calculates the length of a string.

**Assumption:**  The `builtins.cc` file contains the following registration:

```c++
// ... within the BUILTIN_LIST macro ...
DECL_CPP(StringLength, 1) // Name: StringLength, Argc: 1 (takes one argument - the string)
// ...
```

And somewhere else in the V8 codebase (not necessarily in this file), there's a C++ function like:

```c++
Address Builtin_StringLength(int argc, Address* args, Isolate* isolate) {
  // Argument checking (simplified)
  if (argc != 1) {
    // Throw an error
  }
  Tagged<String> str = reinterpret_cast<Tagged<String>>(args[0]);
  int length = str->length();
  // ... return the length as a JavaScript number ...
}
```

**Hypothetical Input and Output:**

* **Input (from JavaScript):** `getStringLength("example")`
* **V8's Internal Processing:** V8 identifies `getStringLength` as a built-in, looks up its corresponding C++ function (`Builtin_StringLength`), and calls it with the string "example" as an argument.
* **Output (from the C++ function):** The integer `7` (the length of "example").
* **Output (back to JavaScript):** `7`

**Common Programming Errors (Related to Built-ins):**

While you don't directly *write* or modify the code in `builtins.cc` as a JavaScript developer, understanding its role helps explain the behavior and error messages you might encounter:

1. **Calling Methods on `null` or `undefined`:** Many built-in methods (like those on `String` or `Array`) are implemented as built-ins. If you try to call them on `null` or `undefined`, you'll get a `TypeError` because these built-ins expect a valid object instance.

   ```javascript
   let str = null;
   // str.indexOf("a"); // TypeError: Cannot read properties of null (reading 'indexOf')
   ```

2. **Incorrect Number of Arguments:** Some built-ins have a specific number of arguments they expect. While JavaScript often handles missing arguments with `undefined`, some built-ins might throw errors or behave unexpectedly if the argument count is wrong. This is less common in user-facing JavaScript but more relevant in the internal workings of V8.

3. **Type Mismatches:** Built-ins often expect arguments of specific types. Passing the wrong type can lead to `TypeError` or unexpected behavior.

   ```javascript
   // Math.sin("hello"); // This might not throw an error directly, but the result would be NaN
   ```

4. **Security Vulnerabilities (Indirectly):** Bugs in the implementation of built-ins (the C++ code behind them) can potentially introduce security vulnerabilities. This is why the V8 team invests heavily in testing and security audits.

In summary, `v8/src/builtins/builtins.cc` is a foundational file in V8. It's the table of contents for V8's pre-defined functionalities, connecting the high-level JavaScript API with optimized, low-level implementations. Understanding its purpose is key to comprehending how V8 efficiently executes JavaScript code.

### 提示词
```
这是目录为v8/src/builtins/builtins.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins.h"

#include "src/api/api-inl.h"
#include "src/builtins/builtins-descriptors.h"
#include "src/builtins/builtins-inl.h"
#include "src/builtins/data-view-ops.h"
#include "src/codegen/assembler-inl.h"
#include "src/codegen/callable.h"
#include "src/codegen/macro-assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/diagnostics/code-tracer.h"
#include "src/execution/isolate.h"
#include "src/interpreter/bytecodes.h"
#include "src/logging/code-events.h"  // For CodeCreateEvent.
#include "src/logging/log.h"          // For V8FileLogger.
#include "src/objects/fixed-array.h"
#include "src/objects/objects-inl.h"
#include "src/objects/visitors.h"
#include "src/snapshot/embedded/embedded-data-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// Forward declarations for C++ builtins.
#define FORWARD_DECLARE(Name, Argc) \
  Address Builtin_##Name(int argc, Address* args, Isolate* isolate);
BUILTIN_LIST_C(FORWARD_DECLARE)
#undef FORWARD_DECLARE

namespace {

// TODO(jgruber): Pack in CallDescriptors::Key.
struct BuiltinMetadata {
  const char* name;
  Builtins::Kind kind;

  struct BytecodeAndScale {
    interpreter::Bytecode bytecode : 8;
    interpreter::OperandScale scale : 8;
  };

  static_assert(sizeof(interpreter::Bytecode) == 1);
  static_assert(sizeof(interpreter::OperandScale) == 1);
  static_assert(sizeof(BytecodeAndScale) <= sizeof(Address));

  // The `data` field has kind-specific contents.
  union KindSpecificData {
    // TODO(jgruber): Union constructors are needed since C++11 does not support
    // designated initializers (e.g.: {.parameter_count = count}). Update once
    // we're at C++20 :)
    // The constructors are marked constexpr to avoid the need for a static
    // initializer for builtins.cc (see check-static-initializers.sh).
    constexpr KindSpecificData() : cpp_entry(kNullAddress) {}
    constexpr KindSpecificData(Address cpp_entry) : cpp_entry(cpp_entry) {}
    constexpr KindSpecificData(int parameter_count,
                               int /* To disambiguate from above */)
        : parameter_count(static_cast<int16_t>(parameter_count)) {}
    constexpr KindSpecificData(interpreter::Bytecode bytecode,
                               interpreter::OperandScale scale)
        : bytecode_and_scale{bytecode, scale} {}
    Address cpp_entry;                    // For CPP builtins.
    int16_t parameter_count;              // For TFJ builtins.
    BytecodeAndScale bytecode_and_scale;  // For BCH builtins.
  } data;
};

#define DECL_CPP(Name, Argc) \
  {#Name, Builtins::CPP, {FUNCTION_ADDR(Builtin_##Name)}},
#define DECL_TSJ(Name, Count, ...) {#Name, Builtins::TSJ, {Count, 0}},
#define DECL_TFJ(Name, Count, ...) {#Name, Builtins::TFJ, {Count, 0}},
#define DECL_TSC(Name, ...) {#Name, Builtins::TSC, {}},
#define DECL_TFC(Name, ...) {#Name, Builtins::TFC, {}},
#define DECL_TFS(Name, ...) {#Name, Builtins::TFS, {}},
#define DECL_TFH(Name, ...) {#Name, Builtins::TFH, {}},
#define DECL_BCH(Name, OperandScale, Bytecode) \
  {#Name, Builtins::BCH, {Bytecode, OperandScale}},
#define DECL_ASM(Name, ...) {#Name, Builtins::ASM, {}},
const BuiltinMetadata builtin_metadata[] = {
    BUILTIN_LIST(DECL_CPP, DECL_TSJ, DECL_TFJ, DECL_TSC, DECL_TFC, DECL_TFS,
                 DECL_TFH, DECL_BCH, DECL_ASM)};
#undef DECL_CPP
#undef DECL_TFJ
#undef DECL_TSC
#undef DECL_TFC
#undef DECL_TFS
#undef DECL_TFH
#undef DECL_BCH
#undef DECL_ASM

}  // namespace

BytecodeOffset Builtins::GetContinuationBytecodeOffset(Builtin builtin) {
  DCHECK(Builtins::KindOf(builtin) == TFJ || Builtins::KindOf(builtin) == TFC ||
         Builtins::KindOf(builtin) == TFS);
  return BytecodeOffset(BytecodeOffset::kFirstBuiltinContinuationId +
                        ToInt(builtin));
}

Builtin Builtins::GetBuiltinFromBytecodeOffset(BytecodeOffset id) {
  Builtin builtin = Builtins::FromInt(
      id.ToInt() - BytecodeOffset::kFirstBuiltinContinuationId);
  DCHECK(Builtins::KindOf(builtin) == TFJ || Builtins::KindOf(builtin) == TFC ||
         Builtins::KindOf(builtin) == TFS);
  return builtin;
}

void Builtins::TearDown() { initialized_ = false; }

const char* Builtins::Lookup(Address pc) {
  // Off-heap pc's can be looked up through binary search.
  Builtin builtin = OffHeapInstructionStream::TryLookupCode(isolate_, pc);
  if (Builtins::IsBuiltinId(builtin)) return name(builtin);

  // May be called during initialization (disassembler).
  if (!initialized_) return nullptr;
  for (Builtin builtin_ix = Builtins::kFirst; builtin_ix <= Builtins::kLast;
       ++builtin_ix) {
    if (code(builtin_ix)->contains(isolate_, pc)) {
      return name(builtin_ix);
    }
  }
  return nullptr;
}

FullObjectSlot Builtins::builtin_slot(Builtin builtin) {
  Address* location = &isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return FullObjectSlot(location);
}

FullObjectSlot Builtins::builtin_tier0_slot(Builtin builtin) {
  DCHECK(IsTier0(builtin));
  Address* location =
      &isolate_->builtin_tier0_table()[Builtins::ToInt(builtin)];
  return FullObjectSlot(location);
}

void Builtins::set_code(Builtin builtin, Tagged<Code> code) {
  DCHECK_EQ(builtin, code->builtin_id());
  DCHECK(Internals::HasHeapObjectTag(code.ptr()));
  // The given builtin may be uninitialized thus we cannot check its type here.
  isolate_->builtin_table()[Builtins::ToInt(builtin)] = code.ptr();
}

Tagged<Code> Builtins::code(Builtin builtin) {
  Address ptr = isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return Cast<Code>(Tagged<Object>(ptr));
}

Handle<Code> Builtins::code_handle(Builtin builtin) {
  Address* location = &isolate_->builtin_table()[Builtins::ToInt(builtin)];
  return Handle<Code>(location);
}

// static
int Builtins::GetStackParameterCount(Builtin builtin) {
  DCHECK(Builtins::KindOf(builtin) == TSJ || Builtins::KindOf(builtin) == TFJ);
  return builtin_metadata[ToInt(builtin)].data.parameter_count;
}

namespace {

void ParameterCountToString(char* buffer, size_t buffer_size,
                            int parameter_count) {
  if (parameter_count == kDontAdaptArgumentsSentinel) {
    snprintf(buffer, buffer_size, "kDontAdaptArgumentsSentinel");
  } else {
    snprintf(buffer, buffer_size, "JSParameterCount(%d)", parameter_count - 1);
  }
}

}  // namespace

// static
bool Builtins::CheckFormalParameterCount(
    Builtin builtin, int function_length,
    int formal_parameter_count_with_receiver) {
  DCHECK_LE(0, function_length);
  if (!Builtins::IsBuiltinId(builtin)) {
    return true;
  }

  Kind kind = KindOf(builtin);
  // TODO(ishell): enable the check for TFJ/TSJ.
  if (kind == CPP) {
    int parameter_count = Builtins::GetFormalParameterCount(builtin);
    if (parameter_count != formal_parameter_count_with_receiver) {
      if ((false)) {
        // Enable this block to print a command line that should fix the
        // mismatch.
        const size_t kBufSize = 32;
        char actual_count[kBufSize];
        char expected_count[kBufSize];
        ParameterCountToString(actual_count, kBufSize, parameter_count);
        ParameterCountToString(expected_count, kBufSize,
                               formal_parameter_count_with_receiver);
        PrintF(
            "\n##### "
            "sed -i -z -r 's/%s\\(%s,[\\\\\\n[:space:]]+%s\\)/%s(%s, %s)/g' "
            "src/builtins/builtins-definitions.h\n",
            KindNameOf(builtin), name(builtin), actual_count,
            KindNameOf(builtin), name(builtin), expected_count);
      }
      return false;
    }
  }
  return true;
}

// static
CallInterfaceDescriptor Builtins::CallInterfaceDescriptorFor(Builtin builtin) {
  CallDescriptors::Key key;
  switch (builtin) {
// This macro is deliberately crafted so as to emit very little code,
// in order to keep binary size of this function under control.
#define CASE_OTHER(Name, ...)                          \
  case Builtin::k##Name: {                             \
    key = Builtin_##Name##_InterfaceDescriptor::key(); \
    break;                                             \
  }
    BUILTIN_LIST(IGNORE_BUILTIN, IGNORE_BUILTIN, IGNORE_BUILTIN, CASE_OTHER,
                 CASE_OTHER, CASE_OTHER, CASE_OTHER, IGNORE_BUILTIN, CASE_OTHER)
#undef CASE_OTHER
    default:
      Builtins::Kind kind = Builtins::KindOf(builtin);
      DCHECK_NE(BCH, kind);
      if (kind == TSJ || kind == TFJ || kind == CPP) {
        return JSTrampolineDescriptor{};
      }
      UNREACHABLE();
  }
  return CallInterfaceDescriptor{key};
}

// static
Callable Builtins::CallableFor(Isolate* isolate, Builtin builtin) {
  Handle<Code> code = isolate->builtins()->code_handle(builtin);
  return Callable{code, CallInterfaceDescriptorFor(builtin)};
}

// static
bool Builtins::HasJSLinkage(Builtin builtin) {
  DCHECK_NE(BCH, Builtins::KindOf(builtin));
  return CallInterfaceDescriptorFor(builtin) == JSTrampolineDescriptor{};
}

// static
const char* Builtins::name(Builtin builtin) {
  int index = ToInt(builtin);
  DCHECK(IsBuiltinId(index));
  return builtin_metadata[index].name;
}

// static
const char* Builtins::NameForStackTrace(Isolate* isolate, Builtin builtin) {
#if V8_ENABLE_WEBASSEMBLY
  // Most builtins are never shown in stack traces. Those that are exposed
  // to JavaScript get their name from the object referring to them. Here
  // we only support a few internal builtins that have special reasons for
  // being shown on stack traces:
  // - builtins that are allowlisted in {StubFrame::Summarize}.
  // - builtins that throw the same error as one of those above, but would
  //   lose information and e.g. print "indexOf" instead of "String.indexOf".
  switch (builtin) {
    case Builtin::kDataViewPrototypeGetBigInt64:
      return "DataView.prototype.getBigInt64";
    case Builtin::kDataViewPrototypeGetBigUint64:
      return "DataView.prototype.getBigUint64";
    case Builtin::kDataViewPrototypeGetFloat16:
      return "DataView.prototype.getFloat16";
    case Builtin::kDataViewPrototypeGetFloat32:
      return "DataView.prototype.getFloat32";
    case Builtin::kDataViewPrototypeGetFloat64:
      return "DataView.prototype.getFloat64";
    case Builtin::kDataViewPrototypeGetInt8:
      return "DataView.prototype.getInt8";
    case Builtin::kDataViewPrototypeGetInt16:
      return "DataView.prototype.getInt16";
    case Builtin::kDataViewPrototypeGetInt32:
      return "DataView.prototype.getInt32";
    case Builtin::kDataViewPrototypeGetUint8:
      return "DataView.prototype.getUint8";
    case Builtin::kDataViewPrototypeGetUint16:
      return "DataView.prototype.getUint16";
    case Builtin::kDataViewPrototypeGetUint32:
      return "DataView.prototype.getUint32";
    case Builtin::kDataViewPrototypeSetBigInt64:
      return "DataView.prototype.setBigInt64";
    case Builtin::kDataViewPrototypeSetBigUint64:
      return "DataView.prototype.setBigUint64";
    case Builtin::kDataViewPrototypeSetFloat16:
      return "DataView.prototype.setFloat16";
    case Builtin::kDataViewPrototypeSetFloat32:
      return "DataView.prototype.setFloat32";
    case Builtin::kDataViewPrototypeSetFloat64:
      return "DataView.prototype.setFloat64";
    case Builtin::kDataViewPrototypeSetInt8:
      return "DataView.prototype.setInt8";
    case Builtin::kDataViewPrototypeSetInt16:
      return "DataView.prototype.setInt16";
    case Builtin::kDataViewPrototypeSetInt32:
      return "DataView.prototype.setInt32";
    case Builtin::kDataViewPrototypeSetUint8:
      return "DataView.prototype.setUint8";
    case Builtin::kDataViewPrototypeSetUint16:
      return "DataView.prototype.setUint16";
    case Builtin::kDataViewPrototypeSetUint32:
      return "DataView.prototype.setUint32";
    case Builtin::kDataViewPrototypeGetByteLength:
      return "get DataView.prototype.byteLength";
    case Builtin::kThrowDataViewDetachedError:
    case Builtin::kThrowDataViewOutOfBounds:
    case Builtin::kThrowDataViewTypeError: {
      DataViewOp op = static_cast<DataViewOp>(isolate->error_message_param());
      return ToString(op);
    }
    case Builtin::kStringPrototypeToLocaleLowerCase:
      return "String.toLocaleLowerCase";
    case Builtin::kStringPrototypeIndexOf:
    case Builtin::kThrowIndexOfCalledOnNull:
      return "String.indexOf";
#if V8_INTL_SUPPORT
    case Builtin::kStringPrototypeToLowerCaseIntl:
#endif
    case Builtin::kThrowToLowerCaseCalledOnNull:
      return "String.toLowerCase";
    case Builtin::kWasmIntToString:
      return "Number.toString";
    default:
      // Callers getting this might well crash, which might be desirable
      // because it's similar to {UNREACHABLE()}, but contrary to that a
      // careful caller can also check the value and use it as an "is a
      // name available for this builtin?" check.
      return nullptr;
  }
#else
  return nullptr;
#endif  // V8_ENABLE_WEBASSEMBLY
}

void Builtins::PrintBuiltinCode() {
  DCHECK(v8_flags.print_builtin_code);
#ifdef ENABLE_DISASSEMBLER
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* builtin_name = name(builtin);
    if (PassesFilter(base::CStrVector(builtin_name),
                     base::CStrVector(v8_flags.print_builtin_code_filter))) {
      CodeTracer::Scope trace_scope(isolate_->GetCodeTracer());
      OFStream os(trace_scope.file());
      Tagged<Code> builtin_code = code(builtin);
      builtin_code->Disassemble(builtin_name, os, isolate_);
      os << "\n";
    }
  }
#endif
}

void Builtins::PrintBuiltinSize() {
  DCHECK(v8_flags.print_builtin_size);
  for (Builtin builtin = Builtins::kFirst; builtin <= Builtins::kLast;
       ++builtin) {
    const char* builtin_name = name(builtin);
    const char* kind = KindNameOf(builtin);
    Tagged<Code> code = Builtins::code(builtin);
    PrintF(stdout, "%s Builtin, %s, %d\n", kind, builtin_name,
           code->instruction_size());
  }
}

// static
Address Builtins::CppEntryOf(Builtin builtin) {
  DCHECK(Builtins::IsCpp(builtin));
  return builtin_metadata[ToInt(builtin)].data.cpp_entry;
}

// static
bool Builtins::IsBuiltin(const Tagged<Code> code) {
  return Builtins::IsBuiltinId(code->builtin_id());
}

bool Builtins::IsBuiltinHandle(Handle<HeapObject> maybe_code,
                               Builtin* builtin) const {
  Address* handle_location = maybe_code.location();
  Address* builtins_table = isolate_->builtin_table();
  if (handle_location < builtins_table) return false;
  Address* builtins_table_end = &builtins_table[Builtins::kBuiltinCount];
  if (handle_location >= builtins_table_end) return false;
  *builtin = FromInt(static_cast<int>(handle_location - builtins_table));
  return true;
}

// static
bool Builtins::IsIsolateIndependentBuiltin(Tagged<Code> code) {
  Builtin builtin = code->builtin_id();
  return Builtins::IsBuiltinId(builtin) &&
         Builtins::IsIsolateIndependent(builtin);
}

// static
void Builtins::InitializeIsolateDataTables(Isolate* isolate) {
  EmbeddedData embedded_data = EmbeddedData::FromBlob(isolate);
  IsolateData* isolate_data = isolate->isolate_data();

  // The entry table.
  for (Builtin i = Builtins::kFirst; i <= Builtins::kLast; ++i) {
    DCHECK(Builtins::IsBuiltinId(isolate->builtins()->code(i)->builtin_id()));
    DCHECK(!isolate->builtins()->code(i)->has_instruction_stream());
    isolate_data->builtin_entry_table()[ToInt(i)] =
        embedded_data.InstructionStartOf(i);
  }

  // T0 tables.
  for (Builtin i = Builtins::kFirst; i <= Builtins::kLastTier0; ++i) {
    const int ii = ToInt(i);
    isolate_data->builtin_tier0_entry_table()[ii] =
        isolate_data->builtin_entry_table()[ii];
    isolate_data->builtin_tier0_table()[ii] = isolate_data->builtin_table()[ii];
  }
}

// static
void Builtins::EmitCodeCreateEvents(Isolate* isolate) {
  if (!isolate->IsLoggingCodeCreation()) return;

  Address* builtins = isolate->builtin_table();
  int i = 0;
  HandleScope scope(isolate);
  for (; i < ToInt(Builtin::kFirstBytecodeHandler); i++) {
    Handle<Code> builtin_code(&builtins[i]);
    Handle<AbstractCode> code = Cast<AbstractCode>(builtin_code);
    PROFILE(isolate, CodeCreateEvent(LogEventListener::CodeTag::kBuiltin, code,
                                     Builtins::name(FromInt(i))));
  }

  static_assert(kLastBytecodeHandlerPlusOne == kBuiltinCount);
  for (; i < kBuiltinCount; i++) {
    Handle<Code> builtin_code(&builtins[i]);
    Handle<AbstractCode> code = Cast<AbstractCode>(builtin_code);
    interpreter::Bytecode bytecode =
        builtin_metadata[i].data.bytecode_and_scale.bytecode;
    interpreter::OperandScale scale =
        builtin_metadata[i].data.bytecode_and_scale.scale;
    PROFILE(isolate,
            CodeCreateEvent(
                LogEventListener::CodeTag::kBytecodeHandler, code,
                interpreter::Bytecodes::ToString(bytecode, scale).c_str()));
  }
}

// static
Handle<Code> Builtins::CreateInterpreterEntryTrampolineForProfiling(
    Isolate* isolate) {
  DCHECK_NOT_NULL(isolate->embedded_blob_code());
  DCHECK_NE(0, isolate->embedded_blob_code_size());

  Tagged<Code> code = isolate->builtins()->code(
      Builtin::kInterpreterEntryTrampolineForProfiling);

  CodeDesc desc;
  desc.buffer = reinterpret_cast<uint8_t*>(code->instruction_start());

  int instruction_size = code->instruction_size();
  desc.buffer_size = instruction_size;
  desc.instr_size = instruction_size;

  // Ensure the code doesn't require creation of metadata, otherwise respective
  // fields of CodeDesc should be initialized.
  DCHECK_EQ(code->safepoint_table_size(), 0);
  DCHECK_EQ(code->handler_table_size(), 0);
  DCHECK_EQ(code->constant_pool_size(), 0);
  // TODO(v8:11036): The following DCHECK currently fails if the mksnapshot is
  // run with enabled code comments, i.e. --interpreted_frames_native_stack is
  // incompatible with --code-comments at mksnapshot-time. If ever needed,
  // implement support.
  DCHECK_EQ(code->code_comments_size(), 0);
  DCHECK_EQ(code->unwinding_info_size(), 0);

  desc.safepoint_table_offset = instruction_size;
  desc.handler_table_offset = instruction_size;
  desc.constant_pool_offset = instruction_size;
  desc.code_comments_offset = instruction_size;
  desc.builtin_jump_table_info_offset = instruction_size;

  CodeDesc::Verify(&desc);

  return Factory::CodeBuilder(isolate, desc, CodeKind::BUILTIN)
      // Mimic the InterpreterEntryTrampoline.
      .set_builtin(Builtin::kInterpreterEntryTrampoline)
      .Build();
}

Builtins::Kind Builtins::KindOf(Builtin builtin) {
  DCHECK(IsBuiltinId(builtin));
  return builtin_metadata[ToInt(builtin)].kind;
}

// static
const char* Builtins::KindNameOf(Builtin builtin) {
  Kind kind = Builtins::KindOf(builtin);
  // clang-format off
  switch (kind) {
    case CPP: return "CPP";
    case TSJ: return "TSJ";
    case TFJ: return "TFJ";
    case TSC: return "TSC";
    case TFC: return "TFC";
    case TFS: return "TFS";
    case TFH: return "TFH";
    case BCH: return "BCH";
    case ASM: return "ASM";
  }
  // clang-format on
  UNREACHABLE();
}

// static
bool Builtins::IsCpp(Builtin builtin) {
  return Builtins::KindOf(builtin) == CPP;
}

// static
CodeEntrypointTag Builtins::EntrypointTagFor(Builtin builtin) {
  if (builtin == Builtin::kNoBuiltinId) {
    // Special case needed for example for tests.
    return kDefaultCodeEntrypointTag;
  }

#if V8_ENABLE_DRUMBRAKE
  if (builtin == Builtin::kGenericJSToWasmInterpreterWrapper) {
    return kJSEntrypointTag;
  } else if (builtin == Builtin::kGenericWasmToJSInterpreterWrapper) {
    return kWasmEntrypointTag;
  }
#endif  // V8_ENABLE_DRUMBRAKE

  Kind kind = Builtins::KindOf(builtin);
  switch (kind) {
    case CPP:
    case TSJ:
    case TFJ:
      return kJSEntrypointTag;
    case BCH:
      return kBytecodeHandlerEntrypointTag;
    case TFC:
    case TSC:
    case TFS:
    case TFH:
    case ASM:
      return CallInterfaceDescriptorFor(builtin).tag();
  }
  UNREACHABLE();
}

// static
bool Builtins::AllowDynamicFunction(Isolate* isolate,
                                    DirectHandle<JSFunction> target,
                                    Handle<JSObject> target_global_proxy) {
  if (v8_flags.allow_unsafe_function_constructor) return true;
  HandleScopeImplementer* impl = isolate->handle_scope_implementer();
  Handle<NativeContext> responsible_context = impl->LastEnteredContext();
  // TODO(verwaest): Remove this.
  if (responsible_context.is_null()) {
    return true;
  }
  if (*responsible_context == target->context()) return true;
  return isolate->MayAccess(responsible_context, target_global_proxy);
}

Builtin ExampleBuiltinForTorqueFunctionPointerType(
    size_t function_pointer_type_id) {
  switch (function_pointer_type_id) {
#define FUNCTION_POINTER_ID_CASE(id, name) \
  case id:                                 \
    return Builtin::k##name;
    TORQUE_FUNCTION_POINTER_TYPE_TO_BUILTIN_MAP(FUNCTION_POINTER_ID_CASE)
#undef FUNCTION_POINTER_ID_CASE
    default:
      UNREACHABLE();
  }
}

}  // namespace internal
}  // namespace v8
```
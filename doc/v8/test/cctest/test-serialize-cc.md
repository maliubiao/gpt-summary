Response:
Let's break down the thought process for analyzing this V8 serialization test file.

**1. Initial Scan and Keyword Recognition:**

* **Filename:** `test-serialize.cc` immediately tells us it's a test file related to serialization.
* **Copyright:** Standard copyright notice, skip for now.
* **Includes:**  A large number of includes from `include/v8-*` and `src/*`. These are strong indicators of the areas being tested. Look for keywords like:
    * `v8-context.h`, `v8-isolate.h`: Context and Isolate management.
    * `v8-snapshot.h`:  Core serialization/deserialization functionality.
    * `src/snapshot/*`:  Internal implementation details of snapshots.
    * `test/cctest/*`:  V8's internal testing framework.
* **Namespaces:** `v8::internal` confirms this is testing V8's internal implementation, not the public API.
* **Struct `StartupBlobs`:** This clearly defines a structure to hold serialized data – startup, read-only, and shared spaces. This is central to the serialization process.
* **Class `TestSerializer`:** Provides helper functions for creating and manipulating isolates, specifically for testing serialization. Key functions like `NewIsolateInitialized`, `NewIsolate`, `NewIsolateFromBlob`, and the internal `NewIsolate` (with `with_serializer`) are important.
* **Function `Serialize`:** This function *is* the core serialization logic being tested. It creates a context, performs GC, and then uses `ReadOnlySerializer`, `SharedHeapSerializer`, and `StartupSerializer` to generate the blobs.
* **Function `Deserialize`:**  The counterpart to `Serialize`, taking the blobs and creating a new isolate.
* **Function `SanityCheck`:** Basic checks to ensure the deserialized isolate is in a reasonable state.
* **`UNINITIALIZED_TEST` macros:**  These are part of the V8 testing framework. Each test function focuses on a specific aspect of serialization. The names are often descriptive (e.g., `StartupSerializerOnce`, `StartupSerializerTwiceRunScript`, `ContextSerializerContext`).

**2. Understanding the Core Functionality (Serialization/Deserialization):**

The core purpose is to test the process of serializing a V8 Isolate (or parts of it, like a Context) and then deserializing it to restore its state. This involves:

* **Serialization:** Converting the internal state of the Isolate (or Context) into a byte stream (the "blobs"). This needs to capture the heap, code, and other relevant data.
* **Deserialization:** Reconstructing the Isolate (or Context) from the serialized blobs. This is crucial for fast startup and for features like code caching.

**3. Analyzing Individual Test Cases:**

Go through each `UNINITIALIZED_TEST` and try to understand its purpose:

* **`StartupSerializerOnce`:**  Basic serialization and deserialization of a fresh isolate.
* **`StartupSerializerTwice`:** Serializing, deserializing, then serializing and deserializing again. This tests the idempotency and stability of the process.
* **`StartupSerializerOnceRunScript` and `StartupSerializerTwiceRunScript`:**  Similar to the above, but with the addition of running a simple script after deserialization to ensure the environment is functional.
* **`SerializeContext`:**  Focuses on serializing *just* a Context, rather than the entire Isolate.
* **`SnapshotCompression` (if enabled):** Tests the compression and decompression of snapshot data.
* **`ContextSerializerContext`:** Deserializes a previously serialized Context into an existing Isolate.
* **`SerializeCustomContext`:** Serializes a Context after running some more complex JavaScript code, testing the serialization of a more complex state.
* **`ContextSerializerCustomContext`:** Deserializes the "custom" Context.
* **`CustomSnapshotDataBlob1`:** Uses a pre-created snapshot blob to initialize an Isolate, testing the basic loading of snapshots.
* **`CustomSnapshotDataBlobOverwriteGlobal`:** Checks how snapshots interact with existing global object templates.
* **`CustomSnapshotDataBlobStringNotInternalized`:** Tests the handling of strings that are not internalized during snapshot creation.

**4. Connecting to JavaScript Functionality:**

Serialization/deserialization directly relates to:

* **Fast Startup:**  Instead of recompiling everything, V8 can load a pre-built snapshot of its initial state.
* **Code Caching:**  Serialized code can be stored and reused, improving performance.
* **Context Management:** Serializing and deserializing contexts allows for saving and restoring specific JavaScript environments.

**5. Identifying Potential Programming Errors:**

The tests implicitly reveal potential errors:

* **Incorrect Blob Handling:** If the blobs are corrupted or not handled correctly, deserialization will fail.
* **State Inconsistencies:** If the serialization process doesn't capture all necessary state, the deserialized Isolate/Context might not function correctly.
* **Memory Management Issues:** Incorrect allocation or deallocation during serialization/deserialization can lead to crashes or leaks.
* **Version Mismatches:**  Trying to deserialize a snapshot created with a different V8 version can cause problems.

**6. Formulating the Summary:**

Based on the above analysis, we can create a summary that covers the key aspects:

* **Core Functionality:** Testing Isolate and Context serialization/deserialization.
* **Test Scenarios:**  Various scenarios including single and multiple serialization/deserialization, running scripts after deserialization, and handling custom contexts and snapshot blobs.
* **Relevance to JavaScript:**  Enables faster startup, code caching, and context management.
* **Potential Errors:** Highlights common issues like incorrect blob handling and state inconsistencies.

This structured approach, starting with a high-level overview and then diving into details, allows for a comprehensive understanding of the code's functionality. The process involves keyword recognition, understanding core concepts, analyzing individual tests, linking to broader functionalities, and identifying potential problems.
Let's break down the functionality of the provided C++ code snippet (`v8/test/cctest/test-serialize.cc`).

**Core Functionality:**

The primary function of `v8/test/cctest/test-serialize.cc` is to **test the serialization and deserialization mechanisms within the V8 JavaScript engine.** This involves:

1. **Serializing an Isolate or Context:**  Taking a snapshot of the V8 engine's state (either the entire isolate or a specific context) and converting it into a binary representation (a "blob").
2. **Deserializing an Isolate or Context:**  Taking a previously generated blob and reconstructing the V8 engine's state from it.

**Key Areas Tested:**

The code contains numerous test cases (`UNINITIALIZED_TEST`) that verify different aspects of serialization:

* **Basic Isolate Serialization/Deserialization:** Testing the fundamental ability to serialize a fresh isolate and then successfully deserialize it. (`StartupSerializerOnce`, `StartupSerializerTwice`)
* **Running Scripts After Deserialization:** Ensuring that a deserialized isolate is functional and can execute JavaScript code. (`StartupSerializerOnceRunScript`, `StartupSerializerTwiceRunScript`)
* **Context Serialization/Deserialization:** Testing the ability to serialize and deserialize specific JavaScript contexts independently of the entire isolate. (`SerializeContext`, `ContextSerializerContext`, `SerializeCustomContext`, `ContextSerializerCustomContext`)
* **Snapshot Compression (if enabled):**  Verifying the functionality of compressing and decompressing snapshot data to potentially reduce its size. (`SnapshotCompression`)
* **Using Custom Snapshot Blobs:**  Testing the ability to initialize a V8 isolate using a pre-generated snapshot blob, potentially for faster startup or specific configurations. (`CustomSnapshotDataBlob1`, `CustomSnapshotDataBlobOverwriteGlobal`, `CustomSnapshotDataBlobStringNotInternalized`)
* **Handling of Global Objects and Templates:** Ensuring that serialization correctly captures and restores global objects and their properties, even when custom global templates are involved. (`CustomSnapshotDataBlobOverwriteGlobal`)
* **Handling of Various JavaScript Constructs:**  The "CustomContext" tests specifically run more complex JavaScript code before serialization, which likely tests the serialization of various JavaScript objects, functions, and internal states.

**Is it a Torque Source File?**

No, `v8/test/cctest/test-serialize.cc` ends with `.cc`, which indicates it's a **C++ source file**. Torque source files typically end with `.tq`.

**Relationship to JavaScript Functionality (and JavaScript Examples):**

The serialization functionality tested in this file is crucial for several aspects of JavaScript execution in V8:

* **Faster Startup:**  By serializing a "snapshot" of the initial state of the V8 engine, subsequent instances can be created more quickly by deserializing this snapshot instead of rebuilding everything from scratch.

   ```javascript
   // Example of how V8 might use serialization internally for startup:

   // (Conceptual - not actual JavaScript API)
   const snapshotBlob = getPrecompiledSnapshot(); // Load the serialized data
   const isolate = v8.createIsolateFromSnapshot(snapshotBlob);
   const context = isolate.createContext();
   // ... continue execution
   ```

* **Code Caching:** V8 can serialize compiled JavaScript code to disk. When the same code is encountered again, it can be deserialized from the cache, avoiding recompilation and improving performance.

   ```javascript
   // Example of code caching (simplified concept):

   // V8 internally:
   const scriptSource = "function add(a, b) { return a + b; }";
   const cachedCode = loadCachedCode(scriptSource);

   if (cachedCode) {
       const compiledFunction = deserializeCode(cachedCode);
       // Use the deserialized function
   } else {
       const compiledFunction = compile(scriptSource);
       saveCachedCode(scriptSource, serializeCode(compiledFunction));
       // Use the compiled function
   }
   ```

* **Potentially for Saving and Restoring Application State (Less Common in Web Browsers):** In some embedded environments or Node.js applications, serialization could theoretically be used to save the state of the JavaScript environment and restore it later.

**Code Logic Inference (with Hypothetical Input/Output):**

Let's consider the `StartupSerializerOnce` test:

**Hypothetical Input:**

1. An uninitialized V8 isolate created using `TestSerializer::NewIsolateInitialized()`. This isolate has the basic V8 infrastructure but no user-defined scripts or complex objects.

**Code Logic Flow:**

1. The `Serialize(isolate)` function is called:
   - A default context is created within the isolate.
   - A garbage collection is performed to clean up unused memory.
   - `ReadOnlySerializer`, `SharedHeapSerializer`, and `StartupSerializer` are used to write the isolate's state to memory buffers (the blobs).
2. The original isolate is disposed of.
3. `Deserialize(blobs)` is called:
   - A new isolate is created and initialized using the previously generated blobs.
4. A new context is created in the deserialized isolate.
5. `SanityCheck(isolate)` is performed, which includes basic checks like verifying the presence of the global object and native context.

**Hypothetical Output:**

- The `Serialize` function produces three `base::Vector<const uint8_t>` representing the startup, read-only, and shared space snapshots. These are binary data.
- The `Deserialize` function returns a pointer to a newly created `v8::Isolate` object that is functionally equivalent to the original isolate before serialization. The `SanityCheck` will pass, indicating the deserialization was successful.

**Common Programming Errors (Related to Serialization):**

While the test code itself is designed to *find* errors in V8's serialization, here are some common programming errors users might encounter when *interacting* with serialization-like concepts or when extending V8:

1. **Incorrectly Handling Snapshot Blobs:**  If you're working with custom startup snapshots, providing an invalid or corrupted blob during isolate creation will lead to errors or crashes.

   ```c++
   // Potential error: Passing a null or corrupted snapshot blob
   v8::Isolate::CreateParams params;
   params.snapshot_blob = nullptr; // Error!
   v8::Isolate* isolate = v8::Isolate::New(params);
   ```

2. **Version Mismatches:** Trying to deserialize a snapshot created with a different version of V8 is likely to cause issues due to changes in internal data structures.

3. **Forgetting to Dispose of Snapshots:** If you create snapshot data, you are responsible for freeing the allocated memory. Failure to do so will result in memory leaks.

   ```c++
   v8::StartupData data = v8::Isolate::CreateSnapshotDataBlob(...);
   // ... use the data ...
   delete[] data.data; // Important to free the memory
   ```

4. **Serializing Objects with Native Resources:** If JavaScript objects hold pointers to external native resources (e.g., file handles, network connections), simply serializing the JavaScript object won't preserve the state of those resources. You'd need a custom mechanism to handle the serialization and restoration of these external resources.

**Summary of Functionality (for Part 1):**

This first part of `v8/test/cctest/test-serialize.cc` primarily sets up the testing infrastructure and includes basic tests for serializing and deserializing entire V8 isolates. It demonstrates the fundamental ability to capture the state of the engine and restore it later. It also introduces helper classes and functions used throughout the test suite for managing isolates and snapshot blobs. The tests aim to ensure the core serialization mechanism is working correctly for a clean, newly initialized isolate.

### 提示词
```
这是目录为v8/test/cctest/test-serialize.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-serialize.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2007-2010 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <signal.h>
#include <sys/stat.h>

#include <vector>

#include "include/v8-context.h"
#include "include/v8-cppgc.h"
#include "include/v8-extension.h"
#include "include/v8-function.h"
#include "include/v8-locker.h"
#include "include/v8-platform.h"
#include "include/v8-sandbox.h"
#include "include/v8-snapshot.h"
#include "src/api/api-inl.h"
#include "src/codegen/compilation-cache.h"
#include "src/codegen/compiler.h"
#include "src/codegen/script-details.h"
#include "src/common/assert-scope.h"
#include "src/debug/debug-coverage.h"
#include "src/flags/flags.h"
#include "src/heap/heap-inl.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/parked-scope-inl.h"
#include "src/heap/read-only-heap.h"
#include "src/heap/read-only-promotion.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces.h"
#include "src/numbers/hash-seed-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/js-regexp-inl.h"
#include "src/objects/objects-inl.h"
#include "src/runtime/runtime.h"
#include "src/snapshot/code-serializer.h"
#include "src/snapshot/context-deserializer.h"
#include "src/snapshot/context-serializer.h"
#include "src/snapshot/read-only-deserializer.h"
#include "src/snapshot/read-only-serializer.h"
#include "src/snapshot/shared-heap-deserializer.h"
#include "src/snapshot/shared-heap-serializer.h"
#include "src/snapshot/snapshot-compression.h"
#include "src/snapshot/snapshot.h"
#include "src/snapshot/startup-deserializer.h"
#include "src/snapshot/startup-serializer.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"
#include "test/cctest/setup-isolate-for-tests.h"
namespace v8 {
namespace internal {

namespace {

// A convenience struct to simplify management of the blobs required to
// deserialize an isolate.
struct StartupBlobs {
  base::Vector<const uint8_t> startup;
  base::Vector<const uint8_t> read_only;
  base::Vector<const uint8_t> shared_space;

  void Dispose() {
    startup.Dispose();
    read_only.Dispose();
    shared_space.Dispose();
  }
};

}  // namespace

// TestSerializer is used for testing isolate serialization.
class TestSerializer {
 public:
  static v8::Isolate* NewIsolateInitialized() {
    const bool kEnableSerializer = true;
    DisableEmbeddedBlobRefcounting();
    v8::Isolate* v8_isolate = NewIsolate(kEnableSerializer);
    v8::Isolate::Scope isolate_scope(v8_isolate);
    i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
    isolate->InitWithoutSnapshot();
    return v8_isolate;
  }

  // Wraps v8::Isolate::New, but with a test isolate under the hood.
  // Allows flexibility to bootstrap with or without snapshot even when
  // the production Isolate class has one or the other behavior baked in.
  static v8::Isolate* NewIsolate(const v8::Isolate::CreateParams& params) {
    const bool kEnableSerializer = false;
    v8::Isolate* v8_isolate = NewIsolate(kEnableSerializer);
    v8::Isolate::Initialize(v8_isolate, params);
    return v8_isolate;
  }

  static v8::Isolate* NewIsolateFromBlob(const StartupBlobs& blobs) {
    SnapshotData startup_snapshot(blobs.startup);
    SnapshotData read_only_snapshot(blobs.read_only);
    SnapshotData shared_space_snapshot(blobs.shared_space);
    const bool kEnableSerializer = false;
    v8::Isolate* v8_isolate = NewIsolate(kEnableSerializer);
    v8::Isolate::Scope isolate_scope(v8_isolate);
    i::Isolate* isolate = reinterpret_cast<i::Isolate*>(v8_isolate);
    isolate->InitWithSnapshot(&startup_snapshot, &read_only_snapshot,
                              &shared_space_snapshot, false);
    return v8_isolate;
  }

 private:
  // Creates an Isolate instance configured for testing.
  static v8::Isolate* NewIsolate(bool with_serializer) {
    i::Isolate* isolate = i::Isolate::New();
    v8::Isolate* v8_isolate = reinterpret_cast<v8::Isolate*>(isolate);

    if (with_serializer) isolate->enable_serializer();
    isolate->set_array_buffer_allocator(CcTest::array_buffer_allocator());
    isolate->setup_delegate_ = new SetupIsolateDelegateForTests;

    return v8_isolate;
  }
};

namespace {

enum CodeCacheType { kLazy, kEager, kAfterExecute };

void DisableAlwaysOpt() {
  // Isolates prepared for serialization do not optimize. The only exception is
  // with the flag --always-turbofan.
  v8_flags.always_turbofan = false;
}

base::Vector<const uint8_t> WritePayload(
    const base::Vector<const uint8_t>& payload) {
  int length = payload.length();
  uint8_t* blob = NewArray<uint8_t>(length);
  memcpy(blob, payload.begin(), length);
  return base::VectorOf(blob, length);
}

// Convenience wrapper around the convenience wrapper.
v8::StartupData CreateSnapshotDataBlob(const char* embedded_source) {
  v8::StartupData data = CreateSnapshotDataBlobInternal(
      v8::SnapshotCreator::FunctionCodeHandling::kClear, embedded_source);
  return data;
}

StartupBlobs Serialize(v8::Isolate* isolate) {
  // We have to create one context.  One reason for this is so that the builtins
  // can be loaded from self hosted JS builtins and their addresses can be
  // processed.  This will clear the pending fixups array, which would otherwise
  // contain GC roots that would confuse the serialization/deserialization
  // process.
  v8::Isolate::Scope isolate_scope(isolate);
  {
    v8::HandleScope scope(isolate);
    v8::Context::New(isolate);
  }

  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);
  {
    // Note that we need to run a garbage collection without stack at this
    // point, so that all dead objects are reclaimed. This is required to avoid
    // conservative stack scanning and guarantee deterministic behaviour.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(
        i_isolate->heap());
    heap::InvokeMemoryReducingMajorGCs(i_isolate->heap());
  }

  // Note this effectively reimplements Snapshot::Create, keep in sync.

  SafepointScope safepoint(i_isolate, SafepointKind::kIsolate);
  DisallowGarbageCollection no_gc;
  HandleScope scope(i_isolate);

  if (i_isolate->heap()->read_only_space()->writable()) {
    // Promote objects from mutable heap spaces to read-only space prior to
    // serialization. Objects can be promoted if a) they are themselves
    // immutable-after-deserialization and b) all objects in the transitive
    // object graph also satisfy condition a).
    ReadOnlyPromotion::Promote(i_isolate, safepoint, no_gc);
    // When creating the snapshot from scratch, we are responsible for sealing
    // the RO heap here. Note we cannot delegate the responsibility e.g. to
    // Isolate::Init since it should still be possible to allocate into RO
    // space after the Isolate has been initialized, for example as part of
    // Context creation.
    i_isolate->read_only_heap()->OnCreateHeapObjectsComplete(i_isolate);
  }

  ReadOnlySerializer read_only_serializer(i_isolate,
                                          Snapshot::kDefaultSerializerFlags);
  read_only_serializer.Serialize();

  SharedHeapSerializer shared_space_serializer(
      i_isolate, Snapshot::kDefaultSerializerFlags);

  StartupSerializer ser(i_isolate, Snapshot::kDefaultSerializerFlags,
                        &shared_space_serializer);
  ser.SerializeStrongReferences(no_gc);

  ser.SerializeWeakReferencesAndDeferred();

  shared_space_serializer.FinalizeSerialization();
  SnapshotData startup_snapshot(&ser);
  SnapshotData read_only_snapshot(&read_only_serializer);
  SnapshotData shared_space_snapshot(&shared_space_serializer);
  return {WritePayload(startup_snapshot.RawData()),
          WritePayload(read_only_snapshot.RawData()),
          WritePayload(shared_space_snapshot.RawData())};
}

base::Vector<const char> ConstructSource(base::Vector<const char> head,
                                         base::Vector<const char> body,
                                         base::Vector<const char> tail,
                                         int repeats) {
  size_t source_length = head.size() + body.size() * repeats + tail.size();
  char* source = NewArray<char>(source_length);
  CopyChars(source, head.begin(), head.length());
  for (int i = 0; i < repeats; i++) {
    CopyChars(source + head.length() + i * body.length(), body.begin(),
              body.length());
  }
  CopyChars(source + head.length() + repeats * body.length(), tail.begin(),
            tail.length());
  return base::VectorOf(source, source_length);
}

v8::Isolate* Deserialize(const StartupBlobs& blobs) {
  v8::Isolate* isolate = TestSerializer::NewIsolateFromBlob(blobs);
  CHECK(isolate);
  return isolate;
}

void SanityCheck(v8::Isolate* v8_isolate) {
  Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate);
  v8::HandleScope scope(v8_isolate);
#ifdef VERIFY_HEAP
  HeapVerifier::VerifyHeap(isolate->heap());
#endif
  CHECK(IsJSObject(*isolate->global_object()));
  CHECK(IsContext(*isolate->native_context()));
  isolate->factory()->InternalizeString(base::StaticCharVector("Empty"));
}

void TestStartupSerializerOnceImpl() {
  v8::Isolate* isolate = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs = Serialize(isolate);
  isolate->Dispose();
  isolate = Deserialize(blobs);
  {
    v8::HandleScope handle_scope(isolate);
    v8::Isolate::Scope isolate_scope(isolate);

    v8::Local<v8::Context> env = v8::Context::New(isolate);
    env->Enter();

    SanityCheck(isolate);
  }
  isolate->Dispose();
  blobs.Dispose();
  FreeCurrentEmbeddedBlob();
}

}  // namespace

UNINITIALIZED_TEST(StartupSerializerOnce) {
  DisableAlwaysOpt();
  TestStartupSerializerOnceImpl();
}

UNINITIALIZED_TEST(StartupSerializerTwice) {
  DisableAlwaysOpt();
  v8::Isolate* isolate = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs1 = Serialize(isolate);
  isolate->Dispose();

  isolate = Deserialize(blobs1);
  StartupBlobs blobs2 = Serialize(isolate);
  isolate->Dispose();
  blobs1.Dispose();

  isolate = Deserialize(blobs2);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    v8::Local<v8::Context> env = v8::Context::New(isolate);
    env->Enter();

    SanityCheck(isolate);
  }
  isolate->Dispose();
  blobs2.Dispose();
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(StartupSerializerOnceRunScript) {
  DisableAlwaysOpt();
  v8::Isolate* isolate = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs = Serialize(isolate);
  isolate->Dispose();
  isolate = Deserialize(blobs);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    v8::Local<v8::Context> env = v8::Context::New(isolate);
    env->Enter();

    const char* c_source = "\"1234\".length";
    v8::Local<v8::Script> script = v8_compile(c_source);
    v8::Maybe<int32_t> result = script->Run(isolate->GetCurrentContext())
                                    .ToLocalChecked()
                                    ->Int32Value(isolate->GetCurrentContext());
    CHECK_EQ(4, result.FromJust());
  }
  isolate->Dispose();
  blobs.Dispose();
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(StartupSerializerTwiceRunScript) {
  DisableAlwaysOpt();
  v8::Isolate* isolate = TestSerializer::NewIsolateInitialized();
  StartupBlobs blobs1 = Serialize(isolate);
  isolate->Dispose();

  isolate = Deserialize(blobs1);
  StartupBlobs blobs2 = Serialize(isolate);
  isolate->Dispose();
  blobs1.Dispose();

  isolate = Deserialize(blobs2);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);

    v8::Local<v8::Context> env = v8::Context::New(isolate);
    env->Enter();

    const char* c_source = "\"1234\".length";
    v8::Local<v8::Script> script = v8_compile(c_source);
    v8::Maybe<int32_t> result = script->Run(isolate->GetCurrentContext())
                                    .ToLocalChecked()
                                    ->Int32Value(isolate->GetCurrentContext());
    CHECK_EQ(4, result.FromJust());
  }
  isolate->Dispose();
  blobs2.Dispose();
  FreeCurrentEmbeddedBlob();
}

static void SerializeContext(base::Vector<const uint8_t>* startup_blob_out,
                             base::Vector<const uint8_t>* read_only_blob_out,
                             base::Vector<const uint8_t>* shared_space_blob_out,
                             base::Vector<const uint8_t>* context_blob_out) {
  v8::Isolate* v8_isolate = TestSerializer::NewIsolateInitialized();
  Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate);
  Heap* heap = isolate->heap();
  {
    v8::Isolate::Scope isolate_scope(v8_isolate);

    v8::Persistent<v8::Context> env;
    {
      HandleScope scope(isolate);
      env.Reset(v8_isolate, v8::Context::New(v8_isolate));
    }
    CHECK(!env.IsEmpty());
    {
      v8::HandleScope handle_scope(v8_isolate);
      v8::Local<v8::Context>::New(v8_isolate, env)->Enter();
    }

    // If we don't do this then we end up with a stray root pointing at the
    // context even after we have disposed of env.
    {
      // Note that we need to run a garbage collection without stack at this
      // point, so that all dead objects are reclaimed. This is required to
      // avoid conservative stack scanning and guarantee deterministic
      // behaviour.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMemoryReducingMajorGCs(heap);
    }

    {
      v8::HandleScope handle_scope(v8_isolate);
      v8::Local<v8::Context>::New(v8_isolate, env)->Exit();
    }

    HandleScope scope(isolate);
    i::Tagged<i::Context> raw_context =
        i::Cast<i::Context>(*v8::Utils::OpenPersistent(env));

    env.Reset();

    IsolateSafepointScope safepoint(heap);

    if (!isolate->initialized_from_snapshot()) {
      // When creating the snapshot from scratch, we are responsible for sealing
      // the RO heap here. Note we cannot delegate the responsibility e.g. to
      // Isolate::Init since it should still be possible to allocate into RO
      // space after the Isolate has been initialized, for example as part of
      // Context creation.
      isolate->read_only_heap()->OnCreateHeapObjectsComplete(isolate);
    }

    DisallowGarbageCollection no_gc;
    SnapshotByteSink read_only_sink;
    ReadOnlySerializer read_only_serializer(isolate,
                                            Snapshot::kDefaultSerializerFlags);
    read_only_serializer.Serialize();

    SharedHeapSerializer shared_space_serializer(
        isolate, Snapshot::kDefaultSerializerFlags);

    SnapshotByteSink startup_sink;
    StartupSerializer startup_serializer(
        isolate, Snapshot::kDefaultSerializerFlags, &shared_space_serializer);
    startup_serializer.SerializeStrongReferences(no_gc);

    SnapshotByteSink context_sink;
    ContextSerializer context_serializer(
        isolate, Snapshot::kDefaultSerializerFlags, &startup_serializer,
        SerializeEmbedderFieldsCallback(v8::SerializeInternalFieldsCallback()));
    context_serializer.Serialize(&raw_context, no_gc);

    startup_serializer.SerializeWeakReferencesAndDeferred();

    shared_space_serializer.FinalizeSerialization();

    SnapshotData read_only_snapshot(&read_only_serializer);
    SnapshotData shared_space_snapshot(&shared_space_serializer);
    SnapshotData startup_snapshot(&startup_serializer);
    SnapshotData context_snapshot(&context_serializer);

    *context_blob_out = WritePayload(context_snapshot.RawData());
    *startup_blob_out = WritePayload(startup_snapshot.RawData());
    *read_only_blob_out = WritePayload(read_only_snapshot.RawData());
    *shared_space_blob_out = WritePayload(shared_space_snapshot.RawData());
  }
  v8_isolate->Dispose();
}

#ifdef SNAPSHOT_COMPRESSION
UNINITIALIZED_TEST(SnapshotCompression) {
  DisableAlwaysOpt();
  base::Vector<const uint8_t> startup_blob;
  base::Vector<const uint8_t> read_only_blob;
  base::Vector<const uint8_t> shared_space_blob;
  base::Vector<const uint8_t> context_blob;
  SerializeContext(&startup_blob, &read_only_blob, &shared_space_blob,
                   &context_blob);
  SnapshotData original_snapshot_data(context_blob);
  SnapshotData compressed =
      i::SnapshotCompression::Compress(&original_snapshot_data);
  SnapshotData decompressed =
      i::SnapshotCompression::Decompress(compressed.RawData());
  CHECK_EQ(context_blob, decompressed.RawData());

  startup_blob.Dispose();
  read_only_blob.Dispose();
  shared_space_blob.Dispose();
  context_blob.Dispose();
}
#endif  // SNAPSHOT_COMPRESSION

UNINITIALIZED_TEST(ContextSerializerContext) {
  DisableAlwaysOpt();
  base::Vector<const uint8_t> startup_blob;
  base::Vector<const uint8_t> read_only_blob;
  base::Vector<const uint8_t> shared_space_blob;
  base::Vector<const uint8_t> context_blob;
  SerializeContext(&startup_blob, &read_only_blob, &shared_space_blob,
                   &context_blob);

  StartupBlobs blobs = {startup_blob, read_only_blob, shared_space_blob};
  v8::Isolate* v8_isolate = TestSerializer::NewIsolateFromBlob(blobs);
  CHECK(v8_isolate);
  {
    v8::Isolate::Scope isolate_scope(v8_isolate);

    Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate);
    HandleScope handle_scope(isolate);
    DirectHandle<Object> root;
    Handle<JSGlobalProxy> global_proxy =
        isolate->factory()->NewUninitializedJSGlobalProxy(
            JSGlobalProxy::SizeWithEmbedderFields(0));
    {
      SnapshotData snapshot_data(context_blob);
      root = ContextDeserializer::DeserializeContext(
                 isolate, &snapshot_data, 0, false, global_proxy,
                 DeserializeEmbedderFieldsCallback(
                     v8::DeserializeInternalFieldsCallback()))
                 .ToHandleChecked();
      CHECK(IsContext(*root));
      CHECK(Cast<Context>(root)->global_proxy() == *global_proxy);
    }

    DirectHandle<Object> root2;
    {
      SnapshotData snapshot_data(context_blob);
      root2 = ContextDeserializer::DeserializeContext(
                  isolate, &snapshot_data, 0, false, global_proxy,
                  DeserializeEmbedderFieldsCallback(
                      v8::DeserializeInternalFieldsCallback()))
                  .ToHandleChecked();
      CHECK(IsContext(*root2));
      CHECK(!root.is_identical_to(root2));
    }
    context_blob.Dispose();
  }
  v8_isolate->Dispose();
  blobs.Dispose();
  FreeCurrentEmbeddedBlob();
}

static void SerializeCustomContext(
    base::Vector<const uint8_t>* startup_blob_out,
    base::Vector<const uint8_t>* read_only_blob_out,
    base::Vector<const uint8_t>* shared_space_blob_out,
    base::Vector<const uint8_t>* context_blob_out) {
  v8::Isolate* isolate = TestSerializer::NewIsolateInitialized();
  Isolate* i_isolate = reinterpret_cast<Isolate*>(isolate);

  {
    v8::Global<v8::Context> env;
    v8::Isolate::Scope isolate_scope(isolate);

    {
      HandleScope scope(i_isolate);
      env.Reset(isolate, v8::Context::New(isolate));
    }
    CHECK(!env.IsEmpty());
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context>::New(isolate, env)->Enter();
      // After execution, e's function context refers to the global object.
      CompileRun(
          "var e;"
          "(function() {"
          "  e = function(s) { return eval (s); }"
          "})();"
          "var o = this;"
          "var r = Math.random();"
          "var c = Math.sin(0) + Math.cos(0);"
          "var f = (function(a, b) { return a + b; }).bind(1, 2, 3);"
          "var s = parseInt('12345');"
          "var p = 0;"
          "(async ()=>{ p = await 42; })();");

      base::Vector<const char> source = ConstructSource(
          base::StaticCharVector("function g() { return [,"),
          base::StaticCharVector("1,"),
          base::StaticCharVector("];} a = g(); b = g(); b.push(1);"), 100000);
      v8::MaybeLocal<v8::String> source_str = v8::String::NewFromUtf8(
          isolate, source.begin(), v8::NewStringType::kNormal, source.length());
      CompileRun(source_str.ToLocalChecked());
      source.Dispose();
    }
    // If we don't do this then we end up with a stray root pointing at the
    // context even after we have disposed of env.
    {
      // Note that we need to run a garbage collection without stack at this
      // point, so that all dead objects are reclaimed. This is required to
      // avoid conservative stack scanning and guarantee deterministic
      // behaviour.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(
          i_isolate->heap());
      heap::InvokeMemoryReducingMajorGCs(i_isolate->heap());
    }

    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context>::New(isolate, env)->Exit();
    }

    {
      HandleScope scope(i_isolate);
      i::Tagged<i::Context> raw_context =
          i::Cast<i::Context>(*v8::Utils::OpenPersistent(env));

      // On purpose we do not reset the global context here --- env.Reset() ---
      // so that it is found below, during heap verification at the GC before
      // isolate disposal.

      SafepointScope safepoint(i_isolate, SafepointKind::kIsolate);
      DisallowGarbageCollection no_gc;

      if (i_isolate->heap()->read_only_space()->writable()) {
        // Promote objects from mutable heap spaces to read-only space prior to
        // serialization. Objects can be promoted if a) they are themselves
        // immutable-after-deserialization and b) all objects in the transitive
        // object graph also satisfy condition a).
        ReadOnlyPromotion::Promote(i_isolate, safepoint, no_gc);
        // When creating the snapshot from scratch, we are responsible for
        // sealing the RO heap here. Note we cannot delegate the responsibility
        // e.g. to Isolate::Init since it should still be possible to allocate
        // into RO space after the Isolate has been initialized, for example as
        // part of Context creation.
        i_isolate->read_only_heap()->OnCreateHeapObjectsComplete(i_isolate);
      }

      SnapshotByteSink read_only_sink;
      ReadOnlySerializer read_only_serializer(
          i_isolate, Snapshot::kDefaultSerializerFlags);
      read_only_serializer.Serialize();

      SharedHeapSerializer shared_space_serializer(
          i_isolate, Snapshot::kDefaultSerializerFlags);

      SnapshotByteSink startup_sink;
      StartupSerializer startup_serializer(i_isolate,
                                           Snapshot::kDefaultSerializerFlags,
                                           &shared_space_serializer);
      startup_serializer.SerializeStrongReferences(no_gc);

      SnapshotByteSink context_sink;
      ContextSerializer context_serializer(
          i_isolate, Snapshot::kDefaultSerializerFlags, &startup_serializer,
          SerializeEmbedderFieldsCallback(
              v8::SerializeInternalFieldsCallback()));
      context_serializer.Serialize(&raw_context, no_gc);

      startup_serializer.SerializeWeakReferencesAndDeferred();

      shared_space_serializer.FinalizeSerialization();

      SnapshotData read_only_snapshot(&read_only_serializer);
      SnapshotData shared_space_snapshot(&shared_space_serializer);
      SnapshotData startup_snapshot(&startup_serializer);
      SnapshotData context_snapshot(&context_serializer);

      *context_blob_out = WritePayload(context_snapshot.RawData());
      *startup_blob_out = WritePayload(startup_snapshot.RawData());
      *read_only_blob_out = WritePayload(read_only_snapshot.RawData());
      *shared_space_blob_out = WritePayload(shared_space_snapshot.RawData());
    }

    // At this point, the heap must be in a consistent state and this GC must
    // not crash, even with the live handle to the global environment.
    heap::InvokeMajorGC(i_isolate->heap());
    // We reset the global context, before isolate disposal.
  }

  isolate->Dispose();
}

UNINITIALIZED_TEST(ContextSerializerCustomContext) {
  DisableAlwaysOpt();
  base::Vector<const uint8_t> startup_blob;
  base::Vector<const uint8_t> read_only_blob;
  base::Vector<const uint8_t> shared_space_blob;
  base::Vector<const uint8_t> context_blob;
  SerializeCustomContext(&startup_blob, &read_only_blob, &shared_space_blob,
                         &context_blob);

  StartupBlobs blobs = {startup_blob, read_only_blob, shared_space_blob};
  v8::Isolate* v8_isolate = TestSerializer::NewIsolateFromBlob(blobs);
  CHECK(v8_isolate);
  {
    v8::Isolate::Scope isolate_scope(v8_isolate);

    Isolate* isolate = reinterpret_cast<Isolate*>(v8_isolate);
    HandleScope handle_scope(isolate);
    DirectHandle<Object> root;
    Handle<JSGlobalProxy> global_proxy =
        isolate->factory()->NewUninitializedJSGlobalProxy(
            JSGlobalProxy::SizeWithEmbedderFields(0));
    {
      SnapshotData snapshot_data(context_blob);
      root = ContextDeserializer::DeserializeContext(
                 isolate, &snapshot_data, 0, false, global_proxy,
                 DeserializeEmbedderFieldsCallback(
                     v8::DeserializeInternalFieldsCallback()))
                 .ToHandleChecked();
      CHECK(IsContext(*root));
      DirectHandle<NativeContext> context = Cast<NativeContext>(root);

      // Add context to the weak native context list
      Cast<Context>(context)->set(Context::NEXT_CONTEXT_LINK,
                                  isolate->heap()->native_contexts_list(),
                                  UPDATE_WRITE_BARRIER);
      isolate->heap()->set_native_contexts_list(*context);

      CHECK(context->global_proxy() == *global_proxy);
      Handle<String> o = isolate->factory()->NewStringFromAsciiChecked("o");
      Handle<JSObject> global_object(context->global_object(), isolate);
      Handle<Object> property =
          JSReceiver::GetDataProperty(isolate, global_object, o);
      CHECK(property.is_identical_to(global_proxy));

      v8::Local<v8::Context> v8_context = v8::Utils::ToLocal(context);
      v8::Context::Scope context_scope(v8_context);
      double r = CompileRun("r")
                     ->ToNumber(v8_isolate->GetCurrentContext())
                     .ToLocalChecked()
                     ->Value();
      CHECK(0.0 <= r && r < 1.0);
      // Math.random still works.
      double random = CompileRun("Math.random()")
                          ->ToNumber(v8_isolate->GetCurrentContext())
                          .ToLocalChecked()
                          ->Value();
      CHECK(0.0 <= random && random < 1.0);
      double c = CompileRun("c")
                     ->ToNumber(v8_isolate->GetCurrentContext())
                     .ToLocalChecked()
                     ->Value();
      CHECK_EQ(1, c);
      int f = CompileRun("f()")
                  ->ToNumber(v8_isolate->GetCurrentContext())
                  .ToLocalChecked()
                  ->Int32Value(v8_isolate->GetCurrentContext())
                  .FromJust();
      CHECK_EQ(5, f);
      f = CompileRun("e('f()')")
              ->ToNumber(v8_isolate->GetCurrentContext())
              .ToLocalChecked()
              ->Int32Value(v8_isolate->GetCurrentContext())
              .FromJust();
      CHECK_EQ(5, f);
      v8::Local<v8::String> s = CompileRun("s")
                                    ->ToString(v8_isolate->GetCurrentContext())
                                    .ToLocalChecked();
      CHECK(s->Equals(v8_isolate->GetCurrentContext(), v8_str("12345"))
                .FromJust());
      v8::Local<v8::String> p = CompileRun("p")
                                    ->ToString(v8_isolate->GetCurrentContext())
                                    .ToLocalChecked();
      CHECK(
          p->Equals(v8_isolate->GetCurrentContext(), v8_str("42")).FromJust());
      int a = CompileRun("a.length")
                  ->ToNumber(v8_isolate->GetCurrentContext())
                  .ToLocalChecked()
                  ->Int32Value(v8_isolate->GetCurrentContext())
                  .FromJust();
      CHECK_EQ(100001, a);
      int b = CompileRun("b.length")
                  ->ToNumber(v8_isolate->GetCurrentContext())
                  .ToLocalChecked()
                  ->Int32Value(v8_isolate->GetCurrentContext())
                  .FromJust();
      CHECK_EQ(100002, b);
    }
    context_blob.Dispose();
  }
  v8_isolate->Dispose();
  blobs.Dispose();
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlob1) {
  DisableAlwaysOpt();
  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("f()")->Int32Value(isolate1->GetCurrentContext());
    CHECK_EQ(42, result.FromJust());
    CHECK(CompileRun("this.g")->IsUndefined());
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

static void UnreachableCallback(const FunctionCallbackInfo<Value>& info) {
  UNREACHABLE();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobOverwriteGlobal) {
  DisableAlwaysOpt();
  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test that the snapshot overwrites the object template when there are
  // duplicate global properties.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::ObjectTemplate> global_template =
        v8::ObjectTemplate::New(isolate1);
    global_template->Set(
        isolate1, "f",
        v8::FunctionTemplate::New(isolate1, UnreachableCallback));
    v8::Local<v8::Context> context =
        v8::Context::New(isolate1, nullptr, global_template);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("f()")->Int32Value(isolate1->GetCurrentContext());
    CHECK_EQ(42, result.FromJust());
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobStringNotInternalized) {
  DisableAlwaysOpt();
  const char* source1 =
      R"javascript(
      // String would be internalized if it came from a literal so create "AB"
      // via a function call.
      var global = String.fromCharCode(65, 66);
      function f() { return global; }
      )javascript";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8:
```
Response: My thinking process to summarize the provided C++ code snippet went like this:

1. **Initial Scan for Keywords and Purpose:** I quickly scanned the code for obvious keywords and patterns related to its function. I noticed `#include "include/v8-snapshot.h"`, `Serialize`, `Deserialize`, `StartupBlobs`, `SnapshotData`, `ContextSerializer`, `StartupSerializer`, and test-related namespaces like `v8::internal` and `test::cctest`. This immediately suggested that the code is related to V8's snapshot functionality and is likely part of its testing framework.

2. **Identify Core Functionality:** The presence of `Serialize` and `Deserialize` functions, along with structures like `StartupBlobs` and `SnapshotData`, clearly points to the core functionality: serializing and deserializing the state of a V8 isolate. The "startup" and "snapshot" terms reinforce this idea, indicating that the code deals with saving and restoring the initial state of the V8 engine.

3. **Analyze `StartupBlobs`:**  This struct groups `startup`, `read_only`, and `shared_space` blobs. These are the key components of a V8 snapshot. The `Dispose()` method confirms it's responsible for managing the memory associated with these blobs.

4. **Examine `TestSerializer` Class:**  This class appears to be a helper for creating and managing V8 isolates specifically for serialization testing. Methods like `NewIsolateInitialized()`, `NewIsolate(const v8::Isolate::CreateParams&)`, and `NewIsolateFromBlob()` illustrate different ways to create isolates, some initialized from scratch and others restored from serialized data.

5. **Delve into `Serialize()` Function:**  This function's implementation reveals the steps involved in creating a snapshot:
    * Creating a context (necessary for builtins).
    * Performing a garbage collection to ensure a clean state.
    * Promoting immutable objects to the read-only heap.
    * Using `ReadOnlySerializer`, `SharedHeapSerializer`, and `StartupSerializer` to serialize different parts of the isolate.
    * Packaging the serialized data into `SnapshotData` objects.

6. **Understand `Deserialize()` Function:** This function is simpler, taking the `StartupBlobs` and using `TestSerializer::NewIsolateFromBlob()` to reconstruct the V8 isolate from the serialized data.

7. **Note `SanityCheck()`:** This function performs basic validation on a deserialized isolate, confirming the presence of essential objects like the global object and context.

8. **Identify the Tests:** The `UNINITIALIZED_TEST` macros indicate that this part of the code defines various test cases for the serialization/deserialization functionality. The names of the tests (e.g., `StartupSerializerOnce`, `StartupSerializerTwice`, `StartupSerializerOnceRunScript`) clearly indicate what aspects of the serialization process are being tested. Running scripts after serialization is also a key part of validating the restored state.

9. **Look for JavaScript Relevance:**  The tests use `v8::Context::New()`, `v8::Script::Compile()`, and `script->Run()` which are directly related to executing JavaScript code within the V8 engine. The test names mentioning "RunScript" confirm this connection. I also noted the usage of `CompileRun()` which simplifies the compilation and execution of JavaScript snippets within the tests.

10. **Formulate the Summary:** Based on the above observations, I formulated the summary, highlighting the core functionality (serialization and deserialization), the key components involved (blobs, serializers), the testing aspect, and the connection to JavaScript (through script execution within the tests). I specifically pointed out the different test scenarios like serializing once, twice, and running scripts after deserialization.

11. **Construct the JavaScript Example:**  To illustrate the JavaScript relevance, I created a simple example demonstrating the concept of saving and restoring state, even though JavaScript doesn't have direct snapshotting capabilities like V8's internal implementation. This helped to bridge the gap between the C++ code and the user's understanding of JavaScript. I focused on `JSON.stringify` and `JSON.parse` as a readily understandable analogy for serialization and deserialization in the JavaScript world.

By following this structured approach, I could effectively analyze the C++ code, understand its purpose, and clearly explain its functionality and relevance to JavaScript. The key was to identify the core concepts, break down the code into manageable parts, and connect the technical details to higher-level concepts.这是 `v8/test/cctest/test-serialize.cc` 文件的第一部分，主要负责测试 V8 JavaScript 引擎的**序列化和反序列化**功能。

**核心功能归纳:**

1. **测试 V8 隔离（Isolate）的序列化和反序列化:**  该文件包含多个测试用例，用于验证将 V8 引擎的运行状态（Isolate）保存到二进制数据（序列化）并在之后从该数据恢复运行状态（反序列化）的功能是否正常工作。这包括：
    * **基本序列化/反序列化流程:**  测试将一个新初始化的 Isolate 序列化，然后反序列化，并验证反序列化后的 Isolate 是否可用。
    * **多次序列化/反序列化:** 测试连续进行多次序列化和反序列化操作，确保状态的正确性。
    * **序列化/反序列化后运行脚本:**  测试在序列化一个运行过脚本的 Isolate 后，反序列化该 Isolate 并再次运行相同的脚本，验证脚本执行结果的正确性。
    * **上下文（Context）的序列化/反序列化:**  测试独立序列化和反序列化 JavaScript 上下文，这允许更细粒度的状态保存和恢复。

2. **使用快照（Snapshot）:**  序列化和反序列化在 V8 中通常通过快照来实现。该文件中的测试用例会创建和使用快照数据（startup blob, read-only blob, shared space blob）来保存和恢复 Isolate 的状态。

3. **自定义快照数据（Custom Snapshot Data Blob）:**  测试用例还涵盖了使用自定义的快照数据 blob 初始化 Isolate 的场景。这允许在 Isolate 启动时预先加载特定的 JavaScript 代码或对象，用于快速启动或创建特定的运行环境。

4. **测试快照的完整性:**  包含对快照数据的校验和 (checksum) 的测试，以确保序列化和反序列化过程中数据没有被损坏。

5. **测试内部字段的序列化和反序列化:**  验证了如何序列化和反序列化 JavaScript 对象的内部字段，这对于持有 C++ 端数据的 JavaScript 对象非常重要。

6. **测试不同类型的 JavaScript 对象序列化:** 涵盖了诸如 `Uint8Array`, `Int32Array`, `ArrayBuffer`, `DataView` 等不同类型的 JavaScript 对象的序列化和反序列化，确保这些复杂类型的数据也能正确保存和恢复。

**与 JavaScript 功能的关系及 JavaScript 举例:**

该 C++ 代码直接测试了 V8 引擎的核心功能，而 V8 引擎是 JavaScript 的运行环境。序列化和反序列化功能与 JavaScript 的关系在于，它允许：

* **加速 JavaScript 应用的启动:**  通过预先序列化引擎的核心状态和一些常用的 JavaScript 代码，可以在下次启动时直接加载快照，避免重复的解析和编译过程，从而显著提升启动速度。Node.js 就利用了快照技术。
* **创建自定义的 JavaScript 运行环境:**  可以使用自定义的快照数据来创建一个预先配置好的 JavaScript 环境，其中包含特定的全局对象、函数或模块。
* **持久化 JavaScript 应用的状态:**  虽然 JavaScript 本身没有直接的序列化 Isolate 的 API，但了解 V8 的内部机制可以帮助开发者设计出更高效的状态保存和恢复方案。

**JavaScript 举例 (概念性):**

在 JavaScript 中，我们没有直接操作 V8 快照的 API。但是，可以想象以下概念性的场景：

```javascript
// 假设 V8 提供了一个这样的 API (实际不存在)
async function saveAppState(filepath) {
  const snapshotData = await V8.serializeIsolate();
  // 将 snapshotData 保存到文件
  // ...
}

async function loadAppState(filepath) {
  // 从文件加载 snapshotData
  // ...
  const restoredIsolate = await V8.deserializeIsolate(snapshotData);
  return restoredIsolate;
}

// 保存应用状态
saveAppState('app_state.snapshot');

// 稍后，恢复应用状态
const restored = await loadAppState('app_state.snapshot');
// restored 现在是一个恢复了之前状态的 V8 实例
```

**实际上，JavaScript 中更常见的状态持久化方式是使用 `JSON.stringify` 和 `JSON.parse` 来序列化和反序列化 JavaScript 对象:**

```javascript
// 序列化
const appState = {
  count: 10,
  data: ['a', 'b', 'c']
};
const serializedState = JSON.stringify(appState);
localStorage.setItem('app_state', serializedState);

// 反序列化
const savedState = localStorage.getItem('app_state');
if (savedState) {
  const restoredState = JSON.parse(savedState);
  console.log(restoredState.count); // 输出 10
}
```

虽然 `JSON.stringify` 和 `JSON.parse` 无法保存整个 V8 Isolate 的状态（例如编译后的代码），但它们是 JavaScript 中常用的状态持久化手段。  V8 的内部序列化机制则更加底层和强大，能够保存更完整的引擎状态。

总而言之，这个 C++ 代码文件的第一部分是 V8 引擎序列化和反序列化功能的测试基础，它验证了核心机制的正确性，而这些机制直接影响到 JavaScript 应用的启动速度、环境定制和状态持久化等方面。

Prompt: 
```
这是目录为v8/test/cctest/test-serialize.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共4部分，请归纳一下它的功能

"""
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
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    v8::Local<v8::Value> result = CompileRun("f()").As<v8::Value>();
    CHECK(result->IsString());
    i::Tagged<i::String> str =
        *v8::Utils::OpenDirectHandle(*result.As<v8::String>());
    CHECK_EQ(std::string(str->ToCString().get()), "AB");
    CHECK(!IsInternalizedString(str));
    CHECK(!i::ReadOnlyHeap::Contains(str));
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

namespace {

void TestCustomSnapshotDataBlobWithIrregexpCode(
    v8::SnapshotCreator::FunctionCodeHandling function_code_handling) {
  DisableAlwaysOpt();
  const char* source =
      "var re1 = /\\/\\*[^*]*\\*+([^/*][^*]*\\*+)*\\//;\n"
      "function f() { return '/* a comment */'.search(re1); }\n"
      "function g() { return 'not a comment'.search(re1); }\n"
      "function h() { return '// this is a comment'.search(re1); }\n"
      "var re2 = /a/;\n"
      "function i() { return '/* a comment */'.search(re2); }\n"
      "f(); f(); g(); g(); h(); h(); i(); i();\n";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 =
      CreateSnapshotDataBlobInternal(function_code_handling, source);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  Isolate* i_isolate1 = reinterpret_cast<Isolate*>(isolate1);
  {
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    {
      // Check that compiled irregexp code has been flushed prior to
      // serialization.
      i::DirectHandle<i::JSRegExp> re =
          Utils::OpenDirectHandle(*CompileRun("re1").As<v8::RegExp>());
      CHECK(!re->data(i_isolate1)->HasCompiledCode());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("f()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(0, result.FromJust());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("g()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(-1, result.FromJust());
    }
    {
      v8::Maybe<int32_t> result =
          CompileRun("h()")->Int32Value(isolate1->GetCurrentContext());
      CHECK_EQ(-1, result.FromJust());
    }
    {
      // Check that ATOM regexp remains valid.
      i::DirectHandle<i::JSRegExp> re =
          Utils::OpenDirectHandle(*CompileRun("re2").As<v8::RegExp>());
      i::Tagged<i::RegExpData> data = re->data(i_isolate1);
      CHECK_EQ(data->type_tag(), RegExpData::Type::ATOM);
      CHECK(!data->HasCompiledCode());
    }
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

}  // namespace

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithIrregexpCodeKeepCode) {
  TestCustomSnapshotDataBlobWithIrregexpCode(
      v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithIrregexpCodeClearCode) {
  TestCustomSnapshotDataBlobWithIrregexpCode(
      v8::SnapshotCreator::FunctionCodeHandling::kClear);
}

UNINITIALIZED_TEST(SnapshotChecksum) {
  DisableAlwaysOpt();
  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);
  CHECK(i::Snapshot::VerifyChecksum(&data1));
  const_cast<char*>(data1.data)[142] = data1.data[142] ^ 4;  // Flip a bit.
  CHECK(!i::Snapshot::VerifyChecksum(&data1));
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

struct InternalFieldData {
  uint32_t data;
};

v8::StartupData SerializeInternalFields(v8::Local<v8::Object> holder, int index,
                                        void* data) {
  if (data == reinterpret_cast<void*>(2000)) {
    // Used for SnapshotCreatorTemplates test. We check that none of the fields
    // have been cleared yet.
    CHECK_NOT_NULL(holder->GetAlignedPointerFromInternalField(1));
  } else {
    CHECK_EQ(reinterpret_cast<void*>(2016), data);
  }
  if (index != 1) return {nullptr, 0};
  InternalFieldData* embedder_field = static_cast<InternalFieldData*>(
      holder->GetAlignedPointerFromInternalField(index));
  if (embedder_field == nullptr) return {nullptr, 0};
  int size = sizeof(*embedder_field);
  char* payload = new char[size];
  // We simply use memcpy to serialize the content.
  memcpy(payload, embedder_field, size);
  return {payload, size};
}

std::vector<InternalFieldData*> deserialized_data;

void DeserializeInternalFields(v8::Local<v8::Object> holder, int index,
                               v8::StartupData payload, void* data) {
  if (payload.raw_size == 0) {
    holder->SetAlignedPointerInInternalField(index, nullptr);
    return;
  }
  CHECK_EQ(reinterpret_cast<void*>(2017), data);
  InternalFieldData* embedder_field = new InternalFieldData{0};
  memcpy(embedder_field, payload.data, payload.raw_size);
  holder->SetAlignedPointerInInternalField(index, embedder_field);
  deserialized_data.push_back(embedder_field);
}

using Int32Expectations = std::vector<std::tuple<const char*, int32_t>>;

void TestInt32Expectations(const Int32Expectations& expectations) {
  for (const auto& e : expectations) {
    ExpectInt32(std::get<0>(e), std::get<1>(e));
  }
}

struct SnapshotCreatorParams {
  explicit SnapshotCreatorParams(const intptr_t* external_references = nullptr,
                                 const StartupData* existing_blob = nullptr) {
    allocator.reset(ArrayBuffer::Allocator::NewDefaultAllocator());
    create_params.array_buffer_allocator = allocator.get();
    create_params.external_references = external_references;
    create_params.snapshot_blob = existing_blob;
  }

  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator;
  v8::Isolate::CreateParams create_params;
};

void TypedArrayTestHelper(
    const char* code, const Int32Expectations& expectations,
    const char* code_to_run_after_restore = nullptr,
    const Int32Expectations& after_restore_expectations = Int32Expectations(),
    v8::ArrayBuffer::Allocator* allocator = nullptr) {
  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator =
      allocator != nullptr ? allocator : CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    CHECK(deserialized_data.empty());  // We do not expect any embedder data.
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);
    if (code_to_run_after_restore) {
      CompileRun(code_to_run_after_restore);
    }
    TestInt32Expectations(after_restore_expectations);
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithOffHeapTypedArray) {
  const char* code =
      "var x = new Uint8Array(128);"
      "x[0] = 12;"
      "var arr = new Array(17);"
      "arr[1] = 24;"
      "var y = new Uint32Array(arr);"
      "var buffer = new ArrayBuffer(128);"
      "var z = new Int16Array(buffer);"
      "z[0] = 48;";
  Int32Expectations expectations = {std::make_tuple("x[0]", 12),
                                    std::make_tuple("y[1]", 24),
                                    std::make_tuple("z[0]", 48)};

  TypedArrayTestHelper(code, expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobSharedArrayBuffer) {
  const char* code =
      "var x = new Int32Array([12, 24, 48, 96]);"
      "var y = new Uint8Array(x.buffer)";
  Int32Expectations expectations = {
    std::make_tuple("x[0]", 12),
    std::make_tuple("x[1]", 24),
#if !V8_TARGET_BIG_ENDIAN
    std::make_tuple("y[0]", 12),
    std::make_tuple("y[1]", 0),
    std::make_tuple("y[2]", 0),
    std::make_tuple("y[3]", 0),
    std::make_tuple("y[4]", 24)
#else
    std::make_tuple("y[3]", 12),
    std::make_tuple("y[2]", 0),
    std::make_tuple("y[1]", 0),
    std::make_tuple("y[0]", 0),
    std::make_tuple("y[7]", 24)
#endif
  };

  TypedArrayTestHelper(code, expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobArrayBufferWithOffset) {
  const char* code =
      "var x = new Int32Array([12, 24, 48, 96]);"
      "var y = new Int32Array(x.buffer, 4, 2)";
  Int32Expectations expectations = {
      std::make_tuple("x[1]", 24),
      std::make_tuple("x[2]", 48),
      std::make_tuple("y[0]", 24),
      std::make_tuple("y[1]", 48),
  };

  // Verify that the typed arrays use the same buffer (not independent copies).
  const char* code_to_run_after_restore = "x[2] = 57; y[0] = 42;";
  Int32Expectations after_restore_expectations = {
      std::make_tuple("x[1]", 42),
      std::make_tuple("y[1]", 57),
  };

  TypedArrayTestHelper(code, expectations, code_to_run_after_restore,
                       after_restore_expectations);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobDataView) {
  const char* code =
      "var x = new Int8Array([1, 2, 3, 4]);"
      "var v = new DataView(x.buffer)";
  Int32Expectations expectations = {std::make_tuple("v.getInt8(0)", 1),
                                    std::make_tuple("v.getInt8(1)", 2),
                                    std::make_tuple("v.getInt16(0)", 258),
                                    std::make_tuple("v.getInt16(1)", 515)};

  TypedArrayTestHelper(code, expectations);
}

namespace {
class AlternatingArrayBufferAllocator : public v8::ArrayBuffer::Allocator {
 public:
  AlternatingArrayBufferAllocator()
      : allocation_fails_(false),
        allocator_(v8::ArrayBuffer::Allocator::NewDefaultAllocator()) {}
  ~AlternatingArrayBufferAllocator() { delete allocator_; }
  void* Allocate(size_t length) override {
    allocation_fails_ = !allocation_fails_;
    if (allocation_fails_) return nullptr;
    return allocator_->Allocate(length);
  }

  void* AllocateUninitialized(size_t length) override {
    return this->Allocate(length);
  }

  void Free(void* data, size_t size) override { allocator_->Free(data, size); }

  void* Reallocate(void* data, size_t old_length, size_t new_length) override {
    START_ALLOW_USE_DEPRECATED()
    return allocator_->Reallocate(data, old_length, new_length);
    END_ALLOW_USE_DEPRECATED()
  }

 private:
  bool allocation_fails_;
  v8::ArrayBuffer::Allocator* allocator_;
};
}  // anonymous namespace

UNINITIALIZED_TEST(CustomSnapshotManyArrayBuffers) {
  const char* code =
      "var buffers = [];"
      "for (let i = 0; i < 70; i++) buffers.push(new Uint8Array(1000));";
  Int32Expectations expectations = {std::make_tuple("buffers.length", 70)};
  std::unique_ptr<v8::ArrayBuffer::Allocator> allocator(
      new AlternatingArrayBufferAllocator());
  TypedArrayTestHelper(code, expectations, nullptr, Int32Expectations(),
                       allocator.get());
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobDetachedArrayBuffer) {
  const char* code =
      "var x = new Int16Array([12, 24, 48]);"
      "%ArrayBufferDetach(x.buffer);";
  Int32Expectations expectations = {std::make_tuple("x.buffer.byteLength", 0),
                                    std::make_tuple("x.length", 0)};

  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);

    v8::Local<v8::Value> x = CompileRun("x");
    CHECK(x->IsTypedArray());
    i::DirectHandle<i::JSTypedArray> array =
        i::Cast<i::JSTypedArray>(v8::Utils::OpenDirectHandle(*x));
    CHECK(array->WasDetached());
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

i::Handle<i::JSArrayBuffer> GetBufferFromTypedArray(
    v8::Local<v8::Value> typed_array) {
  CHECK(typed_array->IsTypedArray());

  i::DirectHandle<i::JSArrayBufferView> view =
      i::Cast<i::JSArrayBufferView>(v8::Utils::OpenDirectHandle(*typed_array));

  return i::handle(i::Cast<i::JSArrayBuffer>(view->buffer()),
                   view->GetIsolate());
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobOnOrOffHeapTypedArray) {
  const char* code =
      "var x = new Uint8Array(8);"
      "x[0] = 12;"
      "x[7] = 24;"
      "var y = new Int16Array([12, 24, 48]);"
      "var z = new Int32Array(64);"
      "z[0] = 96;";
  Int32Expectations expectations = {
      std::make_tuple("x[0]", 12), std::make_tuple("x[7]", 24),
      std::make_tuple("y[2]", 48), std::make_tuple("z[0]", 96)};

  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      TestInt32Expectations(expectations);
      i::DirectHandle<i::JSArrayBuffer> buffer =
          GetBufferFromTypedArray(CompileRun("x"));
      // The resulting buffer should be on-heap.
      CHECK(buffer->IsEmpty());
      creator.SetDefaultContext(
          context, v8::SerializeInternalFieldsCallback(
                       SerializeInternalFields, reinterpret_cast<void*>(2016)));
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(),
        v8::DeserializeInternalFieldsCallback(DeserializeInternalFields,
                                              reinterpret_cast<void*>(2017)));
    v8::Context::Scope c_scope(context);
    TestInt32Expectations(expectations);

    i::DirectHandle<i::JSArrayBuffer> buffer =
        GetBufferFromTypedArray(CompileRun("x"));
    // The resulting buffer should be on-heap.
    CHECK(buffer->IsEmpty());

    buffer = GetBufferFromTypedArray(CompileRun("y"));
    CHECK(buffer->IsEmpty());

    buffer = GetBufferFromTypedArray(CompileRun("z"));
    // The resulting buffer should be off-heap.
    CHECK(!buffer->IsEmpty());
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobTypedArrayNoEmbedderFieldCallback) {
  const char* code = "var x = new Uint8Array(8);";
  DisableAlwaysOpt();
  i::v8_flags.allow_natives_syntax = true;
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob;
  {
    SnapshotCreatorParams testing_params;
    v8::SnapshotCreator creator(testing_params.create_params);
    v8::Isolate* isolate = creator.GetIsolate();
    {
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);

      CompileRun(code);
      creator.SetDefaultContext(context, v8::SerializeInternalFieldsCallback());
    }
    blob =
        creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kClear);
  }

  v8::Isolate::CreateParams create_params;
  create_params.snapshot_blob = &blob;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = TestSerializer::NewIsolate(create_params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(
        isolate, nullptr, v8::MaybeLocal<v8::ObjectTemplate>(),
        v8::MaybeLocal<v8::Value>(), v8::DeserializeInternalFieldsCallback());
    v8::Context::Scope c_scope(context);
  }
  isolate->Dispose();
  delete[] blob.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlob2) {
  DisableAlwaysOpt();
  const char* source2 =
      "function f() { return g() * 2; }"
      "function g() { return 43; }"
      "/./.test('a')";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data2 = CreateSnapshotDataBlob(source2);

  v8::Isolate::CreateParams params2;
  params2.snapshot_blob = &data2;
  params2.array_buffer_allocator = CcTest::array_buffer_allocator();
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate2 = TestSerializer::NewIsolate(params2);
  {
    v8::Isolate::Scope i_scope(isolate2);
    v8::HandleScope h_scope(isolate2);
    v8::Local<v8::Context> context = v8::Context::New(isolate2);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("f()")->Int32Value(isolate2->GetCurrentContext());
    CHECK_EQ(86, result.FromJust());
    result = CompileRun("g()")->Int32Value(isolate2->GetCurrentContext());
    CHECK_EQ(43, result.FromJust());
  }
  isolate2->Dispose();
  delete[] data2.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

static void SerializationFunctionTemplate(
    const v8::FunctionCallbackInfo<v8::Value>& info) {
  CHECK(i::ValidateCallbackInfo(info));
  info.GetReturnValue().Set(info[0]);
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobOutdatedContextWithOverflow) {
  DisableAlwaysOpt();
  const char* source1 =
      "var o = {};"
      "(function() {"
      "  function f1(x) { return f2(x) instanceof Array; }"
      "  function f2(x) { return foo.bar(x); }"
      "  o.a = f2.bind(null);"
      "  o.b = 1;"
      "  o.c = 2;"
      "  o.d = 3;"
      "  o.e = 4;"
      "})();\n";

  const char* source2 = "o.a(42)";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);

    v8::Local<v8::ObjectTemplate> global = v8::ObjectTemplate::New(isolate);
    v8::Local<v8::ObjectTemplate> property = v8::ObjectTemplate::New(isolate);
    v8::Local<v8::FunctionTemplate> function =
        v8::FunctionTemplate::New(isolate, SerializationFunctionTemplate);
    property->Set(isolate, "bar", function);
    global->Set(isolate, "foo", property);

    v8::Local<v8::Context> context = v8::Context::New(isolate, nullptr, global);
    v8::Context::Scope c_scope(context);
    v8::Local<v8::Value> result = CompileRun(source2);
    v8::Maybe<bool> compare =
        v8_str("42")->Equals(isolate->GetCurrentContext(), result);
    CHECK(compare.FromJust());
  }
  isolate->Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithLocker) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate0 = v8::Isolate::New(create_params);
  {
    v8::Locker locker(isolate0);
    v8::Isolate::Scope i_scope(isolate0);
    v8::HandleScope h_scope(isolate0);
    v8::Local<v8::Context> context = v8::Context::New(isolate0);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result =
        CompileRun("Math.cos(0)")->Int32Value(isolate0->GetCurrentContext());
    CHECK_EQ(1, result.FromJust());
  }
  isolate0->Dispose();

  const char* source1 = "function f() { return 42; }";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data1 = CreateSnapshotDataBlob(source1);

  v8::Isolate::CreateParams params1;
  params1.snapshot_blob = &data1;
  params1.array_buffer_allocator = CcTest::array_buffer_allocator();
  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate1 = TestSerializer::NewIsolate(params1);
  {
    v8::Locker locker(isolate1);
    v8::Isolate::Scope i_scope(isolate1);
    v8::HandleScope h_scope(isolate1);
    v8::Local<v8::Context> context = v8::Context::New(isolate1);
    v8::Context::Scope c_scope(context);
    v8::Maybe<int32_t> result = CompileRun("f()")->Int32Value(context);
    CHECK_EQ(42, result.FromJust());
  }
  isolate1->Dispose();
  delete[] data1.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobStackOverflow) {
  DisableAlwaysOpt();
  const char* source =
      "var a = [0];"
      "var b = a;"
      "for (var i = 0; i < 10000; i++) {"
      "  var c = [i];"
      "  b.push(c);"
      "  b.push(c);"
      "  b = c;"
      "}";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source);

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    const char* test =
        "var sum = 0;"
        "while (a) {"
        "  sum += a[0];"
        "  a = a[1];"
        "}"
        "sum";
    v8::Maybe<int32_t> result =
        CompileRun(test)->Int32Value(isolate->GetCurrentContext());
    CHECK_EQ(9999 * 5000, result.FromJust());
  }
  isolate->Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

bool IsCompiled(const char* name) {
  return i::Cast<i::JSFunction>(v8::Utils::OpenHandle(*CompileRun(name)))
      ->shared()
      ->is_compiled();
}

UNINITIALIZED_TEST(SnapshotDataBlobWithWarmup) {
  DisableAlwaysOpt();
  const char* warmup = "Math.abs(1); Math.random = 1;";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData cold = CreateSnapshotDataBlob(nullptr);
  v8::StartupData warm = WarmUpSnapshotDataBlobInternal(cold, warmup);
  delete[] cold.data;

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &warm;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    // Running the warmup script has effect on whether functions are
    // pre-compiled, but does not pollute the context.
    CHECK(IsCompiled("Math.abs"));
    CHECK(IsCompiled("String.raw"));
    CHECK(CompileRun("Math.random")->IsFunction());
  }
  isolate->Dispose();
  delete[] warm.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithWarmup) {
  DisableAlwaysOpt();
  const char* source =
      "function f() { return Math.abs(1); }\n"
      "function g() { return String.raw(1); }\n"
      "Object.valueOf(1);"
      "var a = 5";
  const char* warmup = "a = f()";

  DisableEmbeddedBlobRefcounting();
  v8::StartupData cold = CreateSnapshotDataBlob(source);
  v8::StartupData warm = WarmUpSnapshotDataBlobInternal(cold, warmup);
  delete[] cold.data;

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &warm;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    // Running the warmup script has effect on whether functions are
    // pre-compiled, but does not pollute the context.
    CHECK(IsCompiled("f"));
    CHECK(IsCompiled("Math.abs"));
    CHECK(!IsCompiled("g"));
    CHECK(IsCompiled("String.raw"));
    CHECK(IsCompiled("Array.prototype.lastIndexOf"));
    CHECK_EQ(5, CompileRun("a")->Int32Value(context).FromJust());
  }
  isolate->Dispose();
  delete[] warm.data;
  FreeCurrentEmbeddedBlob();
}

namespace {
v8::StartupData CreateCustomSnapshotWithKeep() {
  SnapshotCreatorParams testing_params;
  v8::SnapshotCreator creator(testing_params.create_params);
  v8::Isolate* isolate = creator.GetIsolate();
  {
    v8::HandleScope handle_scope(isolate);
    {
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      v8::Local<v8::String> source_str = v8_str(
          "function f() { return Math.abs(1); }\n"
          "function g() { return String.raw(1); }");
      v8::ScriptOrigin origin(v8_str("test"));
      v8::ScriptCompiler::Source source(source_str, origin);
      CompileRun(isolate->GetCurrentContext(), &source,
                 v8::ScriptCompiler::kEagerCompile);
      creator.SetDefaultContext(context);
    }
  }
  return creator.CreateBlob(v8::SnapshotCreator::FunctionCodeHandling::kKeep);
}
}  // namespace

UNINITIALIZED_TEST(CustomSnapshotDataBlobWithKeep) {
  DisableAlwaysOpt();
  DisableEmbeddedBlobRefcounting();
  v8::StartupData blob = CreateCustomSnapshotWithKeep();

  {
    v8::Isolate::CreateParams params;
    params.snapshot_blob = &blob;
    params.array_buffer_allocator = CcTest::array_buffer_allocator();
    // Test-appropriate equivalent of v8::Isolate::New.
    v8::Isolate* isolate = TestSerializer::NewIsolate(params);
    {
      v8::Isolate::Scope isolate_scope(isolate);
      v8::HandleScope handle_scope(isolate);
      v8::Local<v8::Context> context = v8::Context::New(isolate);
      v8::Context::Scope context_scope(context);
      CHECK(IsCompiled("f"));
      CHECK(IsCompiled("g"));
    }
    isolate->Dispose();
  }
  delete[] blob.data;
  FreeCurrentEmbeddedBlob();
}

UNINITIALIZED_TEST(CustomSnapshotDataBlobImmortalImmovableRoots) {
  DisableAlwaysOpt();
  // Flood the startup snapshot with shared function infos. If they are
  // serialized before the immortal immovable root, the root will no longer end
  // up on the first page.
  base::Vector<const char> source =
      ConstructSource(base::StaticCharVector("var a = [];"),
                      base::StaticCharVector("a.push(function() {return 7});"),
                      base::StaticCharVector("\0"), 10000);

  DisableEmbeddedBlobRefcounting();
  v8::StartupData data = CreateSnapshotDataBlob(source.begin());

  v8::Isolate::CreateParams params;
  params.snapshot_blob = &data;
  params.array_buffer_allocator = CcTest::array_buffer_allocator();

  // Test-appropriate equivalent of v8::Isolate::New.
  v8::Isolate* isolate = TestSerializer::NewIsolate(params);
  {
    v8::Isolate::Scope i_scope(isolate);
    v8::HandleScope h_scope(isolate);
    v8::Local<v8::Context> context = v8::Context::New(isolate);
    v8::Context::Scope c_scope(context);
    CHECK_EQ(7, CompileRun("a[0]()")->Int32Value(context).FromJust());
  }
  isolate->Dispose();
  source.Dispose();
  delete[] data.data;  // We can dispose of the snapshot blob now.
  FreeCurrentEmbeddedBlob();
}

TEST(TestThatAlwaysSucceeds) {}

TEST(TestCheckThatAlwaysFails) {
  bool ArtificialFailure = false;
  CHECK(ArtificialFailure);
}

TEST(TestFatal) { GRACEFUL_FATAL("fatal"); }

int CountBuiltins() {
  // Check that we have not deserialized any additional builtin.
  HeapObjectIterator iterator(CcTest::heap());
  DisallowGarbageCollection no_gc;
  int counter = 0;
  for (Tagged<HeapObject> obj = iterator.Next(); !obj.is_null();
       obj = iterator.Next()) {
    if (IsCode(obj) && Cast<Code>(obj)->kind() == CodeKind::BUILTIN) counter++;
  }
  return counter;
}

static DirectHandle<SharedFunctionInfo> CompileScript(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, AlignedCachedData* cached_data,
    v8::ScriptCompiler::CompileOptions options,
    ScriptCompiler::InMemoryCacheResult expected_lookup_result =
        ScriptCompiler::InMemoryCacheResult::kMiss) {
  ScriptCompiler::CompilationDetails compilation_details;
  auto result = Compiler::GetSharedFunctionInfoForScriptWithCachedData(
                    isolate, source, script_details, cached_data, options,
                    ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE,
                    &compilation_details)
                    .ToHandleChecked();
  CHECK_EQ(compilation_details.in_memory_cache_result, expected_lookup_result);
  return result;
}

static DirectHandle<SharedFunctionInfo> CompileScriptAndProduceCache(
    Isolate* isolate, Handle<String> source,
    const ScriptDetails& script_details, AlignedCachedData** out_cached_data,
    v8::ScriptCompiler::CompileOptions options,
    ScriptCompiler::InMemoryCacheResult expected_lookup_result =
        ScriptCompiler::InMemoryCacheResult::kMiss) {
  ScriptCompiler::CompilationDetails compilation_details;
  DirectHandle<SharedFunctionInfo> sfi =
      Compiler::GetSharedFunctionInfoForScript(
          isolate, source, script_details, options,
          ScriptCompiler::kNoCacheNoReason, NOT_NATIVES_CODE,
          &compilation_details)
          .ToHandleChecked();
  CHECK_EQ(compilation_details.in_memory_cache_result, expected_lookup_result);
  std::unique_ptr<ScriptCompiler::CachedData> cached_data(
      ScriptCompiler::CreateCodeCache(ToApiHandle<UnboundScript>(sfi)));
  uint8_t* buffer = NewArray<uint8_t>(cached_data->length);
  MemCopy(buffer, cached_data->data, cached_data->length);
  *out_cached_data = new i::AlignedCachedData(buffer, cached_data->length);
  (*out_cached_data)->AcquireDataOwnership();
  return sfi;
}


"""


```
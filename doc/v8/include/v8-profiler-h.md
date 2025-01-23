Response:
The user is asking for a summary of the functionalities provided by the C++ header file `v8-profiler.h`.

Here's a breakdown of the thought process to arrive at the summarized answer:

1. **Identify the File's Purpose:** The comment at the beginning clearly states "Profiler support for the V8 JavaScript engine." This is the core function of the header.

2. **Scan for Major Components:** Look for classes and structs that define key concepts within the profiler. Keywords like `class`, `struct`, and `enum` are good indicators. The header defines:
    * `CpuProfileNode`: Represents a node in a CPU profile call graph.
    * `CpuProfile`: Represents a CPU profile.
    * `CpuProfiler`:  The main interface for controlling CPU profiling.
    * `HeapGraphEdge`: Represents an edge in a heap graph.
    * `HeapGraphNode`: Represents a node in a heap graph.
    * `HeapSnapshot`: Represents a snapshot of the heap.
    * `AllocationProfile`: Represents a profile of allocations.
    * `EmbedderGraph`:  Allows embedding information into heap snapshots.
    * `HeapProfiler`:  The main interface for controlling heap profiling.

3. **Analyze Each Component's Functionality:** Go through each identified class and struct and summarize its purpose based on its member functions and data members. For example:
    * `CpuProfileNode`:  Focus on methods like `GetFunctionName`, `GetScriptId`, `GetHitCount`, `GetChildrenCount`, etc. These clearly relate to information about a single function call within the profile.
    * `CpuProfile`: Focus on methods like `GetTitle`, `GetTopDownRoot`, `GetSamplesCount`, `Serialize`, etc. These relate to the overall CPU profile and its data.
    * `CpuProfiler`: Focus on methods like `Start`, `Stop`, `SetSamplingInterval`, etc. These are the actions a user would take to control CPU profiling.
    * Similarly, analyze `HeapGraphEdge`, `HeapGraphNode`, `HeapSnapshot`, `AllocationProfile`, `EmbedderGraph`, and `HeapProfiler`.

4. **Look for Enums and Helper Structures:** Note down important enums and structs that support the main classes. Examples include:
    * `CpuProfileNode::SourceType`:  Categorizes the origin of a profiled function.
    * `CpuProfile::SerializationFormat`: Defines how the profile can be serialized.
    * `CpuProfilingMode`:  Controls how line numbers are represented in the CPU profile.
    * `HeapGraphEdge::Type`:  Categorizes the type of connection between heap objects.
    * `HeapGraphNode::Type`: Categorizes the type of heap object.
    * `HeapSnapshot::SerializationFormat`: Defines how the heap snapshot can be serialized.

5. **Identify Core Profiling Types:** Distinguish between CPU profiling and Heap profiling as the two main capabilities.

6. **Note Key Features of Each Profiling Type:**
    * **CPU Profiling:** Focus on call graphs, sampling, function information, deoptimization information.
    * **Heap Profiling:** Focus on object graphs, object types, sizes, retainers, snapshots, allocation tracking.

7. **Address Specific Instructions:**  Go back to the prompt and address each specific instruction:
    * ".tq extension":  Point out that this header doesn't have that extension.
    * Relationship to JavaScript: Explain how the profiler helps understand JavaScript execution and memory usage. Provide a simple conceptual JavaScript example.
    * Code Logic/Assumptions:  Since the header is a definition file and doesn't contain logic, explain that this section isn't applicable but mention the underlying mechanisms (sampling, instrumentation) conceptually.
    * Common Programming Errors: Focus on errors related to performance and memory leaks, as these are what profilers help identify. Provide illustrative JavaScript examples.

8. **Synthesize a Summary:** Combine the analysis into a concise summary of the header's functionalities, covering both CPU and Heap profiling.

9. **Review and Refine:** Ensure the summary is accurate, easy to understand, and covers the main points. Check for clarity and conciseness. Make sure it aligns with the "Part 1" instruction and prepares for a potential "Part 2".

By following these steps, we can systematically dissect the header file and provide a comprehensive and accurate summary of its functionality.
```javascript
// 假设我们有如下一段 JavaScript 代码

function outerFunction() {
  let a = 1;
  innerFunction();
}

function innerFunction() {
  let b = 2;
  console.log(a + b); // 这里会报错，因为 a 在 innerFunction 的作用域外
}

outerFunction();

// 常见错误：在 innerFunction 中访问了 outerFunction 的局部变量 a，导致 ReferenceError。
```

## v8/include/v8-profiler.h 功能归纳 (第 1 部分)

`v8/include/v8-profiler.h` 是 V8 JavaScript 引擎中用于提供 **性能分析** 功能的 C++ 头文件。它定义了用于收集和分析 CPU 使用情况和内存分配情况的接口和数据结构。

**主要功能可以归纳为以下几点：**

1. **CPU 性能分析 (CPU Profiling):**
   - **记录函数调用关系:**  通过采样的方式记录程序执行期间的函数调用栈，构建一个 **调用图 (Call Graph)**。
   - **统计函数执行时间:** 记录每个函数被采样到的次数，从而推断其执行时间占比。
   - **提供源代码信息:**  关联调用图节点到具体的 JavaScript 源代码位置（脚本 ID、行号、列号）。
   - **支持去优化信息:** 记录函数被去优化的原因和发生的位置。
   - **多种采样模式:**  允许配置不同的采样模式，例如基于叶子节点或调用者行号来区分调用栈。
   - **灵活的启动和停止:**  提供启动和停止 CPU 性能分析的接口，可以指定标题、采样选项等。
   - **数据导出:**  可以将收集到的 CPU 性能数据导出为 JSON 等格式，方便后续分析。

2. **内存分配分析 (Heap Profiling):**
   - **创建堆快照 (Heap Snapshot):**  在特定时间点捕获 JavaScript 堆的内存状态，包括对象、对象之间的引用关系、对象大小等信息。
   - **构建对象图 (Object Graph):**  将堆快照中的对象和它们之间的引用关系组织成一个有向图。
   - **提供对象信息:**  获取堆快照中每个对象的类型、名称、大小、ID 等信息。
   - **查找对象引用关系:**  可以查找某个对象被哪些对象引用，以及它引用了哪些对象。
   - **支持嵌入器对象:**  允许将 V8 引擎外部的 C++ 对象也纳入到堆快照中。
   - **数据导出:**  可以将堆快照数据导出为 JSON 等格式。
   - **分配追踪 (Allocation Tracking):**  通过采样的方式记录对象的分配信息，构建 **分配图 (Allocation Graph)**，显示哪些函数调用导致了哪些对象的分配。

3. **通用接口和数据结构:**
   - **`OutputStream`:**  一个抽象接口，用于将性能分析数据以流的形式输出。
   - **`CpuProfileNode`:**  表示 CPU 调用图中的一个节点，包含函数信息和子节点。
   - **`CpuProfile`:**  表示一个完整的 CPU 性能分析结果，包含调用图、采样数据等。
   - **`HeapGraphEdge`:**  表示堆对象图中的一条边，即对象之间的引用关系。
   - **`HeapGraphNode`:**  表示堆对象图中的一个节点，即一个 JavaScript 对象。
   - **`HeapSnapshot`:**  表示一个 JavaScript 堆快照。
   - **`AllocationProfile`:** 表示一个内存分配分析结果。
   - **`EmbedderGraph`:** 用于在堆快照中表示嵌入器 (V8 引擎外部) 的对象及其引用关系。

**关于 v8/include/v8-profiler.h 的特性：**

- **不是 Torque 代码:**  文件名以 `.h` 结尾，表明它是一个 C++ 头文件，而不是以 `.tq` 结尾的 V8 Torque 源代码。
- **与 JavaScript 功能密切相关:**  该头文件提供的功能直接服务于分析 JavaScript 代码的性能和内存使用情况。

**代码逻辑推理 (假设):**

由于是头文件，主要定义接口，实际的逻辑实现在 `.cc` 文件中。但可以进行一些假设性的输入输出推理：

**假设输入 (CPU Profiling):**

- 启动 CPU Profiler，开始记录一段时间的 JavaScript 代码执行。
- JavaScript 代码中包含多个函数调用，部分函数可能被 JIT 优化，后续可能发生去优化。

**假设输出 (CPU Profiling):**

- 一个 `CpuProfile` 对象，其中包含：
    - 一个以 `CpuProfileNode` 组成的调用树，反映了函数调用关系和执行路径。
    - 每个 `CpuProfileNode` 包含函数名、脚本 ID、行号、被采样次数等信息。
    - 如果发生了去优化，相关的 `CpuProfileNode` 会包含 `CpuProfileDeoptInfo`，描述去优化原因和堆栈信息。
    - 如果启用了采样记录，则会包含一个样本列表，每个样本指向调用树中的一个节点。

**假设输入 (Heap Profiling):**

- 触发一个堆快照。
- JavaScript 代码中创建了多个不同类型的对象 (例如，普通对象、数组、字符串)。
- 对象之间存在引用关系。

**假设输出 (Heap Profiling):**

- 一个 `HeapSnapshot` 对象，其中包含：
    - 一个以 `HeapGraphNode` 组成的对象图，表示堆中的对象。
    - 每个 `HeapGraphNode` 包含对象类型、大小、ID 等信息。
    - 对象之间的引用关系由 `HeapGraphEdge` 表示。

**总结:**

`v8/include/v8-profiler.h` 定义了 V8 引擎的性能分析接口，主要用于收集和分析 CPU 使用情况和内存分配情况。它提供了用于 CPU 性能分析 (通过采样记录函数调用栈) 和内存分配分析 (通过堆快照和分配追踪) 的核心数据结构和接口，帮助开发者理解和优化 JavaScript 代码的性能和内存使用。

### 提示词
```
这是目录为v8/include/v8-profiler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-profiler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2010 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_V8_PROFILER_H_
#define V8_V8_PROFILER_H_

#include <limits.h>

#include <memory>
#include <unordered_set>
#include <vector>

#include "cppgc/common.h"          // NOLINT(build/include_directory)
#include "v8-local-handle.h"       // NOLINT(build/include_directory)
#include "v8-message.h"            // NOLINT(build/include_directory)
#include "v8-persistent-handle.h"  // NOLINT(build/include_directory)

/**
 * Profiler support for the V8 JavaScript engine.
 */
namespace v8 {

enum class EmbedderStateTag : uint8_t;
class HeapGraphNode;
struct HeapStatsUpdate;
class Object;
enum StateTag : uint16_t;

using NativeObject = void*;
using SnapshotObjectId = uint32_t;
using ProfilerId = uint32_t;

struct CpuProfileDeoptFrame {
  int script_id;
  size_t position;
};

namespace internal {
class CpuProfile;
}  // namespace internal

}  // namespace v8

#ifdef V8_OS_WIN
template class V8_EXPORT std::vector<v8::CpuProfileDeoptFrame>;
#endif

namespace v8 {

struct V8_EXPORT CpuProfileDeoptInfo {
  /** A pointer to a static string owned by v8. */
  const char* deopt_reason;
  std::vector<CpuProfileDeoptFrame> stack;
};

}  // namespace v8

#ifdef V8_OS_WIN
template class V8_EXPORT std::vector<v8::CpuProfileDeoptInfo>;
#endif

namespace v8 {

/**
 * CpuProfileNode represents a node in a call graph.
 */
class V8_EXPORT CpuProfileNode {
 public:
  struct LineTick {
    /** The 1-based number of the source line where the function originates. */
    int line;

    /** The count of samples associated with the source line. */
    unsigned int hit_count;
  };

  // An annotation hinting at the source of a CpuProfileNode.
  enum SourceType {
    // User-supplied script with associated resource information.
    kScript = 0,
    // Native scripts and provided builtins.
    kBuiltin = 1,
    // Callbacks into native code.
    kCallback = 2,
    // VM-internal functions or state.
    kInternal = 3,
    // A node that failed to symbolize.
    kUnresolved = 4,
  };

  /** Returns function name (empty string for anonymous functions.) */
  Local<String> GetFunctionName() const;

  /**
   * Returns function name (empty string for anonymous functions.)
   * The string ownership is *not* passed to the caller. It stays valid until
   * profile is deleted. The function is thread safe.
   */
  const char* GetFunctionNameStr() const;

  /** Returns id of the script where function is located. */
  int GetScriptId() const;

  /** Returns resource name for script from where the function originates. */
  Local<String> GetScriptResourceName() const;

  /**
   * Returns resource name for script from where the function originates.
   * The string ownership is *not* passed to the caller. It stays valid until
   * profile is deleted. The function is thread safe.
   */
  const char* GetScriptResourceNameStr() const;

  /**
   * Return true if the script from where the function originates is flagged as
   * being shared cross-origin.
   */
  bool IsScriptSharedCrossOrigin() const;

  /**
   * Returns the number, 1-based, of the line where the function originates.
   * kNoLineNumberInfo if no line number information is available.
   */
  int GetLineNumber() const;

  /**
   * Returns 1-based number of the column where the function originates.
   * kNoColumnNumberInfo if no column number information is available.
   */
  int GetColumnNumber() const;

  /**
   * Returns the number of the function's source lines that collect the samples.
   */
  unsigned int GetHitLineCount() const;

  /** Returns the set of source lines that collect the samples.
   *  The caller allocates buffer and responsible for releasing it.
   *  True if all available entries are copied, otherwise false.
   *  The function copies nothing if buffer is not large enough.
   */
  bool GetLineTicks(LineTick* entries, unsigned int length) const;

  /** Returns bailout reason for the function
    * if the optimization was disabled for it.
    */
  const char* GetBailoutReason() const;

  /**
    * Returns the count of samples where the function was currently executing.
    */
  unsigned GetHitCount() const;

  /** Returns id of the node. The id is unique within the tree */
  unsigned GetNodeId() const;

  /**
   * Gets the type of the source which the node was captured from.
   */
  SourceType GetSourceType() const;

  /** Returns child nodes count of the node. */
  int GetChildrenCount() const;

  /** Retrieves a child node by index. */
  const CpuProfileNode* GetChild(int index) const;

  /** Retrieves the ancestor node, or null if the root. */
  const CpuProfileNode* GetParent() const;

  /** Retrieves deopt infos for the node. */
  const std::vector<CpuProfileDeoptInfo>& GetDeoptInfos() const;

  static const int kNoLineNumberInfo = Message::kNoLineNumberInfo;
  static const int kNoColumnNumberInfo = Message::kNoColumnInfo;
};

/**
 * An interface for exporting data from V8, using "push" model.
 */
class V8_EXPORT OutputStream {
 public:
  enum WriteResult { kContinue = 0, kAbort = 1 };
  virtual ~OutputStream() = default;
  /** Notify about the end of stream. */
  virtual void EndOfStream() = 0;
  /** Get preferred output chunk size. Called only once. */
  virtual int GetChunkSize() { return 1024; }
  /**
   * Writes the next chunk of snapshot data into the stream. Writing
   * can be stopped by returning kAbort as function result. EndOfStream
   * will not be called in case writing was aborted.
   */
  virtual WriteResult WriteAsciiChunk(char* data, int size) = 0;
  /**
   * Writes the next chunk of heap stats data into the stream. Writing
   * can be stopped by returning kAbort as function result. EndOfStream
   * will not be called in case writing was aborted.
   */
  virtual WriteResult WriteHeapStatsChunk(HeapStatsUpdate* data, int count) {
    return kAbort;
  }
};

/**
 * CpuProfile contains a CPU profile in a form of top-down call tree
 * (from main() down to functions that do all the work).
 */
class V8_EXPORT CpuProfile {
 public:
  enum SerializationFormat {
    kJSON = 0  // See format description near 'Serialize' method.
  };
  /** Returns CPU profile title. */
  Local<String> GetTitle() const;

  /** Returns the root node of the top down call tree. */
  const CpuProfileNode* GetTopDownRoot() const;

  /**
   * Returns number of samples recorded. The samples are not recorded unless
   * |record_samples| parameter of CpuProfiler::StartCpuProfiling is true.
   */
  int GetSamplesCount() const;

  /**
   * Returns profile node corresponding to the top frame the sample at
   * the given index.
   */
  const CpuProfileNode* GetSample(int index) const;

  /**
   * Returns the timestamp of the sample. The timestamp is the number of
   * microseconds since some unspecified starting point.
   * The point is equal to the starting point used by GetStartTime.
   */
  int64_t GetSampleTimestamp(int index) const;

  /**
   * Returns time when the profile recording was started (in microseconds)
   * since some unspecified starting point.
   */
  int64_t GetStartTime() const;

  /**
   * Returns state of the vm when sample was captured.
   */
  StateTag GetSampleState(int index) const;

  /**
   * Returns state of the embedder when sample was captured.
   */
  EmbedderStateTag GetSampleEmbedderState(int index) const;

  /**
   * Returns time when the profile recording was stopped (in microseconds)
   * since some unspecified starting point.
   * The point is equal to the starting point used by GetStartTime.
   */
  int64_t GetEndTime() const;

  /**
   * Deletes the profile and removes it from CpuProfiler's list.
   * All pointers to nodes previously returned become invalid.
   */
  void Delete();

  /**
   * Prepare a serialized representation of the profile. The result
   * is written into the stream provided in chunks of specified size.
   *
   * For the JSON format, heap contents are represented as an object
   * with the following structure:
   *
   *  {
   *    nodes: [nodes array],
   *    startTime: number,
   *    endTime: number
   *    samples: [strings array]
   *    timeDeltas: [numbers array]
   *  }
   *
   */
  void Serialize(OutputStream* stream,
                 SerializationFormat format = kJSON) const;
};

enum CpuProfilingMode {
  // In the resulting CpuProfile tree, intermediate nodes in a stack trace
  // (from the root to a leaf) will have line numbers that point to the start
  // line of the function, rather than the line of the callsite of the child.
  kLeafNodeLineNumbers,
  // In the resulting CpuProfile tree, nodes are separated based on the line
  // number of their callsite in their parent.
  kCallerLineNumbers,
};

// Determines how names are derived for functions sampled.
enum CpuProfilingNamingMode {
  // Use the immediate name of functions at compilation time.
  kStandardNaming,
  // Use more verbose naming for functions without names, inferred from scope
  // where possible.
  kDebugNaming,
};

enum CpuProfilingLoggingMode {
  // Enables logging when a profile is active, and disables logging when all
  // profiles are detached.
  kLazyLogging,
  // Enables logging for the lifetime of the CpuProfiler. Calls to
  // StartRecording are faster, at the expense of runtime overhead.
  kEagerLogging,
};

// Enum for returning profiling status. Once StartProfiling is called,
// we want to return to clients whether the profiling was able to start
// correctly, or return a descriptive error.
enum class CpuProfilingStatus {
  kStarted,
  kAlreadyStarted,
  kErrorTooManyProfilers
};

/**
 * Result from StartProfiling returning the Profiling Status, and
 * id of the started profiler, or 0 if profiler is not started
 */
struct CpuProfilingResult {
  const ProfilerId id;
  const CpuProfilingStatus status;
};

/**
 * Delegate for when max samples reached and samples are discarded.
 */
class V8_EXPORT DiscardedSamplesDelegate {
 public:
  DiscardedSamplesDelegate() = default;

  virtual ~DiscardedSamplesDelegate() = default;
  virtual void Notify() = 0;

  ProfilerId GetId() const { return profiler_id_; }

 private:
  friend internal::CpuProfile;

  void SetId(ProfilerId id) { profiler_id_ = id; }

  ProfilerId profiler_id_;
};

/**
 * Optional profiling attributes.
 */
class V8_EXPORT CpuProfilingOptions {
 public:
  // Indicates that the sample buffer size should not be explicitly limited.
  static const unsigned kNoSampleLimit = UINT_MAX;

  /**
   * \param mode Type of computation of stack frame line numbers.
   * \param max_samples The maximum number of samples that should be recorded by
   *                    the profiler. Samples obtained after this limit will be
   *                    discarded.
   * \param sampling_interval_us controls the profile-specific target
   *                             sampling interval. The provided sampling
   *                             interval will be snapped to the next lowest
   *                             non-zero multiple of the profiler's sampling
   *                             interval, set via SetSamplingInterval(). If
   *                             zero, the sampling interval will be equal to
   *                             the profiler's sampling interval.
   * \param filter_context If specified, profiles will only contain frames
   *                       using this context. Other frames will be elided.
   */
  CpuProfilingOptions(
      CpuProfilingMode mode = kLeafNodeLineNumbers,
      unsigned max_samples = kNoSampleLimit, int sampling_interval_us = 0,
      MaybeLocal<Context> filter_context = MaybeLocal<Context>());

  CpuProfilingOptions(CpuProfilingOptions&&) = default;
  CpuProfilingOptions& operator=(CpuProfilingOptions&&) = default;

  CpuProfilingMode mode() const { return mode_; }
  unsigned max_samples() const { return max_samples_; }
  int sampling_interval_us() const { return sampling_interval_us_; }

 private:
  friend class internal::CpuProfile;

  bool has_filter_context() const { return !filter_context_.IsEmpty(); }
  void* raw_filter_context() const;

  CpuProfilingMode mode_;
  unsigned max_samples_;
  int sampling_interval_us_;
  Global<Context> filter_context_;
};

/**
 * Interface for controlling CPU profiling. Instance of the
 * profiler can be created using v8::CpuProfiler::New method.
 */
class V8_EXPORT CpuProfiler {
 public:
  /**
   * Creates a new CPU profiler for the |isolate|. The isolate must be
   * initialized. The profiler object must be disposed after use by calling
   * |Dispose| method.
   */
  static CpuProfiler* New(Isolate* isolate,
                          CpuProfilingNamingMode = kDebugNaming,
                          CpuProfilingLoggingMode = kLazyLogging);

  /**
   * Synchronously collect current stack sample in all profilers attached to
   * the |isolate|. The call does not affect number of ticks recorded for
   * the current top node.
   */
  static void CollectSample(Isolate* isolate);

  /**
   * Disposes the CPU profiler object.
   */
  void Dispose();

  /**
   * Changes default CPU profiler sampling interval to the specified number
   * of microseconds. Default interval is 1000us. This method must be called
   * when there are no profiles being recorded.
   */
  void SetSamplingInterval(int us);

  /**
   * Sets whether or not the profiler should prioritize consistency of sample
   * periodicity on Windows. Disabling this can greatly reduce CPU usage, but
   * may result in greater variance in sample timings from the platform's
   * scheduler. Defaults to enabled. This method must be called when there are
   * no profiles being recorded.
   */
  void SetUsePreciseSampling(bool);

  /**
   * Starts collecting a CPU profile. Several profiles may be collected at once.
   * Generates an anonymous profiler, without a String identifier.
   */
  CpuProfilingResult Start(
      CpuProfilingOptions options,
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);

  /**
   * Starts collecting a CPU profile. Title may be an empty string. Several
   * profiles may be collected at once. Attempts to start collecting several
   * profiles with the same title are silently ignored.
   */
  CpuProfilingResult Start(
      Local<String> title, CpuProfilingOptions options,
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);

  /**
   * Starts profiling with the same semantics as above, except with expanded
   * parameters.
   *
   * |record_samples| parameter controls whether individual samples should
   * be recorded in addition to the aggregated tree.
   *
   * |max_samples| controls the maximum number of samples that should be
   * recorded by the profiler. Samples obtained after this limit will be
   * discarded.
   */
  CpuProfilingResult Start(
      Local<String> title, CpuProfilingMode mode, bool record_samples = false,
      unsigned max_samples = CpuProfilingOptions::kNoSampleLimit);

  /**
   * The same as StartProfiling above, but the CpuProfilingMode defaults to
   * kLeafNodeLineNumbers mode, which was the previous default behavior of the
   * profiler.
   */
  CpuProfilingResult Start(Local<String> title, bool record_samples = false);

  /**
   * Starts collecting a CPU profile. Title may be an empty string. Several
   * profiles may be collected at once. Attempts to start collecting several
   * profiles with the same title are silently ignored.
   */
  CpuProfilingStatus StartProfiling(
      Local<String> title, CpuProfilingOptions options,
      std::unique_ptr<DiscardedSamplesDelegate> delegate = nullptr);

  /**
   * Starts profiling with the same semantics as above, except with expanded
   * parameters.
   *
   * |record_samples| parameter controls whether individual samples should
   * be recorded in addition to the aggregated tree.
   *
   * |max_samples| controls the maximum number of samples that should be
   * recorded by the profiler. Samples obtained after this limit will be
   * discarded.
   */
  CpuProfilingStatus StartProfiling(
      Local<String> title, CpuProfilingMode mode, bool record_samples = false,
      unsigned max_samples = CpuProfilingOptions::kNoSampleLimit);

  /**
   * The same as StartProfiling above, but the CpuProfilingMode defaults to
   * kLeafNodeLineNumbers mode, which was the previous default behavior of the
   * profiler.
   */
  CpuProfilingStatus StartProfiling(Local<String> title,
                                    bool record_samples = false);

  /**
   * Stops collecting CPU profile with a given id and returns it.
   */
  CpuProfile* Stop(ProfilerId id);

  /**
   * Stops collecting CPU profile with a given title and returns it.
   * If the title given is empty, finishes the last profile started.
   */
  CpuProfile* StopProfiling(Local<String> title);

  /**
   * Generate more detailed source positions to code objects. This results in
   * better results when mapping profiling samples to script source.
   */
  static void UseDetailedSourcePositionsForProfiling(Isolate* isolate);

 private:
  CpuProfiler();
  ~CpuProfiler();
  CpuProfiler(const CpuProfiler&);
  CpuProfiler& operator=(const CpuProfiler&);
};

/**
 * HeapSnapshotEdge represents a directed connection between heap
 * graph nodes: from retainers to retained nodes.
 */
class V8_EXPORT HeapGraphEdge {
 public:
  enum Type {
    kContextVariable = 0,  // A variable from a function context.
    kElement = 1,          // An element of an array.
    kProperty = 2,         // A named object property.
    kInternal = 3,         // A link that can't be accessed from JS,
                           // thus, its name isn't a real property name
                           // (e.g. parts of a ConsString).
    kHidden = 4,           // A link that is needed for proper sizes
                           // calculation, but may be hidden from user.
    kShortcut = 5,         // A link that must not be followed during
                           // sizes calculation.
    kWeak = 6              // A weak reference (ignored by the GC).
  };

  /** Returns edge type (see HeapGraphEdge::Type). */
  Type GetType() const;

  /**
   * Returns edge name. This can be a variable name, an element index, or
   * a property name.
   */
  Local<Value> GetName() const;

  /** Returns origin node. */
  const HeapGraphNode* GetFromNode() const;

  /** Returns destination node. */
  const HeapGraphNode* GetToNode() const;
};


/**
 * HeapGraphNode represents a node in a heap graph.
 */
class V8_EXPORT HeapGraphNode {
 public:
  enum Type {
    kHidden = 0,         // Hidden node, may be filtered when shown to user.
    kArray = 1,          // An array of elements.
    kString = 2,         // A string.
    kObject = 3,         // A JS object (except for arrays and strings).
    kCode = 4,           // Compiled code.
    kClosure = 5,        // Function closure.
    kRegExp = 6,         // RegExp.
    kHeapNumber = 7,     // Number stored in the heap.
    kNative = 8,         // Native object (not from V8 heap).
    kSynthetic = 9,      // Synthetic object, usually used for grouping
                         // snapshot items together.
    kConsString = 10,    // Concatenated string. A pair of pointers to strings.
    kSlicedString = 11,  // Sliced string. A fragment of another string.
    kSymbol = 12,        // A Symbol (ES6).
    kBigInt = 13,        // BigInt.
    kObjectShape = 14,   // Internal data used for tracking the shapes (or
                         // "hidden classes") of JS objects.
  };

  /** Returns node type (see HeapGraphNode::Type). */
  Type GetType() const;

  /**
   * Returns node name. Depending on node's type this can be the name
   * of the constructor (for objects), the name of the function (for
   * closures), string value, or an empty string (for compiled code).
   */
  Local<String> GetName() const;

  /**
   * Returns node id. For the same heap object, the id remains the same
   * across all snapshots.
   */
  SnapshotObjectId GetId() const;

  /** Returns node's own size, in bytes. */
  size_t GetShallowSize() const;

  /** Returns child nodes count of the node. */
  int GetChildrenCount() const;

  /** Retrieves a child by index. */
  const HeapGraphEdge* GetChild(int index) const;
};

/**
 * HeapSnapshots record the state of the JS heap at some moment.
 */
class V8_EXPORT HeapSnapshot {
 public:
  enum SerializationFormat {
    kJSON = 0  // See format description near 'Serialize' method.
  };

  /** Returns the root node of the heap graph. */
  const HeapGraphNode* GetRoot() const;

  /** Returns a node by its id. */
  const HeapGraphNode* GetNodeById(SnapshotObjectId id) const;

  /** Returns total nodes count in the snapshot. */
  int GetNodesCount() const;

  /** Returns a node by index. */
  const HeapGraphNode* GetNode(int index) const;

  /** Returns a max seen JS object Id. */
  SnapshotObjectId GetMaxSnapshotJSObjectId() const;

  /**
   * Deletes the snapshot and removes it from HeapProfiler's list.
   * All pointers to nodes, edges and paths previously returned become
   * invalid.
   */
  void Delete();

  /**
   * Prepare a serialized representation of the snapshot. The result
   * is written into the stream provided in chunks of specified size.
   * The total length of the serialized snapshot is unknown in
   * advance, it can be roughly equal to JS heap size (that means,
   * it can be really big - tens of megabytes).
   *
   * For the JSON format, heap contents are represented as an object
   * with the following structure:
   *
   *  {
   *    snapshot: {
   *      title: "...",
   *      uid: nnn,
   *      meta: { meta-info },
   *      node_count: nnn,
   *      edge_count: nnn
   *    },
   *    nodes: [nodes array],
   *    edges: [edges array],
   *    strings: [strings array]
   *  }
   *
   * Nodes reference strings, other nodes, and edges by their indexes
   * in corresponding arrays.
   */
  void Serialize(OutputStream* stream,
                 SerializationFormat format = kJSON) const;
};


/**
 * An interface for reporting progress and controlling long-running
 * activities.
 */
class V8_EXPORT ActivityControl {
 public:
  enum ControlOption {
    kContinue = 0,
    kAbort = 1
  };
  virtual ~ActivityControl() = default;
  /**
   * Notify about current progress. The activity can be stopped by
   * returning kAbort as the callback result.
   */
  virtual ControlOption ReportProgressValue(uint32_t done, uint32_t total) = 0;
};

/**
 * AllocationProfile is a sampled profile of allocations done by the program.
 * This is structured as a call-graph.
 */
class V8_EXPORT AllocationProfile {
 public:
  struct Allocation {
    /**
     * Size of the sampled allocation object.
     */
    size_t size;

    /**
     * The number of objects of such size that were sampled.
     */
    unsigned int count;
  };

  /**
   * Represents a node in the call-graph.
   */
  struct Node {
    /**
     * Name of the function. May be empty for anonymous functions or if the
     * script corresponding to this function has been unloaded.
     */
    Local<String> name;

    /**
     * Name of the script containing the function. May be empty if the script
     * name is not available, or if the script has been unloaded.
     */
    Local<String> script_name;

    /**
     * id of the script where the function is located. May be equal to
     * v8::UnboundScript::kNoScriptId in cases where the script doesn't exist.
     */
    int script_id;

    /**
     * Start position of the function in the script.
     */
    int start_position;

    /**
     * 1-indexed line number where the function starts. May be
     * kNoLineNumberInfo if no line number information is available.
     */
    int line_number;

    /**
     * 1-indexed column number where the function starts. May be
     * kNoColumnNumberInfo if no line number information is available.
     */
    int column_number;

    /**
     * Unique id of the node.
     */
    uint32_t node_id;

    /**
     * List of callees called from this node for which we have sampled
     * allocations. The lifetime of the children is scoped to the containing
     * AllocationProfile.
     */
    std::vector<Node*> children;

    /**
     * List of self allocations done by this node in the call-graph.
     */
    std::vector<Allocation> allocations;
  };

  /**
   * Represent a single sample recorded for an allocation.
   */
  struct Sample {
    /**
     * id of the node in the profile tree.
     */
    uint32_t node_id;

    /**
     * Size of the sampled allocation object.
     */
    size_t size;

    /**
     * The number of objects of such size that were sampled.
     */
    unsigned int count;

    /**
     * Unique time-ordered id of the allocation sample. Can be used to track
     * what samples were added or removed between two snapshots.
     */
    uint64_t sample_id;
  };

  /**
   * Returns the root node of the call-graph. The root node corresponds to an
   * empty JS call-stack. The lifetime of the returned Node* is scoped to the
   * containing AllocationProfile.
   */
  virtual Node* GetRootNode() = 0;
  virtual const std::vector<Sample>& GetSamples() = 0;

  virtual ~AllocationProfile() = default;

  static const int kNoLineNumberInfo = Message::kNoLineNumberInfo;
  static const int kNoColumnNumberInfo = Message::kNoColumnInfo;
};

/**
 * An object graph consisting of embedder objects and V8 objects.
 * Edges of the graph are strong references between the objects.
 * The embedder can build this graph during heap snapshot generation
 * to include the embedder objects in the heap snapshot.
 * Usage:
 * 1) Define derived class of EmbedderGraph::Node for embedder objects.
 * 2) Set the build embedder graph callback on the heap profiler using
 *    HeapProfiler::AddBuildEmbedderGraphCallback.
 * 3) In the callback use graph->AddEdge(node1, node2) to add an edge from
 *    node1 to node2.
 * 4) To represent references from/to V8 object, construct V8 nodes using
 *    graph->V8Node(value).
 */
class V8_EXPORT EmbedderGraph {
 public:
  class Node {
   public:
    /**
     * Detachedness specifies whether an object is attached or detached from the
     * main application state. While unkown in general, there may be objects
     * that specifically know their state. V8 passes this information along in
     * the snapshot. Users of the snapshot may use it to annotate the object
     * graph.
     */
    enum class Detachedness : uint8_t {
      kUnknown = 0,
      kAttached = 1,
      kDetached = 2,
    };

    Node() = default;
    virtual ~Node() = default;
    virtual const char* Name() = 0;
    virtual size_t SizeInBytes() = 0;
    /**
     * The corresponding V8 wrapper node if not null.
     * During heap snapshot generation the embedder node and the V8 wrapper
     * node will be merged into one node to simplify retaining paths.
     */
    virtual Node* WrapperNode() { return nullptr; }
    virtual bool IsRootNode() { return false; }
    /** Must return true for non-V8 nodes. */
    virtual bool IsEmbedderNode() { return true; }
    /**
     * Optional name prefix. It is used in Chrome for tagging detached nodes.
     */
    virtual const char* NamePrefix() { return nullptr; }

    /**
     * Returns the NativeObject that can be used for querying the
     * |HeapSnapshot|.
     */
    virtual NativeObject GetNativeObject() { return nullptr; }

    /**
     * Detachedness state of a given object. While unkown in general, there may
     * be objects that specifically know their state. V8 passes this information
     * along in the snapshot. Users of the snapshot may use it to annotate the
     * object graph.
     */
    virtual Detachedness GetDetachedness() { return Detachedness::kUnknown; }

    /**
     * Returns the address of the object in the embedder heap, or nullptr to not
     * specify the address. If this address is provided, then V8 can generate
     * consistent IDs for objects across subsequent heap snapshots, which allows
     * devtools to determine which objects were retained from one snapshot to
     * the next. This value is used only if GetNativeObject returns nullptr.
     */
    virtual const void* GetAddress() { return nullptr; }

    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
  };

  /**
   * Returns a node corresponding to the given V8 value. Ownership is not
   * transferred. The result pointer is valid while the graph is alive.
   *
   * For now the variant that takes v8::Data is not marked as abstract for
   * compatibility, but embedders who subclass EmbedderGraph are expected to
   * implement it. Then in the implementation of the variant that takes
   * v8::Value, they can simply forward the call to the one that takes
   * v8::Local<v8::Data>.
   */
  virtual Node* V8Node(const v8::Local<v8::Value>& value) = 0;

  /**
   * Returns a node corresponding to the given V8 value. Ownership is not
   * transferred. The result pointer is valid while the graph is alive.
   *
   * For API compatibility, this default implementation just checks that the
   * data is a v8::Value and forward it to the variant that takes v8::Value,
   * which is currently required to be implemented. In the future we'll remove
   * the v8::Value variant, and make this variant that takes v8::Data abstract
   * instead. If the embedder subclasses v8::EmbedderGraph and also use
   * v8::TracedReference<v8::Data>, they must override this variant.
   */
  virtual Node* V8Node(const v8::Local<v8::Data>& value);

  /**
   * Adds the given node to the graph and takes ownership of the node.
   * Returns a raw pointer to the node that is valid while the graph is alive.
   */
  virtual Node* AddNode(std::unique_ptr<Node> node) = 0;

  /**
   * Adds an edge that represents a strong reference from the given
   * node |from| to the given node |to|. The nodes must be added to the graph
   * before calling this function.
   *
   * If name is nullptr, the edge will have auto-increment indexes, otherwise
   * it will be named accordingly.
   */
  virtual void AddEdge(Node* from, Node* to, const char* name = nullptr) = 0;

  virtual ~EmbedderGraph() = default;
};

class QueryObjectPredicate {
 public:
  virtual ~QueryObjectPredicate() = default;
  virtual bool Filter(v8::Local<v8::Object> object) = 0;
};

/**
 * Interface for controlling heap profiling. Instance of the
 * profiler can be retrieved using v8::Isolate::GetHeapProfiler.
 */
class V8_EXPORT HeapProfiler {
 public:
  void QueryObjects(v8::Local<v8::Context> context,
                    QueryObjectPredicate* predicate,
                    std::vector<v8::Global<v8::Object>>* objects);

  enum SamplingFlags {
    kSamplingNoFlags = 0,
    kSamplingForceGC = 1 << 0,
    kSamplingIncludeObjectsCollectedByMajorGC = 1 << 1,
    kSamplingIncludeObjectsCollectedByMinorGC = 1 << 2,
  };

  /**
   * Callback function invoked during heap snapshot generation to retrieve
   * the embedder object graph. The callback should use graph->AddEdge(..) to
   * add references between the objects.
   * The callback must not trigger garbage collection in V8.
   */
  typedef void (*BuildEmbedderGraphCallback)(v8::Isolate* isolate,
                                             v8::EmbedderGraph* graph,
                                             void* data);

  /**
   * Callback function invoked during heap snapshot generation to retrieve
   * the detachedness state of a JS object referenced by a TracedReference.
   *
   * The callback takes Local<Value> as parameter to allow the embedder to
   * unpack the TracedReference into a Local and reuse that Local for different
   * purposes.
   */
  using GetDetachednessCallback = EmbedderGraph::Node::Detachedness (*)(
      v8::Isolate* isolate, const v8::Local<v8::Value>& v8_value,
      uint16_t class_id, void* data);

  /** Returns the number of snapshots taken. */
  int GetSnapshotCount();

  /** Returns a snapshot by index. */
  const HeapSnapshot* GetHeapSnapshot(int index);

  /**
   * Returns SnapshotObjectId for a heap object referenced by |value| if
   * it has been seen by the heap profiler, kUnknownObjectId otherwise.
   */
  SnapshotObjectId GetObjectId(Local<Value> value);

  /**
   * Returns SnapshotObjectId for a native object referenced by |value| if it
   * has been seen by the heap profiler, kUnknownObjectId otherwise.
   */
  SnapshotObjectId GetObjectId(NativeObject value);

  /**
   * Returns heap object with given SnapshotObjectId if the object is alive,
   * otherwise empty handle is returned.
   */
  Local<Value> FindObjectById(SnapshotObjectId id);

  /**
   * Clears internal map from SnapshotObjectId to heap object. T
```
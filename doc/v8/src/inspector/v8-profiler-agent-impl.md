Response: Let's break down the thought process for summarizing the C++ code and providing the JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `v8-profiler-agent-impl.cc` and a JavaScript example demonstrating its interaction (if any).

2. **Initial Scan for Keywords:** Quickly look for familiar terms related to profiling, debugging, and JavaScript interaction. Keywords like "Profiler," "Coverage," "CPUProfile," "consoleProfile," "JavaScript,"  "Script," and "URL" stand out. This immediately suggests the file is about performance analysis and code coverage.

3. **Identify Key Classes and Namespaces:** Notice the `v8_inspector` namespace and the `V8ProfilerAgentImpl` class. This is likely the main actor. Also, pay attention to nested namespaces like `ProfilerAgentState` and anonymous namespaces, which contain helper functions.

4. **Analyze the `V8ProfilerAgentImpl` Class:** This is the core. Look at its methods:
    * `consoleProfile`, `consoleProfileEnd`:  Clearly related to starting and stopping profiling initiated from the JavaScript console.
    * `enable`, `disable`: Control the profiler's active state.
    * `setSamplingInterval`: Configures the profiling granularity.
    * `start`, `stop`: Initiate and terminate CPU profiling.
    * `startPreciseCoverage`, `stopPreciseCoverage`, `takePreciseCoverage`, `getBestEffortCoverage`, `triggerPreciseCoverageDeltaUpdate`: Methods clearly dealing with code coverage measurement.

5. **Examine Helper Functions:** The anonymous namespace contains functions like `buildInspectorObjectFor`, `createCPUProfile`, `buildInspectorObjectForSamples`, etc. These strongly suggest the code is involved in converting internal V8 profiling data into a format suitable for the DevTools protocol (the "inspector" part). The names hint at building data structures for nodes, samples, and timestamps within a profile. `resourceNameToUrl` suggests handling script identification.

6. **Trace the Flow of Actions:**  Consider how these methods might be used. A typical profiling workflow would involve:
    * Enabling the profiler.
    * Starting a profile (either programmatically or via the console).
    * Letting the code run.
    * Stopping the profile.
    * Receiving the profiling data.

7. **Connect to JavaScript:** The `consoleProfile` and `consoleProfileEnd` methods are the most direct link to JavaScript. These correspond to the `console.profile()` and `console.profileEnd()` JavaScript API calls. This is the key to the JavaScript example.

8. **Understand Code Coverage:** The presence of "Coverage" related methods indicates functionality for measuring which parts of the code have been executed. The "Precise" and "BestEffort" prefixes suggest different levels of detail or accuracy.

9. **Formulate the Summary:** Based on the analysis, start drafting a summary that covers the key functionalities:
    * **Core Functionality:**  CPU profiling and code coverage.
    * **Triggering Profiling:**  JavaScript console (`console.profile`) and programmatic API.
    * **Data Collection:**  Collecting CPU usage samples and code execution counts.
    * **Data Transformation:** Converting internal V8 data into a format for the DevTools.
    * **Coverage Modes:**  Precise and best-effort coverage.
    * **Configuration:** Setting the sampling interval.
    * **Interaction with DevTools:**  Sending profiling and coverage data to the frontend.

10. **Construct the JavaScript Example:**  Since `console.profile` and `console.profileEnd` are the most obvious JavaScript connections, create a simple example that demonstrates their use. Focus on:
    * Starting a profile with a label.
    * Running some JavaScript code.
    * Ending the profile with the same label.
    * Explaining that the profile data will appear in the browser's DevTools.

11. **Refine and Organize:** Review the summary and the example for clarity and accuracy. Ensure the language is precise and avoids jargon where possible. Organize the summary logically.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:** Maybe the code directly executes JavaScript. **Correction:**  The code *manages* the profiling *of* JavaScript execution, but it's C++. It interacts with the V8 engine, which runs JavaScript.
* **Focus on Data Structures:**  Don't get bogged down in the details of every single data structure (like `ProfileNode`, `PositionTickInfo`) unless it's crucial for the high-level understanding. Recognize their purpose (representing profile data) and move on.
* **Clarify DevTools Connection:** Explicitly mention that the data is sent to the browser's developer tools. This clarifies the "inspector" aspect.
* **Emphasize User Interaction:** Highlight how developers initiate profiling and view the results through the DevTools.

By following these steps, combining keyword recognition, code analysis, and understanding the context of the V8 engine and DevTools, a comprehensive and accurate summary can be created. The JavaScript example directly follows from identifying the `console.profile` and `console.profileEnd` methods as the primary JavaScript interaction points.
这个 C++ 源代码文件 `v8-profiler-agent-impl.cc` 是 V8 JavaScript 引擎中 **Inspector (开发者工具)** 的一部分， 负责实现 **Profiler (性能分析器)** 的功能。

**它的主要功能可以归纳为：**

1. **管理 CPU Profiling:**
   - **启动和停止 CPU 性能分析:**  允许从 Inspector 前端 (通常是浏览器开发者工具) 启动和停止 CPU 性能分析。
   - **配置采样间隔:** 可以设置 CPU 性能分析的采样频率，影响分析的精度和性能开销。
   - **记录和存储性能数据:**  收集 JavaScript 代码执行时的 CPU 使用情况，生成调用栈信息和执行时间数据。
   - **生成性能分析报告:** 将收集到的性能数据转换为 Inspector 前端可以理解的格式 (基于 `protocol::Profiler::Profile`)，以便在开发者工具中展示火焰图、调用树等。

2. **管理代码覆盖率 (Code Coverage):**
   - **启动和停止代码覆盖率收集:** 允许从 Inspector 前端启动和停止代码覆盖率的收集。
   - **配置覆盖率模式:** 支持不同的覆盖率模式，例如精确计数 (precise count) 和块级覆盖 (block coverage)，可以记录代码执行的次数或者代码块的覆盖情况。
   - **收集覆盖率数据:**  在 JavaScript 代码执行期间记录哪些代码被执行过，以及执行的次数。
   - **生成覆盖率报告:** 将收集到的覆盖率数据转换为 Inspector 前端可以理解的格式 (基于 `protocol::Profiler::ScriptCoverage`)，以便在开发者工具中展示哪些代码被覆盖，哪些没有被覆盖。
   - **支持增量更新:** 允许在覆盖率收集过程中触发更新，获取最新的覆盖率数据。

3. **与 Inspector 前端通信:**
   - 使用 Chrome DevTools Protocol (CDP) 与前端进行通信，接收前端的指令 (例如启动/停止分析、设置参数) 并将分析结果发送回前端。

4. **与 V8 引擎交互:**
   - 使用 V8 提供的 Profiler API (`v8::CpuProfiler`) 来启动和停止 CPU 性能分析，并获取性能数据。
   - 使用 V8 提供的 Coverage API (`v8::debug::Coverage`) 来启动和停止代码覆盖率收集，并获取覆盖率数据。

5. **管理 Profiler 状态:**
   - 维护 Profiler 的状态，例如是否已启用、是否正在进行性能分析或代码覆盖率收集。
   - 使用 `protocol::DictionaryValue` 来持久化 Profiler 的状态，以便在 Inspector 会话恢复后可以恢复之前的状态。

**它与 JavaScript 的功能关系，可以用以下 JavaScript 例子说明：**

```javascript
// 在浏览器的开发者工具的 Console 面板中执行

// 启动 CPU 性能分析，并命名为 "MyProfile"
console.profile("MyProfile");

function myFunction() {
  let sum = 0;
  for (let i = 0; i < 1000000; i++) {
    sum += i;
  }
  return sum;
}

myFunction();

// 停止 CPU 性能分析
console.profileEnd("MyProfile");

// 启动代码覆盖率收集
debugger; // 加上 debugger 语句，以便在开发者工具中控制执行流程

function anotherFunction() {
  console.log("This function is called.");
}

if (Math.random() > 0.5) {
  anotherFunction();
}

// 在开发者工具的 Coverage 面板中查看覆盖率结果
```

**解释:**

- **`console.profile("MyProfile")` 和 `console.profileEnd("MyProfile")`:** 这两个 JavaScript API 调用直接对应了 `v8-profiler-agent-impl.cc` 中的 `V8ProfilerAgentImpl::consoleProfile` 和 `V8ProfilerAgentImpl::consoleProfileEnd` 方法。当你在 JavaScript 代码中调用 `console.profile()` 时，V8 引擎会通知 Inspector 的 ProfilerAgent 开始记录 CPU 性能数据。调用 `console.profileEnd()` 则会停止记录并生成性能分析报告，你可以在浏览器开发者工具的 **Profiler** 或 **Performance** 面板中查看结果。

- **代码覆盖率的例子:**  虽然没有直接的 JavaScript API 来启动代码覆盖率收集，但通常是通过浏览器的开发者工具 (Coverage 面板) 来启动的。当启动代码覆盖率收集后，`v8-profiler-agent-impl.cc` 中的相关代码 (例如 `V8ProfilerAgentImpl::startPreciseCoverage`) 会被触发，开始记录 JavaScript 代码的执行情况。最终的覆盖率报告会在 Coverage 面板中展示，显示哪些代码被执行了，哪些没有被执行。

**总结:**

`v8-profiler-agent-impl.cc` 是 V8 引擎中负责实现开发者工具性能分析器和代码覆盖率功能的关键组件。它接收来自前端的指令，与 V8 引擎的 Profiler 和 Coverage API 交互，收集性能和覆盖率数据，并将结果格式化后发送回前端，最终在浏览器的开发者工具中呈现给开发者，帮助他们分析 JavaScript 代码的性能瓶颈和代码覆盖情况。

### 提示词
```
这是目录为v8/src/inspector/v8-profiler-agent-impl.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/inspector/v8-profiler-agent-impl.h"

#include <vector>

#include "include/v8-profiler.h"
#include "src/base/atomicops.h"
#include "src/base/platform/time.h"
#include "src/debug/debug-interface.h"
#include "src/inspector/protocol/Protocol.h"
#include "src/inspector/string-util.h"
#include "src/inspector/v8-debugger.h"
#include "src/inspector/v8-inspector-impl.h"
#include "src/inspector/v8-inspector-session-impl.h"
#include "src/inspector/v8-stack-trace-impl.h"

namespace v8_inspector {

namespace ProfilerAgentState {
static const char samplingInterval[] = "samplingInterval";
static const char userInitiatedProfiling[] = "userInitiatedProfiling";
static const char profilerEnabled[] = "profilerEnabled";
static const char preciseCoverageStarted[] = "preciseCoverageStarted";
static const char preciseCoverageCallCount[] = "preciseCoverageCallCount";
static const char preciseCoverageDetailed[] = "preciseCoverageDetailed";
static const char preciseCoverageAllowTriggeredUpdates[] =
    "preciseCoverageAllowTriggeredUpdates";
}  // namespace ProfilerAgentState

namespace {

String16 resourceNameToUrl(V8InspectorImpl* inspector,
                           v8::Local<v8::String> v8Name) {
  String16 name = toProtocolString(inspector->isolate(), v8Name);
  if (!inspector) return name;
  std::unique_ptr<StringBuffer> url =
      inspector->client()->resourceNameToUrl(toStringView(name));
  return url ? toString16(url->string()) : name;
}

std::unique_ptr<protocol::Array<protocol::Profiler::PositionTickInfo>>
buildInspectorObjectForPositionTicks(const v8::CpuProfileNode* node) {
  unsigned lineCount = node->GetHitLineCount();
  if (!lineCount) return nullptr;
  auto array =
      std::make_unique<protocol::Array<protocol::Profiler::PositionTickInfo>>();
  std::vector<v8::CpuProfileNode::LineTick> entries(lineCount);
  if (node->GetLineTicks(&entries[0], lineCount)) {
    for (unsigned i = 0; i < lineCount; i++) {
      std::unique_ptr<protocol::Profiler::PositionTickInfo> line =
          protocol::Profiler::PositionTickInfo::create()
              .setLine(entries[i].line)
              .setTicks(entries[i].hit_count)
              .build();
      array->emplace_back(std::move(line));
    }
  }
  return array;
}

std::unique_ptr<protocol::Profiler::ProfileNode> buildInspectorObjectFor(
    V8InspectorImpl* inspector, const v8::CpuProfileNode* node) {
  v8::Isolate* isolate = inspector->isolate();
  v8::HandleScope handleScope(isolate);
  auto callFrame =
      protocol::Runtime::CallFrame::create()
          .setFunctionName(toProtocolString(isolate, node->GetFunctionName()))
          .setScriptId(String16::fromInteger(node->GetScriptId()))
          .setUrl(resourceNameToUrl(inspector, node->GetScriptResourceName()))
          .setLineNumber(node->GetLineNumber() - 1)
          .setColumnNumber(node->GetColumnNumber() - 1)
          .build();
  auto result = protocol::Profiler::ProfileNode::create()
                    .setCallFrame(std::move(callFrame))
                    .setHitCount(node->GetHitCount())
                    .setId(node->GetNodeId())
                    .build();

  const int childrenCount = node->GetChildrenCount();
  if (childrenCount) {
    auto children = std::make_unique<protocol::Array<int>>();
    for (int i = 0; i < childrenCount; i++)
      children->emplace_back(node->GetChild(i)->GetNodeId());
    result->setChildren(std::move(children));
  }

  const char* deoptReason = node->GetBailoutReason();
  if (deoptReason && deoptReason[0] && strcmp(deoptReason, "no reason"))
    result->setDeoptReason(deoptReason);

  auto positionTicks = buildInspectorObjectForPositionTicks(node);
  if (positionTicks) result->setPositionTicks(std::move(positionTicks));

  return result;
}

std::unique_ptr<protocol::Array<int>> buildInspectorObjectForSamples(
    v8::CpuProfile* v8profile) {
  auto array = std::make_unique<protocol::Array<int>>();
  int count = v8profile->GetSamplesCount();
  for (int i = 0; i < count; i++)
    array->emplace_back(v8profile->GetSample(i)->GetNodeId());
  return array;
}

std::unique_ptr<protocol::Array<int>> buildInspectorObjectForTimestamps(
    v8::CpuProfile* v8profile) {
  auto array = std::make_unique<protocol::Array<int>>();
  int count = v8profile->GetSamplesCount();
  uint64_t lastTime = v8profile->GetStartTime();
  for (int i = 0; i < count; i++) {
    uint64_t ts = v8profile->GetSampleTimestamp(i);
    array->emplace_back(static_cast<int>(ts - lastTime));
    lastTime = ts;
  }
  return array;
}

void flattenNodesTree(V8InspectorImpl* inspector,
                      const v8::CpuProfileNode* node,
                      protocol::Array<protocol::Profiler::ProfileNode>* list) {
  list->emplace_back(buildInspectorObjectFor(inspector, node));
  const int childrenCount = node->GetChildrenCount();
  for (int i = 0; i < childrenCount; i++)
    flattenNodesTree(inspector, node->GetChild(i), list);
}

std::unique_ptr<protocol::Profiler::Profile> createCPUProfile(
    V8InspectorImpl* inspector, v8::CpuProfile* v8profile) {
  auto nodes =
      std::make_unique<protocol::Array<protocol::Profiler::ProfileNode>>();
  flattenNodesTree(inspector, v8profile->GetTopDownRoot(), nodes.get());
  return protocol::Profiler::Profile::create()
      .setNodes(std::move(nodes))
      .setStartTime(static_cast<double>(v8profile->GetStartTime()))
      .setEndTime(static_cast<double>(v8profile->GetEndTime()))
      .setSamples(buildInspectorObjectForSamples(v8profile))
      .setTimeDeltas(buildInspectorObjectForTimestamps(v8profile))
      .build();
}

std::unique_ptr<protocol::Debugger::Location> currentDebugLocation(
    V8InspectorImpl* inspector) {
  auto stackTrace = V8StackTraceImpl::capture(inspector->debugger(), 1);
  CHECK(stackTrace);
  CHECK(!stackTrace->isEmpty());
  return protocol::Debugger::Location::create()
      .setScriptId(String16::fromInteger(stackTrace->topScriptId()))
      .setLineNumber(stackTrace->topLineNumber())
      .setColumnNumber(stackTrace->topColumnNumber())
      .build();
}

volatile int s_lastProfileId = 0;

}  // namespace

class V8ProfilerAgentImpl::ProfileDescriptor {
 public:
  ProfileDescriptor(const String16& id, const String16& title)
      : m_id(id), m_title(title) {}
  String16 m_id;
  String16 m_title;
};

V8ProfilerAgentImpl::V8ProfilerAgentImpl(
    V8InspectorSessionImpl* session, protocol::FrontendChannel* frontendChannel,
    protocol::DictionaryValue* state)
    : m_session(session),
      m_isolate(m_session->inspector()->isolate()),
      m_state(state),
      m_frontend(frontendChannel) {}

V8ProfilerAgentImpl::~V8ProfilerAgentImpl() {
  if (m_profiler) m_profiler->Dispose();
}

void V8ProfilerAgentImpl::consoleProfile(const String16& title) {
  if (!m_enabled) return;
  String16 id = nextProfileId();
  m_startedProfiles.push_back(ProfileDescriptor(id, title));
  startProfiling(id);
  m_frontend.consoleProfileStarted(
      id, currentDebugLocation(m_session->inspector()), title);
}

void V8ProfilerAgentImpl::consoleProfileEnd(const String16& title) {
  if (!m_enabled) return;
  String16 id;
  String16 resolvedTitle;
  // Take last started profile if no title was passed.
  if (title.isEmpty()) {
    if (m_startedProfiles.empty()) return;
    id = m_startedProfiles.back().m_id;
    resolvedTitle = m_startedProfiles.back().m_title;
    m_startedProfiles.pop_back();
  } else {
    for (size_t i = 0; i < m_startedProfiles.size(); i++) {
      if (m_startedProfiles[i].m_title == title) {
        resolvedTitle = title;
        id = m_startedProfiles[i].m_id;
        m_startedProfiles.erase(m_startedProfiles.begin() + i);
        break;
      }
    }
    if (id.isEmpty()) return;
  }
  std::unique_ptr<protocol::Profiler::Profile> profile =
      stopProfiling(id, true);
  if (!profile) return;
  m_frontend.consoleProfileFinished(
      id, currentDebugLocation(m_session->inspector()), std::move(profile),
      resolvedTitle);
}

Response V8ProfilerAgentImpl::enable() {
  if (!m_enabled) {
    m_enabled = true;
    m_state->setBoolean(ProfilerAgentState::profilerEnabled, true);
  }

  return Response::Success();
}

Response V8ProfilerAgentImpl::disable() {
  if (m_enabled) {
    for (size_t i = m_startedProfiles.size(); i > 0; --i)
      stopProfiling(m_startedProfiles[i - 1].m_id, false);
    m_startedProfiles.clear();
    stop(nullptr);
    stopPreciseCoverage();
    DCHECK(!m_profiler);
    m_enabled = false;
    m_state->setBoolean(ProfilerAgentState::profilerEnabled, false);
  }

  return Response::Success();
}

Response V8ProfilerAgentImpl::setSamplingInterval(int interval) {
  if (m_profiler) {
    return Response::ServerError(
        "Cannot change sampling interval when profiling.");
  }
  m_state->setInteger(ProfilerAgentState::samplingInterval, interval);
  return Response::Success();
}

void V8ProfilerAgentImpl::restore() {
  DCHECK(!m_enabled);
  if (m_state->booleanProperty(ProfilerAgentState::profilerEnabled, false)) {
    m_enabled = true;
    DCHECK(!m_profiler);
    if (m_state->booleanProperty(ProfilerAgentState::userInitiatedProfiling,
                                 false)) {
      start();
    }
    if (m_state->booleanProperty(ProfilerAgentState::preciseCoverageStarted,
                                 false)) {
      bool callCount = m_state->booleanProperty(
          ProfilerAgentState::preciseCoverageCallCount, false);
      bool detailed = m_state->booleanProperty(
          ProfilerAgentState::preciseCoverageDetailed, false);
      bool updatesAllowed = m_state->booleanProperty(
          ProfilerAgentState::preciseCoverageAllowTriggeredUpdates, false);
      double timestamp;
      startPreciseCoverage(Maybe<bool>(callCount), Maybe<bool>(detailed),
                           Maybe<bool>(updatesAllowed), &timestamp);
    }
  }
}

Response V8ProfilerAgentImpl::start() {
  if (m_recordingCPUProfile) return Response::Success();
  if (!m_enabled) return Response::ServerError("Profiler is not enabled");
  m_recordingCPUProfile = true;
  m_frontendInitiatedProfileId = nextProfileId();
  startProfiling(m_frontendInitiatedProfileId);
  m_state->setBoolean(ProfilerAgentState::userInitiatedProfiling, true);
  return Response::Success();
}

Response V8ProfilerAgentImpl::stop(
    std::unique_ptr<protocol::Profiler::Profile>* profile) {
  if (!m_recordingCPUProfile) {
    return Response::ServerError("No recording profiles found");
  }
  m_recordingCPUProfile = false;
  std::unique_ptr<protocol::Profiler::Profile> cpuProfile =
      stopProfiling(m_frontendInitiatedProfileId, !!profile);
  if (profile) {
    *profile = std::move(cpuProfile);
    if (!*profile) return Response::ServerError("Profile is not found");
  }
  m_frontendInitiatedProfileId = String16();
  m_state->setBoolean(ProfilerAgentState::userInitiatedProfiling, false);
  return Response::Success();
}

Response V8ProfilerAgentImpl::startPreciseCoverage(
    Maybe<bool> callCount, Maybe<bool> detailed,
    Maybe<bool> allowTriggeredUpdates, double* out_timestamp) {
  if (!m_enabled) return Response::ServerError("Profiler is not enabled");
  *out_timestamp = v8::base::TimeTicks::Now().since_origin().InSecondsF();
  bool callCountValue = callCount.value_or(false);
  bool detailedValue = detailed.value_or(false);
  bool allowTriggeredUpdatesValue = allowTriggeredUpdates.value_or(false);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageStarted, true);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageCallCount,
                      callCountValue);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageDetailed,
                      detailedValue);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageAllowTriggeredUpdates,
                      allowTriggeredUpdatesValue);
  // BlockCount is a superset of PreciseCount. It includes block-granularity
  // coverage data if it exists (at the time of writing, that's the case for
  // each function recompiled after the BlockCount mode has been set); and
  // function-granularity coverage data otherwise.
  using C = v8::debug::Coverage;
  using Mode = v8::debug::CoverageMode;
  Mode mode = callCountValue
                  ? (detailedValue ? Mode::kBlockCount : Mode::kPreciseCount)
                  : (detailedValue ? Mode::kBlockBinary : Mode::kPreciseBinary);
  C::SelectMode(m_isolate, mode);
  return Response::Success();
}

Response V8ProfilerAgentImpl::stopPreciseCoverage() {
  if (!m_enabled) return Response::ServerError("Profiler is not enabled");
  m_state->setBoolean(ProfilerAgentState::preciseCoverageStarted, false);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageCallCount, false);
  m_state->setBoolean(ProfilerAgentState::preciseCoverageDetailed, false);
  v8::debug::Coverage::SelectMode(m_isolate,
                                  v8::debug::CoverageMode::kBestEffort);
  return Response::Success();
}

namespace {
std::unique_ptr<protocol::Profiler::CoverageRange> createCoverageRange(
    int start, int end, int count) {
  return protocol::Profiler::CoverageRange::create()
      .setStartOffset(start)
      .setEndOffset(end)
      .setCount(count)
      .build();
}

Response coverageToProtocol(
    V8InspectorImpl* inspector, const v8::debug::Coverage& coverage,
    std::unique_ptr<protocol::Array<protocol::Profiler::ScriptCoverage>>*
        out_result) {
  auto result =
      std::make_unique<protocol::Array<protocol::Profiler::ScriptCoverage>>();
  v8::Isolate* isolate = inspector->isolate();
  for (size_t i = 0; i < coverage.ScriptCount(); i++) {
    v8::debug::Coverage::ScriptData script_data = coverage.GetScriptData(i);
    v8::Local<v8::debug::Script> script = script_data.GetScript();
    auto functions = std::make_unique<
        protocol::Array<protocol::Profiler::FunctionCoverage>>();
    for (size_t j = 0; j < script_data.FunctionCount(); j++) {
      v8::debug::Coverage::FunctionData function_data =
          script_data.GetFunctionData(j);
      auto ranges = std::make_unique<
          protocol::Array<protocol::Profiler::CoverageRange>>();

      // Add function range.
      ranges->emplace_back(createCoverageRange(function_data.StartOffset(),
                                               function_data.EndOffset(),
                                               function_data.Count()));

      // Process inner blocks.
      for (size_t k = 0; k < function_data.BlockCount(); k++) {
        v8::debug::Coverage::BlockData block_data =
            function_data.GetBlockData(k);
        ranges->emplace_back(createCoverageRange(block_data.StartOffset(),
                                                 block_data.EndOffset(),
                                                 block_data.Count()));
      }

      functions->emplace_back(
          protocol::Profiler::FunctionCoverage::create()
              .setFunctionName(toProtocolString(
                  isolate,
                  function_data.Name().FromMaybe(v8::Local<v8::String>())))
              .setRanges(std::move(ranges))
              .setIsBlockCoverage(function_data.HasBlockCoverage())
              .build());
    }
    String16 url;
    v8::Local<v8::String> name;
    if (script->SourceURL().ToLocal(&name) && name->Length()) {
      url = toProtocolString(isolate, name);
    } else if (script->Name().ToLocal(&name) && name->Length()) {
      url = resourceNameToUrl(inspector, name);
    }
    result->emplace_back(protocol::Profiler::ScriptCoverage::create()
                             .setScriptId(String16::fromInteger(script->Id()))
                             .setUrl(url)
                             .setFunctions(std::move(functions))
                             .build());
  }
  *out_result = std::move(result);
  return Response::Success();
}
}  // anonymous namespace

Response V8ProfilerAgentImpl::takePreciseCoverage(
    std::unique_ptr<protocol::Array<protocol::Profiler::ScriptCoverage>>*
        out_result,
    double* out_timestamp) {
  if (!m_state->booleanProperty(ProfilerAgentState::preciseCoverageStarted,
                                false)) {
    return Response::ServerError("Precise coverage has not been started.");
  }
  v8::HandleScope handle_scope(m_isolate);
  v8::debug::Coverage coverage = v8::debug::Coverage::CollectPrecise(m_isolate);
  *out_timestamp = v8::base::TimeTicks::Now().since_origin().InSecondsF();
  return coverageToProtocol(m_session->inspector(), coverage, out_result);
}

void V8ProfilerAgentImpl::triggerPreciseCoverageDeltaUpdate(
    const String16& occasion) {
  if (!m_state->booleanProperty(ProfilerAgentState::preciseCoverageStarted,
                                false)) {
    return;
  }
  if (!m_state->booleanProperty(
          ProfilerAgentState::preciseCoverageAllowTriggeredUpdates, false)) {
    return;
  }
  v8::HandleScope handle_scope(m_isolate);
  v8::debug::Coverage coverage = v8::debug::Coverage::CollectPrecise(m_isolate);
  std::unique_ptr<protocol::Array<protocol::Profiler::ScriptCoverage>>
      out_result;
  coverageToProtocol(m_session->inspector(), coverage, &out_result);
  double now = v8::base::TimeTicks::Now().since_origin().InSecondsF();
  m_frontend.preciseCoverageDeltaUpdate(now, occasion, std::move(out_result));
}

Response V8ProfilerAgentImpl::getBestEffortCoverage(
    std::unique_ptr<protocol::Array<protocol::Profiler::ScriptCoverage>>*
        out_result) {
  v8::HandleScope handle_scope(m_isolate);
  v8::debug::Coverage coverage =
      v8::debug::Coverage::CollectBestEffort(m_isolate);
  return coverageToProtocol(m_session->inspector(), coverage, out_result);
}

String16 V8ProfilerAgentImpl::nextProfileId() {
  return String16::fromInteger(
      v8::base::Relaxed_AtomicIncrement(&s_lastProfileId, 1));
}

void V8ProfilerAgentImpl::startProfiling(const String16& title) {
  v8::HandleScope handleScope(m_isolate);
  if (!m_startedProfilesCount) {
    DCHECK(!m_profiler);
    m_profiler = v8::CpuProfiler::New(m_isolate);
    int interval =
        m_state->integerProperty(ProfilerAgentState::samplingInterval, 0);
    if (interval) m_profiler->SetSamplingInterval(interval);
  }
  ++m_startedProfilesCount;
  m_profiler->StartProfiling(toV8String(m_isolate, title), true);
}

std::unique_ptr<protocol::Profiler::Profile> V8ProfilerAgentImpl::stopProfiling(
    const String16& title, bool serialize) {
  v8::HandleScope handleScope(m_isolate);
  v8::CpuProfile* profile =
      m_profiler->StopProfiling(toV8String(m_isolate, title));
  std::unique_ptr<protocol::Profiler::Profile> result;
  if (profile) {
    if (serialize) result = createCPUProfile(m_session->inspector(), profile);
    profile->Delete();
  }
  --m_startedProfilesCount;
  if (!m_startedProfilesCount) {
    m_profiler->Dispose();
    m_profiler = nullptr;
  }
  return result;
}

}  // namespace v8_inspector
```
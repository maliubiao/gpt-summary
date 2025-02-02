Response:

### 提示词
```
这是目录为blink/renderer/core/dom/abort_signal_registry.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/abort_signal_registry.h"

#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/dom/abort_signal_composition_type.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/execution_context_lifecycle_observer.h"

namespace blink {

// static
const char AbortSignalRegistry::kSupplementName[] = "AbortSignalRegistry";

// static
AbortSignalRegistry* AbortSignalRegistry::From(ExecutionContext& context) {
  AbortSignalRegistry* registry =
      Supplement<ExecutionContext>::From<AbortSignalRegistry>(context);
  if (!registry) {
    registry = MakeGarbageCollected<AbortSignalRegistry>(context);
    Supplement<ExecutionContext>::ProvideTo(context, registry);
  }
  return registry;
}

AbortSignalRegistry::AbortSignalRegistry(ExecutionContext& context)
    : Supplement<ExecutionContext>(context),
      ExecutionContextLifecycleObserver(&context) {}

AbortSignalRegistry::~AbortSignalRegistry() = default;

void AbortSignalRegistry::Trace(Visitor* visitor) const {
  visitor->Trace(event_listener_signals_);
  visitor->Trace(signals_registered_for_abort_);
  visitor->Trace(signals_registered_for_priority_);
  Supplement<ExecutionContext>::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

void AbortSignalRegistry::ContextDestroyed() {
  event_listener_signals_.clear();
}

void AbortSignalRegistry::RegisterAbortAlgorithm(
    EventListener* listener,
    AbortSignal::AlgorithmHandle* handle) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  event_listener_signals_.Set(listener, handle);
}

void AbortSignalRegistry::RegisterSignal(const AbortSignal& signal,
                                         AbortSignalCompositionType type) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  switch (type) {
    case AbortSignalCompositionType::kAbort:
      signals_registered_for_abort_.insert(&signal);
      break;
    case AbortSignalCompositionType::kPriority:
      signals_registered_for_priority_.insert(&signal);
      break;
  }
}

void AbortSignalRegistry::UnregisterSignal(const AbortSignal& signal,
                                           AbortSignalCompositionType type) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  switch (type) {
    case AbortSignalCompositionType::kAbort:
      signals_registered_for_abort_.erase(&signal);
      break;
    case AbortSignalCompositionType::kPriority:
      signals_registered_for_priority_.erase(&signal);
      break;
  }
}

}  // namespace blink
```
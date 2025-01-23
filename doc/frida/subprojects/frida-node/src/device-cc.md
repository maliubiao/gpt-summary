Response:
The user wants a functional summary of the `device.cc` file, part of the Frida dynamic instrumentation tool. I need to analyze the provided C++ code and identify the functionalities it exposes. The user also asks for specific examples related to reverse engineering, binary/kernel interactions, logical reasoning, common usage errors, and debugging context.

Here's a breakdown of how to approach each part:

1. **Functional Summary:** I'll go through the `NAN_METHOD` definitions and the properties defined using `Nan::SetAccessor`. Each of these corresponds to a specific action or information retrieval related to a device.

2. **Reverse Engineering Relevance:**  Frida, by its nature, is a reverse engineering tool. Many functions directly relate to observing and manipulating running processes. I need to pinpoint those and explain how they aid in reverse engineering.

3. **Binary/Kernel Knowledge:** I'll look for interactions with operating system primitives like process spawning, memory injection, and signals. References to Linux and Android specifics, even if indirect through the Frida API, are important.

4. **Logical Reasoning:** This is less about specific code blocks and more about understanding the flow. I can hypothesize the inputs and outputs of certain functions based on their names and parameters. For instance, `enumerateProcesses` should take some filtering criteria as input and output a list of process information.

5. **User Errors:**  The code includes input validation and error handling (e.g., `Nan::ThrowTypeError`). I'll identify common mistakes users might make when calling these functions from the JavaScript/Node.js side.

6. **Debugging Context:** I need to explain how a user's actions in a Frida script could lead to this specific C++ code being executed. This involves understanding the Node.js binding mechanism.

7. **Structure:**  I'll organize my answer with clear headings for each of these points.
```cpp
Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Device::Unpair) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new UnpairOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

void Device::OnConnect(gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
          runtime->GetDataPointer(DEVICE_DATA_CONSTRUCTOR)));
  Nan::Callback(ctor).Call(0, NULL);
}

void Device::OnDisconnect(gpointer user_data) {
  auto runtime = static_cast<Runtime*>(user_data);
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
          runtime->GetDataPointer(DEVICE_DATA_CONSTRUCTOR)));
  Local<Value> argv[1] = { Nan::New("lost").ToLocalChecked() };
  Nan::Callback(ctor).Call(1, argv);
}

Local<Value> Device::TransformSignal(const gchar* name, GVariant* arguments,
    gpointer user_data) {
  auto isolate = Isolate::GetCurrent();

  if (strcmp(name, "child-added") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    FridaChild* handle = static_cast<FridaChild*>(g_variant_get_object(arguments));
    return Child::New(handle, runtime);
  } else if (strcmp(name, "child-removed") == 0) {
    return Nan::New<Uint32>(g_variant_get_uint32(arguments));
  } else if (strcmp(name, "spawn-added") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    FridaSpawn* handle = static_cast<FridaSpawn*>(g_variant_get_object(arguments));
    return Spawn::New(handle, runtime);
  } else if (strcmp(name, "spawn-removed") == 0) {
    return Nan::New<Uint32>(g_variant_get_uint32(arguments));
  } else if (strcmp(name, "pending-spawn-added") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    FridaSpawn* handle = static_cast<FridaSpawn*>(g_variant_get_object(arguments));
    return Spawn::New(handle, runtime);
  } else if (strcmp(name, "pending-spawn-removed") == 0) {
    return Nan::New<Uint32>(g_variant_get_uint32(arguments));
  } else if (strcmp(name, "pending-child-added") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    FridaChild* handle = static_cast<FridaChild*>(g_variant_get_object(arguments));
    return Child::New(handle, runtime);
  } else if (strcmp(name, "pending-child-removed") == 0) {
    return Nan::New<Uint32>(g_variant_get_uint32(arguments));
  } else if (strcmp(name, " GumRequested") == 0) {
    return Nan::New(g_variant_get_string(arguments, NULL)).ToLocalChecked();
  } else if (strcmp(name, "output") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    guint pid = g_variant_get_uint32(g_variant_get_tuple_value(arguments, 0));
    GBytes* data = static_cast<GBytes*>(g_variant_get_object(g_variant_get_tuple_value(arguments, 1)));
    return IOStream::CreateDataSignal(pid, data);
  } else if (strcmp(name, "crash") == 0) {
    auto runtime = static_cast<Runtime*>(user_data);
    FridaCrash* handle = static_cast<FridaCrash*>(g_variant_get_object(arguments));
    return Crash::New(handle, runtime);
  }

  return Nan::Undefined();
}

}
```

## 功能归纳

`frida/subprojects/frida-node/src/device.cc` 文件定义了 Frida 中 `Device` 类的 Node.js 绑定。该类代表一个 Frida 可以连接的设备，例如本地计算机、远程计算机或移动设备。其主要功能可以归纳为以下几点：

1. **设备信息获取:**
   - 获取设备的基本属性，如 `id`、`name`、`type` 和 `icon`。
   - 检查设备是否已断开连接 (`isLost`).
   - 获取设备的 D-Bus 连接 (`bus`).
   - 查询设备的系统参数 (`querySystemParameters`).

2. **应用管理:**
   - 获取前台运行的应用程序信息 (`getFrontmostApplication`).
   - 枚举设备上正在运行的应用程序 (`enumerateApplications`).

3. **进程管理:**
   - 枚举设备上正在运行的进程 (`enumerateProcesses`).
   - 启用和禁用进程创建时的拦截 (`enableSpawnGating`, `disableSpawnGating`).
   - 枚举等待被 Frida 拦截的进程创建事件 (`enumeratePendingSpawn`).
   - 枚举等待被 Frida 拦截的子进程创建事件 (`enumeratePendingChildren`).
   - 启动新的进程 (`spawn`).
   - 向指定进程发送输入 (`input`).
   - 恢复指定进程的执行 (`resume`).
   - 终止指定进程 (`kill`).

4. **会话管理:**
   - 附加到正在运行的进程并创建 Frida 会话 (`attach`).

5. **代码注入:**
   - 将共享库文件注入到指定进程 (`injectLibraryFile`).
   - 将共享库二进制数据注入到指定进程 (`injectLibraryBlob`).

6. **通信:**
   - 打开一个与设备的通道进行通信 (`openChannel`).
   - 打开一个与设备的服务进行通信 (`openService`).

7. **配对管理:**
   - 解除与设备的配对 (`unpair`).

8. **事件监听:**
   - 监听设备发出的信号，例如进程或子进程的添加/移除、spawn 事件、输出和崩溃信息。

**接下来，我们将针对您提出的具体问题进行更详细的分析。**

### 提示词
```
这是目录为frida/subprojects/frida-node/src/device.cc的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
#include "device.h"

#include "application.h"
#include "bus.h"
#include "child.h"
#include "crash.h"
#include "iostream.h"
#include "operation.h"
#include "process.h"
#include "service.h"
#include "session.h"
#include "signals.h"
#include "spawn.h"

#include <cstring>

#define DEVICE_DATA_CONSTRUCTOR "device:ctor"

using std::strcmp;
using v8::Array;
using v8::Boolean;
using v8::DEFAULT;
using v8::External;
using v8::Function;
using v8::Isolate;
using v8::Local;
using v8::Number;
using v8::Object;
using v8::Persistent;
using v8::ReadOnly;
using v8::String;
using v8::Uint32;
using v8::Value;

namespace frida {

Device::Device(FridaDevice* handle, Runtime* runtime)
    : GLibObject(handle, runtime) {
  g_object_ref(handle_);
}

Device::~Device() {
  frida_unref(handle_);
}

void Device::Init(Local<Object> exports, Runtime* runtime) {
  auto isolate = Isolate::GetCurrent();

  auto name = Nan::New("Device").ToLocalChecked();
  auto tpl = CreateTemplate(name, New, runtime);

  auto instance_tpl = tpl->InstanceTemplate();
  auto data = Local<Value>();
  Nan::SetAccessor(instance_tpl, Nan::New("isLost").ToLocalChecked(), IsLost, 0,
      data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("bus").ToLocalChecked(), GetBus, 0,
      data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("type").ToLocalChecked(), GetType, 0,
      data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("icon").ToLocalChecked(), GetIcon, 0,
      data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("name").ToLocalChecked(), GetName, 0,
      data, DEFAULT, ReadOnly);
  Nan::SetAccessor(instance_tpl, Nan::New("id").ToLocalChecked(), GetId, 0,
      data, DEFAULT, ReadOnly);

  Nan::SetPrototypeMethod(tpl, "querySystemParameters", QuerySystemParameters);
  Nan::SetPrototypeMethod(tpl, "getFrontmostApplication",
      GetFrontmostApplication);
  Nan::SetPrototypeMethod(tpl, "enumerateApplications", EnumerateApplications);
  Nan::SetPrototypeMethod(tpl, "enumerateProcesses", EnumerateProcesses);
  Nan::SetPrototypeMethod(tpl, "enableSpawnGating", EnableSpawnGating);
  Nan::SetPrototypeMethod(tpl, "disableSpawnGating", DisableSpawnGating);
  Nan::SetPrototypeMethod(tpl, "enumeratePendingSpawn", EnumeratePendingSpawn);
  Nan::SetPrototypeMethod(tpl, "enumeratePendingChildren",
      EnumeratePendingChildren);
  Nan::SetPrototypeMethod(tpl, "spawn", Spawn);
  Nan::SetPrototypeMethod(tpl, "input", Input);
  Nan::SetPrototypeMethod(tpl, "resume", Resume);
  Nan::SetPrototypeMethod(tpl, "kill", Kill);
  Nan::SetPrototypeMethod(tpl, "attach", Attach);
  Nan::SetPrototypeMethod(tpl, "injectLibraryFile", InjectLibraryFile);
  Nan::SetPrototypeMethod(tpl, "injectLibraryBlob", InjectLibraryBlob);
  Nan::SetPrototypeMethod(tpl, "openChannel", OpenChannel);
  Nan::SetPrototypeMethod(tpl, "openService", OpenService);
  Nan::SetPrototypeMethod(tpl, "unpair", Unpair);

  auto ctor = Nan::GetFunction(tpl).ToLocalChecked();
  Nan::Set(exports, name, ctor);
  runtime->SetDataPointer(DEVICE_DATA_CONSTRUCTOR,
      new Persistent<Function>(isolate, ctor));
}

Local<Object> Device::New(gpointer handle, Runtime* runtime) {
  auto ctor = Nan::New<Function>(
      *static_cast<Persistent<Function>*>(
      runtime->GetDataPointer(DEVICE_DATA_CONSTRUCTOR)));
  const int argc = 1;
  Local<Value> argv[argc] = { Nan::New<External>(handle) };
  return Nan::NewInstance(ctor, argc, argv).ToLocalChecked();
}

NAN_METHOD(Device::New) {
  if (!info.IsConstructCall()) {
    Nan::ThrowError("Use the `new` keyword to create a new instance");
    return;
  }

  if (info.Length() != 1 || !info[0]->IsExternal()) {
    Nan::ThrowTypeError("Bad argument, expected raw handle");
    return;
  }

  auto runtime = GetRuntimeFromConstructorArgs(info);

  auto handle = static_cast<FridaDevice*>(
      Local<External>::Cast(info[0])->Value());
  auto wrapper = new Device(handle, runtime);
  auto obj = info.This();
  wrapper->Wrap(obj);
  auto signals_obj = Signals::New(handle, runtime, TransformSignal, runtime);

  Nan::Set(obj, Nan::New("signals").ToLocalChecked(), signals_obj);

  auto signals_wrapper = ObjectWrap::Unwrap<Signals>(signals_obj);
  signals_wrapper->SetConnectCallback(OnConnect, runtime);
  signals_wrapper->SetDisconnectCallback(OnDisconnect, runtime);

  info.GetReturnValue().Set(obj);
}

NAN_PROPERTY_GETTER(Device::GetId) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Nan::New(frida_device_get_id(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Device::GetName) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Nan::New(frida_device_get_name(handle)).ToLocalChecked());
}

NAN_PROPERTY_GETTER(Device::GetIcon) {
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());
  auto handle = wrapper->GetHandle<FridaDevice>();

  GVariant* icon = frida_device_get_icon(handle);
  if (icon != NULL)
    info.GetReturnValue().Set(Runtime::ValueFromVariant(icon));
  else
    info.GetReturnValue().SetNull();
}

NAN_PROPERTY_GETTER(Device::GetType) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(Runtime::ValueFromEnum(
      frida_device_get_dtype(handle), FRIDA_TYPE_DEVICE_TYPE));
}

NAN_PROPERTY_GETTER(Device::GetBus) {
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());
  auto handle = wrapper->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Bus::New(frida_device_get_bus(handle), wrapper->runtime_));
}

NAN_PROPERTY_GETTER(Device::IsLost) {
  auto handle = ObjectWrap::Unwrap<Device>(
      info.Holder())->GetHandle<FridaDevice>();

  info.GetReturnValue().Set(
      Nan::New(static_cast<bool>(frida_device_is_lost(handle))));
}

namespace {

class QuerySystemParametersOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_query_system_parameters(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    parameters_ = frida_device_query_system_parameters_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto value = Runtime::ValueFromParametersDict(parameters_);
    g_hash_table_unref(parameters_);
    return value;
  }

 private:
  GHashTable* parameters_;
};

}

NAN_METHOD(Device::QuerySystemParameters) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new QuerySystemParametersOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class GetFrontmostApplicationOperation : public Operation<FridaDevice> {
 public:
  GetFrontmostApplicationOperation(FridaFrontmostQueryOptions* options)
    : application_(NULL),
      options_(options) {
  }

  ~GetFrontmostApplicationOperation() {
    g_object_unref(options_);
    g_clear_object(&application_);
  }

 protected:
  void Begin() {
    frida_device_get_frontmost_application(handle_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    application_ = frida_device_get_frontmost_application_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    if (application_ == NULL)
      return Nan::Null();
    return Application::New(application_, runtime_);
  }

 private:
  FridaApplication* application_;
  FridaFrontmostQueryOptions* options_;
};

}

NAN_METHOD(Device::GetFrontmostApplication) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 1) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto scope_value = info[0];

  auto options = frida_frontmost_query_options_new();
  bool valid = true;

  if (!scope_value->IsNull()) {
    FridaScope scope;
    if (Runtime::ValueToEnum(scope_value, FRIDA_TYPE_SCOPE, &scope))
      frida_frontmost_query_options_set_scope(options, scope);
    else
      valid = false;
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new GetFrontmostApplicationOperation(options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumerateApplicationsOperation : public Operation<FridaDevice> {
 public:
  EnumerateApplicationsOperation(FridaApplicationQueryOptions* options)
    : applications_(NULL),
      options_(options) {
  }

  ~EnumerateApplicationsOperation() {
    g_object_unref(options_);
    g_clear_object(&applications_);
  }

 protected:
  void Begin() {
    frida_device_enumerate_applications(handle_, options_, cancellable_,
        OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    applications_ = frida_device_enumerate_applications_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_application_list_size(applications_);
    auto applications = Nan::New<Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_application_list_get(applications_, i);
      auto application = Application::New(handle, runtime_);
      Nan::Set(applications, i, application);
      g_object_unref(handle);
    }
    return applications;
  }

 private:
  FridaApplicationList* applications_;
  FridaApplicationQueryOptions* options_;
};

}

NAN_METHOD(Device::EnumerateApplications) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto identifiers_value = info[0];
  auto scope_value = info[1];

  auto options = frida_application_query_options_new();
  bool valid = true;

  if (identifiers_value->IsArray()) {
    auto array = Local<Array>::Cast(identifiers_value);

    uint32_t n = array->Length();

    for (uint32_t i = 0; i != n; i++) {
      auto element_value = Nan::Get(array, i).ToLocalChecked();

      if (!element_value->IsString()) {
        Nan::ThrowTypeError("Bad argument, not a valid application ID");
        valid = false;
        break;
      }
      Nan::Utf8String identifier(element_value);

      frida_application_query_options_select_identifier(options, *identifier);
    }
  } else {
    Nan::ThrowTypeError("Bad argument, 'identifiers' must be an array of "
        "application IDs");
    valid = false;
  }

  if (valid && !scope_value->IsNull()) {
    FridaScope scope;
    if (Runtime::ValueToEnum(scope_value, FRIDA_TYPE_SCOPE, &scope))
      frida_application_query_options_set_scope(options, scope);
    else
      valid = false;
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new EnumerateApplicationsOperation(options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumerateProcessesOperation : public Operation<FridaDevice> {
 public:
  EnumerateProcessesOperation(FridaProcessQueryOptions* options)
    : processes_(NULL),
      options_(options) {
  }

  ~EnumerateProcessesOperation() {
    g_object_unref(options_);
    g_clear_object(&processes_);
  }

 protected:
  void Begin() {
    frida_device_enumerate_processes(handle_, options_, cancellable_, OnReady,
        this);
  }

  void End(GAsyncResult* result, GError** error) {
    processes_ = frida_device_enumerate_processes_finish(handle_, result,
        error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_process_list_size(processes_);
    auto processes = Nan::New<Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_process_list_get(processes_, i);
      auto process = Process::New(handle, runtime_);
      Nan::Set(processes, i, process);
      g_object_unref(handle);
    }
    return processes;
  }

 private:
  FridaProcessList* processes_;
  FridaProcessQueryOptions* options_;
};

}

NAN_METHOD(Device::EnumerateProcesses) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto pids_value = info[0];
  auto scope_value = info[1];

  auto options = frida_process_query_options_new();
  bool valid = true;

  if (pids_value->IsArray()) {
    auto array = Local<Array>::Cast(pids_value);

    uint32_t n = array->Length();

    for (uint32_t i = 0; i != n; i++) {
      auto element_value = Nan::Get(array, i).ToLocalChecked();

      int64_t pid = -1;
      if (element_value->IsNumber()) {
        pid = Nan::To<int64_t>(element_value).FromMaybe(-1);
      }
      if (pid < 0) {
        Nan::ThrowTypeError("Bad argument, not a valid process ID");
        valid = false;
        break;
      }

      frida_process_query_options_select_pid(options, pid);
    }
  } else {
    Nan::ThrowTypeError("Bad argument, 'pids' must be an array of process IDs");
    valid = false;
  }

  if (valid && !scope_value->IsNull()) {
    FridaScope scope;
    if (Runtime::ValueToEnum(scope_value, FRIDA_TYPE_SCOPE, &scope))
      frida_process_query_options_set_scope(options, scope);
    else
      valid = false;
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new EnumerateProcessesOperation(options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnableSpawnGatingOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_enable_spawn_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_enable_spawn_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Device::EnableSpawnGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new EnableSpawnGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class DisableSpawnGatingOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_disable_spawn_gating(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_disable_spawn_gating_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }
};

}

NAN_METHOD(Device::DisableSpawnGating) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new DisableSpawnGatingOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumeratePendingSpawnOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_enumerate_pending_spawn(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    pending_spawn_ = frida_device_enumerate_pending_spawn_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_spawn_list_size(pending_spawn_);
    auto pending_spawn = Nan::New<Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_spawn_list_get(pending_spawn_, i);
      auto spawn = Spawn::New(handle, runtime_);
      Nan::Set(pending_spawn, i, spawn);
      g_object_unref(handle);
    }

    g_object_unref(pending_spawn_);

    return pending_spawn;
  }

 private:
  FridaSpawnList* pending_spawn_;
};

}

NAN_METHOD(Device::EnumeratePendingSpawn) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new EnumeratePendingSpawnOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class EnumeratePendingChildrenOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_enumerate_pending_children(handle_, cancellable_, OnReady,
        this);
  }

  void End(GAsyncResult* result, GError** error) {
    pending_children_ = frida_device_enumerate_pending_children_finish(handle_,
        result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto size = frida_child_list_size(pending_children_);
    auto pending_children = Nan::New<Array>(size);
    for (auto i = 0; i != size; i++) {
      auto handle = frida_child_list_get(pending_children_, i);
      auto child = Child::New(handle, runtime_);
      Nan::Set(pending_children, i, child);
      g_object_unref(handle);
    }

    g_object_unref(pending_children_);

    return pending_children;
  }

 private:
  FridaChildList* pending_children_;
};

}

NAN_METHOD(Device::EnumeratePendingChildren) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  auto operation = new EnumeratePendingChildrenOperation();
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class SpawnOperation : public Operation<FridaDevice> {
 public:
  SpawnOperation(gchar* program, FridaSpawnOptions* options)
    : program_(program),
      options_(options) {
  }

  ~SpawnOperation() {
    g_object_unref(options_);
    g_free(program_);
  }

 protected:
  void Begin() {
    frida_device_spawn(handle_, program_, options_, cancellable_, OnReady,
        this);
  }

  void End(GAsyncResult* result, GError** error) {
    pid_ = frida_device_spawn_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<Uint32>(pid_);
  }

 private:
  gchar* program_;
  FridaSpawnOptions* options_;
  guint pid_;
};

}

NAN_METHOD(Device::Spawn) {
  auto isolate = info.GetIsolate();
  auto context = isolate->GetCurrentContext();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 7) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto program_value = info[0];
  auto argv_value = info[1];
  auto envp_value = info[2];
  auto env_value = info[3];
  auto cwd_value = info[4];
  auto stdio_value = info[5];
  auto aux_value = info[6];

  if (!program_value->IsString()) {
    Nan::ThrowTypeError("Bad argument, 'program' must be a string");
    return;
  }
  Nan::Utf8String program(program_value);

  auto options = frida_spawn_options_new();
  bool valid = true;

  if (!argv_value->IsNull()) {
    gchar** argv;
    gint argv_length;
    valid = Runtime::ValueToStrv(argv_value, &argv, &argv_length);
    if (valid) {
      frida_spawn_options_set_argv(options, argv, argv_length);
      g_strfreev(argv);
    }
  }

  if (valid && !envp_value->IsNull()) {
    gchar** envp;
    gint envp_length;
    valid = Runtime::ValueToEnvp(envp_value, &envp, &envp_length);
    if (valid) {
      frida_spawn_options_set_envp(options, envp, envp_length);
      g_strfreev(envp);
    }
  }

  if (valid && !env_value->IsNull()) {
    gchar** env;
    gint env_length;
    valid = Runtime::ValueToEnvp(env_value, &env, &env_length);
    if (valid) {
      frida_spawn_options_set_env(options, env, env_length);
      g_strfreev(env);
    }
  }

  if (valid && !cwd_value->IsNull()) {
    if (cwd_value->IsString()) {
      Nan::Utf8String cwd(cwd_value);
      frida_spawn_options_set_cwd(options, *cwd);
    } else {
      Nan::ThrowTypeError("Bad argument, 'cwd' must be a string");
      valid = false;
    }
  }

  if (valid && !stdio_value->IsNull()) {
    FridaStdio stdio;
    valid = Runtime::ValueToEnum(stdio_value, FRIDA_TYPE_STDIO, &stdio);
    if (valid)
      frida_spawn_options_set_stdio(options, stdio);
  }

  if (valid) {
    if (aux_value->IsObject()) {
      auto object = Local<Object>::Cast(aux_value);

      Local<Array> keys(object->GetOwnPropertyNames(context).ToLocalChecked());
      uint32_t n = keys->Length();

      GHashTable* aux = frida_spawn_options_get_aux(options);

      for (uint32_t i = 0; i != n; i++) {
        auto key = Nan::Get(keys, i).ToLocalChecked();
        auto value = Nan::Get(object, key).ToLocalChecked();
        if (value->IsUndefined()) {
          continue;
        }

        Nan::Utf8String k(key);

        auto v = Runtime::ValueToVariant(value);
        if (v == NULL) {
          valid = false;
          break;
        }

        g_hash_table_insert(aux, g_strdup(*k), g_variant_ref_sink(v));
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'aux' must be an object");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new SpawnOperation(g_strdup(*program), options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class InputOperation : public Operation<FridaDevice> {
 public:
  InputOperation(guint pid, GBytes* data)
    : pid_(pid), data_(data) {
  }

  ~InputOperation() {
    g_bytes_unref(data_);
  }

 protected:
  void Begin() {
    frida_device_input(handle_, pid_, data_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_input_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  const guint pid_;
  GBytes* data_;
};

}

NAN_METHOD(Device::Input) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 2 || !info[0]->IsNumber() ||
      !node::Buffer::HasInstance(info[1])) {
    Nan::ThrowTypeError("Bad argument, expected pid and data");
    return;
  }

  auto pid = Nan::To<int64_t>(info[0]).FromMaybe(0);
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad pid");
    return;
  }

  auto buffer = info[1];
  auto data = g_bytes_new(node::Buffer::Data(buffer),
      node::Buffer::Length(buffer));

  auto operation = new InputOperation(static_cast<guint>(pid), data);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class ResumeOperation : public Operation<FridaDevice> {
 public:
  ResumeOperation(guint pid) : pid_(pid) {
  }

 protected:
  void Begin() {
    frida_device_resume(handle_, pid_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_resume_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  const guint pid_;
};

}

NAN_METHOD(Device::Resume) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto pid = Nan::To<int64_t>(info[0]).FromMaybe(0);
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto operation = new ResumeOperation(static_cast<guint>(pid));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class KillOperation : public Operation<FridaDevice> {
 public:
  KillOperation(guint pid) : pid_(pid) {
  }

 protected:
  void Begin() {
    frida_device_kill(handle_, pid_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_kill_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::Undefined();
  }

 private:
  const guint pid_;
};

}

NAN_METHOD(Device::Kill) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto pid = Nan::To<int64_t>(info[0]).FromMaybe(0);
  if (pid <= 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto operation = new KillOperation(static_cast<guint>(pid));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class AttachOperation : public Operation<FridaDevice> {
 public:
  AttachOperation(guint pid, FridaSessionOptions* options)
    : pid_(pid),
      options_(options) {
  }

  ~AttachOperation() {
    g_object_unref(options_);
  }

 protected:
  void Begin() {
    frida_device_attach(handle_, pid_, options_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    session_ = frida_device_attach_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Session::New(session_, runtime_);
    g_object_unref(session_);
    return wrapper;
  }

 private:
  const guint pid_;
  FridaSessionOptions* options_;
  FridaSession* session_;
};

}

NAN_METHOD(Device::Attach) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 3) {
    Nan::ThrowTypeError("Missing one or more arguments");
    return;
  }

  auto pid_value = info[0];
  auto realm_value = info[1];
  auto persist_timeout_value = info[2];

  int64_t pid = -1;
  if (pid_value->IsNumber()) {
    pid = Nan::To<int64_t>(pid_value).FromMaybe(-1);
  }
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }

  auto options = frida_session_options_new();
  bool valid = true;

  if (!realm_value->IsNull()) {
    FridaRealm realm;
    if (Runtime::ValueToEnum(realm_value, FRIDA_TYPE_REALM, &realm))
      frida_session_options_set_realm(options, realm);
    else
      valid = false;
  }

  if (valid && !persist_timeout_value->IsNull()) {
    if (persist_timeout_value->IsNumber()) {
      auto persist_timeout =
          Nan::To<int32_t>(persist_timeout_value).FromMaybe(-1);
      if (persist_timeout >= 0) {
        frida_session_options_set_persist_timeout(options, persist_timeout);
      } else {
        Nan::ThrowTypeError("Bad argument, invalid 'persistTimeout'");
        valid = false;
      }
    } else {
      Nan::ThrowTypeError("Bad argument, 'persistTimeout' must be a number");
      valid = false;
    }
  }

  if (!valid) {
    g_object_unref(options);
    return;
  }

  auto operation = new AttachOperation(static_cast<guint>(pid), options);
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class InjectLibraryFileOperation : public Operation<FridaDevice> {
 public:
  InjectLibraryFileOperation(guint pid, gchar* path, gchar* entrypoint,
      gchar* data)
    : pid_(pid),
      path_(path),
      entrypoint_(entrypoint),
      data_(data) {
  }

  ~InjectLibraryFileOperation() {
    g_free(data_);
    g_free(entrypoint_);
    g_free(path_);
  }

 protected:
  void Begin() {
    frida_device_inject_library_file(handle_, pid_, path_, entrypoint_, data_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    id_ = frida_device_inject_library_file_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<Uint32>(id_);
  }

 private:
  const guint pid_;
  gchar* path_;
  gchar* entrypoint_;
  gchar* data_;
  guint id_;
};

}

NAN_METHOD(Device::InjectLibraryFile) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 4 || !info[0]->IsNumber() || !info[1]->IsString() ||
      !info[2]->IsString() || !info[3]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }

  auto pid = Nan::To<int64_t>(info[0]).FromMaybe(-1);
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  Nan::Utf8String path(info[1]);
  Nan::Utf8String entrypoint(info[2]);
  Nan::Utf8String data(info[3]);

  auto operation = new InjectLibraryFileOperation(static_cast<guint>(pid),
      g_strdup(*path), g_strdup(*entrypoint), g_strdup(*data));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class InjectLibraryBlobOperation : public Operation<FridaDevice> {
 public:
  InjectLibraryBlobOperation(guint pid, GBytes* blob, gchar* entrypoint,
      gchar* data)
    : pid_(pid),
      blob_(blob),
      entrypoint_(entrypoint),
      data_(data) {
  }

  ~InjectLibraryBlobOperation() {
    g_free(data_);
    g_free(entrypoint_);
    g_bytes_unref(blob_);
  }

 protected:
  void Begin() {
    frida_device_inject_library_blob(handle_, pid_, blob_, entrypoint_, data_,
        cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    id_ = frida_device_inject_library_blob_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    return Nan::New<Uint32>(id_);
  }

 private:
  const guint pid_;
  GBytes* blob_;
  gchar* entrypoint_;
  gchar* data_;
  guint id_;
};

}

NAN_METHOD(Device::InjectLibraryBlob) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 4 || !info[0]->IsNumber() ||
      !node::Buffer::HasInstance(info[1]) || !info[2]->IsString() ||
      !info[3]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }

  auto pid = Nan::To<int64_t>(info[0]).FromMaybe(-1);
  if (pid < 0) {
    Nan::ThrowTypeError("Bad argument, expected pid");
    return;
  }
  auto buffer = info[1];
  auto blob = g_bytes_new(node::Buffer::Data(buffer),
      node::Buffer::Length(buffer));
  Nan::Utf8String entrypoint(info[2]);
  Nan::Utf8String data(info[3]);

  auto operation = new InjectLibraryBlobOperation(static_cast<guint>(pid),
      blob, g_strdup(*entrypoint), g_strdup(*data));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class OpenChannelOperation : public Operation<FridaDevice> {
 public:
  OpenChannelOperation(gchar* address)
    : address_(address),
      stream_(NULL) {
  }

  ~OpenChannelOperation() {
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_device_open_channel(handle_, address_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    stream_ = frida_device_open_channel_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = IOStream::New(stream_, runtime_);
    g_object_unref(stream_);
    return wrapper;
  }

 private:
  gchar* address_;
  GIOStream* stream_;
};

}

NAN_METHOD(Device::OpenChannel) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }
  Nan::Utf8String address(info[0]);

  auto operation = new OpenChannelOperation(g_strdup(*address));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class OpenServiceOperation : public Operation<FridaDevice> {
 public:
  OpenServiceOperation(gchar* address)
    : address_(address) {
  }

  ~OpenServiceOperation() {
    g_free(address_);
  }

 protected:
  void Begin() {
    frida_device_open_service(handle_, address_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    service_ = frida_device_open_service_finish(handle_, result, error);
  }

  Local<Value> Result(Isolate* isolate) {
    auto wrapper = Service::New(service_, runtime_);
    g_object_unref(service_);
    return wrapper;
  }

 private:
  gchar* address_;
  FridaService* service_;
};

}

NAN_METHOD(Device::OpenService) {
  auto isolate = info.GetIsolate();
  auto wrapper = ObjectWrap::Unwrap<Device>(info.Holder());

  if (info.Length() < 1 || !info[0]->IsString()) {
    Nan::ThrowTypeError("Bad argument");
    return;
  }
  Nan::Utf8String address(info[0]);

  auto operation = new OpenServiceOperation(g_strdup(*address));
  operation->Schedule(isolate, wrapper, info);

  info.GetReturnValue().Set(operation->GetPromise(isolate));
}

namespace {

class UnpairOperation : public Operation<FridaDevice> {
 protected:
  void Begin() {
    frida_device_unpair(handle_, cancellable_, OnReady, this);
  }

  void End(GAsyncResult* result, GError** error) {
    frida_device_unpair_finish(handle_, result, error);
  }

  Local<Value> Result(
```
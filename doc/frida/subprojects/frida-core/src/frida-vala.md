Response:
### 功能归纳

`frida.vala` 是 Frida 工具的核心源代码文件之一，主要实现了 Frida 的核心功能，包括设备管理、进程管理、注入、调试等功能。以下是该文件的主要功能归纳：

1. **初始化与关闭**：
   - `init()` 和 `init_with_runtime()`：初始化 Frida 运行时环境。
   - `shutdown()` 和 `deinit()`：关闭 Frida 运行时环境，释放资源。

2. **设备管理**：
   - `DeviceManager` 类：管理设备的添加、移除、查找等操作。支持本地设备、远程设备和 USB 设备的管理。
   - `Device` 类：表示一个设备，提供了查询系统参数、枚举应用程序、枚举进程、注入等功能。

3. **进程管理**：
   - `Process` 类：表示一个进程，提供了获取进程信息、查找进程、枚举进程等功能。
   - `Spawn` 和 `Child` 类：表示新生成的进程或子进程，提供了枚举、管理这些进程的功能。

4. **注入与调试**：
   - `spawn()`：启动一个新进程并注入 Frida 的调试代码。
   - `resume()`：恢复一个被暂停的进程。
   - `kill()`：终止一个进程。
   - `input()`：向进程的标准输入发送数据。

5. **信号与事件处理**：
   - `Device` 类中定义了多个信号，如 `spawn_added`、`spawn_removed`、`child_added`、`child_removed` 等，用于处理进程生成、子进程添加、进程崩溃等事件。

6. **异步操作**：
   - 大部分操作都提供了异步和同步两种方式，如 `get_device_by_id()` 和 `get_device_by_id_sync()`，分别用于异步和同步获取设备。

### 涉及二进制底层与 Linux 内核的功能

1. **进程注入**：
   - `spawn()` 和 `resume()` 函数涉及到进程的创建和控制，这些操作通常需要与操作系统内核交互，特别是在 Linux 系统中，可能需要使用 `ptrace` 系统调用来控制进程的执行。

2. **进程管理**：
   - `enumerate_processes()` 函数用于枚举系统中的所有进程，这通常需要调用系统 API 来获取进程列表。在 Linux 中，这可能是通过读取 `/proc` 文件系统来实现的。

3. **信号处理**：
   - `process_crashed` 信号用于处理进程崩溃事件，这通常涉及到操作系统内核发送的信号（如 `SIGSEGV`）的处理。

### LLDB 调试示例

假设我们想要调试 `spawn()` 函数的执行过程，可以使用 LLDB 进行调试。以下是一个简单的 LLDB Python 脚本示例，用于跟踪 `spawn()` 函数的调用：

```python
import lldb

def spawn_trace(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    # 设置断点在 spawn 函数
    breakpoint = target.BreakpointCreateByName("frida_device_spawn")
    breakpoint.SetCondition("pid == 1234")  # 假设我们只关心特定进程 ID 的 spawn

    # 运行程序
    process.Continue()

    # 打印调用栈
    for frame in thread:
        print(frame)

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f spawn_trace.spawn_trace spawn_trace')
```

### 假设输入与输出

假设我们调用 `spawn()` 函数启动一个新进程：

- **输入**：
  - `program`: `/bin/ls`
  - `options`: `{ "argv": ["-l", "/"], "env": { "PATH": "/usr/bin" } }`

- **输出**：
  - 返回新进程的 PID，例如 `1234`。

### 常见使用错误

1. **设备未找到**：
   - 用户尝试通过 `get_device_by_id()` 获取一个不存在的设备 ID，导致抛出 `Error.INVALID_ARGUMENT` 异常。
   - **示例**：
     ```vala
     try {
         var device = device_manager.get_device_by_id("nonexistent_id");
     } catch (Error e) {
         print("Error: %s", e.message);
     }
     ```

2. **进程未找到**：
   - 用户尝试通过 `get_process_by_pid()` 获取一个不存在的进程 PID，导致抛出 `Error.INVALID_ARGUMENT` 异常。
   - **示例**：
     ```vala
     try {
         var process = device.get_process_by_pid(9999);
     } catch (Error e) {
         print("Error: %s", e.message);
     }
     ```

### 用户操作步骤

1. **初始化 Frida**：
   - 用户调用 `Frida.init()` 初始化 Frida 运行时。

2. **获取设备管理器**：
   - 用户通过 `DeviceManager` 类获取设备管理器实例。

3. **查找设备**：
   - 用户调用 `get_device_by_id()` 或 `get_device_by_type()` 查找特定设备。

4. **枚举进程**：
   - 用户调用 `enumerate_processes()` 枚举设备上的所有进程。

5. **注入与调试**：
   - 用户调用 `spawn()` 启动一个新进程并注入 Frida 的调试代码，然后使用 `resume()` 恢复进程执行。

6. **处理事件**：
   - 用户监听 `spawn_added`、`child_added` 等信号，处理进程生成、子进程添加等事件。

通过这些步骤，用户可以逐步实现进程的调试和控制。
Prompt: 
```
这是目录为frida/subprojects/frida-core/src/frida.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
[CCode (gir_namespace = "Frida", gir_version = "1.0")]
namespace Frida {
	public extern void init ();
	public extern void init_with_runtime (Runtime runtime);
	public extern void shutdown ();
	public extern void deinit ();
	public extern unowned MainContext get_main_context ();

	public extern void unref (void * obj);

	public extern void version (out uint major, out uint minor, out uint micro, out uint nano);
	public extern unowned string version_string ();

	public enum Runtime {
		GLIB,
		OTHER;

		public static Runtime from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Runtime> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Runtime> (this);
		}
	}

	public class DeviceManager : Object {
		public signal void added (Device device);
		public signal void removed (Device device);
		public signal void changed ();

		public delegate bool Predicate (Device device);

		private Promise<bool> start_request;
		private Promise<bool> stop_request;

		private HostSessionService service = null;
		private Gee.ArrayList<Device> devices = new Gee.ArrayList<Device> ();
		private Gee.ArrayList<DeviceObserverEntry> on_device_added = new Gee.ArrayList<DeviceObserverEntry> ();

		private Cancellable io_cancellable = new Cancellable ();

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield stop_service (cancellable);
		}

		public void close_sync (Cancellable? cancellable = null) throws IOError {
			try {
				create<CloseTask> ().execute (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private class CloseTask : ManagerTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.close (cancellable);
			}
		}

		public async Device get_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return check_device (yield find_device_by_id (id, timeout, cancellable));
		}

		public Device get_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return check_device (find_device_by_id_sync (id, timeout, cancellable));
		}

		public async Device get_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (yield find_device_by_type (type, timeout, cancellable));
		}

		public Device get_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (find_device_by_type_sync (type, timeout, cancellable));
		}

		public async Device get_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (yield find_device (predicate, timeout, cancellable));
		}

		public Device get_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return check_device (find_device_sync (predicate, timeout, cancellable));
		}

		private Device check_device (Device? device) throws Error {
			if (device == null)
				throw new Error.INVALID_ARGUMENT ("Device not found");
			return device;
		}

		public async Device? find_device_by_id (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return yield find_device ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public Device? find_device_by_id_sync (string id, int timeout = 0, Cancellable? cancellable = null) throws Error, IOError {
			return find_device_sync ((device) => { return device.id == id; }, timeout, cancellable);
		}

		public async Device? find_device_by_type (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return yield find_device ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public Device? find_device_by_type_sync (DeviceType type, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			return find_device_sync ((device) => { return device.dtype == type; }, timeout, cancellable);
		}

		public async Device? find_device (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			foreach (var device in devices) {
				if (predicate (device))
					return device;
			}

			bool started = start_request != null && start_request.future.ready;
			if (started && timeout == 0)
				return null;

			Device? added_device = null;
			var addition_observer = new DeviceObserverEntry ((device) => {
				if (predicate (device)) {
					added_device = device;
					find_device.callback ();
				}
			});
			on_device_added.add (addition_observer);

			Source? timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (find_device.callback);
				timeout_source.attach (MainContext.get_thread_default ());
			}

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (find_device.callback);
			cancel_source.attach (MainContext.get_thread_default ());

			bool waiting = false;

			if (!started) {
				ensure_service_and_then_call.begin (() => {
						if (waiting && timeout == 0)
							find_device.callback ();
						return false;
					}, io_cancellable);
			}

			waiting = true;
			yield;
			waiting = false;

			cancel_source.destroy ();

			if (timeout_source != null)
				timeout_source.destroy ();

			on_device_added.remove (addition_observer);

			return added_device;
		}

		public Device? find_device_sync (Predicate predicate, int timeout = 0, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<FindDeviceTask> () as FindDeviceTask;
			task.predicate = (device) => {
				return predicate (device);
			};
			task.timeout = timeout;
			return task.execute (cancellable);
		}

		private class FindDeviceTask : ManagerTask<Device?> {
			public Predicate predicate;
			public int timeout;

			protected override async Device? perform_operation () throws Error, IOError {
				return yield parent.find_device (predicate, timeout, cancellable);
			}
		}

		public async DeviceList enumerate_devices (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield ensure_service (cancellable);

			return new DeviceList (devices.slice (0, devices.size));
		}

		public DeviceList enumerate_devices_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumerateDevicesTask> ().execute (cancellable);
		}

		private class EnumerateDevicesTask : ManagerTask<DeviceList> {
			protected override async DeviceList perform_operation () throws Error, IOError {
				return yield parent.enumerate_devices (cancellable);
			}
		}

		public async Device add_remote_device (string address, RemoteDeviceOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
#if HAVE_SOCKET_BACKEND
			check_open ();

			var socket_device = yield get_device ((device) => {
					return device.provider is SocketHostSessionProvider;
				}, 0, cancellable);

			string id = "socket@" + address;

			foreach (var device in devices) {
				if (device.id == id)
					return device;
			}

			unowned string name = address;

			var raw_options = new HostSessionOptions ();
			var opts = raw_options.map;
			opts["address"] = address;
			if (options != null) {
				TlsCertificate? cert = options.certificate;
				if (cert != null)
					opts["certificate"] = cert;

				string? origin = options.origin;
				if (origin != null)
					opts["origin"] = origin;

				string? token = options.token;
				if (token != null)
					opts["token"] = token;

				int interval = options.keepalive_interval;
				if (interval != -1)
					opts["keepalive_interval"] = interval;
			}

			var device = new Device (this, socket_device.provider, id, name, raw_options);
			devices.add (device);
			added (device);
			changed ();

			return device;
#else
			throw new Error.NOT_SUPPORTED ("Socket backend not available");
#endif
		}

		public Device add_remote_device_sync (string address, RemoteDeviceOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<AddRemoteDeviceTask> ();
			task.address = address;
			task.options = options;
			return task.execute (cancellable);
		}

		private class AddRemoteDeviceTask : ManagerTask<Device> {
			public string address;
			public RemoteDeviceOptions? options;

			protected override async Device perform_operation () throws Error, IOError {
				return yield parent.add_remote_device (address, options, cancellable);
			}
		}

		public async void remove_remote_device (string address, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			yield ensure_service (cancellable);

			string id = "socket@" + address;

			foreach (var device in devices) {
				if (device.id == id) {
					yield device._do_close (APPLICATION_REQUESTED, true, cancellable);
					removed (device);
					changed ();
					return;
				}
			}

			throw new Error.INVALID_ARGUMENT ("Device not found");
		}

		public void remove_remote_device_sync (string address, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<RemoveRemoteDeviceTask> ();
			task.address = address;
			task.execute (cancellable);
		}

		private class RemoveRemoteDeviceTask : ManagerTask<void> {
			public string address;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.remove_remote_device (address, cancellable);
			}
		}

		internal void _release_device (Device device) {
			var device_did_exist = devices.remove (device);
			assert (device_did_exist);
		}

		private async void ensure_service (Cancellable? cancellable) throws Error, IOError {
			if (start_request == null) {
				start_request = new Promise<bool> ();
				start_service.begin ();
			}

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			} catch (IOError e) {
				cancellable.set_error_if_cancelled ();
				throw new Error.INVALID_OPERATION ("DeviceManager is closing");
			}
		}

		private async void ensure_service_and_then_call (owned SourceFunc callback, Cancellable cancellable) {
			var source = new IdleSource ();
			source.set_callback (ensure_service_and_then_call.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield ensure_service (cancellable);
			} catch (GLib.Error e) {
			}

			callback ();
		}

		private async void start_service () {
			service = new HostSessionService.with_default_backends ();
			try {
				service.provider_available.connect (on_provider_available);
				service.provider_unavailable.connect (on_provider_unavailable);

				yield service.start (io_cancellable);

				start_request.resolve (true);
			} catch (IOError e) {
				service.provider_available.disconnect (on_provider_available);
				service.provider_unavailable.disconnect (on_provider_unavailable);
				service = null;

				start_request.reject (e);
				start_request = null;
			}
		}

		private void on_provider_available (HostSessionProvider provider) {
			var device = new Device (this, provider);
			devices.add (device);

			foreach (var observer in on_device_added.to_array ())
				observer.func (device);

			var started = start_request.future.ready;
			if (started) {
				added (device);
				changed ();
			}
		}

		private void on_provider_unavailable (HostSessionProvider provider) {
			var started = start_request.future.ready;

			foreach (var device in devices) {
				if (device.provider == provider) {
					if (started)
						removed (device);
					device._do_close.begin (DEVICE_LOST, false, io_cancellable);
					break;
				}
			}

			if (started)
				changed ();
		}

		private void check_open () throws Error {
			if (stop_request != null)
				throw new Error.INVALID_OPERATION ("Device manager is closed");
		}

		private async void stop_service (Cancellable? cancellable) throws IOError {
			while (stop_request != null) {
				try {
					yield stop_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			stop_request = new Promise<bool> ();

			io_cancellable.cancel ();

			try {
				if (start_request != null) {
					try {
						yield ensure_service (cancellable);
					} catch (GLib.Error e) {
						cancellable.set_error_if_cancelled ();
					}
				}

				foreach (var device in devices.to_array ())
					yield device._do_close (APPLICATION_REQUESTED, true, cancellable);
				devices.clear ();

				if (service != null) {
					yield service.stop (cancellable);
					service.provider_available.disconnect (on_provider_available);
					service.provider_unavailable.disconnect (on_provider_unavailable);
					service = null;
				}

				stop_request.resolve (true);
			} catch (IOError e) {
				stop_request.reject (e);
				stop_request = null;
				throw e;
			}
		}

		private T create<T> () {
			return Object.new (typeof (T), parent: this);
		}

		private abstract class ManagerTask<T> : AsyncTask<T> {
			public weak DeviceManager parent {
				get;
				construct;
			}
		}

		private delegate void DeviceObserverFunc (Device device);

		private class DeviceObserverEntry {
			public DeviceObserverFunc func;

			public DeviceObserverEntry (owned DeviceObserverFunc func) {
				this.func = (owned) func;
			}
		}
	}

	public class DeviceList : Object {
		private Gee.List<Device> items;

		internal DeviceList (Gee.List<Device> items) {
			this.items = items;
		}

		public int size () {
			return items.size;
		}

		public new Device get (int index) {
			return items.get (index);
		}
	}

	public class Device : Object {
		public signal void spawn_added (Spawn spawn);
		public signal void spawn_removed (Spawn spawn);
		public signal void child_added (Child child);
		public signal void child_removed (Child child);
		public signal void process_crashed (Crash crash);
		public signal void output (uint pid, int fd, Bytes data);
		public signal void uninjected (uint id);
		public signal void lost ();

		public string id {
			get {
				if (_id != null)
					return _id;
				return provider.id;
			}
		}

		public string name {
			get {
				if (_name != null)
					return _name;
				return provider.name;
			}
		}

		public Variant? icon {
			get;
			construct;
		}

		public DeviceType dtype {
			get {
				switch (provider.kind) {
					case HostSessionProviderKind.LOCAL:
						return DeviceType.LOCAL;
					case HostSessionProviderKind.REMOTE:
						return DeviceType.REMOTE;
					case HostSessionProviderKind.USB:
						return DeviceType.USB;
					default:
						assert_not_reached ();
				}
			}
		}

		public Bus bus {
			get {
				return _bus;
			}
		}

		private string? _id;
		private string? _name;
		internal HostSessionProvider provider;
		private unowned DeviceManager? manager;

		private HostSessionOptions? host_session_options;
		private Promise<HostSession>? host_session_request;
		private Promise<bool>? close_request;

		internal HostSession? current_host_session;
		private Gee.HashMap<AgentSessionId?, Session> agent_sessions =
			new Gee.HashMap<AgentSessionId?, Session> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.HashSet<Promise<Session>> pending_attach_requests = new Gee.HashSet<Promise<Session>> ();
		private Gee.HashMap<AgentSessionId?, Promise<bool>> pending_detach_requests =
			new Gee.HashMap<AgentSessionId?, Promise<bool>> (AgentSessionId.hash, AgentSessionId.equal);
		private Gee.Set<Service> services = new Gee.HashSet<Service> ();
		private Bus _bus;

		public delegate bool ProcessPredicate (Process process);

		internal Device (DeviceManager? mgr, HostSessionProvider prov, string? id = null, string? name = null,
				HostSessionOptions? options = null) {
			Object (icon: prov.icon);

			_id = id;
			_name = name;
			manager = mgr;
			host_session_options = options;

			assign_provider (prov);
		}

		construct {
			_bus = new Bus (this);
		}

		private void assign_provider (HostSessionProvider prov) {
			provider = prov;
			provider.host_session_detached.connect (on_host_session_detached);
			provider.agent_session_detached.connect (on_agent_session_detached);
		}

		public bool is_lost () {
			return close_request != null;
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				return yield host_session.query_system_parameters (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public HashTable<string, Variant> query_system_parameters_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<QuerySystemParametersTask> ().execute (cancellable);
		}

		private class QuerySystemParametersTask : DeviceTask<HashTable<string, Variant>> {
			protected override async HashTable<string, Variant> perform_operation () throws Error, IOError {
				return yield parent.query_system_parameters (cancellable);
			}
		}

		public async Application? get_frontmost_application (FrontmostQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			try {
				var app = yield host_session.get_frontmost_application (raw_options, cancellable);

				if (app.pid == 0)
					return null;

				return new Application (app.identifier, app.name, app.pid, app.parameters);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public Application? get_frontmost_application_sync (FrontmostQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<GetFrontmostApplicationTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class GetFrontmostApplicationTask : DeviceTask<Application?> {
			public FrontmostQueryOptions? options;

			protected override async Application? perform_operation () throws Error, IOError {
				return yield parent.get_frontmost_application (options, cancellable);
			}
		}

		public async ApplicationList enumerate_applications (ApplicationQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			HostApplicationInfo[] applications;
			try {
				applications = yield host_session.enumerate_applications (raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Application> ();
			foreach (var app in applications)
				result.add (new Application (app.identifier, app.name, app.pid, app.parameters));
			return new ApplicationList (result);
		}

		public ApplicationList enumerate_applications_sync (ApplicationQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnumerateApplicationsTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class EnumerateApplicationsTask : DeviceTask<ApplicationList> {
			public ApplicationQueryOptions? options;

			protected override async ApplicationList perform_operation () throws Error, IOError {
				return yield parent.enumerate_applications (options, cancellable);
			}
		}

		public async Process get_process_by_pid (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process_by_pid (pid, options, cancellable));
		}

		public Process get_process_by_pid_sync (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_by_pid_sync (pid, options, cancellable));
		}

		public async Process get_process_by_name (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process_by_name (name, options, cancellable));
		}

		public Process get_process_by_name_sync (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_by_name_sync (name, options, cancellable));
		}

		public async Process get_process (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (yield find_process (predicate, options, cancellable));
		}

		public Process get_process_sync (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return check_process (find_process_sync (predicate, options, cancellable));
		}

		private Process check_process (Process? process) throws Error {
			if (process == null)
				throw new Error.INVALID_ARGUMENT ("Process not found");
			return process;
		}

		public async Process? find_process_by_pid (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return yield find_process ((process) => { return process.pid == pid; }, options, cancellable);
		}

		public Process? find_process_by_pid_sync (uint pid, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			return find_process_sync ((process) => { return process.pid == pid; }, options, cancellable);
		}

		public async Process? find_process_by_name (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var folded_name = name.casefold ();
			return yield find_process ((process) => { return process.name.casefold () == folded_name; }, options, cancellable);
		}

		public Process? find_process_by_name_sync (string name, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var folded_name = name.casefold ();
			return find_process_sync ((process) => { return process.name.casefold () == folded_name; }, options, cancellable);
		}

		public async Process? find_process (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			Process? process = null;
			bool done = false;
			bool waiting = false;
			var main_context = MainContext.get_thread_default ();

			ProcessMatchOptions opts = (options != null) ? options : new ProcessMatchOptions ();
			int timeout = opts.timeout;

			ProcessQueryOptions enumerate_options = new ProcessQueryOptions ();
			enumerate_options.scope = opts.scope;

			Source? timeout_source = null;
			if (timeout > 0) {
				timeout_source = new TimeoutSource (timeout);
				timeout_source.set_callback (() => {
					done = true;
					if (waiting)
						find_process.callback ();
					return false;
				});
				timeout_source.attach (main_context);
			}

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				done = true;
				if (waiting)
					find_process.callback ();
				return false;
			});
			cancel_source.attach (MainContext.get_thread_default ());

			try {
				while (!done) {
					var processes = yield enumerate_processes (enumerate_options, cancellable);

					var num_processes = processes.size ();
					for (var i = 0; i != num_processes; i++) {
						var p = processes.get (i);
						if (predicate (p)) {
							process = p;
							break;
						}
					}

					if (process != null || done || timeout == 0)
						break;

					var delay_source = new TimeoutSource (500);
					delay_source.set_callback (find_process.callback);
					delay_source.attach (main_context);

					waiting = true;
					yield;
					waiting = false;

					delay_source.destroy ();
				}
			} finally {
				cancel_source.destroy ();

				if (timeout_source != null)
					timeout_source.destroy ();
			}

			return process;
		}

		public Process? find_process_sync (ProcessPredicate predicate, ProcessMatchOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<FindProcessTask> ();
			task.predicate = (process) => {
				return predicate (process);
			};
			task.options = options;
			return task.execute (cancellable);
		}

		private class FindProcessTask : DeviceTask<Process?> {
			public ProcessPredicate predicate;
			public ProcessMatchOptions? options;

			protected override async Process? perform_operation () throws Error, IOError {
				return yield parent.find_process (predicate, options, cancellable);
			}
		}

		public async ProcessList enumerate_processes (ProcessQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var raw_options = (options != null) ? options._serialize () : make_parameters_dict ();

			var host_session = yield get_host_session (cancellable);

			HostProcessInfo[] processes;
			try {
				processes = yield host_session.enumerate_processes (raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Process> ();
			foreach (var p in processes)
				result.add (new Process (p.pid, p.name, p.parameters));
			return new ProcessList (result);
		}

		public ProcessList enumerate_processes_sync (ProcessQueryOptions? options = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var task = create<EnumerateProcessesTask> ();
			task.options = options;
			return task.execute (cancellable);
		}

		private class EnumerateProcessesTask : DeviceTask<ProcessList> {
			public ProcessQueryOptions? options;

			protected override async ProcessList perform_operation () throws Error, IOError {
				return yield parent.enumerate_processes (options, cancellable);
			}
		}

		public async void enable_spawn_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void enable_spawn_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<EnableSpawnGatingTask> ().execute (cancellable);
		}

		private class EnableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.enable_spawn_gating (cancellable);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void disable_spawn_gating_sync (Cancellable? cancellable = null) throws Error, IOError {
			create<DisableSpawnGatingTask> ().execute (cancellable);
		}

		private class DisableSpawnGatingTask : DeviceTask<void> {
			protected override async void perform_operation () throws Error, IOError {
				yield parent.disable_spawn_gating (cancellable);
			}
		}

		public async SpawnList enumerate_pending_spawn (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostSpawnInfo[] pending_spawn;
			try {
				pending_spawn = yield host_session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Spawn> ();
			foreach (var p in pending_spawn)
				result.add (Spawn.from_info (p));
			return new SpawnList (result);
		}

		public SpawnList enumerate_pending_spawn_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumeratePendingSpawnTask> ().execute (cancellable);
		}

		private class EnumeratePendingSpawnTask : DeviceTask<SpawnList> {
			protected override async SpawnList perform_operation () throws Error, IOError {
				return yield parent.enumerate_pending_spawn (cancellable);
			}
		}

		public async ChildList enumerate_pending_children (Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			HostChildInfo[] pending_children;
			try {
				pending_children = yield host_session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			var result = new Gee.ArrayList<Child> ();
			foreach (var p in pending_children)
				result.add (Child.from_info (p));
			return new ChildList (result);
		}

		public ChildList enumerate_pending_children_sync (Cancellable? cancellable = null) throws Error, IOError {
			return create<EnumeratePendingChildrenTask> ().execute (cancellable);
		}

		private class EnumeratePendingChildrenTask : DeviceTask<ChildList> {
			protected override async ChildList perform_operation () throws Error, IOError {
				return yield parent.enumerate_pending_children (cancellable);
			}
		}

		public async uint spawn (string program, SpawnOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			check_open ();

			var raw_options = HostSpawnOptions ();
			if (options != null) {
				var argv = options.argv;
				if (argv != null) {
					raw_options.has_argv = true;
					raw_options.argv = argv;
				}

				var envp = options.envp;
				if (envp != null) {
					raw_options.has_envp = true;
					raw_options.envp = envp;
				}

				var env = options.env;
				if (env != null) {
					raw_options.has_env = true;
					raw_options.env = env;
				}

				var cwd = options.cwd;
				if (cwd != null)
					raw_options.cwd = cwd;

				raw_options.stdio = options.stdio;

				raw_options.aux = options.aux;
			}

			var host_session = yield get_host_session (cancellable);

			uint pid;
			try {
				pid = yield host_session.spawn (program, raw_options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			return pid;
		}

		public uint spawn_sync (string program, SpawnOptions? options = null, Cancellable? cancellable = null)
				throws Error, IOError {
			var task = create<SpawnTask> ();
			task.program = program;
			task.options = options;
			return task.execute (cancellable);
		}

		private class SpawnTask : DeviceTask<uint> {
			public string program;
			public SpawnOptions? options;

			protected override async uint perform_operation () throws Error, IOError {
				return yield parent.spawn (program, options, cancellable);
			}
		}

		public async void input (uint pid, Bytes data, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.input (pid, data.get_data (), cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void input_sync (uint pid, Bytes data, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<InputTask> ();
			task.pid = pid;
			task.data = data;
			task.execute (cancellable);
		}

		private class InputTask : DeviceTask<void> {
			public uint pid;
			public Bytes data;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.input (pid, data, cancellable);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public void resume_sync (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var task = create<ResumeTask> ();
			task.pid = pid;
			task.execute (cancellable);
		}

		private class ResumeTask : DeviceTask<void> {
			public uint pid;

			protected override async void perform_operation () throws Error, IOError {
				yield parent.resume (pid, cancellable);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			check_open ();

			var host_session = yield get_host_session (cancellable);

			try {
				yield host_session.kill (pid, cancellable);
			} catch (GLib.Error e) {
				/* The process being killed might be the other end of the connection. */
				if (!(e is IOError.CLOSED))
					throw_dbus_error (e);
			}
		}

"""


```
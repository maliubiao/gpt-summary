Response:
### 功能归纳

该文件是 Frida 动态插桩工具的核心部分，主要功能包括设备管理、进程管理、应用程序管理、进程注入、进程控制等。以下是该文件的主要功能归纳：

1. **设备管理**：
   - **设备枚举**：通过 `DeviceManager` 类，可以枚举本地和远程设备，支持通过设备 ID、设备类型或自定义条件查找设备。
   - **设备添加与移除**：支持添加和移除远程设备，并处理设备的连接和断开事件。
   - **设备状态管理**：管理设备的生命周期，包括设备的启动、关闭、连接状态等。

2. **进程管理**：
   - **进程枚举**：通过 `Device` 类，可以枚举当前设备上的所有进程，支持通过进程 ID、进程名称或自定义条件查找进程。
   - **进程控制**：支持对进程进行控制，包括启动进程 (`spawn`)、恢复进程 (`resume`)、终止进程 (`kill`) 等操作。
   - **进程注入**：支持向目标进程注入代码，并监控进程的输出。

3. **应用程序管理**：
   - **应用程序枚举**：可以枚举设备上运行的应用程序，支持通过应用程序名称、ID 等条件查找应用程序。
   - **应用程序控制**：支持获取当前前台运行的应用程序 (`get_frontmost_application`)。

4. **进程注入与控制**：
   - **进程注入**：支持向目标进程注入代码，并监控进程的输出。
   - **进程控制**：支持对进程进行控制，包括启动进程 (`spawn`)、恢复进程 (`resume`)、终止进程 (`kill`) 等操作。

5. **信号与事件处理**：
   - **信号处理**：通过信号机制处理设备、进程、应用程序的状态变化，如设备添加、移除、进程崩溃等事件。
   - **事件监听**：支持监听进程的输出、崩溃、子进程创建等事件。

6. **异步操作**：
   - **异步任务**：通过 `async` 和 `yield` 关键字实现异步操作，支持异步设备管理、进程管理、应用程序管理等操作。

### 涉及二进制底层与 Linux 内核的部分

1. **进程控制**：
   - `spawn`、`resume`、`kill` 等操作涉及对进程的直接控制，这些操作通常需要与操作系统内核交互，通过系统调用（如 `fork`、`exec`、`kill` 等）来实现。
   - 例如，`spawn` 操作可能会调用 `fork` 和 `exec` 系统调用来创建新进程，`kill` 操作可能会调用 `kill` 系统调用来终止进程。

2. **进程注入**：
   - 进程注入通常涉及将代码注入到目标进程的地址空间中，并修改目标进程的执行流程。这通常需要与操作系统内核交互，使用 `ptrace` 系统调用或其他类似的机制来实现。

3. **设备管理**：
   - 设备管理涉及与硬件设备的交互，如 USB 设备、网络设备等。这些操作通常需要与 Linux 内核的驱动程序交互，使用 `ioctl` 系统调用来控制设备。

### 使用 LLDB 复刻调试功能的示例

假设我们想要复刻 `spawn` 功能，即启动一个新进程并注入代码。我们可以使用 LLDB 的 Python 脚本来实现类似的功能。

#### LLDB Python 脚本示例

```python
import lldb

def spawn_process(debugger, command, result, internal_dict):
    # 解析命令参数
    args = command.split()
    if len(args) < 1:
        result.AppendMessage("Usage: spawn <program> [args...]")
        return

    program = args[0]
    args = args[1:]

    # 获取当前目标
    target = debugger.GetSelectedTarget()
    if not target:
        result.AppendMessage("No target selected.")
        return

    # 启动新进程
    launch_info = lldb.SBLaunchInfo(args)
    launch_info.SetExecutableFile(lldb.SBFileSpec(program), True)
    error = lldb.SBError()
    process = target.Launch(launch_info, error)

    if error.Success():
        result.AppendMessage(f"Process {process.GetProcessID()} launched successfully.")
    else:
        result.AppendMessage(f"Failed to launch process: {error}")

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f spawn_process.spawn_process spawn')
```

#### 使用示例

在 LLDB 中加载脚本并执行 `spawn` 命令：

```bash
(lldb) command script import /path/to/spawn_process.py
(lldb) spawn /bin/ls -l
```

### 假设输入与输出

假设我们有一个设备管理器 `DeviceManager`，我们想要查找一个设备并启动一个进程。

#### 输入

```vala
var manager = new DeviceManager ();
var device = manager.get_device_by_id_sync ("local");
var pid = device.spawn_sync ("/bin/ls", new SpawnOptions ());
```

#### 输出

- 如果设备存在且进程启动成功，输出将是进程的 PID。
- 如果设备不存在或进程启动失败，将抛出异常。

### 用户常见的使用错误

1. **设备未找到**：
   - 用户尝试通过不存在的设备 ID 查找设备，导致 `Error.INVALID_ARGUMENT` 异常。
   - 示例：`manager.get_device_by_id_sync ("nonexistent_device")`。

2. **进程未找到**：
   - 用户尝试通过不存在的进程 ID 或名称查找进程，导致 `Error.INVALID_ARGUMENT` 异常。
   - 示例：`device.get_process_by_pid_sync (9999)`。

3. **异步操作未等待**：
   - 用户在异步操作中未正确使用 `yield`，导致操作未完成就继续执行后续代码。
   - 示例：`device.spawn ("/bin/ls")` 未使用 `yield`。

### 用户操作如何一步步到达这里

1. **初始化设备管理器**：
   - 用户首先初始化 `DeviceManager`，准备管理设备。

2. **查找设备**：
   - 用户通过设备 ID 或类型查找设备，获取 `Device` 对象。

3. **枚举进程或应用程序**：
   - 用户通过 `Device` 对象枚举当前设备上的进程或应用程序。

4. **启动进程**：
   - 用户通过 `Device` 对象的 `spawn` 方法启动一个新进程。

5. **控制进程**：
   - 用户通过 `resume`、`kill` 等方法控制进程的执行。

6. **处理信号与事件**：
   - 用户通过信号机制处理设备、进程、应用程序的状态变化。

通过这些步骤，用户可以逐步实现对设备的控制、进程的管理以及代码的注入。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/frida.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
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
```
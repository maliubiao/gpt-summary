Response:
### 功能归纳

`fruity-host-session.vala` 是 Frida 工具中用于与 iOS 设备进行交互的核心模块。它主要负责管理与 iOS 设备的连接、会话的创建与销毁、进程的调试与控制等功能。以下是该文件的主要功能归纳：

1. **设备管理**：
   - 通过 `FruityHostSessionBackend` 类管理 iOS 设备的连接与断开。
   - 使用 `Fruity.DeviceMonitor` 监控设备的连接状态，并在设备连接或断开时触发相应的事件处理。

2. **会话管理**：
   - `FruityHostSessionProvider` 类负责提供与设备的会话连接，支持通过 USB 或远程连接与设备通信。
   - 提供了创建、销毁、链接会话的功能，支持通过 `HostSession` 接口与设备进行交互。

3. **进程调试与控制**：
   - 通过 `FruityHostSession` 类实现对 iOS 进程的调试和控制，包括进程的启动、暂停、恢复、终止等操作。
   - 支持通过 LLDB（Low-Level Debugger）与 iOS 设备进行调试会话，允许用户附加到正在运行的进程或启动新的进程进行调试。

4. **系统信息查询**：
   - 提供了查询 iOS 设备系统信息的功能，包括操作系统版本、硬件信息、网络接口等。
   - 通过 `query_system_parameters` 方法获取设备的详细信息。

5. **应用程序管理**：
   - 支持枚举设备上安装的应用程序，获取应用程序的详细信息（如名称、版本、图标等）。
   - 提供了获取当前前台应用程序的功能。

6. **调试功能**：
   - 支持通过 LLDB 进行进程调试，允许用户附加到进程并控制其执行。
   - 提供了通过 `spawn` 方法启动新的进程进行调试的功能。

7. **错误处理与取消操作**：
   - 提供了对操作取消的支持，允许用户通过 `Cancellable` 对象取消正在进行的操作。
   - 对常见的错误进行了处理，如设备连接失败、会话创建失败等。

### 涉及二进制底层与 Linux 内核的示例

虽然该文件主要针对 iOS 设备，但其中涉及到的 LLDB 调试功能与底层二进制调试相关。LLDB 是一个低级别的调试器，常用于调试编译后的二进制文件。以下是一个使用 LLDB 进行调试的示例：

#### LLDB 调试示例

假设我们有一个 iOS 应用程序的二进制文件 `example_app`，我们可以使用 LLDB 进行调试：

```bash
# 启动 LLDB 并附加到进程
lldb
(lldb) process attach --name example_app

# 设置断点
(lldb) breakpoint set --name main

# 继续执行
(lldb) continue

# 查看寄存器状态
(lldb) register read

# 单步执行
(lldb) step

# 查看内存
(lldb) memory read 0x1000
```

#### LLDB Python 脚本示例

LLDB 还支持通过 Python 脚本进行自动化调试。以下是一个简单的 LLDB Python 脚本示例，用于自动化调试过程：

```python
import lldb

def attach_and_break(process_name):
    # 创建调试器实例
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)

    # 创建目标
    target = debugger.CreateTargetWithFileAndArch(process_name, None)
    if not target:
        print(f"Failed to create target for {process_name}")
        return

    # 附加到进程
    process = target.AttachToProcessWithName(lldb.SBListener(), process_name, False)
    if not process:
        print(f"Failed to attach to process {process_name}")
        return

    # 设置断点
    breakpoint = target.BreakpointCreateByName("main")
    if not breakpoint:
        print("Failed to set breakpoint at main")
        return

    # 继续执行
    process.Continue()

    # 打印寄存器状态
    for thread in process:
        print(f"Thread {thread.GetThreadID()}:")
        for frame in thread:
            print(f"  {frame.GetFunctionName()} at {frame.GetPC()}")

    # 结束调试
    process.Detach()

# 调用函数进行调试
attach_and_break("example_app")
```

### 假设输入与输出

假设我们有一个 iOS 设备连接，并且我们想要调试一个名为 `com.example.app` 的应用程序：

1. **输入**：
   - 设备连接成功。
   - 用户请求附加到 `com.example.app` 进程。

2. **输出**：
   - 系统返回进程的 PID。
   - 用户可以通过 LLDB 控制进程的执行，设置断点、查看寄存器状态等。

### 常见使用错误

1. **设备未连接**：
   - 用户尝试调试时，设备未连接或未正确配置。
   - **解决方法**：确保设备已通过 USB 连接，并且已启用开发者模式。

2. **进程未运行**：
   - 用户尝试附加到一个未运行的进程。
   - **解决方法**：确保目标进程正在运行，或者使用 `spawn` 方法启动进程。

3. **权限不足**：
   - 用户尝试调试一个需要更高权限的进程。
   - **解决方法**：确保设备已越狱，或者使用合法的开发者证书进行调试。

### 用户操作步骤

1. **连接设备**：
   - 用户通过 USB 连接 iOS 设备，并确保设备已启用开发者模式。

2. **启动 Frida**：
   - 用户启动 Frida 工具，并选择与设备进行连接。

3. **选择目标进程**：
   - 用户通过 Frida 提供的接口选择要调试的目标进程。

4. **附加到进程**：
   - 用户通过 `attach` 方法附加到目标进程，系统返回进程的 PID。

5. **调试进程**：
   - 用户通过 LLDB 或其他调试工具控制进程的执行，设置断点、查看内存等。

6. **结束调试**：
   - 用户通过 `kill` 方法终止进程，或通过 `detach` 方法断开与进程的连接。

### 总结

`fruity-host-session.vala` 是 Frida 工具中用于与 iOS 设备进行交互的核心模块，提供了设备管理、会话管理、进程调试与控制等功能。通过 LLDB，用户可以深入调试 iOS 应用程序的二进制代码，查看寄存器状态、设置断点等。
Prompt: 
```
这是目录为frida/subprojects/frida-core/src/fruity/fruity-host-session.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
namespace Frida {
	public class FruityHostSessionBackend : Object, HostSessionBackend {
		private Fruity.DeviceMonitor device_monitor = new Fruity.DeviceMonitor ();
		private Gee.Map<Fruity.Device, FruityHostSessionProvider> providers =
			new Gee.HashMap<Fruity.Device, FruityHostSessionProvider> ();

		private Cancellable io_cancellable = new Cancellable ();

		construct {
			device_monitor.device_attached.connect (on_device_attached);
			device_monitor.device_detached.connect (on_device_detached);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			yield device_monitor.start (cancellable);
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			yield device_monitor.stop (cancellable);

			foreach (var provider in providers.values) {
				provider_unavailable (provider);
				yield provider.close (cancellable);
			}
			providers.clear ();
		}

		private void on_device_attached (Fruity.Device device) {
			var provider = new FruityHostSessionProvider (device);
			providers[device] = provider;
			provider_available (provider);
		}

		private void on_device_detached (Fruity.Device device) {
			FruityHostSessionProvider provider;
			if (providers.unset (device, out provider)) {
				provider_unavailable (provider);
				provider.close.begin (io_cancellable);
			}
		}
	}

	public class FruityHostSessionProvider : Object, HostSessionProvider, HostChannelProvider, HostServiceProvider, Pairable {
		public Fruity.Device device {
			get;
			construct;
		}

		public string id {
			get { return device.udid; }
		}

		public string name {
			get { return _name; }
		}

		public Variant? icon {
			get { return device.icon; }
		}

		public HostSessionProviderKind kind {
			get {
				return (device.connection_type == USB)
					? HostSessionProviderKind.USB
					: HostSessionProviderKind.REMOTE;
			}
		}

		private FruityHostSession? host_session;
		private string _name;

		public FruityHostSessionProvider (Fruity.Device device) {
			Object (device: device);
			_name = device.name;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			yield Fruity.DTXConnection.close_all (device, cancellable);
		}

		public async HostSession create (HostSessionOptions? options, Cancellable? cancellable) throws Error, IOError {
			if (host_session != null)
				throw new Error.INVALID_OPERATION ("Already created");

			host_session = new FruityHostSession (device);
			host_session.agent_session_detached.connect (on_agent_session_detached);

			return host_session;
		}

		public async void destroy (HostSession session, Cancellable? cancellable) throws Error, IOError {
			if (session != host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			host_session.agent_session_detached.disconnect (on_agent_session_detached);

			yield host_session.close (cancellable);
			host_session = null;
		}

		public async AgentSession link_agent_session (HostSession host_session, AgentSessionId id, AgentMessageSink sink,
				Cancellable? cancellable) throws Error, IOError {
			if (host_session != this.host_session)
				throw new Error.INVALID_ARGUMENT ("Invalid host session");

			return yield this.host_session.link_agent_session (id, sink, cancellable);
		}

		private void on_agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash) {
			agent_session_detached (id, reason, crash);
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			return yield device.open_channel (address, cancellable);
		}

		public async Service open_service (string address, Cancellable? cancellable) throws Error, IOError {
			string[] tokens = address.split (":", 2);
			unowned string protocol = tokens[0];
			unowned string service_name = tokens[1];

			if (protocol == "plist") {
				var stream = yield device.open_lockdown_service (service_name, cancellable);

				return new PlistService (stream);
			}

			if (protocol == "dtx") {
				var connection = yield Fruity.DTXConnection.obtain (device, cancellable);

				return new DTXService (service_name, connection);
			}

			if (protocol == "xpc") {
				var tunnel = yield device.find_tunnel (cancellable);
				if (tunnel == null)
					throw new Error.NOT_SUPPORTED ("RemoteXPC not supported by device");

				var service_info = tunnel.discovery.get_service (service_name);
				var stream = yield tunnel.open_tcp_connection (service_info.port, cancellable);

				return new XpcService (new Fruity.XpcConnection (stream));
			}

			throw new Error.NOT_SUPPORTED ("Unsupported service address");
		}

		private async void unpair (Cancellable? cancellable) throws Error, IOError {
			try {
				var client = yield device.get_lockdown_client (cancellable);
				yield client.unpair (cancellable);
			} catch (Fruity.LockdownError e) {
				if (e is Fruity.LockdownError.NOT_PAIRED)
					return;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	public class FruityHostSession : Object, HostSession {
		public Fruity.Device device {
			get;
			construct;
		}

		private Gee.HashMap<uint, LLDBSession> lldb_sessions = new Gee.HashMap<uint, LLDBSession> ();
		private Gee.HashMap<AgentSessionId?, GadgetEntry> gadget_entries =
			new Gee.HashMap<AgentSessionId?, GadgetEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Promise<RemoteServer>? remote_server_request;
		private RemoteServer? current_remote_server;
		private Timer? last_server_check_timer;
		private Error? last_server_check_error;
		private Gee.HashMap<AgentSessionId?, AgentSessionId?> remote_agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionId?> (AgentSessionId.hash, AgentSessionId.equal);

		private Gee.HashMap<AgentSessionId?, AgentSessionEntry> agent_sessions =
			new Gee.HashMap<AgentSessionId?, AgentSessionEntry> (AgentSessionId.hash, AgentSessionId.equal);

		private Cancellable io_cancellable = new Cancellable ();

		private const double MIN_SERVER_CHECK_INTERVAL = 5.0;
		private const string GADGET_APP_ID = "re.frida.Gadget";
		private const string DEBUGSERVER_ENDPOINT_17PLUS = "com.apple.internal.dt.remote.debugproxy";
		private const string DEBUGSERVER_ENDPOINT_14PLUS = "com.apple.debugserver.DVTSecureSocketProxy";
		private const string DEBUGSERVER_ENDPOINT_LEGACY = "com.apple.debugserver?tls=handshake-only";
		private const string[] DEBUGSERVER_ENDPOINT_CANDIDATES = {
			DEBUGSERVER_ENDPOINT_17PLUS,
			DEBUGSERVER_ENDPOINT_14PLUS,
			DEBUGSERVER_ENDPOINT_LEGACY,
		};

		public FruityHostSession (Fruity.Device device) {
			Object (device: device);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (remote_server_request != null) {
				try {
					var server = yield try_get_remote_server (cancellable);
					if (server != null) {
						try {
							yield server.connection.close (cancellable);
						} catch (GLib.Error e) {
						}
					}
				} catch (Error e) {
				}
			}

			while (!gadget_entries.is_empty) {
				var iterator = gadget_entries.values.iterator ();
				iterator.next ();
				var entry = iterator.get ();
				yield entry.close (cancellable);
			}

			while (!lldb_sessions.is_empty) {
				var iterator = lldb_sessions.values.iterator ();
				iterator.next ();
				var session = iterator.get ();
				yield session.close (cancellable);
			}

			io_cancellable.cancel ();
		}

		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.query_system_parameters (cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var parameters = new HashTable<string, Variant> (str_hash, str_equal);

			try {
				var lockdown = yield device.get_lockdown_client (cancellable);
				var response = yield lockdown.get_value (null, null, cancellable);
				Fruity.PlistDict properties = response.get_dict ("Value");

				var os = new HashTable<string, Variant> (str_hash, str_equal);
				os["id"] = "ios";
				os["name"] = properties.get_string ("ProductName");
				os["version"] = properties.get_string ("ProductVersion");
				os["build"] = properties.get_string ("BuildVersion");
				parameters["os"] = os;

				parameters["platform"] = "darwin";

				parameters["arch"] = properties.get_string ("CPUArchitecture").has_prefix ("arm64") ? "arm64" : "arm";

				var hardware = new HashTable<string, Variant> (str_hash, str_equal);
				hardware["product"] = properties.get_string ("ProductType");
				hardware["platform"] = properties.get_string ("HardwarePlatform");
				hardware["model"] = properties.get_string ("HardwareModel");
				parameters["hardware"] = hardware;

				parameters["access"] = "jailed";

				parameters["name"] = properties.get_string ("DeviceName");
				parameters["udid"] = properties.get_string ("UniqueDeviceID");

				add_interfaces (parameters, properties);
			} catch (Fruity.LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			} catch (Fruity.PlistError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return parameters;
		}

		private static void add_interfaces (HashTable<string, Variant> parameters,
				Fruity.PlistDict properties) throws Fruity.PlistError {
			var ifaces = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

			add_network_interface (ifaces, "ethernet", properties.get_string ("EthernetAddress"));
			add_network_interface (ifaces, "wifi", properties.get_string ("WiFiAddress"));
			add_network_interface (ifaces, "bluetooth", properties.get_string ("BluetoothAddress"));

			if (properties.has ("PhoneNumber")) {
				ifaces.open (VariantType.VARDICT);
				ifaces.add ("{sv}", "type", new Variant.string ("cellular"));
				ifaces.add ("{sv}", "phone-number", new Variant.string (properties.get_string ("PhoneNumber")));
				ifaces.close ();
			}

			parameters["interfaces"] = ifaces.end ();
		}

		private static void add_network_interface (VariantBuilder ifaces, string type, string address) {
			ifaces.open (VariantType.VARDICT);
			ifaces.add ("{sv}", "type", new Variant.string (type));
			ifaces.add ("{sv}", "address", new Variant.string (address));
			ifaces.close ();
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.get_frontmost_application (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = FrontmostQueryOptions._deserialize (options);
			var scope = opts.scope;

			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			Fruity.DeviceInfoService.ProcessInfo? process = null;
			string? app_path = null;
			foreach (Fruity.DeviceInfoService.ProcessInfo candidate in processes) {
				if (!candidate.foreground_running)
					continue;

				if (!candidate.is_application)
					continue;

				bool is_main_process;
				string path = compute_app_path_from_executable_path (candidate.real_app_name, out is_main_process);
				if (!is_main_process)
					continue;

				process = candidate;
				app_path = path;
				break;
			}
			if (process == null)
				return HostApplicationInfo.empty ();

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			Fruity.ApplicationDetails? app = apps.first_match (app => app.path == app_path);
			if (app == null)
				return HostApplicationInfo.empty ();

			unowned string identifier = app.identifier;

			var info = HostApplicationInfo (identifier, app.name, process.pid, make_parameters_dict ());

			if (scope != MINIMAL) {
				add_app_metadata (info.parameters, app);

				add_process_metadata (info.parameters, process);

				if (scope == FULL) {
					var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

					Bytes png = yield springboard.get_icon_png_data (identifier);
					add_app_icons (info.parameters, png);
				}
			}

			return info;
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_applications (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ApplicationQueryOptions._deserialize (options);
			var scope = opts.scope;

			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			fetch_apps.begin (apps_request, cancellable);
			fetch_processes.begin (processes_request, cancellable);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			apps = maybe_filter_apps (apps, opts);

			Gee.Map<string, Bytes>? icons = null;
			if (scope == FULL) {
				var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

				var app_ids = new Gee.ArrayList<string> ();
				foreach (var app in apps)
					app_ids.add (app.identifier);

				icons = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);
			}

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			var process_by_app_path = new Gee.HashMap<string, Fruity.DeviceInfoService.ProcessInfo> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
				bool is_main_process;
				string app_path = compute_app_path_from_executable_path (process.real_app_name, out is_main_process);
				if (is_main_process)
					process_by_app_path[app_path] = process;
			}

			var result = new HostApplicationInfo[0];

			foreach (Fruity.ApplicationDetails app in apps) {
				unowned string identifier = app.identifier;
				Fruity.DeviceInfoService.ProcessInfo? process = process_by_app_path[app.path];

				var info = HostApplicationInfo (identifier, app.name, (process != null) ? process.pid : 0,
					make_parameters_dict ());

				if (scope != MINIMAL) {
					add_app_metadata (info.parameters, app);

					if (process != null) {
						add_app_state (info.parameters, process);

						add_process_metadata (info.parameters, process);
					}
				}

				if (scope == FULL)
					add_app_icons (info.parameters, icons[identifier]);

				result += info;
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var app in yield server.session.enumerate_applications (options, cancellable))
						result += app;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && server.flavor == REGULAR) {
				try {
					return yield server.session.enumerate_processes (options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			var opts = ProcessQueryOptions._deserialize (options);
			var scope = opts.scope;

			var processes_request = new Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> ();
			var apps_request = new Promise<Gee.List<Fruity.ApplicationDetails>> ();
			fetch_processes.begin (processes_request, cancellable);
			fetch_apps.begin (apps_request, cancellable);

			Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes =
				yield processes_request.future.wait_async (cancellable);
			processes = maybe_filter_processes (processes, opts);

			Gee.List<Fruity.ApplicationDetails> apps = yield apps_request.future.wait_async (cancellable);
			var app_by_path = new Gee.HashMap<string, Fruity.ApplicationDetails> ();
			foreach (var app in apps)
				app_by_path[app.path] = app;

			var app_ids = new Gee.ArrayList<string> ();
			var app_pids = new Gee.ArrayList<uint> ();
			var app_by_main_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			var app_by_related_pid = new Gee.HashMap<uint, Fruity.ApplicationDetails> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
				unowned string executable_path = process.real_app_name;

				bool is_main_process;
				string app_path = compute_app_path_from_executable_path (executable_path, out is_main_process);

				Fruity.ApplicationDetails? app = app_by_path[app_path];
				if (app != null) {
					uint pid = process.pid;

					if (is_main_process) {
						app_ids.add (app.identifier);
						app_pids.add (pid);
						app_by_main_pid[pid] = app;
					} else {
						app_by_related_pid[pid] = app;
					}
				}
			}

			Gee.Map<uint, Bytes>? icon_by_pid = null;
			if (scope == FULL) {
				icon_by_pid = new Gee.HashMap<uint, Bytes> ();

				var springboard = yield Fruity.SpringboardServicesClient.open (device, cancellable);

				var pngs = yield springboard.get_icon_png_data_batch (app_ids.to_array (), cancellable);

				int i = 0;
				foreach (string app_id in app_ids) {
					icon_by_pid[app_pids[i]] = pngs[app_id];
					i++;
				}
			}

			var result = new HostProcessInfo[0];

			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes) {
				uint pid = process.pid;
				if (pid == 0)
					continue;

				Fruity.ApplicationDetails? app = app_by_main_pid[pid];
				string name = (app != null) ? app.name : process.name;

				var info = HostProcessInfo (pid, name, make_parameters_dict ());

				if (scope != MINIMAL) {
					var parameters = info.parameters;

					add_process_metadata (parameters, process);

					parameters["path"] = process.real_app_name;

					Fruity.ApplicationDetails? related_app = (app != null) ? app : app_by_related_pid[pid];
					if (related_app != null) {
						string[] applications = { related_app.identifier };
						parameters["applications"] = applications;
					}

					if (app != null && process.foreground_running)
						parameters["frontmost"] = true;
				}

				if (scope == FULL) {
					Bytes? png = icon_by_pid[pid];
					if (png != null)
						add_app_icons (info.parameters, png);
				}

				result += info;
			}

			if (server != null && server.flavor == GADGET) {
				try {
					foreach (var process in yield server.session.enumerate_processes (options, cancellable))
						result += process;
				} catch (GLib.Error e) {
				}
			}

			return result;
		}

		private async void fetch_apps (Promise<Gee.List<Fruity.ApplicationDetails>> promise, Cancellable? cancellable) {
			try {
				var installation_proxy = yield Fruity.InstallationProxyClient.open (device, cancellable);

				var apps = yield installation_proxy.browse (cancellable);

				promise.resolve (apps);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private async void fetch_processes (Promise<Gee.List<Fruity.DeviceInfoService.ProcessInfo>> promise,
				Cancellable? cancellable) {
			try {
				var device_info = yield Fruity.DeviceInfoService.open (device, cancellable);

				var processes = yield device_info.enumerate_processes (cancellable);

				promise.resolve (processes);
			} catch (GLib.Error e) {
				promise.reject (e);
			}
		}

		private Gee.List<Fruity.ApplicationDetails> maybe_filter_apps (Gee.List<Fruity.ApplicationDetails> apps,
				ApplicationQueryOptions options) {
			if (!options.has_selected_identifiers ())
				return apps;

			var app_by_identifier = new Gee.HashMap<string, Fruity.ApplicationDetails> ();
			foreach (Fruity.ApplicationDetails app in apps)
				app_by_identifier[app.identifier] = app;

			var filtered_apps = new Gee.ArrayList<Fruity.ApplicationDetails> ();
			options.enumerate_selected_identifiers (identifier => {
				Fruity.ApplicationDetails? app = app_by_identifier[identifier];
				if (app != null)
					filtered_apps.add (app);
			});

			return filtered_apps;
		}

		private Gee.List<Fruity.DeviceInfoService.ProcessInfo> maybe_filter_processes (
				Gee.List<Fruity.DeviceInfoService.ProcessInfo> processes, ProcessQueryOptions options) {
			if (!options.has_selected_pids ())
				return processes;

			var process_by_pid = new Gee.HashMap<uint, Fruity.DeviceInfoService.ProcessInfo> ();
			foreach (Fruity.DeviceInfoService.ProcessInfo process in processes)
				process_by_pid[process.pid] = process;

			var filtered_processes = new Gee.ArrayList<Fruity.DeviceInfoService.ProcessInfo> ();
			options.enumerate_selected_pids (pid => {
				Fruity.DeviceInfoService.ProcessInfo? process = process_by_pid[pid];
				if (process != null)
					filtered_processes.add (process);
			});

			return filtered_processes;
		}

		private static string compute_app_path_from_executable_path (string executable_path, out bool is_main_process) {
			string app_path = executable_path;

			int dot_app_start = app_path.last_index_of (".app/");
			if (dot_app_start != -1) {
				app_path = app_path[0:dot_app_start + 4];

				string subpath = executable_path[app_path.length + 1:];
				is_main_process = !("/" in subpath);
			} else {
				is_main_process = false;
			}

			return app_path;
		}

		private void add_app_metadata (HashTable<string, Variant> parameters, Fruity.ApplicationDetails app) {
			string? version = app.version;
			if (version != null)
				parameters["version"] = version;

			string? build = app.build;
			if (build != null)
				parameters["build"] = build;

			parameters["path"] = app.path;

			Gee.Map<string, string> containers = app.containers;
			if (!containers.is_empty) {
				var containers_dict = new VariantBuilder (VariantType.VARDICT);
				foreach (var entry in containers.entries)
					containers_dict.add ("{sv}", entry.key, new Variant.string (entry.value));
				parameters["containers"] = containers_dict.end ();
			}

			if (app.debuggable)
				parameters["debuggable"] = true;
		}

		private void add_app_state (HashTable<string, Variant> parameters, Fruity.DeviceInfoService.ProcessInfo process) {
			if (process.foreground_running)
				parameters["frontmost"] = true;
		}

		private void add_app_icons (HashTable<string, Variant> parameters, Bytes png) {
			var icons = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

			icons.open (VariantType.VARDICT);
			icons.add ("{sv}", "format", new Variant.string ("png"));
			icons.add ("{sv}", "image", Variant.new_from_data (new VariantType ("ay"), png.get_data (), true, png));
			icons.close ();

			parameters["icons"] = icons.end ();
		}

		private void add_process_metadata (HashTable<string, Variant> parameters, Fruity.DeviceInfoService.ProcessInfo? process) {
			DateTime? started = process.start_date;
			if (started != null)
				parameters["started"] = started.format_iso8601 ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.enable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.disable_spawn_gating (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_spawn (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				return yield server.session.enumerate_pending_children (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			var server = yield try_get_remote_server (cancellable);
			if (server != null && (server.flavor != GADGET || program == GADGET_APP_ID)) {
				try {
					return yield server.session.spawn (program, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}
			}

			if (program[0] == '/')
				throw new Error.NOT_SUPPORTED ("Only able to spawn apps");

			var launch_options = new LLDB.LaunchOptions ();

			if (options.has_envp)
				throw new Error.NOT_SUPPORTED ("The 'envp' option is not supported when spawning iOS apps");

			if (options.has_env)
				launch_options.env = options.env;

			if (options.cwd.length > 0)
				throw new Error.NOT_SUPPORTED ("The 'cwd' option is not supported when spawning iOS apps");

			HashTable<string, Variant> aux = options.aux;

			Variant? aslr = aux["aslr"];
			if (aslr != null) {
				if (!aslr.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'aslr' option must be a string");
				launch_options.aslr = LLDB.ASLR.from_nick (aslr.get_string ());
			}

			string? gadget_path = null;
			Variant? gadget_value = aux["gadget"];
			if (gadget_value != null) {
				if (!gadget_value.is_of_type (VariantType.STRING)) {
					throw new Error.INVALID_ARGUMENT ("The 'gadget' option must be a string pointing at the " +
						"frida-gadget.dylib to use");
				}
				gadget_path = gadget_value.get_string ();
			}

			var installation_proxy = yield Fruity.InstallationProxyClient.open (device, cancellable);

			var query = new Fruity.PlistDict ();
			var ids = new Fruity.PlistArray ();
			ids.add_string (program);
			query.set_array ("BundleIDs", ids);

			var matches = yield installation_proxy.lookup (query, cancellable);
			var app = matches[program];
			if (app == null)
				throw new Error.INVALID_ARGUMENT ("Unable to find app with bundle identifier “%s”", program);

			string[] argv = { app.path };
			if (options.has_argv) {
				var provided_argv = options.argv;
				var length = provided_argv.length;
				for (int i = 1; i < length; i++)
					argv += provided_argv[i];
			}

			var lldb = yield start_lldb_service (cancellable);
			var process = yield lldb.launch (argv, launch_options, cancellable);
			if (process.observed_state == ALREADY_RUNNING) {
				yield lldb.kill (cancellable);
				yield lldb.close (cancellable);

				lldb = yield start_lldb_service (cancellable);
				process = yield lldb.launch (argv, launch_options, cancellable);
			}

			var session = new LLDBSession (lldb, process, gadget_path, device);
			add_lldb_session (session);

			return process.pid;
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.input (pid, data, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			var session = lldb_sessions[pid];
			if (session != null) {
				yield session.resume (cancellable);
				return;
			}

			var server = yield get_remote_server (cancellable);
			try {
				yield server.session.resume (pid, cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			var lldb_session = lldb_sessions[pid];
			if (lldb_session != null) {
				yield lldb_session.kill (cancellable);
				return;
			}

			var server = yield try_get_remote_server (cancellable);
			if (server != null) {
				try {
					yield server.session.kill (pid, cancellable);
					return;
				} catch (GLib.Error e) {
					if (server.flavor == REGULAR)
						throw_dbus_error (e);
				}
			}

			try {
				var lldb = yield start_lldb_service (cancellable);
				var process = yield lldb.attach_by_pid (pid, cancellable);

				lldb_session = new LLDBSession (lldb, process, null, device);
				yield lldb_session.kill (cancellable);
				yield lldb_session.close (cancellable);
			} catch (Error e) {
				var process_control = yield Fruity.ProcessControlService.open (device, cancellable);
				yield process_control.kill (pid, cancellable);
			}
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			var lldb_session = lldb_sessions[pid];
			if (lldb_session != null) {
				var gadget_details = yield lldb_session.query_gadget_details (cancellable);

				return yield attach_via_gadget (pid, options, gadget_details, cancellable);
			}

			var server = yield try_get_remote_server (cancellable);
			if (server != null) {
				try {
					return yield attach_via_remote (pid, options, server, cancellable);
				} catch (Error e) {
					if (server.flavor == REGULAR)
						throw_api_error (e);
				}
			}

			if (pid == 0)
				throw new Error.NOT_SUPPORTED ("The Frida system session is not available on jailed iOS");

			var lldb = yield start_lldb_service (cancellable);
			var process = yield lldb.attach_by_pid (pid, cancellable);

			string? gadget_path = null;

			lldb_session = new LLDBSession (lldb, process, gadget_path, device);
			add_lldb_session (lldb_session);

			var gadget_details = yield lldb_session.query_gadget_details (cancellable);

			return yield attach_via_gadget (pid, options, gadget_details, cancellable);
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Only meant to be implemented by services");
		}

		private async LLDB.Client start_lldb_service (Cancellable? cancellable) throws Error, IOError {
			foreach (unowned string endpoint in DEBUGSERVER_ENDPOINT_CANDIDATES) {
				try {
					var lldb_stream = yield device.open_lockdown_service (endpoint, cancellable);
					return yield LLDB.Client.open (lldb_stream, cancellable);
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED))
						throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
			}

			throw new Error.NOT_SUPPORTED ("This feature requires an iOS Developer Disk Image to be mounted; " +
				"run Xcode briefly or use ideviceimagemounter to mount one manually");
		}

		private async AgentSessionId attach_via_gadget (uint pid, HashTable<string, Variant> options,
				Fruity.Injector.GadgetDetails gadget_details, Cancellable? cancellable) throws Error, IOError {
			try {
				var stream = yield device.open_channel (
					("tcp:%" + uint16.FORMAT_MODIFIER + "u").printf (gadget_details.port),
					cancellable);

				WebServiceTransport transport = PLAIN;
				string? origin = null;

				stream = yield negotiate_connection (stream, transport, "lolcathost", origin, cancellable);

				var connection = yield new DBusConnection (stream, null, DBusConnectionFlags.NONE, null, cancellable);

				HostSession host_session = yield connection.get_proxy (null, ObjectPath.HOST_SESSION,
					DO_NOT_LOAD_PROPERTIES, cancellable);

				AgentSessionId remote_session_id;
				try {
					remote_session_id = yield host_session.attach (pid, options, cancellable);
				} catch (GLib.Error e) {
					throw_dbus_error (e);
				}

				var local_session_id = AgentSessionId.generate ();
				var gadget_entry = new GadgetEntry (local_session_id, host_session, connection);
				gadget_entry.detached.connect (on_gadget_entry_detached);
				gadget_entries[local_session_id] = gadget_entry;
				agent_sessions[local_session_id] = new AgentSessionEntry (remote_session_id, connection);

				return local_session_id;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		private async AgentSessionId attach_via_remote (uint pid, HashTable<string, Variant> options, RemoteServer server,
				Cancellable? cancellable) throws Error, IOError {
			AgentSessionId remote_session_id;
			try {
				remote_session_id = yield server.session.attach (pid, options, cancellable);
			} catch (GLib.Error e) {
				throw_dbus
"""


```
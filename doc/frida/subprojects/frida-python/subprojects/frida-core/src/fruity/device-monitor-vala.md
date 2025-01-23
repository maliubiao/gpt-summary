Response:
### 功能归纳

`DeviceMonitor` 类是 Frida 工具中用于监控设备连接和断开的核心组件。它主要负责以下功能：

1. **设备监控**：
   - 监控设备的连接（`device_attached`）和断开（`device_detached`）。
   - 通过 `start` 和 `stop` 方法启动和停止设备监控。

2. **后端管理**：
   - 管理多个后端（`Backend`），如 `UsbmuxBackend` 和 `PortableCoreDeviceBackend`，用于处理不同类型的设备连接（如 USB 和网络）。
   - 每个后端负责具体的设备连接和断开事件，并通过信号通知 `DeviceMonitor`。

3. **设备管理**：
   - 维护一个设备列表（`devices`），记录当前连接的设备。
   - 通过 `Transport` 接口与设备进行通信，处理设备的连接、断开、数据传输等操作。

4. **设备连接类型**：
   - 支持 USB 和网络两种连接类型（`ConnectionType`）。
   - 通过 `Device` 类提供设备的详细信息，如 UDID、名称、图标等。

5. **USB 设备管理**：
   - 通过 `UsbmuxBackend` 处理 USB 设备的连接和断开。
   - 支持 USB 设备的模式切换（`modeswitch`），用于处理设备在不同模式下的连接。

6. **网络设备管理**：
   - 通过 `PortableCoreDeviceBackend` 处理网络设备的连接和断开。
   - 支持通过网络发现和配对设备。

7. **异步操作**：
   - 使用异步方法（`async`）处理设备的启动、停止、连接等操作，确保不会阻塞主线程。

### 涉及二进制底层和 Linux 内核的部分

1. **USB 设备管理**：
   - 通过 `LibUSB` 库与 USB 设备进行通信，处理 USB 设备的连接和断开。
   - 使用 `LibUSB.Context` 和 `LibUSB.Device` 等类与 USB 设备进行底层交互。

2. **网络设备管理**：
   - 通过 `PairingBrowser` 和 `PairingStore` 类处理网络设备的发现和配对。
   - 使用 `InetSocketAddress` 类处理网络设备的地址和端口信息。

### 使用 LLDB 复刻调试功能的示例

假设我们想要调试 `DeviceMonitor` 类的 `start` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令示例

```lldb
# 启动 LLDB 并附加到目标进程
lldb -p <pid>

# 在 `DeviceMonitor.start` 方法处设置断点
b frida::fruity::DeviceMonitor::start

# 运行程序
run

# 当断点触发时，打印当前状态
p state

# 继续执行
continue
```

#### LLDB Python 脚本示例

```python
import lldb

def start_device_monitor(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()

    # 设置断点
    breakpoint = target.BreakpointCreateByName("frida::fruity::DeviceMonitor::start")
    print(f"Breakpoint set at: {breakpoint}")

    # 运行程序
    process.Continue()

    # 当断点触发时，打印当前状态
    frame = thread.GetSelectedFrame()
    state = frame.FindVariable("state")
    print(f"Current state: {state}")

    # 继续执行
    process.Continue()

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f start_device_monitor.start_device_monitor start_device_monitor')
```

### 假设输入与输出

#### 输入
- 用户调用 `DeviceMonitor.start()` 方法启动设备监控。

#### 输出
- `DeviceMonitor` 类开始监控设备连接和断开。
- 当设备连接时，触发 `device_attached` 信号。
- 当设备断开时，触发 `device_detached` 信号。

### 用户常见使用错误

1. **未正确处理异步操作**：
   - 用户可能在调用 `start` 或 `stop` 方法时未正确处理异步操作，导致程序阻塞或崩溃。
   - 示例：未使用 `yield` 关键字等待异步操作完成。

2. **未正确处理设备断开**：
   - 用户可能在设备断开时未正确处理资源释放，导致内存泄漏或资源占用。
   - 示例：未调用 `device.close()` 方法释放设备资源。

### 用户操作如何一步步到达这里

1. **启动 Frida 工具**：
   - 用户启动 Frida 工具，加载目标应用程序。

2. **调用 `DeviceMonitor.start()`**：
   - 用户调用 `DeviceMonitor.start()` 方法，开始监控设备连接和断开。

3. **设备连接**：
   - 当设备连接时，`DeviceMonitor` 类触发 `device_attached` 信号，通知用户设备已连接。

4. **设备断开**：
   - 当设备断开时，`DeviceMonitor` 类触发 `device_detached` 信号，通知用户设备已断开。

5. **停止监控**：
   - 用户调用 `DeviceMonitor.stop()` 方法，停止设备监控。

通过以上步骤，用户可以监控设备的连接和断开状态，并进行相应的处理。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/device-monitor.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public sealed class DeviceMonitor : Object {
		public signal void device_attached (Device device);
		public signal void device_detached (Device device);

		private State state = CREATED;
		private Gee.List<Backend> backends = new Gee.ArrayList<Backend> ();
		private Gee.Map<string, Device> devices = new Gee.HashMap<string, Device> ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			STOPPED,
		}

		private delegate void NotifyCompleteFunc ();

		construct {
			add_backend (new UsbmuxBackend ());
#if MACOS
			add_backend (new MacOSCoreDeviceBackend ());
#else
			add_backend (new PortableCoreDeviceBackend ());
#endif
		}

		public async void start (Cancellable? cancellable = null) throws IOError {
			state = STARTING;

			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					start.callback ();
			};

			foreach (var backend in backends)
				do_start.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;

			var b = (PortableCoreDeviceBackend) backends.first_match (b => b is PortableCoreDeviceBackend);
			if (b != null && b.supports_modeswitch)
				yield b.activate_modeswitch_support (cancellable);

			state = STARTED;

			foreach (var device in devices.values)
				device_attached (device);
		}

		public async void stop (Cancellable? cancellable = null) throws IOError {
			var remaining = backends.size + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					stop.callback ();
			};

			foreach (var backend in backends)
				do_stop.begin (backend, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;

			foreach (var device in devices.values)
				device.close ();
			devices.clear ();

			state = STOPPED;
		}

		private async void do_start (Backend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.start (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private async void do_stop (Backend backend, Cancellable? cancellable, NotifyCompleteFunc on_complete) {
			try {
				yield backend.stop (cancellable);
			} catch (IOError e) {
			}

			on_complete ();
		}

		private void add_backend (Backend backend) {
			backends.add (backend);
			backend.transport_attached.connect (on_transport_attached);
			backend.transport_detached.connect (on_transport_detached);
		}

		private void on_transport_attached (Transport transport) {
			unowned string udid = transport.udid;

			var device = devices[udid];
			if (device == null) {
				device = new Device ();
				devices[udid] = device;
			}

			device.transports.add (transport);

			if (state != STARTING && device.transports.size == 1)
				device_attached (device);
		}

		private void on_transport_detached (Transport transport) {
			unowned string udid = transport.udid;

			var device = devices[udid];
			device.transports.remove (transport);
			if (device.transports.is_empty) {
				devices.unset (udid);

				if (state != STARTING)
					device_detached (device);
			}
		}
	}

	public sealed class Device : Object, HostChannelProvider {
		public ConnectionType connection_type {
			get {
				return (transports.first_match (t => t.connection_type == USB) != null)
					? ConnectionType.USB
					: ConnectionType.NETWORK;
			}
		}

		public string udid {
			get {
				foreach (var transport in transports)
					return transport.udid;
				assert_not_reached ();
			}
		}

		public string name {
			get {
				var transport = transports.first_match (t => t.name != null);
				if (transport == null)
					return "iOS Device";
				return transport.name;
			}
		}

		public Variant? icon {
			get {
				var transport = transports.first_match (t => t.icon != null);
				if (transport == null)
					return null;
				return transport.icon;
			}
		}

		public Gee.Set<Transport> transports {
			get;
			default = new Gee.TreeSet<Transport> (compare_transports);
		}

		private Gee.Queue<UsbmuxLockdownServiceRequest> usbmux_lockdown_service_requests =
			new Gee.ArrayQueue<UsbmuxLockdownServiceRequest> ();
		private LockdownClient? cached_usbmux_lockdown_client;

		internal void close () {
			transports.clear ();
		}

		public UsbmuxDevice? find_usbmux_device () {
			var transport = transports.first_match (t => t.usbmux_device != null && t.connection_type == USB);
			if (transport == null)
				transport = transports.first_match (t => t.usbmux_device != null);
			return (transport != null) ? transport.usbmux_device : null;
		}

		public UsbmuxDevice get_usbmux_device () throws Error {
			var d = find_usbmux_device ();
			if (d == null)
				throw new Error.NOT_SUPPORTED ("USB connection not available");
			return d;
		}

		public async Tunnel? find_tunnel (Cancellable? cancellable) throws Error, IOError {
			var usbmux_device = find_usbmux_device ();
			foreach (var transport in transports) {
				Tunnel? tunnel = yield transport.find_tunnel (usbmux_device, cancellable);
				if (tunnel != null)
					return tunnel;
			}
			return null;
		}

		public async LockdownClient get_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			var stream = yield open_lockdown_service ("", cancellable);
			return new LockdownClient (stream);
		}

		public async IOStream open_lockdown_service (string service_name, Cancellable? cancellable) throws Error, IOError {
			var tunnel = yield find_tunnel (cancellable);
			if (tunnel != null) {
				ServiceInfo? service_info = null;
				bool needs_checkin = service_name == "";
				try {
					service_info = tunnel.discovery.get_service (
						(service_name == "") ? "com.apple.mobile.lockdown.remote.trusted" : service_name);
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED))
						throw e;
				}
				if (service_info == null) {
					service_info = tunnel.discovery.get_service (service_name + ".shim.remote");
					needs_checkin = true;
				}

				var stream = yield tunnel.open_tcp_connection (service_info.port, cancellable);

				if (needs_checkin) {
					var service = new PlistServiceClient (stream);

					var checkin = new Plist ();
					checkin.set_string ("Request", "RSDCheckin");
					checkin.set_string ("Label", "Xcode");
					checkin.set_string ("ProtocolVersion", "2");

					try {
						yield service.query (checkin, cancellable);

						var result = yield service.read_message (cancellable);
						if (result.has ("Error")) {
							var error_type = result.get_string ("Error");
							if (error_type == "ServiceProhibited")
								throw new Error.PERMISSION_DENIED ("Service prohibited");
							throw new Error.NOT_SUPPORTED ("%s", error_type);
						}
					} catch (PlistServiceError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					} catch (PlistError e) {
						throw new Error.PROTOCOL ("%s", e.message);
					}
				}

				return stream;
			}

			if (service_name == "") {
				var client = yield open_usbmux_lockdown_client (cancellable);
				return client.service.stream;
			}

			var request = new UsbmuxLockdownServiceRequest (service_name, cancellable);
			bool first_request = usbmux_lockdown_service_requests.is_empty;
			usbmux_lockdown_service_requests.offer (request);

			if (first_request)
				process_usbmux_lockdown_service_requests.begin ();

			return yield request.promise.future.wait_async (cancellable);
		}

		private async void process_usbmux_lockdown_service_requests () {
			UsbmuxLockdownServiceRequest? req;
			bool already_invalidated = false;
			while ((req = usbmux_lockdown_service_requests.peek ()) != null) {
				try {
					if (cached_usbmux_lockdown_client == null)
						cached_usbmux_lockdown_client = yield open_usbmux_lockdown_client (req.cancellable);
					var stream = yield cached_usbmux_lockdown_client.start_service (req.service_name, req.cancellable);
					req.promise.resolve (stream);
				} catch (GLib.Error e) {
					if (e is LockdownError.CONNECTION_CLOSED && cached_usbmux_lockdown_client != null &&
							!already_invalidated) {
						cached_usbmux_lockdown_client = null;
						already_invalidated = true;
						continue;
					}
					req.promise.reject ((e is LockdownError.INVALID_SERVICE)
						? (Error) new Error.NOT_SUPPORTED ("%s", e.message)
						: (Error) new Error.TRANSPORT ("%s", e.message));
				}

				usbmux_lockdown_service_requests.poll ();
			}
		}

		private async LockdownClient open_usbmux_lockdown_client (Cancellable? cancellable) throws Error, IOError {
			try {
				var client = yield LockdownClient.open (get_usbmux_device (), cancellable);
				yield client.start_session (cancellable);
				return client;
			} catch (LockdownError e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}

		public async IOStream open_channel (string address, Cancellable? cancellable) throws Error, IOError {
			string[] tokens = address.split (":", 2);
			unowned string protocol = tokens[0];
			unowned string location = tokens[1];

			if (protocol == "tcp") {
				var channel = yield open_tcp_channel (location, ALLOW_ANY_TRANSPORT, cancellable);
				return channel.stream;
			}

			if (protocol == "lockdown")
				return yield open_lockdown_service (location, cancellable);

			throw new Error.NOT_SUPPORTED ("Unsupported channel address");
		}

		public async TcpChannel open_tcp_channel (string location, OpenTcpChannelFlags flags, Cancellable? cancellable)
				throws Error, IOError {
			var usbmux_device = find_usbmux_device ();
			var tunnel = yield find_tunnel (cancellable);

			uint16 port;
			ulong raw_port;
			if (ulong.try_parse (location, out raw_port)) {
				if (raw_port == 0 || raw_port > uint16.MAX)
					throw new Error.INVALID_ARGUMENT ("Invalid TCP port");
				port = (uint16) raw_port;
			} else {
				if (tunnel == null)
					throw new Error.NOT_SUPPORTED ("Unable to resolve port name; tunnel not available");
				if ((flags & OpenTcpChannelFlags.ALLOW_TUNNEL) == 0)
					throw new Error.NOT_SUPPORTED ("Connection to tunnel service not allowed by flags");
				var service_info = tunnel.discovery.get_service (location);
				port = service_info.port;
			}

			Error? pending_error = null;

			if ((flags & OpenTcpChannelFlags.ALLOW_TUNNEL) != 0 && tunnel != null) {
				try {
					var stream = yield tunnel.open_tcp_connection (port, cancellable);
					return new TcpChannel () { stream = stream, kind = TUNNEL };
				} catch (Error e) {
					if (e is Error.SERVER_NOT_RUNNING)
						pending_error = e;
					else
						throw e;
				}
			}

			if ((flags & OpenTcpChannelFlags.ALLOW_USBMUX) != 0 && usbmux_device != null) {
				if (usbmux_device.connection_type == USB) {
					UsbmuxClient client = null;
					try {
						client = yield UsbmuxClient.open (cancellable);

						yield client.connect_to_port (usbmux_device.id, port, cancellable);

						return new TcpChannel () { stream = client.connection, kind = USBMUX };
					} catch (GLib.Error e) {
						if (client != null)
							client.close.begin ();

						if (e is UsbmuxError.CONNECTION_REFUSED)
							throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

						throw new Error.TRANSPORT ("%s", e.message);
					}
				}

				InetSocketAddress device_address = usbmux_device.network_address;
				var target_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: device_address.address,
					port: port,
					flowinfo: device_address.flowinfo,
					scope_id: device_address.scope_id
				);

				var client = new SocketClient ();
				try {
					var connection = yield client.connect_async (target_address, cancellable);

					Tcp.enable_nodelay (connection.socket);

					return new TcpChannel () { stream = connection, kind = USBMUX };
				} catch (GLib.Error e) {
					if (e is IOError.CONNECTION_REFUSED)
						throw new Error.SERVER_NOT_RUNNING ("%s", e.message);

					throw new Error.TRANSPORT ("%s", e.message);
				}
			}

			if (pending_error != null)
				throw pending_error;
			throw new Error.TRANSPORT ("No viable transport found");
		}

		private static int compare_transports (Transport a, Transport b) {
			return score_transport (b) - score_transport (a);
		}

		private static int score_transport (Transport t) {
			int score = 0;
			if (t.connection_type == USB)
				score++;
			if (t.usbmux_device != null)
				score++;
			return score;
		}

		private class UsbmuxLockdownServiceRequest {
			public string service_name;
			public Cancellable? cancellable;
			public Promise<IOStream> promise = new Promise<IOStream> ();

			public UsbmuxLockdownServiceRequest (string service_name, Cancellable? cancellable) {
				this.service_name = service_name;
				this.cancellable = cancellable;
			}
		}
	}

	public class TcpChannel {
		public IOStream stream;
		public Kind kind;

		public enum Kind {
			USBMUX,
			TUNNEL
		}
	}

	[Flags]
	public enum OpenTcpChannelFlags {
		ALLOW_USBMUX,
		ALLOW_TUNNEL,
		ALLOW_ANY_TRANSPORT = ALLOW_USBMUX | ALLOW_TUNNEL,
	}

	public interface Transport : Object {
		public abstract ConnectionType connection_type {
			get;
		}

		public abstract string udid {
			get;
		}

		public abstract string? name {
			get;
		}

		public abstract Variant? icon {
			get;
		}

		public abstract UsbmuxDevice? usbmux_device {
			get;
		}

		public abstract async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError;
	}

	public enum ConnectionType {
		USB,
		NETWORK
	}

	public interface Tunnel : Object {
		public abstract DiscoveryService discovery {
			get;
		}

		public abstract int64 opened_at {
			get;
		}

		public abstract async void close (Cancellable? cancellable) throws IOError;
		public abstract async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError;
	}

	public interface Backend : Object {
		public signal void transport_attached (Transport transport);
		public signal void transport_detached (Transport transport);

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	private sealed class UsbmuxBackend : Object, Backend {
		public bool available {
			get {
				return usbmux != null;
			}
		}

		private Gee.Map<UsbmuxDevice, UsbmuxTransport> transports = new Gee.HashMap<UsbmuxDevice, UsbmuxTransport> ();

		private UsbmuxClient? usbmux;

		private Promise<bool> start_request;
		private Cancellable start_cancellable;
		private SourceFunc on_start_completed;

		private Cancellable io_cancellable = new Cancellable ();

		public async void start (Cancellable? cancellable) throws IOError {
			start_request = new Promise<bool> ();
			start_cancellable = new Cancellable ();
			on_start_completed = start.callback;

			var main_context = MainContext.get_thread_default ();

			var timeout_source = new TimeoutSource (500);
			timeout_source.set_callback (start.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (start.callback);
			cancel_source.attach (main_context);

			do_start.begin ();

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			on_start_completed = null;
		}

		private async void do_start () {
			bool success = yield try_open_usbmux_client ();
			if (success) {
				/* Perform a dummy-request to flush out any pending device attach notifications. */
				try {
					yield usbmux.connect_to_port (uint.MAX, 0, start_cancellable);
					assert_not_reached ();
				} catch (GLib.Error expected_error) {
					if (expected_error.code == IOError.CONNECTION_CLOSED) {
						/* Deal with usbmuxd closing the connection when receiving commands in the wrong state. */
						usbmux.close.begin (null);

						success = yield try_open_usbmux_client ();
						if (success) {
							UsbmuxClient flush_client = null;
							try {
								flush_client = yield UsbmuxClient.open (start_cancellable);
								try {
									yield flush_client.connect_to_port (uint.MAX, 0, start_cancellable);
									assert_not_reached ();
								} catch (GLib.Error expected_error) {
								}
							} catch (GLib.Error e) {
								success = false;
							}

							if (flush_client != null)
								flush_client.close.begin (null);

							if (!success && usbmux != null) {
								usbmux.close.begin (null);
								usbmux = null;
							}
						}
					}
				}
			}

			start_request.resolve (success);

			if (on_start_completed != null)
				on_start_completed ();
		}

		private async bool try_open_usbmux_client () {
			bool success = true;

			try {
				usbmux = yield UsbmuxClient.open (start_cancellable);
				usbmux.device_attached.connect (on_device_attached);
				usbmux.device_detached.connect (on_device_detached);

				yield usbmux.enable_listen_mode (start_cancellable);
			} catch (GLib.Error e) {
				success = false;
			}

			if (!success && usbmux != null) {
				usbmux.close.begin (null);
				usbmux = null;
			}

			return success;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
			start_cancellable.cancel ();

			try {
				yield start_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			if (usbmux != null) {
				yield usbmux.close (cancellable);
				usbmux = null;
			}

			transports.clear ();
		}

		private void on_device_attached (UsbmuxDevice device) {
			add_transport.begin (device);
		}

		private void on_device_detached (UsbmuxDevice device) {
			remove_transport (device);
		}

		private async void add_transport (UsbmuxDevice device) {
			var transport = new UsbmuxTransport (device);
			transports[device] = transport;

			string? name = null;
			Variant? icon = null;
			if (device.connection_type == USB) {
				bool got_details = false;
				for (int i = 1; !got_details && transports.has_key (device); i++) {
					try {
						_extract_details_for_device (device.product_id, device.udid, out name, out icon);
						got_details = true;
					} catch (Error e) {
						if (i != 20) {
							var main_context = MainContext.get_thread_default ();

							var delay_source = new TimeoutSource.seconds (1);
							delay_source.set_callback (add_transport.callback);
							delay_source.attach (main_context);

							var cancel_source = new CancellableSource (io_cancellable);
							cancel_source.set_callback (add_transport.callback);
							cancel_source.attach (main_context);

							yield;

							cancel_source.destroy ();
							delay_source.destroy ();

							if (io_cancellable.is_cancelled ())
								return;
						} else {
							break;
						}
					}
				}
				if (!transports.has_key (device))
					return;
				if (!got_details) {
					remove_transport (device);
					return;
				}
			} else {
				name = "iOS Device [%s]".printf (device.network_address.address.to_string ());
			}
			transport._name = (owned) name;
			transport._icon = (owned) icon;

			transport_attached (transport);
		}

		private void remove_transport (UsbmuxDevice device) {
			UsbmuxTransport transport;
			transports.unset (device, out transport);
			transport_detached (transport);
		}

		public extern static void _extract_details_for_device (int product_id, string udid, out string name,
			out Variant? icon) throws Error;
	}

	private sealed class UsbmuxTransport : Object, Transport {
		public UsbmuxDevice device {
			get;
			construct;
		}

		public ConnectionType connection_type {
			get {
				return device.connection_type;
			}
		}

		public string udid {
			get {
				return device.udid;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Variant? icon {
			get {
				return _icon;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return device;
			}
		}

		internal string _name;
		internal Variant? _icon;

		public UsbmuxTransport (UsbmuxDevice device) {
			Object (device: device);
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			return null;
		}
	}

	private sealed class PortableCoreDeviceBackend : Object, Backend, UsbDeviceBackend {
		public bool supports_modeswitch {
			get {
				return LibUSB.has_capability (HAS_HOTPLUG) != 0;
			}
		}

		public bool modeswitch_allowed {
			get {
				return _modeswitch_allowed;
			}
		}

		private State state = CREATED;

		private Gee.Set<PortableCoreDeviceUsbTransport> usb_transports = new Gee.HashSet<PortableCoreDeviceUsbTransport> ();
		private Promise<bool> usb_started = new Promise<bool> ();
		private Promise<bool> usb_stopped = new Promise<bool> ();
		private bool _modeswitch_allowed = false;

		private Thread<void>? usb_worker;
		private LibUSB.Context? usb_context;
		private LibUSB.HotCallbackHandle iphone_callback;
		private LibUSB.HotCallbackHandle ipad_callback;
		private uint pending_usb_device_arrivals = 0;
		private Gee.Map<uint32, LibUSB.Device> polled_usb_devices = new Gee.HashMap<uint32, LibUSB.Device> ();
		private Source? polled_usb_timer;
		private uint polled_usb_outdated = 0;
		private Gee.Set<unowned PendingUsbOperation> pending_usb_ops = new Gee.HashSet<unowned PendingUsbOperation> ();

		private PairingBrowser network_browser = PairingBrowser.make_default ();
		private Gee.Map<string, PortableCoreDeviceNetworkTransport> network_transports =
			new Gee.HashMap<string, PortableCoreDeviceNetworkTransport> ();

		private PairingStore pairing_store = new PairingStore ();

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			CREATED,
			STARTING,
			STARTED,
			FLUSHING,
			STOPPING,
			STOPPED,
		}

		private const uint16 VENDOR_ID_APPLE = 0x05ac;
		private const uint16 PRODUCT_ID_IPHONE = 0x12a8;
		private const uint16 PRODUCT_ID_IPAD = 0x12ab;

		private delegate void NotifyCompleteFunc ();

		construct {
			main_context = MainContext.ref_thread_default ();

			network_browser.service_discovered.connect (on_network_pairing_service_discovered);
		}

		public async void start (Cancellable? cancellable) throws IOError {
			lock (state)
				state = STARTING;

			usb_worker = new Thread<void> ("frida-core-device-usb", perform_usb_work);

			yield network_browser.start (cancellable);

			try {
				yield usb_started.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			lock (state)
				state = STARTED;
		}

		public async void stop (Cancellable? cancellable) throws IOError {
			lock (state)
				state = FLUSHING;

			io_cancellable.cancel ();

			if (usb_context != null)
				usb_context.interrupt_event_handler ();

			yield network_browser.stop (cancellable);

			foreach (var transport in network_transports.values.to_array ())
				yield transport.close (cancellable);
			network_transports.clear ();

			foreach (var transport in usb_transports.to_array ())
				yield transport.close (cancellable);
			usb_transports.clear ();

			try {
				yield usb_stopped.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}

			usb_worker.join ();
			usb_worker = null;

			usb_context = null;

			lock (state)
				state = STOPPED;
		}

		public async void activate_modeswitch_support (Cancellable? cancellable) throws IOError {
			_modeswitch_allowed = true;

			var pending_transports = usb_transports.to_array ();
			var remaining = pending_transports.length + 1;

			NotifyCompleteFunc on_complete = () => {
				remaining--;
				if (remaining == 0)
					activate_modeswitch_support.callback ();
			};

			foreach (var transport in pending_transports)
				do_activate_modeswitch_support.begin (transport, cancellable, on_complete);

			var source = new IdleSource ();
			source.set_callback (() => {
				on_complete ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());

			yield;

			on_complete = null;
		}

		private async void do_activate_modeswitch_support (PortableCoreDeviceUsbTransport transport, Cancellable? cancellable,
				NotifyCompleteFunc on_complete) {
			try {
				yield transport.open (cancellable);
			} catch (GLib.Error e) {
			}

			on_complete ();
		}

		private void perform_usb_work () {
			if (LibUSB.Context.init (out usb_context) != SUCCESS) {
				schedule_on_frida_thread (() => {
					usb_started.resolve (true);
					usb_stopped.resolve (true);
					return Source.REMOVE;
				});
				return;
			}

			AtomicUint.inc (ref pending_usb_device_arrivals);

			bool callbacks_registered = true;
			if (LibUSB.has_capability (HAS_HOTPLUG) != 0) {
				usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE,
					PRODUCT_ID_IPHONE, LibUSB.HotPlugEvent.MATCH_ANY, on_usb_hotplug_event, out iphone_callback);
				usb_context.hotplug_register_callback (DEVICE_ARRIVED | DEVICE_LEFT, ENUMERATE, VENDOR_ID_APPLE,
					PRODUCT_ID_IPAD, LibUSB.HotPlugEvent.MATCH_ANY, on_usb_hotplug_event, out ipad_callback);
			} else {
				refresh_polled_usb_devices ();

				var source = new TimeoutSource.seconds (2);
				source.set_callback (() => {
					AtomicUint.set (ref polled_usb_outdated, 1);
					usb_context.interrupt_event_handler ();
					return Source.CONTINUE;
				});
				source.attach (main_context);
				polled_usb_timer = source;
			}

			if (AtomicUint.dec_and_test (ref pending_usb_device_arrivals)) {
				schedule_on_frida_thread (() => {
					usb_started.resolve (true);
					return Source.REMOVE;
				});
			}

			while (state != STOPPING) {
				int completed = 0;
				usb_context.handle_events_completed (out completed);

				if (AtomicUint.compare_and_exchange (ref polled_usb_outdated, 1, 0))
					refresh_polled_usb_devices ();

				if (state == FLUSHING) {
					if (callbacks_registered) {
						usb_context.hotplug_deregister_callback (iphone_callback);
						usb_context.hotplug_deregister_callback (ipad_callback);
						callbacks_registered = false;
					}

					if (polled_usb_timer != null) {
						polled_usb_timer.destroy ();
						polled_usb_timer = null;
					}

					lock (state) {
						if (pending_usb_ops.is_empty)
							state = STOPPING;
					}
				}
			}

			schedule_on_frida_thread (() => {
				usb_stopped.resolve (true);
				return Source.REMOVE;
			});
		}

		private int on_usb_hotplug_event (LibUSB.Context ctx, LibUSB.Device device, LibUSB.HotPlugEvent event) {
			if (event == DEVICE_ARRIVED)
				on_usb_device_arrived (device);
			else
				on_usb_device_left (device);
			return 0;
		}

		private void on_usb_device_arrived (LibUSB.Device device) {
			AtomicUint.inc (ref pending_usb_device_arrivals);
			schedule_on_frida_thread (() => {
				handle_usb_device_arrival.begin (device);
				return Source.REMOVE;
			});
		}

		private void on_usb_device_left (LibUSB.Device device) {
			schedule_on_frida_thread (() => {
				handle_usb_device_departure.begin (device);
				return Source.REMOVE;
			});
		}

		private async void handle_usb_device_arrival (LibUSB.Device raw_device) {
			try {
				UsbDevice usb_device;
				try {
					usb_device = new UsbDevice (raw_device, this);
				} catch (Error e) {
					return;
				}

				unowned string udid = usb_device.udid;
				var transport = usb_transports.first_match (t => t.udid == udid);

				bool may_need_time_to_settle = state != STARTING && (transport == null || transport.modeswitch_in_progress);
				if (may_need_time_to_settle) {
					try {
						yield sleep (250, io_cancellable);
					} catch (IOError e) {
					}
				}

				if (transport != null) {
					if (!transport.try_complete_modeswitch (raw_device))
						transport = null;
				}

				if (io_cancellable.is_cancelled ())
					return;

				if (transport == null) {
					transport = new PortableCoreDeviceUsbTransport (this, usb_device, pairing_store);
					usb_transports.add (transport);

					if (state != STARTING) {
						try {
							yield transport.open (io_cancellable);
						} catch (GLib.Error e) {
						}
					}

					transport_attached (transport);
				}
			} finally {
				if (AtomicUint.dec_and_test (ref pending_usb_device_arrivals) && state == STARTING)
					usb_started.resolve (true);
			}
		}

		private async void handle_usb_device_departure (LibUSB.Device raw_device) {
			var transport = usb_transports.first_match (t => t.usb_device.raw_device == raw_device && !t.modeswitch_in_progress);
			if (transport == null)
				return;

			transport_detached (transport);
			usb_transports.remove (transport);

			try {
				yield transport.close (io_cancellable);
			} catch (IOError e) {
			}
		}

		private void refresh_polled_usb_devices () {
			var current_devices = new Gee.HashMap<uint32, LibUSB.Device> ();
			foreach (var device in usb_context.get_device_list ()) {
				var desc = LibUSB.DeviceDescriptor (device);

				if (desc.idVendor != VENDOR_ID_APPLE)
					continue;

				if (desc.idProduct != PRODUCT_ID_IPHONE && desc.idProduct != PRODUCT_ID_IPAD)
					continue;

				uint id = make_usb_device_id (device, desc);
				current_devices[id] = device;

				if (!polled_usb_devices.has_key (id))
					on_usb_device_arrived (device);
			}

			foreach (var e in polled_usb_devices.entries) {
				if (!current_devices.has_key (e.key))
					on_usb_device_left (e.value);
			}

			polled_usb_devices = current_devices;
		}

		private UsbOperation allocate_usb_operation () throws Error {
			var op = new PendingUsbOperation (this);

			bool added = false;
			lock (state) {
				switch (state) {
					case CREATED:
						break;
					case STARTING:
					case STARTED:
						pending_usb_ops.add (op);
						added = true;
						break;
					case FLUSHING:
					case STOPPING:
					case STOPPED:
						break;
				}
			}

			if (!added)
				throw new Error.INVALID_OPERATION ("Unable to allocate USB operation in the current state");

			return op;
		}

		private void on_usb_operation_complete (PendingUsbOperation op) {
			lock (state)
				pending_usb_ops.remove (op);

			if (usb_context != null)
				usb_context.interrupt_event_handler ();
		}

		private static uint32 make_usb_device_id (LibUSB.Device device, LibUSB.DeviceDescriptor desc) {
			return ((uint32) device.get_port_number () << 24) |
				((uint32) device.get_device_address () << 16) |
				(uint32) desc.idProduct;
		}

		private void on_network_pairing_service_discovered (PairingServiceDetails service) {
			var peer = pairing_store.find_peer_matching_service (service);
			if (peer == null)
				return;

			var transport = network_transports[peer.udid];
			if (transport == null) {
				transport = new PortableCoreDeviceNetworkTransport (peer, pairing_store, service.endpoint,
					service.interface_address);
				network_transports[peer.udid] = transport;
				transport_attached (transport);
			} else {
				transport.endpoint = service.endpoint;
				transport.interface_address = service.interface_address;
			}
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class PendingUsbOperation : Object, UsbOperation {
			public LibUSB.Transfer transfer {
				get {
					return _transfer;
				}
			}

			private weak PortableCoreDeviceBackend backend;
			private LibUSB.Transfer _transfer;

			public PendingUsbOperation (PortableCoreDeviceBackend backend) {
				this.backend = backend;
			}

			construct {
				_transfer = new LibUSB.Transfer ();
			}

			public override void dispose () {
				if (_transfer != null) {
					_transfer = null;
					backend.on_usb_operation_complete (this);
				}

				base.dispose ();
			}
		}
	}

	private sealed class PortableCoreDeviceUsbTransport : Object, Transport {
		public UsbDevice usb_device {
			get {
				return _usb_device;
			}
		}

		public ConnectionType connection_type {
			get {
				return USB;
			}
		}

		public string udid {
			get {
				return _usb_device.udid;
			}
		}

		public string? name {
			get {
				return _name;
			}
		}

		public Variant? icon {
			get {
				return null;
			}
		}

		public UsbmuxDevice? usbmux_device {
			get {
				return null;
			}
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public bool modeswitch_in_progress {
			get {
				return modeswitch_request != null;
			}
		}

		private unowned PortableCoreDeviceBackend parent;
		private UsbDevice _usb_device;
		private Gee.List<InetSocketAddress> ncm_ifaddrs;
		private UsbNcmConfig? ncm_config;
		private string? _name;

		private Promise<UsbDevice>? dev
```
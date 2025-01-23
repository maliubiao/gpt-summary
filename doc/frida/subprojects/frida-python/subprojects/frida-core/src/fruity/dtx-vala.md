Response:
### 功能归纳

`dtx.vala` 文件是 Frida 工具中用于与 iOS 设备通信的核心模块，主要实现了与 iOS 设备的 DTX（Distributed Transaction）协议通信。DTX 协议是 Apple 用于在设备和主机之间进行通信的协议，通常用于调试、监控和控制 iOS 设备上的进程和应用程序。以下是该文件的主要功能：

1. **设备信息获取**：
   - `DeviceInfoService` 类用于获取设备上运行的进程信息。通过 `enumerate_processes` 方法，可以获取设备上所有正在运行的进程的详细信息，包括进程 ID（PID）、进程名称、启动时间等。

2. **应用程序列表获取**：
   - `ApplicationListingService` 类用于获取设备上安装的应用程序列表。通过 `enumerate_applications` 方法，可以获取应用程序的详细信息，如应用程序类型、显示名称、Bundle ID、版本号等。

3. **进程控制**：
   - `ProcessControlService` 类用于控制设备上的进程。通过 `kill` 方法，可以终止指定 PID 的进程。

4. **DTX 协议通信**：
   - `DTXConnection` 类负责与 iOS 设备建立 DTX 连接，并处理 DTX 消息的发送和接收。它支持分片消息的处理，确保大消息能够正确传输。
   - `DTXChannel` 类表示一个 DTX 通道，用于在设备和主机之间进行通信。它支持同步和异步的消息发送与接收，并处理不同类型的 DTX 消息（如 INVOKE、RESULT、ERROR 等）。

5. **消息分片与重组**：
   - `DTXConnection` 类处理 DTX 消息的分片和重组。当消息过大时，DTX 协议会将消息分成多个片段进行传输，接收端需要将这些片段重新组合成完整的消息。

6. **错误处理与协议验证**：
   - 代码中包含了大量的错误处理和协议验证逻辑，确保通信过程中的数据完整性和正确性。例如，如果接收到的消息不符合预期格式，会抛出 `Error.PROTOCOL` 异常。

### 涉及二进制底层和 Linux 内核的部分

虽然该文件主要涉及 iOS 设备的通信协议，但其中一些底层操作（如字节流的读取与写入、消息的分片与重组）与二进制数据处理密切相关。例如：

- **字节流处理**：`DTXConnection` 类中的 `read_fragment` 方法负责从输入流中读取 DTX 消息片段，并根据消息头信息进行解析。这涉及到对二进制数据的直接操作，如读取特定字节、解析消息头等。
- **消息分片与重组**：`DTXConnection` 类中的 `process_incoming_fragments` 方法负责将接收到的消息片段重新组合成完整的消息。这涉及到对二进制数据的拼接和验证。

### LLDB 调试示例

假设你想使用 LLDB 调试 `DTXConnection` 类中的 `read_fragment` 方法，以下是一个可能的 LLDB Python 脚本示例：

```python
import lldb

def read_fragment_debug(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 获取 read_fragment 方法的地址
    read_fragment_addr = target.FindFunctions("read_fragment")[0].GetStartAddress()

    # 设置断点
    breakpoint = target.BreakpointCreateByAddress(read_fragment_addr.GetLoadAddress(target))
    breakpoint.SetCondition('thread.GetThreadID() == 1')  # 仅在特定线程中断

    # 继续执行
    process.Continue()

    # 打印调试信息
    if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
        print("Hit breakpoint in read_fragment method")
        # 打印当前帧的局部变量
        for var in frame.GetVariables(True, True, True, True):
            print(f"{var.GetName()} = {var.GetValue()}")

# 注册 LLDB 命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f read_fragment_debug.read_fragment_debug read_fragment_debug')
```

### 假设输入与输出

假设你调用 `DeviceInfoService` 的 `enumerate_processes` 方法，以下是一个假设的输入与输出：

- **输入**：调用 `enumerate_processes` 方法，不传递任何参数。
- **输出**：返回一个包含设备上所有进程信息的列表，每个进程信息包括 PID、名称、启动时间等。

```vala
var processes = yield device_info_service.enumerate_processes();
foreach (var process in processes) {
    print("PID: %u, Name: %s, Start Date: %s".printf(process.pid, process.name, process.start_date.to_string()));
}
```

### 常见使用错误

1. **未正确处理异步操作**：
   - 错误示例：在调用 `enumerate_processes` 方法时，未使用 `yield` 关键字，导致程序阻塞或无法正确获取结果。
   - 正确示例：使用 `yield` 关键字等待异步操作完成。

   ```vala
   var processes = yield device_info_service.enumerate_processes();
   ```

2. **未处理异常**：
   - 错误示例：在调用 `open` 方法时，未捕获可能抛出的异常，导致程序崩溃。
   - 正确示例：使用 `try-catch` 块捕获并处理异常。

   ```vala
   try {
       var service = yield DeviceInfoService.open(channel_provider);
   } catch (Error e) {
       print("Error: %s".printf(e.message));
   }
   ```

### 用户操作步骤

1. **初始化服务**：
   - 用户首先通过 `DeviceInfoService.open` 方法初始化 `DeviceInfoService` 服务。

2. **获取进程信息**：
   - 用户调用 `enumerate_processes` 方法获取设备上所有进程的信息。

3. **处理结果**：
   - 用户遍历返回的进程列表，并处理每个进程的信息（如打印到控制台或存储到文件）。

4. **错误处理**：
   - 用户在处理过程中捕获并处理可能出现的异常，确保程序的健壮性。

通过这些步骤，用户可以逐步获取设备上的进程信息，并进行进一步的分析或操作。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/dtx.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
	public class DeviceInfoService : Object, AsyncInitable {
		public HostChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private DeviceInfoService (HostChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async DeviceInfoService open (HostChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new DeviceInfoService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.deviceinfo");

			return true;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Error, IOError {
			var result = new Gee.ArrayList<ProcessInfo> ();

			var response = yield channel.invoke ("runningProcesses", null, cancellable);

			NSArray? processes = response as NSArray;
			if (processes == null)
				throw new Error.PROTOCOL ("Malformed response");

			foreach (var element in processes.elements) {
				NSDictionary? process = element as NSDictionary;
				if (process == null)
					throw new Error.PROTOCOL ("Malformed response");

				var info = new ProcessInfo ();

				info.pid = (uint) process.get_value<NSNumber> ("pid").integer;

				info.name = process.get_value<NSString> ("name").str;
				info.real_app_name = resolve_real_app_name (process.get_value<NSString> ("realAppName").str);
				info.is_application = process.get_value<NSNumber> ("isApplication").boolean;

				NSNumber? foreground_running;
				if (process.get_optional_value ("foregroundRunning", out foreground_running))
					info.foreground_running = foreground_running.boolean;

				NSDate? start_date;
				if (process.get_optional_value ("startDate", out start_date))
					info.start_date = start_date.to_date_time ();

				result.add (info);
			}

			return result;
		}

		private static string resolve_real_app_name (string name) {
			if (name.has_prefix ("/var/"))
				return "/private" + name;
			return name;
		}

		public class ProcessInfo : Object {
			public uint pid {
				get;
				set;
			}

			public string name {
				get;
				set;
			}

			public string real_app_name {
				get;
				set;
			}

			public bool is_application {
				get;
				set;
			}

			public bool foreground_running {
				get;
				set;
			}

			public DateTime? start_date {
				get;
				set;
			}
		}
	}

	public class ApplicationListingService : Object, AsyncInitable {
		public HostChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private ApplicationListingService (HostChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async ApplicationListingService open (HostChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new ApplicationListingService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.device.applictionListing");

			return true;
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (NSDictionary? query = null,
				Cancellable? cancellable = null) throws Error, IOError {
			var result = new Gee.ArrayList<ApplicationInfo> ();

			var args = new DTXArgumentListBuilder ()
				.append_object ((query != null) ? query : new NSDictionary ())
				.append_object (new NSString (""));
			var response = yield channel.invoke ("installedApplicationsMatching:registerUpdateToken:", args, cancellable);

			NSArray? apps = response as NSArray;
			if (apps == null)
				throw new Error.PROTOCOL ("Malformed response");

			foreach (var element in apps.elements) {
				NSDictionary? app = element as NSDictionary;
				if (app == null)
					throw new Error.PROTOCOL ("Malformed response");

				var info = new ApplicationInfo ();

				info.app_type = ApplicationType.from_dtx (app.get_value<NSString> ("Type").str);
				info.display_name = app.get_value<NSString> ("DisplayName").str;
				info.bundle_identifier = app.get_value<NSString> ("CFBundleIdentifier").str;
				info.bundle_path = app.get_value<NSString> ("BundlePath").str;
				info.restricted = app.get_value<NSNumber> ("Restricted").boolean;

				NSNumber num_val;
				NSString? str_val;
				NSArray arr_val;

				if (app.get_optional_value<NSString> ("Version", out str_val))
					info.version = str_val.str;

				if (app.get_optional_value<NSNumber> ("Placeholder", out num_val))
					info.placeholder = num_val.boolean;

				if (app.get_optional_value<NSString> ("ExecutableName", out str_val))
					info.executable_name = str_val.str;

				if (app.get_optional_value<NSArray> ("AppExtensionUUIDs", out arr_val)) {
					var uuids = new string[arr_val.length];
					uint i = 0;
					foreach (var uuid in arr_val.elements) {
						str_val = uuid as NSString;
						if (str_val == null)
							throw new Error.PROTOCOL ("Malformed response");
						uuids[i] = str_val.str;
						i++;
					}
					info.app_extension_uuids = uuids;
				}

				if (app.get_optional_value<NSString> ("PluginUUID", out str_val))
					info.plugin_uuid = str_val.str;

				if (app.get_optional_value<NSString> ("PluginIdentifier", out str_val))
					info.plugin_identifier = str_val.str;

				if (app.get_optional_value<NSString> ("ContainerBundleIdentifier", out str_val))
					info.container_bundle_identifier = str_val.str;

				if (app.get_optional_value<NSString> ("ContainerBundlePath", out str_val))
					info.container_bundle_path = str_val.str;

				result.add (info);
			}

			return result;
		}

		public class ApplicationInfo : Object {
			public ApplicationType app_type {
				get;
				set;
			}

			public string display_name {
				get;
				set;
			}

			public string bundle_identifier {
				get;
				set;
			}

			public string bundle_path {
				get;
				set;
			}

			public string? version {
				get;
				set;
			}

			public bool placeholder {
				get;
				set;
			}

			public bool restricted {
				get;
				set;
			}

			public string? executable_name {
				get;
				set;
			}

			public string[]? app_extension_uuids {
				get;
				set;
			}

			public string? plugin_uuid {
				get;
				set;
			}

			public string? plugin_identifier {
				get;
				set;
			}

			public string? container_bundle_identifier {
				get;
				set;
			}

			public string? container_bundle_path {
				get;
				set;
			}
		}

		public enum ApplicationType {
			SYSTEM = 1,
			USER,
			PLUGIN_KIT;

			public static ApplicationType from_nick (string nick) throws Error {
				return Marshal.enum_from_nick<ApplicationType> (nick);
			}

			public string to_nick () {
				return Marshal.enum_to_nick<ApplicationType> (this);
			}

			internal static ApplicationType from_dtx (string type) {
				if (type == "System")
					return SYSTEM;

				if (type == "User")
					return USER;

				if (type == "PluginKit")
					return PLUGIN_KIT;

				assert_not_reached ();
			}
		}
	}

	public class ProcessControlService : Object, AsyncInitable {
		public HostChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private ProcessControlService (HostChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async ProcessControlService open (HostChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new ProcessControlService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.processcontrol");

			return true;
		}

		public async void kill (uint pid, Cancellable? cancellable = null) throws Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_object (new NSNumber.from_integer (pid));
			yield channel.invoke ("killPid:", args, cancellable);
		}
	}

	public class DTXConnection : Object, DTXTransport {
		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
		}

		public enum State {
			OPEN,
			CLOSED
		}

		private static Gee.HashMap<HostChannelProvider, Future<DTXConnection>> connections;

		private State _state = OPEN;

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private Gee.HashMap<uint32, Gee.ArrayList<Fragment>> fragments = new Gee.HashMap<uint32, Gee.ArrayList<Fragment>> ();
		private uint32 next_fragment_identifier = 1;
		private size_t total_buffered = 0;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();

		private DTXControlChannel control_channel;
		private Gee.HashMap<uint32, unowned DTXChannel> channels = new Gee.HashMap<uint32, unowned DTXChannel> ();
		private int32 next_channel_code = 1;

		private const uint32 DTX_FRAGMENT_MAGIC = 0x1f3d5b79U;
		private const uint MAX_BUFFERED_COUNT = 100;
		private const size_t MAX_BUFFERED_SIZE = 30 * 1024 * 1024;
		private const size_t MAX_MESSAGE_SIZE = 128 * 1024 * 1024;
		private const size_t MAX_FRAGMENT_SIZE = 128 * 1024;
		private const string REMOTESERVER_ENDPOINT_17PLUS = "lockdown:com.apple.instruments.dtservicehub";
		private const string REMOTESERVER_ENDPOINT_14PLUS = "lockdown:com.apple.instruments.remoteserver.DVTSecureSocketProxy";
		private const string REMOTESERVER_ENDPOINT_LEGACY = "lockdown:com.apple.instruments.remoteserver?tls=handshake-only";
 		private const string[] REMOTESERVER_ENDPOINT_CANDIDATES = {
			REMOTESERVER_ENDPOINT_17PLUS,
			REMOTESERVER_ENDPOINT_14PLUS,
			REMOTESERVER_ENDPOINT_LEGACY,
		};

		public static async DTXConnection obtain (HostChannelProvider channel_provider, Cancellable? cancellable)
				throws Error, IOError {
			if (connections == null)
				connections = new Gee.HashMap<HostChannelProvider, Future<DTXConnection>> ();

			while (connections.has_key (channel_provider)) {
				var future = connections[channel_provider];
				try {
					return yield future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			var request = new Promise<DTXConnection> ();
			connections[channel_provider] = request.future;

			Error pending_error = null;

			foreach (unowned string endpoint in REMOTESERVER_ENDPOINT_CANDIDATES) {
				try {
					var stream = yield channel_provider.open_channel (endpoint, cancellable);

					var connection = new DTXConnection (stream);
					connection.notify["state"].connect (on_connection_state_changed);

					request.resolve (connection);

					return connection;
				} catch (Error e) {
					if (!(e is Error.NOT_SUPPORTED)) {
						pending_error = e;
						break;
					}
				}
			}

			Error api_error = (pending_error == null)
				? new Error.NOT_SUPPORTED ("This feature requires an iOS Developer Disk Image to be mounted; " +
					"run Xcode briefly or use ideviceimagemounter to mount one manually")
				: pending_error;

			request.reject (api_error);
			connections.unset (channel_provider);

			throw api_error;
		}

		public static async void close_all (HostChannelProvider channel_provider, Cancellable? cancellable) throws IOError {
			if (connections == null)
				return;

			while (connections.has_key (channel_provider)) {
				var future = connections[channel_provider];
				try {
					var connection = yield future.wait_async (cancellable);
					connections.unset (channel_provider);
					yield connection.close (cancellable);
				} catch (Error e) {
					continue;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			if (connections.size == 0)
				connections = null;
		}

		private static void on_connection_state_changed (Object object, ParamSpec pspec) {
			DTXConnection connection = (DTXConnection) object;
			if (connection.state != CLOSED)
				return;

			foreach (var entry in connections.entries) {
				var future = entry.value;

				if (future.ready) {
					DTXConnection c = future.value;
					if (c == connection) {
						connections.unset (entry.key);
						return;
					}
				}
			}
		}

		public DTXConnection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = new DataInputStream (stream.get_input_stream ());
			input.byte_order = LITTLE_ENDIAN;
			output = stream.get_output_stream ();

			control_channel = new DTXControlChannel (this);
			channels[control_channel.code] = control_channel;

			try {
				control_channel.notify_of_published_capabilities ();
			} catch (Error e) {
				assert_not_reached ();
			}

			process_incoming_fragments.begin ();
		}

		public override void dispose () {
			foreach (var channel in channels.values)
				channel.transport = null;
			channels.clear ();

			base.dispose ();
		}

		private async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (close.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async (Priority.DEFAULT, cancellable);
			} catch (IOError e) {
			}
		}

		public DTXChannel make_channel (string identifier) throws Error {
			check_open ();

			int32 channel_code = next_channel_code++;

			var channel = new DTXChannel (channel_code, this);
			channels[channel_code] = channel;

			establish_channel.begin (channel, identifier);

			return channel;
		}

		private void remove_channel (DTXChannel channel) {
			channels.unset (channel.code);

			if (channel != control_channel)
				control_channel.cancel_channel.begin (channel.code, io_cancellable);
		}

		private async void establish_channel (DTXChannel channel, string identifier) {
			try {
				yield control_channel.request_channel (channel.code, identifier, io_cancellable);
			} catch (GLib.Error e) {
				channels.unset (channel.code);
			}
		}

		private async void process_incoming_fragments () {
			while (true) {
				try {
					var fragment = yield read_fragment ();

					if (fragment.count == 1) {
						process_message (fragment.bytes.get_data (), fragment);
						continue;
					}

					Gee.ArrayList<Fragment> entries = fragments[fragment.identifier];
					if (entries == null) {
						if (fragments.size == MAX_BUFFERED_COUNT)
							throw new Error.PROTOCOL ("Total buffered count exceeds maximum");
						if (fragment.index != 0)
							throw new Error.PROTOCOL ("Expected first fragment to have index of zero");
						fragment.data_size = 0;

						entries = new Gee.ArrayList<Fragment> ();
						fragments[fragment.identifier] = entries;
					}
					entries.add (fragment);

					var first_fragment = entries[0];

					if (fragment.bytes != null) {
						var size = fragment.bytes.get_size ();

						first_fragment.data_size += (uint32) size;
						if (first_fragment.data_size > MAX_MESSAGE_SIZE)
							throw new Error.PROTOCOL ("Message size exceeds maximum");

						total_buffered += size;
						if (total_buffered > MAX_BUFFERED_SIZE)
							throw new Error.PROTOCOL ("Total buffered size exceeds maximum");
					}

					if (entries.size == fragment.count) {
						var message = new uint8[first_fragment.data_size];

						var sorted_entries = entries.order_by ((a, b) => (int) a.index - (int) b.index);
						uint i = 0;
						size_t offset = 0;
						while (sorted_entries.next ()) {
							Fragment f = sorted_entries.get ();

							if (f.index != i)
								throw new Error.PROTOCOL ("Inconsistent fragments received");

							var bytes = f.bytes;
							if (bytes != null) {
								var size = bytes.get_size ();
								Memory.copy ((uint8 *) message + offset, (uint8 *) bytes.get_data (), size);
								offset += size;
							}

							i++;
						}

						fragments.unset (fragment.identifier);
						total_buffered -= message.length;

						process_message (message, first_fragment);
					}
				} catch (GLib.Error e) {
					_state = CLOSED;
					notify_property ("state");

					foreach (var channel in channels.values.to_array ())
						channel.close ();
					channels.clear ();

					return;
				}
			}
		}

		private async Fragment read_fragment () throws Error, IOError {
			var io_priority = Priority.DEFAULT;

			try {
				size_t minimum_header_size = 32;

				yield prepare_to_read (minimum_header_size);

				uint32 magic = input.read_uint32 (io_cancellable);
				if (magic != DTX_FRAGMENT_MAGIC)
					throw new Error.PROTOCOL ("Expected DTX message magic, got 0x%08x", magic);

				var fragment = new Fragment ();

				var header_size = input.read_uint32 (io_cancellable);
				if (header_size < minimum_header_size)
					throw new Error.PROTOCOL ("Expected header size of >= 32, got %u", header_size);

				fragment.index = input.read_uint16 (io_cancellable);
				fragment.count = input.read_uint16 (io_cancellable);
				fragment.data_size = input.read_uint32 (io_cancellable);
				fragment.identifier = input.read_uint32 (io_cancellable);
				fragment.conversation_index = input.read_uint32 (io_cancellable);
				fragment.channel_code = input.read_int32 (io_cancellable);
				fragment.flags = input.read_uint32 (io_cancellable);

				size_t extra_header_size = header_size - minimum_header_size;
				if (extra_header_size > 0)
					yield input.skip_async (extra_header_size, io_priority, io_cancellable);

				if (fragment.count == 1 || fragment.index != 0) {
					if (fragment.data_size == 0)
						throw new Error.PROTOCOL ("Empty fragments are not allowed");
					if (fragment.data_size > MAX_FRAGMENT_SIZE)
						throw new Error.PROTOCOL ("Fragment size exceeds maximum");

					if (fragment.data_size > input.get_buffer_size ())
						input.set_buffer_size (fragment.data_size);

					yield prepare_to_read (fragment.data_size);
					fragment.bytes = input.read_bytes (fragment.data_size, io_cancellable);
				}

				return fragment;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		private void process_message (uint8[] raw_message, Fragment fragment) throws Error {
			const size_t header_size = 16;

			size_t message_size = raw_message.length;
			if (message_size < header_size)
				throw new Error.PROTOCOL ("Malformed message");

			uint8 * m = (uint8 *) raw_message;

			var message = DTXMessage ();
			message.type = (DTXMessageType) *m;
			message.identifier = fragment.identifier;
			message.conversation_index = fragment.conversation_index;
			message.channel_code = fragment.channel_code;
			message.transport_flags = (DTXMessageTransportFlags) fragment.flags;

			uint32 aux_size = uint32.from_little_endian (*((uint32 *) (m + 4)));
			uint64 data_size = uint64.from_little_endian (*((uint64 *) (m + 8)));
			if (aux_size > message_size || data_size > message_size || data_size != message_size - header_size ||
					aux_size > data_size) {
				throw new Error.PROTOCOL ("Malformed message");
			}

			size_t aux_start_offset = header_size;
			size_t aux_end_offset = aux_start_offset + aux_size;
			message.aux_data = raw_message[aux_start_offset:aux_end_offset];

			size_t payload_start_offset = aux_end_offset;
			size_t payload_end_offset = payload_start_offset + (size_t) (data_size - aux_size);
			message.payload_data = raw_message[payload_start_offset:payload_end_offset];

			int32 channel_code = message.channel_code;
			bool is_notification = false;
			if (message.type == INVOKE) {
				channel_code = -channel_code;
			} else if (message.type == RESULT && channel_code < 0) {
				channel_code = -channel_code;
				is_notification = true;
			}

			var channel = channels[channel_code];
			if (channel == null)
				return;

			switch (message.type) {
				case INVOKE:
					channel.handle_invoke (message);
					break;
				case OK:
				case RESULT:
				case ERROR:
					if (is_notification)
						channel.handle_notification (message);
					else
						channel.handle_response (message);
					break;
				case BARRIER:
					channel.handle_barrier (message);
					break;
			}
		}

		private void send_message (DTXMessage message, out uint32 identifier) {
			const size_t message_header_size = 16;
			uint32 message_aux_size = message.aux_data.length;
			uint64 message_data_size = message_aux_size + message.payload_data.length;
			size_t message_size = message_header_size + (size_t) message_data_size;
			const uint8 message_flags_a = 0;
			const uint8 message_flags_b = 0;
			const uint8 message_reserved = 0;

			const uint32 fragment_header_size = 32;
			const uint16 fragment_index = 0;
			const uint16 fragment_count = 1;
			uint32 fragment_data_size = (uint32) message_size;
			uint32 fragment_identifier = message.identifier;
			if (fragment_identifier == 0)
				fragment_identifier = next_fragment_identifier++;
			uint32 fragment_flags = message.transport_flags;

			var data = new uint8[fragment_header_size + message_size];

			uint8 * p = (uint8 *) data;
			*((uint32 *) (p + 0)) = DTX_FRAGMENT_MAGIC.to_little_endian ();
			*((uint32 *) (p + 4)) = fragment_header_size.to_little_endian ();
			*((uint16 *) (p + 8)) = fragment_index.to_little_endian ();
			*((uint16 *) (p + 10)) = fragment_count.to_little_endian ();
			*((uint32 *) (p + 12)) = fragment_data_size.to_little_endian ();
			*((uint32 *) (p + 16)) = fragment_identifier.to_little_endian ();
			*((uint32 *) (p + 20)) = message.conversation_index.to_little_endian ();
			*((int32 *) (p + 24)) = message.channel_code.to_little_endian ();
			*((uint32 *) (p + 28)) = fragment_flags.to_little_endian ();
			p += fragment_header_size;

			*(p + 0) = message.type;
			*(p + 1) = message_flags_a;
			*(p + 2) = message_flags_b;
			*(p + 3) = message_reserved;
			*((uint32 *) (p + 4)) = message_aux_size.to_little_endian ();
			*((uint64 *) (p + 8)) = message_data_size.to_little_endian ();
			p += message_header_size;

			Memory.copy (p, message.aux_data, message.aux_data.length);
			p += message.aux_data.length;

			Memory.copy (p, message.payload_data, message.payload_data.length);
			p += message.payload_data.length;

			assert (p == (uint8 *) data + data.length);

			write_bytes (new Bytes.take ((owned) data));

			identifier = fragment_identifier;
		}

		private async void prepare_to_read (size_t required) throws GLib.Error {
			while (true) {
				size_t available = input.get_available ();
				if (available >= required)
					return;
				ssize_t n = yield input.fill_async ((ssize_t) (required - available), Priority.DEFAULT, io_cancellable);
				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");
			}
		}

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				size_t bytes_written;
				try {
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
						out bytes_written);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private void check_open () throws Error {
			if (_state != OPEN)
				throw new Error.INVALID_OPERATION ("Connection is closed");
		}

		private class Fragment {
			public uint16 index;
			public uint16 count;
			public uint32 data_size;
			public uint32 identifier;
			public uint32 conversation_index;
			public int32 channel_code;
			public uint32 flags;
			public Bytes? bytes;
		}
	}

	private class DTXControlChannel : DTXChannel {
		public DTXControlChannel (DTXTransport transport) {
			Object (code: 0, transport: transport);
		}

		public void notify_of_published_capabilities () throws Error {
			var capabilities = new NSDictionary ();
			capabilities.set_value ("com.apple.private.DTXConnection", new NSNumber.from_integer (1));
			capabilities.set_value ("com.apple.private.DTXBlockCompression", new NSNumber.from_integer (2));

			var args = new DTXArgumentListBuilder ()
				.append_object (capabilities);
			invoke_without_reply ("_notifyOfPublishedCapabilities:", args);
		}

		public async void request_channel (int32 code, string identifier, Cancellable? cancellable) throws Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_int32 (code)
				.append_object (new NSString (identifier));
			yield invoke ("_requestChannelWithCode:identifier:", args, cancellable);
		}

		public async void cancel_channel (int32 code, Cancellable? cancellable) throws Error, IOError {
			var args = new DTXArgumentListBuilder ()
				.append_int32 (code);
			yield invoke ("_channelCanceled:", args, cancellable);
		}
	}

	public class DTXChannel : Object {
		public signal void invocation (string method_name, DTXArgumentList args, DTXMessageTransportFlags transport_flags);
		public signal void notification (NSObject obj);
		public signal void barrier ();

		public int32 code {
			get;
			construct;
		}

		public weak DTXTransport? transport {
			get;
			set;
		}

		public State state {
			get {
				return _state;
			}
		}

		public enum State {
			OPEN,
			CLOSED
		}

		private State _state = OPEN;

		private Gee.HashMap<uint32, Promise<NSObject?>> pending_responses = new Gee.HashMap<uint32, Promise<NSObject?>> ();

		public DTXChannel (int32 code, DTXTransport transport) {
			Object (code: code, transport: transport);
		}

		public override void dispose () {
			close ();

			base.dispose ();
		}

		internal void close () {
			_state = CLOSED;
			notify_property ("state");

			var error = new Error.TRANSPORT ("Channel closed");
			foreach (var request in pending_responses.values.to_array ())
				request.reject (error);

			if (transport != null) {
				transport.remove_channel (this);
				transport = null;
			}
		}

		public async NSObject? invoke (string method_name, DTXArgumentListBuilder? args, Cancellable? cancellable)
				throws Error, IOError {
			check_open ();

			var message = DTXMessage ();
			message.type = INVOKE;
			message.channel_code = code;
			message.transport_flags = EXPECTS_REPLY;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);

			var request = new Promise<NSObject?> ();
			pending_responses[identifier] = request;

			try {
				return yield request.future.wait_async (cancellable);
			} finally {
				pending_responses.unset (identifier);
			}
		}

		public void invoke_without_reply (string method_name, DTXArgumentListBuilder? args) throws Error {
			check_open ();

			var message = DTXMessage ();
			message.type = INVOKE;
			message.channel_code = code;
			message.transport_flags = NONE;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);
		}

		internal void handle_invoke (DTXMessage message) throws Error {
			NSString? method_name = NSKeyedArchive.decode (message.payload_data) as NSString;
			if (method_name == null)
				throw new Error.PROTOCOL ("Malformed invocation payload");

			var args = DTXArgumentList.parse (message.aux_data);

			invocation (method_name.str, args, message.transport_flags);
		}

		internal void handle_response (DTXMessage message) throws Error {
			var request = pending_responses[message.identifier];
			if (request != null) {
				switch (message.type) {
					case OK:
						request.resolve (null);
						break;
					case RESULT:
						request.resolve (NSKeyedArchive.decode (message.payload_data));
						break;
					case ERROR: {
						NSError? error = NSKeyedArchive.decode (message.payload_data) as NSError;
						if (error == null)
							throw new Error.PROTOCOL ("Malformed error payload");

						var description = new StringBuilder.sized (128);

						var user_info = error.user_info;
						if (user_info != null) {
							NSString? val;
							if (user_info.get_optional_value ("NSLocalizedDescription", out val))
								description.append (val.str);
						}

						if (description.len == 0) {
							description.append_printf ("Invocation failed; domain=%s code=%" +
									int64.FORMAT_MODIFIER + "d",
								error.domain.str, error.code);
						}

						request.reject (new Error.NOT_SUPPORTED ("%s", description.str));

						break;
					}
					default:
						assert_not_reached ();
				}
			}
		}

		internal void handle_notification (DTXMessage message) throws Error {
			var payload = NSKeyedArchive.decode (message.payload_data);
			notification (payload);
		}

		internal void handle_barrier (DTXMessage message) throws Error {
			barrier ();
		}

		private void check_open () throws Error {
			if (_state != OPEN)
				throw new Error.INVALID_OPERATION ("Channel is closed");
		}
	}

	public interface DTXTransport : Object {
		public abstract void send_message (DTXMessage message, out uint32 identifier);
		public abstract void remove_channel (DTXChannel channel);
	}

	public enum DTXMessageType {
		OK = 0,
		INVOKE = 2,
		RESULT = 3,
		ERROR = 4,
		BARRIER = 5
	}

	public struct DTXMessage {
		public DTXMessageType type;
		public uint32 identifier;
		public uint32 conversation_index;
		public int32 channel_code;
		public DTXMessageTransportFlags transport_flags;
		public unowned uint8[] aux_data;
		public unowned uint8[] payload_data;
	}

	[Flags]
	public enum DTXMessageTransportFlags {
		NONE          = 0,
		EXPECTS_REPLY = (1 << 0),
	}

	public class DTXArgumentList {
		public Value[] elements;

		private DTXArgumentList (owned Value[] elements) {
			this.elements = (owned) elements;
		}

		public static DTXArgumentList parse (uint8[] data) throws Error {
			var elements = new Value[0];

			var reader = new PrimitiveReader (data);

			reader.skip (PRIMITIVE_DICTIONARY_HEADER_SIZE);

			while (reader.available_bytes != 0) {
				PrimitiveType type;

				type = (PrimitiveType) reader.read_uint32 ();
				if (type != INDEX)
					throw new Error.PROTOCOL ("Unsupported primitive dictionary key type");

				type = (PrimitiveType) reader.read_uint32 ();
				switch (type) {
					case STRING: {
						size_t size = reader.read_uint32 ();
						string val = reader.read_string (size);

						var gval = Value (typeof (string));
						gval.take_string ((owned) val);
						elements += (owned) gval;

						break;
					}
					case BUFFER: {
						size_t size = reader.read_uint32 ();
						unowned uint8[] buf = reader.read_byte_array (size);

						NSObject? obj = NSKeyedArchive.decode (buf);
						if (obj != null) {
							var gval = Value (Type.from_instance (obj));
							gval.set_instance (obj);
							elements += (owned) gval;
						} else {
							var gval = Value (typeof (NSObject));
							elements += (owned) gval;
						}

						break;
					}
					case INT32: {
						int32 val = reader.read_int32 ();

						var gval = Value (typeof (int));
						gval.set_int (val);
						elements += (owned) gval;

						break;
					}
					case INT64: {
						int64 val = reader.read_int64 ();

						var gval = Value (typeof (int64));
						gval.set_int64 (val);
						elements += (owned) gval;

						break;
					}
					case DOUBLE: {
						double val = reader.read_double ();

						var gval = Value (typeof (double));
						gval.set_double (val);
						elements += (owned) gval;

						break;
					}
					default:
						throw new Error.PROTOCOL ("Unsupported primitive dictionary value type");
				}
			}

			return new DTXArgumentList ((owned) elements);
		}
	}

	public class DTXArgumentListBuilder {
		private PrimitiveBuilder blob = new PrimitiveBuilder ();

		pu
```
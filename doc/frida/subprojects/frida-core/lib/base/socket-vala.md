Response:
这个文件是Frida动态插桩工具的核心部分之一，主要负责处理与网络通信相关的功能，特别是通过Socket进行通信的逻辑。以下是对该文件功能的详细分析：

### 1. **Socket地址解析**
   - **功能**: 该文件提供了多个函数来解析Socket地址，包括控制端口和集群端口的地址解析。这些函数可以处理Unix域套接字和网络地址。
   - **示例**:
     - `parse_control_address` 和 `parse_cluster_address` 用于解析控制端口和集群端口的地址。
     - `parse_socket_address` 是通用的地址解析函数，支持Unix域套接字和网络地址。
   - **底层实现**:
     - 对于Unix域套接字，使用了`UnixSocketAddress`类来处理Unix域套接字地址。
     - 对于网络地址，使用了`NetworkAddress`类来解析IP地址和端口。

### 2. **Socket通信**
   - **功能**: 该文件提供了UDP和TCP的Socket通信功能，包括数据的发送和接收。
   - **示例**:
     - `Udp.recv` 和 `Udp.send` 用于UDP数据报的接收和发送。
     - `Tcp.enable_nodelay` 用于启用TCP的Nagle算法（禁用Nagle算法以减少延迟）。
   - **底层实现**:
     - 使用了`DatagramBased`接口来处理UDP数据报的接收和发送。
     - 使用了`Socket`类来处理TCP连接。

### 3. **WebSocket通信**
   - **功能**: 该文件实现了WebSocket的握手、连接管理以及数据的传输。
   - **示例**:
     - `negotiate_connection` 用于与WebSocket服务器进行握手，并建立连接。
     - `WebConnection` 类封装了WebSocket连接，提供了数据的接收和发送功能。
   - **底层实现**:
     - 使用了`Soup.WebsocketConnection`来处理WebSocket协议。
     - 使用了`IOStream`接口来处理输入输出流。

### 4. **Web服务**
   - **功能**: 该文件实现了一个简单的Web服务，支持HTTP和WebSocket请求的处理。
   - **示例**:
     - `WebService` 类用于启动一个Web服务，监听指定的端口，并处理传入的HTTP和WebSocket请求。
     - `ConnectionHandler` 类用于处理每个连接，包括HTTP请求和WebSocket连接的建立。
   - **底层实现**:
     - 使用了`Soup.Server`来处理HTTP请求。
     - 使用了`Soup.WebsocketConnection`来处理WebSocket连接。

### 5. **调试功能**
   - **功能**: 该文件中的代码主要用于网络通信，不直接涉及调试功能。但可以通过LLDB调试工具来调试这些网络通信的实现。
   - **LLDB调试示例**:
     - 假设你想调试`Udp.recv`函数的实现，可以使用以下LLDB命令：
       ```bash
       breakpoint set --name Udp.recv
       run
       ```
     - 如果你想使用LLDB的Python脚本来调试`WebConnection`类的行为，可以编写如下脚本：
       ```python
       import lldb

       def breakpoint_callback(frame, bp_loc, dict):
           print("Breakpoint hit in WebConnection class")
           return True

       target = lldb.debugger.GetSelectedTarget()
       breakpoint = target.BreakpointCreateByName("WebConnection::on_message")
       breakpoint.SetScriptCallbackFunction("breakpoint_callback")
       ```

### 6. **逻辑推理与假设输入输出**
   - **假设输入**:
     - 假设用户调用`parse_control_address("127.0.0.1", 27042)`。
   - **假设输出**:
     - 输出将是一个`SocketConnectable`对象，表示解析后的控制地址。

### 7. **常见使用错误**
   - **错误示例**:
     - 用户可能错误地传递了一个无效的IP地址或端口号，导致`parse_socket_address`抛出`Error.INVALID_ARGUMENT`异常。
     - 用户可能在没有正确配置TLS证书的情况下尝试启动一个HTTPS服务，导致`WebService`启动失败。

### 8. **用户操作路径**
   - **调试线索**:
     - 用户启动Frida服务器，尝试连接到控制端口。
     - 如果连接失败，用户可能会检查`parse_control_address`函数的实现，查看地址解析是否正确。
     - 如果WebSocket握手失败，用户可能会检查`negotiate_connection`函数的实现，查看握手过程是否有问题。

### 总结
这个文件主要实现了Frida工具中与网络通信相关的功能，包括Socket地址解析、UDP/TCP通信、WebSocket通信以及Web服务的实现。通过LLDB调试工具，用户可以调试这些网络通信的实现，排查连接问题。
Prompt: 
```
这是目录为frida/subprojects/frida-core/lib/base/socket.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
namespace Frida {
	public const uint16 DEFAULT_CONTROL_PORT = 27042;
	public const uint16 DEFAULT_CLUSTER_PORT = 27052;

	public SocketConnectable parse_control_address (string? address, uint16 port = 0) throws Error {
		return parse_socket_address (address, port, "127.0.0.1", DEFAULT_CONTROL_PORT);
	}

	public SocketConnectable parse_cluster_address (string? address, uint16 port = 0) throws Error {
		return parse_socket_address (address, port, "127.0.0.1", DEFAULT_CLUSTER_PORT);
	}

	public SocketConnectable parse_socket_address (string? address, uint16 port, string default_address,
			uint16 default_port) throws Error {
		if (address == null)
			address = default_address;
		if (port == 0)
			port = default_port;

#if !WINDOWS
		if (address.has_prefix ("unix:")) {
			string path = address.substring (5);

			UnixSocketAddressType type = UnixSocketAddress.abstract_names_supported ()
				? UnixSocketAddressType.ABSTRACT
				: UnixSocketAddressType.PATH;

			return new UnixSocketAddress.with_type (path, -1, type);
		}
#endif

		try {
			return NetworkAddress.parse (address, port);
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}
	}

	namespace UnixSocket {
		public extern void tune_buffer_sizes (int fd);
	}

	namespace Tcp {
		public extern void enable_nodelay (Socket socket);
	}

	namespace Udp {
		public size_t recv (uint8[] data, DatagramBased source, Cancellable? cancellable, out InetSocketAddress remote_address)
				throws Error, IOError {
			var v = InputVector ();
			v.buffer = data;
			v.size = data.length;

			InputVector[] vectors = { v };

			var m = InputMessage ();
			remote_address = null;
			m.address = &remote_address;
			m.vectors = vectors;
			m.num_vectors = vectors.length;

			InputMessage[] messages = { m };

			try {
				source.receive_messages (messages, 0, 0, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			return messages[0].bytes_received;
		}

		public void send (uint8[] data, DatagramBased sink, Cancellable? cancellable) throws Error, IOError {
			send_to (data, null, sink, cancellable);
		}

		public void send_to (uint8[] data, InetSocketAddress? dest_addr, DatagramBased sink, Cancellable? cancellable)
				throws Error, IOError {
			var v = OutputVector ();
			v.buffer = data;
			v.size = data.length;

			OutputVector[] vectors = { v };

			var m = OutputMessage ();
			m.address = dest_addr;
			m.vectors = vectors;
			m.num_vectors = vectors.length;

			OutputMessage[] messages = { m };

			try {
				sink.send_messages (messages, 0, 0, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}
	}

	public class EndpointParameters : Object {
		public string? address {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public TlsCertificate? certificate {
			get;
			construct;
		}

		public string? origin {
			get;
			construct;
		}

		public AuthenticationService? auth_service {
			get;
			construct;
		}

		public File? asset_root {
			get;
			set;
		}

		public EndpointParameters (string? address = null, uint16 port = 0, TlsCertificate? certificate = null,
				string? origin = null, AuthenticationService? auth_service = null, File? asset_root = null) {
			Object (
				address: address,
				port: port,
				certificate: certificate,
				origin: origin,
				auth_service: auth_service,
				asset_root: asset_root
			);
		}
	}

	public async IOStream negotiate_connection (IOStream stream, WebServiceTransport transport, string host, string? origin,
			Cancellable? cancellable) throws Error, IOError {
		var input = (DataInputStream) Object.new (typeof (DataInputStream),
			"base-stream", stream.get_input_stream (),
			"close-base-stream", false,
			"newline-type", DataStreamNewlineType.CR_LF);
		OutputStream output = stream.get_output_stream ();

		var request = new StringBuilder.sized (256);
		request.append ("GET /ws HTTP/1.1\r\n");
		string protocol = (transport == TLS) ? "wss" : "ws";
		NetworkAddress addr;
		try {
			addr = NetworkAddress.parse (host, 0);
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}
		uint16 port = addr.get_port ();
		var uri = Uri.build (UriFlags.NONE, protocol, null, addr.get_hostname (), (port != 0) ? port : -1, "/ws", null, null);
		var msg = new Soup.Message.from_uri ("GET", uri);
		Soup.websocket_client_prepare_handshake (msg, origin, null, null);
		msg.request_headers.replace ("Host", make_host_header_value (uri));
		msg.request_headers.replace ("User-Agent", "Frida/" + _version_string ());
		msg.request_headers.foreach ((name, val) => {
			request.append (name + ": " + val + "\r\n");
		});
		request.append ("\r\n");

		var response = new StringBuilder.sized (256);
		try {
			size_t bytes_written;
			yield output.write_all_async (request.str.data, Priority.DEFAULT, cancellable, out bytes_written);

			string? line = null;
			do {
				size_t length;
				line = yield input.read_line_async (Priority.DEFAULT, cancellable, out length);
				if (line == null)
					throw new Error.TRANSPORT ("Connection closed");
				if (line != "")
					response.append (line + "\r\n");
			} while (line != "");
		} catch (GLib.Error e) {
			if (e is IOError.CANCELLED)
				throw (IOError) e;
			throw new Error.TRANSPORT ("%s", e.message);
		}

		var headers = new Soup.MessageHeaders (RESPONSE);
		Soup.HTTPVersion ver;
		uint status_code;
		string reason_phrase;
		if (!Soup.headers_parse_response (response.str, (int) response.len, headers, out ver, out status_code,
				out reason_phrase)) {
			throw new Error.PROTOCOL ("Invalid response");
		}

		if (status_code != Soup.Status.SWITCHING_PROTOCOLS) {
			if (status_code == Soup.Status.FORBIDDEN)
				throw new Error.INVALID_ARGUMENT ("Incorrect origin");
			else
				throw new Error.PROTOCOL ("%s", reason_phrase);
		}

		WebConnection connection = null;
		var frida_context = MainContext.ref_thread_default ();
		var dbus_context = yield get_dbus_context ();
		var dbus_source = new IdleSource ();
		dbus_source.set_callback (() => {
			var websocket = new Soup.WebsocketConnection (stream, msg.uri, CLIENT, origin, protocol,
				new List<Soup.WebsocketExtension> ());
			connection = new WebConnection (websocket);

			var frida_source = new IdleSource ();
			frida_source.set_callback (negotiate_connection.callback);
			frida_source.attach (frida_context);

			return Source.REMOVE;
		});
		dbus_source.attach (dbus_context);
		yield;

		return connection;
	}

	private string make_host_header_value (Uri uri) {
		unowned string host = uri.get_host ();
		if (!Hostname.is_ip_address (host))
			return host;
		var inet_addr = new InetAddress.from_string (host);
		return (inet_addr.get_family () == IPV6) ? @"[$host]" : host;
	}

	public class WebService : Object {
		public signal void incoming (IOStream connection, SocketAddress remote_address, DynamicInterface? dynamic_iface);

		public EndpointParameters endpoint_params {
			get;
			construct;
		}

		public WebServiceFlavor flavor {
			get;
			construct;
		}

		public PortConflictBehavior on_port_conflict {
			get;
			construct;
			default = FAIL;
		}

		public DynamicInterfaceObserver? dynamic_interface_observer {
			get;
			construct;
		}

		public SocketAddress? listen_address {
			get {
				return _listen_address;
			}
		}

		private ConnectionHandler main_handler;
		private SocketAddress? _listen_address;
		private Gee.Map<string, ConnectionHandler> dynamic_interface_handlers = new Gee.HashMap<string, ConnectionHandler> ();

		private Cancellable io_cancellable = new Cancellable ();

		private MainContext? frida_context;
		private MainContext? dbus_context;

		public WebService (EndpointParameters endpoint_params, WebServiceFlavor flavor,
				PortConflictBehavior on_port_conflict = FAIL, DynamicInterfaceObserver? dynif_observer = null) {
			Object (
				endpoint_params: endpoint_params,
				flavor: flavor,
				on_port_conflict: on_port_conflict,
				dynamic_interface_observer: dynif_observer
			);
		}

		public async void start (Cancellable? cancellable) throws Error, IOError {
			frida_context = MainContext.ref_thread_default ();
			dbus_context = yield get_dbus_context ();

			cancellable.set_error_if_cancelled ();

			var start_request = new Promise<SocketAddress> ();
			schedule_on_dbus_thread (() => {
				handle_start_request.begin (start_request, cancellable);
				return Source.REMOVE;
			});

			_listen_address = yield start_request.future.wait_async (cancellable);
		}

		private async void handle_start_request (Promise<SocketAddress> start_request, Cancellable? cancellable) {
			try {
				SocketAddress effective_address = yield do_start (cancellable);
				schedule_on_frida_thread (() => {
					start_request.resolve (effective_address);
					return Source.REMOVE;
				});
			} catch (GLib.Error e) {
				GLib.Error start_error = e;
				schedule_on_frida_thread (() => {
					start_request.reject (start_error);
					return Source.REMOVE;
				});
			}
		}

		private async SocketAddress do_start (Cancellable? cancellable) throws Error, IOError {
			main_handler = make_connection_handler (null);
			SocketAddress? first_effective_address = null;
			SocketConnectable connectable = (flavor == CONTROL)
				? parse_control_address (endpoint_params.address, endpoint_params.port)
				: parse_cluster_address (endpoint_params.address, endpoint_params.port);
			var enumerator = connectable.enumerate ();
			while (true) {
				SocketAddress? address;
				try {
					address = yield enumerator.next_async (io_cancellable);
				} catch (GLib.Error e) {
					throw new Error.NOT_SUPPORTED ("%s", e.message);
				}
				if (address == null)
					break;

				SocketAddress? effective_address = null;
				InetSocketAddress? inet_address = address as InetSocketAddress;
				if (inet_address != null) {
					effective_address = main_handler.listen_on_inet_address (inet_address);
				} else {
					main_handler.listen_on_socket_address (address);
					effective_address = address;
				}

				if (first_effective_address == null)
					first_effective_address = effective_address;
			}

			if (first_effective_address == null)
				throw new Error.NOT_SUPPORTED ("Unable to resolve listening address");

			if (dynamic_interface_observer != null) {
				dynamic_interface_observer.interface_attached.connect (on_dynamic_interface_attached);
				dynamic_interface_observer.interface_detached.connect (on_dynamic_interface_detached);
				dynamic_interface_observer.start ();
			}

			return first_effective_address;
		}

		private void on_dynamic_interface_attached (DynamicInterface iface) {
			unowned string name = iface.name;

			uint16 port = endpoint_params.port;
			if (port == 0)
				port = (flavor == CONTROL) ? DEFAULT_CONTROL_PORT : DEFAULT_CLUSTER_PORT;

			var handler = make_connection_handler (iface);
			try {
				handler.listen_on_inet_address (new InetSocketAddress (iface.ip, port));
			} catch (Error e) {
				return;
			}
			dynamic_interface_handlers[name] = handler;
		}

		private void on_dynamic_interface_detached (DynamicInterface iface) {
			ConnectionHandler handler;
			if (dynamic_interface_handlers.unset (iface.name, out handler))
				handler.close ();
		}

		private ConnectionHandler make_connection_handler (DynamicInterface? dynamic_iface) {
			var handler = new ConnectionHandler (dynamic_iface, endpoint_params, on_port_conflict);
			handler.incoming.connect (on_incoming_connection);
			return handler;
		}

		private void on_incoming_connection (ConnectionHandler handler, IOStream connection, SocketAddress remote_address) {
			schedule_on_frida_thread (() => {
				incoming (connection, remote_address, handler.dynamic_iface);
				return Source.REMOVE;
			});
		}

		public void stop () {
			io_cancellable.cancel ();

			schedule_on_dbus_thread (() => {
				do_stop ();
				return Source.REMOVE;
			});
		}

		private void do_stop () {
			foreach (var handler in dynamic_interface_handlers.values)
				handler.close ();
			dynamic_interface_handlers.clear ();

			if (dynamic_interface_observer != null) {
				dynamic_interface_observer.interface_attached.disconnect (on_dynamic_interface_attached);
				dynamic_interface_observer.interface_detached.disconnect (on_dynamic_interface_detached);
			}

			if (main_handler != null)
				main_handler.close ();
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			assert (frida_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			assert (dbus_context != null);

			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}

		private class ConnectionHandler : Object {
			public signal void incoming (IOStream connection, SocketAddress remote_address);

			public DynamicInterface? dynamic_iface {
				get;
				construct;
			}

			public EndpointParameters endpoint_params {
				get;
				construct;
			}

			public PortConflictBehavior on_port_conflict {
				get;
				construct;
				default = FAIL;
			}

			private Soup.Server server;
			private Gee.Set<WebConnection> connections = new Gee.HashSet<WebConnection> ();
			private Cancellable io_cancellable = new Cancellable ();

			public ConnectionHandler (DynamicInterface? dynamic_iface, EndpointParameters endpoint_params,
					PortConflictBehavior on_port_conflict) {
				Object (
					dynamic_iface: dynamic_iface,
					endpoint_params: endpoint_params,
					on_port_conflict: on_port_conflict
				);
			}

			construct {
				server = (Soup.Server) Object.new (typeof (Soup.Server),
					"tls-certificate", endpoint_params.certificate);

				server.add_websocket_handler ("/ws", endpoint_params.origin, null, on_websocket_opened);

				if (endpoint_params.asset_root != null)
					server.add_handler (null, on_asset_request);
			}

			public void close () {
				io_cancellable.cancel ();

				if (endpoint_params.asset_root != null)
					server.remove_handler ("/");
				server.remove_handler ("/ws");

				server.disconnect ();

				foreach (var connection in connections.to_array ()) {
					try {
						connection.close (null);
					} catch (IOError e) {
						assert_not_reached ();
					}
					remove_connection (connection);
				}
			}

			public InetSocketAddress listen_on_inet_address (InetSocketAddress address) throws Error {
				InetSocketAddress candidate_address = address;
				uint16 start_port = address.get_port ();
				uint16 candidate_port = start_port;
				do {
					try {
						server.listen (candidate_address, compute_listen_options ());
						return candidate_address;
					} catch (GLib.Error e) {
						if (e is IOError.ADDRESS_IN_USE && on_port_conflict == PICK_NEXT) {
							candidate_port++;
							if (candidate_port == start_port)
								throw new Error.ADDRESS_IN_USE ("Unable to bind to any port");
							if (candidate_port == 0)
								candidate_port = 1024;
							candidate_address = new InetSocketAddress (candidate_address.get_address (),
								candidate_port);
						} else {
							throw_listen_error (e);
						}
					}
				} while (true);
			}

			public void listen_on_socket_address (SocketAddress address) throws Error {
				try {
					server.listen (address, compute_listen_options ());
				} catch (GLib.Error e) {
					throw_listen_error (e);
				}
			}

			private Soup.ServerListenOptions compute_listen_options () {
				return (endpoint_params.certificate != null)
					? Soup.ServerListenOptions.HTTPS
					: 0;
			}

			[NoReturn]
			private static void throw_listen_error (GLib.Error e) throws Error {
				if (e is IOError.ADDRESS_IN_USE)
					throw new Error.ADDRESS_IN_USE ("%s", e.message);

				if (e is IOError.PERMISSION_DENIED)
					throw new Error.PERMISSION_DENIED ("%s", e.message);

				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			private void on_websocket_opened (Soup.Server server, Soup.ServerMessage msg, string path,
					Soup.WebsocketConnection connection) {
				var peer = new WebConnection (connection);
				peer.websocket_closed.connect (on_websocket_closed);
				connections.add (peer);

				IOStream soup_stream = connection.get_io_stream ();

				SocketConnection socket_stream;
				soup_stream.get ("base-iostream", out socket_stream);

				SocketAddress remote_address;
				try {
					remote_address = socket_stream.get_remote_address ();
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				incoming (peer, remote_address);
			}

			private void on_websocket_closed (WebConnection connection) {
				remove_connection (connection);
			}

			private void remove_connection (WebConnection connection) {
				connection.websocket_closed.disconnect (on_websocket_closed);
				connections.remove (connection);
			}

			private void on_asset_request (Soup.Server server, Soup.ServerMessage msg, string path,
					HashTable<string, string>? query) {
				msg.get_response_headers ().replace ("Server", "Frida/" + _version_string ());

				unowned string method = msg.get_method ();
				if (method != "GET" && method != "HEAD") {
					msg.set_status (Soup.Status.METHOD_NOT_ALLOWED, null);
					return;
				}

				File location = endpoint_params.asset_root.resolve_relative_path (path.next_char ());

				msg.pause ();
				handle_asset_request.begin (path, location, msg);
			}

			private async void handle_asset_request (string path, File file, Soup.ServerMessage msg) {
				int priority = Priority.DEFAULT;

				string attributes = FileAttribute.STANDARD_TYPE + "," + FileAttribute.STANDARD_SIZE;

				FileInfo info;
				FileInputStream? stream = null;
				try {
					info = yield file.query_info_async (attributes, FileQueryInfoFlags.NONE, priority, io_cancellable);

					FileType type = info.get_file_type ();
					if (type == DIRECTORY) {
						if (!path.has_suffix ("/")) {
							handle_misplaced_request (path + "/", msg);
							return;
						}

						File index_file = file.get_child ("index.html");
						try {
							var index_info = yield index_file.query_info_async (attributes,
								FileQueryInfoFlags.NONE, priority, io_cancellable);
							file = index_file;
							info = index_info;
							type = index_info.get_file_type ();
						} catch (GLib.Error e) {
						}
					}

					if (type != DIRECTORY)
						stream = yield file.read_async (priority, io_cancellable);
				} catch (GLib.Error e) {
					msg.set_status (Soup.Status.NOT_FOUND, null);
					msg.unpause ();
					return;
				}

				if (stream == null)
					yield handle_directory_request (path, file, msg);
				else
					yield handle_file_request (file, info, stream, msg);
			}

			private async void handle_directory_request (string path, File file, Soup.ServerMessage msg) {
				var listing = new StringBuilder.sized (1024);

				string escaped_path = Markup.escape_text (path);
				listing.append ("""<html>
<head><title>Index of %s</title></head>
<body>
<h1>Index of %s</h1><hr><pre>""".printf (escaped_path, escaped_path));

				if (path != "/")
					listing.append ("<a href=\"../\">../</a>");

				listing.append_c ('\n');

				string attributes =
					FileAttribute.STANDARD_DISPLAY_NAME + "," +
					FileAttribute.STANDARD_TYPE + "," +
					FileAttribute.TIME_MODIFIED + "," +
					FileAttribute.STANDARD_SIZE;
				int priority = Priority.DEFAULT;

				try {
					var enumerator = yield file.enumerate_children_async (attributes, FileQueryInfoFlags.NONE, priority,
						io_cancellable);

					List<FileInfo> files = yield enumerator.next_files_async (int.MAX, priority, io_cancellable);

					files.sort ((a, b) => {
						bool a_is_dir = a.get_file_type () == DIRECTORY;
						bool b_is_dir = b.get_file_type () == DIRECTORY;
						if (a_is_dir == b_is_dir)
							return strcmp (a.get_display_name (), b.get_display_name ());
						else if (a_is_dir)
							return -1;
						else
							return 1;
					});

					foreach (FileInfo info in files) {
						string display_name = info.get_display_name ();
						FileType type = info.get_file_type ();
						DateTime modified = info.get_modification_date_time ().to_local ();

						string link = Markup.escape_text (display_name);
						if (type == DIRECTORY)
							link += "/";

						listing
							.append ("<a href=\"")
							.append (link)
							.append ("\">")
							.append (link)
							.append ("</a>");

						int padding_needed = 50 - link.length;
						while (padding_needed > 0) {
							listing.append_c (' ');
							padding_needed--;
						}

						listing
							.append_c (' ')
							.append (modified.format ("%d-%b-%Y %H:%M"))
							.append ("            ");

						string size_info;
						if (type != DIRECTORY)
							size_info = info.get_size ().to_string ();
						else
							size_info = "-";
						listing.append_printf ("%8s\n", size_info);
					}
				} catch (GLib.Error e) {
					msg.set_status (Soup.Status.NOT_FOUND, null);
					msg.unpause ();
					return;
				}

				listing.append ("</pre><hr></body>\n</html>");

				msg.set_status (Soup.Status.OK, null);

				if (msg.get_method () == "HEAD") {
					var headers = msg.get_response_headers ();
					headers.replace ("Content-Type", "text/html");
					headers.replace ("Content-Length", listing.len.to_string ());
				} else {
					msg.set_response ("text/html", Soup.MemoryUse.COPY, listing.str.data);
				}

				msg.unpause ();
			}

			private async void handle_file_request (File file, FileInfo info, FileInputStream stream, Soup.ServerMessage msg) {
				msg.set_status (Soup.Status.OK, null);

				var headers = msg.get_response_headers ();
				headers.replace ("Content-Type", guess_mime_type_for (file.get_path ()));
				headers.replace ("Content-Length", info.get_size ().to_string ());

				if (msg.get_method () == "HEAD") {
					msg.unpause ();
					return;
				}

				var body = msg.get_response_body ();
				body.set_accumulate (false);

				bool finished = false;
				bool waiting = false;
				ulong finished_handler = msg.finished.connect (() => {
					finished = true;
					if (waiting)
						handle_file_request.callback ();
				});
				ulong write_handler = msg.wrote_body_data.connect (chunk => {
					if (waiting)
						handle_file_request.callback ();
				});
				try {
					var buffer = new uint8[64 * 1024];
					while (true) {
						ssize_t n;
						try {
							n = yield stream.read_async (buffer, Priority.DEFAULT, io_cancellable);
						} catch (IOError e) {
							break;
						}
						if (n == 0 || finished)
							break;

						body.append_take (buffer[0:n]);

						msg.unpause ();

						waiting = true;
						yield;
						waiting = false;

						if (finished)
							break;

						msg.pause ();
					}
				} finally {
					msg.disconnect (write_handler);
					msg.disconnect (finished_handler);
					if (!finished)
						msg.unpause ();
				}
			}

			private void handle_misplaced_request (string redirect_uri, Soup.ServerMessage msg) {
				msg.set_redirect (Soup.Status.MOVED_PERMANENTLY, redirect_uri);

				string body = """<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>%s</center>
</body>
</html>""".printf ("Frida/" + _version_string ());

				if (msg.get_method () == "HEAD") {
					var headers = msg.get_response_headers ();
					headers.replace ("Content-Type", "text/html");
					headers.replace ("Content-Length", body.length.to_string ());
				} else {
					msg.set_response ("text/html", Soup.MemoryUse.COPY, body.data);
				}

				msg.unpause ();
			}

			private static string guess_mime_type_for (string path) {
				if (path.has_suffix (".html"))
					return "text/html";

				if (path.has_suffix (".js"))
					return "text/javascript";

				if (path.has_suffix (".json"))
					return "application/json";

				if (path.has_suffix (".css"))
					return "text/css";

				if (path.has_suffix (".jpeg") || path.has_suffix (".jpg"))
					return "image/jpeg";

				if (path.has_suffix (".png"))
					return "image/png";

				if (path.has_suffix (".gif"))
					return "image/gif";

				bool uncertain;
				return ContentType.guess (path, null, out uncertain);
			}
		}
	}

	public enum WebServiceTransport {
		PLAIN,
		TLS
	}

	public enum WebServiceFlavor {
		CONTROL,
		CLUSTER
	}

	public enum PortConflictBehavior {
		FAIL,
		PICK_NEXT
	}

	public interface DynamicInterfaceObserver : Object {
		public signal void interface_attached (DynamicInterface iface);
		public signal void interface_detached (DynamicInterface iface);

		public abstract void start ();
	}

	public class DynamicInterface : Object {
		public string name {
			get;
			construct;
		}

		public InetAddress ip {
			get;
			construct;
		}

		public DynamicInterface (string name, InetAddress ip) {
			Object (name: name, ip: ip);
		}
	}

	public extern static unowned string _version_string ();

	private class WebConnection : IOStream {
		public signal void websocket_closed ();

		public Soup.WebsocketConnection websocket {
			get;
			construct;
		}

		public override InputStream input_stream {
			get {
				return _input_stream;
			}
		}

		public override OutputStream output_stream {
			get {
				return _output_stream;
			}
		}

		public IOCondition pending_io {
			get {
				lock (state)
					return _pending_io;
			}
		}

		private WebInputStream _input_stream;
		private WebOutputStream _output_stream;

		private Soup.WebsocketState state;
		private IOCondition _pending_io;
		private ByteArray recv_queue = new ByteArray ();
		private ByteArray send_queue = new ByteArray ();

		private Gee.Map<unowned Source, IOCondition> sources = new Gee.HashMap<unowned Source, IOCondition> ();

		private MainContext main_context;

		public WebConnection (Soup.WebsocketConnection websocket) {
			Object (websocket: websocket);
		}

		construct {
			websocket.max_incoming_payload_size = (256 * 1024) + 1; // XXX: There's an off-by-one error in libsoup

			_input_stream = new WebInputStream (this);
			_output_stream = new WebOutputStream (this);

			state = websocket.state;
			_pending_io = (state == OPEN) ? IOCondition.OUT : IOCondition.IN;

			main_context = MainContext.ref_thread_default ();

			websocket.closed.connect (on_closed);
			websocket.message.connect (on_message);
		}

		~WebConnection () {
			websocket.message.disconnect (on_message);
			websocket.closed.disconnect (on_closed);
		}

		public override bool close (GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		public override async bool close_async (int io_priority, GLib.Cancellable? cancellable) throws IOError {
			_close ();
			return true;
		}

		private void _close () {
			if (main_context.is_owner ()) {
				do_close ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					do_close ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}
		}

		private void do_close () {
			if (websocket.state != OPEN)
				return;

			websocket.close (1000, "Closing");
		}

		public ssize_t recv (uint8[] buffer) throws IOError {
			ssize_t n;
			lock (state) {
				n = ssize_t.min (recv_queue.len, buffer.length);
				if (n > 0) {
					Memory.copy (buffer, recv_queue.data, n);
					recv_queue.remove_range (0, (uint) n);

					recompute_pending_io_unlocked ();
				} else {
					if (state == OPEN)
						n = -1;
				}

			}

			if (n == -1)
				throw new IOError.WOULD_BLOCK ("Resource temporarily unavailable");

			return n;
		}

		public ssize_t send (uint8[] buffer) {
			lock (state)
				send_queue.append (buffer);

			if (main_context.is_owner ()) {
				process_send_queue ();
			} else {
				var source = new IdleSource ();
				source.set_callback (() => {
					process_send_queue ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}

			return buffer.length;
		}

		private void process_send_queue () {
			if (websocket.state != OPEN)
				return;

			size_t max_message_size = (size_t) websocket.max_incoming_payload_size - 1;

			while (true) {
				uint8[]? chunk = null;
				lock (state) {
					size_t n = size_t.min (send_queue.len, max_message_size);
					if (n == 0)
						return;
					chunk = send_queue.data[0:n];
					send_queue.remove_range (0, (uint) n);
				}

				websocket.send_binary (chunk);
			}
		}

		public void register_source (Source source, IOCondition condition) {
			lock (state)
				sources[source] = condition;
		}

		public void unregister_source (Source source) {
			lock (state)
				sources.unset (source);
		}

		private void on_closed () {
			lock (state) {
				state = websocket.state;
				recompute_pending_io_unlocked ();
			}

			websocket_closed ();
		}

		private void on_message (int type, Bytes message) {
			lock (state) {
				recv_queue.append (message.get_data ());
				recompute_pending_io_unlocked ();
			}
		}

		private void recompute_pending_io_unlocked () {
			IOCondition new_io = 0;
			if (recv_queue.len > 0 || state != OPEN)
				new_io |= IN;
			if (state == OPEN)
				new_io |= OUT;
			_pending_io = new_io;

			foreach (var entry in sources.entries) {
				unowned Source source = entry.key;
				IOCondition c = entry.value;
				if ((new_io & c) != 0)
					source.set_ready_time (0);
			}
		}
	}

	private class WebInputStream : InputStream, PollableInputStream {
		public weak WebConnection connection {
			get;
			construct;
		}

		public WebInputStream (WebConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override ssize_t read (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_readable () {
			return (connection.pending_io & IOCondition.IN) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new WebIOSource (connection, IOCondition.IN), cancellable);
		}

		public ssize_t read_nonblocking_fn (uint8[] buffer) throws GLib.Error {
			return connection.recv (buffer);
		}
	}

	private class WebOutputStream : OutputStream, PollableOutputStream {
		public weak WebConnection connection {
			get;
			construct;
		}

		public WebOutputStream (WebConnection connection) {
			Object (connection: connection);
		}

		public override bool close (Cancellable? cancellable) throws IOError {
			return true;
		}

		public override async bool close_async (int io_priority, Cancellable? cancellable) throws GLib.IOError {
			return close (cancellable);
		}

		public override bool flush (GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override async bool flush_async (int io_priority, GLib.Cancellable? cancellable) throws GLib.Error {
			return true;
		}

		public override ssize_t write (uint8[] buffer, Cancellable? cancellable) throws IOError {
			assert_not_reached ();
		}

		public bool can_poll () {
			return true;
		}

		public bool is_writable () {
			return (connection.pending_io & IOCondition.OUT) != 0;
		}

		public PollableSource create_source (Cancellable? cancellable) {
			return new PollableSource.full (this, new WebIOSource (connection, IOCondition.OUT), cancellable);
		}

		public ssize_t write_nonblocking_fn (uint8[]? buffer) throws GLib.Error {
			return connection.send (buffer);
		}

		public PollableReturn writev_nonblocking_fn (OutputVector[] vectors, out size_t bytes_written) throws GLib.Error {
			assert_not_reached ();
		}
	}

	private class WebIOSource : Source {
		public WebConnection connection;
		public IOCondition condition;

		public WebIOSource (WebConnection connection, IOCondition condition) {
			this.connection = connection;
			this.condition = condition;

			connection.register_source (this, condition);
		}

		~WebIOSource () {
			connection.unregister_source (this);
		}

		protected override bool prepare (out int timeout) {
			timeout = -1;
			return (connection.pending_io & condition) != 0;
		}

		protected override bool check () {
			return (connection.pending_io & condition) != 0;
		}

		protected override bool dispatch (SourceFunc? callback) {
			set_ready_time (-1);

			if (callback == null)
				return Source.REMOVE;

			return callback ();
		}

		protected static bool closure_callback (Closure closure) {
			var return_value = Value (typeof (bool));

			closure.invoke (ref return_value, {});

			return return_value.get_boolean ();
		}
	}
}

"""

```
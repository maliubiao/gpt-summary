Response:
### 功能归纳

该源代码文件 `device-monitor.vala` 是 Frida 工具中用于监控和管理设备连接的核心模块，主要功能包括：

1. **USB 设备管理与模式切换**：
   - 通过 `PortableCoreDeviceUsbTransport` 类管理 USB 设备的连接、模式切换（如从普通模式切换到调试模式）以及网络配置。
   - 支持通过 `LibUSB` 库与 USB 设备进行底层通信，确保设备在调试模式下正常工作。

2. **网络隧道建立与管理**：
   - 通过 `PortableUsbTunnel` 和 `PortableNetworkTunnel` 类建立和管理网络隧道，用于在设备和主机之间传输数据。
   - 支持通过 TCP 连接与设备进行通信，确保调试数据的可靠传输。

3. **设备发现与配对**：
   - 通过 `PairingBrowser` 和 `PairingService` 接口实现设备的发现与配对功能，支持通过 mDNS（多播 DNS）协议发现设备。
   - 支持通过 `PairingStore` 存储和管理设备的配对信息，确保设备在后续连接时能够快速配对。

4. **网络接口管理与配置**：
   - 通过 `NcmPeer` 类管理网络接口的配置，支持通过 `UsbNcmDriver` 驱动与设备的网络接口进行通信。
   - 支持通过 `NetworkStack` 和 `UdpSocket` 等类进行网络通信，确保设备与主机之间的网络连接稳定。

5. **超时与错误处理**：
   - 通过 `TimeoutSource` 和 `CancellableSource` 实现超时和取消操作的处理，确保在设备连接或通信过程中出现问题时能够及时处理。
   - 支持通过 `Error` 和 `IOError` 处理各种异常情况，确保程序的健壮性。

### 涉及二进制底层与 Linux 内核的举例

1. **USB 设备通信**：
   - 通过 `LibUSB` 库与 USB 设备进行底层通信，确保设备在调试模式下正常工作。例如，`_usb_device.ensure_open()` 方法用于确保 USB 设备已打开并准备好进行通信。

2. **网络接口管理**：
   - 通过 `Linux.Network.IfAddrs` 和 `Linux.Network.IfNameindex` 等 Linux 内核接口获取和管理网络接口信息。例如，`detect_ncm_ifaddrs_on_system` 方法通过 `getifaddrs` 和 `if_nameindex` 等系统调用获取网络接口的 IP 地址和名称。

### LLDB 调试示例

假设我们需要调试 `PortableUsbTunnel` 类的 `open` 方法，可以使用以下 LLDB 命令或 Python 脚本：

#### LLDB 命令示例

```lldb
# 设置断点
b PortableUsbTunnel.open

# 运行程序
run

# 查看变量
p usb_device
p ncm_peer
p pairing_store

# 单步执行
n
s

# 继续执行
c
```

#### LLDB Python 脚本示例

```python
import lldb

def debug_portable_usb_tunnel_open(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    # 设置断点
    breakpoint = target.BreakpointCreateByName("PortableUsbTunnel.open")
    process.Continue()

    # 获取变量
    usb_device = frame.FindVariable("usb_device")
    ncm_peer = frame.FindVariable("ncm_peer")
    pairing_store = frame.FindVariable("pairing_store")

    print(f"usb_device: {usb_device}")
    print(f"ncm_peer: {ncm_peer}")
    print(f"pairing_store: {pairing_store}")

    # 单步执行
    thread.StepOver()
    thread.StepInto()

    # 继续执行
    process.Continue()

# 注册命令
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f debug_portable_usb_tunnel_open.debug_portable_usb_tunnel_open debug_portable_usb_tunnel_open')
```

### 假设输入与输出

1. **输入**：
   - USB 设备已连接并处于调试模式。
   - 设备的网络接口已配置并准备好进行通信。

2. **输出**：
   - 成功建立 USB 隧道，设备与主机之间的网络连接稳定。
   - 设备发现与配对成功，配对信息存储在 `PairingStore` 中。

### 用户常见错误与调试线索

1. **USB 设备未正确连接**：
   - 用户可能未正确连接 USB 设备或设备未处于调试模式。调试线索：检查 `_usb_device.ensure_open()` 方法的返回值，确保设备已正确打开。

2. **网络接口配置错误**：
   - 用户可能未正确配置网络接口或网络接口未准备好。调试线索：检查 `detect_ncm_ifaddrs_on_system` 方法的返回值，确保网络接口的 IP 地址和名称正确。

3. **配对信息错误**：
   - 用户可能未正确配对设备或配对信息未存储在 `PairingStore` 中。调试线索：检查 `PairingService.open` 方法的返回值，确保配对信息正确。

### 用户操作步骤

1. **连接 USB 设备**：
   - 用户通过 USB 线连接设备，并确保设备处于调试模式。

2. **启动 Frida 工具**：
   - 用户启动 Frida 工具，并选择要调试的设备。

3. **建立 USB 隧道**：
   - Frida 工具通过 `PortableUsbTunnel` 类建立 USB 隧道，确保设备与主机之间的网络连接稳定。

4. **设备发现与配对**：
   - Frida 工具通过 `PairingBrowser` 和 `PairingService` 接口发现设备并进行配对，配对信息存储在 `PairingStore` 中。

5. **开始调试**：
   - 用户通过 Frida 工具开始调试设备，确保调试数据的可靠传输。

通过以上步骤，用户可以逐步完成设备的连接、隧道建立、配对和调试操作。
### 提示词
```
这是目录为frida/subprojects/frida-python/subprojects/frida-core/src/fruity/device-monitor.vala的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```
ice_request;
		private Promise<LibUSB.Device>? modeswitch_request;
		private Promise<Tunnel?>? tunnel_request;
		private NcmPeer? ncm_peer;

		public PortableCoreDeviceUsbTransport (PortableCoreDeviceBackend parent, UsbDevice device, PairingStore store) {
			Object (pairing_store: store);

			this.parent = parent;
			_usb_device = device;

			char product[LibUSB.DEVICE_STRING_BYTES_MAX + 1];
			var res = device.raw_device.get_device_string (PRODUCT, product);
			if (res >= LibUSB.Error.SUCCESS) {
				product[res] = '\0';
				_name = (string) product;
			}
		}

		public async UsbDevice open (Cancellable? cancellable) throws Error, IOError {
			while (device_request != null) {
				try {
					return yield device_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			device_request = new Promise<UsbDevice> ();

			try {
				ncm_ifaddrs = yield NcmPeer.detect_ncm_ifaddrs_on_system (_usb_device, cancellable);
				if (ncm_ifaddrs.is_empty) {
					_usb_device.ensure_open ();

					if (parent.modeswitch_allowed) {
						modeswitch_request = new Promise<LibUSB.Device> ();
						if (yield _usb_device.maybe_modeswitch (cancellable)) {
							var source = new TimeoutSource.seconds (2);
							source.set_callback (() => {
								if (modeswitch_request != null) {
									modeswitch_request.reject (new Error.TRANSPORT ("Modeswitch timed out"));
									modeswitch_request = null;
								}
								return Source.REMOVE;
							});
							source.attach (MainContext.get_thread_default ());

							LibUSB.Device raw_device = null;
							try {
								raw_device = yield modeswitch_request.future.wait_async (cancellable);
							} finally {
								source.destroy ();
							}

							_usb_device = new UsbDevice (raw_device, parent);
							_usb_device.ensure_open ();
						} else {
							modeswitch_request = null;
						}
					}

					bool device_configuration_changed;
					try {
						ncm_config = UsbNcmConfig.prepare (_usb_device, out device_configuration_changed);
						if (device_configuration_changed)
							yield sleep (250, cancellable);
					} catch (Error e) {
					}

					ncm_ifaddrs = yield NcmPeer.detect_ncm_ifaddrs_on_system (_usb_device, cancellable);
				}

				device_request.resolve (_usb_device);

				return _usb_device;
			} catch (GLib.Error e) {
				device_request.reject (e);
				device_request = null;

				throw_api_error (e);
			}
		}

		public bool try_complete_modeswitch (LibUSB.Device device) {
			if (modeswitch_request == null)
				return false;
			modeswitch_request.resolve (device);
			modeswitch_request = null;
			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (tunnel_request != null) {
				try {
					var tunnel = yield tunnel_request.future.wait_async (cancellable);
					if (tunnel != null)
						yield tunnel.close (cancellable);
				} catch (Error e) {
				} finally {
					tunnel_request = null;
				}
			}

			ncm_peer = null;

			if (device_request != null) {
				try {
					var usb_device = yield device_request.future.wait_async (cancellable);
					yield usb_device.close (cancellable);
				} catch (Error e) {
				} finally {
					device_request = null;
				}
			}
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel> ();

			try {
				var usb_device = yield open (cancellable);

				bool supported_by_os = true;
				if (device != null) {
					try {
						var lockdown = yield LockdownClient.open (device, cancellable);
						yield lockdown.start_session (cancellable);
						var response = yield lockdown.get_value (null, null, cancellable);
						Fruity.PlistDict properties = response.get_dict ("Value");
						if (properties.get_string ("ProductName") == "iPhone OS") {
							uint ios_major_version = uint.parse (properties.get_string ("ProductVersion").split (".")[0]);
							supported_by_os = ios_major_version >= 17;
						}
					} catch (LockdownError e) {
						throw new Error.PERMISSION_DENIED ("%s", e.message);
					}
				}

				PortableUsbTunnel? tunnel = null;
				if (supported_by_os) {
					if (ncm_peer == null) {
						if (!ncm_ifaddrs.is_empty) {
							ncm_peer = yield NcmPeer.locate_on_system_netifs (ncm_ifaddrs, cancellable);
						} else if (ncm_config != null) {
							ncm_peer = yield NcmPeer.establish_using_our_driver (usb_device, ncm_config,
								cancellable);
						}
					}

					if (ncm_peer != null) {
						tunnel = new PortableUsbTunnel (usb_device, ncm_peer, pairing_store);
						tunnel.lost.connect (on_tunnel_lost);
						try {
							yield tunnel.open (cancellable);
						} catch (Error e) {
							if (e is Error.NOT_SUPPORTED)
								tunnel = null;
							else
								throw e;
						}
					}
				}

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}

		private void on_tunnel_lost () {
			tunnel_request = null;
		}
	}

	private class NcmPeer {
		public NetworkStack netstack;
		public InetAddress ip;
		public UsbNcmDriver? ncm;

		~NcmPeer () {
			if (ncm != null)
				ncm.close ();
		}

		public static async Gee.List<InetSocketAddress> detect_ncm_ifaddrs_on_system (UsbDevice usb_device,
				Cancellable? cancellable) throws Error, IOError {
			var device_ifaddrs = new Gee.ArrayList<InetSocketAddress> ();

#if LINUX
			var fruit_finder = FruitFinder.make_default ();
			unowned string udid = usb_device.udid;

			var ncm_interfaces = new Gee.HashSet<string> ();
			var names = if_nameindex ();
			try {
				for (Linux.Network.IfNameindex * cur = names; cur->if_index != 0; cur++) {
					string? candidate_udid = fruit_finder.udid_from_iface (cur->if_name);
					if (candidate_udid != udid)
						continue;

					ncm_interfaces.add (cur->if_name);
				}
			} finally {
				if_freenameindex (names);
			}
			if (ncm_interfaces.is_empty)
				return device_ifaddrs;

			yield Network.wait_until_interfaces_ready (ncm_interfaces, cancellable);

			Linux.Network.IfAddrs ifaddrs;
			Linux.Network.getifaddrs (out ifaddrs);
			for (unowned Linux.Network.IfAddrs candidate = ifaddrs; candidate != null; candidate = candidate.ifa_next) {
				if (candidate.ifa_addr.sa_family != Posix.AF_INET6)
					continue;

				if (!ncm_interfaces.contains (candidate.ifa_name))
					continue;

				device_ifaddrs.add ((InetSocketAddress) SocketAddress.from_native ((void *) candidate.ifa_addr, sizeof (Posix.SockAddrIn6)));
			}
			if (device_ifaddrs.is_empty && !ncm_interfaces.is_empty)
				throw new Error.NOT_SUPPORTED ("no IPv6 address on NCM network interface");
#endif

			return device_ifaddrs;
		}

#if LINUX
		[CCode (cheader_filename = "net/if.h", cname = "if_nameindex")]
		private extern static Linux.Network.IfNameindex* if_nameindex ();

		[CCode (cheader_filename = "net/if.h", cname = "if_freenameindex")]
		private extern static void if_freenameindex (Linux.Network.IfNameindex* index);
#endif

		public static async NcmPeer locate_on_system_netifs (Gee.List<InetSocketAddress> ifaddrs, Cancellable? cancellable)
				throws Error, IOError {
			var main_context = MainContext.ref_thread_default ();

			var probes = new Gee.ArrayList<ActiveMulticastDnsProbe> ();
			var handlers = new Gee.HashMap<ActiveMulticastDnsProbe, ulong> ();
			ActiveMulticastDnsProbe? successful_probe = null;
			InetSocketAddress? observed_sender = null;
			foreach (var addr in ifaddrs) {
				var probe = new ActiveMulticastDnsProbe (addr, main_context, cancellable);
				var handler = probe.response_received.connect ((probe, response, sender) => {
					successful_probe = probe;
					observed_sender = sender;
					locate_on_system_netifs.callback ();
				});
				probes.add (probe);
				handlers[probe] = handler;
			}

			var timeout_source = new TimeoutSource.seconds (2);
			timeout_source.set_callback (locate_on_system_netifs.callback);
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (locate_on_system_netifs.callback);
			cancel_source.attach (main_context);

			yield;

			cancel_source.destroy ();
			timeout_source.destroy ();
			foreach (var e in handlers.entries)
				e.key.disconnect (e.value);
			foreach (var p in probes)
				p.cancel ();

			cancellable.set_error_if_cancelled ();

			if (successful_probe == null)
				throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for mDNS reply");

			return new NcmPeer () {
				netstack = successful_probe.netstack,
				ip = observed_sender.get_address (),
				ncm = null,
			};
		}

		private class ActiveMulticastDnsProbe : Object {
			public signal void response_received (Bytes response, InetSocketAddress sender);

			public NetworkStack netstack;
			public UdpSocket sock;
			public DatagramBasedSource response_source;

			public ActiveMulticastDnsProbe (InetSocketAddress ifaddr, MainContext main_context, Cancellable? cancellable)
					throws Error, IOError {
				var local_ip = ifaddr.get_address ();
				netstack = new SystemNetworkStack (local_ip, ifaddr.scope_id);

				sock = netstack.create_udp_socket ();
				sock.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: local_ip,
					scope_id: netstack.scope_id
				));
				DatagramBased sock_datagram = sock.datagram_based;

				var remoted_mdns_request = make_remoted_mdns_request ();
				var mdns_address = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
					address: new InetAddress.from_string ("ff02::fb"),
					port: 5353,
					scope_id: netstack.scope_id
				);
				Udp.send_to (remoted_mdns_request.get_data (), mdns_address, sock_datagram, cancellable);

				response_source = sock_datagram.create_source (IN, cancellable);
				response_source.set_callback (on_socket_readable);
				response_source.attach (main_context);
			}

			public void cancel () {
				response_source.destroy ();
			}

			private bool on_socket_readable () {
				size_t n;
				uint8 response_buf[2048];
				InetSocketAddress sender;
				try {
					n = Udp.recv (response_buf, sock.datagram_based, null, out sender);
				} catch (GLib.Error e) {
					return Source.REMOVE;
				}

				var response = new Bytes (response_buf[:n]);
				response_received (response, sender);

				return Source.CONTINUE;
			}
		}

		public static async NcmPeer establish_using_our_driver (UsbDevice usb_device, UsbNcmConfig ncm_config,
				Cancellable? cancellable) throws Error, IOError {
			var ncm = yield UsbNcmDriver.open (usb_device, ncm_config, cancellable);

			if (ncm.remote_ipv6_address == null) {
				ulong change_handler = ncm.notify["remote-ipv6-address"].connect ((obj, pspec) => {
					establish_using_our_driver.callback ();
				});

				var main_context = MainContext.get_thread_default ();

				var timeout_source = new TimeoutSource.seconds (2);
				timeout_source.set_callback (establish_using_our_driver.callback);
				timeout_source.attach (main_context);

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (establish_using_our_driver.callback);
				cancel_source.attach (main_context);

				yield;

				cancel_source.destroy ();
				timeout_source.destroy ();
				ncm.disconnect (change_handler);

				cancellable.set_error_if_cancelled ();

				if (ncm.remote_ipv6_address == null)
					throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for the NCM remote IPv6 address");
			}

			return new NcmPeer () {
				netstack = ncm.netstack,
				ip = ncm.remote_ipv6_address,
				ncm = ncm,
			};
		}

		private static Bytes make_remoted_mdns_request () {
			uint16 transaction_id = 0;
			uint16 flags = 0;
			uint16 num_questions = 1;
			uint16 answer_rrs = 0;
			uint16 authority_rrs = 0;
			uint16 additional_rrs = 0;
			string components[] = { "_remoted", "_tcp", "local" };
			uint16 record_type = 12;
			uint16 dns_class = 1 | 0x8000;
			return new BufferBuilder (BIG_ENDIAN)
				.append_uint16 (transaction_id)
				.append_uint16 (flags)
				.append_uint16 (num_questions)
				.append_uint16 (answer_rrs)
				.append_uint16 (authority_rrs)
				.append_uint16 (additional_rrs)
				.append_uint8 ((uint8) components[0].length)
				.append_string (components[0], StringTerminator.NONE)
				.append_uint8 ((uint8) components[1].length)
				.append_string (components[1], StringTerminator.NONE)
				.append_uint8 ((uint8) components[2].length)
				.append_string (components[2], StringTerminator.NUL)
				.append_uint16 (record_type)
				.append_uint16 (dns_class)
				.build ();
		}
	}

	private sealed class PortableUsbTunnel : Object, Tunnel {
		public signal void lost ();

		public UsbDevice usb_device {
			get;
			construct;
		}

		public NcmPeer ncm_peer {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		private UsbNcmDriver? ncm;
		private TunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;
		private int64 _opened_at = -1;

		public PortableUsbTunnel (UsbDevice device, NcmPeer peer, PairingStore store) {
			Object (
				usb_device: device,
				ncm_peer: peer,
				pairing_store: store
			);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var netstack = ncm_peer.netstack;

			var bootstrap_rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ncm_peer.ip,
				port: 58783,
				scope_id: netstack.scope_id
			);
			var bootstrap_stream = yield netstack.open_tcp_connection (bootstrap_rsd_endpoint, cancellable);
			var bootstrap_disco = yield DiscoveryService.open (bootstrap_stream, cancellable);

			var tunnel_service = bootstrap_disco.get_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice");
			var tunnel_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: ncm_peer.ip,
				port: tunnel_service.port,
				scope_id: netstack.scope_id
			);
			var pairing_transport = new XpcPairingTransport (yield netstack.open_tcp_connection (tunnel_endpoint, cancellable));
			var pairing_service = yield PairingService.open (pairing_transport, pairing_store, cancellable);

			TunnelConnection tc = yield pairing_service.open_tunnel (ncm_peer.ip, netstack, cancellable);
			tc.closed.connect (on_tunnel_connection_close);

			_opened_at = get_monotonic_time ();

			var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tc.remote_address,
				port: tc.remote_rsd_port,
				scope_id: tc.tunnel_netstack.scope_id
			);
			var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
			var disco = yield DiscoveryService.open (rsd_connection, cancellable);

			tunnel_connection = tc;
			_discovery_service = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();

			yield tunnel_connection.close (cancellable);

			if (ncm != null)
				ncm.close ();
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			var netstack = tunnel_connection.tunnel_netstack;
			var endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tunnel_connection.remote_address,
				port: port,
				scope_id: netstack.scope_id
			);
			return yield netstack.open_tcp_connection (endpoint, cancellable);
		}

		private void on_tunnel_connection_close () {
			lost ();
		}
	}

	private sealed class PortableCoreDeviceNetworkTransport : Object, Transport {
		public PairingPeer peer {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public InetSocketAddress endpoint {
			get;
			set;
		}

		public InetSocketAddress interface_address {
			get;
			set;
		}

		public ConnectionType connection_type {
			get {
				return NETWORK;
			}
		}

		public string udid {
			get {
				return peer.udid;
			}
		}

		public string? name {
			get {
				return peer.name;
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

		private Promise<Tunnel>? tunnel_request;

		public PortableCoreDeviceNetworkTransport (PairingPeer peer, PairingStore store, InetSocketAddress endpoint,
				InetSocketAddress interface_address) {
			Object (
				peer: peer,
				pairing_store: store,
				endpoint: endpoint,
				interface_address: interface_address
			);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (tunnel_request != null) {
				try {
					var tunnel = yield tunnel_request.future.wait_async (cancellable);
					yield tunnel.close (cancellable);
				} catch (Error e) {
				} finally {
					tunnel_request = null;
				}
			}
		}

		public async Tunnel? find_tunnel (UsbmuxDevice? device, Cancellable? cancellable) throws Error, IOError {
			while (tunnel_request != null) {
				try {
					return yield tunnel_request.future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}
			tunnel_request = new Promise<Tunnel> ();

			try {
				var tunnel = new PortableNetworkTunnel (endpoint, interface_address, pairing_store);
				yield tunnel.open (cancellable);

				tunnel_request.resolve (tunnel);

				return tunnel;
			} catch (GLib.Error e) {
				tunnel_request.reject (e);
				tunnel_request = null;

				throw_api_error (e);
			}
		}
	}

	private sealed class PortableNetworkTunnel : Object, Tunnel {
		public InetSocketAddress endpoint {
			get;
			construct;
		}

		public InetSocketAddress interface_address {
			get;
			construct;
		}

		public PairingStore pairing_store {
			get;
			construct;
		}

		public DiscoveryService discovery {
			get {
				return _discovery_service;
			}
		}

		public int64 opened_at {
			get {
				return _opened_at;
			}
		}

		private TunnelConnection? tunnel_connection;
		private DiscoveryService? _discovery_service;
		private int64 _opened_at = -1;

		private const uint PAIRING_CONNECTION_TIMEOUT = 2000;

		public PortableNetworkTunnel (InetSocketAddress endpoint, InetSocketAddress interface_address, PairingStore store) {
			Object (
				endpoint: endpoint,
				interface_address: interface_address,
				pairing_store: store
			);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			var netstack = new SystemNetworkStack (interface_address.get_address (), interface_address.scope_id);

			var pairing_connection = yield netstack.open_tcp_connection_with_timeout (endpoint, PAIRING_CONNECTION_TIMEOUT,
				cancellable);
			var pairing_transport = new PlainPairingTransport (pairing_connection);
			var pairing_service = yield PairingService.open (pairing_transport, pairing_store, cancellable);

			TunnelConnection tc = yield pairing_service.open_tunnel (endpoint.get_address (), netstack, cancellable);

			_opened_at = get_monotonic_time ();

			var rsd_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tc.remote_address,
				port: tc.remote_rsd_port,
				scope_id: tc.tunnel_netstack.scope_id
			);
			var rsd_connection = yield tc.tunnel_netstack.open_tcp_connection (rsd_endpoint, cancellable);
			var disco = yield DiscoveryService.open (rsd_connection, cancellable);

			tunnel_connection = tc;
			_discovery_service = disco;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			_discovery_service.close ();

			yield tunnel_connection.close (cancellable);
		}

		public async IOStream open_tcp_connection (uint16 port, Cancellable? cancellable) throws Error, IOError {
			var netstack = tunnel_connection.tunnel_netstack;
			var endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: tunnel_connection.remote_address,
				port: port,
				scope_id: netstack.scope_id
			);
			return yield netstack.open_tcp_connection (endpoint, cancellable);
		}
	}

	public interface FruitFinder : Object {
		public static FruitFinder make_default () {
#if LINUX && !ANDROID
			return new LinuxFruitFinder ();
#else
			return new NullFruitFinder ();
#endif
		}

		public abstract string? udid_from_iface (string ifname) throws Error;
	}

	public class NullFruitFinder : Object, FruitFinder {
		public string? udid_from_iface (string ifname) throws Error {
			return null;
		}
	}

	public interface PairingBrowser : Object {
		public const string SERVICE_NAME = "_remotepairing._tcp.local";

		public signal void service_discovered (PairingServiceDetails service);

		public static PairingBrowser make_default () {
#if WINDOWS
			return new WindowsPairingBrowser ();
#elif LINUX && !ANDROID
			return new LinuxPairingBrowser ();
#else
			return new NullPairingBrowser ();
#endif
		}

		public abstract async void start (Cancellable? cancellable) throws IOError;
		public abstract async void stop (Cancellable? cancellable) throws IOError;
	}

	public class NullPairingBrowser : Object, PairingBrowser {
		public async void start (Cancellable? cancellable) throws IOError {
		}

		public async void stop (Cancellable? cancellable) throws IOError {
		}
	}

	public class PairingServiceDetails {
		public string identifier;
		public Bytes auth_tag;
		public InetSocketAddress endpoint;
		public InetSocketAddress interface_address;
	}

	private async void sleep (uint duration_msec, Cancellable? cancellable) throws IOError {
		var main_context = MainContext.get_thread_default ();

		var delay_source = new TimeoutSource (duration_msec);
		delay_source.set_callback (sleep.callback);
		delay_source.attach (main_context);

		var cancel_source = new CancellableSource (cancellable);
		cancel_source.set_callback (sleep.callback);
		cancel_source.attach (main_context);

		yield;

		cancel_source.destroy ();
		delay_source.destroy ();

		cancellable.set_error_if_cancelled ();
	}
}
```
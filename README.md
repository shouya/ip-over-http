## IP over HTTP

This is a toy project demonstrating proxifying IP packs to HTTP
proxies. It sets up a TUN device to handle all outgoing packets(L3),
then pass IP packets (currently only TCP supported) directly to a
transparent proxy(L4) that forward TCP connections to an HTTP
proxy. This proxy must support CONNECT method and does not require
authentication.

Using this architecture no extra TCP/IP packet resolution other than
modifying src/dst ip/port and fixing checksum is required, therefore
it is more concise and probably more efficient than typical
implementations. The logic is copied from
[fqrouter's blog](http://fqrouter.tumblr.com/post/51474945203/socks%E4%BB%A3%E7%90%86%E8%BD%ACvpn).

This code almost translated entirely from
[radaiming](https://github.com/radaiming)'s
[https://github.com/radaiming/tcp-over-http] project.

Currently the code only support forwarding TCP connections to an HTTP
proxy. In the future I might add support for more L4 protocols and
more proxies.

### Usage

Build:

```bash
$ make
```

Run as root:

```bash
$ sudo ./tun
```


Add route table:

```bash
$ sudo ip route add 1.2.3.4 dev tun0
```

Test it:

```bash
$ curl 1.2.3.4
```

MIT License

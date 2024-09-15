bernweb

A partially complete ultra-fast per-file DSCPing, epolling, and multithreading http/https server.

No ipv6 support since I don't have an ipv6 connection (should be trivial to add it though).

Mime types are stored in xattrs, you must ingest files before the server can see them.

Depends on gnutls.

Operating modes (chosen at buildtime):
 Unix dentry:
  Call openat2(), fgetxattr(), and statx() to get file information.
  Can serve changing (i.e. growing, added) files
 Internal Dentry (incomplete, (based on my ftb server code (ftb server not publicly available))):
  CANNOT SERVE CHANGING FILES
  At startup an internal data structure is created with all valid files in the documentroot.
  A single file descriptor is held open for each valid file.
  sendfile() with a non-NULL offset pointer is used so many clients can concurrently receive the same file.
  Not finished due to https://gitlab.com/gnutls/gnutls/-/issues/1580

If your system is configured to have a large tcp_keepalive_time (the default on most Linux distributions) you should keep BERNWEB_SET_KEEPIDLE defined
If not you can comment out the define, and the config file parsing will be slightly simpler and there will be 1 less syscall.

Compile time options
* Where the config file is located - #define CONFIG_FILE in src/main.c - default: "/etc/bernweb/bernweb.conf"
* Whether to setsockopt() on TCP_KEEPIDLE
* More yet to be documented

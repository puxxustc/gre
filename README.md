# GRE #

Userspace GRE tunnel, designed for OpenVZ servers (require TUN device support).

Checksum, Key, Sequence are not supported.

## Pre-builds ##

Platform  | Architecture | URL
----------|--------------|----
GNU/Linux | x86_64       | https://s3.pxx.io/snapshot/gre/gre-x86_64
&nbsp;    | armv6l       | https://s3.pxx.io/snapshot/gre/gre-armv6l
&nbsp;    | armv7l       | https://s3.pxx.io/snapshot/gre/gre-armv7l
&nbsp;    | aarch64      | https://s3.pxx.io/snapshot/gre/gre-aarch64


## Build ##

```bash
gcc -std=gnu99 -O2 -pipe -o gre gre.c
```

## Usage ##

```bash
sudo ./gre <tun dev> remote local
```

## License ##

Copyright (C) 2015 - 2017, Xiaoxiao <i@pxx.io>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

# antd-tunnel-plugin
**tunnel** is an [antd plugin](https://github.com/lxsang/ant-http) providing a generic purpose publish/subscribe message protocol using a single websocket connection.

## Build from source
As **tunnel** is an **Antd's** plugin, the server must be pre-installed

### build dep
* git
* make
* build-essential
* ant-http (libantd.so)


### build
When all dependencies are installed, the build can be done with a few single command lines:

```bash
mkdir tunnel
cd tunnel
# replace x.x.x by a version number
wget -O- https://get.iohub.dev/antd_plugin | bash -s "tunnel-x.x.x"

# or install from a tarball distribution in dist/
tar xvzf tunnel-x.x.x.tar.gz
cd tunnel-x.x.x
./configure --prefix=/opt/www --enable-debug=yes
make
sudo make install
```

### Generate distribution
```sh
libtoolize
aclocal
autoconf
automake --add-missing
make distcheck
``` 

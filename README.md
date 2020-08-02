# antd-wterm-plugin
**wterm** is an [antd plugin](https://github.com/lxsang/ant-http) providing the Terminal gateway to the web using websocket.

## Build from source
As **wterm** is an **Antd's** plugin, the server must be pre-installed

### build dep
* git
* make
* build-essential


### build
When all dependencies are installed, the build can be done with a few single command lines:

```bash
mkdir antd
cd antd
# replace x.x.x by a version number
wget -O- https://get.bitdojo.dev/antd_plugin | bash -s "wterm-x.x.x"

# or install from a tarball distribution in dist/
tar xvzf wterm-x.x.x.tar.gz
cd wterm-x.x.x
./configure --prefix=/opt/www --enable-debug=yes
make
sudo make install
```


## Run
To run the Antd server with the **wterm** plugin:
```sh
/path/to/your/build/antd
```

Web applications can be put on **/path/to/your/build/htdocs**, the web socket to **wterm** is available at:
```
ws://your_host:your_port/wterm
```
This websocket address can be used with [xterm.js](https://xtermjs.org) to provide web based termnial access

### Generate distribution
```sh
libtoolize
aclocal
autoconf
automake --add-missing
make distcheck
``` 
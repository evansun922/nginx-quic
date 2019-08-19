## 帮助我们改进 Nginx-Quic


# 开始 Nginx-Quic

## nginx-quic 介绍

本项目是为了让nginx支持quic协议，并且保持nginx的原有功能不变。这个项目是将开源项目chromium中的quic部分集成到nginx中，所以需要nginx和chromium两个项目的源代码。

目前此项目仅在linux内核下，epoll网络模型下进行过测试，需要linux内核4.18.20-1.el6.elrepo.x86_64以上，推荐使用nginx-1.16.0以上的版本，目前只在1.14.2和1.16.0两个版本上测试。

bin目录下提供了一个已经编译好的nginx-quic，大家可以在centos，redhat，ubuntu等版本中运行测试，nginx-quic的 --prefix=/opt/nginx/。

---

## 编译
nginx-quic编译步骤比较复杂，因为用到了chromium项目中的编译环境，所以我尽量说的详细一些，另外，可以看一些[gn相关的文档](https://chromium.googlesource.com/chromium/src/+/56807c6cb383140af0c03da8f6731d77785d7160/tools/gn/docs/reference.md)学习一下。

- 整个编译需要在ubuntu 14系统下进行，可以使用虚拟机编译，具体可见chromium编译对linux系统版本的要求。
- 下载chromium，下载详见： [chromium的下载及编译](https://chromium.googlesource.com/chromium/src/+/master/docs/linux_build_instructions.md/)。
- 下载nginx版本源码。
- 执行mk2gn.py脚本，脚本具体参数如下：
```         
            python3 mk2gn.py </path/to/nginx> </path/to/chromium/src> <args>

             </path/to/nginx>:                      nginx源码根目录路径。
             </path/to/chromium/src>:    chromium源码src目录路径。
             < args>:                                          configure nginx时，所需的参数。                 
```
- 切到chromium的src目录，执行 gn gen out/Release --args="is_component_build=false is_debug=false"。
- 执行 ninja -C out/Release  nginx，编译好的nginx-quic就在 out/Release目录中。


### 注意事项：
- 如果编译者需要自己定义一些宏或者追加一些库的话，可以手动修改 __chromium/src/net/BUILD.gn__ 文件，修改nginx相关的配置项。
```
                            executable("nginx") {
                                sources = [
                                    # 所用到的.c或者.cc源码，一般不用修改
                                ]
                                include_dirs = [
                                    #头文件dir，类似与 "-I"
                                ]
                                lib_dirs = [
                                    #  库的搜索目录，类似与-L your libdir
                                ]
                                libs = [
                                    # dynamic library: pthread or static library: /path/xxx.a
                                ]
                                cflags_c = [
                                    # 编译选项
                                    "-D_FORTIFY_SOURCE=2",
                                    "-DTCP_FASTOPEN=23",
                                    "-DNDK_SET_VAR",
                                ]
                            }
```
- 编译nginx用到的所有静态库，在编译静态库时加入 "-fPIC"编译选项。
- 无需增加openssl静态库，nginx-quic会用到chromium的boringssl。

---
## nginx-quic 配置

### Example Configuration


 >           http {
>
>               ...
>
>               server {
>                    listen              443 quic reuseport >sndbuf=1048576 rcvbuf=1048576;
 >                   
 >                   quic_ssl_certificate                 ssl/tv.test.com.crt;
 >                   quic_ssl_certificate_key       ssl/tv.test.com.pkcs8;
>
>                   quic_bbr                        on;
>                   quic_flush_interval 20;
>
>
>                   ...
>               }

###  Directives
```
Syntax:                listen   quic;
Default:               listen   *:80 | *:8000 quic;
Context:              server
Example:             listen       443 quic reuseport sndbuf=1048576 rcvbuf=1048576;
为listen配置新加一个参数quic， 只要带这个参数，这个监听就会使用quic协议，需要注意 quic 参数与ssl， http2参数不兼容，不可同时使用，使用quic参数，务必带上reuseport


Syntax:        quic_ssl_certificate       /path/to/tv.test.com.crt;
Default:        — 
Context:      server
 quic用到的ssl证书


Syntax:               quic_ssl_certificate_key          /path/to/tv.test.com.pkcs8;
Default:              —
Context:             server
quic用到的ssl证书的key
可以使用下面的命令，将*.key转换成*.pkcs8:
openssl pkcs8 -topk8 -outform DER -inform PEM -in tv.test.com.key -out tv.test.com.pkcs8 -nocrypt


Syntax:            quic_bbr      on | off;
Default:           quic_bbr      off;
Context:          http,  server,  location
quic是否启用bbr拥塞算法


Syntax:          quic_flush_interval     number;
Default:         quic_flush_interval     40;
Context:        http,  server,   location
间隔多少毫秒刷新一次系统调用sendmmsg的缓冲输出。


Syntax:          quic_idle_network_timeout     time;
Default:         quic_idle_network_timeout     10m;
Context:        http,  server,   location
客户端网络空闲超时时间，默认10分钟。
```

## 作者
- sunlei     &emsp; email: sswin0922@163.com

## Help us to improve the Nginx-Quic


# Begin to Nginx-Quic

## Why nginx-quic

The purpose of this project is to make nginx support quic and keep the original functions of nginx unchanged.
this project requires nignx and chromium source code

At present, this project had only been tested under the Linux kernel and epoll network, which requires Linux kernel 4.18.20-1. El6. Elrepo. X86_64 and above.

There is a compiled nginx-quic in bin,you can run it on centos, redhat, ubuntu, etc, the test nginx-quic's --prefix=/opt/nginx/.

[中文版文档](https://github.com/evansun922/nginx-quic/blob/master/README-CN.md)
---

## Compile
The compilation step of nginx-quic is quite complicated, so I will try to explain it in detail. In addition, you can read some [gn documents](https://chromium.googlesource.com/chromium/src/+/56807c6cb383140af0c03da8f6731d77785d7160/tools/gn/docs/reference.md) to learn it.

The compilation needs to be carried out under ubuntu 14, which can be compiled using virtual machine. please see the official website of chromium for Linux system requirements.
- download chromium, see:  [the official website of chromium](https://chromium.googlesource.com/chromium/src/+/master/docs/linux_build_instructions.md/).
- download nginx source code.
- run mk2gn.py, The parameters of the script are as follows:
```         
            python3 mk2gn.py </path/to/nginx> </path/to/chromium/src> <version> < args>

             </path/to/nginx>:                      path of nginx.
             </path/to/chromium/src>:    path of chromium/src.
             <version> :                                     version of ningx (1.16.0，1.14.2，1.17.1etc).
             < args>：                                        when configure nginx, the parameters required to configure.                 
```
- cd /path/to/chromium/src, and run __gn gen out/Release --args="is_component_build=false is_debug=false"__.
- run __ninja -C out/Release  nginx__.


### Mark：
- If you need to define macros or add some libraries, you can manually modify the chromium/src/net/BUILD.gn about  the configuration of nginx.
```
                            executable("nginx") {
                                sources = [
                                    # the source file .c or .cc,  you don't usually modify it.
                                ]
                                include_dirs = [
                                    #add the directory dir to the list of directories to be searched for header files during preprocessing.
                                ]
                                lib_dirs = [
                                    #  add directory dir to the list of directories to be searched for libraries.
                                ]
                                libs = [
                                    # dynamic library: pthread or static library: /path/xxx.a
                                ]
                                cflags_c = [
                                    # compile option flags
                                    "-D_FORTIFY_SOURCE=2",
                                    "-DTCP_FASTOPEN=23",
                                    "-DNDK_SET_VAR",
                                ]
                            }
```
- All of static libraries used by nginx, which should be compiled with the flag "-fPIC".
- no use openssl, nginx-quic use boringssl of chromium.

---
## nginx-quic Configuration

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
add flag "quic" of "listen" for using quic ,  when you use flag "quic", be sure to bring the flag "reuseport" and you can not used "ssl" or "http2" at the same time.


Syntax:        quic_ssl_certificate       /path/to/tv.test.com.crt;
Default:        — 
Context:      server
 ssl-certificate of quic. 


Syntax:               quic_ssl_certificate_key          /path/to/tv.test.com.pkcs8;
Default:              —
Context:             server
 ssl-certificate's key of quic. 
you can use this cmd to change "*.key" to "*.pkcs8":
openssl pkcs8 -topk8 -outform DER -inform PEM -in tv.test.com.key -out tv.test.com.pkcs8 -nocrypt


Syntax:            quic_bbr      on | off;
Default:           quic_bbr      off;
Context:          http,  server,  location
enable bbr of quic


Syntax:          quic_flush_interval     number;
Default:         quic_flush_interval     40;
Context:        http,  server,   location
the buffered of sendmmsg is refreshed every "number" milliseconds.
```

## Author
- sunlei     &emsp; email: sswin0922@163.com
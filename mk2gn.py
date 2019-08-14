#!/usr/bin/env python

import os,sys
#import db

include_dirs = []
lib_dirs     = []
sources      = []
libs         = []
flags_c      = []

def GetNginxVersion(nginx_h):
    try:
        fd = open(nginx_h, "r")
        
        while True:
            line = fd.readline()

            if line == "":
                break

            if line.find("#define nginx_version") == 0:
                line = line.replace("#define nginx_version", "").strip()
                fd.close()
                return int(line)
                

        fd.close()

    except Exception as e:
        print("get version of nginx failed")
        sys.exit(1)

if __name__ == '__main__':
    
    if len(sys.argv) < 4:
        print("Usage: python3 mk2gn.py </path/to/nginx> </path/to/chromium/src> <args>")
        print("\nOptions:")
        print("    </path/to/nginx>:         path of nginx.")
        print("    </path/to/chromium/src>:  path of chromium/src.")
        print("    < args>:                  when configure nginx, the parameters required to configure.\n")
        sys.exit(0)

    quic_module_root        = os.getcwd()
    nginx_root              = os.path.realpath(sys.argv[1])
    chromium_root           = os.path.realpath(sys.argv[2])
    nginx_version           = 0
    nginx_args              = []
    patch_path              = ""
    nginx_src_core_nginx_h  = ""
    chromium_net_gn         = ""

    
    if nginx_root[-1] == '/':
        nginx_src_core_nginx_h = nginx_root + "src/core/nginx.h"
    else:
        nginx_src_core_nginx_h = nginx_root + "/src/core/nginx.h"
    
    if chromium_root[-1] == '/':
        chromium_net_gn = chromium_root + "net/BUILD.gn"
    else:
        chromium_net_gn = chromium_root + "/net/BUILD.gn"
        

    if os.path.exists(quic_module_root+"/quic_module") == False:
        print("""Not found the dir "quic_moudle" in current dir "%s"."""%(quic_module_root))
        sys.exit(0)

    if os.path.exists(nginx_src_core_nginx_h) == False:
        print("""Not found the "src/core/nginx.h" in nginx dir "%s"."""%(nginx_root))
        sys.exit(0)

    if os.path.exists(chromium_root) == False:
        print("""Not found the "net/BUILD.gn" in chromium dir "%s"."""%(chromium_root))
        sys.exit(0)
        

    nginx_version = GetNginxVersion(nginx_src_core_nginx_h)
    print("This current version of nginx is %d."%(nginx_version))
    if nginx_version >= 1016000:
        patch_path = quic_module_root + "/patch/quic-1.16.0.patch"
    elif nginx_version == 1014002:
        patch_path = quic_module_root + "/patch/quic-1.14.2.patch"
    else:
        print("Not support current version of nginx(%d) to patch."%(nginx_version))
        sys.exit(0)
        
    argc = len(sys.argv)
    for i in range(3, argc):
        nginx_args.append(sys.argv[i])

    # patch nginx        
    os.chdir(nginx_root)

    cmd = "patch -p0 <%s"%(patch_path)
    print("run %s"%(cmd))
    os.system(cmd)

    cmd = "./configure"
    for a in nginx_args:
        cmd = cmd + " " + a
    cmd = cmd + " --add-module=" + quic_module_root + "/quic_module"
    print("run %s"%(cmd))
    os.system(cmd)
    


    try:
        fd = open("objs/Makefile", "r")

        begin_all_incs = False
        begin_sources  = False
        begin_lib      = False
        
        while True:
            line = fd.readline()
            
            if line == "":
                break
            
            if line.find("ALL_INCS =") == 0:
                line = line.replace("ALL_INCS =", "")
                begin_all_incs = True

            if begin_all_incs == True:
                line = line.replace("-I", "")
                line = line.replace("\\", "").strip()
                if line == "":
                    begin_all_incs = False
                    continue
                if line.find("boringssl") >= 0 or line.find("openssl") >= 0:
                    continue

                line = os.path.realpath(line)
                include_dirs.append(line)
                continue


            
            if line.find("\t$(LINK) -o objs/nginx") == 0:
                begin_lib = True
                continue;

            if begin_lib == True:
                if line.find("\tobjs") == 0:
                    continue

                line = line.strip()
                if line == "":
                    begin_lib = False
                    continue
                
                arys = line.split(" ")
                for item in arys:
                    item = item.strip()
                    if item == "":
                        continue
                    if item.find("boringssl") >= 0 or item.find("openssl") >= 0:
                        continue
                    
                    if item.find("-l") == 0:
                        if item in ("-ldl","-lpthread","-lm"):
                            continue
                        libs.append(item.replace("-l", ""))
                        continue

                    if item.find("-L") == 0:
                        item = item.replace("-L", "")
                        item = os.path.realpath(item)
                        lib_dirs.append(item)
                        continue

                    item = os.path.realpath(item)
                    if os.path.exists(item) == True:
                        libs.append(item)

                continue

            if line.find("CFLAGS = ") == 0:
                line = line.replace("CFLAGS = ", "").strip()

                arys = line.split(" ")
                for item in arys:
                    item = item.strip()
                    if item == "":
                        continue;
                    if item.find("boringssl") >= 0 or item.find("openssl") >= 0:
                        continue
                    
                    if item.find("-I") == 0:
                        item = item.replace("-I", "")
                        item = os.path.realpath(item)
                        include_dirs.append(item)
                        continue

                    if item.find("-L") == 0:
                        item = item.replace("-L", "")
                        item = os.path.realpath(item)
                        lib_dirs.append(item)
                        continue

                    if item in ("-pipe","-O","-O2","-O3","-g","-W","-Wall","-Wpointer-arith","-Wno-unused-parameter","-Werror","-m64"):
                        continue
                    flags_c.append(item)
                continue

                    
            if line.find("modules:") == 0:
                begin_sources = True
                continue;

            if begin_sources == True:
                if line.find("objs/nginx") == 0:
                    continue
                
                if line.find("objs/") == 0:
                    line = fd.readline()
                    line = line.strip()
                    if line[0] != '/':
                        line = os.path.realpath(line)
                    sources.append(line)


        fd.close()

        
    except Exception as e:
        print("open \"objs/Makefile\" failed, %s"%(str(e)))
        sys.exit(1)


    os.chdir(chromium_root)
    os.system("git checkout net/BUILD.gn")
    os.system("mv net/BUILD.gn net/BUILD.gn.old")

    try:
        in_fd = open("net/BUILD.gn.old", "r")        
        out_fd = open("net/BUILD.gn", "w")

        while True:
            line = in_fd.readline()
            if line == "":
                break

            if line.find("""  executable("quic_client_for_interop_test") """) == 0:
                out_fd.writelines("""  executable("nginx") {\n""")
        
                out_fd.writelines("""    sources = [\n""")
                for m in sources:
                    out_fd.writelines("""      "%s",\n"""%(m))
                out_fd.writelines("""    ]\n""")
            
                out_fd.writelines("""    include_dirs = [\n""")
                for a in include_dirs:
                    out_fd.writelines("""      "%s",\n"""%(a))
                out_fd.writelines("""    ]\n""")
            

                out_fd.writelines("""    deps = [\n""")
                out_fd.writelines("""      ":epoll_quic_tools",\n""")
                out_fd.writelines("""      ":epoll_server",\n""")
                out_fd.writelines("""      ":net",\n""")
                out_fd.writelines("""      ":simple_quic_tools",\n""")
                out_fd.writelines("""      "//base",\n""")
                out_fd.writelines("""      "//third_party/boringssl",\n""")
                out_fd.writelines("""    ]\n""")

                out_fd.writelines("""    lib_dirs = [\n""")
                out_fd.writelines("""      # -L your libdir\n""")
                for l in lib_dirs:
                    out_fd.writelines("""      "%s",\n"""%(l))
                out_fd.writelines("""    ]\n""")

                out_fd.writelines("""    libs = [\n""")
                out_fd.writelines("""      # dynamic library: pthread or static library: /path/xxx.a\n""")
                for l in libs:
                    out_fd.writelines("""      "%s",\n"""%(l))
                out_fd.writelines("""    ]\n""")

                out_fd.writelines("""    cflags_c = [\n""")
                for f in flags_c:
                    out_fd.writelines("""      "%s",\n"""%(f))
                out_fd.writelines("""    ]\n""")
            
                out_fd.writelines("""  }\n\n""")
                
                
                
            out_fd.writelines(line)
            
        

        
        out_fd.close()
        in_fd.close()
        
    except Exception as e:
        print("write nginx.gn failed. %s"%(str(e)))








        

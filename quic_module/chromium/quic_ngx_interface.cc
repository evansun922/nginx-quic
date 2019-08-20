
/*
 * Copyright (C) sunlei
 */

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <vector>
#include <ngx_core.h>

#include "base/at_exit.h"
#include "base/strings/stringprintf.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "quic_ngx_backend.h"
#include "quic_ngx_server.h"
#include "quic_ngx_stream.h"
#include "quic_ngx_interface.h"



#define set_ngx_quic_args(argc, argv, v)                \
  argv[argc] = new char[(v).length()+1];                \
  memset(argv[argc], 0, (v).length()+1);                \
  memcpy(argv[(argc)++], (v).c_str(), (v).length()+1)


void* ngx_init_quic(void* ngx_module_context,
                    int listen_fd,
                    int port,
                    int address_family,
                    CreateNgxTimer create_ngx_timer,
                    AddNgxTimer add_ngx_timer,
                    DelNgxTimer del_ngx_timer,
                    FreeNgxTimer free_ngx_timer,
                    RequestHttpQuic2Ngx req_quic_2_ngx,
                    SetStreamForNgx set_stream_for_ngx,
                    const char* certificate_file,
                    const char* key_file,
                    int bbr,
                    int idle_network_timeout) {
  // base::AtExitManager exit_manager;
  
  int quic_argc = 0;
  char *quic_argv[10];
  memset(quic_argv, 0, sizeof(quic_argv));
  
  std::string v = "libngx_quic";
  set_ngx_quic_args(quic_argc, quic_argv, v);
  
  v = base::StringPrintf("--certificate_file=%s", certificate_file);
  set_ngx_quic_args(quic_argc, quic_argv, v);
  
  v = base::StringPrintf("--key_file=%s", key_file);
  set_ngx_quic_args(quic_argc, quic_argv, v);
  
  // v = "--v=1";
  // set_ngx_quic_args(quic_argc, quic_argv, v);
  
  const char* usage = "Usage: quic_server [options]";
  std::vector<std::string> non_option_args =
    quic::QuicParseCommandLineFlags(usage, quic_argc,
                   reinterpret_cast<char **>(quic_argv));
  if (!non_option_args.empty()) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  for (int i = 0; i < quic_argc; i++) {
    delete[] quic_argv[i];
    quic_argv[i] = nullptr;
  }

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  // settings.logging_dest = logging::LOG_TO_ALL;
  // settings.log_file = "/tmp/quic.log";
  // settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  CHECK(logging::InitLogging(settings));

  if (bbr) {
    SetQuicReloadableFlag(quic_default_to_bbr, true);
  }
  
  quic::QuicNgxBackend* backend = new quic::QuicNgxBackend();
  backend->InitializeBackend("");
  backend->set_ngx_args(req_quic_2_ngx, set_stream_for_ngx);
  quic::QuicNgxServer* server =
    new quic::QuicNgxServer(quic::CreateDefaultProofSource(),
                            backend,
                            idle_network_timeout);
  server->Initialize(ngx_module_context,
                     listen_fd,
                     port,
                     address_family,
                     create_ngx_timer,
                     add_ngx_timer,
                     del_ngx_timer,
                     free_ngx_timer);
  return server;
}

void ngx_free_quic(void* chromium_server) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);

  delete server->server_backend();
  delete server;
}

void ngx_shutdown_quic(void* chromium_server) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);
  server->Shutdown();
}

void ngx_read_dispatch_packets(void* chromium_server,
                               void* ngx_connection) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);
  server->ReadAndDispatchPackets(ngx_connection);
}

ssize_t ngx_send_quic_packets(void* quic_stream,
                              const char*data, int len) {
  if (!quic_stream) {
    return -1;
  }
  
  quic::QuicNgxStream *stream =
    reinterpret_cast<quic::QuicNgxStream*>(quic_stream);
  // HTTP/1.x TODO if user data of start = "HTTP/1" is bug
  if (len >= 7 && memcmp(data, "HTTP/1.", 7) == 0 ) {
    if (stream->SendHttpHeaders(data, len) == false) {
      return -1;
    }
  } else {
    stream->SendHttpbody(data, len);
  }

  return len;
}

int ngx_flush_cache_packets(void* chromium_server) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);

  if (server->FlushWriteCache() == true) {
    return NGX_AGAIN;
  }

  return NGX_OK;
}

int ngx_can_write(void* chromium_server) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);

  if (server->CanWrite() == true) {
    return NGX_AGAIN; 
  }

  return NGX_OK;
}

void ngx_set_nc_for_quic_stream(void* quic_stream,
                                void* ngx_connection) {
  quic::QuicNgxStream *stream =
    reinterpret_cast<quic::QuicNgxStream*>(quic_stream);
  stream->set_ngx_connection(ngx_connection);
}




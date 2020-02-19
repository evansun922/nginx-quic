
/*
 * Copyright (C) sunlei
 */

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <vector>
#include <ngx_core.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include "base/at_exit.h"
#include "base/strings/stringprintf.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "quic_ngx_http_backend.h"
#include "quic_ngx_http_server.h"
#include "quic_ngx_http_stream.h"
#include "quic_ngx_http_interface.h"
#include "proof_source_nginx.h"



#define set_ngx_quic_args(argc, argv, v)                \
  argv[argc] = new char[(v).length()+1];                \
  memset(argv[argc], 0, (v).length()+1);                \
  memcpy(argv[(argc)++], (v).c_str(), (v).length()+1)


void* ngx_http_init_quic(void* ngx_module_context,
                         int listen_fd,
                         int port,
                         int address_family,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer,
                         RequestHttpQuic2Ngx req_quic_2_ngx,
                         SetStreamForNgx set_stream_for_ngx,
                         SetEPOLLOUT set_epoll_out,
                         char **certificate_list,
                         char **certificate_key_list,
                         int bbr,
                         int ietf_draft,
                         int idle_network_timeout,
                         uintptr_t ngx_log_level) {
  // base::AtExitManager exit_manager;
  
  int quic_argc = 0;
  char *quic_argv[10];
  memset(quic_argv, 0, sizeof(quic_argv));
  
  std::string v = "libngx_quic";
  set_ngx_quic_args(quic_argc, quic_argv, v);
  
  // v = base::StringPrintf("--certificate_file=%s", certificate_file);
  // set_ngx_quic_args(quic_argc, quic_argv, v);
  
  // v = base::StringPrintf("--key_file=%s", keyfile.c_str());
  // set_ngx_quic_args(quic_argc, quic_argv, v);
  
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

  quic::quic_nginx_init_logging(ngx_log_level);
  
  if (bbr) {
    SetQuicReloadableFlag(quic_default_to_bbr_v2, true);
  }

  quic::ParsedQuicVersionVector supported_versions;
  if (ietf_draft) {
    quic::QuicVersionInitializeSupportForIetfDraft();
    supported_versions = {quic::ParsedQuicVersion(
                          quic::PROTOCOL_TLS1_3,
                          quic::QUIC_VERSION_99)};
  } else {
    supported_versions = quic::AllSupportedVersions();
  }
  for (const auto& version : supported_versions) {
    QuicEnableVersion(version);
  }
  
  quic::QuicNgxHttpBackend* backend = new quic::QuicNgxHttpBackend();
  backend->InitializeBackend("");
  backend->set_ngx_args(req_quic_2_ngx, set_stream_for_ngx);

  auto proof_source = std::make_unique<quic::ProofSourceNginx>();
  for (int i = 0; certificate_list[i] && certificate_key_list[i]; i++) {
    
    proof_source->Initialize(base::FilePath(certificate_list[i]),
                             base::FilePath(certificate_key_list[i]),
                             base::FilePath());    
  }

  quic::QuicConfig config;
  quic::QuicTagVector connection_options;
  connection_options.push_back(quic::k5RTO);
  // config.SetConnectionOptionsToSend(connection_options);
  config.SetInitialReceivedConnectionOptions(connection_options);
  
  quic::QuicNgxHttpServer* server =
    new quic::QuicNgxHttpServer(
                            std::move(proof_source),
                            config,
                            supported_versions,
                            backend,
                            idle_network_timeout);
  backend->set_server(server);
  server->Initialize(ngx_module_context,
                     listen_fd,
                     port,
                     address_family,
                     create_ngx_timer,
                     add_ngx_timer,
                     del_ngx_timer,
                     free_ngx_timer,
                     set_epoll_out);
  
  return server;
}

void ngx_http_free_quic(void* chromium_server) {
  quic::QuicNgxHttpServer *server =
    reinterpret_cast<quic::QuicNgxHttpServer*>(chromium_server);

  quic::QuicNgxHttpBackend* back_end = server->server_backend();
  delete server;
  delete back_end;
}

void ngx_http_shutdown_quic(void* chromium_server) {
  quic::QuicNgxHttpServer *server =
    reinterpret_cast<quic::QuicNgxHttpServer*>(chromium_server);
  server->Shutdown();
}

void ngx_http_read_dispatch_packets(void* chromium_server,
                               void* ngx_connection) {
  quic::QuicNgxHttpServer *server =
    reinterpret_cast<quic::QuicNgxHttpServer*>(chromium_server);
  server->ReadAndDispatchPackets(ngx_connection);
}

ssize_t ngx_http_send_quic_packets(void* quic_stream,
                              const char*data, int len) {
  if (!quic_stream) {
    return -1;
  }
  
  quic::QuicNgxHttpStream *stream =
    reinterpret_cast<quic::QuicNgxHttpStream*>(quic_stream);
  //  start = "HTTP/1"
  if (false == stream->get_send_header()) {
    if (len < 7 || memcmp(data, "HTTP/1.", 7) != 0 ) {
      return -1;
    }
    if (stream->SendHttpHeaders(data, len) == false) {
      return -1;
    }
  } else {
    if (stream->SendHttpbody(data, len) == false) {
      return -1;
    }
  }

  return len;
}

size_t ngx_http_stream_buffered_size(void* quic_stream) {
  if (!quic_stream) {
    return 0;
  }
  
  quic::QuicNgxHttpStream *stream =
    reinterpret_cast<quic::QuicNgxHttpStream*>(quic_stream);

  return stream->BufferedDataBytes();
}

int ngx_http_flush_cache_packets(void* chromium_server) {
  quic::QuicNgxHttpServer *server =
    reinterpret_cast<quic::QuicNgxHttpServer*>(chromium_server);

  if (server->FlushWriteCache() == true) {
    return NGX_AGAIN;
  }

  return NGX_OK;
}

int ngx_http_can_write(void* chromium_server) {
  quic::QuicNgxHttpServer *server =
    reinterpret_cast<quic::QuicNgxHttpServer*>(chromium_server);

  if (server->CanWrite() == true) {
    return NGX_AGAIN; 
  }

  return NGX_OK;
}

void ngx_http_set_nc_for_quic_stream(void* quic_stream,
                                void* ngx_connection) {
  quic::QuicNgxHttpStream *stream =
    reinterpret_cast<quic::QuicNgxHttpStream*>(quic_stream);
  stream->set_ngx_connection(ngx_connection);
}


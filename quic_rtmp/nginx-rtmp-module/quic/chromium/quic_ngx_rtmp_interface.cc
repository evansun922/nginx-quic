
/*
 * Copyright (C) sunlei
 */

#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <vector>
#include <ngx_core.h>

#include "base/at_exit.h"
#include "base/strings/stringprintf.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/simple_ticket_crypter.h"
#include "quic_ngx_rtmp_server.h"
#include "quic_ngx_rtmp_interface.h"
#include "proof_source_nginx.h"
#include "quic_ngx_rtmp_session.h"


#define set_ngx_quic_args(argc, argv, v)                \
  argv[argc] = new char[(v).length()+1];                \
  memset(argv[argc], 0, (v).length()+1);                \
  memcpy(argv[(argc)++], (v).c_str(), (v).length()+1)


void* ngx_rtmp_init_quic(void* ngx_module_context,
                         int listen_fd,
                         int port,
                         int address_family,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer,
                         char **certificate_list,
                         char **certificate_key_list,
                         ProcessRtmpData process_rtmp_data,
                         SetVisitorForNgx set_visitor_for_ngx,
                         SetEPOLLOUT set_epoll_out,
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

  // bbr
  SetQuicReloadableFlag(quic_default_to_bbr_v2, true);


  auto proof_source = std::make_unique<quic::ProofSourceNginx>();
  proof_source->SetTicketCrypter(
      std::make_unique<quic::SimpleTicketCrypter>
      (quic::QuicChromiumClock::GetInstance()));
  for (int i = 0; certificate_list[i] && certificate_key_list[i]; i++) {
    
    proof_source->Initialize(base::FilePath(certificate_list[i]),
                             base::FilePath(certificate_key_list[i]),
                             base::FilePath());
  }

  // quic::QuicConfig config;
  // quic::QuicTagVector connection_options;
  // connection_options.push_back(quic::k5RTO);
  // // config.SetConnectionOptionsToSend(connection_options);
  // config.SetInitialReceivedConnectionOptions(connection_options);
  
  quic::QuicNgxRtmpServer* server =
    new quic::QuicNgxRtmpServer(listen_fd, port,
                                std::move(proof_source));
                         

  server->Initialize(ngx_module_context,
                     address_family,
                     create_ngx_timer,
                     add_ngx_timer,
                     del_ngx_timer,
                     free_ngx_timer,
                     process_rtmp_data,
                     set_visitor_for_ngx,
                     set_epoll_out);
  
  return server;
}

void ngx_rtmp_free_quic(void* chromium_server) {
  quic::QuicNgxRtmpServer *server =
    reinterpret_cast<quic::QuicNgxRtmpServer*>(chromium_server);
  delete server;
}

void ngx_rtmp_shutdown_quic(void* chromium_server) {
  quic::QuicNgxRtmpServer *server =
    reinterpret_cast<quic::QuicNgxRtmpServer*>(chromium_server);
  server->Shutdown();
}

void ngx_rtmp_read_dispatch_packets(void* chromium_server,
                                    void* ngx_connection) {
  quic::QuicNgxRtmpServer *server =
    reinterpret_cast<quic::QuicNgxRtmpServer*>(chromium_server);
  server->ReadAndDispatchPackets(ngx_connection);
}

ssize_t ngx_rtmp_send_quic_packets(
                          void* quic_visitor,
                          const char*data,
                          int len) {
  if (!quic_visitor) {
    return -1;
  }
  
  quic::QuicNgxRtmpVisitor *visitor =
    reinterpret_cast<quic::QuicNgxRtmpVisitor*>(quic_visitor);
  if (visitor->Write(data, len) == false) {
    return -1;
  }

  return len;
}

void ngx_rtmp_sendfin(void* quic_visitor) {
  if (!quic_visitor) {
    return;
  }
  
  quic::QuicNgxRtmpVisitor *visitor =
    reinterpret_cast<quic::QuicNgxRtmpVisitor*>(quic_visitor);
  visitor->SendFin();
}

// size_t ngx_http_stream_buffered_size(void* quic_stream) {
//   if (!quic_stream) {
//     return 0;
//   }
  
//   quic::QuicNgxHttpStream *stream =
//     reinterpret_cast<quic::QuicNgxHttpStream*>(quic_stream);

//   return stream->BufferedDataBytes();
// }

int ngx_rtmp_flush_cache_packets(void* chromium_server) {
  quic::QuicNgxRtmpServer *server =
    reinterpret_cast<quic::QuicNgxRtmpServer*>(chromium_server);

  if (server->FlushWriteCache() == true) {
    return NGX_AGAIN;
  }

  return NGX_OK;
}

int ngx_rtmp_can_write(void* chromium_server) {
  quic::QuicNgxRtmpServer *server =
    reinterpret_cast<quic::QuicNgxRtmpServer*>(chromium_server);

  if (server->CanWrite() == true) {
    return NGX_AGAIN; 
  }

  return NGX_OK;
}

void ngx_rtmp_set_nc_for_quic_visitor(
                      void* quic_visitor,
                      void* ngx_connection) {
  quic::QuicNgxRtmpVisitor *visitor =
    reinterpret_cast<quic::QuicNgxRtmpVisitor*>(quic_visitor);
  visitor->SetNc(ngx_connection);
}



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
#include "quic_ngx_backend.h"
#include "quic_ngx_server.h"
#include "quic_ngx_stream.h"
#include "quic_ngx_interface.h"
#include "proof_source_nginx.h"


static bool ngx_try_key2pkcs8(const char* in_file, const char* out_file);

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
                    char **certificate_list,
                    char **certificate_key_list,
                    int bbr,
                    int ietf_draft,
                    int idle_network_timeout) {
  // base::AtExitManager exit_manager;
  std::vector<std::string> pkcs8_paths;
  
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

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  // settings.logging_dest = logging::LOG_TO_ALL;
  // settings.log_file = "/tmp/quic.log";
  // settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  CHECK(logging::InitLogging(settings));

  if (bbr) {
    SetQuicReloadableFlag(quic_default_to_bbr_v2, true);
  }

  quic::ParsedQuicVersionVector supported_versions;
  if (ietf_draft) {
    quic::QuicVersionInitializeSupportForIetfDraft();
    quic::ParsedQuicVersion version(quic::PROTOCOL_TLS1_3, quic::QUIC_VERSION_99);
    quic::QuicEnableVersion(version);
    supported_versions = {version};
  } else {
    supported_versions = quic::AllSupportedVersions();
  }
  
  quic::QuicNgxBackend* backend = new quic::QuicNgxBackend();
  backend->InitializeBackend("");
  backend->set_ngx_args(req_quic_2_ngx, set_stream_for_ngx);

  auto proof_source = std::make_unique<quic::ProofSourceNginx>();
  for (int i = 0; certificate_list[i] && certificate_key_list[i]; i++) {

    std::string keyfile = certificate_key_list[i];
    std::string outfile = base::StringPrintf(
                         "/tmp/.%d-%p-%lu.pkcs8",
                         getpid(), certificate_key_list[i], time(0));
    pkcs8_paths.push_back(outfile);
    bool had_key2pkcs8 = ngx_try_key2pkcs8(certificate_key_list[i],
                                           outfile.c_str());
    if (had_key2pkcs8) {
      keyfile = outfile;
    }
    
    proof_source->Initialize(base::FilePath(certificate_list[i]),
                             base::FilePath(keyfile), base::FilePath());    
  }

  quic::QuicConfig config;
  quic::QuicTagVector connection_options;
  connection_options.push_back(quic::k5RTO);
  // config.SetConnectionOptionsToSend(connection_options);
  config.SetInitialReceivedConnectionOptions(connection_options);
  
  quic::QuicNgxServer* server =
    new quic::QuicNgxServer(/*quic::CreateDefaultProofSource(),*/
                            std::move(proof_source),
                            config,
                            supported_versions,
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
  
  for (auto pkcs8_path : pkcs8_paths) {
    ::remove(pkcs8_path.c_str());
  }
  
  return server;
}

void ngx_free_quic(void* chromium_server) {
  quic::QuicNgxServer *server =
    reinterpret_cast<quic::QuicNgxServer*>(chromium_server);

  quic::QuicNgxBackend* back_end = server->server_backend();
  delete server;
  delete back_end;
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
  //  start = "HTTP/1"
  if (false == stream->get_send_header()) {
    if (len < 7 || memcmp(data, "HTTP/1.", 7) != 0 ) {
      return -1;
    }
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

static bool ngx_try_key2pkcs8(const char* in_file, const char* out_file) {

  BIO *in, *out, *key;
  EVP_PKEY *pkey;
  FILE *fp;
  PKCS8_PRIV_KEY_INFO *p8inf;
  bool rs = true;

  in = NULL;
  out = NULL;
  key = NULL;
  pkey = NULL;
  fp = NULL;
  p8inf = NULL;
  
  in = BIO_new_file(in_file, "r");
  if (in == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }
  
  fp = fopen(out_file, "wb");
  if (fp == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }
  
  out = BIO_new_fp(fp, BIO_CLOSE);
  if (out == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }

  key = BIO_new_file(in_file, "r");
  if (key == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }

  pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
  if (pkey == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }

  p8inf = EVP_PKEY2PKCS8(pkey);
  if (p8inf == NULL) {
    rs = false;
    goto key2pkcs8_end;
  }

  i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
  
 key2pkcs8_end:
  if (p8inf) {
    PKCS8_PRIV_KEY_INFO_free(p8inf);
  }

  if (pkey) {
    EVP_PKEY_free(pkey);
  }

  if (out) {
    BIO_free_all(out);
  } else if (fp) {
    fclose(fp);
  }

  if (in) {
    BIO_free(in);
  }

  if (key) {
    BIO_free(key);
  }

  return rs;
}


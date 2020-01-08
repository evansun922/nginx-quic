
/*
 * Copyright (C) sunlei
 */

#include "proof_source_nginx.h"

#include "base/strings/string_number_conversions.h"
#include "crypto/openssl_util.h"
#include "net/cert/x509_util.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "third_party/boringssl/src/include/openssl/digest.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/pem.h"

using std::string;
using namespace net;

namespace quic {

ProofSourceNginx::ProofItem::ProofItem() = default;
ProofSourceNginx::ProofItem::~ProofItem() = default;
  
ProofSourceNginx::ProofSourceNginx() {}

ProofSourceNginx::~ProofSourceNginx() {
  proof_item_hash_.clear();
  for (size_t i = 0; i < proof_items_.size(); i++) {
    delete proof_items_[i];
  }
  proof_items_.clear();
}

bool ProofSourceNginx::Initialize(const base::FilePath& cert_path,
                                     const base::FilePath& key_path,
                                     const base::FilePath& sct_path) {
  crypto::EnsureOpenSSLInit();

  std::string cert_data;
  if (!base::ReadFileToString(cert_path, &cert_data)) {
    DLOG(FATAL) << "Unable to read certificates.";
    return false;
  }

  CertificateList certs_in_file =
      X509Certificate::CreateCertificateListFromBytes(
          cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);

  if (certs_in_file.empty()) {
    DLOG(FATAL) << "No certificates.";
    return false;
  }

  ProofItem *proof_item = new ProofItem();
  proof_items_.emplace_back(proof_item);
  
  std::vector<string> certs;
  for (const scoped_refptr<X509Certificate>& cert : certs_in_file) {
    std::vector<std::string> dns_names;
    if (cert->GetSubjectAltName(&dns_names, nullptr)) {
      for (auto dns_name : dns_names) {
        proof_item_hash_[dns_name] = proof_item;
      }
    }
    certs.emplace_back(
        x509_util::CryptoBufferAsStringPiece(cert->cert_buffer()));
  }
  proof_item->chain = new quic::ProofSource::Chain(certs);

  std::string key_data;
  if (!base::ReadFileToString(key_path, &key_data)) {
    DLOG(FATAL) << "Unable to read key.";
    return false;
  }

  if (
      // memcmp(key_data.data(),
      //        "-----BEGIN RSA PRIVATE KEY-----",
      //        sizeof("-----BEGIN RSA PRIVATE KEY-----")-1) == 0 ||
      // memcmp(key_data.data(),
      //        "-----BEGIN EC PRIVATE KEY-----",
      //        sizeof("-----BEGIN EC PRIVATE KEY-----")-1) == 0 ||
      // memcmp(key_data.data(),
      //        "-----BEGIN PRIVATE KEY-----",
      //        sizeof("-----BEGIN PRIVATE KEY-----")-1) == 0
      memcmp(key_data.data(),
             "-----BEGIN ",
             sizeof("-----BEGIN ")-1) == 0
      ) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(
                                const_cast<char*>(key_data.data()),
                                static_cast<int>(key_data.size())));
    if (!bio) {
      LOG(ERROR) << "Could not allocate BIO for buffer?";
      return false;
    }

    bssl::UniquePtr<EVP_PKEY> pkey(
           PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if (!pkey) {
      LOG(ERROR) << "Could not decode private key file: " << key_path.value();
      return false;
    }

    proof_item->private_key = bssl::UpRef(pkey.get());
    
  } else {

    const uint8_t* p = reinterpret_cast<const uint8_t*>(key_data.data());
    std::vector<uint8_t> input(p, p + key_data.size());

    CBS cbs;
    CBS_init(&cbs, input.data(), input.size());
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
    if (!pkey || CBS_len(&cbs) != 0) {
      return false;
    }

    proof_item->private_key = std::move(pkey);
  }
  
  if (!proof_item->private_key.get()) {
    DLOG(FATAL) << "Unable to create private key.";
    return false;
  }

  // Loading of the signed certificate timestamp is optional.
  if (sct_path.empty()) {
    return true;
  }

  if (!base::ReadFileToString(sct_path, &proof_item->signed_certificate_timestamp)) {
    DLOG(FATAL) << "Unable to read signed certificate timestamp.";
    return false;
  }

  return true;
}

void ProofSourceNginx::GetProof(const quic::QuicSocketAddress& server_addr,
                                   const std::string& hostname,
                                   const std::string& server_config,
                                   quic::QuicTransportVersion quic_version,
                                   quiche::QuicheStringPiece chlo_hash,
                                   std::unique_ptr<Callback> callback) {
  // As a transitional implementation, just call the synchronous version of
  // GetProof, then invoke the callback with the results and destroy it.
  quic::QuicReferenceCountedPointer<quic::ProofSource::Chain> chain;
  string signature;
  string leaf_cert_sct;
  quic::QuicCryptoProof out_proof;

  const bool ok = GetProofInner(server_addr, hostname, server_config,
                                quic_version, chlo_hash, &chain, &out_proof);
  callback->Run(ok, chain, out_proof, nullptr /* details */);
}

quic::QuicReferenceCountedPointer<quic::ProofSource::Chain>
ProofSourceNginx::GetCertChain(const quic::QuicSocketAddress& server_address,
                                  const std::string& hostname) {
  ProofItem* proof_item = GetProofItem(hostname);
  if (proof_item == nullptr) {
    quic::QuicReferenceCountedPointer<quic::ProofSource::Chain> chain;
    return chain;
  }
  return proof_item->chain;
}

void ProofSourceNginx::ComputeTlsSignature(
    const quic::QuicSocketAddress& server_address,
    const std::string& hostname,
    uint16_t signature_algorithm,
    quiche::QuicheStringPiece in,
    std::unique_ptr<SignatureCallback> callback) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  bssl::ScopedEVP_MD_CTX sign_context;
  EVP_PKEY_CTX* pkey_ctx;

  ProofItem* proof_item = GetProofItem(hostname);
  if (proof_item == nullptr) {
    return;
  }

  size_t siglen;
  string sig;
  if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(), nullptr,
                          proof_item->private_key.get()) ||
      (EVP_PKEY_id(proof_item->private_key.get()) == EVP_PKEY_RSA &&
       (!EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1))) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(in.data()),
                            in.size()) ||
      !EVP_DigestSignFinal(sign_context.get(), nullptr, &siglen)) {
    callback->Run(false, sig);
    return;
  }
  sig.resize(siglen);
  if (!EVP_DigestSignFinal(
          sign_context.get(),
          reinterpret_cast<uint8_t*>(const_cast<char*>(sig.data())), &siglen)) {
    callback->Run(false, sig);
    return;
  }
  sig.resize(siglen);

  callback->Run(true, sig);
}

bool ProofSourceNginx::GetProofInner(
    const quic::QuicSocketAddress& server_addr,
    const string& hostname,
    const string& server_config,
    quic::QuicTransportVersion quic_version,
    quiche::QuicheStringPiece chlo_hash,
    quic::QuicReferenceCountedPointer<quic::ProofSource::Chain>* out_chain,
    quic::QuicCryptoProof* proof) {

  ProofItem* proof_item = GetProofItem(hostname);
  if (proof_item == nullptr) {
    return false;
  }
  
  DCHECK(proof != nullptr);
  DCHECK(proof_item->private_key.get()) << " this: " << this;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  bssl::ScopedEVP_MD_CTX sign_context;
  EVP_PKEY_CTX* pkey_ctx;

  uint32_t len_tmp = chlo_hash.length();
  if (!EVP_DigestSignInit(sign_context.get(), &pkey_ctx, EVP_sha256(), nullptr,
                          proof_item->private_key.get()) ||
      (EVP_PKEY_id(proof_item->private_key.get()) == EVP_PKEY_RSA &&
       (!EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1))) ||
      !EVP_DigestSignUpdate(
          sign_context.get(),
          reinterpret_cast<const uint8_t*>(quic::kProofSignatureLabel),
          sizeof(quic::kProofSignatureLabel)) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(&len_tmp),
                            sizeof(len_tmp)) ||
      !EVP_DigestSignUpdate(sign_context.get(),
                            reinterpret_cast<const uint8_t*>(chlo_hash.data()),
                            len_tmp) ||
      !EVP_DigestSignUpdate(
          sign_context.get(),
          reinterpret_cast<const uint8_t*>(server_config.data()),
          server_config.size())) {
    return false;
  }
  // Determine the maximum length of the signature.
  size_t len = 0;
  if (!EVP_DigestSignFinal(sign_context.get(), nullptr, &len)) {
    return false;
  }
  std::vector<uint8_t> signature(len);
  // Sign it.
  if (!EVP_DigestSignFinal(sign_context.get(), signature.data(), &len)) {
    return false;
  }
  signature.resize(len);
  proof->signature.assign(reinterpret_cast<const char*>(signature.data()),
                          signature.size());
  *out_chain = proof_item->chain;
  VLOG(1) << "signature: "
          << base::HexEncode(proof->signature.data(), proof->signature.size());
  proof->leaf_cert_scts = proof_item->signed_certificate_timestamp;
  return true;
}

ProofSourceNginx::ProofItem* ProofSourceNginx::GetProofItem
                                    (const std::string& hostname) {
  auto it = proof_item_hash_.find(hostname);
  if (it == proof_item_hash_.end()) {
    std::size_t pos = hostname.find(".");
    if (std::string::npos == pos) {
      return nullptr;
    }
    std::string hn = "*" + hostname.substr(pos);
    it = proof_item_hash_.find(hn);
    if (it == proof_item_hash_.end()) {
      return nullptr;
    }
  }

  return it->second;
}

}  // namespace net

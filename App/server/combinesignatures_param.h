#ifndef COMBINESIGNATURESPARAM_H
#define COMBINESIGNATURESPARAM_H

#include <string>
#include <vector>
#include <crypto-tss-rsa/RSASigShare.h>
#include <crypto-tss-rsa/RSAKeyMeta.h>
#include <crypto-tss-rsa/RSAPublicKey.h>
#include <crypto-bn/bn.h>

// JSON fields in HTTP request body
#define FIELD_NAME_DOC                   "doc"
#define FIELD_NAME_SIG_ARR               "sig_shares"
#define FIELD_NAME_KEY_META              "key_meta"
#define FIELD_NAME_RSA_PUBLIC_KEY        "rsa_public_key"

//#define FIELD_NAME_MSG_DIGEST            "msg_digest"

class CombineSignaturesParam {
public:
    CombineSignaturesParam(const std::string &req_body);

    bool check_sig_shares() const;

    bool check_key_meta() const;

    bool check_msg_digest() const;

    std::string request_id_;
    std::vector <safeheron::tss_rsa::RSASigShare> sig_shares_;
    safeheron::tss_rsa::RSAKeyMeta key_meta_;
    std::string msg_digest_;
};

#endif // COMBINESIGNATURESPARAM_H
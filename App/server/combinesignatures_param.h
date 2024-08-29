#ifndef COMBINESIGNATURESPARAM_H
#define COMBINESIGNATURESPARAM_H

#include <string>
#include <vector>
#include <crypto-tss-rsa/RSASigShare.h>
#include <crypto-tss-rsa/RSAKeyMeta.h>
#include <crypto-tss-rsa/RSAPublicKey.h>
#include <crypto-bn/bn.h>

class CombineSignaturesParam {
public:
    CombineSignaturesParam(const std::string &req_body);
    bool check_sig_shares() const;
    bool check_key_meta() const;
    bool check_msg_digest() const;

    std::string request_id_;
    std::vector<safeheron::tss_rsa::RSASigShare> sig_shares_;
    safeheron::tss_rsa::RSAKeyMeta key_meta_;
    std::string msg_digest_;
};

#endif // COMBINESIGNATURESPARAM_H
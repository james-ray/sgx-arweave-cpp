#include "CombineSignaturesParam.h"
#include <json/json.h>

CombineSignaturesParam::CombineSignaturesParam(const std::string &req_body) {
    // Parse req_body to initialize sig_shares_, key_meta_, and msg_digest_
    JSON::Root root = JSON::Root::parse(req_body);
    // Assuming the JSON structure is known and valid
    // Parse sig_shares_
    for (const auto &sig_share : root["sig_shares"]) {
        safeheron::tss_rsa::RSASigShare share;
        // Initialize share from JSON
        sig_shares_.push_back(share);
    }
    // Parse key_meta_
    // Initialize key_meta_ from JSON
    // Parse msg_digest_
    msg_digest_ = root["msg_digest"].asString();
}

bool CombineSignaturesParam::check_sig_shares() const {
    // Implement validation logic for sig_shares_
    return !sig_shares_.empty();
}

bool CombineSignaturesParam::check_key_meta() const {
    // Implement validation logic for key_meta_
    return true;
}

bool CombineSignaturesParam::check_msg_digest() const {
    // Implement validation logic for msg_digest_
    return !msg_digest_.empty();
}
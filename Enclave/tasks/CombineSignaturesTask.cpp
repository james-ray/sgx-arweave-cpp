#include "CombineSignaturesTask.h"
#include "TaskConstant.h"
#include "common/tee_util.h"
#include "common/tee_error.h"
#include "common/log_t.h"
#include "json/json.h"
#include <crypto-curve/curve.h>
#include <crypto-ecies/ecies.h>
#include <crypto-encode/base64.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <map>
#include <sstream>

#include "Enclave_t.h"

using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::ecies::ECIES;

extern std::mutex g_list_mutex;
extern std::map<std::string, KeyShardContext *> g_keyContext_list;

int CombineSignaturesTask::get_task_type() {
    return eTaskType_CombineSignatures;
}

int CombineSignaturesTask::execute(const std::string &request_id, const std::string &request, std::string &reply,
                                   std::string &error_msg) {
    int ret = 0;
    JSON::Root req_root;
    std::string doc;
    RSAPublicKey public_key;
    RSAKeyMeta key_meta;
    safeheron::bignum::BN out_sig;

    FUNC_BEGIN;
    if (request.length() == 0) {
        error_msg = format_msg("Request ID: %s, request is null!", request_id.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_INVALID_PARAMETER;
    }

    req_root = JSON::Root::parse(request);
    if (!req_root.is_valid()) {
        error_msg = format_msg("Request ID: %s, request body is not in JSON! request: %s",
                               request_id.c_str(), request.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_INVALID_PARAMETER;
    }
    doc = req_root["doc"].asString();
    INFO_OUTPUT_CONSOLE("--->DOC: %s\n", doc.c_str());

    // Parse sig_shares
    std::vector<RSASigShare> sig_shares;
    STR_ARRAY sig_shares_str_arr = req_root["sig_shares"].asStringArrary();
    for (const std::string &sig_share_str : sig_shares_str_arr) {
        INFO_OUTPUT_CONSOLE("--->try parsing sig_share_str: %s \n", sig_share_str.c_str());
        JSON::Root sig_share_json = JSON::Root::parse(sig_share_str);
        if (sig_share_json.is_valid()) {
            RSASigShare sig_share;
            sig_share.set_index(sig_share_json["index"].asInt());
            sig_share.set_sig_share(safeheron::bignum::BN(sig_share_json["sig_share"].asString().c_str(), 16));
            sig_share.set_z(safeheron::bignum::BN(sig_share_json["z"].asString().c_str(), 16));
            sig_share.set_c(safeheron::bignum::BN(sig_share_json["c"].asString().c_str(), 16));
            sig_shares.push_back(sig_share);
        }else{
            INFO_OUTPUT_CONSOLE("--->sig_share_json is invalid: %s \n", sig_share_str.c_str());
            error_msg = format_msg("Request ID: %s, sig_share_json is not valid! sig_share_str: %s",
                                   request_id.c_str(), sig_share_str.c_str());
            ERROR("%s", error_msg.c_str());
            return TEE_ERROR_INVALID_PARAMETER;
        }
    }
    INFO_OUTPUT_CONSOLE("--->after parse sig_shares: %zu\n", sig_shares.size());

    // Parse public_key
    JSON::Root public_key_json = req_root["public_key"].asJson();
    public_key.set_e(safeheron::bignum::BN(public_key_json["e"].asString().c_str(), 16));
    public_key.set_n(safeheron::bignum::BN(public_key_json["n"].asString().c_str(), 16));
    std::string public_key_n_str;
    public_key.n().ToHexStr(public_key_n_str);
    INFO_OUTPUT_CONSOLE("--->after parse public_key: n %s\n", public_key_n_str.c_str());

    // Parse key_meta
    JSON::Root key_meta_json = req_root["key_meta"].asJson();
    key_meta.set_k(key_meta_json["k"].asInt());
    key_meta.set_l(key_meta_json["l"].asInt());
    std::vector<safeheron::bignum::BN> vki_arr;
    STR_ARRAY vki_str_arr = key_meta_json["vkiArr"].asStringArrary();
    for (const std::string &vki_str : vki_str_arr) {
        vki_arr.push_back(safeheron::bignum::BN(vki_str.c_str(), 16));
    }
    key_meta.set_vki_arr(vki_arr);
    key_meta.set_vku(safeheron::bignum::BN(key_meta_json["vku"].asString().c_str(), 16));
    key_meta.set_vkv(safeheron::bignum::BN(key_meta_json["vkv"].asString().c_str(), 16));

    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: key_meta.vki_arr %ld\n", key_meta.vki_arr().size());
    std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(doc,1024,safeheron::tss_rsa::SaltLength::AutoLength);
    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: doc_pss %s\n", doc_pss.c_str());
    if (!safeheron::tss_rsa::CombineSignatures(doc_pss, sig_shares, public_key, key_meta, out_sig)) {
        error_msg = format_msg("Request ID: %s, CombineSignature failed!", request_id.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_COMBINE_SIGNATURE_FAILED;
    }

    return get_reply_string(request_id, out_sig, reply);
}

int CombineSignaturesTask::get_reply_string(const std::string &request_id, const safeheron::bignum::BN &out_sig,
                                            std::string &out_str) {
    JSON::Root reply_json;
    reply_json["success"] = true;
    std::string sig_str;
    out_sig.ToHexStr(sig_str);
    reply_json["signature"] = sig_str;
    out_str = JSON::Root::write(reply_json);
    return 0;
}
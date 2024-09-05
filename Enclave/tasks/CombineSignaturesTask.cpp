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
    std::vector<RSASigShare> sig_arr;
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

    // Parse sig_arr
    JSON::Root sig_shares_json = req_root["sig_shares"].asJson();
    for (int i = 0; i < 3; ++i) {
        JSON::Value item = sig_shares_json[i];
        if (item.is_valid()) {
            RSASigShare sig_share;
            sig_share.set_index(item["index"].asInt());
            sig_share.set_sig_share(safeheron::bignum::BN(item["sig_share"].asString().c_str(), 16));
            sig_share.set_z(safeheron::bignum::BN(item["z"].asString().c_str(), 16));
            sig_share.set_c(safeheron::bignum::BN(item["c"].asString().c_str(), 16));
            sig_arr.push_back(sig_share);
        }
    }
    INFO_OUTPUT_CONSOLE("--->after parse sig_shares: %ld\n", sig_arr.size());

    // Parse public_key
    JSON::Root public_key_json = req_root["public_key"].asJson();
    public_key.set_e(safeheron::bignum::BN(public_key_json["e"].asString().c_str(), 16));
    public_key.set_n(safeheron::bignum::BN(public_key_json["n"].asString().c_str(), 16));
    INFO_OUTPUT_CONSOLE("--->after parse public_key: n %s\n", public_key.n().ToHexStr().c_str());

    // Parse key_meta
    JSON::Root key_meta_json = req_root["key_meta"].asJson();
    key_meta.set_k(key_meta_json["k"].asInt());
    key_meta.set_l(key_meta_json["l"].asInt());
    std::vector<safeheron::bignum::BN> vki_arr;
    for (int i = 0; i < 3; ++i) {
        JSON::Value item = key_meta_json["vkiArr"][i];
        if (item.is_valid()) {
            vki_arr.push_back(safeheron::bignum::BN(item.asString().c_str(), 16));
        }
    }
    key_meta.set_vki_arr(vki_arr);
    key_meta.set_vku(safeheron::bignum::BN(key_meta_json["vku"].asString().c_str(), 16));
    key_meta.set_vkv(safeheron::bignum::BN(key_meta_json["vkv"].asString().c_str(), 16));

    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: key_meta.vki_arr %ld\n", key_meta.vki_arr().size());

    if (!safeheron::tss_rsa::CombineSignatures(doc, sig_arr, public_key, key_meta, out_sig)) {
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
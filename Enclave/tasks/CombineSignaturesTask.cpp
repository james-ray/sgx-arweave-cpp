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
#include <sstream> // Include for std::istringstream

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

    // Parse sig_arr, public_key, and key_meta from JSON manually
    JSON::Root sig_shares_json = req_root["sig_shares"].asJson();
    for (int i = 0; i < cJSON_GetArraySize((cJSON*)sig_shares_json.m_read_root); ++i) {
        cJSON* item = cJSON_GetArrayItem((cJSON*)sig_shares_json.m_read_root, i);
        if (item && item->type == cJSON_Object) {
            cJSON* sig_share_item = cJSON_GetObjectItem(item, "sig_share");
            if (sig_share_item && sig_share_item->type == cJSON_String) {
                RSASigShare sig_share;
                std::string sig_share_str = sig_share_item->valuestring;

                // Parse the sig_share string into a JSON object
                JSON::Root sig_share_json = JSON::Root::parse(sig_share_str);
                if (sig_share_json.is_valid()) {
                    sig_share.index = sig_share_json["index"].asInt();
                    sig_share.sig_share = safeheron::bignum::BN(sig_share_json["sig_share"].asString());
                    sig_share.z = safeheron::bignum::BN(sig_share_json["z"].asString());
                    sig_share.c = safeheron::bignum::BN(sig_share_json["c"].asString());
                    sig_arr.push_back(sig_share);
                } else {
                    error_msg = format_msg("Request ID: %s, failed to parse sig_share JSON: %s", request_id.c_str(), sig_share_str.c_str());
                    ERROR("%s", error_msg.c_str());
                    return TEE_ERROR_INVALID_PARAMETER;
                }
            }
        }
    }
    INFO_OUTPUT_CONSOLE("--->after parse sig_shares: %d\n", sig_arr.size());

    // Parse public_key
    JSON::Root public_key_json = req_root["public_key"].asJson();
    public_key.e = safeheron::bignum::BN(public_key_json["e"]);
    public_key.n = safeheron::bignum::BN(public_key_json["n"]);
    INFO_OUTPUT_CONSOLE("--->after parse public_key: n %ld\n", public_key.n);

    // Parse key_meta
    JSON::Root key_meta_json = req_root["key_meta"].asJson();
    key_meta.k = key_meta_json["k"].asInt();
    key_meta.l = key_meta_json["l"].asInt();
    for (int i = 0; i < cJSON_GetArraySize((cJSON*)key_meta_json["vkiArr"].m_read_root); ++i) {
        cJSON* item = cJSON_GetArrayItem((cJSON*)key_meta_json["vkiArr"].m_read_root, i);
        if (item && item->type == cJSON_String) {
            key_meta.vkiArr.push_back(item->valuestring);
        }
    }
    key_meta.vku = key_meta_json["vku"].asString();
    key_meta.vkv = key_meta_json["vkv"].asString();

    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: key_meta.vkiArr %d\n", key_meta.vkiArr.size());

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
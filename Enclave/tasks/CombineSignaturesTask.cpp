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
extern std::map<std::string, KeyShardContext*> g_keyContext_list;

int CombineSignaturesTask::get_task_type() {
    return eTaskType_CombineSignatures;
}

int CombineSignaturesTask::execute(const std::string &request_id, const std::string &request, std::string &reply, std::string &error_msg) {
    int ret = 0;
    JSON::Root req_root;
    std::string doc;
    std::vector<RSASigShare> sig_arr;
    RSAPublicKey public_key;
    RSAKeyMeta key_meta;
    safeheron::bignum::BN out_sig;

    FUNC_BEGIN;
    INFO_OUTPUT_CONSOLE("--->FUNC_BEGIN: \n");
    if (request.length() == 0) {
        error_msg = format_msg( "Request ID: %s, request is null!", request_id.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_INVALID_PARAMETER;
    }

    // Parse request parameters from request body data
    req_root = JSON::Root::parse(request);
    INFO_OUTPUT_CONSOLE("--->req_root: %s\n", req_root.serialize();
    if (!req_root.is_valid()) {
        error_msg = format_msg( "Request ID: %s, request body is not in JSON! request: %s",
                                request_id.c_str(), request.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_INVALID_PARAMETER;
    }
    doc = req_root["doc"].asString();
    INFO_OUTPUT_CONSOLE("--->DOC: %s\n", doc.c_str());
    // Parse sig_arr, public_key, and key_meta from JSON manually
    for (const auto& sig : req_root["sig_shares"].asStringArrary()) {
        RSASigShare sig_share;
        sig_share.FromJsonString(sig);
        sig_arr.push_back(sig_share);
    }
    public_key.FromJsonString(req_root["public_key"].asString());
    key_meta.FromJsonString(req_root["key_meta"].asString());

    // Call the Safeheron API to combine signatures
    if (!safeheron::tss_rsa::CombineSignatures(doc, sig_arr, public_key, key_meta, out_sig)) {
        error_msg = format_msg( "Request ID: %s, CombineSignature failed!", request_id.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_COMBINE_SIGNATURE_FAILED;
    }

    // Construct reply JSON
    return get_reply_string(request_id, out_sig, reply);
}

int CombineSignaturesTask::get_reply_string(const std::string &request_id, const safeheron::bignum::BN &out_sig, std::string &out_str) {
    JSON::Root reply_json;
    reply_json["success"] = true;
    std::string sig_str;
    out_sig.ToHexStr(sig_str);
    reply_json["signature"] = sig_str;
    out_str = JSON::Root::write(reply_json);
    return 0;
}
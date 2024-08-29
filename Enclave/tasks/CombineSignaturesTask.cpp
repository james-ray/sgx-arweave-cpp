// CombineSignatures.cpp
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

#include "Enclave_t.h"

using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::ecies::ECIES;

extern std::mutex g_list_mutex;
extern std::map<std::string, KeyShardContext*> g_keyContext_list;

int CombineSignaturesTask::get_task_type()
{
    return eTaskType_CombineSignatures;
}

int CombineSignaturesTask::execute(
        const std::string & request_id,
        const std::string & request,
        std::string & reply,
        std::string & error_msg )
{
    int ret = 0;
    JSON::Root req_root;
    std::string doc;
    std::vector<RSASigShare> sig_arr;
    RSAPublicKey public_key;
    RSAKeyMeta key_meta;
    safeheron::bignum::BN out_sig;

    FUNC_BEGIN;

    if (request.length() == 0) {
        error_msg = format_msg( "Request ID: %s, request is null!", request_id.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_INVALID_PARAMETER;
    }

    // Parse request parameters from request body data
    req_root = JSON::Root::parse( request );
    if ( !req_root.is_valid() ) {
        error_msg = format_msg( "Request ID: %s, request body is not in JSON! request: %s",
                                request_id.c_str(), request.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_INVALID_PARAMETER;
    }
    doc = req_root["doc"].asString();
    sig_arr = req_root["sig_arr"].asRSASigShareArray();
    public_key = req_root["public_key"].asRSAPublicKey();
    key_meta = req_root["key_meta"].asRSAKeyMeta();

    // Call the Safeheron API to combine signatures
    if ( !safeheron::tss_rsa::CombineSignature(doc, sig_arr, public_key, key_meta, out_sig) ) {
        error_msg = format_msg( "Request ID: %s, CombineSignature failed!", request_id.c_str() );
        ERROR( "%s", error_msg.c_str() );
        return TEE_ERROR_COMBINE_SIGNATURE_FAILED;
    }

    // Construct reply JSON string
    JSON::Root root;
    root["success"] = true;
    root["signature"] = out_sig.ToHexStr();
    reply = JSON::Root::write( root );

    FUNC_END;

    return ret;
}
#include "msg_handler.h"
#include "listen_svr.h"
#include "Enclave_u.h"
#include "keyshard_param.h"
#include "combinesignatures_param.h"
#include "../common/define.h"
#include "../common/log_u.h"
#include "../common/tee_error.h"
#include <cpprest/http_client.h>
#include <safeheron/crypto-encode/base64.h>
#include <sgx_urts.h>
#include <sgx_report.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_pce.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#include <list>
#include "../App.h"

using namespace web;
using namespace http;
using namespace utility;

#define SGX_AESM_ADDR "SGX_AESM_ADDR"
#if defined(_MSC_VER)
#define ENCLAVE_PATH _T("enclave.signed.dll")
#else
#define ENCLAVE_PATH "enclave.signed.so"
#endif

// Defined in App.cpp
extern sgx_enclave_id_t global_eid;
extern std::string g_key_shard_generation_path;
extern std::string g_key_shard_query_path;
extern std::string g_combine_sigs_path;
extern std::string g_root_seed_query_path;
extern std::string g_request_ids;
extern std::string g_private_key;
extern std::string g_public_key;
extern std::string g_sign_node_public_keys;
extern int g_max_thread_task_count;

// Thread pool and mutex
std::list<ThreadTask *> msg_handler::s_thread_pool;
std::mutex msg_handler::s_thread_lock;
std::string g_plain_seeds;

/**
 * @brief : Call ECALL to enter the enclave. The key shards will be generated in TEE.
 *          This function is called by generation request task thread
 *          as it will take some time to calculate.
 *
 * @param[in] keyshard_param : The context of GenerateKeyShard_Task.
 * @return int: return 0 if success, otherwise return an error code.
 */
static int GenerateKeyShard_Task(void *keyshard_param) {
    int ret;
    size_t result_len = 0;
    char *result = nullptr;
    sgx_status_t sgx_status;
    std::string request_id;
    std::string pubkey_list_hash;
    std::string param_string;
    std::string enclave_report;
    std::string reply_body;
    KeyShardParam *param = (KeyShardParam *) keyshard_param;
    web::json::value result_json;

    FUNC_BEGIN;

    if (!param) {
        ERROR("keyshard_param is null in GenerateKeyShard()!");
        reply_body = msg_handler::GetMessageReply(false, APP_ERROR_INVALID_PARAMETER,
                                                  "keyshard_param is null in GenerateKeyShard()!");
        ret = APP_ERROR_INVALID_PARAMETER;
        goto _exit;
    }
    param_string = param->to_json_string();
    request_id = param->request_id_;

    // Call ECALL to generate keys shards in TEE
    if ((sgx_status = ecall_run(global_eid, &ret, eTaskType_Generate, request_id.c_str(),
                                param_string.c_str(), param_string.length(), &result, &result_len)) != SGX_SUCCESS) {
        ERROR("Request ID: %s,  ecall_run() raised an error! sgx_status: %d, error message: %s",
              request_id.c_str(), sgx_status, t_strerror((int) sgx_status));
        reply_body = msg_handler::GetMessageReply(false, sgx_status, "ECALL raised an error!");
        ret = sgx_status;
        goto _exit;
    }
    if (0 != ret) {
        ERROR("Request ID: %s,  ecall_run() failed with eTaskType_Generate! ret: 0x%x, error message: %s",
              request_id.c_str(), ret, result ? result : "");
        ERROR("Request ID: %s,  param_string: %s", request_id.c_str(), param_string.c_str());
        reply_body = msg_handler::GetMessageReply(false, ret, result ? result : "");
        goto _exit;
    }
    INFO_OUTPUT_CONSOLE("Request ID: %s, generate key shards successfully. result: %s", request_id.c_str(), result);

    // Get public key list hash in result
    result_json = json::value::parse(result);
    pubkey_list_hash = result_json.at(FIELD_NAME_PUBKEY_LIST_HASH).as_string();
    if (pubkey_list_hash.empty()) {
        ERROR("Request ID: %s, pubkey_list_hash is empty!", request_id.c_str());
        reply_body = msg_handler::GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "pubkey_list_hash is empty.");
        ret = APP_ERROR_INVALID_PARAMETER;
        goto _exit;
    }

    if (g_private_key.empty()) {
		if (result_json.has_field("server_private_key")) {
        	g_private_key = result_json.at("server_private_key").as_string();
        	result_json.erase("server_private_key");
        	// Check if g_private_key is an empty string
        	if (g_private_key.empty()) {
            	ERROR("Request ID: %s, g_private_key is empty!", request_id.c_str());
            	reply_body = msg_handler::GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "g_private_key is empty.");
            	ret = APP_ERROR_INVALID_PARAMETER;
            	goto _exit;
        	}
    	}else{
        	ERROR("Request ID: %s, g_private_key not generated!", request_id.c_str());
        	reply_body = msg_handler::GetMessageReply(false, sgx_status, "ECALL raised an error!");
        	ret = sgx_status;
        	goto _exit;
    	}
    	if (result_json.has_field("server_public_key")) {
        	g_public_key = result_json.at("server_public_key").as_string();
        	// Check if g_public_key is an empty string
        	if (g_public_key.empty()) {
            	ERROR("Request ID: %s, g_public_key is empty!", request_id.c_str());
            	reply_body = msg_handler::GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "g_public_key is empty.");
            	ret = APP_ERROR_INVALID_PARAMETER;
            	goto _exit;
        	}
    	}else{
        	ERROR("Request ID: %s, server_public_key not generated!", request_id.c_str());
        	reply_body = msg_handler::GetMessageReply(false, sgx_status, "ECALL raised an error!");
        	ret = sgx_status;
        	goto _exit;
    	}
    }else{
      	result_json["server_public_key"] = json::value(g_public_key);
    }

    // Generate enclave quote
    if ((ret = msg_handler::GenerateEnclaveReport(request_id, pubkey_list_hash, enclave_report)) != 0) {
        ERROR("Request ID: %s,  msg_handler::GenerateEnclaveReport() failed! pubkey_list_hash: %s, ret: %d",
              request_id.c_str(), pubkey_list_hash.c_str(), ret);
        reply_body = msg_handler::GetMessageReply(false, ret, "Failed to create enclave report!");
        goto _exit;
    }
    INFO_OUTPUT_CONSOLE("Request ID: %s, generate remote attestation report successfully.", request_id.c_str());

    // Add remote attestation report to JSON object
    result_json["tee_report"] = json::value(enclave_report);

    // Serialize JSON object to a string
    reply_body = result_json.serialize();

    INFO_OUTPUT_CONSOLE("Request ID: %s, second time packing data successfully.", request_id.c_str());

    // OK
    ret = 0;
    try {
        listen_svr::PostRequest(request_id, param->webhook_url_, reply_body).wait();
        ecall_set_generation_status(global_eid, &ret, request_id.c_str(), pubkey_list_hash.c_str(),
                                    eKeyStatus_Finished);
        INFO_OUTPUT_CONSOLE("Request ID: %s, key shard generation result has post to callback address successfully.",
                            request_id.c_str());
    } catch (const std::exception &e) {
        ecall_set_generation_status(global_eid, &ret, request_id.c_str(), pubkey_list_hash.c_str(), eKeyStatus_Error);
        ERROR("Request ID: %s Error exception: %s", request_id.c_str(), e.what());
    }

    FUNC_END;
	_exit:
    if (result) {
        free(result);
        result = nullptr;
    }
    if (param) {
        delete param;
        param = nullptr;
    }
    return ret;
}

msg_handler::msg_handler() {

}

msg_handler::~msg_handler() {

}

int msg_handler::process(
        const std::string &req_id,
        const std::string &req_path,
        const std::string &req_body,
        std::string &resp_body) {
    int ret = 0;

    FUNC_BEGIN;

    if (req_path == g_key_shard_generation_path) {
        ret = GenerateKeyShard(req_id, req_body, resp_body);
    } else if (req_path == g_key_shard_query_path) {
        ret = QueryKeyShardState(req_id, req_body, resp_body);
    } else if (req_path == g_combine_sigs_path) {
        ret = CombineSignatures(req_id, req_body, resp_body);
    } else if (req_path == g_root_seed_query_path) {
        ret = QueryRootKey(req_id, req_body, resp_body);
    } else {
        ERROR("Request path is unknown! req_path: %s", req_path.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_REQ_PATH, "Request path is unknown!");
        ret = APP_ERROR_INVALID_REQ_PATH;
    }

    FUNC_END;

    return ret;
}

// Construct a reply JSON string with nodes "success" and "message".
std::string msg_handler::GetMessageReply(
        bool success,
        int code,
        const char *format, ...) {
    char message[4096] = {0};
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message) - 1, format, args);
    va_end(args);

    json::value root = json::value::object(true);
    root["success"] = json::value(success);
    root["code"] = json::value(code);
    root["message"] = json::value(message);
    return root.serialize();
}

// Generate the report for current enclave
int msg_handler::GenerateEnclaveReport(
        const std::string &request_id,
        const std::string &pubkey_list_hash,
        std::string &report) {
    int ret = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    uint32_t quote_size = 0;
    uint8_t *p_quote_buffer = nullptr;
    sgx_target_info_t qe_target_info;
    sgx_report_t app_report;
    sgx_quote3_t *p_quote = nullptr;
    sgx_ql_auth_data_t *p_auth_data = nullptr;
    sgx_ql_ecdsa_sig_data_t *p_sig_data = nullptr;
    sgx_ql_certification_data_t *p_cert_data = nullptr;
    FILE *fptr = nullptr;
    bool is_out_of_proc = false;
    char *out_of_proc = getenv(SGX_AESM_ADDR);

    FUNC_BEGIN;

    if (request_id.length() == 0) {
        ERROR("Request ID is null!");
        return -1;
    }
    if (pubkey_list_hash.length() == 0) {
        ERROR("Request ID: %s, pubkey_list_hash is null!", request_id.c_str());
        return -1;
    }
    INFO("Request ID: %s, pubkey_list_hash: %s", request_id.c_str(), pubkey_list_hash.c_str());

    if (out_of_proc) {
        is_out_of_proc = true;
    }

#if !defined(_MSC_VER)
    // There 2 modes on Linux: one is in-proc mode, the QE3 and PCE are loaded within the user's process.
    // the other is out-of-proc mode, the QE3 and PCE are managed by a daemon. If you want to use in-proc
    // mode which is the default mode, you only need to install libsgx-dcap-ql. If you want to use the
    // out-of-proc mode, you need to install libsgx-quote-ex as well. This sample is built to demo both 2
    // modes, so you need to install libsgx-quote-ex to enable the out-of-proc mode.
    if (!is_out_of_proc) {
        // Following functions are valid in Linux in-proc mode only.
        qe3_ret = sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT);
        if (SGX_QL_SUCCESS != qe3_ret) {
            ERROR("Request ID: %s, Error in set enclave load policy: 0x%04x", request_id.c_str(), qe3_ret);
            ret = -1;
            goto _exit;
        }

        // Try to load PCE and QE3 from Ubuntu-like OS system path
        if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1") ||
            SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1") ||
            SGX_QL_SUCCESS !=
            sgx_ql_set_path(SGX_QL_IDE_PATH, "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1")) {

            // Try to load PCE and QE3 from RHEL-like OS system path
            if (SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_PCE_PATH, "/usr/lib64/libsgx_pce.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_QE3_PATH, "/usr/lib64/libsgx_qe3.signed.so.1") ||
                SGX_QL_SUCCESS != sgx_ql_set_path(SGX_QL_IDE_PATH, "/usr/lib64/libsgx_id_enclave.signed.so.1")) {
                ERROR("Request ID: %s, Error in set PCE/QE3/IDE directory.", request_id.c_str());
                ret = -1;
                goto _exit;
            }
        }

        qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1");
        if (SGX_QL_SUCCESS != qe3_ret) {
            qe3_ret = sgx_ql_set_path(SGX_QL_QPL_PATH, "/usr/lib64/libdcap_quoteprov.so.1");
            if (SGX_QL_SUCCESS != qe3_ret) {
                // Ignore the error, because user may want to get cert type=3 quote
                WARN("Request ID: %s, Warning: Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.",
                     request_id.c_str());
            }
        }
    }
#endif

    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        ERROR("Request ID: %s, Error in sgx_qe_get_target_info. 0x%04x", request_id.c_str(), qe3_ret);
        ret = -1;
        goto _exit;
    }

    sgx_status = ecall_create_report(global_eid, &ret, (char *) request_id.c_str(),
                                     (char *) pubkey_list_hash.c_str(), &qe_target_info, &app_report);
    if ((SGX_SUCCESS != sgx_status) || (0 != ret)) {
        ERROR("Request ID: %s, Call to get_app_enclave_report() failed", request_id.c_str());
        ret = -1;
        goto _exit;
    }

    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        ERROR("Request ID: %s, Error in sgx_qe_get_quote_size. 0x%04x", request_id.c_str(), qe3_ret);
        ret = -1;
        goto _exit;
    }

    p_quote_buffer = (uint8_t *) malloc(quote_size);
    if (nullptr == p_quote_buffer) {
        ERROR("Request ID: %s, Couldn't allocate quote_buffer", request_id.c_str());
        ret = -1;
        goto _exit;
    }
    memset(p_quote_buffer, 0, quote_size);

    // Get the Quote
    qe3_ret = sgx_qe_get_quote(&app_report,
                               quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        ERROR("Request ID: %s, Error in sgx_qe_get_quote. 0x%04x", request_id.c_str(), qe3_ret);
        ret = -1;
        goto _exit;
    }

    p_quote = (sgx_quote3_t *) p_quote_buffer;
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *) p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t *) p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t * )((uint8_t *) p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

#if defined(DEBUG_ARWEAVE)
#if _WIN32
    fopen_s(&fptr, "quote.dat", "wb");
#else
    fptr = fopen("quote.dat","wb");
#endif
    if( fptr )
    {
        fwrite(p_quote, quote_size, 1, fptr);
        fclose(fptr);
    }
#endif

    report = safeheron::encode::base64::EncodeToBase64(p_quote_buffer, quote_size);

    if (!is_out_of_proc) {
        qe3_ret = sgx_qe_cleanup_by_policy();
        if (SGX_QL_SUCCESS != qe3_ret) {
            ERROR("Request ID: %s, Error in cleanup enclave load policy: 0x%04x", request_id.c_str(), qe3_ret);
            ret = -1;
            goto _exit;
        }
    }

    // OK
    ret = 0;
    FUNC_END;

    _exit:
    if (!p_quote_buffer) {
        free(p_quote_buffer);
        p_quote_buffer = nullptr;
    }
    return ret;
}

// Free all threads which are stopped in s_thread_pool
void msg_handler::ReleaseStoppedThreads() {
    std::lock_guard <std::mutex> lock(s_thread_lock);

    // Free all stopped task threads in pool
    for (auto it = s_thread_pool.begin(); it != s_thread_pool.end();) {
        if ((*it)->is_stopped()) {
            delete *it;
            it = s_thread_pool.erase(it);
        } else {
            it++;
        }
    }
}

// Free all thread objects in s_thread_pool
void msg_handler::DestroyThreadPool() {
    std::lock_guard <std::mutex> lock(s_thread_lock);
    for (auto it = s_thread_pool.begin();
         it != s_thread_pool.end();
            ) {
        delete *it;
        it = s_thread_pool.erase(it);
    }
}

// Generating key shard message handler
int msg_handler::GenerateKeyShard(
        const std::string &req_id,
        const std::string &req_body,
        std::string &resp_body) {
    int ret = 0;
    KeyShardParam *req_param = nullptr;

    FUNC_BEGIN;

    // Return if thread pool has no thread resource
    std::lock_guard <std::mutex> lock(s_thread_lock);
    if (s_thread_pool.size() >= g_max_thread_task_count) {
        resp_body = GetMessageReply(false, APP_ERROR_SERVER_IS_BUSY, "TEE service is busy!");
        return APP_ERROR_SERVER_IS_BUSY;
    }
    s_thread_lock.unlock();

    // All parameters must be valid!
    if (!(req_param = new KeyShardParam(req_body))) {
        ERROR("Request ID: %s, new KeyShardParam object failed!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_MALLOC_FAILED, "new KeyShardParam object failed!");
        return APP_ERROR_MALLOC_FAILED;
    }
    if (!req_param->check_pubkey_list()) {
        ERROR("Request ID: %s, User pubkey list is invalid! size: %d", req_id.c_str(),
              (int) req_param->pubkey_list_.size());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PUBLIC_KEY_LIST, "Field '%s' value is invalid!",
                                    FIELD_NAME_USER_PUBLICKEY_LIST);
        return APP_ERROR_INVALID_PUBLIC_KEY_LIST;
    }
    if (!req_param->check_k()) {
        ERROR("Request ID: %s, Parameter k is invalid! k: %d", req_id.c_str(), req_param->k_);
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_K, "Field '%s' value is invalid!", FIELD_NAME_NUMERATOR_K);
        return APP_ERROR_INVALID_K;
    }
    if (!req_param->check_l()) {
        ERROR("Request ID: %s, Parameter l is invalid! l: %d", req_id.c_str(), req_param->l_);
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_L, "Field '%s' value is invalid!",
                                    FIELD_NAME_DENOMINATOR_L);
        return APP_ERROR_INVALID_L;
    }
    if (!req_param->check_key_length()) {
        ERROR("Request ID: %s, Parameter key length is invalid! key_length: %d", req_id.c_str(),
              req_param->key_length_);
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_KEYBITS, "Field '%s' value is invalid!",
                                    FIELD_NAME_KEY_LENGTH);
        return APP_ERROR_INVALID_KEYBITS;
    }
    if (!req_param->check_webhook_url()) {
        ERROR("Request ID: %s, Parameter webhook url is invalid! webhook url: %s", req_id.c_str(),
              req_param->webhook_url_.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_WEBHOOK_URL, "Field '%s' value is invalid!",
                                    FIELD_NAME_WEBHOOK_URL);
        return APP_ERROR_INVALID_WEBHOOK_URL;
    }
    req_param->request_id_ = req_id;

    // Create a thread for generation task
    ThreadTask *task = new ThreadTask(GenerateKeyShard_Task, req_param);
    if ((ret = task->start()) != 0) {
        resp_body = GetMessageReply(false, APP_ERROR_FAILED_TO_START_THREAD, "Create task thread failed!");
        return APP_ERROR_FAILED_TO_START_THREAD;
    }
    s_thread_lock.lock();
    s_thread_pool.push_back(task);
    s_thread_lock.unlock();

    // return OK
    resp_body = GetMessageReply(true, 0, "Request has been accepted.");

    FUNC_END;

    return ret;
}

int msg_handler::QueryKeyShardState(
        const std::string &req_id,
        const std::string &req_body,
        std::string &resp_body) {
    int ret = 0;
    size_t result_len = 0;
    char *result = nullptr;
    sgx_status_t sgx_status;
    std::string pubkey_list_hash;
    web::json::value req_json = json::value::parse(req_body);

    FUNC_BEGIN;

    // return error message if request body is invalid
    if (!req_json.has_field(FIELD_NAME_PUBKEY_LIST_HASH) ||
        !req_json.at(FIELD_NAME_PUBKEY_LIST_HASH).is_string()) {
        ERROR("Request ID: %s, %s node is not in request body or has a wrong type!",
              req_id.c_str(), FIELD_NAME_PUBKEY_LIST_HASH);
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "invalid input, please check your data.");
        ret = -1;
        goto _exit;
    }
    pubkey_list_hash = req_json.at(FIELD_NAME_PUBKEY_LIST_HASH).as_string();

    // call ECALL to query keys status in TEE
    if ((sgx_status = ecall_run(global_eid, &ret, eTaskType_Query, req_id.c_str(),
                                pubkey_list_hash.c_str(), pubkey_list_hash.length(), &result, &result_len)) !=
        SGX_SUCCESS) {
        ERROR("Request ID: %s,  ecall_run() encounter an error! sgx_status: %d, error message: %s",
              req_id.c_str(), sgx_status, t_strerror((int) sgx_status));
        resp_body = GetMessageReply(false, sgx_status, "ECALL encounter an error!");
        ret = -1;
        goto _exit;
    }
    if (0 != ret) {
        ERROR("Request ID: %s,  ecall_run() failed with eTaskType_Query! pubkey_list_hash: %s, ret: 0x%x, error message: %s",
              req_id.c_str(), pubkey_list_hash.c_str(), ret, result ? result : "");
        resp_body = GetMessageReply(false, ret, result ? result : "");
        ret = -1;
        goto _exit;
    }

    // OK
    resp_body = result;
    ret = 0;

    FUNC_END;

    _exit:
    if (result) {
        free(result);
        result = nullptr;
    }
    return ret;
}

std::string get_public_key_for_index(size_t index) {
    // Split g_sign_node_public_keys by comma
    std::istringstream public_keys_stream(g_sign_node_public_keys);
    std::string pubkey;
    std::vector<std::string> public_keys;
    while (std::getline(public_keys_stream, pubkey, ',')) {
        public_keys.push_back(pubkey);
    }

    // Fetch the public key at the given index
    if (index >= public_keys.size()) {
        throw std::runtime_error("Index out of bounds in g_sign_node_public_keys");
    }
    return public_keys[index];
}

std::string get_plain_text_for_index(size_t index) {
    // Split g_plain_seeds by comma
    std::istringstream plain_seeds_stream(g_plain_seeds);
    std::string plain_text;
    std::vector<std::string> plain_seeds;
    while (std::getline(plain_seeds_stream, plain_text, ',')) {
        plain_seeds.push_back(plain_text);
    }

    // Fetch the plain text at the given index
    if (index >= plain_seeds.size()) {
        throw std::runtime_error("Index out of bounds in g_plain_seeds");
    }
    return plain_seeds[index];
}

bool is_timestamp_within_half_hour(const std::string &timestamp_str) {
    // Get the current time in Unix timestamp format
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);

    // Convert the timestamp string to a long integer
    long timestamp = std::stol(timestamp_str);

    // Calculate the difference in seconds
    long time_difference = now_time_t - timestamp;

    // Check if the difference is within 10 minutes (600 seconds)
    return std::abs(time_difference) <= 600;
}

int msg_handler::QueryRootKey(
        const std::string &req_id,
        const std::string &req_body,
        std::string &resp_body) {
    int ret = 0;
    size_t result_len = 0;
    char *result = nullptr;
    sgx_status_t sgx_status;
    std::string request_id;
    std::string msg_digest;
    std::string timestamp;
    std::string remote_public_key_hex;
    std::string plain_text;
    std::string param_string;
    web::json::value req_json;
    web::json::value response_json;
    std::istringstream request_ids_stream(g_request_ids);
    std::string id;
    std::vector<std::string> request_ids;
    auto it = request_ids.end();
    size_t index = 0;
    web::json::value encryption_request_json;

    FUNC_BEGIN;

    try {
        req_json = web::json::value::parse(req_body);
        // Print the req_json as a pretty-printed JSON structure
		INFO_OUTPUT_CONSOLE("Request ID: %s, req_json (pretty): %s", req_id.c_str(), req_json.serialize().c_str());
    } catch (const std::exception &e) {
        ERROR("Request ID: %s, invalid input data!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "invalid input, please check your data.");
        ret = -1;
        goto _exit2;
    }

// Validate request body
    if (!req_json.has_field(FIELD_NAME_REQUEST_ID) || !req_json.at(FIELD_NAME_REQUEST_ID).is_string() ||
        !req_json.has_field("signature") || !req_json.at("signature").is_string() ||
        !req_json.has_field("timestamp") || !req_json.at("timestamp").is_string() ||
        !req_json.has_field("msg_digest") || !req_json.at("msg_digest").is_string()) {
        ERROR("Request ID: %s, invalid input data!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "invalid input, please check your data.");
        ret = -1;
        goto _exit2;
    }

    request_id = req_json.at(FIELD_NAME_REQUEST_ID).as_string();
    timestamp = req_json.at("timestamp").as_string();
    msg_digest = req_json.at("msg_digest").as_string();

    if (g_plain_seeds.empty()){
        ERROR("Request ID: %s, g_plain_seeds is empty!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "g_plain_seeds is empty.");
        ret = -1;
        goto _exit2;
    }

    if (!is_timestamp_within_half_hour(timestamp)) {
        ERROR("Request ID: %s, timestamp is not within 10 mins !", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "timestamp is not within 10 mins.");
        ret = -1;
        goto _exit2;
    }

// Check if g_request_ids is empty or if request_id is not found in g_request_ids
    if (g_request_ids.empty() || g_request_ids.find(request_id) == std::string::npos) {
        ERROR("Request ID: %s, request_id not found in g_request_ids!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "request_id not found.");
        ret = -1;
        goto _exit2;
    }

// Find the index of request_id
    while (std::getline(request_ids_stream, id, ',')) {
        request_ids.push_back(id);
    }

    it = std::find(request_ids.begin(), request_ids.end(), request_id);
    if (it == request_ids.end()) {
        ERROR("Request ID: %s, request_id not found in g_request_ids!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "request_id not found.");
        ret = -1;
        goto _exit2;
    }
    index = std::distance(request_ids.begin(), it);

    try {
        // Fetch the corresponding public key and plain text for the index
        remote_public_key_hex = get_public_key_for_index(index);
        plain_text = get_plain_text_for_index(index);
    } catch (const std::exception &e) {
        ERROR("Request ID: %s, Error fetching data: %s", req_id.c_str(), e.what());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "Error fetching data.");
        ret = -1;
        goto _exit2;
    }
    if (g_private_key.empty()) {
        ERROR("Request ID: %s, g_private_key is empty!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INTERNAL_ERROR, "g_private_key is empty.");
        ret = APP_ERROR_INTERNAL_ERROR;
        goto _exit2;
    }

    // Form the request JSON
    // Add private key from global variable to req_json
    encryption_request_json["private_key_hex"] = web::json::value::string(g_private_key);
    encryption_request_json["remote_public_key_hex"] = web::json::value::string(remote_public_key_hex);
    encryption_request_json["plain_text"] = web::json::value::string(plain_text);
    encryption_request_json["signature"] = req_json.at("signature");
    encryption_request_json["timestamp"] = web::json::value::string(timestamp);
    encryption_request_json["msg_digest"] = web::json::value::string(msg_digest);
    param_string = encryption_request_json.serialize();

    // Call ECALL to perform encryption in TEE
    if ((sgx_status = ecall_run(global_eid, &ret, eTaskType_EncryptText, req_id.c_str(),
                                param_string.c_str(), param_string.length(), &result, &result_len)) != SGX_SUCCESS) {
        ERROR("Request ID: %s, ecall_run() raised an error! sgx_status: %d, error message: %s",
              req_id.c_str(), sgx_status, t_strerror((int) sgx_status));
        resp_body = GetMessageReply(false, sgx_status, "ECALL raised an error!");
        ret = sgx_status;
        goto _exit2;
    }

    // Parse the result JSON
    response_json = web::json::value::parse(result);
    if (response_json.has_field("encrypted_aes_key") && response_json.has_field("encrypted_text")) {
        resp_body = response_json.serialize();
        ret = 0;
    } else {
        ERROR("Request ID: %s, encryption failed!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "encryption failed.");
        ret = APP_ERROR_INVALID_PARAMETER;
    }

    FUNC_END;
	INFO_OUTPUT_CONSOLE("Request ID: %s, resp_body (pretty): %s", req_id.c_str(), resp_body.c_str());
    _exit2:
    if (result) {
        free(result);
        result = nullptr;
    }
    return ret;
}

int msg_handler::CombineSignatures(
        const std::string &req_id,
        const std::string &req_body,
        std::string &resp_body) {
    int ret = 0;
    size_t result_len = 0;
    char *result = nullptr;
    sgx_status_t sgx_status;
    std::string param_string;
    web::json::value req_json = json::value::parse(req_body);
    web::json::value result_json;

    FUNC_BEGIN;

    // Validate request body
    if (!req_json.has_field(FIELD_NAME_DOC) || !req_json.at(FIELD_NAME_DOC).is_string() ||
        !req_json.has_field(FIELD_NAME_SIG_ARR) || !req_json.at(FIELD_NAME_SIG_ARR).is_array() ||
        !req_json.has_field(FIELD_NAME_RSA_PUBLIC_KEY) || !req_json.at(FIELD_NAME_RSA_PUBLIC_KEY).is_object() ||
        !req_json.has_field(FIELD_NAME_KEY_META) || !req_json.at(FIELD_NAME_KEY_META).is_object()) {
        ERROR("Request ID: %s, invalid input data!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "invalid input, please check your data.");
        ret = -1;
        goto _exit;
    }
    if (g_private_key.empty()) {
        ERROR("Request ID: %s, g_private_key is empty!", req_id.c_str());
        resp_body = GetMessageReply(false, APP_ERROR_INTERNAL_ERROR, "g_private_key is empty.");
        ret = APP_ERROR_INTERNAL_ERROR;
        goto _exit;
    }
    // Add private key from global variable to req_json
    req_json["private_key_hex"] = web::json::value::string(g_private_key);

    // Convert parameters to JSON string
    param_string = req_json.serialize();

    // Call ECALL to combine signatures in TEE
    if ((sgx_status = ecall_run(global_eid, &ret, eTaskType_CombineSignatures, req_id.c_str(),
                                param_string.c_str(), param_string.length(), &result, &result_len)) != SGX_SUCCESS) {
        ERROR("Request ID: %s, ecall_run() raised an error! sgx_status: %d, error message: %s",
              req_id.c_str(), sgx_status, t_strerror((int) sgx_status));
        resp_body = GetMessageReply(false, sgx_status, "ECALL raised an error!");
        ret = sgx_status;
        goto _exit;
    }

    // Parse the result JSON
    result_json = web::json::value::parse(result);
    if (result_json.has_field("plain_seeds")) {
        g_plain_seeds = result_json.at("plain_seeds").as_string();
        result_json.erase("plain_seeds");
        // Check if g_plain_seeds is an empty string
        if (g_plain_seeds.empty()) {
            ERROR("Request ID: %s, plain_seeds is empty!", req_id.c_str());
            resp_body = GetMessageReply(false, APP_ERROR_INVALID_PARAMETER, "plain_seeds is empty.");
            ret = APP_ERROR_INVALID_PARAMETER;
            goto _exit;
        }
    }else{
        ERROR("Request ID: %s, plain_seeds not generated!", req_id.c_str());
        resp_body = GetMessageReply(false, sgx_status, "ECALL raised an error!");
        ret = sgx_status;
        goto _exit;
    }

    // Convert the modified JSON back to a string
    resp_body = result_json.serialize();
    ret = 0;

    FUNC_END;

    _exit:
    if (result) {
        free(result);
        result = nullptr;
    }
    return ret;
}
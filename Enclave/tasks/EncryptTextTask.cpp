#include "EncryptTextTask.h"
#include "TaskConstant.h"
#include "common/tee_util.h"
#include "common/tee_error.h"
#include "common/log_t.h"
#include "json/json.h"
#include "crypto-curve/curve_point.h"
#include "crypto-curve/curve.h"
#include <crypto-ecies/symm.h>
#include <crypto-encode/base64.h>
#include "crypto-encode/hex.h"
#include <crypto-bn/rand.h>

#include "Enclave_t.h"

using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

extern std::mutex g_list_mutex;
extern std::map<std::string, KeyShardContext *> g_keyContext_list;

BN EncryptTextTask::compute_shared_secret(const BN &private_key, const std::vector<uint8_t> &remote_pubkey_bytes) {
    const Curve *curve = safeheron::curve::GetCurveParam(CurveType::P256);
    CurvePoint remote_public_key;
    if (remote_pubkey_bytes.size() == 33) {
        remote_public_key.DecodeCompressed(remote_pubkey_bytes.data(), CurveType::P256);
    } else if (remote_pubkey_bytes.size() == 65) {
        remote_public_key.DecodeFull(remote_pubkey_bytes.data(), CurveType::P256);
    } else {
        throw std::runtime_error("Invalid remote_pubkey length");
    }
    CurvePoint shared_secret_point = remote_public_key;
    shared_secret_point *= private_key;
    return shared_secret_point.x();
}

std::vector<uint8_t> EncryptTextTask::encrypt_with_aes_key(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext) {
    std::vector<uint8_t> iv(16, 0);
    std::string fixed_iv = "sign_node!@#";
    std::copy(fixed_iv.begin(), fixed_iv.end(), iv.begin());
    //std::generate(iv.begin(), iv.end(), std::rand);
    safeheron::ecies::AES aes(256);
    std::string key_str(key.begin(), key.end());
    std::string iv_str(iv.begin(), iv.end());
    if (!aes.initKey_CBC(key_str, iv_str)) {
        throw std::runtime_error("Failed to initialize AES key for encryption");
    }
    std::string plaintext_str(plaintext.begin(), plaintext.end());
    std::string ciphertext;
    if (!aes.encrypt(plaintext_str, ciphertext)) {
        throw std::runtime_error("AES encryption failed");
    }
    std::vector<uint8_t> result(iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

std::pair<std::string, std::string> EncryptTextTask::perform_ecdh_and_encrypt(const BN &local_private_key, const std::string &plaintext, const std::string &remote_pubkey_hex) {
    // Decode the remote public key from hex
    std::string remote_pubkey_str = safeheron::encode::hex::DecodeFromHex(remote_pubkey_hex);
    std::vector<uint8_t> remote_pubkey_bytes(remote_pubkey_str.begin(), remote_pubkey_str.end());
    if (remote_pubkey_bytes.size() != 33 && remote_pubkey_bytes.size() != 65) {
        throw std::runtime_error("Invalid remote_pubkey length");
    }

    // Compute the shared secret
    BN shared_secret = compute_shared_secret(local_private_key, remote_pubkey_bytes);
    std::string shared_secret_str;
    shared_secret.ToBytesBE(shared_secret_str);
    std::vector<uint8_t> shared_secret_bytes(shared_secret_str.begin(), shared_secret_str.end());

    // Generate a random AES key
    std::vector<uint8_t> aes_key(32);
    BN rand_bn = safeheron::rand::RandomBNStrict(256);
    rand_bn.ToBytesBE(reinterpret_cast<char*>(aes_key.data()));

    // Encrypt the plaintext using the random AES key
    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> encrypted_text = encrypt_with_aes_key(aes_key, plaintext_bytes);

    // Encrypt the random AES key using the shared secret
    std::vector<uint8_t> encrypted_aes_key = encrypt_with_aes_key(shared_secret_bytes, aes_key);

    // Encode the encrypted AES key and encrypted text to base64
    std::string encrypted_aes_key_base64 = safeheron::encode::base64::EncodeToBase64(encrypted_aes_key.data(), encrypted_aes_key.size());
    std::string encrypted_text_base64 = safeheron::encode::base64::EncodeToBase64(encrypted_text.data(), encrypted_text.size());

    return std::make_pair(encrypted_aes_key_base64, encrypted_text_base64);
}

int EncryptTextTask::execute(const std::string &request_id, const std::string &request, std::string &reply,
                             std::string &error_msg) {
    int ret = 0;
    JSON::Root req_root;

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

    // Extract fields from request JSON
    std::string private_key_hex = req_root["private_key_hex"].asString();
    std::string remote_public_key_hex = req_root["remote_public_key_hex"].asString();
    std::string plain_text = req_root["plain_text"].asString();

    // Convert private_key_hex to BN
    BN local_private_key;
    local_private_key = local_private_key.FromHexStr(private_key_hex);

    // Encrypt plain_text and generate a random AES key
    auto [encrypted_aes_key, encrypted_text] = perform_ecdh_and_encrypt(local_private_key, plain_text, remote_public_key_hex);

    // Prepare response JSON
    ret = get_reply_string(request_id, encrypted_aes_key, encrypted_text, reply);

    FUNC_END;
    return ret;
}

int EncryptTextTask::get_reply_string(const std::string &request_id, const std::string &encrypted_aes_key,
                                      const std::string &encrypted_text, std::string &out_str) {
    JSON::Root reply_json;
    reply_json["success"] = true;
    reply_json["encrypted_aes_key"] = encrypted_aes_key;
    reply_json["encrypted_text"] = encrypted_text;
    out_str = JSON::Root::write(reply_json);
    return 0;
}

int EncryptTextTask::get_task_type() {
    return eTaskType_EncryptText;
}
#include "EncryptTextTask.h"
#include "TaskConstant.h"
#include "common/tee_util.h"
#include "common/tee_error.h"
#include "common/log_t.h"
#include "json/json.h"
#include "crypto-hash/hash256.h"
#include "crypto-curve/curve_point.h"
#include "crypto-curve/curve.h"
#include <crypto-ecies/symm.h>
#include <crypto-encode/base64.h>
#include "crypto-encode/hex.h"
#include "crypto-curve/ecdsa.h"
#include <crypto-bn/rand.h>
#include <chrono>
#include <ctime>

#include "Enclave_t.h"

using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;

extern std::mutex g_list_mutex;
extern std::map<std::string, KeyShardContext *> g_keyContext_list;

BN EncryptTextTask::compute_shared_secret(const BN &private_key, const std::vector <uint8_t> &remote_pubkey_bytes) {
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
    BN shared_secret = shared_secret_point.x();
    std::string shared_secret_str;
    shared_secret.ToHexStr(shared_secret_str);
    INFO_OUTPUT_CONSOLE("Shared Secret: %s\n", shared_secret_str.c_str());
    return shared_secret;
}

std::vector <uint8_t>
EncryptTextTask::encrypt_with_aes_key(const std::vector <uint8_t> &key, const std::vector <uint8_t> &plaintext) {
    std::vector <uint8_t> iv(16, 0);
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
    std::vector <uint8_t> result(iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

std::pair <std::string, std::string>
EncryptTextTask::perform_ecdh_and_encrypt(const BN &local_private_key, const std::string &plaintext,
                                          const std::string &remote_pubkey_hex) {
    // Decode the remote public key from hex
    std::string remote_pubkey_str = safeheron::encode::hex::DecodeFromHex(remote_pubkey_hex);
    std::vector <uint8_t> remote_pubkey_bytes(remote_pubkey_str.begin(), remote_pubkey_str.end());
    if (remote_pubkey_bytes.size() != 33 && remote_pubkey_bytes.size() != 65) {
        throw std::runtime_error("Invalid remote_pubkey length");
    }

    // Compute the shared secret
    BN shared_secret = compute_shared_secret(local_private_key, remote_pubkey_bytes);
    std::string shared_secret_str;
    shared_secret.ToBytesBE(shared_secret_str);
    std::vector <uint8_t> shared_secret_bytes(shared_secret_str.begin(), shared_secret_str.end());

    // Generate a random AES key
    std::vector <uint8_t> aes_key(32);
    BN rand_bn = safeheron::rand::RandomBNStrict(256);
    std::string temp_str;
    rand_bn.ToBytesBE(temp_str);
    std::copy(temp_str.begin(), temp_str.begin() + 32, aes_key.begin());
    // Print the random number
    std::string rand_bn_str;
    rand_bn.ToHexStr(rand_bn_str);
    INFO_OUTPUT_CONSOLE("Random Number: %s\n", rand_bn_str.c_str());

    // Encrypt the plaintext using the random AES key
    std::vector <uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    std::vector <uint8_t> encrypted_text = encrypt_with_aes_key(aes_key, plaintext_bytes);

    // Encrypt the random AES key using the shared secret
    std::vector <uint8_t> encrypted_aes_key = encrypt_with_aes_key(shared_secret_bytes, aes_key);

    // Encode the encrypted AES key and encrypted text to base64
    std::string encrypted_aes_key_base64 = safeheron::encode::base64::EncodeToBase64(encrypted_aes_key.data(),
                                                                                     encrypted_aes_key.size());
    std::string encrypted_text_base64 = safeheron::encode::base64::EncodeToBase64(encrypted_text.data(),
                                                                                  encrypted_text.size());

    return std::make_pair(encrypted_aes_key_base64, encrypted_text_base64);
}

// Function to concatenate request_id and timestamp and derive a SHA-256 hash using safeheron::hash::CHash256
std::string EncryptTextTask::derive_sha256_hash(const std::string &request_id, const std::string &timestamp) {
    std::string concatenated = request_id + timestamp;
    std::string hash_hex;
    if (!sha256_hash(concatenated, hash_hex)) {
        ERROR("derive sha256_hash failed");
    }
    INFO_OUTPUT_CONSOLE("concatenated: %s\n", concatenated.c_str());
    INFO_OUTPUT_CONSOLE("hash_hex: %s\n", hash_hex.c_str());
    return hash_hex;
}

// Function to verify the signature using msg_digest and remote_public_key_hex
bool EncryptTextTask::verify_signature(const std::string &msg_digest, const std::string &signature,
                                       const std::string &remote_public_key_hex) {
    // Decode the public key from hex
    std::string remote_pubkey_str = safeheron::encode::hex::DecodeFromHex(remote_public_key_hex);
    std::vector <uint8_t> remote_pubkey_bytes(remote_pubkey_str.begin(), remote_pubkey_str.end());
    CurvePoint remote_public_key;
    if (remote_pubkey_bytes.size() == 33) {
        remote_public_key.DecodeCompressed(remote_pubkey_bytes.data(), CurveType::P256);
    } else if (remote_pubkey_bytes.size() == 65) {
        remote_public_key.DecodeFull(remote_pubkey_bytes.data(), CurveType::P256);
    } else {
        ERROR("Invalid remote_pubkey length");
        return false;
    }

    // Convert msg_digest and signature to the required formats
    std::string msg_digest_str = safeheron::encode::hex::DecodeFromHex(msg_digest);
    std::string signature_str = safeheron::encode::hex::DecodeFromHex(signature);

    if (msg_digest_str.size() != 32 || signature_str.size() != 64) {
        ERROR("Invalid msg_digest or signature length");
        return false;
    }

    uint8_t digest32[32];
    std::copy(msg_digest_str.begin(), msg_digest_str.end(), digest32);

    uint8_t sig64[64];
    std::copy(signature_str.begin(), signature_str.end(), sig64);

    // Verify the signature using safeheron::curve::ecdsa::Verify
    return safeheron::curve::ecdsa::Verify(CurveType::P256, remote_public_key, digest32, sig64);
}

std::string EncryptTextTask::decrypt_with_aes_key(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext) {
    INFO_OUTPUT_CONSOLE("---> begin decrypt_with_aes_key\n");

    // Debug log to print the key
    std::string key_hex = safeheron::encode::hex::EncodeToHex(key.data(), key.size());
    INFO_OUTPUT_CONSOLE("--->AES key: %s\n", key_hex.c_str());

    // Debug log to print the ciphertext
    std::string ciphertext_hex = safeheron::encode::hex::EncodeToHex(ciphertext.data(), ciphertext.size());
    INFO_OUTPUT_CONSOLE("--->Ciphertext: %s\n", ciphertext_hex.c_str());

    try {
        // Split the IV and ciphertext
        if (ciphertext.size() < 16) {
            ERROR("Ciphertext too short to contain IV");
            throw std::runtime_error("Ciphertext too short to contain IV");
        }
        std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 16);
        std::vector<uint8_t> actual_ciphertext(ciphertext.begin() + 16, ciphertext.end());

        // Initialize AES-256-CBC decryption
        safeheron::ecies::AES aes(256);
        std::string key_str(key.begin(), key.end());
        std::string iv_str(iv.begin(), iv.end());

        if (!aes.initKey_CBC(key_str, iv_str)) {
            ERROR("Failed to initialize AES key for decryption");
            throw std::runtime_error("Failed to initialize AES key for decryption");
        }

        std::string ciphertext_str(actual_ciphertext.begin(), actual_ciphertext.end());
        std::string plaintext;

        if (!aes.decrypt(ciphertext_str, plaintext)) {
            ERROR("AES decryption failed");
            throw std::runtime_error("AES decryption failed");
        }

        INFO_OUTPUT_CONSOLE("--->decrypt_with_aes_key: %s\n", plaintext.c_str());
        return plaintext;
    } catch (const std::exception &e) {
        ERROR("Exception during AES decryption: %s", e.what());
        throw;
    }
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
        error_msg = format_msg("Request ID: %s, request body is not in JSON! request: %s", request.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_INVALID_PARAMETER;
    }

    // Load encrypted private key and AES key from request JSON fields
    std::string encrypted_private_key_hex = req_root["encrypted_private_key_hex"].asString();
    std::string aes_key_hex = req_root["aes_key_hex"].asString();

    // Decode hex strings to byte vectors
    std::string encrypted_private_key_str = safeheron::encode::hex::DecodeFromHex(encrypted_private_key_hex);
    std::vector<uint8_t> encrypted_private_key(encrypted_private_key_str.begin(), encrypted_private_key_str.end());

    std::string aes_key_str = safeheron::encode::hex::DecodeFromHex(aes_key_hex);
    std::vector<uint8_t> aes_key(aes_key_str.begin(), aes_key_str.end());

    // Decrypt the private key using the AES key
    std::string decrypted_private_key_str = decrypt_with_aes_key(aes_key, encrypted_private_key);
    std::vector<uint8_t> decrypted_private_key_bytes(decrypted_private_key_str.begin(), decrypted_private_key_str.end());

    // Convert decrypted private key bytes to BN
    BN local_private_key;
    local_private_key.FromBytesBE(decrypted_private_key_bytes.data(), decrypted_private_key_bytes.size());

    std::string remote_public_key_hex = req_root["remote_public_key_hex"].asString();
    std::string plain_text = req_root["plain_text"].asString();
    std::string signature = req_root["signature"].asString();
    std::string msg_digest = req_root["msg_digest"].asString();
    std::string timestamp = req_root["timestamp"].asString();
    std::string req_request_id = req_root["request_id"].asString();

    // Derive SHA-256 hash and compare with msg_digest
    std::string derived_hash = derive_sha256_hash(req_request_id, timestamp);
    if (derived_hash != msg_digest) {
        error_msg = format_msg("Request ID: %s, msg_digest does not match derived hash %s !", request_id.c_str(),
                               derived_hash.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_INVALID_PARAMETER;
    }

    // Verify the signature
    if (!verify_signature(msg_digest, signature, remote_public_key_hex)) {
        error_msg = format_msg("Request ID: %s, signature verification failed!", request_id.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_INVALID_PARAMETER;
    }

    auto result = perform_ecdh_and_encrypt(local_private_key, plain_text, remote_public_key_hex);
    std::string encrypted_aes_key = result.first;
    std::string encrypted_text = result.second;

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
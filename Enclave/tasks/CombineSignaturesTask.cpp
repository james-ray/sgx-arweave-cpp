#include "CombineSignaturesTask.h"
#include "TaskConstant.h"
#include "common/tee_util.h"
#include "common/tee_error.h"
#include "common/log_t.h"
#include "json/json.h"
#include <vector>
#include <string>
#include "crypto-curve/curve_point.h"
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include <crypto-ecies/symm.h>
#include <crypto-encode/base64.h>
#include "crypto-encode/hex.h"
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


extern std::mutex g_list_mutex;
extern std::map<std::string, KeyShardContext *> g_keyContext_list;


BN CombineSignaturesTask::compute_shared_secret(const BN &private_key, const std::vector <uint8_t> &remote_pubkey_bytes) {
    // Initialize the curve
    const Curve *curve = safeheron::curve::GetCurveParam(CurveType::P256);

    // Decode the remote public key
    CurvePoint remote_public_key;
    if (remote_pubkey_bytes.size() == 33) {
        remote_public_key.DecodeCompressed(remote_pubkey_bytes.data(), CurveType::P256);
    } else if (remote_pubkey_bytes.size() == 65) {
        remote_public_key.DecodeFull(remote_pubkey_bytes.data(), CurveType::P256);
    } else {
        throw std::runtime_error("Invalid remote_pubkey length");
    }

    // Compute the shared secret using ECC multiplication
    CurvePoint shared_secret_point = remote_public_key;
    shared_secret_point *= private_key;

    // Convert the shared secret point to a BN
    BN shared_secret = shared_secret_point.x();

    return shared_secret;
}

std::string CombineSignaturesTask::decrypt_with_aes_key(const std::vector <uint8_t> &key, const std::vector <uint8_t> &ciphertext) {
    // Initialize AES-256-CBC decryption
    safeheron::ecies::AES aes(256);
    std::string key_str(key.begin(), key.end());
    std::string iv(16, 0); // Assuming a zero IV for simplicity, replace with actual IV if available

    if (!aes.initKey_CBC(key_str, iv)) {
        throw std::runtime_error("Failed to initialize AES key and IV");
    }

    std::string ciphertext_str(ciphertext.begin(), ciphertext.end());
    std::string plaintext;

    if (!aes.decrypt(ciphertext_str, plaintext)) {
        throw std::runtime_error("AES decryption failed");
    }
    INFO_OUTPUT_CONSOLE("--->decrypt_with_aes_key: %s\n", plaintext.c_str());
    return plaintext;
}

std::string CombineSignaturesTask::perform_ecdh_and_decrypt(const BN &local_private_key,
                                                            const std::string &encrypted_aes_key_base64,
                                                            const std::string &encrypted_seed_base64,
                                                            const std::string &remote_pubkey_hex) {
    // Decode base64 inputs
    std::string encrypted_aes_key_str = safeheron::encode::base64::DecodeFromBase64(encrypted_aes_key_base64);
    std::vector <uint8_t> encrypted_aes_key(encrypted_aes_key_str.begin(), encrypted_aes_key_str.end());

    std::string encrypted_seed_str = safeheron::encode::base64::DecodeFromBase64(encrypted_seed_base64);
    std::vector <uint8_t> encrypted_seed(encrypted_seed_str.begin(), encrypted_seed_str.end());

    // Decode hex public key
    std::string remote_pubkey_str = safeheron::encode::hex::DecodeFromHex(remote_pubkey_hex);
    std::vector <uint8_t> remote_pubkey_bytes(remote_pubkey_str.begin(), remote_pubkey_str.end());

    // Ensure the length is either 33 (compressed) or 65 (uncompressed)
    if (remote_pubkey_bytes.size() != 33 && remote_pubkey_bytes.size() != 65) {
        throw std::runtime_error("Invalid remote_pubkey length");
    }

    // Compute shared secret
    BN shared_secret = compute_shared_secret(local_private_key, remote_pubkey_bytes);

    // Decrypt the AES key using the shared secret
    std::string shared_secret_str;
    shared_secret.ToBytesBE(shared_secret_str);
    std::vector <uint8_t> shared_secret_bytes(shared_secret_str.begin(), shared_secret_str.end());
    std::string decrypted_aes_key = decrypt_with_aes_key(shared_secret_bytes, encrypted_aes_key);

    // Decrypt the seed using the decrypted AES key
    std::vector <uint8_t> decrypted_aes_key_bytes(decrypted_aes_key.begin(), decrypted_aes_key.end());
    std::string plaintext_seed = decrypt_with_aes_key(decrypted_aes_key_bytes, encrypted_seed);

    return plaintext_seed;
}

int CombineSignaturesTask::get_task_type() {
    return eTaskType_CombineSignatures;
}

int CombineSignaturesTask::execute(const std::string &request_id, const std::string &request, std::string &reply,
                                   std::string &error_msg) {
    int ret = 0;
    JSON::Root req_root;
    std::string doc;
    std::string doc_pss;
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
    doc_pss = req_root["doc_pss"].asString();
    INFO_OUTPUT_CONSOLE("--->DOC_PSS: %s\n", doc_pss.c_str());

    // Load local private key from request JSON field
    BN local_private_key;
    std::string private_key_hex = req_root["private_key_hex"].asString();
    local_private_key.FromHexStr(private_key_hex);
    INFO_OUTPUT_CONSOLE("--->local_private_key: %s\n", private_key_hex.c_str());
    // Parse public_key_list, encrypted_aes_key_list, and encrypted_seed_list
    STR_ARRAY public_key_list = req_root["public_key_list"].asStringArrary();
    STR_ARRAY encrypted_aes_key_list = req_root["encrypted_aes_key_list"].asStringArrary();
    STR_ARRAY encrypted_seed_list = req_root["encrypted_seed_list"].asStringArrary();

    INFO_OUTPUT_CONSOLE("--->public_key_list size: %ld\n", public_key_list.size());
    // Decrypt seeds
    std::vector <std::string> plain_seeds;
    for (size_t i = 0; i < public_key_list.size(); ++i) {
        std::string plain_seed = perform_ecdh_and_decrypt(local_private_key, encrypted_aes_key_list[i],
                                                          encrypted_seed_list[i], public_key_list[i]);
        plain_seeds.push_back(plain_seed);
    }
    // Concatenate plain seeds with commas
    std::string concatenated_plain_seeds;
    for (size_t i = 0; i < plain_seeds.size(); ++i) {
        concatenated_plain_seeds += plain_seeds[i];
        if (i < plain_seeds.size() - 1) {
            concatenated_plain_seeds += ",";
        }
    }
    // Parse sig_shares
    std::vector <RSASigShare> sig_shares;
    STR_ARRAY sig_shares_str_arr = req_root["sig_shares"].asStringArrary();
    for (const std::string &sig_share_str: sig_shares_str_arr) {
        INFO_OUTPUT_CONSOLE("--->try parsing sig_share_str: %s \n", sig_share_str.c_str());
        JSON::Root sig_share_json = JSON::Root::parse(sig_share_str);
        if (sig_share_json.is_valid()) {
            RSASigShare sig_share;
            sig_share.set_index(sig_share_json["index"].asInt());
            sig_share.set_sig_share(safeheron::bignum::BN(sig_share_json["sig_share"].asString().c_str(), 16));
            sig_share.set_z(safeheron::bignum::BN(sig_share_json["z"].asString().c_str(), 16));
            sig_share.set_c(safeheron::bignum::BN(sig_share_json["c"].asString().c_str(), 16));
            sig_shares.push_back(sig_share);
        } else {
            INFO_OUTPUT_CONSOLE("--->sig_share_json is invalid: %s \n", sig_share_str.c_str());
            error_msg = format_msg("Request ID: %s, sig_share_json is not valid! sig_share_str: %s",
                                   request_id.c_str(), sig_share_str.c_str());
            ERROR("%s", error_msg.c_str());
            return TEE_ERROR_INVALID_PARAMETER;
        }
    }
    INFO_OUTPUT_CONSOLE("--->after parse sig_shares: %zu\n", sig_shares.size());

    // Parse public_key
    JSON::Root public_key_json = req_root["rsa_public_key"].asJson();
    public_key.set_e(safeheron::bignum::BN(public_key_json["e"].asString().c_str(), 16));
    public_key.set_n(safeheron::bignum::BN(public_key_json["n"].asString().c_str(), 16));
    std::string public_key_n_str;
    public_key.n().ToHexStr(public_key_n_str);
    INFO_OUTPUT_CONSOLE("--->after parse public_key: n %s\n", public_key_n_str.c_str());

    // Parse key_meta
    JSON::Root key_meta_json = req_root["key_meta"].asJson();
    key_meta.set_k(key_meta_json["k"].asInt());
    key_meta.set_l(key_meta_json["l"].asInt());
    std::vector <safeheron::bignum::BN> vki_arr;
    STR_ARRAY vki_str_arr = key_meta_json["vkiArr"].asStringArrary();
    for (const std::string &vki_str: vki_str_arr) {
        vki_arr.push_back(safeheron::bignum::BN(vki_str.c_str(), 16));
    }
    key_meta.set_vki_arr(vki_arr);
    key_meta.set_vku(safeheron::bignum::BN(key_meta_json["vku"].asString().c_str(), 16));
    key_meta.set_vkv(safeheron::bignum::BN(key_meta_json["vkv"].asString().c_str(), 16));

    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: key_meta.vki_arr %ld\n", key_meta.vki_arr().size());
    //std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(doc,1024,safeheron::tss_rsa::SaltLength::AutoLength);

    // Convert hex string to binary representation
    std::string em_binary = safeheron::encode::hex::DecodeFromHex(doc_pss.c_str());

    if (!safeheron::tss_rsa::VerifyEMSA_PSS(doc, 1024, safeheron::tss_rsa::SaltLength::AutoLength, em_binary)) {
        error_msg = format_msg("Request ID: %s, VerifyEMSA_PSS failed!", request_id.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_COMBINE_SIGNATURE_FAILED;
    }
    INFO_OUTPUT_CONSOLE("--->before call CombineSignatures: doc_pss1 %s\n", doc_pss.c_str());
    if (!safeheron::tss_rsa::CombineSignatures(em_binary, sig_shares, public_key, key_meta, out_sig)) {
        error_msg = format_msg("Request ID: %s, CombineSignature failed!", request_id.c_str());
        ERROR("%s", error_msg.c_str());
        return TEE_ERROR_COMBINE_SIGNATURE_FAILED;
    }

    return get_reply_string(request_id, out_sig, concatenated_plain_seeds, reply);
}

int CombineSignaturesTask::get_reply_string(const std::string &request_id, const safeheron::bignum::BN &out_sig,
                                            std::string &plain_seeds, std::string &out_str) {
    JSON::Root reply_json;
    reply_json["success"] = true;
    std::string sig_str;
    out_sig.ToHexStr(sig_str);
    reply_json["signature"] = sig_str;
    reply_json["plain_seeds"] = plain_seeds;
    out_str = JSON::Root::write(reply_json);
    return 0;
}
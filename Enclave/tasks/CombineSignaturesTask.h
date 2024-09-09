#include "../shell/Dispatcher.h"
#include <crypto-tss-rsa/tss_rsa.h>
#include <crypto-tss-rsa/RSASigShare.h>
#include <crypto-tss-rsa/RSAPublicKey.h>
#include <crypto-tss-rsa/RSAKeyMeta.h>
#include <crypto-encode/hex.h>
#include <crypto-bn/bn.h>
#include <string>
#include <vector>

using safeheron::tss_rsa::RSASigShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::bignum::BN;

class CombineSignaturesTask: public Task
{
public:
    /**
     * @brief : The execution of signature combination tasks.
     * @param request_id[in] : The unique ID of each request.
     * @param request[in] : The request body, JSON string.
     * @param reply[out] : The combined signature result, JSON string.
     * @param error_msg[out] : An error message is returned when the execution is failed.
     * @return int : return 0 if success, otherwise return an error code.
     */
    virtual int execute( const std::string & request_id, const std::string & request, std::string & reply, std::string & error_msg );

    /**
     * @brief : Get the current task type.
     * @return int : Return the task type number defined in TaskConstant.h
     */
    virtual int get_task_type( );

private:
    /**
     * @brief : Construct a JSON string after the signature combination is done.
     * @param request_id[in] : The unique ID of each request.
     * @param out_sig[in] : The combined signature.
     * @param out_str[out] : A JSON string that represents the combination result.
     *                       The JSON structure is shown as below.
     *   {
     *     "success": true,
     *     "signature": "combined signature hex string"
     *   }
     *
     * @return int : Return TEE_OK if success, otherwise return an error code.
     */
    int get_reply_string( const std::string & request_id, const safeheron::bignum::BN & out_sig, std::string &plain_seeds, std::string & out_str );

    BN compute_shared_secret(const BN &private_key, const std::vector<uint8_t> &remote_pubkey_bytes);
    std::string decrypt_with_aes_key(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
    std::string perform_ecdh_and_decrypt(const safeheron::bignum::BN &local_private_key, const std::string &encrypted_aes_key_base64, const std::string &encrypted_seed_base64, const std::string &remote_pubkey_hex);
};

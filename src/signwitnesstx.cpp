#include <iostream>
#include <stdexcept>

#include <CoinCore/hash.h>
#include <CoinCore/numericdata.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

const unsigned char ADDRESS_VERSIONS[] = {30, 50};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 7 || argc > 8)
    {
        cerr << "# Usage: " << argv[0] << " <address> <amount> <outpoint hash> <outpoint index> <outpoint amount> <privkey> [verbose = 0]" << endl;
        return -1;
    }

    try
    {
        string address(argv[1]);
        uint64_t amount = strtoull(argv[2], NULL, 0);
        TxOut txOut(amount, getTxOutScriptForAddress(address, ADDRESS_VERSIONS));

        uchar_vector outpointHash(argv[3]);
        if (outpointHash.size() != 32) throw runtime_error("Invalid outpoint hash.");
        uint32_t outpointIndex = strtoul(argv[4], NULL, 0);
        OutPoint outPoint(outpointHash, outpointIndex);

        uint64_t outpointamount = strtoull(argv[5], NULL, 0);
        uchar_vector privkey(argv[6]);
        if (privkey.size() != 32) throw runtime_error("Invalid private key length.");

        bool verbose = (argc > 7 ? (strtoul(argv[7], NULL, 0) != 0) : false);

        secp256k1_key signingKey;
        signingKey.setPrivKey(privkey);
        uchar_vector pubkey = signingKey.getPubKey();

        uchar_vector redeemscript;
        redeemscript << pushStackItem(pubkey) << OP_CHECKSIG;

        uchar_vector witnessscript;
        witnessscript << OP_1 << pushStackItem(sha256(redeemscript));

        TxIn txIn(outPoint, pushStackItem(witnessscript), 0);

        Transaction tx;
        tx.version = 1;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);
        tx.lockTime = 0;

        uchar_vector signingHash = tx.getSigHash(Coin::SIGHASH_ALL, 0, redeemscript, outpointamount);
        bytes_t sig = secp256k1_sign_rfc6979(signingKey, signingHash);
        sig.push_back(Coin::SIGHASH_ALL);

        TxInWitness txinwit;
        txinwit.push(sig);
        txinwit.push(redeemscript);
        tx.witness.txinwits.push_back(txinwit);

        if (verbose)
        {
            cout << endl << "witness: " << tx.witness.getSerialized(false).getHex() << endl;
            cout << endl << "tx: " << tx.getSerializedWithWitness().getHex() << endl;
        }
        else
        {
            cout << tx.getSerializedWithWitness().getHex() << endl;
        }
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}

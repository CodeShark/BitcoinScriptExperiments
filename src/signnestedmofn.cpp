#include <iostream>
#include <stdexcept>

#include <CoinCore/hash.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

const unsigned char ADDRESS_VERSIONS[] = {0, 5};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 8)
    {
        cerr << "# Usage: " << argv[0] << " <address> <amount> <outpoint hash> <outpoint index> <redeemscript> <n sigs> <privkey 1> [<privkey 2> ...] [<n sigs> <privkey 1> [<privkey 2> ...] ...]>" << endl;
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

        uchar_vector redeemscript(argv[5]);
        bytes_t signingHash;

        {
            TxIn txIn(outPoint, redeemscript, 0);

            Transaction tx;
            tx.version = 1;
            tx.inputs.push_back(txIn);
            tx.outputs.push_back(txOut);
            tx.lockTime = 0;

            signingHash = tx.getHashWithAppendedCode(Coin::SIGHASH_ALL);
        }

        uchar_vector txinscript;
        int pos = 6;
        while (pos < argc)
        {
            int n = strtol(argv[pos], NULL, 0);
            if (n < 1 || n > argc - pos) throw runtime_error("Invalid private key count.");

            pos++;
            txinscript.push_back(OP_0);
            for (int k = 0; k < n; k++)
            {
                uchar_vector privkey(argv[pos++]);
                if (privkey.size() == 32)
                {
                    secp256k1_key signingKey;
                    signingKey.setPrivKey(privkey);
                    bytes_t sig = secp256k1_sign(signingKey, signingHash);
                    sig.push_back(Coin::SIGHASH_ALL);
                    txinscript += opPushData(sig.size());
                    txinscript += sig;
                }
                else
                {
                    txinscript.push_back(OP_0);
                }
            } 
        }

        txinscript += opPushData(redeemscript.size());
        txinscript += redeemscript;

        TxIn txIn(outPoint, txinscript, 0);

        Transaction tx;
        tx.version = 1;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);
        tx.lockTime = 0;

        cout << endl << "tx: " << tx.getSerialized().getHex() << endl; 
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}

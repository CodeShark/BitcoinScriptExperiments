#include <iostream>
#include <stdexcept>

#include <CoinCore/hash.h>
#include <CoinCore/secp256k1.h>

#include <CoinQ/CoinQ_script.h>

const unsigned char ADDRESS_VERSIONS[] = {0, 5};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 6)
    {
        cerr << "# Usage: " << argv[0] << " <inner m> <inner n> <outer m> <outer n> <pubkey 1> [<pubkey 2> ...]" << endl;
        return -1;
    }

    try
    {
        int im = strtol(argv[1], NULL, 0);
        int in = strtol(argv[2], NULL, 0);
        if (im < 1 || im > in || in > 15) throw runtime_error("Invalid inner m-of-n.");

        int om = strtol(argv[3], NULL, 0);
        int on = strtol(argv[4], NULL, 0);
        if (om < 1 || om > on || on > 15) throw runtime_error("Invalid outer m-of-n.");

        int nPubKeys = in * on;

        if (nPubKeys > 15) throw runtime_error("Maximum of 15 signature operations exceeded.");

        if (argc - 5 != nPubKeys) throw runtime_error("Invalid number of public keys.");

        std::vector<uchar_vector> pubkeys;
        for (int i = 5; i < argc; i++)
        {
            uchar_vector pubkey(argv[i]);
            if (pubkey.size() != 33) throw runtime_error("Invalid pubkey length.");

            pubkeys.push_back(pubkey);
        }

        uchar_vector redeemscript;
        redeemscript.push_back(om + OP_1_OFFSET);
        redeemscript.push_back(OP_TOALTSTACK);
        for (int i = 0; i < on - 1; i++)
        {
            redeemscript.push_back(im + OP_1_OFFSET);
            for (int j = 0; j < in; j++)
            {
                int k = in * i + j;
                redeemscript += opPushData(pubkeys[k].size());
                redeemscript += pubkeys[k];
            }
            redeemscript.push_back(in + OP_1_OFFSET);
            redeemscript.push_back(OP_CHECKMULTISIG);
            redeemscript.push_back(OP_IF);
                redeemscript.push_back(OP_FROMALTSTACK);
                redeemscript.push_back(OP_1SUB);
                redeemscript.push_back(OP_IFDUP);
                redeemscript.push_back(OP_IF);
                    redeemscript.push_back(OP_TOALTSTACK);
        }
        redeemscript.push_back(im + OP_1_OFFSET);
        for (int j = 0; j < in; j++)
        {
            int k = in * (on - 1) + j;
            redeemscript += opPushData(pubkeys[k].size());
            redeemscript += pubkeys[k];
        }
        redeemscript.push_back(in + OP_1_OFFSET);
        redeemscript.push_back(OP_IF);
            redeemscript.push_back(OP_FROMALTSTACK);
            redeemscript.push_back(OP_1SUB);
            redeemscript.push_back(OP_TOALTSTACK);
        redeemscript.push_back(OP_ENDIF);

        for (int i = 2; i < 2*on; i++) { redeemscript.push_back(OP_ENDIF); }

        redeemscript.push_back(OP_FROMALTSTACK);
        redeemscript.push_back(OP_NOT);

        cout << endl << "redeemscript: " << redeemscript.getHex() << endl;

        uchar_vector txoutscript;
        txoutscript.push_back(OP_HASH160);
        txoutscript.push_back(0x14);
        txoutscript += ripemd160(sha256(redeemscript));
        txoutscript.push_back(OP_EQUAL);
        cout << endl << "address: " << getAddressForTxOutScript(txoutscript, ADDRESS_VERSIONS) << endl;

        OutPoint outPoint(bytes_t(32, 0), 0);
        TxIn txIn(outPoint, redeemscript, 0);
        TxOut txOut(100000, bytes_t());
        Transaction tx;
        tx.version = 0;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);
        tx.lockTime = 0xffffffff;
        cout << endl << "tx: " << tx.getSerialized().getHex() << endl; 
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}

#include <iostream>
#include <stdexcept>

#include "scriptnum.h"

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
    if (argc != 4)
    {
        cerr << "# Usage: " << argv[0] << " <unlocked pubkey> <locked pubkey> <locktime>" << endl;
        return -1;
    }

    try
    {
        uchar_vector unlocked_pubkey(argv[1]);
        if (unlocked_pubkey.size() != 33) throw runtime_error("Invalid unlocked pubkey length.");

        uchar_vector locked_pubkey(argv[2]);
        if (locked_pubkey.size() != 33) throw runtime_error("Invalid locked pubkey length.");

        int64_t locktime = strtoll(argv[3], NULL, 0);
        if (locktime < 0 || locktime > 0xffffffff) throw runtime_error("Invalid locktime.");

        uchar_vector serialized_locktime = CScriptNum::serialize(locktime);

        uchar_vector redeemscript;
        redeemscript += opPushData(locked_pubkey.size());
        redeemscript += locked_pubkey;
        redeemscript.push_back(OP_CHECKSIG);
        redeemscript.push_back(OP_IF);
            // We're using the locked pubkey
            redeemscript += opPushData(serialized_locktime.size());
            redeemscript += serialized_locktime;
            redeemscript.push_back(OP_CHECKLOCKTIMEVERIFY);
            redeemscript.push_back(OP_DROP);
            redeemscript.push_back(OP_1);
        redeemscript.push_back(OP_ELSE);
            // We're using the unlocked pubkey
            redeemscript += opPushData(unlocked_pubkey.size());
            redeemscript += unlocked_pubkey;
            redeemscript.push_back(OP_CHECKSIG);
        redeemscript.push_back(OP_ENDIF);

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
        tx.lockTime = (uint32_t)locktime;

        cout << endl << "tx: " << tx.getSerialized().getHex() << endl; 
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}

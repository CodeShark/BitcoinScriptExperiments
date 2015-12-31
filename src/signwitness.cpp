#include <iostream>
#include <stdexcept>

#include <CoinCore/hash.h>
#include <CoinCore/numericdata.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

const unsigned char ADDRESS_VERSIONS[] = {111, 196};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 6)
    {
        cerr << "# Usage: " << argv[0] << " <address> <amount> <outpoint hash> <outpoint index> <privkey>" << endl;
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

        uchar_vector privkey(argv[5]);
        if (privkey.size() != 32) throw runtime_error("Invalid private key length.");

        secp256k1_key signingKey;
        signingKey.setPrivKey(privkey);
        uchar_vector pubkey = signingKey.getPubKey();

        uchar_vector redeemscript;
        redeemscript += opPushData(pubkey.size());
        redeemscript += pubkey;
        redeemscript.push_back(OP_CHECKSIG);

        cout << endl << "redeemscript: " << redeemscript.getHex() << endl;

        uchar_vector scripthash = sha256(redeemscript);
        uchar_vector witnessscript;
        witnessscript.push_back(OP_1);
        witnessscript += opPushData(scripthash.size());
        witnessscript += scripthash;

        uchar_vector hashPrevouts;
        {
            uchar_vector ss;
            ss += VarInt(1).getSerialized();
            ss += outPoint.getSerialized();
            hashPrevouts = sha256_2(ss);
        }

        uchar_vector hashSequence;
        {
            uchar_vector ss;
            ss += VarInt(1).getSerialized();
            ss += uint_to_vch(0, 2);
            hashSequence = sha256_2(ss);
        }

        uchar_vector hashOutputs;
        {
            uchar_vector ss;
            ss += VarInt(1).getSerialized();
            ss += txOut.getSerialized();
            hashOutputs = sha256_2(ss);
        }

        uchar_vector ss;
        ss += uint_to_vch(1, 2);
        ss += hashPrevouts;
        ss += hashSequence;
        ss += outPoint.getSerialized();
        ss += VarInt(redeemscript.size()).getSerialized();
        ss += redeemscript;
        ss += uint_to_vch(amount, 2);
        ss += uint_to_vch(0, 2);
        ss += hashOutputs;
        ss += uint_to_vch(0, 2);
        ss += uint_to_vch((uint32_t)SIGHASH_ALL, 2);
        uchar_vector signingHash = sha256_2(ss);

        bytes_t sig = secp256k1_sign(signingKey, signingHash);
        sig.push_back(SIGHASH_ALL);

        uchar_vector witness;
        witness += VarInt(2).getSerialized();
        witness += VarInt(sig.size()).getSerialized();
        witness += sig;
        witness += VarInt(redeemscript.size()).getSerialized();
        witness += redeemscript;

        cout << endl << "witness: " << witness.getHex() << endl;

        TxIn txIn(outPoint, witnessscript, 0);

        Transaction tx;
        tx.version = 1;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);

        // version
        uchar_vector rval = uint_to_vch(tx.version, 2);

        // mask and flag
        rval.push_back(0);
        rval.push_back(1);

        uint64_t i;
        // inputs
        rval += VarInt(tx.inputs.size()).getSerialized();
        for (i = 0; i < tx.inputs.size(); i++)
            rval += tx.inputs[i].getSerialized(true);

        // outputs
        rval += VarInt(tx.outputs.size()).getSerialized();
        for (i = 0; i < tx.outputs.size(); i++)
            rval += tx.outputs[i].getSerialized();

        // witness
        rval += witness;

        // lock time
        rval += uint_to_vch(tx.lockTime, 2);

        cout << endl << "tx: " << rval.getHex() << endl;
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}

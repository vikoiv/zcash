#include <gtest/gtest.h>

#include "test/data/block_107401.h"
#include "test/data/block_107401_inputs.json.h"

#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "gtest/json_test_vectors.h"
#include "main.h"

#include <map>

// Fake the input of a given block
class FakeCoinsViewDB : public CCoinsView {
    std::map<uint256, CCoins> db;

public:
    FakeCoinsViewDB(UniValue& inputs) {
        for (auto i : inputs.getValues()) {
            CCoins newCoins;
            newCoins.nHeight = i["height"].get_int();
            newCoins.vout.resize(i["len"].get_int());
            for (auto o : i["vout"].get_array().getValues()) {
                auto arr = o.get_array();
                CTxOut txOut;
                txOut.nValue = arr[1].get_real();
                auto hex = ParseHex(arr[2].get_str());
                txOut.scriptPubKey = CScript(hex.begin(), hex.end());
                newCoins.vout[arr[0].get_int()] = txOut;
            }
            db.insert(std::pair<uint256, CCoins>(uint256S(i["txid"].get_str()), newCoins));
        }
    }

    bool GetAnchorAt(const uint256 &rt, ZCIncrementalMerkleTree &tree) const {
        return false;
    }

    bool GetNullifier(const uint256 &nf) const {
        return false;
    }

    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        coins = db.at(txid);
        return true;
    }

    bool HaveCoins(const uint256 &txid) const {
        return true;
    }

    uint256 GetBestBlock() const {
        uint256 a;
        return a;
    }

    uint256 GetBestAnchor() const {
        uint256 a;
        return a;
    }

    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashAnchor,
                    CAnchorsMap &mapAnchors,
                    CNullifiersMap &mapNullifiers) {
        return false;
    }

    bool GetStats(CCoinsStats &stats) const {
        return false;
    }
};

#define MAKE_STRING(x) std::string((x), (x)+sizeof(x))

TEST(ConnectBlock, LargeBlock) {
    // Test for issue 2017-05-01.a
    SelectParams(CBaseChainParams::MAIN);
    CBlock block;
    DecodeHexBlk(block, block_107401);

    // Fake its inputs
    UniValue block_inputs = read_json(MAKE_STRING(json_tests::block_107401_inputs));
    FakeCoinsViewDB fakeDB(block_inputs);
    CCoinsViewCache view(&fakeDB);

    // Fake the chain
    auto hashPrev = uint256S("000000000d21e0be050941f417800812396e0688be4ee85ef16aaf9c058f338c");
    CBlockIndex indexPrev;
    indexPrev.phashBlock = &hashPrev;
    CBlockIndex index(block);
    index.pprev = &indexPrev;
    index.nHeight = 107401;

    CValidationState state;
    EXPECT_TRUE(ConnectBlock(block, state, &index, view));
}
#include "volePSI/Paxos.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <iostream>
#include <vector>
#include <array>

using namespace osuCrypto;

struct ThreeBytes {
    std::array<uint8_t, 3> data;
    ThreeBytes operator^(const ThreeBytes& o) const { return {u8(data[0]^o.data[0]), u8(data[1]^o.data[1]), u8(data[2]^o.data[2])}; }
    ThreeBytes& operator^=(const ThreeBytes& o) { data[0]^=o.data[0]; data[1]^=o.data[1]; data[2]^=o.data[2]; return *this; }
    ThreeBytes operator&(const ThreeBytes& o) const { return {u8(data[0]&o.data[0]), u8(data[1]&o.data[1]), u8(data[2]&o.data[2])}; }
    bool operator==(const ThreeBytes& o) const { return data == o.data; }
    bool operator!=(const ThreeBytes& o) const { return !(*this == o); }
};

std::ostream& operator<<(std::ostream& os, const ThreeBytes& v) {
    return os << std::hex << (int)v.data[0] << " " << (int)v.data[1] << " " << (int)v.data[2] << std::dec;
}

template<typename IdxType, typename ValueType>
ValueType sparseDecode(volePSI::Paxos<IdxType>& paxos, const block& input,
                        span<const ValueType> sparseStorage, span<const ValueType> denseStorage)
{
    std::vector<IdxType> rows(paxos.mWeight);
    block denseHash;
    paxos.mHasher.hashBuildRow1(&input, rows.data(), &denseHash);

    ValueType val = sparseStorage[rows[0]];
    for (u64 j = 1; j < paxos.mWeight; ++j)
        val ^= sparseStorage[rows[j]];

    for (u64 i = 0; i < paxos.mDenseSize; ++i)
        if (*oc::BitIterator((u8*)&denseHash, i))
            val ^= denseStorage[i];

    return val;
}

int main()
{
    u64 n = 8;
    i64 delta = 2;
    u64 N = (2 * delta + 1) * n;
    block seed = toBlock(0, 0);
    PRNG prng(seed);

    std::vector<block> serverSet(n), keys(N);
    std::vector<ThreeBytes> vals(N), generatedShares(n);

    for (u64 i = 0; i < n; ++i) serverSet[i] = prng.get<block>();

    for (u64 i = 0; i < n; ++i)
    {
        block r = prng.get<block>();
        ThreeBytes share = { ((u8*)&r)[0], ((u8*)&r)[1], ((u8*)&r)[2] };
        generatedShares[i] = share;
        u64 x = serverSet[i].get<u64>(0);
        for (i64 j = 0; j < 2 * delta + 1; ++j) {
            u64 idx = (2 * delta + 1) * i + j;
            keys[idx] = toBlock(serverSet[i].get<u64>(1), (u64)((i64)x - delta + j));
            vals[idx] = share;
        }
    }

    volePSI::Paxos<u64> paxos;
    paxos.init(N, 3, 40, volePSI::PaxosParam::DenseType::Binary, seed);
    std::vector<ThreeBytes> storage(paxos.size());
    paxos.solve<ThreeBytes>(keys, vals, storage, &prng);

    span<const ThreeBytes> full(storage.data(), storage.size());
    span<const ThreeBytes> sparsePart(storage.data(), paxos.mSparseSize);
    span<const ThreeBytes> densePart(storage.data() + paxos.mSparseSize, paxos.mDenseSize);

    bool allOk = true;
    for (u64 i = 0; i < n; ++i) {
        for (i64 j = 0; j < 2 * delta + 1; ++j) {
            u64 idx = (2 * delta + 1) * i + j;

            ThreeBytes decodedStd;
            span<const block> in(&keys[idx], 1);
            span<ThreeBytes> out(&decodedStd, 1);
            paxos.decode<ThreeBytes>(in, out, full);

            ThreeBytes decodedSparse = sparseDecode<u64, ThreeBytes>(paxos, keys[idx], sparsePart, densePart);

            bool ok = (decodedStd == generatedShares[i]) && (decodedSparse == generatedShares[i]);
            if (!ok) allOk = false;

            std::cout << "point " << i << " (share=" << generatedShares[i] << ") | "
                      << "paxos.decode=" << decodedStd << " | sparseDecode=" << decodedSparse
                      << " -> " << (ok ? "OK" : "ECHEC") << "\n";
        }
    }

    std::cout << "\n" << (allOk ? "SUCCES : sparseDecode == paxos.decode() sur toutes les cles."
                                 : "ECHEC : divergence detectee.") << "\n";
    return 0;
}
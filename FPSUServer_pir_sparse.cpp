#include "volePSI/Paxos.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

extern "C" {
#include "libsimplepir.h"
}

using namespace osuCrypto;

struct ThreeBytes {
    std::array<uint8_t, 3> data;

    ThreeBytes operator^(const ThreeBytes& other) const {
        ThreeBytes result;
        result.data[0] = data[0] ^ other.data[0];
        result.data[1] = data[1] ^ other.data[1];
        result.data[2] = data[2] ^ other.data[2];
        return result;
    }

    ThreeBytes& operator^=(const ThreeBytes& other) {
        data[0] ^= other.data[0];
        data[1] ^= other.data[1];
        data[2] ^= other.data[2];
        return *this;
    }

    ThreeBytes operator&(const ThreeBytes& other) const {
        ThreeBytes result;
        result.data[0] = data[0] & other.data[0];
        result.data[1] = data[1] & other.data[1];
        result.data[2] = data[2] & other.data[2];
        return result;
    }

    bool operator==(const ThreeBytes& other) const { return data == other.data; }
    bool operator!=(const ThreeBytes& other) const { return !(*this == other); }
};

namespace {
    GoUint64 packThreeBytes(const ThreeBytes& value) {
        return (static_cast<GoUint64>(value.data[0]) << 16) |
               (static_cast<GoUint64>(value.data[1]) << 8) |
               static_cast<GoUint64>(value.data[2]);
    }

    ThreeBytes unpackThreeBytes(GoUint64 packed) {
        ThreeBytes value;
        value.data[0] = static_cast<uint8_t>((packed >> 16) & 0xff);
        value.data[1] = static_cast<uint8_t>((packed >> 8) & 0xff);
        value.data[2] = static_cast<uint8_t>(packed & 0xff);
        return value;
    }

    void printThreeBytes(const ThreeBytes& value) {
        std::cout << std::hex << std::setfill('0')
                  << std::setw(2) << static_cast<int>(value.data[0]) << " "
                  << std::setw(2) << static_cast<int>(value.data[1]) << " "
                  << std::setw(2) << static_cast<int>(value.data[2])
                  << std::dec;
    }

    template<typename IdxType>
    void printDenseSelection(
        volePSI::Paxos<IdxType>& paxos,
        const block& denseHash,
        u64 maxToPrint = 20)
    {
        u64 printed = 0;
        u64 total = 0;

        std::cout << "{";
        for (u64 i = 0; i < paxos.mDenseSize; ++i) {
            if (*oc::BitIterator((u8*)&denseHash, i)) {
                if (printed < maxToPrint) {
                    if (printed)
                        std::cout << ", ";
                    std::cout << i;
                    ++printed;
                }
                ++total;
            }
        }
        if (total > maxToPrint)
            std::cout << ", ...";
        std::cout << "} (" << total << " colonnes denses actives)\n";
    }

    void setupSparsePirServer(span<const ThreeBytes> sparseStorage) {
        std::vector<GoUint64> packed(sparseStorage.size());
        for (u64 i = 0; i < sparseStorage.size(); ++i)
            packed[i] = packThreeBytes(sparseStorage[i]);

        PIRServerSetupU64(1, packed.data(), static_cast<GoUint64>(packed.size()));
    }

    ThreeBytes pirReadSparseValue(u64 row) {
        if (row > static_cast<u64>(std::numeric_limits<int>::max()))
            throw std::runtime_error("PIR bridge target index exceeds int range");

        PIRClientQuery(static_cast<int>(row));
        PIRServerAnswer(1);
        return unpackThreeBytes(PIRClientExtractValue());
    }

    template<typename IdxType>
    ThreeBytes sparseDecodeWithPir(
        volePSI::Paxos<IdxType>& paxos,
        const block& input,
        span<const ThreeBytes> denseStorage)
    {
        if ((u64)denseStorage.size() != paxos.mDenseSize)
            throw RTE_LOC;

        std::vector<IdxType> rows(paxos.mWeight);
        block denseHash;
        paxos.mHasher.hashBuildRow1(&input, rows.data(), &denseHash);

        ThreeBytes val = pirReadSparseValue(rows[0]);
        for (u64 j = 1; j < paxos.mWeight; ++j)
            val ^= pirReadSparseValue(rows[j]);

        if (paxos.mDt != volePSI::PaxosParam::DenseType::Binary)
            throw std::runtime_error("sparseDecodeWithPir only supports Binary dense mode");

        for (u64 i = 0; i < paxos.mDenseSize; ++i) {
            if (*oc::BitIterator((u8*)&denseHash, i))
                val ^= denseStorage[i];
        }

        return val;
    }

    template<typename IdxType>
    void printTheoryWithPir(
        volePSI::Paxos<IdxType>& paxos,
        const block& input,
        span<const ThreeBytes> denseStorage)
    {
        std::vector<IdxType> rows(paxos.mWeight);
        block denseHash;
        paxos.mHasher.hashBuildRow1(&input, rows.data(), &denseHash);

        std::cout << "\n--- Inspection theorique avec PIR pour x_i ---\n";
        std::cout << "x_i = toBlock(tag=" << input.get<u64>(0)
                  << ", valeur=" << input.get<u64>(1) << ")\n";
        std::cout << "Ligne sparse theorique : 000...1...1...1...000 avec les 1 en ";
        for (u64 j = 0; j < paxos.mWeight; ++j) {
            if (j)
                std::cout << ", ";
            std::cout << "h" << (j + 1) << "(x_i)=" << rows[j];
        }
        std::cout << "\n";

        ThreeBytes sparseXor = pirReadSparseValue(rows[0]);
        std::cout << "Contributions sparse recuperees par PIR :\n";
        std::cout << "  PIR(L[" << rows[0] << "]) = ";
        printThreeBytes(sparseXor);
        std::cout << "\n";
        for (u64 j = 1; j < paxos.mWeight; ++j) {
            ThreeBytes v = pirReadSparseValue(rows[j]);
            sparseXor ^= v;
            std::cout << "  PIR(L[" << rows[j] << "]) = ";
            printThreeBytes(v);
            std::cout << "\n";
        }
        std::cout << "XOR sparse via PIR = ";
        printThreeBytes(sparseXor);
        std::cout << "\n";

        ThreeBytes denseXor{{{0, 0, 0}}};
        for (u64 i = 0; i < paxos.mDenseSize; ++i) {
            if (*oc::BitIterator((u8*)&denseHash, i))
                denseXor ^= denseStorage[i];
        }

        std::cout << "r(x_i) selectionne les colonnes denses ";
        printDenseSelection(paxos, denseHash);
        std::cout << "XOR dense local = ";
        printThreeBytes(denseXor);
        std::cout << "\n";
        std::cout << "Decode theorique PIR = XOR sparse via PIR ^ XOR dense local = ";
        printThreeBytes(sparseXor ^ denseXor);
        std::cout << "\n";
    }
}

int main()
{
    GlobalInitPIR();

    const u64 d = 2;
    const u64 n = 8;
    const i64 delta = 2;
    const u64 N = (2 * delta + 1) * n;

    block seed = toBlock(0, 0);
    PRNG prng(seed);

    std::cout << "Test sparse decode avec PIR interne sur la partie creuse\n";
    std::cout << "-------------------------------------------------------\n";

    std::vector<std::vector<block>> serverSets(d, std::vector<block>(n));
    std::vector<std::vector<block>> keys(d, std::vector<block>(N));
    std::vector<std::vector<ThreeBytes>> vals(d, std::vector<ThreeBytes>(N));

    for (u64 dim = 0; dim < d; ++dim) {
        for (u64 i = 0; i < n; ++i)
            serverSets[dim][i] = prng.get<block>();
    }

    for (u64 i = 0; i < n; ++i) {
        ThreeBytes share1{{{0xAA, 0xBB, 0xCC}}};
        ThreeBytes share2 = share1;

        u64 x1 = serverSets[0][i].get<u64>(0);
        u64 x2 = serverSets[1][i].get<u64>(0);

        for (i64 j = 0; j < 2 * delta + 1; ++j) {
            i64 offset = -delta + j;
            u64 idx = (2 * delta + 1) * i + j;

            keys[0][idx] = toBlock(serverSets[0][i].get<u64>(1), static_cast<u64>(static_cast<i64>(x1) + offset));
            keys[1][idx] = toBlock(serverSets[1][i].get<u64>(1), static_cast<u64>(static_cast<i64>(x2) + offset));
            vals[0][idx] = share1;
            vals[1][idx] = share2;
        }
    }

    volePSI::Paxos<u64> paxos;
    paxos.init(N, 3, 40, volePSI::PaxosParam::DenseType::Binary, seed);

    std::vector<std::vector<ThreeBytes>> storage(d, std::vector<ThreeBytes>(paxos.size()));

    auto startEncode = std::chrono::high_resolution_clock::now();
    paxos.solve<ThreeBytes>(keys[0], vals[0], storage[0], &prng);
    paxos.solve<ThreeBytes>(keys[1], vals[1], storage[1], &prng);
    auto endEncode = std::chrono::high_resolution_clock::now();

    double encodeMs = std::chrono::duration_cast<std::chrono::microseconds>(endEncode - startEncode).count() / 1000.0;
    std::cout << "Encode time = " << encodeMs << " ms\n";
    std::cout << "mSparseSize = " << paxos.mSparseSize
              << " | mDenseSize = " << paxos.mDenseSize
              << " | mWeight = " << paxos.mWeight << "\n";

    span<const ThreeBytes> sparsePart0(storage[0].data(), paxos.mSparseSize);
    span<const ThreeBytes> densePart0(storage[0].data() + paxos.mSparseSize, paxos.mDenseSize);

    std::cout << "\n--- Setup serveur PIR avec L = partie sparse seulement ---\n";
    setupSparsePirServer(sparsePart0);

    printTheoryWithPir<u64>(paxos, keys[0][0], densePart0);

    ThreeBytes decodedPir = sparseDecodeWithPir<u64>(paxos, keys[0][0], densePart0);

    ThreeBytes decodedStandard;
    span<const block> inputSpan(&keys[0][0], 1);
    span<ThreeBytes> outputSpan(&decodedStandard, 1);
    span<const ThreeBytes> tableSpan(storage[0].data(), storage[0].size());
    paxos.decode<ThreeBytes>(inputSpan, outputSpan, tableSpan);

    std::cout << "\nDecode standard = ";
    printThreeBytes(decodedStandard);
    std::cout << "\nDecode PIR sparse = ";
    printThreeBytes(decodedPir);
    std::cout << "\n";

    std::cout << (decodedPir == decodedStandard
                  ? "OK : PIR sparse coherent avec paxos.decode().\n"
                  : "ECHEC : PIR sparse diverge de paxos.decode().\n");

    bool allOk = true;
    for (u64 i = 0; i < N; ++i) {
        ThreeBytes got = sparseDecodeWithPir<u64>(paxos, keys[0][i], densePart0);
        if (got != vals[0][i])
            allOk = false;
    }

    std::cout << (allOk ? "OK" : "ECHEC")
              << " : sparseDecodeWithPir reconstruit les " << N
              << " valeurs de la dimension 0.\n";

    std::cout << "\nTest termine.\n";
    return allOk && decodedPir == decodedStandard ? 0 : 1;
}

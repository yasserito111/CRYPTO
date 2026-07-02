#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <bicycl.hpp>

#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <array>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <algorithm>

using namespace osuCrypto;

constexpr size_t kMaxValueBytes = 4096;
constexpr size_t kMaxValueBlocks = kMaxValueBytes / sizeof(block);
using ValueType = std::array<block, kMaxValueBlocks>;

namespace osuCrypto {
    using ValueTypeAlias = ::ValueType;
    ValueTypeAlias operator^(const ValueTypeAlias& a, const ValueTypeAlias& b);
    ValueTypeAlias operator&(const ValueTypeAlias& a, const ValueTypeAlias& b);
}

#include "volePSI/Paxos.h"

// --------------------------------------------------
// Opérateurs requis par Paxos sur ValueType
// --------------------------------------------------
namespace osuCrypto {
    ValueType operator^(const ValueType& a, const ValueType& b) {
        ValueType result;
        for (size_t i = 0; i < result.size(); ++i)
            result[i] = a[i] ^ b[i];
        return result;
    }

    ValueType& operator^=(ValueType& a, const ValueType& b) {
        for (size_t i = 0; i < a.size(); ++i)
            a[i] = a[i] ^ b[i];
        return a;
    }

    ValueType operator&(const ValueType& a, const ValueType& b) {
        ValueType result;
        for (size_t i = 0; i < result.size(); ++i)
            result[i] = a[i] & b[i];
        return result;
    }
}

std::ostream& operator<<(std::ostream& os, const ValueType& v) {
    for (const auto& blk : v)
        os << blk << " ";
    return os;
}

// --------------------------------------------------
// Vérifie si un ValueType est tout à zéro
// --------------------------------------------------
bool is_zero_valuetype(const ValueType& v) {
    for (const auto& b : v)
        if (b != ZeroBlock) return false;
    return true;
}

// --------------------------------------------------
// Sérialisation compacte CipherText <-> ValueType
// --------------------------------------------------
namespace {
    void append_u32(std::vector<unsigned char>& out, std::uint32_t v) {
        out.push_back(static_cast<unsigned char>((v >> 24) & 0xff));
        out.push_back(static_cast<unsigned char>((v >> 16) & 0xff));
        out.push_back(static_cast<unsigned char>((v >> 8) & 0xff));
        out.push_back(static_cast<unsigned char>(v & 0xff));
    }

    std::uint32_t read_u32(const std::vector<unsigned char>& data, size_t& offset) {
        if (offset + 4 > data.size()) {
            throw std::runtime_error("Invalid serialized payload length");
        }
        std::uint32_t value = 0;
        value |= static_cast<std::uint32_t>(data[offset++]) << 24;
        value |= static_cast<std::uint32_t>(data[offset++]) << 16;
        value |= static_cast<std::uint32_t>(data[offset++]) << 8;
        value |= static_cast<std::uint32_t>(data[offset++]);
        return value;
    }

    std::vector<unsigned char> encode_mpz(const BICYCL::Mpz& value) {
        std::vector<unsigned char> abs_bytes = static_cast<std::vector<unsigned char>>(value);
        std::vector<unsigned char> out;
        out.reserve(1 + 4 + abs_bytes.size());
        if (value.sgn() < 0) {
            out.push_back(0x01);
        } else if (value.sgn() > 0) {
            out.push_back(0x00);
        } else {
            out.push_back(0x02);
        }
        append_u32(out, static_cast<std::uint32_t>(abs_bytes.size()));
        out.insert(out.end(), abs_bytes.begin(), abs_bytes.end());
        return out;
    }

    BICYCL::Mpz decode_mpz(const std::vector<unsigned char>& data, size_t& offset) {
        if (offset >= data.size()) {
            throw std::runtime_error("Unexpected end of serialized ciphertext");
        }
        const unsigned char marker = data[offset++];
        const std::uint32_t len = read_u32(data, offset);
        if (offset + len > data.size()) {
            throw std::runtime_error("Serialized coefficient is truncated");
        }

        std::vector<unsigned char> bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;

        if (marker == 0x02) {
            return BICYCL::Mpz(0ul);
        }

        BICYCL::Mpz value(bytes);
        if (marker == 0x01) {
            value.neg();
        }
        return value;
    }

    std::vector<unsigned char> encode_qfi(const BICYCL::QFI& qfi) {
        std::vector<unsigned char> out;
        std::vector<unsigned char> a_bytes = encode_mpz(qfi.a());
        std::vector<unsigned char> b_bytes = encode_mpz(qfi.b());
        std::vector<unsigned char> c_bytes = encode_mpz(qfi.c());
        out.insert(out.end(), a_bytes.begin(), a_bytes.end());
        out.insert(out.end(), b_bytes.begin(), b_bytes.end());
        out.insert(out.end(), c_bytes.begin(), c_bytes.end());
        return out;
    }

    BICYCL::QFI decode_qfi(const std::vector<unsigned char>& data, size_t& offset) {
        BICYCL::Mpz a = decode_mpz(data, offset);
        BICYCL::Mpz b = decode_mpz(data, offset);
        BICYCL::Mpz c = decode_mpz(data, offset);
        return BICYCL::QFI(a, b, c);
    }
}

void ciphertext_to_valuetype(const BICYCL::CL_HSMqk::CipherText& ct, ValueType& out)
{
    std::vector<unsigned char> payload;
    std::vector<unsigned char> c1_bytes = encode_qfi(ct.c1());
    std::vector<unsigned char> c2_bytes = encode_qfi(ct.c2());
    payload.insert(payload.end(), c1_bytes.begin(), c1_bytes.end());
    payload.insert(payload.end(), c2_bytes.begin(), c2_bytes.end());

    std::fill(out.begin(), out.end(), ZeroBlock);
    std::uint32_t payload_len = static_cast<std::uint32_t>(payload.size());
    const size_t header_size = sizeof(payload_len);
    if (header_size + payload.size() > kMaxValueBytes) {
        throw std::runtime_error("Serialized ciphertext is larger than the fixed ValueType capacity");
    }

    std::memcpy(out.data(), &payload_len, header_size);
    std::memcpy(reinterpret_cast<unsigned char*>(out.data()) + header_size, payload.data(), payload.size());
}

BICYCL::CL_HSMqk::CipherText valuetype_to_ciphertext(
    const BICYCL::CL_HSMqk& crypto_system,
    const ValueType& vt)
{
    const size_t bytes_capacity = sizeof(ValueType);
    const unsigned char* raw = reinterpret_cast<const unsigned char*>(vt.data());
    if (bytes_capacity < sizeof(std::uint32_t)) {
        throw std::runtime_error("ValueType is too small for serialization");
    }

    std::uint32_t payload_len = 0;
    std::memcpy(&payload_len, raw, sizeof(payload_len));
    if (payload_len > bytes_capacity - sizeof(payload_len)) {
        throw std::runtime_error("Serialized ciphertext is larger than the ValueType buffer");
    }

    std::vector<unsigned char> payload(raw + sizeof(payload_len), raw + sizeof(payload_len) + payload_len);
    size_t offset = 0;
    BICYCL::QFI c1 = decode_qfi(payload, offset);
    BICYCL::QFI c2 = decode_qfi(payload, offset);
    return BICYCL::CL_HSMqk::CipherText(c1, c2);
}

// --------------------------------------------------
// Main
// --------------------------------------------------
int main()
{
    try {
        // 1. Init BICYCL
        BICYCL::RandGen randgen;
        BICYCL::Mpz q;
        q = (unsigned long)65537;

        size_t k = 1;
        size_t DeltaK_nbits = 1024;
        BICYCL::CL_HSMqk crypto_system(q, k, DeltaK_nbits, randgen);
        BICYCL::CL_HSMqk::SecretKey secret_key = crypto_system.keygen(randgen);
        BICYCL::CL_HSMqk::PublicKey  public_key = crypto_system.keygen(secret_key);

        // 2. Paramètres Paxos
        u64 n = 8;
        u64 m = 5;
        i64 delta = 2;
        u64 N = (2 * delta + 1) * n;
        block seed = toBlock(0, 0);
        PRNG prng(seed);

        std::vector<block>     serverSet1(n), serverSet2(n);
        std::vector<block>     keys1(N),      keys2(N);
        std::vector<ValueType> vals1(N),       vals2(N);

        for (u64 i = 0; i < n; ++i) {
            serverSet1[i] = prng.get<block>();
            serverSet2[i] = prng.get<block>();
        }

        // 3. Chiffrement et remplissage (share1 + share2 = 0 mod q)
        for (u64 i = 0; i < n; ++i)
        {
            block clear_share1 = prng.get<block>();

            BICYCL::Mpz m1_mpz(clear_share1.get<u64>(0) % 65537UL);

            // m2 = q - m1  =>  m1 + m2 ≡ 0 mod q
            BICYCL::Mpz m2_mpz;
            if (m1_mpz == BICYCL::Mpz(0ul))
                m2_mpz = BICYCL::Mpz(0ul);
            else
                BICYCL::Mpz::sub(m2_mpz, q, m1_mpz);

            BICYCL::CL_HSMqk::ClearText m1(crypto_system, m1_mpz);
            BICYCL::CL_HSMqk::ClearText m2(crypto_system, m2_mpz);

            BICYCL::CL_HSMqk::CipherText cipher1 = crypto_system.encrypt(public_key, m1, randgen);
            BICYCL::CL_HSMqk::CipherText cipher2 = crypto_system.encrypt(public_key, m2, randgen);

            ValueType share1_encoded, share2_encoded;
            ciphertext_to_valuetype(cipher1, share1_encoded);
            ciphertext_to_valuetype(cipher2, share2_encoded);

            u64 x1 = serverSet1[i].get<u64>(0);
            u64 x2 = serverSet2[i].get<u64>(0);

            for (i64 j = 0; j < 2 * delta + 1; ++j)
            {
                i64 offset = -delta + j;
                keys1[(2*delta+1)*i + j] = toBlock(serverSet1[i].get<u64>(1),
                                                   static_cast<u64>(static_cast<i64>(x1) + offset));
                keys2[(2*delta+1)*i + j] = toBlock(serverSet2[i].get<u64>(1),
                                                   static_cast<u64>(static_cast<i64>(x2) + offset));
                vals1[(2*delta+1)*i + j] = share1_encoded;
                vals2[(2*delta+1)*i + j] = share2_encoded;
            }
        }

        // 4. Encodage Paxos OKVS
        volePSI::Paxos<u64> paxos;
        paxos.init(N, 3, 40, volePSI::PaxosParam::DenseType::Binary, seed);

        std::vector<ValueType> storage1(paxos.size()), storage2(paxos.size());
        paxos.solve<ValueType>(keys2, vals2, storage2, &prng);
        paxos.solve<ValueType>(keys1, vals1, storage1, &prng);

        std::cout << "Paxos OKVS encoded successfully\n";

        // 5. Décodage (CORRECTION des correspondances de clés pour le test)
        std::vector<block>     clientSet1(m), clientSet2(m);
        std::vector<ValueType> decoded1(m),   decoded2(m);

        // Cas indices 0 et 1 : Clés valides ET synchronisées (génèrent un succès)
        clientSet1[0] = keys1[0]; 
        clientSet2[0] = keys2[0];
        
        clientSet1[1] = keys1[5]; 
        clientSet2[1] = keys2[5];

        // Cas indice 2 : Clés valides mais NON synchronisées entre Jeu 1 et Jeu 2 (génère un échec d'addition)
        clientSet1[2] = keys1[10];
        clientSet2[2] = keys2[15];

        // Cas indices 3 et 4 : Clés complètement hors de l'OKVS (génèrent du bruit/exception gérée)
        for (u64 i = 3; i < m; ++i) {
            clientSet1[i] = prng.get<block>();
            clientSet2[i] = prng.get<block>();
        }

        auto startDecode = std::chrono::high_resolution_clock::now();
        paxos.decode<ValueType>(clientSet1, decoded1, storage1);
        paxos.decode<ValueType>(clientSet2, decoded2, storage2);
        auto endDecode = std::chrono::high_resolution_clock::now();

        double decodeMs = std::chrono::duration_cast<std::chrono::microseconds>(
                              endDecode - startDecode).count() / 1000.0;
        std::cout << "decode time = " << decodeMs << " ms\n";

        // 6. Reconstruction homomorphe et vérification
        for (u64 i = 0; i < m; ++i)
        {
            bool found = false;
            try {
                BICYCL::CL_HSMqk::CipherText c1 = valuetype_to_ciphertext(crypto_system, decoded1[i]);
                BICYCL::CL_HSMqk::CipherText c2 = valuetype_to_ciphertext(crypto_system, decoded2[i]);

                BICYCL::CL_HSMqk::CipherText c_sum =
                    crypto_system.add_ciphertexts(public_key, c1, c2, randgen);

                BICYCL::CL_HSMqk::ClearText decrypted_sum = crypto_system.decrypt(secret_key, c_sum);

                BICYCL::Mpz zero(0ul);
                found = (decrypted_sum == zero);
            } catch (const std::exception&) {
                found = false;
            }

            if (found)
                std::cout << "decode successed:  The server already has the number " << i << "\n";
            else
                std::cout << "decode failed: The server does not have the number value " << i << "\n";
        }

        std::cout << "decode success" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
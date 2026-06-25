#include "volePSI/Paxos.h"
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

using namespace osuCrypto;

using ValueType = std::array<block, 37>;

// --------------------------------------------------
// Opérateurs requis par Paxos sur ValueType
// --------------------------------------------------
namespace osuCrypto {
    ValueType operator^(const ValueType& a, const ValueType& b) {
        ValueType result;
        for (size_t i = 0; i < 37; ++i)
            result[i] = a[i] ^ b[i];
        return result;
    }

    ValueType& operator^=(ValueType& a, const ValueType& b) {
        for (size_t i = 0; i < 37; ++i)
            a[i] = a[i] ^ b[i];
        return a;
    }

    ValueType operator&(const ValueType& a, const ValueType& b) {
        ValueType result;
        for (size_t i = 0; i < 37; ++i)
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
// Sérialisation QFI <-> string
// --------------------------------------------------
std::string qfi_to_string(const BICYCL::QFI& qfi) {
    std::ostringstream ss;
    ss << qfi.a() << " " << qfi.b() << " " << qfi.c();
    return ss.str();
}

BICYCL::QFI string_to_qfi(const std::string& str) {
    std::istringstream ss(str);
    std::string a_str, b_str, c_str;
    ss >> a_str >> b_str >> c_str;
    BICYCL::Mpz a(a_str), b(b_str), c(c_str);
    return BICYCL::QFI(a, b, c);
}

// --------------------------------------------------
// Sérialisation CipherText <-> ValueType
// --------------------------------------------------
void ciphertext_to_valuetype(const BICYCL::CL_HSMqk::CipherText& ct, ValueType& out)
{
    std::string combined = qfi_to_string(ct.c1()) + " | " + qfi_to_string(ct.c2());
    std::fill(out.begin(), out.end(), ZeroBlock);
    size_t copy_size = std::min(combined.size(), sizeof(ValueType));
    std::memcpy(out.data(), combined.data(), copy_size);
}

BICYCL::CL_HSMqk::CipherText valuetype_to_ciphertext(
    const BICYCL::CL_HSMqk& crypto_system,
    const ValueType& vt)
{
    std::string str(reinterpret_cast<const char*>(vt.data()), sizeof(ValueType));
    str.resize(strnlen(str.data(), sizeof(ValueType)));

    size_t pos = str.find('|');
    if (pos == std::string::npos)
        throw std::runtime_error("Invalid ciphertext format");

    std::string q1_str = str.substr(0, pos);
    std::string q2_str = str.substr(pos + 1);

    // Trim espaces
    auto trim = [](std::string& s) {
        s.erase(0, s.find_first_not_of(" \t"));
        s.erase(s.find_last_not_of(" \t") + 1);
    };
    trim(q1_str); trim(q2_str);

    return BICYCL::CL_HSMqk::CipherText(string_to_qfi(q1_str), string_to_qfi(q2_str));
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

        // 5. Décodage
        std::vector<block>     clientSet1(m), clientSet2(m);
        std::vector<ValueType> decoded1(m),   decoded2(m);

        clientSet1[0] = keys1[3];
        clientSet2[0] = keys2[0];
        for (u64 i = 1; i < m; ++i) {
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
            // Si la clé était absente de l'OKVS, le décodé est tout zéro
            if (is_zero_valuetype(decoded1[i]) || is_zero_valuetype(decoded2[i])) {
                std::cout << "decode failed:  The server does not have the number value " << i << "\n";
                continue;
            }

            try {
                BICYCL::CL_HSMqk::CipherText c1 = valuetype_to_ciphertext(crypto_system, decoded1[i]);
                BICYCL::CL_HSMqk::CipherText c2 = valuetype_to_ciphertext(crypto_system, decoded2[i]);

                BICYCL::CL_HSMqk::CipherText c_sum =
                    crypto_system.add_ciphertexts(public_key, c1, c2, randgen);

                BICYCL::CL_HSMqk::ClearText decrypted_sum = crypto_system.decrypt(secret_key, c_sum);

                BICYCL::Mpz zero;
                zero = 0ul;
                if (decrypted_sum == zero)
                    std::cout << "decode successed: The server already has the number " << i << "\n";
                else
                    std::cout << "decode failed:  The server does not have the number value " << i << "\n";

            } catch (const std::exception& e) {
                std::cout << "decode failed:  The server does not have the number value " << i
                          << " (" << e.what() << ")\n";
            }
        }

        std::cout << "decode success\n";

        // 7. Affichage keys/vals (comme la version sans BICYCL)
        std::cout << "================Keys1=================\n";
        for (u64 i = 0; i < N; ++i)
            std::cout << keys1[i] << " ";
        std::cout << "\n";

        std::cout << "================Vals1=================\n";
        for (u64 i = 0; i < N; ++i)
            std::cout << vals1[i] << "\n";

        std::cout << "================Keys2=================\n";
        for (u64 i = 0; i < N; ++i)
            std::cout << keys2[i] << " ";
        std::cout << "\n";

        std::cout << "================Vals2=================\n";
        for (u64 i = 0; i < N; ++i)
            std::cout << vals2[i] << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
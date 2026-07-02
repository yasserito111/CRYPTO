#include "volePSI/Paxos.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <iostream>
#include <vector>
#include <chrono>
#include <string>

using namespace osuCrypto;

int main()
{
    using ValueType = block;

    // Retour aux 5 valeurs précises de n (de 8 à 10000)
    std::vector<u64> n_values = {8, 64, 256, 1024, 10000};
    u64 m = 5;
    i64 delta = 2; 
    
    // Définition de la dimension d (d serveurs/clés/sets)
    const u64 d = 3; 

    block seed = toBlock(0, 0);
    PRNG prng(seed);

    std::cout << "Prise en compte de " << d << " dimensions (d=" << d << ")\n";
    std::cout << "--------------------------------------------------------\n";

    for (u64 n : n_values)
    {
        u64 N = (2 * delta + 1) * n;
        std::cout << "\n--- Test avec n = " << n << " | N = " << N << " ---\n";

        // Déclaration des structures de données indexées par la dimension (taille d)
        std::vector<std::vector<block>> serverSets(d, std::vector<block>(n));
        std::vector<std::vector<block>> keys(d, std::vector<block>(N));
        std::vector<std::vector<ValueType>> vals(d, std::vector<ValueType>(N));

        // Génération des ensembles de serveurs pour chaque dimension
        for (u64 dim = 0; dim < d; ++dim)
        {
            for (u64 i = 0; i < n; ++i)
            {
                serverSets[dim][i] = prng.get<block>();
            }
        }

        // Construction des clés et des partages (shares) pour chaque dimension
        for (u64 i = 0; i < n; ++i)
        {
            std::vector<block> shares(d);
            block sum = ZeroBlock;
            
            // Génération des d-1 premiers partages aléatoirement
            for (u64 dim = 0; dim < d - 1; ++dim)
            {
                shares[dim] = prng.get<block>();
                sum = sum ^ shares[dim];
            }
            // Le dernier partage sécurise l'équation (somme XOR = ZeroBlock)
            shares[d - 1] = sum;

            // Application du décalage (offset) pour chaque dimension
            for (u64 dim = 0; dim < d; ++dim)
            {
                u64 x = serverSets[dim][i].get<u64>(0);

                for (i64 j = 0; j < 2 * delta + 1; ++j)
                {
                    i64 offset = -delta + j;
                    u64 idx = (2 * delta + 1) * i + j;

                    keys[dim][idx] = toBlock(
                        serverSets[dim][i].get<u64>(1),
                        static_cast<u64>(static_cast<i64>(x) + offset)
                    );

                    vals[dim][idx] = shares[dim];
                }
            }
        }

        // Initialisation de Paxos OKVS
        volePSI::Paxos<u64> paxos;
        paxos.init(N, 3, 40, volePSI::PaxosParam::DenseType::Binary, seed);

        // Encodage (Solve) pour chaque dimension
        std::vector<std::vector<ValueType>> storage(d, std::vector<ValueType>(paxos.size()));
        
        auto startEncode = std::chrono::high_resolution_clock::now();
        for (u64 dim = 0; dim < d; ++dim)
        {
            paxos.solve<ValueType>(keys[dim], vals[dim], storage[dim], &prng);
        }
        auto endEncode = std::chrono::high_resolution_clock::now();
        
        double encodeMs = std::chrono::duration_cast<std::chrono::microseconds>(endEncode - startEncode).count() / 1000.0;
        std::cout << "Encode time (" << d << " dimensions) = " << encodeMs << " ms\n";

        // Décodage (Decode)
        std::vector<std::vector<block>> clientSets(d, std::vector<block>(m));
        std::vector<std::vector<ValueType>> decoded(d, std::vector<ValueType>(m));

        for (u64 dim = 0; dim < d; ++dim)
        {
            // On force la correspondance sur l'index 0 pour avoir le "successed"
            if (dim == 0)
                clientSets[dim][0] = keys[dim][3]; 
            else
                clientSets[dim][0] = keys[dim][0];

            for (u64 i = 1; i < m; ++i)
            {
                clientSets[dim][i] = prng.get<block>();
            }
        }

        auto startDecode = std::chrono::high_resolution_clock::now();
        for (u64 dim = 0; dim < d; ++dim)
        {
            paxos.decode<ValueType>(clientSets[dim], decoded[dim], storage[dim]);
        }
        auto endDecode = std::chrono::high_resolution_clock::now();

        double decodeMs = std::chrono::duration_cast<std::chrono::microseconds>(endDecode - startDecode).count() / 1000.0;
        std::cout << "decode time = " << decodeMs << " ms\n";

        // Affichage des statuts au format strict
        for (u64 i = 0; i < m; ++i)
        {
            block checkXor = ZeroBlock;
            for (u64 dim = 0; dim < d; ++dim)
            {
                checkXor = checkXor ^ decoded[dim][i];
            }

            if (neq(checkXor, ZeroBlock))
            {
                std::cout << "decode failed: The server does not have the number value " << i << "\n";
            }
            else
            {
                std::cout << "decode successed:  The server already has the number " << i << "\n";
            }
        }
        
        std::cout << "decode success" << std::endl;

        // --- SECTION : AFFICHAGE DYNAMIQUE UNIQUE POUR N=8 ---
        if (n == 8)
        {
            for (u64 dim = 0; dim < d; ++dim)
            {
                std::cout << "================Keys" << (dim + 1) << "=================\n";
                for (u64 i = 0; i < N; ++i)
                {
                    std::cout << keys[dim][i] << " ";
                }
                std::cout << "\n";

                std::cout << "================Vals" << (dim + 1) << "=================\n";
                for (u64 i = 0; i < N; ++i)
                {
                    std::cout << vals[dim][i] << " ";
                }
                std::cout << "\n";
            }
        }
    }

    return 0;
}
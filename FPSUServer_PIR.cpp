#include "volePSI/Paxos.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <iostream>
#include <vector>
#include <chrono>
#include <string>

// --- PASSERELLE SIMPLEPIR ---
extern "C" {
    #include "libsimplepir.h"
}

using namespace osuCrypto;

int main()
{
    // Initialisation globale de SimplePIR
    GlobalInitPIR();

    using ValueType = block;

    // Paramètres fixes avec d = 2 dimensions
    const u64 d = 2; 
    u64 n = 8;
    u64 m = 5;
    i64 delta = 2;
    u64 N = (2 * delta + 1) * n;

    block seed = toBlock(0, 0);
    PRNG prng(seed);

    std::cout << "Prise en compte de " << d << " dimensions (d=" << d << ")\n";
    std::cout << "--------------------------------------------------------\n";

    // Structures de données pour d = 2 dimensions
    std::vector<std::vector<block>> serverSets(d, std::vector<block>(n));
    std::vector<std::vector<block>> keys(d, std::vector<block>(N));
    std::vector<std::vector<ValueType>> vals(d, std::vector<ValueType>(N));

    for (u64 dim = 0; dim < d; ++dim) {
        for (u64 i = 0; i < n; ++i) {
            serverSets[dim][i] = prng.get<block>();
        }
    }

    // Génération des paires de partages et construction des clés/valeurs
    for (u64 i = 0; i < n; ++i)
    { 
        block share1 = prng.get<block>();
        block share2 = share1; // share1 ^ share2 = ZeroBlock

        u64 x1 = serverSets[0][i].get<u64>(0);
        u64 x2 = serverSets[1][i].get<u64>(0);

        for (i64 j = 0; j < 2 * delta + 1; ++j)
        {
            i64 offset = -delta + j;
            u64 idx = (2 * delta + 1) * i + j;

            keys[0][idx] = toBlock(serverSets[0][i].get<u64>(1), static_cast<u64>(static_cast<i64>(x1) + offset));
            keys[1][idx] = toBlock(serverSets[1][i].get<u64>(1), static_cast<u64>(static_cast<i64>(x2) + offset));

            vals[0][idx] = share1;
            vals[1][idx] = share2;
        }
    }

    // Initialisation Paxos OKVS
    volePSI::Paxos<u64> paxos;
    paxos.init(N, 3, 40, volePSI::PaxosParam::DenseType::Binary, seed);

    std::vector<std::vector<ValueType>> storage(d, std::vector<ValueType>(paxos.size()));

    // Encodage (Solve)
    auto startEncode = std::chrono::high_resolution_clock::now();
    paxos.solve<ValueType>(keys[0], vals[0], storage[0], &prng);
    paxos.solve<ValueType>(keys[1], vals[1], storage[1], &prng);
    auto endEncode = std::chrono::high_resolution_clock::now();

    double encodeMs = std::chrono::duration_cast<std::chrono::microseconds>(endEncode - startEncode).count() / 1000.0;
    std::cout << "Encode time (" << d << " dimensions) = " << encodeMs << " ms\n";
    std::cout << "Paxos OKVS encoded successfully\n";

    // =========================================================================
    // ÉTAPE PIR SERVEURS : Setup de la DB sous forme de matrice PIR
    // =========================================================================
    std::cout << "\n--- [ÉCHANGE PIR] PHASE : SETUP SERVEURS ---\n";
    PIRServerSetup(1, storage[0].size());
    PIRServerSetup(2, storage[1].size());

    // Définition des requêtes du client
    std::vector<std::vector<block>> clientSets(d, std::vector<block>(m));
    std::vector<std::vector<ValueType>> decoded(d, std::vector<ValueType>(m));

    clientSets[0][0] = keys[0][3]; // Match forcé à l'index 0
    clientSets[1][0] = keys[1][0];    

    for (u64 i = 1; i < m; ++i) {
        clientSets[0][i] = prng.get<block>();
        clientSets[1][i] = prng.get<block>();    
    }

    // =========================================================================
    // ÉTAPE PIR CLIENT & SERVEUR : Simulation de la transaction PIR pour l'élément 0
    // =========================================================================
    std::cout << "\n--- [ÉCHANGE PIR] PHASE : TRANSACTION EN LIGNE (Exemple Index 0) ---\n";
    int indexCible = 3; // Le client veut récupérer l'élément à l'index 3 en cachette
    PIRClientQuery(indexCible); 
    PIRServerAnswer(1);
    PIRServerAnswer(2);
    PIRClientExtract();
    std::cout << "--------------------------------------------------------\n\n";

    // Décodage classique local (pour la mesure du temps et vérification)
    auto startDecode = std::chrono::high_resolution_clock::now();
    paxos.decode<ValueType>(clientSets[0], decoded[0], storage[0]);
    paxos.decode<ValueType>(clientSets[1], decoded[1], storage[1]);
    auto endDecode = std::chrono::high_resolution_clock::now();

    double decodeMs = std::chrono::duration_cast<std::chrono::microseconds>(endDecode - startDecode).count() / 1000.0;
    std::cout << "decode time = " << decodeMs << " ms\n";

    // Vérification des résultats
    for (u64 i = 0; i < m; ++i)
    {
        if (neq(decoded[0][i] ^ decoded[1][i], ZeroBlock)) {
            std::cout << "decode failed: The server does not have the number value " << i << "\n";
        } else {
            std::cout << "decode successed:  The server already has the number " << i << "\n";
        }
    }

    std::cout << "decode success" << std::endl;

    return 0;
}
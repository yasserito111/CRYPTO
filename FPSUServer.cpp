#include "volePSI/Paxos.h"

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <iostream>
#include <vector>
#include <chrono>
#include <string>

using namespace osuCrypto;

// --------------------------------------------------
// Fonction de hash string -> block
// --------------------------------------------------

block hashString(const std::string& s)
{
    std::hash<std::string> h;

    u64 x = h(s);

    return toBlock(x, 0);
}

// --------------------------------------------------
// Main
// --------------------------------------------------

int main()
{
    using ValueType = block;
// ValueType peut être constitué de plusieurs blocks :  ValueType = Value256; peut fonctionner et double la taille de storage également
// sinon on peut tester ValueType = std::array<block, 2>; et dans ce cas vals[i][0] = prng.get<block>(); et
//vals[i][1] = prng.get<block>(); par exemple



    u64 n = 8;
 u64 m = 5;

	i64 delta=2;
	u64 N=(2*delta+1)*n;
    block seed = toBlock(0, 0);
// block seed = sysRandomSeed();
    PRNG prng(seed);
 std::vector<block> serverSet1(n);
std::vector<block> serverSet2(n);

    std::vector<block> keys1(N);
    std::vector<ValueType> vals1(N);
   std::vector<block> keys2(N);
    std::vector<ValueType> vals2(N);


 for (u64 i = 0; i < n; ++i)
    {

        serverSet1[i] = prng.get<block>();
 	serverSet2[i] = prng.get<block>();    
}

   block share1;
   block share2; 

    // Construction des clés, génération pour tout i d'une paire share1 et share2 telle que share1+share2=0
// Puis construction des valeurs associées aux clés IL FAUT LES CHIFFRER
    for (u64 i = 0; i < n; ++i)
    { 
	 share1= prng.get<block>(); //A chiffrer
	 share2=share1; //A chiffrer
u64 x1 = serverSet1[i].get<u64>(0);
u64 x2 = serverSet2[i].get<u64>(0);

	for (i64 j = 0; j < 2*delta+1; ++j)
	{

	i64 offset = -delta + j;
 	// std::cout << "(2*delta+1)*i+j"<<(2*delta+1)*i+j <<"\n";

	keys1[(2*delta+1)*i+j] =
    	toBlock(serverSet1[i].get<u64>(1),
        static_cast<u64>(
            static_cast<i64>(x1) + offset
        )
   	 );

	keys2[(2*delta+1)*i+j] =
   	 toBlock(serverSet2[i].get<u64>(1),
        static_cast<u64>(
            static_cast<i64>(x2) + offset
        )
    );

       // keys1[(2*delta+1)*i+j] = serverSet1[i]^toBlock((i64)(-delta+j),0);
	// keys2[(2*delta+1)*i+j] = serverSet2[i]^toBlock((i64)(-delta+j),0);

	vals1[(2*delta+1)*i+j]=share1;
	vals2[(2*delta+1)*i+j]=share2;

	}
}
 

    volePSI::Paxos<u64> paxos;

    paxos.init(
        N,
        3,
        40,
        volePSI::PaxosParam::DenseType::Binary,
        seed
    );

    std::vector<ValueType> storage2(
        paxos.size()
    );

    paxos.solve<ValueType>(
        keys2,
        vals2,
        storage2,
        &prng
    );
 std::vector<ValueType> storage1(
        paxos.size()
    );

    paxos.solve<ValueType>(
        keys1,
        vals1,
        storage1,
        &prng
    );

    std::cout << "Paxos OKVS encoded successfully\n";
//=============================================================
//==========================================================
 std::vector<block> clientSet1(m);
std::vector<block> clientSet2(m);
 std::vector<ValueType> decoded1(m);
 std::vector<ValueType> decoded2(m);
	clientSet1[0] = keys1[3];
 	clientSet2[0] = keys2[0];    
for (u64 i = 1; i < m; ++i)
    {

        clientSet1[i] = prng.get<block>();
 	clientSet2[i] = prng.get<block>();    
}

auto startDecode = std::chrono::high_resolution_clock::now();
    paxos.decode<ValueType>(
        clientSet1,
        decoded1,
        storage1
    );
    paxos.decode<ValueType>(
        clientSet2,
        decoded2,
        storage2
    );

auto endDecode = std::chrono::high_resolution_clock::now();

double decodeMs =
    std::chrono::duration_cast<std::chrono::microseconds>(
        endDecode - startDecode).count() / 1000.0;

std::cout << "decode time = " << decodeMs << " ms\n";


 for (u64 i = 0; i < m; ++i)
    {
        if (neq(decoded1[i]^decoded2[i],ZeroBlock))
        {
            std::cout << "decode failed: The server does not have the number value "
                      << i << "\n";

        }
	else { std::cout << "decode successed:  The server already has the number "
                      << i << "\n";

}
    }

    std::cout << "decode success" << std::endl;





std::cout << "================Keys1=================\n";

  for (u64 i = 0; i < N; ++i)
    {
        std::cout << keys1[i] << " ";
}
    std::cout << "\n";
 std::cout << "================Vals1=================\n";

 for (u64 i = 0; i < N; ++i)
    {
        std::cout << vals1[i] << " ";
}
    std::cout << "\n";
std::cout << "================Keys2=================\n";

  for (u64 i = 0; i < N; ++i)
    {
        std::cout << keys2[i] << " ";
}
    std::cout << "\n";
 std::cout << "================Vals2=================\n";

 for (u64 i = 0; i < N; ++i)
    {
        std::cout << vals2[i] << " ";
}
    std::cout << "\n";

    return 0;
}


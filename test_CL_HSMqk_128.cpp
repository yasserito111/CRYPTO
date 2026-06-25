#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include "bicycl.hpp"
#include "internals.hpp"

using namespace BICYCL;
using Clock = std::chrono::high_resolution_clock;
using us    = std::chrono::microseconds;
static long us_since(Clock::time_point t0)
{
    return std::chrono::duration_cast<us>(Clock::now() - t0).count();
}


static size_t qfi_bits(const QFI &q)
{
    size_t ba = mpz_sizeinbase(static_cast<mpz_srcptr>(q.a()), 2);
    size_t bb = mpz_sizeinbase(static_cast<mpz_srcptr>(q.b()), 2);
    return ba + bb;
}

static size_t cleartext_bits(const CL_HSMqk::ClearText &m)
{
    std::ostringstream oss;
    oss << m;
    size_t digits = oss.str().size();
    return static_cast<size_t>(std::ceil(digits * 3.32193));
}

static size_t ciphertext_bits(const CL_HSMqk::CipherText &c)
{
    return qfi_bits(c.c1()) + qfi_bits(c.c2());/*cipher=c1||c2*/
}

static std::string seclevel_str(SecLevel sec)
{
    std::ostringstream oss;
    oss << sec;
    return oss.str();
}
static void print_sep(const std::vector<int> &widths)
{
    for (int w : widths)
        std::cout << "+" << std::string(w + 2, '-');
    std::cout << "+\n"; /*tableau genere */
}
static void print_row(const std::vector<std::string> &cells,
                      const std::vector<int>          &widths)
{
    for (size_t i = 0; i < cells.size(); ++i)
        std::cout << "| " << std::left << std::setw(widths[i])
                  << cells[i] << " ";
    std::cout << "|\n";
}
struct BenchResult
{
    std::string seclevel;
    size_t      q_bits;
    size_t      k;
    size_t      plaintext_bits;
    size_t      ciphertext_bits;
    long        t_keygen_sk;
    long        t_keygen_pk;
    long        t_encrypt;
    long        t_decrypt;
    long        t_add_ct;
    long        t_decrypt_sum;
    bool        correct;
};

static Mpz gen_prime(size_t nb_bits)
{
    mpz_t tmp;
    mpz_init(tmp);
    /* 2^(nb_bits-1) + 1, puis premier suivant */
    mpz_set_ui(tmp, 1);
    mpz_mul_2exp(tmp, tmp, nb_bits - 1);
    mpz_add_ui(tmp, tmp, 1);
    mpz_nextprime(tmp, tmp);
    /* Mpz depuis string décimale */
    char *str = mpz_get_str(nullptr, 10, tmp);
    Mpz q{std::string(str)};
    free(str);
    mpz_clear(tmp);
    return q;
}
static BenchResult run_bench(SecLevel sec, size_t q_bits, size_t k,
                              RandGen &rng)
{
    BenchResult r;
    r.seclevel = seclevel_str(sec);
    r.q_bits   = q_bits;
    r.k        = k;
    Mpz q = gen_prime(q_bits);
    CL_HSMqk C(q, k, sec, rng);
    using SK = CL_HSMqk::SecretKey;
    using PK = CL_HSMqk::PublicKey;
    using CT = CL_HSMqk::ClearText;
    using CI = CL_HSMqk::CipherText;
    /* -- Génération de clés -- */
    auto t0 = Clock::now();
    SK sk   = C.keygen(rng);
    r.t_keygen_sk = us_since(t0);
    t0 = Clock::now();
    PK pk = C.keygen(sk);
    r.t_keygen_pk = us_since(t0);
    /* -- Messages aléatoires -- */
    CT m1(C, rng);
    CT m2(C, rng);
    r.plaintext_bits = cleartext_bits(m1);/*voici ou  on voit la taille du plaintext */
    /* -- Chiffrement -- */
    t0 = Clock::now();
    CI c1 = C.encrypt(pk, m1, rng);
    r.t_encrypt = us_since(t0);
    CI c2 = C.encrypt(pk, m2, rng);
    r.ciphertext_bits = ciphertext_bits(c1);/*voici ou on voit taille ciphertext */
    /* -- Déchiffrement -- */
    t0 = Clock::now();
    CT plain1 = C.decrypt(sk, c1);
    r.t_decrypt = us_since(t0);
    CT plain2   = C.decrypt(sk, c2);
    /* Addition */
    CT m_sum = C.add_cleartexts(m1, m2);
    t0 = Clock::now();
    CI c_sum = C.add_ciphertexts(pk, c1, c2, rng);
    r.t_add_ct = us_since(t0);
    t0 = Clock::now();
    CT t_sum = C.decrypt(sk, c_sum);
    r.t_decrypt_sum = us_since(t0);
    r.correct = (plain1 == m1) && (plain2 == m2) && (t_sum == m_sum);
    return r;
}
static void print_size_table(const std::vector<BenchResult> &results)
{
    std::cout << "\n";
    std::cout << "+-------------------------------------------------------------+\n";
    std::cout << "|         TAILLES PLAINTEXT / CIPHERTEXT (bits)               |\n";
    std::cout << "+-------------------------------------------------------------+\n";

    std::vector<std::string> headers =
        {"SecLevel", "q (bits)", "k", "PT (bits)", "CT (bits)", "Ratio CT/PT", "OK"};
    std::vector<int> widths = {9, 8, 4, 10, 10, 11, 3};
    print_sep(widths);
    print_row(headers, widths);
    print_sep(widths);
    for (const auto &r : results)
    {
        double ratio = (r.plaintext_bits > 0)
                       ? (double)r.ciphertext_bits / r.plaintext_bits : 0.0;
        std::ostringstream os_ratio;
        os_ratio << std::fixed << std::setprecision(1) << ratio << "x";

        print_row({r.seclevel,
                   std::to_string(r.q_bits),
                   std::to_string(r.k),
                   std::to_string(r.plaintext_bits),
                   std::to_string(r.ciphertext_bits),
                   os_ratio.str(),
                   r.correct ? "OK" : "KO"},
                  widths);
    }
    print_sep(widths);
}

static void print_timing_table(const std::vector<BenchResult> &results)
{
    std::cout << "\n";
    std::cout << "+--------------------------------------------------------------------------+\n";
    std::cout << "|                       TIMINGS (microsecondes)                            |\n";
    std::cout << "+--------------------------------------------------------------------------+\n";

    std::vector<std::string> headers =
        {"SecLvl", "q(b)", "k", "KGen(sk)", "KGen(pk)", "Encrypt", "Decrypt", "Add(ct)", "Dec(sum)"};
    std::vector<int> widths = {7, 5, 4, 10, 10, 9, 9, 9, 10};

    print_sep(widths);
    print_row(headers, widths);
    print_sep(widths);

    for (const auto &r : results)
    {
        print_row({r.seclevel,
                   std::to_string(r.q_bits),
                   std::to_string(r.k),
                   std::to_string(r.t_keygen_sk),
                   std::to_string(r.t_keygen_pk),
                   std::to_string(r.t_encrypt),
                   std::to_string(r.t_decrypt),
                   std::to_string(r.t_add_ct),
                   std::to_string(r.t_decrypt_sum)},
                  widths);
    }
    print_sep(widths);
}

static void print_correctness_table(const std::vector<BenchResult> &results)
{
    std::cout << "\n";
    std::cout << "+------------------------------------------+\n";
    std::cout << "|       VERIFICATION DE CORRECTION         |\n";
    std::cout << "+------------------------------------------+\n";
    std::vector<std::string> headers = {"SecLevel", "q (bits)", "k", "Resultat"};
    std::vector<int> widths = {9, 8, 4, 28};
    print_sep(widths);
    print_row(headers, widths);
    print_sep(widths);
    bool all_ok = true;
    for (const auto &r : results)
    {
        std::string status = r.correct
            ? "OK  (decrypt + homomorphisme)"
            : "ECHEC !!!";
        print_row({r.seclevel,
                   std::to_string(r.q_bits),
                   std::to_string(r.k),
                   status}, widths);
        all_ok &= r.correct;
    }
    print_sep(widths);

    std::cout << "\nResultat global : "
              << (all_ok ? "TOUS LES TESTS PASSES [OK]" : "DES TESTS ONT ECHOUE [KO]")
              << "\n\n";
}
int main(int argc, char *argv[])
{
    RandGen rng;
    randseed_from_argv(rng, argc, argv);
    const std::vector<SecLevel> sec_levels = {
        SecLevel::_112,
        SecLevel::_128,
        SecLevel::_192
    };
    const size_t Q_BITS = 256;
    const size_t K      = 1;

    std::vector<BenchResult> results;
    results.reserve(sec_levels.size());
    const size_t total = sec_levels.size();
    std::cout << "=== Benchmark CL_HSMqk (q=" << Q_BITS
              << " bits, k=" << K << ") ===\n";
    std::cout << total << " niveaux de securite\n\n";
    size_t idx = 1;
    for (SecLevel sec : sec_levels)
    {
        std::cout << "  [" << idx++ << "/" << total << "]"
                  << "  SecLevel=" << sec
                  << "  q=" << Q_BITS << " bits"
                  << "  k=" << K << " ... " << std::flush;

        BenchResult r = run_bench(sec, Q_BITS, K, rng);
        results.push_back(r);

        std::cout << (r.correct ? "OK" : "ECHEC") << "\n";
    }
    print_size_table(results);
    print_timing_table(results);
    print_correctness_table(results);
    bool all_ok = true;
    for (const auto &r : results) all_ok &= r.correct;
    Test::result_line("CL_HSMqk q=256bits bench", all_ok);
    return all_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
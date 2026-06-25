#include <stdio.h>
#include <string.h>
#include <time.h>
#include "relic.h"
#include "relic_test.h"

typedef struct {
    const char *label;
    int         modbits;
} SecurityLevel;

static const SecurityLevel SEC_LEVELS[] = {
    { "112", 2048 },/*c'est pour avoir le meme niveau de secu*/
    { "128", 3072 },
    { "192", 7680 },
};
static const int N_LEVELS = 3;

static const int MSG_SIZES[] = { 32, 64, 128, 256 };
static const int N_MSG_SIZES = 4;
static double elapsed_ms(const struct timespec *t0, const struct timespec *t1)
{
    return (t1->tv_sec  - t0->tv_sec)  * 1000.0
         + (t1->tv_nsec - t0->tv_nsec) / 1e6;
}
static void print_sep(const int *widths, int ncols)
{
    for (int i = 0; i < ncols; i++) {
        printf("+");
        for (int j = 0; j < widths[i] + 2; j++) printf("-");
    }
    printf("+\n");
}
static void print_row(const char **cells, const int *widths, int ncols)
{
    for (int i = 0; i < ncols; i++)
        printf("| %-*s ", widths[i], cells[i]);
    printf("|\n");
}
typedef struct {
    char   seclevel[8];
    int    modbits;       /* taille du modulus n                       */
    int    k;             /* taille du message demandée (bits)         */
    int    pt_bits;       /* taille réelle du message généré (bits)    */
    int    ct_bits;       /* taille du ciphertext = 2 * |n| (bits)     */
    double t_keygen_sk;   /* ms — génération clé privée+publique       */
    double t_encrypt;     /* ms                                        */
    double t_decrypt;     /* ms                                        */
    double t_add_ct;      /* ms — addition homomorphe côté chiffré     */
    double t_dec_sum;     /* ms — déchiffrement de la somme            */
    double t_mul_ct;      /* ms — multiplication scalaire côté chiffré */
    int    ok_dec;
    int    ok_add;
    int    ok_mul;
} BenchResult;
static int run_bench(BenchResult *r,
                     const SecurityLevel *sec,
                     int k,
                     bn_t pub_shared, phpe_t prv_shared,
                     int reuse_key)
{
    int code = RLC_ERR;
    struct timespec t0, t1;
    bn_t m1, m2, c1, c2, s, prod, nsq;
    bn_null(m1); bn_null(m2);
    bn_null(c1); bn_null(c2);
    bn_null(s);  bn_null(prod); bn_null(nsq);
    strncpy(r->seclevel, sec->label, sizeof(r->seclevel) - 1);
    r->modbits = sec->modbits;
    r->k       = k;
    r->ok_dec  = r->ok_add = r->ok_mul = 0;

    RLC_TRY {
        bn_new(m1); bn_new(m2);
        bn_new(c1); bn_new(c2);
        bn_new(s);  bn_new(prod); bn_new(nsq);

        /* ---- Génération de clés ---- */
        if (!reuse_key) {
            clock_gettime(CLOCK_MONOTONIC, &t0);
            if (cp_phpe_gen(pub_shared, prv_shared, sec->modbits) != RLC_OK)
                RLC_ERROR(end);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            r->t_keygen_sk = elapsed_ms(&t0, &t1);
        } else {
            r->t_keygen_sk = 0.0;   /* clé réutilisée, on ne rechronomètre pas */
        }
        /* Vraies tailles */
        r->pt_bits = k;                      /* message de k bits par construction */
        r->ct_bits = 2 * bn_bits(pub_shared); /* c in Z/n²Z */
        /* ---- Message aléatoire de k bits (< n) ---- */
        bn_rand(m1, RLC_POS, k);
        /* ---- Chiffrement ---- */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (cp_phpe_enc(c1, m1, pub_shared) != RLC_OK) RLC_ERROR(end);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        r->t_encrypt = elapsed_ms(&t0, &t1);
        /* ---- Déchiffrement ---- */
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (cp_phpe_dec(m2, c1, prv_shared) != RLC_OK) RLC_ERROR(end);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        r->t_decrypt = elapsed_ms(&t0, &t1);
        r->ok_dec = (bn_cmp(m1, m2) == RLC_EQ);
        /* ---- Addition ---- */
        bn_rand(m1, RLC_POS, k);
        bn_rand(m2, RLC_POS, k);
        if (cp_phpe_enc(c1, m1, pub_shared) != RLC_OK) RLC_ERROR(end);
        if (cp_phpe_enc(c2, m2, pub_shared) != RLC_OK) RLC_ERROR(end);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (cp_phpe_add(s, c1, c2, pub_shared) != RLC_OK) RLC_ERROR(end);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        r->t_add_ct = elapsed_ms(&t0, &t1);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (cp_phpe_dec(prod, s, prv_shared) != RLC_OK) RLC_ERROR(end);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        r->t_dec_sum = elapsed_ms(&t0, &t1);
        bn_add(m1, m1, m2);
        bn_mod(m1, m1, pub_shared);
        r->ok_add = (bn_cmp(m1, prod) == RLC_EQ);
        /* ---- Homomorphisme scalaire : Enc(m)^k = Enc(m*k mod n) ---- */
        bn_rand(m1, RLC_POS, k);
        bn_rand(m2, RLC_POS, k);
        if (cp_phpe_enc(c1, m1, pub_shared) != RLC_OK) RLC_ERROR(end);
        bn_sqr(nsq, pub_shared);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bn_mxp(prod, c1, m2, nsq);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        r->t_mul_ct = elapsed_ms(&t0, &t1);
        if (cp_phpe_dec(c1, prod, prv_shared) != RLC_OK) RLC_ERROR(end);
        bn_mul(m1, m1, m2);
        bn_mod(m1, m1, pub_shared);
        r->ok_mul = (bn_cmp(m1, c1) == RLC_EQ);
        code = RLC_OK;
    }
    RLC_CATCH_ANY { RLC_ERROR(end); }

end:
    bn_free(m1); bn_free(m2);
    bn_free(c1); bn_free(c2);
    bn_free(s);  bn_free(prod); bn_free(nsq);
    return code;
}
static void print_size_table(const BenchResult *R, int n)
{
    printf("\n");
    printf("+------------------------------------------------------------------+\n");
    printf("|          TAILLES PLAINTEXT / CIPHERTEXT (bits)                   |\n");
    printf("+------------------------------------------------------------------+\n");
    printf("  Note: PT = k bits (taille du message)                            \n");
    printf("        CT = 2 * |n| bits (c in Z/n^2 Z) — independant de k       \n");
    const char *hdr[] = {"SecLevel","Modulus","k (bits)","PT (bits)","CT (bits)","Ratio","OK"};
    int w[]           = {9,         8,         8,         10,         10,         7,      3};
    int nc = 7;
    print_sep(w, nc);
    print_row(hdr, w, nc);
    print_sep(w, nc);
    for (int i = 0; i < n; i++) {
        char mod[12], k[8], pt[12], ct[12], ratio[10];
        snprintf(mod,   sizeof(mod),   "%d", R[i].modbits);
        snprintf(k,     sizeof(k),     "%d", R[i].k);
        snprintf(pt,    sizeof(pt),    "%d", R[i].pt_bits);
        snprintf(ct,    sizeof(ct),    "%d", R[i].ct_bits);
        snprintf(ratio, sizeof(ratio), "%.1fx",
                 R[i].pt_bits > 0 ? (double)R[i].ct_bits / R[i].pt_bits : 0.0);

        int ok = R[i].ok_dec && R[i].ok_add && R[i].ok_mul;
        const char *row[] = {R[i].seclevel, mod, k, pt, ct, ratio, ok ? "OK" : "KO"};
        print_row(row, w, nc);
    }
    print_sep(w, nc);
}
static void print_timing_table(const BenchResult *R, int n)
{
    printf("\n");
    printf("+-------------------------------------------------------------------------------------+\n");
    printf("|                           TIMINGS (millisecondes)                                  |\n");
    printf("+-------------------------------------------------------------------------------------+\n");
    const char *hdr[] = {"SecLvl","k","KeyGen","Encrypt","Decrypt","Add(ct)","Dec(sum)","Mul(ct)"};
    int w[]           = {7,       5,  10,       9,        9,        9,        9,         9};
    int nc = 8;
    print_sep(w, nc);
    print_row(hdr, w, nc);
    print_sep(w, nc);
    for (int i = 0; i < n; i++) {
        char k[8], kg[12], enc[12], dec[12], add[12], dsum[12], mul[12];
        snprintf(k,    sizeof(k),    "%d",    R[i].k);
        snprintf(kg,   sizeof(kg),   "%.2f",  R[i].t_keygen_sk);
        snprintf(enc,  sizeof(enc),  "%.2f",  R[i].t_encrypt);
        snprintf(dec,  sizeof(dec),  "%.2f",  R[i].t_decrypt);
        snprintf(add,  sizeof(add),  "%.2f",  R[i].t_add_ct);
        snprintf(dsum, sizeof(dsum), "%.2f",  R[i].t_dec_sum);
        snprintf(mul,  sizeof(mul),  "%.2f",  R[i].t_mul_ct);
        const char *row[] = {R[i].seclevel, k, kg, enc, dec, add, dsum, mul};
        print_row(row, w, nc);
    }
    print_sep(w, nc);
    printf("  Note: KeyGen = 0.00 quand la cle est reutilisee pour les variantes k\n");
}
static void print_correctness_table(const BenchResult *R, int n)
{
    printf("\n");
    printf("+----------------------------------------------------+\n");
    printf("|             VERIFICATION DE CORRECTION             |\n");
    printf("+----------------------------------------------------+\n");
    const char *hdr[] = {"SecLevel","k","Decrypt","Add homo","Mul homo"};
    int w[]           = {9,         5,  9,         9,         9};
    int nc = 5;
    print_sep(w, nc);
    print_row(hdr, w, nc);
    print_sep(w, nc);
     int all_ok = 1;
    for (int i = 0; i < n; i++) {
        char k[8];
        snprintf(k, sizeof(k), "%d", R[i].k);
        const char *row[] = {
            R[i].seclevel, k,
            R[i].ok_dec ? "OK" : "ECHEC",
            R[i].ok_add ? "OK" : "ECHEC",
            R[i].ok_mul ? "OK" : "ECHEC"
        };
        print_row(row, w, nc);
        all_ok &= (R[i].ok_dec && R[i].ok_add && R[i].ok_mul);
    }
    print_sep(w, nc);

    printf("\nResultat global : %s\n\n",
           all_ok ? "TOUS LES TESTS PASSES [OK]" : "DES TESTS ONT ECHOUE [KO]");
}
int main(void)
{
    core_init();

    const int total = N_LEVELS * N_MSG_SIZES;
    BenchResult results[N_LEVELS * N_MSG_SIZES];
    printf("=== Benchmark Paillier (RELIC cp_phpe) ===\n");
    printf("%d niveaux x %d tailles de message = %d tests\n\n",
           N_LEVELS, N_MSG_SIZES, total);
    int idx = 0;
    for (int i = 0; i < N_LEVELS; i++) {
        bn_t pub;
        phpe_t prv;
        bn_null(pub); phpe_null(prv);
        bn_new(pub);  phpe_new(prv);
        printf("  Generation de cle SecLevel=%s (modulus %d bits) ...",
               SEC_LEVELS[i].label, SEC_LEVELS[i].modbits);
        fflush(stdout);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = cp_phpe_gen(pub, prv, SEC_LEVELS[i].modbits);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double kg_time = elapsed_ms(&t0, &t1);
        if (rc != RLC_OK) {
            printf(" ERREUR\n");
            /* remplir les lignes de ce niveau avec des zéros */
            for (int j = 0; j < N_MSG_SIZES; j++) {
                memset(&results[idx], 0, sizeof(BenchResult));
                strncpy(results[idx].seclevel, SEC_LEVELS[i].label, 7);
                results[idx].modbits = SEC_LEVELS[i].modbits;
                results[idx].k = MSG_SIZES[j];
                idx++;
            }
            bn_free(pub); phpe_free(prv);
            continue;
        }
        printf(" OK (%.1f ms)\n", kg_time);

        for (int j = 0; j < N_MSG_SIZES; j++) {
            int k = MSG_SIZES[j];
            printf("    [%d/%d]  k=%d bits ... ",
                   idx + 1, total, k);
            fflush(stdout);
            /* run_bench avec clé déjà générée (reuse_key=1) */
            int ok = run_bench(&results[idx], &SEC_LEVELS[i], k, pub, prv, 1);
            /* on stocke le temps keygen seulement pour la 1ère ligne du niveau */
            if (j == 0) results[idx].t_keygen_sk = kg_time;
            if (ok == RLC_OK) {
                int pass = results[idx].ok_dec
                        && results[idx].ok_add
                        && results[idx].ok_mul;
                printf("%s\n", pass ? "OK" : "ECHEC");
            } else {
                printf("ERREUR RLC\n");
            }
            idx++;
        }

        bn_free(pub);
        phpe_free(prv);
    }
    print_size_table(results, total);
    print_timing_table(results, total);
    print_correctness_table(results, total);
    int all_ok = 1;
    for (int i = 0; i < total; i++)
        all_ok &= (results[i].ok_dec && results[i].ok_add && results[i].ok_mul);

    core_clean();
    return all_ok ? 0 : 1;
}

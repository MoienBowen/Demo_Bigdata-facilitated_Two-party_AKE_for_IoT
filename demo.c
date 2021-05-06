#include "miracl.h"
#include <argp.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hashing_to_big(char *msg, big hash_nb);
void hashing_to_str(char *msg, char *hash_str);
void hashing_display(char *msg_hashed);
void PRF_E(big r_in, big mk, int sec_level, char *r_out);
void PRF_F(int index, char *salt, int sec_level, big f_out);
// float diff_time(timeval t1, timeval t2);

#define z 50
#define L 500         // Save local storage in demo
#define data_size 500 // size of a single data item, 500 or 1000
#define I_PAD 0x36    // for HMAC definition
#define O_PAD 0x5C    // for HMAC definition
#define MR_HASH_BYTES 32

// argp parameters
const char *argp_program_version = "20210505";
const char doc[] = "This is a demo for bigdata-facilited two-party AKE for IoT";
static char args_doc[] = "ARG1";
static struct argp_option options[] = {{"low", 'l', 0, 0, "128 bits security"},
                                       {"high", 'h', 0, 0, "256 bits security"},
                                       {0}};

struct curve {
  char *A;
  char *B;
  char *P;
  char *Q;
  char *X;
  char *Y;
  int sec_level;
};

static int parse_opt(int key, char *arg, struct argp_state *state);
static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int argc, char **argv) {
  // Get Curve from input option
  struct curve curve;
  argp_parse(&argp, argc, argv, 0, 0, &curve);
  if (curve.sec_level != 128 && curve.sec_level != 256) {
    printf("Please check your option.\n");
    exit(EXIT_FAILURE);
  }

  // Get data from file
  FILE *fp;
  char *line = NULL;
  size_t len = data_size;
  ssize_t read;

  char **bigdata = (char **)malloc(L * sizeof(char *));
  int pos = 0;
  if (data_size == 500) {
    fp = fopen("./bigdata_0_5KB.txt", "r");
  } else if (data_size == 1000) {
    fp = fopen("./bigdata_1KB.txt", "r");
  } else {
    printf("Please check or generate relevant bigdata set.\n");
    exit(EXIT_FAILURE);
  }

  if (fp == NULL)
    exit(EXIT_FAILURE);

  while ((read = getline(&line, &len, fp)) != -1) {
    bigdata[pos] = (char *)malloc(data_size * sizeof(char));
    strncpy(bigdata[pos], line, data_size);
    pos += 1;
  }

  fclose(fp);
  if (line)
    free(line);

  // Key generation
  big a, b, p, q, x, y, sk, mk, k, kp, od;
  epoint *g, *w, *pk;

  miracl *mip = mirsys(curve.sec_level, 16);

  a = mirvar(0);
  b = mirvar(0);
  p = mirvar(0);
  q = mirvar(0);
  x = mirvar(0);
  y = mirvar(0);
  sk = mirvar(0);
  mk = mirvar(0);
  k = mirvar(0);
  kp = mirvar(0);
  od = mirvar(0);
  expint(2, curve.sec_level, od);

  instr(a, curve.A);
  instr(b, curve.B);
  instr(p, curve.P);
  instr(q, curve.Q);
  instr(x, curve.X);
  instr(y, curve.Y);

  time_t seed;
  time(&seed);
  irand((unsigned long)seed);

  ecurve_init(a, b, p, MR_PROJECTIVE); // initialise curve

  g = epoint_init();  // base point
  w = epoint_init();  // infinity point
  pk = epoint_init(); // public key point

  if (!epoint_set(x, y, 0, g)) // initialise point of order q
  {
    printf("Point (x,y) is not on the curve\n");
    exit(EXIT_FAILURE);
  }
  ecurve_mult(q, g, w);
  if (!point_at_infinity(w)) {
    printf("Point (x,y) is not of order q\n");
    exit(EXIT_FAILURE);
  }

  bigrand(q, sk);
  bigrand(od, mk);
  bigrand(q, k);
  bigrand(od, kp);
  prepare_monty(q);
  ecurve_mult(sk, g, pk);

  printf("==========================================\n");
  printf("size parameters:\nz: %d\n", z);
  printf("secret key sk:\n");
  otnum(sk, stdout);
  printf("piblic key pk:\n");
  epoint_get(pk, x, y);
  otnum(x, stdout);
  otnum(y, stdout);
  printf("first authentication factor - key mk:\n");
  otnum(mk, stdout);
  printf("second authentication factor - key K:\n");
  otnum(k, stdout);
  printf("second authentication factor - key k':\n");
  otnum(kp, stdout);
  printf("==========================================\n\n");

  // Tag generation

  big tag[L];
  big tmp_f;
  tmp_f = mirvar(0);
  char kp_str[curve.sec_level];

  for (int i = 0; i < L; i++) {
    tag[i] = mirvar(0);
    hashing_to_big(bigdata[i], tag[i]);
    nres_modmult(k, tag[i], tag[i]);
    otstr(kp, kp_str);
    PRF_F(i, kp_str, curve.sec_level, tmp_f);
    nres_modadd(tmp_f, tag[i], tag[i]);
  }

  mirkill(tmp_f);

  printf("[v] Tag generation completed\n");

  // First message generation

  big r1, r2;
  epoint *ac, *gp;

  r1 = mirvar(0);
  r2 = mirvar(0);

  ac = epoint_init();
  gp = epoint_init();

  bigrand(q, r1);
  bigrand(od, r2);

  ecurve_mult(r1, pk, ac);
  ecurve_mult(r1, g, gp);

  int index_is_used[L] = {0};
  int Ic[z];
  int index;
  for (int i = 0; i < z; i++) {
    index = rand() % L;
    while (index_is_used[index] == 1) {
      index = rand() % L;
    }
    Ic[i] = index;
    index_is_used[index] = 1;
  }

  // Generate M1
  char m1c[2000];
  char m1chashed[MR_HASH_BYTES + 1];
  char msg_tmp[curve.sec_level];
  big x_tmp, y_tmp;
  x_tmp = mirvar(0);
  y_tmp = mirvar(0);

  otstr(mk, m1c);
  epoint_get(ac, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m1c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m1c, msg_tmp);
  epoint_get(gp, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m1c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m1c, msg_tmp);
  otstr(r2, msg_tmp);
  strcat(m1c, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Ic[i]);
    strcat(m1c, msg_tmp);
  }

  hashing_to_str(m1c, m1chashed);

  printf("[v] First message generation completed\n");

  // First message vef

  big r3, sumx, d_hashed, tmp_f_in_xy, sumy;
  epoint *as, *bs, *dh;
  char r2p[MR_HASH_BYTES];

  r3 = mirvar(0);
  sumx = mirvar(0);
  d_hashed = mirvar(0);
  tmp_f_in_xy = mirvar(0);
  sumy = mirvar(0);

  as = epoint_init();
  bs = epoint_init();
  dh = epoint_init();

  ecurve_mult(sk, gp, as);

  char m1s[2000];
  char m1shashed[MR_HASH_BYTES + 1];

  otstr(mk, m1s);
  epoint_get(as, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m1s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m1s, msg_tmp);
  epoint_get(gp, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m1s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m1s, msg_tmp);
  otstr(r2, msg_tmp);
  strcat(m1s, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Ic[i]);
    strcat(m1s, msg_tmp);
  }

  hashing_to_str(m1s, m1shashed);

  if (strcmp(m1s, m1c) != 0) {
    printf("[x] First message verification failed\n");
    exit(EXIT_FAILURE);
  } else {
    printf("[v] First message verification completed\n");
  }

  // Second message gen

  int Is[z];
  for (int i = 0; i < z; i++) {
    index = rand() % L;
    while (index_is_used[index] == 1) {
      index = rand() % L;
    }
    Is[i] = index;
    index_is_used[index] = 1;
  }

  PRF_E(r2, mk, curve.sec_level, r2p);

  for (int i = 0; i < z; i++) {
    // X for Ic
    hashing_to_big(bigdata[Ic[i]], d_hashed);
    PRF_F(Ic[i], r2p, curve.sec_level, tmp_f_in_xy);
    nres_modmult(d_hashed, tmp_f_in_xy, d_hashed);
    nres_modadd(d_hashed, sumx, sumx);

    // Y for Ic
    nres_modmult(tag[Ic[i]], tmp_f_in_xy, tmp_f_in_xy);
    nres_modadd(tmp_f_in_xy, sumy, sumy);

    // X for Is
    hashing_to_big(bigdata[Is[i]], d_hashed);
    PRF_F(Is[i], r2p, curve.sec_level, tmp_f_in_xy);
    nres_modmult(d_hashed, tmp_f_in_xy, d_hashed);
    nres_modadd(d_hashed, sumx, sumx);

    // Y for Is
    nres_modmult(tag[Is[i]], tmp_f_in_xy, tmp_f_in_xy);
    nres_modadd(tmp_f_in_xy, sumy, sumy);
  }

  nres_modmult(k, sumx, sumx);

  bigrand(q, r3);

  ecurve_mult(r3, pk, bs);
  ecurve_mult(r3, as, dh);

  char m2s[2000];
  char m2shashed[MR_HASH_BYTES + 1];
  epoint_get(as, x_tmp, y_tmp);
  otstr(x_tmp, m2s);
  otstr(y_tmp, msg_tmp);
  strcat(m2s, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m2s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m2s, msg_tmp);
  epoint_get(dh, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m2s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m2s, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Is[i]);
    strcat(m2s, msg_tmp);
  }
  otstr(sumx, msg_tmp);
  strcat(m2s, msg_tmp);
  otstr(sumy, msg_tmp);
  strcat(m2s, msg_tmp);
  strcat(m2s, m1chashed); // stand for (1) gp, r2, Ic and M1

  hashing_to_str(m2s, m2shashed);

  printf("[v] Second message generation completed\n");

  mirkill(d_hashed);
  mirkill(tmp_f_in_xy);
  mirkill(r3);

  // Second message vef

  big tmp_f_in_c_1, tmp_f_in_c_2, yp;
  epoint *dhp;
  char r2pp[MR_HASH_BYTES + 1];

  tmp_f_in_c_1 = mirvar(0);
  tmp_f_in_c_2 = mirvar(0);
  yp = mirvar(0);

  dhp = epoint_init();

  PRF_E(r2, mk, curve.sec_level, r2pp);

  otstr(kp, kp_str);

  for (int i = 0; i < z; i++) {
    // for Ic
    PRF_F(Ic[i], r2pp, curve.sec_level, tmp_f_in_c_1);
    PRF_F(Ic[i], kp_str, curve.sec_level, tmp_f_in_c_2);
    nres_modmult(tmp_f_in_c_1, tmp_f_in_c_2, tmp_f_in_c_2);
    nres_modadd(tmp_f_in_c_2, yp, yp);

    // for Is
    PRF_F(Is[i], r2pp, curve.sec_level, tmp_f_in_c_1);
    PRF_F(Is[i], kp_str, curve.sec_level, tmp_f_in_c_2);
    nres_modmult(tmp_f_in_c_1, tmp_f_in_c_2, tmp_f_in_c_2);
    nres_modadd(tmp_f_in_c_2, yp, yp);
  }

  nres_modadd(sumx, yp, yp);
  ecurve_mult(r1, bs, dhp);

  char m2c[2000];
  char m2chashed[MR_HASH_BYTES + 1];

  epoint_get(ac, x_tmp, y_tmp);
  otstr(x_tmp, m2c);
  otstr(y_tmp, msg_tmp);
  strcat(m2c, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m2c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m2c, msg_tmp);
  epoint_get(dhp, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m2c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m2c, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Is[i]);
    strcat(m2c, msg_tmp);
  }
  otstr(sumx, msg_tmp);
  strcat(m2c, msg_tmp);
  otstr(yp, msg_tmp);
  strcat(m2c, msg_tmp);
  strcat(m2c, m1chashed); // stand for (1) gp, r2, Ic and M1

  hashing_to_str(m2c, m2chashed);

  if (strcmp(m2shashed, m2chashed) != 0) {
    printf("[x] Second message verification failed\n");
    exit(EXIT_FAILURE);
  } else {
    printf("[v] Second message verification completed\n");
  }

  mirkill(tmp_f_in_c_1);
  mirkill(tmp_f_in_c_2);
  mirkill(sumx);

  // Third message gen

  char m3c[2000];
  char m3chashed[MR_HASH_BYTES + 1];

  epoint_get(ac, x_tmp, y_tmp);
  otstr(x_tmp, m3c);
  otstr(y_tmp, msg_tmp);
  strcat(m3c, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m3c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m3c, msg_tmp);
  epoint_get(dhp, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m3c, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m3c, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Ic[i]);
    strcat(m2s, msg_tmp);
    sprintf(msg_tmp, "%d", Is[i]);
    strcat(m2s, msg_tmp);
  }
  otstr(yp, msg_tmp);
  strcat(m3c, msg_tmp);
  strcat(m3c, m1chashed); // stand for (1) gp, r2, Ic and M1
  strcat(m3c, m2shashed); // stand for (2) b, Is, X and M2

  hashing_to_str(m3c, m3chashed);

  printf("[v] Third message generation completed\n");

  mirkill(r1);

  // Sesison key on c

  char skc[2000];
  char skchashed[MR_HASH_BYTES + 1];

  otstr(mk, skc);
  epoint_get(ac, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  epoint_get(dhp, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(skc, msg_tmp);
  otstr(yp, msg_tmp);
  strcat(skc, msg_tmp);
  hashing_to_str(skc, skchashed);

  printf("[)] Client's session key generation completed\n");

  // Third message vef

  char m3s[2000];
  char m3shashed[MR_HASH_BYTES + 1];

  epoint_get(as, x_tmp, y_tmp);
  otstr(x_tmp, m3s);
  otstr(y_tmp, msg_tmp);
  strcat(m3s, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m3s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m3s, msg_tmp);
  epoint_get(dh, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(m3s, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(m3s, msg_tmp);
  for (int i = 0; i < z; i++) {
    sprintf(msg_tmp, "%d", Ic[i]);
    strcat(m2s, msg_tmp);
    sprintf(msg_tmp, "%d", Is[i]);
    strcat(m2s, msg_tmp);
  }
  otstr(sumy, msg_tmp);
  strcat(m3s, msg_tmp);
  strcat(m3s, m1chashed); // stand for (1) gp, r2, Ic and M1
  strcat(m3s, m2shashed); // stand for (2) b, Is, X and M2

  hashing_to_str(m3s, m3shashed);

  if (strcmp(m2shashed, m2chashed) != 0) {
    printf("[x] Third message verification failed\n");
    exit(EXIT_FAILURE);
  } else {
    printf("[v] Third message verification completed\n");
  }

  // Sesison key on s

  char sks[2000];
  char skshashed[MR_HASH_BYTES + 1];

  otstr(mk, sks);
  epoint_get(as, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  epoint_get(bs, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  epoint_get(dh, x_tmp, y_tmp);
  otstr(x_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  otstr(y_tmp, msg_tmp);
  strcat(sks, msg_tmp);
  otstr(sumy, msg_tmp);
  strcat(sks, msg_tmp);
  hashing_to_str(sks, skshashed);

  printf("[)] Server's session key generation completed\n");

  // Free
  for (int i = 0; i < L; i++) {
    free(bigdata[i]);
    mirkill(tag[i]);
  }
  free(bigdata);
  mirkill(x_tmp);
  mirkill(y_tmp);
  mirkill(sumy);
  mirkill(yp);
  mirkill(a);
  mirkill(b);
  mirkill(p);
  mirkill(q);
  mirkill(x);
  mirkill(y);
  mirkill(sk);
  mirkill(mk);
  mirkill(k);
  mirkill(kp);
  mirkill(od);
}

static int parse_opt(int key, char *arg, struct argp_state *state) {
  struct curve *curve = state->input;

  switch (key) {
  case 'l':
    // secp256k1 parameters
    curve->A = "0";
    curve->B = "7";
    curve->P =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    curve->Q =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    curve->X =
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    curve->Y =
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    curve->sec_level = 128;
    break;

  case 'h':
    // secp521r1 parameters
    curve->A =
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
    curve->B =
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156"
        "193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00";
    curve->P =
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    curve->Q =
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51"
        "868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    curve->X =
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa1"
        "4b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
    curve->Y =
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97"
        "ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";
    curve->sec_level = 256;
    break;

  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

void hashing_to_str(char *msg, char *hash_str) {
  sha256 sh;
  shs256_init(&sh);
  for (int i = 0; msg[i] != '\0'; i++) {
    shs256_process(&sh, msg[i]);
  }
  shs256_hash(&sh, hash_str);

  // magic error: output length may pass MR_HASH_BYTES
  if (strlen(hash_str) > MR_HASH_BYTES)
    hash_str[MR_HASH_BYTES] = '\0';
}

void hashing_display(char *msg_hashed) {
  for (int i = 0; i < strlen(msg_hashed); i++) {
    printf("%02x", (unsigned char)msg_hashed[i]);
  }
  printf("\n");
}

void hashing_to_big(char *msg, big hash_nb) {
  char res[MR_HASH_BYTES + 1];
  hashing_to_str(msg, res);
  bytes_to_big(MR_HASH_BYTES, res, hash_nb);
}

// HMAC(H, K) == H(K ^ opad, H(K ^ ipad, text))
void PRF_E(big r_in, big mk, int sec_level, char *r_out) {
  uint8_t mk_str[sec_level];
  uint8_t long_str[sec_level];
  uint8_t res_hash[MR_HASH_BYTES + 1];
  uint8_t r_in_str[sec_level];

  otstr(mk, mk_str);
  // if the mk is bigger than the buffer size MR_HASH_BYTES
  // aaply the hash function to it and use the result
  if (strlen(mk_str) > MR_HASH_BYTES) {
    hashing_to_str(mk_str, mk_str);
  }

  size_t len_mk = strlen(mk_str);

  for (size_t i = 0; i < len_mk; i++)
    res_hash[i] = I_PAD ^ mk_str[i];
  if (len_mk < (size_t)MR_HASH_BYTES)
    for (size_t i = len_mk; i < MR_HASH_BYTES; i++)
      res_hash[i] = I_PAD ^ 0;
  res_hash[MR_HASH_BYTES] = '\0';

  strcpy(long_str, res_hash);
  otstr(r_in, r_in_str);
  strcat(long_str, r_in_str);
  hashing_to_str(long_str, r_in_str);

  for (size_t i = 0; i < len_mk; i++)
    res_hash[i] = O_PAD ^ mk_str[i];
  if (len_mk < (size_t)MR_HASH_BYTES)
    for (size_t i = len_mk; i < MR_HASH_BYTES; i++)
      res_hash[i] = O_PAD ^ 0;
  res_hash[MR_HASH_BYTES] = '\0';

  memset(long_str, 0, sizeof(long_str));
  strcpy(long_str, res_hash);
  strcat(long_str, r_in_str);
  hashing_to_str(long_str, r_out);
}

void PRF_F(int index, char *salt, int sec_level, big f_out) {
  uint8_t salt_str[MR_HASH_BYTES + 1];
  uint8_t long_str[sec_level];
  uint8_t res_hash[MR_HASH_BYTES + 1];
  uint8_t index_str[MR_HASH_BYTES + 1];

  // if the salt is bigger than the buffer size MR_HASH_BYTES
  // aaply the hash function to it and use the result
  if (strlen(salt) > MR_HASH_BYTES) {
    hashing_to_str(salt, salt_str);
  } else {
    strcpy(salt_str, salt);
    salt_str[strlen(salt)] = '\0';
  }
  size_t len_salt = strlen(salt_str);

  for (size_t i = 0; i < len_salt; i++)
    res_hash[i] = I_PAD ^ salt_str[i];
  if (len_salt < (size_t)MR_HASH_BYTES)
    for (size_t i = len_salt; i < MR_HASH_BYTES; i++)
      res_hash[i] = I_PAD ^ 0;
  res_hash[MR_HASH_BYTES] = '\0';

  sprintf(index_str, "%d", index);
  strcpy(long_str, res_hash);
  strcat(long_str, index_str);
  hashing_to_str(long_str, index_str);

  for (size_t i = 0; i < len_salt; i++)
    res_hash[i] = O_PAD ^ salt_str[i];
  if (len_salt < (size_t)MR_HASH_BYTES)
    for (size_t i = len_salt; i < MR_HASH_BYTES; i++)
      res_hash[i] = O_PAD ^ 0;
  res_hash[MR_HASH_BYTES] = '\0';

  memset(long_str, 0, sizeof(long_str));
  strcpy(long_str, res_hash);
  strcat(long_str, index_str);
  hashing_to_big(long_str, f_out);
}

// float diff_time(timeval t1, timeval t2){
//     // struct timeval t;
//     // gettimeofday(&t, NULL);
//     return (float)(t2.tv_sec - t1.tv_sec) * 1000 + (float)(t2.tv_usec -
//     t1.tv_usec) / 1000;
// }

import random
import time

P = 5 * (1 << 55) + 1
ALPHA = 3
T = 2

R_F_PRE = 2
R_P = 10
R_F_POST = 2
TOTAL_ROUNDS = R_F_PRE + R_P + R_F_POST

RATE = 1
CAPACITY = 1


TOTAL_ROUNDS = R_F_PRE + R_P + R_F_POST


def generate_mds(prime, t, seed=0xDEADBEEF):
    rng = random.Random(seed)
    while True:
        xs = [rng.randrange(1, prime) for _ in range(t)]
        ys = [rng.randrange(1, prime) for _ in range(t)]
        ok = (
            len(set(xs)) == t
            and len(set(ys)) == t
            and all((x + y) % prime != 0 for x in xs for y in ys)
        )
        if ok:
            break
    return [
        [pow((xs[i] + ys[j]) % prime, -1, prime) for j in range(t)] for i in range(t)
    ]


def generate_round_constants(prime, t, total_rounds, seed=0xDEADBEEF):
    rng = random.Random(seed)
    return [[rng.randrange(prime) for _ in range(t)] for _ in range(total_rounds)]


MDS = generate_mds(P, T)
ROUND_CONSTANTS = generate_round_constants(P, T, TOTAL_ROUNDS)


def sbox(v):
    return pow(v, ALPHA, P)


def linear_layer(state):
    return [sum(MDS[i][j] * state[j] for j in range(T)) % P for i in range(T)]


def add_round_constants(state, rc):
    return [(state[i] + rc[i]) % P for i in range(T)]


def full_round(state, rc):
    s = add_round_constants(state, rc)
    s = [sbox(v) for v in s]
    s = linear_layer(s)
    return s


def partial_round(state, rc):
    s = add_round_constants(state, rc)
    s[0] = sbox(s[0])
    s = linear_layer(s)
    return s


def poseidon_perm(state):
    s = list(state)
    rc_idx = 0
    for _ in range(R_F_PRE):
        s = full_round(s, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
    for _ in range(R_P):
        s = partial_round(s, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
    for _ in range(R_F_POST):
        s = full_round(s, ROUND_CONSTANTS[rc_idx])
        rc_idx += 1
    return s


def sponge_hash(message_blocks):
    state = [0] * T
    for m in message_blocks:
        state[0] = (state[0] + m) % P
        state = poseidon_perm(state)
    return state[0]


if __name__ == "__main__":

    FLAG = open("flag.txt", "r").read()

    try:
        preimage = random.randint(1, P - 1)
        hash_value = sponge_hash([preimage])

        print("Hash:", hash_value)
        start_time = time.time()

        guessed = []
        while True:
            guess = int(input("Enter preimage: ")) % P

            if sponge_hash([guess]) == hash_value:
                if guess == preimage:
                    print("Correct preimage and hash match!")
                    break
                else:
                    if guess in guessed:
                        print("No cheating!")
                        exit()

                    guessed.append(guess)
                    print("Correct hash but wrong preimage")

        end_time = time.time()
        if end_time - start_time > 150:
            print("Too slow!")
            exit()

        print(FLAG)
    except Exception:
        exit()

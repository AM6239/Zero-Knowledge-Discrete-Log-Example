# An example implementation of a zero knowledge proof using the discrete logarithm problem

import random
import sys

import sympy


class Agent:

    def share(self, **kwargs):
        print(f"\n*** {self.agent} ***")
        if kwargs.get('header_text', None) is not None:
            print(f"{kwargs.get('header_text')}")
        for name, value in kwargs.items():
            if name != 'header_text':
                print(f"{name} = {value}")


class Prover(Agent):

    def __init__(self):
        super().__init__()
        self.agent = "Prover"
        self.malicious = False
        MIN_PRIME = 2 ** 20  # ensure the prime number is large to ensure the mod problem is non-trivial
        MAX_PRIME = MIN_PRIME * 2
        self.p = sympy.randprime(MIN_PRIME, MAX_PRIME)  # generate the prime number (divisor in the mod)
        self.g = random.randrange(2, self.p)  # create a random integer as the base of the exponential, ensuring its not 1
        self.x = random.randrange(0, self.p - 1)  # generate the secret e.g. password
        self.y = self.g ** self.x % self.p
        self.r = None  # Generated at the start each iteration of zero knowledge interaction
        self.C = None  # Generated at the start each iteration of zero knowledge interaction
        self.verifiers_challenge_choice = None
        print(f"\nProver initialisation\np = {self.p} <-- the prime number (divisor in the mod) \n"
              f"g = {self.g} <-- the base of the exponential of the number in the mod\n"
              f"x = {self.x} <-- the exponential of the number in the mod, i.e. THE SECRET")
        print(f"y = g^x mod p = {self.g}^{self.x} mod {self.p} = {self.y}")

    def pick_random_r_and_calc_C(self):
        self.r = random.randrange(0, self.p - 2)
        C = self.g ** self.r % self.p
        return C

    def respond(self, verifier_challenge_choice):
        if verifier_challenge_choice:
            w = (self.x + self.r) % (self.p - 1)
            return w
        else:
            return self.r


class Verifier(Agent):
    def __init__(self, number_of_rounds):
        super().__init__()
        self.agent = "Verifier"
        self.number_of_rounds = number_of_rounds
        self.p = None
        self.g = None
        self.y = None
        self.C = None
        self.w = None
        self.choice = None

    def choose_challenge(self):
        self.choice = random.randint(0, 1)  # True if verifier asks for (x+r)mod(p-1),
        # False if they pick that they want r
        return self.choice

    def verify(self, prover_response):
        if self.choice:
            w = prover_response
            if (self.C * self.y) % self.p == self.g ** w % self.p:
                self.share(verifier_result="Pass")
                return True
            else:
                self.share(verifier_result="Fail")
                return False
        else:
            r = prover_response
            if self.C == self.g ** r % self.p:
                self.share(verifier_result="Pass")
                return True
            else:
                self.share(verifier_result="Fail")
                return False

    @staticmethod
    def confidence_level(result, round_number):
        if result:
            conf_level = 1 - 0.5 ** round_number
            print(f"Pass, confidence level = {conf_level * 100}%")
        else:
            print(f"Fail, confidence level = 0%")
            sys.exit()


if __name__ == '__main__':
    prover = Prover()
    verifier = Verifier(10)

    prover.share(header_text="initialisation values (p, g and y)", p=prover.p, g=prover.g, y=prover.y)
    verifier.p, verifier.g, verifier.y = prover.p, prover.g, prover.y

    # Begin interaction
    round_number = 1
    result = None

    while result is not False and round_number <= verifier.number_of_rounds:
        prover.share(header_text="Commitment value, C", C=prover.pick_random_r_and_calc_C())
        verifier.C = prover.pick_random_r_and_calc_C()

        verifier_challenge_choice = verifier.choose_challenge()
        if verifier_challenge_choice:
            verifier.share(header_text='Challenge: please share (x+r)mod(p-1)')
        else:
            verifier.share(header_text='Challenge: please share r')

        prover_response = prover.respond(verifier_challenge_choice)
        if verifier_challenge_choice:
            prover.share(header_text=f"w = (x+r)mod(p-1) = {prover_response}")
        else:
            prover.share(header_text=f"r = {prover_response}")

        result = verifier.verify(prover_response)
        verifier.confidence_level(result, round_number)
        round_number += 1

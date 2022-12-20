import random
def nth_value(n, seed):
    random.seed(seed)
    for i in range(n):
        x = random.randint(0, 1000)
        print(i + 1, ":", x)  
    return x   

seed = random.randint(0, 1000)
nonce = nth_value(3, seed)
print("Nonce: ", nonce)
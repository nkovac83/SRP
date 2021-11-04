# Izvještaj s laboratorijskih vježbi

# 1.Laboratorijska vježba

## Zadatak

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. 

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container):

- dvije žrtve station-1
- station-2
- napadač evil-station.

Za izvođenje ove vježbe koristili smo unaprijed izrađene skripte i konfiguracijske datoteke kako bismo mogli upravljati docker containerima, koji su nam predstavljali računala unutar mreže.

Pokretali smo ih skriptom **./start.sh** , a zaustavljali pomoću **./stop.sh**

Za pokretanje interaktivnog shella za svaki container koristili smo naredbu (u ovom primjeru za station-2):

**$** **docker exec -it station-2 bash**

Nakon toga smo pomoću netcata iz jednog containera otvorili port, i na njega se spojili s drugog containera:

station-1: **$ netcat -lp 9000**

station-2: **$ netcat station-1 9000**

Za realizaciju napada koristili smo alat arpspoof kojeg pozivamo iz containera evil-station, i govorimo mu na kojim stationima želimo izvršiti napad:

**$ arpspoof -t station-1 station-2**

Pokretanjem naredbe **$tcpdump** možemo pratiti tok prometa kroz mrežu.

Ukoliko želimo ne samo pratiti, već i prekinuti komunikaciju između dvaju napadnutih stationa za to koristimo naredbu: **$ echo 0 > /proc/sys/net/ipv4/ip_forward** Ova naredba nam zaustavlja protok prometa od "man-in-the-middle" postaje prema finalnoj destinaciji. Napad koji smo realizirali na vježbama presretao je podatke samo iz jednog smjera, ali napad se može izvršiti i tako da se presretnu podaci neovisno o tome u kojem smjeru se šalju.

# 2. Laboratorijska vježba

October 26, 2021

U sklopu vježbe student će riješiti odgovarajući *crypto* izazov, odnosno dešifrirati odgovarajući *ciphertext* u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

Za pripremu *crypto* izazova, odnosno enkripciju korištena je Python biblioteka `[cryptography](https://cryptography.io/en/latest/)`. *Plaintext* koji student treba otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz navedene biblioteke - [Fernet](https://cryptography.io/en/latest/fernet/).

Fernet koristi sljedeće *low-level* kriptografske mehanizme:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

U ovom dijelu vježbi, najprije ćemo se kratko upoznati sa načinom na koji možete enkriptirati i dekriptirati poruke korištenjem Fernet sustava.

Rad u Pythonu(v3).

- instaliranje kriptografijskog modula i pokretanje Python-a:

```
$ pip install cryptography$ python
```

- vježba enkripcije i dekripcije plaintext-a:

```
$ from cryptography.fernet import Fernet$ plaintext = b"hello world"$ ciphertext = f.encrypt(plaintext)$ ciphertextb'gAAAAABhd8p8KqK_-nK5frGwI8OITZAFuvSSo645LOcTCDuuSHymEkt6nY4dp4jKODdaoFAZXHtXLQFTqsjSeJwsBhDuJ4ADEw=='$ f.decrypt(ciphertext)b'hello world'
```

- preuzimanje osobnog challenge-a na lokalno računalo:

```
from cryptography.hazmat.primitives import hashesdef hash(input):    if not isinstance(input, bytes):        input = input.encode()    digest = hashes.Hash(hashes.SHA256())    digest.update(input)    hash = digest.finalize()    return hash.hex()if __name__ == "__main__":    h = hash('kovacevic_nikola')    print(h)
```

- dekripcija challenge-a:

```
import base64def brute_force():    ctr = 0    while True:        key_bytes = ctr.to_bytes(32, "big")        key = base64.urlsafe_b64encode(key_bytes)        if not (ctr + 1) % 1000:            print(f"[*] Keys tested: {ctr+ 1:,}", end="\r")        # Now initialize the Fernet system with the given key        # and try to decrypt your challenge.        # Think, how do you know that the key tested is the correct key        # (i.e., how do you break out of this infinite loop)?        ctr += 1if __name__ == "__main__":    brute_force()
```

```
$ python brute_force.py[*] Keys tested: 51,012,000
```

- Za enkripciju smo koristili **ključeve ograničene entropije - 22 bita**
- konačan program za enkripciju u Python-u:

```
import base64from cryptography.fernet import Fernetfrom cryptography.hazmat.primitives import hashesdef hash(input):    if not isinstance(input, bytes):        input = input.encode()    digest = hashes.Hash(hashes.SHA256())    digest.update(input)    hash = digest.finalize()    return hash.hex()def test_png(header):    if header.startswith(b"\211PNG\r\n\032\n"):        return truedef brute_force():    filename = "1b7fcafff48334c38b3aa1cc7582090ee7a5c9317e1a2ac39cc78b6fd93e544c.encrypted"    with open(filename, "rb") as file:        ciphertext = file.read()        # Now do something with the ciphertext    ctr = 0    while True:        key_bytes = ctr.to_bytes(32, "big")        key = base64.urlsafe_b64encode(key_bytes)        if not (ctr + 1) % 1000:            print(f"[*] Keys tested: {ctr+ 1:,}", end="\r")        # Now initialize the Fernet system with the given key        # and try to decrypt your challenge.        # Think, how do you know that the key tested is the correct key        # (i.e., how do you break out of this infinite loop)?        try:            plaintext = Fernet(key).decrypt(ciphertext)            header = plaintext[:32]            if test_png(header):                print(f"[+] KEY FOUND: {key}")                # Writing to a file                with open("BINGO.png", "wb") as file:                    file.write(plaintext)                break        except Exception:            pass        ctr += 1if __name__ == "__main__":    brute_force()
```

- u terminalu pokrenemo brute_force() napad i čekamo dok se petlja ne izvrši, kada se zaustavi to znači da smo uspješno dekriptirali naš challenge što možemo i provjeriti pronalazeći datoteku (u ovom slučaju sliku) na lokalnom računalu.
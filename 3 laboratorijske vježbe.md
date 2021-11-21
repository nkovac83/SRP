# 3. laboratorijske vježbe

November 9, 2021 

Cilj vježbe je primjeniti teoreteske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične krito mehanizme: *message authentication code (MAC)* i *digitalne potpise* zasnovane na javnim ključevima.

### Izazov 1

- Implementirajmo zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg *message authentication code (MAC)* algoritma. Pri tome koristimo HMAC mehanizam iz Python biblioteka `[cryptography](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)`.
- U lokalnom direktoriju smo kreirali tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želimo zaštititi - message.txt
- u sljedećem kodu:  pišemo funkciju za izračun MAC vrijednosti za danu poruku te funkciju za provjeru validnosti MAC-a za danu poruku:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = b"my secret"

    with open("message.txt", "rb") as file:
        content = file.read()

    mac = generate_MAC(key, content)

    with open("message.sig", "wb") as file:
        file.write(mac)
    
    with open("message.sig", "rb") as file:
        signature = file.read()

    is_authentic = verify_MAC(key, signature, content)
    print(is_authentic)
```

- otvaramo datoteku message.txt i učitajemo sadržaj datoteke u memoriju, generiramo `mac`, otvaramo datoteku message.sig i unesemo `mac` te iz tako zapisane datoteke čitamo `content` i spremamo ga u `signature`. Funkcija `verifiy_mac` provjerava je li poruka validna (True) ili je mijenjana (False).

```bash
(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
b'nove mjere'

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
2441d2233b0d909031654780d28089ecf5545d5e15672d777b2febf1a6995861

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
True

(marino_juric) C:\Users\A507\marino_juric\marino_juric>python .\message_integrity.py
False
```

- nakon što smo promijenili sadržaj message.txt MAC poruke nije validan i ispisuje se False

### Izazov 2

- U ovom izazovu želimo utvrditi vremenski ispravnu skevencu transakcija sa odgovarajućim dionicama. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju [http://a507-server.local](http://a507-server.local/).
- Preuzimamo program `wget` dostupan na [wget download](https://eternallybored.org/misc/wget/) i zatim ga pohranjujemo u direktorij gdje ćemo pisati Python skriptu za rješavanje ovog izazova.
- Osobne izazove preuzimamo izvršavanjem sljedeće naredbe u terminalu:
    
    `wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/<juric_marino>/`
    
- Sa servera preuzimamo personalizirane izazove (direktorij `juric_marino/mac_challege`). Nalozi se nalaze u datotekama označenim kao `order_<n>.txt` a odgovarajući autentikacijski kod (*digitalni potpis*) u datotekama `order_<n>.sig`.
- Tajna vrijednost koja se koristi kao ključ u MAC algoritmu dobivena je iz našeg imena:

```python
key = "juric_marino".encode()
```

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os 

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":
    key = "juric_marino".encode()

    path = os.path.join("challenges", "juric_marino", "mac_challenge")
        
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"
        msg_filepath = os.path.join(path, msg_filename)
        sig_filepath = os.path.join(path, sig_filename)

        with open(msg_filepath, "rb") as file:
            msg = file.read()   
        with open(sig_filename, "rb") as file:
            sig = file.read()  

        is_authentic = verify_MAC(key, sig, msg)

        print(f'Message {msg.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

- spremamo u `path` /challenges/juric_marino/mac_challenge na koji u svakom ponavljanju for petlje join-amo `msg_filename` i `sig_filename` koje se povećavaju kako brojač raste (datoteke se zovu `order_{ctr}.txt` i `order_{ctr}.sig` pri čemu je `ctr` brojač koji se povećava).
- Čitamo iz tih datoteka i spremamo sadržaj u `msg` i `sig` koje zajedno s `key` šaljemo funkciji `verify_mac` koja provjerava je li MAC validan.
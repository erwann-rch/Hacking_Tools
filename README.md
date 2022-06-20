# Hacking_Tools
***

# /!\ WORK IN PROGRESS ... 
All the hacking tools I coded


## Cryptography
**
- ```Fernet.py``` : Permit to encrypt and decrypt a file entered in parameter with a filekey. This use the *__symetric encryption__* algorithm of Fernet.
            **__USAGE__** : ```python3 Fernet.py {-c/-d} -F [filename]```
            
- ```Cesar.py``` : Permit to encrypt and decrypt a file with a key or not, both entered in parameters. This use the well know *__symetric encryption__* algorithm of Cesar with a little difference : the shift increase at each characters, it's improved Cesar cypher.                            
        **__USAGE__** : ```python3 Cesar.py {-c/-d} -F [filename] {-k INT}``` (if no key are specified in encryption process that's gonna take 1 as the first shift and in decryption process that's gonna bruteforce all the 26 possibilities for the first shift).
 

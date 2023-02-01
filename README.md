# 🔒 ft_ssl

# MD5
- MD5 (128 bits)
- SHA-1 (160bits)
- SHA-2 (256-512bits)

Ces 3 fonctions de hashage se base sur la construction de [Merkle-Damgard](https://fr.wikipedia.org/wiki/Construction_de_Merkle-Damg%C3%A5rd)

<img width="75%" align="center" alt="Construction Merkle-Damgard" src="https://user-images.githubusercontent.com/22857002/207308481-d876e9a9-d651-433b-b38a-7dec247fac00.png"></img>


> La construction de Merkle-Damgård emploie une fonction de compression avec une entrée et une sortie de taille fixe, et divise le message à hacher en blocs de taille fixe. Les blocs sont ensuite envoyés les uns après les autres dans la fonction de compression. Le résultat de chaque compression est ensuite transmis au bloc suivant selon plusieurs schémas :
> 
> - Miyaguchi-Preneel
> - Matyas-Meyer-Oseas
> - Davies-Meyer
> 
> Le premier bloc utilise un vecteur d'initialisation constant puisque aucun autre bloc ne le précède. 

## Etape Algo MD5
1. Preparation
   1. On divise le message en blocs de 512 bits.
   2. On applique un remplissage de manière à avoir un message dont la longueur est un multiple de 512
   3. On y ajoute la taille (en 64bits) totale du message a la fin.
2. Calcule du hash
   1. On envoie chacun des blocs de 512 bits dans la fonction de hashage
   2. On additionne le retour de la fonction a la precendente valeur
3. Affichage du hash
   1. On convertie les 4 entiers en little endian
   2. On l'affiche en hexa

![lol](https://www.hds.utc.fr/~wschon/sr06/crypto/images/md5_1.gif)

# DES

![Diagram DES](https://user-images.githubusercontent.com/22857002/216019624-0be004af-b54c-4a16-aea7-88596f36a500.svg)

## Pseudocode

```C
// Pre-processing: padding with zeros
append padding until len in bits ≡ 0 (mod 64)

var long key // The keys given by the user
var long keys[16]
var long left, right

// Generate Keys

// PC1 (64bits to 56bits) 
key := permutation(key, PC1)
left := (key rightshift 28) and 0xFFFFFFF
right := key and 0xFFFFFFF

for i from 0 to 16 do
	right := right rightrotate KEY_shift[i]
	left := left rightrotate  KEY_shift[i]
	var long concat := (left leftshift 28) or right
	// PC2 (56bits to 48bits)
	keys[i] := permutation(concat, PC2)
end for

// To decrypt a message reverse the order of the keys
if decrypt do
	reverse keys
end if

// Encrypt or Decrypt
for each 64-bit chunk of padded message do
	var long tmp

	// IP
	chunk := permutation(chunk, IP)
	left := chunk rightshift 32
	right := chunk and 0xFFFFFFFF
	for i from 0 to 16 do
		tmp := right
		// E (32bits to 48bits)
		right := expansion(right, E)
		right := right xor keys[i]
		// Substitution (48bits to 32bits)
		right := substitution(right)
		// P
		right := permutation(right, P)
		right := right xor left
		left := tmp
	end for
	// Concat right and left
	var long cipher_chunk := (right rightshift 32) or left
	// FP
	cipher_chunk := permutation(cipher_chunk, FP)
end for
```

## Pense bete
![XOR diagram](https://user-images.githubusercontent.com/22857002/216021133-94ce4136-2ecd-46ee-ac55-a6133c00bee0.png)

## Source
- [Youtube - Complément : Fonctions de hachage](https://www.youtube.com/watch?v=-k_axU98AZ4)
- [Wikipedia MD5](https://fr.wikipedia.org/wiki/MD5)
- [Etude d'une fonction de hachage : le MD5](https://www.bibmath.net/crypto/index.php?action=affiche&quoi=moderne/md5)
- [Wikipedia Sha256](https://en.wikipedia.org/wiki/SHA-2)
- [DES algo - Scaler](https://www.scaler.com/topics/des-algorithm/)
- [Cryptage symetrique DES - Youtube](https://www.youtube.com/watch?v=eIbgy_ra9Us)

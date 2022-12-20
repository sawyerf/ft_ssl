# ft_ssl_md5

## How do you do you do what you going to do do ?

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

## Source
- [Youtube - Complément : Fonctions de hachage](https://www.youtube.com/watch?v=-k_axU98AZ4)
- [Wikipedia MD5](https://fr.wikipedia.org/wiki/MD5)
- [Etude d'une fonction de hachage : le MD5](https://www.bibmath.net/crypto/index.php?action=affiche&quoi=moderne/md5)
- [Wikipedia Sha256](https://en.wikipedia.org/wiki/SHA-2)
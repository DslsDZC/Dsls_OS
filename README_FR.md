[English](#en) | [Español](#es) | [Français](#fr) | [Deutsch](#de) | [中文](#zh)

# Dsls_OS

[](https://github.com/DslsDZC/Dsls_OS)

Un noyau de système d'exploitation moderne développé en interne, prenant en charge l'architecture x86_64.

## 🚀 Architecture de Base

Non disponible

## 🛠️ Caractéristiques Techniques

| Module             | Détails d'Implémentation                                                    |
|--------------------|-----------------------------------------------------------------------------|
| Gestion Mémoire    | Allocateur SLAB + Isolation des Tables de Pages (voir mm/slab.c)           |
| Ordonnancement     | File d'Attente à Rétroaction Multiniveaux (kernel/sched.c)                 |
| Virtualisation     | Support Intel VMX (arch/x86_64/vmx.c)                                       |
| Système de Stockage| Pilote AHCI + Double FS Ext2/FAT32 (drivers/ahci.c, fs/ext2.c)              |
| Pile Réseau        | Pilote e1000 + Pile TCP/IP (drivers/e1000.c)                                 |

## 📦 Guide de Compilation

Voici le guide de compilation :

``
# Installer la chaîne d'outils
sudo apt install clang-15 lld qemu-system-x86
# Compiler le noyau
make ARCH=x86_64
# Créer l'image de démarrage
make image
# Démarrer QEMU
make run
``

## 🌐 Exemple de Sortie

Voici un exemple de sortie :

``
[ OK ] Initialized SMP (4 CPUs)
[ OK ] Memory: 1024MB @ 0x100000
[ OK ] AHCI Controller: 2 Ports Initialized
[ OK ] EXT2 FS: Mounted rootfs at /dev/sda1
``

## 🤝 Contribution

1.  Forker le dépôt
2.  Créer une branche de fonctionnalité (git checkout -b feat/nouvelle-fonctionnalite)
3.  Commiter les modifications (git commit -m 'Ajout d'une fonctionnalité incroyable')
4.  Pousser vers la branche (git push origin feat/nouvelle-fonctionnalite)
5.  Ouvrir une Pull Request

## 📝 Licence

Apache 2.0 © 2025 L'équipe de développement Dsls

## 📂 Structure de Fichiers Recommandée

Voici la structure de fichiers recommandée :

``
/os
├── Makefile        # Automatisation de la compilation
├── arch
│   └── x86_64
│       ├── boot.asm    # Chargeur d'amorçage
│       ├── smp.c       # Support multi-cœur
│       └── vmx.c       # Virtualisation
├── drivers
│   ├── pci.c       # Pilote PCI
│   ├── ahci.c      # Pilote SATA
│   └── e1000.c     # Pilote de carte réseau (NIC)
├── fs
│   ├── vfs.c       # Système de Fichiers Virtuel (VFS)
│   ├── ext2.c      # Implémentation EXT2
│   └── fat32.c     # Implémentation FAT32
├── kernel
│   ├── main.c      # Point d'entrée du noyau
│   ├── task.c      # Gestion des processus
│   ├── sched.c     # Ordonnanceur
│   └── syscall.c   # Appels système
├── lib
│   ├── string.c    # Utilitaires de chaînes de caractères
│   ├── elf.c       # Chargeur ELF
│   └── list.c      # Liste chaînée
├── mm
│   ├── page.c      # Tables de pages
│   ├── slab.c      # Allocation mémoire
│   └── vma.c       # Zones de Mémoire Virtuelle (VMA)
├── net
│   ├── ip.c        # Protocole IP
│   ├── tcp.c       # Protocole TCP
│   └── socket.c    # API Socket
└── user
    ├── init.c      # Initialisation utilisateur
    └── shell.c     # Implémentation du Shell
``

---

## 🐛 Suivi des Problèmes

**VERSION :** 1.2
**PROJET :** DSLS_OS
**DATE :** 2023-10-15

### [CATÉGORIE "Problèmes Hérités Non Résolus"]

**PROBLÈME N° :** BUG-004
**FICHIER :** kernel/sched.c
**PLAGE DE LIGNES :** 50-55
**SÉVÉRITÉ :** ⚠️ CRITIQUE
**TYPE :** Erreur Logique
**DESC. :** Algorithme de dégradation de priorité incorrect dans `schedule()`
**EXTRAIT DE CODE :**

``
p->counter = (p->counter >> 2) + p->priority;
``

**ANALYSE :** Un décalage à droite de 2 bits provoque une dégradation plus rapide de la tranche de temps que prévu, recommander un décalage de 1 bit
**FICHIERS ASSOCIÉS :** `include/sched.h kernel/task.c`

**PROBLÈME N° :** BUG-005
**FICHIER :** drivers/ahci.c
**LIGNE :** 27
**SÉVÉRITÉ :** ⚠️ CRITIQUE
**TYPE :** Fuite de Ressources
**DESC. :** `cl_base` alloué mais non libéré
**EXTRAIT DE CODE :**

``
cl_base = alloc_phys_pages(1);
``

**DÉTAILS :** Fuite de mémoire physique de 4KB par initialisation de port, ajouter `free_phys_pages` après la désactivation de `port->cmd`

### [CATÉGORIE "Nouvelles Découvertes Critiques"]

**PROBLÈME N° :** BUG-006
**FICHIER :** kernel/main.asm
**LIGNE :** 29
**SÉVÉRITÉ :** 🔥 FATAL
**TYPE :** Erreur de l'Éditeur de Liens
**DESC. :** Symbole non défini `kernel_main`
**EXTRAIT DE CODE :**

``
    jmp kernel_main
``

**SOLUTION :**

1.  Définir explicitement le point d'entrée dans `linker.ld`
2.  S'assurer de la déclaration extern pour `kernel_main`

**PROBLÈME N° :** BUG-007
**FICHIER :** mm/slab.c
**LIGNE :** 55
**SÉVÉRITÉ :** ⚠️ CRITIQUE
**TYPE :** Défaut de Concurrence
**DESC. :** Barrière mémoire manquante dans le spinlock
**EXTRAIT DE CODE :**

``
#define spin_unlock(lock) __sync_lock_release(lock)
``

**REPRODUCTION :** L'incohérence du cache peut causer des erreurs d'état de verrou en SMP
**CORRECTIF :**

``
#define spin_unlock(lock) \
    __asm__ __volatile__("" ::: "memory"); \
    __sync_lock_release(lock);
``

### [VALIDATION]

**SOMME DE CONTRÔLE :** 89A3F2C1
**STATUT :** NON RÉSOLU
**ORDRE DE PRIORITÉ :** `BUG-006 > BUG-007 > BUG-004 > BUG-005`

## Liste des Corrections de Défauts de Code (Version Complète)

1.  Fuite mémoire du pilote AHCI
    * Fichier : drivers/ahci.c Lignes : 18-19
    * Symptôme : Les variables cl_base/fis_base sont allouées de manière répétée mais non libérées
    * Correctif : Supprimer les déclarations en double, établir une liste chaînée globale de gestion de la mémoire pour suivre l'allocation des pages physiques

2.  Énumération manquante des périphériques de pont PCI
    * Fichier : drivers/pci.c Lignes : 68-73
    * Symptôme : Les périphériques du bus secondaire du pont PCI-PCI ne sont pas scannés de manière récursive
    * Correctif : Lorsqu'un périphérique de pont est détecté, lire le numéro du bus secondaire et appeler récursivement la fonction d'énumération

3.  Condition de concurrence dans l'état du pilote de la carte réseau
    * Fichier : drivers/e1000.c Ligne : 45
    * Symptôme : Une erreur de syntaxe "=while" provoque l'échec de la détection de l'état du registre
    * Correctif : Supprimer le signe égal redondant, ajouter la gestion du bouclage de l'index de l'anneau de tampon DMA

4.  Condition de concurrence dans l'ordonnanceur
    * Fichier : kernel/sched.c Ligne : 50
    * Symptôme : La mise à jour du compteur de tâches manque de protection par verrou dans un environnement multi-cœur
    * Correctif : Ajouter des opérations de désactivation/activation des interruptions locales avant et après la modification du compteur

5.  Fonctions de remplacement (stubs) d'appels système manquantes
    * Fichier : kernel/syscall.c Lignes : 13-14
    * Symptôme : Les fonctions mmput/vfs_close ne sont pas implémentées, provoquant des erreurs de l'éditeur de liens
    * Correctif : Ajouter des fonctions de remplacement à symbole faible pour implémenter les opérations de base de libération de mémoire/fichier

6.  Erreur de registre de segment du chargeur d'amorçage
    * Fichier : arch/x86_64/boot.asm Lignes : 21-25
    * Symptôme : Les paramètres du sélecteur de segment en mode protégé sont incomplets
    * Correctif : Compléter l'initialisation des registres de segment fs/gs/ss, corriger la longueur limite du descripteur GDT

7.  Faux partage du cache SLAB
    * Fichier : mm/slab.c Ligne : 15
    * Symptôme : L'accès par plusieurs cœurs CPU à la même ligne de cache entraîne une dégradation des performances
    * Correctif : Ajouter un remplissage d'alignement de 64 octets dans la structure slab_cache

8.  Exception de libération de grande page
    * Fichier : mm/page.c Ligne : 93
    * Symptôme : L'adresse de libération de la mémoire physique supérieure à 1 page n'est pas alignée
    * Correctif : Effectuer une opération de masque d'alignement PAGE_SIZE lors du calcul de l'adresse de base de la mémoire physique

9.  Troncature des noms de fichiers longs FAT32
    * Fichier : fs/fat32.c Lignes : 127-135
    * Symptôme : La somme de contrôle des entrées VFAT n'est pas validée, ce qui provoque des noms de fichiers corrompus
    * Correctif : Ajouter une logique de comparaison des sommes de contrôle, rejeter les entrées de noms longs dont la somme de contrôle a échoué

10. Défaut de parcours de répertoire Ext2
    * Fichier : fs/ext2.c Ligne : 88
    * Symptôme : Les fichiers supprimés apparaissent toujours dans la liste du répertoire
    * Correctif : Ajouter un filtrage pour les entrées avec un numéro d'inode 0 ou un type de fichier inconnu

11. Erreur de chemin de compilation croisée
    * Fichier : Makefile Ligne : 5
    * Symptôme : Le répertoire d'en-têtes du noyau n'est pas correctement pointé
    * Correctif : Changer "-I/chemin/vers/compilateur-croise/include" en "-I./lib"

12. Instruction d'assembleur manquante
    * Fichier : arch/x86_64/smp.c Ligne : 42
    * Symptôme : Le TLB n'est pas vidé, ce qui rend le mappage d'adresses virtuelles invalide
    * Correctif : Insérer la séquence d'instructions "invlpg" après l'initialisation de l'APIC

13. Descripteur de mémoire UEFI manquant
    * Fichier : kernel/main.c Ligne : 34
    * Symptôme : La structure EFI_MEMORY_DESCRIPTOR n'est pas définie
    * Correctif : Ajouter la définition de la structure incluant les champs Type/PhysAddr/NumPages

14. Exception de support de virtualisation
    * Fichier : lib/vmx.h Lignes : 28-30
    * Symptôme : Les exigences d'alignement de la région VMXON ne sont pas gérées
    * Correctif : Allouer une région VMXON alignée sur 4 Ko et ajouter la validation des masques CR0/CR4
    
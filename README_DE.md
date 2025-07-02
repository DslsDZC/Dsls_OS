[English](#en) | [Español](#es) | [Français](#fr) | [Deutsch](#de) | [中文](#zh)

# Dsls_OS

[](https://github.com/DslsDZC/Dsls_OS)

Ein selbst entwickelter moderner Betriebssystemkern, der die x86_64-Architektur unterstützt.

## 🚀 Kernarchitektur

Nicht verfügbar

## 🛠️ Technische Merkmale

| Modul               | Implementierungsdetails                                                    |
|---------------------|----------------------------------------------------------------------------|
| Speicherverwaltung  | SLAB-Allokator + Seitentabellenisolierung (siehe mm/slab.c)                |
| Prozess-Scheduling  | Multilevel-Feedback-Warteschlange (kernel/sched.c)                         |
| Virtualisierung     | Intel VMX-Unterstützung (arch/x86_64/vmx.c)                                |
| Speichersystem      | AHCI-Treiber + Duales FS Ext2/FAT32 (drivers/ahci.c, fs/ext2.c)            |
| Netzwerkstack       | e1000-Treiber + TCP/IP-Stack (drivers/e1000.c)                               |

## 📦 Bauanleitung

Hier ist die Bauanleitung:

``
# Toolchain installieren
sudo apt install clang-15 lld qemu-system-x86
# Kernel bauen
make ARCH=x86_64
# Boot-Image erstellen
make image
# QEMU starten
make run
``

## 🌐 Beispielausgabe

Hier ist eine Beispielausgabe:

``
[ OK ] Initialized SMP (4 CPUs)
[ OK ] Memory: 1024MB @ 0x100000
[ OK ] AHCI Controller: 2 Ports Initialized
[ OK ] EXT2 FS: Mounted rootfs at /dev/sda1
``

## 🤝 Mitwirken

1.  Das Repository forken
2.  Feature-Branch erstellen (git checkout -b feat/neues-feature)
3.  Änderungen committen (git commit -m 'Füge tolles Feature hinzu')
4.  Auf den Branch pushen (git push origin feat/neues-feature)
5.  Pull-Request öffnen

## 📝 Lizenz

Apache 2.0 © 2025 Dsls Entwicklungsteam

## 📂 Empfohlene Dateistruktur

Hier ist die empfohlene Dateistruktur:

``
/os
├── Makefile        # Build-Automatisierung
├── arch
│   └── x86_64
│       ├── boot.asm    # Bootloader
│       ├── smp.c       # Mehrkernunterstützung
│       └── vmx.c       # Virtualisierung
├── drivers
│   ├── pci.c       # PCI-Treiber
│   ├── ahci.c      # SATA-Treiber
│   └── e1000.c     # NIC-Treiber (Netzwerkkarte)
├── fs
│   ├── vfs.c       # Virtuelles Dateisystem (VFS)
│   ├── ext2.c      # EXT2-Implementierung
│   └── fat32.c     # FAT32-Implementierung
├── kernel
│   ├── main.c      # Kernel-Einstiegspunkt
│   ├── task.c      # Prozessverwaltung
│   ├── sched.c     # Scheduler
│   └── syscall.c   # Systemaufrufe
├── lib
│   ├── string.c    # String-Dienstprogramme
│   ├── elf.c       # ELF-Lader
│   └── list.c      # Verkettete Liste
├── mm
│   ├── page.c      # Seitentabellen
│   ├── slab.c      # Speicherzuweisung
│   └── vma.c       # Virtuelle Speicherbereiche (VMA)
├── net
│   ├── ip.c        # IP-Protokoll
│   ├── tcp.c       # TCP-Protokoll
│   └── socket.c    # Socket-API
└── user
    ├── init.c      # Benutzerinitialisierung
    └── shell.c     # Shell-Implementierung
``

---

## 🐛 Problemverfolgung

**VERSION:** 1.2
**PROJEKT:** DSLS_OS
**DATUM:** 2023-10-15

### [KATEGORIE "Ungelöste Altprobleme"]

**PROBLEM-NR.:** BUG-004
**DATEI:** kernel/sched.c
**ZEILENBEREICH:** 50-55
**SCHWEREGRAD:** ⚠️ KRITISCH
**TYP:** Logikfehler
**BESCHREIBUNG:** Falscher Prioritätsverfallsalgorithmus in `schedule()`
**CODEAUSSCHNITT:**

``
p->counter = (p->counter >> 2) + p->priority;
``

**ANALYSE:** Rechtsverschiebung um 2 Bits verursacht schnelleren Zeitscheibenverfall als vorgesehen, Verschiebung um 1 Bit empfohlen
**ZUGEHÖRIGE DATEIEN:** `include/sched.h kernel/task.c`

**PROBLEM-NR.:** BUG-005
**DATEI:** drivers/ahci.c
**ZEILE:** 27
**SCHWEREGRAD:** ⚠️ KRITISCH
**TYP:** Ressourcenleck
**BESCHREIBUNG:** `cl_base` zugewiesen, aber nicht freigegeben
**CODEAUSSCHNITT:**

``
cl_base = alloc_phys_pages(1);
``

**DETAILS:** 4KB physisches Speicherleck pro Port-Initialisierung, `free_phys_pages` nach Deaktivierung von `port->cmd` hinzufügen

### [KATEGORIE "Neue kritische Funde"]

**PROBLEM-NR.:** BUG-006
**DATEI:** kernel/main.asm
**ZEILE:** 29
**SCHWEREGRAD:** 🔥 FATAL
**TYP:** Linker-Fehler
**BESCHREIBUNG:** Undefiniertes Symbol `kernel_main`
**CODEAUSSCHNITT:**

``
    jmp kernel_main
``

**LÖSUNG:**

1.  Einstiegspunkt explizit in `linker.ld` definieren
2.  Extern-Deklaration für `kernel_main` sicherstellen

**PROBLEM-NR.:** BUG-007
**DATEI:** mm/slab.c
**ZEILE:** 55
**SCHWEREGRAD:** ⚠️ KRITISCH
**TYP:** Nebenläufigkeitsfehler
**BESCHREIBUNG:** Fehlende Speicherbarriere im Spinlock
**CODEAUSSCHNITT:**

``
#define spin_unlock(lock) __sync_lock_release(lock)
``

**REPRODUKTION:** Cache-Inkohärenz kann zu Sperrstatusfehlern in SMP führen
**FIX:**

``
#define spin_unlock(lock) \
    __asm__ __volatile__("" ::: "memory"); \
    __sync_lock_release(lock);
``

### [VALIDIERUNG]

**PRÜFSUMME:** 89A3F2C1
**STATUS:** UNGELÖST
**PRIORITÄTSREIHENFOLGE:** `BUG-006 > BUG-007 > BUG-004 > BUG-005`

## Liste der Codefehlerkorrekturen (Vollversion)

1.  Speicherleck im AHCI-Treiber
    * Datei: drivers/ahci.c Zeilen: 18-19
    * Symptom: Die Variablen cl_base/fis_base werden wiederholt zugewiesen, aber nicht freigegeben
    * Fix: Doppelte Deklarationsanweisungen entfernen, eine globale Speicherverwaltungs-Verkettungsliste einrichten, um die Zuweisung physischer Seiten zu verfolgen

2.  Fehlende Aufzählung von PCI-Brückengeräten
    * Datei: drivers/pci.c Zeilen: 68-73
    * Symptom: Sekundärbusgeräte der PCI-PCI-Brücke werden nicht rekursiv gescannt
    * Fix: Wenn ein Brückengerät erkannt wird, die Sekundärbusnummer lesen und die Aufzählungsfunktion rekursiv aufrufen

3.  Race-Condition im Zustand des Netzwerkkartentreibers
    * Datei: drivers/e1000.c Zeile: 45
    * Symptom: Ein Syntaxfehler "=while" führt zum Fehlschlagen der Registerzustandserkennung
    * Fix: Redundantes Gleichheitszeichen entfernen, Behandlung für den Index-Wrap-Around des DMA-Pufferrings hinzufügen

4.  Race-Condition im Scheduler
    * Datei: kernel/sched.c Zeile: 50
    * Symptom: Die Aktualisierung des Task-Zählers ist in einer Mehrkernumgebung nicht durch eine Sperre geschützt
    * Fix: Lokale Interrupt-Deaktivierungs-/-Aktivierungsoperationen vor und nach der Zähleränderung hinzufügen

5.  Fehlende Systemaufruf-Stub-Funktionen
    * Datei: kernel/syscall.c Zeilen: 13-14
    * Symptom: Die Funktionen mmput/vfs_close sind nicht implementiert, was zu Linker-Fehlern führt
    * Fix: Stub-Funktionen mit schwachen Symbolen hinzufügen, um grundlegende Speicher-/Dateifreigabeoperationen zu implementieren

6.  Fehler im Segmentregister des Bootloaders
    * Datei: arch/x86_64/boot.asm Zeilen: 21-25
    * Symptom: Die Segmentselektor-Einstellungen im Protected Mode sind unvollständig
    * Fix: Initialisierung der Segmentregister fs/gs/ss ergänzen, Längenbegrenzung des GDT-Deskriptors korrigieren

7.  False Sharing im SLAB-Cache
    * Datei: mm/slab.c Zeile: 15
    * Symptom: Zugriff mehrerer CPU-Kerne auf dieselbe Cache-Zeile führt zu Leistungseinbußen
    * Fix: 64-Byte-Alignment-Padding in der slab_cache-Struktur hinzufügen

8.  Ausnahme bei der Freigabe großer Seiten
    * Datei: mm/page.c Zeile: 93
    * Symptom: Die Freigabeadresse für physischen Speicher, der größer als 1 Seite ist, ist nicht ausgerichtet
    * Fix: PAGE_SIZE-Ausrichtungsmaskenoperation bei der Berechnung der physischen Adressbasis durchführen

9.  Kürzung langer Dateinamen bei FAT32
    * Datei: fs/fat32.c Zeilen: 127-135
    * Symptom: Die VFAT-Eintragsprüfsumme wird nicht validiert, was zu verstümmelten Dateinamen führt
    * Fix: Prüfsummenvergleichslogik hinzufügen, Lange Namenseinträge mit fehlgeschlagener Prüfsumme verwerfen

10. Fehler beim Durchlaufen von Ext2-Verzeichnissen
    * Datei: fs/ext2.c Zeile: 88
    * Symptom: Gelöschte Dateien erscheinen immer noch in der Verzeichnisliste
    * Fix: Filterung für Einträge mit Inode-Nummer 0 oder unbekanntem Dateityp hinzufügen

11. Fehler im Cross-Compilation-Pfad
    * Datei: Makefile Zeile: 5
    * Symptom: Das Kernel-Header-Verzeichnis ist nicht korrekt angegeben
    * Fix: "-I/pfad/zum/cross-compiler/include" zu "-I./lib" ändern

12. Fehlende Assembler-Instruktion
    * Datei: arch/x86_64/smp.c Zeile: 42
    * Symptom: Der TLB wird nicht geleert, was die virtuelle Adresszuordnung ungültig macht
    * Fix: "invlpg"-Instruktionssequenz nach der APIC-Initialisierung einfügen

13. Fehlender UEFI-Speicherdeskriptor
    * Datei: kernel/main.c Zeile: 34
    * Symptom: Die Struktur EFI_MEMORY_DESCRIPTOR ist nicht definiert
    * Fix: Strukturdefinition einschließlich der Felder Type/PhysAddr/NumPages hinzufügen

14. Ausnahme bei der Virtualisierungsunterstützung
    * Datei: lib/vmx.h Zeilen: 28-30
    * Symptom: Die Ausrichtungsanforderungen für die VMXON-Region werden nicht behandelt
    * Fix: Eine auf 4 KB ausgerichtete VMXON-Region zuweisen und die CR0/CR4-Maskenvalidierung hinzufügen

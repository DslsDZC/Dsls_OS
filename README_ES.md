[English](#en) | [Español](#es) | [Français](#fr) | [Deutsch](#de) | [中文](#zh)

# Dsls_OS

[](https://github.com/DslsDZC/Dsls_OS)

Un núcleo del sistema operativo moderno autodesarrollado que soporta la arquitectura x86_64.

## 🚀 Arquitectura central

无

## 🛠️ Características técnicas

| Módulo | Detalles de implementación |
| ---------------- | ----------------------------------------------------------------------- |
| Memoria mgmt | Asignador Slab para objetos pequeños + aislamiento mediante tablas de páginas de 4 niveles (PML4) (ver MM/Slab.C) |
| Proceso de programación | Cola de retroalimentación multinivel (kernel/sched.c) |
| Virtualización | Soporte para Intel VT-x mediante VMX root mode con EPT (Arch/x86_64/vmx.c) |
| Sistema de almacenamiento | Conductor AHCI + ext2/fat32 dual FS (controladores/ahci.c, fs/ext2.c) |
| Pila de red | Controlador E1000 + TCP/IP Stack (controladores/E1000.C) |

## 📦 Guía de construcción

Aquí está la guía de construcción:

```bash
# Instale la cadena de herramientas Sudo APT Instalar Clang-15 LLD QEMU-System-X86 
# Build Kernel Make Arch = x86_64 
# Crear imagen de arranque hacer imagen 
# Inicio QEMU Hacer ejecutar
```

## 🌐 Salida de muestra

Aquí está la salida de muestra:

```text
[ OK ] Initialized SMP (4 CPUs) 
[ OK ] Memory: 1024MB @ 0x100000 
[ OK ] AHCI Controller: 2 Ports Initialized 
[ OK ] EXT2 FS: Mounted rootfs at /dev/sda1
```

## 🤝 Contribución

1. Bifurca el repositorio
2. Crear rama de características (Git Checkout -B Feat/New -Fature)
3. Cambios de confirmación (Git Commit -M 'Agregar característica sorprendente')
4. Push to Branch (Git Push Origin Feat/New-Fature)
5. Solicitud de extracción de apertura

## 📝 Licencia

Apache 2.0 © 2025 Dsls Development Team

## 📂 Estructura de archivo recomendada

Aquí está la estructura de archivo recomendada:

```text
/os 
├── Makefile       # Automatización de construcción
├── arch 
│   └── x86_64 
│       ├── boot.asm   # Cargador de arranque
│       ├── smp.c      # Soporte multicore
│       └── vmx.c      # Virtualización
├── drivers 
│   ├── pci.c     # Controlador PCI
│   ├── ahci.c    # Controlador SATA
│   └── e1000.c   # Controlador de red
├── fs 
│   ├── vfs.c     # Sistema de archivos virtual
│   ├── ext2.c    # Implementación EXT2
│   └── fat32.c   # Implementación FAT32
├── kernel 
│   ├── main.c    # Entrada del kernel
│   ├── task.c    # Gestión de procesos
│   ├── sched.c   # Planificador
│   └── syscall.c # Llamadas al sistema
├── lib 
│   ├── string.c  # Utilidades de cadenas
│   ├── elf.c     # Cargador ELF
│   └── list.c    # Lista enlazada
├── mm 
│   ├── page.c    # Tablas de páginas
│   ├── slab.c    # Asignación de memoria
│   └── vma.c     # Áreas de memoria virtual
├── net 
│   ├── ip.c      # Protocolo IP
│   ├── tcp.c     # Protocolo TCP
│   └── socket.c  # API de sockets
└── user 
    ├── init.c    # Inicio de usuario
    └── shell.c   # Implementación de shell
```

---

## 🐛 Tracker de emisión

** Versión: ** 1.2
** Proyecto: ** Dsls_OS
** Fecha: ** 2025-05-11

### [Categoría "Problemas heredados no resueltos"]

** Problema: ** Bug-004
** Archivo: ** kernel/sched.c
** line_range: ** 50-55
** Severidad: ** ⚠️ Crítico
** Tipo: ** Error lógico
** DESC: ** Algoritmo de desintegración de prioridad incorrecta en `shell ()`
** code_snippet: **

```c
p->counter = (p->counter >> 2) + p->priority;
```

** Análisis: ** El cambio derecho por 2 bits causa una descomposición de hilos de tiempo más rápido que el diseñado, recomendar el cambio por 1 bit
** Relation_files: ** `include/sched.h kernel/task.c`

** Problema: ** Bug-005
** archivo: ** controladores/ahci.c
** Línea: ** 27
** Severidad: ** ⚠️ Crítico
** Tipo: ** Fuga de recursos
** Desc: ** `cl_base` asignado pero no lanzado
** code_snippet: **

```c
cl_base = alloc_phys_pages(1);
```

** Detalles: ** Fugas de memoria física de 4kb por puerto init, agregue `free_phys_pages` después de` puerto-> cmd` deshabilitado

### [Categoría "Nuevos hallazgos críticos"]

** Problema: ** Bug-006
** Archivo: ** kernel/main.asm
** Línea: ** 29
** Severidad: ** 🔥 fatal
** Tipo: ** Error de enlazador
** Desc: ** Símbolo indefinido `Kernel_Main`
** code_snippet: **

```assembly
    jmp kernel_main
```

**SOLUCIÓN:**

1. Definir explícitamente el punto de entrada en `Linker.ld`
2. Asegurar la declaración externa para `kernel_main`

** Problema: ** Bug-007
** Archivo: ** mm/slab.c
** Línea: ** 55
** Severidad: ** ⚠️ Crítico
** Tipo: ** Defecto de concurrencia
** Desc: ** Falta de barrera de memoria en Spinlock
** code_snippet: **

```c
#define spin_unlock(lock) __sync_lock_release(lock)
```

** Reproducir: ** La incoherencia de caché puede causar errores de estado de bloqueo en SMP
**ARREGLAR:**

```c
#define spin_unlock(lock) \
    __asm__ __volatile__("" ::: "memory"); \
    __sync_lock_release(lock);
```
### [Validación]

** SUMACIÓN DE CHECK: ** 89A3F2C1
** Estado: ** no resuelto
** Priority_order: ** `Bug-006> Bug-007> Bug-004> Bug-005`

## Lista de corrección de defectos del código (versión completa

1. Fugas de memoria del controlador ahci
- Archivo: controladores/AHCI.C Líneas 18-19
- Síntoma: variables CL_BASE/FIS_BASE asignadas repetidamente pero no liberadas
- Corrección: eliminar declaraciones de declaración duplicadas, establecer una lista vinculada de gestión de memoria global para rastrear la asignación de páginas físicas

2. Enumeración del dispositivo PCI del dispositivo PCI Falta
- Archivo: controladores/PCI.C Lines 68-73
- Síntoma: los dispositivos de autobuses secundarios del puente PCI-PCI no están escaneados recursivamente
- Corrección: cuando se detecte un dispositivo de puente, lea el número de bus secundario y llame recursivamente a la función de enumeración

3. Carrera de estado de conductor de tarjetas de red
- Archivo: controladores/E1000.C Línea 45
- Síntoma: "= While" El error de sintaxis hace que la detección de estado de registro falle
- Corrección: elimine el signo redundante igual, agregue el manejo envolvente del índice de anillo de búfer DMA

4. Condición de la carrera del planificador
- Archivo: kernel/sched.c Line 50
- Síntoma: la actualización del contador de tareas carece de protección de bloqueo en un entorno de múltiples núcleos
- Arreglar: agregue las operaciones de interrupción/habilitación de interrupción local antes y después de la modificación del contador

5. Funciones de pedal de llamadas del sistema faltantes
- Archivo: kernel/syscall.c líneas 13-14
- Síntoma: las funciones MMPut/VFS_Close no se implementan, causando errores de enlazador
- Corrección: agregue funciones de stub de símbolo débil para implementar operaciones básicas de versión de memoria/archivo

6. Error de registro del segmento del gestor de arranque
- Archivo: Arch/x86_64/boot.asm líneas 21-25
- Síntoma: la configuración del selector de segmento de modo protegido está incompleta
- Corrección: Suplemento FS/GS/SS Inicialización del registro del segmento, longitud del límite del descriptor GDT correcto

7. Cache de losa Falso Compartir
- Archivo: MM/Slab.C Line 15
- Síntoma: las CPU múltiples que acceden a la misma línea de caché conducen a la degradación del rendimiento
- FIJAR: agregue el relleno de alineación de 64 bytes en la estructura de Slab_Cache

8. Excepción de lanzamiento de la página grande
- Archivo: MM/Page.C Line 93
- Síntoma: la dirección de liberación de memoria física de más de 1 página no está alineada
- Corrección: Realice la operación de máscara de alineación de PAGE_SIZE al calcular la base de la dirección física

9. Fat32 Truncamiento largo del nombre de archivo
- Archivo: FS/FAT32.C Lines 127-135
- Síntoma: la suma de verificación de entrada de VFAT no está validada, causando nombres de archivos confusos
- Corrección: agregue la lógica de comparación de suma de verificación, descarte las entradas de nombre largo con suma de verificación fallida

10. Defecto transversal del directorio Ext2
- Archivo: FS/Ext2.C Line 88
- Síntoma: los archivos eliminados aún aparecen en la lista de directores
- Se corrige: agregue el filtrado para las entradas con el número de inodo 0 o el tipo de archivo desconocido

11. Error de ruta de compilación cruzada
- Archivo: Makefile Line 5
- Síntoma: el directorio de encabezado del núcleo no apunta correctamente a
-FIJAR: Cambiar "-i/ruta/a/compilador cruzado/incluir" a "-i./lib"

12. Falta la instrucción del ensamblador
- Archivo: Arch/x86_64/smp.c Line 42
- Síntoma: TLB no está enjuagado, lo que hace que el mapeo de direcciones virtuales se vuelva inválida
- Corrección: inserte la secuencia de instrucciones "invlpg" después de la inicialización APIC

13. Descriptor de memoria de UEFI faltante
- Archivo: Kernel/Main.C Line 34
- Síntoma: la estructura EFI_Memory_Descriptor no está definida
- FIJAR: Agregar definición de estructura que incluye los campos de tipo/Physaddr/Numpages

14. Excepción de soporte de virtualización
- Archivo: Lib/VMX.H Líneas 28-30
- Síntoma: no se manejan los requisitos de alineación de la región VMXON
- FIJAR: Asigne la región vmxon alineada de 4KB y agregue la validación de máscara CR0/CR4

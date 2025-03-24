# Program pro správu hesel (BPC-VBA projekt)

### Zadání projektu:
Vytvořte program, který bude umožňovat ukládání hesel do souboru v zašifrované podobě. Hesla budou chráněna hlavním heslem a bude je možné měnit nebo mazat.




## Autoři

- Petr Zelinka
- Jakub Semerád


## Požadavky pro zprovoznění

Nainstalovat platformu pro tvorbu software msys2 [MSYS2](https://www.msys2.org/).
V msys2 konzoli doinstalovat balíčky:  
```bash
    pacman -S mingw-w64-ucrt-x86_64-gcc
    pacman -S mingw-w64-ucrt-x86_64-gdb
    pacman -S mingw-w64-ucrt-x86_64-cunit
```  
  
Mít ve vývojovém prostředí přidané knihovny crypto a cunit. 
Přidat msys do proměnných prostředí systému.
```bash
    MINGW_HOME=C:\msys64\ucrt
    PATH=%PATH%;C:\msys64\ucrt\bin
```
## Jak zprovoznit

Naklonovat si tento repozitář.

```bash
   git clone https://ntb-2919-01s.utko.feec.vutbr.cz/bpc-vba/semeradj/password-manager.git

```

Importovat jako nový projekt do svého vývojového prostředí. Testováno v Eclipse. Sestavit. Program funguje přes parametry v konzoli, je odzkoušeno v externí cmd konzoli.




    
## O projektu

Uživatel si může vytvořit vlastní trezor chráněný hlavním heslem. Generuje se náhodná sůl a inicializační vektor. Hlavní heslo uživatele a sůl se spojí a zahešují algoritmem SHA256. Klíč je derivován z hlavního hesla a soli a heš je pro větší bezpečnost zašifrován algoritmem AES256 v režimu CBC. Zašifrovaný heš, sůl a IV se uloží do souboru, který si uživatel zvolil, zakódovaného v base64. Uživatel může přidat nové přihlašovací údaje služby, opět, heslo je zašifrováno pomocí AES256 v režimu CBC a zakódováno v base64. Po vytvoření trezoru musí být všechny operace s trezorem autentizována, v takovém případě se heš načte ze souboru, dekóduje, dešifruje a následně porovná. Uživatel může odstranit záznam o službě, změnit přihlašovací údeja služby, změnit hlavní heslo, přečíst hesla ze souboru v zašifrované podobě, přečíst službu v dešifrované podobě a odstranit trezor hesel.
# Použítí

        1. Vytvoření trezoru: `password-manager.exe -i [FILENAME]`
        2. Smazání trezoru: `password-manager.exe -i [FILENAME] -d`
        3. Přidání služby: `password-manager.exe -f [FILENAME] -a [SERVICENAME]`
        4. Smazání služby: `password-manager.exe -f [FILENAME] -d [SERVICENAME]`
        5. Přečtení trezoru: `password-manager.exe -f [FILENAME] -r`
        6. Přečtení služby: `password-manager.exe -f [FILENAME] -r [SERVICENAME]`
        7. Změna služby: `password-manager.exe -f [FILENAME] -e [SERVICENAME]`
        8. Změna hlavního hesla: `password-manager.exe -f [FILENAME] -e`

        Ve výchozím nastavení je trezor vytvořen do ~/

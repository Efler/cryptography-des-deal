# DES/DEAL Encryptor

Шифрование данных с помощью алгоритмов DES и DEAL

---

## Algorithms

Данная библиотека позволяет производить шифрование/дешифрование данных и файлов с помощью алгоритмов шифрования `Data Encryption Standard (DES)` и его усовершенствованной версией `Data Encryption Algorithm with Larger blocks (DEAL)`

**Параметры DES:**
* Размер блока: `64 бит`
* Размер ключа: `56 бит`
* Колличество раундов: `16`

**Параметры DEAL:**
* Размер блока: `128 бит`
* Размер ключа: `128`, `192` или `256 бит` _(в зависимости от конфигурации)_
* Количество раундов: `6` или `8` _(в зависимости от конфигурации)_

---

## Configuration

Оба алгоритма поддерживают различные режимы шифрования блоков и различные типы набивки блока

**Режимы шифрования блоков:**
* `ECB` - Electronic Codebook
* `CBC` - Cipher Block Chaining
* `PCBC` - Propagating Cipher Block Chaining
* `CFB` - Cipher Feedback
* `OFB` - Output Feedback
* `CTR` - Counter mode
* `RD` - Random Delta

**Типы набивки блока:**
* `Zeroz`
* `ANSI`
* `X.923`
* `PKCS7`
* `ISO10126`

Шифрование можно производить как синхронно, так и асинхронно _(количество потоков конфигурируется)_

---

## Usage

Шифрование/дешифрование и конфигурация производится через класс `EncryptorManager`

Конструктор класса принимает следующие параметры:
* Ключ шифрования _(64 или 128 бит в зависимости от алгоритма шифрования)_
* Алгоритм шифрования
   - `DES`
   - `DEAL_128`
   - `DEAL_192`
   - `DEAL_256`
* Режим шифрования блоков
   - `ECB`
   - `CBC`
   - `PCBC`
   - `CFB`
   - `OFB`
   - `CTR`
   - RandomDelta
* Тип набивки блока
   - `Zeroz`
   - `ANSI`
   - `X.923`
   - `PKCS7`
   - `ISO10126`
* Вектор инициализации


**Пример создания `EncryptorManager`**

```
// key = 0x133457788BBCDFF1
byte[] key = new byte[] {
        (byte) 0x13, (byte) 0x34, (byte) 0x57, (byte) 0x79,
        (byte) 0x9B, (byte) 0xBC, (byte) 0xDF, (byte) 0xF1
};

// initialization vector = 0x1F3400789AB5DEF7
 byte[] IV = new byte[]{
        (byte) 0x1F, (byte) 0x34, (byte) 0x00, (byte) 0x78,
        (byte) 0x9A, (byte) 0xB5, (byte) 0xDE, (byte) 0xF7
};

EncryptorManager manager = new EncryptorManager(
        key,
        EncryptorManager.EncryptionAlgorithm.DES,
        EncryptModes.Mode.CTR,
        Paddings.PaddingType.ISO10126,
        IV
);
```


**Шифрование/дешифрование байтов**

_синхронно_
```
byte[] plainText = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09
};

byte[] encryptedText = manager.encryptSync(plainText);      // шифрование
byte[] decryptedText = manager.decryptSync(encryptedText);  // дешифрование

// Arrays.equals(plainText, decryptedText)   --> true
```

_aсинхронно_
```
byte[] plainText = new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09
};

byte[] encryptedText = manager.encryptAsync(plainText, 5);      // шифрование (5 - количество задействованных потоков)
byte[] decryptedText = manager.decryptAsync(encryptedText, 5);  // дешифрование (5 - количество задействованных потоков)

// Arrays.equals(plainText, decryptedText)   --> true
```


**Шифрование/дешифрование файлов**

_синхронно_
```
manager.encryptFileSync("[input_file_path]", "[output_file_path]");  // шифрование
manager.decryptFileSync("[input_file_path]", "[output_file_path]");  // дешифрование
```

_aсинхронно_
```
manager.encryptFileAsync("[input_file_path]", "[output_file_path]", 5);  // шифрование (5 - количество задействованных потоков)
manager.decryptFileAsync("[input_file_path]", "[output_file_path]", 5);  // дешифрование (5 - количество задействованных потоков)
```

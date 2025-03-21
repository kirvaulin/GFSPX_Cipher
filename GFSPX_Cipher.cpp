#include <vector>
#include <array>
#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include <cstring>

using namespace boost::multiprecision;

// Определение S-блока (пример из статьи)
const std::array<uint8_t, 16> SBOX = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

// Обратный S-блок
const std::array<uint8_t, 16> INV_SBOX = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

// P-перестановка (пример из статьи)
const std::array<uint8_t, 32> P_PERMUTATION = {
    0, 8, 16, 24, 1, 9, 17, 25,
    2, 10, 18, 26, 3, 11, 19, 27,
    4, 12, 20, 28, 5, 13, 21, 29,
    6, 14, 22, 30, 7, 15, 23, 31
};

// Обратная P-перестановка
const std::array<uint8_t, 32> INV_P_PERMUTATION = {
    0, 4, 8, 12, 16, 20, 24, 28,
    1, 5, 9, 13, 17, 21, 25, 29,
    2, 6, 10, 14, 18, 22, 26, 30,
    3, 7, 11, 15, 19, 23, 27, 31
};

// Структура для хранения истории операций
struct History {
    uint16_t input;
    uint16_t a;
    uint16_t b;
};

std::vector<History> history;

// Функция F1 (ARX операции)
uint16_t F1_encrypt(uint16_t input, uint16_t key) {
    uint16_t a = (input << 5) | (input >> (16 - 5));  // Циклический сдвиг влево на 5
    uint16_t b = (input << 1) | (input >> (16 - 1));  // Циклический сдвиг влево на 1

    // Сохраняем историю для последующего дешифрования
    history.emplace_back(History{ input, a, b });

    return a ^ b ^ key;  // Только XOR
}

uint16_t F1_decrypt(uint16_t input, uint16_t key) {
    // Берём последние сохранённые значения из истории
    History h = history.back();
    history.pop_back();

    // Восстанавливаем исходное значение
    return h.a ^ h.b ^ key;
}

// Функция F2 (SPN структура)
uint32_t F2(uint32_t input, uint32_t key) {
    // Применение ключа
    input ^= key;

    // Применение S-блоков (8 S-блоков 4x4)
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t nibble = (input >> (4 * i)) & 0xF;  // Извлечение 4-битного блока
        nibble = SBOX[nibble];  // Применение S-блока
        output |= (uint32_t)nibble << (4 * i);  // Сборка результата
    }

    // Применение P-перестановки
    uint32_t permuted_output = 0;
    for (int i = 0; i < 32; ++i) {
        permuted_output |= ((output >> P_PERMUTATION[i]) & 0x1) << i;
    }

    return permuted_output;
}

// Функция F2_inv (обратная SPN структура)
uint32_t F2_inv(uint32_t input, uint32_t key) {
    // Применение обратной P-перестановки
    uint32_t permuted_output = 0;
    for (int i = 0; i < 32; ++i) {
        permuted_output |= ((input >> INV_P_PERMUTATION[i]) & 0x1) << i;
    }

    // Применение обратных S-блоков (8 S-блоков 4x4)
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t nibble = (permuted_output >> (4 * i)) & 0xF;  // Извлечение 4-битного блока
        nibble = INV_SBOX[nibble];  // Применение обратного S-блока
        output |= (uint32_t)nibble << (4 * i);  // Сборка результата
    }

    // Применение ключа
    output ^= key;

    return output;
}

// Функция циклического сдвига влево для 128-битного числа
uint128_t rotate_left_128(const uint128_t& value, int shift) {
    if (shift >= 128) shift %= 128;
    if (shift == 0) return value;

    uint128_t result;
    if (shift < 64) {
        result = (value << shift) | (value >> (128 - shift));
    }
    else {
        shift -= 64;
        result = (value << shift) | (value >> (128 - shift));
    }
    return result;
}

// Генерация раундовых ключей
void GenerateRoundKeys(uint128_t initial_key, std::vector<uint32_t>& round_keys) {
    uint128_t key = initial_key;
    for (int i = 0; i < 20; ++i) {
        // Циклический сдвиг влево на 113 бит
        uint128_t temp0 = rotate_left_128(key, 113);

        // Применение S-блоков к старшим 8 битам
        uint8_t high_bits = static_cast<uint8_t>((temp0 >> 120).convert_to<uint64_t>() & 0xFF);  // Старшие 8 бит
        uint8_t temp1 = SBOX[(high_bits >> 4) & 0xF] << 4 | SBOX[high_bits & 0xF];

        // XOR с счётчиком раундов (10-14 биты)
        uint8_t round_counter = i;
        uint8_t temp3 = static_cast<uint8_t>((temp0 >> 10).convert_to<uint64_t>() & 0x1F) ^ round_counter;

        // Обновление ключа
        key = (static_cast<uint128_t>(temp1) << 120) | (temp0 & ((uint128_t(1) << 120) - 1));
        key = (key & ~(uint128_t(0x1F) << 10)) | (static_cast<uint128_t>(temp3) << 10);

        // Извлечение раундового ключа (старшие 64 бита)
        uint32_t round_key = static_cast<uint32_t>((key >> 96).convert_to<uint64_t>() & 0xFFFFFFFF);
        round_keys.push_back(round_key);
    }
}

// Шифрование GFSPX
void GFSPX_Encrypt(uint64_t plaintext, const std::vector<uint32_t>& round_keys, uint64_t& ciphertext) {
    // Инициализация ветвей
    uint16_t L0 = (plaintext >> 48) & 0xFFFF;
    uint16_t L1 = (plaintext >> 32) & 0xFFFF;
    uint16_t R0 = (plaintext >> 16) & 0xFFFF;
    uint16_t R1 = plaintext & 0xFFFF;

    

    // Раунды шифрования
    for (int i = 0; i < 20; ++i) {
        // Получение раундового ключа
        uint32_t round_key = round_keys[i];
        //std::cout << "Round " << i << " key: " << std::hex << round_key << std::endl;

        // Применение функций F1 и F2
        F1_encrypt(L1, round_key & 0xFFFF);
        F1_encrypt(R0, round_key >> 16);
        uint32_t temp = F2((L1 << 16) | R0, round_key);

        // Перемещение ветвей
        L1 = temp >> 16;
        R0 = temp & 0xFFFF;

        std::swap(L0, R0);
        std::swap(L1, R1);

        //std::cout << "After round " << i << ": L0=" << std::hex << L0 << ", L1=" << L1 << ", R0=" << R0 << ", R1=" << R1 << std::endl;
    }

    // Формирование шифртекста
    ciphertext = (static_cast<uint64_t>(L0) << 48) |
        (static_cast<uint64_t>(L1) << 32) |
        (static_cast<uint64_t>(R0) << 16) |
        R1;
}

// Дешифрование GFSPX
void GFSPX_Decrypt(uint64_t ciphertext, const std::vector<uint32_t>& round_keys, uint64_t& plaintext) {
    // Инициализация ветвей
    uint16_t L0 = (ciphertext >> 48) & 0xFFFF;
    uint16_t L1 = (ciphertext >> 32) & 0xFFFF;
    uint16_t R0 = (ciphertext >> 16) & 0xFFFF;
    uint16_t R1 = ciphertext & 0xFFFF;

   

    // Обратные раунды дешифрования
    for (int i = 19; i >= 0; --i) {
        // Получение раундового ключа
        uint32_t round_key = round_keys[i];
        //std::cout << "Round " << i << " key: " << std::hex << round_key << std::endl;

        // Восстановление значений до перестановок
        std::swap(L0, R0);
        std::swap(L1, R1);

        // Обратный раунд
        uint32_t temp = F2_inv((L1 << 16) | R0, round_key);

        // Расчёт восстановленных значений L1 и R0
        F1_decrypt(temp >> 16, round_key & 0xFFFF);
        F1_decrypt(temp & 0xFFFF, round_key >> 16);

        L1 = temp >> 16;
        R0 = temp & 0xFFFF;

        //std::cout << "After round " << i << ": L0=" << std::hex << L0 << ", L1=" << L1 << ", R0=" << R0 << ", R1=" << R1 << std::endl;
    }

    // Формирование открытого текста
    plaintext = (static_cast<uint64_t>(L0) << 48) |
        (static_cast<uint64_t>(L1) << 32) |
        (static_cast<uint64_t>(R0) << 16) |
        R1;
}

// Тестирование функций F2 и F2_inv
void TestF2AndF2Inv() {
    // Тестовые данные
    std::vector<uint32_t> test_inputs = {
        0x00000000,  // Минимальное значение
        0xFFFFFFFF,  // Максимальное значение
        0x12345678,  // Произвольное значение
        0xABCDEF01,  // Произвольное значение
        0xDEADBEEF   // Произвольное значение
    };

    std::vector<uint32_t> test_keys = {
        0x00000000,  // Минимальный ключ
        0xFFFFFFFF,  // Максимальный ключ
        0x12345678,  // Произвольный ключ
        0xABCDEF01,  // Произвольный ключ
        0xDEADBEEF   // Произвольный ключ
    };

    // Проверка для каждой пары input и key
    for (uint32_t input : test_inputs) {
        for (uint32_t key : test_keys) {
            uint32_t encrypted = F2(input, key);
            uint32_t decrypted = F2_inv(encrypted, key);

            if (decrypted != input) {
                std::cout << "Test failed for input=" << std::hex << input
                    << ", key=" << std::hex << key
                    << ". Decrypted=" << std::hex << decrypted << std::endl;
            }
            else {
                std::cout << "Test passed for input=" << std::hex << input
                    << ", key=" << std::hex << key << std::endl;
            }
        }
    }
}

// Функция для преобразования строки в вектор 64-битных блоков
std::vector<uint64_t> stringToBlocks(const std::string& text) {
    std::vector<uint64_t> blocks;
    size_t length = text.size();
    size_t blockCount = (length + 7) / 8; // Количество 64-битных блоков

    for (size_t i = 0; i < blockCount; ++i) {
        uint64_t block = 0;
        size_t start = i * 8;
        size_t end = std::min(start + 8, length);

        for (size_t j = start; j < end; ++j) {
            block |= static_cast<uint64_t>(text[j]) << ((j - start) * 8);
        }
        blocks.push_back(block);
    }

    return blocks;
}

// Функция для преобразования вектора 64-битных блоков обратно в строку
std::string blocksToString(const std::vector<uint64_t>& blocks) {
    std::string text;
    for (uint64_t block : blocks) {
        for (int i = 0; i < 8; ++i) {
            char ch = static_cast<char>((block >> (i * 8)) & 0xFF);
            if (ch != '\0') {
                text += ch;
            }
        }
    }
    return text;
}

int main() {
    // Инициализация 128-битного ключа
    uint128_t key("0x0123456789ABCDEF0123456789ABCDEF");

    // Инициализация открытого текста
    std::string plaintext = "Hang the boy, can't I never learn anything? Ain't he played me tricks enough like that for me to be looking out for him by this time? But old fools is the biggest fools there is. Can't learn an old dog new tricks, as the saying is. But my goodness, he never plays them alike, two days, and how is a body to know what's coming? He 'pears to know just how long he can torment me before I get my dander up, and he knows if he can make out to put me off for a minute or make me laugh, it's all down again and I can't hit him a lick. I ain't doing my duty by that boy, and that's the Lord's truth, goodness knows. Spare the rod and spile the child, as the Good Book says. I'm a laying up sin and suffering for us both, I know. He's full of the Old Scratch, but laws-a-me! he's my own dead sister's boy, poor thing, and I ain't got the heart to lash him, some how. Every time I let him off, my conscience does hurt me so, and every time I hit him my old heart most breaks. Well-a-well, man that is born of woman is of few days and full of trouble, as the Scripture says, and reckon it's so. He'll play hookey this evening1, and I'll just be obleeged to make him work, to-morrow, to punish him. It's mighty hard to make him work Saturdays, when all the boys is having holiday, but he hates work more than he hates anything else, and I've GOT to do some of my duty by him, or I'll be the ruination of the child.";

    // Преобразование текста в 64-битные блоки
    std::vector<uint64_t> blocks = stringToBlocks(plaintext);

    // Генерация раундовых ключей
    std::vector<uint32_t> round_keys;
    GenerateRoundKeys(key, round_keys);

    // Шифрование каждого блока
    std::vector<uint64_t> encryptedBlocks;
    for (uint64_t block : blocks) {
        uint64_t ciphertext = 0;
        GFSPX_Encrypt(block, round_keys, ciphertext);
        encryptedBlocks.push_back(ciphertext);
    }

    // Вывод зашифрованных блоков в шестнадцатеричном формате
    std::cout << "Encrypted blocks (hex):" << std::endl;
    for (uint64_t block : encryptedBlocks) {
        std::cout << std::hex << block << " "; // Вывод в hex
    }
    std::cout << std::dec << std::endl; // Возврат к десятичному формату

    // Дешифрование каждого блока
    std::vector<uint64_t> decryptedBlocks;
    for (uint64_t block : encryptedBlocks) {
        uint64_t decryptedText = 0;
        GFSPX_Decrypt(block, round_keys, decryptedText);
        decryptedBlocks.push_back(decryptedText);
    }

    // Преобразование расшифрованных блоков обратно в строку
    std::string decryptedText = blocksToString(decryptedBlocks);

    // Вывод результатов
    std::cout << "Original text: " << plaintext << std::endl;
    std::cout << "Decrypted text: " << decryptedText << std::endl;

    // Проверка корректности
    if (plaintext == decryptedText) {
        std::cout << "Decryption successful!" << std::endl;
    }
    else {
        std::cout << "Decryption failed!" << std::endl;
    }

    return 0;
}
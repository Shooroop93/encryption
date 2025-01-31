package com.encryption.service.algoritm.aesCtr;

import com.encryption.app.error.EncryptionException;
import com.encryption.app.service.encryption.DefaultSaltNonceStreamHandler;
import com.encryption.app.service.encryption.EncryptionService;
import com.encryption.app.service.encryption.EncryptionServiceAesGcm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.UUID;

public class EncryptionServiceAesGcmTest {
    protected EncryptionService encryptionService;

    @BeforeEach
    public void createNewEncryptionServiceAesCtr() {
        encryptionService = new EncryptionServiceAesGcm(new DefaultSaltNonceStreamHandler());
    }

    @Test
    public void encryptServiceStreamTest_1() throws EncryptionException {
        String text = UUID.randomUUID().toString();
        byte[] resultEncryptStream = encryptStream(text, UUID.randomUUID().toString());
        Assertions.assertNotEquals(text, new String(resultEncryptStream, StandardCharsets.UTF_8));
    }

    @Test
    public void encryptServiceStreamTest_2() {
        Assertions.assertThrows(EncryptionException.class, () -> {
            encryptStream(UUID.randomUUID().toString(), "");
        }, "Password empty");
    }

    @Test
    public void encryptServiceStreamTest_3() {
        Assertions.assertThrows(EncryptionException.class, () -> {
            encryptStream(UUID.randomUUID().toString(), null);
        }, "Password null");
    }

    @Test
    public void decryptServiceStreamTest_4() throws EncryptionException {
        String password = UUID.randomUUID().toString();
        String text = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(text, password);
        byte[] resultDecryptStream = decryptStream(resultEncryptStream, password);

        Assertions.assertNotEquals(text, new String(resultEncryptStream, StandardCharsets.UTF_8));
        Assertions.assertEquals(text, new String(resultDecryptStream, StandardCharsets.UTF_8));
    }

    @Test
    public void decryptServiceStreamTest_6() throws EncryptionException {
        String password = UUID.randomUUID().toString();
        String text = "A".repeat(10 * 1024 * 1024);

        byte[] resultEncryptStream = encryptStream(text, password);

        byte[] resultDecryptStream = decryptStream(resultEncryptStream, password);

        Assertions.assertEquals(text, new String(resultDecryptStream, StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "!@#$%^&*()_+-=[]{};:'\",.<>/?\\|`~",
            "©®™✓✗★☆→↓↑←⇧⇩⇦⇨✔✖✚✛✜✝☑☒✍✏",
            "𝒜𝓑𝓒𝓓𝓔𝓕𝓖𝓗𝓘𝒥𝒦𝒱𝒲𝒳𝒴𝒵",
            "𝓪𝓫𝓬𝓭𝓮𝓯𝓰𝓱𝓲𝒿𝓀𝓵𝓶𝓷𝓸𝓹𝓺𝓻𝓼𝓽𝓾𝓿𝔀𝔁𝔂𝔷",
            "𝕬𝕭𝕮𝕯𝕰𝕱𝕲𝕳𝕴𝕵𝕶𝕷𝕸𝕹𝕺𝕻𝕼𝕽𝕾𝕿𝖀𝖁𝖂𝖃𝖄𝖅",
            "𝖆𝖇𝖈𝖉𝖊𝖋𝖌𝖍𝖎𝖏𝖐𝖑𝖒𝖓𝖔𝖕𝖖𝖗𝖘𝖙𝖚𝖛𝖜𝖝𝖞𝖟",
            "😀😁😂🤣😃😄😅😆😉😊😋😎😍😘🥰😜🤑🤓🤠🥳🤩😇",
            "🙈🙉🙊💖💙💚💛💜🖤💔💕💞💗💝💘💟❣💌💤💢💣💥💦💨",
            "🎶🎵🎷🎸🎹🎺🎻🥁🎼🎧🎤📢📣📯🔔🔕📻📺📡🔍🔎🔬",
            "🎲🎳🎮🎯🏆🥇🥈🥉🏅🎖🎟🎫🏰🏯🗿🗼🗽🕌🏛🏟🏜🏝🏞🏙🌍🌎🌏🌐",
            "01001000 01100101 01101100 01101100 01101111 00100000 01010111 01101111 01110010 01101100 01100100",
            "101010 110110 111000 100101 010010 101011",
            "𐎀𐎁𐎂𐎃𐎄𐎅𐎆𐎇𐎈𐎉𐎊𐎋𐎌𐎍𐎎𐎏𐎐𐎑𐎒𐎓𐎔𐎕𐎖𐎗",
            "𐏀𐏁𐏂𐏃𐏄𐏅𐏆𐏇𐏈𐏉𐏊𐏋𐏌𐏍𐏎𐏏𐏐𐏑𐏒𐏓𐏔𐏕𐏖𐏗",
            "SHA-256: 64EC88CA00B268E5BA1A35678A1B5316D212F4F366B24772333814829A4D28A6",
            "MD5: 098F6BCD4621D373CADE4E832627B4F6",
            "🅰🅱🆎🅾🚾ℹ⚠⛔⛪⚕🚻🚮💢🔞🚸🔆🔅",
            "🀄🃏🎴🛑🛅🛂🛄🛃🚰🚾🚹🚺🚻♿🚇🚙🚕🛳🚲🚶🏋🏂🏄🏊🚴🏍🛵🚖🚍🚆",
            "🔋📡💡🔌📲📱📶📞📟📠📹📺📻📀💽💾💿🎥🎬🎼",
            "-", "          ", ",", "a", "ы", "1", "^", "_!@#$%^&*()_+}{\"--=~!`:>?#$Ff_f32АВСацйца2334_Ца12355пц", "", "1234567890", "Привет мир", "Hello world", "Hallo Welt", "Bonjour le monde", "Hola mundo", "Ciao mondo", "你好世界", "こんにちは世界", "안녕하세요 세계", "مرحبا بالعالم", "नमस्ते दुनिया", "হ্যালো ওয়ার্ল্ড", "Merhaba dünya", "שלום עולם", "Olá mundo", "Привіт світ", "Witaj świecie", "Hej världen", "Ahoj světe", "Cześć świecie", "Moien Welt", "γεια σου κόσμε", "Hello ምስራቅ አለም", "ہیلو دنیا", "Helló világ", "Saluton mondo", "Selam dünya", "こんにちは、プログラミングの世界へようこそ！", "01001000 01100101 01101100 01101100 01101111 00100000 01010111 01101111 01110010 01101100 01100100", "SHA-256: 64EC88CA00B268E5BA1A35678A1B5316D212F4F366B24772333814829A4D28A6"})
    public void decryptAesCtrServiceStreamTest_7(String testValue) throws EncryptionException {
        String password = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(testValue, password);
        byte[] resultDecryptStream = decryptStream(resultEncryptStream, password);

        Assertions.assertEquals(testValue, new String(resultDecryptStream, StandardCharsets.UTF_8));
    }

    @Test
    public void testUtf8Encoding() throws EncryptionException {
        String originalText = "Hello 世界! Привет мир! こんにちは世界!";

        testEncoding(originalText, StandardCharsets.UTF_8, "UTF-8");
    }

    @Test
    public void testUtf16Encoding() throws EncryptionException {
        String originalText = "Hello 世界! Привет мир! こんにちは世界!";

        testEncoding(originalText, StandardCharsets.UTF_16, "UTF-16");
    }

    @Test
    public void testAsciiEncoding() throws EncryptionException {
        String originalText = "Hello World! 12345 !@#$%^&*()";

        testEncoding(originalText, StandardCharsets.US_ASCII, "ASCII");
    }

    private void testEncoding(String originalText, Charset charset, String encodingName) throws EncryptionException {
        String password = UUID.randomUUID().toString();

        byte[] originalBytes = originalText.getBytes(charset);

        ByteArrayInputStream inputStream = new ByteArrayInputStream(originalBytes);
        ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
        encryptionService.encrypt(inputStream, encryptedOutput, password);
        byte[] encryptedBytes = encryptedOutput.toByteArray();

        ByteArrayInputStream encryptedInput = new ByteArrayInputStream(encryptedBytes);
        ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
        encryptionService.decrypt(encryptedInput, decryptedOutput, password);
        byte[] decryptedBytes = decryptedOutput.toByteArray();
        String decryptedText = new String(decryptedBytes, charset);

        Assertions.assertEquals(
                originalText,
                decryptedText,
                "The text after encryption/decryption in encoding " + encodingName + " must match the original text"
        );
    }

    @Test
    public void destroyDecryptServiceStreamTest() throws EncryptionException {
        String text = "Test Testov Test";
        String password = "qwerty12345";

        byte[] encrypted = encryptStream(text, password);
        int idx = encrypted.length / 2;
        encrypted[idx] ^= 0xFF;

        Assertions.assertThrows(EncryptionException.class, () -> {
            decryptStream(encrypted, password);
        }, "AES-GCM must fail with exception on corrupted data");
    }

    @Test
    public void testDecryptWithWrongPasswordGcmThrows() throws EncryptionException {
        String password = UUID.randomUUID().toString();
        String text = UUID.randomUUID().toString();

        byte[] resultEncryptStream = encryptStream(text, password);

        Assertions.assertThrows(EncryptionException.class, () -> {
            decryptStream(resultEncryptStream, "qwerty12345");
        });
    }

    @Test
    public void testRandomBinaryData() throws EncryptionException {
        byte[] originalBytes = new byte[1024];
        new SecureRandom().nextBytes(originalBytes);

        String password = UUID.randomUUID().toString();

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();
        encryptionService.encrypt(new ByteArrayInputStream(originalBytes), encryptedOut, password);
        byte[] encrypted = encryptedOut.toByteArray();

        ByteArrayOutputStream decryptedOut = new ByteArrayOutputStream();
        encryptionService.decrypt(new ByteArrayInputStream(encrypted), decryptedOut, password);
        byte[] decryptedBytes = decryptedOut.toByteArray();

        Assertions.assertArrayEquals(originalBytes, decryptedBytes,
                "Binary data must be identical after encryption/decryption");
    }

    private byte[] decryptStream(byte[] encryptResult, String password) throws EncryptionException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptResult);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        encryptionService.decrypt(byteArrayInputStream, byteArrayOutputStream, password);
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] encryptStream(String text, String password) throws EncryptionException {
        InputStream inputStream = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encryptionService.encrypt(inputStream, outputStream, password);
        return outputStream.toByteArray();
    }
}
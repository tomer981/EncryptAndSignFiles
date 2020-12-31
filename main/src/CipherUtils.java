import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CipherUtils {
    private static final int ALGORITHM_PARAMS_BYTE_SIZE = 18;
    private static final int SYMMETRIC_KEY_BYTE_SIZE = 256;
    private static final int DIGEST_BYTE_SIZE = 32;

    public static byte[] DigestMessage(String algorithmName, byte[] data, String encryptionMessageDigestProvider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithmName, encryptionMessageDigestProvider);
        return messageDigest.digest(data);
    }

    public static MyKeyStore GetKeyStore(String keyStorePath, String keyStorePassword, String alias)
            throws NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException,
            IOException {
        FileInputStream inputStreamClientKeyFile = GetFileInputStream(keyStorePath);
        MyKeyStore keyStore = new MyKeyStore(inputStreamClientKeyFile, keyStorePassword, alias);

        inputStreamClientKeyFile.close();

        return keyStore;
    }

    public static FileInputStream GetFileInputStream(String filePath) {
        FileInputStream file = null;
        try {
            file = new FileInputStream(filePath);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return file;
    }

    public static byte[] ReadFile(String filePath) throws IOException {
        FileInputStream inputStreamFile = GetFileInputStream(filePath);
        byte[] fileContent = inputStreamFile.readAllBytes();

        inputStreamFile.close();

        return fileContent;
    }

    public static byte[] Sign(String algorithmName, PrivateKey privateKey, byte[] data, String encryptionSignProvider)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        Signature signature = Signature.getInstance(algorithmName, encryptionSignProvider);// (SHA256withRSA taking from
                                                                                           // certificate)
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static SecretKey GetSymmetricKey(String keyAlgorithmName, int keySize, String encryptionSecureRandomProvider,
            String encryptionKeyGeneratorProvider) throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", encryptionSecureRandomProvider);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keyAlgorithmName, encryptionKeyGeneratorProvider);
        secureRandom.setSeed(711);// only for debugging
        keyGenerator.init(keySize, secureRandom);
        return keyGenerator.generateKey();
    }

    public static Cipher GetCipher(int mode, String AlgorithmName, Key key, AlgorithmParameters algorithmParameters,
            String cipherProvider) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(AlgorithmName, cipherProvider);
        if (algorithmParameters == null) {
            cipher.init(mode, key);
        } else {
            cipher.init(mode, key, algorithmParameters);
        }
        return cipher;
    }

    public static void WritePlaintextToFile(byte[] data, String filePath) throws IOException {
        File File = new File(filePath);
        FileOutputStream outStream = new FileOutputStream(File, true);
        outStream.write(data);
        outStream.flush();
        outStream.close();
    }

    public static void EncryptToFile(Cipher cipher, byte[] data, String filePath) throws IOException {
        File encodedFile = new File(filePath);
        FileOutputStream outStream = new FileOutputStream(encodedFile, true);
        CipherOutputStream cos = new CipherOutputStream(outStream, cipher);
        cos.write(data);
        cos.flush();
        cos.close();
    }

    // decrypt file using CipherInputStream
    public static byte[] DecryptFromFile(String filePath, Cipher cipher) throws IOException {
        FileInputStream encryptedStreamFile = GetFileInputStream(filePath);

        CipherInputStream cisDecodedFile = new CipherInputStream(encryptedStreamFile, cipher);
        byte[] decryptedData = cisDecodedFile.readAllBytes();

        cisDecodedFile.close();

        return decryptedData;
    }

    public static SecretKey GetSecretKeyFromConfigFile(FileInputStream configStreamFile, Cipher cipherRSA,
            String algorithmName) throws IOException, BadPaddingException, IllegalBlockSizeException {
        byte[] encryptSymmetricKey = configStreamFile.readNBytes(SYMMETRIC_KEY_BYTE_SIZE);
        byte[] encodedSymmetricKey = cipherRSA.doFinal(encryptSymmetricKey);

        return new SecretKeySpec(encodedSymmetricKey, 0, encodedSymmetricKey.length, algorithmName);
    }

    public static byte[] GetDigestFromConfigFile(FileInputStream configStreamFile)
            throws IOException, BadPaddingException, IllegalBlockSizeException {
        return configStreamFile.readNBytes(DIGEST_BYTE_SIZE);
    }

    public static AlgorithmParameters GetAlgorithmParametersFromConfigFile(FileInputStream configStreamFile,
            String algorithmName, String decryption_PARAMETERS_PROVIDER)
            throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] algoByte = new byte[ALGORITHM_PARAMS_BYTE_SIZE];

        configStreamFile.read(algoByte);
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(algorithmName, decryption_PARAMETERS_PROVIDER);
        algParams.init(algoByte);

        return algParams;
    }
}


import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.crypto.*;

import static java.lang.System.exit;

public class UI {
    private static final String EXECUTION_PATH = System.getProperty("user.dir");
    private static final String PLAIN_TEXT_PATH = EXECUTION_PATH + "/plaintext.txt";
    private static final String ENCRYPTED_FILE_PATH = EXECUTION_PATH + "/encrypted";
    private static final String CONFIG_FILE_PATH = EXECUTION_PATH + "/config";
    private static final String DECRYPTED_FILE_PATH = EXECUTION_PATH + "/decrypted.txt";
    private static final String DIGEST_ALGORITHM_NAME = "SHA-256";
    private static final String CLIENT_KEY_STORE_PATH = EXECUTION_PATH + "/keys/client.keystore";
    private static final String SERVER_KEY_STORE_PATH = EXECUTION_PATH + "/keys/server.keystore";
    private static final String SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
    private static final String SYMMETRIC_KEY_ALGORITHM_NAME = "AES";
    private static final String ASYMMETRIC_ALGORITHM_CIPHER_NAME = "RSA";
    private static final int SYMMETRIC_KEY_SIZE = 256;
    private static final String SYMMETRIC_CIPHER_ALGORITHM_NAME = "AES/CBC/PKCS5Padding";

    //KeyStore alias name
    private static final String CLIENT_ALIAS = "client";
    private static final String SERVER_ALIAS = "server";

    //Encryption Providers
    private static final String ENCRYPTION_SECURE_RANDOM_PROVIDER = "SUN";
    private static final String ENCRYPTION_KEY_GENERATOR_PROVIDER = "SunJCE";
    private static final String ENCRYPTION_MESSAGE_DIGEST_PROVIDER = "SUN";
    private static final String ENCRYPTION_SIGN_PROVIDER = "SunRsaSign";
    private static final String ENCRYPTION_CIPHER_PROVIDER = "SunJCE";
    private static final String ENCRYPTION_RSA_PROVIDER = "SunJCE";

    //Decryption Providers
    private static final String Decryption_MESSAGE_DIGEST_PROVIDER = "SUN";
    private static final String Decryption_PARAMETERS_PROVIDER = "SunJCE";
    private static final String Decryption_SIGN_PROVIDER = "SunRsaSign";
    private static final String Decryption_CIPHER_PROVIDER = "SunJCE";
    private static final String Decryption_RSA_PROVIDER = "SunJCE";

    public void runEncryption(String keyStorePassword)
            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {

        System.out.println("Start to encrypt file: " + PLAIN_TEXT_PATH);

        // read file
        byte[] fileContent = CipherUtils.ReadFile(PLAIN_TEXT_PATH);

        // get KeyStore
        MyKeyStore keyStore = CipherUtils.GetKeyStore(CLIENT_KEY_STORE_PATH, keyStorePassword, CLIENT_ALIAS);

        // messageDigest
        byte[] digestedFile = CipherUtils.DigestMessage(DIGEST_ALGORITHM_NAME, fileContent, ENCRYPTION_MESSAGE_DIGEST_PROVIDER);

        // Signature
        byte[] byteSignature = CipherUtils.Sign(SIGNATURE_ALGORITHM_NAME, keyStore.GetPrivateKey(), fileContent, ENCRYPTION_SIGN_PROVIDER);

        // generate symmetric key
        SecretKey symmetricKey = CipherUtils.GetSymmetricKey(SYMMETRIC_KEY_ALGORITHM_NAME, SYMMETRIC_KEY_SIZE, ENCRYPTION_SECURE_RANDOM_PROVIDER, ENCRYPTION_KEY_GENERATOR_PROVIDER);

        // encrypt plaintext + Signature
        Cipher cipherCBC = CipherUtils.GetCipher(Cipher.ENCRYPT_MODE, SYMMETRIC_CIPHER_ALGORITHM_NAME, symmetricKey, null, ENCRYPTION_CIPHER_PROVIDER);

        // encrypt symmetric key
        Cipher cipherRSA = CipherUtils.GetCipher(Cipher.ENCRYPT_MODE, ASYMMETRIC_ALGORITHM_CIPHER_NAME, keyStore.GetTrustedPublicKey(SERVER_ALIAS), null, ENCRYPTION_RSA_PROVIDER);

        // delete encrypt and config files
        Files.deleteIfExists(Paths.get(ENCRYPTED_FILE_PATH));
        Files.deleteIfExists(Paths.get(CONFIG_FILE_PATH));

        // encrypted symmetric key and signature
        byte[] encryptedSymmetricKey = cipherRSA.doFinal(symmetricKey.getEncoded());
        byte[] encryptedSign = cipherCBC.doFinal(byteSignature);

        //create config file - move to function in ChipperUtils
        CipherUtils.WritePlaintextToFile(cipherCBC.getParameters().getEncoded(), CONFIG_FILE_PATH);
        CipherUtils.WritePlaintextToFile(digestedFile, CONFIG_FILE_PATH);
        CipherUtils.WritePlaintextToFile(encryptedSymmetricKey, CONFIG_FILE_PATH);
        CipherUtils.WritePlaintextToFile(encryptedSign, CONFIG_FILE_PATH);
        System.out.println("Config File created: " + CONFIG_FILE_PATH);

        // create encrypt file
        CipherUtils.EncryptToFile(cipherCBC, fileContent, ENCRYPTED_FILE_PATH);
        System.out.println("File encrypted: " + ENCRYPTED_FILE_PATH);

        System.out.println("Encryption completed successfully\n");
    }

    public void runDecryption(String keyStorePassword) throws
            IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException, NoSuchProviderException {

        System.out.println("Start to decrypt file: " + ENCRYPTED_FILE_PATH);

        // open config file
        FileInputStream configStreamFile = CipherUtils.GetFileInputStream(CONFIG_FILE_PATH);

        // get keyStore
        MyKeyStore keyStore = CipherUtils.GetKeyStore(SERVER_KEY_STORE_PATH, keyStorePassword, SERVER_ALIAS);

        // create asymmetricCipher object for decryption
        Cipher cipherRSA = CipherUtils.GetCipher(Cipher.DECRYPT_MODE, ASYMMETRIC_ALGORITHM_CIPHER_NAME, keyStore.GetPrivateKey(), null, Decryption_RSA_PROVIDER);

        // read algorithmParameter bytes and symmetric key from config file
        AlgorithmParameters algParams = CipherUtils.GetAlgorithmParametersFromConfigFile(configStreamFile, SYMMETRIC_KEY_ALGORITHM_NAME, Decryption_PARAMETERS_PROVIDER);
        byte[] digestFromConfig = CipherUtils.GetDigestFromConfigFile(configStreamFile);
        SecretKey symmetricKey = CipherUtils.GetSecretKeyFromConfigFile(configStreamFile, cipherRSA, SYMMETRIC_KEY_ALGORITHM_NAME);

        // create symmetricCipher object for decryption
        Cipher cipherCBC = CipherUtils.GetCipher(Cipher.DECRYPT_MODE, SYMMETRIC_CIPHER_ALGORITHM_NAME, symmetricKey, algParams, Decryption_CIPHER_PROVIDER);

        // decrypt ciphertext data to plaintext
        byte[] decryptedData = CipherUtils.DecryptFromFile(ENCRYPTED_FILE_PATH, cipherCBC);

        // get byteSignature from configFile
        byte[] encryptSignature = configStreamFile.readAllBytes();
        byte[] signaturesBytes = cipherCBC.doFinal(encryptSignature);

        // digest
        byte[] digestFromDecryptedFile = CipherUtils.DigestMessage(DIGEST_ALGORITHM_NAME, decryptedData, Decryption_MESSAGE_DIGEST_PROVIDER);/////// *********
        if (!Arrays.equals(digestFromConfig, digestFromDecryptedFile)) {
            System.out.println("Digest is invalid: Decrypted file is Not the same data file.");
            exit(0);
        }
        System.out.println("Digest is valid.");

        // Signature
        boolean isSignatureVerify = CipherUtils.verifySignature(SIGNATURE_ALGORITHM_NAME, Decryption_SIGN_PROVIDER, decryptedData, signaturesBytes, keyStore.GetTrustedPublicKey(CLIENT_ALIAS));
        if (isSignatureVerify) {
            System.out.println("Signature is valid.");
            System.out.println("Decrypted file created: " + DECRYPTED_FILE_PATH);
        } else {
            System.out.println("Signature is invalid " + DECRYPTED_FILE_PATH);
            exit(0);
        }

        // final
        Files.deleteIfExists(Paths.get(DECRYPTED_FILE_PATH));
        CipherUtils.WritePlaintextToFile(decryptedData, DECRYPTED_FILE_PATH);
    }
}
// c:\download\tomer.txt
// c:\client.keystore

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class MyKeyStore {
    private KeyStore m_KeyStore;
    private PrivateKey m_PrivateKey;
    private String m_Password;

    public MyKeyStore(FileInputStream fileStream, String keyStorePassword, String alias)
            throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException,
            UnrecoverableEntryException {
        m_Password = keyStorePassword;
        loadKeyStore(fileStream);
        getPrivateKey(alias);
    }

    private void loadKeyStore(FileInputStream fileStream)
            throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
        m_KeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        m_KeyStore.load(fileStream, m_Password.toCharArray());
    }

    private void getPrivateKey(String alias)
            throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(m_Password.toCharArray());
        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) m_KeyStore.getEntry(alias, protParam);
        m_PrivateKey = pkEntry.getPrivateKey();
    }

    public KeyStore GetKeyStore() {
        return m_KeyStore;
    }

    public PrivateKey GetPrivateKey() {
        return m_PrivateKey;
    }

    public PublicKey GetTrustedPublicKey(String alias) throws KeyStoreException {
        Certificate trustedCertificate = m_KeyStore.getCertificate(alias);

        return trustedCertificate.getPublicKey();
    }

    public String GetM_Password() {
        return m_Password;
    }

    public Certificate GetTrustedCertificate(String aliac) throws KeyStoreException {
        return m_KeyStore.getCertificate(aliac);
    }
}
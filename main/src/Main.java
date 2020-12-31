import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, NoSuchFieldException, InvalidAlgorithmParameterException, NoSuchProviderException {
        if(args.length > 0)
        {
            run(args[0]);
        }
        else
        {
            run("123456");
        }

    }

    private static void run(String keyStorePassword) throws InvalidKeyException, NoSuchAlgorithmException,
            CertificateException, KeyStoreException, UnrecoverableEntryException, SignatureException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchFieldException, IOException,
            InvalidAlgorithmParameterException, NoSuchProviderException {
        UI ui = new UI();

        ui.runEncryption(keyStorePassword);
        ui.runDecryption(keyStorePassword);
    }
}
//C:\Download\tomer.txt
package DiffieHellman;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Clase para realizar un intercambio de claves Diffie-Hellman.
 * 
 * @author Raquel Romero Pedraza
 */
public class DiffieHellman {

    private PrivateKey privateKey;
    private PublicKey  publicKey;
    private PublicKey  receivedPublicKey;
    private  byte[]    secretKey;

    /**
     * Genera a partir de la clave pública de otro objeto 
     * Diffie-Hellman, la clave secreta común
     */
    public void generateCommonSecretKey() {

        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            secretKey = shortenSecretKey(keyAgreement.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Genera un par de claves Diffie-Hellman
     * pública y privada para el objeto
     */
    public void generateKeys() {

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(1024);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey  = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public PublicKey getPublicKey() {

        return publicKey;
    }

    
    public byte[] getSecretKey() {

        return secretKey;
    }

    /**
     * In a real life example you must serialize the public key for transferring.
     * 
     * @param publicKeyPerson
     */
    public void receivePublicKeyFrom(PublicKey publicKeyPerson) {

        receivedPublicKey = publicKeyPerson;
    }

    /**
     * 
     * El tamaño de la clave simétrica de 1024 bits es tan grande 
     * para DES que debemos acortar el tamaño de la clave. Puede 
     * obtener las primeras 8 claves largas de la matriz de bytes 
     * o puede usar una fábrica de claves
     *
     * @param   longKey
     *
     * @return
     */
    private byte[] shortenSecretKey(final byte[] longKey) {

        try {

            // Usa 8 bytes (64 bits) para DES, 6 bytes (48 bits) para Blowfish
            final byte[] shortenedKey = new byte[8];

            System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);

            return shortenedKey;

        } catch (Exception e) {
        }

        return null;
    }
}

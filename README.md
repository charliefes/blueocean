import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

public class PgpKeyUtils {

    public static PGPPublicKey parsePublicKey(String pgpPublicKeyString) throws IOException {
        // Convert the PGP public key string to an input stream
        ByteArrayInputStream pgpPublicKeyStream = new ByteArrayInputStream(pgpPublicKeyString.getBytes());

        // Create a PGP public key ring collection from the input stream
        PGPPublicKeyRingCollection pgpPublicKeyRingCollection = new PGPPublicKeyRingCollection(pgpPublicKeyStream);

        // Iterate through the key rings in the collection
        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIterator.next();

            // Iterate through the keys in the key ring
            Iterator<PGPPublicKey> keyIterator = keyRing.getPublicKeys();
            while (keyIterator.hasNext()) {
                PGPPublicKey publicKey = keyIterator.next();

                // Return the first public key found
                return publicKey;
            }
        }

        // If no key is found, return null or handle the situation as needed
        return null;
    }

    public static void main(String[] args) {
        // Example usage:
        String pgpPublicKeyString = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                                    "Version: BCPG v1.68\n" +
                                    "...\n" +  // Your key content here
                                    "-----END PGP PUBLIC KEY BLOCK-----";

        try {
            PGPPublicKey publicKey = parsePublicKey(pgpPublicKeyString);
            if (publicKey != null) {
                System.out.println("Key ID: " + Long.toHexString(publicKey.getKeyID()));
                System.out.println("Algorithm: " + publicKey.getAlgorithm());
                // Add more key information as needed
            } else {
                System.out.println("No public key found.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

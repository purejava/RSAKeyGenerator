package org.purejava.rsakey;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

/**
 * A simple utility class that generates a RSA PGPPublicKey/PGPSecretKey pair.
 * <p>
 usage: RSAKeyGenerator [-a] identity passPhrase
 <p>
 * Where identity is the name to be associated with the public key. The keys are placed 
 * in the files identity.pub.[asc|bpg] and identity.secret.[asc|bpg].
 *
 * @author Ralph Plawetzki <ralph@purejava.org>
 */
public class RSAKeyGenerator
{

    private static void exportKeys(
        OutputStream        publicOut,
        OutputStream        secretOut,
        PGPSecretKey        secKey,
        boolean             armor)
        throws IOException
    {    
        if (armor)
        {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        secKey.encode(secretOut);
        
        secretOut.close();

        if (armor)
        {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey    key = secKey.getPublicKey();
        key.encode(publicOut);
        
        publicOut.close();
        
    }
    
    public static void main(String[] args) throws Exception
    {
        if (args.length < 2)
        {
            System.out.println("RSAKeyGenerator [-a] identity passPhrase");
            System.exit(0);
        }
        
        if (args[0].equals("-a"))
        {
            if (args.length < 3)
            {
                System.out.println("RSAKeyGenerator [-a] identity passPhrase");
                System.exit(0);
            }
        }
        
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator    kpg = KeyPairGenerator.getInstance("RSA", "BC");
        
        // Length of generated key in bits
        kpg.initialize(2048);
        
        KeyPair kpEnc = kpg.generateKeyPair();
        
        PGPKeyPair encKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpEnc, new Date());
        
        PGPSignatureSubpacketVector unhashedPcks = null;
        
        PGPSignatureSubpacketGenerator svg = new PGPSignatureSubpacketGenerator();
        
        // ExpirationTime of generated key in seconds
        svg.setKeyExpirationTime(true, 86400L * 366 * 2);
        svg.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS + KeyFlags.ENCRYPT_STORAGE);
        svg.setPrimaryUserID(true, true);
        svg.setFeature(true, Features.FEATURE_MODIFICATION_DETECTION);
        PGPSignatureSubpacketVector hashedPcks = svg.generate();
        
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);    
        
        if (args[0].equals("-a"))
        {
            PGPSecretKey secKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                encKeyPair,
                args[1],
                hashedPcks,
                unhashedPcks,
                new JcaPGPContentSignerBuilder(encKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(args[2].toCharArray()));
            
            FileOutputStream    out1 = new FileOutputStream(args[1] + ".public.asc");
            FileOutputStream    out2 = new FileOutputStream(args[1] + ".secret.asc");
            
            System.out.println("Exported key pair to " + args[1] + ".secret.asc" + " and " + args[1] + ".public.asc");
            exportKeys(out1, out2, secKey, true);
        }
        else
        {
            PGPSecretKey secKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                    encKeyPair,
                    args[0],
                    hashedPcks,
                    unhashedPcks,
                    new JcaPGPContentSignerBuilder(encKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                    new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(args[1].toCharArray()));
            
            FileOutputStream    out1 = new FileOutputStream(args[0] + ".public.bpg");
            FileOutputStream    out2 = new FileOutputStream(args[0] + ".secret.bpg");
            
            System.out.println("Exported key pair to " + args[0] + ".secret.bpg" + " and " + args[0] + ".public.bpg");
            exportKeys(out1, out2, secKey, false);
        }
    }
}

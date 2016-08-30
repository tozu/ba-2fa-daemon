package Utils;

import models.BTToken;
import org.spongycastle.util.encoders.Base64;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

public class Encryption {

    public enum OSType {
        Windows, MacOS, Linux, Other
    }

    private OSType detectedOS;
    private Process process = null;

    private String mEncKey;

    private int IV_OTP = 1337;

    private KeyPair keyPair;

        private final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private final String KEY_PATH = "./";

    private static Encryption mInstance;

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    public static Encryption getInstance() {
        if (mInstance == null) {
            mInstance = new Encryption();
        }
        return mInstance;
    }

    private Encryption() {
        if (!loadKeypair(KEY_PATH)) {
            System.out.println("Couldn't load keypair...");
            RSAKeyGen();

            loadKeypair(KEY_PATH);
        }
    }

    public void setEncKey(String _key) {
        mEncKey = _key;
    }

    private String getEncKey() {
        return mEncKey;
    }

    // # OTP Generation
    public String createHASH_SHA256(String msg) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(msg.getBytes("UTF-8"));

            StringBuffer stringBuffer = new StringBuffer();
            for (byte hashedByte : hashedBytes) {
                stringBuffer.append(Integer.toString((hashedByte & 0xff) + 0x100, 16)
                        .substring(1));
            }
            return stringBuffer.toString();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String createHMAC_SHA256(String msg, String keyString) {
        String digest = null;
        try {
            SecretKeySpec key = new SecretKeySpec((keyString).getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            byte[] bytes = mac.doFinal(msg.getBytes(StandardCharsets.US_ASCII));

            StringBuilder hash = new StringBuilder();
            for (byte aByte : bytes) {
                String hex = Integer.toHexString(0xFF & aByte);
                if (hex.length() == 1) {
                    hash.append('0');
                }
                hash.append(hex);
            }

            digest = hash.toString(); // Base64.toBase64String(bytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest;
    }

    // AES-128 (IV randomly from library)
    public String encryptAES128(String plaintext, BTToken.Token token) {
        try {

            byte[] salt = saltGeneration();
            token.setSalt(salt);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(getEncKey().toCharArray(), salt, 65536, 256);
            SecretKey tmp = keyFactory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, secret);

            AlgorithmParameters parms = cipher.getParameters();
            byte[] iv = parms.getParameterSpec(IvParameterSpec.class).getIV();
            token.setIV(iv);

            byte[] encrypted = cipher.doFinal(plaintext.getBytes());

            return Base64.toBase64String(encrypted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException | InvalidParameterSpecException e) {
            e.printStackTrace();
        }

        return null;
    }

    public String decryptAES128(String encrypted, BTToken.Token token) {
        try {
            byte[] iv = token.getIV();
            byte[] salt = token.getSalt();

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(getEncKey().toCharArray(), salt, 65536, 256);
            SecretKey tmp = keyFactory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

            byte[] plain = cipher.doFinal(Base64.decode(encrypted));

            return new String(plain);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] saltGeneration() {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(8);
    }

    // RSA
    private KeyPair RSAKeyGen() {
        System.out.println("...generate new keypair");
        keyPair = null;
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA" /*, PROVIDER */);
            System.out.println("provider of keygen: " + keygen.getProvider().getName());
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keygen.initialize(2048, random);
            keyPair = keygen.generateKeyPair();
            System.out.println("Keys successfully generated");
            saveKeypair(KEY_PATH, keyPair);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Keys NOT successfully generated");
            e.printStackTrace();
        }
        return keyPair;
    }

    private boolean saveKeypair(String path, KeyPair _keyPair) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA" /*, PROVIDER */);
            X509EncodedKeySpec x509EncodedKeySpec = factory.getKeySpec(_keyPair.getPublic(), X509EncodedKeySpec.class);
            String strPub = Base64.toBase64String(x509EncodedKeySpec.getEncoded());
            System.out.println("Public Key: " + strPub);
            FileOutputStream out = new FileOutputStream(new File(path + "/daemon.pub"));
            out.write(strPub.getBytes());

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = factory.getKeySpec(_keyPair.getPrivate(), PKCS8EncodedKeySpec.class);
            byte[] bytesPriv = pkcs8EncodedKeySpec.getEncoded();
            String strPriv = Base64.toBase64String(bytesPriv);
            System.out.println("Private Key: " + strPriv);

            Arrays.fill(bytesPriv, (byte) 0);

            out = new FileOutputStream(new File(path + "/daemon.priv"));
            out.write(strPriv.getBytes());

            System.out.println("Saved keypair sucessfully to file");
            return true;
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            System.out.println("Could NOT save keypair sucessfully to file");
            return false;
        }
    }

    public PublicKey convertPublicKey(String publicKey) {
        PublicKey pubKey = null;
        try {
            byte[] encodedPB = Base64.decode(publicKey);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedPB);

            KeyFactory kf = KeyFactory.getInstance("RSA" /*, PROVIDER */);
            pubKey = kf.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return pubKey;
    }

    private boolean loadKeypair(String path) {
        try {
            File filePub = new File(path + "/daemon.pub");
            FileInputStream fileIn = new FileInputStream(filePub);
            byte[] encodedPublicKey = new byte[(int) filePub.length()];
            fileIn.read(encodedPublicKey);
            fileIn.close();

            File filePriv = new File(path + "/daemon.priv");
            fileIn = new FileInputStream(filePriv);
            byte[] encodedPrivateKey = new byte[(int) filePriv.length()];
            fileIn.read(encodedPrivateKey);
            fileIn.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] dataEncodedPublicKey = Base64.decode(encodedPublicKey);
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dataEncodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

            byte[] dataEncodedPrivateKey = Base64.decode(encodedPrivateKey);
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dataEncodedPrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

            Arrays.fill(dataEncodedPrivateKey, (byte) 0);

            keyPair = new KeyPair(publicKey, privateKey);
            System.out.println("Could load keys successfully");
            return true;
        } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.out.println("Could NOT load keys successfully");
            return false;
        }
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public byte[] encryptRSA(String _plain, PublicKey _pubKey) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, _pubKey);
            return cipher.doFinal(_plain.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String dectryptRSA(byte[] _encrypted, PrivateKey _privKey) {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, _privKey);
            return new String(cipher.doFinal(_encrypted));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] signRSA(String _data, PrivateKey _privKey) {
        final Signature signature;
        try {
            signature = Signature.getInstance("SHA256withRSA" /*, PROVIDER */);
            signature.initSign(_privKey);
            signature.update(_data.getBytes());
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] signRSA(byte[] _data, PrivateKey _privKey) {
        final Signature signature;
        try {
            signature = Signature.getInstance("SHA256withRSA" /*, PROVIDER */);
            signature.initSign(_privKey);
            signature.update(_data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean verifyRSA(byte[] _data, byte[] _signData, PublicKey _pubKey) {
        final Signature signature;
        try {
            signature = Signature.getInstance("SHA256withRSA" /*, PROVIDER */);
            signature.initVerify(_pubKey);
            signature.update(_data);
            return signature.verify(_signData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    // OTP Generation - WINDOWS
    public String generateKeyForWindows() {
        return getBiosSN() +              //SerialNumber
                getMainboardSN() +  //SerialNumber
                getOSSN() +         //SerialNumber
                getMemchipPN() +    //PartNumber
                IV_OTP;     //adding random initialization vector
        // equals (bios SN + mainboard SN + OS SN + MEMChip (1st) PN) of current device
    }

    private String getSerialNumber(String device, String searchnumber) {
        String serialNumber = "";

        try {
            process = Runtime.getRuntime().exec("wmic " + device + " get " + searchnumber);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        OutputStream outStream = process.getOutputStream();
        InputStream inStream = process.getInputStream();

        try {
            outStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        Scanner scanner = new Scanner(inStream);
        try {
            while (scanner.hasNext()) {
                String next = scanner.next();
                if ("SerialNumber".equals(next)) {
                    serialNumber = scanner.next().trim();
                    break;
                } else if ("PartNumber".equals(next)) {
                    serialNumber = scanner.next().trim();
                }
            }
        } finally {
            try {
                inStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        //System.out.println("Found SN: " + serialNumber);
        return serialNumber;
    }

    private String getBiosSN() {
        return getSerialNumber("bios", "serialnumber");
    }

    private String getMainboardSN() {
        return getSerialNumber("baseboard", "serialnumber");
    }

    private String getOSSN() {
        return getSerialNumber("os", "serialnumber");
    }

    private String getMemchipPN() {
        return getSerialNumber("memorychip", "partnumber");
    }

    // OTP Generation - LINUX
    public String generateKeyForLinux() {
        // TODO linux
        return "";
    }

    public void incrementIV() {
        System.out.println("\t[increment IV]");
        IV_OTP += 1;
    }

    public OSType getOperatingSystemType() {
        if (detectedOS == null) {
            String OS = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
            if ((OS.contains("mac")) || (OS.contains("darwin"))) {
                detectedOS = OSType.MacOS;
            } else if (OS.contains("win")) {
                detectedOS = OSType.Windows;
            } else if (OS.contains("nux")) {
                detectedOS = OSType.Linux;
            } else {
                detectedOS = OSType.Other;
            }
        }
        return detectedOS;
    }
}
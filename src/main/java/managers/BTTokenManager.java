package managers;

import Utils.Encryption;
import Utils.JsonUtils;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import models.BTToken;
import org.apache.commons.io.FileUtils;

import javax.bluetooth.RemoteDevice;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * Created by Tobias on 21.04.2016.
 */
public class BTTokenManager {

    private final String proximityTokenFilePath = "./proximityToken.txt";
    private File btTokenFile = new File(proximityTokenFilePath);

    private Encryption enc;

    private List<BTToken.Token> btTokens;

    private static BTTokenManager mInstance;

    public static BTTokenManager getInstance() {
        if (mInstance == null) {
            mInstance = new BTTokenManager();
        }
        return mInstance;
    }

    private BTTokenManager() {
        loadFile();
        enc = Encryption.getInstance();
    }

    private boolean loadFile() {
        if (!btTokenFile.exists()) {
            try {
                btTokens = new ArrayList<>();
                return btTokenFile.createNewFile();
            } catch (IOException e) {
                System.out.println("error while file creation");
                e.printStackTrace();
                return false;
            }
        } else {
            try {
                String fileContent = FileUtils.readFileToString(btTokenFile);
                JsonNode jsonBTToken = JsonUtils.toJson(fileContent);
                String json = jsonBTToken.asText();
                if (json != null && !json.equals("")) {
                    btTokens = JsonUtils.fromJson(json, new TypeReference<List<BTToken.Token>>() {
                    });
                } else {
                    btTokens = new ArrayList<>();
                }
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
            return true;
        }
    }

    public boolean saveToken(BTToken.Token btToken) {
        try {
            btTokens.add(btToken);

            String updatedBTTokens = JsonUtils.toJson(btTokens).toString();
            FileWriter fileWriter = new FileWriter(btTokenFile);
            fileWriter.write(updatedBTTokens);
            fileWriter.close();

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        System.out.print("---- /saved [NEW] Token to file");
        return true;
    }

    public boolean updateOTP(BTToken.Token _device, String _updatedOTP) {
        System.out.print("---- /save [UPDATED] Token to file + size: ");
        if (btTokens != null) {
            System.out.println(btTokens.size());
        } else {
            System.out.println("0");
        }
        try {
            BTToken.Token updatedDevice = new BTToken.Token();
            updatedDevice.setDevice(_device.getDevice());
            updatedDevice.setOtp(_updatedOTP);
//            updatedDevice.setKey(_device.getKey());
            updatedDevice.setPublicKey(_device.getPublicKey());
            updatedDevice.setSalt(_device.getSalt());
            updatedDevice.setIV(_device.getIV());
            btTokens.remove(_device);

            btTokens.add(updatedDevice);
            String updatedBTTokens = JsonUtils.toJson(btTokens).toString();
            FileWriter fileWriter = new FileWriter(btTokenFile);
            fileWriter.write(updatedBTTokens);
            fileWriter.close();

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        System.out.print("---- /save [UPDATED] Token to file");
        return true;
    }

    private String createHashForBTDevice(String device) {
        return enc.createHASH_SHA256(device);
    }

    public String createEncryptedHashForBTDevice(String plain, BTToken.Token token) {
        return enc.encryptAES128(plain, token);
    }

    private String createDecryptedHashForBTDevice(String encrypted, BTToken.Token token) {
        String hash = enc.decryptAES128(encrypted, token);
        return createHashForBTDevice(hash);
    }

    public boolean isKnownToken(Vector<RemoteDevice> currentBTDevices) {
        for (RemoteDevice btDevice : currentBTDevices) {
            String device = createHashForBTDevice(btDevice.toString());
            System.out.println("device: " + device);
            for (BTToken.Token btToken : btTokens) {
                String decryptedHash = createDecryptedHashForBTDevice(btToken.getDevice(), btToken);
//                System.out.println("decrypted from btTokens: " + decryptedHash);
                if (decryptedHash.equals(device)) {
                    return true;
                }
            }
        }
        return false;
    }

    public RemoteDevice returnDeviceIfKnown(Vector<RemoteDevice> currentBTDevices) {
        for (RemoteDevice btDevice : currentBTDevices) {
            String device = createHashForBTDevice(btDevice.toString());
            for (BTToken.Token btToken : btTokens) {
                String decryptedHash = createDecryptedHashForBTDevice(btToken.getDevice(), btToken);
                if (decryptedHash.equals(device)) {
                    return btDevice;
                }
            }
        }
        return null;
    }

    public BTToken.Token getTokenForBTDevice(RemoteDevice _device) {
        String device = createHashForBTDevice(_device.toString());
        for (BTToken.Token btToken : btTokens) {
            String decryptedHash = createDecryptedHashForBTDevice(btToken.getDevice(), btToken);

            if (decryptedHash.equals(device)) {
                return btToken;
            }
        }
        return null;
    }

    public List<BTToken.Token> getBtTokens() {
        return btTokens;
    }
}

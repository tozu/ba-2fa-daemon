package managers;

import Utils.Encryption;
import models.BTToken;

import javax.bluetooth.RemoteDevice;

/**
 * Created by Tobias on 21.04.2016.
 */
public class OTPManager {
    private Encryption enc;
    private BluetoothManager btManager;
    private BTTokenManager btTokenManager;

    private static OTPManager mInstance;

    public static OTPManager getInstance() {
        if (mInstance == null) {
            mInstance = new OTPManager();
        }
        return mInstance;
    }

    private OTPManager() {
        btTokenManager = BTTokenManager.getInstance();
        enc = Encryption.getInstance();
        btManager = BluetoothManager.getInstance();
    }

    public String createOTP() {
        if (enc.getOperatingSystemType() == Encryption.OSType.Windows) {
            return enc.createHASH_SHA256(enc.generateKeyForWindows());
        } else if (enc.getOperatingSystemType() == Encryption.OSType.Linux) {
            return enc.createHASH_SHA256(enc.generateKeyForLinux());
        } else {
            return null;
        }
    }

    public boolean verifyOTP(RemoteDevice _device, BTToken.Token _token, String receivedOTP) {
        if (receivedOTP == null) {
            return false;
        }

        String currentOTP = _token.getOtp();
        if (currentOTP.equals(receivedOTP)) {
            enc.incrementIV();

            String newOTP = createOTP();
            if (btManager.sendOTPToDevice(_device, newOTP, _token)) {
                return btTokenManager.updateOTP(_token, newOTP);
            } else {
                System.out.println("\t Sending the updated OTP was unsuccessful, didn't update the OTP for the device");
                return false;
            }
        } else {
            System.out.println("\t[COMPARE OTP] - FAILED!");
            return false;
        }
    }

    public boolean verifyHMAC(RemoteDevice device, BTToken.Token _token, String receivedHMAC, String clientHMACKey) {
        if (receivedHMAC == null) {
            return false;
        }

        String possibleHMAC = enc.createHMAC_SHA256(_token.getOtp(), clientHMACKey);
        if (possibleHMAC.equals(receivedHMAC)) {
            enc.incrementIV();

            String newOTP = createOTP();
            if (btManager.sendOTPToDevice(device, newOTP, _token)) {
                return btTokenManager.updateOTP(_token, newOTP);
            } else {
                System.out.println("\t Sending the updated OTP was unsuccessful, didn't update the OTP for the device");
                return false;
            }
        } else {
            System.out.println("\t [compareHMAC] - FAILED!");
            return false;
        }
    }

}

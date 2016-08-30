package main;

import Utils.BTDiscovery;
import Utils.Encryption;
import managers.BTTokenManager;
import managers.BluetoothManager;
import managers.OTPManager;
import managers.PasswordManager;
import models.BTToken;
import org.eclipse.jetty.server.Response;
import spark.Filter;
import spark.Request;

import javax.bluetooth.RemoteDevice;
import java.io.IOException;
import java.util.Scanner;
import java.util.Vector;

import static spark.Spark.*;

public class Main {
    private static final String keystoreFile = "keystore.jks";
    private static final String truststoreFile = "truststore";

    private BTDiscovery btDiscovery;
    private BTTokenManager btTokenManager;
    private BluetoothManager btManager;
    private OTPManager otpManager;

    private PasswordManager pwdManager;
    private Encryption encManager;

    private static int tries = 0;

    private static Main cInstance;

    private static Main getInstance() {
        if (cInstance == null) {
            cInstance = new Main();
        }
        return cInstance;
    }

    private static void enableCORS(final String origin, final String methods, final String headers) {
        options("/*", (request, response) -> {

            // Access-Control-Expose-Headers


            String accessControlRequestHeaders = request.headers("Access-Control-Request-Headers");
            if (accessControlRequestHeaders != null) {
                response.header("Access-Control-Allow-Headers", accessControlRequestHeaders);
                response.header("Access-Control-Allow-Origin", accessControlRequestHeaders);
            }

            String accessControlRequestMethod = request.headers("Access-Control-Request-Method");
            if (accessControlRequestMethod != null) {
                response.header("Access-Control-Allow-Methods", accessControlRequestMethod);
            }

            return "OK";
        });

        before((request, response) -> {
            response.header("Access-Control-Allow-Origin", origin);
            response.header("Access-Control-Request-Method", methods);
            response.header("Access-Control-Allow-Headers", headers);
            response.header("Access-Control-Expose-Headers", "foundBT");
        });
    }

    private Main() {

        secure(keystoreFile, "13371337", null, null); // truststoreFile, "changeit");
        enableCORS("*", "*", "*");

        btDiscovery = BTDiscovery.getInstance();
        btTokenManager = BTTokenManager.getInstance();

        btManager = BluetoothManager.getInstance();
        otpManager = OTPManager.getInstance();

        pwdManager = PasswordManager.getInstance();
        encManager = Encryption.getInstance();
    }

    public static void main(String[] args) {
        Main BTDaemon = getInstance();

        if (BTDaemon.pwdManager.getPasswordHash() == null) {
            System.out.println("[SETUP]"
                    + "\nPlease enter a password to protect your Daemon and its tokens");
            System.out.print("Password: ");
            // check on input
            Scanner cmdLine = new Scanner(System.in);
            String input = cmdLine.nextLine();
            while (input.length() <= 0) {
                input = cmdLine.nextLine();
            }
            if (BTDaemon.pwdManager.savePasswordToFile(input)) {
                BTDaemon.encManager.setEncKey(input);
            } else {
                System.out.println("[ERROR] setting up Encryption key");
                return;
            }
        } else {
            System.out.println("[SETUP]" + "\nPlease enter the password of the daemon!");
            System.out.print("Password: ");

            // check on input
            Scanner cmdLine = new Scanner(System.in);
            String input = cmdLine.nextLine();
            while (input.length() <= 0) {
                input = cmdLine.nextLine();
            }

            String hashInput = BTDaemon.encManager.createHASH_SHA256(input);
            if (!hashInput.equals(BTDaemon.pwdManager.getPasswordHash())) {
                return;
            } else {
                BTDaemon.encManager.setEncKey(input);
                System.out.println("password correct!");
            }
        }

        if (BTDaemon.btTokenManager.getBtTokens().size() == 0) {
            BTDaemon.setupNewDevice();
        }

        // test page
        get("/hello", (req, res) -> "Hello World");

        get("/addNewDevice", (request, response) -> {
            BTDaemon.setupNewDevice();
            return "";
        });

        // scans for nearby BT devices
        get("/scanForBT", (req, res) -> {
            System.out.println("---- /scanForBT executed");
            BTDaemon.btDiscovery.findBTDevices();
            return "";
        });

        // Check if authorized token is nearby
        get("/checkForAuthToken", (req, res) -> {
            String level = req.queryParams("level");
            int lvl = Integer.parseInt(level);
            System.out.println("---- /checkForAuthToken executed with Sec. Level: " + lvl);

            String hmac = req.queryParams("hmac");
            System.out.println("---- /checkForAuthToken with hmac: " + hmac);

            if (BTDaemon.checkAuthentication(lvl, hmac)) {
                res.header("foundBT", "true");
                System.out.println("SUCCESSFUL");
//                res.status(Response.SC_OK);
                return "SUCCESSFUL";
            } else {
                res.header("foundBT", "false");
//                res.status(Response.SC_BAD_REQUEST);
                return "FAIL";
            }
        });
    }

    private boolean checkAuthentication(int securityLevel, String clientHMACKey) {
        btDiscovery.findBTDevices();
        Vector<RemoteDevice> currentBTDevices = btDiscovery.getBTDevices();
        RemoteDevice currentBTDevice;
        BTToken.Token btToken;
        switch (securityLevel) {
            case 1:
                return btTokenManager.isKnownToken(currentBTDevices);
            case 2:
                currentBTDevice = btTokenManager.returnDeviceIfKnown(currentBTDevices);
                btToken = btTokenManager.getTokenForBTDevice(currentBTDevice);
                if (currentBTDevice != null && btToken != null) {
                    String receivedOTP = btManager.requestFromDevice(currentBTDevice, BluetoothManager.REQUESTS.DAEMON_REQUESTS_OTP);
                    return otpManager.verifyOTP(currentBTDevice, btToken, receivedOTP);
                }
                return false;
            case 3:
                if (clientHMACKey == null) {
                    return false;
                }

                currentBTDevice = btTokenManager.returnDeviceIfKnown(currentBTDevices);
                btToken = btTokenManager.getTokenForBTDevice(currentBTDevice);
                if (currentBTDevice != null && btToken != null) {
                    String receivedHMAC = btManager.requestFromDevice(currentBTDevice, BluetoothManager.REQUESTS.DAEMON_REQUESTS_HMAC);
                    return otpManager.verifyHMAC(currentBTDevice, btToken, receivedHMAC, clientHMACKey);
                }
                return false;
            default:
                return false;
        }
    }

    private void setupNewDevice() {
        System.out.println("---- /Setup");
        try {
            Vector<RemoteDevice> currentBTDevices;

            btDiscovery.findBTDevices();
            currentBTDevices = btDiscovery.getBTDevices();

            if (currentBTDevices.size() == 0) {
                System.out.println("Couldn't find a BT Devices - Retry (" + tries + ")");
                while (tries <= 2) {
                    btDiscovery.findBTDevices();
                    currentBTDevices = btDiscovery.getBTDevices();
                    tries++;
                    if (currentBTDevices.size() == 0) {
                        System.out.println("Couldn't find a BT Devices - Retry (" + tries + ")");
                    } else {
                        // no more looping needed found some
                        break;
                    }
                }
                // tries are over, check the result
                if (currentBTDevices.size() == 0) {
                    System.out.println("Couldn't find a BT Devices - after " + (tries + 1) + " tries");
                    return;
                } else {
                    // could find a bt device
                    tries = 1;
                }
            }

            System.out.println("Choose device from List: \n");
            int n = 0;
            for (RemoteDevice device : currentBTDevices) {
                System.out.println((n + 1) + ". " + device.getFriendlyName(false));
                n++;
            }
            System.out.print("Chosen device: ");
            Scanner scanner = new Scanner(System.in);

            int position;
            try {
                position = Integer.valueOf(scanner.nextLine());
            } catch (NumberFormatException e) {
                position = 0;
            }

            while (position <= 0 || position > currentBTDevices.size()) {
                System.out.println("Please enter a VALID Number!");
                System.out.print("Chosen device: ");
                position = Integer.valueOf(scanner.nextLine());
            }
            RemoteDevice device = currentBTDevices.elementAt(position - 1);

            System.out.println("Choose Level of Security: ");
            System.out.print("\t(1) Proximity Auth. only\n");
            System.out.print("\t(2) Proximity Auth. + OTP\n");
            System.out.print("\t(3) Proximity Auth. + OTP + HMAC\n");
            System.out.print("Security Level: ");

            int level;
            try {
                level = Integer.valueOf(scanner.nextLine());
            } catch (NumberFormatException e) {
                level = 0;
            }

            while (level <= 0 || level >= 4) {
                System.out.println("Please choose a VALID Security Level!");
                System.out.print("Security Level: ");
                level = Integer.valueOf(scanner.nextLine());
            }
            scanner.close();
            BTToken.Token btToken = new BTToken.Token();

            String token = btTokenManager.createEncryptedHashForBTDevice(device.getBluetoothAddress(), btToken);
            btToken.setDevice(token);

            switch (level) {
                case 2:
                case 3:
                    String pb_bt = btManager.requestFromDevice(device, BluetoothManager.REQUESTS.DAEMON_REQUEST_PUBLIC_KEY);
                    if (pb_bt == null) {
                        System.out.println("[ERROR] Failure requesting Public Key from BT Device");
                        break;
                    } else {
                        btToken.setPublicKey(pb_bt);
                    }

                    String otp = otpManager.createOTP();
                    if (btManager.sendOTPToDevice(device, otp, btToken)) {
                        btToken.setOtp(otp);
                        break;
                    } else {
                        System.out.println("could NOT set level 2 security. are you sure it is supported?");
                        break;
                    }
                default:
                    break;
            }

            if (!btTokenManager.saveToken(btToken)) {
                System.out.println("ERROR while saving token to file!");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
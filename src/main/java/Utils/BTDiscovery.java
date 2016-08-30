package Utils;

import com.intel.bluetooth.BlueCoveConfigProperties;
import com.intel.bluetooth.BlueCoveImpl;

import javax.bluetooth.*;
import java.io.IOException;
import java.util.Vector;

public class BTDiscovery implements DiscoveryListener {

    private Vector<RemoteDevice> mDiscoveredDevices;
    private Vector<String> serviceFound;
    private UUID my_uuid = new UUID("4e5d48e075df11e3981f0800200c9a66", false);

    private Object serviceSearchCompletedEvent = new Object();
    private final Object inquiryCompletedEvent = new Object();

    private static BTDiscovery mInstance;

    public static BTDiscovery getInstance() {
        if (mInstance == null) {
            mInstance = new BTDiscovery();
        }
        return mInstance;
    }

    private BTDiscovery() {
        BlueCoveImpl.setConfigProperty(BlueCoveConfigProperties.PROPERTY_CONNECT_TIMEOUT, "5000");
        mDiscoveredDevices = new Vector<>();
        serviceFound = new Vector<>();
    }

    public Vector<RemoteDevice> getBTDevices() {
        return mDiscoveredDevices;
    }

    public Vector<String> getServiceFound() {
        return serviceFound;
    }

    public void findBTDevices() {
        mDiscoveredDevices.clear();

        synchronized (inquiryCompletedEvent) {
            boolean started;
            try {
                started = LocalDevice.getLocalDevice().getDiscoveryAgent().startInquiry(DiscoveryAgent.GIAC, this);
                if (started) {
                    System.out.println("wait for device inquiry to complete...");
                    inquiryCompletedEvent.wait();
                }
            } catch (BluetoothStateException | InterruptedException e) {
                e.printStackTrace();
            }

        }
    }

    public void searchServiceForDevice(RemoteDevice _device) {
        UUID[] searchUUIDSet = new UUID[]{my_uuid};
        int[] attrIDs = new int[]{0x0003};

        synchronized (serviceSearchCompletedEvent) {
            try {
//                System.out.println("search services on: " + _device.getFriendlyName(false) + " (" + _device.getBluetoothAddress() + ")");
                LocalDevice.getLocalDevice().getDiscoveryAgent().searchServices(attrIDs, searchUUIDSet, _device, this);
                serviceSearchCompletedEvent.wait();
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Device search
    @Override
    public void deviceDiscovered(RemoteDevice remoteDevice, DeviceClass deviceClass) {
        try {
            mDiscoveredDevices.addElement(remoteDevice);
            System.out.println("Device " + remoteDevice.getFriendlyName(false) + " found");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void inquiryCompleted(int discType) {
        synchronized (inquiryCompletedEvent) {
            System.out.println("Device inquiry completed");
            inquiryCompletedEvent.notifyAll();
        }
    }

    // Service search
    @Override
    public void servicesDiscovered(int transID, ServiceRecord[] serviceRecords) {
        serviceFound.clear();
        for (ServiceRecord record : serviceRecords) {

            String url = record.getConnectionURL(ServiceRecord.NOAUTHENTICATE_NOENCRYPT, false);
            if (url == null) {
                continue;
            }
            serviceFound.add(url);
            DataElement serviceName = record.getAttributeValue(0x0003);
//            if (serviceName != null) {
//                System.out.println("service " + serviceName.getValue() + " found: " + url);
//                //hasOBEXFileTransfer = true;
//            } else {
//                System.out.println("service found: " + url);
//            }

        }
    }

    @Override
    public void serviceSearchCompleted(int transID, int respID) {
//        System.out.println(" --- serviceSearchCompleted - transID: " + transID + " - respID: " + respID);
        synchronized (serviceSearchCompletedEvent) {
            serviceSearchCompletedEvent.notifyAll();
        }
    }

}

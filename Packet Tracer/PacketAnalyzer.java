import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class PacketAnalyzer {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static void main(String[] args) throws IOException {
        String filename = "";
        // if user input not provided, let the user know that an input is needed
        try {
            filename = args[0];
        }
        catch (ArrayIndexOutOfBoundsException e){
            System.out.println("User input not provided");
            System.exit(0);
        }

        byte[] data = readFile(filename);
        ArrayList<Byte> byteArrayList = new ArrayList<>();
        for(byte i: data)
            byteArrayList.add(i);

        ethernetModel(byteArrayList);
    }

    private static byte[] readFile(String file) {

        Path path = null;
        byte[] res = new byte[0];
        try{
            path = Paths.get(file);
            res = Files.readAllBytes(path);
        }catch (IOException e){
            System.out.println("Error in reading file! Try again!");
            System.exit(0);
        }
        return res;
    }

    private static void ethernetModel(ArrayList<Byte> data){
        int packetSize = data.size();
        String destinationMacAddress = bytesToHex(data.subList(0,6));
        String sourceMacAddress = bytesToHex(data.subList(6,12));
        String protocolModel = protocolDeduction(data.subList(12,14), bytesToHex(data.subList(12,13)));
        System.out.println("ETHER: ----- Ether Header -----");
        System.out.println("ETHER:");
        System.out.println("ETHER: Packet size = "+packetSize+" bytes");
        String Res = printMacAddress(destinationMacAddress.toCharArray());
        System.out.println("ETHER: Destination = "+Res+",");
        Res = printMacAddress(sourceMacAddress.toCharArray());
        System.out.println("ETHER: Source = "+Res+",");
        if(protocolModel.equals("0800 (IP)")) {
            System.out.println("ETHER: Ethertype = 0800 (IP)");
            System.out.println("ETHER:");
            ipModel(data);
        }
    }

    private static String printMacAddress(char[] macAddress){
        String Res = macAddress[0]+"";
        for(int i=1; i<macAddress.length; i++){
            if(i%2 == 0)
                Res += ":";
            Res += macAddress[i];
        }
        return Res;
    }

    private static void icmpModel(ArrayList<Byte> data, int start) {
        int type = Integer.parseInt(bytesToHex(data.subList(start,start+1)),16);
        String icmpType = "";
        switch (type) {
            case 0:
                icmpType = type + " (Eco Reply)";
                break;
            case 3:
                icmpType = type + " (Destination Unreachable)";
                break;
            case 4:
                icmpType = type + " (Source Quench)";
                break;
            case 8:
                icmpType = type + " (Eco Request)";
                break;
            case 11:
                icmpType = type + " (Time Exceeded)";
                break;
            case 12:
                icmpType = type + " (Parameter Problem)";
                break;
            case 13:
                icmpType = type + " (Timestamp request)";
                break;
            case 14:
                icmpType = type + " (Timestamp reply)";
                break;
            case 15:
                icmpType = type + " (Information Request)";
                break;
            case 16:
                icmpType = type + " (Information Reply)";
                break;
            case 17:
                icmpType = type + " (Address mask request)";
                break;
            case 18:
                icmpType = type + " (Address mask response)";
                break;
        }
        int code = Integer.parseInt(bytesToHex(data.subList(start+1,start+2)),16);
        String checksum = "0x"+bytesToHex(data.subList(start+2,start+4));

        System.out.println("ICMP: ----- ICMP Header -----");
        System.out.println("ICMP:");
        System.out.println("ICMP: Type = "+icmpType);
        System.out.println("ICMP: Code = "+code);
        System.out.println("ICMP: Checksum = "+checksum);
        System.out.println("ICMP:");
    }

    private static void udpModel(ArrayList<Byte> data, int start) {
        int sourcePort = Integer.parseInt(bytesToHex(data.subList(start,start+2)),16);
        int destinationPort = Integer.parseInt(bytesToHex(data.subList(start+2,start+4)),16);
        int length = Integer.parseInt(bytesToHex(data.subList(start+4,start+6)),16);
        String checksum = "0x"+bytesToHex(data.subList(start+6,start+8));
        System.out.println("UDP: ----- UDP Header -----");
        System.out.println("UDP:");
        System.out.println("UDP: Source port = "+sourcePort);
        System.out.println("UDP: Destination port = "+destinationPort);
        System.out.println("UDP: Length = "+length);
        System.out.println("UDP: Checksum = "+checksum);
        System.out.println("UDP:");
        System.out.println("UDP: Data: (first 64 bytes)");
        dataTranslator(data.subList(start+8, Integer.min(data.size(), start+72)),"UDP");

    }

    private static void tcpModel(ArrayList<Byte> data, int start) {
        int sourcePort = Integer.parseInt(bytesToHex(data.subList(start,start+2)),16);
        int destinationPort = Integer.parseInt(bytesToHex(data.subList(start+2,start+4)),16);
        int sequenceNumber = Integer.parseInt(bytesToHex(data.subList(start+4,start+8)),16);
        long ackNumber = Long.parseLong(bytesToHex(data.subList(start+8,start+12)),16);
        char [] flagChar = bytetoBit(data.subList(start+12,start+14));
        int dataOffset = countBinaryToInt(flagChar[0],flagChar[1],flagChar[2],flagChar[3])*4;
        String flag =  "0x"+Integer.toHexString(bytearray2intarray(data.subList(start+13,start+14))[0]);
        String urgentPointer = "";
        if(flagChar[10]=='0')
            urgentPointer = "..0. .... = No urgent pointer";
        else
            urgentPointer = "..1. .... = urgent pointer available";
        String ack = "";
        if(flagChar[11] == '1')
            ack = "...1 .... = Acknowledgement";
        else
            ack = "...0 .... = No Acknowledgement";
        String push = "";
        if(flagChar[12] == '1')
            push = ".... 1... = Push";
        else
            push = ".... 0... = No Push";
        String reset = "";
        if(flagChar[13]=='0')
            reset = ".... .0.. = No reset";
        else
            reset = ".... .1.. = Reset";
        String syn = "";
        if(flagChar[14]=='0')
            syn = ".... ..0. = No Syn";
        else
            syn = ".... ..1. = Syn";
        String fin = "";
        if(flagChar[15] == '0')
            fin = ".... ...0 = No Fin";
        else
            fin = ".... ...1 = No Fin";
        int window = Integer.parseInt(bytesToHex(data.subList(start+14,start+16)),16);
        String checksum = "0x"+bytesToHex(data.subList(start+16,start+18));
        String urgPointer = Integer.toHexString(bytearray2intarray(data.subList(start+18,start+20))[0]+bytearray2intarray(data.subList(start+18,start+20))[1]);
        String options = "";
        if(dataOffset>20)
            options = "Options Available";
        else
            options = "No options";
        System.out.println("TCP: ----- TCP Header -----");
        System.out.println("TCP:");
        System.out.println("TCP: Source port = "+sourcePort);
        System.out.println("TCP: Destination port = "+destinationPort);
        System.out.println("TCP: Sequence number = "+sequenceNumber);
        System.out.println("TCP: Acknowledgement number = "+ackNumber);
        System.out.println("TCP: Data offset = "+dataOffset+" bytes");
        System.out.println("TCP: Flags = "+flag);
        System.out.println("TCP:       "+urgentPointer);
        System.out.println("TCP:       "+push);
        System.out.println("TCP:       "+reset);
        System.out.println("TCP:       "+syn);
        System.out.println("TCP:       "+fin);
        System.out.println("TCP: Window = "+window);
        System.out.println("TCP: Checksum = "+checksum);
        System.out.println("TCP: Urgent pointer = "+urgPointer);
        System.out.println("TCP: "+options);
        System.out.println("TCP:");
        System.out.println("TCP: Data: (first 64 bytes)");
        dataTranslator(data.subList(start+dataOffset, Integer.min(data.size(), (start+dataOffset)+64)), "TCP");
    }

    private static void dataTranslator(List<Byte> subList, String tcp_udp) {
        char[] dataInHex = bytesToHex(subList).toCharArray();
        int[] dataInDecimal = bytearray2intarray(subList);
        char[] data = new char[dataInDecimal.length];
        for(int i=0; i<dataInDecimal.length; i++){
            if(dataInDecimal[i]>32 && dataInDecimal[i]<127)
                data[i] = (char) dataInDecimal[i];
            else
                data[i] = '.';
        }
        String temp1 = "";
        String temp2 = data[0]+"";
        int j = 1;
        for(int i = 0; i<dataInHex.length; i++){
            temp1 += dataInHex[i];
            if((i+1)%4==0)
                temp1+=" ";
            if((i+1)%32==0 || i==dataInHex.length-1) {
                System.out.print(tcp_udp+": " + temp1);
                if((i+1)%32!=0 && (dataInHex.length-1) == i){
                    int k = 32 - ((i+1)%32);
                    int m = 8 - ((i+1)%32) / 4 ;
                    for(int n = 0; n<k+m; n++){
                        System.out.print(" ");
                    }
                }
                System.out.println("    '"+temp2+"'");
                temp1 = "";
                temp2 = "";
            }
            if((i+1)%2==0 && j<data.length){
                temp2 += data[j++];
            }
        }
    }

    private static void ipModel(ArrayList<Byte> data) {
        int version = data.get(14) >> 4;
        int headerLength = data.subList(14,34).size();
        String typeOfService = "0x"+bytesToHex(data.subList(15,16));
        char[] serviceType = bytetoBit(data.subList(15,16));
        int count = countBinaryToInt('0',serviceType[0], serviceType[1], serviceType[2]);
        String precedence = "xxx. .... = "+count+" (precedence)";
        String delay = ""+serviceType[3];
        if(delay.equals("0"))
            delay = "...0 .... = normal delay";
        else if(delay.equals("1"))
            delay = "...1 .... = low delay";
        String throughput = ""+serviceType[4];
        if(throughput.equals("0"))
            throughput = ".... 0... = normal throughput";
        else
            throughput = ".... 1... = high throughput";
        String reliability = ""+serviceType[5];
        if(reliability.equals("0"))
            reliability = ".... .0.. = normal reliability";
        else
            reliability = ".... .1.. = high reliability";
        int totalLength = (data.get(16) + data.get(17)) & 0xff;
        long identification = Long.parseLong(bytesToHex(data.subList(18,19)) + bytesToHex(data.subList(19,20)), 16);
        char[] flagchar1 = bytetoBit(data.subList(20,21));
        count = countBinaryToInt('0',flagchar1[0], flagchar1[1], flagchar1[2]);
        String flags = "0x"+count;
        String doNotFragment = "";
        if(flagchar1[1]=='1')
            doNotFragment = ".1.. .... = do not fragment";
        else
            doNotFragment = ".0.. .... = do fragment";
        String lastFragment = "";
        if(flagchar1[2] == '0')
            lastFragment = "..0. .... = last fragment";
        else
            lastFragment = "..1. .... = not the last fragment";
        int fragmentOffset = (Integer.parseInt( bytesToHex(data.subList(20,21)) +  bytesToHex(data.subList(21,22)), 16) & 0b0001111111111111);
        int timeToLive = data.get(22) & 0xff;
        String protocolModel = protocolDeduction(data.subList(23,24), bytesToHex(data.subList(23,24)));
        String checksum = "0x"+bytesToHex(data.subList(24,26));
        int[] ipSourceAddress = bytearray2intarray(data.subList(26,30));
        int[] ipDestinationAddress = bytearray2intarray(data.subList(30,34));

        System.out.println("IP: ----- IP Header -----");
        System.out.println("IP:");
        System.out.println("IP: Version = "+version);
        System.out.println("IP: Header length = "+headerLength+" bytes");
        System.out.println("IP: Type of service = "+typeOfService);
        System.out.println("IP:        "+precedence);
        System.out.println("IP:        "+delay);
        System.out.println("IP:        "+reliability);
        System.out.println("IP: Total length = "+totalLength+" bytes");
        System.out.println("IP: Identification = "+identification);
        System.out.println("IP: Flags = "+flags);
        System.out.println("IP:        "+doNotFragment);
        System.out.println("IP:        "+lastFragment);
        System.out.println("IP: Fragment offset = "+fragmentOffset+" bytes");
        System.out.println("IP: Time to live = "+timeToLive+" seconds/hops");
        System.out.println("IP: Protocol = "+protocolModel);
        System.out.println("IP: Header checksum = "+checksum);
        System.out.print("IP: Source address = "+printIpAddress(ipSourceAddress));
        System.out.println();
        System.out.println("IP: Destination address = "+printIpAddress(ipDestinationAddress));

        if(headerLength>20)
            System.out.println("IP: Options Available");
        else
            System.out.println("IP: No options");
        System.out.println("IP:");

        switch (protocolModel) {
            case "01 (ICMP)":
                icmpModel(data, 14+headerLength);
                break;
            case "06 (TCP)":
                tcpModel(data, 14+headerLength);
                break;
            case "11 (UDP)":
                udpModel(data, 14+headerLength);
                break;
        }
    }

    private static StringBuilder printIpAddress(int[] ipAddress){
        StringBuilder res = new StringBuilder();
        for(int i=0; i<ipAddress.length; i++){
            if(i == ipAddress.length-1)
                res.append(ipAddress[i]);
            else
                res.append(ipAddress[i]).append(".");
        }
        return res;
    }

    private static char[] bytetoBit(List<Byte> byteArray) {
        final char[] bits = new char[8*byteArray.size()];
        for(int i = 0; i < byteArray.size(); i++) {
            byte byteNumber = byteArray.get(i);
            int b = i << 3;
            int m = 0x1;
            for(int j = 7; j >= 0; j--) {
                int bitNumber = byteNumber & m;
                if(bitNumber == 0) {
                    bits[b + j] = '0';
                } else {
                    bits[b + j] = '1';
                }
                m <<= 1;
            }
        }
        return bits;
    }

    private static int[] bytearray2intarray(List<Byte> bytes)
    {
        int[] arr = new int[bytes.size()];
        int i = 0;
        for (byte b : bytes)
            arr[i++] = b & 0xff;
        return arr;

    }

    private static String bytesToHex(List<Byte> b) {
        char[] CharsInHex = new char[b.size() * 2];
        for ( int j = 0; j < b.size(); j++ ) {
            int n = b.get(j) & 0xFF;
            CharsInHex[j * 2] = hexArray[n >>> 4];
            CharsInHex[j * 2 + 1] = hexArray[n & 0x0F];
        }
        return new String(CharsInHex);
    }

    private static int countBinaryToInt(char n, char a, char b, char c){
        int count = 0;
        if(n == '1')
            count+=8;
        if(a == '1')
            count+=4;
        if(b == '1')
            count+=2;
        if(c == '1')
            count+=1;
        return count;
    }

    private static String protocolDeduction(List<Byte> protocolData, String protocolType){
        if(protocolData.size() == 1){
            if(protocolType.equals("06"))
                return protocolType+" (TCP)";
            if(protocolType.equals("11"))
                return protocolType+" (UDP)";
            if(protocolType.equals("01"))
                return protocolType+" (ICMP)";
        }

        String secondHalfHexValue = bytesToHex(protocolData.subList(1,2));
        if((protocolType + secondHalfHexValue).equals("0800"))
            return "0800 (IP)";
        else 
            return protocolType+secondHalfHexValue+" (IPV6)";
    }

}

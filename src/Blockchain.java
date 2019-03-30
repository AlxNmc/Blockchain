/*--------------------------------------------------------

1. Name / Date:
    Alex Niemiec / 10/23/2018

2. Java version used, if not the official version for the class:
    build 1.8.0_191-b12

3. Precise command-line compilation examples / instructions:

> javac Blockchain.java

4. Precise examples / instructions to run this program:

> java java Blockchain 0
> java java Blockchain 1
> java java Blockchain 2

*Start using batch file that executes all three commands at once if possible

5. List of files needed for running the program.

BlockInput0.txt, BlockInput1.txt, BlockInput2.txt
in the same directory as class file

5. Notes:
The xml file created has two copies of the blockchain, most likely beacuse I am storing the
blocks in a double-ended queue and the data that results when this data type is marshaled
into XML is formatted this way.

As of right now, my verification method causes errors, so I have left it disabled. The ledger
created by process 0 shows that the blockchain appears to be correct (correct block sequence and
solution hash each block is stored in a field in each subsequent block)

I did not implement command-line functionality
----------------------------------------------------------*/

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.Marshaller;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

//When initialized creates a set of port numbers for our process based on the process number
class Ports{
    public static int pubKeyPort;
    public static int unverifiedBlockPort;
    public static int blockchainUpdatePort;

    Ports(int processNum){
        set(processNum);
    }
    private static void set(int p){
        pubKeyPort              = 4710 + p;
        unverifiedBlockPort     = 4820 + p;
        blockchainUpdatePort    = 4930 + p;
    }
}

//When initialized creates a publicly available key pair for our process
class Keys{
    public static PublicKey publicKey;
    public static PrivateKey privateKey;
    public static PublicKey[] pubKeys;

    Keys(long seed) {
        set(seed);
        pubKeys = new PublicKey[3];
    }

    //create a new key pair based on the passed seed
    private void set(long s){
        try{
            //Create SecureRandom object using SHA1 and set seed using the seed passed by constructor
            SecureRandom randNumGen = SecureRandom.getInstance("SHA1PRNG", "SUN");
            randNumGen.setSeed(s);
            //Create KeyPairGenerator object with RSA algorithm and initialize using random value from SecureRandom
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, randNumGen);
            //Set public variables using the key pair generator
            KeyPair keys = keyGen.genKeyPair();
            publicKey = keys.getPublic();
            privateKey = keys.getPrivate();
        }catch(NoSuchAlgorithmException ex){
            ex.printStackTrace();
        }catch (NoSuchProviderException ex) {
            ex.printStackTrace();
        }
    }
}

//accepts a connection whenever an updated blockchain ledger is distributed and stores it. The verification function
//is faulty as of right now
class BlockchainUpdateServer extends Thread{
    static BlockLedger blockLedger;
    public void run(){
        blockLedger = new BlockLedger();
        int q_len = 6;
        Socket socket;
        try{
            ServerSocket svSocket = new ServerSocket(Ports.blockchainUpdatePort, q_len);
            while(true){
                socket = svSocket.accept();
                new BlockchainUpdateWorker(socket).start();

            }
        }catch(IOException iox){
            System.out.println(iox);
        }
    }
    public static BlockLedger getBL(){
        return blockLedger;
    }
    public static void setBL(BlockLedger bl){
        blockLedger = bl;
    }
}

//Manages new connections having to do with updates to the blockchain ledger
class BlockchainUpdateWorker extends Thread{
    Socket s;
    BlockchainUpdateWorker(Socket socket){
        s = socket;
    }
    public void run(){
        BufferedReader in;
        BlockLedger blockLedger;
        String XMLBlockLedger;
        try{
            //read data line by line into XMLBlockLedger variable
            in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            String line;
            XMLBlockLedger = in.readLine();
            while((line=in.readLine())!=null){
                XMLBlockLedger += "\n" + line;
            }
            //Unmarshal the data back into a BlockLedger object
            blockLedger = (BlockLedger) Blockchain.XMLtoObject(XMLBlockLedger, BlockLedger.class);
            //The verification method call below is disabled to show functionality without errors
            // if(verifyChain(blockLedger)){
            System.out.println("Ledger updated");
            BlockchainUpdateServer.setBL(blockLedger);
            if(Blockchain.processNum == 0){
                writeToFile(blockLedger);
            }
            //}
        }catch(Exception ex){ex.printStackTrace();}
    }
    //verifies blockchain by performing a variety of checks on the data
    private boolean verifyChain(BlockLedger BL){
        try {
            Object[] brArray = BL.getLedger().toArray();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            BlockRecord previous = (BlockRecord) brArray[0];
            BlockRecord next;
            String prevSHash;
            String currentSHash;
            String signedSHash;
            int prevNum;
            int nextNum;

            //iterate through an array version of the data starting at second element and verify each block
            //in reference to the last
            for(int i = 1; i<brArray.length; i++){
                next = (BlockRecord) brArray[i];

                //check proper sequence of block numbers
                prevNum = Integer.parseInt(previous.getABlockNum());
                nextNum = Integer.parseInt(next.getABlockNum());
                if (nextNum != (prevNum + 1)){
                    System.out.println("Blockchain rejected. Out of sequence.");
                    return false;
                }

                //retrieve fields relevant to the needed checks
                prevSHash = previous.getDSolutionHash();
                currentSHash = next.getDSolutionHash();
                signedSHash = next.getDSignedSolutionHash();

                //restore block to state appropriate for checking validity of solution
                next.setDSolutionHash(null);
                next.setDSignedSolutionHash(null);
                next.setCPrevSHA256(prevSHash);

                //validate signed solution hash using the verifying process' public key
                if(!Blockchain.verifyString(currentSHash, signedSHash, next.getAVID())){
                    System.out.println("Blockchain rejected. Solution signature invalid.");
                }

                //recreate solution hash using seed and raw block data and check against given solution
                String solutionHash = Blockchain.makeSHA256hash(Blockchain.makeXML(next));
                if(!currentSHash.contains(solutionHash)){
                    System.out.println("Blockchain rejected. Solution hash mismatch.");
                    return false;
                }

                //recreate work calculation on solution hash
                byte[] bytesHash = md.digest(solutionHash.getBytes("UTF-8"));
                String hexString = DatatypeConverter.printHexBinary(bytesHash);
                int workNum = Integer.parseInt(hexString.substring(0, 4), 16);

                //check validity of solution
                if(workNum>=(0xFFFF/4)){
                    System.out.println("Blockchain rejected. Solution incorrect.");
                    return false;
                }
            }
            return true;
        }catch (Exception ex){ex.printStackTrace();}
        return false;
    }

    //write XML data form of block ledger to file
    void writeToFile(BlockLedger BL){
        try{
            File file = new File("./BlockchainLedger.xml");
            JAXBContext jbC = JAXBContext.newInstance(BlockLedger.class);
            Marshaller jbM = jbC.createMarshaller();
            jbM.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            jbM.marshal(BL, file);
        }catch (Exception ex){ex.printStackTrace();}
    }
}

//Listens for connections related to new unverified blocks
class UnverifiedBlockServer extends Thread{
    //Blocking Queue that holds all blocks in line for verification. The oldest block is always polled first.
    BlockingQueue<BlockRecord> bQueue;

    UnverifiedBlockServer(){bQueue = new PriorityBlockingQueue<>();}

    public void run(){
        //The solver thread is started immediately on initiation
        new UBSolver().start();
        int q_len = 6;
        Socket socket;
        try{
            ServerSocket svSocket = new ServerSocket(Ports.unverifiedBlockPort, q_len);
            while(true){
                socket = svSocket.accept();
                new UBWorker(socket).start();
            }
        }catch(IOException iox){
            System.out.println(iox);
        }
    }

    //Handles new unverified block connections and adds the new blocks to the priority queue in the Unverified Block Server
    class UBWorker extends Thread{
        Socket s;
        UBWorker(Socket socket){s=socket;}
        public void run(){
            String xmlBlock;
            BufferedReader in;
            BlockRecord block;
            try{
                //read data line by line into the xmlBlock string
                in = new BufferedReader(new InputStreamReader(s.getInputStream()));
                String line;
                xmlBlock = in.readLine();
                while((line=in.readLine())!=null){
                    xmlBlock += "\n" + line;
                }
                //Unmarshall the block and add it to the queue
                block = (BlockRecord) Blockchain.XMLtoObject(xmlBlock, BlockRecord.class);
                bQueue.add(block);
                s.close();
            }catch(Exception ex){ System.out.println(ex); }
        }
    }
    //Responsible for pulling blocks from the priority blocking queue and attempting to verify in competition with the
    //other two processes
    class UBSolver extends Thread{
        BlockRecord unverified;
        BlockRecord verified;
        public void run(){
            try{
                while(true){
                    unverified = bQueue.take();
                    //check if block is already in blockchain
                    if(inBlockchain(unverified)) continue;
                    //check signed UUID
                    if(!Blockchain.verifyString(unverified.getBUUID(),unverified.getBSignedUUID(), unverified.getBPID())){
                        System.out.println("UUID verification failed.");
                        continue;
                    }
                    //check signed hash
                    String signedHash = unverified.getCSignedSHA256();
                    unverified.setCSignedSHA256(null);
                    String XMLcleanBlock = Blockchain.makeXML(unverified);
                    String hashedCleanBlock = Blockchain.makeSHA256hash(XMLcleanBlock);
                    if(!Blockchain.verifyString(hashedCleanBlock, signedHash, unverified.getBPID())){
                        System.out.println("Signed hash verification failed.");
                        continue;
                    }
                    //place signed hash back into block after checking
                    unverified.setCSignedSHA256(signedHash);

                    //retireve and incorporate the data necessary for the work step. That is, a random seed, the solution
                    //hash from the previous block and the block number
                    String seed = randomSeed(8);
                    String prevHash = BlockchainUpdateServer.getBL().getLedger().peekLast().SolutionHash;
                    int blockNum = Integer.parseInt(BlockchainUpdateServer.getBL().getLedger().peekLast().BlockNum)+1;

                    //assign the new values to the block
                    unverified.setAVID(Integer.toString(Blockchain.processNum));
                    unverified.setDSeed(seed);
                    unverified.setCPrevSHA256(prevHash);
                    unverified.setABlockNum(Integer.toString(blockNum));
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    String XMLsolutionBlock = Blockchain.makeXML(unverified);

                    int i = 0; //keeps track of loop iterations to coordinate checking the blockchain for updates
                    while(true){
                        //check if block has been verified yet
                        if(i == 4){
                            System.out.println("Time to check..");
                            if(inBlockchain(unverified)){
                                System.out.println("Giving up.");
                                break;
                            }
                            i=0;
                        }

                        //update block number and previous solution hash
                        unverified = (BlockRecord) Blockchain.XMLtoObject(XMLsolutionBlock, BlockRecord.class);
                        int newNum = Integer.parseInt(BlockchainUpdateServer.getBL().getLedger().peekLast().BlockNum)+1;
                        unverified.setABlockNum(Integer.toString(newNum));
                        unverified.setCPrevSHA256(BlockchainUpdateServer.getBL().getLedger().peekLast().getDSolutionHash());
                        XMLsolutionBlock = Blockchain.makeXML(unverified);

                        //Create hash and create unique workNum integer
                        String solutionHash = Blockchain.makeSHA256hash(XMLsolutionBlock);
                        byte[] bytesHash = md.digest(solutionHash.getBytes("UTF-8"));
                        String hexString = DatatypeConverter.printHexBinary(bytesHash);
                        int workNum = Integer.parseInt(hexString.substring(0,4),16);

                        //check if workNum is below a certain threshold. Currently set to 1/4th of max value.
                        if(workNum<(0xFFFF/4)){
                            //Wait an extra 2 seconds, and then add solution and a signed version to the block
                            //and pass it on for distribution
                            System.out.println("Block solved!");
                            Thread.sleep(2000);
                            verified = (BlockRecord) Blockchain.XMLtoObject(XMLsolutionBlock, BlockRecord.class);
                            verified.setDSolutionHash(solutionHash);
                            verified.setDSignedSolutionHash(Blockchain.signString(solutionHash));
                            distributeNewBlockchain(verified);
                            break;
                        }else {
                            //if not solved, assign a new seed value and contine to the next iteration of the loop
                            System.out.println("Not solved :(");
                            String oldSeed = seed;
                            seed = randomSeed(8);
                            XMLsolutionBlock = swapSeed(oldSeed, seed, XMLsolutionBlock);
                        }
                        i++;
                    }

                }
            }catch(Exception ex){ex.printStackTrace();}
        }

        //checks if a given block is in the blockchain by comparing UUIDs
        Boolean inBlockchain(BlockRecord block){
            boolean inLedger = false;
            for(BlockRecord b: BlockchainUpdateServer.getBL().getLedger()){
                if(Integer.parseInt(b.getABlockNum())!=0 && block.getBUUID().contains(b.getBUUID())){
                    inLedger = true;
                    break;
                }
            }
            return inLedger;
        }

        //generates a random seed using Math.random() to achieve randomness
        String randomSeed(int length){
            char[] cArr = new char[length];
            int random;
            for(int i=0; i<length; i++){
                random = (int)(Math.random()*25);
                cArr[i] = (char)(65+random);
            }
            return new String(cArr);
        }

        //Swaps seed directly in XML data by replacing the appropriate Seed line with a new one
        String swapSeed(String oldSeed, String newSeed, String XMLblock){
            String targetLine = "<DSeed>" + oldSeed + "</DSeed>";
            String newLine = "<DSeed>" + newSeed + "</DSeed>";
            String newBlock = XMLblock.replaceAll(targetLine,newLine);
            System.out.println("Swapped " + oldSeed + " for " + newSeed);
            return newBlock;
        }

        //Adds new verified block to the ledger and sends the ledger out to all other processes
        void distributeNewBlockchain(BlockRecord verifiedBlock){
            Socket s;
            PrintStream out;
            try {
                //One final check to make sure the block hasn't been verified by another process
                if(!inBlockchain(verifiedBlock)){
                    BlockLedger BL = BlockchainUpdateServer.getBL();
                    BL.Ledger.addLast(verifiedBlock);
                    for(int i=0; i<3; i++){
                        s = new Socket("localhost", 4930+i);
                        out = new PrintStream(s.getOutputStream());
                        out.print(Blockchain.makeXML(BL));
                        s.close();
                    }
                }
            }catch(Exception ex){ex.printStackTrace();}
        }
    }
}

//Listens for connections related to distribution of public keys
class PubKeyServer extends Thread{

    public void run(){
        int q_len = 6;
        Socket socket;
        try{
            System.out.println("Public Key Server listening at " + Ports.pubKeyPort);
            ServerSocket svSocket = new ServerSocket(Ports.pubKeyPort, q_len);
            while(true) {
                socket = svSocket.accept();
                new PubKeyWorker(socket).start();
            }
        }catch(IOException iox) {
            System.out.println(iox);
        }
    }
}

//Handles new public key multicast connections
class PubKeyWorker extends Thread{
    Socket s;
    PubKeyWorker(Socket socket){
        s = socket;
    }
    public void run(){
        try{
            //read process id and public key object from input stream
            ObjectInputStream in = new ObjectInputStream(s.getInputStream());
            int id = in.readInt();
            if(Keys.pubKeys[id]==null){
                Keys.pubKeys[id] = (PublicKey) in.readObject();
            }

            //send keys if ours is not in pubKeys array yet
            if(Keys.pubKeys[Blockchain.processNum]==null){
                Blockchain.sendKey();
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }
    }
}

//Allows for convenient XML marshalling of a group of BlockRecord objects. The objects are stored in a double-ended queue
@XmlRootElement
class BlockLedger{
    public Deque<BlockRecord> Ledger;

    BlockLedger(){
        Ledger = new ArrayDeque<>();
        BlockRecord firstBlock = new BlockRecord();
        firstBlock.setABlockNum("0");
        firstBlock.setBUUID(UUID.randomUUID().toString());
        String hash = Blockchain.makeSHA256hash(Blockchain.makeXML(firstBlock));
        firstBlock.setDSolutionHash(hash);
        Ledger.add(firstBlock);
    }
    public Deque<BlockRecord> getLedger(){
        return Ledger;
    }
    @XmlElement
    public void setLedger(Deque<BlockRecord> ledger){
        Ledger = ledger;
    }
}

//The BlockRecord class that represents each element of our blockchain. Implements Comperable interface to allow
//for prioritizing blocks by age in priority queue
@XmlRootElement
class BlockRecord implements Comparable<BlockRecord> {
    String BlockNum;
    String TimeStamp;
    String vID;
    String pID;
    String UUID;
    String SignedUUID;
    String PrevSHA256;
    String SignedSHA256;
    String Seed;
    String SignedSolutionHash;
    String SolutionHash;
    String First;
    String Last;
    String DOB;
    String SS;
    String Condition;
    String Treatment;
    String Rx;

    public String getABlockNum(){return BlockNum;}
    @XmlElement
    public void setABlockNum(String blockNum){BlockNum=blockNum;}

    public String getATimeStamp(){return TimeStamp;}
    @XmlElement
    public void setATimeStamp(String timeStamp){TimeStamp=timeStamp;}

    public String getAVID(){return vID;}
    @XmlElement
    public void setAVID(String vid){vID=vid;}

    public String getBPID(){return pID;}
    @XmlElement
    public void setBPID(String pid){pID=pid;}

    public String getBUUID(){return UUID;}
    @XmlAttribute
    public void setBUUID(String uuid){UUID=uuid;}

    public String getBSignedUUID(){return SignedUUID;}
    @XmlElement
    public void setBSignedUUID(String signeduuid){ SignedUUID =signeduuid;}

    public String getCPrevSHA256(){return PrevSHA256;}
    @XmlElement
    public void setCPrevSHA256(String prevsha256){PrevSHA256 =prevsha256;}

    public String getCSignedSHA256(){return SignedSHA256;}
    @XmlElement
    public void setCSignedSHA256(String sha256){SignedSHA256 =sha256;}

    public String getDSeed(){return Seed;}
    @XmlElement
    public void setDSeed(String seed){Seed=seed;}

    public String getDSignedSolutionHash(){return SignedSolutionHash;}
    @XmlElement
    public void setDSignedSolutionHash(String signedSolutionHash){SignedSolutionHash=signedSolutionHash;}

    public String getDSolutionHash(){return SolutionHash;}
    @XmlElement
    public void setDSolutionHash(String solutionHash){SolutionHash=solutionHash;}

    public String getEFirst(){return First;}
    @XmlElement
    public void setEFirst(String first){First=first;}

    public String getELast(){return Last;}
    @XmlElement
    public void setELast(String last){Last=last;}

    public String getFDOB(){return DOB;}
    @XmlElement
    public void setFDOB(String dob){DOB=dob;}

    public String getFSS(){return SS;}
    @XmlElement
    public void setFSS(String ss){SS=ss;}

    public String getGCondition(){return Condition;}
    @XmlElement
    public void setGCondition(String condition){Condition=condition;}

    public String getGTreatment(){return Treatment;}
    @XmlElement
    public void setGTreatment(String treatment){Treatment=treatment;}

    public String getHRx(){return Rx;}
    @XmlElement
    public void setHRx(String rx){Rx=rx;}

    public int compareTo(BlockRecord br){
        long t1 =  Long.parseLong(br.getATimeStamp());
        long t2 = Long.parseLong(this.getATimeStamp());
        return (int)(t2 - t1);
    }
}


public class Blockchain {
    public static int processNum;

    //reads records from file and creates a block record object for each line of data
    //the block is then passed to the sendUnverifiedBlock function for marshalling and multicasting
    static void readFile(String fileName){
        File file = new File("./" + fileName);
        try{
            Scanner sc = new Scanner(file);
            while(sc.hasNextLine()){
                BlockRecord block = new BlockRecord();
                Date date = new Date();
                String ln = sc.nextLine();
                String[] entries = ln.split("\\s+");
                String uuid = UUID.randomUUID().toString();

                //fill block record with appropriate entries
                block.setATimeStamp(String.format(Long.toString(date.getTime())));
                block.setBPID(Integer.toString(processNum));
                block.setBUUID(uuid);
                block.setBSignedUUID(signString(uuid));
                block.setEFirst(entries[0]);
                block.setELast(entries[1]);
                block.setFDOB(entries[2]);
                block.setFSS(entries[3]);
                block.setGCondition(entries[4]);
                block.setGTreatment(entries[5]);
                block.setHRx(entries[6]);
                sendUnverifiedBlock(block);
            }
        }catch(Exception ex){ex.printStackTrace();}
    }

    //signs and marshals the new block and the multicasts it to all processes for verification
    static void sendUnverifiedBlock(BlockRecord block){
        //Get a signed hash string of block data and add to block
        String xmlString = makeXML(block);
        String hashString = makeSHA256hash(xmlString);
        String signedHash = signString(hashString);
        block.setCSignedSHA256(signedHash);

        //Send block to unverified block sockets of all 3 processes
        for(int i=0; i<3; i++){
            try{
                Socket s = new Socket("localhost", 4820+i);
                PrintStream out = new PrintStream(s.getOutputStream());
                out.print(makeXML(block));
                s.close();
            }catch(IOException iox){
                System.out.println(iox);
            }
        }
    }

    //Use an object output stream to marshal public keys to the public key server for each process
    static void sendKey(){
        for(int i=0; i<3; i++){
            try{
                System.out.println("Connecting to " + 471 + i);
                Socket s = new Socket("localhost", 4710+i);
                ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
                oos.writeInt(processNum);
                oos.writeObject(Keys.publicKey);
                oos.flush();
            }catch (IOException iox){
                System.out.println(iox);
            }
        }
    }

    //creates a SHA-256 hash from a string
    static String makeSHA256hash(String data){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data.getBytes());
            byte bytes[] = md.digest();

            StringBuffer sBuffer = new StringBuffer();
            for(int i=0; i<bytes.length; i++){
                sBuffer.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            return sBuffer.toString();
        }catch(Exception ex){ ex.printStackTrace(); }
        return null;
    }

    //signs a string with the private key of this process
    static String signString(String data){
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(Keys.privateKey);
            sig.update(data.getBytes());
            return Base64.getEncoder().encodeToString(sig.sign());
        }catch(Exception ex){ex.printStackTrace();}
        return null;
    }

    //verifies signature using original data and process number of the signer. The process number
    //is used to retrieve the
    static boolean verifyString(String data, String signature, String pID){
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(Keys.pubKeys[Integer.parseInt(pID)]);
            sig.update(data.getBytes());
            return sig.verify(Base64.getDecoder().decode(signature));
        }catch(Exception ex){ex.printStackTrace();}
        return false;
    }

    //Converts any object to xml string
    static String makeXML(Object obj){
        //Convert block object to xml string
        try{
            JAXBContext jaxbContext = JAXBContext.newInstance(obj.getClass());
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            StringWriter sw = new StringWriter();
            jaxbMarshaller.marshal(obj, sw);

            return sw.toString();
        }catch(Exception ex){ex.printStackTrace();}
        return null;
    }

    //Converts objects into XML data based on the class of the object
    static Object XMLtoObject(String XMLtext, Class objectClass) {
        Object obj = null;
        try{
            JAXBContext jxc = JAXBContext.newInstance(objectClass);
            Unmarshaller um = jxc.createUnmarshaller();
            StringReader sReader = new StringReader(XMLtext);
            obj = um.unmarshal(sReader);
        }catch(Exception ex){ex.printStackTrace();}
        return obj;
    }

    public static void main(String[] args) {
        //set process number and filename based on given argument
        String filename = "BlockInput0.txt";
        if(args.length < 1) processNum = 0;
        else if(args[0].equals("0")) processNum = 0;
        else if(args[0].equals("1")) {
            processNum = 1;
            filename = "BlockInput1.txt";
        }
        else if(args[0].equals("2")) {
            processNum = 2;
            filename = "BlockInput2.txt";
        }
        else processNum = 0;

        //Initialize Ports and Keys objects
        new Ports(processNum);
        new Keys(System.currentTimeMillis());

        //Start servers
        new PubKeyServer().start();
        new UnverifiedBlockServer().start();
        new BlockchainUpdateServer().start();

        //Initialize the ledger (starts with one dummy block)
        new BlockLedger();

        //Wait to ensure all servers are running
        try{Thread.sleep(1000);}catch(Exception e){e.printStackTrace();}

        //Let process 2 initialize sharing of keys
        if(processNum == 2){
            sendKey();
        }
        //needed to allow for public keys to finish being shared
        try{Thread.sleep(1000);}catch(Exception e){e.printStackTrace();}

        //read file associated with this process and send out the resulting blocks
        readFile(filename);
    }

}

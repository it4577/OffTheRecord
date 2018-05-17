// Check code here : https://play.golang.org/
package main

import (
	// General libraries
	"fmt"
	"io"
	strc "strconv"
	"sync"
	// Cryptography libraries
	"crypto"
	caes "crypto/aes"
	ccpr "crypto/cipher"
	cmac "crypto/hmac"
	crnd "crypto/rand"
	crsa "crypto/rsa"
	csha "crypto/sha256"
	// Math libraries
	mbig "math/big"
)

var DEBUG bool

var ZERO = mbig.NewInt(0)
var ONE  = mbig.NewInt(1)
var TWO  = mbig.NewInt(2)

var wg sync.WaitGroup

// Participant
type Participant struct {
	// Identity Information
	uuid int        // Unique User ID
	name string     // User Name
	msgs []string   // Messages
	indx int        // Message Index
	// Diffie-Hellman Information
	dhModPrm int    // Prime or Modulus (P)
	dhBaseRt int    // Base or Primitive Root (G)
	dhSecExp int    // Secret Exponential (a, b)
	dhPubLoc int    // Locally Generated Public Key (x, y)
	dhPubRem int    // Remotely Generated Public Key (x, y)
	dhShdKey int    // Computed Shared DH Key
	dhEncHsh []byte // Computed Hash of Shared DH Key (EK)
	dhMacHsh []byte // Computed Hash of Shared DH Hash (MK)
	// RSA Encryption Information
	pkiPubKey *crsa.PublicKey  // Local Public Key
	pkiPrvKey *crsa.PrivateKey // Local Private Key
	pkiRemKey *crsa.PublicKey  // Remote Public Key
	// Communcication Channels
	chI chan int
	chB chan []byte
	chS chan string
	chK chan *crsa.PublicKey
}

// Constructor for Participant Struct
// Reference: https://stackoverflow.com/questions/18125625/constructors-in-go
func NewParticipant(uuid int, name string, msgs []string) *Participant {
	if DEBUG { fmt.Println("\n#### Creating participant", name, "and initializing:") }
	p := new(Participant)
	p.uuid = uuid
	p.name = name
	p.msgs = msgs
	p.indx = 0
	p.genRSAKeys()
	if p.uuid == 1 { p.genDHPubKeys() }
	p.chI = make(chan int)
	p.chB = make(chan []byte)
	p.chS = make(chan string)
	p.chK = make(chan *crsa.PublicKey)
	return p
}

func (p *Participant) getChannels() (chan int, chan []byte, chan string, chan *crsa.PublicKey) {
	return p.chI, p.chB, p.chS, p.chK
}

// Reference: https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/
func (p *Participant) genDHPubKeys() {
	p.dhModPrm = getPrime()
	p.dhBaseRt = getPrimitiveRoot(p.dhModPrm)
	if DEBUG { fmt.Println(p.name, "\t> Generating 32-bit prime: ", p.dhModPrm) }
}

// Reference: https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/
func (p *Participant) genDHPrvKeys() {
	//var secExp *mbig.Int
	var pubLoc mbig.Int
	tmp := mbig.NewInt(int64(p.dhModPrm))
	if tmp.Cmp(ZERO) <= 0 {
		if DEBUG { fmt.Println(p.name, "\t> [ERROR] - Error from generating private and shared DH values") }
		return
	}	
	secExp, _ := crnd.Int(crnd.Reader, tmp) // Panics and does not return error
	pubLoc.Exp(mbig.NewInt(int64(p.dhBaseRt)), secExp, mbig.NewInt(int64(p.dhModPrm)))
	p.dhSecExp = int(secExp.Int64())
	p.dhPubLoc = int(pubLoc.Int64())
}

// Reference: https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/
func (p *Participant) genDHShdKey() {
	var shdKey mbig.Int
	shdKey.Exp(mbig.NewInt(int64(p.dhPubRem)), mbig.NewInt(int64(p.dhSecExp)), mbig.NewInt(int64(p.dhModPrm)))
	p.dhShdKey = int(shdKey.Int64())
	p.dhEncHsh = p.genHash(p.dhShdKey)
	p.dhMacHsh = p.genHashByte(p.dhEncHsh)
}

// Reference: https://golang.org/pkg/crypto/rsa/
func (p *Participant) genRSAKeys() {
	p.pkiPrvKey, _ = crsa.GenerateKey(crnd.Reader, 2048)
	p.pkiPubKey = &p.pkiPrvKey.PublicKey
	if DEBUG { fmt.Println(p.name, "\t> Generating 2048-bit private and public keys") }
}

// Reference: https://golang.org/pkg/crypto/hmac/
func (p *Participant) genMAC(msg []byte) []byte {
	mac := cmac.New(csha.New, p.dhMacHsh)
	mac.Write(msg)
	genMAC := mac.Sum(nil)
	return genMAC
}

// Reference: https://golang.org/pkg/crypto/hmac/
func (p *Participant) chkMAC(msg []byte, rcvMAC []byte) bool {
	mac := cmac.New(csha.New, p.dhMacHsh)
	mac.Write(msg)
	genMAC := mac.Sum(nil)
	return cmac.Equal(rcvMAC, genMAC)
}

// Reference: https://golang.org/pkg/crypto/sha256/
func (p *Participant) genHash(data int) []byte {
	hash := csha.Sum256([]byte(strc.Itoa(data)))
	return hash[:]
}

// Reference: https://golang.org/pkg/crypto/sha256/
func (p *Participant) genHashByte(data []byte) []byte {
	hash := csha.Sum256(data)
	return hash[:]
}

// Reference: https://golang.org/pkg/crypto/rsa
func (p *Participant) genSign(hash []byte) []byte {
	sign, err := crsa.SignPKCS1v15(crnd.Reader, p.pkiPrvKey, crypto.SHA256, hash[:])
	if err != nil {
		if DEBUG { fmt.Println(p.name, "\t> [ERROR] -  Error from signing:", err) }
		return nil
	}
	return sign
}

// Reference: https://golang.org/pkg/crypto/rsa
func (p *Participant) chkSign(hash []byte, sign []byte) bool {
	err := crsa.VerifyPKCS1v15(p.pkiRemKey, crypto.SHA256, hash[:], sign)
	if err != nil {
		if DEBUG { fmt.Println(p.name, "\t> [ERROR] - Error from verification:", err) }
		return false
	}
	return true
}

// Reference: http://guzalexander.com/2013/12/06/golang-channels-tutorial.html
// Reference: https://blog.golang.org/pipelines
func (p *Participant) msgSend(msg string, cS chan<- string, cB chan<- []byte) {
	pMsg := p.msgs[p.indx]
	if DEBUG { fmt.Println(p.name, "\t> Encrypting message") }
	cMsg := msgEncrypt(p.dhEncHsh, []byte(pMsg))
	hmac := p.genMAC(cMsg)
	fmt.Println(p.name, "\t> Sending message :", pMsg)
	cS <-string(cMsg)
	cB <-hmac
}

// Reference: http://guzalexander.com/2013/12/06/golang-channels-tutorial.html
// Reference: https://blog.golang.org/pipelines
func (p *Participant) msgRecv() {
	cMsg := []byte(<-p.chS)
	if (p.chkMAC(cMsg, <-p.chB)) {
		if DEBUG { fmt.Println(p.name, "\t> Received message with valid HMAC") }
		pMsg := string(msgDecrypt(p.dhEncHsh, cMsg))
		fmt.Println(p.name, "\t> Received message:", pMsg)
	} else {
		if DEBUG { fmt.Println(p.name, "\t> Received message with INVALID HMAC, unable to decrypt") }
		pMsg := string(msgDecrypt(p.dhEncHsh, cMsg))
		fmt.Println(p.name, "\t> Received message:", pMsg)
	}
}

// Reference: https://golang.org/pkg/crypto/rsa
func (p *Participant) pkiEncrypt(data int) []byte {
	ctxt, _ := crsa.EncryptPKCS1v15(crnd.Reader, p.pkiRemKey, []byte(strc.Itoa(data)))
	return ctxt
}

// Reference: https://golang.org/pkg/crypto/rsa
func (p *Participant) pkiDecrypt(data []byte) int {
	ptmp, _ := crsa.DecryptPKCS1v15(crnd.Reader, p.pkiPrvKey, data)
	ptxt, _ := strc.Atoi(string(ptmp))
	return ptxt
}

// Reference: https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
func msgEncrypt(key []byte, data []byte) []byte {
	block, err := caes.NewCipher(key)
	if err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from encryption (1):", err) }
		return nil
	}
	aesgcm, err := ccpr.NewGCM(block)
	if err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from encryption (2):", err) }
		return nil
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(crnd.Reader, nonce); err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from encryption (3):", err) }
		return nil
	}
	ctext := aesgcm.Seal(nonce, nonce, data, nil)
	return ctext
}

// Reference: https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
func msgDecrypt(key []byte, data []byte) []byte {
	block, err := caes.NewCipher(key)
	if err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from decryption (1):", err) }
		return nil
	}
	aesgcm, err := ccpr.NewGCM(block)
	if err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from decryption (2):", err) }
		return nil
	}
	nonceSize := aesgcm.NonceSize()
	if len(data) <= nonceSize {
		if DEBUG { fmt.Println("\t[ERROR] - Error from decryption (3): Missing or malformed nonce") }
		return nil
	}
	nonce, ctext := data[:nonceSize], data[nonceSize:]
	ptext, err := aesgcm.Open(nil, nonce, ctext, nil)
	if err != nil {
		if DEBUG { fmt.Println("\t[ERROR] - Error from decryption (4):", err) }
		return nil
	}
	return ptext
}

//***************************************************************************//

// Reference: https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
func getPrime() (prime int) {
	var prm *mbig.Int
	var err error
	for {
		prm, err = crnd.Prime(crnd.Reader, 32) // 64 takes too long
		if err == nil {
			break
		}
	}
	prime, _ = strc.Atoi(prm.String())
	return
}

// Reference: https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
func getPrimitiveRoot(prm int) int {
	var phi int
	var tmp int
	var chk mbig.Int
	var factors []*mbig.Int
	var flag bool

	phi = prm - 1
	factors = getPrimeFactors(mbig.NewInt(int64(phi)))
	for i := 2; i < phi; i++ {
		flag = false
		for _, f := range factors {
			tmp = int(f.Int64())
			chk.Exp(mbig.NewInt(int64(i)), mbig.NewInt(int64(phi/tmp)), mbig.NewInt(int64(prm)))
			if chk.Cmp(ONE) == 0 {
				flag = true
				break
			}
		}
		if flag == false {
			return i
		}
	}
	return -1
}

// Reference: https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
func getPrimeFactors(prm *mbig.Int) (factors []*mbig.Int) {
	d, m := new(mbig.Int), new(mbig.Int)
	for i := TWO; i.Cmp(prm) != 1; i.Add(i, ONE) {
		d.DivMod(prm, i, m)
		for m.Cmp(ZERO) == 0 {
			factors = append(factors, new(mbig.Int).Set(i))
			prm.Set(d)
			d.DivMod(prm, i, m)
		}
	}
	return
}

func initKeyExchange(sndr *Participant, rcvr *Participant) {
	// Assign channel from participants
	iSnd, bSnd, _, kSnd := sndr.getChannels()
	iRcv, bRcv, _, kRcv := rcvr.getChannels()

	// Send PKI key information
	if DEBUG { fmt.Println("\n[KeyExchange]\tSending PKI keys") }
	go func() {
		kSnd <-rcvr.pkiPubKey
		kRcv <-sndr.pkiPubKey
	}()
	
	// Recieve and store key material information
	if DEBUG { fmt.Println("[KeyExchange]\tRecieving PKI keys") }
	sndr.pkiRemKey = <-kSnd
	rcvr.pkiRemKey = <-kRcv

	// Send DH key material information
	if DEBUG { fmt.Println("[KeyExchange]\tSending DH key material") }
	go func() {
		bRcv <-sndr.pkiEncrypt(sndr.dhModPrm)
		bRcv <-sndr.pkiEncrypt(sndr.dhBaseRt)
	}()
	
	// Recieve and store key material information
	if DEBUG { fmt.Println("[KeyExchange]\tRecieving DH key material") }
	rcvr.dhModPrm = rcvr.pkiDecrypt(<-bRcv)
	rcvr.dhBaseRt = rcvr.pkiDecrypt(<-bRcv)

	// Generate secret and public key values
	if DEBUG { fmt.Println("[KeyExchange]\tParticipants generating private and shared DH values") }
	sndr.genDHPrvKeys()
	rcvr.genDHPrvKeys()

	// Send Diffie-Hellman initiation information
	if DEBUG { fmt.Println("[KeyExchange]\tSending DH initiation information") }
	go func() {
		iRcv <-sndr.dhPubLoc
		bRcv <-sndr.genSign(sndr.genHash(sndr.dhPubLoc))
		iSnd <-rcvr.dhPubLoc
		bSnd <-rcvr.genSign(rcvr.genHash(rcvr.dhPubLoc))
	}()

	// Recieve and store Diffie-Hellman initiation information
	if DEBUG { fmt.Println("[KeyExchange]\tRecieving DH initiation information") }
	rcvr.dhPubRem  = <-iRcv
	rRcvSign      := <-bRcv
	sndr.dhPubRem  = <-iSnd
	sRcvSign      := <-bSnd
	// Validate recieved information and generate new keys
	rVal := rcvr.chkSign(rcvr.genHash(rcvr.dhPubRem), rRcvSign)	
	if rVal {
		if DEBUG { fmt.Println(rcvr.name, "\t> Received and validated DH information from", sndr.name) }
		if DEBUG { fmt.Println(rcvr.name, "\t> Generating shared DH key") }
		rcvr.genDHShdKey()
	} else {
		if DEBUG { fmt.Println(rcvr.name, "\t> Received but FAILED to validate signature of DH information from", sndr.name) }
	}		
	sVal := sndr.chkSign(sndr.genHash(sndr.dhPubRem), sRcvSign)
	if sVal {
		if DEBUG { fmt.Println(sndr.name, "\t> Received and validated DH information from", rcvr.name) }
		if DEBUG { fmt.Println(sndr.name, "\t> Generating shared DH key") }
		sndr.genDHShdKey()
	} else {
		if DEBUG { fmt.Println(sndr.name, "\t> Received but FAILED to validate signature of DH information from", rcvr.name) }
	}
}

func msgSendRecv(ps []*Participant, sndr int) {
	defer wg.Done()
	fmt.Println("\n####", ps[sndr].name, " > Sending message #", (ps[sndr].indx + 1))
	for p, _ := range ps {
		if ps[p].uuid != (sndr + 1) {
				if DEBUG { fmt.Println("---- Getting channels for", ps[p].name) }
			_, cB, cS, _ := ps[p].getChannels()
			go ps[sndr].msgSend(ps[sndr].msgs[ps[sndr].indx], cS, cB)
			ps[p].msgRecv()
		}
	}
	ps[sndr].indx++
}

func initDHRekey(sndr *Participant, rcvr *Participant) {
	defer wg.Done()

	// Assign channel from participants
	sI, sB, _, _ := sndr.getChannels()
	rI, rB, _, _ := rcvr.getChannels()

	fmt.Println("\n#### Message exchange complete. Initiating participant rekey")

	// Generate secret and public key values
	if DEBUG { fmt.Println("[ReKey]\tParticipants generating private and shared DH values") }
	sndr.genDHPrvKeys()
	rcvr.genDHPrvKeys()

	// Send Diffie-Hellman initiation information
	if DEBUG { fmt.Println("[ReKey]\tSending DH initiation information") }
	go func() {
		rI <-sndr.dhPubLoc
		rB <-sndr.genMAC([]byte(string(sndr.dhPubLoc)))
		sI <-rcvr.dhPubLoc
		sB <-rcvr.genMAC([]byte(string(rcvr.dhPubLoc)))
	}()

	// Recieve and store Diffie-Hellman initiation information
	if DEBUG { fmt.Println("[ReKey]\tRecieving DH initiation information") }
	rcvr.dhPubRem = <-rI
	rRcvMac      := <-rB
	sndr.dhPubRem = <-sI
	sRcvMac      := <-sB
	// Validate recieved information and generate new keys
	if rcvr.chkMAC([]byte(string(rcvr.dhPubRem)), rRcvMac) {
		if DEBUG { fmt.Println(rcvr.name, "\t> Received and validated DH information from", sndr.name) }
		if DEBUG { fmt.Println(rcvr.name, "\t> Generating shared DH key") }
		rcvr.genDHShdKey()
	} else {
		if DEBUG { fmt.Println(rcvr.name, "\t> Received but FAILED to validate MAC of DH information from", sndr.name) }
	}	
	if sndr.chkMAC([]byte(string(sndr.dhPubRem)), sRcvMac) {
		if DEBUG { fmt.Println(sndr.name, "\t> Received and validated DH information from", rcvr.name) }
		if DEBUG { fmt.Println(sndr.name, "\t> Generating shared DH key") }
		sndr.genDHShdKey()
	} else {
		if DEBUG { fmt.Println(sndr.name, "\t> Received but FAILED to validate MAC of DH information from", rcvr.name) }
	}
}

func main() {
	// Set debug variable for printing more information about application activities
	DEBUG = false

	// Create messages
	aMsgs := []string{"Lights on", "Forward drift?", "413 is in", "The Eagle has landed"}
	bMsgs := []string{"30 seconds", "Yes", "Houston, Tranquility base here", "A small step for a student, a giant leap for the group"}

	// Create participants
	alice := *NewParticipant(1, "Alice", aMsgs)
	bob   := *NewParticipant(2, "Bob",   bMsgs)
	
	// Initiate PKI and DH key exchange
	initKeyExchange(&alice, &bob)
	
	// Group the participants (Must be after Key Exchange)
	Participants := []*Participant { &alice, &bob }

	// Add intruder to communications (Optional)
	eMsgs := []string{"Malware", "Replay", "Hacked", "Impersonation"}
	eve   := *NewParticipant(3, "Eve",   eMsgs)
	Participants = append(Participants, &eve)
	//*/

	// Determine the number of messages to send
	var cnt int
	for _, p := range Participants {
		cnt += len(p.msgs)
	}
	
	// Send messages and rekey after each
	for i := 0; i < cnt; i++ {
		wg.Add(1)
		go msgSendRecv(Participants, i%len(Participants))
		wg.Wait()
		wg.Add(1)
		go initDHRekey(Participants[0], Participants[1])
		wg.Wait()
	}
}

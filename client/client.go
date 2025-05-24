package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

type File struct {
	FileKey      []byte // 32 bytes
	Location     uuid.UUID
	LocationOrig []byte
	Invitations  map[string]*Invitation
	InviteLocs   map[string]uuid.UUID
	InvDiagram   map[string][]string
	Owner        string
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
	Password          string
	PasswordKey       []byte
	PrivateFileKey    userlib.PKEDecKey
	PrivateSigningKey userlib.DSSignKey
	FileInfo          map[string]*File // https://go.dev/blog/maps
	Salt              []byte
}

type UserWithSalt struct {
	Userinfo []byte
	Salt     []byte
	MAC      []byte
}

type Invitation struct {
	FileKey        []byte
	Location       uuid.UUID
	SenderUsername string
}

// Source: https://stackoverflow.com/questions/68166558/generic-structs-with-go
type ObjectWithSignature[T any] struct {
	Object    T
	Signature []byte
}

type Data[T any] struct {
	// For "securing" data in a struct for marshalling
	Data T
}

type HybridEncData struct {
	SymKey         []byte
	ObjectLocation uuid.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func UsernameToUUID(username string) (content uuid.UUID, err error) {
	// Converts a username to a hashed UUID.
	marshalled, err := json.Marshal(username)
	out, _ := uuid.FromBytes(userlib.Hash(marshalled)[:16])
	return out, err
}

func EncryptUser(userPtr *User, location uuid.UUID) (err error) {
	// Encrypts the User in userPtr and sends it to Datastore.
	passwordKeyTotal := userlib.Argon2Key([]byte((*userPtr).Password), (*userPtr).Salt, 32)
	passwordKey := passwordKeyTotal[:16]
	passwordMACKey := passwordKeyTotal[16:]
	marshalledUser, err := json.Marshal(*userPtr)
	if err != nil {
		return err
	}
	encUser := userlib.SymEnc(passwordKey, userlib.RandomBytes(16), marshalledUser)
	MAC, err := userlib.HMACEval(passwordMACKey, encUser)
	if err != nil {
		return err
	}
	withSalt := UserWithSalt{encUser, (*userPtr).Salt, MAC}
	sentStruct, err := json.Marshal(withSalt)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(location, sentStruct)
	return nil
}

func (userPtr *User) EncryptUser() (err error) {
	location, err := UsernameToUUID((*userPtr).Username)
	if err != nil {
		return err
	}
	return EncryptUser(userPtr, location)
}

func ReceiveSymObject[T any](Key []byte, location uuid.UUID) (obj *T, err error) {
	rawBytes, ok := userlib.DatastoreGet(location)
	if !ok {
		return nil, errors.New("file location not found")
	}
	if len(Key) != 32 {
		return nil, errors.New("invalid invite symkey length")
	}
	var fileWithMAC ObjectWithSignature[[]byte]
	err = json.Unmarshal(rawBytes, &fileWithMAC)
	// userlib.DebugMsg("File with MAC: %v", fileWithMAC)
	if err != nil {
		return nil, err
	}
	MAC, err := userlib.HMACEval(Key[16:], fileWithMAC.Object) // checking validity of FileKey
	if err != nil {
		return nil, err
	}
	ok = userlib.HMACEqual(fileWithMAC.Signature, MAC)
	if !ok {
		return nil, errors.New("bad signature")
	}
	fileBytes := userlib.SymDec(Key[:16], fileWithMAC.Object)
	// userlib.DebugMsg("File: %v", fileBytes)
	var data Data[T]
	err = json.Unmarshal(fileBytes, &data)
	// userlib.DebugMsg("Data: %v", data.Data)
	if err != nil {
		return nil, err
	}
	return &data.Data, nil
}

func SendSymObject[T any](Key []byte, location uuid.UUID, obj *T) (err error) {
	iv := userlib.RandomBytes(16)

	data := Data[T]{*obj}
	byteObj, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if len(Key) != 32 {
		return errors.New("invalid invite symkey length")
	}
	// userlib.DebugMsg("Initial byte string: %v", byteObj)
	encObj := userlib.SymEnc(Key[:16], iv, byteObj)
	// userlib.DebugMsg("Encoded byte string: %v", encObj)
	// first 16 bytes always used for encoding, last 16 used for MAC
	// ALWAYS ENCRYPT-THEN-MAC
	MAC, err := userlib.HMACEval(Key[16:], encObj)
	if err != nil {
		return err
	}
	out := ObjectWithSignature[[]byte]{encObj, MAC}
	marshalledOut, err := json.Marshal(out)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(location, marshalledOut)
	return nil
}

func ReceiveAsymObjectSignOptional[T any](privateFileKey userlib.PKEDecKey, location uuid.UUID, publicSignKey userlib.DSVerifyKey, checkSign bool) (obj *T, err error) {

	data, ok := userlib.DatastoreGet(location)
	if !ok {
		return nil, errors.New("object not found at pointer")
	}
	var invWithMAC ObjectWithSignature[[]byte]
	err = json.Unmarshal(data, &invWithMAC)
	if err != nil {
		return nil, err
	}
	if checkSign {
		err = userlib.DSVerify(publicSignKey, invWithMAC.Object, invWithMAC.Signature)
		if err != nil {
			return nil, err
		}
	}
	// Hybrid encryption
	SymEncDataMarshal, err := userlib.PKEDec(privateFileKey, invWithMAC.Object)
	if err != nil {
		return nil, err
	}
	var SymEncObj HybridEncData
	err = json.Unmarshal(SymEncDataMarshal, &SymEncObj)
	if err != nil {
		return nil, err
	}
	dataObj, err := ReceiveSymObject[Data[T]](SymEncObj.SymKey, SymEncObj.ObjectLocation)
	if err != nil {
		return nil, err
	}
	return &dataObj.Data, nil
}

func ReceiveAsymObject[T any](privateFileKey userlib.PKEDecKey, location uuid.UUID, publicSignKey userlib.DSVerifyKey) (obj *T, err error) {

	return ReceiveAsymObjectSignOptional[T](privateFileKey, location, publicSignKey, true)
}

func SendAsymObject[T any](publicFileKey userlib.PKEEncKey, location uuid.UUID, privateSignKey userlib.DSSignKey, obj *T) (err error) {

	// Hybrid encryption
	newSymKey := userlib.RandomBytes(32)
	randLoc, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	sentData := Data[T]{*obj}
	SendSymObject[Data[T]](newSymKey, randLoc, &sentData)

	data := HybridEncData{newSymKey, randLoc}
	marshalInv, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("Bytes sent via RSA: %v", len(marshalInv))
	// 113 for HybridEncData
	encObj, err := userlib.PKEEnc(publicFileKey, marshalInv)
	if err != nil {
		return err
	}
	Signature, err := userlib.DSSign(privateSignKey, encObj)
	if err != nil {
		return err
	}
	out := ObjectWithSignature[[]byte]{encObj, Signature}
	marshalOut, err := json.Marshal(out)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(location, marshalOut)
	return nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	new_UUID, err := UsernameToUUID(username)
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(new_UUID)
	if username == "" || ok {
		return nil, errors.New("blank or already existing username")
	}
	public_file_key, private_file_key, _ := userlib.PKEKeyGen()
	private_sign_key, public_sign_key, _ := userlib.DSKeyGen()
	salt := userlib.RandomBytes(16)
	// userlib.DebugMsg("Generated Salt: %v", salt)
	passwordKeyTotal := userlib.Argon2Key([]byte(password), salt, 32)
	// userlib.DebugMsg("Password: %v", passwordKeyTotal)
	passwordKey := passwordKeyTotal[:16]
	// https://gobyexample.com/maps
	fileMap := make(map[string]*File)
	newUserPtr := &User{username, password, passwordKey, private_file_key, private_sign_key, fileMap, salt}
	err = EncryptUser(newUserPtr, new_UUID)
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet("Public File Key for "+username, public_file_key)
	userlib.KeystoreSet("Public Signing Key for "+username, public_sign_key)
	return newUserPtr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	newUUID, err := UsernameToUUID(username)
	if err != nil {
		return nil, err
	}
	userData, ok := userlib.DatastoreGet(newUUID)
	if !ok {
		return nil, errors.New("did not get user data")
	}
	encUser := UserWithSalt{}
	err = json.Unmarshal(userData, &encUser)
	if err != nil || len(encUser.Userinfo) < 16 { // check if less than one cipher block
		return nil, errors.New("invalid data in datastore (may be tampering)")
	}
	// userlib.DebugMsg("Salt: %v", encUser.Salt)
	passwordKeyTotal := userlib.Argon2Key([]byte(password), encUser.Salt, 32)
	// userlib.DebugMsg("Password: %v", passwordKeyTotal)
	testMAC, err := userlib.HMACEval(passwordKeyTotal[16:], encUser.Userinfo)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(testMAC, encUser.MAC) { // check HMAC
		return nil, errors.New("invalid MAC (may be tampering or wrong password)")
	}
	user := User{}
	err = json.Unmarshal(userlib.SymDec(passwordKeyTotal[:16], encUser.Userinfo), &user)
	if err != nil {
		return nil, err
	}
	if username != user.Username || password != user.Password {
		return nil, errors.New("invalid username or password (something weird happened here)")
	}
	return &user, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	/**
	Structure of a File
	UUID: File object, containing relevant metadata
	UUID+1: LastLocAddress, or the address of the last append to the file.
	This is the only item that needs to change when appending!
	UUID+2...UUID+n: the file contents, split into however many times append has happened
	*/
	tmpPtr, err := GetUser((*userdata).Username, (*userdata).Password)
	if err != nil {
		return err
	}
	*userdata = *tmpPtr
	file, ok := userdata.FileInfo[filename]
	if ok { // file exists
		byteUUID := file.LocationOrig
		newContentLocation := AddOneToByteArr(AddOneToByteArr(byteUUID))
		UUIDplusone, err := uuid.FromBytes(AddOneToByteArr(byteUUID))
		if err != nil {
			return err
		}
		newContentUUID, err := uuid.FromBytes(newContentLocation)
		if err != nil {
			return err
		}
		// delete all other entries
		_, err = userdata.LoadAndDeleteFile(filename, true)
		if err != nil {
			return err
		}

		// save newContentLocation to UUID+1, save file to newContentLocation
		err = SendSymObject(file.FileKey, UUIDplusone, &newContentLocation)
		if err != nil {
			return err
		}
		err = SendSymObject(file.FileKey, newContentUUID, &content)
		if err != nil {
			return err
		}
	} else { // create new File
		LocationOrig := userlib.RandomBytes(16)
		Location, err := uuid.FromBytes(LocationOrig)
		if err != nil {
			return err
		}
		FileKey := userlib.RandomBytes(32)
		Owner := userdata.Username
		newFile := File{FileKey, Location, LocationOrig, make(map[string]*Invitation), make(map[string]uuid.UUID), make(map[string][]string), Owner}
		err = SendSymObject(FileKey, Location, &newFile)
		if err != nil {
			return err
		}
		byteplustwo := AddOneToByteArr(AddOneToByteArr(LocationOrig))
		if len(content) == 0 { // if no content, lastLocation should point to itself
			byteplustwo = AddOneToByteArr(LocationOrig)
		}
		UUIDplusone, err := uuid.FromBytes(AddOneToByteArr(LocationOrig))
		if err != nil {
			return err
		}
		UUIDplustwo, err := uuid.FromBytes(byteplustwo)
		if err != nil {
			return err
		}
		err = SendSymObject(FileKey, UUIDplusone, &byteplustwo)
		if err != nil {
			return err
		}
		if len(content) != 0 {
			err = SendSymObject(FileKey, UUIDplustwo, &content)
			if err != nil {
				return err
			}
		}

		userdata.FileInfo[filename] = &newFile // update FileInfo
		// userlib.DebugMsg("File: %v", newFile)
		err = userdata.EncryptUser()
		if err != nil {
			return nil
		}
		// userlib.DebugMsg("File info: %v", userdata.FileInfo)
		// create invitation for oneself (mostly so that FileKey can be updated in AppendToFile)
		_, err = userdata.CreateInvitation(filename, userdata.Username)
		if err != nil {
			return err
		} // no need to accept it back (already exists in own User)
	}
	return nil
}

func (userdata *User) UpdateFileKey(filename string, file *File) (err error) {
	invite, ok := file.Invitations[userdata.Username] // check if invited
	inviteLoc, ok2 := file.InviteLocs[userdata.Username]
	if ok && ok2 { // update invitation and key
		newInvite, err := userdata.GetInvitation(invite.SenderUsername, inviteLoc, filename, file.Owner)
		if err != nil {
			return err
		}
		*invite = *newInvite
		file.FileKey = invite.FileKey
		// cannot grab another person's invitation; invitation is two-person street
	} else {
		return errors.New("not invited to this file")
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Appends to file
	if len(content) == 0 {
		return nil // do nothing
	}
	// userdata, err := GetUser((*userdata).Username, (*userdata).Password) // bandwidth requirements
	// if err != nil {
	// 	return err
	// }
	// userlib.DebugMsg("File info: %v", userdata.FileInfo)

	file, ok := userdata.FileInfo[filename]
	if !ok {
		return errors.New("file not found")
	}
	err := userdata.UpdateFileKey(filename, file)
	if err != nil {
		return err
	}
	locUUID, err := uuid.FromBytes(AddOneToByteArr(file.LocationOrig)) // UUID of lastLocation
	if err != nil {
		return err
	}
	lastLocBytesPtr, err := ReceiveSymObject[[]byte](file.FileKey, locUUID)
	if err != nil {
		return err
	}
	// userlib.DebugMsg("Got lastLocation []byte")
	newLastLocBytes := AddOneToByteArr(*lastLocBytesPtr)
	newUUID, err := uuid.FromBytes(newLastLocBytes) // UUID to send append to
	if err != nil {
		return err
	}
	err = SendSymObject(file.FileKey, newUUID, &content)
	if err != nil {
		return err
	}
	err = SendSymObject(file.FileKey, locUUID, &newLastLocBytes)
	return err
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	return userdata.LoadAndDeleteFile(filename, false)
}

// https://stackoverflow.com/questions/15311969/checking-the-equality-of-two-slices
func AreEqual(a []byte, b []byte) (equal bool) {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (userdata *User) LoadAndDeleteFile(filename string, delete bool) (content []byte, err error) {
	tmpPtr, err := GetUser((*userdata).Username, (*userdata).Password)
	if err != nil {
		return nil, err
	}
	*userdata = *tmpPtr
	file, ok := userdata.FileInfo[filename]
	if !ok {
		return nil, errors.New("file not found")
	}
	err = userdata.UpdateFileKey(filename, file)
	if err != nil {
		return nil, err
	}
	runningAddress := AddOneToByteArr(AddOneToByteArr(file.LocationOrig))
	fileContents := []byte(nil)
	UUID, err := uuid.FromBytes(runningAddress)
	if err != nil {
		return nil, err
	}
	lastUUID, err := uuid.FromBytes(AddOneToByteArr(file.LocationOrig))
	if err != nil {
		return nil, err
	}
	lastLocation, err := ReceiveSymObject[[]byte](file.FileKey, lastUUID)
	if err != nil {
		return nil, err
	}
	*lastLocation = AddOneToByteArr(*lastLocation) // one beyond the UUID of the last element
	// https://stackoverflow.com/questions/15311969/checking-the-equality-of-two-slices
	for !AreEqual(runningAddress, *lastLocation) { // while element found in item
		decodedSnippet, err := ReceiveSymObject[[]byte](file.FileKey, UUID)
		// userlib.DebugMsg("File key: %v", file.FileKey)
		if err != nil {
			return nil, err
		}
		if len(*decodedSnippet) == 0 {
			return nil, errors.New("missing append in middle (tampering?)")
		}
		// https://stackoverflow.com/questions/16248241/concatenate-two-slices-in-go
		fileContents = append(fileContents, *decodedSnippet...)
		runningAddress = AddOneToByteArr(runningAddress) // move both up by one
		if delete {
			userlib.DatastoreDelete(UUID)
		}
		UUID, err = uuid.FromBytes(runningAddress)
		if err != nil {
			return nil, err
		}
	}
	// userlib.DebugMsg("File contents: %v; string version: %s", fileContents, fileContents)
	// userlib.DebugMsg("File: %v", file)
	err = userdata.EncryptUser()
	if err != nil {
		return nil, err
	}
	return fileContents, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	tmpPtr, err := GetUser((*userdata).Username, (*userdata).Password)
	if err != nil {
		return uuid.Nil, err
	}
	*userdata = *tmpPtr
	file, ok := userdata.FileInfo[filename]
	if !ok {
		return uuid.Nil, errors.New("file not found")
	}
	publicFileKey, ok := userlib.KeystoreGet("Public File Key for " + recipientUsername)
	if !ok {
		return uuid.Nil, errors.New("username key not found")
	}
	UUID, err := uuid.FromBytes(userlib.RandomBytes(16)) // random UUID
	if err != nil {
		return uuid.Nil, err
	}
	invitation := Invitation{file.FileKey, file.Location, userdata.Username}
	err = SendAsymObject[Invitation](publicFileKey, UUID, userdata.PrivateSigningKey, &invitation)
	if err != nil {
		return uuid.Nil, err
	}

	// Update file and send it back
	username := userdata.Username
	// userlib.DebugMsg("File: %v", file)
	file.Invitations[recipientUsername] = &invitation
	file.InviteLocs[recipientUsername] = UUID
	if username == file.Owner {
		file.InvDiagram[recipientUsername] = (make([]string, 0, 10))
	} else { // putting name into correct place
		for key, arr := range file.InvDiagram {
			// https://stackoverflow.com/questions/10485743/contains-method-for-a-slice
			if key == recipientUsername || ElemInArr(arr, (recipientUsername)) {
				return uuid.Nil, errors.New("invitation already accepted")
			} else if key == username || ElemInArr(arr, username) {
				file.InvDiagram[key] = append(file.InvDiagram[key], recipientUsername)
			}
		}
	}
	err = SendSymObject[File](file.FileKey, file.Location, file)
	if err != nil {
		return uuid.Nil, err
	}
	err = userdata.EncryptUser()
	if err != nil {
		return uuid.Nil, err
	}
	return UUID, nil
}

func ElemInArr[T comparable](arr []T, elem T) (found bool) {
	// https://stackoverflow.com/questions/68053957/go-with-generics-type-parameter-t-is-not-comparable-with
	for idx := range arr {
		testElem := arr[idx]
		if testElem == elem {
			return true
		}
	}
	return false
}

func AddOneToByteArr(oldAddress []byte) (address []byte) {
	address = make([]byte, len(oldAddress))
	copy(address, oldAddress)
	if len(address) == 0 {
		userlib.DebugMsg("This should not happen; code will likely panic")
	}
	reverseI := len(address) - 1
	running := address[reverseI]
	for running == 255 { // handling any carryover
		address[reverseI] = 0
		if reverseI == 0 {
			// https://stackoverflow.com/questions/53737435/how-to-prepend-int-to-slice
			address = append(address, 0)
			copy(address[1:], address)
			address[0] = 1
		} else {
			reverseI = reverseI - 1
			running = address[reverseI]
		}
	}
	address[reverseI] = address[reverseI] + 1
	return address
}

func (userdata *User) GetInvitation(senderUsername string, invitationPtr uuid.UUID, filename string, fileOwner string) (invite *Invitation, err error) {
	publicSignKey, ok := userlib.KeystoreGet("Public Signing Key for " + senderUsername)
	if !ok {
		return nil, errors.New("sender sign key not found")
	}
	invitePtr, err := ReceiveAsymObject[Invitation](userdata.PrivateFileKey, invitationPtr, publicSignKey)
	if err != nil {
		// activates only when RevokeInvitation called
		invitePtr, err = ReceiveAsymObjectSignOptional[Invitation](userdata.PrivateFileKey, invitationPtr, publicSignKey, false)
		if err != nil {
			return nil, err
		}
		if fileOwner == "" {
			filePtr, err := ReceiveSymObject[File]((*invitePtr).FileKey, (*invitePtr).Location)
			if err != nil {
				return nil, err
			}
			fileOwner = (*filePtr).Owner // get original owner
		}
		publicSignKey, ok := userlib.KeystoreGet("Public Signing Key for " + fileOwner)
		if !ok {
			return nil, errors.New("sender sign key not found")
		}
		invitePtr, err = ReceiveAsymObject[Invitation](userdata.PrivateFileKey, invitationPtr, publicSignKey)
		if err != nil {
			return nil, err
		}
	}
	return invitePtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	tmpPtr, err := GetUser((*userdata).Username, (*userdata).Password)
	if err != nil {
		return err
	}
	*userdata = *tmpPtr
	invitePtr, err := userdata.GetInvitation(senderUsername, invitationPtr, filename, "")
	if err != nil {
		return err
	}

	// Update everything
	invite := *invitePtr
	_, ok := userdata.FileInfo[filename]
	if ok {
		return errors.New("file already exists in user's fileinfo")
	}
	// get File
	newFilePtr, err := ReceiveSymObject[File](invite.FileKey, invite.Location)
	if err != nil {
		return err
	}
	userdata.FileInfo[filename] = newFilePtr // file stored in User
	// update User
	err = userdata.EncryptUser()
	return err // if nil, will return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	tmpPtr, err := GetUser((*userdata).Username, (*userdata).Password)
	if err != nil {
		return err
	}
	*userdata = *tmpPtr
	file, ok := (*userdata).FileInfo[filename]
	if !ok {
		return errors.New("file not found")
	}
	_, ok = file.InvDiagram[recipientUsername]
	// userlib.DebugMsg("Invitation diagram: %v", file.InvDiagram)
	if !ok {
		return errors.New("owner did not share directly with this user")
	}
	// https://stackoverflow.com/questions/1736014/delete-key-in-map
	delete(file.Invitations, recipientUsername)
	for idx := range file.InvDiagram[recipientUsername] {
		username := file.InvDiagram[recipientUsername][idx]
		delete(file.Invitations, username)
	}
	delete(file.InvDiagram, recipientUsername)
	delete(file.InviteLocs, recipientUsername)

	fileContents, err := userdata.LoadAndDeleteFile(filename, true) // pull and delete contents
	if err != nil {
		return err
	}
	// Make new SymKey, re-encrypt file with it, and adjust everyone's invites
	newKey := userlib.RandomBytes(32)
	file.FileKey = newKey // update key in File
	// userlib.DebugMsg("New key: %v", userdata.FileInfo[filename].FileKey)
	// userlib.DebugMsg("New key: %v", newKey)
	err = SendSymObject(newKey, file.Location, &file) // update file info
	if err != nil {
		return err
	}
	// RevokeAccess "flattens" the file into one UUID
	lastLocAddress := AddOneToByteArr(AddOneToByteArr(file.LocationOrig))
	UUID, err := uuid.FromBytes(lastLocAddress)
	if err != nil {
		return err
	}
	err = SendSymObject[[]byte](newKey, UUID, &fileContents)
	if err != nil {
		return err
	}
	UUID, err = uuid.FromBytes(AddOneToByteArr(file.LocationOrig))
	if err != nil {
		return err
	}
	err = SendSymObject[[]byte](newKey, UUID, &lastLocAddress)
	if err != nil {
		return err
	}

	for username, UUID := range file.InviteLocs {
		newInvite := Invitation{file.FileKey, file.Location, userdata.Username}
		// send new invite at same invite location
		publicFileKey, ok := userlib.KeystoreGet("Public File Key for " + username)
		if !ok {
			return errors.New("receiver file key not found")
		}
		err = SendAsymObject[Invitation](publicFileKey, UUID, userdata.PrivateSigningKey, &newInvite)
		if err != nil {
			return err
		}
	}
	userdata.FileInfo[filename] = file
	err = userdata.EncryptUser()
	if err != nil {
		return err
	}
	return nil
}
